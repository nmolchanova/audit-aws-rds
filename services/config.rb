
coreo_aws_rule "rds-inventory" do
  action :define
  service :rds
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "RDS Instance Inventory"
  description "This rule performs an inventory on all RDS DB instances in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["db_instances"]
  audit_objects ["object.db_instances.db_instance_identifier"]
  operators ["=~"]
  raise_when [//]
  id_map "object.db_instances.db_instance_identifier"
end

coreo_aws_rule "rds-short-backup-retention-period" do
  action :define
  service :rds
  link "http://kb.cloudcoreo.com/mydoc_rds-short-backup-retention-period.html"
  display_name "RDS short backup retention period"
  description "The affected RDS database has a short backup retention period (less than 30 days)."
  category "Dataloss"
  suggested_action "Modify the backup retension period to increase it to greater than 30 days."
  level "Low"
  objectives ["db_instances"]
  audit_objects ["db_instances.backup_retention_period"]
  operators ["<"]
  raise_when [30]
  id_map "object.db_instances.db_instance_identifier"
end

coreo_aws_rule "rds-no-auto-minor-version-upgrade" do
  action :define
  service :rds
  link "http://kb.cloudcoreo.com/mydoc_rds-no-auto-minor-version-upgrade.html"
  display_name "RDS not set to automatically upgrade"
  description "RDS is not set to automatically upgrade minor versions on your database instance."
  category "Reliability"
  suggested_action "Consider whether you would like AWS to automatically upgrade minor versions on your database instance. Modify your settings to allow minor version upgrades if possible."
  level "High"
  objectives ["db_instances"]
  audit_objects ["db_instances.auto_minor_version_upgrade"]
  operators ["=="]
  raise_when [false]
  id_map "object.db_instances.db_instance_identifier"
end

coreo_aws_rule "rds-db-publicly-accessible" do
  action :define
  service :rds
  link "http://kb.cloudcoreo.com/mydoc_rds-db-publicly-accessible.html"
  display_name "RDS is publicly accessible to the world"
  description "The affected RDS database is publicly accessible to the world."
  category "Security"
  suggested_action "Consider whether the affected RDS database should be publicly accessible to the world. If not, modify the option which enables your RDS database to become publicly accessible."
  level "High"
  objectives ["db_instances"]
  audit_objects ["db_instances.publicly_accessible"]
  operators ["=="]
  raise_when [true]
  id_map "object.db_instances.db_instance_identifier"
end


coreo_uni_util_variables "rds-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.rds-rds-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.rds-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.rds-planwide.results' => 'unset'},
                {'GLOBAL::number_violations' => '0'}
            ])
end

coreo_aws_rule_runner_rds "advise-rds" do
  rules ${AUDIT_AWS_RDS_ALERT_LIST}
  action :run
  regions ${AUDIT_AWS_RDS_REGIONS}
end

coreo_uni_util_variables "rds-update-planwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.rds-planwide.results' => 'COMPOSITE::coreo_aws_rule_runner_rds.advise-rds.report'},
                {'GLOBAL::number_violations' => 'COMPOSITE::coreo_aws_rule_runner_rds.advise-rds.number_violations'},

            ])
end


coreo_uni_util_jsrunner "tags-to-notifiers-array-rds" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.9.7-beta18"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }
                  ])
  json_input '{"compositeName":"PLAN::stack_name",
                "planName":"PLAN::name",
                "cloudAccountName": "PLAN::cloud_account_name",
                "violations": COMPOSITE::coreo_aws_rule_runner_rds.advise-rds.report}'
  function <<-EOH

const compositeName = json_input.compositeName;
const planName = json_input.planName;
const cloudAccount = json_input.cloudAccountName;
const cloudObjects = json_input.violations;

const NO_OWNER_EMAIL = "${AUDIT_AWS_RDS_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_RDS_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_RDS_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_RDS_SEND_ON}";

const alertListJSON = [${AUDIT_AWS_RDS_ALERT_LIST}];
const alertListArray = alertListJSON.replace(/'/g, '"');
const ruleInputs = {};

let userSuppression;
let userSchemes;

const fs = require('fs');
const yaml = require('js-yaml');

function setSuppression() {
  try {
    userSuppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
    console.log(`Error reading suppression.yaml file`);
    userSuppression = [];
  }
  coreoExport('suppression', JSON.stringify(userSuppression));
}

function setTable() {
  try {
    userSchemes = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
    console.log(`Error reading table.yaml file`);
    userSchemes = {};
  }
  coreoExport('table', JSON.stringify(userSchemes));
}
setSuppression();
setTable();

const argForConfig = {
    NO_OWNER_EMAIL, cloudObjects, userSuppression, OWNER_TAG,
    userSchemes, alertListArray, ruleInputs, ALLOW_EMPTY,
    SEND_ON, cloudAccount, compositeName, planName
}


function createConfig(argForConfig) {
    let JSON_INPUT = {
        compositeName: argForConfig.compositeName,
        planName: argForConfig.planName,
        violations: argForConfig.cloudObjects,
        userSchemes: argForConfig.userSchemes,
        userSuppression: argForConfig.userSuppression,
        alertList: argForConfig.alertListArray,
        disabled: argForConfig.ruleInputs,
        cloudAccount: argForConfig.cloudAccount
    };
    let SETTINGS = {
        NO_OWNER_EMAIL: argForConfig.NO_OWNER_EMAIL,
        OWNER_TAG: argForConfig.OWNER_TAG,
        ALLOW_EMPTY: argForConfig.ALLOW_EMPTY, SEND_ON: argForConfig.SEND_ON,
        SHOWN_NOT_SORTED_VIOLATIONS_COUNTER: false
    };
    return {JSON_INPUT, SETTINGS};
}

const {JSON_INPUT, SETTINGS} = createConfig(argForConfig);
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');

const emails = CloudCoreoJSRunner.createEmails(JSON_INPUT, SETTINGS);
const suppressionJSON = CloudCoreoJSRunner.createJSONWithSuppress(JSON_INPUT, SETTINGS);

coreoExport('JSONReport', JSON.stringify(suppressionJSON));
coreoExport('report', JSON.stringify(suppressionJSON['violations']));

callback(emails);
  EOH
end

# in the context of audit-aws, the jsrunner above is action :nothing, so these composite vars don't resolve
# commenting out until addressed

coreo_uni_util_variables "rds-update-planwide-3" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner_rds.advise-rds.report' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-rds.report'},
                {'COMPOSITE::coreo_uni_util_variables.rds-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-rds.JSONReport'},
                {'GLOBAL::table' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-rds.table'}
            ])
end

coreo_uni_util_jsrunner "tags-rollup-rds" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-rds.return'
  function <<-EOH
const notifiers = json_input;

function setTextRollup() {
    let emailText = '';
    let numberOfViolations = 0;
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        if(hasEmail) {
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['num_violations'] + "\\n";
        }
    });

    textRollup += 'Number of Violating Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;
}


let textRollup = '';
setTextRollup();

callback(textRollup);
  EOH
end

coreo_uni_util_notify "advise-rds-to-tag-values" do
  action((("${AUDIT_AWS_RDS_ALERT_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-rds.return'
end

coreo_uni_util_notify "advise-rds-rollup" do
  action((("${AUDIT_AWS_RDS_ALERT_RECIPIENT}".length > 0) and (! "${AUDIT_AWS_RDS_OWNER_TAG}".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty ${AUDIT_AWS_RDS_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_RDS_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup-rds.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_RDS_ALERT_RECIPIENT}', :subject => 'CloudCoreo rds rule results on PLAN::stack_name :: PLAN::name'
  })
end
