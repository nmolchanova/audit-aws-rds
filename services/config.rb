
coreo_aws_rule "rds-inventory" do
  action :define
  service :rds
  # link "http://kb.cloudcoreo.com/mydoc_ec2-inventory.html"
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
  level "Warning"
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
  level "Critical"
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
  level "Critical"
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
                {'COMPOSITE::coreo_uni_util_variables.rds-planwide.number_violations' => '0'}
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
                {'COMPOSITE::coreo_uni_util_variables.rds-planwide.number_violations' => 'COMPOSITE::coreo_aws_rule_runner_rds.advise-rds.number_violations'},

            ])
end


coreo_uni_util_jsrunner "tags-to-notifiers-array-rds" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.10.7-9"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }
                  ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "cloud account name": "PLAN::cloud_account_name",
                "violations": COMPOSITE::coreo_aws_rule_runner_rds.advise-rds.report}'
  function <<-EOH



function setTableAndSuppression() {
  let table;
  let suppression;

  const fs = require('fs');
  const yaml = require('js-yaml');
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
      console.log("Error reading suppression.yaml file: " , e);
      suppression = {};
  }
  try {
      table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
      console.log("Error reading table.yaml file: ", e);
      table = {};
  }
  coreoExport('table', JSON.stringify(table));
  coreoExport('suppression', JSON.stringify(suppression));
  
  let alertListToJSON = "${AUDIT_AWS_RDS_ALERT_LIST}";
  let alertListArray = alertListToJSON.replace(/'/g, '"');
  json_input['alert list'] = alertListArray || [];
  json_input['suppression'] = suppression || [];
  json_input['table'] = table || {};
}


setTableAndSuppression();

const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_RDS_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_RDS_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_RDS_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_RDS_SEND_ON}";
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;

const SETTINGS = { NO_OWNER_EMAIL, OWNER_TAG, 
    ALLOW_EMPTY, SEND_ON, SHOWN_NOT_SORTED_VIOLATIONS_COUNTER};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditRDS = new CloudCoreoJSRunner(JSON_INPUT, SETTINGS);
const letters = AuditRDS.getLetters();

const newJSONInput = AuditRDS.getSortedJSONForAuditPanel();
coreoExport('JSONReport', JSON.stringify(newJSONInput));
coreoExport('report', JSON.stringify(newJSONInput['violations']));

callback(letters);
  EOH
end

# in the context of audit-aws, the jsrunner above is action :nothing, so these composite vars don't resolve
# commenting out until addressed

coreo_uni_util_variables "rds-update-planwide-3" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner_rds.advise-rds.report' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-rds.report'},
                {'COMPOSITE::coreo_uni_util_variables.rds-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-rds.JSONReport'},
                {'COMPOSITE::coreo_uni_util_variables.rds-planwide.table' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-rds.table'}
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
