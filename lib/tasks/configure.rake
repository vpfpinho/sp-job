


desc 'Update project configuration: action=overwrite => update system,user,project; action => hotfix update project only; other no change (dryrun)'
task :configure, [ :action ] do |task, args|
  require_relative '../sp/job/configure/configure'
  run_configure(args)
end
