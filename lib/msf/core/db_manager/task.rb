# frozen_string_literal: true
module Msf::DBManager::Task
  #
  # Find or create a task matching this type/data
  #
  def find_or_create_task(opts)
    report_task(opts)
  end

  def report_task(opts)
    return unless active
    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace = opts.delete(:workspace) || workspace
      path = opts.delete(:path) || (raise "A task :path is required")

      ret = {}

      user      = opts.delete(:user)
      desc      = opts.delete(:desc)
      error     = opts.delete(:error)
      info      = opts.delete(:info)
      mod       = opts.delete(:mod)
      options   = opts.delete(:options)
      prog      = opts.delete(:prog)
      result    = opts.delete(:result)
      completed_at = opts.delete(:completed_at)
      task = wspace.tasks.new

      task.created_by = user
      task.description = desc
      task.error = error if error
      task.info = info
      task.module = mod
      task.options = options
      task.path = path
      task.progress = prog
      task.result = result if result
      msf_import_timestamps(opts, task)
      # Having blank completed_ats, while accurate, will cause unstoppable tasks.
      task.completed_at = if completed_at.nil? || completed_at.empty?
                            opts[:updated_at]
                          else
                            completed_at
                          end
      task.save!
      ret[:task] = task
    end
  end

  #
  # This methods returns a list of all tasks in the database
  #
  def tasks(wspace = workspace)
    ::ActiveRecord::Base.connection_pool.with_connection do
      wspace.tasks
    end
  end
end
