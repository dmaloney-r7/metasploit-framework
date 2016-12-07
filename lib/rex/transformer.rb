# frozen_string_literal: true
# -*- coding: binary -*-
module Rex
  ###
  #
  # Transformer - more than meets the eye!
  #
  # This class, aside from having a kickass name, is responsible for translating
  # object instances of one or more types into a single list instance of one or
  # more types.  This is useful for translating object instances that be can
  # either strings or an array of strings into an array of strings, for
  # instance.  It lets you make things take a uniform structure in an abstract
  # manner.
  #
  ###
  class Transformer
    #
    # Translates the object instance supplied in src_instance to an instance of
    # dst_class.  The dst_class parameter's instance must support the <<
    # operator.  An example call to this method looks something like:
    #
    # Transformer.transform(string, Array, [ String ], target)
    #
    def self.transform(src_instance, dst_class, supported_classes,
                       target = nil)
      dst_instance = dst_class.new

      if src_instance.is_a?(Array)
        src_instance.each do |src_inst|
          Transformer.transform_single(src_inst, dst_instance,
                                       supported_classes, target)
        end
      elsif !src_instance.is_a?(NilClass)
        Transformer.transform_single(src_instance, dst_instance,
                                     supported_classes, target)
      end

      dst_instance
    end

    protected

    #
    # Transform a single source instance.
    #
    def self.transform_single(src_instance, dst_instance,
                              supported_classes, target)
      # If the src instance's class is supported, just add it to the dst
      # instance
      if supported_classes.include?(src_instance.class)
        dst_instance << src_instance
      # If the src instance's class is an array, then we should check to see
      # if any of the supporting classes support from_a.
      elsif src_instance.is_a?(Array)
        new_src_instance = nil

        # Walk each supported class calling from_a if exported
        supported_classes.each do |sup_class|
          next if sup_class.respond_to?('from_a') == false

          new_src_instance = sup_class.from_a(src_instance)

          unless new_src_instance.nil?
            dst_instance << new_src_instance
            break
          end
        end

        # If we don't have a valid new src instance, then we suck
        bomb_translation(src_instance, target) if new_src_instance.nil?

      # If the source instance is a string, query each of the supported
      # classes to see if they can serialize it to their particular data
      # type.
      elsif src_instance.is_a?(String)
        new_src_instance = nil

        # Walk each supported class calling from_s if exported
        supported_classes.each do |sup_class|
          next if sup_class.respond_to?('from_s') == false

          new_src_instance = sup_class.from_s(src_instance)

          unless new_src_instance.nil?
            dst_instance << new_src_instance
            break
          end
        end

        # If we don't have a valid new src instance, then we suck
        bomb_translation(src_instance, target) if new_src_instance.nil?
      # Otherwise, bomb translation
      else
        bomb_translation(src_instance, target)
      end
    end

    def self.bomb_translation(src_instance, target) # :nodoc:
      error = "Invalid source class (#{src_instance.class})"

      error += " for #{target}" unless target.nil?

      raise ArgumentError, error, caller
    end
  end
end
