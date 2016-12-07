# frozen_string_literal: true
#
# This Module was developed by Thomas Hafner.
# No other references about the author.
#

# TITLE:
#
#   Cartesian
#
# SUMMARY:
#
#   Cartesian product and similar methods.
#
# AUTHORS:
#
#   - Thomas Hafner

#
module Enumerable
  class << self
    # Provides the cross-product of two or more Enumerables.
    # This is the class-level method. The instance method
    # calls on this.
    #
    #   Enumerable.cart([1,2], [4], ["apple", "banana"])
    #   #=> [[1, 4, "apple"], [1, 4, "banana"], [2, 4, "apple"], [2, 4, "banana"]]
    #
    #   Enumerable.cart([1,2], [3,4])
    #   #=> [[1, 3], [1, 4], [2, 3], [2, 4]]

    def cartesian_product(*enums)
      result = [[]]
      while [] != enums
        t = result
        result = []
        b, *enums = enums
        t.each do |a|
          b.each do |n|
            result << a + [n]
          end
        end
      end
      if block_given?
        result.each { |e| yield(e) }
      else
        result
      end
    end

    alias cart cartesian_product
  end

  # The instance level version of <tt>Enumerable::cartesian_product</tt>.
  #
  #   a = []
  #   [1,2].cart([4,5]){|elem| a << elem }
  #   a  #=> [[1, 4],[1, 5],[2, 4],[2, 5]]

  def cartesian_product(*enums, &block)
    Enumerable.cartesian_product(self, *enums, &block)
  end

  alias cart cartesian_product

  # Operator alias for cross-product.
  #
  #   a = [1,2] ** [4,5]
  #   a  #=> [[1, 4],[1, 5],[2, 4],[2, 5]]
  #
  def **(enum)
    Enumerable.cartesian_product(self, enum)
  end

  # Expected to be an enumeration of arrays. This method
  # iterates through combinations of each in position.
  #
  #   a = [ [0,1], [2,3] ]
  #   a.each_combo { |c| p c }
  #
  # produces
  #
  #   [0, 2]
  #   [0, 3]
  #   [1, 2]
  #   [1, 3]
  #
  def each_combo
    a = collect do |x|
      x.respond_to?(:to_a) ? x.to_a : 0..x
    end

    if a.size == 1
      r = a.shift
      r.each do |n|
        yield n
      end
    else
      r = a.shift
      r.each do |n|
        a.each_combo do |s|
          yield [n, *s]
        end
      end
    end
  end

  # As with each_combo but returns combos collected in an array.
  #
  def combos
    a = []
    each_combo { |c| a << c }
    a
  end
end
