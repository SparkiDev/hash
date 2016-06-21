# Copyright (c) 2016 Sean Parkinson
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#


class LogicVector
  attr_reader :name, :vector, :num_ops, :left, :right, :op

  def initialize(n, v, c=0, l=nil, r=nil, o=nil)
    @name = n
    @vector = v
    @num_ops = c
    @left = l
    @right = r
    @op = o
  end

  def ~()
    LogicVector.new("~"+@name, ~@vector, @num_ops+1, self, nil, "~")
  end
  def &(b)
    LogicVector.new("(#{@name}&#{b.name})", b.vector & @vector,
        b.num_ops+@num_ops+1, self, b, "&")
  end
  def *(b)
    LogicVector.new("(#{@name}*#{b.name})", b.vector & (~@vector),
        b.num_ops+@num_ops+1, self, b, "*")
  end
  def |(b)
    LogicVector.new("(#{@name}|#{b.name})", b.vector | @vector,
        b.num_ops+@num_ops+1, self, b, "|")
  end
  def ^(b)
    LogicVector.new("(#{@name}^#{b.name})", b.vector ^ @vector,
        b.num_ops+@num_ops+1, self, b, "^")
  end

  def to_s()
    "#{num_ops} #{name}"
  end
end

class LogicVectors
  @@bin_op = { "~" => lambda { |x| ~x } }
  @@comp_op = { "&" => lambda { |x,y| x & y },
                "|" => lambda { |x,y| x | y },
                "^" => lambda { |x,y| x ^ y } }
#               "*" => lambda { |x,y| x * y },
  def initialize()
    @list = {}
  end
  def <<(a)
    @list[a.name] = a
    self
  end

  def combine(cnt)
    k = @list.keys
    0.upto(k.length-1) do |i|
      li = @list[k[i]]
      if li.num_ops + 1 == cnt
        @@bin_op.keys.each do |op|
          next if li.op == op
          self << @@bin_op[op].call(li)
        end
      end
      (i+1).upto(k.length-1) do |j|
        lj = @list[k[j]]
        next if lj.num_ops + li.num_ops + 1 != cnt
        @@comp_op.keys.each do |op|
          if lj.op == op and op != "*"
            next if lj.left.name == li.name or lj.right.name == li.name
            n = "("+lj.left.name+op+"("+li.name+op+lj.right.name+"))"
            next if @list[n]
          end
          if lj.right and lj.right.op == op and op != "*"
            next if lj.right.left.name == li.name
          end
          if li.op == op and op != "*"
            n = "("+li.left.name+op+"("+li.right.name+op+lj.name+"))"
            next if @list[n]
            n = "("+li.right.name+op+"("+li.left.name+op+lj.name+"))"
            next if @list[n]
          end
          if lj.op == op and op != "*" and li.op == op
            next if lj.left == li.left or lj.left == li.right
          end
          lv = @@comp_op[op].call(li, lj)
          self << lv if lv.vector != li.vector and lv.vector != lj.vector
        end
      end
    end
  end

  def gen(max)
    1.upto(max) do |c|
      combine(c)
      puts @list.keys.length
    end
  end

  def find(v)
    @list.keys.each do |k|
      if @list[k].vector == v
        puts @list[k]
      end
    end
  end
end

a = LogicVector.new("a", 0x0f)
b = LogicVector.new("b", 0x33)
c = LogicVector.new("c", 0x55)
# a ^ (~b & c)
res = 0x4b
# (a & b) ^ (~a & c)
#res = 0x53
# (a & b) ^ (a & c) ^ (b & c)
#res = 0x17

lvs = LogicVectors.new()
lvs << a
lvs << b
lvs << c
lvs.gen(4)
lvs.find(res)

