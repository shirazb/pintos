#!/usr/bin/ruby

# gem install colorize => colors


iterations = ARGV.empty? ? 1 : ARGV[0].to_i
puts iterations

concurrenyBugs = false
totalOutput = []

for i in 1..iterations
  output = []
  count = 0
  `make clean && make check -j | grep -w FAIL`.split(/\n+/).each{ |t|
    if t.include? 'FAIL'
      count += 1
      output |= [t[10..-1]]
    end
  }

  puts ""
  output.each{ |t| puts "failing #{t}" }
  puts "failing #{count/2} tests"

  totalOutput |= output
  concurrencyBugs = true if count/2 != totalOutput.length
end

puts "\nAll failing tests"
totalOutput.each{ |t| puts "failing #{t}"}
puts "failing #{totalOutput.length} tests across #{iterations} iterations"
puts "Concurrency bugs present" if concurrencyBugs
