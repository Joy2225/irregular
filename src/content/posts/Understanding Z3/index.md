---
title: Understanding Z3 from a beginner's perspective
published: 2023-12-25
description: "How to use this blog template."
image: "./Z3.png"
tags: ["Python", "CTF", "Solver"]
category: Guides
draft: false
---

<!-- > Cover image source: [Source](https://image.civitai.com/xG1nkqKTMzGDvpLrqFT7WA/208fc754-890d-4adb-9753-2c963332675d/width=2048/01651-1456859105-(colour_1.5),girl,_Blue,yellow,green,cyan,purple,red,pink,_best,8k,UHD,masterpiece,male%20focus,%201boy,gloves,%20ponytail,%20long%20hair,.jpeg) -->

# <u>Description</u>
This post covers the basic understanding of the Z3-Solver library in python. The codes are taken from [hacktricks](https://book.hacktricks.xyz/reversing/reversing-tools-basic-methods/satisfiability-modulo-theories-smt-z3) and I have written about how to understand the codes and the things which might be hard to understand for beginners. Hope this helps.

<hr>

# <u>Boolean</u>
```python
#Taken from hacktricks website
#pip3 install z3-solver
from z3 import *
s = Solver() #The solver will be given the conditions

x = Bool("x") #Declare the symbos x, y and z as type boolean
y = Bool("y")
z = Bool("z")

# (x or y or !z) and y
s.add(And(Or(x,y,Not(z)),y))
s.check() #If response is "sat" then the model is satifable, if "unsat" something is wrong
print(s.model()) #Print valid values to satisfy the model
```

Majorly all the things are explained in the comments. One thing whose exact explanation I was looking for is the **`add`** function. 
- s.add(constraints) - Basically it gives the solver the constraints.

Now the above code is satisfied by some specific values of x, y and z.
The output is:-
```
[z = False, y = True, x = False]
```

Now if you try to give something which cannot be solved. For example, if we give something as (x AND !x) which can never be true, then it throws an exception
```python
from z3 import *
s = Solver() 
x = Bool("x")
s.add(And(x,Not(x)))
s.check()
print(s.model())
```

**Output:**
```
Traceback (most recent call last):
  File "/home/joy/.local/lib/python3.10/site-packages/z3/z3.py", line 7131, in model
    return ModelRef(Z3_solver_get_model(self.ctx.ref(), self.solver), self.ctx)
  File "/home/joy/.local/lib/python3.10/site-packages/z3/z3core.py", line 4185, in Z3_solver_get_model
    _elems.Check(a0)
  File "/home/joy/.local/lib/python3.10/site-packages/z3/z3core.py", line 1505, in Check
    raise self.Exception(self.get_error_message(ctx, err))
z3.z3types.Z3Exception: b'there is no current model'

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/home/joy/bi0s/Learning/Z3/test.py", line 6, in <module>
    print(s.model())
  File "/home/joy/.local/lib/python3.10/site-packages/z3/z3.py", line 7133, in model
    raise Z3Exception("model is not available")
z3.z3types.Z3Exception: model is not available
```

# <u>Integers/Simplify/Reals</u>

```python
#Taken from hacktricks website
from z3 import *

x = Int('x')
y = Int('y')
#Simplify a "complex" ecuation
print(simplify(And(x + 1 >= 3, x**2 + x**2 + y**2 + 2 >= 5)))
#And(x >= 2, 2*x**2 + y**2 >= 3)

#Note that Z3 is capable to treat irrational numbers (An irrational algebraic number is a root of a polynomial with integer coefficients. Internally, Z3 represents all these numbers precisely.)
#so you can get the decimals you need from the solution
r1 = Real('r1')
r2 = Real('r2')
#Solve the ecuation
print(solve(r1**2 + r2**2 == 3, r1**3 == 2))
#Solve the ecuation with 30 decimals
set_option(precision=30)
print(solve(r1**2 + r2**2 == 3, r1**3 == 2))
```

**Output:**
```
And(x >= 2, 2*x**2 + y**2 >= 3)
[r1 = 1.2599210498?, r2 = -1.1885280594?]
None
[r1 = 1.259921049894873164767210607278?,
 r2 = -1.188528059421316533710369365015?]
None
```

The above code is pretty straightforward with the comments and the output. One doubt which might occur is why **`None`** is being printed. It is due to the fact that Z3's **`solve`** method, when used with the Real numbers and an irrational equation, may not always provide a precise solution. The floating-point arithmetic involved in solving equations with irrational numbers can sometimes lead to numerical imprecision, and Z3 might not be able to find an exact solution.

# <u> Printing model </u>

```python
from z3 import *

x, y, z = Reals('x y z')
s = Solver()
s.add(x > 1, y > 1, x + y > 3, z - x < 10)
s.check()

m = s.model()
print ("x = %s" % m[x])
for d in m.decls():
    print("%s = %s" % (d.name(), m[d]))
```

**Output:**
```
x = 3/2
y = 2
x = 3/2
z = 0
```

**Print Variable Values:**    
`print("x = %s" % m[x])`
This line prints the value assigned to the variable `x` in the satisfying model.

**Print All Variable Values:**
```
for d in m.decls():
	print("%s = %s" % (d.name(), m[d]))
```
This loop iterates over all declarations in the model (`m.decls()`), printing the name and value of each variable in the satisfying assignment.

In summary, this code sets up a system of real variables and constraints using the Z3 library, checks if there exists an assignment of values to the variables that satisfies the constraints, and then prints the values of the variables in a satisfying assignment if one is found.

# <u>Machine Arithmetic</u>

Modern CPUs and main-stream programming languages use arithmetic over **fixed-size bit-vectors**. Machine arithmetic is available in Z3Py as **Bit-Vectors**.

```python
from z3 import *

x = BitVec('x', 16) #Bit vector variable "x" of length 16 bit
y = BitVec('y', 16)

e = BitVecVal(10, 16) #Bit vector with value 10 of length 16bits
a = BitVecVal(-1, 16)
b = BitVecVal(65535, 16)
print(simplify(a == b)) #This is True!
a = BitVecVal(-1, 32)
b = BitVecVal(65535, 32)
print(simplify(a == b)) #This is False
```

Output:
```
True
False
```

In 2's complement of `16 bit` -1, it gets converted to `65535` itself. Thats why z3 considers -1 and 65535 as equal in 16 bits, but in 32 bits, the 2's complement of -1 is (2<sup>31</sup> - 1). Hence they are not equal.

# <u>Signed/Unsigned Numbers</u>

Z3 provides special signed versions of arithmetical operations where it makes a difference whether the **bit-vector is treated as signed or unsigned**. In Z3Py, the operators **<, <=, >, >=, /, % and >>** correspond to the **signed** versions. The corresponding **unsigned** operators are **ULT(Unsigned lesser than), ULE(Unsigned lesser equal to), UGT(Unsigned greater than), UGE(Unsigned greater equal to), UDiv(Unsigned Division), URem(Unsigned Remainder), LShL(Logical Shift Left) and LShR(Logical shift right),.**

```python
from z3 import *

# Create to bit-vectors of size 32
x, y = BitVecs('x y', 32)
solve(x + y == 2, x > 0, y > 0)

# Bit-wise operators
# & bit-wise and
# | bit-wise or
# ~ bit-wise not
solve(x & y == ~y)
solve(x < 0)

# using unsigned version of < 
solve(ULT(x, 0))
```

Output:
```
[y = 1, x = 1]
[x = 0, y = 4294967295]
[x = 4294967295]
no solution
```

# <u>Functions</u>

**Interpreted functions** such as arithmetic where the **function +** has a **fixed standard interpretation** (it adds two numbers). **Uninterpreted functions** and constants are **maximally flexible**; they allow **any interpretation** that is **consistent** with the **constraints** over the function or constant.

Example: f applied twice to x results in x again, but f applied once to x is different from x.
```python
from z3 import *
x = Int('x')
y = Int('y')
f = Function('f', IntSort(), IntSort())

s = Solver()
s.add(f(f(x)) == x, f(x) == y, x != y)
s.check()
m = s.model()

print("f(f(x)) =", m.evaluate(f(f(x))))
print("f(x) =", m.evaluate(f(x)))
print(m.evaluate(f(2)))

s.add(f(x) == 4) #Find the value that generates 4 as response
s.check()
print(s.model())
```

Output
```
f(f(x)) = 0
f(x) = 1
1
[x = 2, y = 4, f = [2 -> 4, else -> 2]]
```

In Z3, the `Function` function is used to declare a function symbol. Its prototype is as follows:
```python
Function(name, *domain, range)
```

- `name`: A string that represents the name of the function symbol.
- `*domain`: A variable number of arguments representing the sorts (data types) of the function's domain (input types). These can be one or more sorts.
- `range`: The sort (data type) representing the function's codomain (output type).

In Z3, `IntSort()` is a function that returns the sort (data type) representing integers. In Z3, sorts are used to define the types of variables and functions.

Here's a breakdown:

- `IntSort()` is a function call that returns the integer sort in Z3.
- The `IntSort()` function represents the sort (data type) of integers.
- In Z3, a "sort" refers to a particular type or domain of values, and `IntSort()` specifically refers to the sort of integers.

# <u>Printing all valid models</u>
Now you might be asking, that `s.model()` gives only 1 model which is valid. But there might be other models which are valid. How do I see them? Don't worry. I also had the same question, and I got you covered.
```python
from z3 import *

x,y = Bools('x y')
s=Solver()
s.add(Or(x,y))
while s.check() == sat: 
	model = s.model()
	# Print the values of the current model
	print("Model:", model)
	# Create constraints to exclude the current model
	exclude_current_model = Or([v() != model[v] for v in model])
	# Add the exclusion constraint to the solver
	s.add(exclude_current_model)  

print("No more models.")
```

Output:
```
Model: [y = False, x = True]
Model: [y = True]
No more models.
```

The 2nd model means that if y is true, x can be anything i.e:- true or false. Hence all 3 models is shown indirectly.
