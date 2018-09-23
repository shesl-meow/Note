<center>Worse-Case to Average-Case Reduction for SIS</center>

If one wants to build the cryptography based on *worst-case lattice problems*, one just bases it on one of the these two problems:

- Small Integer Solution (**SIS**) Problem
- Learning With Erroes (**LWE**) Problem

*PostScript: Minicrypt &rarr; one of the 5 worlds of impagliazzo*

```mermaid
graph TB;
subgraph worse-case
LP(Lattice Problems)
end
subgraph average-case
SIS(Small Integer Solution, SIS)
LWE(Learning With Errors, LWE)
end
LP-->SIS
LP-->LWE
```



**Representing Lattices**:

- $$L(B) = \{z: z = Bx\ for\ x\ in\ Z^n\}$$

- $$L^{\perp}(A) = \{z\ in\ Z^m:Az = 0 \mod q\}$$

 