import re
s = '''
/Applications/MAMP/htdocs/CTF/XMAN/code.php:3:
array (size=232)
  0 => 
    array (size=3)
      0 => int 376
      2 => int 1
  1 => 
    array (size=3)
      0 => int 312
      1 => string '' (length=2)
      2 => int 2
  2 => 
    array (size=3)
      0 => int 379
      2 => int 2
  3 => string '=' (length=1)
  4 => 
    array (size=3)
      1 => string ' ' (length=1)
      2 => int 2
  5 => 
    array (size=3)
      0 => int 318
      1 => string '' (length=6)
      2 => int 2
  6 => string ';' (length=1)
  7 => 
    array (size=3)
      0 => int 379
      1 => string '
' (length=1)
      2 => int 2
  8 => 
    array (size=3)
      0 => int 312
      1 => string '' (length=3)
      2 => int 3
  9 => 
    array (size=3)
      0 => int 379
      1 => string '  ' (length=2)
      2 => int 3
  10 => string '=' (length=1)
  11 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 3
  12 => 
    array (size=3)
      0 => int 310
      1 => string 'base64_decode' (length=13)
      2 => int 3
  13 => string '(' (length=1)
  14 => 
    array (size=3)
      0 => int 318
      1 => string '' (length=6)
      2 => int 3
  15 => string ')' (length=1)
  16 => string ';' (length=1)
  17 => 
    array (size=3)
      0 => int 379
      1 => string '
' (length=1)
      2 => int 3
  18 => 
    array (size=3)
      0 => int 312
      1 => string '' (length=4)
      2 => int 4
  19 => 
    array (size=3)
      0 => int 379
      2 => int 4
  20 => string '=' (length=1)
  21 => 
    array (size=3)
      1 => string ' ' (length=1)
      2 => int 4
  22 => 
    array (size=3)
      0 => int 318
      1 => string '' ()
      2 => int 4
  23 => string ';' (length=1)
  24 => 
    array (size=3)
      0 => int 379
      1 => string '
' (length=1)
      2 => int 4
  25 => 
    array (size=3)
      0 => int 312
      1 => string '$dd' (length=3)
      2 => int 5
  26 => 
    array (size=3)
      0 => int 379
      1 => string '    ' (length=4)
      2 => int 5
  27 => string '=' (length=1)
  28 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 5
  29 => 
    array (size=3)
      0 => int 318
      1 => string '"85"' (length=4)
      2 => int 5
  30 => string ';' (length=1)
  31 => 
    array (size=3)
      0 => int 379
      1 => string '
' (length=1)
      2 => int 5
  32 => 
    array (size=3)
      0 => int 312
      1 => string '$____' (length=5)
      2 => int 6
  33 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 6
  34 => string '=' (length=1)
  35 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 6
  36 => 
    array (size=3)
      0 => int 318
      1 => string '' (length=9)
      2 => int 6
  37 => string ';' (length=1)
  38 => 
    array (size=3)
      0 => int 379
      1 => string '
' (length=1)
      2 => int 6
  39 => 
    array (size=3)
      0 => int 312
      1 => string '' (length=6)
      2 => int 7
  40 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 7
  41 => string '=' (length=1)
  42 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 7
  43 => 
    array (size=3)
      0 => int 318
      1 => string '"In"' (length=4)
      2 => int 7
  44 => string '.' (length=1)
  45 => 
    array (size=3)
      0 => int 318
      1 => string '' (length=3)
      2 => int 7
  46 => string '.' (length=1)
  47 => 
    array (size=3)
      0 => int 318
      1 => string '"P"' (length=3)
      2 => int 7
  48 => string '.' (length=1)
  49 => 
    array (size=3)
      0 => int 318
      1 => string '"h"' (length=3)
      2 => int 7
  50 => string '.' (length=1)
  51 => 
    array (size=3)
      0 => int 318
      1 => string '' (length=3)
      2 => int 7
  52 => string ';' (length=1)
  53 => 
    array (size=3)
      0 => int 379
      1 => string '
' (length=1)
      2 => int 7
  54 => 
    array (size=3)
      0 => int 323
      2 => int 8
  55 => string '(' (length=1)
  56 => 
    array (size=3)
      0 => int 312
      1 => string '$i' (length=2)
      2 => int 8
  57 => string '=' (length=1)
  58 => 
    array (size=3)
      0 => int 308
      1 => string '0' (length=1)
      2 => int 8
  59 => string ';' (length=1)
  60 => 
    array (size=3)
      0 => int 312
      1 => string '$i' (length=2)
      2 => int 8
  61 => string '<' (length=1)
  62 => 
    array (size=3)
      0 => int 308
      1 => string '10' (length=2)
      2 => int 8
  63 => string ';' (length=1)
  64 => 
    array (size=3)
      0 => int 312
      1 => string '$i' (length=2)
      2 => int 8
  65 => 
    array (size=3)
      0 => int 299
      1 => string '++' (length=2)
      2 => int 8
  66 => string ')' (length=1)
  67 => string '{' (length=1)
  68 => 
    array (size=3)
      0 => int 379
      1 => string '
    ' (length=5)
      2 => int 8
  69 => 
    array (size=3)
      0 => int 312
      1 => string '$dd' (length=3)
      2 => int 9
  70 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 9
  71 => string '=' (length=1)
  72 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 9
  73 => 
    array (size=3)
      0 => int 312
      1 => string '$dd' (length=3)
      2 => int 9
  74 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 9
  75 => string '+' (length=1)
  76 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 9
  77 => 
    array (size=3)
      0 => int 308
      1 => string '1' (length=1)
      2 => int 9
  78 => string ';' (length=1)
  79 => 
    array (size=3)
      0 => int 379
      1 => string '
' (length=1)
      2 => int 9
  80 => string '}' (length=1)
  81 => 
    array (size=3)
      0 => int 379
      1 => string '
' (length=1)
      2 => int 10
  82 => 
    array (size=3)
      0 => int 312
      1 => string '' (length=8)
      2 => int 11
  83 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 11
  84 => string '=' (length=1)
  85 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 11
  86 => 
    array (size=3)
      0 => int 310
      1 => string 'chr' (length=3)
      2 => int 11
  87 => string '(' (length=1)
  88 => 
    array (size=3)
      0 => int 312
      1 => string '$dd' (length=3)
      2 => int 11
  89 => string ')' (length=1)
  90 => string ';' (length=1)
  91 => 
    array (size=3)
      0 => int 379
      1 => string '
' (length=1)
      2 => int 11
  92 => 
    array (size=3)
      0 => int 312
      1 => string '$dc' (length=3)
      2 => int 12
  93 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 12
  94 => string '=' (length=1)
  95 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 12
  96 => 
    array (size=3)
      0 => int 312
      1 => string '$dd' (length=3)
      2 => int 12
  97 => string ';' (length=1)
  98 => 
    array (size=3)
      0 => int 379
      1 => string '
' (length=1)
      2 => int 12
  99 => 
    array (size=3)
      0 => int 320
      2 => int 13
  100 => string '{' (length=1)
  101 => 
    array (size=3)
      0 => int 379
      1 => string '
    ' (length=5)
      2 => int 13
  102 => 
    array (size=3)
      0 => int 312
      1 => string '$dd' (length=3)
      2 => int 14
  103 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 14
  104 => string '=' (length=1)
  105 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 14
  106 => 
    array (size=3)
      0 => int 312
      1 => string '$dc' (length=3)
      2 => int 14
  107 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 14
  108 => string '+' (length=1)
  109 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 14
  110 => 
    array (size=3)
      0 => int 312
      1 => string '$dc' (length=3)
      2 => int 14
  111 => string ';' (length=1)
  112 => 
    array (size=3)
      0 => int 379
      1 => string '
    ' (length=5)
      2 => int 14
  113 => 
    array (size=3)
      0 => int 312
      1 => string '$dc' (length=3)
      2 => int 15
  114 => 
    array (size=3)
      0 => int 299
      2 => int 15
  115 => string ';' (length=1)
  116 => 
    array (size=3)
      0 => int 379
      1 => string '
' (length=1)
      2 => int 15
  117 => string '}' (length=1)
  118 => 
    array (size=3)
      0 => int 321
      2 => int 16
  119 => string '(' (length=1)
  120 => 
    array (size=3)
      0 => int 312
      1 => string '$dc' (length=3)
      2 => int 16
  121 => string '<' (length=1)
  122 => 
    array (size=3)
      0 => int 308
      1 => string '100' (length=3)
      2 => int 16
  123 => string ')' (length=1)

  125 => 
    array (size=3)
      0 => int 379
      1 => string '
' (length=1)
      2 => int 16
  126 => 
    array (size=3)
      0 => int 312
      1 => string '$_GET' (length=5)
      2 => int 17
  127 => string '[' (length=1)
  128 => 
    array (size=3)
      0 => int 318
      1 => string ''secret'' (length=8)
      2 => int 17
  129 => string ']' (length=1)
  130 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 17
  131 => string '=' (length=1)
  132 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 17
  133 => 
    array (size=3)
      0 => int 355
      1 => string 'isset' (length=5)
      2 => int 17
  134 => string '(' (length=1)
  135 => 
    array (size=3)
      0 => int 312
      1 => string '$_GET' (length=5)
      2 => int 17
  136 => string '[' (length=1)
  137 => 
    array (size=3)
      0 => int 318
      1 => string ''secret'' (length=8)
      2 => int 17
  138 => string ']' (length=1)
  139 => string ')' (length=1)
  140 => string '?' (length=1)
  141 => 
    array (size=3)
      0 => int 312
      1 => string '$_GET' (length=5)
      2 => int 17
  142 => string '[' (length=1)
  143 => 
    array (size=3)
      0 => int 318
      1 => string ''secret'' (length=8)
      2 => int 17
  144 => string ']' (length=1)
  145 => string ':' (length=1)
  146 => 
    array (size=3)
      0 => int 308
      1 => string '1' (length=1)
      2 => int 17
  147 => string ';' (length=1)
  148 => 
    array (size=3)
      0 => int 379
      1 => string '
' (length=1)
      2 => int 17
  149 => 
    array (size=3)
      0 => int 330
      2 => int 18
  150 => string '(' (length=1)
  151 => 
    array (size=3)
      0 => int 312
      1 => string '$_GET' (length=5)
      2 => int 18
  152 => string '[' (length=1)
  153 => 
    array (size=3)
      0 => int 318
      1 => string ''secret'' (length=8)
      2 => int 18
  154 => string ']' (length=1)
  155 => string ')' (length=1)
  156 => string '{' (length=1)
  157 => 
    array (size=3)
      0 => int 379
      1 => string '
    ' (length=5)
      2 => int 18
  158 => 
    array (size=3)
      0 => int 332
      2 => int 19
  159 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 19
  160 => 
    array (size=3)
      0 => int 308
      1 => string '1' (length=1)
      2 => int 19
  161 => string ':' (length=1)
  162 => 
    array (size=3)
      0 => int 379
      1 => string '
        ' (length=9)
      2 => int 19
  163 => 
    array (size=3)
      0 => int 319
      1 => string 'echo' (length=4)
      2 => int 20
  164 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 20
  165 => 
    array (size=3)
      0 => int 318
      1 => string '"XMAN2018!"' (length=11)
      2 => int 20
  166 => string ';' (length=1)
  167 => 
    array (size=3)
      0 => int 379
      1 => string '
        ' (length=9)
      2 => int 20
  168 => 
    array (size=3)
      0 => int 334
      2 => int 21
  169 => string ';' (length=1)
  170 => 
    array (size=3)
      0 => int 379
      1 => string '
    ' (length=5)
      2 => int 21
  171 => 
    array (size=3)
      0 => int 332
      2 => int 22
  172 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 22
  173 => 
    array (size=3)
      0 => int 308
      1 => string '4' (length=1)
      2 => int 22
  174 => string ':' (length=1)
  175 => 
    array (size=3)
      0 => int 379
      1 => string '
        ' (length=9)
      2 => int 22
  176 => 
    array (size=3)
      0 => int 334
      2 => int 23
  177 => string ';' (length=1)
  178 => 
    array (size=3)
      0 => int 379
      1 => string '
    ' (length=5)
      2 => int 23
  179 => 
    array (size=3)
      0 => int 332
      2 => int 24
  180 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 24
  181 => 
    array (size=3)
      0 => int 312
      1 => string '$dd' (length=3)
      2 => int 24
  182 => string ':' (length=1)
  183 => 
    array (size=3)
      0 => int 379
      1 => string '
        ' (length=9)
      2 => int 24
  184 => 
    array (size=3)
      0 => int 312
      1 => string '$fl' (length=3)
      2 => int 25
  185 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 25
  186 => string '=' (length=1)
  187 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 25
  188 => 
    array (size=3)
      0 => int 312
      1 => string '' (length=2)
      2 => int 25
  189 => string '.' (length=1)
  190 => 
    array (size=3)
      0 => int 318
      1 => string '"{"' (length=3)
      2 => int 25
  191 => string '.' (length=1)
  192 => string '"' (length=1)
  193 => 
    array (size=3)
      0 => int 312
      1 => string '' (length=3)
      2 => int 25
  194 => string '"' (length=1)
  195 => string '.' (length=1)
  196 => 
    array (size=3)
      0 => int 312
      1 => string '' (length=8)
      2 => int 25
  197 => string '.' (length=1)
  198 => 
    array (size=3)
      0 => int 312
      1 => string '' (length=4)
      2 => int 25
  199 => string '.' (length=1)
  200 => 
    array (size=3)
      0 => int 312
      1 => string '' (length=8)
      2 => int 25
  201 => string '.' (length=1)
  202 => 
    array (size=3)
      0 => int 310
      1 => string 'str_rot13' (length=9)
      2 => int 25
  203 => string '(' (length=1)
  204 => 
    array (size=3)
      0 => int 312
      1 => string '' (length=5)
      2 => int 25
  205 => string ')' (length=1)
  206 => string '.' (length=1)
  207 => 
    array (size=3)
      0 => int 312
      1 => string '' (length=6)
      2 => int 25
  208 => string '.' (length=1)
  209 => 
    array (size=3)
      0 => int 318
      1 => string '' (length=6)
      2 => int 25
  210 => string ';' (length=1)
  211 => 
    array (size=3)
      0 => int 379
      1 => string '
        ' (length=9)
      2 => int 25
  212 => 
    array (size=3)
      0 => int 319
      1 => string 'echo' (length=4)
      2 => int 26
  213 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 26
  214 => 
    array (size=3)
      0 => int 312
      1 => string '$fl' (length=3)
      2 => int 26
  215 => string ';' (length=1)
  216 => 
    array (size=3)
      0 => int 379
      1 => string '
        ' (length=9)
      2 => int 26
  217 => 
    array (size=3)
      0 => int 334
      1 => string 'break' (length=5)
      2 => int 27
  218 => string ';' (length=1)
  219 => 
    array (size=3)
      0 => int 379
      1 => string '
    ' (length=5)
      2 => int 27
  220 => 
    array (size=3)
      0 => int 333
      2 => int 28
  221 => string ':' (length=1)
  222 => 
    array (size=3)
      0 => int 379
      1 => string '
        ' (length=9)
      2 => int 28
  223 => 
    array (size=3)
      0 => int 319
      2 => int 29
  224 => 
    array (size=3)
      0 => int 379
      1 => string ' ' (length=1)
      2 => int 29
  225 => 
    array (size=3)
      0 => int 318
      1 => string '"XMAN NB!"' (length=10)
      2 => int 29
  226 => string ';' (length=1)
  227 => 
    array (size=3)
      0 => int 379
      1 => string '
' (length=1)
      2 => int 29
  228 => string '}' (length=1)
  229 => 
    array (size=3)
      0 => int 379
      1 => string '
' (length=1)
      2 => int 30
  230 => 
    array (size=3)
      0 => int 378
' (length=3)
      2 => int 31
  231 => 
    array (size=3)
      0 => int 314
      1 => string '

' (length=2)
      2 => int 32
'''

# r = re.findall(r"string '(.*)' (length=",s)
# print r
rlink = "string '(.*?)' \(length="
r = re.findall(rlink,s)
l = len(r)
code = ''
for i in xrange(0,l):
	code = code+r[i]
print code