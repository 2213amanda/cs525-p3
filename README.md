# Project 3

- Name: Amanda Tuttle
- Email: amandatuttle631@u.boisestate.edu
- Class: CS525-001

## Known Bugs or Issues

There are no bugs or issues that I know of.

## Experience

I definitely had an easier time with this project than I did with project 2. The fact that all of the lab.h functions and definitions were preestablished was a big help, especially since the step of converting theory to actionable code is typically a step I struggle on. I also learned from my mistakes in the previous project where I had terrible code coverage and no time to fix it, and this time took the approach of writing a function, writing the unit tests for that function, and making sure I had full coverage for that function before moving onto the next one. This worked fairly well except for the table modifying functions, where I felt like I needed all of those functions written to use them in testing each other. It was in this section where I struggled most, partially due to AI gaslighting me (saying that there was no such existing code branch in code *it* wrote while I was trying to resolve code coverage), and partially because of difficult logic. I don't know if it's realistically possible to hit this edge case, but if a massive chunk of memory was allocated for a table then the table_add function could result in a seg fault. I had to add new code and reorder validity checks in order for this to fail instead of crash, which took me quite a few tries. Thankfully this is the most trouble I had with this project, although it almost makes me feel like I'm missing something compared to last time. 

## Design

The code handles /0, /31 and /32 addressing as special cases. The code implements strict checks for these addresses to prevent the logic for "normal" addresses from running on them, which would cause errors and crashes. For instance, in cidr_mask, shifting a 32-bit integer by 32 bits (in the case of a /0 address) causes undefined behavior, so instead a check for prefix == 0 is done, and 0 is explicitly returned. 

The table finds the longest prefix by by choosing the route that matches the destination IP and has the largest cidr prefix length. This can be done regardless of the order of the table because take_lookup() scans every possible route and remembers the matching route with the greatest prefix length. As it iterates, the current best matching route will be compared to the current table entry, and if the current entry is a greater match, then it becomes the new best matching route. 
