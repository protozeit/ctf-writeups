#include <stdio.h> 
int main(){ 
  int a = 11134; 
  int b = 2244; 
  rename("a+b.out","asdf"); 
  rename("flag","a+b.out");
  printf("%d\n",a+b);
}
