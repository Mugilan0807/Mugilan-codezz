#include <stdio.h>
#include <math.h>
//simple calculator

int main() {
    int number1;
    int number2;
    char operator;
    int result;

    printf("ENTER A NUMBER:");
    scanf("%d", &number1);

    printf("ENTER ANOTHER NUMBER:");
    scanf("%d", &number2);

    printf("ENTER THE OPERATOR FOR THE CALCULATION TO BE PERFORMED('+','-','*','/'):");
    scanf(" %c", &operator);

    if(number2 == 0){
        printf("division by zero is not possible");
    }


    switch(operator){
        case '+':
            result = number1 + number2;
            printf("The Result is: %d", result);
            break;
        case '-':
            result = number1 - number2;
            printf("The Result is: %d", result);
            break;
        case '*':
            result = number1 * number2;
            printf("The Result is: %d", result);
            break;
        case '/':
            result = number1 / number2;
            printf("The Result is: %d", result);
            break;
        default:
            printf("invalid operator");
            break;
    }
    return 0;

}