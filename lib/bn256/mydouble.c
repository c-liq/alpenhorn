/*
 * File:   dclxvi-20130329/mydouble.c
 * Author: Ruben Niederhagen, Peter Schwabe
 * Public Domain
 */

#include "mydouble.h"

#include <math.h>

double remround(double a, double d)
{
	double carry = round(a / d);
	return a - carry * d;
}

