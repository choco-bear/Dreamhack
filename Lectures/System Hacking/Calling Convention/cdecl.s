	.file	"cdecl.c"
	.intel_syntax noprefix
	.text
	.globl	callee
	.type	callee, @function
callee:
	nop
	ret
	.size	callee, .-callee
	.globl	caller
	.type	caller, @function
caller:
	push	2
	push	1
	call	callee
	add	esp, 8
	nop
	ret
	.size	caller, .-caller
	.ident	"GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0"
	.section	.note.GNU-stack,"",@progbits
