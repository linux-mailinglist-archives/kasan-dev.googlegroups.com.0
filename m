Return-Path: <kasan-dev+bncBAABBMH35SIQMGQEIGPLUQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id A436B4E554B
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 16:33:04 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id 15-20020adf808f000000b00203e488fa4esf633439wrl.3
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 08:33:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648049584; cv=pass;
        d=google.com; s=arc-20160816;
        b=FX2yXzUK1+kJgle0qXpChT5Op7RS1m6HbglbY0e7YVDBOl9kkAo5OrAguBNyFSLzMR
         B+WcV+qooBq6ehmzDSu5+ojg0fpH8H5ewjTI8ELIQglMnI8yZKMAlYWcYJruREzyjj2N
         79aoAXhgcbPlecKW1N6yT4o+eANvUR3Fj+J3kJUGa0JPUo+wph/A9NNvrTfoWnAubMux
         UGMcVwfSYsz5YdiAX81rdlG38J0SujRE8VUVUKfUZAkqHcL+Gi6iT0JZ0TDiOlKU2Sqa
         w5oQfGJBP35TV1kLtXraf9EfC3xIgIhjyUBjBNB5rwhZJ1iN4QaGuWpooSfslHeOt9NX
         UFjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TPekI61Chy6EKV6wWg5aF6WVEempFU+Y6IL3ervQIBA=;
        b=bCK4wyknTyrl5c8p1iEgmUA9111Z5Xp5nx9JljE1LbiR3AbEEoS+nkyXW6nFLe2w0v
         T15jSJPvMFCPwe6aE2bJFGaEUbyQZo2ULtrzb6ES1WLZUvuk2yqrwU6/9uetQhv38ATG
         dWMENH/4e1pwFgKht0a36Y/XCiSfjGWZIY7SUdKtTPPudZX2VkboKGXcpzxDiretYxXN
         6LRJD5Zi5svKzRIENT0ox7H/wU43EGk4El53LiI73Nr1XOqCaetgRBapRuh1kLvmI1Ye
         xKvz7d7+f9biUuT+fljdC8EMzwzacNWIcJQ5LPb3WP28AOdUs7oKhDmYFELP1fWUwsqi
         P5tQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=EQv2T55i;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TPekI61Chy6EKV6wWg5aF6WVEempFU+Y6IL3ervQIBA=;
        b=X9XT4ydthXkTN9RaIT7ibNTgY5ZPdCTNSCMNVYXZyStmALNRSj1cgWqfSOGvp9X/L8
         uQtD5spLq9vCk67PkucCv8QAGPcGZANlDSvo7Ucjl64iTtNitFj75S7CfqQ/6zoybF0h
         qTcPn0Csckrx4s/h/sC6BpeuRKnfolZ5QB39felhYWEMygvS+mNgsCUAVyDgbl8ehbxS
         k7OJr4u17Xssi0ZMvzWREWO4R1oC5LIegaLt8Pd4Y9omlPiLLmTW9G+twawuelYYXNI3
         gJ4xvJGEKGvuzJ3Ta5xwYEwyjSPT6mTnFAJTCK36uO1kiMLfpNBSLNPxeCl5+R1L9DRw
         yF4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TPekI61Chy6EKV6wWg5aF6WVEempFU+Y6IL3ervQIBA=;
        b=vyvP50RXXfS11nRbnj4la71jep/LMLs+7VC2qAg2ezSqJmCu1/SF+JDCoUU9QjvRmJ
         XNds6ejfWyK5WH4FqLmrVsdTYGgebAtRix+rloKrtf4kNi1cltMvGmZx+AIJpsiTAmw/
         rIUqGmGyR5YyV6373Q3Ua1wEvynW4K/15tJXCOkZNfEvHBkivwFA5t0F+zjB1xpC9b2V
         RGEBzwockEgbY57zia0wSoh6NgE4Cz1Gp/cMc1U5SmHGKqc60oppBaaL25KC2VEd7xnF
         mmtr4cr/Hy/asV+QRQqTTnPIlr36jkrX6ufsHIFdOuw8wE6p8L0sK/VVMr3zal/1YMkH
         xCFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533SUgMB7mWyoGRTCWvkx0ly5KWw6vbVeykdhsLtgP1dZPjCG59Z
	VPRmRqLnn9v5TwPTK+7qyys=
X-Google-Smtp-Source: ABdhPJw3PgzDnG4OggkPZo3NFKz395jssHAaXKccxNR062BbGuoNIpeQqXoWEmRs9ADLVSCZXdI7pg==
X-Received: by 2002:a05:6000:144d:b0:205:8905:4cc1 with SMTP id v13-20020a056000144d00b0020589054cc1mr375398wrx.508.1648049584376;
        Wed, 23 Mar 2022 08:33:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6d8d:0:b0:203:dadb:4a0c with SMTP id l13-20020a5d6d8d000000b00203dadb4a0cls76425wrs.1.gmail;
 Wed, 23 Mar 2022 08:33:03 -0700 (PDT)
X-Received: by 2002:a05:6000:1541:b0:204:18f1:f6b5 with SMTP id 1-20020a056000154100b0020418f1f6b5mr333804wry.485.1648049583635;
        Wed, 23 Mar 2022 08:33:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648049583; cv=none;
        d=google.com; s=arc-20160816;
        b=NhOql/uI0WMNNon21Wyy1q0hJOWMLWcUXbxFLpzEP/fM76BMUhC/Sj6YC+kCJ3Us/U
         yDhCYmIlYxxHK+WTsQypiNIY414XMWKpsRAKn5L4jI29SCeP7Q/LEoSegxoSUqKVxM3S
         wyEZJG1JeDH1SxCbo6KslEUSv+FpAiO5lsR2f19HJ2p5Ckc/9XVg24TMRs0EuD++4rka
         46N3rQrvd32+pEw6Wt2JUYMfZctEOxUdeOYG15l1B4rB+BbgK++F5JDmqq1PHrXNCmro
         /vxmF50D5MinHMPNLZXVGJ2HX1J2c8vwMF4e+aSbZh7Eim5JztN4X54BT4pCbjfhnbmK
         MTMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=T6yJKZfG38tzu4tVtlVcnWPw3LrS2FpvC9JjJySIrEg=;
        b=GL63aYIwwsAwe0VmqGTAMcCDLCv18qfNP8VuksIexCdtATgIMTTtugNPbICL0mNERz
         RH6UfFty0aMYidfRvZjPbQCzAXqekNnAPSHPCQIxUgEMf6GpBP7djLdtL88L4u4WuQLX
         Zq3gC5iApiiyNjxxzDZTSdwRjDh9eb1U+4jdXhs4PBxugELN8FoQth2oHyRpjorDXOFh
         nDl6GB+6VrEVLatgh5OenGTU+I7IryPunXjYqYRMjWPJY+gjkiU3cD8ufpyfat6NnET3
         uSddef9vnRnlT94lg7mTH5+FRPUAcjeyL10pA86HYlzzwwXGWHL98dbfGGSSQonB8g6W
         ADeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=EQv2T55i;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id bg3-20020a05600c3c8300b0037e391f947bsi528031wmb.4.2022.03.23.08.33.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 23 Mar 2022 08:33:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Mark Rutland <mark.rutland@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 2/4] arm64, scs: save scs_sp values per-cpu when switching stacks
Date: Wed, 23 Mar 2022 16:32:53 +0100
Message-Id: <f75c58b17bfaa419f84286cd174e3a08f971b779.1648049113.git.andreyknvl@google.com>
In-Reply-To: <cover.1648049113.git.andreyknvl@google.com>
References: <cover.1648049113.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=EQv2T55i;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

From: Andrey Konovalov <andreyknvl@google.com>

When an interrupt happens, the current Shadow Call Stack (SCS) pointer
is switched to a per-interrupt one stored in a per-CPU variable. The old
pointer is then saved on the normal stack and restored when the interrupt
is handled.

To collect the current stack trace based on SCS when the interrupt is
being handled, we need to know the SCS pointers that belonged to the
task and potentially other interrupts that were interrupted.

Instead of trying to retrieve the SCS pointers from the stack, change
interrupt handlers (for hard IRQ, Normal and Critical SDEI) to save the
previous SCS pointer in a per-CPU variable.

Note that interrupts stack. A task can be interrupted by a hard IRQ,
which then can interrupted by a normal SDEI, etc. This is handled by
using a separate per-CPU variable for each interrupt type.

Also reset the saved SCS pointer when exiting the interrupt. This allows
checking whether we should include any interrupt frames when collecting
the stack trace. While we could use in_hardirq(), there seems to be no
easy way to check whether we are in an SDEI handler. Directly checking
the per-CPU variables for being non-zero is more resilient.

Also expose both the the added saved SCS variables and the existing SCS
base variables in arch/arm64/include/asm/scs.h so that the stack trace
collection impementation can use them.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/include/asm/assembler.h | 12 ++++++++++++
 arch/arm64/include/asm/scs.h       | 13 ++++++++++++-
 arch/arm64/kernel/entry.S          | 28 ++++++++++++++++++++++++----
 arch/arm64/kernel/irq.c            |  4 +---
 arch/arm64/kernel/sdei.c           |  5 ++---
 5 files changed, 51 insertions(+), 11 deletions(-)

diff --git a/arch/arm64/include/asm/assembler.h b/arch/arm64/include/asm/assembler.h
index 8c5a61aeaf8e..ca018e981d13 100644
--- a/arch/arm64/include/asm/assembler.h
+++ b/arch/arm64/include/asm/assembler.h
@@ -270,6 +270,18 @@ alternative_endif
 	ldr	\dst, [\dst, \tmp]
 	.endm
 
+	/*
+	 * @src: Register whose value gets stored in sym
+	 * @sym: The name of the per-cpu variable
+	 * @tmp0: Scratch register
+	 * @tmp1: Another scratch register
+	 */
+	.macro str_this_cpu src, sym, tmp0, tmp1
+	adr_l	\tmp0, \sym
+	get_this_cpu_offset \tmp1
+	str	\src, [\tmp0, \tmp1]
+	.endm
+
 /*
  * vma_vm_mm - get mm pointer from vma pointer (vma->vm_mm)
  */
diff --git a/arch/arm64/include/asm/scs.h b/arch/arm64/include/asm/scs.h
index 8297bccf0784..2bb2b32f787b 100644
--- a/arch/arm64/include/asm/scs.h
+++ b/arch/arm64/include/asm/scs.h
@@ -24,6 +24,17 @@
 	.endm
 #endif /* CONFIG_SHADOW_CALL_STACK */
 
-#endif /* __ASSEMBLY __ */
+#else /* __ASSEMBLY__ */
+
+#include <linux/percpu.h>
+
+DECLARE_PER_CPU(unsigned long *, irq_shadow_call_stack_ptr);
+DECLARE_PER_CPU(unsigned long *, irq_shadow_call_stack_saved_ptr);
+DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_ptr);
+DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_saved_ptr);
+DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_ptr);
+DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_saved_ptr);
+
+#endif /* __ASSEMBLY__ */
 
 #endif /* _ASM_SCS_H */
diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
index ede028dee81b..1c62fecda172 100644
--- a/arch/arm64/kernel/entry.S
+++ b/arch/arm64/kernel/entry.S
@@ -880,7 +880,8 @@ NOKPROBE(ret_from_fork)
  */
 SYM_FUNC_START(call_on_irq_stack)
 #ifdef CONFIG_SHADOW_CALL_STACK
-	stp	scs_sp, xzr, [sp, #-16]!
+	/* Save the current SCS pointer and load the per-IRQ one. */
+	str_this_cpu scs_sp, irq_shadow_call_stack_saved_ptr, x15, x17
 	ldr_this_cpu scs_sp, irq_shadow_call_stack_ptr, x17
 #endif
 	/* Create a frame record to save our LR and SP (implicit in FP) */
@@ -902,7 +903,9 @@ SYM_FUNC_START(call_on_irq_stack)
 	mov	sp, x29
 	ldp	x29, x30, [sp], #16
 #ifdef CONFIG_SHADOW_CALL_STACK
-	ldp	scs_sp, xzr, [sp], #16
+	/* Restore saved SCS pointer and reset the saved value. */
+	ldr_this_cpu scs_sp, irq_shadow_call_stack_saved_ptr, x17
+	str_this_cpu xzr, irq_shadow_call_stack_saved_ptr, x15, x17
 #endif
 	ret
 SYM_FUNC_END(call_on_irq_stack)
@@ -1024,11 +1027,16 @@ SYM_CODE_START(__sdei_asm_handler)
 #endif
 
 #ifdef CONFIG_SHADOW_CALL_STACK
-	/* Use a separate shadow call stack for normal and critical events */
+	/*
+	 * Use a separate shadow call stack for normal and critical events.
+	 * Save the current SCS pointer and load the per-SDEI one.
+	 */
 	cbnz	w4, 3f
+	str_this_cpu src=scs_sp, sym=sdei_shadow_call_stack_normal_saved_ptr, tmp0=x5, tmp1=x6
 	ldr_this_cpu dst=scs_sp, sym=sdei_shadow_call_stack_normal_ptr, tmp=x6
 	b	4f
-3:	ldr_this_cpu dst=scs_sp, sym=sdei_shadow_call_stack_critical_ptr, tmp=x6
+3:	str_this_cpu src=scs_sp, sym=sdei_shadow_call_stack_critical_saved_ptr, tmp0=x5, tmp1=x6
+	ldr_this_cpu dst=scs_sp, sym=sdei_shadow_call_stack_critical_ptr, tmp=x6
 4:
 #endif
 
@@ -1062,6 +1070,18 @@ SYM_CODE_START(__sdei_asm_handler)
 	ldp	lr, x1, [x4, #SDEI_EVENT_INTREGS + S_LR]
 	mov	sp, x1
 
+#ifdef CONFIG_SHADOW_CALL_STACK
+	/* Restore saved SCS pointer and reset the saved value. */
+	ldrb	w5, [x4, #SDEI_EVENT_PRIORITY]
+	cbnz	w5, 5f
+	ldr_this_cpu dst=scs_sp, sym=sdei_shadow_call_stack_normal_saved_ptr, tmp=x6
+	str_this_cpu src=xzr, sym=sdei_shadow_call_stack_normal_saved_ptr, tmp0=x5, tmp1=x6
+	b	6f
+5:	ldr_this_cpu dst=scs_sp, sym=sdei_shadow_call_stack_critical_saved_ptr, tmp=x6
+	str_this_cpu src=xzr, sym=sdei_shadow_call_stack_critical_saved_ptr, tmp0=x5, tmp1=x6
+6:
+#endif
+
 	mov	x1, x0			// address to complete_and_resume
 	/* x0 = (x0 <= SDEI_EV_FAILED) ?
 	 * EVENT_COMPLETE:EVENT_COMPLETE_AND_RESUME
diff --git a/arch/arm64/kernel/irq.c b/arch/arm64/kernel/irq.c
index bda49430c9ea..4199f900714a 100644
--- a/arch/arm64/kernel/irq.c
+++ b/arch/arm64/kernel/irq.c
@@ -28,11 +28,9 @@ DEFINE_PER_CPU(struct nmi_ctx, nmi_contexts);
 
 DEFINE_PER_CPU(unsigned long *, irq_stack_ptr);
 
-
-DECLARE_PER_CPU(unsigned long *, irq_shadow_call_stack_ptr);
-
 #ifdef CONFIG_SHADOW_CALL_STACK
 DEFINE_PER_CPU(unsigned long *, irq_shadow_call_stack_ptr);
+DEFINE_PER_CPU(unsigned long *, irq_shadow_call_stack_saved_ptr);
 #endif
 
 static void init_irq_scs(void)
diff --git a/arch/arm64/kernel/sdei.c b/arch/arm64/kernel/sdei.c
index d20620a1c51a..269adcb9e854 100644
--- a/arch/arm64/kernel/sdei.c
+++ b/arch/arm64/kernel/sdei.c
@@ -39,12 +39,11 @@ DEFINE_PER_CPU(unsigned long *, sdei_stack_normal_ptr);
 DEFINE_PER_CPU(unsigned long *, sdei_stack_critical_ptr);
 #endif
 
-DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_ptr);
-DECLARE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_ptr);
-
 #ifdef CONFIG_SHADOW_CALL_STACK
 DEFINE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_ptr);
+DEFINE_PER_CPU(unsigned long *, sdei_shadow_call_stack_normal_saved_ptr);
 DEFINE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_ptr);
+DEFINE_PER_CPU(unsigned long *, sdei_shadow_call_stack_critical_saved_ptr);
 #endif
 
 static void _free_sdei_stack(unsigned long * __percpu *ptr, int cpu)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f75c58b17bfaa419f84286cd174e3a08f971b779.1648049113.git.andreyknvl%40google.com.
