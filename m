Return-Path: <kasan-dev+bncBAABBMP35SIQMGQEWV27LKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3016C4E554C
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 16:33:06 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id n9-20020a2e82c9000000b002435af2e8b9sf716552ljh.20
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Mar 2022 08:33:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648049585; cv=pass;
        d=google.com; s=arc-20160816;
        b=fx6+GbdRcpbRX7zVMQGg7w/1Iu56jBgVXtO/AmBdDT3/kZarhaI49Rvcm7tjGfxVAx
         iggr2U66L8VqAZ2LSZ2NZveRAZtOEKtGqU4cFBBDFahVq8Y2xm4pjr7516F1qN60Ywm0
         CZZl09o+E+jZBUpYRKOo7hLm7hmBAz3/bfRq0HaoEwm2oThphgB5txDPtJJBbzc886gc
         stXtO00Y3I1Qej11XO/GnynZFSY/OVETk9gUy7rPt050osqB7BTDLUyKXJidrXK3S+Vl
         +NBQkiLzFCotiuzmjp439gcyFlEpZSdZIwuxjrDy3GdSF3u3wEzyBfPvGCK4fiQER0uz
         P7bA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/bwL+uzbk9c64uK2MxGYD24/O342EJvsd0sf4qIw8Wg=;
        b=RREuXJ8BGkSdjUQXrroHtsNDHb4iW4pzbK0uTJKqw+2n4sYpJJBErb29X+hBkxpM7S
         bTShFyAHVXzl2mUhr0A6yCQMEPA6PSm2KuzkzymCFmMBegxURcsGV6Bow5y/RA2GHVIf
         yLyUDjkwuxNu7xifm8LZjBie3yViLn3K70xN3LzYE9UCiVi8sXFKXubNK2CsGQqI6kSn
         JKPXwniOhWHCjMLyedxftmkK+OEQ9rsmEgIzXxLagJXvG72qvOMzDI0sSpj7tohSVm+O
         XMCj+groeoAwPF2SK0J3x6syXEvfAyYVj7qrOS4qhaUzOZIKbVUswhS5ozUjmSYzF50P
         8pcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="CHABMq/e";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/bwL+uzbk9c64uK2MxGYD24/O342EJvsd0sf4qIw8Wg=;
        b=XVbx1fndK96/uOYFuZci3qihT9432PA5vbVYQIRwgLQeJskUNaF80bwlp4IeyBlzxK
         3/8WnvhQCOC97Ca+yQ3eJTXr8k2eFLskOtqhjjlzAfgVO/MdGwYVvm28GT58XDSp2B4Q
         +PYe5GIrGzpOvMI6+Qhn0BD/uJ2VewJ5CtDgt963MW2ikfh5EU+nTx4zfRUjQHh7lTMQ
         t1v84CpDkXxMBHn4zDuik+L8t3mM8hhj/3dY91GWDJjnhwqwDpoy2Lqmxi1mLoQuZUqm
         1GfwKbgOSeqJRnn5rjMxwAdlqeHndRINYgrrySxYFHOsnGNoR1WRiJc27h7flhFnxpUi
         aQAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/bwL+uzbk9c64uK2MxGYD24/O342EJvsd0sf4qIw8Wg=;
        b=1scpVH3QEGyrEv5eEhlDkx66HHAQzGpK4+TtIXvU3Qm/t4tH0CGBajfVSv5844hf3q
         LUNQ3RaTGI19TA64vt1JMMD2uwrSYqMCVCGxCmghzGSahBSSt0Imeu3ZA6VgXz0kCkUU
         O1AfzJFfTWpnloxx51KHgPDu+j+6+r6iwoVp5gqK7fL7fhUMv/wHgaDuKQV+XHuK7mjL
         t3q20s6VmZBwdsS8Ytk0OvQWuHLyjfObIepb0f54z3NJYqxxpdJS73rl0zkSTYVEC+kh
         jikK0GEW1zEQEtWZ7/uVgJKGi8vpmhvZPtFMOopAG+xmNFWIS9P5YA9G/y2pBsChi0UA
         M7vg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530i205BIVc2LPBR24dMDrAAVPv8nLa/YzaeF91ugrQIQdqEJBQN
	mYZ2nDrGl+zbnC0EC6KY0o4=
X-Google-Smtp-Source: ABdhPJxLkJQEwGSniXYw632nvIPkqPOpTQxd7qFEqNAlIWLt3azUbUvqRqWpe48t2V9ThtzALtWXxg==
X-Received: by 2002:a2e:9c99:0:b0:249:146e:57a9 with SMTP id x25-20020a2e9c99000000b00249146e57a9mr413887lji.319.1648049585615;
        Wed, 23 Mar 2022 08:33:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1241:b0:248:b17:7fcf with SMTP id
 h1-20020a05651c124100b002480b177fcfls4083390ljh.8.gmail; Wed, 23 Mar 2022
 08:33:04 -0700 (PDT)
X-Received: by 2002:a2e:b892:0:b0:249:9ea1:4bf with SMTP id r18-20020a2eb892000000b002499ea104bfmr463171ljp.250.1648049584812;
        Wed, 23 Mar 2022 08:33:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648049584; cv=none;
        d=google.com; s=arc-20160816;
        b=e6rvTOmnOcNHc0zSGffQGWvEbgjDTDg/aTmoCPpyfcwO1K6DQ5h/PKWOFXVaW+ElcT
         Ux4Bh2E+bQvdnh8MBzRMlUq4VscNFklMyqZnHdLXz2zFkmzTZK1w9amI11VMhtchSy1B
         CKSi/tS4To1xYzGRNQOg35vW4L26Sqf1Q2/QW5jf//UmFk8Z7PODsz635k9kb/OjlzsW
         EC6RVgEMk3CiboyIJGkwWz5AHx7H5oep3sViD82uBE3CeSRGMFKrQtGzmWdOootfLBSU
         tKjgR6M+vg8/kCWuX1SZYN8gPK9L77lwH1iEuUfexHhWWrdIPWmFy5GWzx3HBQHUU9Yh
         Fr7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MP8VVStpf2u5pFq9LJYVTfW5maMxRrDNwrS4C/iOhFE=;
        b=F6LxCse3mboe6NkWSB9C/a9RpC/5/JKKRrBXtOjv045NXbGqJH7UD/wQpN039UEsXJ
         cjzqEbWGd7mheVyaGO8MjeAZy35P1nR+2i1LJmfLFrgFECpLtXFRn1423dsp37wU5u4C
         SjIaUGZNLALg91Jaf2q2zhvxSocvaNzxaFeo7oQ0NPxNsOshxAgVX7PwYswoupBFVn5A
         +eP6NnC/HdU42ZZf8uEHABmK664XGyuMCh+zA/6k88GlfiTFQoeJKZPvIwMsOQouZ0Cw
         8/JRSE/b5m4KGzrWQeYJhvI8Q70e04sUAJWFPajZQdaAMpm0mGkh2tG944u9y3W5uhaH
         q2VQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="CHABMq/e";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id p16-20020a2e9ad0000000b00247f6f7df5esi19210ljj.7.2022.03.23.08.33.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 23 Mar 2022 08:33:04 -0700 (PDT)
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
Subject: [PATCH v2 3/4] arm64: implement stack_trace_save_shadow
Date: Wed, 23 Mar 2022 16:32:54 +0100
Message-Id: <0bb72ea8fa88ef9ae3508c23d993952a0ae6f0f9.1648049113.git.andreyknvl@google.com>
In-Reply-To: <cover.1648049113.git.andreyknvl@google.com>
References: <cover.1648049113.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="CHABMq/e";       spf=pass
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

Implement the stack_trace_save_shadow() interface that collects stack
traces based on the Shadow Call Stack (SCS) for arm64.

The implementation walks through available SCS pointers (the per-task one
and the per-interrupt-type ones) and copies the frames.

Note that the frame of the interrupted function is not included into
the stack trace, as it is not yet saved on the SCS when an interrupt
happens.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/Kconfig             |  1 +
 arch/arm64/kernel/stacktrace.c | 83 ++++++++++++++++++++++++++++++++++
 2 files changed, 84 insertions(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index a659e238f196..d89cecf6c923 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -201,6 +201,7 @@ config ARM64
 	select MMU_GATHER_RCU_TABLE_FREE
 	select HAVE_RSEQ
 	select HAVE_RUST
+	select HAVE_SHADOW_STACKTRACE
 	select HAVE_STACKPROTECTOR
 	select HAVE_SYSCALL_TRACEPOINTS
 	select HAVE_KPROBES
diff --git a/arch/arm64/kernel/stacktrace.c b/arch/arm64/kernel/stacktrace.c
index e4103e085681..89daa710d91b 100644
--- a/arch/arm64/kernel/stacktrace.c
+++ b/arch/arm64/kernel/stacktrace.c
@@ -12,9 +12,11 @@
 #include <linux/sched/debug.h>
 #include <linux/sched/task_stack.h>
 #include <linux/stacktrace.h>
+#include <linux/scs.h>
 
 #include <asm/irq.h>
 #include <asm/pointer_auth.h>
+#include <asm/scs.h>
 #include <asm/stack_pointer.h>
 #include <asm/stacktrace.h>
 
@@ -210,3 +212,84 @@ noinline notrace void arch_stack_walk(stack_trace_consume_fn consume_entry,
 
 	walk_stackframe(task, &frame, consume_entry, cookie);
 }
+
+static const struct {
+	unsigned long ** __percpu saved;
+	unsigned long ** __percpu base;
+} scs_parts[] = {
+#ifdef CONFIG_ARM_SDE_INTERFACE
+	{
+		.saved = &sdei_shadow_call_stack_critical_saved_ptr,
+		.base = &sdei_shadow_call_stack_critical_ptr,
+	},
+	{
+		.saved = &sdei_shadow_call_stack_normal_saved_ptr,
+		.base = &sdei_shadow_call_stack_normal_ptr,
+	},
+#endif /* CONFIG_ARM_SDE_INTERFACE */
+	{
+		.saved = &irq_shadow_call_stack_saved_ptr,
+		.base = &irq_shadow_call_stack_ptr,
+	},
+};
+
+static inline bool walk_shadow_stack_part(
+				unsigned long *scs_top, unsigned long *scs_base,
+				unsigned long *store, unsigned int size,
+				unsigned int *skipnr, unsigned int *len)
+{
+	unsigned long *frame;
+
+	for (frame = scs_top; frame >= scs_base; frame--) {
+		if (*skipnr > 0) {
+			(*skipnr)--;
+			continue;
+		}
+		/*
+		 * Do not leak PTR_AUTH tags in stack traces.
+		 * Use READ_ONCE_NOCHECK as SCS is poisoned with Generic KASAN.
+		 */
+		store[(*len)++] =
+			ptrauth_strip_insn_pac(READ_ONCE_NOCHECK(*frame));
+		if (*len >= size)
+			return true;
+	}
+
+	return false;
+}
+
+noinline notrace int arch_stack_walk_shadow(unsigned long *store,
+					    unsigned int size,
+					    unsigned int skipnr)
+{
+	unsigned long *scs_top, *scs_base, *scs_next;
+	unsigned int len = 0, part;
+
+	preempt_disable();
+
+	/* Get the SCS pointer. */
+	asm volatile("mov %0, x18" : "=&r" (scs_top));
+
+	/* The top SCS slot is empty. */
+	scs_top -= 1;
+
+	/* Handle SDEI and hardirq frames. */
+	for (part = 0; part < ARRAY_SIZE(scs_parts); part++) {
+		scs_next = *this_cpu_ptr(scs_parts[part].saved);
+		if (scs_next) {
+			scs_base = *this_cpu_ptr(scs_parts[part].base);
+			if (walk_shadow_stack_part(scs_top, scs_base, store,
+						   size, &skipnr, &len))
+				goto out;
+			scs_top = scs_next;
+		}
+	}
+
+	/* Handle task and softirq frames. */
+	scs_base = task_scs(current);
+	walk_shadow_stack_part(scs_top, scs_base, store, size, &skipnr, &len);
+
+out:
+	preempt_enable();
+	return len;
+}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0bb72ea8fa88ef9ae3508c23d993952a0ae6f0f9.1648049113.git.andreyknvl%40google.com.
