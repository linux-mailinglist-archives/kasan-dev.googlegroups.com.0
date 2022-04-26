Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWWDUCJQMGQEKUAEY4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B8A8510428
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:46:19 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id b16-20020a056512305000b00471effe87f9sf4663390lfb.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:46:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991578; cv=pass;
        d=google.com; s=arc-20160816;
        b=XBUvKnUXDowrxpyvcYCqRMLbfbpn4dc/yrWHfJmdCn6j5Lzsiu5um9S7xdCyGr6aWp
         KYQDAg10kAwpGCL62xcfZqFEoLjRtMRfn26K/wyaqzxYL7SnOyU7WWv46EVql1WF/1xZ
         XiTP1XWjlgNaFjNnQvg5Dh+ypU019eCeKjBnwDcozgLBx97RAPCZStqImhf/3gSemivb
         BfQES1UJahPUYZTLXsdnT4lHx+AvJQ6BosnSXWwDaRvHRwI0Pul/0RWh4h2m937XeYhd
         6WX5ObEdVFPjcUAiy/7eDCc26Z+rHiXSzYllIX5MUKnUMPAoiqLuu0MuJuVUiER5gnJy
         ngEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=koQEVCRleeaNlshsPE2M+r62HHElxTiHF5+p85q79rc=;
        b=uu5VTvk2RWaczKUi8eGhv7aR1oCoMI6pWrYqEAFKVSRYWK7NeUp2XuR0172p6DJbdc
         54FH0Lf4uSjKfv9mEzkX34nZr7ju62OFBXJvp0M84hsLkVAnW1QQAwN0WtzTSR+1YFkV
         IhM0pqXstGo8TBexbpGCWYJfy9PitP0pCqmvZWH9sJOJ8QyjC/tqY7YZNLM7UbThUcwP
         e9Ixq9O4IB3qIwuWOXM4nguLCLyNGE5c+D6SQuFcmLBBdN8ytykmtvpHQoqT699KwPnC
         8OPKf/B37lNSximLtOIaMUWbvTVdXqu0wcy+Yy2VPdDEPYgDJF7Wq+m9iIgPMB7QNWSK
         Ed0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="q/8YNmW2";
       spf=pass (google.com: domain of 32sfoygykcdy8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=32SFoYgYKCdY8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=koQEVCRleeaNlshsPE2M+r62HHElxTiHF5+p85q79rc=;
        b=geBERF0rpFnOn+GcijSTX7K531EqW6bdpvXHwurkgPAWIhptZhfG7sunyNh2PfRdq/
         tR0tQFBzYmTnlbkOIABSpk67SiH9WDFCZqM6jIjWl+Cbydx8cMtvnIQ0kC9sR7ViiuzQ
         G3LC0U6okZlMtK4GQGOeAYKAIj+ywzonhOokwE6nhLvgaxnPXD0iAbey0tcSmUIvetB0
         DsMuttg/LYk7n1dGwfvUQn9XC8bx0VabXSRZQi3gFR1f7InBJ3gzx7KQ3cXlYR1oSoW9
         0ThqQozuX/WGFsmCxVIO3pjJNYzqOEhRca+sQoEwvQx8etc80pjsH/2LFVi1P9D6BfCN
         jkAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=koQEVCRleeaNlshsPE2M+r62HHElxTiHF5+p85q79rc=;
        b=M7VTIWxoRLah/+P9r43nDv/CTFgHFSWjRxDx7t1P2N2PFvmtLsgR83uE7UPjBoXH6T
         d42NMO/4dIGtwbAT45W2jPxP7xRMYg9FCR3bd7qwoRjc4d8sQWoQdzAe6+Ld2R6cXWK/
         hiiIdjAfeSJZjXI3vRCDydT2lZntVBt+KbnXghPYY+dqy/SL3jeLIeWgnL0IekKqyn6n
         n/7wtcStT/aUqwMDdxgird8BhvwBCf/MSduChmNm0BaOHhCtJwT9bEdB52/ymb0qZ3FI
         kW0sq6TDCI66EA4V5igALeqp/xLPINjPyFpP3ZRmgZaz3yBqAzaIXoBDZYVBJ2G+Xlms
         h9Zg==
X-Gm-Message-State: AOAM532uz2Cw5I9u3k03dJPIwaKpJ6DuYdKEP6ERoxHgO+h/37ECITvR
	byXDvYwqevOmI/Estuge+m8=
X-Google-Smtp-Source: ABdhPJyhBmWN8MkgUgEac3oi/Jv9Fw5nbK/FdRsC9YXZVPx3aXTdq0HjCsxMXo9GxrK3ah8dTUtUSw==
X-Received: by 2002:a05:6512:32c2:b0:471:9030:8065 with SMTP id f2-20020a05651232c200b0047190308065mr17211443lfg.417.1650991578698;
        Tue, 26 Apr 2022 09:46:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1507:b0:24f:25b5:39ce with SMTP id
 e7-20020a05651c150700b0024f25b539cels199670ljf.6.gmail; Tue, 26 Apr 2022
 09:46:17 -0700 (PDT)
X-Received: by 2002:a2e:9e8d:0:b0:24b:5af4:3feb with SMTP id f13-20020a2e9e8d000000b0024b5af43febmr14996104ljk.257.1650991577555;
        Tue, 26 Apr 2022 09:46:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991577; cv=none;
        d=google.com; s=arc-20160816;
        b=pSQeUMdYefF6qr/h2v5bJ1OaG1M0tErdjn2GQlbhFglSAFFbF+COZ+8T+MkdEe8scX
         3njpX3G+shdW7GtGbsJCxXSzwdU0NQFoWF5amaI6p/kt1X/M25l1ycXOHawMQa70irN/
         oVd0CnS2hr25dbnxG+gz8bwWtw87IVBQttNckzoHbSYqbbKy6wBsDZoBeoqFkjvEDIkj
         Dgjzb/lBQ3Nz0k9VdmGZcfVW8cbUylZnTbbIkG7ex/UBxS8+a0pVGEq+6k/Iav2Mxybo
         o+/i1Fby1oASHM1unW09L5mYqxuFT2NMx84G8TMBT5O/3ziW+cvphD1fUf3Ca8PAQDAB
         kfYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Jk0NMFQ+GIouP+k3atOjYdUnEj7isi+T1qF4OKInEvY=;
        b=q1EJF29lTU5kyuPDX1B0wfOZkENocev8SLdypVvuTd3ZgoqD/xRH92Lb6xdEua+kSq
         eAx7EsnIZV/HTKZ3C4FQOgZy8QJVp1ntuZhtEUdbcp07ezubGNJ6om69uh6IYpC0Bfpt
         6sLcBQTWzCEVaTPfPZJIPQNKKlHRBnv/PkUQ6KwjA2hhiwh+Y7ALWRy0WWk9HXJO1o02
         yMcplco6/SAC6k8iiWroXJm8YwBaE1ZY9p46aB9BQS6tFH7a3shx5iW6yA7e74CMS49y
         7I8w0cY63M4+uQGq9c4nDyo8uEZdNEb5tNDShIWgzdrVq3aJuprOs8ChCJE+F6a/QF2A
         mKtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="q/8YNmW2";
       spf=pass (google.com: domain of 32sfoygykcdy8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=32SFoYgYKCdY8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id h20-20020a2e3a14000000b0024f1cf9b1b0si103038lja.4.2022.04.26.09.46.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:46:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32sfoygykcdy8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id sh14-20020a1709076e8e00b006f3b7adb9ffso1015274ejc.16
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:46:17 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:330b:b0:425:eded:7cfe with SMTP id
 e11-20020a056402330b00b00425eded7cfemr10281416eda.357.1650991577116; Tue, 26
 Apr 2022 09:46:17 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:43:14 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-46-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 45/46] x86: kmsan: handle register passing from
 uninstrumented code
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="q/8YNmW2";       spf=pass
 (google.com: domain of 32sfoygykcdy8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=32SFoYgYKCdY8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Replace instrumentation_begin() with instrumentation_begin_with_regs()
to let KMSAN handle the non-instrumented code and unpoison pt_regs
passed from the instrumented part. This is done to reduce the number of
false positive reports.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 -- this patch was previously called "x86: kmsan: handle register
    passing from uninstrumented code". Instead of adding KMSAN-specific
    code to every instrumentation_begin()/instrumentation_end() section,
    we changed instrumentation_begin() to
    instrumentation_begin_with_regs() where applicable.

Link: https://linux-review.googlesource.com/id/I435ec076cd21752c2f877f5da81f5eced62a2ea4
---
 arch/x86/entry/common.c         |  3 ++-
 arch/x86/include/asm/idtentry.h | 10 +++++-----
 arch/x86/kernel/cpu/mce/core.c  |  2 +-
 arch/x86/kernel/kvm.c           |  2 +-
 arch/x86/kernel/nmi.c           |  2 +-
 arch/x86/kernel/sev.c           |  4 ++--
 arch/x86/kernel/traps.c         | 14 +++++++-------
 arch/x86/mm/fault.c             |  2 +-
 8 files changed, 20 insertions(+), 19 deletions(-)

diff --git a/arch/x86/entry/common.c b/arch/x86/entry/common.c
index 6c2826417b337..047d157987859 100644
--- a/arch/x86/entry/common.c
+++ b/arch/x86/entry/common.c
@@ -14,6 +14,7 @@
 #include <linux/mm.h>
 #include <linux/smp.h>
 #include <linux/errno.h>
+#include <linux/kmsan.h>
 #include <linux/ptrace.h>
 #include <linux/export.h>
 #include <linux/nospec.h>
@@ -75,7 +76,7 @@ __visible noinstr void do_syscall_64(struct pt_regs *regs, int nr)
 	add_random_kstack_offset();
 	nr = syscall_enter_from_user_mode(regs, nr);
 
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 
 	if (!do_syscall_x64(regs, nr) && !do_syscall_x32(regs, nr) && nr != -1) {
 		/* Invalid system call, but still a system call. */
diff --git a/arch/x86/include/asm/idtentry.h b/arch/x86/include/asm/idtentry.h
index 7924f27f5c8b1..172b9b6f90628 100644
--- a/arch/x86/include/asm/idtentry.h
+++ b/arch/x86/include/asm/idtentry.h
@@ -53,7 +53,7 @@ __visible noinstr void func(struct pt_regs *regs)			\
 {									\
 	irqentry_state_t state = irqentry_enter(regs);			\
 									\
-	instrumentation_begin();					\
+	instrumentation_begin_with_regs(regs);				\
 	__##func (regs);						\
 	instrumentation_end();						\
 	irqentry_exit(regs, state);					\
@@ -100,7 +100,7 @@ __visible noinstr void func(struct pt_regs *regs,			\
 {									\
 	irqentry_state_t state = irqentry_enter(regs);			\
 									\
-	instrumentation_begin();					\
+	instrumentation_begin_with_regs(regs);				\
 	__##func (regs, error_code);					\
 	instrumentation_end();						\
 	irqentry_exit(regs, state);					\
@@ -197,7 +197,7 @@ __visible noinstr void func(struct pt_regs *regs,			\
 	irqentry_state_t state = irqentry_enter(regs);			\
 	u32 vector = (u32)(u8)error_code;				\
 									\
-	instrumentation_begin();					\
+	instrumentation_begin_with_regs(regs);				\
 	kvm_set_cpu_l1tf_flush_l1d();					\
 	run_irq_on_irqstack_cond(__##func, regs, vector);		\
 	instrumentation_end();						\
@@ -237,7 +237,7 @@ __visible noinstr void func(struct pt_regs *regs)			\
 {									\
 	irqentry_state_t state = irqentry_enter(regs);			\
 									\
-	instrumentation_begin();					\
+	instrumentation_begin_with_regs(regs);				\
 	kvm_set_cpu_l1tf_flush_l1d();					\
 	run_sysvec_on_irqstack_cond(__##func, regs);			\
 	instrumentation_end();						\
@@ -264,7 +264,7 @@ __visible noinstr void func(struct pt_regs *regs)			\
 {									\
 	irqentry_state_t state = irqentry_enter(regs);			\
 									\
-	instrumentation_begin();					\
+	instrumentation_begin_with_regs(regs);				\
 	__irq_enter_raw();						\
 	kvm_set_cpu_l1tf_flush_l1d();					\
 	__##func (regs);						\
diff --git a/arch/x86/kernel/cpu/mce/core.c b/arch/x86/kernel/cpu/mce/core.c
index 981496e6bc0e4..e5acff54f7d55 100644
--- a/arch/x86/kernel/cpu/mce/core.c
+++ b/arch/x86/kernel/cpu/mce/core.c
@@ -1376,7 +1376,7 @@ static void queue_task_work(struct mce *m, char *msg, void (*func)(struct callba
 /* Handle unconfigured int18 (should never happen) */
 static noinstr void unexpected_machine_check(struct pt_regs *regs)
 {
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 	pr_err("CPU#%d: Unexpected int18 (Machine Check)\n",
 	       smp_processor_id());
 	instrumentation_end();
diff --git a/arch/x86/kernel/kvm.c b/arch/x86/kernel/kvm.c
index 8b1c45c9cda87..3df82a51ab1b5 100644
--- a/arch/x86/kernel/kvm.c
+++ b/arch/x86/kernel/kvm.c
@@ -250,7 +250,7 @@ noinstr bool __kvm_handle_async_pf(struct pt_regs *regs, u32 token)
 		return false;
 
 	state = irqentry_enter(regs);
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 
 	/*
 	 * If the host managed to inject an async #PF into an interrupt
diff --git a/arch/x86/kernel/nmi.c b/arch/x86/kernel/nmi.c
index e73f7df362f5d..5078417e16ec1 100644
--- a/arch/x86/kernel/nmi.c
+++ b/arch/x86/kernel/nmi.c
@@ -328,7 +328,7 @@ static noinstr void default_do_nmi(struct pt_regs *regs)
 
 	__this_cpu_write(last_nmi_rip, regs->ip);
 
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 
 	handled = nmi_handle(NMI_LOCAL, regs);
 	__this_cpu_add(nmi_stats.normal, handled);
diff --git a/arch/x86/kernel/sev.c b/arch/x86/kernel/sev.c
index e6d316a01fdd4..9bfc29fc9c983 100644
--- a/arch/x86/kernel/sev.c
+++ b/arch/x86/kernel/sev.c
@@ -1330,7 +1330,7 @@ DEFINE_IDTENTRY_VC_KERNEL(exc_vmm_communication)
 
 	irq_state = irqentry_nmi_enter(regs);
 
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 
 	if (!vc_raw_handle_exception(regs, error_code)) {
 		/* Show some debug info */
@@ -1362,7 +1362,7 @@ DEFINE_IDTENTRY_VC_USER(exc_vmm_communication)
 	}
 
 	irqentry_enter_from_user_mode(regs);
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 
 	if (!vc_raw_handle_exception(regs, error_code)) {
 		/*
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 1563fb9950059..9d3c9c4de94d3 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -305,7 +305,7 @@ static noinstr bool handle_bug(struct pt_regs *regs)
 	/*
 	 * All lies, just get the WARN/BUG out.
 	 */
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 	/*
 	 * Since we're emulating a CALL with exceptions, restore the interrupt
 	 * state to what it was at the exception site.
@@ -336,7 +336,7 @@ DEFINE_IDTENTRY_RAW(exc_invalid_op)
 		return;
 
 	state = irqentry_enter(regs);
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 	handle_invalid_op(regs);
 	instrumentation_end();
 	irqentry_exit(regs, state);
@@ -490,7 +490,7 @@ DEFINE_IDTENTRY_DF(exc_double_fault)
 #endif
 
 	irqentry_nmi_enter(regs);
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 	notify_die(DIE_TRAP, str, regs, error_code, X86_TRAP_DF, SIGSEGV);
 
 	tsk->thread.error_code = error_code;
@@ -820,14 +820,14 @@ DEFINE_IDTENTRY_RAW(exc_int3)
 	 */
 	if (user_mode(regs)) {
 		irqentry_enter_from_user_mode(regs);
-		instrumentation_begin();
+		instrumentation_begin_with_regs(regs);
 		do_int3_user(regs);
 		instrumentation_end();
 		irqentry_exit_to_user_mode(regs);
 	} else {
 		irqentry_state_t irq_state = irqentry_nmi_enter(regs);
 
-		instrumentation_begin();
+		instrumentation_begin_with_regs(regs);
 		if (!do_int3(regs))
 			die("int3", regs, 0);
 		instrumentation_end();
@@ -1026,7 +1026,7 @@ static __always_inline void exc_debug_kernel(struct pt_regs *regs,
 	 */
 	unsigned long dr7 = local_db_save();
 	irqentry_state_t irq_state = irqentry_nmi_enter(regs);
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 
 	/*
 	 * If something gets miswired and we end up here for a user mode
@@ -1105,7 +1105,7 @@ static __always_inline void exc_debug_user(struct pt_regs *regs,
 	 */
 
 	irqentry_enter_from_user_mode(regs);
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 
 	/*
 	 * Start the virtual/ptrace DR6 value with just the DR_STEP mask
diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
index f2250a32a10ca..676e394f1af5b 100644
--- a/arch/x86/mm/fault.c
+++ b/arch/x86/mm/fault.c
@@ -1557,7 +1557,7 @@ DEFINE_IDTENTRY_RAW_ERRORCODE(exc_page_fault)
 	 */
 	state = irqentry_enter(regs);
 
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 	handle_page_fault(regs, error_code, address);
 	instrumentation_end();
 
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-46-glider%40google.com.
