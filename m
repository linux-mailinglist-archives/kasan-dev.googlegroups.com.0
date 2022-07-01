Return-Path: <kasan-dev+bncBCCMH5WKTMGRBR4H7SKQMGQEKSTT25Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 691A9563546
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:25:13 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id m5-20020a170902768500b0016a1c410f6csf1514384pll.13
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:25:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685512; cv=pass;
        d=google.com; s=arc-20160816;
        b=eJ7MEkvRnLxQ5RLxOv7e396IquXq0KM/8SKXQri+1xbMrEJdAlY2HomlRrVfU8wbzQ
         kvLHOiArGtJrNuDBAH1xYT2dUVgT9O9hgiVLBthCkv8SPb6gRI/q9VLFqPsT686zXNw1
         tT8yPUBP8j6dM6RGOkwdhQ+1BXUU1oSMWl4/0sPMax0X2/M/o3iidoxv2A58orcHsLMi
         Duz1OfG17KDdAQBziskoJ8hEI+yzYCL4Se1Ygjp4SGD7bs01p16+uEh2inLI/j2MPox6
         q0p7QBAFb8GCjtJC8Xc5tFvW+btZeRTbKUEk4qHaV9gguMyYjneB2usNSJlAIC7RNIQB
         WmTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=iY0FZwaBe5AEJr/9zlJTuhBZ2q6uWGihPKyx6dFedTM=;
        b=V9ru6F2XwcofEisr/9v63yEjP1mpo7sarXaNdcALThYhf7U0Nqt5xfuP1ai2C7hhTm
         h6XLIwPZcrG5ZnNOQauni3UqKCV+A6pATypcrFdfuWQmPjpbHK06PLCnpIoK9zQpnlpl
         NEjuYizyUfX5eVD5XYrib+6sYQgEmoJFtvawdedb6FHUWqfgVMeW3nJtR9wogAphlocv
         nBS+SD251scKKfiArtq9HCHl3Flwv/Bl6QdTBK5rH/Cr4y/TOJZl8c3prfqpx98JHVJj
         UPiEd0Vjf/plZyO31NUHn5Dyksb0Iryqor40o549SKGB5QONcUmZmEgNcrerMu7lBzjo
         ge4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QikpwS8H;
       spf=pass (google.com: domain of 3xgo_ygykceunspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3xgO_YgYKCeUNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iY0FZwaBe5AEJr/9zlJTuhBZ2q6uWGihPKyx6dFedTM=;
        b=Z9anNAaK0uTLk3ueXeRjf/oNW+XSMFRDjjlXxt2YonbcoHILvpf55NJ4tIlJQvPfVB
         3AdWUmCFGZw2CEeuXZ534oMfisHruGZbnYdNFYkkdTHReXK14DP2HkZXzZFftm1pc/Y2
         Xt07i0jOAQKwqofliZMZtf0Gz/D7mT4+Pg6az72Y3dWrG+NdU+4HTi3VHXTIFuwZfQ+M
         sOlQkvsBiN5wa2E5fAo+rZOG50NLrKGr6CVrpk9y2XFofWTxDDK6GFP5JHXcJMvBk/Fq
         Z1Bau81Vub1pPUIAT6+VSpAuEsVTx2jew6UGY6qt/wJBmwHmOCeJ3W/R8nw4l6MGoh4H
         +6kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iY0FZwaBe5AEJr/9zlJTuhBZ2q6uWGihPKyx6dFedTM=;
        b=Vxf/fKp2S6DGkrBxfqufrZivpwD6e3lko3556SH/IQVD2T6/cJ0eMlypIZxlCo5sut
         1qlP6TC0eWGfTLixEgC6hv8+Z5ot1ASO45mx5GHARb3EeiltjftA5//loWDQ9JCE3Y1K
         3sSfyv5mOjanok3Det0LIc1ghquM7TRVZAbHm1ctUwf76aDYT6OEw7rVUe8HFu9pMG08
         qLoGfGcx79cunN7KzS+YcrDhjN010/c0RQGMjq7MatFFe9azbG7gADzD0GDAQlNOp4Bw
         r8XACMUMHClFi+2BWlZ35EnQolspmHuzBFsN59dMiagoyfaEYVrNGAGm1/5jp7oZ61tu
         nhGg==
X-Gm-Message-State: AJIora9rtIxK4+GPMR+422Cq429rSz+KpSQNz+HM7w2cLTpQO/h0skKo
	eIL12fdrjUDpiMhH4E1vtLw=
X-Google-Smtp-Source: AGRyM1v/qgnrcf0fXPKFcWFmTgyrM7YS2oPcHOyXXaDTFL/nVFCFwFSz95/X9ThoXTwhdZgjMME7FA==
X-Received: by 2002:a63:50:0:b0:3fe:2558:185b with SMTP id 77-20020a630050000000b003fe2558185bmr12577579pga.513.1656685511884;
        Fri, 01 Jul 2022 07:25:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8d01:b0:1ec:74d6:d32 with SMTP id
 c1-20020a17090a8d0100b001ec74d60d32ls317763pjo.2.-pod-control-gmail; Fri, 01
 Jul 2022 07:25:11 -0700 (PDT)
X-Received: by 2002:a17:902:6b0b:b0:16a:5c43:9aa6 with SMTP id o11-20020a1709026b0b00b0016a5c439aa6mr20288011plk.91.1656685511089;
        Fri, 01 Jul 2022 07:25:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685511; cv=none;
        d=google.com; s=arc-20160816;
        b=rzBH1ajy9nbcyxGWirsD2YH7DWj3oPnBo12epDW7GJg8ntk9JrX9rKMOEiTuJIpjWM
         7lLIo1iFSyFaHemaT5EKf/HnzIUiTZyz4UAPnUMBxaVHvbuQ67lOlbo6doyx1vh3QNPG
         VsmNJlR0EKffy0Ijc2+vGNvLfXcVfm1R1Y0zPe9IUj5H+FPOS3TP+aalcj7eOv2SLg5P
         Jd/kt+Y6j+2GJmMciI4VNHTtU1ESE5bdbxPNEA3jEtY1HwjSyyU0AdR0q6Xf/Ad5RY7c
         QZAevAq/ok498P/ekHm2qtb6W/DGxNuJtBcddjjkKeBvWjYnluD9WApge6g4u/tduDC0
         Tdaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=kErHaO8c2VDyOovKMTTPjLnffjCar7lX0B4oxY8ZYJM=;
        b=hTIA+vxFzmk9EnuN65dJpoLwvW19w3lf6lSwlxd4n3cgZoTKpx7d3/ktdc+BfJRsjf
         wZjA4tRsGHCTD/umMbk3ld+kzM1DZt+jtMEV3CQz45Z+q1Yjh+iPKasU+Pd/sTAdvx5S
         knlqdqQlgCYsZEylN0N6XfM6R6oNsXu/DdPq6p6/T4aFZKJWQ4fxhRn1IjyX4uhaiFV3
         5GTWkbOmrwsWuabhcF6hrzUiqrqsA/TLFG8wXPngroLyyxUpwgaGU67vG6ZB2SmkmQE0
         u+AJPrV5DqMOq2ke7enB4A6gKEGWCYQ+/6+yQ6GAtKt+NUgXDIfOuaCt6SWTcUcnODmF
         x81A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QikpwS8H;
       spf=pass (google.com: domain of 3xgo_ygykceunspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3xgO_YgYKCeUNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id e7-20020a056a00162700b005252382435esi825373pfc.1.2022.07.01.07.25.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:25:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xgo_ygykceunspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-31c1f45e612so20543577b3.0
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:25:11 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a81:d82:0:b0:31b:fd6f:9005 with SMTP id
 124-20020a810d82000000b0031bfd6f9005mr16667693ywn.389.1656685510371; Fri, 01
 Jul 2022 07:25:10 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:23:06 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-42-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 41/45] entry: kmsan: introduce kmsan_unpoison_entry_regs()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QikpwS8H;       spf=pass
 (google.com: domain of 3xgo_ygykceunspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3xgO_YgYKCeUNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
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

struct pt_regs passed into IRQ entry code is set up by uninstrumented
asm functions, therefore KMSAN may not notice the registers are
initialized.

kmsan_unpoison_entry_regs() unpoisons the contents of struct pt_regs,
preventing potential false positives. Unlike kmsan_unpoison_memory(),
it can be called under kmsan_in_runtime(), which is often the case in
IRQ entry code.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/Ibfd7018ac847fd8e5491681f508ba5d14e4669cf
---
 include/linux/kmsan.h | 15 +++++++++++++++
 kernel/entry/common.c |  5 +++++
 mm/kmsan/hooks.c      | 27 +++++++++++++++++++++++++++
 3 files changed, 47 insertions(+)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index e8b5c306c4aa1..c4412622b9a78 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -246,6 +246,17 @@ void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
  */
 void kmsan_handle_urb(const struct urb *urb, bool is_out);
 
+/**
+ * kmsan_unpoison_entry_regs() - Handle pt_regs in low-level entry code.
+ * @regs:	struct pt_regs pointer received from assembly code.
+ *
+ * KMSAN unpoisons the contents of the passed pt_regs, preventing potential
+ * false positive reports. Unlike kmsan_unpoison_memory(),
+ * kmsan_unpoison_entry_regs() can be called from the regions where
+ * kmsan_in_runtime() returns true, which is the case in early entry code.
+ */
+void kmsan_unpoison_entry_regs(const struct pt_regs *regs);
+
 #else
 
 static inline void kmsan_init_shadow(void)
@@ -342,6 +353,10 @@ static inline void kmsan_handle_urb(const struct urb *urb, bool is_out)
 {
 }
 
+static inline void kmsan_unpoison_entry_regs(const struct pt_regs *regs)
+{
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
diff --git a/kernel/entry/common.c b/kernel/entry/common.c
index 032f164abe7ce..055d3bdb0442c 100644
--- a/kernel/entry/common.c
+++ b/kernel/entry/common.c
@@ -5,6 +5,7 @@
 #include <linux/resume_user_mode.h>
 #include <linux/highmem.h>
 #include <linux/jump_label.h>
+#include <linux/kmsan.h>
 #include <linux/livepatch.h>
 #include <linux/audit.h>
 #include <linux/tick.h>
@@ -24,6 +25,7 @@ static __always_inline void __enter_from_user_mode(struct pt_regs *regs)
 	user_exit_irqoff();
 
 	instrumentation_begin();
+	kmsan_unpoison_entry_regs(regs);
 	trace_hardirqs_off_finish();
 	instrumentation_end();
 }
@@ -352,6 +354,7 @@ noinstr irqentry_state_t irqentry_enter(struct pt_regs *regs)
 		lockdep_hardirqs_off(CALLER_ADDR0);
 		rcu_irq_enter();
 		instrumentation_begin();
+		kmsan_unpoison_entry_regs(regs);
 		trace_hardirqs_off_finish();
 		instrumentation_end();
 
@@ -367,6 +370,7 @@ noinstr irqentry_state_t irqentry_enter(struct pt_regs *regs)
 	 */
 	lockdep_hardirqs_off(CALLER_ADDR0);
 	instrumentation_begin();
+	kmsan_unpoison_entry_regs(regs);
 	rcu_irq_enter_check_tick();
 	trace_hardirqs_off_finish();
 	instrumentation_end();
@@ -452,6 +456,7 @@ irqentry_state_t noinstr irqentry_nmi_enter(struct pt_regs *regs)
 	rcu_nmi_enter();
 
 	instrumentation_begin();
+	kmsan_unpoison_entry_regs(regs);
 	trace_hardirqs_off_finish();
 	ftrace_nmi_enter();
 	instrumentation_end();
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 9aecbf2825837..c7528bcbb2f91 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -358,6 +358,33 @@ void kmsan_unpoison_memory(const void *address, size_t size)
 }
 EXPORT_SYMBOL(kmsan_unpoison_memory);
 
+/*
+ * Version of kmsan_unpoison_memory() that can be called from within the KMSAN
+ * runtime.
+ *
+ * Non-instrumented IRQ entry functions receive struct pt_regs from assembly
+ * code. Those regs need to be unpoisoned, otherwise using them will result in
+ * false positives.
+ * Using kmsan_unpoison_memory() is not an option in entry code, because the
+ * return value of in_task() is inconsistent - as a result, certain calls to
+ * kmsan_unpoison_memory() are ignored. kmsan_unpoison_entry_regs() ensures that
+ * the registers are unpoisoned even if kmsan_in_runtime() is true in the early
+ * entry code.
+ */
+void kmsan_unpoison_entry_regs(const struct pt_regs *regs)
+{
+	unsigned long ua_flags;
+
+	if (!kmsan_enabled)
+		return;
+
+	ua_flags = user_access_save();
+	kmsan_internal_unpoison_memory((void *)regs, sizeof(*regs),
+				       KMSAN_POISON_NOCHECK);
+	user_access_restore(ua_flags);
+}
+EXPORT_SYMBOL(kmsan_unpoison_entry_regs);
+
 void kmsan_check_memory(const void *addr, size_t size)
 {
 	if (!kmsan_enabled)
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-42-glider%40google.com.
