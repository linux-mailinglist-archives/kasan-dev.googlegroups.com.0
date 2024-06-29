Return-Path: <kasan-dev+bncBCT4XGV33UIBBXHD7WZQMGQEUTELDDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 83CD891CA92
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Jun 2024 04:30:55 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id 5614622812f47-3d5a7f03d22sf1392680b6e.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 19:30:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719628254; cv=pass;
        d=google.com; s=arc-20160816;
        b=DmJ28NnSkC+RK5821Djvikq5f8ZX7ltc7JfVDzfPvz2s9b4nqQH9Qk2ANo+UWIsQPp
         0J9f+1CL9PgxJ9h7ZCDQ+Z0kognroZ8o9/D7aIOJYL3zkzHcZCsqAadhSrNGk0GCmI4S
         mrkTFCkU+bZ4tVwHq4DVJIpP0WL+hARY27ss4vi4ewCA5U19GXlf3nWrWV4FhcJTzQHu
         XCNeaUO9gABxP53Qrl2OoSjM4TIzqf6uOMwupivIBsMOlxkaYSlVkP5TuUKlcGQRQ4kC
         F79ivjVKguLcMBQ6Nu4mWOU1s9ObwutMn+CuG2uPsPd4NFzGgI8QqdK5O8eQFv4dYVIR
         MmSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=0txSb8Hzgr9q/CkStO3ysiKs6lLBME20fGqhge6dCGU=;
        fh=DAmfKi4cvMWVVgPcQQ/WJxIvRN25WwE7pQR4Qtj8vnk=;
        b=RfDCpyfVkwqK06NmUx8UESEpxwtNwwepcnsseIwVIBCvdix9AkZCI7n7eZyAlg9qDK
         0IEF6hx2amT727qaYAm5kDjFpo0584sylzxcgcryk31gUF+U+7jYWWrrsmePb6zPVdHW
         KHewxMTdE9conSM412zS5vEawlFYfpuu706ovljhdiFDLr2MrBUMkpGXgGeHUwA8dzu8
         GGvlXikHuLaAS+TDvlwQVjQCQAZ+7c5uAnWAlsWcQTxc3A8RZnteog4x3c3/J891w4pL
         jrQDR83KFjdU9l3cmfef6LeZp8w+h0OJuxfEWpLgTjoPi/FWMCqQ9Kr3i9q1Q4gyVosV
         6EGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=2XCs+Zzp;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719628254; x=1720233054; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0txSb8Hzgr9q/CkStO3ysiKs6lLBME20fGqhge6dCGU=;
        b=aEBjD7BvImcMjaGSLfUT8Uro787ljT7M0vS//xW+U+gg6AfjfL2QBZfD3rTXv+dFm5
         9OkfOPOCCjsLXykZeJg+U8cCqwvZohwpq9SKyS9fcPz8/UT2hI6hFmHw8Wy7sL9re0GQ
         nmgpJv9Ab+HYhZWL3oPmn3Icf2F2kJZrZwY8sny84fj1FB66U1uBahdOATNoB7ZNM5AQ
         Z8akhySPCiXI7MI2SDJLYDbb91UvTHMrEqvydslh3HkB45Glv/r20hlB7jpqpVklT34R
         NSYYyT/KFZ8hurtUE618ESovNq5WRF1/OTMgVIfXeSIFH2dhVKlUWMuBxm3XJljHOWB4
         35IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719628254; x=1720233054;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0txSb8Hzgr9q/CkStO3ysiKs6lLBME20fGqhge6dCGU=;
        b=AgngHPnEVeQ+9dq0R00p0VkoS2hC3nnDPsgfYriVs4lLNfcMjcUglj59I1CVeTz9Iq
         gg8TIjCKP44kYls6WPVMidQc4J2p7Asi48KgFwpEJXwpX7zI0ToTJe1TGg0ItnYl8JtS
         0cepIjgSjVOPNBgr8WIuWlyYBvjIIrw1tmrrULyMS1oUNkH3xaJkxT8/P+gg3ZhqUkp4
         QsTuXSTdb6pR8fRtj2B8F2DoPCfw4BneHMbGXbBLMvp8B5iu9MZtiW9Ssm8pEbsgmw0V
         y5i8lgU+FohfiNljfI0yDWe42ow+X0stkmUfzkcnkxkiF9qgFzMt26UzPyLRAN5yLvm0
         ZH3A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU66goWT/PBLhEtUcWWCUZhR3/Y5SCFqLTQztCyCh7tVy56Sl6MNaRTcV0zAqxgQ/HgMVy8ZZHjmI65hjW+F39UPmbBsfD9ug==
X-Gm-Message-State: AOJu0Ywp379gcO8qD3oItAmDCzf8KhpA6NL7GQvcrv8JeiyPVoY/8nwd
	Sq1u2NZgj9Yvj5VUqxdVZRsATFlTmTFJflNSFGjdF76qsyOOESdL
X-Google-Smtp-Source: AGHT+IEmODW4Fre/vMJYorbr9YYkAhV4KDKcHeBZ2oyc3DGMgy11pfQWPkN0Ij/oREibwf2RIT29kQ==
X-Received: by 2002:a05:6808:2222:b0:3d5:65b1:22a2 with SMTP id 5614622812f47-3d565b13617mr10050577b6e.32.1719628252822;
        Fri, 28 Jun 2024 19:30:52 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2d15:b0:706:6f90:b101 with SMTP id
 d2e1a72fcca58-7081a120ea0ls754202b3a.2.-pod-prod-01-us; Fri, 28 Jun 2024
 19:30:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV3G/KutcTXWPF7chmuJHt6VHqed+ublDCtAbNqJW8lkS5jbdAoysn/z00/BtS3DjeI5a1YalwOju682LuFTt38avpxXcZqEcoduw==
X-Received: by 2002:a05:6a00:1901:b0:706:65f6:3ab9 with SMTP id d2e1a72fcca58-70aaad6dd26mr12255b3a.20.1719628251513;
        Fri, 28 Jun 2024 19:30:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719628251; cv=none;
        d=google.com; s=arc-20160816;
        b=GLBbY1xofrwCLWdGCYlw72B1lPI9sCG2dGpYnSGMTGd1T5m1axHRPv9+GaCroVyWcq
         2a1+XWU1K9uAS4kk9flzxiZMTn3pfKhu8ObedZB3Ha23i2ZdCo49wPhFJDSFD0nyNPkC
         6suQudNCfEYKAacSfZP7t0fcN21HpUOL3JdkAX+5I/59D5P6VYPqbAO0XLQwHXV+wQRk
         THhH1RmADLpu3JXkttwLwhGf2pw2YHXWN/eC9A7Ph3LTJy2Hd2Z5Wi0p1oYF+u1Z0IH7
         wS9uXdN/djwh2IqHN+Di/K3homn5UzieJzb6RCbK7UbRrEC5n6nWYn3rTB/ObkrmJ9NG
         IDXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=gpLFssAVmEB41OBhvyNVqMUVokCE6OpdV2/zMZEbJGk=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=V3eGS6nAez8E0mknjezyZGpf2hzXb4tH0f8WS8KtLEbO0oUvUl76SeaeNnvTQDvO9g
         CyLkiiJXFmFGTEyIic7DmpWZdKERFu+g2EvXjPCK1T7RaX/ByJ9tOo1uof1d2YrMpKYy
         V6O7Ba0A/gRg6cHjHoL9flBNNmkKQrTF0ikuUvEliQ+eOAr0slNEo+cdHgGC+pYGzNuP
         OkGl0X2k4LXHQX91AnMrqeqNiVF1pkxhDN3MFXT25pTzGar/mtTGbwkZ9d5JpgEj/6fX
         yUVlmMU83B88aScq7G7XLldiVc6VWUcEjZm0lHOeVPNvZ8+Ynh0iPVOj6UbYh9UaRrVF
         cdfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=2XCs+Zzp;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-70804a976d1si121393b3a.6.2024.06.28.19.30.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jun 2024 19:30:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 65D03CE434F;
	Sat, 29 Jun 2024 02:30:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 918ADC116B1;
	Sat, 29 Jun 2024 02:30:48 +0000 (UTC)
Date: Fri, 28 Jun 2024 19:30:48 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kmsan-allow-disabling-kmsan-checks-for-the-current-task.patch removed from -mm tree
Message-Id: <20240629023048.918ADC116B1@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=2XCs+Zzp;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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


The quilt patch titled
     Subject: kmsan: allow disabling KMSAN checks for the current task
has been removed from the -mm tree.  Its filename was
     kmsan-allow-disabling-kmsan-checks-for-the-current-task.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: allow disabling KMSAN checks for the current task
Date: Fri, 21 Jun 2024 13:34:55 +0200

Like for KASAN, it's useful to temporarily disable KMSAN checks around,
e.g., redzone accesses.  Introduce kmsan_disable_current() and
kmsan_enable_current(), which are similar to their KASAN counterparts.

Make them reentrant in order to handle memory allocations in interrupt
context.  Repurpose the allow_reporting field for this.

Link: https://lkml.kernel.org/r/20240621113706.315500-12-iii@linux.ibm.com
Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Heiko Carstens <hca@linux.ibm.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: <kasan-dev@googlegroups.com>
Cc: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Masami Hiramatsu (Google) <mhiramat@kernel.org>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Steven Rostedt (Google) <rostedt@goodmis.org>
Cc: Sven Schnelle <svens@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 Documentation/dev-tools/kmsan.rst |   11 +++++++++--
 include/linux/kmsan.h             |   24 ++++++++++++++++++++++++
 include/linux/kmsan_types.h       |    2 +-
 mm/kmsan/core.c                   |    1 -
 mm/kmsan/hooks.c                  |   18 +++++++++++++++---
 mm/kmsan/report.c                 |    7 ++++---
 tools/objtool/check.c             |    2 ++
 7 files changed, 55 insertions(+), 10 deletions(-)

--- a/Documentation/dev-tools/kmsan.rst~kmsan-allow-disabling-kmsan-checks-for-the-current-task
+++ a/Documentation/dev-tools/kmsan.rst
@@ -110,6 +110,13 @@ in the Makefile. Think of this as applyi
 function in the file or directory. Most users won't need KMSAN_SANITIZE, unless
 their code gets broken by KMSAN (e.g. runs at early boot time).
 
+KMSAN checks can also be temporarily disabled for the current task using
+``kmsan_disable_current()`` and ``kmsan_enable_current()`` calls. Each
+``kmsan_enable_current()`` call must be preceded by a
+``kmsan_disable_current()`` call; these call pairs may be nested. One needs to
+be careful with these calls, keeping the regions short and preferring other
+ways to disable instrumentation, where possible.
+
 Support
 =======
 
@@ -338,11 +345,11 @@ Per-task KMSAN state
 ~~~~~~~~~~~~~~~~~~~~
 
 Every task_struct has an associated KMSAN task state that holds the KMSAN
-context (see above) and a per-task flag disallowing KMSAN reports::
+context (see above) and a per-task counter disallowing KMSAN reports::
 
   struct kmsan_context {
     ...
-    bool allow_reporting;
+    unsigned int depth;
     struct kmsan_context_state cstate;
     ...
   }
--- a/include/linux/kmsan.h~kmsan-allow-disabling-kmsan-checks-for-the-current-task
+++ a/include/linux/kmsan.h
@@ -239,6 +239,22 @@ void kmsan_unpoison_entry_regs(const str
  */
 void *kmsan_get_metadata(void *addr, bool is_origin);
 
+/**
+ * kmsan_enable_current(): Enable KMSAN for the current task.
+ *
+ * Each kmsan_enable_current() current call must be preceded by a
+ * kmsan_disable_current() call. These call pairs may be nested.
+ */
+void kmsan_enable_current(void);
+
+/**
+ * kmsan_disable_current(): Disable KMSAN for the current task.
+ *
+ * Each kmsan_disable_current() current call must be followed by a
+ * kmsan_enable_current() call. These call pairs may be nested.
+ */
+void kmsan_disable_current(void);
+
 #else
 
 static inline void kmsan_init_shadow(void)
@@ -338,6 +354,14 @@ static inline void kmsan_unpoison_entry_
 {
 }
 
+static inline void kmsan_enable_current(void)
+{
+}
+
+static inline void kmsan_disable_current(void)
+{
+}
+
 #endif
 
 #endif /* _LINUX_KMSAN_H */
--- a/include/linux/kmsan_types.h~kmsan-allow-disabling-kmsan-checks-for-the-current-task
+++ a/include/linux/kmsan_types.h
@@ -31,7 +31,7 @@ struct kmsan_context_state {
 struct kmsan_ctx {
 	struct kmsan_context_state cstate;
 	int kmsan_in_runtime;
-	bool allow_reporting;
+	unsigned int depth;
 };
 
 #endif /* _LINUX_KMSAN_TYPES_H */
--- a/mm/kmsan/core.c~kmsan-allow-disabling-kmsan-checks-for-the-current-task
+++ a/mm/kmsan/core.c
@@ -43,7 +43,6 @@ void kmsan_internal_task_create(struct t
 	struct thread_info *info = current_thread_info();
 
 	__memset(ctx, 0, sizeof(*ctx));
-	ctx->allow_reporting = true;
 	kmsan_internal_unpoison_memory(info, sizeof(*info), false);
 }
 
--- a/mm/kmsan/hooks.c~kmsan-allow-disabling-kmsan-checks-for-the-current-task
+++ a/mm/kmsan/hooks.c
@@ -39,12 +39,10 @@ void kmsan_task_create(struct task_struc
 
 void kmsan_task_exit(struct task_struct *task)
 {
-	struct kmsan_ctx *ctx = &task->kmsan_ctx;
-
 	if (!kmsan_enabled || kmsan_in_runtime())
 		return;
 
-	ctx->allow_reporting = false;
+	kmsan_disable_current();
 }
 
 void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags)
@@ -424,3 +422,17 @@ void kmsan_check_memory(const void *addr
 					   REASON_ANY);
 }
 EXPORT_SYMBOL(kmsan_check_memory);
+
+void kmsan_enable_current(void)
+{
+	KMSAN_WARN_ON(current->kmsan_ctx.depth == 0);
+	current->kmsan_ctx.depth--;
+}
+EXPORT_SYMBOL(kmsan_enable_current);
+
+void kmsan_disable_current(void)
+{
+	current->kmsan_ctx.depth++;
+	KMSAN_WARN_ON(current->kmsan_ctx.depth == 0);
+}
+EXPORT_SYMBOL(kmsan_disable_current);
--- a/mm/kmsan/report.c~kmsan-allow-disabling-kmsan-checks-for-the-current-task
+++ a/mm/kmsan/report.c
@@ -8,6 +8,7 @@
  */
 
 #include <linux/console.h>
+#include <linux/kmsan.h>
 #include <linux/moduleparam.h>
 #include <linux/stackdepot.h>
 #include <linux/stacktrace.h>
@@ -158,12 +159,12 @@ void kmsan_report(depot_stack_handle_t o
 
 	if (!kmsan_enabled)
 		return;
-	if (!current->kmsan_ctx.allow_reporting)
+	if (current->kmsan_ctx.depth)
 		return;
 	if (!origin)
 		return;
 
-	current->kmsan_ctx.allow_reporting = false;
+	kmsan_disable_current();
 	ua_flags = user_access_save();
 	raw_spin_lock(&kmsan_report_lock);
 	pr_err("=====================================================\n");
@@ -216,5 +217,5 @@ void kmsan_report(depot_stack_handle_t o
 	if (panic_on_kmsan)
 		panic("kmsan.panic set ...\n");
 	user_access_restore(ua_flags);
-	current->kmsan_ctx.allow_reporting = true;
+	kmsan_enable_current();
 }
--- a/tools/objtool/check.c~kmsan-allow-disabling-kmsan-checks-for-the-current-task
+++ a/tools/objtool/check.c
@@ -1202,6 +1202,8 @@ static const char *uaccess_safe_builtin[
 	"__sanitizer_cov_trace_switch",
 	/* KMSAN */
 	"kmsan_copy_to_user",
+	"kmsan_disable_current",
+	"kmsan_enable_current",
 	"kmsan_report",
 	"kmsan_unpoison_entry_regs",
 	"kmsan_unpoison_memory",
_

Patches currently in -mm which might be from iii@linux.ibm.com are


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240629023048.918ADC116B1%40smtp.kernel.org.
