Return-Path: <kasan-dev+bncBCT4XGV33UIBBPX5ZWZQMGQEGG2FVWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D8D590FA99
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 02:58:40 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id 5614622812f47-3d2228a495asf303170b6e.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 17:58:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718845119; cv=pass;
        d=google.com; s=arc-20160816;
        b=WYvjoOyf6w7KQQW8IYriYfFkGuPm3WWs0Iwhp+pFv6KJbXstJs1gj4e58fvB6V3csQ
         R3+yvEMzJ3iNfRJ+m8CaTtqg0VuUAB4AXfxlmvyRCXzv6lnkMnKrLCDmJwbGpgtZ1EIF
         CZdImLSbdtzzBuakYekVHJcYii08dvIsr8EM6VnttBcsJITjkmTeN3ySICovZRkna8rg
         d0qSaFU6C7YqneyB8qiL0CRYzE7CqI9OPFjGf/j/4cMc8OcVZQ+g6QcIslVVaysdBZj8
         C5JRofaENrDigC/I2JS2gR1gOAA8XvsshJoYqsIt0bqGineia08Tf2UBhZ/5psWo8NoX
         YuEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=X2Y5I77wR+f9uSIus25Nr7PkwYCoSod24ZUyWnqJwBA=;
        fh=DR9KKU1epCq5EY9xG8aJieEq63dIkLt2MTbfZ7HW8FQ=;
        b=fjXnC8uUXXFMBnELtq6BpET3w8VhzN4kF/qvMNAlmx7At3PYFUlD+jgJARSM1edk4h
         sKE2q2i9dwV1ceX1IUh2hKhDjJsap2XClcbZEJC7f1Vhw24KTHt8sHjIiT+SkxzZM3qv
         MGJF5IpSr9XaGix+7mddmu/f4LnWD0HNuHpcqGCxcH8YXYfE1QKuvMxYNWR/P4ptaXkL
         BhYmfixWZ6Vnt8iIIzpv/PnuuGJXxLB18DGNvYIBhFjrwO+PKdEZEkv3Gl6vqIz4sAux
         jbwZS26t2/ynhMJ0l83Ym/zQign2mJesrqt8OF20Ce6gsrQsvD5GCy8Y1Bll27dbNYjP
         yZDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Ecq+QRmX;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718845119; x=1719449919; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=X2Y5I77wR+f9uSIus25Nr7PkwYCoSod24ZUyWnqJwBA=;
        b=mfoMYSs3tss6g5DehtdndRmdX/vmJbJHCpmf1EbEjCIe0x97jyIxQ83GLtqTdFfLGx
         NoeOPgECvhR6AdrhriECtIwfoz6KQk6CI8m8rJYDWHtUBcAc5j5VJXC4dJDCqJNIk6sk
         ZtoxwUsxrvOlSXrfdcRzYyzGq2NIdlHjJ2dY+FSKI7Ud7u4Ik0kRI00tS/yEP0iWizW+
         JoGC5a+7355Xw3K+MhWcHPute1IIO5yU6hiEklfVcMSB5cddc21KOWibshJpiBr9SFBn
         uHKROTIM2w9Dq6c3MEBUqfVdEzeYuAd0X0K18ko2ga3o6FnCo4dOBpCS+n9jkR+G8RZF
         +TSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718845119; x=1719449919;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=X2Y5I77wR+f9uSIus25Nr7PkwYCoSod24ZUyWnqJwBA=;
        b=dz6qIWLJtAOq99AhPMoFzC5uDsMvqMePW3Yx/4A6Ni480OMYdbigazJHxbNi2HTRYg
         eVoYj8NiM+Ipzm0FDwtObDk0WA2zJMsKHza2VGO26zzoXbMB+9MeLPzxwl8VUqNo74Df
         fSq2bRhHvUPfmVHmD9+TJkZZf2ecokf+CX8De6jPLj/bFfkzanlWdo25CFskI5xDYVRJ
         OcFxkP2evtLAW1dZbrG8rJaYCjeLpRZ4Jx8o+bYVn9kGf2OJYiqed1mWig5AAtlgWIzd
         +WdV8fzpMNi1SK+6lrCsPpfA5UVjjMpjQiEW2recGyrEK20bRKcFKcAUWGLsOW6C34zi
         j3lA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXmuzX70oosHVLw7LzVBxoOEK7YEOK3jtg121DvEuvyvm912n/480aOudCm2Yeeb7rXLh7irLt/wv3bVKaHJQnwrOVmuI72Q==
X-Gm-Message-State: AOJu0YyBnGi6QBXkkBxJzGuealAK+J4r78T7Wds8aPKHPypMamOttu4C
	vcP1gbmTPHmArkB+emghPPbe+5etxzSi24owK79uuy3owRwQdGHO
X-Google-Smtp-Source: AGHT+IHQ/05reOsNOuyipB0DpyF4eJrwbMYE//ds0NYbdgHtnL1ks1YeW1C6/YfG91JmWhVSiDm/fg==
X-Received: by 2002:a05:6870:c1cb:b0:24f:d159:ea2 with SMTP id 586e51a60fabf-25c949ffaedmr3992434fac.28.1718845118956;
        Wed, 19 Jun 2024 17:58:38 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:418f:b0:25c:a475:98e6 with SMTP id
 586e51a60fabf-25cb5ed50d6ls408322fac.1.-pod-prod-02-us; Wed, 19 Jun 2024
 17:58:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVeQRqOMFseSyyeaCUmXDNpeg+kNU8Bzspz/SsB1ueJRQ9gMcXLM1YEJaLGMDXegBfJ+RJwcSNY5q47gTlPqoLsZJ8jLt/uT4fYHA==
X-Received: by 2002:a05:6870:1653:b0:254:75b9:b212 with SMTP id 586e51a60fabf-25c94d72262mr4224338fac.55.1718845117199;
        Wed, 19 Jun 2024 17:58:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718845117; cv=none;
        d=google.com; s=arc-20160816;
        b=sUIRhgst6lTwlExPN2vDFjzMGY/GofkEAuwcWgFPHZe9p4VgDCxbneXCB14webGhc8
         ORWktHxMKb5+9JgTPYaMK5ob1N4acUAVsGo47m4JMpeSLev7O91TNePKXjYaxDETM9y+
         Ofv86+VvtmSK3UPiF7fSVV2n9xuszJYuRUDy1dTnYuB7GpDP73Z9IOL5MseeI2diqKDd
         rTG59R84LTojIUp7ETYJ+GgOt2I8zREdkykhPeTmE9kQj89oblKO2ARIy1rYHNxUQGzh
         SJrYjuElu4LewslUZsRuFCazoJGyU7aS36MSjr2ErGL6n1WPiy/NPbG6xWI13ZigqB6n
         1nsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=DUD/loRM4P0ggE3YUHDMm2d1hkcH93eMzKyqg5c5f/w=;
        fh=YLJcVBHySIoH6a7eXFb8EZw2NzFQuSbk32Vvne46C7E=;
        b=mmLDU+Sbrzk2D2vUH1cmuZ+ZyAr3wG7S3+dAwCMoinDnHXb1+oSp5PIk/0aNMZpw86
         DAKF+Xa5RYZ4M/hKItTumLj5PnV6AmnVbINUj7nfjIEYGEiAtGBKf5PEPCS0+VKMr7Dn
         bOKuQo0q/fzvmmDSmLJ0Zg1JfDv5OINo8lhGFgLxjOAIcs/hXWyO5zm+9nnlN+ksiDqH
         Oux/S0qmP7WcRr6lKHN7jNc9xFwsl762/YT8aWSgs5600NNlkNt24HkWpATA1LAR7Tx8
         qz6gXQISzPuk885i2ESMONwJ3khbC7SirktsLXpmEOPPOdOWTxJfxospczoO+H96Z8tE
         iXxg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Ecq+QRmX;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2598b0dacb9si205260fac.3.2024.06.19.17.58.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 17:58:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id AEC87CE22D7;
	Thu, 20 Jun 2024 00:58:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F182AC2BBFC;
	Thu, 20 Jun 2024 00:58:33 +0000 (UTC)
Date: Wed, 19 Jun 2024 17:58:33 -0700
To: mm-commits@vger.kernel.org,vbabka@suse.cz,svens@linux.ibm.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,penberg@kernel.org,mhiramat@kernel.org,mark.rutland@arm.com,kasan-dev@googlegroups.com,iamjoonsoo.kim@lge.com,hca@linux.ibm.com,gor@linux.ibm.com,glider@google.com,elver@google.com,dvyukov@google.com,cl@linux.com,borntraeger@linux.ibm.com,agordeev@linux.ibm.com,42.hyeyoo@gmail.com,iii@linux.ibm.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kmsan-allow-disabling-kmsan-checks-for-the-current-task.patch added to mm-unstable branch
Message-Id: <20240620005833.F182AC2BBFC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=Ecq+QRmX;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.73.55 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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


The patch titled
     Subject: kmsan: allow disabling KMSAN checks for the current task
has been added to the -mm mm-unstable branch.  Its filename is
     kmsan-allow-disabling-kmsan-checks-for-the-current-task.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kmsan-allow-disabling-kmsan-checks-for-the-current-task.patch

This patch will later appear in the mm-unstable branch at
    git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

Before you just go and hit "reply", please:
   a) Consider who else should be cc'ed
   b) Prefer to cc a suitable mailing list as well
   c) Ideally: find the original patch on the mailing list and do a
      reply-to-all to that, adding suitable additional cc's

*** Remember to use Documentation/process/submit-checklist.rst when testing your code ***

The -mm tree is included into linux-next via the mm-everything
branch at git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm
and is updated there every 2-3 working days

------------------------------------------------------
From: Ilya Leoshkevich <iii@linux.ibm.com>
Subject: kmsan: allow disabling KMSAN checks for the current task
Date: Wed, 19 Jun 2024 17:43:46 +0200

Like for KASAN, it's useful to temporarily disable KMSAN checks around,
e.g., redzone accesses.  Introduce kmsan_disable_current() and
kmsan_enable_current(), which are similar to their KASAN counterparts.

Make them reentrant in order to handle memory allocations in interrupt
context.  Repurpose the allow_reporting field for this.

Link: https://lkml.kernel.org/r/20240619154530.163232-12-iii@linux.ibm.com
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
 
+/*
+ * kmsan_enable_current(): Enable KMSAN for the current task.
+ *
+ * Each kmsan_enable_current() current call must be preceded by a
+ * kmsan_disable_current() call. These call pairs may be nested.
+ */
+void kmsan_enable_current(void);
+
+/*
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

ftrace-unpoison-ftrace_regs-in-ftrace_ops_list_func.patch
kmsan-make-the-tests-compatible-with-kmsanpanic=1.patch
kmsan-disable-kmsan-when-deferred_struct_page_init-is-enabled.patch
kmsan-increase-the-maximum-store-size-to-4096.patch
kmsan-fix-is_bad_asm_addr-on-arches-with-overlapping-address-spaces.patch
kmsan-fix-kmsan_copy_to_user-on-arches-with-overlapping-address-spaces.patch
kmsan-remove-a-useless-assignment-from-kmsan_vmap_pages_range_noflush.patch
kmsan-remove-an-x86-specific-include-from-kmsanh.patch
kmsan-expose-kmsan_get_metadata.patch
kmsan-export-panic_on_kmsan.patch
kmsan-allow-disabling-kmsan-checks-for-the-current-task.patch
kmsan-introduce-memset_no_sanitize_memory.patch
kmsan-support-slab_poison.patch
kmsan-use-align_down-in-kmsan_get_metadata.patch
kmsan-do-not-round-up-pg_data_t-size.patch
mm-slub-let-kmsan-access-metadata.patch
mm-slub-disable-kmsan-when-checking-the-padding-bytes.patch
mm-kfence-disable-kmsan-when-checking-the-canary.patch
lib-zlib-unpoison-dfltcc-output-buffers.patch
kmsan-accept-ranges-starting-with-0-on-s390.patch
s390-boot-turn-off-kmsan.patch
s390-use-a-larger-stack-for-kmsan.patch
s390-boot-add-the-kmsan-runtime-stub.patch
s390-checksum-add-a-kmsan-check.patch
s390-cpacf-unpoison-the-results-of-cpacf_trng.patch
s390-cpumf-unpoison-stcctm-output-buffer.patch
s390-diag-unpoison-diag224-output-buffer.patch
s390-ftrace-unpoison-ftrace_regs-in-kprobe_ftrace_handler.patch
s390-irqflags-do-not-instrument-arch_local_irq_-with-kmsan.patch
s390-mm-define-kmsan-metadata-for-vmalloc-and-modules.patch
s390-string-add-kmsan-support.patch
s390-traps-unpoison-the-kernel_stack_overflows-pt_regs.patch
s390-uaccess-add-kmsan-support-to-put_user-and-get_user.patch
s390-uaccess-add-the-missing-linux-instrumentedh-include.patch
s390-unwind-disable-kmsan-checks.patch
s390-kmsan-implement-the-architecture-specific-functions.patch
kmsan-enable-on-s390.patch

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240620005833.F182AC2BBFC%40smtp.kernel.org.
