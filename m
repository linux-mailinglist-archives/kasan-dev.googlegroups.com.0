Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPNQWT4QKGQEW6SOGSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A17D23E9AA
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Aug 2020 11:00:47 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id f19sf1151712iol.10
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Aug 2020 02:00:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596790846; cv=pass;
        d=google.com; s=arc-20160816;
        b=gWxmQNIGMkLVb4gef0GXbpK0Uc8Vmw+2V1Rz2XEGPqwAv1qJ6vfAsjwByJchaoznqF
         MjCbiI8Hgg0as8Ol9B/oe0xwOJbeqdiIEAmZlu6ILZEXS4kcr3GUKGYt82v7H/lRWNj1
         VrPFmrDu9nFnO7k/0Jtvw+O9D6rV8BopcTmxQVoCdlf9XLna1SzGXnRnnIbElqf6hSw/
         vQEavVao0TP14Onrsaf6n4Z28GoXo5uveU1uqn8KQErUXbl90SCugBL21KHkWHFLz4Dj
         op3/EB1qoefoZcXxka4kxNXaYdvyvL301Xr4n6IPBkElBxI89WcJLDgL2UfArLPMhSL1
         tV1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=46ItRYrovaPePVBJu0S+jOuhA2jye6NswWcYWKDl20A=;
        b=iubZBDH5cXcn0MO/qt4l2cOI+nS2ezBvufQFhGvLGfUe+LL+wvEG/1ebnswIWvNg3P
         IO53gddEYRUPPc/GEDCOahoISQEuW26voacA+QcRri4shiD9PY8PPkWq/PS8YbmJdNT5
         6Hr/OywJmphCapf3+VuO8ZMsBf7JbJa9RZzmfLkufRWSNwlqkAMrQ7PUTdSknCrn6Kj9
         vdayRFCLf9F3wqGRMzGJa3Re5hW90af15WQNuTDwHUPu6mPfM637DX3lH54plJp2rplv
         y+xl/isXCbO8TcspRqMKp/ldwo29CWN0Fh3zdYPnhYUqKe3tvrpY0ldVkDX0viC9vF4S
         1IBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=clG4WrVQ;
       spf=pass (google.com: domain of 3pbgtxwukcsebisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3PBgtXwUKCSEBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=46ItRYrovaPePVBJu0S+jOuhA2jye6NswWcYWKDl20A=;
        b=kQsOa2ycjkGitvRrVz3YNstQaUyUJxQTNVmOXXY5d7dvWaagoiUOu7jl2eh4UmJPNY
         bqZfk/aIexba/IqX2z2MP/xz8u10wblx+PK3G/oJoWfCxAJERZh90G8WxgCqBzNGNnMA
         YMD3e4HEA60L6THVDClUj5xevN+21gUFp+TOhE8G+P9bU6nmRRDzliVTRf3xP1irlEnB
         0bvU0V/kl3nT+dlOmDkeS2DXmWWoINJdePfDbFVFb6FoywNjC6tnyQvGgDr1/lSKBTqb
         w4AIp0IYN9tgT7UjUOLqzelmGx17GbPmIlc9pO0ZMzSkxiv9GrRscMDcp4xjzr+Vs5iK
         O3Jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=46ItRYrovaPePVBJu0S+jOuhA2jye6NswWcYWKDl20A=;
        b=glU9VmThbsa2HLHdlqyeuXu4cPW3hc/ztkPrTvc77EZCr4a4biY3FBH1ps/9j2svkD
         p8HSgBKpzhfWN0OcLzjSeb005ln7ErzdivwqrnXlsbo7JJJ4aD5WOzlxOi79Z8gt67L2
         dE8SFWx8Qjg9Fu2lIFAY0bCMHXrPHS76CrW3cZBVmqCoyE/BrKkjIivsZtG2WZM5VoPM
         dzEPNnURWJKLLX4lcq/AehBhcfiIUaUxvhjg7KXVXkt3dfZtB9iv3ced2DugBnBdxBN4
         aMExbIDNtQZmPbVVoz/nlbgdQq6PhHe9fwPfD/ubW0mJjWe02A24AjP24MvFt5gU9khG
         Ug4Q==
X-Gm-Message-State: AOAM532F1CPPgyT0KamuACrX7n/tTeKjuVGnqgWJwq7R8RcdP7VsHAqJ
	CAVsnePWQMYj4I3BlzaBZ7M=
X-Google-Smtp-Source: ABdhPJwsfFJVh8ELgtfq0sepww30j0sa2Q/WRb0Ms6FjBeKENqJIOiPoopYWQzOTXFCQhw6uUOM4nw==
X-Received: by 2002:a92:d4cf:: with SMTP id o15mr2959784ilm.160.1596790845938;
        Fri, 07 Aug 2020 02:00:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ba4c:: with SMTP id o73ls2212438ili.11.gmail; Fri, 07
 Aug 2020 02:00:45 -0700 (PDT)
X-Received: by 2002:a92:89c9:: with SMTP id w70mr3447891ilk.250.1596790845524;
        Fri, 07 Aug 2020 02:00:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596790845; cv=none;
        d=google.com; s=arc-20160816;
        b=QoN/tJ0hUYoZfLijjMCqfRgM1mV1K7LA4uH5fOBVRzCjEDuFEUnidYwYHAFfXTYctU
         RsYD9pDjjqC69zoohCrQgzxzZdvSu2seT0iKPxInALtNQCFEzLI+rFm9GeCZ/r9mH+mk
         QgTr3+REURnPAG9Q1wKfUm3xYKd8a4Ox0yQOgElzsUHTKpA+F7DKHfQW3YSizGLKSl3T
         DE4QrGSz2tBhPIkNW3/5hkgVzp8sHAZLXbHQ/uZy4NDCJV+euiaCHmYrM5ZHe6gR05G/
         t4vo1ofMzafQkphm0sYP09fOq5a/7KuMuYjpr1x+qZJ8nPuLe5Qx+US/incxy+OQdNIc
         oe0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=oCzauoN+RxiYcRFcgDoGwgH2irisX28lT31YYK8dufk=;
        b=vaF439wC6OLyUP9MF9Ek3g0gVS/q5wxopYzpvcR/NHQkXbvkCdFNeDXX/kH9eeAzlS
         KhVDT/u+MxWB9w/iI1CkOXc7ppUFJCeXs96xj4/pLEnhOVGHEChVYdK1EROwZ0jj/c0E
         Il+cz6pDtENulkK9UTa+BAYUq+yB8vneUhTtbR+5nlbp4ojnDZ7iL1TzJPkQ1fSpHJRE
         Iq8WBFpH1KwGC3gC69fY96fyCjHZfwhAYcmLYpe3Wi27uDO1hw1V60fxwKf883FJjoH2
         cDWx7ppe7IDcn9eLKhg78b0vTrkY9h/MVrrB0W/QeoUMrgVxKcCfoYoK/OeOYtQZ8ZuY
         90uQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=clG4WrVQ;
       spf=pass (google.com: domain of 3pbgtxwukcsebisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3PBgtXwUKCSEBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id k88si401650ilg.0.2020.08.07.02.00.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Aug 2020 02:00:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pbgtxwukcsebisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id q7so1215567qtd.1
        for <kasan-dev@googlegroups.com>; Fri, 07 Aug 2020 02:00:45 -0700 (PDT)
X-Received: by 2002:a0c:f14d:: with SMTP id y13mr12756071qvl.136.1596790844872;
 Fri, 07 Aug 2020 02:00:44 -0700 (PDT)
Date: Fri,  7 Aug 2020 11:00:31 +0200
Message-Id: <20200807090031.3506555-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.236.gb10cc79966-goog
Subject: [PATCH] kcsan: Treat runtime as NMI-like with interrupt tracing
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: peterz@infradead.org, bp@alien8.de, tglx@linutronix.de, mingo@kernel.org, 
	mark.rutland@arm.com, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, 
	syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=clG4WrVQ;       spf=pass
 (google.com: domain of 3pbgtxwukcsebisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3PBgtXwUKCSEBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Since KCSAN instrumentation is everywhere, we need to treat the hooks
NMI-like for interrupt tracing. In order to present an as 'normal' as
possible context to the code called by KCSAN when reporting errors, we
need to update the IRQ-tracing state.

Tested: Several runs through kcsan-test with different configuration
(PROVE_LOCKING on/off), as well as hours of syzbot testing with the
original config that caught the problem (without CONFIG_PARAVIRT=y,
which appears to cause IRQ state tracking inconsistencies even when
KCSAN remains off, see Link).

Link: https://lkml.kernel.org/r/0000000000007d3b2d05ac1c303e@google.com
Fixes: 248591f5d257 ("kcsan: Make KCSAN compatible with new IRQ state tracking")
Reported-by: syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com
Co-developed-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---
Patch Note: This patch applies to latest mainline. While current
mainline suffers from the above problem, the configs required to hit the
issue are likely not enabled too often (of course with PROVE_LOCKING on;
we hit it on syzbot though). It'll probably be wise to queue this as
normal on -rcu, just in case something is still off, given the
non-trivial nature of the issue. (If it should instead go to mainline
right now as a fix, I'd like some more test time on syzbot.)
---
 kernel/kcsan/core.c  | 79 ++++++++++++++++++++++++++++++++++----------
 kernel/kcsan/kcsan.h |  3 +-
 2 files changed, 62 insertions(+), 20 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 9147ff6a12e5..6202a645f1e2 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -291,13 +291,28 @@ static inline unsigned int get_delay(void)
 				0);
 }
 
-void kcsan_save_irqtrace(struct task_struct *task)
-{
+/*
+ * KCSAN instrumentation is everywhere, which means we must treat the hooks
+ * NMI-like for interrupt tracing. In order to present a 'normal' as possible
+ * context to the code called by KCSAN when reporting errors we need to update
+ * the IRQ-tracing state.
+ *
+ * Save and restore the IRQ state trace touched by KCSAN, since KCSAN's
+ * runtime is entered for every memory access, and potentially useful
+ * information is lost if dirtied by KCSAN.
+ */
+
+struct kcsan_irq_state {
+	unsigned long		flags;
 #ifdef CONFIG_TRACE_IRQFLAGS
-	task->kcsan_save_irqtrace = task->irqtrace;
+	int			hardirqs_enabled;
 #endif
-}
+};
 
+/*
+ * This is also called by the reporting task for the other task, to generate the
+ * right report with CONFIG_KCSAN_VERBOSE. No harm in restoring more than once.
+ */
 void kcsan_restore_irqtrace(struct task_struct *task)
 {
 #ifdef CONFIG_TRACE_IRQFLAGS
@@ -305,6 +320,41 @@ void kcsan_restore_irqtrace(struct task_struct *task)
 #endif
 }
 
+/*
+ * Saves/restores IRQ state (see comment above). Need noinline to work around
+ * unfortunate code-gen upon inlining, resulting in objtool getting confused as
+ * well as losing stack trace information.
+ */
+static noinline void kcsan_irq_save(struct kcsan_irq_state *irq_state)
+{
+#ifdef CONFIG_TRACE_IRQFLAGS
+	current->kcsan_save_irqtrace = current->irqtrace;
+	irq_state->hardirqs_enabled = lockdep_hardirqs_enabled();
+#endif
+	if (!kcsan_interrupt_watcher) {
+		kcsan_disable_current(); /* Lockdep might WARN, etc. */
+		raw_local_irq_save(irq_state->flags);
+		lockdep_hardirqs_off(_RET_IP_);
+		kcsan_enable_current();
+	}
+}
+
+static noinline void kcsan_irq_restore(struct kcsan_irq_state *irq_state)
+{
+	if (!kcsan_interrupt_watcher) {
+		kcsan_disable_current(); /* Lockdep might WARN, etc. */
+#ifdef CONFIG_TRACE_IRQFLAGS
+		if (irq_state->hardirqs_enabled) {
+			lockdep_hardirqs_on_prepare(_RET_IP_);
+			lockdep_hardirqs_on(_RET_IP_);
+		}
+#endif
+		raw_local_irq_restore(irq_state->flags);
+		kcsan_enable_current();
+	}
+	kcsan_restore_irqtrace(current);
+}
+
 /*
  * Pull everything together: check_access() below contains the performance
  * critical operations; the fast-path (including check_access) functions should
@@ -350,11 +400,13 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 	flags = user_access_save();
 
 	if (consumed) {
-		kcsan_save_irqtrace(current);
+		struct kcsan_irq_state irqstate;
+
+		kcsan_irq_save(&irqstate);
 		kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_MAYBE,
 			     KCSAN_REPORT_CONSUMED_WATCHPOINT,
 			     watchpoint - watchpoints);
-		kcsan_restore_irqtrace(current);
+		kcsan_irq_restore(&irqstate);
 	} else {
 		/*
 		 * The other thread may not print any diagnostics, as it has
@@ -387,7 +439,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	unsigned long access_mask;
 	enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
 	unsigned long ua_flags = user_access_save();
-	unsigned long irq_flags = 0;
+	struct kcsan_irq_state irqstate;
 
 	/*
 	 * Always reset kcsan_skip counter in slow-path to avoid underflow; see
@@ -412,14 +464,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		goto out;
 	}
 
-	/*
-	 * Save and restore the IRQ state trace touched by KCSAN, since KCSAN's
-	 * runtime is entered for every memory access, and potentially useful
-	 * information is lost if dirtied by KCSAN.
-	 */
-	kcsan_save_irqtrace(current);
-	if (!kcsan_interrupt_watcher)
-		local_irq_save(irq_flags);
+	kcsan_irq_save(&irqstate);
 
 	watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
 	if (watchpoint == NULL) {
@@ -559,9 +604,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	remove_watchpoint(watchpoint);
 	kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
 out_unlock:
-	if (!kcsan_interrupt_watcher)
-		local_irq_restore(irq_flags);
-	kcsan_restore_irqtrace(current);
+	kcsan_irq_restore(&irqstate);
 out:
 	user_access_restore(ua_flags);
 }
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index 29480010dc30..6eb35a9514d8 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -24,9 +24,8 @@ extern unsigned int kcsan_udelay_interrupt;
 extern bool kcsan_enabled;
 
 /*
- * Save/restore IRQ flags state trace dirtied by KCSAN.
+ * Restore IRQ flags state trace dirtied by KCSAN.
  */
-void kcsan_save_irqtrace(struct task_struct *task);
 void kcsan_restore_irqtrace(struct task_struct *task);
 
 /*
-- 
2.28.0.236.gb10cc79966-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200807090031.3506555-1-elver%40google.com.
