Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7FRQX4QKGQE5VCAHWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A243231D37
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jul 2020 13:09:49 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id d16sf8388323eje.20
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jul 2020 04:09:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596020988; cv=pass;
        d=google.com; s=arc-20160816;
        b=kCBy6fcFbzaY4wlHKkjzFwVDeIkUki/8apUOonUbWLm1pwD4OY9RyXB5R2S/oykGz1
         NOHgNqPaWDHTAbBdigFnNxQ3Vzf9CWUC1l8M/EdzwWs4pOOfcLdyx0O5ZHV6FJ1YuVVL
         4/v6rlBfUNZtbY+A54B8Zf8WoloKrJRyk/p9xe11PPhnBXl25Kfr3CqhCxg8cCSsco9n
         l7a58LaXl+bYU7Jo70QBrC8Gr3HcpL573FNehGzN7ezb2ZNs8xXIBpKl/t4ZolcT3NHY
         A32c7S8+uLfkVCQqH2qZ0i7NZUhykJW9oI0MRjAe+QOnuhF6D1bdEiyBrx8iBw3Av6m3
         m17w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=wiOE/La2wuhNyyLiOvrw3oY26JRjqkizuoO/wiQsqOE=;
        b=YpA2CZVZ3FX5KyBSQYc1JhlmXrzKjl63UANI4DeyHx1GXGCJBZxN82kCLvUrbHTEjM
         92dECxtPNZNlh+jWGoWDBrT/i2kkN/IOnNA0QH8fHanUDJ2awfHz8sJ62BRTl2UmjwZ1
         Rz0DZUnHDvKrZheWaf/h9BvBvZI5bTctBZW4XBFrbSVpyo1lfeqWY7b1bNJX6UwE3ID9
         M/ULE1TguIxt+qlezIyzTf5vqhXZ6MyY5Ci8Fb/U6gXDHehskH8IY8YnMfLDoRtTX0Mg
         X2qh+YhxJZveGArd39PqUyDSqUvCQa/JmqxhAFdiWVNAcCgFoJa77bos8kmR89hrCNg1
         LEJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wEfYgmft;
       spf=pass (google.com: domain of 3-1ghxwukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3-1ghXwUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=wiOE/La2wuhNyyLiOvrw3oY26JRjqkizuoO/wiQsqOE=;
        b=bpnP5ghz8RzrIAD55dYledLVYOeA0w+uHIEO6qtwRFn/exxvQdM3nWu7vwrt0W7/IU
         turEkEw33kYoajdgu3G3Lgae7U/J8X279wZeBxQ/D3w5MB5dWAeixb3BL6jm2MNEz1NS
         vewseW2KA9ac/pGG3RDhQ7RR6cTwNjiWJZmlGvmLV7KyEyhd8L/cTW+Qx2jK4ZputfmL
         tczvE8T7Rc+LMZf3ZfEVIGHJkhxS7E70M4fv4eYHvwWBP6z3EgdZDqgit7qnbkUbFjeL
         Jr077mCCf9jz4g+I8S7SBkjdXhRG3vPq9FDwsnytT4pxWY1HpuGz5gOybwSMlMQ9b/BZ
         pFHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wiOE/La2wuhNyyLiOvrw3oY26JRjqkizuoO/wiQsqOE=;
        b=X/vglKTqBBfWZuff7S6Ztziv6k8kjMFZ+NTLPLs4FOPwwPqHMFK50ZBjn5T2SQAWq0
         Y1tFjyfhNFgLOQ4w7xG1JiGyNYV2gSO3rnr9YOX8i6JvnVlEqWfCnJfA2FNKlQJbHQNi
         gvAtwZp/ZJd+PN6PAPFD67os3sUye1MD543tH1xpjdZCGk1eRhuYE9sJVV1faHzj1Lgb
         KH0WA7MCcECZWBkpDbsHXPnjPgoo+EDMfan7iccwEKkzahhpw9MbPYQbWP38zUqVMNBp
         XNNSVO+dQd6oPXYIDz03POhOnag9vKurPWqAXW+2ksYJKkW2REPGJWw0EfwmGnA6Vd3R
         BhjQ==
X-Gm-Message-State: AOAM532cs/I9u5ULfnKpL8P5qytnHm/33tJ0jx2/v9fdyvh0+5Bi+FcC
	xf6IgtEA5AfNzMf3QRXVfAA=
X-Google-Smtp-Source: ABdhPJw0kbJRkSEehssxyG/FFC91DeXVxjW1Q3Gz8dA6P+RIfVDzMbvWdkMWaKFpKYV65lhRDR0c7Q==
X-Received: by 2002:a17:906:1596:: with SMTP id k22mr31065674ejd.509.1596020988794;
        Wed, 29 Jul 2020 04:09:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1d37:: with SMTP id dh23ls1624163edb.1.gmail; Wed,
 29 Jul 2020 04:09:48 -0700 (PDT)
X-Received: by 2002:a50:ee07:: with SMTP id g7mr31416625eds.320.1596020988123;
        Wed, 29 Jul 2020 04:09:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596020988; cv=none;
        d=google.com; s=arc-20160816;
        b=BgLrRKtIG/y6VIlDXpi4jhKJZ3dv4yzBGPFyWIWA42fzcPhfiG8nYHdva02Uw8tRxP
         krKAnSVQp8xRs7un3UFlrDB/DlxY7TvwnuLohceVspgodA0cHheX4e9ssdTR89fpm1/f
         9mebbI676Ap+aV0VdHLqKPVhXWWC3BfLUn6CLvU8Vq4wbN2fF5Fj9pdNZMRsuM9Jh3K2
         VyaR/aqKXbVocj5WnB1HH6z3MjsA+tBM9QnJSjZcgklHV9UUQaCDGLg0517cFviOSA8B
         DgNbFoqZmEAWbXrRXMZjOx6I/0Vvif6OrVurNKqvLdYKgY6BFcrYWl6oVbpmzUPkwdEa
         wIng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=bGSTmhcT1A+YDeTIlpgIQTYHsX+reXp1jHDYNBfMLqs=;
        b=AZgKJmjmBY0WpcOlEPZPTcNzWQGh1t15BIOopQa8Qmaz9ywDzxHENuV9xVytlUl0PL
         aPNnpVLrtacKlONmKk71YGhaRpyzV37BuytPe0W8fRe84EAlu865cCzRK4jpvXC8V3Rs
         l5rLjEuNKt/9y2qkN0uxuVTH0vi31HeUttlzMT4x1AqTIo20eEf5qOc5YASBt6rKsdOx
         Gs8meaWvAL73yH0uZbTCLpPbZL5GLAIJq738qNTo+Kwhbyw2AG4Y1HKaxVFlXrMGk2Fg
         eoLK9W3hPEh24AYbLzxqzCAjAGXL2l4zUmlbv9rtmx2YUFgRlFdf+eeOI/mdWwdQW1Xp
         /K6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wEfYgmft;
       spf=pass (google.com: domain of 3-1ghxwukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3-1ghXwUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id b6si106149edq.1.2020.07.29.04.09.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Jul 2020 04:09:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-1ghxwukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id z1so6535904wrn.18
        for <kasan-dev@googlegroups.com>; Wed, 29 Jul 2020 04:09:48 -0700 (PDT)
X-Received: by 2002:a7b:c38e:: with SMTP id s14mr8164909wmj.124.1596020987677;
 Wed, 29 Jul 2020 04:09:47 -0700 (PDT)
Date: Wed, 29 Jul 2020 13:09:15 +0200
Message-Id: <20200729110916.3920464-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.rc0.142.g3c755180ce-goog
Subject: [PATCH tip/locking/core v2 1/2] lockdep: Refactor IRQ trace events
 fields into struct
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, mingo@kernel.org
Cc: tglx@linutronix.de, bp@alien8.de, paulmck@kernel.org, will@kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wEfYgmft;       spf=pass
 (google.com: domain of 3-1ghxwukctiszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3-1ghXwUKCTISZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
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

Refactor the IRQ trace events fields, used for printing information
about the IRQ trace events, into a separate struct 'irqtrace_events'.

This improves readability by separating the information only used in
reporting, as well as enables (simplified) storing/restoring of
irqtrace_events snapshots.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Introduce patch, as pre-requisite to "kcsan: Improve IRQ state trace
  reporting".
---
 include/linux/irqflags.h | 13 +++++++++
 include/linux/sched.h    | 11 ++------
 kernel/fork.c            | 16 ++++-------
 kernel/locking/lockdep.c | 58 +++++++++++++++++++++-------------------
 4 files changed, 50 insertions(+), 48 deletions(-)

diff --git a/include/linux/irqflags.h b/include/linux/irqflags.h
index 5811ee8a5cd8..bd5c55755447 100644
--- a/include/linux/irqflags.h
+++ b/include/linux/irqflags.h
@@ -33,6 +33,19 @@
 
 #ifdef CONFIG_TRACE_IRQFLAGS
 
+/* Per-task IRQ trace events information. */
+struct irqtrace_events {
+	unsigned int	irq_events;
+	unsigned long	hardirq_enable_ip;
+	unsigned long	hardirq_disable_ip;
+	unsigned int	hardirq_enable_event;
+	unsigned int	hardirq_disable_event;
+	unsigned long	softirq_disable_ip;
+	unsigned long	softirq_enable_ip;
+	unsigned int	softirq_disable_event;
+	unsigned int	softirq_enable_event;
+};
+
 DECLARE_PER_CPU(int, hardirqs_enabled);
 DECLARE_PER_CPU(int, hardirq_context);
 
diff --git a/include/linux/sched.h b/include/linux/sched.h
index 8d1de021b315..52e0fdd6a555 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -18,6 +18,7 @@
 #include <linux/mutex.h>
 #include <linux/plist.h>
 #include <linux/hrtimer.h>
+#include <linux/irqflags.h>
 #include <linux/seccomp.h>
 #include <linux/nodemask.h>
 #include <linux/rcupdate.h>
@@ -980,17 +981,9 @@ struct task_struct {
 #endif
 
 #ifdef CONFIG_TRACE_IRQFLAGS
-	unsigned int			irq_events;
+	struct irqtrace_events		irqtrace;
 	unsigned int			hardirq_threaded;
-	unsigned long			hardirq_enable_ip;
-	unsigned long			hardirq_disable_ip;
-	unsigned int			hardirq_enable_event;
-	unsigned int			hardirq_disable_event;
 	u64				hardirq_chain_key;
-	unsigned long			softirq_disable_ip;
-	unsigned long			softirq_enable_ip;
-	unsigned int			softirq_disable_event;
-	unsigned int			softirq_enable_event;
 	int				softirqs_enabled;
 	int				softirq_context;
 	int				irq_config;
diff --git a/kernel/fork.c b/kernel/fork.c
index 70d9d0a4de2a..56a640799680 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -2035,17 +2035,11 @@ static __latent_entropy struct task_struct *copy_process(
 	seqcount_init(&p->mems_allowed_seq);
 #endif
 #ifdef CONFIG_TRACE_IRQFLAGS
-	p->irq_events = 0;
-	p->hardirq_enable_ip = 0;
-	p->hardirq_enable_event = 0;
-	p->hardirq_disable_ip = _THIS_IP_;
-	p->hardirq_disable_event = 0;
-	p->softirqs_enabled = 1;
-	p->softirq_enable_ip = _THIS_IP_;
-	p->softirq_enable_event = 0;
-	p->softirq_disable_ip = 0;
-	p->softirq_disable_event = 0;
-	p->softirq_context = 0;
+	memset(&p->irqtrace, 0, sizeof(p->irqtrace));
+	p->irqtrace.hardirq_disable_ip	= _THIS_IP_;
+	p->irqtrace.softirq_enable_ip	= _THIS_IP_;
+	p->softirqs_enabled		= 1;
+	p->softirq_context		= 0;
 #endif
 
 	p->pagefault_disabled = 0;
diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
index c9ea05edce25..7b5800374c40 100644
--- a/kernel/locking/lockdep.c
+++ b/kernel/locking/lockdep.c
@@ -3484,19 +3484,21 @@ check_usage_backwards(struct task_struct *curr, struct held_lock *this,
 
 void print_irqtrace_events(struct task_struct *curr)
 {
-	printk("irq event stamp: %u\n", curr->irq_events);
+	const struct irqtrace_events *trace = &curr->irqtrace;
+
+	printk("irq event stamp: %u\n", trace->irq_events);
 	printk("hardirqs last  enabled at (%u): [<%px>] %pS\n",
-		curr->hardirq_enable_event, (void *)curr->hardirq_enable_ip,
-		(void *)curr->hardirq_enable_ip);
+		trace->hardirq_enable_event, (void *)trace->hardirq_enable_ip,
+		(void *)trace->hardirq_enable_ip);
 	printk("hardirqs last disabled at (%u): [<%px>] %pS\n",
-		curr->hardirq_disable_event, (void *)curr->hardirq_disable_ip,
-		(void *)curr->hardirq_disable_ip);
+		trace->hardirq_disable_event, (void *)trace->hardirq_disable_ip,
+		(void *)trace->hardirq_disable_ip);
 	printk("softirqs last  enabled at (%u): [<%px>] %pS\n",
-		curr->softirq_enable_event, (void *)curr->softirq_enable_ip,
-		(void *)curr->softirq_enable_ip);
+		trace->softirq_enable_event, (void *)trace->softirq_enable_ip,
+		(void *)trace->softirq_enable_ip);
 	printk("softirqs last disabled at (%u): [<%px>] %pS\n",
-		curr->softirq_disable_event, (void *)curr->softirq_disable_ip,
-		(void *)curr->softirq_disable_ip);
+		trace->softirq_disable_event, (void *)trace->softirq_disable_ip,
+		(void *)trace->softirq_disable_ip);
 }
 
 static int HARDIRQ_verbose(struct lock_class *class)
@@ -3699,7 +3701,7 @@ EXPORT_SYMBOL_GPL(lockdep_hardirqs_on_prepare);
 
 void noinstr lockdep_hardirqs_on(unsigned long ip)
 {
-	struct task_struct *curr = current;
+	struct irqtrace_events *trace = &current->irqtrace;
 
 	if (unlikely(!debug_locks))
 		return;
@@ -3752,8 +3754,8 @@ void noinstr lockdep_hardirqs_on(unsigned long ip)
 skip_checks:
 	/* we'll do an OFF -> ON transition: */
 	this_cpu_write(hardirqs_enabled, 1);
-	curr->hardirq_enable_ip = ip;
-	curr->hardirq_enable_event = ++curr->irq_events;
+	trace->hardirq_enable_ip = ip;
+	trace->hardirq_enable_event = ++trace->irq_events;
 	debug_atomic_inc(hardirqs_on_events);
 }
 EXPORT_SYMBOL_GPL(lockdep_hardirqs_on);
@@ -3763,8 +3765,6 @@ EXPORT_SYMBOL_GPL(lockdep_hardirqs_on);
  */
 void noinstr lockdep_hardirqs_off(unsigned long ip)
 {
-	struct task_struct *curr = current;
-
 	if (unlikely(!debug_locks))
 		return;
 
@@ -3784,12 +3784,14 @@ void noinstr lockdep_hardirqs_off(unsigned long ip)
 		return;
 
 	if (lockdep_hardirqs_enabled()) {
+		struct irqtrace_events *trace = &current->irqtrace;
+
 		/*
 		 * We have done an ON -> OFF transition:
 		 */
 		this_cpu_write(hardirqs_enabled, 0);
-		curr->hardirq_disable_ip = ip;
-		curr->hardirq_disable_event = ++curr->irq_events;
+		trace->hardirq_disable_ip = ip;
+		trace->hardirq_disable_event = ++trace->irq_events;
 		debug_atomic_inc(hardirqs_off_events);
 	} else {
 		debug_atomic_inc(redundant_hardirqs_off);
@@ -3802,7 +3804,7 @@ EXPORT_SYMBOL_GPL(lockdep_hardirqs_off);
  */
 void lockdep_softirqs_on(unsigned long ip)
 {
-	struct task_struct *curr = current;
+	struct irqtrace_events *trace = &current->irqtrace;
 
 	if (unlikely(!debug_locks || current->lockdep_recursion))
 		return;
@@ -3814,7 +3816,7 @@ void lockdep_softirqs_on(unsigned long ip)
 	if (DEBUG_LOCKS_WARN_ON(!irqs_disabled()))
 		return;
 
-	if (curr->softirqs_enabled) {
+	if (current->softirqs_enabled) {
 		debug_atomic_inc(redundant_softirqs_on);
 		return;
 	}
@@ -3823,9 +3825,9 @@ void lockdep_softirqs_on(unsigned long ip)
 	/*
 	 * We'll do an OFF -> ON transition:
 	 */
-	curr->softirqs_enabled = 1;
-	curr->softirq_enable_ip = ip;
-	curr->softirq_enable_event = ++curr->irq_events;
+	current->softirqs_enabled = 1;
+	trace->softirq_enable_ip = ip;
+	trace->softirq_enable_event = ++trace->irq_events;
 	debug_atomic_inc(softirqs_on_events);
 	/*
 	 * We are going to turn softirqs on, so set the
@@ -3833,7 +3835,7 @@ void lockdep_softirqs_on(unsigned long ip)
 	 * enabled too:
 	 */
 	if (lockdep_hardirqs_enabled())
-		mark_held_locks(curr, LOCK_ENABLED_SOFTIRQ);
+		mark_held_locks(current, LOCK_ENABLED_SOFTIRQ);
 	lockdep_recursion_finish();
 }
 
@@ -3842,8 +3844,6 @@ void lockdep_softirqs_on(unsigned long ip)
  */
 void lockdep_softirqs_off(unsigned long ip)
 {
-	struct task_struct *curr = current;
-
 	if (unlikely(!debug_locks || current->lockdep_recursion))
 		return;
 
@@ -3853,13 +3853,15 @@ void lockdep_softirqs_off(unsigned long ip)
 	if (DEBUG_LOCKS_WARN_ON(!irqs_disabled()))
 		return;
 
-	if (curr->softirqs_enabled) {
+	if (current->softirqs_enabled) {
+		struct irqtrace_events *trace = &current->irqtrace;
+
 		/*
 		 * We have done an ON -> OFF transition:
 		 */
-		curr->softirqs_enabled = 0;
-		curr->softirq_disable_ip = ip;
-		curr->softirq_disable_event = ++curr->irq_events;
+		current->softirqs_enabled = 0;
+		trace->softirq_disable_ip = ip;
+		trace->softirq_disable_event = ++trace->irq_events;
 		debug_atomic_inc(softirqs_off_events);
 		/*
 		 * Whoops, we wanted softirqs off, so why aren't they?
-- 
2.28.0.rc0.142.g3c755180ce-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200729110916.3920464-1-elver%40google.com.
