Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMEQ234AKGQELSYGBZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 649EC225E18
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jul 2020 14:04:02 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id 65sf10306236plf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jul 2020 05:04:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595246641; cv=pass;
        d=google.com; s=arc-20160816;
        b=WSBaRK5SPFLi5Zn0RScawQHuAzUZ95e4cRckkSltQ7osaQny/Z2KuoUqDN6uHNrPbQ
         6TDafmC9uYzqGAjauZhYxndWp1qOngLCnm9xq6XwBQAA0MRbtT0l57uNJvHekG5Uv2s+
         Gh0/Dl3J5dj3jpfTvOzeqiBkBCHJhIYFjOtfYlK6bxXoKJe01hLsIMXApFOCalnCikwC
         tl7BLWNcMZ/FOhFyLG/u3kEAwg2iJnn/NfNyjE7VW6ZADcSotbPKIja6dkbwzQpwV1ii
         igaSur6Lwejcbgko3wK2d5Fi2JZNNIJoS/H1CauexQxvM9SyoU5GkdDH65nNR6fYPKwo
         WVbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=3wjccQsUE3q8t52kcbyEUlBlqN2XByGkE+iYU4b1QoI=;
        b=mzs82VPvWsfzN51DMCNsT7zGpHVdVP5yjmenI8voB1Yqvr5+PK2iC9JRq2J5TIrQ8l
         W3w0o7ewLDJTy3BqY8cFkp/TA1ijAmSd4sooyMxOKeOZelYZTvulG2o5klISB9jt0aXq
         dgjaI2aMFGk++QQq145qr5M0RQaM5CfgviZLLbRAjPfFBNODageT3EOkrYDdRZXHcrjM
         Wi4K4ltc1FM2AcFBe4aFelJ5IJRZp9KF0FwJjuLL9HUlrHVAwqnnpc/KLDiHrHhM+gw8
         23GsokcBZT2XW/0c/5vIIRMsf8B/g3ajnBKGb9BRg8jhFPHAIK8JpWtrJk2nKbacYNnG
         T3IQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iASTdcQE;
       spf=pass (google.com: domain of 3l4gvxwukczq29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3L4gVXwUKCZQ29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=3wjccQsUE3q8t52kcbyEUlBlqN2XByGkE+iYU4b1QoI=;
        b=jECs5ZuRpRhOmKU2CdHBAxG6O/WBKhADY1TMthmuDIq2Tzz1YtRnbufUz5Kx/ghfgA
         +fL+U0wVdqaaGY3fKpuoreooRV4i5IhKFX2PYanqF4FOL3AD/HJ8okxcp3luZB1MrY0D
         //oYKycTPrPl041NjcUD3JrEOPuZ5m7HVTm4fnrZZAQUKaUBisIBEAOcTawAMYwKyB3r
         p/nvtc6PzwKhel/pBh04Z1gWFQERt/1WvvyWcWkuZjKiZQSgHFprW1nmyM9KR8aEQMt2
         TMMpqK+GnfksWyijnemPFYc+d5fiU8T3Ch5MlH38aG1e92guulPwMpncJu8Q9mX+NTiM
         BiQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3wjccQsUE3q8t52kcbyEUlBlqN2XByGkE+iYU4b1QoI=;
        b=kUZM5B3mt1FncowvYe7vhtOatsZmGymGamot64G3fsNtSSr18R0QYGEPwAuO25GW1R
         W0Vf02xS1jims29r0g/HjGjyllVPc5/0BCQu5/jAlPYjplDNbmxIE/Zw1Z9/co5GF55W
         +3tLnGH2SQ0+3kIUo08OghnUdAlKeei/cLjN9pWYeP4wHZLRjufUJGhx43wm/fUBw0as
         4UqjumbAp1yc83yC+rLY968RNrr18lGZBdAmOR7Xjn6LEb6nRVxcAQetwndSJly8mfqN
         vfipM9I7OhuZB26wE2TisDkIturffq/fx0enn3bAIJSsCF0yXpBLFGGgVqIq3tJGZ3d7
         b8FQ==
X-Gm-Message-State: AOAM533R3EOsKDRz2Atoui0OIHEIBFrbDDSzaCcMYQXiaSV6ioBjomEM
	WuGID8o1Npv87medvVVK07g=
X-Google-Smtp-Source: ABdhPJzkGP+kx8WHyKYFtF5tOzhAMOom3yAn7yqgRwVXtesr3UFl9uEDBaeZDmrfF8zzuNd+AToIpA==
X-Received: by 2002:a17:90a:3769:: with SMTP id u96mr24159381pjb.198.1595246640818;
        Mon, 20 Jul 2020 05:04:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a16:: with SMTP id w22ls8152960pjn.1.canary-gmail;
 Mon, 20 Jul 2020 05:04:00 -0700 (PDT)
X-Received: by 2002:a17:90b:46d0:: with SMTP id jx16mr21829186pjb.222.1595246640368;
        Mon, 20 Jul 2020 05:04:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595246640; cv=none;
        d=google.com; s=arc-20160816;
        b=TGo+5dVpZDkQyl7aoTPjiAycdjJiewMVwTDys2Re8L3b4+LUjKPQXaDXupMbzRLhBy
         6dNCTk+EQI4mbyZJytBNCFo4G3IiaXxsOiUVhP43d9S19h0ULo2N00pm2OmLa/RlDICr
         yqqC53amivCSgc095nopuRlZSvqtvLbbIflvO5qOUH50Pm8coh3wRNTddyIVQDUqANac
         ACBi8FXU1E84GDPvqPpnIHTMEyMqIY5blpfhW/4MRxndue21+2HFyhI76DbrsZm80I8m
         y3EYoUNjK53z6ggIBPjR75nvR9i1ezOqUnVzsZ9/Wy9Xkcdye+297qONwKcpGlTeA9js
         GNsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=hO0JBht5uOWoAmAL+7KjQJEygdsPtbQCk3P9CwJY3U0=;
        b=jLE/VeMysqHIxnae8+hLeYQHQgaDjR53ivEvo/xRsZwQgkzS8ft2RuPDlePLTdzama
         KxluDEEiCyMEwscVG7da7IwwOqAnT113SFuXHihctcThx7ttLDtgAgLx/VG4ehfH7wHY
         dXX5yb4+dnvXCG8noilR58JrFsXXW8xPLl4OK/9flMMH9hqLGjbAycQpcPYJksWQiL2b
         Te32eECjizmie0ErES64SVY9Hqzq0zaUoWGRGlcZzJzbSQ90jfyMBS9IJuLcH3bAUNqv
         xNC1iiXNCA6tTlXoCcXGz7ENSc9TLFyUNK7Eg60o/rTQQ+b6HuFGzmaZ8th1PYTOTKdj
         nZmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iASTdcQE;
       spf=pass (google.com: domain of 3l4gvxwukczq29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3L4gVXwUKCZQ29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id y197si880815pfc.4.2020.07.20.05.04.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jul 2020 05:04:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3l4gvxwukczq29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id 1so6666505qkm.19
        for <kasan-dev@googlegroups.com>; Mon, 20 Jul 2020 05:04:00 -0700 (PDT)
X-Received: by 2002:a0c:b9a8:: with SMTP id v40mr21901301qvf.90.1595246639491;
 Mon, 20 Jul 2020 05:03:59 -0700 (PDT)
Date: Mon, 20 Jul 2020 14:03:48 +0200
Message-Id: <20200720120348.2406588-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.rc0.105.gf9edc3c819-goog
Subject: [PATCH tip/locking/core] kcsan: Improve IRQ state trace reporting
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org
Cc: bp@alien8.de, tglx@linutronix.de, mingo@kernel.org, paulmck@kernel.org, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iASTdcQE;       spf=pass
 (google.com: domain of 3l4gvxwukczq29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3L4gVXwUKCZQ29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
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

To improve the general usefulness of the IRQ state trace information
with KCSAN enabled, save and restore the trace information when entering
and exiting the KCSAN runtime as well as when generating a KCSAN report.

Without this, reporting the IRQ state trace (whether via a KCSAN report
or outside of KCSAN via a lockdep report) is rather useless due to
continuously being touched by KCSAN. This is because if KCSAN is
enabled, every instrumented memory access causes changes to IRQ state
tracking information (either by KCSAN disabling/enabling interrupts or
taking report_lock when generating a report).

Before "lockdep: Prepare for NMI IRQ state tracking", KCSAN avoided
touching the IRQ state trace via raw_local_irq_save/restore() and
lockdep_off/on().

Fixes: 248591f5d257 ("kcsan: Make KCSAN compatible with new IRQ state tracking")
Signed-off-by: Marco Elver <elver@google.com>
---


Hi, Peter,

If this is reasonable, please take it into the branch that currently has
the series around "lockdep: Prepare for NMI IRQ state tracking"
(tip/locking/core?).

Thanks,
-- Marco


---
 include/linux/sched.h | 13 +++++++++++++
 kernel/kcsan/core.c   | 39 +++++++++++++++++++++++++++++++++++++++
 kernel/kcsan/kcsan.h  |  7 +++++++
 kernel/kcsan/report.c |  3 +++
 4 files changed, 62 insertions(+)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index 692e327d7455..ca5324b1657c 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1199,6 +1199,19 @@ struct task_struct {
 #endif
 #ifdef CONFIG_KCSAN
 	struct kcsan_ctx		kcsan_ctx;
+#ifdef CONFIG_TRACE_IRQFLAGS
+	struct {
+		unsigned int		irq_events;
+		unsigned long		hardirq_enable_ip;
+		unsigned long		hardirq_disable_ip;
+		unsigned int		hardirq_enable_event;
+		unsigned int		hardirq_disable_event;
+		unsigned long		softirq_disable_ip;
+		unsigned long		softirq_enable_ip;
+		unsigned int		softirq_disable_event;
+		unsigned int		softirq_enable_event;
+	} kcsan_save_irqtrace;
+#endif
 #endif
 
 #ifdef CONFIG_FUNCTION_GRAPH_TRACER
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 732623c30359..7e8347c14530 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -291,6 +291,36 @@ static inline unsigned int get_delay(void)
 				0);
 }
 
+void kcsan_save_irqtrace(struct task_struct *task)
+{
+#ifdef CONFIG_TRACE_IRQFLAGS
+	task->kcsan_save_irqtrace.irq_events = task->irq_events;
+	task->kcsan_save_irqtrace.hardirq_enable_ip = task->hardirq_enable_ip;
+	task->kcsan_save_irqtrace.hardirq_disable_ip = task->hardirq_disable_ip;
+	task->kcsan_save_irqtrace.hardirq_enable_event = task->hardirq_enable_event;
+	task->kcsan_save_irqtrace.hardirq_disable_event = task->hardirq_disable_event;
+	task->kcsan_save_irqtrace.softirq_disable_ip = task->softirq_disable_ip;
+	task->kcsan_save_irqtrace.softirq_enable_ip = task->softirq_enable_ip;
+	task->kcsan_save_irqtrace.softirq_disable_event = task->softirq_disable_event;
+	task->kcsan_save_irqtrace.softirq_enable_event = task->softirq_enable_event;
+#endif
+}
+
+void kcsan_restore_irqtrace(struct task_struct *task)
+{
+#ifdef CONFIG_TRACE_IRQFLAGS
+	task->irq_events = task->kcsan_save_irqtrace.irq_events;
+	task->hardirq_enable_ip = task->kcsan_save_irqtrace.hardirq_enable_ip;
+	task->hardirq_disable_ip = task->kcsan_save_irqtrace.hardirq_disable_ip;
+	task->hardirq_enable_event = task->kcsan_save_irqtrace.hardirq_enable_event;
+	task->hardirq_disable_event = task->kcsan_save_irqtrace.hardirq_disable_event;
+	task->softirq_disable_ip = task->kcsan_save_irqtrace.softirq_disable_ip;
+	task->softirq_enable_ip = task->kcsan_save_irqtrace.softirq_enable_ip;
+	task->softirq_disable_event = task->kcsan_save_irqtrace.softirq_disable_event;
+	task->softirq_enable_event = task->kcsan_save_irqtrace.softirq_enable_event;
+#endif
+}
+
 /*
  * Pull everything together: check_access() below contains the performance
  * critical operations; the fast-path (including check_access) functions should
@@ -336,9 +366,11 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 	flags = user_access_save();
 
 	if (consumed) {
+		kcsan_save_irqtrace(current);
 		kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_MAYBE,
 			     KCSAN_REPORT_CONSUMED_WATCHPOINT,
 			     watchpoint - watchpoints);
+		kcsan_restore_irqtrace(current);
 	} else {
 		/*
 		 * The other thread may not print any diagnostics, as it has
@@ -396,6 +428,12 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		goto out;
 	}
 
+	/*
+	 * Save and restore the IRQ state trace touched by KCSAN, since KCSAN's
+	 * runtime is entered for every memory access, and potentially useful
+	 * information is lost if dirtied by KCSAN.
+	 */
+	kcsan_save_irqtrace(current);
 	if (!kcsan_interrupt_watcher)
 		local_irq_save(irq_flags);
 
@@ -539,6 +577,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 out_unlock:
 	if (!kcsan_interrupt_watcher)
 		local_irq_restore(irq_flags);
+	kcsan_restore_irqtrace(current);
 out:
 	user_access_restore(ua_flags);
 }
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index 763d6d08d94b..29480010dc30 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -9,6 +9,7 @@
 #define _KERNEL_KCSAN_KCSAN_H
 
 #include <linux/kcsan.h>
+#include <linux/sched.h>
 
 /* The number of adjacent watchpoints to check. */
 #define KCSAN_CHECK_ADJACENT 1
@@ -22,6 +23,12 @@ extern unsigned int kcsan_udelay_interrupt;
  */
 extern bool kcsan_enabled;
 
+/*
+ * Save/restore IRQ flags state trace dirtied by KCSAN.
+ */
+void kcsan_save_irqtrace(struct task_struct *task);
+void kcsan_restore_irqtrace(struct task_struct *task);
+
 /*
  * Initialize debugfs file.
  */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 6b2fb1a6d8cd..9d07e175de0f 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -308,6 +308,9 @@ static void print_verbose_info(struct task_struct *task)
 	if (!task)
 		return;
 
+	/* Restore IRQ state trace for printing. */
+	kcsan_restore_irqtrace(task);
+
 	pr_err("\n");
 	debug_show_held_locks(task);
 	print_irqtrace_events(task);
-- 
2.28.0.rc0.105.gf9edc3c819-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200720120348.2406588-1-elver%40google.com.
