Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7VRQX4QKGQERH5IJ4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 126C4231D38
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jul 2020 13:09:52 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id b22sf9693851otp.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jul 2020 04:09:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596020991; cv=pass;
        d=google.com; s=arc-20160816;
        b=eQn54chDYGeKnIt9gEkbOAClugGICjCLp4f9A0TszS5eGmPeJF0hR96tpTUDm7bbYb
         SSZJQcYE0cE0HemWgQD0dWigX3S0r3L1j9swHsGp+DSQUP6sLw+9jORxyNefyULSAXYq
         ys6t+hNbXnCOP7za+eVzwob6D37tcB1vh5pJyLOAD2IfutxiM09BP1DH0DrGaKr4zPjz
         XNxGpdV8HOCoJBwEUq5XzJm1pNn7hHC5EEJixlO+qcPSM0R4e4q28kzR4T62mtjoR7Dn
         5c1aYue5oCtzEhS5Np0ESZPsanVVi+QHU7fRRZsQLR4s2XcO1SAXWAhUhPgtOmZewZqc
         1SRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=zQk2FZtH7EvnhGnnmK1Jxdg0F2htNqD/6LxwUVSqq/s=;
        b=rFMdAB2Uty4qgixEdganmmSAOOkRWQ5ulC37TI7Jd1glNry7lePeP+clEBqZmI9giY
         P9IZtHIVc0H62MKDfjavxU5Utou6WrNNGcVbCHU91RPCY+hkt4cf9YA5nRchi7Zb5R5W
         7C1jmDfEIriC0fhdwrBitPSUKEcp506TJwuj2p7FCtdsUdG/dudz1Jus4K1bzk0X8SIA
         PNsA/vEPotsm0noV6HRCLCzqrIMkEKVT5SyldtqHlCyQ5b0TljsHnV3ahzqDguLyG/w8
         YZ0HCXXKEu4+P6IMcechqQ1rNS6uMdCymf/gPlXegesfzR/SVRAFPUrhEnJl8mlmtfJk
         gsgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fBDgIpc0;
       spf=pass (google.com: domain of 3_vghxwukctqubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3_VghXwUKCTQUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zQk2FZtH7EvnhGnnmK1Jxdg0F2htNqD/6LxwUVSqq/s=;
        b=sIQMvHEm8yksr+zzum3KX9Szq5KScHxtxx+QzoeXnS8PimlrkBPFScUutuVe3J14mc
         7Hrq4MEBCZ7oBOBVdPMAlZeXnoQ89UxNZdSye2NSi9Wwyy58eb2L8haUsjs6ZSWj0b1M
         0bg+c1vHuMLDg72099ZMuRJWvZEPsgOPDQrNYjibs6361LSlQQwaKFOH478CpdlOCxhh
         IVKcmGagGkgbV4DDJw1wQTQWbfUCZjgUk/mgx/MBOEi/P1oze/HmUitIIU/nnsvH7mUk
         TcVcsyxKDqPHzYdqEbDw3hmJlkvbDYQuBJsKlWYk5OWF6fLAtfnAPtUaVu3OjFdqZVlN
         ANOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zQk2FZtH7EvnhGnnmK1Jxdg0F2htNqD/6LxwUVSqq/s=;
        b=tua7l5215JXxjBz1ry2EE4+ZnV7zD+tEsfQ2gf5leRQUDVRXbODfGU02kLmsCmNLdD
         6plk62+kVjVzJNTJB2T91E7KsdgjpYlblPLRM/vmeWudymd2lhHVbgmkaiH6nzITNumr
         CIFyVgNT+w4U7UPH8QDTR3p2ZfRcG1Pl1c84Y5Br7GsqFAhYvtYnRORqUAGgM1c0AqSg
         k2zt7Xe/IjgHeuHTLk438fq0wwG5mYCq4+au94ZkNiGte95O3Hs3jAVFnOdlI7M2ddUt
         Ty7QmRmo0EwYL42gLQ/+hgyvdFo3QknIZAu7X+8PVHA14s4gfun0uyM4ck9iJhecGX5Y
         1ArA==
X-Gm-Message-State: AOAM532b+pZg4z1SkZfUvc2ysziN4VW3KtE4+YFCYiSNQT+yskw0bSul
	OaBSbUEM8O8Z+VlY3fdspgg=
X-Google-Smtp-Source: ABdhPJzBBvYRiGEbaDDWclzaoJ+SbEyZfES2Rc0MGlmopP6hsgbibp7Q/MShxpOpNZrOvdOwvKPfsw==
X-Received: by 2002:aca:5296:: with SMTP id g144mr7156316oib.129.1596020990832;
        Wed, 29 Jul 2020 04:09:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:8cd:: with SMTP id 196ls377360oii.4.gmail; Wed, 29 Jul
 2020 04:09:50 -0700 (PDT)
X-Received: by 2002:aca:a983:: with SMTP id s125mr7275012oie.30.1596020990480;
        Wed, 29 Jul 2020 04:09:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596020990; cv=none;
        d=google.com; s=arc-20160816;
        b=vqfSvTWEEF8ZlohqWHmxbAQqK7blMycoJOFgBLFJs6KButBhXqvtZxeEsWVGG9ItPF
         BcN1/rb85PY9xsQOO3KT5H6BuG89WqJAZmXEE6cxstvfDUDzh17M3j/+NRZ01RaR1WbI
         Ig2SYN+d0a4BitZjY+F854KU8aG7sWNY6zEEI5FzNfpin1v7w5101MjRR0hwCYc2LBGB
         Mp8SwapQGJjkjnCZuKgqdAAp9pTs8R1/CePZLY1Vu6vL/KIe9LshmGQBeGRKsBUI7PdM
         Pj/p8RcwpTDC5eJlW25LbYh3rjaiyewzP24Sug5knUbwC2DtRxcwv3qHYQ5be4uCok+A
         tlkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=hCZz7pD2WpbFrBmK0yvXbCAHYFWZieUEyvav6WgX9Ww=;
        b=a/2c9rHHQPIuQtDNCE4vCmBe5W/fM0A0VcUMFA/qiAi8AKZmV1kDy1AJ9LnfsSDa5D
         mhSDKrgn2jmxxfH/bs7DSKI2QXqQSIMDSNliE82M51YvIFhE10A8t4Y7XLj/SdD+edK1
         DQUln7oOJ0bVDWf63g9jExj5uYjQv/Zjv6Ne6j78SGOugLqr9ffwDcR/LsaEtYE3Zn1C
         hR6Y80t2tA57Cwt+Wo7ePmuZN4HZvLPf1sGiq/Jb4hpxhX5heWR1GezevMXHOayCRaiD
         S97RPUEvv5vWeM2nWrB1Yl4fqZhMcXelR6MowAWj325wvJkiOeGo9N0Nf4fpoz3Gvlaf
         Gecg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fBDgIpc0;
       spf=pass (google.com: domain of 3_vghxwukctqubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3_VghXwUKCTQUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id m21si124819oih.4.2020.07.29.04.09.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Jul 2020 04:09:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_vghxwukctqubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id j207so22621119ybg.20
        for <kasan-dev@googlegroups.com>; Wed, 29 Jul 2020 04:09:50 -0700 (PDT)
X-Received: by 2002:a25:7908:: with SMTP id u8mr30559476ybc.144.1596020989922;
 Wed, 29 Jul 2020 04:09:49 -0700 (PDT)
Date: Wed, 29 Jul 2020 13:09:16 +0200
In-Reply-To: <20200729110916.3920464-1-elver@google.com>
Message-Id: <20200729110916.3920464-2-elver@google.com>
Mime-Version: 1.0
References: <20200729110916.3920464-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.rc0.142.g3c755180ce-goog
Subject: [PATCH tip/locking/core v2 2/2] kcsan: Improve IRQ state trace reporting
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, peterz@infradead.org, mingo@kernel.org
Cc: tglx@linutronix.de, bp@alien8.de, paulmck@kernel.org, will@kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fBDgIpc0;       spf=pass
 (google.com: domain of 3_vghxwukctqubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3_VghXwUKCTQUblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
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

To improve the general usefulness of the IRQ state trace events with
KCSAN enabled, save and restore the trace information when entering and
exiting the KCSAN runtime as well as when generating a KCSAN report.

Without this, reporting the IRQ trace events (whether via a KCSAN report
or outside of KCSAN via a lockdep report) is rather useless due to
continuously being touched by KCSAN. This is because if KCSAN is
enabled, every instrumented memory access causes changes to IRQ trace
events (either by KCSAN disabling/enabling interrupts or taking
report_lock when generating a report).

Before "lockdep: Prepare for NMI IRQ state tracking", KCSAN avoided
touching the IRQ trace events via raw_local_irq_save/restore() and
lockdep_off/on().

Fixes: 248591f5d257 ("kcsan: Make KCSAN compatible with new IRQ state tracking")
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Use simple struct copy, now that the IRQ trace events are in a struct.

Depends on:  "lockdep: Prepare for NMI IRQ state tracking"
---
 include/linux/sched.h |  4 ++++
 kernel/kcsan/core.c   | 23 +++++++++++++++++++++++
 kernel/kcsan/kcsan.h  |  7 +++++++
 kernel/kcsan/report.c |  3 +++
 4 files changed, 37 insertions(+)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index 52e0fdd6a555..060e9214c8b5 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1184,8 +1184,12 @@ struct task_struct {
 #ifdef CONFIG_KASAN
 	unsigned int			kasan_depth;
 #endif
+
 #ifdef CONFIG_KCSAN
 	struct kcsan_ctx		kcsan_ctx;
+#ifdef CONFIG_TRACE_IRQFLAGS
+	struct irqtrace_events		kcsan_save_irqtrace;
+#endif
 #endif
 
 #ifdef CONFIG_FUNCTION_GRAPH_TRACER
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 732623c30359..0fe068192781 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -291,6 +291,20 @@ static inline unsigned int get_delay(void)
 				0);
 }
 
+void kcsan_save_irqtrace(struct task_struct *task)
+{
+#ifdef CONFIG_TRACE_IRQFLAGS
+	task->kcsan_save_irqtrace = task->irqtrace;
+#endif
+}
+
+void kcsan_restore_irqtrace(struct task_struct *task)
+{
+#ifdef CONFIG_TRACE_IRQFLAGS
+	task->irqtrace = task->kcsan_save_irqtrace;
+#endif
+}
+
 /*
  * Pull everything together: check_access() below contains the performance
  * critical operations; the fast-path (including check_access) functions should
@@ -336,9 +350,11 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
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
@@ -396,6 +412,12 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
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
 
@@ -539,6 +561,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
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
2.28.0.rc0.142.g3c755180ce-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200729110916.3920464-2-elver%40google.com.
