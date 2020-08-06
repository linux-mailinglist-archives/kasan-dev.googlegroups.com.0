Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV4FWD4QKGQE4VALV6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id CC0A523DA9F
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Aug 2020 15:17:11 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id u11sf12529291lfg.11
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Aug 2020 06:17:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596719831; cv=pass;
        d=google.com; s=arc-20160816;
        b=yEk9ZXpvXnCyOHxjCZfbAWR0Jn3J8SQoSItWuQ74FEOuZyebrrWDCepfrdxpWxeg/M
         VvIM2cAbAj1GLIkSWkkeq5JX1nMbSbqWE+4Z0rUx+MtTTvgqQdHZnf0iZlrB/XmBUqyS
         k+qlaN/OU6ccGmeq7nhcGJIaj/9Kmeo5U7US5f/swEKjxmiTrzk/A5IRIFmYgvErgRTb
         vLgDHn+xoZFiHc+EiAZz5ROzG5Yi7mUhfTAkihyOdv75YEuyszNRz8C9vBlzyMgpGsaF
         SxKQ5W6ApjxfgdWENMGMes8yPTmubAJCBGt3F2N76JDpzXfx84UBH+tv0+rJyH6RetEY
         tBlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=0AQRNceYqitVwrIAOJPtIXnAEsHlqrwlXyLEDRNEcEA=;
        b=yb4iYRDNWF8fIy48852sn5m+HFz+V08VLBj3z4i7GnPS9G88XtLzs4VxJGJ7TALtM8
         KcZ5qtxvUoJT43KiYkQlkA8OK21lbRA6KaNsHgDW+Wy0cxrNDwzv8YGi/uykRB1OR+ac
         lAY8CynNC1rmoiqOTv8cWEMcAuEieB6V8abICmXPCKxxINezMIs7XUcTVAxZIBrDPIj4
         CowMpzKWRdmqwBlVWQV6GYuP6tSEQKmYcxfQ4WkIvk0lQ0i5sG4OefDgiHaP1rFVNalP
         RGE+N/d1+gZwJaN871d2uAa48hIxD0wX2AqR1oTWXwjnhjiY/NsVcIuIJAfYB27W7GTq
         gUMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kBP+hi0Q;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=0AQRNceYqitVwrIAOJPtIXnAEsHlqrwlXyLEDRNEcEA=;
        b=gpeZhX1T4mkXRvH0B0ItNW2UvVwbbmxyoc7/NPP0LP1u3ht9EOOwUnA8F+jr3fIB6o
         fNNjcNwDyZpBYSqOFQWH7Lv4ICkLI4hNdrNdMDtHU0aMzooVhrBjIMMKA7FDvboUSpkH
         IQxlEWnYkCBOCKZ020ecOMoq0q5tN1hpLmmgfwgzuLmVnoat8Wb7NnOv0ko4ZQ/XvMYu
         ptMOy1hjp9Tw3ZCRM5+65G4tmrbtznGyhCDDDC8/ceAQVHUUm1aQ36nbx+S25lzBolGF
         jM8Kd9pPOmApmkvkWLci4rR4CA7Vp1ItVK/yP78v38vhfop3wCTu6d6UnXeZ2af5kItL
         bnTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0AQRNceYqitVwrIAOJPtIXnAEsHlqrwlXyLEDRNEcEA=;
        b=LyrMrsNJpHqcitaYC4n3n/V4zYwgZdiGDlTnkHza5+Nim1iaU+DqreQjrX0VfA4+4y
         brmoD6l64ZOhdm5jjxvp4GRWTauIvcGrFnnLaAlAd9QWHuTBJbqFIPlhW6WPgMCFWB84
         4tgMCainr6TunfG7jtSeJddOSTBJ1WAFbdhAvLHqOJLX8ODOSF6W3YduDjlX9xT8nXiH
         LYA6qaeBhsexhwcsvoAhQS085DQuLWS+4/NDoTBV8DuP+WC0z6wK+GNC9wbbtqOE11Ct
         JTnbnePKNG40pNn9d5AFr38gUc4S/4tixJ+CKnZJ78HDcK68lFjT1qUwaqgxqmxen/RH
         zThA==
X-Gm-Message-State: AOAM5336ZD7ear7OTx9dy3XWCLAJ0HyOODiFMMHCfLcQvrri8Zh1vsfE
	OKmyxwyGtBdkEKvR3epzgBw=
X-Google-Smtp-Source: ABdhPJwUKlI2nAm6CpKOAJ9nCmM5ctdSIb4z8RTEKBYR7qliCUklV2FA0qmJ106iu+K+kEEyYwc1GA==
X-Received: by 2002:a2e:9acc:: with SMTP id p12mr4111731ljj.363.1596719831266;
        Thu, 06 Aug 2020 06:17:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4845:: with SMTP id 5ls1648999lfy.2.gmail; Thu, 06 Aug
 2020 06:17:10 -0700 (PDT)
X-Received: by 2002:a19:8095:: with SMTP id b143mr3911839lfd.175.1596719830568;
        Thu, 06 Aug 2020 06:17:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596719830; cv=none;
        d=google.com; s=arc-20160816;
        b=IZBJe5o+rU+Trv9/TFvgaA9g21QBLFWhh9DtTh/ZIIbu5J0gKfQtCZLFuTIPbU2W60
         lrhcGZIWX6yV9JElHMTVE8Q5JQfMqKjX3FD3L2QwVtAIB1rV4JWzTxaUfOOsAR/cZuzW
         6Eca0eH/FCl+f1Xc3pKOP5c8cfRXJtbpGd10h4BFIG9viJBXgMooZoTqS21ZAatZX6Xt
         hFKIEotyD4sP33FilSY6zwT9QZcjFn+2Pb7ojMeXBPbyfA+546t1eXdHJkFSRRLm3TOc
         +g14u1H92EFuaewH/FSx3PczoHRSwLTfTxR21eTINMAU1vnz76b4XbHRRzhjBrLbhO3e
         G5nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=C+eYpjO9tZjVIJJgZzQi1cMIXwcXEBDu4nry89JkOG4=;
        b=B4/epNTw9J1lMXHvCyJYWfQmEAWj800KKoMg09dfJgg788tmv2CA5ETw5m5FfTY3S+
         sURdzj0U50ZuRAB7wzUtfrxwtLpQIfbq3059E2IXisU6sJbKNE81JKF43wiktwCAipd6
         vti/HRJq9eAsowUAkZYfTmepHqh3fOhwL7rn8+a/8TNgapNPtWgGCCwFVbpB1j3XexaB
         3m1Ypl2zx+j6xYfwiuGZbXzmc0byz2B+CRcnh/KzbBjih7LUyNiuvAkJSZ3plYDoR7Po
         iw6FZQrWnwy8wLztrdU/8m5cMzXLn8bx6wZn4Q++ewaa+wTGmdyXpqyfp8khdVNt+9jn
         wT9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kBP+hi0Q;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id a7si147695ljp.2.2020.08.06.06.17.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Aug 2020 06:17:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id f12so8130726wru.13
        for <kasan-dev@googlegroups.com>; Thu, 06 Aug 2020 06:17:10 -0700 (PDT)
X-Received: by 2002:a5d:5682:: with SMTP id f2mr7283059wrv.248.1596719829770;
        Thu, 06 Aug 2020 06:17:09 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id a10sm6529088wrx.15.2020.08.06.06.17.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Aug 2020 06:17:07 -0700 (PDT)
Date: Thu, 6 Aug 2020 15:17:02 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org
Cc: Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, fenghua.yu@intel.com,
	"H. Peter Anvin" <hpa@zytor.com>,
	LKML <linux-kernel@vger.kernel.org>, Ingo Molnar <mingo@redhat.com>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Luck, Tony" <tony.luck@intel.com>,
	the arch/x86 maintainers <x86@kernel.org>, yu-cheng.yu@intel.com,
	jgross@suse.com, sdeep@vmware.com,
	virtualization@lists.linux-foundation.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
Message-ID: <20200806131702.GA3029162@elver.google.com>
References: <0000000000007d3b2d05ac1c303e@google.com>
 <20200805132629.GA87338@elver.google.com>
 <20200805134232.GR2674@hirez.programming.kicks-ass.net>
 <20200805135940.GA156343@elver.google.com>
 <20200805141237.GS2674@hirez.programming.kicks-ass.net>
 <20200805141709.GD35926@hirez.programming.kicks-ass.net>
 <CANpmjNN6FWZ+MsAn3Pj+WEez97diHzqF8hjONtHG15C2gSpSgw@mail.gmail.com>
 <CANpmjNNy3XKQqgrjGPPKKvXhAoF=mae7dk8hmoS4k4oNnnB=KA@mail.gmail.com>
 <20200806074723.GA2364872@elver.google.com>
 <20200806113236.GZ2674@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200806113236.GZ2674@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kBP+hi0Q;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, Aug 06, 2020 at 01:32PM +0200, peterz@infradead.org wrote:
> On Thu, Aug 06, 2020 at 09:47:23AM +0200, Marco Elver wrote:
> > Testing my hypothesis that raw then nested non-raw
> > local_irq_save/restore() breaks IRQ state tracking -- see the reproducer
> > below. This is at least 1 case I can think of that we're bound to hit.
...
> 
> /me goes ponder things...
> 
> How's something like this then?
> 
> ---
>  include/linux/sched.h |  3 ---
>  kernel/kcsan/core.c   | 62 ++++++++++++++++++++++++++++++++++++---------------
>  2 files changed, 44 insertions(+), 21 deletions(-)

Thank you! That approach seems to pass syzbot (also with
CONFIG_PARAVIRT) and kcsan-test tests.

I had to modify it some, so that report.c's use of the restore logic
works and not mess up the IRQ trace printed on KCSAN reports (with
CONFIG_KCSAN_VERBOSE).

I still need to fully convince myself all is well now and we don't end
up with more fixes. :-) If it passes further testing, I'll send it as a
real patch (I want to add you as Co-developed-by, but would need your
Signed-off-by for the code you pasted, I think.)

Thanks,
-- Marco

------ >8 ------

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 9147ff6a12e5..b1d5dca10aa5 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -4,6 +4,7 @@
 #include <linux/bug.h>
 #include <linux/delay.h>
 #include <linux/export.h>
+#include <linux/ftrace.h>
 #include <linux/init.h>
 #include <linux/kernel.h>
 #include <linux/list.h>
@@ -291,13 +292,28 @@ static inline unsigned int get_delay(void)
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
+	int			hardirqs;
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
@@ -305,6 +321,34 @@ void kcsan_restore_irqtrace(struct task_struct *task)
 #endif
 }
 
+static void kcsan_irq_save(struct kcsan_irq_state *irq_state) {
+#ifdef CONFIG_TRACE_IRQFLAGS
+	current->kcsan_save_irqtrace = current->irqtrace;
+	irq_state->hardirqs = lockdep_hardirqs_enabled();
+#endif
+	if (!kcsan_interrupt_watcher) {
+		raw_local_irq_save(irq_state->flags);
+		kcsan_disable_current(); /* Lockdep might WARN. */
+		lockdep_hardirqs_off(CALLER_ADDR0);
+		kcsan_enable_current();
+	}
+}
+
+static void kcsan_irq_restore(struct kcsan_irq_state *irq_state) {
+	if (!kcsan_interrupt_watcher) {
+#ifdef CONFIG_TRACE_IRQFLAGS
+		if (irq_state->hardirqs) {
+			kcsan_disable_current(); /* Lockdep might WARN. */
+			lockdep_hardirqs_on_prepare(CALLER_ADDR0);
+			lockdep_hardirqs_on(CALLER_ADDR0);
+			kcsan_enable_current();
+		}
+#endif
+		raw_local_irq_restore(irq_state->flags);
+	}
+	kcsan_restore_irqtrace(current);
+}
+
 /*
  * Pull everything together: check_access() below contains the performance
  * critical operations; the fast-path (including check_access) functions should
@@ -350,11 +394,13 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
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
@@ -387,7 +433,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	unsigned long access_mask;
 	enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
 	unsigned long ua_flags = user_access_save();
-	unsigned long irq_flags = 0;
+	struct kcsan_irq_state irqstate;
 
 	/*
 	 * Always reset kcsan_skip counter in slow-path to avoid underflow; see
@@ -412,14 +458,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
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
@@ -559,9 +598,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
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
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200806131702.GA3029162%40elver.google.com.
