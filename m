Return-Path: <kasan-dev+bncBCV5TUXXRUIBBX6UV74QKGQEZQRSAHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C29923D9F7
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Aug 2020 13:32:49 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 4sf7398713pjf.5
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Aug 2020 04:32:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596713568; cv=pass;
        d=google.com; s=arc-20160816;
        b=iPYL3v8eluB2OlWpoj4kZP39BuOoLMrJ+c57bfvqndbC/smBVc83xizDhnxSiUCNtp
         2jQW90zW3lW3jWxd0Ql2a5KiuWYk2r1TrW1UknooU75dHNfJ781z0G+GDWezK4LCORga
         Z2VeInBnLFFrKDI+IVoEFVlU+uORvajwcJzArlZFsG0edtMi8PI9qoIM70t8quZ1WkSO
         MGnuJntyQbsjCZr6o+YtKrHl+ZrhgJCwmX5ELxyMl0P+REy+VobXpQzM0B+nZ0Dl8wXj
         G/9ctGMMARt49EPjFOhnYB/LcLp5446EJwvQjbtbSNnZk/S1Lm1cw0LCi0vrpAegMKXW
         gDIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=nZzACEAQuCP1DwPNX22qKUR4cyegUOxvNQdOR8sE2JE=;
        b=jD7G7BxAEaXM6Vo7kwPtsgWTAHY3bTvmzZTfzdC34txoUSqssgCi3xghrynI+iXDSU
         ArBbv41+wlEMPoI4/c6Biw9fHsIduOvXgNRmkfJGukspHOUR+BfbV8p2vQF4ciJuUZqT
         EUdAX6vOBkojmdpJvAPHbC5dKFd8lRH90IdrcqLgAXR7j16x5mkNwA4Kc/x/Oi4onqW7
         F3jLIhUxbYW+wBy/5TZ+Xgx/RVQUsNMpGpnLzf6tU9K6LmyLv1X8RbZ5j2UopiA4KNo0
         1tHEbyM8xd6ibHDwuL7tl+y83kJwtlBUllmruMGtozuM/rB7jUgKpjRnL7BOE6FJWWJs
         8lhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=0sTLMzAi;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nZzACEAQuCP1DwPNX22qKUR4cyegUOxvNQdOR8sE2JE=;
        b=ONu1kwp7c6RtZSl+RDi036mvkhDDCNmEisYAGJpR2K3usDvYu6oPFEn5/kPLjAvznS
         zvanzERdWmJML3lcXvZJgX3RyUc6uuEs9MHOCmat+h8bb5eEZn4+ZC2T+nagNRIYBlGr
         IAX11m4R6Yv2OYW5mU6mRVDOYGhN2UoXwRyYs81wsQ/9DKg2BEHPEYXQM/3yBW/UgsKD
         R8ZpaIoaDySqsDSG1U4EVHVkgCOZ9vVLqvpsm+6okAZpZvxeq5bpCOsKEwdq8E8RZTs6
         wIvsn6Qi0BvOnkW9DpTD2rfhB99vvra//bXUXtaYDibML7WrQEG1WUmiMiUx1yrKITfv
         2IEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nZzACEAQuCP1DwPNX22qKUR4cyegUOxvNQdOR8sE2JE=;
        b=NdJla1a/dN+JqmBDY4fZ569gap4uPOYvYit4Y+YsbBZACPoYaxiCP+rPbccp7/++ky
         SVn/naHzBtwhOIuYlrgtbTNRxx0ac/pfOIHSkQk/Gu7LdTyZK1KcfXF1FBUmsrno2ZXB
         mHJhLVQDEEk2UDMaqOU2aDu//wxtYS6GwWzTE+sMEwYijt8BS5rDcGYDXB/ngkscGNHe
         LZOwALweRT6rO4FkA3mnAY0q2JMDIZCxccQ9KOSFIc9cFlGPfd1SyNntBNkhV9KzG/oz
         7nErlaenmPBN2MCAmVhGElosa3bCjUViMkZn7o8+6Qz6Bgtx3OoeTB5gyZJC/f6Ljhw2
         QMKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328+jAxjNBX/tZ12ugOyPfJ+1mU86CJmKL0Czla0K+5DqmmHlkE
	QQCILwPHVVFlLh5HMqxhPJE=
X-Google-Smtp-Source: ABdhPJzBEd2r/wHIeRgmitkWTToAoZJZRzgYYLolCMWeTWT9evaOzvOmWjYto1LzfKMXciGhRAvrRA==
X-Received: by 2002:a17:90b:803:: with SMTP id bk3mr8132138pjb.57.1596713567841;
        Thu, 06 Aug 2020 04:32:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb8f:: with SMTP id m15ls2463915pls.5.gmail; Thu, 06
 Aug 2020 04:32:47 -0700 (PDT)
X-Received: by 2002:a17:90a:7a83:: with SMTP id q3mr8198969pjf.178.1596713567329;
        Thu, 06 Aug 2020 04:32:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596713567; cv=none;
        d=google.com; s=arc-20160816;
        b=nJX53mDq8AR21LqNgh+vPifycwlsxCZH9AELlUVwQs2Uah1XhhAo3fsXs5nR2M7bU9
         XmU0rtc1fP8MYxC1i7pGHH+9ZkpbJW49v6q6zVnHVIARJ+iZv8K3hlOUDYqKDPpL1T2Q
         jSNYdtiJc49IAgnPTRVA3E5wj3vNHL5f5lGByrQEI3unaOMBbjevD26eQq/rCicUMiSx
         kLA9hWHlobPtrDW6nUcm/5fEoc6eNbaQa+s9v2GsdfD1lmCslJbaU73mP21U+qdzjuVf
         RKYRhxLx0aOxmgXgG2bB7HMvmXKjUS+LSDWBn2UJcW+gX3q9+qWnnrdjftwlu6qmB/Bc
         n21A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=HOHNK/Wwh4r+dLOwnbPsU+//UraXJR2JWx5StwnIbMY=;
        b=Ann7QXKXubr6wA8W8Zy9nl3P8t5X4i9U+TarI46EUshsijVEnN33Pc9w8gy2sEsO5f
         5cd9LTJ4jWtwh55z9IhWOeLjnM6qkUkcS+AyfnzkwpOrH0bDD4ByJBE1AbwPiXpNVqVw
         ByzhSH4uw+d3lp1+us55es21UfZOpcqkagLxTh11TCrDdR8ecjclzer9DjyeE8O9XRou
         oPyr98CaSlMBAHqvIBEQapIGKG0WreFVaNjinZUWLzNbpAz7O1eEpvmwpNXVRvGJeZPp
         TjDqYTJSzt1ZF3rDdRya43OCRJU7s/uJ0NV02QlT8toh2X9gJ+fuzZtaWeytq5FEE6G+
         FfkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=0sTLMzAi;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id 90si14973plb.3.2020.08.06.04.32.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Aug 2020 04:32:47 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1k3e8V-0006OU-91; Thu, 06 Aug 2020 11:32:39 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 33BE7300446;
	Thu,  6 Aug 2020 13:32:36 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 0DD6F2B61F1E7; Thu,  6 Aug 2020 13:32:36 +0200 (CEST)
Date: Thu, 6 Aug 2020 13:32:36 +0200
From: peterz@infradead.org
To: Marco Elver <elver@google.com>
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
Message-ID: <20200806113236.GZ2674@hirez.programming.kicks-ass.net>
References: <0000000000007d3b2d05ac1c303e@google.com>
 <20200805132629.GA87338@elver.google.com>
 <20200805134232.GR2674@hirez.programming.kicks-ass.net>
 <20200805135940.GA156343@elver.google.com>
 <20200805141237.GS2674@hirez.programming.kicks-ass.net>
 <20200805141709.GD35926@hirez.programming.kicks-ass.net>
 <CANpmjNN6FWZ+MsAn3Pj+WEez97diHzqF8hjONtHG15C2gSpSgw@mail.gmail.com>
 <CANpmjNNy3XKQqgrjGPPKKvXhAoF=mae7dk8hmoS4k4oNnnB=KA@mail.gmail.com>
 <20200806074723.GA2364872@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200806074723.GA2364872@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=0sTLMzAi;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Thu, Aug 06, 2020 at 09:47:23AM +0200, Marco Elver wrote:
> Testing my hypothesis that raw then nested non-raw
> local_irq_save/restore() breaks IRQ state tracking -- see the reproducer
> below. This is at least 1 case I can think of that we're bound to hit.

Aaargh!

> diff --git a/init/main.c b/init/main.c
> index 15bd0efff3df..0873319dcff4 100644
> --- a/init/main.c
> +++ b/init/main.c
> @@ -1041,6 +1041,22 @@ asmlinkage __visible void __init start_kernel(void)
>  	sfi_init_late();
>  	kcsan_init();
>  
> +	/* DEBUG CODE */
> +	lockdep_assert_irqs_enabled(); /* Pass. */
> +	{
> +		unsigned long flags1;
> +		raw_local_irq_save(flags1);

This disables IRQs but doesn't trace..

> +		{
> +			unsigned long flags2;
> +			lockdep_assert_irqs_enabled(); /* Pass - expectedly blind. */

Indeed, we didn't trace the above disable, so software state is still
on.

> +			local_irq_save(flags2);

So here we save IRQ state, and unconditionally disable IRQs and trace
them disabled.

> +			lockdep_assert_irqs_disabled(); /* Pass. */
> +			local_irq_restore(flags2);

But here, we restore IRQ state to 'disabled' and explicitly trace it
disabled *again* (which is a bit daft, but whatever).

> +		}
> +		raw_local_irq_restore(flags1);

This then restores the IRQ state to enable, but no tracing.

> +	}
> +	lockdep_assert_irqs_enabled(); /* FAIL! */

And we're out of sync... :/

/me goes ponder things...

How's something like this then?

---
 include/linux/sched.h |  3 ---
 kernel/kcsan/core.c   | 62 ++++++++++++++++++++++++++++++++++++---------------
 2 files changed, 44 insertions(+), 21 deletions(-)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index 06ec60462af0..2f5aef57e687 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1193,9 +1193,6 @@ struct task_struct {
 
 #ifdef CONFIG_KCSAN
 	struct kcsan_ctx		kcsan_ctx;
-#ifdef CONFIG_TRACE_IRQFLAGS
-	struct irqtrace_events		kcsan_save_irqtrace;
-#endif
 #endif
 
 #ifdef CONFIG_FUNCTION_GRAPH_TRACER
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 9147ff6a12e5..9c4436bf0561 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -291,17 +291,50 @@ static inline unsigned int get_delay(void)
 				0);
 }
 
-void kcsan_save_irqtrace(struct task_struct *task)
+/*
+ * KCSAN hooks are everywhere, which means they're NMI like for interrupt
+ * tracing. In order to present a 'normal' as possible context to the code
+ * called by KCSAN when reporting errors we need to update the irq-tracing
+ * state.
+ *
+ * Save and restore the IRQ state trace touched by KCSAN, since KCSAN's
+ * runtime is entered for every memory access, and potentially useful
+ * information is lost if dirtied by KCSAN.
+ */
+
+struct kcsan_irq_state {
+	unsigned long		flags;
+#ifdef CONFIG_TRACE_IRQFLAGS
+	int			hardirqs;
+	struct irqtrace_events	irqtrace;
+#endif
+};
+
+void kcsan_save_irqtrace(struct kcsan_irq_state *irq_state)
 {
 #ifdef CONFIG_TRACE_IRQFLAGS
-	task->kcsan_save_irqtrace = task->irqtrace;
+	irq_state->irqtrace = task->irqtrace;
+	irq_state->hardirq = lockdep_hardirqs_enabled();
 #endif
+	if (!kcsan_interrupt_watcher) {
+		raw_local_irq_save(irq_state->flags);
+		lockdep_hardirqs_off(CALLER_ADDR0);
+	}
 }
 
-void kcsan_restore_irqtrace(struct task_struct *task)
+void kcsan_restore_irqtrace(struct kcsan_irq_state *irq_state)
 {
+	if (!kcsan_interrupt_watcher) {
+#ifdef CONFIG_TRACE_IRQFLAGS
+		if (irq_state->hardirqs) {
+			lockdep_hardirqs_on_prepare(CALLER_ADDR0);
+			lockdep_hardirqs_on(CALLER_ADDR0);
+		}
+#endif
+		raw_local_irq_restore(irq_state->flags);
+	}
 #ifdef CONFIG_TRACE_IRQFLAGS
-	task->irqtrace = task->kcsan_save_irqtrace;
+	task->irqtrace = irq_state->irqtrace;
 #endif
 }
 
@@ -350,11 +383,13 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 	flags = user_access_save();
 
 	if (consumed) {
-		kcsan_save_irqtrace(current);
+		struct kcsan_irq_state irqstate;
+
+		kcsan_save_irqtrace(&irqstate);
 		kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_MAYBE,
 			     KCSAN_REPORT_CONSUMED_WATCHPOINT,
 			     watchpoint - watchpoints);
-		kcsan_restore_irqtrace(current);
+		kcsan_restore_irqtrace(&irqstate);
 	} else {
 		/*
 		 * The other thread may not print any diagnostics, as it has
@@ -387,7 +422,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	unsigned long access_mask;
 	enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
 	unsigned long ua_flags = user_access_save();
-	unsigned long irq_flags = 0;
+	struct kcsan_irq_state irqstate;
 
 	/*
 	 * Always reset kcsan_skip counter in slow-path to avoid underflow; see
@@ -412,14 +447,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
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
+	kcsan_save_irqtrace(&irqstate);
 
 	watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
 	if (watchpoint == NULL) {
@@ -559,9 +587,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	remove_watchpoint(watchpoint);
 	kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
 out_unlock:
-	if (!kcsan_interrupt_watcher)
-		local_irq_restore(irq_flags);
-	kcsan_restore_irqtrace(current);
+	kcsan_restore_irqtrace(&irqstate);
 out:
 	user_access_restore(ua_flags);
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200806113236.GZ2674%40hirez.programming.kicks-ass.net.
