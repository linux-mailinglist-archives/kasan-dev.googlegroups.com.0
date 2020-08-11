Return-Path: <kasan-dev+bncBCV5TUXXRUIBBA72ZP4QKGQEK77NOCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 78FEC242135
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 22:18:12 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id k142sf10127769qke.7
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 13:18:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597177091; cv=pass;
        d=google.com; s=arc-20160816;
        b=mf5neO1MmMVPqYEoLh+ny0qsNYddYM3RU5OY5AzQFLvHVX1ZwKvqy7P6ETUt5CIl8A
         f5/z0OniZifB6iI0FP1pR7/f6LzYr+SJzfWpqNUkp526ymiWxxYE7YcPHPZEgj8trklB
         J92b5mdgMNAYy/cTpzYmzrXxtX8Tu7RovdJDfogRX8ZDtj2Qd+vX7LsA8zY3o8ewlrAZ
         40ZdG1rY//ENPO2/kzPZjqmyQowo5IMbuYn7oKNt3dwJUT7dIDMceo5YVm+KvAiIKR7/
         xqnmRF/0TnDlDWNFJRSV4zxV5sqkCC21Qfa48gKW4gy7+FXOkowUke/e6eb3qrvYrd5l
         j4sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tCX0zlRUVfXs1oMffOgYATOPYtn0rGBMyEunIaRfmWM=;
        b=d4+GTsLTAdz6M2yXn7WjbJnNaI6y0/DcQhgeNolD7KQSUehqKu9toDiS1Y6kLcKMw4
         AxaNZ7ERWZBeuIdo8xjt8JhB69SzBs4DzEhn03nrS8CT7p/6SEvCMd/jTTuM1h6WqOXE
         3VARxJUveUsXRoO5189A4tJPh9g5Gm9/K+Hcwyl4tSOeZtUtnDwJpUeP6Z66/fNA2hs/
         j5hY5GYyKhxPJLxILXEZYqXpF0/47EoGXA7x+tUJj7Gcdw6O8Jgby++gI7Obz1a6PbvQ
         JWF74TnKja0MxuTVVfRARNiQHhOzwrBZdFdSqYiv1rzbAg92j11LfHPivv5wa8izj1Cq
         ObhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=zULSQsAh;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tCX0zlRUVfXs1oMffOgYATOPYtn0rGBMyEunIaRfmWM=;
        b=Bx295I4kBYsTZ6LHT2Fagqiy1ULOBgD4VNWjVPzWVAcL4YG0F6Kg6IZWtGMXozsIJ1
         enIWsVgq3k58OvnzSFwkvCZZMVC4UoTNVxssUV8rp1V0du2v8YShXV8P5unWh6mi9+rJ
         3KGnUmuYNhDgJMMPs64lWCW/AL2BVIRBZoNizJbAQjLCSic5eNznuSnwSOhfKnDOKpFw
         q9QpBMZ8N7i7VVx5tDTLKTUJfvlH1npwE93m7PphTFDpwzokrJeQVQYUB3P3AFSlB1HB
         7DSpg2rc7Bl4EpP3SoKxOlLhdlwpTOcvKa1M3VI/Qbkr0ntLrOPI17ixgf9olq2uNEBP
         6YZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tCX0zlRUVfXs1oMffOgYATOPYtn0rGBMyEunIaRfmWM=;
        b=ZdTOFrTiFU5GbaWyC9TTFKQf5ix1wIaXvmJ47hcYYJ7D8OT2rQqHIZbMOlLUZ0XUMm
         wPznF2+4vVq19RZkT6Ajz8PltmeSDFkYe26QbH6Dxn0yOg75pzn8HnYeW9ZE2LD859Up
         txA/tErh89tLivaDt9s6XdqN9fSH+38s+UbzoXIUVAQ63HK7PD/SCeNb5u8bqh9MG7K5
         z94Vft5H4FSPQhqR5ogYkdzUWv31K6NyF0UcWJSe4lgk4yJ3Zcx3XhQtKUAKJNlLrUsQ
         B7sEMH+kYTgZc3urnK0ODhJCsmVWOPM3ldPt1pd7/BIcDLvHKG6ncopfGXoPPSHB6EbI
         dYgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530EfeWTnPUo1D334XENBt+KPYaC0Znbq0PXp/az+GHUp269n2rq
	XYOSlFeSlnhWxlYky1A5o4M=
X-Google-Smtp-Source: ABdhPJzroTIfdbbreclbZ3PEu3OOZKsnKZm5VuvzWkaTEFcBha/dzKtdv9R8OcnX+ezVnyAHcpLhrg==
X-Received: by 2002:a05:620a:35d:: with SMTP id t29mr2610877qkm.447.1597177091230;
        Tue, 11 Aug 2020 13:18:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5482:: with SMTP id q2ls5469225qvy.8.gmail; Tue, 11 Aug
 2020 13:18:10 -0700 (PDT)
X-Received: by 2002:ad4:51d1:: with SMTP id p17mr3179380qvq.14.1597177090950;
        Tue, 11 Aug 2020 13:18:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597177090; cv=none;
        d=google.com; s=arc-20160816;
        b=dNABh6XxsQLLJmCOfw3Wb7Tjis28uWeR+/tYQHAb/6KvK5rIbV1kkOXpW3FXSIHya3
         zJVMXZhZN3+oasHslIdW3v2HMQvKKCRj0/pmG/Z6OzYDtG3dBxUnDJagC1b8wO//0ZQy
         fbXnRJq+tYEQdhVAnnpGL18tkNNJGTDiaAwOoW5FHotIiV6TKen7X1HWvHoZq+JKfKqP
         jqXSXllmcCDCjShFyC6pxPrHAhT1qXosAJ42f5Cd5dKvRok84MYkftS5yKevKGQQoVdK
         tBdMvT1OafsJQALpkVIF+idnqQmutW5M5MswGTiRJMsvkS0jXj9Dfn3Dj0z9bEyBoJPj
         akiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=LQfBOeOjjqS/nBAqElZF8KgMdzWHn+FKx6prXkYnbW4=;
        b=Hv0T9PO6PyuyYWhlPzE7SZa4hae9zvjh9GIUPHWYKsAC1tC9BqM/AdZwAnnsO/ZRmv
         XCAU5tJvVxHNpiQVi+9I9p3bywbxDaA5gyZFULKOy6MeaMItcsdArlU1jYyxQO5AQwoo
         OG19R98wCdVyJMQN6mGFqBh740emjb9Ge20Hn3UaeSFCaSJ77mvZHebJckcvFOGtH1SO
         +8H9mdrC7RJPBZK6phDNKqq4pTg96FN+Rfl1QRPxqfrwFthYBcOfl321hiSggFiAyKly
         O0/cFvklHy3/VdKTtYZqHZ49AhP82n3ABAOEdNL4Z77PEJyxNGoVuHdNlDzLZjk+pgU4
         EL5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=zULSQsAh;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id b21si296931qtq.1.2020.08.11.13.18.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Aug 2020 13:18:10 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1k5aid-0001H9-J1; Tue, 11 Aug 2020 20:17:59 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 916843012C3;
	Tue, 11 Aug 2020 22:17:55 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 76B9D2B05AEA1; Tue, 11 Aug 2020 22:17:55 +0200 (CEST)
Date: Tue, 11 Aug 2020 22:17:55 +0200
From: peterz@infradead.org
To: =?iso-8859-1?Q?J=FCrgen_Gro=DF?= <jgross@suse.com>
Cc: Marco Elver <elver@google.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, fenghua.yu@intel.com,
	"H. Peter Anvin" <hpa@zytor.com>,
	LKML <linux-kernel@vger.kernel.org>, Ingo Molnar <mingo@redhat.com>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Luck, Tony" <tony.luck@intel.com>,
	the arch/x86 maintainers <x86@kernel.org>, yu-cheng.yu@intel.com,
	sdeep@vmware.com, virtualization@lists.linux-foundation.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Wei Liu <wei.liu@kernel.org>, Steven Rostedt <rostedt@goodmis.org>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
Message-ID: <20200811201755.GI35926@hirez.programming.kicks-ass.net>
References: <20200807113838.GA3547125@elver.google.com>
 <e5bf3e6a-efff-7170-5ee6-1798008393a2@suse.com>
 <CANpmjNPau_DEYadey9OL+iFZKEaUTqnFnyFs1dU12o00mg7ofA@mail.gmail.com>
 <20200807151903.GA1263469@elver.google.com>
 <20200811074127.GR3982@worktop.programming.kicks-ass.net>
 <a2dffeeb-04f0-8042-b39a-b839c4800d6f@suse.com>
 <20200811081205.GV3982@worktop.programming.kicks-ass.net>
 <07f61573-fef1-e07c-03f2-a415c88dec6f@suse.com>
 <20200811092054.GB2674@hirez.programming.kicks-ass.net>
 <20200811094651.GH35926@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200811094651.GH35926@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=zULSQsAh;
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

On Tue, Aug 11, 2020 at 11:46:51AM +0200, peterz@infradead.org wrote:

> So let me once again see if I can't find a better solution for this all.
> Clearly it needs one :/

So the below boots without triggering the debug code from Marco -- it
should allow nesting local_irq_save/restore under raw_local_irq_*().

I tried unconditional counting, but there's some _reallly_ wonky /
asymmetric code that wrecks that and I've not been able to come up with
anything useful.

This one starts counting when local_irq_save() finds it didn't disable
IRQs while lockdep though it did. At that point, local_irq_restore()
will decrement and enable things again when it reaches 0.

This assumes local_irq_save()/local_irq_restore() are nested sane, which
is mostly true.

This leaves #PF, which I fixed in these other patches, but I realized it
needs fixing for all architectures :-( No bright ideas there yet.

---
 arch/x86/entry/thunk_32.S       |  5 ----
 include/linux/irqflags.h        | 45 +++++++++++++++++++-------------
 init/main.c                     | 16 ++++++++++++
 kernel/locking/lockdep.c        | 58 +++++++++++++++++++++++++++++++++++++++++
 kernel/trace/trace_preemptirq.c | 33 +++++++++++++++++++++++
 5 files changed, 134 insertions(+), 23 deletions(-)

diff --git a/arch/x86/entry/thunk_32.S b/arch/x86/entry/thunk_32.S
index 3a07ce3ec70b..f1f96d4d8cd6 100644
--- a/arch/x86/entry/thunk_32.S
+++ b/arch/x86/entry/thunk_32.S
@@ -29,11 +29,6 @@ SYM_CODE_START_NOALIGN(\name)
 SYM_CODE_END(\name)
 	.endm
 
-#ifdef CONFIG_TRACE_IRQFLAGS
-	THUNK trace_hardirqs_on_thunk,trace_hardirqs_on_caller,1
-	THUNK trace_hardirqs_off_thunk,trace_hardirqs_off_caller,1
-#endif
-
 #ifdef CONFIG_PREEMPTION
 	THUNK preempt_schedule_thunk, preempt_schedule
 	THUNK preempt_schedule_notrace_thunk, preempt_schedule_notrace
diff --git a/include/linux/irqflags.h b/include/linux/irqflags.h
index bd5c55755447..67e2a16d3846 100644
--- a/include/linux/irqflags.h
+++ b/include/linux/irqflags.h
@@ -23,12 +23,16 @@
   extern void lockdep_hardirqs_on_prepare(unsigned long ip);
   extern void lockdep_hardirqs_on(unsigned long ip);
   extern void lockdep_hardirqs_off(unsigned long ip);
+  extern void lockdep_hardirqs_save(unsigned long ip, unsigned long flags);
+  extern void lockdep_hardirqs_restore(unsigned long ip, unsigned long flags);
 #else
   static inline void lockdep_softirqs_on(unsigned long ip) { }
   static inline void lockdep_softirqs_off(unsigned long ip) { }
   static inline void lockdep_hardirqs_on_prepare(unsigned long ip) { }
   static inline void lockdep_hardirqs_on(unsigned long ip) { }
   static inline void lockdep_hardirqs_off(unsigned long ip) { }
+  static inline void lockdep_hardirqs_save(unsigned long ip, unsigned long flags) { }
+  static inline void lockdep_hardirqs_restore(unsigned long ip, unsigned long flags) { }
 #endif
 
 #ifdef CONFIG_TRACE_IRQFLAGS
@@ -49,10 +53,13 @@ struct irqtrace_events {
 DECLARE_PER_CPU(int, hardirqs_enabled);
 DECLARE_PER_CPU(int, hardirq_context);
 
-  extern void trace_hardirqs_on_prepare(void);
-  extern void trace_hardirqs_off_finish(void);
-  extern void trace_hardirqs_on(void);
-  extern void trace_hardirqs_off(void);
+extern void trace_hardirqs_on_prepare(void);
+extern void trace_hardirqs_off_finish(void);
+extern void trace_hardirqs_on(void);
+extern void trace_hardirqs_off(void);
+extern void trace_hardirqs_save(unsigned long flags);
+extern void trace_hardirqs_restore(unsigned long flags);
+
 # define lockdep_hardirq_context()	(this_cpu_read(hardirq_context))
 # define lockdep_softirq_context(p)	((p)->softirq_context)
 # define lockdep_hardirqs_enabled()	(this_cpu_read(hardirqs_enabled))
@@ -120,17 +127,19 @@ do {						\
 #else
 # define trace_hardirqs_on_prepare()		do { } while (0)
 # define trace_hardirqs_off_finish()		do { } while (0)
-# define trace_hardirqs_on()		do { } while (0)
-# define trace_hardirqs_off()		do { } while (0)
-# define lockdep_hardirq_context()	0
-# define lockdep_softirq_context(p)	0
-# define lockdep_hardirqs_enabled()	0
-# define lockdep_softirqs_enabled(p)	0
-# define lockdep_hardirq_enter()	do { } while (0)
-# define lockdep_hardirq_threaded()	do { } while (0)
-# define lockdep_hardirq_exit()		do { } while (0)
-# define lockdep_softirq_enter()	do { } while (0)
-# define lockdep_softirq_exit()		do { } while (0)
+# define trace_hardirqs_on()			do { } while (0)
+# define trace_hardirqs_off()			do { } while (0)
+# define trace_hardirqs_save(flags)		do { } while (0)
+# define trace_hardirqs_restore(flags)		do { } while (0)
+# define lockdep_hardirq_context()		0
+# define lockdep_softirq_context(p)		0
+# define lockdep_hardirqs_enabled()		0
+# define lockdep_softirqs_enabled(p)		0
+# define lockdep_hardirq_enter()		do { } while (0)
+# define lockdep_hardirq_threaded()		do { } while (0)
+# define lockdep_hardirq_exit()			do { } while (0)
+# define lockdep_softirq_enter()		do { } while (0)
+# define lockdep_softirq_exit()			do { } while (0)
 # define lockdep_hrtimer_enter(__hrtimer)	false
 # define lockdep_hrtimer_exit(__context)	do { } while (0)
 # define lockdep_posixtimer_enter()		do { } while (0)
@@ -185,18 +194,18 @@ do {						\
 	do { trace_hardirqs_on(); raw_local_irq_enable(); } while (0)
 #define local_irq_disable() \
 	do { raw_local_irq_disable(); trace_hardirqs_off(); } while (0)
+
 #define local_irq_save(flags)				\
 	do {						\
 		raw_local_irq_save(flags);		\
-		trace_hardirqs_off();			\
+		trace_hardirqs_save(flags);		\
 	} while (0)
 
-
 #define local_irq_restore(flags)			\
 	do {						\
 		if (raw_irqs_disabled_flags(flags)) {	\
 			raw_local_irq_restore(flags);	\
-			trace_hardirqs_off();		\
+			trace_hardirqs_restore(flags);	\
 		} else {				\
 			trace_hardirqs_on();		\
 			raw_local_irq_restore(flags);	\
diff --git a/init/main.c b/init/main.c
index 15bd0efff3df..0873319dcff4 100644
--- a/init/main.c
+++ b/init/main.c
@@ -1041,6 +1041,22 @@ asmlinkage __visible void __init start_kernel(void)
 	sfi_init_late();
 	kcsan_init();
 
+	/* DEBUG CODE */
+	lockdep_assert_irqs_enabled(); /* Pass. */
+	{
+		unsigned long flags1;
+		raw_local_irq_save(flags1);
+		{
+			unsigned long flags2;
+			lockdep_assert_irqs_enabled(); /* Pass - expectedly blind. */
+			local_irq_save(flags2);
+			lockdep_assert_irqs_disabled(); /* Pass. */
+			local_irq_restore(flags2);
+		}
+		raw_local_irq_restore(flags1);
+	}
+	lockdep_assert_irqs_enabled(); /* FAIL! */
+
 	/* Do the rest non-__init'ed, we're now alive */
 	arch_call_rest_init();
 
diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
index 3617abb08e31..2c88574b817c 100644
--- a/kernel/locking/lockdep.c
+++ b/kernel/locking/lockdep.c
@@ -3763,6 +3763,30 @@ void noinstr lockdep_hardirqs_on(unsigned long ip)
 }
 EXPORT_SYMBOL_GPL(lockdep_hardirqs_on);
 
+static DEFINE_PER_CPU(int, hardirqs_disabled);
+
+void lockdep_hardirqs_restore(unsigned long ip, unsigned long flags)
+{
+	if (unlikely(!debug_locks))
+		return;
+
+	if (in_nmi()) {
+		if (!IS_ENABLED(CONFIG_TRACE_IRQFLAGS_NMI))
+			return;
+	} else if (current->lockdep_recursion & LOCKDEP_RECURSION_MASK)
+		return;
+
+	if (__this_cpu_read(hardirqs_disabled) &&
+	    __this_cpu_dec_return(hardirqs_disabled) == 0) {
+
+		lockdep_hardirqs_on_prepare(ip);
+		lockdep_hardirqs_on(ip);
+	} else {
+		lockdep_hardirqs_off(ip);
+	}
+}
+EXPORT_SYMBOL_GPL(lockdep_hardirqs_restore);
+
 /*
  * Hardirqs were disabled:
  */
@@ -3805,6 +3829,40 @@ void noinstr lockdep_hardirqs_off(unsigned long ip)
 }
 EXPORT_SYMBOL_GPL(lockdep_hardirqs_off);
 
+void lockdep_hardirqs_save(unsigned long ip, unsigned long flags)
+{
+	if (unlikely(!debug_locks))
+		return;
+
+	/*
+	 * Matching lockdep_hardirqs_on(), allow NMIs in the middle of lockdep;
+	 * they will restore the software state. This ensures the software
+	 * state is consistent inside NMIs as well.
+	 */
+	if (in_nmi()) {
+		if (!IS_ENABLED(CONFIG_TRACE_IRQFLAGS_NMI))
+			return;
+	} else if (current->lockdep_recursion & LOCKDEP_RECURSION_MASK)
+		return;
+
+	/*
+	 * If IRQs were disabled, but IRQ tracking state said enabled we
+	 * 'missed' an update (or are nested inside raw_local_irq_*()) and
+	 * cannot rely on IRQ state to tell us when we should enable again.
+	 *
+	 * Count our way through this.
+	 */
+	if (raw_irqs_disabled_flags(flags)) {
+		if (__this_cpu_read(hardirqs_enabled)) {
+			WARN_ON_ONCE(__this_cpu_read(hardirqs_disabled) != 0);
+			__this_cpu_write(hardirqs_disabled, 1);
+		} else if (__this_cpu_read(hardirqs_disabled))
+			__this_cpu_inc(hardirqs_disabled);
+	}
+	lockdep_hardirqs_off(ip);
+}
+EXPORT_SYMBOL_GPL(lockdep_hardirqs_save);
+
 /*
  * Softirqs will be enabled:
  */
diff --git a/kernel/trace/trace_preemptirq.c b/kernel/trace/trace_preemptirq.c
index f10073e62603..080deaa1d9c9 100644
--- a/kernel/trace/trace_preemptirq.c
+++ b/kernel/trace/trace_preemptirq.c
@@ -85,6 +85,36 @@ void trace_hardirqs_off(void)
 EXPORT_SYMBOL(trace_hardirqs_off);
 NOKPROBE_SYMBOL(trace_hardirqs_off);
 
+void trace_hardirqs_save(unsigned long flags)
+{
+	lockdep_hardirqs_save(CALLER_ADDR0, flags);
+
+	if (!this_cpu_read(tracing_irq_cpu)) {
+		this_cpu_write(tracing_irq_cpu, 1);
+		tracer_hardirqs_off(CALLER_ADDR0, CALLER_ADDR1);
+		if (!in_nmi())
+			trace_irq_disable_rcuidle(CALLER_ADDR0, CALLER_ADDR1);
+	}
+}
+EXPORT_SYMBOL(trace_hardirqs_save);
+NOKPROBE_SYMBOL(trace_hardirqs_save);
+
+void trace_hardirqs_restore(unsigned long flags)
+{
+	if (this_cpu_read(tracing_irq_cpu)) {
+		if (!in_nmi())
+			trace_irq_enable_rcuidle(CALLER_ADDR0, CALLER_ADDR1);
+		tracer_hardirqs_on(CALLER_ADDR0, CALLER_ADDR1);
+		this_cpu_write(tracing_irq_cpu, 0);
+	}
+
+	lockdep_hardirqs_restore(CALLER_ADDR0, flags);
+}
+EXPORT_SYMBOL(trace_hardirqs_restore);
+NOKPROBE_SYMBOL(trace_hardirqs_restore);
+
+#ifdef __s390__
+
 __visible void trace_hardirqs_on_caller(unsigned long caller_addr)
 {
 	if (this_cpu_read(tracing_irq_cpu)) {
@@ -113,6 +143,9 @@ __visible void trace_hardirqs_off_caller(unsigned long caller_addr)
 }
 EXPORT_SYMBOL(trace_hardirqs_off_caller);
 NOKPROBE_SYMBOL(trace_hardirqs_off_caller);
+
+#endif /* __s390__ */
+
 #endif /* CONFIG_TRACE_IRQFLAGS */
 
 #ifdef CONFIG_TRACE_PREEMPT_TOGGLE

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200811201755.GI35926%40hirez.programming.kicks-ass.net.
