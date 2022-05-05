Return-Path: <kasan-dev+bncBDAMN6NI5EERB74P2GJQMGQEZBY2BKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id F261B51CBAD
	for <lists+kasan-dev@lfdr.de>; Thu,  5 May 2022 23:56:15 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id sd38-20020a1709076e2600b006f3e54b1dbcsf1416928ejc.4
        for <lists+kasan-dev@lfdr.de>; Thu, 05 May 2022 14:56:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651787775; cv=pass;
        d=google.com; s=arc-20160816;
        b=E3rOUOEaAIIOcxgaXhJcdt18dEPeNhBf+kwrKU6K7r6qCJeOXKLhwG56mmYAIQJ0bt
         pRxwkaWcsVjfj3IxmHTbmUJDSAfVijiJnAOFz26HvOaCPd/lpXq+04Hdp7sk7SG2/Wh5
         3tasAuzOxf39HDTeAh/AVACMNPAGUlb/cZ33x1QYH1QK0v465Y7y+VsW1KQdmsejml+f
         5YXAB5zKc13F+qW1/OcYzNl1TSvwHIqQEw7DHkq24Onm7008uKGQBMbC9f+A3aNjWPFb
         KuyTyZMdAtla97OMq5Vg0ljiiYNBIbSWuVT1MoAqsYQDHwtCFvXuHOjQA6f9Ux5sDH5R
         DuDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=3hy94FCqG17f+ys9ZU+wn2Qv+RutszEQPQeMO3Me8vQ=;
        b=k+E9CBCPMwtvNb+3NWj8y7cUht6P6Imd2gfLYsu4RDK71gwjcBnqKGeEjVByjsl042
         OMHDe09qfsg0X/lSO9LTGgUny4WXHRJ210O6QQ5FO+9ahHfFL4/DGGF2w/g67zofoV+g
         zlYb4hQ0IbczFKig30h03mMnNQxxAlmSNDm+iePSkcyYGJFVL0FemXEpxCTfBMK1+M43
         VONz2C2dz7gI41vtn2N9yd70tulx0XRdg42r8CjmG/X6MUqI5m1BYmY3sumeGHwMisfq
         GSMI72FaNEza7dkN/Lsn+ieCr+mlc+X7ixAm53VrIsRbLbEDbigbJ6u6XUR7dhk0qT6P
         5l5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=PSrYskSY;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3hy94FCqG17f+ys9ZU+wn2Qv+RutszEQPQeMO3Me8vQ=;
        b=huRM+BbP8wIugUlFfbMr6Gcwta3Ne26V7CL+EDi4u64mx8kYwKbdkvCv5SezQl4ja9
         /orRTe+KF1tVoDyQadXvJotDRhfHG0LT+1gDL8CYieMRcaChdlcbPzBdjWRwHRe241H5
         /tlp6C3SAWwsf3DHbPurvIzOmHQo7PV9cHGZzGy7f534OWbJMJAhhID4KjenHW1ACG0n
         Ti9dSYWTPTFTZaSIm76HCqUw5zGFve9JpUEWlstKO28A/CIu8vuPFCQcl+Kig45FKttF
         OCx+zBtHj7x9asAwPIu69z/FXU31vkN3r8b4bH8aAIR6NO2r2xOFo1l1Op7r8fVYB3pN
         cJ+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3hy94FCqG17f+ys9ZU+wn2Qv+RutszEQPQeMO3Me8vQ=;
        b=w+Bz3i2akHZ07o76QPCCWYs+dRkCX6lhU341MvyEQMHTJSMChQns/ftgu3gzzGvAjd
         Fdp1k0H5QQLRf+Ect9Vxhkv7fYVF3APg75CrqR5eSimoZIUEs8rmwY5ou9+vDDfoD9dQ
         IpsLl3LhnuFY5GPfiz5QpmHu0e4DQFDJv9uLSkQ/hIIn3CM6fotu7fxFE/WWrIV8iQm9
         rOrcdHlrP+hOPPwl9Il5NKn3ma3wd2oRax8SX9ASL2/UbiDqSa84c3CJL50NiBFuEIQh
         Fp6P9biMWwTuEf02YaRTR6TCBf8SjZO/KfnuKwsQwszp9IGznvEfY06ELRI4EOZaF/Iy
         pqSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533M+LiLmYKRwyOW5A7fQTjeFyqyhlYAPYP2tW6/nq86O+IvIEQ+
	bzlMp50kRFszhNozcRmapKA=
X-Google-Smtp-Source: ABdhPJzXyAglsxgVpg2vG83ad5o56l6vOB8UVjfEZl/C7Ptk0vdtiAy0/IiXoHTCX5QVivE3TW25kQ==
X-Received: by 2002:a17:906:a5b:b0:6f4:55f6:78af with SMTP id x27-20020a1709060a5b00b006f455f678afmr238089ejf.238.1651787775502;
        Thu, 05 May 2022 14:56:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:26d2:b0:428:f87:ccd8 with SMTP id
 x18-20020a05640226d200b004280f87ccd8ls6329740edd.1.gmail; Thu, 05 May 2022
 14:56:14 -0700 (PDT)
X-Received: by 2002:a50:cd55:0:b0:428:5101:b729 with SMTP id d21-20020a50cd55000000b004285101b729mr261028edj.361.1651787774442;
        Thu, 05 May 2022 14:56:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651787774; cv=none;
        d=google.com; s=arc-20160816;
        b=GpCJf7LzchA4SSrBPCjK3NLTEj6fIiBdNBedQguTWOOp4hlwTeCZr/SElV30Cmub73
         haUWmIGEc4JXsWGLTG0D9HzknJeMYHo1paDBOvyZQnYiG0+COwQ6dhuWj61YUWYCptpS
         eeLZoHu5KIcCk0ObPwKPOCP2ulB34n2P2q4YpQUEJpTBlUwhRX4SzIPMfsVCM3lDNAOa
         M1NJF1uQEknLfyX2DsInFxkRWR6DNfFpo+q0wmbz74OdrCFzp4ePli2Vkr1iSDLfPi2B
         cCW+kIxittOIQqWDMHSZgTvQFRRZ2QWTJePOjLUlDGAT/xuCPLNBcVeSEB+toLBRQbmX
         fF3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=Xigc7SGokGXaGXENHUlGV+lz8hEFE/+jKrwKMtiGA38=;
        b=ELI8MMJwyKUh1mOxOeiyGYVjOu4vF6QzW1e7IzFg6Bs/CL+d38Mg+c9lNqlM86lWPZ
         XcxRUI5Y7ndtgrw7Vf51OXJ65yFcnxE9exzx8pjok3VJ+8eWlRX1VduCBdAXXZ6N+Af6
         2Wf4ScY5WPIkjQDyd31DLgURtYb7whrVE77JbhxvoM1T0RjYFpnwv54G65xK/NAtnBrs
         aBl+sWOqKUZDfQ47fRbJlW4fC+pK1mp43SGYXjHTcZ4DmIyuekG/d6zazPDXi+r4Alzs
         YzZpgrx5ZEL+iaOmBmbKrJso7n33BsxgYAluy+/CCQazg01OZ9Hm4rAr9MXLrmGrVEZK
         Or3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=PSrYskSY;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id c19-20020a05640227d300b00418d53b44b8si105176ede.0.2022.05.05.14.56.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 May 2022 14:56:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton
 <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>,
 Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav
 Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter
 <cl@linux.com>, David Rientjes <rientjes@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu
 <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, Ingo
 Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim
 <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, Marco Elver
 <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox
 <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg
 <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Petr Mladek
 <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik
 <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil
 Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, Linux
 Memory Management List <linux-mm@kvack.org>, Linux-Arch
 <linux-arch@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v3 28/46] kmsan: entry: handle register passing from
 uninstrumented code
In-Reply-To: <CAG_fn=XxAhBEBP2KJvahinbaxLAd1xvqTfRJdAu1Tk5r8=01jw@mail.gmail.com>
References: <20220426164315.625149-1-glider@google.com>
 <20220426164315.625149-29-glider@google.com> <87a6c6y7mg.ffs@tglx>
 <CAG_fn=U7PPBmmkgxFcWFQUCqZitzMizr1e69D9f26sGGzeitLQ@mail.gmail.com>
 <87y1zjlhmj.ffs@tglx>
 <CAG_fn=XxAhBEBP2KJvahinbaxLAd1xvqTfRJdAu1Tk5r8=01jw@mail.gmail.com>
Date: Thu, 05 May 2022 23:56:12 +0200
Message-ID: <878rrfiqyr.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=PSrYskSY;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 tglx@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

Alexander,

On Thu, May 05 2022 at 20:04, Alexander Potapenko wrote:
> On Tue, May 3, 2022 at 12:00 AM Thomas Gleixner <tglx@linutronix.de> wrote:
>> > Regarding the regs, you are right. It should be enough to unpoison the
>> > regs at idtentry prologue instead.
>> > I tried that initially, but IIRC it required patching each of the
>> > DEFINE_IDTENTRY_XXX macros, which already use instrumentation_begin().
>>
>> Exactly 4 instances :)
>>
>
> Not really, I had to add a call to `kmsan_unpoison_memory(regs,
> sizeof(*regs));` to the following places in
> arch/x86/include/asm/idtentry.h:
> - DEFINE_IDTENTRY()
> - DEFINE_IDTENTRY_ERRORCODE()
> - DEFINE_IDTENTRY_RAW()
> - DEFINE_IDTENTRY_RAW_ERRORCODE()
> - DEFINE_IDTENTRY_IRQ()
> - DEFINE_IDTENTRY_SYSVEC()
> - DEFINE_IDTENTRY_SYSVEC_SIMPLE()
> - DEFINE_IDTENTRY_DF()
>
> , but even that wasn't enough. For some reason I also had to unpoison
> pt_regs directly in
> DEFINE_IDTENTRY_SYSVEC(sysvec_apic_timer_interrupt) and
> DEFINE_IDTENTRY_IRQ(common_interrupt).
> In the latter case, this could have been caused by
> asm_common_interrupt being entered from irq_entries_start(), but I am
> not sure what is so special about sysvec_apic_timer_interrupt().
>
> Ideally, it would be great to find that single point where pt_regs are
> set up before being passed to all IDT entries.
> I used to do that by inserting calls to kmsan_unpoison_memory right
> into arch/x86/entry/entry_64.S
> (https://github.com/google/kmsan/commit/3b0583f45f74f3a09f4c7e0e0588169cef918026),
> but that required storing/restoring all GP registers. Maybe there's a
> better way?

Yes. Something like this should cover all exceptions and syscalls before
anything instrumentable can touch @regs. Anything up to those points is
either off-limit for instrumentation or does not deal with @regs.

--- a/kernel/entry/common.c
+++ b/kernel/entry/common.c
@@ -24,6 +24,7 @@ static __always_inline void __enter_from
 	user_exit_irqoff();
 
 	instrumentation_begin();
+	unpoison(regs);
 	trace_hardirqs_off_finish();
 	instrumentation_end();
 }
@@ -352,6 +353,7 @@ noinstr irqentry_state_t irqentry_enter(
 		lockdep_hardirqs_off(CALLER_ADDR0);
 		rcu_irq_enter();
 		instrumentation_begin();
+		unpoison(regs);
 		trace_hardirqs_off_finish();
 		instrumentation_end();
 
@@ -367,6 +369,7 @@ noinstr irqentry_state_t irqentry_enter(
 	 */
 	lockdep_hardirqs_off(CALLER_ADDR0);
 	instrumentation_begin();
+	unpoison(regs);
 	rcu_irq_enter_check_tick();
 	trace_hardirqs_off_finish();
 	instrumentation_end();
@@ -452,6 +455,7 @@ irqentry_state_t noinstr irqentry_nmi_en
 	rcu_nmi_enter();
 
 	instrumentation_begin();
+	unpoison(regs);
 	trace_hardirqs_off_finish();
 	ftrace_nmi_enter();
 	instrumentation_end();

As I said: 4 places :)

> Fortunately, I don't think we need to insert extra instrumentation
> into instrumentation_begin()/instrumentation_end() regions.
>
> What I have in mind is adding a bool flag to kmsan_context_state, that
> the instrumentation sets to true before the function call.
> When entering an instrumented function, KMSAN would check that flag
> and set it to false, so that the context state can be only used once.
> If a function is called from another instrumented function, the
> context state is properly set up, and there is nothing to worry about.
> If it is called from non-instrumented code (either noinstr or the
> skipped files that have KMSAN_SANITIZE:=n), KMSAN would detect that
> and wipe the context state before use.

Sounds good.

Thanks,

	tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/878rrfiqyr.ffs%40tglx.
