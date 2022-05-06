Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5V32WJQMGQEJCWCTFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1289251DE6A
	for <lists+kasan-dev@lfdr.de>; Fri,  6 May 2022 19:42:16 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id r20-20020a056e02109400b002cc174742c9sf4582293ilj.5
        for <lists+kasan-dev@lfdr.de>; Fri, 06 May 2022 10:42:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651858935; cv=pass;
        d=google.com; s=arc-20160816;
        b=bICGOBj4fW2ZPIv1EOC3YtKGjBVtBHcg10dOdNdSJGcJx9FDXQmkR8SVz84o3wxJtT
         pWeLfksCzanCiQO5NUsRSQI1OyBoT4JaTr35Y5KgZf4ClGICL/vQggWCR+5m6gkDM2tZ
         kVB1NYK0yC9VnaQJb0W24NheGOyffumUzOXE7zlL6+j1tYIHa9UN9RDFGQGh08Ty8ktT
         DXIJX0Tm5PFb2dxQB2JkLvfK+eseKRdj5lkumxVfO6l/Bi8Ev656DSPUi2ARcWUix293
         yR5fC20ylMyKR6RQSmrcJk3Iog74jwsDInotKUrTORZQzT/EUqCR3ylnW4nLLL9fVvXk
         WPCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8mBCw4iJYVawRWFHhFTlcr0ozXzzJiLQg1Os2xkqOBE=;
        b=k7/iB3/VKmKDqPPqiYr/QwfbGEhKZHY3ehFzcp9XecCdGAhhcF7MyAhbdwwOmD02kx
         Cp1BeuAk44fKoxH6ftwZv42v8uFzSTarPJOCJPze6d2NOtwDNbDxM8pS5q3CAnOXvU6u
         GyvmFufwKvnk2rOEwLKgPz6RGbhkoFIFm4OrhgccbXy60zPQM60C0B+M4RW9PLRaX6q5
         GG9HfGzYobqVD8squhQ2fm7xFwp2y/FoxSLZfmyryzHyzLxIUOvFAe62xTa5CHO+k4BK
         QtGicj2e5q6PSE+up9mYjfiLced8Bu03GpcYty+IUO7mC8aCr2XGrHuapTSkZB9kMmeD
         a2/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=emmUN3k1;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8mBCw4iJYVawRWFHhFTlcr0ozXzzJiLQg1Os2xkqOBE=;
        b=BSM2D0pCbkNEqn5pcWQFCfpfONBZxRcn24eIYZetKmqkZw4QDF/JO0ysHCMggulP0o
         Jmidqdedi5ekkytu9JOyto1C0krN8hryrdNwff/NiULp6ZYUqwDYSDUI3rkXu8K/fTy5
         0Ga1JrWdQqAfsd2LGVDjfdSTXoJvx1L5weKizIQDqUI0Veu5/f5LPAM1JNbONbfcq6MX
         9FWIqzlT6i5cKepM7OrGg4U7+SV4a9jafgUZ0+JcskG5WTbDTewL0Bpz6Q9Ls3ULvH59
         +tUVxbPHb+q8JxQBwz56SGqokXmBh6zUkX1iBNR97IWiFueeiMypweFrBbZlrS2phgTx
         mL6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8mBCw4iJYVawRWFHhFTlcr0ozXzzJiLQg1Os2xkqOBE=;
        b=iQFPXYgSQbrNKiwwhR19FjCH2NA3V1JwWZvXbld9fc5PUZJdwb3vkE3gDjewpbVzP/
         TMSw0ad0LmoRuB8jpJV6OJB7IS9AohoSpOqEWC4A4Pq5uLncNeDrZNv2og1g9JVBDUsX
         i0YB8/f9WUX1z6QfGrNBtuoQs9SdBU31cgFfZBHrbYl5sUekUsr750Jw9q7/fINoQ+dV
         v9N27YLVxPZ/9QVkF8gi2f6mbG/siepl+CFiwaguuCZr/swBLYXVZPx7PyyG/O6Wve/N
         2DdHbUFmYAGnZcJiEvs1wAvmUn68lRm8o+Xr9zMD2hsCWNH9aCvQ+ocfqrkbxrdJFYFw
         F0mQ==
X-Gm-Message-State: AOAM532CaKiI4tT6J8BMKzs7F6OlyjAX/Mo1BPoPMl9+OId5GKlhvKBY
	CqBeIaYHB/o+VWw0Ln7+/ks=
X-Google-Smtp-Source: ABdhPJw3TOeTghANh9em7O+z5G67s/TA7NgIvWvuizMZp7S2hVQ9CoFvpSlE88AjK/zOeKb/G55PRw==
X-Received: by 2002:a05:6e02:20ee:b0:2cf:38af:d466 with SMTP id q14-20020a056e0220ee00b002cf38afd466mr1773699ilv.64.1651858934748;
        Fri, 06 May 2022 10:42:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:130c:b0:32b:8cba:d72d with SMTP id
 r12-20020a056638130c00b0032b8cbad72dls1604263jad.5.gmail; Fri, 06 May 2022
 10:42:14 -0700 (PDT)
X-Received: by 2002:a02:6626:0:b0:32b:7881:c62f with SMTP id k38-20020a026626000000b0032b7881c62fmr1955295jac.251.1651858934363;
        Fri, 06 May 2022 10:42:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651858934; cv=none;
        d=google.com; s=arc-20160816;
        b=nqoePieaED8NO2AxYxuRqdOlMyFOnnKZDcXKmmbjjzZQttyLx9dAAsjgXeAIfuSz/4
         8M4BwcnbbwDB3ZyKo3QWKO3xspTmx5aiDiXp2gSOfhhy4ztVSOVZGhqIqWE6/JozZCQ3
         Plx6FjBBJ7qRPz7EW0thnC51qH+DB4P+0rMWSIrOLWB9VoHLdu4qqhTxoAoayZ7KsxlZ
         k0iXTU6+3VV0ZGYS57NZn/YFGSOjnkX8wUDyKwF6VDxG2q3iE15y5FUz7D9cYUhzQFhq
         QqdDN2B+JZ3AakiZzg+4tEHjJMPRPGMMkEcqf0sMi5W/v0Ozx3CBvIHAraVQ9W3U5MSE
         YkFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YKfnJFHuOviCdMg0UB5UffT9B/WVcObEOxiRN5y2Kug=;
        b=bUS0ZVIgbqXyDITP7kon3W2jxMGrx1ZpYT9JsCagft7W58FZQ/JQd+I6OMoNV/7jjb
         jn9qDuW+pSDfHPqG2sR2Uul0ODqRzpV6eUrb3gzA7orWV+UQswDSO7Jvfv+d5r+a16uM
         3W/H4dIM5cqfVwCX0nSYhF5AGXOHZggVT2AHJvk2Stitqv414PaFlFuCcj9B/4o1UGry
         AoQSI8LUicCqm9SRdZcFR5H8UbJoYZxVGO2j7LmrKuFOvZlr99iSApXMOsXq00LGi0IX
         X1/+JTc7/gl3m4Y88y2qF/EU3i0AA3MDbzgj5gNbtwRqi8eCdlhBBIBgSsu5EkRGc5xq
         3NLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=emmUN3k1;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id g21-20020a05663816d500b0032b605d0db3si559445jat.1.2022.05.06.10.42.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 May 2022 10:42:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id v59so14071725ybi.12
        for <kasan-dev@googlegroups.com>; Fri, 06 May 2022 10:42:14 -0700 (PDT)
X-Received: by 2002:a25:bb0f:0:b0:61d:60f9:aaf9 with SMTP id
 z15-20020a25bb0f000000b0061d60f9aaf9mr3038082ybg.199.1651858933696; Fri, 06
 May 2022 10:42:13 -0700 (PDT)
MIME-Version: 1.0
References: <20220426164315.625149-1-glider@google.com> <20220426164315.625149-29-glider@google.com>
 <87a6c6y7mg.ffs@tglx> <CAG_fn=U7PPBmmkgxFcWFQUCqZitzMizr1e69D9f26sGGzeitLQ@mail.gmail.com>
 <87y1zjlhmj.ffs@tglx> <CAG_fn=XxAhBEBP2KJvahinbaxLAd1xvqTfRJdAu1Tk5r8=01jw@mail.gmail.com>
 <878rrfiqyr.ffs@tglx> <CAG_fn=XVchXCcOhFt+rP=vinRhkyrXJSP46cyvcZeHJWaDquGg@mail.gmail.com>
 <87k0ayhc43.ffs@tglx>
In-Reply-To: <87k0ayhc43.ffs@tglx>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 6 May 2022 19:41:37 +0200
Message-ID: <CAG_fn=UpcXMqJiZvho6_G3rjvjQA-3Ax6X8ONVO0D+4Pttc9dA@mail.gmail.com>
Subject: Re: [PATCH v3 28/46] kmsan: entry: handle register passing from
 uninstrumented code
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=emmUN3k1;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, May 6, 2022 at 6:14 PM Thomas Gleixner <tglx@linutronix.de> wrote:
>
> On Fri, May 06 2022 at 16:52, Alexander Potapenko wrote:
> > On Thu, May 5, 2022 at 11:56 PM Thomas Gleixner <tglx@linutronix.de> wrote:
> >> @@ -452,6 +455,7 @@ irqentry_state_t noinstr irqentry_nmi_en
> >>         rcu_nmi_enter();
> >>
> >>         instrumentation_begin();
> >> +       unpoison(regs);
> >>         trace_hardirqs_off_finish();
> >>         ftrace_nmi_enter();
> >>         instrumentation_end();
> >>
> >> As I said: 4 places :)
> >
> > These four instances still do not look sufficient.
> > Right now I am seeing e.g. reports with the following stack trace:
> >
> > BUG: KMSAN: uninit-value in irqtime_account_process_tick+0x255/0x580
> > kernel/sched/cputime.c:382
> >  irqtime_account_process_tick+0x255/0x580 kernel/sched/cputime.c:382
> >  account_process_tick+0x98/0x450 kernel/sched/cputime.c:476
> >  update_process_times+0xe4/0x3e0 kernel/time/timer.c:1786
> >  tick_sched_handle kernel/time/tick-sched.c:243
> >  tick_sched_timer+0x83e/0x9e0 kernel/time/tick-sched.c:1473
> >  __run_hrtimer+0x518/0xe50 kernel/time/hrtimer.c:1685
> >  __hrtimer_run_queues kernel/time/hrtimer.c:1749
> >  hrtimer_interrupt+0x838/0x15a0 kernel/time/hrtimer.c:1811
> >  local_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1086
> >  __sysvec_apic_timer_interrupt+0x1ae/0x680 arch/x86/kernel/apic/apic.c:1103
> >  sysvec_apic_timer_interrupt+0x95/0xc0 arch/x86/kernel/apic/apic.c:1097
> > ...
> > (uninit creation stack trace is irrelevant here, because it is some
> > random value from the stack)
> >
> > sysvec_apic_timer_interrupt() receives struct pt_regs from
> > uninstrumented code, so regs can be partially uninitialized.
> > They are not passed down the call stack directly, but are instead
> > saved by set_irq_regs() in sysvec_apic_timer_interrupt() and loaded by
> > get_irq_regs() in tick_sched_timer().
>
> sysvec_apic_timer_interrupt() invokes irqentry_enter() _before_
> set_irq_regs() and irqentry_enter() unpoisons @reg.
>
> Confused...

As far as I can tell in this case sysvect_apic_timer_interrupt() is
called by the following code in arch/x86/kernel/idt.c:

  INTG(LOCAL_TIMER_VECTOR,                asm_sysvec_apic_timer_interrupt),

, which does not use IDTENTRY_SYSVEC framework and thus does not call
irqentry_enter().

I guess handling those will require wrapping every interrupt gate into
a function that performs register unpoisoning?

By the way, if it helps, I think we don't necessarily have to call
kmsan_unpoison_memory() from within the
instrumentation_begin()/instrumentation_end() region?
We could move the call to the beginning of irqentry_enter(), removing
unnecessary duplication.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUpcXMqJiZvho6_G3rjvjQA-3Ax6X8ONVO0D%2B4Pttc9dA%40mail.gmail.com.
