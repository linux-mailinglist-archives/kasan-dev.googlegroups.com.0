Return-Path: <kasan-dev+bncBCCMH5WKTMGRBU4N4WJQMGQEGQNAXZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 33C735202F2
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 18:52:37 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id p187-20020a6742c4000000b0032d98ef9a15sf552544vsa.11
        for <lists+kasan-dev@lfdr.de>; Mon, 09 May 2022 09:52:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652115156; cv=pass;
        d=google.com; s=arc-20160816;
        b=rLxr7gmJwbWuTUqJPSjSb0vKczBmC2leffTOZp5BBjh89wg0npvtDBhSbFI71OPpfu
         tADV9TVEvbnb6xPA5TrQ+L97TU0cTE4b8PktMEdOgKeKp+FDa5K8LN0JliqM5+jgUfZG
         FmdrV+BhryeiHct4aRQmnzkEUv1fO8RgtvQLNj935UVk4pcYJJKVRv8KgbGToVvHYRs8
         iveajr0Qjfishlt5UQcKUZPKPBDHFh6/iKY/0ZpDgbg5TN4GS2rW6lLWy8yL/tkhFTFF
         patSHD+X5jKJeSjkFKh/uHYJmrodl1kns5na7wqXsxJXgFVrqj4lhrr3lZ7ZtqGUofJm
         SSFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=26a+7AEdiAomMpRKN0GOuqgw/HqFCJ+J3f5Jwt4oiQI=;
        b=pzagMJz4dDlGTmza9GLMeMZUN88LIqCeaIQ7MF7Yt2e9GHOQrRDkYW1CEny5HUuwUr
         YL5FXPsR99P8HHWW9fISRL0prfpyrlPF5X2L8daeL4PBXtD28LbKPF0zB+r0F6+UzRw4
         ArAncLKsQ/dFs4szNEaKjWW7X2BzLgNup+wrUYb74EUKvayfHZHcZ5OkcsQp0rI9POS6
         jvQCf2gFzdm02LPU8iH4eJRmWPclXQijotBtvDL9JMNMjBLzWRdt1gXC9/33n312oxhl
         1r/yGFbQCA6dB8V6zHIk2rFMM8Vt6ht9tB2ecjEr1PqB97rc23zsJCK3K2tH9u5JONjj
         wPLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CU57t1DG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=26a+7AEdiAomMpRKN0GOuqgw/HqFCJ+J3f5Jwt4oiQI=;
        b=Crsjj7i0MqZkQYhRTW0FU0hvGCif96+RFhhqIdhoXQa2zEL/pMCtVMg3xZjKYBnKWC
         7gj8/MG7fPWIUfcC7+AbQ/JMG5cAV+Hk5Hcfw6qb6bIYmDKc4S2UAFl45Uxw2j94y3VN
         cDHi8jbInZwAG7lAbxxFDVw4bObsRvNSBJ3dZqzQotJ7wBgdVXo8EoFP8YZe8pbQldfd
         zo8r53keXsvsnsss39DAJRmreFv579ncbtCJmUw9PFJkcbA5MXs9vxTK2EW6fpFh5zZ6
         zF/CEanJkCKI/3XCDj/rrJ/gFK/uFxzhi8rrphqUri1enh56V4xzzF5L6R3jMIjkzc50
         ybCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=26a+7AEdiAomMpRKN0GOuqgw/HqFCJ+J3f5Jwt4oiQI=;
        b=F/WeNwtaT8sqZvVfzhL0RyyD0OYd4sG4MIZUhIlJiyDU3H2w9vVw2rMIarfZKs1vI5
         Ju+yYtH2C8ON6vM6cQZXaAXlw6xJone2mADRzgOYccZxC6pNXdl/5ZjhsydRRSLYidDA
         xlX7f86RH0kpmwC963Em0pNU98BOiLq1sjYoMNMjZ87YKRUxZBHUWZsyeJi5vFmjWFUc
         GimZPLxEUumOw9SkI5NMsWEnJbpbEtUZiCoRIcBWtXVbgeiYsiwCM6VBiLnKn8r4oYaS
         Ega+A0eMsk+BuRttPbTjIxJ16t5Fmbd2nlzQLfuVk31HhgzuPtJ9Ac6xzPWCZ/LPjF7s
         fWSg==
X-Gm-Message-State: AOAM532NnJzJJzcDBbgNzXvQMN7tJ4XKvMZ2CiYrvWFr0l4atRHO++jo
	HdJuLsWse+X3O0Z4NgMbMMk=
X-Google-Smtp-Source: ABdhPJwMg81igoqiiE/00IvcVb97WIy9lbxMf51H0mIpUONemaojSy8j8TRh9WashCpr7JL1lMRE+w==
X-Received: by 2002:ac5:cda2:0:b0:351:cba8:d5eb with SMTP id l2-20020ac5cda2000000b00351cba8d5ebmr9402675vka.23.1652115156110;
        Mon, 09 May 2022 09:52:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2d90:0:b0:32c:de18:3114 with SMTP id t138-20020a672d90000000b0032cde183114ls3212532vst.2.gmail;
 Mon, 09 May 2022 09:52:35 -0700 (PDT)
X-Received: by 2002:a05:6102:254:b0:32c:e34f:5857 with SMTP id a20-20020a056102025400b0032ce34f5857mr8806824vsq.68.1652115155502;
        Mon, 09 May 2022 09:52:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652115155; cv=none;
        d=google.com; s=arc-20160816;
        b=EblD4VlRWSFGDbOPlSNbDv52i3fdecH6xMbk/CTIvPsIYdIwPtu2QowW5BMj+dqO5a
         NBUvNWnd9V4aV+yEVwiWGXYPnUNzz6dSUzYu0nLoDvdAVLOJMjS48LhkmY3LlrjSXZLI
         Igm+PHIunjgBw6Rxnnl8NAnsTJr2xChkACbbGbeZgRZ4Zogwb9dexQuWEZFwZsAtgnWe
         becWAYnjz2I82Vo5I/h1TzrvskkcAdI814UY0yyxrTwa4tKRwGLKmQlkN0xNs5a8kSAe
         BbF/Xf8bkkKszU3gI0oxrih5WuEe83+sBZ5m60xKJSRQ1fE8xvwq7x5Dsh8tfr7XF0Xl
         s2uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UXiFk325eT/uin6juY8MDs9uDbcZ0rRGYF4uwLrhYoM=;
        b=Y1/oJRHd8tgO2SpqESgcPP1N3nrpPPnIr9OfjcHyKbTzrcv0UdxvqkJ9W9ygU2lmIk
         3y/+HiQ+5vPuMXfYORlpQSlcqgTPyQVN/gGNTS1WOvc/OLGwYlU573n5A98YXxxlxZZh
         xEebcFUybpo6FlXWQDjf2CFLfNJSSMDPJ30fSKDKhLa5fUD6OM+/jSXmUQCS50di60Mv
         IVHwfPF79UTdNw2jWACd9vkOeTGaFNCoF40th2pLfEUl9mIwE6rG2gYSLIxSd17Hmlup
         +Rvd29zKSuGPUCpNwk6cavQe16DvxAMxw/eZTNRqMVhbYeQjezfLJuQ4jrVTw8Zzp6yk
         uBqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CU57t1DG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id m15-20020a05612210ef00b003529b5015acsi465183vko.2.2022.05.09.09.52.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 May 2022 09:52:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id w187so26053090ybe.2
        for <kasan-dev@googlegroups.com>; Mon, 09 May 2022 09:52:35 -0700 (PDT)
X-Received: by 2002:a25:e7d1:0:b0:645:7216:d9d0 with SMTP id
 e200-20020a25e7d1000000b006457216d9d0mr14454488ybh.307.1652115155053; Mon, 09
 May 2022 09:52:35 -0700 (PDT)
MIME-Version: 1.0
References: <20220426164315.625149-1-glider@google.com> <20220426164315.625149-29-glider@google.com>
 <87a6c6y7mg.ffs@tglx> <CAG_fn=U7PPBmmkgxFcWFQUCqZitzMizr1e69D9f26sGGzeitLQ@mail.gmail.com>
 <87y1zjlhmj.ffs@tglx> <CAG_fn=XxAhBEBP2KJvahinbaxLAd1xvqTfRJdAu1Tk5r8=01jw@mail.gmail.com>
 <878rrfiqyr.ffs@tglx> <CAG_fn=XVchXCcOhFt+rP=vinRhkyrXJSP46cyvcZeHJWaDquGg@mail.gmail.com>
 <87k0ayhc43.ffs@tglx> <CAG_fn=UpcXMqJiZvho6_G3rjvjQA-3Ax6X8ONVO0D+4Pttc9dA@mail.gmail.com>
 <87h762h5c2.ffs@tglx> <CAG_fn=UroTgp0jt77X_E-b1DPJ+32Cye6dRL4DOZ8MRf+XSokg@mail.gmail.com>
In-Reply-To: <CAG_fn=UroTgp0jt77X_E-b1DPJ+32Cye6dRL4DOZ8MRf+XSokg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 May 2022 18:51:59 +0200
Message-ID: <CAG_fn=X8mc9-_-S-+b9HuF4_-PhN3=1umu5twY8oYn1OgRhuLg@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=CU57t1DG;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as
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

On Mon, May 9, 2022 at 6:50 PM Alexander Potapenko <glider@google.com> wrote:
>
> > The callchain is:
> >
> >   asm_sysvec_apic_timer_interrupt               <- ASM entry in gate
> >      sysvec_apic_timer_interrupt(regs)          <- noinstr C entry point
> >         irqentry_enter(regs)                    <- unpoisons @reg
> >         __sysvec_apic_timer_interrupt(regs)     <- the actual handler
> >            set_irq_regs(regs)                   <- stores regs
> >            local_apic_timer_interrupt()
> >              ...
> >              tick_handler()                     <- One of the 4 variants
> >                 regs = get_irq_regs();          <- retrieves regs
> >                 update_process_times(user_tick = user_mode(regs))
> >                    account_process_tick(user_tick)
> >                       irqtime_account_process_tick(user_tick)
> > line 382:                } else if { user_tick }   <- KMSAN complains
> >
> > I'm even more confused now.
>
> Ok, I think I know what's going on.
>
> Indeed, calling kmsan_unpoison_memory() in irqentry_enter() was
> supposed to be enough, but we have code in kmsan_unpoison_memory() (as
> well as other runtime functions) that checks for kmsan_in_runtime()
> and bails out to prevent potential recursion if KMSAN code starts
> calling itself.
>
> kmsan_in_runtime() is implemented as follows:
>
> ==============================================
> static __always_inline bool kmsan_in_runtime(void)
> {
>   if ((hardirq_count() >> HARDIRQ_SHIFT) > 1)
>     return true;
>   return kmsan_get_context()->kmsan_in_runtime;
> }
> ==============================================
> (see the code here:
> https://lore.kernel.org/lkml/20220426164315.625149-13-glider@google.com/#Z31mm:kmsan:kmsan.h)
>
> If we are running in the task context (in_task()==true),
> kmsan_get_context() returns a per-task `struct *kmsan_ctx`.
> If `in_task()==false` and `hardirq_count()>>HARDIRQ_SHIFT==1`, it
> returns a per-CPU one.
> Otherwise kmsan_in_runtime() is considered true to avoid dealing with
> nested interrupts.
>
> So in the case when `hardirq_count()>>HARDIRQ_SHIFT` is greater than
> 1, kmsan_in_runtime() becomes a no-op, which leads to false positives.
Should be "kmsan_unpoison_memory() becomes a no-op..."

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DX8mc9-_-S-%2Bb9HuF4_-PhN3%3D1umu5twY8oYn1OgRhuLg%40mail.gmail.com.
