Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZNV4P3AKGQE3JSGN2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CA281EE368
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 13:28:38 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id v3sf1834006pjy.7
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 04:28:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591270117; cv=pass;
        d=google.com; s=arc-20160816;
        b=IXuA4tCBDuAtVUBiwaRP7FDRH2nesPu2d0V4fk+xxj0/jrwy1wvKxqF74JMalOjpFe
         bqsK3w82y8Dbhd6ow54Ww+7LScEuJzrqWiYZzLA1nBuICsW3GIog2BGHVtJ1VvZa72Zn
         /1bxTXPYtmN9TQIjYYHXoHYb8Fl1+i3ciy30H1gZvyWgEhvuRtzKbN92WeLO1qM2tmwH
         hRhgUZxLx2y4XIzt1ZCWgBpt+DWVYN9YvhzLsqFhBaeomGhfqvpVeBjIPrUyUVs01m3m
         CG4yEfl5YA3kA6LMcMHkhFz9H6mUpv5leNFvz2Yv576eulR2yzdela/szonqeBsG+cCD
         q9hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CP1u7QGbc/g2gtSDwWiiFcn/sY00l1h6Bqk/vYLK+Do=;
        b=H6wKaXCUcwD1C5Ytyqmzba8wlkSMIUkiIZyvww+49Yb0tmmUfhN16sttiD+lqdR1Kp
         gC/kA/gEVZHdHQiDfFSdOYv3T9n3AQhNqLrqkSA76SIgHRW9r3vMzeZs5TICQGRxqwch
         KWRKHUnepNvnIccvbJI4iQLJuoSyy9zBkYOzdJ6WDQo/behEsgIeHroGF5Y+QE/Gitcd
         8eWfDPQyiybtTqi/j8WJlYXh5rPmqwzRk6I90+12o0skHPlpjoNYsXKUv04l+RL53hf6
         tmr47uyPZD7jGTIvYIs5IC4DlhnAycPPW1CH4c8EniKQfS+pav2ZAvp+eGj8O+xgV3xO
         q3dQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JRQAvggw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CP1u7QGbc/g2gtSDwWiiFcn/sY00l1h6Bqk/vYLK+Do=;
        b=asgOoWZYX4J6J3+mo8os0RpmSKvZxd9qg6CNdS1FJv/dFr1kNW4niwQBbzAmDJJGuz
         2TWfqCFv4bUYLSGyEL3HekeW/EvZvW1gDOlUxrj85nz43b9WekXYetIxtn0xP0EPIiV1
         AKUnzgZg+4LAe1tenwEL3eLRJblQuXUwtwNPeaOppWUQHVXyS+TCeb6cV8VDVfHSV37N
         vPaiEjFJLbJ2EJ15vt/1WVFBJUmuQSNn16d/SmG3ttbvMYsPQKjSOTqk8tYXXm+vzMNC
         GqAiBUklDH7/M3LD/ccBcEDVcY/uRzyZy8KW5/rsA0Wq75ZR5iWW+OPcKCciaPBfXbPG
         9nJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CP1u7QGbc/g2gtSDwWiiFcn/sY00l1h6Bqk/vYLK+Do=;
        b=Nnp/+mUu2U5rV+WFO8ng8hgw+pwek+g4oHWCXmeKpsz2oBbGwyHwOx1+cyE7R6N9g5
         w9Sh413NlTO45X4Y+hjfjdktuKWlHwtR5x8RG+u74rGidFn4dGPtxiqCbt1KDEizkfcf
         F0cZ5YdWlnD6INqTXnSuxInBJlAuZDV/ktoe47fbOsmmJ/bzZG1YbzvdY5oovnD2dDg7
         0m7tJGvJWjyoOip7O8AAmxAYSBZ6duEaHwr0acZhyOtICnUvnmFTQAGBP4LS2HneDB3I
         gKNzTQlxomo8EVNMDTimSpEcXRzcq3iIbpFPsSrkCYPYRS0CmiKfMVHXdxXw/3IbxaP0
         IDMg==
X-Gm-Message-State: AOAM5336i9Yyo4JUllxl0dTD38q+Ux0xPzujzqZrJyZe7ck1KE1iOeOM
	H/y3fDhXVCmuk7Enb0CQGGc=
X-Google-Smtp-Source: ABdhPJyrrOb4FoBYYR1IqrE8ynhI77qq8MOn3nIoUk9p76bqkntJx8KgcPcdvhk3KvjBNo2VZsSLmA==
X-Received: by 2002:a17:90a:4d09:: with SMTP id c9mr5684183pjg.137.1591270117202;
        Thu, 04 Jun 2020 04:28:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ab89:: with SMTP id f9ls2100754plr.3.gmail; Thu, 04
 Jun 2020 04:28:36 -0700 (PDT)
X-Received: by 2002:a17:90b:28d:: with SMTP id az13mr5739818pjb.67.1591270116768;
        Thu, 04 Jun 2020 04:28:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591270116; cv=none;
        d=google.com; s=arc-20160816;
        b=0G1L8r1cW/POP3SxlaV4ozYHVBJx+IxVZFbF3Jvopj/f+Re+GjKaZZhuh6Gsvcesel
         cwx/sGimcL39fCjyTqdYR+burydtFUi0gj3QHcZw2IbLdIfiRp16aUABiCGXEeN+ymLw
         bYASryQ5j0wg38hQcsi5a8c6lt0DZvl1GtimYRVQiNBi610kLVZl8NURWK2OSG3D1Jnh
         3EF34Hs3bNRAjxyafesd83EOMtfMl95P7Tt9OqC7ZzndByTWkXolr7sQxgjB8MpRLjr/
         QXqUUdukGr8cEnbx9mfedBmRYFmM1SOPJV+HKhnVVbalIPNPwbVhTFACM51GV+KOlj97
         mE9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0Wd046SRnNXPmZWQmANFyPx5YHXn43TLrkGNrhSkVE8=;
        b=n4GvzDRhbUf1YcOw9KzllnTYrzVWwH/towGJyAOrzwxulAAhfH5fnkADpm7KIS4vme
         tHY+RDXshGZ4tHDh8ZBhsM6Zd+suKDVQvG4YppFWSiLCrGiIf+cHhmwCA8tKi0vyh2rd
         KrN1V4rXtoDOMkZFYVTG0g2HWjAKyyjauNbwXzFlhYKi8MYzzKGgS5ovJyvZMQx4KaaK
         ZgRbWn36JWGnbTkAA5jDILuraGVp6aUEQYXrgWFPDH10k8dGa0ULvMz7C4K3p99zygac
         GiGhL+D4gCjDIwyvZZCpLCEX3XSh1DhwjlG9LRtZchKwnlqQPlqDI08uU/iE1xIGa+Li
         3hqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JRQAvggw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id i4si203723pgl.0.2020.06.04.04.28.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Jun 2020 04:28:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id a21so4737645oic.8
        for <kasan-dev@googlegroups.com>; Thu, 04 Jun 2020 04:28:36 -0700 (PDT)
X-Received: by 2002:a05:6808:3ac:: with SMTP id n12mr2720496oie.172.1591270115850;
 Thu, 04 Jun 2020 04:28:35 -0700 (PDT)
MIME-Version: 1.0
References: <20200604095057.259452-1-elver@google.com> <20200604110918.GA2750@hirez.programming.kicks-ass.net>
In-Reply-To: <20200604110918.GA2750@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Jun 2020 13:28:24 +0200
Message-ID: <CANpmjNPgqjZaz9R9dq_4xiRShcFTX0APyqfsX1JhBZo9ON-kCg@mail.gmail.com>
Subject: Re: [PATCH -tip] kcov: Make runtime functions noinstr-compatible
To: Peter Zijlstra <peterz@infradead.org>
Cc: Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JRQAvggw;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Thu, 4 Jun 2020 at 13:09, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Thu, Jun 04, 2020 at 11:50:57AM +0200, Marco Elver wrote:
> > The KCOV runtime is very minimal, only updating a field in 'current',
> > and none of __sanitizer_cov-functions generates reports nor calls any
> > other external functions.
>
> Not quite true; it writes to t->kcov_area, and we need to make
> absolutely sure that doesn't take faults or triggers anything else
> untowards.

Ah, right.

> > Therefore we can make the KCOV runtime noinstr-compatible by:
> >
> >   1. always-inlining internal functions and marking
> >      __sanitizer_cov-functions noinstr. The function write_comp_data() is
> >      now guaranteed to be inlined into __sanitize_cov_trace_*cmp()
> >      functions, which saves a call in the fast-path and reduces stack
> >      pressure due to the first argument being a constant.
> >
> >   2. For Clang, correctly pass -fno-stack-protector via a separate
> >      cc-option, as -fno-conserve-stack does not exist on Clang.
> >
> > The major benefit compared to adding another attribute to 'noinstr' to
> > not collect coverage information, is that we retain coverage visibility
> > in noinstr functions. We also currently lack such an attribute in both
> > GCC and Clang.
> >
>
> > -static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> > +static __always_inline void write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> >  {
> >       struct task_struct *t;
> >       u64 *area;
> > @@ -231,59 +231,59 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
> >       }
> >  }
>
> This thing; that appears to be the meat of it, right?
>
> I can't find where t->kcov_area comes from.. is that always
> kcov_mmap()'s vmalloc_user() ?

Yeah, looks like it.

> That whole kcov_remote stuff confuses me.
>
> KCOV_ENABLE() has kcov_fault_in_area(), which supposedly takes the
> vmalloc faults for the current task, but who does it for the remote?
>
> Now, luckily Joerg went and ripped out the vmalloc faults, let me check
> where those patches are... w00t, they're upstream in this merge window.
>
> So no #PF from writing to t->kcov_area then, under the assumption that
> the vmalloc_user() is the only allocation site.
>
> But then there's hardware watchpoints, if someone goes and sets a data
> watchpoint in the kcov_area we're screwed. Nothing actively prevents
> that from happening. Then again, the same is currently true for much of
> current :/
>
> Also, I think you need __always_inline on kaslr_offset()
>
>
> And, unrelated to this patch in specific, I suppose I'm going to have to
> extend objtool to look for data that is used from noinstr, to make sure
> we exclude it from inspection and stuff, like that kaslr offset crud for
> example.
>
> Anyway, yes, it appears you're lucky (for having Joerg remove vmalloc
> faults) and this mostly should work as is.

Hmm, looks like this doesn't generally work then. :-/

An alternative would be to check if '__noinstr_text_start <= _RET_IP_
< __noinstr_text_end' in __sanitizer_cov-functions and return if
that's the case. This could be #ifdef'd when we get a compiler that
can do __no_sanitize_coverage. At least that way we get working KCOV
for now.

Would that work?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPgqjZaz9R9dq_4xiRShcFTX0APyqfsX1JhBZo9ON-kCg%40mail.gmail.com.
