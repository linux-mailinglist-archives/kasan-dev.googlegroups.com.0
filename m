Return-Path: <kasan-dev+bncBCMIZB7QWENRB2WR5T5AKGQEXCTHC3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id C19D8265A96
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 09:36:11 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id 196sf5406882qkn.6
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 00:36:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599809770; cv=pass;
        d=google.com; s=arc-20160816;
        b=00YO6POsHEn/mgSV6WMrPihiHyuN5yjfrZ0NID/R20fknrFMtHbLYz3Z1jMW3iJ6xv
         pBBZRQx6gFk388uJEbnc/4CRfkKRK/vlvH+b6tzHlvwycQ5zwo83A4CqsNwnNey6nnHv
         Ly6ubpG+VkT2TWrnn/oyLNCrJPLmycbWBbpBWcCmpUir3z6SyrD06Qf385iBkQyVJ3vp
         7XjQ09Buf8/U1mYG0R8UjseY5sha3ZodNvZixNPSzl93GfL3a9Q2JWfdiT/uVuSWFJct
         H3RDnVEM5tSyhsTK1c/AaenVZ55HjPUTeImhMer4BXKzvskxJ+KvbprImcedLyC+zmc5
         7umg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3Pes1lU/x7eoSGK+j69b1I9ioyG6RGgWSgZK6qD8PTo=;
        b=kHqzRVd4FM7vsFTfJmlOA9ZY5o8XermsprrGu1gW5NJFT19ksGqI/qPf1YK/uGkFnn
         Idd0n7Eb+NT+FQssti5wTwMvD1RNoNP+oBv4sUpXwITKGSYKwCzQT7nJAeTXFzLTxnWI
         iOcYi/BXV6zyJEV7bZjffNVne+rECEM/De5nVGXfYHQSR4xhOBS63UHN498yxl7jhsCe
         2+nn4zYB+Qiw0lkskostPlrzXcXTOTXYE/FQAqEUph03evuuavDbcMKazbEl/UI4nmHI
         6dwy74CM0bh7WpXHIVgbIhCRi5pbTMDR9yC9OJ4xZqDru9nIbn72w3q+wme5tu8GHoi6
         NrJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="JiUND/gj";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3Pes1lU/x7eoSGK+j69b1I9ioyG6RGgWSgZK6qD8PTo=;
        b=m0snqwIjV54E8ASzdKHLUNP7ySvaIgNOwLMn2BkD6GK9l5zf7KMcAXPyAvxEZI/NHR
         neaq0TvNpRtbIajD3XBEsOPI4FDVl+TBZoRagXlBYcOdyyGS9bXUoNmE3Rxy0vLB6U5i
         83hJP7btr9xKoQS6eu93qUeDOZ2ATjOXbZrbr8eQXQ95bQiEHWchIWFWQYBRtfA3VVLf
         eW5xUqltIe8z65KctLy3/LPcWc9BV4UFi+eXfcDy3mJi0eqOAIEQh9gKOQ8gKM74JkOj
         cVirBxYBFUn2xjH8VWQkuCThG4nhUacMypB9HPyiUxosj3Yc7iaQ+vSKTmxzvq+uFpQ1
         VGhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3Pes1lU/x7eoSGK+j69b1I9ioyG6RGgWSgZK6qD8PTo=;
        b=l3GUrTsM4B2PLniK7geRzW3O3jrgWY0tq/rEz/gW6DfcA2ogZmE+zvUWp5guzg19r2
         oWMQlOOrOhDb06ACnWXdgUV5qH6Ql/FJ7aj5CZ3q0R1vA7r0dwaG3HdbMD78TXjGJzPZ
         XP8vbyN87pyjUXTS4qQ7LqjbOw88fluiNgU0kvT6SmSr14vjjCjf8DL3CauYeR4vXsEu
         dBNzvlQJnYQ82/w7D5R4Pcno1P/Ai1bSJSOIeey14pEpmM9WwYS5psmHq2tGRxE5PZT0
         RgNUwvr7ab6QsFaMmbYKnLlM0chtvKZ7DMNvIiaF48daFy0bD5g9Ya88eVZhYLn+sZEE
         bUGQ==
X-Gm-Message-State: AOAM530Bt/B4pnq1TOss+VVpeUo9mGLBrwuxxdGMADGlHhYfhkD7XSl4
	B0IAkla5g6DwyYf6DCIJweQ=
X-Google-Smtp-Source: ABdhPJxsxtKz0vEIvEYcxDw4kCkvcldP3Aj0jhBA/UcpUsz46B1Vp+Nb9ZT1cJzYNPvM3d6pGHEbbQ==
X-Received: by 2002:ac8:5205:: with SMTP id r5mr644016qtn.371.1599809770506;
        Fri, 11 Sep 2020 00:36:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:24ba:: with SMTP id t55ls510734qtc.8.gmail; Fri, 11 Sep
 2020 00:36:10 -0700 (PDT)
X-Received: by 2002:ac8:4d07:: with SMTP id w7mr690055qtv.243.1599809770013;
        Fri, 11 Sep 2020 00:36:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599809770; cv=none;
        d=google.com; s=arc-20160816;
        b=QwX2Ptjn+o/BqsVH/J5v1/iKZm5mtifsc3+r0/oiX0BYEEhYgTePdUAxWiKG62Syhk
         QkZJ0TLF8L5ibWv26+dWaQG5oMUQPQs1iTnxXBpQ/QKR3e/E0u2me755SDDLvAsrqMXc
         nJHgt8eXR76i0BcEYTar06n4QLPwHGZqckE62wYdQG8po7gBGmlt9TAXy/LLKHUxwBs0
         5a8u77UTmtUHGUfgmNzxnlI7z99+4I9M2vgwVB0o9sDyxhINo1oViAv1+qpvfeS+6QwX
         S6hbe9VSuP5naWT2DVgt5W0JBGX+qzZmILeUsmvSbrnm9BersTsaSxAchA7O1LhXftyf
         3gtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AgNHmGolg065FIPbyM/md78J/4QNU3wlyP9uV/8/RYg=;
        b=1K0xkojkXxq60AFaY5GEKELteXxbVipwEOLjfzP52M46fZq8od33Bm6w24px8YfDf2
         rq8Kxt8urkZnpgqnenCLz4f7LDagkS4t8sfxuRjuEG8ImT3mCVZ8aY8UbLH7ofBEACc3
         zPMAkefy7tqIZwDHzQLuSGD7R3NScj7NhVaQaXIW5Hk+fgLzpbIDs8N70vQs3O9L2+WH
         kMN1w2Y9XqUpyW8f7urwVzxrUs4iesYqcJ5r9zkDF01lJHuK3kLchs4Q5lTjmaw8ZafI
         1eoOW7Rbv4zjHnPBzg/wgVhYAR8IMulLTtZ9S/uxt4QHNHhlyQiLAJ3Puk9UG+xoxrqq
         AZRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="JiUND/gj";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id a27si104469qtw.4.2020.09.11.00.36.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Sep 2020 00:36:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id t20so7116815qtr.8
        for <kasan-dev@googlegroups.com>; Fri, 11 Sep 2020 00:36:09 -0700 (PDT)
X-Received: by 2002:ac8:5215:: with SMTP id r21mr667601qtn.257.1599809769436;
 Fri, 11 Sep 2020 00:36:09 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <e399d8d5-03c2-3c13-2a43-3bb8e842c55a@intel.com>
 <20200908153102.GB61807@elver.google.com> <feb73053-17a6-8b43-5b2b-51a813e81622@suse.cz>
 <20200908155631.GC61807@elver.google.com>
In-Reply-To: <20200908155631.GC61807@elver.google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Sep 2020 09:35:58 +0200
Message-ID: <CACT4Y+YZqj0CJTumpHr-g9HcRgs+JHwWP5eg1nYHP0E-Zw25DQ@mail.gmail.com>
Subject: Re: [PATCH RFC 00/10] KFENCE: A low-overhead sampling-based memory
 safety error detector
To: Marco Elver <elver@google.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Dave Hansen <dave.hansen@intel.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>, 
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="JiUND/gj";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Sep 8, 2020 at 5:56 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Sep 08, 2020 at 05:36PM +0200, Vlastimil Babka wrote:
> > On 9/8/20 5:31 PM, Marco Elver wrote:
> > >>
> > >> How much memory overhead does this end up having?  I know it depends on
> > >> the object size and so forth.  But, could you give some real-world
> > >> examples of memory consumption?  Also, what's the worst case?  Say I
> > >> have a ton of worst-case-sized (32b) slab objects.  Will I notice?
> > >
> > > KFENCE objects are limited (default 255). If we exhaust KFENCE's memory
> > > pool, no more KFENCE allocations will occur.
> > > Documentation/dev-tools/kfence.rst gives a formula to calculate the
> > > KFENCE pool size:
> > >
> > >     The total memory dedicated to the KFENCE memory pool can be computed as::
> > >
> > >         ( #objects + 1 ) * 2 * PAGE_SIZE
> > >
> > >     Using the default config, and assuming a page size of 4 KiB, results in
> > >     dedicating 2 MiB to the KFENCE memory pool.
> > >
> > > Does that clarify this point? Or anything else that could help clarify
> > > this?
> >
> > Hmm did you observe that with this limit, a long-running system would eventually
> > converge to KFENCE memory pool being filled with long-aged objects, so there
> > would be no space to sample new ones?
>
> Sure, that's a possibility. But remember that we're not trying to
> deterministically detect bugs on 1 system (if you wanted that, you
> should use KASAN), but a fleet of machines! The non-determinism of which
> allocations will end up in KFENCE, will ensure we won't end up with a
> fleet of machines of identical allocations. That's exactly what we're
> after. Even if we eventually exhaust the pool, you'll still detect bugs
> if there are any.
>
> If you are overly worried, either the sample interval or number of
> available objects needs to be tweaked to be larger. The default of 255
> is quite conservative, and even using something larger on a modern
> system is hardly noticeable. Choosing a sample interval & number of
> objects should also factor in how many machines you plan to deploy this
> on. Monitoring /sys/kernel/debug/kfence/stats can help you here.

Hi Marco,

I reviewed patches and they look good to me (minus some local comments
that I've left).

The main question/concern I have is what Vlastimil mentioned re
long-aged objects.
Is the default sample interval values reasonable for typical
workloads? Do we have any guidelines on choosing the sample interval?
Should it depend on workload/use pattern?
By "reasonable" I mean if the pool will last long enough to still
sample something after hours/days? Have you tried any experiments with
some workload (both short-lived processes and long-lived
processes/namespaces) capturing state of the pool? It can make sense
to do to better understand dynamics. I suspect that the rate may need
to be orders of magnitude lower.

Also I am wondering about the boot process (both kernel and init).
It's both inherently almost the same for the whole population of
machines and inherently produces persistent objects. Should we lower
the rate for the first minute of uptime? Or maybe make it proportional
to uptime?

I feel it's quite an important aspect. We can have this awesome idea
and implementation, but radically lower its utility by using bad
sampling value (which will have silent "failure mode" -- no bugs
detected).

But to make it clear: all of this does not conflict with the merge of
the first version. Just having tunable sampling interval is good
enough. We will get the ultimate understanding only when we start
using it widely anyway.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYZqj0CJTumpHr-g9HcRgs%2BJHwWP5eg1nYHP0E-Zw25DQ%40mail.gmail.com.
