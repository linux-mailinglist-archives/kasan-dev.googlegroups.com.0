Return-Path: <kasan-dev+bncBDQ27FVWWUFRBXND62FAMGQENVGGYBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C64B423D76
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 14:09:03 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id j26-20020a4a92da000000b002a80a30e964sf1585158ooh.13
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 05:09:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633522141; cv=pass;
        d=google.com; s=arc-20160816;
        b=nO9ATG4R5ccVePL64rZmyRdE0LlJFl7Yf7qsH2rEJNHwDTkxvwcqH8tf/5j4tYsDy3
         BvrLQxU6MdtvkqzyBmav1s9pZd4j9I3pjLI9pQGvFoHQZ0I3BoU6yB8wdhhcdujHP7gt
         gi40XJrS0CasxDYNvpqaNOjWJl2Dg5pVS9mXa3f6Rgv6zxGRUw31rRCb9iFOVqZ+f2Cf
         S3PJxQHga/Lft7gJ3cxlGOo/58nyy/Hahw6qrRQiE8s5tFx8QgosMYNYZ1AwbGu/mUef
         fF4OSckp8ZmEAs7qTmm7bbm/MBjCECQgyp1jdy9PCEbwug1D8XTOkO4aJ6XWXB8fPJX8
         YPtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=//0XvfxiuWZPYexvHtlmfkA761rEAKaUTnc8lTbF2gk=;
        b=ke7Lty29k61AOpAEJCpZCvUo98Y/ZBusZSSRhtZhp1pFbr6qkxmcGwdFkxHw+WXvJN
         4+8oi91hVHy33Z8sMC2jByQoYuJoyP7kUB4rt9ZqL+jkf0UDbIgOXXlzP56mA7sD455i
         TMbPs5YOCY0ClrnMxsdaQaO8CPmWV8elZxfOpB7eTSP8qhzJ/6+GWG/q3hLXNSvEQuii
         HWYLtqL2UmhHcxMLg8L3Tt9hE+sMWQFkZ2MzcbTNQDPgcCqezIkVy9+6qKtZzSAe/un/
         4lW+CP1WroBMX1Y7aNC/gDFcyzzys9BHK09kRZUzYXeaTz5ogiejcX02RfOOyh1/rEv2
         UgNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=N00Lzp22;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=//0XvfxiuWZPYexvHtlmfkA761rEAKaUTnc8lTbF2gk=;
        b=W/VG1f36YHlhHNBCZMYVPBgCaAZmW2zwYhhFTMQHICHu4igKEMAjjY4fUv1qCkif3T
         Pn+P/liIdnUHhfPEmnUPgEqLBIJCOXnhQBJFYdKEqYEUN5DDGsT8sq16H9FrWxmnBhBV
         sAdilPwepQDPbozOI7bJYzZZJOudh5KEHYtOQ2bHl6QJZvhgfaC4IqQVPaEX7YT67foJ
         ANQf232RVgYPhuQZNMzv1NdTXFo7Y2claPmogN1YP+3fVvhPhKx4jjhLz6Eh4wMNPd+Y
         nCCKJ19KFqOn2FSAFAhbZEYKj0zIli3d3Z+DeF896bj4GJ050JX97VLvYCktWN6nEcnT
         2LMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=//0XvfxiuWZPYexvHtlmfkA761rEAKaUTnc8lTbF2gk=;
        b=pTCADbu0q48ejhcqxpDdpFQM18zbXgFP4dGqDbg/vv+fpfK3V/M+uJ+zyJJ3dvXjg4
         md3tDwZnqPUJ4b8UGz/LWsV79RQZy1H6ZQUYYhX33qZBpc2Au17ZOWbRLKe+mVwF94s3
         YCJ9MI4NiTEw/aarUo3ZfjJebC2IlcmHc6SGgSdY7jNBZnf1Szt0XxCMeqYNzIYWENun
         YwKlfAxC417JnZwxBPw5E6WlnIYbZSA0w8rlQQO2qp2bDOzF7Kcoh7vdytCyGQvIqKO/
         9R7z3Wiy0V/FqyifxtNZ+OKU9v509oR4m7uikLFoz/Gm/X6R+DhKeGIiP16OZ/xySdu6
         PFcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530SjXAJUL04TjzBNIOWdJwjikwhpc3ySVUKBIHuUS5nImzIHUvX
	bQnIVvS0raFk2A8vo08eYg8=
X-Google-Smtp-Source: ABdhPJxWe/BKM0iXPE1iwHF/UNZQ4FJKHPfsvc1WbwIImjb9osyXlFW1IJf8w2pn1jtZ21dMHnAI1A==
X-Received: by 2002:a54:4f0e:: with SMTP id e14mr7057534oiy.73.1633522141823;
        Wed, 06 Oct 2021 05:09:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:df56:: with SMTP id w83ls5014743oig.3.gmail; Wed, 06 Oct
 2021 05:09:01 -0700 (PDT)
X-Received: by 2002:a05:6808:1387:: with SMTP id c7mr6820393oiw.151.1633522141405;
        Wed, 06 Oct 2021 05:09:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633522141; cv=none;
        d=google.com; s=arc-20160816;
        b=vzSxcvECVZzKfgkReQKXjpeE6JQ1cbAkclvDGhAyR/aHaljTjj63B75mj5tmoNAQai
         H1jKMTdRY6Q6OS0VitCMbh6MKm1j/PVGX5NnFpYDTNbR3dW/AmJ7jkiOGVKHONiM4LxQ
         14RH58XffF2RLjCnHvDx6FxZ5LFqE8KgEt4dMs2RsVvCq1iNbFbkR744y7lWrtugqNIr
         U++ujo4tKv9ioa9QF/KZkebrALLG6g8Fb+PKwLbzhmQMJzf/blIJid/DpwUYN/VoxSUZ
         0qmquSd48D1Sr8hXYSou3CD/HUBx1jjYaTzxpsvqf3uN4EHhxGgtxo7iZ2n+MLEZh5cu
         jUXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=V33FRyfxRCOnEo8u7n9r2mHqIS4K2al0g2rrhqi7dVU=;
        b=D7lvPskNHE6UWh0BUg7s27N13/iCk+FNFA14GH5WHJk7qRkqSaTw6RPTETy8gDJxBk
         /hOh/DmDboZxD9m84MJvDQK+31RLXbJNHCEkmbL+dxREB8SGdHA0gphDwAWDUADo+Bfb
         t7nX0gcV28gDX5V9Hiz98DoJdU07snOCYc57j4aHJ9B7Z510EYRpH8ifGcYjRvYspdGW
         bBJD7M0uPCxft9g0EiKqL++OWZL8sJKdm+KYzO022eDU+Ekgw0sIUSo6g1dJznyt2tPc
         LVwHPkBJsoonQnxkrugK4RcCAk+kEr5Ru2ICzjt4waiEA7Uo9AsHrJ1DhxQoDWjkP7NB
         M6lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=N00Lzp22;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id m30si2064043ooa.1.2021.10.06.05.09.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Oct 2021 05:09:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id a73so2343662pge.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Oct 2021 05:09:01 -0700 (PDT)
X-Received: by 2002:a05:6a00:2311:b0:431:c19f:2a93 with SMTP id h17-20020a056a00231100b00431c19f2a93mr36461867pfh.11.1633522140499;
        Wed, 06 Oct 2021 05:09:00 -0700 (PDT)
Received: from localhost ([2001:4479:e300:600:322:fa78:c55e:6913])
        by smtp.gmail.com with ESMTPSA id h6sm5249368pji.6.2021.10.06.05.08.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Oct 2021 05:09:00 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Peter Zijlstra <peterz@infradead.org>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 paulmck@kernel.org, rcu@vger.kernel.org, Thomas Gleixner
 <tglx@linutronix.de>, Mark Rutland <mark.rutland@arm.com>
Subject: Re: instrument_atomic_read()/_write() in noinstr functions?
In-Reply-To: <YV1W8FAV6h2t5gQo@hirez.programming.kicks-ass.net>
References: <871r4z55fn.fsf@dja-thinkpad.axtens.net>
 <YV1W8FAV6h2t5gQo@hirez.programming.kicks-ass.net>
Date: Wed, 06 Oct 2021 23:08:57 +1100
Message-ID: <87k0iq4ap2.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=N00Lzp22;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::535 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Peter,

Thanks for your quick response, it is extremely helpful.

>> commit b58e733fd774 ("rcu: Fixup noinstr warnings") adds some
>> instrument_atomic_read calls to rcu_nmi_enter - a function marked
>> noinstr. Similar calls are added to some other functions as well.
>
> It moves the instrumentation, it was already there. Specifically:
>
> -       seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
> +       seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
>
> removes the instrumentation from the critical place where RCU isn't yet
> watching, which is then added back here:
>
> +       // instrumentation for the noinstr rcu_dynticks_eqs_enter()
> +       instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));
>
> Once it's deemed safe to run instrumentation.

Ah, my bad.

>> This is causing me some grief on powerpc64 while trying to enable
>> KASAN. powerpc64 book3s takes some NMIs in real mode, and in real mode
>> we can't access where I'm proposing to put the KASAN shadow - we can
>> only access it with translations on. So I end up taking a fault in the
>> kasan_check_read path via rcu_nmi_enter.
>
> Then your entry ordering is wrong :-( RCU should be the very last thing,
> once RCU is watching it should be safe to run instrumentation.
>
>> As far as I can tell `instrumentation_begin()` and
>> `instrumentation_end()` don't make it safe to call instrumentation, they
>> just tell the developer that instrumentation is safe. (And they are used
>> to check the balance of _begin()/_end() blocks.)
>
> That is correct. In that respect it is an unsafe (pun intended)
> annotation. The annotation can be used to annotate away actual
> violations (although the one at hand is not one such). There are some
> explicitly unsafe annotations like that though, typically WARNs in early
> init code where we really can't do much better than to ignore and hope
> the error gets out.
>
>> Is the underlying assumption that the KASAN shadow will always be safe
>> to access, even in functions marked noinstr? It seems to undercut what
>> an architecture can assume about a function marked noinstr...
>
> The assumption is that RCU is the very last thing in the entry code to
> be enabled, and the very first to be disabled. Therefore, the moment RCU
> is active we can allow instrumentation, and hence the
> instrumentation_begin() is correct there.
>
> The NMI dance on x86 is particularly nasty, but the first part
> (currently all in entry_64.S) ensures the kernel page-tables are active
> and that we have a kernel stack.

Yeah, this is where we come unstuck. We don't always activate kernel
page tables/turn on data relocations/leave real mode/whatever. In some
cases we run in real mode for (I believe) the entire NMI handler.

> Then we call into C, which is still gnarly and deals with
> self-recursion, but eventually calls irqentry_nmi_enter(). This then
> carefully frobs the preempt, lockdep and rcu states into the right place
> after which we have a fully 'normal' C context.
>
>> P.S. On a more generic note instrumentation_begin()/_end() is now
>> scattered across the kernel and it makes me a bit nervous. It's making a
>> statement about something that is in part a property of how the arch
>> implements instrumentation. Are arches expected to implement things in
>> such a way as to make these blocks accurate?
>
> Yes, there's only a limited ways in which all this can slot toghether
> due to all the nasty inter-dependencies. Thomas and me spend quite a bit
> of time trying to untangle the web such that we have a coherent
> entry/exit ordering that's actually workable.
>
> Pretty much everybody had this wrong and was/is broken in various
> non-fun ways.

Fair enough. What exactly are the preconditions for instrumentation?  In
other words, what must the arch ensure is true before we pass an
instrumentation_begin()?

I know from KASAN that we need to be able to access the shadow memory,
which on most (all?) platforms means we need relocations/virtual
addressing on. I don't know what else needs to be satisfied. (I'm
guessing we want to be in a position where taking a fault won't bring
down the system, for example.)

> It's just that we didn't seem to have gotten around to writing
> much documentation for any of this :/

A problem which I too suffer from - I am in no position to throw stones here!

>> For example in
>> arch/powerpc/include/asm/interrupt.h::interrupt_nmi_enter_prepare we
>> currently sometimes call nmi_enter in real mode; should we instead only
>> call it when we have translations on?
>
> nmi_enter() is the 'old' interface that has known issues. That said, you
> seem to have a comment exactly there:
>
> 	/*
> 	 * Do not use nmi_enter() for pseries hash guest taking a real-mode
> 	 * NMI because not everything it touches is within the RMA limit.
> 	 */
> 	if (!IS_ENABLED(CONFIG_PPC_BOOK3S_64) ||
> 			!firmware_has_feature(FW_FEATURE_LPAR) ||
> 			radix_enabled() || (mfmsr() & MSR_DR))
> 		nmi_enter();
>
>
> To me it sounds like this real-mode is something that's not a normal C
> context and really should not ever run any instrumented code. As such I
> don't think it should be using RCU.

Yeah, so it looks to me that we should not be calling nmi_enter() when
we don't have data relocations on (the mfmsr() & MSR_DR test) - we
shouldn't special case pseries hash guests.

I'll have to think through the implications of that, neither powerpc
exceptions nor Linux's exception handing are really my areas of
expertise!

What's the new interface I'm supposed to be using? Things like
irqentry_nmi_enter?

> Let me illustrate with the IRQ entry code, as that's easier:
>
> Your code currently seems to do things like:
>
> DEFINE_INTERRUPT_HANDLER_ASYNC()
>   interrupt_async_enter_prepare()
>     interrupt_enter_prepare()
>       trace_hardirqs_off()
>         lockdep_hardirqs_off()
> 	tracer_hardirqs_off()  // relies on RCU
> 	trace_irq_disable()    // relies on RCU
>     irq_enter()
>       rcu_irq_enter() // relies on lockdep, enables RCU
>       ...
>
>
> And there's a 'funnier' one involving trace_hardirqs_on(), there
> lockdep itself relies on RCU and RCU relies on lockdep. But I'm not
> quite sure how power does that.

We take most exceptions (on 64-bit server platforms, at least, and as
currently configured, etc etc) with relocations already on. But there
are 5 interrupts defined in the ISA which we always take with
relocations _off_.

It sounds like we may have been a bit optimistic about how far into the
generic kernel we could go in these cases. I guess the right thing to do
is to handle them quickly, touching only arch-specific known-safe
things, and then get out. But I will read the RCU docs to check what it
expects of us and bikeshed things on the linuxppc-dev list.

Thanks again, I really appreciate the quick, detailed and patient reply!

Kind regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87k0iq4ap2.fsf%40dja-thinkpad.axtens.net.
