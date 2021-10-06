Return-Path: <kasan-dev+bncBCV5TUXXRUIBB55N6WFAMGQEDUBCALQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 162E6423942
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 09:57:44 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id r14-20020ac25c0e000000b003fc149ed50esf1319867lfp.11
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 00:57:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633507063; cv=pass;
        d=google.com; s=arc-20160816;
        b=BYQPU7Fi17g+JvwE9CdxJ+0IPHoI+KXIypYW3wcsUugtD1DPY6/u2bAspKNVVG5TZy
         OlDW/MbQoDMG5lv9YWQgg/HSH5i0YHyVGPcWMkmlvgbuPsaAPKhYmzWA6Uz6hCdyaR+0
         Mnr5UzdoQQctpYClfu8BxyY/5n1MWTE2UpXFoIbVm6wGi0z6MOXbBfIJEQBKJwACpk0P
         D7BloYp7n/uMhJndYyC9w4amR8rKboJU+IyqtoUhsc4puaromg+p75lNGGH9Kuz8njWN
         eNJjigpl0h/lSKiQ9r25QNlne7w18CPuQEZkrtzRLWL23ZbT2KyGz5jhZ4apYsnSIg5V
         oWFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=WbqOgPRybN2t3tE9j7iTcJWcHvtGGwcYyvS5G8ulv50=;
        b=rWQP9Zv9VZtGqQ7cD6SDwoxu7iTD101Lda7IWMV/HoPwuOuBnEyxA41IA134/BiALa
         SCKYGlXT8c3XHy7zPxWyuO5DITqxRiZpkaAbGqpkfDuogEkUHBbfSWOcK/X7CYX+f4xV
         jIX4Ga9IHdPncpe0/4bvc5iBjrT2DoRj7A7WBiZETRyU6ayTw5neXczz4bPTJnLQ5vEk
         +Oe5cIbpbwrrAI2uR4q6HKC7PBZiORNiTANHUCqr87bnUiJ/bMScS8aJhdw00yo6Vlff
         2UdcjmNCWvZplbZ7dx4GlXXJ5ewqa+0UgbZUgtF0HCN3k5e42yy7deGq17zlohgSUPzC
         kSpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=ldKp5AGB;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WbqOgPRybN2t3tE9j7iTcJWcHvtGGwcYyvS5G8ulv50=;
        b=hgT3/Mm0uAYYxUqB/ak4sVcv9RE3o9h95CNqFzeVOQhx/aFsuJP9SpmBlztLWN+/jU
         UMdLSOBstMfwfdUg8OyspuG7/CTvSLoxcVZ61hQZZKlfDac9W3k5pqKEs/2heU3T0SNy
         6hOh/3uSQeUqJ8UFZzwRGb7PL0WiseUJFRE4QYsr3vKdI9iJiWTinKIKnOqK84fGTjAI
         P2SvYDi7C0BUR81XK/WGUafGuLj1+W/+kZcb6I2rHgecg89NgwcJvvI26YIAnmQFpaX0
         4O9aLDbUcL+YlZ8BsOsYsqieWLL3iRjzvtak7JoEeN5G9mBK2iPKm1yVLFM1v1SGFmdc
         FIUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WbqOgPRybN2t3tE9j7iTcJWcHvtGGwcYyvS5G8ulv50=;
        b=uR/nQiGBPbtRhSJ44gCmYyMS38rLy0MYM9vwPkXiz7PCZs9RjCusAJx7W+a/vismPI
         ygB+D+RIbjufH/HxNijzj4alm3VOnaiR7dg6/hdpbSeny5E9vqRNca9z8p0lHTrIupnS
         2HFA5alAsUu5B1yoHhYhGBRmmnUYfuoBwI5PxcxNXZeeNEyWSzZhZzJeGDDyQhaFnNcD
         Lfpj1rj3FUFzhjCfXagGxssVVNTFc2nvYxTvK3K3RsrmV8mSY8Iv/ai0l3keFejv063D
         WvFHJliO8C+PycMlH7o6V6PZ6WZksHT8H8y3NPBGu6ZZsf6ZlOTazsLByERrBkoQgHev
         ZhMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Uc7lRwGv9x1MrzGcW2XhVSDEvVgiNjwLNlIeOiQHCBgN3/m9g
	32+nJluS7dB4jaIaAHOI14w=
X-Google-Smtp-Source: ABdhPJxSmHHkYesuBGHhKw5zlJpook0Lc5iGvrBwyfs07YSepH90sEu4iszCs2j3GfTJ+ODo5K4TYg==
X-Received: by 2002:a05:6512:33c1:: with SMTP id d1mr7989538lfg.621.1633507063602;
        Wed, 06 Oct 2021 00:57:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f14:: with SMTP id y20ls2196538lfa.1.gmail; Wed,
 06 Oct 2021 00:57:42 -0700 (PDT)
X-Received: by 2002:ac2:58e5:: with SMTP id v5mr8366417lfo.589.1633507062491;
        Wed, 06 Oct 2021 00:57:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633507062; cv=none;
        d=google.com; s=arc-20160816;
        b=glWl2Kp71qQuVYl2whRpOlnpGgxT7pFXHfjgjFvJhmmqnRLju/+adtdQk3KP1j3oPf
         CU1cPbrXHa/UOS0CQ+UbOtteR/c+XzBcVEqdzD10GKRIYtL0xGiR383LQ3uLBvWfXggI
         OIhrL+9tYlHZy16TNvO9a+sYDjGO3ByshFUvDvcGYErikit8QgjNc37ZjNY4TCsdC8D3
         y/EHyZatQK5vpklPeUIo4yqxP68c/Gb4lDs6a5tkMyoIB5ZQuZcEBNOeGvR4dGhNgVCX
         9+rmtOFT8zphidPWQRYqPOU/9STpjZ9PGSx93q6jzP4BkoNJ3zlzXg9HlnVisWLUHQ32
         0smw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=QgYsG4DybyVUkLhBWL4qDYk9xpuJmOv7rcrX1JZVF7o=;
        b=ito2FmHb2MY5JF9DYKwOyyRTbs6FiaOC0BKKNZZsGu4QPR3abtTUfErrAaCz7sQPiX
         nJDyp300xtK9lyPpB2iPakZPS1Wrxljx4Te/DnlMge09sseIabnXZInn24YIp/rBl+ux
         Ep0fRNcpxF5gQG4Jt6jHBsC1ZX4yLVy2AY/wwonSo9x2cKz72YOpHJSADZchViUCSCnU
         nL34f1Sf7LMSK+tR3zJNsxxRdUG0w7SWjWMzSgU0NjR9l5D99eIY4VRDJvzsADwoY6NN
         E69WfGSej8qQ8IGKBV6XD5MHqnQS+AKJOIYFinchhrQ7h+JsgE1hncdRO1DSuPAls2+c
         cfZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=ldKp5AGB;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id w6si851854lfa.7.2021.10.06.00.57.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Oct 2021 00:57:41 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mY1o1-008ERF-Em; Wed, 06 Oct 2021 07:57:37 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 842E9300056;
	Wed,  6 Oct 2021 09:57:36 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 67566200C9CA8; Wed,  6 Oct 2021 09:57:36 +0200 (CEST)
Date: Wed, 6 Oct 2021 09:57:36 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	paulmck@kernel.org, rcu@vger.kernel.org,
	Thomas Gleixner <tglx@linutronix.de>,
	Mark Rutland <mark.rutland@arm.com>
Subject: Re: instrument_atomic_read()/_write() in noinstr functions?
Message-ID: <YV1W8FAV6h2t5gQo@hirez.programming.kicks-ass.net>
References: <871r4z55fn.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <871r4z55fn.fsf@dja-thinkpad.axtens.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=ldKp5AGB;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Oct 06, 2021 at 12:05:00PM +1100, Daniel Axtens wrote:
> Hi,
> 
> commit b58e733fd774 ("rcu: Fixup noinstr warnings") adds some
> instrument_atomic_read calls to rcu_nmi_enter - a function marked
> noinstr. Similar calls are added to some other functions as well.

It moves the instrumentation, it was already there. Specifically:

-       seq = atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);
+       seq = arch_atomic_add_return(RCU_DYNTICK_CTRL_CTR, &rdp->dynticks);

removes the instrumentation from the critical place where RCU isn't yet
watching, which is then added back here:

+       // instrumentation for the noinstr rcu_dynticks_eqs_enter()
+       instrument_atomic_write(&rdp->dynticks, sizeof(rdp->dynticks));

Once it's deemed safe to run instrumentation.

> This is causing me some grief on powerpc64 while trying to enable
> KASAN. powerpc64 book3s takes some NMIs in real mode, and in real mode
> we can't access where I'm proposing to put the KASAN shadow - we can
> only access it with translations on. So I end up taking a fault in the
> kasan_check_read path via rcu_nmi_enter.

Then your entry ordering is wrong :-( RCU should be the very last thing,
once RCU is watching it should be safe to run instrumentation.

> As far as I can tell `instrumentation_begin()` and
> `instrumentation_end()` don't make it safe to call instrumentation, they
> just tell the developer that instrumentation is safe. (And they are used
> to check the balance of _begin()/_end() blocks.)

That is correct. In that respect it is an unsafe (pun intended)
annotation. The annotation can be used to annotate away actual
violations (although the one at hand is not one such). There are some
explicitly unsafe annotations like that though, typically WARNs in early
init code where we really can't do much better than to ignore and hope
the error gets out.

> Is the underlying assumption that the KASAN shadow will always be safe
> to access, even in functions marked noinstr? It seems to undercut what
> an architecture can assume about a function marked noinstr...

The assumption is that RCU is the very last thing in the entry code to
be enabled, and the very first to be disabled. Therefore, the moment RCU
is active we can allow instrumentation, and hence the
instrumentation_begin() is correct there.

The NMI dance on x86 is particularly nasty, but the first part
(currently all in entry_64.S) ensures the kernel page-tables are active
and that we have a kernel stack.

Then we call into C, which is still gnarly and deals with
self-recursion, but eventually calls irqentry_nmi_enter(). This then
carefully frobs the preempt, lockdep and rcu states into the right place
after which we have a fully 'normal' C context.

> P.S. On a more generic note instrumentation_begin()/_end() is now
> scattered across the kernel and it makes me a bit nervous. It's making a
> statement about something that is in part a property of how the arch
> implements instrumentation. Are arches expected to implement things in
> such a way as to make these blocks accurate?

Yes, there's only a limited ways in which all this can slot toghether
due to all the nasty inter-dependencies. Thomas and me spend quite a bit
of time trying to untangle the web such that we have a coherent
entry/exit ordering that's actually workable.

Pretty much everybody had this wrong and was/is broken in various
non-fun ways.

It's just that we didn't seem to have gotten around to writing
much documentation for any of this :/

> For example in
> arch/powerpc/include/asm/interrupt.h::interrupt_nmi_enter_prepare we
> currently sometimes call nmi_enter in real mode; should we instead only
> call it when we have translations on?

nmi_enter() is the 'old' interface that has known issues. That said, you
seem to have a comment exactly there:

	/*
	 * Do not use nmi_enter() for pseries hash guest taking a real-mode
	 * NMI because not everything it touches is within the RMA limit.
	 */
	if (!IS_ENABLED(CONFIG_PPC_BOOK3S_64) ||
			!firmware_has_feature(FW_FEATURE_LPAR) ||
			radix_enabled() || (mfmsr() & MSR_DR))
		nmi_enter();


To me it sounds like this real-mode is something that's not a normal C
context and really should not ever run any instrumented code. As such I
don't think it should be using RCU.


Let me illustrate with the IRQ entry code, as that's easier:

Your code currently seems to do things like:

DEFINE_INTERRUPT_HANDLER_ASYNC()
  interrupt_async_enter_prepare()
    interrupt_enter_prepare()
      trace_hardirqs_off()
        lockdep_hardirqs_off()
	tracer_hardirqs_off()  // relies on RCU
	trace_irq_disable()    // relies on RCU
    irq_enter()
      rcu_irq_enter() // relies on lockdep, enables RCU
      ...


And there's a 'funnier' one involving trace_hardirqs_on(), there
lockdep itself relies on RCU and RCU relies on lockdep. But I'm not
quite sure how power does that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YV1W8FAV6h2t5gQo%40hirez.programming.kicks-ass.net.
