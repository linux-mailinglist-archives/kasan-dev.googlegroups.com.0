Return-Path: <kasan-dev+bncBDBK55H2UQKRB3MQR7FAMGQEIVX2FAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 33CEDCCB28A
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 10:25:03 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-477563e531csf2597095e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 01:25:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766049902; cv=pass;
        d=google.com; s=arc-20240605;
        b=CVrbo++A7WMlrxLNLEaUifPhzLveLlSHEJofme4gQkwMTb36Zkmovl3lqVm4sDFpS5
         SHW/tdjO8BcDlrZ1o8dOK2mTS+AXk3IEFeSbsOZcKm0oQBFreXQ+/8+6z3SU+12KliNT
         55Q9OaUTi7YalUxn4XhDUhWQu+Utx+QkUCNcyKFTKZwRp/RZUM/3KuqL6qCrxSzQlLnp
         LlHYRTO2jAJgl7iLTNzDPaG3pfgYnH3maQeFio5WZG71zwoCHkqXFruK3vNryp2swUTN
         0Gehl0UKxDS5MiCopOuskNHyVgbwnjteEjOM44H1uPwM/hXv7oIkiiQGuXpTtRe3++Mj
         Gohg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Iuxya8nECs6PxGgPCegFsq/GHQpFY06PafxLKNnPYdc=;
        fh=75ZV9qE3/gIt2UcVvCTKYofmZQVLKCIaiCta2HsfSZg=;
        b=i7t5AJYoX0VZ3ZMEWpZx3TxXgctoB4aVlSO8bzbD3kYgmfijYSwzQqEVnd3onTlyQr
         7POHNnMwYM5LJk6+edYQ0uZxNum/83cY7zLusu3HxGVWSJYgULHZJEN3+2Fj6DqpOyK7
         5kM8jQYoY0sa0K/yQaFse4bsjcure9+ymEF3X4qfCzQlKHY5CNyQYXNjOVNi6e2oJyNa
         6yAhdUdS/K/MZhmFEW15Cm5x7O4VIZwCxpXI9L9gALPWI0Rt0Ycf4+B40wEVW5Q/xxYf
         qsa/KiLNuQdp5pR3WLf6yKC++MqIxIO9fn4r9bhjEA3qujL2xNnb5jBu3W9Y14jiPpNw
         3hCQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=eb0JYMQD;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766049902; x=1766654702; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Iuxya8nECs6PxGgPCegFsq/GHQpFY06PafxLKNnPYdc=;
        b=fVdVuDVx3J1nNW3cwkPbwlQvqcDv82auhM2SfbICrTz9csqEeuf3JZXSP36YLEl+im
         EbXpHP2pJxKiLbih89xDabHdpfQJPsn0t7mmyB2zUreI6vMvfoEqUZGcOmd5odet8F8s
         zPlflRau3p++gmFaVjOqROsDStr33QPs9/PWa9yEDn66sKT5splR3CSOC2SOVDFWjlyl
         HgD2Ms0oINDys0tRD22iKCrQVpL0ogoMucivjyTlr2Bn2Ygkj2dk9YQ4cF8ha4/qz2zt
         Cy7y9ZWOcyJjKWio1w+oT4+pFAzdV0kcUYWeobR/4LuTTzOwBQxOyJB5zkse/CYDYFbw
         WhgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766049902; x=1766654702;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Iuxya8nECs6PxGgPCegFsq/GHQpFY06PafxLKNnPYdc=;
        b=sMXQWeGWLPScz2QtlbYjLjwtpPj8fD90FncKrdHP25ZI0uzI/WERGgQVJuu8Ubx1ul
         FhdNIz1jhdgvMa65PstrNPkugaIGCt+gaG+g5m00EK6MeDxA57HDhhOwFIgNg6+1ZbLR
         YVbA67ylbAbdo0G+iGuFumt4hROnQGfrz0vycoDzMrZJnbblkE/PL5JWbTsFM4dpMCo3
         eM9s0WcUBlSl7SzJ0iMHXyUVDjlAWXAD5Ny+OKzgu5QkOmfCy/FGhpyiWSsfWWqcq+oc
         vevuldYz7+n1yzQHYrmkNO7OoxLYaTt1OZNSh/Age7dTzEEIKzroyRFLsU4nGwlmTpee
         G8vg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV0tB+XtzASOiH4tiABIIw4MgxqltPXfO75ukMinUn+7yfn1bRhv/vxwCBcqfOJWQ/3UmDq2A==@lfdr.de
X-Gm-Message-State: AOJu0Yx6U/LcLNxtFXvnwx7xY4mVhqGL2/cPEZ4fOkStkwm0fMCZh4lY
	nmphy8DZtwfpF7j3WrQmk9p4pyLcWQuAj25XaqmKtcLmDBYDsZINjLGq
X-Google-Smtp-Source: AGHT+IG9GkQmcYFvQRktR/1UECF/id0Qb8hZUDGDPdOni2qLrOmm/4kVDRGhIImimWcqqC+XJKI6Ng==
X-Received: by 2002:a05:600c:3f10:b0:47a:7fd0:9efc with SMTP id 5b1f17b1804b1-47a8f8cd9cfmr247459285e9.15.1766049902399;
        Thu, 18 Dec 2025 01:25:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbz00koWfFluXxNDRM8eIRVsVGvOYYXdSRCxx+mZ58eSA=="
Received: by 2002:a05:600c:19ca:b0:46b:f67b:3bc with SMTP id
 5b1f17b1804b1-47a8ea160f4ls34070425e9.0.-pod-prod-06-eu; Thu, 18 Dec 2025
 01:24:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXimBkDBtaDuRESuK0Im3o+gSpvnw48G7xmFb5apIUAYi/TXo2r7MpGaO3tVksozytKky0hx0o8Prc=@googlegroups.com
X-Received: by 2002:a05:600c:6290:b0:477:63db:c718 with SMTP id 5b1f17b1804b1-47a8f8ce390mr262801055e9.16.1766049899435;
        Thu, 18 Dec 2025 01:24:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766049899; cv=none;
        d=google.com; s=arc-20240605;
        b=d+QsUEvvoil9pE/rbhe3inaXK3QTX4Ub601jvYopyZrUeGaSBCn67EM7J67bA6xNY6
         ffrm2YJdFZvkepLp9zMhyw/+vrwC0WAsk0bLr1QdDZ8y6tg7j7Y28zHA5Nmf93oXydm8
         W5ZwWc66/aRCXL6Q9Tt9tdRPVPk/LtjzfrrogNQayGHKdf+HRUR8c/Bpp7GIbQNx35NZ
         XB6jr8QSKaoFPf16W6SwuJmGBjdhoF9SNU0ctvf8ScL/H9wdiOOGT9vKpXhGKSLclmPN
         9pR0uN38lEhsGIRhjeevaY0KHKfXGdnUCLe4KDugf2b2R5uDL4O6wdKSVtYXDboMdlmK
         apHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=aluHAMJsVKd6FNX6fUQBpqcXdYNXA/U4mDlhQLutkcs=;
        fh=1MTu2OJ6DiDq1UCUK7zxZOBEwD4rdSVUMhRltTID3Z8=;
        b=Tu6Zq3toRjzFwlgO3gX9JSYGHlt+tGcSsarpb+Ozdix5O7PvExPMvDpXNCYLNH9jTY
         FelxokjBV/DHIRXb9hw2m6ayQdVBe3JXNCB6Uv20dOt1xrSQKsC+RUlYhd1+M/dFRpGv
         xRQiRnMITxxsizEu2yHkO8ju4y4AQUtUFXs1elV8nmYCbxYtK9QKeDr42vu5tz9h3SO7
         teaPJynrXDD8QQbOn9yPKMpBFGQgj0h2d+W+y5HFayEV4xRxPQvba2Andy0LSnFkyWos
         o8xPG6DewI5OaZbbQImFPQIJNl5NhH2Bj8Em+aTiMf3aQ3y5B6DiAJqpJ9FN2qywtNCB
         k5Lg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=eb0JYMQD;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4324493ba79si49106f8f.3.2025.12.18.01.24.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Dec 2025 01:24:59 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vW9OC-00000008SD8-1oU0;
	Thu, 18 Dec 2025 08:29:37 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 75F1B30056B; Thu, 18 Dec 2025 10:24:39 +0100 (CET)
Date: Thu, 18 Dec 2025 10:24:39 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Brendan Jackman <jackmanb@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>, Ard Biesheuvel <ardb@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH v3 1/3] kasan: mark !__SANITIZE_ADDRESS__ stubs
 __always_inline
Message-ID: <20251218092439.GL3707891@noisy.programming.kicks-ass.net>
References: <20251216-gcov-inline-noinstr-v3-0-10244d154451@google.com>
 <20251216-gcov-inline-noinstr-v3-1-10244d154451@google.com>
 <20251216130155.GD3707891@noisy.programming.kicks-ass.net>
 <DF0JIYFQGFCP.9RDI8V58PFNH@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <DF0JIYFQGFCP.9RDI8V58PFNH@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=eb0JYMQD;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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

On Wed, Dec 17, 2025 at 01:53:33PM +0000, Brendan Jackman wrote:
> On Tue Dec 16, 2025 at 1:01 PM UTC, Peter Zijlstra wrote:
> > On Tue, Dec 16, 2025 at 10:16:34AM +0000, Brendan Jackman wrote:
> >> The x86 instrumented bitops in
> >> include/asm-generic/bitops/instrumented-non-atomic.h are
> >> KASAN-instrumented via explicit calls to instrument_* functions from
> >> include/linux/instrumented.h.
> >> 
> >> This bitops are used from noinstr code in __sev_es_nmi_complete(). This
> >> code avoids noinstr violations by disabling __SANITIZE_ADDRESS__ etc for
> >> the compilation unit.
> >
> > Yeah, so don't do that? That's why we use raw_atomic_*() in things like
> > smp_text_poke_int3_handler().
> 
> Right, this was what Ard suggested in [0]:
> 
> > For the short term, we could avoid this by using arch___set_bit()

arch_set_bit(), right?

> > directly in the SEV code that triggers this issue today. But for the
> > longer term, we should get write of those explicit calls to
> > instrumentation intrinsics, as this is fundamentally incompatible with
> > per-function overrides.
> 
> But, I think the longer term solution is actually now coming from what
> Marco described in [1].

Oh, shiny. But yeah, that is *LONG* term, as in, we can't use that until
this future CLANG (and GCC?) version becomes the minimum version we
support for sanitizer builds.

> So in the meantime what's the cleanest fix? Going straight to the arch_*
> calls from SEV seems pretty yucky in its own right.

This is what I would do (and have done in the past):

 14d3b376b6c3 ("x86/entry, cpumask: Provide non-instrumented variant of cpu_is_offline()")
 f5c54f77b07b ("cpumask: Add a x86-specific cpumask_clear_cpu() helper")

Now, I don't have much to say about SEV; but given Boris did that second
patch above, I'm thinking he won't be objecting too much for doing
something similar in the SEV code.

> Adding special
> un-instrumented wrappers in bitops.h seems overblown for a temporary
> workaround. 

Agreed.

> Meanwhile, disabling __SANITIZE_ADDRESS__ is something the
> SEV code already relies on as a workaround, so if we can just make that
> workaround work for this case too, it seems like a reasonable way
> forward?

I'll defer to Boris on that, this is his code I think.

> Anyway, I don't feel too strongly about this, I'm only pushing back
> for the sake of hysteresis since I already flipflopped a couple of times
> on this fix. If Ard/Marco agree with just using the arch_ functions
> directly I'd be fine with that.

Yeah, fair enough :-)

> And in the meantime, I guess patch 3/3 is OK? 

I'm not sure, ISTR having yelled profanities at GCOV in general for
being just straight up broken. And people seem to insist on adding more
and more *COV variants and I keep yelling at them or something.

That is GCOV, KCOV and llvm-cov are all doing basically the same damn
thing (and sure, llvm-cov gets more edges but details) and we should not
be having 3 different damn interfaces for it. Also, they all should
bloody well respect noinstr and if they don't they're just broken and
all that :-)

That is, I'd as soon just make them all "depend BROKEN" and call it a
day.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251218092439.GL3707891%40noisy.programming.kicks-ass.net.
