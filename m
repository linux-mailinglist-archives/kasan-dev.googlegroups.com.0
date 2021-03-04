Return-Path: <kasan-dev+bncBDV37XP3XYDRBGOBQSBAMGQE6X2O2WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EAC632D923
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 19:02:03 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id 81sf18722759pfv.8
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 10:02:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614880921; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y8RXdmX+Z/BAiHiHVv69nlRI/pZmE9Mv2aac5APQaKUwFM426mwUOMdJkojNxcOI5f
         3iMs3xfg4p8gV3M+zNhwvSRVgbVS6QSte9c2JzfktDEUhSjAlUE029XRcMI7jGAdARFF
         zJMjPZg8hwBNr4UYNCugPmcN+M1IieD/V+ysTZhlTF0JH/s605Mxgli5qIj3B4ZjzG3p
         NNBV8Z51yqbtDDpu87d0uespQqh9ehKMnvXf4sYWjAgG7fgsunmys6RRpxHoHl33I2HV
         S2FQAT6dKfqiokp0NWjpdMj5LhzbLKa7S7sKK4hO59O0APxLUR0zLI9EPrX6zANr4EL9
         jXkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=yNYLKD4lUiFalJwVLSL8O7zZsuEJBaJ1dY6xuNB70Pk=;
        b=NnHEE+KMaZdIIPmoy875Tz0y7E9zCjsv0Lj6//c0i72Hic4SrP024Al0TpunZztmGp
         y/OyVWtMBKAktuQorg/2GyPbFwE65kYoZRAew5NZStqG4BWvyQfY8yPkesL+sT/c/Jg6
         9vXMk7FFFOW+MRXGEXFZjwmLp+uotvHOw++c5WG+UIk9Rt1xjY6Uw6VuU80i3wMKuy8D
         x1ENDIMgfyV9yDIGycS2Y00XO97RfXamBPiHEAVxifi5+Xc+B8t5GrytU2x27mnDO9Sc
         hv9+55dS6+CDkbWS96v/7uhsAZlijb+oUNPTVWJFB1J6Jj8vQ//EVb/EyJODca/qaHMx
         UNUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yNYLKD4lUiFalJwVLSL8O7zZsuEJBaJ1dY6xuNB70Pk=;
        b=qFeWMWL0mAgLXwxJA+N4LEZSGdzg4s7qexYOJ7p9XbcmXezxWUIQEX1WdJl3m4w4L6
         BcB0uXKPXbFtQP6aud1rz/c9EY5xlJm5UzkVvoIRZsxbCzSOeAe6GsbMjr7hAhgmaNJc
         PMz5ZK6O2gJ/7YOWeoa70BU0/WXd9bgyVMNg8QUwI+3TNfBTPlOrcIRtAKXnhHBs8f6G
         mw7Uv1bbXseqrKZxnqO+fJD5oZpjvYa7GBxuF4GkKkB+NQCxeGCuWdPa334R/s7b0eRH
         E2VHV9n7GFsRzxacMVgO+A0GrtkgHNJ+DeYTrfICOKwhH4APRAKFIcSfwQxPqZMVZyfw
         aquA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yNYLKD4lUiFalJwVLSL8O7zZsuEJBaJ1dY6xuNB70Pk=;
        b=aIL+HvKLRlyOHQ3VKejdyADpwtEmVYMbv03sRbDHgkJ49zqhVjD13Z2ZX/R2HnK0yO
         iYhih4UZT9THwY8e7AUnkazPoh8Vms04UXFAt4jqCdVpL0WjHWZaTkx9nIc1f6+SYrus
         pX7IIyDaZU1cjCHNyBJj5YDJBTUho+ItIyFtJGkmEtOfEipnGPxATW98R8g3wg9aQnpq
         ClVDQZhHkQ7RmYaVcdqTxKv/mDBpn9aVj7NJBvXf4GaQGwm5zF/uoNGzIY+pPVSC5Iy/
         mv1+LUxLjPKHRWrBmiPyYjB21UscbHa1nrZkGmYibH5oiJ4L0EaCzwr1wrxfPtEUTx1Z
         2BVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532TRCgcOkZz1TYV6BcA8tFBpUZCpgtJQaYbeGJtX5WIEfSCMbdk
	p8FLR9SIGF3lpKGCVr1Cwz8=
X-Google-Smtp-Source: ABdhPJwDaDCE5L6m16uB3a54qeOEtVrv8dKv176g041OIP7CUmRzxKf/id1dMbui1Ox2gG/Bpty2Rg==
X-Received: by 2002:a63:2d45:: with SMTP id t66mr4424244pgt.449.1614880921398;
        Thu, 04 Mar 2021 10:02:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c40a:: with SMTP id k10ls681562plk.2.gmail; Thu, 04
 Mar 2021 10:02:00 -0800 (PST)
X-Received: by 2002:a17:90a:4497:: with SMTP id t23mr5600399pjg.233.1614880920188;
        Thu, 04 Mar 2021 10:02:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614880920; cv=none;
        d=google.com; s=arc-20160816;
        b=BZA4tZtJGrVzQ/sWs92sur5A6Uq55e9jm+MUKq04ygX/1/BC8VA2AqW840Eft2LmZ/
         A9s1SzsGWwqi0/vYnkVpsAw7YOdyy8qspWDPcTWrIDprGRDdJ4nnBhfJhflpa30/mZaK
         CiuVAYAB2Gb/sB/rkfYt4QOauF2/nniFpxtU+cfqzxIkkmhzJyRuCs59vcj6ENfLPYnf
         eWWvJnqD/I1R4P9wb09Ny0giHtS48858vmgn0Wp5HWs62evGQ7c4oqacwdO01iQLexkR
         w2k9T6wxpRl/A9FMAwl/utHHt5FHZ5uwUZs766Ruy/f77/wI2PiectCoXMExWTjBWDDQ
         hhsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=Rx9w1y6lR0AXBTE6W2W51QrNrTbTRZVSR3aeHfGZBUY=;
        b=LgoT0g4b7ED/phsdIcP/9fDHRNPrwQ+ETgVjXIEaFQA1B0doPlO78Kn8QodKHn3mge
         HFHL/vNfxVpn4R8UOj1fTBN0INFyHhlfPQkWlhzT9AluzuUGxsgUWTfA/jBJhldAFYh/
         QyU5OjOghhua9U4B9H8bpnJTw9TdC1FowMWl9JCEfnFGNgTlYOzcSrADMl50nI3CDqqD
         P/Og8yvGOHzX5y8LlvgaBYKyEQt5I1wpC7uN6nTAJT4DnEyGhLFrKwSB9zw0a/bFBIz7
         LQgvrrqoWywLP0ETd3RGOmR0sN5H47+bxZxaf3zLFjvYMxyuAeL+jbl8XD3p1ytNkFdV
         SAlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id x3si9871pjo.1.2021.03.04.10.02.00
        for <kasan-dev@googlegroups.com>;
        Thu, 04 Mar 2021 10:02:00 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 3662731B;
	Thu,  4 Mar 2021 10:01:59 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.53.210])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 38B273F7D7;
	Thu,  4 Mar 2021 10:01:57 -0800 (PST)
Date: Thu, 4 Mar 2021 18:01:54 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	LKML <linux-kernel@vger.kernel.org>, linuxppc-dev@lists.ozlabs.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	broonie@kernel.org, linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in
 save_stack_trace() and friends
Message-ID: <20210304180154.GD60457@C02TD0UTHF1T.local>
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
 <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com>
 <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu>
 <YD+o5QkCZN97mH8/@elver.google.com>
 <20210304145730.GC54534@C02TD0UTHF1T.local>
 <CANpmjNOSpFbbDaH9hNucXrpzG=HpsoQpk5w-24x8sU_G-6cz0Q@mail.gmail.com>
 <20210304165923.GA60457@C02TD0UTHF1T.local>
 <YEEYDSJeLPvqRAHZ@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YEEYDSJeLPvqRAHZ@elver.google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Mar 04, 2021 at 06:25:33PM +0100, Marco Elver wrote:
> On Thu, Mar 04, 2021 at 04:59PM +0000, Mark Rutland wrote:
> > On Thu, Mar 04, 2021 at 04:30:34PM +0100, Marco Elver wrote:
> > > On Thu, 4 Mar 2021 at 15:57, Mark Rutland <mark.rutland@arm.com> wrote:
> > > > [adding Mark Brown]
> > > >
> > > > The bigger problem here is that skipping is dodgy to begin with, and
> > > > this is still liable to break in some cases. One big concern is that
> > > > (especially with LTO) we cannot guarantee the compiler will not inline
> > > > or outline functions, causing the skipp value to be too large or too
> > > > small. That's liable to happen to callers, and in theory (though
> > > > unlikely in practice), portions of arch_stack_walk() or
> > > > stack_trace_save() could get outlined too.
> > > >
> > > > Unless we can get some strong guarantees from compiler folk such that we
> > > > can guarantee a specific function acts boundary for unwinding (and
> > > > doesn't itself get split, etc), the only reliable way I can think to
> > > > solve this requires an assembly trampoline. Whatever we do is liable to
> > > > need some invasive rework.
> > > 
> > > Will LTO and friends respect 'noinline'?
> > 
> > I hope so (and suspect we'd have more problems otherwise), but I don't
> > know whether they actually so.
> > 
> > I suspect even with 'noinline' the compiler is permitted to outline
> > portions of a function if it wanted to (and IIUC it could still make
> > specialized copies in the absence of 'noclone').
> > 
> > > One thing I also noticed is that tail calls would also cause the stack
> > > trace to appear somewhat incomplete (for some of my tests I've
> > > disabled tail call optimizations).
> > 
> > I assume you mean for a chain A->B->C where B tail-calls C, you get a
> > trace A->C? ... or is A going missing too?
> 
> Correct, it's just the A->C outcome.

I'd assumed that those cases were benign, e.g. for livepatching what
matters is what can be returned to, so B disappearing from the trace
isn't a problem there.

Is the concern debugability, or is there a functional issue you have in
mind?

> > > Is there a way to also mark a function non-tail-callable?
> > 
> > I think this can be bodged using __attribute__((optimize("$OPTIONS")))
> > on a caller to inhibit TCO (though IIRC GCC doesn't reliably support
> > function-local optimization options), but I don't expect there's any way
> > to mark a callee as not being tail-callable.
> 
> I don't think this is reliable. It'd be
> __attribute__((optimize("-fno-optimize-sibling-calls"))), but doesn't
> work if applied to the function we do not want to tail-call-optimize,
> but would have to be applied to the function that does the tail-calling.

Yup; that's what I meant then I said you could do that on the caller but
not the callee.

I don't follow why you'd want to put this on the callee, though, so I
think I'm missing something. Considering a set of functions in different
compilation units:

  A->B->C->D->E->F->G->H->I->J->K

... if K were marked in this way, and J was compiled with visibility of
this, J would stick around, but J's callers might not, and so the a
trace might see:

  A->J->K

... do you just care about the final caller, i.e. you just need
certainty that J will be in the trace?

If so, we can somewhat bodge that by having K have an __always_inline
wrapper which has a barrier() or similar after the real call to K, so
the call couldn't be TCO'd.

Otherwise I'd expect we'd probably need to disable TCO generally.

> So it's a bit backwards, even if it worked.
> 
> > Accoding to the GCC documentation, GCC won't TCO noreturn functions, but
> > obviously that's not something we can use generally.
> > 
> > https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#Common-Function-Attributes
> 
> Perhaps we can ask the toolchain folks to help add such an attribute. Or
> maybe the feature already exists somewhere, but hidden.
> 
> +Cc linux-toolchains@vger.kernel.org
> 
> > > But I'm also not sure if with all that we'd be guaranteed the code we
> > > want, even though in practice it might.
> > 
> > True! I'd just like to be on the least dodgy ground we can be.
> 
> It's been dodgy for a while, and I'd welcome any low-cost fixes to make
> it less dodgy in the short-term at least. :-)

:)

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210304180154.GD60457%40C02TD0UTHF1T.local.
