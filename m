Return-Path: <kasan-dev+bncBDV37XP3XYDRB45DQSBAMGQE7SFDOOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6981132D833
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 17:59:33 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id 17sf7412958plj.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 08:59:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614877172; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZcaNTkf0ID7Ba5ifTJFgcVrDhJjHpDbMaEu+/pS1O+fX8B2rLgSR28JLHKHyOSGRYn
         LFSEkTACTopJXQCwHIhCMznHtS2DikMyAHFqYeLk1qTWDL81+sPOWIRXJzYtwRQcOR7D
         ys9yZyPi3AufyH8Wbw8QYOpDT1QEMsDqqXMGkpjp47v02wM4Ach1N76kExDhjytQ6S8Y
         SZcKmzwvLAG8tGAwObn2EpJwd6ufVYfRIWWdkxF+twDGMFMk+mRgica/4yTb2/GqGors
         BLkAj33yCGuJKBiMQmAf6pmLGWy0qTYCQyipEdX8EVEWYDCdCacmathqE2CjljhmBGtS
         oUkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=09aL2mbrxSLDv8VLKht3rd8raZyOFq+EvplbWaKA33Y=;
        b=YBxL7+K963De7dKd0NtjwoS38RObCNlOfaKqDi9r+68dZvknbQTbUG48zPz7tpYVla
         MrUHx9T7rAIJYKIzxuwuE80c9x6Qap7u8N0PVLcn/SYLupC8V+voP2dtdy5njDzt+F4Q
         dTzfzrWGwRGA520EmshHrZoXAIbemC29UQ5JV9B/8s336q4VgNPBhB/85vbq0OK9X2pP
         oheHM6/9ncAPiCSI4Lo59SLARGZUCBHQ5E8I5+RFRodP/fuzL7ccLw7D07UsGwupgVcC
         G+DFGgLyUphF8AtQ1rKxJKi7u1ljz0P8o/RmO9OmKoB4ySvFYAAtc+k9x35Ir8XB0yBy
         4c0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=09aL2mbrxSLDv8VLKht3rd8raZyOFq+EvplbWaKA33Y=;
        b=JEFBLydo0r6lFE0GZMyHwy10JiUvwjjeehvoqBaANsAzBal/2SB3REWxmgTR+I74Vi
         KTcbbopsHwwiKjT/38R6gs3eCZVzJ8XrbcBiBdEUqwlOo1C036zx6a6lQI8hM49TVXGv
         X1gjPwFKjLNZDlme+UA7sKi/2srksPdyGgKgY38pZhZb1St+zF7xzfoK7S1V3U3bI260
         vd8TrESTM2QfuvcSHgxLL0S5DROPBd807W3ntZaNF4Jbk4yCyUmHL3Yyv/T65Je0LrON
         l5U54f64H6RFlVm7S8hkLP+Eo43WDRtuKye02egx6fCVBZwvhoTq+2LT5jLVfC9aFn94
         Mj3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=09aL2mbrxSLDv8VLKht3rd8raZyOFq+EvplbWaKA33Y=;
        b=hIXaQnHEcDjKPBhs/P2Ktw00J2LPv3VEJ203ojvD5uKWUN4s6B900X16IAJMnFvDhq
         4LG0Bw3yRB95gry+kXWSw5+cYZ006yRqFbxUhV8Q8EUASNZBVX113+zZrty+TKXKr8k5
         /8U0NfjUcZhlKuRyVAHPZi1XB8x0CNYZjN1Ixti84TkVpe+lNBim514hTxYl6ZHzd4FW
         7s5n6N7h831Jz551i7W/rWTZVbNGKNIxOQaMChmYbYKvf6I8AQJbXK+L5VZaM1wU/D08
         kX3vuWQiK/a+G87fslBwkOKub2fIxpF33ecDiibi931H40sRlDTWBgBw8O3jXcFmj62g
         212w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533jDpQYfgN7RAjMyaVhPHXDYpRlTzFh9Rb0jSzEiPbED/FoXhyi
	nDbVe6Pi3pNys1h/Aro66Rk=
X-Google-Smtp-Source: ABdhPJyB7lGveMlrMDaL3tAvyag967MxOIs6zdu5pFUCD8QOgCLFMHaFdg6ezWDHCb61K8v977sBCw==
X-Received: by 2002:aa7:869a:0:b029:1ef:2724:68b1 with SMTP id d26-20020aa7869a0000b02901ef272468b1mr2108511pfo.58.1614877172094;
        Thu, 04 Mar 2021 08:59:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:302:: with SMTP id 2ls2636934pgd.3.gmail; Thu, 04 Mar
 2021 08:59:31 -0800 (PST)
X-Received: by 2002:aa7:9a09:0:b029:1ed:9919:b989 with SMTP id w9-20020aa79a090000b02901ed9919b989mr4677019pfj.20.1614877171454;
        Thu, 04 Mar 2021 08:59:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614877171; cv=none;
        d=google.com; s=arc-20160816;
        b=Er6vUJHcr/Hw388YdJ1TjyZXK9jbnyU2lCsLHrwzxgnkaudGSJW3IsF4aUMT+UJVty
         7uUdsL6KFUrkNRl2eEhlvouZ6LGy5LlYrkRDjagEDPCof2qf6NJql0sW008EiYRWrtKG
         ngxLcOmARHvRN8CJ7M/znRDNJglv+YV3OKM4YSogPRGw0u/0TVskxiOntXdmbKPay/2L
         yUpP1y82uYU/JrKiesPhqaDHkWfXfEFf6IkSR+0xlKjJKwAdSC21r7qOApfiRbYAwhFS
         DX+NjBgcigPyIThtr0L1EExJNTLPQHNxvd/Dd1/SaOec/EyBmigu+gx5yjPgBy59cV7d
         rHkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=TQlCYySSGKD3tn5PA5QBN83twsp7f5KnBmdM8Ag4Njo=;
        b=u5uszXcM5UnrdeYLoaEPFV2ewQpt+Slk+wiByMNdOQlBvMo3u4pyNweq2VR0hFQ67l
         nMA+4FlGchwzlUf0QzSbAlgFHKnF7HCt/phzi2Qf5MCXqd9qGvc7mWSlGwGWO0H80yua
         MthnyTJh8IRpTVMB3YOC40xaKjmz14bpk6yMu7h40dS6Nd8BhaC6/3ovdQl77I6qIYvN
         hSoKIZbUg3iHSaFyvrM9egaITzQxQb64W2NM8I9bfjRmMFLppiqIF29g4wv8Wq+TkobW
         ++khL3NEyKZIfUjUWJLOwqRh5cBAqzPwhsP5OwL3HB7svSVD5HDQMBNTDIzITjcVYNvt
         eg6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id g7si806544pju.3.2021.03.04.08.59.31
        for <kasan-dev@googlegroups.com>;
        Thu, 04 Mar 2021 08:59:31 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E108031B;
	Thu,  4 Mar 2021 08:59:30 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.53.210])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id DA6FF3F7D7;
	Thu,  4 Mar 2021 08:59:28 -0800 (PST)
Date: Thu, 4 Mar 2021 16:59:23 +0000
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
	broonie@kernel.org
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in
 save_stack_trace() and friends
Message-ID: <20210304165923.GA60457@C02TD0UTHF1T.local>
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
 <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com>
 <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu>
 <YD+o5QkCZN97mH8/@elver.google.com>
 <20210304145730.GC54534@C02TD0UTHF1T.local>
 <CANpmjNOSpFbbDaH9hNucXrpzG=HpsoQpk5w-24x8sU_G-6cz0Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOSpFbbDaH9hNucXrpzG=HpsoQpk5w-24x8sU_G-6cz0Q@mail.gmail.com>
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

On Thu, Mar 04, 2021 at 04:30:34PM +0100, Marco Elver wrote:
> On Thu, 4 Mar 2021 at 15:57, Mark Rutland <mark.rutland@arm.com> wrote:
> > [adding Mark Brown]
> >
> > The bigger problem here is that skipping is dodgy to begin with, and
> > this is still liable to break in some cases. One big concern is that
> > (especially with LTO) we cannot guarantee the compiler will not inline
> > or outline functions, causing the skipp value to be too large or too
> > small. That's liable to happen to callers, and in theory (though
> > unlikely in practice), portions of arch_stack_walk() or
> > stack_trace_save() could get outlined too.
> >
> > Unless we can get some strong guarantees from compiler folk such that we
> > can guarantee a specific function acts boundary for unwinding (and
> > doesn't itself get split, etc), the only reliable way I can think to
> > solve this requires an assembly trampoline. Whatever we do is liable to
> > need some invasive rework.
> 
> Will LTO and friends respect 'noinline'?

I hope so (and suspect we'd have more problems otherwise), but I don't
know whether they actually so.

I suspect even with 'noinline' the compiler is permitted to outline
portions of a function if it wanted to (and IIUC it could still make
specialized copies in the absence of 'noclone').

> One thing I also noticed is that tail calls would also cause the stack
> trace to appear somewhat incomplete (for some of my tests I've
> disabled tail call optimizations).

I assume you mean for a chain A->B->C where B tail-calls C, you get a
trace A->C? ... or is A going missing too?

> Is there a way to also mark a function non-tail-callable?

I think this can be bodged using __attribute__((optimize("$OPTIONS")))
on a caller to inhibit TCO (though IIRC GCC doesn't reliably support
function-local optimization options), but I don't expect there's any way
to mark a callee as not being tail-callable.

Accoding to the GCC documentation, GCC won't TCO noreturn functions, but
obviously that's not something we can use generally.

https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#Common-Function-Attributes

> But I'm also not sure if with all that we'd be guaranteed the code we
> want, even though in practice it might.

True! I'd just like to be on the least dodgy ground we can be.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210304165923.GA60457%40C02TD0UTHF1T.local.
