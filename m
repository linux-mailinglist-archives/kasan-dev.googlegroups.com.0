Return-Path: <kasan-dev+bncBDDL3KWR4EBRBT5IQGAAMGQEPKOKIAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C9AF92F6301
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 15:25:20 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id x4sf7439391ioh.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 06:25:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610634319; cv=pass;
        d=google.com; s=arc-20160816;
        b=IrCCFcrpsa4JkROi/r54q9AGTsDEmQs7fGZLPdUE2rj4XwxPr/3i7bYLRcBIJ87J7v
         Vednk0ZLLFF295iQOEDZUzUKR1osNrE4BxUjY8Y+2Mn2HvQyajm1/dkg4THPPK4bReOm
         +U1aVcJxtukH8lo7sgxOO7z/6WDWE6T5S4t0gaDDfBlWkUXZAZOOhcjBZEvXXO2grHFY
         oq8Ka6pMfkqI0r29xshqdsiP/E2XOunxljfV8OcRzmES8PWqWJT9n5fe9h2gHLOnVJRm
         YW5WkOrgi/3I4BsqMjBo/0jwVxMIE1jZU1A5Qa2v88P0HQalPrzocrldONJxv1tjupCf
         Zmbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=IpmXgxxWoIqe31ic4MDNS4l4awH70fMcpwSZpUVFefo=;
        b=c9mYbnXkJZzw+0V7HXryTB50E7QIUHMMgWCQEXLEZlsxfCGd62Mp4S0hA+Hy61us+d
         iJHiX9KdACSkpl06F7jN1LmZIHjHnzqABq5Sp8C2wYSaMaMHTjENZZ6PVdKULorkNipL
         GgTBA4A/PTlhwQJSOQosoB0/dGtvxKSjUAFAffK20LZnouz4PHlUyG9rvlhboy7oauxd
         TZ0NLBH3+3wroPwn1bbOIYirewVAgN0XAoqhOqHBXUQUYV5S1FFIyZYVxZ/EdkBjnD/n
         6RX4WUvnbVxmP1NFJog/rrxZiomvitlaYjlxuaVvN7Hc9pDysvcWY/3N0soQCsLQ8Yce
         qzYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IpmXgxxWoIqe31ic4MDNS4l4awH70fMcpwSZpUVFefo=;
        b=kKZ15keZCs4wsYKzfgMbWy7puhlRScNg9NpTH6/X4q0IbInPdApZUkGnQe8tB202Nd
         Stk0YpJ4mGSLNyo3I1HynEe34ZIx7/jZUGsCoKgQEd/yl4KedjSfpv5ehk67BaKbE0Nj
         zQ3S5NrbriJ2fnjVf0wakUKyHzgI/IjRzWkA/+E6lWFTgiCRGlABBubJiom+wjzzPYFv
         kLfEneqnBJ4YIJrAAGf4u2oLv+gwl/OuRlYAKyHjOYThTweAxYO2Bk3gOm8CsytWPLUG
         IZfVCOxtpx0HbQFwbawIohki9GlXPPALM8zo0gi8w504Xhi5zpQRciiM7DkR8OGPYjOB
         4lFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IpmXgxxWoIqe31ic4MDNS4l4awH70fMcpwSZpUVFefo=;
        b=GgXayoVEqv7KsK8PV37fi6dJ4K7Vv/DFnYXmMm0hCgXo1bRz+AUUDfKB+cnOKMKDSw
         diewwYXZ7uLKCX75l0Sxv2mikytw7+f0yrqV0lvW7FwITKcAjf9lkb1Ti9oVut2kv/zt
         34RM1MBSgvpiPSwayDNV8c6Ktv0j9DbTZodJD/Xd+dqMzDJfsFIa2E0EfixYSMNAYzHJ
         iGdqfrO6Dsh3qHp+O/wIOpEWMgJskTz9+nWCRm4U+gylctuwWZGrQ/R10TJqMGLC/IQv
         ygY9V+nIl/UUWLO3EGDzvfwNtYmWb874/jW3Qjmwd0VSU6Zf7sEjNaqXb056mYhQrnaZ
         pNdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532xivhLljS8gDd3nhlVdgPUJctPXtbSTeOHRGk+aIZ8UIAj5Y9r
	Lf/wN3+ARsxYH8Kf+RJ11p0=
X-Google-Smtp-Source: ABdhPJyvpaCdMCEkq7ab7M9PTfFF7nr+9sBM++447emLsREPf8gL7DUKrfXSwVaxVdZelzVvHYkBdg==
X-Received: by 2002:a02:a417:: with SMTP id c23mr6723776jal.42.1610634319520;
        Thu, 14 Jan 2021 06:25:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:1445:: with SMTP id 66ls756417iou.11.gmail; Thu, 14 Jan
 2021 06:25:19 -0800 (PST)
X-Received: by 2002:a5e:db4b:: with SMTP id r11mr5252145iop.148.1610634319002;
        Thu, 14 Jan 2021 06:25:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610634319; cv=none;
        d=google.com; s=arc-20160816;
        b=iQmvFZAu0VdaVYozje+WD7ut0yWRmRg4Mj+iJ1T2Xl7Pe5iyDGs4fczKVT6am8lgzU
         2jdsSqpNE+rXJrHI6DTpyrr75J/nah22IYdbBpDCdpvMJrno4W2jBarGbQ+baxysRrca
         iD2hM507ax+YGzOKKnjUx+Y092FpbJnpOskwV/xo7aQoZVue+7wHuJiV7pLwGGQLRzLb
         dMKme2X1ectbAAJfqvncXVB1O8nEL0HKEBczPs9DwRJiLNJLcL3Tu7qk6qYt7AkpT/gU
         Nw9NF6M4hFR2BZyM4B/VfLEqzmkkaPtyn+Vq9S821rrUU7RcYbqWx6CQJ37qZdWWMRMw
         Pufg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=uIbXAtnCm+ByNZC38PoqmNjbpQOQzjm/Ftflvn/c3WA=;
        b=Hp/Wgm+If87DfZ2+HKE5/4CP6PLfmFSepgJSQ2OCzGyVpgPnMn9NMl6FwauyyYD8K+
         y2ce0dhpSeUPkyeE3kiKWZdzN0M/f9SvKUN9xsr1PUlHi0msqkvo52dGp6/0YJ4UJ1RJ
         +xUkVRsGJ0LfOyfyGVIFmsTcAkb+JYJicf1wCDEmJvlF/5KlUu5/IIgKMU/ygxqsL/zd
         meCMBtSOHhlSGt8wJpJ2SoSUaHrYBKVN8gIUTvcPOFozb9w5s8wxRuAl6nx02zgm7n6+
         O2L4ig+gXJ3I6DkwMxmdS4E9SYNBdltPjJYjr1HtaZHowFmmHj0qWvyYBWWh1woD+SnI
         gWUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l3si229249iol.1.2021.01.14.06.25.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Jan 2021 06:25:18 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 1090A208C3;
	Thu, 14 Jan 2021 14:25:15 +0000 (UTC)
Date: Thu, 14 Jan 2021 14:25:13 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v2 3/4] arm64: mte: Enable async tag check fault
Message-ID: <20210114142512.GB16561@gaia>
References: <20210107172908.42686-1-vincenzo.frascino@arm.com>
 <20210107172908.42686-4-vincenzo.frascino@arm.com>
 <20210113181121.GF27045@gaia>
 <efbb0722-eb4e-7be2-b929-77ec91cc0ae0@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <efbb0722-eb4e-7be2-b929-77ec91cc0ae0@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Jan 14, 2021 at 10:24:25AM +0000, Vincenzo Frascino wrote:
> On 1/13/21 6:11 PM, Catalin Marinas wrote:
> > On Thu, Jan 07, 2021 at 05:29:07PM +0000, Vincenzo Frascino wrote:
> >>  static inline void mte_sync_tags(pte_t *ptep, pte_t pte)
> >>  {
> >>  }
> >> diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
> >> index 5346953e4382..74b020ce72d7 100644
> >> --- a/arch/arm64/kernel/entry-common.c
> >> +++ b/arch/arm64/kernel/entry-common.c
> >> @@ -37,6 +37,8 @@ static void noinstr enter_from_kernel_mode(struct pt_regs *regs)
> >>  	lockdep_hardirqs_off(CALLER_ADDR0);
> >>  	rcu_irq_enter_check_tick();
> >>  	trace_hardirqs_off_finish();
> >> +
> >> +	mte_check_tfsr_el1();
> >>  }
> >>  
> >>  /*
> >> @@ -47,6 +49,8 @@ static void noinstr exit_to_kernel_mode(struct pt_regs *regs)
> >>  {
> >>  	lockdep_assert_irqs_disabled();
> >>  
> >> +	mte_check_tfsr_el1();
> >> +
> >>  	if (interrupts_enabled(regs)) {
> >>  		if (regs->exit_rcu) {
> >>  			trace_hardirqs_on_prepare();
> >> @@ -243,6 +247,8 @@ asmlinkage void noinstr enter_from_user_mode(void)
> >>  
> >>  asmlinkage void noinstr exit_to_user_mode(void)
> >>  {
> >> +	mte_check_tfsr_el1();
> > 
> > While for kernel entry the asynchronous faults are sync'ed automatically
> > with TFSR_EL1, we don't have this for exit, so we'd need an explicit
> > DSB. But rather than placing it here, it's better if we add a bool sync
> > argument to mte_check_tfsr_el1() which issues a dsb() before checking
> > the register. I think that's the only place where such argument would be
> > true (for now).
> 
> Good point, I will add the dsb() in mte_check_tfsr_el1() but instead of a bool
> parameter I will add something more explicit.

Or rename the function to mte_check_tfsr_el1_no_sync() and have a static
inline mte_check_tfsr_el1() which issues a dsb() before calling the
*no_sync variant.

Adding an enum instead here is not worth it (if that's what you meant by
not using a bool).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210114142512.GB16561%40gaia.
