Return-Path: <kasan-dev+bncBDDL3KWR4EBRBCWIT35AKGQEI5LXILY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id BE7DE2544D7
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 14:16:11 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id z189sf4103080pfz.11
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 05:16:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598530570; cv=pass;
        d=google.com; s=arc-20160816;
        b=bq0w6IZp5YOzV/5JHFcYw3YwQrKCsq4VAyDNtmW7KAOoUQ8r0e91TDsfZNHc3ygxQ2
         +FKOjDmUsL9mvGMvkIHmb3bO3ZjGoi4CZ7zWbFUqYuicDgJYNO10Qdl0IAlOESecrGwo
         uAtxo2hji/wVhMdkR1VbTipPaCnT5yHgeW9bXO9SLFhURm4ZjCJ3UTEs6D7sC16VG8Qk
         lOEQ3nuVkaUeIpp1aPJguw4ZcZ8SOD97KyNx3RNB7IccAU4JvJiXmciN27ZX/UNcn1mO
         ukpto123reczXR64igMwT7gbFNTX0HU7VndhAWe2aNvEJ1vbBFQBDDXTtMFm2APb57XB
         VIxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=2vamPPTKpKgWQhtlbHkOuXRgBmCdgrpyXCYdhQxWatY=;
        b=HyEoWAdRw7AQnxffqljk3QuVPvOtIIUopK9jqCgnJlziuqCGtXSCeKDK+0oKw+03Y1
         olcwzslr02m9GIKye4DUxTXvoUy40B2g5SQjtP6M/Kzr1QuLW8c59Y2OL5Bn1JzQV09h
         pn+8RfAuM7DX/hss9lmck7yItBtsryxSwzvynFIIxxfvBDwPXaprwk4njiE9/Asq3NEy
         BeGvTkR3lm7Z/kQeKru0KHb7y/JMxQK/XJqS5mBNNwrDCOXpwM1TMoE/nYdeY2Ry9WmA
         /eihhnXmxrDe/eMioq9CtmTMwnvcVCA7NiuW522NveM34oCXaFViLY7s0Ut0YCWgK0d3
         X3HQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2vamPPTKpKgWQhtlbHkOuXRgBmCdgrpyXCYdhQxWatY=;
        b=irKquXja4DS3OyZwW05Oi/Qrfl5QYWxnIzAnE1zQWkafrmVYpZYdfWG6jsqfxXH8hO
         P4/Yhh6oTrMpeCNhnDFnlnGm4GV1rT4FP0b/D69ySb89/0n78SRFRFlUh6shmW/vw3a7
         HPVy4hRNSUhgLe/hbd/k4pyKpT6uk0Lvy01cDuID7fEsTzc8wMmkCAnzL/wVByifjqD8
         lNRg8KrCukYLdKjrE/rh/HObzcsIIixbx9Y70SdZ9sAGsRUFVPqZOgrUnXpCsxYnuS6K
         8yBQyvmrteRLbwYxfBPESwZpSMivLsyvHg4iSU1fRDJwLlX01vEA/0U1E17rvoU5OEVV
         aUzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2vamPPTKpKgWQhtlbHkOuXRgBmCdgrpyXCYdhQxWatY=;
        b=My2bv/wYhFq5r+d4t6Ulo6tE+7E//Pb+4J67Gm9rieiTQf3lJ4BosTfNx7bn10ipEM
         iMSqQR9ls8rjdIC/JZzmk4vGSIyN+kWvYpEIQdown4a3WmzRNSAAO+EXVdEEgtuE4pcU
         Ag91NlgF+XYqmrKGelD7Dm7hM/Dw73baXxT5XuKTgb6dF4F/11xI5idQcH2U1/69tFDg
         NZTwgFjg7UUDYt0PGM7EeKdy1DXWFKBbWuIAUmfwbxkpsGRcFcy6ithskriALD7c6ai9
         Cu4v57+8BY8GocIEFohfUvj5G8PWfECDX4OOL+SrBS0mS8rUcZDtOK9rvkejAcPA7Mdr
         jBCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533alujCpDBLZ/f2m+bH6sKfQQrorkoYS1EaJDvbdE76FoAukO9Y
	7HmHDGmQU/funZP6SlZHLUc=
X-Google-Smtp-Source: ABdhPJz+HA8ZsVGujP20jAMJ+AMCzoH/CzZD4kQTfBJKiXvlhEOdfMEAKd5XUH6HF6J06XsajY57uw==
X-Received: by 2002:aa7:874d:: with SMTP id g13mr16289185pfo.309.1598530570483;
        Thu, 27 Aug 2020 05:16:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8682:: with SMTP id g2ls1138297plo.10.gmail; Thu, 27
 Aug 2020 05:16:10 -0700 (PDT)
X-Received: by 2002:a17:902:9a88:: with SMTP id w8mr16233666plp.67.1598530570061;
        Thu, 27 Aug 2020 05:16:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598530570; cv=none;
        d=google.com; s=arc-20160816;
        b=UutZPb1RA8++lglwvP/Rp60zxTAWPpYyRgM518TXbIel3L+uU3v9uem2BgVCORI/I1
         gohmYUFi4kG25RVnuX11juyn6r33Au1yTKQNoMeaXVb8XwarSTkUMXUxSxdGEcPaqVkZ
         kWrIEADaipKU5/Gm4OdzCHrcySvOtLB0kvth+hf41DDC1c0asFneNnD59zN1mhbPYQ1y
         1YK+xPJhIkl2RQa2Dco5TVqkAHQLmYfJsYbo/7tmYHs7C4d7dAC/SYp5/kTsa5+sGKy3
         FlBldJECwIU02ocO14gqLiAmQkjtCl09myUtIOjkzTGRTZSaEva5OwUhfQDONbFSIpqg
         zQYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=5GmEMu09ZA/dXUNynSnstqBiFEdl3xPpY93d3/4myMs=;
        b=pRc1Z7X5culq5VxWs3tkc11lIpI7Ynw1fxN4T3PitNy4T4wjxbw2XAVArpNUxVwYgd
         tzrcuLtSJgPe5Dsndl/Ix6ifqXGbBST4tYGJqdmPDV5Bn/FIZkPmxPMXeug0YdRYMjaJ
         7VXNULu0H1Ys1sumdwu569Gpvxvm3zrtLC/03sdlFGmrvz63UVZomNoANkmj62AK7EAF
         8j6KUkkY4iPoOxfdY/9A6Hp/59AdR3YjqCEUBB08dBjj7CVlx7kQE3wKawrkOeP6UQ57
         c4VGAS6h6ooRFziLWXVsI27NK965GJ2eiC12/BPxb8i3fRtmQy2qN5i0Lznnbj7ncP/x
         y03g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l26si147212pfe.2.2020.08.27.05.16.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Aug 2020 05:16:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.127])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1D0BA207CD;
	Thu, 27 Aug 2020 12:16:06 +0000 (UTC)
Date: Thu, 27 Aug 2020 13:16:04 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 24/35] arm64: mte: Switch GCR_EL1 in kernel entry and exit
Message-ID: <20200827121604.GL29264@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <ec314a9589ef8db18494d533b6eaf1fd678dc010.1597425745.git.andreyknvl@google.com>
 <20200827103819.GE29264@gaia>
 <8affcfbe-b8b4-0914-1651-368f669ddf85@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8affcfbe-b8b4-0914-1651-368f669ddf85@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Thu, Aug 27, 2020 at 11:56:49AM +0100, Vincenzo Frascino wrote:
> On 8/27/20 11:38 AM, Catalin Marinas wrote:
> > On Fri, Aug 14, 2020 at 07:27:06PM +0200, Andrey Konovalov wrote:
> >> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> >> index 7717ea9bc2a7..cfac7d02f032 100644
> >> --- a/arch/arm64/kernel/mte.c
> >> +++ b/arch/arm64/kernel/mte.c
> >> @@ -18,10 +18,14 @@
> >>  
> >>  #include <asm/barrier.h>
> >>  #include <asm/cpufeature.h>
> >> +#include <asm/kasan.h>
> >> +#include <asm/kprobes.h>
> >>  #include <asm/mte.h>
> >>  #include <asm/ptrace.h>
> >>  #include <asm/sysreg.h>
> >>  
> >> +u64 gcr_kernel_excl __read_mostly;
> > 
> > Could we make this __ro_after_init?
> 
> Yes, it makes sense, it should be updated only once through mte_init_tags().
> 
> Something to consider though here is that this might not be the right approach
> if in future we want to add stack tagging. In such a case we need to know the
> kernel exclude mask before any C code is executed. Initializing the mask via
> mte_init_tags() it is too late.

It depends on how stack tagging ends up in the kernel, whether it uses
ADDG/SUBG or not. If it's only IRG, I think it can cope with changing
the GCR_EL1.Excl in the middle of a function.

> I was thinking to add a compilation define instead of having gcr_kernel_excl in
> place. This might not work if the kernel excl mask is meant to change during the
> execution.

A macro with the default value works for me. That's what it basically is
currently, only that it ends up in a variable.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827121604.GL29264%40gaia.
