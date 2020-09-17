Return-Path: <kasan-dev+bncBDDL3KWR4EBRB3VPR35QKGQEBFGDFUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EC4E26E1C5
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 19:08:00 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id a19sf1220540pff.12
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 10:07:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600362478; cv=pass;
        d=google.com; s=arc-20160816;
        b=WtKOA5dFQlcgAUL+uh8hfZ50g+6Voq0kHjnjAosVl/BF8TcfvFbIlrrz/WqLSf5vyh
         VU5lkRvgdem1K/JTc0XBHxaiqhEaUr0Pg8RszHKUHN8yJVPn1QiU0uyfVtrNgqdvrEsf
         HR88r9ATIWIT+i1+HJZX0fIatriqPVsISJMcqbeCHoquG8Umh/+LlvvpaFcc8MJ2ZdLX
         2kI6YAoiN5YRK27eRh5Wywd+yuFLaTa87ObR/ydIe4t2VC59DrB4aQ7xvFLRTtNDxqoj
         MckCtqNeQ9qHppEzpLlFqT4zOwKK5fzI79VdW8mlUZKoNw/rPEP6Ci9aOu1jdWzmVNes
         tBiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=hv38iJIU1q7I6+aY3PYD6r/QXFzaDmvSjDOq6+4scGM=;
        b=fz6Wae7fnYqiYVT0opIuDUMKjzjsj6qGFQ6/AO+DFJXozbG/qeDq1Ki+0Tprih3TKb
         KrbJZbkU6o15KOiFbnRSqKeiiG45Y1gJ5ntzvR7Zj1SqSZogViY5uaEtdEqIgAJuSJX1
         1nKgKuX+GPhMUSIqBvZpgAirKd69TZU/aAjzYZ+tVVR9tiCmEAuEebq9P9GZEU9islHr
         T5YsGrulF8K79i27jsOctqexEMw7FTcttas30pNqMUWJx1jYWTiv7JIu/frkF2KSOIva
         shCFfBgJgX4zgaIVIHpMZlVgeGLdclpmjY8K2wa/gH9R/sCG3dPhRyQMKeOTG4ZsVe9B
         NUzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hv38iJIU1q7I6+aY3PYD6r/QXFzaDmvSjDOq6+4scGM=;
        b=siY5GRtlwrbmyZR2b/bF0VoKG06KBqPPEP5Z1/oThmVLH4cu/tNoTLEhc8702uU4U6
         aTcRACONHbGMNm6KGA8eRM8xdkLRaVZpY96Ta4UZNQoojVuNOl3rf2uiMoqNHzrJ4o+0
         sC654YQp6e4cXsGPNIhRDa1eVwOCfydYp5ybFzyZTlWVqqUs+Y63fJ5NGWfxabeRjp1a
         t30rbUGM9yFR5Y13JInyyNRlqlw8v+/PgCMRWfaXZS4iCYv9+KcjvXnDOPRreIbB7aNP
         XOwxbXAWpNsaQ3Sjq6hElPDHCX1BZ6MfnabQ0Pl4YXNM/2HheXpOvC7M3onVkDfsnRcK
         IKNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hv38iJIU1q7I6+aY3PYD6r/QXFzaDmvSjDOq6+4scGM=;
        b=KTQlHjx65DgurXplcv1akmykbMCD+gsVj6Cus9taTZDu1bfPktjMpG04u0tumTwxmg
         JR/lwRE+Pr0IFWzmCz/fxc7Mqp/KZHmbK/DFHAZyh4UUuTkNEeOiZxrR7HVdc/yxef0Z
         nHOl7TIhr/2bDYpB/p/XK/CMjgfQBgU53bOD/vv9UFnBHxC1NaUM7xv2znDij9e1aCEe
         uSXbc1bAs9GJOonuQTEBevOaLR0XQGvcpInfa6xmuHLpupw6RVB8A7SIJNyThOYp0mKT
         1PjQC7B+QpkvTtS1SgWlEcPxacDAViBJb9woPgH9sPew6BwX/Z/DFeiOHvlxaBzzdT36
         3wxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530PKhWiNRQHfrOng5lbu4BfmPB7X8kqMytmTRqs+aDN2WCs3exg
	yWXT8t2+ivQ1+tFxW367Muo=
X-Google-Smtp-Source: ABdhPJx6ZeWqOuzBuHeTN4UXnBFPu/r3U08aDXh6NANUbP8Vfu67qPxgZV0/C3z6ocrlpOYcLsHFWQ==
X-Received: by 2002:a63:2dc2:: with SMTP id t185mr2926751pgt.28.1600362478749;
        Thu, 17 Sep 2020 10:07:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d704:: with SMTP id y4ls1265289pju.3.canary-gmail;
 Thu, 17 Sep 2020 10:07:58 -0700 (PDT)
X-Received: by 2002:a17:90a:c17:: with SMTP id 23mr9279368pjs.127.1600362477989;
        Thu, 17 Sep 2020 10:07:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600362477; cv=none;
        d=google.com; s=arc-20160816;
        b=IPWEBYjCk4A+ER8PhaVRHbHBH96D36njs7zBa9PCYHYRkcP+qhIxJVI8fFaphYxH5+
         B2A9+ZyNXy6EEXDjLS5BePjjnSxsNNJq2D74MnizT9L74JPju1kkQTfGjx15nYu1D6C1
         /DTknMoqw9NBcDkK6RX/X3D649xZ+l0aURXdJ9XqaDT17XWJJ9te7Rs8+prNR3Rf+Slc
         vO5+v/rm04+g2c9QaI9T4x0LH0fy5rpbKZlXu4b2eO2eZCnlF8ISJU8t2s992X+huvWo
         kHoVuupHqoe2j6OKgft98nPC5G/JnjCg1QSE+bRUNAkPwZmYVoOYi24DdGYOR+xHaog4
         iONw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=qisL3UIIP1bFWfKhHpQiDTGQx4hTyExPaSeY+OMUFT0=;
        b=sygASPVfBaGe5xnOsgrlutAdRviPG9RfM+LJxNT6/EngbBr4nrWQwzCkDlHS4CZEPc
         hayirD/3Huxqh+X51Iz1OgHj7wV+i6d7E53eWs5IV08Fhku0OA3QR3+Wcc3x/hJgVO3F
         j1hDgKywhURCpczCY6lxf9DYKgqZqsE2SCNTRAsln4P25/qOsAwKWvoAAr2Gm2KlrEoI
         KEJ7bbbayLnt4y3x00/9ZMvrpn0RdNHk6ez2zoUGpxiN68in2dpJSp655tIQPOe7vKJL
         WQL4fHCWbpSgUk9jTyjUZLwdWoRurj7vFdwphEcxtxHtRoR+6SLlFB6AznMBFxfQ0hoK
         h1jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id lx5si13573pjb.2.2020.09.17.10.07.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 10:07:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 18D84206CA;
	Thu, 17 Sep 2020 17:07:54 +0000 (UTC)
Date: Thu, 17 Sep 2020 18:07:52 +0100
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
Subject: Re: [PATCH v2 22/37] arm64: mte: Add in-kernel MTE helpers
Message-ID: <20200917170752.GS10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <4ac1ed624dd1b0851d8cf2861b4f4aac4d2dbc83.1600204505.git.andreyknvl@google.com>
 <20200917134653.GB10662@gaia>
 <9ef0a773-71f0-c1d6-b67e-ccf7d8bcbbe6@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9ef0a773-71f0-c1d6-b67e-ccf7d8bcbbe6@arm.com>
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

On Thu, Sep 17, 2020 at 05:17:00PM +0100, Vincenzo Frascino wrote:
> On 9/17/20 2:46 PM, Catalin Marinas wrote:
> >> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> >> index 52a0638ed967..e238ffde2679 100644
> >> --- a/arch/arm64/kernel/mte.c
> >> +++ b/arch/arm64/kernel/mte.c
> >> @@ -72,6 +74,52 @@ int memcmp_pages(struct page *page1, struct page *page2)
> >>  	return ret;
> >>  }
> >>  
> >> +u8 mte_get_mem_tag(void *addr)
> >> +{
> >> +	if (system_supports_mte())
> >> +		asm volatile(ALTERNATIVE("ldr %0, [%0]",
> >> +					 __MTE_PREAMBLE "ldg %0, [%0]",
> >> +					 ARM64_MTE)
> >> +			     : "+r" (addr));
> > This doesn't do what you think it does. LDG indeed reads the tag from
> > memory but LDR loads the actual data at that address. Instead of the
> > first LDR, you may want something like "mov %0, #0xf << 56" (and use
> > some macros to avoid the hard-coded 56).
> >
> 
> Seems I can't encode a shift of 56 neither in mov nor in orr. I propose to
> replace both with an and of the address with itself.
> This should not change anything.

Then use a NOP.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917170752.GS10662%40gaia.
