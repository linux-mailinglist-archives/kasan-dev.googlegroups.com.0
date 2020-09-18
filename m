Return-Path: <kasan-dev+bncBDDL3KWR4EBRBP77SH5QKGQEGRTUBHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id D9AE526F968
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 11:37:04 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id e12sf3334492pfm.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 02:37:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600421823; cv=pass;
        d=google.com; s=arc-20160816;
        b=GMADcYMMjihl2zZHT9LxJjrK9daOQyuV6a8tRiR9BilFgPYa/45yiL/1z5WzdA2O8Y
         ZyrWBnrITxXUvD3s9ttgF5pKYGWNa8/Y8fSiY3ST69teqC0x+wQwP5WOZalqnDO+2LA7
         x9VcAFlC3bolC8yKPWlxU/6RQmC/YVScG4IxPpM7reF9+ebZQyx8jwkb09cX5YESNqxr
         e+ceV1dhilqyS22nDXCu7W8lKIf0Vgs9X5JjtroJmBid7ZZBHlo/FEDe3ASEeIkQonSg
         DJswcx2skwMeO93ZGg5VTQNfIqua8JpCYRGPd2Ss/hz9Cpv2vCcvBjRFylPacMJ/tvOU
         Mm5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=3Cxln72ekaPVybrpM+Kh0qqNQF64h8wJIAbCpFRjih4=;
        b=rb3yEOf9gi5dydpFRdzSDf5UpuvTVLU/yzjyrASwyxrR6eJDjRQkCfxdLuhm8IUfep
         o80vBggMdW7CzzkYEq5dfgzH1580f6jyti9v0O7DHmlR45Ih2zBOsyE6T7uik57Zvrpc
         Wp07YnM/wC1pK4HMwNbPR8wxl7bHoWKl2rrrnMrAQriIp/4jMkoGOyJoqUOXYajsJGFS
         HOTVgb+JeRCKYr7v000Z33Htem5EsrMmOe0nd3Iy7re+zOQf9gDzvnYxpWfv7S6s2qE7
         sr7G8c2G7VneJAitK//cKtCt0o85jJwQlVrBglCH3eX6ej8zJgVA/zRgiP7Bqe92sUbT
         7sPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3Cxln72ekaPVybrpM+Kh0qqNQF64h8wJIAbCpFRjih4=;
        b=ibGf+3/OCe2bILjKgBnYqUP63MzlBLavWUskic9XVHK117sXxnndv4jILIafcGqGtl
         y1vp6im0snxm1F1Dljw7hLm6ah9cohnlUhrrryxl9zdLmQ/QOunCRpV+/myUUcSI4qT8
         n0foLzLBCSdyxxE/uJxBDmTdXkfpoDtAWdVA/hm1tNpJfkwpCW9l2pLDhp8jzEX3k5t1
         /rEa9M0Iv+B/OeoJXFdffI8QcCiiW9WdQhcony+RZNYffbiULE8kPWbqwwujYnQ+TOHb
         Z3sI9QdatNb3r5QJCatfa/tEfHiAl5k0/Y0iFjNQ/+ngJhlvI5EizXVEiD0JT6OdmyeC
         6Hug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3Cxln72ekaPVybrpM+Kh0qqNQF64h8wJIAbCpFRjih4=;
        b=UQa1ysgs/bKYcIReL6kp4gLefID+5suqxOfkl76GRLTAgFfC9Geak5Z9GY3cV6NVc/
         a4EW/OfdwZfPpSmihcNER10xtm7Eo6VFbcHo60cr/6/Jt3VEKWjmMZz4Cpk0AuLhoyP3
         nGq9uIHfWn0izQYqxWwMgjEN+9GFD8tGP1ZFwYtMn2U8JAVm+CcHbLYxX3yWcCA2I/DL
         AdSUpotxMwgYi5qVCIwu+JIIWhlil9MgJyCg3sqICaVNU+cb0i1/NnDqzqZ5tQDTHjK+
         /9mGZ++EZ9JJJvLhI4qJkXiWOLjmQK2OHADYfXLyPGSDPYoswz9hRIBe8G4KNlpRPWjq
         AxBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53237AfzQrMRWofMU/x+4bdCSzSxz394xkW4SNPLhAzyLT9XD/A5
	Z4uwnoh71scAxBNC1ejhQ04=
X-Google-Smtp-Source: ABdhPJwcvo+iPc3RMXOSYubM3yNDD97qKyAjFjRWCtTmD4p6dfg54+niuOnrDpTlwCd1Gzhu0dHvOQ==
X-Received: by 2002:a17:90b:1211:: with SMTP id gl17mr12648995pjb.87.1600421823369;
        Fri, 18 Sep 2020 02:37:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2292:: with SMTP id f18ls1970042pfe.6.gmail; Fri,
 18 Sep 2020 02:37:02 -0700 (PDT)
X-Received: by 2002:aa7:8001:0:b029:142:2501:34e6 with SMTP id j1-20020aa780010000b0290142250134e6mr15424909pfi.63.1600421822661;
        Fri, 18 Sep 2020 02:37:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600421822; cv=none;
        d=google.com; s=arc-20160816;
        b=kWVTO+P1qQBvUc3a2dCAHer7Ae9GlIjH3eFtmfV/rdt2NugodzBzv1vnTpHmpQFgfw
         FFyw1P9v2qilIydBzriU8li1zKeHDBl75TbWYScGIZFrU5ybbhnUxVLlm4XxQu0TknCQ
         +bWaHTKLC/QG/F+f5S6TbwxLJa3gwQduu6qYavzBBULjuPxWbEk0lmhmm60c3Xyu18PZ
         gKTgluLdYCEnohYTCFedU2PSSQD1ZFI+PSxqjxtjFfvd/QqKrIxCpTe+tnS/lxNHu7e7
         uxxOuti9mxm2f4nT/qgnFIKFsSMrasrFdFCepIqGuPYj4KiL+AUr4ZZnnyDMmAqOMU9A
         MuSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=YHOslJA6y0gE+r2JjVOekhKiWx8o75emfe2NXX1Qbhc=;
        b=AjG6gOsrCwNVQQ/xCvGxyr8NFJDug/2aMFj2XqyMqqRoz/Q77a7lnGTypnl5Y16pIO
         C8x82646Otun5ksykPIyg1e49WNfn57HFtIpA549tifNkY0VylH0JlFE+YZEgiE6V4OM
         FPoqv5Bjnx6CtxKqVADtSLUzE7Z8Ogps4Y+UQojR0i+dJ0K5tSsNyraOzZ/8z5Lw+CTQ
         dumL6v8ExLTRY1T+Owt2Qw7aJoEVwiHx/okGgJoVQpWORXan7d7zIrnZPPgHA0vVTy+N
         7arJ5Ch9JLaJJHVneYY+gnlDhlYVTHZO4xUJY3mVdTDTEuEsfX/I/fOyXfOq7yU0nQ92
         rV7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id mj1si208009pjb.3.2020.09.18.02.37.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 18 Sep 2020 02:37:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B0C1C21973;
	Fri, 18 Sep 2020 09:36:59 +0000 (UTC)
Date: Fri, 18 Sep 2020 10:36:57 +0100
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
Message-ID: <20200918093656.GB6335@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <4ac1ed624dd1b0851d8cf2861b4f4aac4d2dbc83.1600204505.git.andreyknvl@google.com>
 <20200917134653.GB10662@gaia>
 <7904f7c2-cf3b-315f-8885-e8709c232718@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <7904f7c2-cf3b-315f-8885-e8709c232718@arm.com>
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

On Thu, Sep 17, 2020 at 03:21:41PM +0100, Vincenzo Frascino wrote:
> On 9/17/20 2:46 PM, Catalin Marinas wrote:
> > On Tue, Sep 15, 2020 at 11:16:04PM +0200, Andrey Konovalov wrote:
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
> > 
> > This doesn't do what you think it does. LDG indeed reads the tag from
> > memory but LDR loads the actual data at that address. Instead of the
> > first LDR, you may want something like "mov %0, #0xf << 56" (and use
> > some macros to avoid the hard-coded 56).
> 
> The result of the load should never be used since it is meaningful only if
> system_supports_mte(). It should be only required for compilation purposes.
> 
> Said that, I think I like more your solution hence I am going to adopt it.

Forgot to mention, please remove the system_supports_mte() if you use
ALTERNATIVE, we don't need both. I think the first asm instruction can
be a NOP since the kernel addresses without KASAN_HW or ARM64_MTE have
the top byte 0xff.

> >> +
> >> +	return 0xF0 | mte_get_ptr_tag(addr);
> >> +}
> >> +
> >> +u8 mte_get_random_tag(void)
> >> +{
> >> +	u8 tag = 0xF;
> >> +	u64 addr = 0;
> >> +
> >> +	if (system_supports_mte()) {
> >> +		asm volatile(ALTERNATIVE("add %0, %0, %0",
> >> +					 __MTE_PREAMBLE "irg %0, %0",
> >> +					 ARM64_MTE)
> >> +			     : "+r" (addr));
> > 
> > What was the intention here? The first ADD doubles the pointer value and
> > gets a tag out of it (possibly doubled as well, depends on the carry
> > from bit 55). Better use something like "orr %0, %0, #0xf << 56".
> 
> Same as above but I will use the orr in the next version.

I wonder whether system_supports_mte() makes more sense here than the
alternative:

	if (!system_supports_mte())
		return 0xff;

	... mte irg stuff ...

(you could do the same for the mte_get_mem_tag() function)

> >> +
> >> +		tag = mte_get_ptr_tag(addr);
> >> +	}
> >> +
> >> +	return 0xF0 | tag;
> > 
> > This function return seems inconsistent with the previous one. I'd
> > prefer the return line to be the same in both.
> 
> The reason why it is different is that in this function extracting the tag from
> the address makes sense only if irg is executed.
> 
> I can initialize addr to 0xf << 56 and make them the same.

I think you are right, they can be different. But see my comment above
about not doing the unnecessary shifting when all you want is to return
0xff with !MTE.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200918093656.GB6335%40gaia.
