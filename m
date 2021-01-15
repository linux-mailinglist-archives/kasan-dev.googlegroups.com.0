Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBJ5QQ6AAMGQEIIHOGMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 491F12F8330
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 19:00:08 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id o15sf5377595oov.22
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 10:00:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733607; cv=pass;
        d=google.com; s=arc-20160816;
        b=FYKaY9MD7FtfZbw8OyaKllL0tLrc14xPlSJI5ThCWCE/Apq3b25lMMH7PckP5mHyZ9
         tw44gQOLyWk7X5tm0YPpViDzLAOLdlYdfRl2VyrKtpRiHJWTvmwRrrds7Byt7sMVwpJR
         6L1qTr0BqDKvZ05qOg1qbhFc96VKaRm7rn8h/Q2wc+Xe5kn2CKr0OJlQIdbVHtJ8JoMM
         vSINOoslUz1AaBnst0KJx8I1YmQUfqpXuwRnA01Cgxo5Lkc8HMLyy9WkNwKHh8rE8kdy
         82MgfBxhbVpl5CnM/0ulJGPRZ5bRuNIiYcTar7Svy9fut9QmabLSpuWc5bn5dIaRmjx9
         5OEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=JWVc21d5DZt/Ax7xIpG/iermoUEtNOIyioikNcPI3OQ=;
        b=nvYUI3QByjbSWKoUUrj5e/lcqcdjDuBwxEjPmPziiZeqNS6FlDNgB09hlIQFeeh45z
         h+qhSDnxb5dld4VjlKGnS/y/GlCGXtKUszY3ICXl9PGVe1ido4Qef6TL2i6wmb3VQtEb
         5m+kccXP0jwDmqFavRSsfwoONW6s2h70JfNDVurccGSlEIIBkIP56RBhsKRRr+wa0Va5
         t++S2XPbbhc3Ufz831S5OZ4ZK+Ra8RR8keV7pCvWqsQIBaJwPh8FiO6r536+XMhSk9Ng
         ZUCOrI/egnRCX+JgO9lttC3VCMcGsrc22OIX0ZeJd99YD/fAhYM4z2+sdE3NkvQO8c8l
         ZReg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JWVc21d5DZt/Ax7xIpG/iermoUEtNOIyioikNcPI3OQ=;
        b=Tqis8vp1bGYe3HE1aojHBf77+PTAAasUdbdM6i4ESoX4kio88GJktvJ95yvQ8ywx1q
         lE/D0/1VNrLlN3UKfp76QA6Z3XR9J0EdzS+vBpEsiKx3oRJK2UB03Kk8twoOVzXYYhzb
         ouCMYMo91drrghh1hr3rnWRmnh7o4YnLaEO0QMuEaffDnqDoXbdleHkB1nS2vTysTfeO
         VBsY3hB3OeUm4DENg5Dp8UI61WWHiKdE/bdOkASsMyvq/qgjyD1t58V0YLqSKkJNQHjH
         r+L3hp+xCvK9xNm5ALlVJMEM9teLmn2vXPfmvTc4G4IGnzkjMFTwDL484akIVnt1nT7S
         JyBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JWVc21d5DZt/Ax7xIpG/iermoUEtNOIyioikNcPI3OQ=;
        b=I71wyEvvGI4XQKQUyMrQDB+Ize+Aqxe0FXZL60vv1RORevw/IEglbz6qpEAMx1IWWD
         2S5V29juaVzOujRcmBx9Z9X8+8GejbzH9QPwB/CSERxIvAH9lHqypywe+Mvm4K6/ZqpI
         nXLE1x5mpLrX0FuxDCm0qrtHNqUiVRJeQK6iUclZxnEg/ES41TsVk5MdOo0QGCewX5ZP
         QYoEk7GZ2hhTmhzuWMVhNy8lduD+iQumbAgH5Vzt3n1iRlgjAPGk+OWk5XxjoLLIhMR2
         noXZeZH8vskCAeebV4b3WnD0+W5jm9fZpaiI3AX6ZkoK3igN+Hv2GEa36xz5K1kt136N
         H78w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532WZBteCxHadjCTR6xYPX8PkBAP8dW3Eir7YvqZc/AtLnzUnKB/
	j7RhKA/pw/y0C4MCQolaEO8=
X-Google-Smtp-Source: ABdhPJzPHkXG1Z7pH8C+rBBpUDSY9oubbl5hhCSE8UkbuGEgHVnbjJ7WGnvkrN2lOT56w3uD9NbOag==
X-Received: by 2002:a05:6830:1610:: with SMTP id g16mr9177732otr.345.1610733607295;
        Fri, 15 Jan 2021 10:00:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1204:: with SMTP id 4ls2362128ois.6.gmail; Fri, 15 Jan
 2021 10:00:06 -0800 (PST)
X-Received: by 2002:a54:4785:: with SMTP id o5mr6455820oic.139.1610733606919;
        Fri, 15 Jan 2021 10:00:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733606; cv=none;
        d=google.com; s=arc-20160816;
        b=JYzC+oPiTtqxf0Zl+Ezq13c0jd2M/Yua33qGebLjBJGPrp6SNC/twP6UVm6TT5KFi9
         oykgUSjTgj+k+PMBmeu8gLvVKSnV9XFv2Q35TZXJx08yp90f3un3YQbUXwXzUcjfGMtS
         +2gXlmCBTihKhm9j8Y34Cksvr+jptLlzKUOC14tQo7MLkuO//6mrN1LFlDgkS5zcTnAS
         jLX3f9cl9jFzUPMpmp7jULijSMU/EJsORcyb6kJ+Cd5fydVi1c78A7+PCUaq9cC2dEOv
         oECg90x3wr1aZGXn4G27RubRBx6oBeEWhAlp9JH78dSPISgtLtWKh9by3bK6WABYbGYT
         xe/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=xTiOIlAimJwFNRzca0FQkYkDDXZoA7RFp+lSIj5BFJ8=;
        b=RJgrefgHMCeRQK1P5eKpnjHvli1+GXxZWlDpmqkk7j34yDstS9p2BdQjkf4MCunWyh
         jbHa/OPqmEYfNVVs8b/Rxol4Wi0wPXycnt/78MeEGWsFVAT6HMmzlPRcSBj4B66GkB4B
         IcHNB0vcOoTPhaYTHmsB5id+ecDoiVxwZdkBIZtSsmfku42ZKl8m8XRCbxjytnQ0wlZ5
         TIv6x5k69tMfwRgRKiLmN4PRUNJwF8C4wLpX3C5fU4tE687VHTg+CWK+Ctk1C7smaW/t
         gXBI8jU1toozse/IAcxO/k5hFb1CD1D3ZS+VU/k2gTcnVtzxVGBHSkzLM5ilXTdCHf8u
         /ucQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id f20si683253oig.2.2021.01.15.10.00.06
        for <kasan-dev@googlegroups.com>;
        Fri, 15 Jan 2021 10:00:06 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B0CC1ED1;
	Fri, 15 Jan 2021 10:00:06 -0800 (PST)
Received: from [10.37.8.30] (unknown [10.37.8.30])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id F33C03F719;
	Fri, 15 Jan 2021 10:00:02 -0800 (PST)
Subject: Re: [PATCH v3 2/2] kasan, arm64: fix pointer tags in KASAN reports
To: Andrey Konovalov <andreyknvl@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Dmitry Vyukov
 <dvyukov@google.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1610731872.git.andreyknvl@google.com>
 <ff30b0afe6005fd046f9ac72bfb71822aedccd89.1610731872.git.andreyknvl@google.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <2dfd9776-4b8f-45f8-b673-ecb7fa6e16be@arm.com>
Date: Fri, 15 Jan 2021 18:03:49 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <ff30b0afe6005fd046f9ac72bfb71822aedccd89.1610731872.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 1/15/21 5:41 PM, Andrey Konovalov wrote:
> As of the "arm64: expose FAR_EL1 tag bits in siginfo" patch, the address
> that is passed to report_tag_fault has pointer tags in the format of 0x0X,
> while KASAN uses 0xFX format (note the difference in the top 4 bits).
> 
> Fix up the pointer tag for kernel pointers in do_tag_check_fault by
> setting them to the same value as bit 55. Explicitly use __untagged_addr()
> instead of untagged_addr(), as the latter doesn't affect TTBR1 addresses.
> 
> Link: https://linux-review.googlesource.com/id/I9ced973866036d8679e8f4ae325de547eb969649
> Fixes: dceec3ff7807 ("arm64: expose FAR_EL1 tag bits in siginfo")
> Fixes: 4291e9ee6189 ("kasan, arm64: print report from tag fault handler")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

> ---
>  arch/arm64/mm/fault.c | 7 ++++---
>  1 file changed, 4 insertions(+), 3 deletions(-)
> 
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index 3c40da479899..35d75c60e2b8 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -709,10 +709,11 @@ static int do_tag_check_fault(unsigned long far, unsigned int esr,
>  			      struct pt_regs *regs)
>  {
>  	/*
> -	 * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN for tag
> -	 * check faults. Mask them out now so that userspace doesn't see them.
> +	 * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN
> +	 * for tag check faults. Set them to corresponding bits in the untagged
> +	 * address.
>  	 */
> -	far &= (1UL << 60) - 1;
> +	far = (__untagged_addr(far) & ~MTE_TAG_MASK) | (far & MTE_TAG_MASK);
>  	do_bad_area(far, esr, regs);
>  	return 0;
>  }
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2dfd9776-4b8f-45f8-b673-ecb7fa6e16be%40arm.com.
