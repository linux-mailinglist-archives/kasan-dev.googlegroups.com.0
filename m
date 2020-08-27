Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB3M4T35AKGQEUFS6PGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B0B42543F5
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 12:43:59 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id h13sf868672uab.19
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 03:43:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598525038; cv=pass;
        d=google.com; s=arc-20160816;
        b=RI6fD8qxDNIz5Tw2tAvFX0F8uTgPvgcZtaGyGAB88S8GXWttTnO2ZgmIZr4B3pRaKj
         3w+R1+SkmmhXOzQhPeOgbRe1zXR93arRzSp8aXXjcDNq0fWL/WGvN0g+2KlrFY8rzPxV
         rZPOx7THsf2oI0Agzx8EL3noOU+GcgrfEenYHYGgykFaGCK9cKqnajJth9adtWdppKyd
         RmgceMv8FTYGFk1E1VVKGdZxmlMXSeWooM9FgZktl3QtgGQSKa3fYA3VL2EPB0vcLjIS
         rbS1iP6Nvd14CaHlyOFt2Y1SCASGHbDH25lTLAYNILCmqd5SUn8hfiOitkBXj7eadGWy
         4YMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=+6wR2NNqRnZZ9UNimD9Mdm2bZcU4uom0JCgioYnfLa4=;
        b=wmW9igvvhJApD2/T1kxzmyw40nIkV7IoBaNTijG+GpCGh6bgorXijuPGY0uXHaKHP2
         gb1XvrZMdombR7TVOwkvgk4EWuNo7zFR9Fcty5jD43K+W5p5lLadv5gzqUBjx5ufLtrN
         IfHYfb/eXKDMRARozBGTo9bowmNzazE9MV0Ns4/CU3zgn//p6GpHMpOcqdmTgzoy6Lbg
         MSpwgbH4xegYaGmG0LbzYBNC3kY1gWnJ90EkC3nk3b8AmHD56vA2CGidiHnP/96nGHdw
         srBV61BMIgDeehbLJSQZgfp3ely1KvWE+Xq2yhBblVg9pMg3EdMqIzE3VMsnL/Z4FxDh
         81tQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+6wR2NNqRnZZ9UNimD9Mdm2bZcU4uom0JCgioYnfLa4=;
        b=JRYPgPZ2UiSqjUPvx4hgvCyk7ZXKkh3Jf/3NCxb5+1Jo5eMpcEYbMcAQrZxSTge/fj
         wtfMELu4EoYrJidEr5yiBsAoj46llRwaSewAnXo/XylgiZqXBNactH0puX5qcXhMD3re
         iKNnrnMQYAmjJYkq1xWExi0yMWnYpCSDMdGezNUZ7g4LgFnimGyRo9/GNaZHfXu7Pv7F
         SySm+W4MT0USYq1FBn+iWrAx5WqUqjEu/oChRnQp3SCkbZp70bcXd9GeHZ1zO4x5EKnS
         KwO+KEeaxnRJEfy1/d/sk2Bd5usESmz9zXwv4p9HRCi3yiJyamYC7wiEZ5mEbGApx1tS
         JJEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+6wR2NNqRnZZ9UNimD9Mdm2bZcU4uom0JCgioYnfLa4=;
        b=tzeU3h+Kxy9ay8TvryXsh8EeJ0tSesLP1XyJIFTtFhLKDFWN0pVxmeIIrrUzq9NwR0
         6lX/q8+j/kp2bpVNTSyNFUTGtOPM3Hb0wvMObgF34XL5HVm36XWEx0sxa8Nn1GPOBWMf
         VoLYxCM+9sbBXtbXKJWLXQjgBPxt5ZAvcEj6y3YongfL1eDsogM0UiY4slWKQf45pxR2
         4f3IAoEh4jadb5W01BuKOV2yahCcOxWQiYYBhk4ce62SFOX4hz/9DWzngKDzEEulgY/L
         XVrWaJjU1C3XE4Wn389UPm9rDd1IBRtt1mxnXFLCA8ekNyjxyk5ise85qq61dQwxjq3P
         +s1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326jF19goBdMOSiT6I+AWdrsbm8BjdYMqkNXaGOHgkXxSw87ADD
	Q8xYCF9UxsmAbF1zrujdsCI=
X-Google-Smtp-Source: ABdhPJz0WvxMyvLr1rCFvi3LsYxs3Sf57xyMH4qivyBk3bcIAZZKxhK1PXhSgYfTcTIHS/eveMEu/w==
X-Received: by 2002:a1f:b6d4:: with SMTP id g203mr11933726vkf.2.1598525038113;
        Thu, 27 Aug 2020 03:43:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:2667:: with SMTP id 94ls133613uag.0.gmail; Thu, 27 Aug
 2020 03:43:57 -0700 (PDT)
X-Received: by 2002:ab0:108:: with SMTP id 8mr11723530uak.25.1598525037579;
        Thu, 27 Aug 2020 03:43:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598525037; cv=none;
        d=google.com; s=arc-20160816;
        b=0kClrZgls9zQtfU3JXH2B7MCq6LSB3qu3EUIAVK5uAuPZSEMRLfbQlk0Tqm0it4g9X
         OqkkQOMkKiMeUReG2EDw0z3qZxwn335ZazQghZigRlb4ZxP1+yrOYtPMROeObFn81CLw
         As1Od+uHGNlfGtm4G6RSfcgjz2E2ZeLwiYBs+d/xcre1SsQleoek81HFZYU7BV9Zxqhq
         nPygyrQbFj5mMt+O1NBuQXlnvr7MIkC2JRDiCCBZ0pFG7WNzPAUYebnorBU9PcaWJVSh
         z8DuAhiswNmxpwDEhVAYIMSUxvP0F9Xaz8lvGgn+EWHwT7ODX2TNQMElm4rwSd3r+z5L
         5i1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=9oST2vmbxmA/3S6YthdqQO/ZsxHBpRhCAo+gpaFgJag=;
        b=ykue2D2Oqcv0JHsqFZILBRoFJ8MFsqLyWp5JD23B2VFKM6qxf+p6qFH6Yn1bCDJNs4
         yqqhfXsgZpQkDCY+13OMbbuauH+bssmz01XDiUoAj7xBmAptRCaUBFzcOIxoUKJOhm/b
         NG8TcNKUdtUKjluZF3og5AvHcSac6yfQNgdZCmvP8DzYihVRU7s61dIcJ09ReT4nJ4/x
         VVKOxGFIVs74IyZp0su+enfxxF78nOWKYGQA0wgaOr0v8Bqv1SoSU5ZrTimD9441/npG
         eQeLoAB81Xu66TkxDm4KFXx9TENgyCSlECXp4Q43LtmkHis4mNRwE+QBRDGLytr9bREY
         gjXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id q1si137972ual.0.2020.08.27.03.43.57
        for <kasan-dev@googlegroups.com>;
        Thu, 27 Aug 2020 03:43:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 07723101E;
	Thu, 27 Aug 2020 03:43:57 -0700 (PDT)
Received: from [192.168.1.190] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id EF7063F66B;
	Thu, 27 Aug 2020 03:43:53 -0700 (PDT)
Subject: Re: [PATCH 22/35] arm64: mte: Enable in-kernel MTE
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1597425745.git.andreyknvl@google.com>
 <6a83a47d9954935d37a654978e96c951cc56a2f6.1597425745.git.andreyknvl@google.com>
 <20200827100155.GD29264@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <a9ca504c-70cb-2fea-77dc-c02ba9dd3a7e@arm.com>
Date: Thu, 27 Aug 2020 11:46:07 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200827100155.GD29264@gaia>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
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

On 8/27/20 11:01 AM, Catalin Marinas wrote:
> On Fri, Aug 14, 2020 at 07:27:04PM +0200, Andrey Konovalov wrote:
>> diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
>> index 4d3abb51f7d4..4d94af19d8f6 100644
>> --- a/arch/arm64/kernel/cpufeature.c
>> +++ b/arch/arm64/kernel/cpufeature.c
>> @@ -1670,6 +1670,9 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
>>  	write_sysreg_s(0, SYS_TFSR_EL1);
>>  	write_sysreg_s(0, SYS_TFSRE0_EL1);
>>  
>> +	/* Enable Match-All at EL1 */
>> +	sysreg_clear_set(tcr_el1, 0, SYS_TCR_EL1_TCMA1);
>> +
>>  	/*
>>  	 * CnP must be enabled only after the MAIR_EL1 register has been set
>>  	 * up. Inconsistent MAIR_EL1 between CPUs sharing the same TLB may
>> @@ -1687,6 +1690,9 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
>>  	mair &= ~MAIR_ATTRIDX(MAIR_ATTR_MASK, MT_NORMAL_TAGGED);
>>  	mair |= MAIR_ATTRIDX(MAIR_ATTR_NORMAL_TAGGED, MT_NORMAL_TAGGED);
>>  	write_sysreg_s(mair, SYS_MAIR_EL1);
>> +
>> +	/* Enable MTE Sync Mode for EL1 */
>> +	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> 
> In the 8th incarnation of the user MTE patches, this initialisation
> moved to proc.S before the MMU is initialised. When rebasing, please
> take this into account.
> 

Thank you for the heads up.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a9ca504c-70cb-2fea-77dc-c02ba9dd3a7e%40arm.com.
