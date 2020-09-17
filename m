Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB3UWR35QKGQEJCKXXVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 32DAF26E068
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 18:14:40 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id f10sf1589083plo.20
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 09:14:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600359278; cv=pass;
        d=google.com; s=arc-20160816;
        b=WnKgebSEJr+y52mXWPCiv+bzEfPbvI4IM2AHRmxjwZIWNf3YXYg0lzof6QwEphHxCz
         ob8Sq54X4fRn8B0GFO5Pt+gWxiGLK+8LmCj3HKXdX09H1Ijv0oMyXrQAfTOiTpOOUhO6
         dbWerq5fa7iwh9WDXF4N/jQo5LIVUpjGPcL+R+d4sROc7gn3YYUX7BEi9+qNeef8Gt3W
         Zyv7Kxf/epnzLZUC6wt99kLAMwIlEJjuNfvMKMQ1jVDer7KvTZUjJl6Fb1HC20qBQGTi
         4zbYBYil5V0j4gtBxcUvU0grZ1jaytRqX3MTLSqKFa0nNuVXNu27hn+XLOKCR9IOihkB
         qA6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=WN6Z7uitl5w/wSc8nY7LYw+n//keBfcg6OtA5FRFON4=;
        b=Po3/r5T+pnKjAKQI3RPJFk5d7XOTnyaMZPDOYVT4AgZa36NfM64r3wSHkk6oKWPJKD
         v3V31B93h/DkxHJTDo1LBhhByziZ+qUGVowUFozj2kqxFKKxmKPDZ9mHtbUUghpwC7qY
         5KOLSz+sJlPSVTdDDFbV2EXviwRdlf+iddC3F15vxQPDVTLZqOsmOn/c8GFOG6TXutk4
         8/zUvGHeSvRT/0mKO2bqGFcKfA0qD5p3itfGHIwzvBz4c6PA9KAPoj55RD2jPCtjhNs+
         +8n3OKaXIIEi9SGzm2AwREMJMZE9tjQmHYjLy4fL/ukh1tHzheY7n/3zTvkcVI4zr7B/
         OI5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WN6Z7uitl5w/wSc8nY7LYw+n//keBfcg6OtA5FRFON4=;
        b=ocIOdUHfuMzdFGzhIZaFVpm2bh74mGH5tSVBdyoLi++yDh7Vud45xfnG/BUog5xfSy
         mWzN16vnBLu4XAyLwtn2y/MVlR0pGZLXEbr1kASWn5U8GzsTXrsZYNwbZEvrHDsBIZOv
         Nl0F3agLey2/8FPlslwlzu/NbO/No/i29rsyRGubuuMndG2zROAM/KxSsTmX5H2gjpQZ
         pTMuI3sl8H8k830tcpq4SRJ4UgiQWyykpmDOY8Zlj5+vHqb14DAQK9KjPKuZnlfM1Eft
         +U09FfENC9r85Cifyr5tjnN2qTyV+2gkaKPbe07hCQb9KFeWi0ObEqRaM+pTlCbTzBFI
         a1hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WN6Z7uitl5w/wSc8nY7LYw+n//keBfcg6OtA5FRFON4=;
        b=FRx16AVTJvWxFqfbBhJzudoQMryIgVm9YIIfepGSnNhVaiEHCpyL187G8iqOHFtCX/
         e93jCpu41a++wP2EQCVvDy7xYhYrSqBtQdDVTAp2TQF366R/yLPElVjQTXR/pis8beFJ
         vAis3PVfZ0yfciL7557n3bQ555RdIhieSpnmH1ncxGysEX35AWMvZxkMcw1mAiwbJOAD
         Z1nRXfpi3Ewa5LfhyRf23rztGuzKwXpJwd6LmTjXVy921qJBwrXXUTYQKxmZNx9EVeAX
         KRDpSsmLWySt/oFkRs1bHHOe6FGveVeQW5fE0rxhF/lWcxOXn/qgZymBJtZ9FxVOAqlF
         u2rA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5304cwVPvCRA4zXdSzbh+xncnFv1dhIqEksAut4S+wyoa5w1+bp0
	TsdJx+HJtMl6vaw/NP7jHKM=
X-Google-Smtp-Source: ABdhPJyS8WdWhrTlhwssv28eKrTdZbgwREbHNz+43pppQAS9ra11XR+IHoxjrmEVz8GnX7/58ynrvQ==
X-Received: by 2002:a17:90a:f098:: with SMTP id cn24mr9136693pjb.158.1600359278432;
        Thu, 17 Sep 2020 09:14:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6b4c:: with SMTP id g12ls1295655plt.7.gmail; Thu, 17
 Sep 2020 09:14:37 -0700 (PDT)
X-Received: by 2002:a17:90b:70e:: with SMTP id s14mr9688839pjz.206.1600359277775;
        Thu, 17 Sep 2020 09:14:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600359277; cv=none;
        d=google.com; s=arc-20160816;
        b=Apt6715AgEKxrJg0fwwPBw8JUd9Z+9cN+W6PguaMQIjPN98iHpt1u9C7cbzZJVKo3y
         kL6d7nxUaXRA3YOCcSux9sMdBf4WIRR2in11zef9WHvABpK0wjmQqPCSgMtRPWRNZyGa
         OGoAZsYHh3xucWQEJsRZDUT7m60SoHZZ30qpr5Sm2/eVjQktBGP6UEuk1mzAW7Mstk/F
         pCNPWwo19JCfo5yUKa5ZWB1WkPFtsklSBTCSNkqvvmSPqUa5HXSOq3/ctmRHb+tW2L1b
         btTpQyuVmZTBO3Ru+9Z1GMB+2Q9kmeIndD4wv3roCG0E5mu4adSPi/sVLCrCyfWjIKye
         KnUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=/eEXjyFYVoSq7dvLcQ5DCIlBakTB4e00DRqp45IImcU=;
        b=ByzXBQXo5cbXewTYvO/1N/9lCebFO9/4lqJGOesqxHJVUHjL8HPfNl3mg0YpKUE64M
         xgePwmUCidbst6R+aBu7S4olC2v/i8TL7dm7hB+WYUmEGtxNPsuTfXgQRAkxYNHtVKVi
         lPBDnqPxuy+ne+eDlquSVE1EwMf8ExLeDWwuAPGIEWfJCJuyMxhYpBgE5Dl4gddX09hw
         ved673BHXkw7fXo/DWdcDq/TfTFSvsBtSVhxe2HDociSuiIdOLQV6O4NBEMGhgorbvQl
         jlj6QWN6MTcc4SwGMwm6QITxK3O4zIcuVOomsQFsBbQyTpcvbu4mIOCRM3wXvt2GQb8+
         EQ6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id v62si29995pgv.0.2020.09.17.09.14.37
        for <kasan-dev@googlegroups.com>;
        Thu, 17 Sep 2020 09:14:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id DD34D11D4;
	Thu, 17 Sep 2020 09:14:36 -0700 (PDT)
Received: from [10.37.8.97] (unknown [10.37.8.97])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id BC3BF3F68F;
	Thu, 17 Sep 2020 09:14:33 -0700 (PDT)
Subject: Re: [PATCH v2 22/37] arm64: mte: Add in-kernel MTE helpers
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
References: <cover.1600204505.git.andreyknvl@google.com>
 <4ac1ed624dd1b0851d8cf2861b4f4aac4d2dbc83.1600204505.git.andreyknvl@google.com>
 <20200917134653.GB10662@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <9ef0a773-71f0-c1d6-b67e-ccf7d8bcbbe6@arm.com>
Date: Thu, 17 Sep 2020 17:17:00 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200917134653.GB10662@gaia>
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



On 9/17/20 2:46 PM, Catalin Marinas wrote:
>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index 52a0638ed967..e238ffde2679 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -72,6 +74,52 @@ int memcmp_pages(struct page *page1, struct page *page2)
>>  	return ret;
>>  }
>>  
>> +u8 mte_get_mem_tag(void *addr)
>> +{
>> +	if (system_supports_mte())
>> +		asm volatile(ALTERNATIVE("ldr %0, [%0]",
>> +					 __MTE_PREAMBLE "ldg %0, [%0]",
>> +					 ARM64_MTE)
>> +			     : "+r" (addr));
> This doesn't do what you think it does. LDG indeed reads the tag from
> memory but LDR loads the actual data at that address. Instead of the
> first LDR, you may want something like "mov %0, #0xf << 56" (and use
> some macros to avoid the hard-coded 56).
>

Seems I can't encode a shift of 56 neither in mov nor in orr. I propose to
replace both with an and of the address with itself.
This should not change anything.

Thoughts?

>> +
>> +	return 0xF0 | mte_get_ptr_tag(addr);
>> +}
>> +
>> +u8 mte_get_random_tag(void)
>> +{
>> +	u8 tag = 0xF;
>> +	u64 addr = 0;
>> +
>> +	if (system_supports_mte()) {
>> +		asm volatile(ALTERNATIVE("add %0, %0, %0",
>> +					 __MTE_PREAMBLE "irg %0, %0",
>> +					 ARM64_MTE)
>> +			     : "+r" (addr));
> What was the intention here? The first ADD doubles the pointer value and
> gets a tag out of it (possibly doubled as well, depends on the carry
> from bit 55). Better use something like "orr %0, %0, #0xf << 56".
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9ef0a773-71f0-c1d6-b67e-ccf7d8bcbbe6%40arm.com.
