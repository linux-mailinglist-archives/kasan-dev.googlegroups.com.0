Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB27F46MAMGQEJMMS2JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 886E65B1F96
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Sep 2022 15:49:32 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id b16-20020a05600c4e1000b003a5a47762c3sf8508744wmq.9
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Sep 2022 06:49:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662644972; cv=pass;
        d=google.com; s=arc-20160816;
        b=dzAVLL2E2j6GkRQG+4GG86+rVQoUILdhDNebstTA3jWbwF03RJd8Fb2avpmUG6bwpW
         WIxqUZVt8hKGqyV5aS0wLYZw/t88D9Kgub5bKwBLZqKajRu01WpbwV4/bSLFkNYutPFb
         7LvA4ATIfxItZPoaiaaUDi0xzUFOA1vpem6pqwyDWkKSrj+W9iYYtOnP3FBfa/u0eJL5
         gJrUqUDXPIYf/EXjEjXzdOtbGgwxDcM1Y0OWR4HrvVe1VZNCTJA3lDYTCY9DBoz/xmP9
         tAt/rs2rrNN+FPc/AeTCsGbFSpscOvAwgmPt+9i5mkykI4FhdRMHTquYtuwGF3Zxu4oT
         2fSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=adBdwYkicpFmlvo034Wez15ED8EaXUkSDe0qGUB8muY=;
        b=jB09QvHEqnOS1ZDo6DvdqseADeq895c1Yow8et9LgjviZ48Nmj6KdF62pe+pvw2/5K
         JlbZEaqmvEm83FrfyQKBH2QANDZzqXCeqel4dw/19MU6xE+6djciENs0O5Y9OWxxgX9r
         JP+yw78QAOmqvGorE6bZLSa5HaBBoWr2dt0d8gTBldUy6HRpipW721QjLxskXtnOCsfl
         azPPRvt4XjmMeDDZALOUstfg+pvTdN27dJqFJV7bhafhfBynfj/yJC+1KYgj5e/eRvQe
         Si8XSoUJkjgVHcOWuGSLBYaPt7ua10eF7Hfg7UqT2of5QLHRQEBR2FTrpOjyK12e47AC
         Fvxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date;
        bh=adBdwYkicpFmlvo034Wez15ED8EaXUkSDe0qGUB8muY=;
        b=OE5XkTPZ8tPF9xzCN6pLBB24q7f7i5dQeNyLnbYVCf90Pwa3JuEzbfDBdk07LnfxNl
         7qkBevw6TWvBWxr7bq8FWU4xjsEZy8q/IXzMsZ+SBfoiRsaiDERDFQDPxFu0qZ3yOLR0
         4fDFzEaETET5QeaOa/kRD/vygfvitahzk7ZJgzfa87VjyLRvYk5acLHq/xUgbNrt//f7
         NsVE54+1u4vHOQTHpYwIadzq15O/aZsjLn8bVfbhV7oho4f3BgVYajQhu1kBpYgJd8/u
         XuPMK+PwnhCAQRxWtKJkGyBA82MdxIo99En/HkJVFi1nETbi22lOBctZ0BGKFXncA97s
         l0SA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=adBdwYkicpFmlvo034Wez15ED8EaXUkSDe0qGUB8muY=;
        b=o3viWvQca1UmwLYJhFzrg4DoUkougtw2p0KNTfdHWO2Y/KJFEhkGxt+/ySxcA7Rg3t
         ypV0ejMkyf8isSZIYwmRcZAjhItMxqdyDqc+q0TcTyjN+TasNXwtv62HFojT2Z5WeBKW
         xxctCxIfvb2DSWiCRCeCSJbzh/AG0NvxtSj0M8QjEEEJ3AaiOWlOtYzfmDf6Lc1PFzrt
         h6I2M85G2V4JnHXDHuXK92LufvkLckFSEVIBtS2cKSU/0L55TlSFXJxpgfuxNIlavb2Q
         5v+fMRGRgb/9VaR5SXJZSoEQA/gdyRrdkBDz9iO+7mH11PmWL2KYp7xNAIyCMJGgvUtv
         Q1jQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0AeNHBPMcC5ScT++Hkq0xCA20JmvHlXyDM5AqoASklYgl2zdnp
	8VPi/rYzUCRR6z1gPiAdQWA=
X-Google-Smtp-Source: AA6agR620mdVhIsHIvr5pyjD8rtRIHXHeggEQOMnYpV98whI3E02Qr1CKrflCV57u0aEOCOOi/g3Ag==
X-Received: by 2002:adf:df8c:0:b0:228:b268:5ede with SMTP id z12-20020adfdf8c000000b00228b2685edemr5147649wrl.141.1662644971987;
        Thu, 08 Sep 2022 06:49:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6187:0:b0:228:c8fc:9de8 with SMTP id j7-20020a5d6187000000b00228c8fc9de8ls3417628wru.1.-pod-prod-gmail;
 Thu, 08 Sep 2022 06:49:31 -0700 (PDT)
X-Received: by 2002:a5d:5391:0:b0:22a:371d:c083 with SMTP id d17-20020a5d5391000000b0022a371dc083mr654908wrv.118.1662644971015;
        Thu, 08 Sep 2022 06:49:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662644971; cv=none;
        d=google.com; s=arc-20160816;
        b=hNuaBFKuj2HipJlwMGti/K0+K3K9Brxg4kBZYeWkqDm0iWqvjcNyn1u3IDrRKIl/g8
         GPEtLlR6wPv1aQ/uDQ3UE7aGDyj5A91G1ep9Pn0+YW3pWCPfuuCaYtXbPlU01/bzsTmx
         WlFlHz4x4VQ4Zhx3zVBTOEbQ5y+aaUbDlgoSf863ab9vjQYrklNOOFcMbj0IxT4FRs0S
         RwUdCw3yRYsXoUnpaLfmh5BIUgOwV1p080a7FKxaTWOYDruPj4yDUZlQEz1sol1GApIu
         WVUMIIHqf6esvwDUTN4m71eaRRCSb47vkNDRQkQazfccAIxSOZSpU7fGXVT9vHM8J4hm
         FhFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=vj18ZTTzuLlKSv9omQEfDSjwDi+Z+XtSx8GLvqYQKAs=;
        b=EXD57S9fbdJThi4yMnbWvQNO5Wa4Lw6x1/XFRmU1unWMiXNSBSzmzASOipWgLpUx+i
         fg5kgA7ekKJvQKESmc7jPr6ncOEHQO253UhodyzzlSdyOXzq79FHS77+PLZRnB1OawAS
         yJE15DTzHZdUJQq2KBM8EB7RWEM9lCjiCGA6o+ZyERJc0r+6+BW7AAOqW0l65Snlj2RX
         YRl07Gfo30ZpDwv5WWzeIrvG0b54widk/rm2wsr9Zwewq7t4zp4WnhSodDu/AayTx5yI
         1NGeFI4hLSib8bOPnsGh6q85sTIecl1ySB0mMeVbMP0e3PvBGy+Q6YKqdX/sZcxvLebX
         6h8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id bi20-20020a05600c3d9400b003a83fda1d81si56904wmb.2.2022.09.08.06.49.30
        for <kasan-dev@googlegroups.com>;
        Thu, 08 Sep 2022 06:49:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6B4E423A;
	Thu,  8 Sep 2022 06:49:36 -0700 (PDT)
Received: from [10.57.14.149] (unknown [10.57.14.149])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 72AF93F7B4;
	Thu,  8 Sep 2022 06:49:28 -0700 (PDT)
Message-ID: <649ce069-050e-83c8-24d6-6aab6bb3f471@arm.com>
Date: Thu, 8 Sep 2022 14:49:25 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.11.0
Subject: Re: [PATCH v2] mte: Initialize tag storage to KASAN_TAG_INVALID
Content-Language: en-US
To: Vladimir Murzin <vladimir.murzin@arm.com>,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>
References: <20220907110015.11489-1-vincenzo.frascino@arm.com>
 <198b1486-d402-9061-a6f0-e522a548f040@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
In-Reply-To: <198b1486-d402-9061-a6f0-e522a548f040@arm.com>
Content-Type: text/plain; charset="UTF-8"
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

Hi Vladimir,

On 9/8/22 11:36, Vladimir Murzin wrote:
> Hi Vincenzo,
> 
> On 9/7/22 12:00, Vincenzo Frascino wrote:
>> When the kernel is entered on aarch64, the MTE allocation tags are in an
>> UNKNOWN state.
>>
>> With MTE enabled, the tags are initialized:
>>  - When a page is allocated and the user maps it with PROT_MTE.
>>  - On allocation, with in-kernel MTE enabled (HW_TAGS KASAN).
>>
>> If the tag pool is zeroed by the hardware at reset, it makes it
>> difficult to track potential places where the initialization of the
>> tags was missed.
>>
>> This can be observed under QEMU for aarch64, which initializes the MTE
>> allocation tags to zero.
>>
>> Initialize to tag storage to KASAN_TAG_INVALID to catch potential
>> places where the initialization of the tags was missed.
>>
>> This is done introducing a new kernel command line parameter
>> "mte.tags_init" that enables the debug option.
>>
>> Note: The proposed solution should be considered a debug option because
>> it might have performance impact on large machines at boot.
>>
>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>> Cc: Will Deacon <will@kernel.org>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> ---
>>  arch/arm64/kernel/mte.c | 47 +++++++++++++++++++++++++++++++++++++++++
>>  1 file changed, 47 insertions(+)
> 
> Nothing in Documentation/ ?
> 

I can have a separate patch that adds documentation of the kernel parameter.

>>
>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index b2b730233274..af9a8eba9be4 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -6,6 +6,7 @@
>>  #include <linux/bitops.h>
>>  #include <linux/cpu.h>
>>  #include <linux/kernel.h>
>> +#include <linux/memblock.h>
>>  #include <linux/mm.h>
>>  #include <linux/prctl.h>
>>  #include <linux/sched.h>
>> @@ -35,6 +36,8 @@ DEFINE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
>>  EXPORT_SYMBOL_GPL(mte_async_or_asymm_mode);
>>  #endif
>>  
>> +static bool mte_tags_init __ro_after_init;
>> +
>>  static void mte_sync_page_tags(struct page *page, pte_t old_pte,
>>  			       bool check_swap, bool pte_is_tagged)
>>  {
>> @@ -98,6 +101,48 @@ int memcmp_pages(struct page *page1, struct page *page2)
>>  	return ret;
>>  }
>>  
>> +/* mte.tags_init=off/on */
>> +static int __init early_mte_tags_init(char *arg)
>> +{
>> +	if (!arg)
>> +		return -EINVAL;
>> +
>> +	if (!strcmp(arg, "off"))
>> +		mte_tags_init = false;
>> +	else if (!strcmp(arg, "on"))
>> +		mte_tags_init = true;
>> +	else
>> +		return -EINVAL;
>> +
> 
> You might want to offload parsing to kstrtobool()
> 

Good point, I was not aware of this API. Thanks!

>> +	return 0;
>> +}
>> +early_param("mte.tags_init", early_mte_tags_init);
>> +
>> +static inline void __mte_tag_storage_init(void)
>> +{
>> +	static bool mte_tags_uninitialized = true;
>> +	phys_addr_t pa_start, pa_end;
>> +	u64 index;
>> +
>> +	if (mte_tags_init && !mte_tags_uninitialized)
>> +		return;
>> +
>> +	for_each_mem_range(index, &pa_start, &pa_end) {
>> +		void *va_start = (void *)__phys_to_virt(pa_start);
>> +		void *va_end = (void *)__phys_to_virt(pa_end);
>> +		size_t va_size = (u64)va_end - (u64)va_start;
>> +
>> +		if (va_start >= va_end)
>> +			break;
>> +
>> +		mte_set_mem_tag_range(va_start, va_size, KASAN_TAG_INVALID, false);
>> +	}
>> +
>> +	/* Tags are now initialized to KASAN_TAG_INVALID */
>> +	mte_tags_uninitialized = false;
>> +	pr_info("MTE: Tag Storage Initialized\n");
> 
> Why All Words Start With Capital Letter? :D
> 

Do you have any preference? :D

> Anyway, you might want to advertise tag value used for initialization.
> 

Yes I agree, I can print "Tag Storage Initialized to 0x.."

>> +}
>> +
>>  static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
>>  {
>>  	/* Enable MTE Sync Mode for EL1. */
>> @@ -105,6 +150,8 @@ static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
>>  			 SYS_FIELD_PREP(SCTLR_EL1, TCF, tcf));
>>  	isb();
>>  
>> +	__mte_tag_storage_init();
>> +
>>  	pr_info_once("MTE: enabled in %s mode at EL1\n", mode);
>>  }
>>  
> 
> Cheers
> Vladimir

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/649ce069-050e-83c8-24d6-6aab6bb3f471%40arm.com.
