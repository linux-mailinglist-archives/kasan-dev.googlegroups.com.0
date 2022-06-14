Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBRPOUCKQMGQET2V4JQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id EC9D354AA56
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jun 2022 09:22:45 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id o23-20020a05600c511700b0039743cd8093sf4407769wms.6
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jun 2022 00:22:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655191365; cv=pass;
        d=google.com; s=arc-20160816;
        b=sxXC2ixjdSphpdgUfYfPpR0L2566xA8r4v9rW+SlY6YhqX2IelB7xU4aMXyvRH+AmP
         db8pTj/fOUmZpERxTMMt2ypOg7VFuCoaBYPUMJqeT7iGe5MZYYfd+ROiVYh8MQj9a/Fy
         TT+RWVY4L2/D8P12ao5KxUQjYKyldZRmXGJPOGsbuu6VVIdMH9DdPURH9IF8f8Mb3C2u
         +ltEJJ/myv/7FpjZ/kwA4ihn1Bvw+S+1mXmykBrPRBnomwpXwSiXpG2ResJCWYLAnk6t
         RaruK5oD1owEhpAHuZLwTnbLPjFj20104M6SFnqdXssChQm3hsjcljZRBY/ux0vQqoBo
         L8Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=fhHr9XfGfMikPmZNm5Oe/WOa9aJB9gtv5Mf/svAmI0w=;
        b=f2IW4RK+QA4FIlsttfeqA2j+NvF+VSOKjxqsZ1D+Z+PCEY6+ipAPrtcgEoMYYAaBvh
         N0BX0kMc+KixCuzROKF8LqX645J7qbVxiZzilJDnKCRIFnmWc8ZdEjCEeMU2JBC7VbC1
         B0F1NabmAjszD2OCCM6qX8B+ZLpeLJ6kikRQvMktPO9WX7HB04itKscHrcjqcAoaPBvu
         nh4116yL9TvTSMZI52fSFqYx/p8wNBB8yXzld4aZ2f8c1G9rY96Qw3V63x9rajWyED2G
         LrUbgJ4QsqTo2PExC6T1dR77Y9AtHVedsITum+O2Tr8DT2wk+I9RQokkMzdl3hUevckh
         HzPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fhHr9XfGfMikPmZNm5Oe/WOa9aJB9gtv5Mf/svAmI0w=;
        b=EEJGvf6bFLKli+JF5xZNti6MYAz1IFlq1fgnhLzkLBTBi21YVf4ZVJ9N+9uY5T0PqB
         wMLFAS3ZBNyHqCkOjrr1S2+W6wcNX+aTi/ydAZjNk/LsEbk8F+L44qO0mH4bMJBp7e0w
         B51HsP0A9uagkx0GBBhfs6zFVlQLoSkA66WsQ5ozfY3C3Fj6VUMkwWap4p1/Xj8MFruP
         81bznZXZGuCES0EJflqYpYsNJdDbjPrlYtJ+yYRCUakm/M8Z7D4KbAQ/XpxOGjd9sN+d
         dIEj3C4BCMoUHc5xYywWZxyVFjC+oLSA1tb4Ocg3z7gcditUVOVGWnvxzG5S1WuTqDY9
         AKPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fhHr9XfGfMikPmZNm5Oe/WOa9aJB9gtv5Mf/svAmI0w=;
        b=GI181133m1TZXBN6z1PROtNIn7ebbdjU2uztjsbGHXcv3Arat8nLj8DYzo9/zxQFpv
         7rebszAEjhPb/Ll3cgMALUpVRvD0f0nJs6km1QkXXPJULH/DVE/LEwib4hR4sy0+v1oP
         gPqR1cb/GLDRLu2b2Y99is7OkpOfyM1wu8E00q1kJnWQQCI3k3UBKlA4+ZfQF58zaSQn
         aMGLH1o0vG8yjCYK2wgFOGcrkbMPM6P1igxkoGoD6XCcn5YgW2QJXo9qkbCbrAtD6pAa
         9RnKlwX/SkWZh/xEg2r4rf4VvZb8wn8nRqMHq4B/L/Y50zf1OvWUO7BlfTCVOZFVjdgs
         U1ug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/yHnpzNFrEujDFR82Q3mq+05SWlTfCooVaKMUKH0GIVpwPhrbF
	Nf/ZyeaufxJ+nsSVemOE2Gw=
X-Google-Smtp-Source: AGRyM1u2jGPg45OT7hUwPA6b1T4EUx+9TXyyh+xvnoWawP6PLUqqefVqG+wI0exqHMrzoDbX2WT85w==
X-Received: by 2002:a05:6000:226:b0:217:851a:4300 with SMTP id l6-20020a056000022600b00217851a4300mr3413666wrz.389.1655191365475;
        Tue, 14 Jun 2022 00:22:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5848:0:b0:219:b7ea:18e1 with SMTP id i8-20020a5d5848000000b00219b7ea18e1ls1986133wrf.2.gmail;
 Tue, 14 Jun 2022 00:22:44 -0700 (PDT)
X-Received: by 2002:adf:b358:0:b0:216:508c:e0bf with SMTP id k24-20020adfb358000000b00216508ce0bfmr3401846wrd.204.1655191364484;
        Tue, 14 Jun 2022 00:22:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655191364; cv=none;
        d=google.com; s=arc-20160816;
        b=bIM3XAKEbAQ5/353ZxSM7oQgO367RGotAGcCPFZY5yCLNzRVmpYjLuAizkOv9SSq/T
         Ubm78x5U6ME0stE6Krd5NIPxXY8H5FfRY3qDy+q6DHCCfudJ+TFSwB38evoUrL3UkJau
         HY6+WRXJQO6tdsLaEK7RCgwFxKe9bAVK6+Y7p22knUZj7w4pLrk+mflvMDkG1B5+0e7p
         ItwshOKVRjZ+AqlCm09CXse8lX9NV3bLe3pWfTsa6IJZAUlUN+duQIWu7IWDUM11n26U
         V3dMHkR8Ew+HJc6IDE8yLH48X3m41+p4TwkeAh3P0gqWvDllPyflonMMsPxDmA2x0uwy
         qjkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=TW+pYc3P2lOWM57VaDJBPIH/Hnvj+YqaDVs+UgX0XZc=;
        b=bKt+Wtr/yjX6Tt2t7oB1c9JwB+lHzdelF2M2lvPW9qWIZzLfY3NZKPToOO+wthOVp6
         +bcZwuYhWBaH8h86M3bUtyhZkOOaoeEVwrNntZRBQzUwiQZbeW2oMIfrdGJd3pR5w8RG
         yJyfvFU2qGbPWUDvTErAYR2/cQoKKwY+IJZESeLjjF3UK4s5yournfSQnJjFwxLn/IEt
         1GB1EJRcHttpnsy0caKCewgfEDR2BpRi6bN3rNzy7jjRh9lOm6GjYcTN/GNZFXr8ucjb
         z5Tk6m2MmQR4ycBk4SRzTRdZartB9E24DVRFEKPIqB427jr8JODLCsYuQNzOtZtYAPyt
         CtKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p17-20020a5d4591000000b00219adf145aesi271406wrq.6.2022.06.14.00.22.44
        for <kasan-dev@googlegroups.com>;
        Tue, 14 Jun 2022 00:22:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id ABBC3D6E;
	Tue, 14 Jun 2022 00:22:43 -0700 (PDT)
Received: from [192.168.4.21] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E29E43F66F;
	Tue, 14 Jun 2022 00:22:41 -0700 (PDT)
Message-ID: <b35a1a9a-9dfc-27f6-8e82-791414454b48@arm.com>
Date: Tue, 14 Jun 2022 08:22:28 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.9.1
Subject: Re: [PATCH] mte: Initialize tag storage to KASAN_TAG_INVALID
Content-Language: en-US
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>
References: <20220607113150.55140-1-vincenzo.frascino@arm.com>
 <CA+fCnZcZcoOz+SVXdVOsrC_pR_PJUoCQnJe3B2u=D_K7=J79+Q@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
In-Reply-To: <CA+fCnZcZcoOz+SVXdVOsrC_pR_PJUoCQnJe3B2u=D_K7=J79+Q@mail.gmail.com>
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

Hy Andrey,

On 6/9/22 19:34, Andrey Konovalov wrote:
> On Tue, Jun 7, 2022 at 1:32 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>> When the kernel is entered on aarch64, the MTE allocation tags are in an
>> UNKNOWN state.
>>
>> With MTE enabled, the tags are initialized:
>>  - When a page is allocated and the user maps it with PROT_MTE.
>>  - On allocation, with in-kernel MTE enabled (KHWASAN).
> 
> Hi Vincenzo,
> 
> I think we should move away from the KHWASAN name - it was used during
> the early prototyping days for SW_TAGS KASAN. What you mean here is
> HW_TAGS KASAN.
> 

You are right, I will fix this in v2. Before re-posting I will wait and see if
there are more comments.

> Thanks!
> 
> 
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
>>
>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index 57b30bcf9f21..259a826363f1 100644
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
>>                                bool check_swap, bool pte_is_tagged)
>>  {
>> @@ -107,6 +110,48 @@ int memcmp_pages(struct page *page1, struct page *page2)
>>         return ret;
>>  }
>>
>> +/* mte.tags_init=off/on */
>> +static int __init early_mte_tags_init(char *arg)
>> +{
>> +       if (!arg)
>> +               return -EINVAL;
>> +
>> +       if (!strcmp(arg, "off"))
>> +               mte_tags_init = false;
>> +       else if (!strcmp(arg, "on"))
>> +               mte_tags_init = true;
>> +       else
>> +               return -EINVAL;
>> +
>> +       return 0;
>> +}
>> +early_param("mte.tags_init", early_mte_tags_init);
>> +
>> +static inline void __mte_tag_storage_init(void)
>> +{
>> +       static bool mte_tags_uninitialized = true;
>> +       phys_addr_t pa_start, pa_end;
>> +       u64 index;
>> +
>> +       if (mte_tags_init && !mte_tags_uninitialized)
>> +               return;
>> +
>> +       for_each_mem_range(index, &pa_start, &pa_end) {
>> +               void *va_start = (void *)__phys_to_virt(pa_start);
>> +               void *va_end = (void *)__phys_to_virt(pa_end);
>> +               size_t va_size = (u64)va_end - (u64)va_start;
>> +
>> +               if (va_start >= va_end)
>> +                       break;
>> +
>> +               mte_set_mem_tag_range(va_start, va_size, KASAN_TAG_INVALID, false);
>> +       }
>> +
>> +       /* Tags are now initialized to KASAN_TAG_INVALID */
>> +       mte_tags_uninitialized = false;
>> +       pr_info("MTE: Tag Storage Initialized\n");
>> +}
>> +
>>  static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
>>  {
>>         /* Enable MTE Sync Mode for EL1. */
>> @@ -114,6 +159,8 @@ static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
>>                          SYS_FIELD_PREP(SCTLR_EL1, TCF, tcf));
>>         isb();
>>
>> +       __mte_tag_storage_init();
>> +
>>         pr_info_once("MTE: enabled in %s mode at EL1\n", mode);
>>  }
>>
>> --
>> 2.36.1
>>
>> --
>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220607113150.55140-1-vincenzo.frascino%40arm.com.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b35a1a9a-9dfc-27f6-8e82-791414454b48%40arm.com.
