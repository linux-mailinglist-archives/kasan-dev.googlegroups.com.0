Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB3VGT35AKGQE7OI44MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FC58254414
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 13:05:19 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id s185sf4397950qkf.13
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 04:05:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598526318; cv=pass;
        d=google.com; s=arc-20160816;
        b=CPI+jflQGgt6Dp1lk/CyN/Wp9jngz1/Pd+g+e4kEpLPGeJjzxE2pk8QjF2l4GXsLW7
         pDhYrg4TyY4Jf0vSt3yD3Lqw9sxkfcIu5173VbRslK0s+oa0db04ceKhXWSGRhHQThDP
         hN8T86Q6X8K4HpRXjiBbMYijnZIiPotRXpBP6+6m57qsY3RbckG/xGjX3KbmaEP/5YKt
         guSk0Zu/MPME+fRX8rqTahABR12J5eufoXdAa6sCpc3YlFiHYIZez2Wub6R/GdZP6aYG
         2i3xpJft7lglGY60AWOuElBYw9NIMhPAd4SSflDmJdUJKp33ZK9XwB2WMVH5o9t5Nv/P
         Me6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=3PhoncmVRO5TtmsZMwhlS25wbBjE5PJw7loZatUSWxc=;
        b=HvJYz6JOKN/DX9upjznvy+zbupzYfThTe6mtSUkQmIvyOjq5C5IxT8t9I3lMIq44ny
         JGJhCzbQfDiGD6YmaB92JA2NqzKQoP8vd+nAWqn9z7fLw4ilqicfV7sc7CSUYcLNl48P
         +7WNOECFvjg/hX4Pg1z5yfLVbw1bneocmNAVUb/x3lT1d1BfAHBXbvr9bFcnXL3SS5Io
         zWCYXtDtyxVDdjkRAEUUzcJJCa4PnGjSuDfWikNZTcWFot0DTRrAbhG5zsuS+Jq7i9Tt
         og/00dNMPJzGsMBRwPFXBir7rHf0u1wznwXnOPxgCBWPVBkfnRo9gjIoP6c27Mf3pipb
         MV8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3PhoncmVRO5TtmsZMwhlS25wbBjE5PJw7loZatUSWxc=;
        b=riXi74loktzeftaim1S1vpbqjI9DmtIHLHzZoo0H6kbJrH9p2MLIy+RYBoZNdxsKka
         y5TwPs9ZPlCBkrhg83FiauunbxwWtqJv94M/o0FOMB2qjGjbWIh51M+vAxzyl3KDcgiB
         CzfnKHOIf6nhGOpNudEDw3b4z8SraoV4xaCIUdRx3FLZTE9gbAXmJ68tWVTsjwJT5NoJ
         NEoEpcWyx4jDn65zU4Wf7tZWaSa7H6rWXLXeTjPNifM4C8vdFPuuZ8GuojM2HjSttQND
         EoekF0QDfh4nyXek7B6DB0jHMWhlZGPwAe7SBh2JA9bzt6ZvyIH8F7hYh3D3YtnEsK1j
         NmoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3PhoncmVRO5TtmsZMwhlS25wbBjE5PJw7loZatUSWxc=;
        b=WFkhlGt/tT6ojs1R3f817VlG9+MfNOpLFtJ4dCUvwomCx67pKL938dlKauLF7rYRGT
         v9p9LyfbIwqy/QqUqHHu6eH2xyu7AiXgMaD33n+aMBZhEVCVBe11XC1966NTA3IKmq6M
         q75r4M0du6jR5twShHWKan+1zJNJIX4xNhKUpVOUt7vV4ICJrLuAkifnuaAZKS/fdx0r
         q6X5AOHbFG6y9aIVw/WOTZ37303a84GS3TaSoPzFIfvoK170s4IWfhnrwiKIBzniePei
         Q7WG3CRhpdKUt6JZLitTAObyhK5n9eyk/DbzEPc3tvr0Sz5wOjqU3KxMhyhFvK5g7Dyv
         8rBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531yRrBs/PeMqfcEF3p/LVlyNhn5XDygKhGktN7aswDrfbpQbKCK
	xHpvjXs6A7+AdL6V8JxHqSQ=
X-Google-Smtp-Source: ABdhPJx7xC8EvUeuE1J0ZK2LX82ACC+C4ycVqdvW2YyynlzgN7VRIQDKBj0W4lvxDKckCuGLhgMjAA==
X-Received: by 2002:aed:2212:: with SMTP id n18mr203936qtc.346.1598526318569;
        Thu, 27 Aug 2020 04:05:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4b6b:: with SMTP id g11ls743305qts.2.gmail; Thu, 27 Aug
 2020 04:05:18 -0700 (PDT)
X-Received: by 2002:ac8:73c4:: with SMTP id v4mr10546999qtp.116.1598526318199;
        Thu, 27 Aug 2020 04:05:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598526318; cv=none;
        d=google.com; s=arc-20160816;
        b=N/sx3ckv0uf371FTuGJAlPb17M0DboIjH70QLO/oDkw9R93/vog9ztBattw6RSkuAG
         JX1IoQR2559LUVM4d9CWA2qIfbJ2wtYWjHjs/mUGbIFyfxuEgaAgqRhdfyR9DKunKVf0
         C6aqotrYRmsC2NawU6S3xnJ+6MKaiSPGmTnAo2t7C2Q1zOtaAoC+4wqAzN25GxAWL2HA
         uOsLPgkGPr7t5+lFH7lW1ETMRv/rR/jDI+Oj4Yh3t5biCALfAPlXl9h7gdbnCytc4564
         xlPlSaMvlf8t2zeUYM85nr627iACWHCFbEsfaWBRYngS9a99odhhKszWHSkJYn7X4n0z
         zrAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=5x6WygjzVFR38bLOwg9zKNoVYCnfnBSN9zE9UfZZxww=;
        b=crXSxcMQBmDnAI5SfXXlTjMIhv2y2CTEDWv2NCL68Rjm7dsILwtQMLrWpA53d4iMbH
         IYsni5ji2Fn9yi2fKcw98SJLF1Ds8LwWKlt20Ahl8C+35JadRJi89rJ7qG8ihyfj+LAm
         kDCd5Z6k2eXn3EcHwFdbAMRT+PVFq2Z11xMoFzLxvhaW3EPPuOGMLO7wuJZqiJaTYLhU
         Q0HGwgAeVH/u6/o97beL0/2hdrGut+Un6sSWpRU/AkS64uSqUEcDt6mPSSqOZ9ifKKfS
         qub0nVoKGWy3eEfwbCv3xH0hhubnNK1gFxdTOByPupu/4LHQfJZy0YyUc7EBWdBj3YY7
         fE/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b21si80654qtq.1.2020.08.27.04.05.18
        for <kasan-dev@googlegroups.com>;
        Thu, 27 Aug 2020 04:05:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 57705106F;
	Thu, 27 Aug 2020 04:05:17 -0700 (PDT)
Received: from [192.168.1.190] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 373753F68F;
	Thu, 27 Aug 2020 04:05:15 -0700 (PDT)
Subject: Re: [PATCH 28/35] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
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
 <07455abaab13824579c1b8e50cc038cf8a0f3369.1597425745.git.andreyknvl@google.com>
 <20200827104147.GG29264@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <c0319233-8985-8cc7-ea72-910b42b2b5d0@arm.com>
Date: Thu, 27 Aug 2020 12:07:28 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200827104147.GG29264@gaia>
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



On 8/27/20 11:41 AM, Catalin Marinas wrote:
> On Fri, Aug 14, 2020 at 07:27:10PM +0200, Andrey Konovalov wrote:
>> Hardware tag-based KASAN has granules of MTE_GRANULE_SIZE. Define
>> KASAN_GRANULE_SIZE to MTE_GRANULE_SIZE for CONFIG_KASAN_HW_TAGS.
>>
>> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>> ---
>>  mm/kasan/kasan.h | 6 ++++++
>>  1 file changed, 6 insertions(+)
>>
>> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
>> index 1d3c7c6ce771..4d8e229f8e01 100644
>> --- a/mm/kasan/kasan.h
>> +++ b/mm/kasan/kasan.h
>> @@ -5,7 +5,13 @@
>>  #include <linux/kasan.h>
>>  #include <linux/stackdepot.h>
>>  
>> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>>  #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
>> +#else
>> +#include <asm/mte.h>
> 
> You could only include the new asm/mte-def.h file (currently mte_asm.h).
>

Agreed, we should only include asm/mte-def.h here since after the suggested
modification will be sufficient for the purpose.

>> +#define KASAN_GRANULE_SIZE	(MTE_GRANULE_SIZE)
>> +#endif
>> +
>>  #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
>>  
>>  #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
>> -- 
>> 2.28.0.220.ged08abb693-goog
>>
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c0319233-8985-8cc7-ea72-910b42b2b5d0%40arm.com.
