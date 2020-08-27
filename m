Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB6GET35AKGQETHGUHHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D0152544C6
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 14:09:30 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id gj13sf3728142pjb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 05:09:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598530169; cv=pass;
        d=google.com; s=arc-20160816;
        b=I/RcIOTuVeyrmiXKUhqGsSXi9yzWobcQSL20jdBsx73DIwikOOj/Lp11SJEqanuLnz
         /K+tzut+F1o7RIKHlvIcZeHPgpWsRgJKgBhaEn5Z4JcicnJij3TX+Q48bnn0PCvJnmjS
         9raHeoi3ofGCRC/iwler1434F2olRxuReG0tzMFEX2+fIXdxTaR7vz6W6vSkS+Vepd+9
         oovx9GtJomab7G0s/v6gle2iplEqeQ2L3Y6vyOT/AW8ujZXNcIKBEF5oMKTEmjC1k+uY
         2LSs1j/b8zIy8qRSqTlE7zfy2Zxyu+oP7S3GjraDm65dwQ8wmKKcytNSg52mVrzxcYXP
         rxEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=JBEML8oJIqMXYZTO40+nhsGo7/ExrjrFfdznHdvjF4E=;
        b=kpnGAx5fe5gOQroz3D+7OCqtWa0aGdLpns6yMi9+mHzcWM50TfFK6Rf4TRGGVvkPxJ
         lzEyBw5MKsVpHUQ3AUdoAsyCSAnYH/ggsK1uqeMppxbdwz5mSx+CJmq7VNd8mDwcN+or
         S4gv9c3bKvJ0Qp3bAUFiaVtb4eZk3OCIPj3qjyYlsFbXwIsFM3BADtOhKHo/YYSG/rTe
         cy/jW5y2pEgeeXchfM18SsRoi050CkljHbnUJIFHrlAD3ogTDx4ZKyQSlb0OssY+27gp
         tnXz8FoYvKs5MRk6nlMSJ0rLZzF3Xm5kHIIzZ5mYgVBNmX8sRn7yv1m0tuez9JqZmYAe
         KbLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JBEML8oJIqMXYZTO40+nhsGo7/ExrjrFfdznHdvjF4E=;
        b=kSHQEN1/f8BhOgBj1/ae9ZoYN4FaFor4++p6iMwIyC6yfTg1zdxDQfBfHGv0m+WKjW
         NoqKE25yMAONA3mp6vYd7Sp0DH0uavZkXkqh10MIco4C+DP4IP49Z9O3LqhbP7N/l/As
         wJDWiOYFq3tgV1Va0a+dokR8SwM0EcrobZ+jXtI6CsemUzDBs8g4PWm2+pJcDZQYzKl9
         mFSX4E1VGYhXhj+9IFH1oBGRwaSS8BKdv+rN2Z+ZSkF9I7tvlJcRVfCkexOrlc9Y531b
         CAiMANMpOYLSCkCazmTCY5Lp785a9O4u5kd9oK+h/ZbP8aUc9k2xp4yJmoqJ88YfNKZQ
         UUcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=JBEML8oJIqMXYZTO40+nhsGo7/ExrjrFfdznHdvjF4E=;
        b=Q21ZWw8yFzJ4UiEsLOdgBy64t0N5heZpWN08zoOsuGNvxyxx7mlKx7dckzyvqLgItr
         /RCoFa4sNkDXmOMRe/AUDSO0oPMc56OO68K8rP8cE1/qMbsxUFH7FtrKPEfdfnp5Vyl9
         aca0JeuPReeSLH6LfbsFt3WZHf/T7ggqOdvn+Y33CvZCptxaZNzRyJIshnwoZidsA3/1
         cyCsPmsY+Q0+XP0LYjVjQTaFgmbiuBgg9lPjJklnKQZlexzhpgVOqlGKAzxByouWnDQ9
         ImHYdoxapSArNZH0h5XBZYDo7zaYW6aFIht120VJMIczKPea2L91F1xfW2BBIC12PaUS
         fghQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5332Rzjc2Lf3MQEbZ/hnbUKnHZlT44w2VQe4C/zvtwkF+j4iDR4U
	MUO4YVtyyTLkp3UmCCzn5YE=
X-Google-Smtp-Source: ABdhPJyk+i1grqqehwrt938rSSMWfuv7mv/ZCqFHkPWTrZXQxpv407oc93ScRqF2jXSO2auMYUMaWQ==
X-Received: by 2002:a17:90b:4383:: with SMTP id in3mr10159622pjb.73.1598530168926;
        Thu, 27 Aug 2020 05:09:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7596:: with SMTP id j22ls1135974pll.8.gmail; Thu, 27
 Aug 2020 05:09:28 -0700 (PDT)
X-Received: by 2002:a17:90b:148b:: with SMTP id js11mr10346837pjb.62.1598530168431;
        Thu, 27 Aug 2020 05:09:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598530168; cv=none;
        d=google.com; s=arc-20160816;
        b=vfFXwl0bi99eWdtKAAtyEkwYSN6AcIkFYUCndblaXLxkHq1Hes+bwiqFygbEBoroh+
         gsCbpLYWawOIV5bQUA+P2HjX+VWPyrGCIcrk/f71iRmc6UGy88v4++XFLdHJhTUwj+X9
         a9v+pbupaM3WFXCU4KqOJLZqAvsA22C/rrEuk1gEWer31pKEnNMY/fpIr6guY5+2tQav
         6oYARtyScNBxWJaSqBAwqQ1STdUtUO4aRcFYIQ3kd5K6twyI5P2HlZGWEWzS/Pz7sURa
         EGL21/InZJ37cFD9s9H+aRmdNPX/tIIeGCg0/JAP3nzMX8LlYpE8/tdzgAn1MH2mDT8o
         1iXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Jpvn056t3PRgdg+aLfW/jwQ9su3cN9adz63/ed0vBls=;
        b=ZiMbC8rpT+0x8LXKu00azHEVccgG8rsKghd0hNUR8Bc9ekFCIPKfpTOFkDMiFeDBIG
         ifR2QUL/Njt3eyldM861Ivg2M+YJgcRWiBkLUp0bOs+R0aAkhk0Tp0KtBKX/UPhS16hL
         w42/D36wg0vNjYJs8oWRjP8M5eXI7uLIGS1zUue7eFQpisFktW03rrLQnv016aJvYUnJ
         qY1WZYQuM+5M8rOg60fHL/mzZ9XFLxF35cwgNGH3QGycW/zODgfiAoEJCiBjPHafbY0D
         XqosCZ9Xp72vaI9lZMmejKISx+aRih64/px0nfmd+UPJSAQ94n12RPYxZKNjJ+2ZX2bj
         7lLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id kx12si330379pjb.0.2020.08.27.05.09.28
        for <kasan-dev@googlegroups.com>;
        Thu, 27 Aug 2020 05:09:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B53F131B;
	Thu, 27 Aug 2020 05:09:27 -0700 (PDT)
Received: from [192.168.1.190] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A751E3F68F;
	Thu, 27 Aug 2020 05:09:24 -0700 (PDT)
Subject: Re: [PATCH 32/35] kasan, arm64: print report from tag fault handler
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
 <4691d6019ef00c11007787f5190841b47ba576c4.1597425745.git.andreyknvl@google.com>
 <20200827104816.GI29264@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <37de7524-b042-831f-6e43-30adf85c83a8@arm.com>
Date: Thu, 27 Aug 2020 13:11:37 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200827104816.GI29264@gaia>
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



On 8/27/20 11:48 AM, Catalin Marinas wrote:
> On Fri, Aug 14, 2020 at 07:27:14PM +0200, Andrey Konovalov wrote:
>> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
>> index c62c8ba85c0e..cf00b3942564 100644
>> --- a/arch/arm64/mm/fault.c
>> +++ b/arch/arm64/mm/fault.c
>> @@ -14,6 +14,7 @@
>>  #include <linux/mm.h>
>>  #include <linux/hardirq.h>
>>  #include <linux/init.h>
>> +#include <linux/kasan.h>
>>  #include <linux/kprobes.h>
>>  #include <linux/uaccess.h>
>>  #include <linux/page-flags.h>
>> @@ -314,11 +315,19 @@ static void report_tag_fault(unsigned long addr, unsigned int esr,
>>  {
>>  	bool is_write = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
>>  
>> +#ifdef CONFIG_KASAN_HW_TAGS
>> +	/*
>> +	 * SAS bits aren't set for all faults reported in EL1, so we can't
>> +	 * find out access size.
>> +	 */
>> +	kasan_report(addr, 0, is_write, regs->pc);
>> +#else
>>  	pr_alert("Memory Tagging Extension Fault in %pS\n", (void *)regs->pc);
>>  	pr_alert("  %s at address %lx\n", is_write ? "Write" : "Read", addr);
>>  	pr_alert("  Pointer tag: [%02x], memory tag: [%02x]\n",
>>  			mte_get_ptr_tag(addr),
>>  			mte_get_mem_tag((void *)addr));
>> +#endif
>>  }
> 
> More dead code. So what's the point of keeping the pr_alert() introduced
> earlier? CONFIG_KASAN_HW_TAGS is always on for in-kernel MTE. If MTE is
> disabled, this function isn't called anyway.
> 

I agree we should remove them (togheter with '#ifdef CONFIG_KASAN_HW_TAGS') or
integrate them with the kasan code if still meaningful.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/37de7524-b042-831f-6e43-30adf85c83a8%40arm.com.
