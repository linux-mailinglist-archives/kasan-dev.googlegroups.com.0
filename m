Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBF7CRX5QKGQERBEINGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id CD29526DE0E
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 16:22:16 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id q11sf1692306ilt.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 07:22:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600352535; cv=pass;
        d=google.com; s=arc-20160816;
        b=uXUna19dHWKe35Bu2F/+gxJe2Z1MUulJW/33roN6vy93p4ACtoqkzBeLAhbXnoYFha
         YJb27K5coiSAdo7bIPgzeZRjQSG7JGdjnCxghOJMul50XeAniTFh/QrDWTk0nxVVyqUS
         laLoAwd/+rZ8VBDY+xRl5GjT3nM5mnbxuvKlsxdBwRSfuWBjuXLrvI0BCdyjlfw5Mx2s
         Y5zCF5WDVP4yazp4Lokvr34p+EGFpJGL5iLMv4RNp3Hrhgd8Jj829/mC++99BiJ04mB/
         Wph3Qm1GIajYnveIXPfBWJr5L3YfA/MZhY1DV2O/2ivj6J7+jlNZbi8umumFvi18OOso
         JCFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=dLtzlMte/KVZxfFOimIIx7ygqR4YzzHbyiBWsCvZvKw=;
        b=ZAlOxIFQjPIMJDyY8oNTgbXA7vEzUqHYU+wEOtFhNHn9J7F1BP2iQQpUkjjwraGEex
         R1mqecwardr1cyVg6F2L/uHErNVUzIt7Z9Jm21R+v79HkLKgUeGGgJ7ov6PYw2mn08E+
         zBPMFrUNALU9If+hD9qVaL5qy19PlWKNF4/TbedgP3s+S9onCPuSbHAfQpp7L+QqV8x5
         pjivF/o3Uws679sInmQMJAc4AOWCXCb2wIKmKFJ+n9R5za678zdKaG5Z61Z8sy+uRnLU
         RD9z57jVMeDou9RGtaKOu7glh0achQbGEHrVQ4G7e5eISfKoUaM0zPlc9XZMIE39iXcW
         WkMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dLtzlMte/KVZxfFOimIIx7ygqR4YzzHbyiBWsCvZvKw=;
        b=HS/Md0Gj5TgKQUffunoAtrwnjH3bSunOhsPHXhqO+s0P2poCmJ0vGizUAqYUf/nZ8g
         SQl9w61sZnrL8F++1ZG1Q1HcPmRzrp7OpVO/101Vdk+0QgT03B0ZtIzQtXhC7UEg75kP
         YpD08pPLFabznPDoJ96nGZ0wrpbD0ceLIx8oCrfZYA8Vsq7fGr8mi9DATknlWb3/ANeA
         0HwiZh4tRW972U1VytIAiZDJlQAzmBvGEfLKKYJ0/djk2dJfDC15XkY+d++4yJIyFMhu
         ti1InBEV7BJDRR1Y+mapoOTWowAT4Faz2UbFMvNIozgVsIsJGJ1sal6zx1XEzShzSut3
         Zqsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dLtzlMte/KVZxfFOimIIx7ygqR4YzzHbyiBWsCvZvKw=;
        b=a1KP9XP+ZdBkX6rcxcRcTB23PLUUcuG5s1jx5Zcl9yQsZYotjMhW4eAMGnD2dsHgap
         urs8ePfIganV2ydkFyUyy1JMXX2R/rzKHAL+pzwD8QitHf77lVkAJTh7+/rhssSwYWGQ
         nEmXuJq1Js5W1tuyQWfdWpwhB0FfGfokZXqYqardNOwuAyIJEOI8cVWCw12zTDgG0PQI
         ULMb+IMpbHOU1e+gWEp9COYD3WcTcFAztQKxJANTx4Pj4PtuoBOegO4hwNgkQaVStG2n
         /4l3lYUw3KXk6ryfcD07ajZmvcMNefsHUYLZ6d9otdL+js+p699hm3YbEHX9WdpXIs69
         arAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531viYS592QDQFgPVbo0aWIqb1Px6wCTy5e2xSwuFy2TRHNvj+EL
	xeBEV0zqayC9/QBmXS58cf4=
X-Google-Smtp-Source: ABdhPJxoRVs0Nj1+XJTPata1rChFJRe7YyXL8M3NQF1Od1SFGu5oIvCXv/bwDqhO/lH6/w3DWhu0UA==
X-Received: by 2002:a92:3209:: with SMTP id z9mr23737058ile.126.1600352535394;
        Thu, 17 Sep 2020 07:22:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7312:: with SMTP id o18ls653369ilc.2.gmail; Thu, 17 Sep
 2020 07:22:14 -0700 (PDT)
X-Received: by 2002:a92:2410:: with SMTP id k16mr4126521ilk.153.1600352534633;
        Thu, 17 Sep 2020 07:22:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600352534; cv=none;
        d=google.com; s=arc-20160816;
        b=lNm2jR8yIqMZnADTWtBpOMXMHzALhrV8Zt1o8bRtMRB2hgwlClwsrN0PO2kmoub3vE
         9I2TAT11qdnrjw6vGumqEBuC4fydTls03Cg/cNt+eEUtZLv6YEvdxNO3wfq/nlI2cLs9
         6f1MNMSJJjcTu0e03i4NpfIIZYA6nzLePj8Xow/4EMnpSn/3VNB1BLFXQGu0x0LpiDjR
         rLQuJKN3/AwXNJiXj0CKXnpx0H+ChUMKChb4p6EpQji3A4xB7+wG/VS0aE5TZICFUpYN
         70HifUBxN8+fN39TdkHDUQ8xfoUta2noJjKFtelqaXL8KTEz0ZIOhkgeIs3r7W3rpghJ
         OdGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=HpiAYCkRtUxkH37pMKIv8CJcZTJPoRlRNZCsIaam7U8=;
        b=hSMej1B+B3oZ3zKKAvNmWkEL+UVpEZD8H8QotnUzAlgL6iFz3nylqygT3xFQajDZWp
         LSrFbJTPO6NQES5KKVHR6JBiwThHGMVvpVLFhU+wKgQ/ekCOXgr0ei4c2wZ6ZV1XImT9
         stlm1j1kWclmpJugzSUyj1rAXXaKwizAGMCAqQ5tQ0Gvvq12EHAqbCF3ibQiwxs8cmYG
         b8OdHHOtl6BnBlc2omgI4HqyxwqmEr/DLcCN/BJKTCSNDz17SDiltZVlCEB379C7i+33
         c5DZ4JmU8KQ17H+KVWMyoMrTseGTw27EyS6CgTxZnsJWSdVBEyWoIw82pamwTEA6CG57
         gE2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z85si1294743ilk.1.2020.09.17.07.22.14
        for <kasan-dev@googlegroups.com>;
        Thu, 17 Sep 2020 07:22:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 29BCF12FC;
	Thu, 17 Sep 2020 07:22:14 -0700 (PDT)
Received: from [192.168.1.190] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 18E6F3F718;
	Thu, 17 Sep 2020 07:22:11 -0700 (PDT)
Subject: Re: [PATCH v2 24/37] arm64: mte: Add in-kernel tag fault handler
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
 <7866d9e6f11f12f1bad42c895bf4947addba71c2.1600204505.git.andreyknvl@google.com>
 <20200917140337.GC10662@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <48ef25ff-0d06-54d9-b467-ff068465e3dc@arm.com>
Date: Thu, 17 Sep 2020 15:24:39 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200917140337.GC10662@gaia>
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

On 9/17/20 3:03 PM, Catalin Marinas wrote:
> On Tue, Sep 15, 2020 at 11:16:06PM +0200, Andrey Konovalov wrote:
>> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
>> index a3bd189602df..cdc23662691c 100644
>> --- a/arch/arm64/mm/fault.c
>> +++ b/arch/arm64/mm/fault.c
>> @@ -294,6 +295,18 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
>>  	do_exit(SIGKILL);
>>  }
>>  
>> +static void report_tag_fault(unsigned long addr, unsigned int esr,
>> +			     struct pt_regs *regs)
>> +{
>> +	bool is_write = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
>> +
>> +	pr_alert("Memory Tagging Extension Fault in %pS\n", (void *)regs->pc);
>> +	pr_alert("  %s at address %lx\n", is_write ? "Write" : "Read", addr);
>> +	pr_alert("  Pointer tag: [%02x], memory tag: [%02x]\n",
>> +			mte_get_ptr_tag(addr),
>> +			mte_get_mem_tag((void *)addr));
>> +}
>> +
>>  static void __do_kernel_fault(unsigned long addr, unsigned int esr,
>>  			      struct pt_regs *regs)
>>  {
>> @@ -641,10 +654,31 @@ static int do_sea(unsigned long addr, unsigned int esr, struct pt_regs *regs)
>>  	return 0;
>>  }
>>  
>> +static void do_tag_recovery(unsigned long addr, unsigned int esr,
>> +			   struct pt_regs *regs)
>> +{
>> +	report_tag_fault(addr, esr, regs);
> 
> I'd only report this once since we expect it to be disabled lazily on
> the other CPUs (i.e. just use a "static bool reported" to keep track).
>

Ok, I will fix it in the next version.

>> +
>> +	/*
>> +	 * Disable Memory Tagging Extension Tag Checking on the local CPU
> 
> Too verbose, just say MTE tag checking, people reading this code should
> have learnt already what MTE stands for ;).
> 

All right, will change it ;)

>> +	 * for the current EL.
>> +	 * It will be done lazily on the other CPUs when they will hit a
>> +	 * tag fault.
>> +	 */
>> +	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_NONE);
>> +	isb();
>> +}
>> +
>> +
>>  static int do_tag_check_fault(unsigned long addr, unsigned int esr,
>>  			      struct pt_regs *regs)
>>  {
>> -	do_bad_area(addr, esr, regs);
>> +	/* The tag check fault (TCF) is per TTBR */
>> +	if (is_ttbr0_addr(addr))
>> +		do_bad_area(addr, esr, regs);
>> +	else
>> +		do_tag_recovery(addr, esr, regs);
> 
> This part looks fine now.
> 

Ok, thanks.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/48ef25ff-0d06-54d9-b467-ff068465e3dc%40arm.com.
