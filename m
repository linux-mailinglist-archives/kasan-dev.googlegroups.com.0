Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBWFCQCAAMGQEQHGNMIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 703512F5DE1
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 10:39:38 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id o23sf3054111pji.9
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 01:39:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610617177; cv=pass;
        d=google.com; s=arc-20160816;
        b=dL3+HPSSFZSTRTpO3+hvJYBWLZBo6fpdzuhNgyfJjduNcYVKTl1zW8X4teSeCovb5e
         wCudUzQ8epsVMFeTiU+gLY+4EYF+Kd/utXnTKuYNXsH8EhoI1L6adABIsncz0CjnqFqa
         MyE15JDIpTLEc2PHzYcHm7R4l2ixlWKrnvRLx8VkhG4sODIOZUsp37RmeHdCWtMicb+y
         E0QkfkR1LLQiRR2Q/0DwjnT/gYGVGTQ4Zy68c/PaPou63KWB5gYBaHiYUpm0KvYg1u8w
         SzvIsMFKeGZyiQXcsbQitjUsCDg9mw7f5iue5OInUMWeqe5uTquQcEUxgmxtXWJmBJ3C
         zf3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=yf3Cxp2KIF7UC6ePSgr1NeDiQHHc9x9LlRD0g6UZMLE=;
        b=Ts4YLtYG4iV21S11eivdWheQls5/X9S83xBpOV3+OkrO6sg4URA0/0I4yTlu5T3gnn
         X4iolGH8U7ufBLO0oDErUtZAtfe+ONWzGMdRZ5iOs+6tpiHJx1F+g1+Pswa0PrbXxpt2
         ebo1Bozpg/7j7WxAFh36f/M9ReEJgQF7LqBS6lNwtj+o76+qtWnRBYOdyJ9TxmJvz7BI
         6BoE6Izu61B4uIVetsNcSMflT6gH6/x6FrTazIk7IQ18Zcv/3DAuqgPFeQ/5u3l0dPbZ
         MKMAU0GgcCW1hkfv0Iv6XPjPH6b8SAHgNibBjEtDH+BaymWg/BVTb9zHYuVf9B+jy42V
         ae4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yf3Cxp2KIF7UC6ePSgr1NeDiQHHc9x9LlRD0g6UZMLE=;
        b=DYvXT09H5tvoN5qkZMnUnByrI4KXEzxej1TxOyPr6gVOWPzs3Kc63i1HlzaiWMXi/h
         sPywglS5ue4bNHebFHVmVA1ruqP+MYYrH3X7BFroD+kiGvuQDaE1+ZfjjTi217VeL+gS
         5qnx+3H/Y3V7H9tB5Y+Lt0YHSuc+IGFPbUvzuFJInBRLx+JCXmKQNO7UV8ciOAhrAN1U
         3aaHahjJNEQMDU3ykKixL8/87BMWXIWqkIXmb9T8RMG00GK+KPUPmvemCQGX2C16PRlr
         WIaeokgT4gHGhQP8W8NfUkaL0GDRpq+W2lOLfXpt2VvB5z8sMJTPNlrb7kNuI7J4U787
         tUNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yf3Cxp2KIF7UC6ePSgr1NeDiQHHc9x9LlRD0g6UZMLE=;
        b=O/JcZg0FWM9oSOYB65jV/Gk9V6eB1JtMoSZ2DFsndBjpyOoHagQUytXcxusBjDhBoW
         5lFotCK4nCjOmlolg5JD05yB0Qq4IDS1G1SBQpYICR41o++m2HEm0ZD9Wut2HGYpxLfv
         qluNiAC5CDEwNhA8uDEej6vF942YwyLx5L1yIy0f+EHZ0hpXGSTr4jFvNQKpoPCqp9YE
         cCgYpFaP8b0zux4ntSbhYM9HrxzPqBq+OwGSVl7Obdh00RyRfNlnrqLxMT/se/ogWogX
         xoHyB2H1GcQ2OMS17YSVjv8L+VU3Q/W833gUYiTwJJzZXH2K4ynPj1k81x1n8Z65tiGc
         jixw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531bBY/jzlLwGcw6TJc0Tc8lhvqONAclyJgy1eQNBRjwpi0I5nkg
	ljmQmRLYO8lh+QJ6A1wneJU=
X-Google-Smtp-Source: ABdhPJzaAtrIM6mCyXKRr2YiBjKnUNmFOwfDoskYvZ9FPJmD9lE+C52XgchKG/AXQagssDghvrYjMA==
X-Received: by 2002:aa7:8d98:0:b029:1a5:929c:1bb2 with SMTP id i24-20020aa78d980000b02901a5929c1bb2mr6735964pfr.4.1610617177026;
        Thu, 14 Jan 2021 01:39:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c205:: with SMTP id 5ls2536355pll.11.gmail; Thu, 14
 Jan 2021 01:39:36 -0800 (PST)
X-Received: by 2002:a17:90b:b0d:: with SMTP id bf13mr4157140pjb.194.1610617176508;
        Thu, 14 Jan 2021 01:39:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610617176; cv=none;
        d=google.com; s=arc-20160816;
        b=in4eMv+cKOLeVVA4IU6It2m0w6+cM2HuoFZUHumWXgIXxXE/nqZpt9UYw7HL7JNlEI
         W7s2jgD17C6mNAJLChpcl1uX8e2+Z/ixLveI4nFuf7kr1FDWUXBgxF5x19srqj26yxw1
         lz61seqVjBjIZSrVJtoQzcwAYtBFF/qPxPr/rZTvKP43YewTb33kscvh9+mc9fg9f37/
         kz+z9IVhi7DfejZNE3CKS1hlkzifpvxY3CGMjXSeJe0h4GiunNP2VGGnUQ02QgzNm8tF
         HRJiG9B39fs3WUsjo0aCIVjCYBoT1HXM2GHS6MvGNXl8qXbmomrO6cFeLi72gHe0ojY3
         hJow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=KCYpl/GGP0qqzDbj+a8SVaCBPh60H+SKXPCVyMhIn/E=;
        b=X9grms8tzmYWSTeCv0rpiohh9bNIcugZnG2JBSYDUchNJZ1VHYrDuN0WIUX2shwJre
         4z5q+5sJ0CLeaLZ1sNXdFkWXNG3CsLf8o6b257oHAJSW7hwcnOAdP6UMRNX8CnKEbZOi
         J/xY0EuuFOXQKqwlSjNRMH3V9UCwpxtGrnXrt+nx2HFsW27QIWm/YvzpT7YkkhIyDnuP
         bWhbAhxbB0LIlF7Z5ku6WBkzx8EmDJjlZ584sNF2rh9Cy0SS4F097VyU62JNnI3/4gHR
         E5mEfWbAaoSsx+bb6XDvSeO3kPhKTki8D6hhgN7mgbM1LF8xeB2TsFyRqxEMNA1JSC4h
         UFjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id nl3si437869pjb.0.2021.01.14.01.39.36
        for <kasan-dev@googlegroups.com>;
        Thu, 14 Jan 2021 01:39:36 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id AE12A1FB;
	Thu, 14 Jan 2021 01:39:35 -0800 (PST)
Received: from [10.0.0.31] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1EC303F70D;
	Thu, 14 Jan 2021 01:39:32 -0800 (PST)
Subject: Re: [PATCH v2 2/4] arm64: mte: Add asynchronous mode support
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210107172908.42686-1-vincenzo.frascino@arm.com>
 <20210107172908.42686-3-vincenzo.frascino@arm.com>
 <20210113172228.GE27045@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <16a57293-37fa-4526-e6cd-61f80b93e12a@arm.com>
Date: Thu, 14 Jan 2021 09:43:19 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210113172228.GE27045@gaia>
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



On 1/13/21 5:22 PM, Catalin Marinas wrote:
> On Thu, Jan 07, 2021 at 05:29:06PM +0000, Vincenzo Frascino wrote:
>> MTE provides an asynchronous mode for detecting tag exceptions. In
>> particular instead of triggering a fault the arm64 core updates a
>> register which is checked by the kernel at the first entry after the tag
>> exception has occurred.
> 
> Just rephrase the "tag exception" here as there's no exception taken.
> Also we don't check this only when the kernel is first entered after a
> tag check fault, as per patch 3.
>

Ok, I will clarify it in v3.

>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -153,8 +153,35 @@ void mte_init_tags(u64 max_tag)
>>  
>>  void mte_enable_kernel(enum kasan_arg_mode mode)
>>  {
>> -	/* Enable MTE Sync Mode for EL1. */
>> -	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
>> +	const char *m;
>> +
>> +	/* Preset parameter values based on the mode. */
>> +	switch (mode) {
>> +	case KASAN_ARG_MODE_OFF:
>> +		return;
>> +	case KASAN_ARG_MODE_LIGHT:
>> +		/* Enable MTE Async Mode for EL1. */
>> +		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_ASYNC);
>> +		m = "asynchronous";
>> +		break;
>> +	case KASAN_ARG_MODE_DEFAULT:
>> +	case KASAN_ARG_MODE_PROD:
>> +	case KASAN_ARG_MODE_FULL:
>> +		/* Enable MTE Sync Mode for EL1. */
>> +		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
>> +		m = "synchronous";
>> +		break;
>> +	default:
>> +		/*
>> +		 * kasan mode should be always set hence we should
>> +		 * not reach this condition.
>> +		 */
>> +		WARN_ON_ONCE(1);
>> +		return;
>> +	}
> 
> I guess the switch statement here will be re-written as we want kasan to
> drive the actual sync/async modes as it sees fit rather than MTE
> guessing what PROD/FULL/LIGHT means.
> 

Yes, this is correct, it will present only sync/async mode.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/16a57293-37fa-4526-e6cd-61f80b93e12a%40arm.com.
