Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBKU4T35AKGQEI6B333Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id 771972543F3
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 12:42:51 +0200 (CEST)
Received: by mail-ua1-x939.google.com with SMTP id z13sf861487uaq.21
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 03:42:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598524970; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dl6NH2TgIlDFiPE4hqAA/S3v2qnnLiRuLmk5jct0EkCFniD/no5p+VFPqulyK2iJ3V
         D5Yqp5RG7dfMYlHAB4yftCXRBwEJ91KIgcxp9FGL5gJt6oEuWvMxfLiKNhHZHpBbjQHg
         a1bU0JT0EtvGxYsVuuJP+vBooKTu5vCUsWj6b5lKi5RW1VlcW8hFyAtsmSF9+9vZfIJn
         9RoH4kMDOgu4nBl0T8MLlyNixFPCnXp/7gpvDv7PboOdPQUVEmZ2aooNlpts3ZFyf+Nq
         OpT0ybkL4Q1AM1OIhcSDAk1837QhEqaALMGBSYw/TsGL5M8D4v4NEfCzDbv38IZ5xmwT
         QnTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=u8T2WDoOlEOdYrXd6fb+xT3nobZl+kxHjLRcTSSuu0g=;
        b=ee3xqt06aC/57ChcSNDG4UwRzLHwte5FcP40E6b/cHxiA33ZUjzv2pQGvUN/Rc5nqM
         a2KT93uj/C1JPR9ryBJf4CIy2qplPPEViAe3tENm55YRy/KLgmNNzNa0tCaGr5LbsBvy
         Ofwz0uxo6dlG2Eznh5VyYTcLazaTbcWaNwGsr9GekFVK+d3b1X5GP03jpoQW8qKziVes
         6XpD/H4kYXgphKaMWIKmGjT7hz59/hus2gJyLAXN6XO2yhrLI2C451Zsq2KvQjmZgHmD
         2BJZvokSDkbmtWf0Wlmq8YYIyS/2WAojlQ5T+zx+4g+Fs/fjug1aYRECQ49ZqnAFJgQK
         fdWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=u8T2WDoOlEOdYrXd6fb+xT3nobZl+kxHjLRcTSSuu0g=;
        b=nNMsT7KBM/RDvg6V/9uYVkZYVz/v0WdVVXPRB5KIJkE0OZJQVeFGmaC6eya7GDcERM
         Vqr/hY+FDto75iee0W8aE1WVwniV1/HmHcbIW+GZryJKdkFbPQUGHiDWBP2LY3xHjyWo
         MECg1TZVVH0Dfyb0LqqLf6s9oo7StF8mRf4trMLKLt3ow48b+twyZtmTvUrs25/2S3EH
         vVdGkKl5ImyuIQOYxm/QmWbK/i/S57Kg2M0bixPNcJoHpqQWDbIS19jCCzxdUhGt57sY
         F8D1QXl//oZlkfQOmqg0uzjNkuUxicYKKZvMi/WGd7nSb6aaXLCbl+4hq8Mz4oxlryDf
         pjJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=u8T2WDoOlEOdYrXd6fb+xT3nobZl+kxHjLRcTSSuu0g=;
        b=mk98ctDZgcFnF58/gGbwaZk4+VUYFqU92yDba4PnQLAd220HgGjMfEOLrlMFg+gwpo
         twdlJmsjYw24Q0TbLRMwfFOVhm9WRWTmP8sBCP/cKk48EAUaj97thK5LkyBMUzqbTAHo
         wqsAnmf1NQ+FIzGdBVon8YOOigUN1glQbAnbcbtcgHA0v8Smi1vIi5AJE6Gwe/YGuCQQ
         AMFpSqt4FMmrYXJw7PFlEFL3gZZNIEAIHQvXWyNETZUpaqUk5go05i1qNpkBJ9djRt7G
         r9EIuvvpK2qzHahP3YWVTh6CnIL5ELuvrVvE6rMzL9Fa9SFgf56b1Ypsmnmdh02Ziac6
         7SfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5300OiD8xrFJJ6oZ81MGCL7eIxDD0nMR8ztmDgWmgtkWjZQWdKVw
	ZDq9IJT9JxW2uKBmvdSfJ9w=
X-Google-Smtp-Source: ABdhPJwMQ8M6tLMORBJ4nIaMRNi8gnrsYrUjOdXEF92KwspMVd+Xb6iXmorvZSvtmDPTQKQiIRU2kg==
X-Received: by 2002:ab0:65c6:: with SMTP id n6mr6990174uaq.57.1598524970529;
        Thu, 27 Aug 2020 03:42:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d817:: with SMTP id e23ls203383vsj.11.gmail; Thu, 27 Aug
 2020 03:42:50 -0700 (PDT)
X-Received: by 2002:a67:f983:: with SMTP id b3mr3869760vsq.20.1598524970169;
        Thu, 27 Aug 2020 03:42:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598524970; cv=none;
        d=google.com; s=arc-20160816;
        b=MJL+OP9u1Eqmur+hnsl4NkWi2bQrHPpHEBipctVcbpRWmqUaNoymmYKthyTR05b4z6
         6D6ppm2H4lK8d71QoIrtE+kHGeUi+/gWoVP4kWtalC8c3IcSi6o+lLLg7LLC2skAH5Dp
         5JHeleFyl3UFaIzEJHVfeRDsfsPv8e9d0FyOkpTipNl/17RdrFSooYvxR9t47mjgFkYu
         hALO5S7Z4TyxUInEDdThMjE09NnM0dHEcm9AT/kuuwVIBFnogoYfa8/luPFCBcmGo5YT
         TqLzPi+miInCi4Par2YHb0ADxJUZLQytGSjIlYHKIPVJfH97QUuuKHDlbRaEKz1S1ZPT
         wJ3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=65nW4OgXjg/gayn4pYv5jGrcIrH3Et8tOSI0rX3E+sk=;
        b=zqVk2M++KV/pGR5stWJxA5XSyp3J2TMtgb/mnxFu4jx200xrOXTabnOZEcPheHrc7A
         9jFKJ6fVSfGXewsvDZFU6CobsNph7ib1LG9tFyc4PZD+ZWM1YWzZf6fVXSNGc1mPnrkj
         JOgMZ4H4ffPefqXVyQTAna+HgCyJLxbqAm0lxBSMBs5imRDY7Bes8j74+O1n0No3tXLC
         SKEcixe7ogLE8m1t+zn/odcL7yOi08wdTFnIIDtswrjvyZxkCytbCcFF2qcMQPS/fFTZ
         lyWXR3q2oc3sWpCDHbXER7WuukO7EgRnEg+H3FQlgT8v+dNkJwIsyW6bxA4ezXF58vR8
         wd4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id x20si65654vko.5.2020.08.27.03.42.49
        for <kasan-dev@googlegroups.com>;
        Thu, 27 Aug 2020 03:42:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 611E8101E;
	Thu, 27 Aug 2020 03:42:49 -0700 (PDT)
Received: from [192.168.1.190] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0285D3F66B;
	Thu, 27 Aug 2020 03:42:45 -0700 (PDT)
Subject: Re: [PATCH 21/35] arm64: mte: Add in-kernel tag fault handler
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
 <f173aacd755e4644485c551198549ac52d1eb650.1597425745.git.andreyknvl@google.com>
 <20200827095429.GC29264@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <b5c519b8-fbec-46ac-7c72-43864175748e@arm.com>
Date: Thu, 27 Aug 2020 11:44:58 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200827095429.GC29264@gaia>
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


On 8/27/20 10:54 AM, Catalin Marinas wrote:
> On Fri, Aug 14, 2020 at 07:27:03PM +0200, Andrey Konovalov wrote:
>> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
>> index 5e832b3387f1..c62c8ba85c0e 100644
>> --- a/arch/arm64/mm/fault.c
>> +++ b/arch/arm64/mm/fault.c
>> @@ -33,6 +33,7 @@
>>  #include <asm/debug-monitors.h>
>>  #include <asm/esr.h>
>>  #include <asm/kprobes.h>
>> +#include <asm/mte.h>
>>  #include <asm/processor.h>
>>  #include <asm/sysreg.h>
>>  #include <asm/system_misc.h>
>> @@ -222,6 +223,20 @@ int ptep_set_access_flags(struct vm_area_struct *vma,
>>  	return 1;
>>  }
>>  
>> +static bool is_el1_mte_sync_tag_check_fault(unsigned int esr)
>> +{
>> +	unsigned int ec = ESR_ELx_EC(esr);
>> +	unsigned int fsc = esr & ESR_ELx_FSC;
>> +
>> +	if (ec != ESR_ELx_EC_DABT_CUR)
>> +		return false;
>> +
>> +	if (fsc == ESR_ELx_FSC_MTE)
>> +		return true;
>> +
>> +	return false;
>> +}
>> +
>>  static bool is_el1_instruction_abort(unsigned int esr)
>>  {
>>  	return ESR_ELx_EC(esr) == ESR_ELx_EC_IABT_CUR;
>> @@ -294,6 +309,18 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
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
>> @@ -317,12 +344,16 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
>>  			msg = "execute from non-executable memory";
>>  		else
>>  			msg = "read from unreadable memory";
>> +	} else if (is_el1_mte_sync_tag_check_fault(esr)) {
>> +		report_tag_fault(addr, esr, regs);
>> +		msg = "memory tagging extension fault";
> 
> IIUC, that's dead code. See my comment below on do_tag_check_fault().
>

That's correct. This was useful with "panic_on_mte_fault" kernel command line
parameter. Since it has now been replaced by a similar kasan feature, this code
can be safely removed.

>>  	} else if (addr < PAGE_SIZE) {
>>  		msg = "NULL pointer dereference";
>>  	} else {
>>  		msg = "paging request";
>>  	}
>>  
>> +
> 
> Unnecessary empty line.
> 

Agree.

>>  	die_kernel_fault(msg, addr, esr, regs);
>>  }
>>  
>> @@ -658,10 +689,27 @@ static int do_sea(unsigned long addr, unsigned int esr, struct pt_regs *regs)
>>  	return 0;
>>  }
>>  
>> +static int do_tag_recovery(unsigned long addr, unsigned int esr,
>> +			   struct pt_regs *regs)
>> +{
>> +	report_tag_fault(addr, esr, regs);
>> +
>> +	/* Skip over the faulting instruction and continue: */
>> +	arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);
> 
> Ooooh, do we expect the kernel to still behave correctly after this? I
> thought the recovery means disabling tag checking altogether and
> restarting the instruction rather than skipping over it. We only skip if
> we emulated it.
> 

I tried to dig it out but I am not sure why we need this as well.

>> +
>> +	return 0;
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
> So we never invoke __do_kernel_fault() for a synchronous tag check in
> the kernel. What's with all the is_el1_mte_sync_tag_check_fault() check
> above?
> 

That's correct. This had a meaning with "panic_on_mte_fault" but since the
feature has been replaced is_el1_mte_sync_tag_check_fault() is not useful anymore.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b5c519b8-fbec-46ac-7c72-43864175748e%40arm.com.
