Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB4V42OAQMGQEVZM3J5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4999C322909
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 11:52:35 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id q3sf9919612ilv.16
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 02:52:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614077554; cv=pass;
        d=google.com; s=arc-20160816;
        b=q84SINLQFCFUyJoSsh6LEcXZQspEevwDezbVG9Ldg9rgSVvi+ansV5oBqWSa/wqO6C
         qRYHP1NdtRlB3zqVe3he4lDOZofXjpGH8/tWLvh8M5JxWxz3/OiEzP3vlr8UwfCoc/rU
         N9PYhtUaswrWbk/hBNfLgdqqU7mBlIPTi1Ypm4fkPEiTVx34/UQNwp4oOTM/X21K4mmJ
         iL8nw2eo8fF9vYLPYQ9zUPed9vpQUrkhKEN5rKsJWTG1nrdc2WS9PpEZTOiiLWlEfM5h
         1kV7b3tD3OMsYSpAIN+zNA3pKCc/n0vyM7wt+TG2q2cAvM7y+/p4YzAu7YnvgNZ7ZP7g
         ji2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=bF019h8Lp4ZGGFBmje7Fhe67ebr2C6zezB4b48fqQ5Q=;
        b=G2OCNxK8DmMdaqPorEv27DHPfYNWWzxb59iNstx7bnR8pCAPdmL5Eb83gWssE0eJ4D
         6qlmGPg+OAkD4Uhv5p4GbaUua5SBL8+rJdxiCB3MX8jsj96csBryKqoJSEqLz41DQ6ik
         AChG1Ay5M7Eo2jytZ84n4z2hIM+4TeOSn6hEE19ueJGEWJiAdVYTII0hlV/r+WWzAXTz
         jXrcbh9qmZpZob55TtwB/ehWIsyPwWZcAI1ehFLdvbwKIx/c/Vsj8czpfpWG9UVRfwmT
         NFEgzVpZIFty+vDAx44VdUBmTRD8H04boMZErINIvwS0Vvoh1V7JEtZ0Xfw3nPAFF4Eo
         BLEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bF019h8Lp4ZGGFBmje7Fhe67ebr2C6zezB4b48fqQ5Q=;
        b=c3f0CdKz5oM89qWKfgk8qlOXJ1QKZvV+KKeAB/6O3xOF8AkT+xSRrYk14K1RHYCrmH
         VuiPW7USLT3UgQES+e4pE/DkdkEUIy9CRHDWQPhYVOP+PpqBfUEL34q5EwfXXhS9DS15
         fL4hIoPRq6m3FnSO/suCbVQzxqaZrg/db2GhBe1kCON58CAuzWRMjhP5CMv3uD77SZ1W
         n0Yg+5by2l7ab2wxMnomyESaFwyKQYlj31sVBbjDn/ii9hEOuQLkBMwViDjnSzgakPKZ
         BhdzLDOo5IN9Pml3pgHtnNdksRqFVmYJ6DYdU2Wnj5oiJXugj1WloJ78hc2dm+YDZqyj
         15Lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bF019h8Lp4ZGGFBmje7Fhe67ebr2C6zezB4b48fqQ5Q=;
        b=LWt6cc2K1F2SI0yx8Vqlghm13OVMx0TfB0AXyykOKWDnxg0Add2fIDI8K52RFRv/QA
         oRmckz6RZ2nkQmC3Qz4htCoU9U4i2hj1otQ/ityR2QwYOvPERLqDs+N0zjdkphZ00Z1S
         klCKHtcEB1j+LTbrXO8bYBA+8SrvDzsEgNqPIsvhQURfluvg4e2/no/p7kgUi6ALQtRo
         GdTNqeSmTiVSRKwro0jpCPCfzlVI0UTHciq6SaEnnbM9wSy8aJpPynnD/MMVND1/xpi0
         EOQUtSFUaCCoQJDiCCpc+dBSr2M/Pve/cI7S10AFvpLVL+H/UdjXWcGta7cAdDynpxZM
         IF1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530xXqI81+/y8/0d3VLxtMZjRE1FCzmAB/kPVGaLbSpKjcgoRw6h
	IzVvTAw/UF3NtdZYfwvbuQ0=
X-Google-Smtp-Source: ABdhPJw5qfEy/XF6AnsmCgNpdeU3+TAPs4xmksliNiWq35Jv8URy0EM5c/vqdns2V+yxlrtarXSdlQ==
X-Received: by 2002:a92:6b11:: with SMTP id g17mr18779474ilc.163.1614077554250;
        Tue, 23 Feb 2021 02:52:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:170a:: with SMTP id u10ls5102614ill.9.gmail; Tue,
 23 Feb 2021 02:52:33 -0800 (PST)
X-Received: by 2002:a92:c105:: with SMTP id p5mr3638568ile.266.1614077553822;
        Tue, 23 Feb 2021 02:52:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614077553; cv=none;
        d=google.com; s=arc-20160816;
        b=eFmKobXo2yNek8U5tsJOW+/60mSNZGPMK79pSMj5siCZEmvEemA+F2kmJWO0vhxuu4
         Nbq/1aXQwLSCEGTdMZoJv9z3RtLeFr+2kWPUqFtKp+a0tCXh6bAZIWHebtHkBjBgek1T
         j9CFJTLMOsKuBCI0VuSE6o1rwboBTCbCF4BBAYujYmr9W1Fzi6DascQAsZC9X6LCFCnX
         Fgki48fxjdR2gIo8Hh54WXgMA3VsoPrC6d9+s/iJzYqGtJpu1CHMCLDtY8Jhj3NXV9xh
         EpneWrHYd7476KJ7WbmDrO7BbjeCIX9jn4Bfny2qiUHueiY20eDQccxAWPsjC0PmomXh
         VCaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=aCK1D2XoK3ZNpKwOYYHYBBPzNLPmHz17ljO1cfKu9pg=;
        b=bYTV3xornFjc2yZAkLPhrkQK9oJB4Qs62RzWTSA4ZVITZXwXUSQkd4ihAZwK2GIKSf
         9YoE4155t/DMC6SSHXHgOrMZff5zYlc4P/TcE9Z01AJ7UfpSune4zLYwn/VHP3ccBTAW
         U3FzjpC8QnB2537gSBFO8d5CCe/vvPMe9fdI+W3uQntBwX2SW0PB4z2NNhM2yD90YYl7
         eJBhqEzGbl8ebm7ptaPCFSwt22l3UuYuIBxPs5eFg0ZTyi0zYobTzY2gjMnlmuT8Nj+V
         1og8PGMIm3v+3OjP2H8kZ3k+U5qTI6fPml59zb0Ld4BXcnDxTxeYUbXXOramhCOdOQlK
         aOPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i2si487999iov.2.2021.02.23.02.52.33
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Feb 2021 02:52:33 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4786F31B;
	Tue, 23 Feb 2021 02:52:33 -0800 (PST)
Received: from [10.37.8.9] (unknown [10.37.8.9])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 4D57E3F70D;
	Tue, 23 Feb 2021 02:52:31 -0800 (PST)
Subject: Re: [PATCH v13 4/7] arm64: mte: Enable TCO in functions that can read
 beyond buffer limits
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-5-vincenzo.frascino@arm.com>
 <20210212172128.GE7718@arm.com>
 <c3d565da-c446-dea2-266e-ef35edabca9c@arm.com>
 <20210222175825.GE19604@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <6111633c-3bbd-edfa-86a0-be580a9ebcc8@arm.com>
Date: Tue, 23 Feb 2021 10:56:46 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210222175825.GE19604@arm.com>
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



On 2/22/21 5:58 PM, Catalin Marinas wrote:
> That's because cpu_hotplug_lock is not a spinlock but a semaphore which
> implies sleeping. I don't think avoiding taking this semaphore
> altogether (as in the *_cpuslocked functions) is the correct workaround.
>

Thinking at it a second time I agree, it is not a good idea avoiding to take the
semaphore in this case.

> The mte_enable_kernel_async() function is called on each secondary CPU
> but we don't really need to attempt to toggle the static key on each of
> them as they all have the same configuration. Maybe do something like:
> 
> 	if (!static_branch_unlikely(&mte_async_mode)))
> 		static_branch_enable(&mte_async_mode);
> 
> so that it's only set on the boot CPU.
> 

This should work, maybe with a comment that if we plan to introduce runtime
switching in between async and sync in future we need to revisit our strategy.

> The alternative is to use a per-CPU mask/variable instead of static
> branches but it's probably too expensive for those functions that were
> meant to improve performance.
> 

I would not go for this approach because the reason why we introduced static
branches instead of having a normal variable saving the state was performances.

> We'll still have an issue with dynamically switching the async/sync mode
> at run-time. Luckily kasan doesn't do this now. The problem is that
> until the last CPU have been switched from async to sync, we can't
> toggle the static label. When switching from sync to async, we need
> to do it on the first CPU being switched.
> 

I totally agree on this point. In the case of runtime switching we might need
the rethink completely the strategy and depends a lot on what we want to allow
and what not. For the kernel I imagine we will need to expose something in sysfs
that affects all the cores and then maybe stop_machine() to propagate it to all
the cores. Do you think having some of the cores running in sync mode and some
in async is a viable solution?

Probably it is worth to discuss it further once we cross that bridge.

> So, I think currently we can set the mte_async_mode label to true in
> mte_enable_kernel_async(), with the 'if' check above. For
> mte_enable_kernel_sync(), don't bother with setting the key to false but
> place a WARN_ONCE if the mte_async_mode is true. We can revisit it if
> kasan ever gains this run-time switch mode.

Indeed, this should work for now.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6111633c-3bbd-edfa-86a0-be580a9ebcc8%40arm.com.
