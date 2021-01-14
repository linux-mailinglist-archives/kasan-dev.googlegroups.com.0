Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB6VVQCAAMGQEFQLTMHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B52F2F5E90
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:20:43 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id l3sf4071268qvr.10
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 02:20:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610619642; cv=pass;
        d=google.com; s=arc-20160816;
        b=jurkSVnr/WAeWIwYx43AROIbBqzu/jjqb/hllIw4cOwwi51oUMVWVzEnEod6CL8rlH
         HwpWOlNXJggzGZWXFmNs+6phye+bqE9T4L6uhdBYSj/8C7COcE05FL+sOZGVa6tFJb0E
         M291Str5/QXTew9IEPxTt5cImD5/Ej6tEKm0gd3uTSJmwFBH2kT3SJ1IRx0pCMbr9d3z
         eO4c3Iij5KPPP/Ndny4odHnn223Rm9UqqivC5gv+XKic8xkSX0NE7M8uf45rWgSeyHpE
         OR/0AAEH7OyB58P5z3oevX8DTBmCSTm1wpVihjOHHp8jyQzrM3ZGI6xNQHgYzS3FtOrC
         XHBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=gmlP+NrCZoaEz0GmHg4VEMi9M8XELXMN+BseIuZX92E=;
        b=EbpkisSZZY2Rx5N/B+HLTTAYG0+DIoWlQOtbxEhoEeHj6UcG48H8PK+YvHf9B2Yl+I
         qevIhv7/+qWBEDbpIlGcifeQzzhWPdInZxXk/vXYKXPzLFo+2lhlV5n/4L4eiOY6XUhk
         7rq3ckc7MCrndB6GsiHT6oFjt83UE/G2UT+8lm6hqYq2703W1ySv5QZokDDp+3RLp+v5
         VlYdT0HiYzH04mJ+QREfVwy2Y41ciHVmMSWCiJnWiwO0bp2htknMDm1FJ1EFoJFNq4kk
         Xf5xRgs3XyDhJXiIhFHHuBYV/yH7f2xaaU5+gqN1rxm+wDDb77bd0RcBcu9IB48e1BbQ
         MZ7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gmlP+NrCZoaEz0GmHg4VEMi9M8XELXMN+BseIuZX92E=;
        b=MxeCns3DKDVHTUNZkOMTin5JzzDzqM0dRni5Cw3GBUhuCGbfjokbQMg0IdRiT9BmE5
         CY5rdrIFrahb0IpAuFaobF04Q6HZGVyhGbNiog+m/i4OuiW+7+BouL3/zYaUOQrF5OaP
         WTjcFKifeez3hg8TonSL0pjkB2b2GhpbXbhMye+tNnyko+a6aKoAKUAZarjWqqvwlCXc
         5Ib/HYl/rho5ucCQCN11RLCO5vLw5Kv63AmUQOXCgYkaIfCTOctJwjL7RpF6UsMUV4RW
         H0HFsmF2c3S01v+V19fBmnq09lSfuGrxJK4XGBUTtTPtASWVxv4CPgZ35+WGRizTlWo7
         amrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gmlP+NrCZoaEz0GmHg4VEMi9M8XELXMN+BseIuZX92E=;
        b=TOt8D4svp+H5kP89DcUZZyov+51xTfLLiIPCvbCPZp8ek0IjidNV7W9AfXJ4raavI0
         j++ZVSYKe3Xo1XbFL2RxxES8JVBa9f2u5CT/qR0NP0kmtDS7LDbv9NRpkoRBnJqJzc/R
         gPO6UQ5s/EWwVadNBx+R3rdFYCu74iQYRazLFd+UL93DkG33+YudeMDUKqLec1f1HMKg
         k5LSwcmZGLKCTHXQsWctomHk44+veRfpNOpk4v/rJLpICr3tnWEVsQ0y5vc/v/HrKKRb
         CxcfNeXKuj49O2E12e+rnBHsYHcAhaXccoJ4GExAphAKQPZA73gV0au4EzKN0UMXPtce
         XGig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530eeTLJO7pFpT36NnQAFAU+pbzrk/Wt+oDM/7YT9VzMY+TXV+5t
	khu3225m7ayJheLOLp2zWMA=
X-Google-Smtp-Source: ABdhPJzVzOCk495pk/+HV6ji5SCh9vWbM4D9YXyb1Q3CIQED0D+VwfuP0+2egORqO4oHVoIM6JoDvg==
X-Received: by 2002:a25:383:: with SMTP id 125mr9467944ybd.120.1610619642422;
        Thu, 14 Jan 2021 02:20:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:23d1:: with SMTP id j200ls2524705ybj.11.gmail; Thu, 14
 Jan 2021 02:20:42 -0800 (PST)
X-Received: by 2002:a25:5855:: with SMTP id m82mr7245506ybb.300.1610619642015;
        Thu, 14 Jan 2021 02:20:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610619642; cv=none;
        d=google.com; s=arc-20160816;
        b=XPVYDSEA6k5DH2ZpN3vOlOV0HA7ygLnMh3tb7X+mH+ICwuRylvBbs0v1G19GeUCnhZ
         /9+vWYp+dl+d/HQd3IJsEzigRZkOLfWM/gCxQqOgRaLjQSzsXa6p+n9kIPaRbs5HOJr2
         hdYOd4QHVnmvxRFle2mpGT6MsHC8wyKK/ZOVMmp2CX61B1BuGVgbUlRyamdVCh2Ui3Vr
         URO0BSAEe8ubPGuB44NPdJpvS3s0F6L+jtUIAXYlFEsuxx74Xve9dqm+1++Rn7aFdmbz
         ew/ms0MJv/7qvGNv8pTSoUukYuucpcfF2VyxWze0OMr0lTgcY3JYzgvBcPZrmzG1hTIp
         VEbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=wB99quEFCs9fi//dTu/Te1sGm2JwPAMAaACab8Ftbx8=;
        b=wzSeXRx60m3aVYbt8HKQY3jtICcxAxB5nJjRokAMLdKd5vmyKJ1cAB8lUwwwsWDJkh
         l+M3Ks7o8GuSJ92NJuT4MKmOjHi4i5bNmmKF9uBJ362PIRF4RwPLYmEBQ4gPuy/aWnXK
         vzpAN9lslqzGcieie3Knb6dEufzMakTfqeBKYHS0ngQr08PHBUebhQZfaK0mvchJ6ufq
         91HvEv6lVfX21luem5qCybbyeY4kDF5YlX1IIIqTkmMY4ijBiapR65SUVFyFyxM+t6DD
         i2G3m9UsmKC1zNWtpc78SLhVBTK0rbQ69PAcmshAql6yze48WzEXw+myyj8zaOez9ldf
         DyXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r12si390125ybc.3.2021.01.14.02.20.41
        for <kasan-dev@googlegroups.com>;
        Thu, 14 Jan 2021 02:20:42 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4C95D1FB;
	Thu, 14 Jan 2021 02:20:41 -0800 (PST)
Received: from [10.0.0.31] (unknown [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 9A4E33F70D;
	Thu, 14 Jan 2021 02:20:39 -0800 (PST)
Subject: Re: [PATCH v2 3/4] arm64: mte: Enable async tag check fault
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210107172908.42686-1-vincenzo.frascino@arm.com>
 <20210107172908.42686-4-vincenzo.frascino@arm.com>
 <20210113181121.GF27045@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <efbb0722-eb4e-7be2-b929-77ec91cc0ae0@arm.com>
Date: Thu, 14 Jan 2021 10:24:25 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210113181121.GF27045@gaia>
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


On 1/13/21 6:11 PM, Catalin Marinas wrote:
> On Thu, Jan 07, 2021 at 05:29:07PM +0000, Vincenzo Frascino wrote:
>> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
>> index d02aff9f493d..a60d3718baae 100644
>> --- a/arch/arm64/include/asm/mte.h
>> +++ b/arch/arm64/include/asm/mte.h
>> @@ -39,6 +39,7 @@ void mte_free_tag_storage(char *storage);
>>  /* track which pages have valid allocation tags */
>>  #define PG_mte_tagged	PG_arch_2
>>  
>> +void mte_check_tfsr_el1(void);
>>  void mte_sync_tags(pte_t *ptep, pte_t pte);
>>  void mte_copy_page_tags(void *kto, const void *kfrom);
>>  void flush_mte_state(void);
>> @@ -56,6 +57,9 @@ void mte_assign_mem_tag_range(void *addr, size_t size);
>>  /* unused if !CONFIG_ARM64_MTE, silence the compiler */
>>  #define PG_mte_tagged	0
>>  
>> +static inline void mte_check_tfsr_el1(void)
>> +{
>> +}
> 
> I think we should enable this dummy function when !CONFIG_KASAN_HW_TAGS.
> It saves us an unnecessary function call in a few places.
> 

Ok, I will add it in v3.

>>  static inline void mte_sync_tags(pte_t *ptep, pte_t pte)
>>  {
>>  }
>> diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
>> index 5346953e4382..74b020ce72d7 100644
>> --- a/arch/arm64/kernel/entry-common.c
>> +++ b/arch/arm64/kernel/entry-common.c
>> @@ -37,6 +37,8 @@ static void noinstr enter_from_kernel_mode(struct pt_regs *regs)
>>  	lockdep_hardirqs_off(CALLER_ADDR0);
>>  	rcu_irq_enter_check_tick();
>>  	trace_hardirqs_off_finish();
>> +
>> +	mte_check_tfsr_el1();
>>  }
>>  
>>  /*
>> @@ -47,6 +49,8 @@ static void noinstr exit_to_kernel_mode(struct pt_regs *regs)
>>  {
>>  	lockdep_assert_irqs_disabled();
>>  
>> +	mte_check_tfsr_el1();
>> +
>>  	if (interrupts_enabled(regs)) {
>>  		if (regs->exit_rcu) {
>>  			trace_hardirqs_on_prepare();
>> @@ -243,6 +247,8 @@ asmlinkage void noinstr enter_from_user_mode(void)
>>  
>>  asmlinkage void noinstr exit_to_user_mode(void)
>>  {
>> +	mte_check_tfsr_el1();
> 
> While for kernel entry the asynchronous faults are sync'ed automatically
> with TFSR_EL1, we don't have this for exit, so we'd need an explicit
> DSB. But rather than placing it here, it's better if we add a bool sync
> argument to mte_check_tfsr_el1() which issues a dsb() before checking
> the register. I think that's the only place where such argument would be
> true (for now).
> 

Good point, I will add the dsb() in mte_check_tfsr_el1() but instead of a bool
parameter I will add something more explicit.

>> +
>>  	trace_hardirqs_on_prepare();
>>  	lockdep_hardirqs_on_prepare(CALLER_ADDR0);
>>  	user_enter_irqoff();
>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index 5d992e16b420..26030f0b79fe 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -185,6 +185,34 @@ void mte_enable_kernel(enum kasan_arg_mode mode)
>>  	isb();
>>  }
>>  
>> +void mte_check_tfsr_el1(void)
>> +{
>> +	u64 tfsr_el1;
>> +
>> +	if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>> +		return;
> 
> If we define the static inline when !CONFIG_KASAN_HW_TAGS, we could add
> the #ifdef here around the whole function.
>

Ok. I will add it in v3.

>> +	if (!system_supports_mte())
>> +		return;
>> +
>> +	tfsr_el1 = read_sysreg_s(SYS_TFSR_EL1);
>> +
>> +	/*
>> +	 * The kernel should never hit the condition TF0 == 1
>> +	 * at this point because for the futex code we set
>> +	 * PSTATE.TCO.
>> +	 */
>> +	WARN_ON(tfsr_el1 & SYS_TFSR_EL1_TF0);
>> +
>> +	if (tfsr_el1 & SYS_TFSR_EL1_TF1) {
>> +		write_sysreg_s(0, SYS_TFSR_EL1);
>> +		isb();
>> +
>> +		pr_err("MTE: Asynchronous tag exception detected!");
>> +	}
>> +}
>> +NOKPROBE_SYMBOL(mte_check_tfsr_el1);
> 
> Do we need this to be NOKPROBE_SYMBOL? It's not that low level.
>
It is an inheritance from when I had this code called very early. I will remove
it in the next version.

>> +
>>  static void update_sctlr_el1_tcf0(u64 tcf0)
>>  {
>>  	/* ISB required for the kernel uaccess routines */
>> @@ -250,6 +278,15 @@ void mte_thread_switch(struct task_struct *next)
>>  	/* avoid expensive SCTLR_EL1 accesses if no change */
>>  	if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
>>  		update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
>> +
>> +	/*
>> +	 * Check if an async tag exception occurred at EL1.
>> +	 *
>> +	 * Note: On the context switch patch we rely on the dsb() present
> 
> s/patch/path/
> 
>> +	 * in __switch_to() to guaranty that the indirect writes to TFSR_EL1
> 
> s/guaranty/guarantee/ (well, still valid though I think rarely used).
> 
>> +	 * are synchronized before this point.
>> +	 */
>> +	mte_check_tfsr_el1();
>>  }
>>  
>>  void mte_suspend_exit(void)
>> -- 
>> 2.30.0
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/efbb0722-eb4e-7be2-b929-77ec91cc0ae0%40arm.com.
