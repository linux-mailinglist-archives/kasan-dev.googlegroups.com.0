Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBBMPV2BAMGQE2XHBHIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 36250339129
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 16:23:50 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id r63sf7349965vkg.6
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 07:23:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615562629; cv=pass;
        d=google.com; s=arc-20160816;
        b=uMGNHtpeSqoiOSJ0mzvE0qJuSmbM/w7bYZFwLvGGdIXdLukQIDfnuxS9mqQEtOqYB2
         S46rTHoLNcMfI2SUu7egIB6KYqUxwrmCuljaXER54kJUAWmSUVEnsXP8BN3xlO4WKUaE
         zrIeNilaqZXn9x0M/JQ1RcScb/e832FXOy3kgH97NMG0/Xng+phNOQgOjrrwm3hDPsNe
         WfAuC43FtE75yB2BlStfF2bRuuqvmYh4UQiS66TOussYNK5PMO/SHr9urTD4BGjQ5UcZ
         wyeipVvChNKg8u8WAb6Tj9sX8a+vTzTcJuxzttJyLk2YIX0xAM2kE44x/azEk/RPeBtS
         Sekg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=/cE3FeRsgBjQFHyHAzMyrfznpGmQTJ6eTdOG6lAFmdU=;
        b=W6ZiyUO5rsWhCiOFbcM5XoF1jXk1qm+zocKQOXmH2ODL9jtS1xqUeXbrjLCfQND/bg
         6vMTV39nPZPRjgv1d1Gbb4/Yx5P+QGc9sngj/8KldS0s/IHsnGCg/PeGFox+6DHRzfui
         q0lcy9o2EyvnI2POkuec2YupHfe/fJ4NQ1cH0IUY0Ps7HLlVxRBx3FaII40nWhQlUVhQ
         +Cug7uTyj0gNpz2v+wVQ/uk2vu9WzXlI5I9EoaPCh3Ekq7oEwtAqgEWjKLS3Gk1YxBjg
         I34P6oQqc6KZ2MDSx0Hzpj7pURVMfGzUSb9Ogf+LcUBwienR+RvEOuxRAHE79t/40vAS
         MkfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/cE3FeRsgBjQFHyHAzMyrfznpGmQTJ6eTdOG6lAFmdU=;
        b=cS2CtLOLcjc78SqpdcQ3EiiuLPnU17AomuU65OG4haabMtVCJMJc6Jpws/FRUEav4m
         SVAZVhoqogFuLkbt5PLilQFluZN2L3gI23KkKGQ+m7PXXlqYtCfH/a87/m+2bcIxK7lS
         X4WeLBVY8yA0J5sPJ+KgdmKLbRgt3SlorhxMpGHyoeRxiVaC7HIlae3BEKb3VY0kbYG0
         8mNA6BXMJYE+AS8paUKoWEZBNhwLz8+gflzpZk5ua3u7KvFB2Ac/aAoqNlvNgzdGKE5n
         l1T68BvVOx6pL35mabJs+oehYluo7CPfBrNviWiAibeYhBXAEnlZf4yoP8mizFpYFhXw
         In9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/cE3FeRsgBjQFHyHAzMyrfznpGmQTJ6eTdOG6lAFmdU=;
        b=na/MeUWiY5TNuyj9zqQPdBIeeIAT9A1fU31fdY3tU6Y0r1+zen9fHivCruOhaLPXqu
         eutFUdiopdC+HExK0PcjEv3Jcx/B/9flkQiRQ0eiSA1wE4mT4hBVQVp8qasVaH4ZdnKk
         Um50Dqc0Ubj/sJYARDlMXJBEkdWBhea0PrrtDS13nIBQE26iEolcAAfMA+i2twm/xjQX
         HlsP//WJ4Ujj1ItohXpEPMbIBQhU2ew+pIJcIcNLeYOby94yDr+tK/rclRi7CMsgd8XA
         V61AJYcqQk7h9PtWoeUEOCl7vuLaZ3sC2v1sg3MmFTAA2aAHfu03TJ0UKBoptQDgxXk7
         xgAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5333k2U7RRj+naBS8te328smukWkkAOZv6wlOxQu6PqO4DfR+gHo
	AwpspSL/1wgR/wvfrcAH3IQ=
X-Google-Smtp-Source: ABdhPJyU2d2ItvrLS2F5g3sO3RWsVpcvaov1jLHXdR7Ti6ZAmjjvhbqdhAujcPoWiQIGti3rNGFWXA==
X-Received: by 2002:a67:e219:: with SMTP id g25mr8237103vsa.38.1615562629270;
        Fri, 12 Mar 2021 07:23:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:475b:: with SMTP id i27ls735389uac.7.gmail; Fri, 12 Mar
 2021 07:23:48 -0800 (PST)
X-Received: by 2002:a9f:2701:: with SMTP id a1mr8878004uaa.120.1615562628758;
        Fri, 12 Mar 2021 07:23:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615562628; cv=none;
        d=google.com; s=arc-20160816;
        b=Ho3VrXPfjM4tMifY6wn2ISH2DsoJgfQOrhdYAKtcTmH6Fw4qQT41mSppgil1mRUv2G
         +x6KKEr68WcpiT/JIYLHwLcaB11Dn3slZSZp4lrgwuQ5HnQQIvSq44fHgPKHv0PGSbV6
         9DLowK86Hv8bwPbQYMqtFCnh7+UlmcSIM+h+v0nUML9Jm/SEipjdt0MU1nCjq2AeTESw
         B5GQOvKEPJIIiY00uM2Kdpb6SAQOt1Hvhx8QXzheLfy5KC0v6o/PFT0hvoy/sF9xDiKc
         cah6pQTkQdBy7P6kxREO6mw5pwgqwV1v1C5rt0Kk3yCTPAwMBtWYuLBjTNxzKkqtuXBu
         MoIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=7dQ6ITEHGM5i9vZsVXzzXonxwvVY8GxYKUu5fC1yj5s=;
        b=NtNSH8SwyOUoWqygesBGMkN5fRo5MdZehxaZ6CV/sOggNg0co1PedksehjRvGMYb0H
         hyvmGzd2KagqPXu4oiXKr3xJKQj7qBfMrsbiLfwIOkTiIw6/H3qCxs/Sqn3zQHt/z867
         O54s4eqHW8r9DsirbvliUjavrAnrBS9HFQaQNCavwYKSjue+4Mlp/1seKp83ccN+hCkY
         kZSITH6eJMGy3ss6NTCtQcyLbRXyFG1TBIgTerWGpIikJkC9daUVIq7aY9soKThIj6T8
         bqj65MOcHMMKTuQr52B+Vop5cZiSzgmbILKydilgxskOtHPtbj7H3obXV1fH+RuoWnkB
         yIuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j11si322543vsi.0.2021.03.12.07.23.48
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Mar 2021 07:23:48 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C1A221FB;
	Fri, 12 Mar 2021 07:23:47 -0800 (PST)
Received: from [10.37.8.6] (unknown [10.37.8.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 3C60A3F7D7;
	Fri, 12 Mar 2021 07:23:45 -0800 (PST)
Subject: Re: [PATCH v15 5/8] arm64: mte: Enable TCO in functions that can read
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
References: <20210312142210.21326-1-vincenzo.frascino@arm.com>
 <20210312142210.21326-6-vincenzo.frascino@arm.com>
 <20210312151259.GB24210@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <31b7a388-4c57-cb25-2d30-da7c37e2b4d6@arm.com>
Date: Fri, 12 Mar 2021 15:23:44 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210312151259.GB24210@arm.com>
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

On 3/12/21 3:13 PM, Catalin Marinas wrote:
> On Fri, Mar 12, 2021 at 02:22:07PM +0000, Vincenzo Frascino wrote:
>> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
>> index 9b557a457f24..8603c6636a7d 100644
>> --- a/arch/arm64/include/asm/mte.h
>> +++ b/arch/arm64/include/asm/mte.h
>> @@ -90,5 +90,20 @@ static inline void mte_assign_mem_tag_range(void *addr, size_t size)
>>  
>>  #endif /* CONFIG_ARM64_MTE */
>>  
>> +#ifdef CONFIG_KASAN_HW_TAGS
>> +/* Whether the MTE asynchronous mode is enabled. */
>> +DECLARE_STATIC_KEY_FALSE(mte_async_mode);
>> +
>> +static inline bool system_uses_mte_async_mode(void)
>> +{
>> +	return static_branch_unlikely(&mte_async_mode);
>> +}
>> +#else
>> +static inline bool system_uses_mte_async_mode(void)
>> +{
>> +	return false;
>> +}
>> +#endif /* CONFIG_KASAN_HW_TAGS */
> 
> You can write this with fewer lines:
> 
> DECLARE_STATIC_KEY_FALSE(mte_async_mode);
> 
> static inline bool system_uses_mte_async_mode(void)
> {
> 	return IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
> 		static_branch_unlikely(&mte_async_mode);
> }
> 
> The compiler will ensure that mte_async_mode is not referred when
> !CONFIG_KASAN_HW_TAGS and therefore doesn't need to be defined.
>

Yes, I agree, but I introduce "#ifdef CONFIG_KASAN_HW_TAGS" in the successive
patch anyway, according to me the overall code looks more uniform like this. But
I do not have a strong opinion or preference on this.

>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index fa755cf94e01..9362928ba0d5 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -26,6 +26,10 @@ u64 gcr_kernel_excl __ro_after_init;
>>  
>>  static bool report_fault_once = true;
>>  
>> +/* Whether the MTE asynchronous mode is enabled. */
>> +DEFINE_STATIC_KEY_FALSE(mte_async_mode);
>> +EXPORT_SYMBOL_GPL(mte_async_mode);
> 
> Maybe keep these bracketed by #ifdef CONFIG_KASAN_HW_TAGS. I think the
> mte_enable_kernel_*() aren't needed either if KASAN_HW is disabled (you
> can do it with an additional patch).
>

Makes sense, I will add it in the next version.

> With these, you can add:
> 
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/31b7a388-4c57-cb25-2d30-da7c37e2b4d6%40arm.com.
