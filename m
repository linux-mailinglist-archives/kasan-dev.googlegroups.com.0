Return-Path: <kasan-dev+bncBDP4V4X7XUARBSWXUKFAMGQE64QR7YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id BEE08411887
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 17:42:02 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id i40-20020a0565123e2800b003f53da59009sf12697092lfv.16
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 08:42:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632152522; cv=pass;
        d=google.com; s=arc-20160816;
        b=HfxohIFgtDsxsu1g/XIFQvtmnBFy/vcmnZ5KpbwHSFk3ohq6nauVbLczu1uwek2g4o
         jso8LzzIMq6VupL803bSgvieT7kT3m1C0J8ugPQjHZUmM1aZEFhCVBy1IEqJycmfHT3+
         7EYQQDkX+h5KYK5WAEbkJbk/Z2UNu8+aJOu+0q+U/OFJ+gFdt3dWLzEbapqdCkxG7DJN
         wxYDk7paMxCIbH7iBDi08hWxHXkZfV6GyrN/HV4I629kVjv2ssrhmod8XW4BL6j1/2Xo
         IYqeI1xAm43agI5xx4DJJRPOaFUBX4/zTDuMC+DhGINUFWVCu9kYBYPNU+Z9QT+zYpnD
         +Czg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=sE2zlXMQSpkT5IoWve82F+/3E0h+4mqlKRsZ8+48lOg=;
        b=OMxxAQFMgah9LG0pQ3E8omoVPfI1Tx61feGNm+VGO0tDCDRuaU4tWOwSUWI3MNyAmS
         jPBsdLJPBPrxZ3UWRLfJsI4QrxwxJnydhQ44oAP2FKkYHddGlO3+fEWNJ10mzoDJqcNv
         hpxb2r0bpsSwfeppxSzu9ZzAZbqM23xEtQbYEsz6N60wARv0G+q6I0VOlvDWkGODQi8n
         ex2Pb3JU5gAUF/djVRNGOpiMRGMLz4sQSyW6DlEJgmFyOSWrYt+T10t8plyEqp/+FGJI
         6NCPpVFfXX2st2ADlCMbMF4wC3ynu/tO/UeGycAnRV16ATfQh8Q5UYZIg841QaS6zEF1
         i0Zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of suzuki.poulose@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=suzuki.poulose@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sE2zlXMQSpkT5IoWve82F+/3E0h+4mqlKRsZ8+48lOg=;
        b=H4hlTg9myghjdmH9yTpiOukX0UnnFzCxHy818lYuL7GYFRFaMIEjWKwp9OqITSz67x
         x7kLVmOHUZnkeYVCeV2Mviimo7MOvXQ//jFe7c4jkIpMxz+ZBTJU6O0jz9foJUXwQZOB
         Ch0GSb9K6b/qv81HJOIrymtBylFdgHT7Xuv2DIgQvBB/zqP4LaUB4Lmc6wgPRMyUG6tF
         3zJ5mm5acIAevtkqV7W7ESnN7S/rpXGllJpdqImFtb08dcgLQmPwfsfVeaaIQOnZ3S9x
         1ZRPEibygzG01KZtqCXnAzJZHWHsCiYR9d640NNJb27DJJ9oVTxgeVuAe7QNGuFRZW6X
         zTwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sE2zlXMQSpkT5IoWve82F+/3E0h+4mqlKRsZ8+48lOg=;
        b=EPPhm0BoJeqS2VPDOGS0ExtwB+hgJn16DVmGlv1+/Y//PXR+15zVieV7bgcrPXeE83
         OKTSvVYtP6ec8lwkGGuZcePjODa8XroRyVf0xjeZDU0NzCgCsXIgJnibCW3pGNHY0heL
         H/z1seuUABsanQZUAgYPZejGUJYp9V02mj6YB+/QfJz9AUZE1MEuqv1EzQU9o8rDRmYe
         ver9HqTQgOSySHTUD3HUYRmUe9yJfGKPy+7Tsbwg3NXr0QkGwLf/FWS0vRBEnKrwp9GX
         yRaqLU3BNciAByeEDO48GbRn+UWpL7u9KMjLhl53xSo7X4df1AImZzvH6bvfHaxcjCEd
         ISmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533jst/57YHPpIQ6mIV0WU4CPPpCWUAJnO5tTwV3dRvAoLLfR5hb
	ckN1GArq1NiZ+dI8+Il7feI=
X-Google-Smtp-Source: ABdhPJwD1NQwfa+x+J/Sp6Jy1dDmMRluuSOhnBGrlI90Xj11BfP7SmQiQEcYqLCVXoZT6wiCLwPbQQ==
X-Received: by 2002:a2e:131a:: with SMTP id 26mr22909645ljt.46.1632152522351;
        Mon, 20 Sep 2021 08:42:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a83:: with SMTP id q3ls736421lfu.2.gmail; Mon, 20
 Sep 2021 08:42:01 -0700 (PDT)
X-Received: by 2002:a05:6512:485:: with SMTP id v5mr3025232lfq.100.1632152521198;
        Mon, 20 Sep 2021 08:42:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632152521; cv=none;
        d=google.com; s=arc-20160816;
        b=WAoYdEn6tnrsIUqgoxRVQFsHJ/nARhzzs+Wg+MpmeZvsmr5/y6tSmTUppmDnpb9Lc+
         siVSFUPUi9+wQ7TTH49Ch8G9Q1MP5+ewbGFgx4LQyFUlj8f6LRcGuYUK9N/dimfvWJ5+
         El+cfQLZP9vpn2MDAwsSd/DUWiSQpgdjh+Gb8KnY4xv5we2vffyW5YtXWAwdBM7eqxkE
         gb7iDaUYCB3V7vILX5fgEZ9MsFoa8vORw3rMQR9Jzl0bGy/K1judTk7w8Bc572yLmvQJ
         4oZrO77/NqwDCOK9eHTyZ5tfS5TRG/fKjPyQl2nV4ne8F88RwES515S7hbU8rjyBnLo9
         hLGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=u5ESHOK3lSxzH3ZfpktdqU+GosBKrIokR/1Nhgl0Wj4=;
        b=guASlLEKrHWzK8P1Cj9sxVB5LJ1e/E3DTlfZm5Y8ciGXUTXYomoNfFiPY6qudNMosl
         6johwwgHhA/xRfKEpHF2tocV9lS5FXMV7tiRJYUWXB6bOo/VHUkSWognE/bTXKF/eGkq
         qILbsZqobcMEMBQWzIGeF0uOC+Gr5mZlw/IJZIjcC28jY71dmqAB5QRSqKmAjNaGdXi5
         A75rF/HmvQM2g4kxnY+1JAnD11KCKLUaevyGKBL5FtrLYw7CPXZ0wilZ++BYsGBZyOO4
         v9v5LCn486OMjr4sH5IMmWTh6/FPdoqnhjtK6DHbn0pktsAJbLMgIguvJxaWbBBJi9uX
         tScg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of suzuki.poulose@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=suzuki.poulose@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t14si824068lff.6.2021.09.20.08.42.01
        for <kasan-dev@googlegroups.com>;
        Mon, 20 Sep 2021 08:42:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of suzuki.poulose@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 216F912FC;
	Mon, 20 Sep 2021 08:42:00 -0700 (PDT)
Received: from [10.57.95.67] (unknown [10.57.95.67])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id DE7D43F59C;
	Mon, 20 Sep 2021 08:41:57 -0700 (PDT)
Subject: Re: [PATCH 3/5] arm64: mte: CPU feature detection for Asymm MTE
To: Vincenzo Frascino <vincenzo.frascino@arm.com>,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
 <20210913081424.48613-4-vincenzo.frascino@arm.com>
From: Suzuki K Poulose <suzuki.poulose@arm.com>
Message-ID: <6e6fb454-886e-95ff-fad2-d003a594acbd@arm.com>
Date: Mon, 20 Sep 2021 16:41:56 +0100
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:78.0)
 Gecko/20100101 Thunderbird/78.14.0
MIME-Version: 1.0
In-Reply-To: <20210913081424.48613-4-vincenzo.frascino@arm.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-GB
X-Original-Sender: suzuki.poulose@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of suzuki.poulose@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=suzuki.poulose@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 13/09/2021 09:14, Vincenzo Frascino wrote:
> Add the cpufeature entries to detect the presence of Asymmetric MTE.
> 
> Note: The tag checking mode is initialized via cpu_enable_mte() ->
> kasan_init_hw_tags() hence to enable it we require asymmetric mode
> to be at least on the boot CPU. If the boot CPU does not have it, it is
> fine for late CPUs to have it as long as the feature is not enabled
> (ARM64_CPUCAP_BOOT_CPU_FEATURE).
> 
> Cc: Will Deacon <will@kernel.org>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Suzuki K Poulose <Suzuki.Poulose@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>


> ---
>   arch/arm64/kernel/cpufeature.c | 10 ++++++++++
>   arch/arm64/tools/cpucaps       |  1 +
>   2 files changed, 11 insertions(+)
> 
> diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
> index f8a3067d10c6..a18774071a45 100644
> --- a/arch/arm64/kernel/cpufeature.c
> +++ b/arch/arm64/kernel/cpufeature.c
> @@ -2317,6 +2317,16 @@ static const struct arm64_cpu_capabilities arm64_features[] = {
>   		.sign = FTR_UNSIGNED,
>   		.cpu_enable = cpu_enable_mte,
>   	},
> +	{
> +		.desc = "Asymmetric Memory Tagging Extension",
> +		.capability = ARM64_MTE_ASYMM,
> +		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,

FWIW, the selected type works for the described use case.

Reviewed-by: Suzuki K Poulose <suzuki.poulose@arm.com>

> +		.matches = has_cpuid_feature,
> +		.sys_reg = SYS_ID_AA64PFR1_EL1,
> +		.field_pos = ID_AA64PFR1_MTE_SHIFT,
> +		.min_field_value = ID_AA64PFR1_MTE_ASYMM,
> +		.sign = FTR_UNSIGNED,
> +	},
>   #endif /* CONFIG_ARM64_MTE */
>   	{
>   		.desc = "RCpc load-acquire (LDAPR)",
> diff --git a/arch/arm64/tools/cpucaps b/arch/arm64/tools/cpucaps
> index 49305c2e6dfd..74a569bf52d6 100644
> --- a/arch/arm64/tools/cpucaps
> +++ b/arch/arm64/tools/cpucaps
> @@ -39,6 +39,7 @@ HW_DBM
>   KVM_PROTECTED_MODE
>   MISMATCHED_CACHE_TYPE
>   MTE
> +MTE_ASYMM
>   SPECTRE_V2
>   SPECTRE_V3A
>   SPECTRE_V4
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6e6fb454-886e-95ff-fad2-d003a594acbd%40arm.com.
