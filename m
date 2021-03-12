Return-Path: <kasan-dev+bncBDDL3KWR4EBRBAMKV2BAMGQE76RA57A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FEA43390E7
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 16:13:07 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id lj2sf9233599pjb.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 07:13:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615561986; cv=pass;
        d=google.com; s=arc-20160816;
        b=EN5ADf+WAawjTjH9LpsMt3ZC6mHVhoGEL+99N9HFR3lTaEdL7RJZZ64TmcqAuyZqQc
         ttXTgdIjCnqREKPapNpDmCN9ZrItvicJKxQmNP/033ILedm1r4/tid6W1VBsN6W92SVI
         VmZI0dGmV0bgAMhGbeptncJRGLCnplj7y9ZHZZON3YVltHGbs2/6W12BovOa9ZU4QMfJ
         KlA//r721jk96jpCgmqt+wep8gV8VYT9UJmH3rOzhvPpauWB7u30oVUcj0InnW4VnBiZ
         SJ6koWGJLsZx2JztDy2P8K5PZwv8qSRKFscg+wGqM9PZsuHwldj26avnCwkkmwInRyX9
         UMyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=f3hBvmC7juAYWjrt0Txmmgq0FuxGdDfJx1HhF8jjL9U=;
        b=xWdc3oGVjHLMLYfJs7Go5FU0y9qxdP/GxRiSWxtIPFv8uu1I4wGUN3enm6sqkR7QoN
         dBjwPASZt+0Z3UpFsjE+bWQxtRwOJuDgBWauSMMJ+kfmkw6mYN8tvXySd8asn1tNVta/
         z16ty8uHlqpPlC0eJMWeavgj8sbITS3B8yki3gwz/2nZ/ZIDtrZXJvuxt9y6SBAIZHFa
         bLQCjBRFUsQFevsz/9s01Je6hoCynyaa7KuUoekhjMRORUxM0WJKM7+ly6+9fwnZNfWV
         JRAxHl2M630A6+j5rb6jfHMTb7Au4s8EwyDqeGuJUXGrCjjUjn8e/0fZABpR65wSXq5m
         FlYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=f3hBvmC7juAYWjrt0Txmmgq0FuxGdDfJx1HhF8jjL9U=;
        b=PFi9DSh6oYinvlXvKWMl7dsw3ox27IaAvVe4gy9KEyiZ3l0bBeuBK87doaKPE7M1Xf
         p4kmhE6d4FmMhKfLqS/4BeAuce7tFKXqGg6tWiJqoyCVx7cTPQ3tB51HHEDeAYCtRkO6
         Tbs94e/bLVFpfdMlUojadHIPMrF1ip8+2N62eh/JZvr1ILj+Y7rg0iaGUJL3BlBo92SP
         Xae+3s935/+5EfYmrxFK8GtYdG2uEffyyDS5XxfC3ptx0Mmn+JsT1DkNfaSJrQTQ35eB
         eoM9/Rrz1eld91+o+msKcmlppzbYaKkr43OZ8irmOR0b4aOq9EtxbgrgntSs6J0xBOH4
         S6sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=f3hBvmC7juAYWjrt0Txmmgq0FuxGdDfJx1HhF8jjL9U=;
        b=phXaVANQVTDiK/2b2JMRKdQ6bIDzZv1vAtnSm/vzKqVy971bosFWJUsxQA1oI3O0Ts
         aYhyp+y6C60rVKF6cNTFfB3hEomHnK73KkFaJbKxrecBjS8t34WpjUa9n3itUNqLGgfy
         hqNdtkeLOe1mF8HCFj4IQCvSET+H3ORuuKVXOaYTqMpLKI4/MpKtd+vT89CZyNN3bjdF
         0ZuMeqse5gTkYgooBvJB7XRem46BOLTfuSemOgC8QmkNDupL/XGTZpZdZmbTYvQytSRq
         zj5xnqftwwANDjZ/q1kAdSDzFUbCikWobZcEA02gZuNVB5Kg/4BcTpqvhM1Gt8AFa1vo
         0beA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Sg21EdezYSPB54rGp2vJS9GE+tHPInVwtEGMOl++hVC4V196M
	szCdWg7XF+2bnQe7SuHwkzw=
X-Google-Smtp-Source: ABdhPJyc7Bqu4hPjR1dGU6gFLF1/PuWIPg4pJekZKyYSJcMYoojzgIpAVVoO3sEn6hGSuB7CD8EnIQ==
X-Received: by 2002:a17:902:f547:b029:e4:6dbc:6593 with SMTP id h7-20020a170902f547b02900e46dbc6593mr13740105plf.4.1615561986036;
        Fri, 12 Mar 2021 07:13:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1057:: with SMTP id gq23ls5369500pjb.0.gmail; Fri,
 12 Mar 2021 07:13:05 -0800 (PST)
X-Received: by 2002:a17:90b:244:: with SMTP id fz4mr14360201pjb.137.1615561985476;
        Fri, 12 Mar 2021 07:13:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615561985; cv=none;
        d=google.com; s=arc-20160816;
        b=TXREJ71RCUWC+eQeF+USJL7ZqRa8az6MiJAEtJI3TJOTjClDDGJY6TaVbeVn91Ve2i
         6dY9t9069b9tOJg0bpicgRVE5ckIa74coxalmzdXUBy4hGUlmKH2O9MT0CNixMvnTUSn
         ExU+LPGI2ZhtH57w+F8AhNaTEhJ3oRab6c/d9k7haKQm/tRhiDDve0FviFrLuDmbYS//
         GH88YaqUEeAClRAWE625g1uG/+Ix8xjbvi+xTKdyKJ8k4loab0jWQ71Wrj2Q3ETPRwRe
         +vrApn21xlrxOyAabEPWjJcut6IBAzE/XR9A7TGiZqgBLyz20c9ubv4JX4OZX7tRoK0g
         JdJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Ccjqmn5upCCbJjsnfIvzmRE3ELG2dQGUsyy8B0/QfJQ=;
        b=hl7N0eT+1T1s76THCe2hR5031dsIbjDBNz9tdz1O5zPw8L//htmQVvM9j9Old9qQo8
         d8gzFcWa445pcVp9bDstXwm2tcCP7iu9jK1cvbjCZ7NVrmNUS27rZA7yGBxj83vyQ8SY
         xLF7IFWUpHowdMCgPpUEUUr0oV3KetAFsYjNpgleK5Kl30sHP/x0fGab303MnIQxjBZM
         RLd4M2fU9Rv8a+J/SWV7tTx0HVyYxfBzwyVKhLhzrJtfR17Qf6EQ60O6unmcf5GYTrkV
         e5pP9dPJN7PT14SOgnjVmqJTb33y/uKPvNJkzYxxiAhsh/vouKlSwddgoIkkgYOJw8AU
         56Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k21si393058pfa.5.2021.03.12.07.13.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Mar 2021 07:13:05 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id A5C7964FD9;
	Fri, 12 Mar 2021 15:13:02 +0000 (UTC)
Date: Fri, 12 Mar 2021 15:13:00 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v15 5/8] arm64: mte: Enable TCO in functions that can
 read beyond buffer limits
Message-ID: <20210312151259.GB24210@arm.com>
References: <20210312142210.21326-1-vincenzo.frascino@arm.com>
 <20210312142210.21326-6-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210312142210.21326-6-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Mar 12, 2021 at 02:22:07PM +0000, Vincenzo Frascino wrote:
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index 9b557a457f24..8603c6636a7d 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -90,5 +90,20 @@ static inline void mte_assign_mem_tag_range(void *addr, size_t size)
>  
>  #endif /* CONFIG_ARM64_MTE */
>  
> +#ifdef CONFIG_KASAN_HW_TAGS
> +/* Whether the MTE asynchronous mode is enabled. */
> +DECLARE_STATIC_KEY_FALSE(mte_async_mode);
> +
> +static inline bool system_uses_mte_async_mode(void)
> +{
> +	return static_branch_unlikely(&mte_async_mode);
> +}
> +#else
> +static inline bool system_uses_mte_async_mode(void)
> +{
> +	return false;
> +}
> +#endif /* CONFIG_KASAN_HW_TAGS */

You can write this with fewer lines:

DECLARE_STATIC_KEY_FALSE(mte_async_mode);

static inline bool system_uses_mte_async_mode(void)
{
	return IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
		static_branch_unlikely(&mte_async_mode);
}

The compiler will ensure that mte_async_mode is not referred when
!CONFIG_KASAN_HW_TAGS and therefore doesn't need to be defined.

> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index fa755cf94e01..9362928ba0d5 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -26,6 +26,10 @@ u64 gcr_kernel_excl __ro_after_init;
>  
>  static bool report_fault_once = true;
>  
> +/* Whether the MTE asynchronous mode is enabled. */
> +DEFINE_STATIC_KEY_FALSE(mte_async_mode);
> +EXPORT_SYMBOL_GPL(mte_async_mode);

Maybe keep these bracketed by #ifdef CONFIG_KASAN_HW_TAGS. I think the
mte_enable_kernel_*() aren't needed either if KASAN_HW is disabled (you
can do it with an additional patch).

With these, you can add:

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210312151259.GB24210%40arm.com.
