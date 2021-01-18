Return-Path: <kasan-dev+bncBDDL3KWR4EBRBMMLS2AAMGQE6VSTVMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id AB5012FA088
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 13:57:22 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id 139sf13252306pgd.11
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 04:57:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610974641; cv=pass;
        d=google.com; s=arc-20160816;
        b=duMPOYu8/7F8elG1GLghUTisGYLY1QOxVmXFTCtSCq0v0X223GuDGteJ0hdomoQ9wY
         WQpRBCFH2qLFH5HIutLHBSNJhkpAIOZLO1GpYr1BmobRGbN13eTOTE/V+tawFs0Jd/SH
         dS17OGg+arPs/sgAxnMJQvKkU85zNiOqCM7a/LSUxtRuy1ykbtenz+jGW0wU95SYZraK
         iAdmQLQzPvv6i1KWH+jzD/XtSpbKpBxxNJmXgF6EFMdJyajj64hlpCxgiYD7I9dR4eyb
         tAooyc7zm7hhYp56E+ZNg8gnyeXDAclHxI2xjrmLolFnWMMaZRRGnRjggcfhr/KSiwhs
         GQJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=lOihRkybHGmi3tdpbR3qDiHcJiXKfJorCNZJgTbXg/I=;
        b=O9U8taIJxTd9FrbHD+T3oHNS5Ny+Led52NTwh9pchjxCHjlYhfn/P7DqDAuCCdxEwc
         izflWTtuy61YPQoNWU+r14xN8KoV/iC0TxVFi8Mc44xEIGchB0BCcBG33bjXo0+OOvQj
         SYZM8x01h7o+iIyzKS7nY5pggGOB9aNq051xzKikmOvfhTyqf4YWqvPvgk4gz2XwkEeW
         TW6bq6J3Uv+yEvJsBnpccwItGtKCu685BQTngSYlzThCjyvOzYqfCZixW+5PPo/AaBq1
         CtDPDuYxiiTMAKwQ7HK6JTuzSHn2wELu5E/MywTn/YSyZFM4UZFmjaiECKiRiJ7oxRuA
         YZgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lOihRkybHGmi3tdpbR3qDiHcJiXKfJorCNZJgTbXg/I=;
        b=WBek/qjWIfdBJggjaZgD9E1Wlbj6XDYoTBKMmQb8csBcSaat7RyFdm9yt5Gzbh4IMk
         N/g8cM6GdlSpzAKZ7nkfHVliUseaNFMGaXjonGqRkXNAXu+LpM5uQiIzyh7w6TO3SLR6
         ntMKlLSzyAueTL6YdHv9kkgzDM0nDu6ryIvhSSrzxjHAe0kFjJmucUSwF7ZHujFc6RjZ
         SBuKxqJkA1oWR7ty0zqjHQHM2tDR753UEqkY3kBCVEn3YFLSE3x0ROQZECTZ/eg9vfrw
         YfR2oR55+wK9U7a6Sy+rQs93ZAH/MQpQ3dJVEbs1zCJYuIkMIHwayh0ZFDnIxUfO4yxQ
         UMZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lOihRkybHGmi3tdpbR3qDiHcJiXKfJorCNZJgTbXg/I=;
        b=pIuaMfR0GGpIM6dpFdxW4GMW4kKJDcLot61fYrkp1IF1tUEeDORmAp4Sct3vfV21Xp
         yGjW4sz+psI1+2uvc0LXAJYq9/Hyz3YIDBfDTVUE4L2kRH2MuoL4vrH4G6NgRw45cu2A
         yItXnxNW02MIni17vDEGKd1NComOYMriMdqGT+XRJJaQ+yv3bULHVAjuLZCue9fmS7uZ
         WZmgjSjrwCH8HQ6jSfnbZu0QJtXPqhhQX1a8QzTYfxDP2G9k5lCVPA/qkZkI9WM/JDZR
         mNmKpqLSInbGaC0kT47q8fhm6SCrt3yQtNnXcLznSQ93lLiIf7GsTZHq3wi20oJyqBZm
         N0IA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533zHyqyT2ikWpiwoyVEIBB95BpmSRHWQd7gohL0XCkqr6DJQ+lG
	bNSLKQFEO3HoId/Kfu7JgRQ=
X-Google-Smtp-Source: ABdhPJwNqS2qt3TpWLpPUFIStOzWvjGcKiOmiQjB/1rY/2AOKKCJ+bbHgKL1uNKTPt/J0+N+bAKPaQ==
X-Received: by 2002:a17:902:9341:b029:dc:102f:c36c with SMTP id g1-20020a1709029341b02900dc102fc36cmr26754116plp.61.1610974641420;
        Mon, 18 Jan 2021 04:57:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4d4f:: with SMTP id j15ls6439734pgt.11.gmail; Mon, 18
 Jan 2021 04:57:20 -0800 (PST)
X-Received: by 2002:a62:5547:0:b029:1a4:cb2a:2833 with SMTP id j68-20020a6255470000b02901a4cb2a2833mr25375541pfb.35.1610974640816;
        Mon, 18 Jan 2021 04:57:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610974640; cv=none;
        d=google.com; s=arc-20160816;
        b=JSaJz5eQI3gS2G7Nq2XLN24cIcy84ZTNETGi0d3TS0C1mMtNTiOL4MzOW+GP5xKHtr
         1Ebt69Y6dl+qjsw9zYmHiWS3ENDrh8TnbyrsumdSMUWyFMDdtK5C3cpXtzpSrfLVAkUr
         F2sMXpH+C+Hb3sc2hd9AOlbwpv1XEJ1Lb5zCjh8EkqugLp5X1nsYYg07DdFQUag+jxni
         /lysFck5dDErV0BGzjVwRIgwaN0KpwhHZnU2F6pIMI+rEujN8eFscYkCetvYpBqybNvP
         KEvO8Yn9Q6NKYZCkAXX1Qpw3jZTFjUJK17Ve0CWDNqQDy/QlJLnnzyB/7cIxKRxOSbi9
         HinA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=XdbS+mMr5oRWlV9vj0M4QjWkXa8H8xCW9X3YWm3Yoe8=;
        b=KbN0DnmZZR2VZMGj65hKmX7qFCZMjbvqdamH5C4KQZQNfB15vLM7WpzA/D/+dACxBU
         cTW/BTU/jjHAhzM8td64hflrGwtb71mYtmzmanpm6JdRcYYj0nYfEEN5yXGI72LQ2fcp
         g9ZNYNC1j2Q9r1REJ4li0X7w8VOIhHATy2bOQE3rWH6z8r+l4SIRfI/ceRmNG/2kXsDu
         /hpCNFUVpODv1sHw9sSMAlO5ypxrOZmsjG+Y4/TANHbLyvb/QQV7Sw5JXn2LZp7zZr/E
         Ma+oq21UpkMrKPkSeNuDvWYJHGVL0/M5KNqk/wgWJFZbX4UB1ZbFdKGzyEzmI9k1XZs8
         DwAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z9si1531426pgv.2.2021.01.18.04.57.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 18 Jan 2021 04:57:20 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 5710322B48;
	Mon, 18 Jan 2021 12:57:18 +0000 (UTC)
Date: Mon, 18 Jan 2021 12:57:15 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v3 3/4] arm64: mte: Enable async tag check fault
Message-ID: <20210118125715.GA4483@gaia>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-4-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210115120043.50023-4-vincenzo.frascino@arm.com>
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

On Fri, Jan 15, 2021 at 12:00:42PM +0000, Vincenzo Frascino wrote:
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index d02aff9f493d..1a715963d909 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -92,5 +92,26 @@ static inline void mte_assign_mem_tag_range(void *addr, size_t size)
>  
>  #endif /* CONFIG_ARM64_MTE */
>  
> +#ifdef CONFIG_KASAN_HW_TAGS
> +void mte_check_tfsr_el1_no_sync(void);
> +static inline void mte_check_tfsr_el1(void)
> +{
> +	mte_check_tfsr_el1_no_sync();
> +	/*
> +	 * The asynchronous faults are synch'ed automatically with
> +	 * TFSR_EL1 on kernel entry but for exit an explicit dsb()
> +	 * is required.
> +	 */
> +	dsb(ish);
> +}

Mark commented already, the barrier should be above
mte_check_tfsr_el1_no_sync(). Regarding the ISB, we are waiting for
confirmation from the architects.

> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index df7a1ae26d7c..6cb92e9d6ad1 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -180,6 +180,32 @@ void mte_enable_kernel(enum kasan_hw_tags_mode mode)
>  	isb();
>  }
>  
> +#ifdef CONFIG_KASAN_HW_TAGS
> +void mte_check_tfsr_el1_no_sync(void)
> +{
> +	u64 tfsr_el1;
> +
> +	if (!system_supports_mte())
> +		return;
> +
> +	tfsr_el1 = read_sysreg_s(SYS_TFSR_EL1);
> +
> +	/*
> +	 * The kernel should never hit the condition TF0 == 1
> +	 * at this point because for the futex code we set
> +	 * PSTATE.TCO.
> +	 */
> +	WARN_ON(tfsr_el1 & SYS_TFSR_EL1_TF0);

I'd change this to a WARN_ON_ONCE() in case we trip over this due to
model bugs etc. and it floods the log.

> +	if (tfsr_el1 & SYS_TFSR_EL1_TF1) {
> +		write_sysreg_s(0, SYS_TFSR_EL1);
> +		isb();

While in general we use ISB after a sysreg update, I haven't convinced
myself it's needed here. There's no side-effect to updating this reg and
a subsequent TFSR access should see the new value. If a speculated load
is allowed to update this reg, we'd probably need an ISB+DSB (I don't
think it does, something to check with the architects).

> +
> +		pr_err("MTE: Asynchronous tag exception detected!");

We discussed this already, I think we should replace this pr_err() with
a call to kasan_report(). In principle, kasan already knows the mode as
it asked for sync/async but we could make this explicit and expand the
kasan API to take some argument (or have separate function like
kasan_report_async()).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210118125715.GA4483%40gaia.
