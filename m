Return-Path: <kasan-dev+bncBDV37XP3XYDRBHXCQ2AAMGQEJB6BJCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id E43822F7F24
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 16:13:35 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id 5sf3903685oth.4
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 07:13:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610723615; cv=pass;
        d=google.com; s=arc-20160816;
        b=WDVDs7CONrCGZrwB6hKm2k3xbTjoJqP+UGldlq/ZjaZigS7J1HENSkdrX/KfGbdaYO
         H4tQtd6TJysCyr1ps6IZsxlJnfD9SY7+rhbxETQVGFccqVcElPZ/3qqliceQJ1T8A7hr
         DJin0TfEPbMuW7fUaPA7qO1Pt5Cghw1CNy2VKaImr6oOdxZhLWHdZ3ZRp/qZ84yfti57
         sL4+fLnml0VLsdQ0qhK9tmNznVUKmrp9BYvMXmMuEL0jtf91Szza01AkjAToOUdrvwlF
         m4P3Fc6RZQN2ijcMsbwnvE1+nzKZm438fzP2TzLgENKYDqtgpaFNjB+j71nxUfR7W+tX
         jR3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3SG2HXWGQoXVw/xmvVGtWUqPAQ8JD6Vzyd6KpAIc0D4=;
        b=yWSqsVV8j2r62KtKHfR9M2HIY6A3L8TVEUx4fztEAseKUe+5T2blzW29xOTqHhEwVW
         MfCFaEr4X4UqR2ViYss4rf7Svtb0onIZHoTNRA7PxjH9lj8SuWmn3APlGjFuTXI6MLqz
         m4NGVSKt0PVluwEDfXRoX8vAE0lFn7REBXSnsuMEh2gHIyOO9FdCAfTw26rFFgKJIZLy
         lkWilt5gwyf4chGQqphgvirNJEJhPT9hFk1zkEuNF2WZFB+SdaYTOrqZ6ZVRJ/BIudAr
         UQh+5n17gdNtqIQC9cNyVW7JlLIr134UXtx1j2yIADV/dFTNmm8IA2IdIerZIWnKkNN8
         3Bmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3SG2HXWGQoXVw/xmvVGtWUqPAQ8JD6Vzyd6KpAIc0D4=;
        b=mdpVYGt+wDT4ysQee02lmy+TDKLdJXzIXtxCZ3s7SzXwRgt4e0ki2tBqLtcfN62Xp6
         76A7gpgO8TM7de+2xibwtuIUsJ0VL18X9Qgz4B/5qYGyF2KBtjyoZXlfMa0m+CvpgTJ8
         pNV0AdDKasYCtGth9pBevefvSIctTiZLkIjj0J86jvlMQPSREFzEWOk93QvsGbB4ZgeF
         woWJ+016DpKRuPPMUruXD7R0TD07obndg8aYrG79nVYzqRLOttIrKrpI0duhO6AHkALb
         37lSYzmiwbI5P4wFBDSXUk0Qs2lC4bMcoe78IpRq5RpGkgQ9dCN9ZfLsEHtJP3cIOxxI
         aYiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3SG2HXWGQoXVw/xmvVGtWUqPAQ8JD6Vzyd6KpAIc0D4=;
        b=IdHVZplrTEOluQSjdqTJMFDIXfcGm5xaT9sAmZ7gsHzK3ws/9KjDgFc/omw8DgKX3F
         O3c0ofX6oxtELjmQ1xL7rGJWWhe6cqckCRBLTmEDYVOX5CS/46DYqyHmmyW+ao0yg8nW
         aUuJMeuBHGBKyWpaGJcEqyGOsHMcqMji1oIC4faC7TGpT/9X6mUbkl1XmNE94QOXacxZ
         9hX0m2mHfsQdIcteD/lRb24+y3LAAx4xtH2eYrKDWFBeWPZ/Txys1jfk4aX9NDmH8bdQ
         iIsRU8aE1EhOZ5QM/YMGhVT+x6I8uWBIqf9nU90cn6h3PMDpFFnm7e4pZ+UPfdCb0czd
         qC+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530L8K+fG9IH8LfDXR48/IbWYZuqvxiIgEYt0G5ZEifYpDgLBUgy
	+MzdAuDfQ6KM3Dz0Io+2Btw=
X-Google-Smtp-Source: ABdhPJwyIfEVKfHtO2xF/lyt8Kh8XIjOfXh6Jw34mGB1FqI1UlYJeaonSzTr3il1P8771kXmso/H2g==
X-Received: by 2002:aca:1716:: with SMTP id j22mr5874405oii.42.1610723614922;
        Fri, 15 Jan 2021 07:13:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:140e:: with SMTP id v14ls2352681otp.4.gmail; Fri,
 15 Jan 2021 07:13:34 -0800 (PST)
X-Received: by 2002:a9d:63c6:: with SMTP id e6mr8431119otl.326.1610723614501;
        Fri, 15 Jan 2021 07:13:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610723614; cv=none;
        d=google.com; s=arc-20160816;
        b=f/XvMPCePumfyU98pU2sWxPYrFojgSza2oFXUtxyfaOTFMndj+3VHtFmONSvSgL4/O
         nVoYoUeG1itbjZRsUeGzOwWUH3WulG85hSs8WuwKYwKP5kBcVqq2gc8FGudfAZ20URxw
         eLeh3vlGlSOMEGuYlsHgw+WDgucOeFJVyqFEOS9JQrUiw8oOk9kNcpDI+I5VQxeX48zE
         YGZ/RT5iKP4/Da4pV3GqwmJA3dKyQNd1MQjYwAO3ppfvTgZEkwM0SAN6PqcDUhQBDVU0
         s8u4fGODQ28MPLjUAkcmv7tDaPLof5ZJPAqY8WnCE7+VesCp3Dz9SbXsnAxaKTMc4AEO
         cDiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=D6JgDkkQCTIy71XCU9TMFJegs6KrISIrfZlPe0IwM50=;
        b=RHzY+XnqU4Ws3rbJgvN8enYBRa4Nwcmu0/IP0Yx4AVe4NVm8wsT/RhkahMpuOZbZg4
         zfE07h5eBN95cxsVpTN2oC6EECVPXCD9f7RvYcf3eCuFSo0PAymIH1xhKQDN35MHD6mH
         7FvDnacVQ0Ty4Kl+Aky2+L15d2CSy5m2qBze2RO/3iZ8RQt9Ak7Xj94lx0lQGA0KqA/l
         sg8B2LXmw4T6PVCQVRo9U6dKr+VDIGJLP+womPH20EdHPYtVKR8UVjt/eghFHohGymOd
         Z+Wwhj0+UHF5AT9c/I9nmCdWl0fKcwrSkBffRH/kR2dlJh//LHQx+Zo+WjF6DSSmFnGB
         xWgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id u2si807638otg.1.2021.01.15.07.13.34
        for <kasan-dev@googlegroups.com>;
        Fri, 15 Jan 2021 07:13:34 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C2EF3D6E;
	Fri, 15 Jan 2021 07:13:33 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.41.13])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E732D3F70D;
	Fri, 15 Jan 2021 07:13:29 -0800 (PST)
Date: Fri, 15 Jan 2021 15:13:27 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v3 2/4] arm64: mte: Add asynchronous mode support
Message-ID: <20210115151327.GB44111@C02TD0UTHF1T.local>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-3-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210115120043.50023-3-vincenzo.frascino@arm.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
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

On Fri, Jan 15, 2021 at 12:00:41PM +0000, Vincenzo Frascino wrote:
> MTE provides an asynchronous mode for detecting tag exceptions. In
> particular instead of triggering a fault the arm64 core updates a
> register which is checked by the kernel after the asynchronous tag
> check fault has occurred.
> 
> Add support for MTE asynchronous mode.
> 
> The exception handling mechanism will be added with a future patch.
> 
> Note: KASAN HW activates async mode via kasan.mode kernel parameter.
> The default mode is set to synchronous.
> The code that verifies the status of TFSR_EL1 will be added with a
> future patch.
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/kernel/mte.c | 26 ++++++++++++++++++++++++--
>  1 file changed, 24 insertions(+), 2 deletions(-)
> 
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 53a6d734e29b..df7a1ae26d7c 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -153,8 +153,30 @@ void mte_init_tags(u64 max_tag)
>  
>  void mte_enable_kernel(enum kasan_hw_tags_mode mode)
>  {
> -	/* Enable MTE Sync Mode for EL1. */
> -	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> +	const char *m;
> +
> +	/* Preset parameter values based on the mode. */
> +	switch (mode) {
> +	case KASAN_HW_TAGS_ASYNC:
> +		/* Enable MTE Async Mode for EL1. */
> +		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_ASYNC);
> +		m = "asynchronous";
> +		break;
> +	case KASAN_HW_TAGS_SYNC:
> +		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> +		m = "synchronous";
> +		break;
> +	default:
> +		/*
> +		 * kasan mode should be always set hence we should
> +		 * not reach this condition.
> +		 */
> +		WARN_ON_ONCE(1);
> +		return;
> +	}
> +
> +	pr_info_once("MTE: enabled in %s mode at EL1\n", m);
> +
>  	isb();
>  }

For clarity, we should have that ISB before the pr_info_once().

As with my comment on patch 1, I think with separate functions this
would be much clearer and simpler:

static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
{
	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, tcf);
	isb();

	pr_info_once("MTE: enabled in %s mode at EL1\n", mode);
}

void mte_enable_kernel_sync(void)
{
	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
}

void mte_enable_kernel_async(void)
{
	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
}

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115151327.GB44111%40C02TD0UTHF1T.local.
