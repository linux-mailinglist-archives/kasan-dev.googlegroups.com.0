Return-Path: <kasan-dev+bncBC7IXAMWVUGBBYNTYHAQMGQETNNXETQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 53307AC21E1
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 13:20:05 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-30a39fa0765sf13758711a91.3
        for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 04:20:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747999202; cv=pass;
        d=google.com; s=arc-20240605;
        b=EqbZ2g8VkVo3nZmb3hnRrb8M/oi7im1JBEhwR/je0QkHhBUSRGvJI8NKuxLjRa2CGl
         rpEnVCDYHehcnKPXEp1ThEhHDpj/aYsswHlfL1JI/PQGPs2FSCRYPWFrLP2yD//NgO5m
         vM1LeuUpTuau3yeQvUcdWxgwTkDuJMf+NuT00Gy7OIbhcdcnCCI6f3ik2vOcGm6CFxSw
         E8q5/bkNc68ga3/6DR+Z7q8vuPpMiLfXE5C5N3qtYCX6AWLN6/JPsoILGSSZCrD/K35z
         sZZPilB9IadGFwft4iGlzmDG9b4MB/ooIGrpS4SWdXTSrfZPCLP6mVPmoLe/4WOvXbsq
         4HWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=EsWFt6dNKIaxbCNYY0wxL+cqKzM2oF/kRR/81dQHs+s=;
        fh=uPjxCaD8A3IwdIaKeQMRkyvS1ahYRbEur2njFRQ6QnE=;
        b=URMbmF0/M1L+reLfLGA3XoxtBrGhKeiF3NUL1sQ7zFKWn/b5yHJzH1ysavy+cYxNQC
         Ev9yRtzbtujE64dyWzuI3MuX9aoN+UZrvTiK+uiPynUH4oxSpVrzc8oLhj9SEIAw6Z0Y
         se37rSqvk86WAkHTwmoEiNEf8PgsPvR/FIsROpOi2M85Sw936YJqMzJ5iQgD1AvW4omA
         C4Oh07+gHp0dakoJ3Ntu/9hp0hHAWUm8gfmplM3rTm0xeAGkqKKaNkZL8h1m9H4nJ4uK
         9YQTpg/CNt5rJ3JeRz2ug0x20BWUPwMyvPiithPfy8lyroUMCFsUf9LKrgR6D1Hm3vRr
         8gaw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ti.com header.s=ti-com-17Q1 header.b=pGrh4cl5;
       spf=pass (google.com: domain of nm@ti.com designates 198.47.19.245 as permitted sender) smtp.mailfrom=nm@ti.com;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=ti.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747999202; x=1748604002; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=EsWFt6dNKIaxbCNYY0wxL+cqKzM2oF/kRR/81dQHs+s=;
        b=ubbamtFCjSwRSZsgtohu6rtJ0OaUmxwW2ctKryZt+1LObPTelp37MN1ir3dw36wTIb
         Xlngw8T/mqGCuDBW6E1RejXqvoXGNScDTL+3DEpEVACnFfw6sI+mSonBhVUlNoUX1dFI
         ZwlqQaXoygIf0Tz70XV6+41iK/o5rFyhPO+2uzbFvFtKP9J8oB8yzfFwAHST5R/Dhfjj
         h5en+9Ull7k/TC+6Dm5M18sUkxEZ6U1mTgs+RmC6y0KXLGAb9ySzgB8ICAfq1bpcs9Gl
         yktfsNKg9N0i00PhBTCK+fC0mdRf7FMV0hCmy366WuHMShbmYgIRYXcl/gIplZJQC8sZ
         cuIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747999202; x=1748604002;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=EsWFt6dNKIaxbCNYY0wxL+cqKzM2oF/kRR/81dQHs+s=;
        b=Mf30wvRD2hZWjVwtlAu83L2mwRewccIrcpbbHADo8+TXBh3nHQ3B3QyfPv2+/c8npz
         K+Fu46jyxM6gDjGpJ4RFj8HFzqDziF8ZMmMJZyahFcUFaHFzzWHL85W/vhYeT+GC/kck
         XQ4aaU9x6zs1H50gTUu/L9ezcfrOh9DO2VX5nk/VMaCaz85zmpQDSwUdA4l8kFaE4e3U
         T2jJusOvebjRjVhOxF0OJ+aO2Thox36aIAz+e/cMp0Y8RjNiOkA7LhRj0HH36U4rLd7x
         iL0iNb60puv+NYUSAMaKh4yaNsdPb4FF7lOiEmph2Ve844SYA8UZTKpIlLTqebY5HLt6
         d6AQ==
X-Forwarded-Encrypted: i=2; AJvYcCXYxiZwNXBwElqxgXITIN1CWxqkgEr4ZfsLFiWMyiYCZmB9XCF0Hjac80fBu1zill6ove32FA==@lfdr.de
X-Gm-Message-State: AOJu0Yyuk4S+j0P1RdxeH8Uwu5+rK8tx5QVyeJkPRvfZE4zIJ44u7tEU
	T6rJhQ2F8xzSfgChUTgahxT1bTyCxZSuDRpE2Wdji2HixrHEzCKW5kjR
X-Google-Smtp-Source: AGHT+IHjwtX7ZCkI5L1Tf7MXi9OFJMQc26b2CUGDqOKPIwzGoRRtswSWN5ZQWMqS/4CBfGKpJxyZvg==
X-Received: by 2002:a17:90b:4b84:b0:310:99bd:3ba4 with SMTP id 98e67ed59e1d1-31099bd3c85mr16948896a91.18.1747999202057;
        Fri, 23 May 2025 04:20:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBF4YRvvUjAFQv5ZhO0WTvka8/l8eigPrCnKfyZgZKGrfg==
Received: by 2002:a17:90a:4818:b0:310:d27a:fca1 with SMTP id
 98e67ed59e1d1-310d27afe37ls1117862a91.1.-pod-prod-03-us; Fri, 23 May 2025
 04:20:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXsAyj75uQBuMFNFBNvixYsb7m6f51e57yxI4bGZxP/9EL3zgt21gTZBI7Nd5k/uFq3V9u44nYQf50=@googlegroups.com
X-Received: by 2002:a05:6808:6f96:b0:3fa:8bfd:773f with SMTP id 5614622812f47-404d865e524mr20144964b6e.2.1747999190390;
        Fri, 23 May 2025 04:19:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747999190; cv=none;
        d=google.com; s=arc-20240605;
        b=AlGVkAisX3NivL+7CUISajoUxMb3MAvHrBPuft4q/ziQDDMMpXIcz6kqsUzsRDLkMq
         B4zmvHAU3/zT6bvyafqZ6vbBxmXqNPN0dGLNGbApzp5Fal/rI6XYFYCwTDdk+Lnu7s9c
         f22R7+MU3cspq/pqa7uTuMqNH8nLlRsXo84sRVVcFz4Hu8mdGMCgNZBojn4EEqdCfs0L
         tjF3gAiLkHTAV1/qiWbXqMam4wmXpORmGz37Vd0IiiYWOn4KUQqI3OuB7bYNM/+OHegt
         sQW1wcd9ptLhsjrUpYLlUOE1b8NbYpiEhDE4R3KGN4LhUlcImAgxnTwZ4cljM1trbBpJ
         e03w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=G3eBoRI6ajKzQj7PIYgoVul0HEV9Bq6GwjJIxWdrMvs=;
        fh=KrHnhLMIJlcgp4GB0sTxjGbFNEt1wbL4BiHahFwv5qQ=;
        b=YUpa63Mh3/h0EIXpYILiXR7ZQJrKEYVl95+3yf/8Et8bHYX7uOEodK1DkDnrUECUiT
         AS8ycfacSESL/JYNJORyl1NAF34Sy6fvt3uyfQSAXH05Yb3i8iz1J1xqpgkWECM+1Uhz
         XkLj4IjCHKTSkfSe9kQ0cZ+kyYGHS0vNCEupp4q/aSQh8F/OJ+KxCZTQblZVruaYPSQK
         uVCSlw4NAzGW+CG8kXC3MssALPWUkolcN6fcyY9GuWC6ixTi1fg2sH/h/DomhibUYSN+
         gp/i0h22ZHZD8YgyTvQPW+HOqkV11Yslj0X/sayNR5AZEZmbue2ZBKwrCoo60HfBR+BA
         37vQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ti.com header.s=ti-com-17Q1 header.b=pGrh4cl5;
       spf=pass (google.com: domain of nm@ti.com designates 198.47.19.245 as permitted sender) smtp.mailfrom=nm@ti.com;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=ti.com
Received: from fllvem-ot03.ext.ti.com (fllvem-ot03.ext.ti.com. [198.47.19.245])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-609f2f38ddbsi206330eaf.1.2025.05.23.04.19.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 23 May 2025 04:19:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of nm@ti.com designates 198.47.19.245 as permitted sender) client-ip=198.47.19.245;
Received: from fllvem-sh03.itg.ti.com ([10.64.41.86])
	by fllvem-ot03.ext.ti.com (8.15.2/8.15.2) with ESMTP id 54NBJc1K2086996;
	Fri, 23 May 2025 06:19:38 -0500
Received: from DFLE110.ent.ti.com (dfle110.ent.ti.com [10.64.6.31])
	by fllvem-sh03.itg.ti.com (8.18.1/8.18.1) with ESMTPS id 54NBJcAC023157
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-SHA256 bits=128 verify=FAIL);
	Fri, 23 May 2025 06:19:38 -0500
Received: from DFLE101.ent.ti.com (10.64.6.22) by DFLE110.ent.ti.com
 (10.64.6.31) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256) id 15.1.2507.23; Fri, 23
 May 2025 06:19:37 -0500
Received: from lelvem-mr06.itg.ti.com (10.180.75.8) by DFLE101.ent.ti.com
 (10.64.6.22) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256) id 15.1.2507.23 via
 Frontend Transport; Fri, 23 May 2025 06:19:37 -0500
Received: from localhost (uda0133052.dhcp.ti.com [128.247.81.232])
	by lelvem-mr06.itg.ti.com (8.18.1/8.18.1) with ESMTP id 54NBJblW1172257;
	Fri, 23 May 2025 06:19:37 -0500
Date: Fri, 23 May 2025 06:19:37 -0500
From: "'Nishanth Menon' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
CC: Arnd Bergmann <arnd@arndb.de>, Russell King <linux@armlinux.org.uk>,
        Daniel Lezcano <daniel.lezcano@linaro.org>,
        Thomas Gleixner
	<tglx@linutronix.de>,
        Santosh Shilimkar <ssantosh@kernel.org>, Lee Jones
	<lee@kernel.org>,
        Allison Randal <allison@lohutok.net>,
        Greg Kroah-Hartman
	<gregkh@linuxfoundation.org>,
        <linux-arm-kernel@lists.infradead.org>,
        "Gustavo A. R. Silva" <gustavoars@kernel.org>,
        Christoph Hellwig
	<hch@lst.de>, Marco Elver <elver@google.com>,
        Andrey Konovalov
	<andreyknvl@gmail.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Ard
 Biesheuvel <ardb@kernel.org>,
        Masahiro Yamada <masahiroy@kernel.org>,
        Nathan
 Chancellor <nathan@kernel.org>,
        Nicolas Schier <nicolas.schier@linux.dev>,
        Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
        Bill Wendling
	<morbo@google.com>,
        Justin Stitt <justinstitt@google.com>, <linux-kernel@vger.kernel.org>,
        <x86@kernel.org>, <kasan-dev@googlegroups.com>,
        <linux-doc@vger.kernel.org>, <kvmarm@lists.linux.dev>,
        <linux-riscv@lists.infradead.org>, <linux-s390@vger.kernel.org>,
        <linux-efi@vger.kernel.org>, <linux-hardening@vger.kernel.org>,
        <linux-kbuild@vger.kernel.org>,
        <linux-security-module@vger.kernel.org>,
        <linux-kselftest@vger.kernel.org>, <sparclinux@vger.kernel.org>,
        <llvm@lists.linux.dev>
Subject: Re: [PATCH v2 05/14] arm: Handle KCOV __init vs inline mismatches
Message-ID: <20250523111937.f2fqhoshqevdoxcl@snowbird>
References: <20250523043251.it.550-kees@kernel.org>
 <20250523043935.2009972-5-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250523043935.2009972-5-kees@kernel.org>
X-C2ProcessedOrg: 333ef613-75bf-4e12-a4b1-8e3623f5dcea
X-Original-Sender: nm@ti.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ti.com header.s=ti-com-17Q1 header.b=pGrh4cl5;       spf=pass
 (google.com: domain of nm@ti.com designates 198.47.19.245 as permitted
 sender) smtp.mailfrom=nm@ti.com;       dmarc=pass (p=QUARANTINE sp=NONE
 dis=NONE) header.from=ti.com
X-Original-From: Nishanth Menon <nm@ti.com>
Reply-To: Nishanth Menon <nm@ti.com>
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

On 21:39-20250522, Kees Cook wrote:
> When KCOV is enabled all functions get instrumented, unless
> the __no_sanitize_coverage attribute is used. To prepare for
> __no_sanitize_coverage being applied to __init functions, we have to
> handle differences in how GCC's inline optimizations get resolved. For
> arm this exposed several places where __init annotations were missing
> but ended up being "accidentally correct". Fix these cases and force
> several functions to be inline with __always_inline.
> 
> Signed-off-by: Kees Cook <kees@kernel.org>
> ---
[...]
> diff --git a/drivers/soc/ti/pm33xx.c b/drivers/soc/ti/pm33xx.c
> index dfdff186c805..dc52a2197d24 100644
> --- a/drivers/soc/ti/pm33xx.c
> +++ b/drivers/soc/ti/pm33xx.c
> @@ -145,7 +145,7 @@ static int am33xx_do_sram_idle(u32 wfi_flags)
>  	return pm_ops->cpu_suspend(am33xx_do_wfi_sram, wfi_flags);
>  }
>  
> -static int __init am43xx_map_gic(void)
> +static int am43xx_map_gic(void)
>  {
>  	gic_dist_base = ioremap(AM43XX_GIC_DIST_BASE, SZ_4K);
>  
> -- 
> 2.34.1
> 
Acked-by: Nishanth Menon <nm@ti.com>
-- 
Regards,
Nishanth Menon
Key (0xDDB5849D1736249D) / Fingerprint: F8A2 8693 54EB 8232 17A3  1A34 DDB5 849D 1736 249D

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250523111937.f2fqhoshqevdoxcl%40snowbird.
