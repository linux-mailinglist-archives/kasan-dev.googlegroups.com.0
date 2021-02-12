Return-Path: <kasan-dev+bncBDDL3KWR4EBRBHXSTKAQMGQEB6ZYBQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id DB80F31A372
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 18:21:35 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id t18sf6858679qva.6
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 09:21:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613150495; cv=pass;
        d=google.com; s=arc-20160816;
        b=1Hkp1P3wtfj87n+cA4xfL+cAeVnCPUa1At2aVzcccgVDyhih1La/tdvf29bt/RlNdw
         +PjT25RAm2vDseZGOOnx8wLRZxvWs473TVtY94Hn3XQfbiqyvqm1WWttkvqyEtFxAzTL
         UtLYPhbKCqCb3fYrhDLTDI8flVLqJOBIQ09NR8KM0M3/QS7RMG8e5x0l+n1xy2UTsRE3
         qrBUw5yBJLS1X0dpITeBmUMsyA/VJF+YG64KeLIRwtNvHhh1Ix4zY06YijDRb8FAo77O
         hfGVDBtB437lnAcbQjT2rrWACIWH/aMz5D7ZhssJ/WQag36iz1USXsho9W6XtTevtGNx
         Q5cA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=8ursGoKM55OIzq6IiRVhDHhTVOo7LOo6NAm6hO1acyQ=;
        b=hFaxV6zbOXC90yZIvJ/g2d/Pn+sOM/WXYucCHMjY9egO4x7PEKYNI95VXz7tJWfwMs
         1edQCTQutAUYOyIE8p4F4+9xKNQRd+JxlGrpcjonLaoluVQon+agZvc9ECHYi53/uXue
         +blbpz7onDiNnjxw22EiRNUbgCPcNyW7mbqGPqD2WueAO2JBYPgtNAD+HURJ/qLzgoPe
         vGRnfFKEsL/7Q47bnGo2B+Vsb1F18LRzitj+utBrViqAoXQ1pEW+Z8e11vm0Py/dlQlg
         JOdCLSePcV5T6v6g9O7/GlJsDnwgJaSjfwZi9/HEl9Vn5XaIDHIOkwcCPN4XNOOUfdJU
         rJxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8ursGoKM55OIzq6IiRVhDHhTVOo7LOo6NAm6hO1acyQ=;
        b=eyJpygQqhDvETFXeXdWbsatcArgQnW09lMG8QKwabiqe/Zah6tCBtjX2QSj1W2rn+Z
         QX1fWWJOtfZmo1G5wO5nzra/MhW8YPlGt7JEVOkb3sv0wbuLMARc3sojI2XnxzNv07vH
         A29Ju8URulp7RTheLtTPeAlO0XWmk+2VbsVjt+uJ9XMA653kykrlAjtXSicGg2MVWoC2
         +cLMmpGui8+TrwUJJhX4EDsz2Nz8AkUIupUjOviqR/vuVT+pMagg+mxkM84wMikxsnHH
         7n1/CWKW8dWapWwbdMNOtWGmxAHxWebKenbjcDareJhyLw1na7kwfgHiB2czeSuLoGRV
         7vhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8ursGoKM55OIzq6IiRVhDHhTVOo7LOo6NAm6hO1acyQ=;
        b=VGlct/BXBSJgS4uvXYAdK1msibT/SYudz+ZmHACzScxZhTDSmT+Z3mPU0trTtKfSg6
         e1ewj5LVcMV1enuJJ50EOZDEJJkZ5tub36hK5LzY5dZPrAYIg5WR9dVKnUXE0e1EuZUj
         g+CtkKpczkHmHHNqVV6mBGKgfsH2RMvymq6PQY3sn0qsvSDG17q1ldZcouNlhvK1VgS/
         VxAQA91jrrDjLVytA3rTRCzmg+fponDBN/Gb8CgCu6n35fylrJUZ1u2beugYAQTxvoJQ
         oBzPWw6cuGYymTDVsobQHTpsbHKqh5oyIsxcIdznErGPBpxk8/dyi1thRZtHfjAmagqU
         Ug1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530pA40kDsHpylHV1D2VBf6XvlfTYkXV+kBZGEQZexKLagiHcZwa
	zrmQKTdqcuJOFoy9tT6K9Z4=
X-Google-Smtp-Source: ABdhPJwckJefi1o0wQweVxAgJTC1C2rKV3aQreXsotMnnar+7EHrtO4OsZenecXaR1CvBe0RIZ++Nw==
X-Received: by 2002:a37:49cd:: with SMTP id w196mr3543778qka.288.1613150494851;
        Fri, 12 Feb 2021 09:21:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a608:: with SMTP id p8ls4898314qke.4.gmail; Fri, 12 Feb
 2021 09:21:34 -0800 (PST)
X-Received: by 2002:a37:64e:: with SMTP id 75mr3679314qkg.334.1613150494478;
        Fri, 12 Feb 2021 09:21:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613150494; cv=none;
        d=google.com; s=arc-20160816;
        b=WNO/EHQBKfyI+tlOgy/Yh7qWGN+A49UXx/HCFi0ZOJkcXgbIT7t8gZW2ijQv4Gd0eY
         cYkAEjRnTRFAklLSZvIIz3ykrYFMhWBQDcRBADyH2OJYaBDFI92MIPCOrVPxAWolHeO4
         xOhuj1/SkFCM7Z6S/Y1YEO5yc6UI1vokH2p+0UgqmSvqV+OhUfAhGD2WL0alCvmmGJec
         SfD4A/+GomnO6PKYf6EvMNsbJySf03qcgyjkqzb+Fuskm3DOjYj9hK0iyeCoDNsDVEa2
         Dlk05hlgLoU9+kzbnj4EU/07nFWVluDV/uSAtv0nHSkRLU6ZA0Enw5jUvAFfWzMMP04Q
         2whA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=OmrxgR/oP3nA4M0XQFbwglJVubIbc1ydbKrNhvUs63c=;
        b=zgPojE8QuXvri7HGCERMGlRPZD2xTv2WCuvdu7pt1oU8a7DijegyjX+QwJx0pW5l2b
         8oAdboKCLRdpCgIcQ46S2crWCfFXXHHVd9VMBKNFfE7sTUij8VVPTcOS+BQ9a/BXtPJ9
         2vPchLBaaYGdBdm+ZoMpJQNJ64Cx+GtYZZhV+oX116gkxmnPnRiHe6wFlWMw34qXkpeQ
         gVmkA+PkIu4SDsve3NL1NFs5qAfQd/GHKfpbWncsbaT9NC4ItzdscFbDN7q4B84a0ltl
         c3ur12jO40TA3+2/qTF79TIrhnfFEs2Cjr/cIVsQwBS6Y/hPe7SCP17Axljho44AW+HS
         yXMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e14si415238qtx.4.2021.02.12.09.21.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Feb 2021 09:21:34 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 34C1964E42;
	Fri, 12 Feb 2021 17:21:31 +0000 (UTC)
Date: Fri, 12 Feb 2021 17:21:28 +0000
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
Subject: Re: [PATCH v13 4/7] arm64: mte: Enable TCO in functions that can
 read beyond buffer limits
Message-ID: <20210212172128.GE7718@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-5-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210211153353.29094-5-vincenzo.frascino@arm.com>
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

On Thu, Feb 11, 2021 at 03:33:50PM +0000, Vincenzo Frascino wrote:
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 706b7ab75f31..65ecb86dd886 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -26,6 +26,10 @@ u64 gcr_kernel_excl __ro_after_init;
>  
>  static bool report_fault_once = true;
>  
> +/* Whether the MTE asynchronous mode is enabled. */
> +DEFINE_STATIC_KEY_FALSE(mte_async_mode);
> +EXPORT_SYMBOL_GPL(mte_async_mode);
> +
>  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
>  {
>  	pte_t old_pte = READ_ONCE(*ptep);
> @@ -119,12 +123,24 @@ static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
>  void mte_enable_kernel_sync(void)
>  {
>  	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
> +
> +	/*
> +	 * This function is called on each active smp core at boot
> +	 * time, hence we do not need to take cpu_hotplug_lock again.
> +	 */
> +	static_branch_disable_cpuslocked(&mte_async_mode);
>  }
>  EXPORT_SYMBOL_GPL(mte_enable_kernel_sync);
>  
>  void mte_enable_kernel_async(void)
>  {
>  	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
> +
> +	/*
> +	 * This function is called on each active smp core at boot
> +	 * time, hence we do not need to take cpu_hotplug_lock again.
> +	 */
> +	static_branch_enable_cpuslocked(&mte_async_mode);
>  }

Sorry, I missed the cpuslocked aspect before. Is there any reason you
need to use this API here? I suggested to add it to the
mte_enable_kernel_sync() because kasan may at some point do this
dynamically at run-time, so the boot-time argument doesn't hold. But
it's also incorrect as this function will be called for hot-plugged
CPUs as well after boot.

The only reason for static_branch_*_cpuslocked() is if it's called from
a region that already invoked cpus_read_lock() which I don't think is
the case here.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210212172128.GE7718%40arm.com.
