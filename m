Return-Path: <kasan-dev+bncBDDL3KWR4EBRB4HGRGAQMGQEIROE4MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id F3FE5314E47
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 12:35:13 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id h10sf9341978ooj.11
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 03:35:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612870512; cv=pass;
        d=google.com; s=arc-20160816;
        b=k8WQyq2JP1xq0D/MdJ9S7rUSitD+aek83Ew2EEhSYlOZvu+ExXi2BTO5UiowVCKfYL
         o1SUuS2NBwVn2mVBxZ8gy0H7KWNAeSDcrn0HFJHn+xCNsTrN3qEf/7ymmw7bdtK8/wt7
         L1pcbgshorFZkNKFSKFxzjXXuIaFCl66cYu/XFXiEiyKWJPS2pTEGqWLqAWbnjbkJQBD
         T073EzlynbKdnuyk240gAJnGuqDh9SPQ+RtLrQeAG3uaINuoCCRaObzxECFtB+vCVoB4
         dUP19SMHDO1Tfa3Y1DMepSLPWoGYjsw2650jk+Y03uQYiV3A6ZAVybTjMTBWuvS98cyA
         0qfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=IzPrq+y400r+D7KqDRDEviT/FUzyGWEAYAqTaeG9AQM=;
        b=1HxoDedirAPlsCy+nQ3aMprnJVcviQ6Ts2E8i9CzCBILNjmf7F2Yco16ecAT+PMgFU
         6d0AaLqo65C6FtQZ8FFlu6JKHACuwqG5WBDbBMvMSDlnYeT9O1NJeYUQoLpfiJYLYfmZ
         xqMqbdTZWaPiSkJsF1XKpicXHvw+yORbu0a6m25sf4Hoftnrvhsst6FVN7D3FukSW4IM
         wS1MmPuQyt+JuuGGaqlwTnFtqfDohALJ5D3+ShV06KJGZ8KIFMFV4uJvZvdpicTErPw1
         Dl7MHyzFI9JXm3H9iM4ZRU2wA6I2QKrpu6V2vXCINLoUuaizoue7Q0SuYD/VcdrDVpHc
         qcKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IzPrq+y400r+D7KqDRDEviT/FUzyGWEAYAqTaeG9AQM=;
        b=Rp6khG0Yy/00aER4l8wkqpc34qbp52lHNThnJPUmSaEkyzHgAiIogHT20/WuAPyQCQ
         CYSJ0jbCnzZQ9skfMWfhb/G03JpeOO/bsrjDLaTde68rUe/6qUWaoVqe4LhtrSrW5jEn
         ABtfB00nGZyJdIXDeH1D+a52ENlBNDv6+ESgpJLJAdOBruHo4PEozQxoXKT+GiZi2NGq
         /CI+0R5EbEfRrTDdDdAK/vTG0uzyHneTPQjkYVPcND0NIztVnSq9T5Qw2S1itxmhS3Gp
         sz45JbU/giLGvdWFO+JSLsuSfHPNF28lWiOxdbUWy14GbTv1rlyjeNeHLm4uRCGp0zlt
         14aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IzPrq+y400r+D7KqDRDEviT/FUzyGWEAYAqTaeG9AQM=;
        b=gnxxHhgztBm7807IQRsVaqi/6PGEsR5LhR+73atwQITHh+hAHaycAmICltINinrWaB
         cwmh2+iGeaQWvlkhBKxkHUSKk9CT2CSZytIQSDtPmSgrr2WXdwS3N9/cSxrlvxAH1sDI
         QFN64YvrQJ0MPK62f8pqedOepLWVhJ0Y4CIudOcF8xTnL830NLVJO1Fs5DhSPj6HH6Q2
         hqDZXmjiy7aOC/pVCGtytkDWzkEU96SeFO/pIV9LV3PCuu/pAvzTqcP2anoLpdltIBFj
         hLVyKcoAtbOlHxrFAFAmMnlq1LBj2GssCiQNtbe+VSBAq2P2ojZtcEGuxpII5aDirTml
         AKRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530gcK+3vFhche/qe1gxJNcm7yO4EoygV9JZcDC+4ctwRJQHFNF2
	5pOVi4yBEq2oICFj/IwXfeA=
X-Google-Smtp-Source: ABdhPJylAkGzYneY510B3DIRFRWf3cTiFLpK0KEHajTT6PVY8hp5S7ZVuShu818yJ+rqfDQJAUTRXA==
X-Received: by 2002:a4a:9d0e:: with SMTP id w14mr15285514ooj.7.1612870512637;
        Tue, 09 Feb 2021 03:35:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:bb82:: with SMTP id l124ls4755432oif.0.gmail; Tue, 09
 Feb 2021 03:35:12 -0800 (PST)
X-Received: by 2002:aca:4b8b:: with SMTP id y133mr2149196oia.93.1612870512222;
        Tue, 09 Feb 2021 03:35:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612870512; cv=none;
        d=google.com; s=arc-20160816;
        b=p2N+Bwi3h9efd8Kkj9IllatcgNqQ1hMGcREmxlln8VCQtcBflpAHY82ZQ02v6Xfim8
         su7LSc0CUyF7Yb0wPdkeMGHZorQfPiDBX+X6nmXzSiqvjbRC9TDcI7rNLbidOWlhEoW3
         1m3MatKDZq/sakaAdGQYXdXlaK+n9WtURAnauX+pRJPy8lTz654j7JIfSkuRuAuUNt0k
         EXZ1oKBITaYSw38wzsRh9CJzMUgSa7RKKsTjKjcpA0jW0GLCQrGIad7QoDoG45LezXcB
         Da6t0zJvCUN1djqcbRT+kiOnftO8SCFz462VHecdeELN7IavZUyX03Fw9SO+lyendGSd
         paeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=OGk1UKXMrdpr0BtQ4crHAjReUGTSxMSLPPs/GvSup50=;
        b=fyIhvnpF7yDW7J0fhiFJ7EbDovBeic83UJzzot5K9DPHGFNj/aKJtxImUqTX6+m9J1
         vs/uZut8ceMvdvk/cYe8ncemqcAVaS2gGb9b9BU7i421uapHZiRwFNiDkJs+PGSfJ0kI
         CmQklrSWv30ZgP3MLD08Lv2oIvvTgrE5jrAwcc5d3XyIcH+ZEiuaZfqL04/frGp5iGrn
         MqOkyDposZu7h0qT3d+WtpUKelPfiYl2v8Aa+k3MhEBHP5nBRN05lN9SGGtGMfL6sTNs
         f9U9iohw0J2a3E0L3tfZuCE+f8W/OLjlocceCTwOaKWIW/iv8fT5S+hVnav7HXLOjLdU
         o9XA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q10si505771oon.2.2021.02.09.03.35.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Feb 2021 03:35:12 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E2DBB64E6C;
	Tue,  9 Feb 2021 11:35:08 +0000 (UTC)
Date: Tue, 9 Feb 2021 11:35:06 +0000
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
Subject: Re: [PATCH v12 4/7] arm64: mte: Enable TCO in functions that can
 read beyond buffer limits
Message-ID: <20210209113505.GD1435@arm.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
 <20210208165617.9977-5-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210208165617.9977-5-vincenzo.frascino@arm.com>
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

On Mon, Feb 08, 2021 at 04:56:14PM +0000, Vincenzo Frascino wrote:
> diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
> index 0deb88467111..f43d78aee593 100644
> --- a/arch/arm64/include/asm/uaccess.h
> +++ b/arch/arm64/include/asm/uaccess.h
> @@ -188,6 +188,21 @@ static inline void __uaccess_enable_tco(void)
>  				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
>  }
>  
> +/* Whether the MTE asynchronous mode is enabled. */
> +DECLARE_STATIC_KEY_FALSE(mte_async_mode);
> +
> +static inline void __uaccess_disable_tco_async(void)
> +{
> +	if (static_branch_unlikely(&mte_async_mode))
> +		 __uaccess_disable_tco();
> +}
> +
> +static inline void __uaccess_enable_tco_async(void)
> +{
> +	if (static_branch_unlikely(&mte_async_mode))
> +		__uaccess_enable_tco();
> +}

I would add a comment here along the lines of what's in the commit log:
these functions disable tag checking only if in MTE async mode since the
sync mode generates exceptions synchronously and the nofault or
load_unaligned_zeropad can handle them.

> +
>  static inline void uaccess_disable_privileged(void)
>  {
>  	__uaccess_disable_tco();
> @@ -307,8 +322,10 @@ do {									\
>  do {									\
>  	int __gkn_err = 0;						\
>  									\
> +	__uaccess_enable_tco_async();					\
>  	__raw_get_mem("ldr", *((type *)(dst)),				\
>  		      (__force type *)(src), __gkn_err);		\
> +	__uaccess_disable_tco_async();					\
>  	if (unlikely(__gkn_err))					\
>  		goto err_label;						\
>  } while (0)
> @@ -379,9 +396,11 @@ do {									\
>  #define __put_kernel_nofault(dst, src, type, err_label)			\
>  do {									\
>  	int __pkn_err = 0;						\
> +	__uaccess_enable_tco_async();					\
>  									\

Nitpick: for consistency with the __get_kernel_nofault() function,
please move the empty line above __uaccess_enable_tco_async().

>  	__raw_put_mem("str", *((type *)(src)),				\
>  		      (__force type *)(dst), __pkn_err);		\
> +	__uaccess_disable_tco_async();					\
>  	if (unlikely(__pkn_err))					\
>  		goto err_label;						\
>  } while(0)

[...]

> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 92078e1eb627..60531afc706e 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -27,6 +27,10 @@ u64 gcr_kernel_excl __ro_after_init;
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
> @@ -170,6 +174,12 @@ void mte_enable_kernel_sync(void)
>  void mte_enable_kernel_async(void)
>  {
>  	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
> +
> +	/*
> +	 * This function is called on each active smp core, we do not
> +	 * to take cpu_hotplug_lock again.
> +	 */
> +	static_branch_enable_cpuslocked(&mte_async_mode);
>  }

Do we need to disable mte_async_mode in mte_enable_kernel_sync()? I
think currently that's only done at boot time but kasan may gain some
run-time features and change the mode dynamically.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210209113505.GD1435%40arm.com.
