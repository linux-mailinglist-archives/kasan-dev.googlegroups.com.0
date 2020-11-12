Return-Path: <kasan-dev+bncBDDL3KWR4EBRBYMHWT6QKGQEV4O2WXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 83D862B022C
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 10:44:02 +0100 (CET)
Received: by mail-ua1-x93f.google.com with SMTP id j44sf497223uag.0
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 01:44:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605174241; cv=pass;
        d=google.com; s=arc-20160816;
        b=NeuSY9Bap8sSeGXCX8VwlyF66DNU9MproUjB6d5kg/KHCEvt0p7YL6kYQb4uq7eQTQ
         Mm+27A/xjfg/iquVmw4qSvZr5FC1bhqEk8Bk1E9J5Me3QNRAPDj8mLcxQvCjYmKZJzt+
         JQUTb4S4GvGK+c7+mpnqj5Z37noZRb8mfuihxHJTGikZfHmU2jTsaldGR3gacm8uJwiX
         qMw/wFfjq/Pch+hi6MrryJgyuq+7EfMxmrzKMCgzLJtCsSDR44YxMSdXOANL1ZzBUfYX
         4nYWftnOkiwF55LqEPkVEIh0qV/iwAxjkiqu5av4J4qQ7oSPFOF+1FkhOhSKO/QXeeyV
         V6Xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=DN4BdlX8x779n0mmxHXLjTxpf7YdVj+qOPsp05FuNSc=;
        b=sF4e/wKjUQ5xUfiRwCcP7HAdNaKZhXYM8RAq1DSiVxKBDuXFPzhOA+d1diQk3FNGZw
         M1uTgkdINZdcI0DutAOYYimL1HT3EUrbaMzu6j5cK0FIeq/Ucu8OJJpdxhggXrqopP9s
         k5J0juh4fOW/ofBgg6gj26Ktzxaa0m+bx2mgxN+053Y5TQjlMhA2rsjPzZSz4IzuZ4jG
         y/ctOyPhiWRfFi6SoQ40I2bIEQBZXRzIERbOE/8CgYmfyYSZw2dGVMzW/3KVRNssff8+
         raMxcgN7+HL2T/NfyctBbtmcTpymaGjOFxkpHdx0lDDpMdAlTc3SfoS9Sl5LqcD5fnUk
         YqJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DN4BdlX8x779n0mmxHXLjTxpf7YdVj+qOPsp05FuNSc=;
        b=TyXfqF022IabDJVocbHVHQJuH/+kqPWHEpmZ/my8mOE8KZP1Dd1P7V0EuesBnYE9Cp
         uHQHxuiN0uywCEYc+JKtqrGoIJRa8VawLB9DfvLOdrAgP75PUxelz9xV2NIVID5B5xWF
         JTAAA1N3DbysaHMzlxW6K/64uYovGyAvJD1dj1i0odnwiDoqstg3yNm7OsH2YtHRl3ia
         hkuMz5apn1WL6LnbTKGkuiQpchJImTAv2aYNAXPjNCWuBjBo5Wkvo7qtcPDkWj6nDvoy
         0rcKhLdKGBdp2gDafzPtMMt5GJR6PcAfnNlvTkvBtyc6TLlHzzVXkQBhKunR9wZxFKnX
         oSiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DN4BdlX8x779n0mmxHXLjTxpf7YdVj+qOPsp05FuNSc=;
        b=g0+yBABOF3lOTNYJcxZgDSZHk0qCqjbyy6GsljR5L4UJ8WUtABtmr3LWzmuv7VnHdd
         62M6uxNOCfgp5T9nGPPJFgbK8+523rgSfpmU0oTlkd/2v+2sJukS/ROBLZKNcqqDFfs8
         oKKOcgorwNQcCpwyiUzAQey7VJVluIeEwhTwnR30PS1dHlcVpiYIAlPzFXYApqCJiFGV
         PW78g7uZZN43DuxayHAt85TZWfocufzwRQ0Rxxi6Fam90yBGquNskzqvyKix1+MzGmdR
         bOzr+IbLlp9yO/O1zzy8ePzHaC/8p1Q1FU+zha0bM5XSOLzBj1k9JuW1NpKVAllrCl3M
         s01g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533tdVhrVK7JVjTDVRCrLpcm57+4Q1RLTsIsJ2UVM6RXYwxU4J2e
	2yi3BO3DHJlx5qv2GjGS2h4=
X-Google-Smtp-Source: ABdhPJwTnhbWyVFbz8nfKc2HKn7zFz/ig5rgWdlhbNWnYasUlAsHIVN2rFSwc+XR3C90AYHaLzuesQ==
X-Received: by 2002:a05:6102:671:: with SMTP id z17mr18802092vsf.32.1605174241249;
        Thu, 12 Nov 2020 01:44:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2046:: with SMTP id q6ls336587vsr.3.gmail; Thu, 12
 Nov 2020 01:44:00 -0800 (PST)
X-Received: by 2002:a67:f8c5:: with SMTP id c5mr18903899vsp.18.1605174240697;
        Thu, 12 Nov 2020 01:44:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605174240; cv=none;
        d=google.com; s=arc-20160816;
        b=LDlBCV8wmFhroU62zrIAAAcFYFqIJdWGj1NI/dbnyyJGa94cPYliHYPc8ubb5+seG6
         3UgbMZ6gNAgfhDio5+lZWulGiJZoYCCj5xzKm1SCM7UY3GAyUGwu2atGvUgbiTmP5626
         PvvzBd8RhLiElM0UC/3uJ3CLSuAqq8h9Qj7zUe5YXVEJVDI9ir4XvPCpVxxGr1quQ9wS
         25MsoQyrEPcs0WD7FegdszkCy6CDLk7sWzk/ZmZ2vW6KcOI7ctyH3JaJI4poTKJh4h2P
         OellfIlTNup2xSrMXJL6rsobYSYCqPwk0cdvP0V4cq93H6Icbpd4lMsFyvWEuJtlJuqW
         gDgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=ZPfHV/Ph4FCRy8P688ml9F+cV6ia0T5YxNnRImvvH8w=;
        b=vfqcPuq40NmXrPrUgVFBct/SROZETEJfiDxJptBttlbNLAw+bIhqznkJykV3x5coWO
         17Zn3wj6JtmKMt8iIUqgfaspYBtMtIqUT12T9jZ+mhca0Z1lvYVaBIIZw6liicnrtFH8
         wZWb7MlVEnIRD63xe/8GPyHj/q8AQkgLGtrgUFA3uMwwqQnOOWj/3lHI0pFH6kbJ8uIy
         JypDJLwex9E2Oh0pVJJr774eJUEn6qEIu+PdkkcptdYFdTk6ndUaHpQgOHOFXk4HI7aZ
         j6W5itUutdTTpK1GHKh0HCDJ5MWFh+5Ifnb1h+4xmwHP5rjPItWgGYBp0Tmw+uRukucm
         RX5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k3si424817vkg.3.2020.11.12.01.44.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Nov 2020 01:44:00 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id F12DD21D40;
	Thu, 12 Nov 2020 09:43:56 +0000 (UTC)
Date: Thu, 12 Nov 2020 09:43:54 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v9 30/44] arm64: kasan: Allow enabling in-kernel MTE
Message-ID: <20201112094354.GF29613@gaia>
References: <cover.1605046192.git.andreyknvl@google.com>
 <5ce2fc45920e59623a4a9d8d39b6c96792f1e055.1605046192.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5ce2fc45920e59623a4a9d8d39b6c96792f1e055.1605046192.git.andreyknvl@google.com>
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

On Tue, Nov 10, 2020 at 11:10:27PM +0100, Andrey Konovalov wrote:
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> Hardware tag-based KASAN relies on Memory Tagging Extension (MTE)
> feature and requires it to be enabled. MTE supports
> 
> This patch adds a new mte_init_tags() helper, that enables MTE in
> Synchronous mode in EL1 and is intended to be called from KASAN runtime
> during initialization.

There's no mte_init_tags() in this function.

> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 600b26d65b41..7f477991a6cf 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -129,6 +129,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>  	return ptr;
>  }
>  
> +void mte_enable(void)
> +{
> +	/* Enable MTE Sync Mode for EL1. */
> +	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> +	isb();
> +}

Nitpick: maybe rename this to mte_enable_kernel() since MTE is already
enabled for user apps.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201112094354.GF29613%40gaia.
