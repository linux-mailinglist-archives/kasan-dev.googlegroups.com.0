Return-Path: <kasan-dev+bncBDA2PU6QWEARBGFU5GFAMGQER47FIBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FA654204BF
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Oct 2021 03:34:17 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id s10-20020a1cf20a000000b0030d66991388sf1658697wmc.7
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Oct 2021 18:34:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633311257; cv=pass;
        d=google.com; s=arc-20160816;
        b=RH6tC2X1X5R1d6bVIx2kMMqF/QsjObgmcwmK0eo11aKPAKs14yMZt8dRw9piXXpd6L
         Ld6Wj2dkmnxVK72aW7n3WK6K7b5C5rypMiUMQvzj7ePHi9FzE7NfkRRWpucD68j3xdfY
         JhxWODpbLQZ/xxm66n/ZAKi0T/d1pCtmIeYY58GGQ8PMI/kyHV4CDMUajc+4kHDaPC6h
         CSYHPwMk0WZpiTyVhItEaHmco66oU5YSlX91C2ws1jWTDe3sFP4PrFpKGQh4csYoANM/
         AZHWwnZnIlwVB5JtEl4Ds3k0XFDD7t1K/wxGmkaic8qvuz87rDW1TTbGigTbxVgzStYK
         c0cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:cc:references:to
         :subject:sender:dkim-signature;
        bh=fG0rmfLJa3iiNfBbfmx1sljnnK+3Cb8qP1C3CwUl5bw=;
        b=N3dSFowH6CKQFxzHmbfQCJhxDKxrmXPtkDwu3eC49H2VxvQ8zxPayqTl+26/OVYGIO
         uSMOByPBiJh+YiJVQwWvLHinlleH6Qp8MdHqsjzV1+mq2vjC1k78kCeKXlc2EM5Yr+3V
         wJ1mUkTxNqrKW5zdECaw18822wRCD8ZHyT6kzYja9XhYAPwSGFyy9Z5ezqG8GR/k0Coy
         saFmzdUzkqK3Gc3XVnLp4RnbcR07v/EPaoRRSsmD5UhEelis34GBamnriDZEuGQ1kFya
         3I7iBTU9Fj71NZ+oYuo7xXXteCG9Suq041Wa5SJRmdoWpppMDqAfeBXMGnCdSyDNwrir
         DsHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sholland.org header.s=fm3 header.b=EjcmciBX;
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=YC6izWu0;
       spf=pass (google.com: domain of samuel@sholland.org designates 64.147.123.18 as permitted sender) smtp.mailfrom=samuel@sholland.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:references:cc:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fG0rmfLJa3iiNfBbfmx1sljnnK+3Cb8qP1C3CwUl5bw=;
        b=ty/PX5lm1Bc/5sqCcIIcnK5hGtZmRkPWjyBnhxw3eT7ZzZBET/kDUaYttAo6E8NSnn
         PfIW580n4cCj9o9njWixNhTDw3wWMhyKGndwQ1VXWKiAPbXCAvIJLgU1TMfr0Rt5sBBm
         tOJuy0GJND6jBCti/RstPAGWHyVVhpHFue0bE1ZpTfp0HDJTwA5Lj6H3XUzwDxUMg2HW
         AeMwdWay1LhGCRF8fkfx1pUnKotHiq+IiizZXaxmVHBooDtrDQ9olrWqiUhzEaqO2nDB
         8nmb9q96qrbDbE4Z9L15Yc/gtsWpDYMZbtGzuIZakDg1R/gpIn4p/KSSyE8E3hkfUuNW
         xTag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:references:cc:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fG0rmfLJa3iiNfBbfmx1sljnnK+3Cb8qP1C3CwUl5bw=;
        b=KvYTIFr6+U9GWIdOUzOz4I8lbmzQZM7HUhghdHYaibNMDsyCySzN6Lp+1hErEpEZAE
         RQsutEH2TA5PfO5x80nfToZpeMAJEfCWwGOfNR2HbNqiDCyttkXj5YtPznvrFgZb66ES
         rFnqxCkOin94ulVgjM3CRp/GSgwZG9qjKgzxw6Q3SiogecghfaBIT9BK3SkRcZBwmCSp
         BMhBcUytqCGH7rALrSAWYPM1C/HJhVbF/ZWYFesHhBpjMjUnEEMA6wX12fdnMrh42HpJ
         RiN8KwU/C4RDi4EcpX7aL8EY7OIRem9d4NvQFBa+uP8PGja21jkE7o3y/av3S19kv6W7
         gt9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533A+T4AY07QQUbfsoWkfRVmHVRi2NfYtL/1pVyxaPFErBxnnw6e
	bzwW0APASuhH/tc+6TIOWGA=
X-Google-Smtp-Source: ABdhPJw61dKNys9uTGv4T08Mjw1m02cT1DjnkehSyffnGFw4y1jH/1Xf+1wKDqcskxSdDtIAMzaBZQ==
X-Received: by 2002:adf:a101:: with SMTP id o1mr10811649wro.379.1633311257082;
        Sun, 03 Oct 2021 18:34:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:8b92:: with SMTP id o18ls21483244wra.0.gmail; Sun, 03
 Oct 2021 18:34:16 -0700 (PDT)
X-Received: by 2002:adf:a29d:: with SMTP id s29mr8291728wra.231.1633311256278;
        Sun, 03 Oct 2021 18:34:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633311256; cv=none;
        d=google.com; s=arc-20160816;
        b=H5L9NQpL1KrR3kTDVnHjLYmblbBVmnteGzP6BdgSjxjjOE3RicYgWdPliYOTW48qCr
         u9gH7VY5cdcXqQf7+5JbK0gWtX8XiTzrr5NcUZcasvajuZZDhhPWDc6c9bWhwhgZYe2X
         fMCsME9AOGOUB7O55fdSLxYx6aJzg/2iYb5hyyxutuVmbZm+QNUOk0Oy0OmtcVaXreOI
         dep0sQhZ41FsDFmKRu/T6ayzr4w7HRoeNrMgnVnDjYkSkUWg4OE0Pr0Dktn/HfCMS+rK
         yEjHe1oQOlaCuCrSNCoLV6RGwaOqL8T0DLKN2EZ99y2Ix5LuR7Quvbin95dwjpf/G++u
         gPaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:cc:references:to:subject
         :dkim-signature:dkim-signature;
        bh=j08sh6m6YgSaQWXZPVhA3JZmyLlucPN/yEkWrIr4Uc0=;
        b=TVtjdOtlsXyHURXBrvrUSYvSfIG29NE8oKnAiUFNtiHPXt+YfZdZtSUKqnxYjtR+9v
         ET6E5J5p0P4yCLWX53XvOxCQ+XYOsCHsNzYCHE3l+4lE+ZJpYNe357avyrQoqxhM19Ig
         Lotsf/pyPZvHE9rqOGAMdUbbM0W2oJP9uzVkSuoohB8ut1NB+iM3awSH1lRfEZb/UfOG
         kB1INBE2I+cT5iSUxT5kZ7lK6NkxJglpzUfaNP6JVgSp15Gzi9f3SH7eyb0rvFYNq7l6
         2F7FkaeiEV2T1ktGQKaUX/GfnZqySd3LpEVSOzErYa1fuK5FIdPIb4R6fcpxDiJTAHJ7
         7xkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sholland.org header.s=fm3 header.b=EjcmciBX;
       dkim=pass header.i=@messagingengine.com header.s=fm1 header.b=YC6izWu0;
       spf=pass (google.com: domain of samuel@sholland.org designates 64.147.123.18 as permitted sender) smtp.mailfrom=samuel@sholland.org
Received: from wnew4-smtp.messagingengine.com (wnew4-smtp.messagingengine.com. [64.147.123.18])
        by gmr-mx.google.com with ESMTPS id g8si769332wrh.0.2021.10.03.18.34.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 03 Oct 2021 18:34:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel@sholland.org designates 64.147.123.18 as permitted sender) client-ip=64.147.123.18;
Received: from compute4.internal (compute4.nyi.internal [10.202.2.44])
	by mailnew.west.internal (Postfix) with ESMTP id 2F73A2B012EA;
	Sun,  3 Oct 2021 21:34:13 -0400 (EDT)
Received: from mailfrontend2 ([10.202.2.163])
  by compute4.internal (MEProxy); Sun, 03 Oct 2021 21:34:14 -0400
X-ME-Sender: <xms:E1paYc1__yfUYN85tBFlf72T7I1jqtG8d0yBiLWQrQMdN5ebn0lL3w>
    <xme:E1paYXG0jXORCRdVxXIEoUldnVdUZ9-NV51DGwmp2RrYQVPV-S9EsUpoF9cL3SLMn
    gt6mI6pVunQPNUD8A>
X-ME-Received: <xmr:E1paYU6y_9AKaPRO0DydJIqpi-eNzSWzNyW2C_hfAiQvd2upjRqNZFzsJVVOgS314Xr9ZcJDQ7PIZSb0EGAsL0X8wTYe6yY_Kx6a2kunrTpjL-l3aqWRS2V8MA>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvtddrudeluddggeeiucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepuffvfhfhkffffgggjggtgfesthejredttdefjeenucfhrhhomhepufgrmhhu
    vghlucfjohhllhgrnhguuceoshgrmhhuvghlsehshhholhhlrghnugdrohhrgheqnecugg
    ftrfgrthhtvghrnhepgfevffetleehffejueekvdekvdeitdehveegfeekheeuieeiueet
    uefgtedtgeegnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrh
    homhepshgrmhhuvghlsehshhholhhlrghnugdrohhrgh
X-ME-Proxy: <xmx:E1paYV1r3P_dvbSWePjc29cvvEWXFXN_ST5zIbpEPxJBZKODWiJg5g>
    <xmx:E1paYfEIT9WVE1jLcCr3siueJ7uhD9Jjw7DJRQzmJNQs8z1hFiummw>
    <xmx:E1paYe_wwZGRhioAsm199qxDzvYAafosWWiaQjXxjiQ7BlJUzHNBfQ>
    <xmx:FFpaYemw4ofYc9WS4pEaHrrRkD84RolIzYf9F3aJI6S2r_8jmQPaT8zgwwo>
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Sun,
 3 Oct 2021 21:34:10 -0400 (EDT)
Subject: Re: [PATCH v2 04/10] riscv: Implement sv48 support
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>
References: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
 <20210929145113.1935778-5-alexandre.ghiti@canonical.com>
Cc: Jonathan Corbet <corbet@lwn.net>, Paul Walmsley
 <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>,
 Albert Ou <aou@eecs.berkeley.edu>, Zong Li <zong.li@sifive.com>,
 Anup Patel <anup@brainfault.org>, Atish Patra <Atish.Patra@wdc.com>,
 Christoph Hellwig <hch@lst.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Ard Biesheuvel <ardb@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
 Kees Cook <keescook@chromium.org>, Guo Ren <guoren@linux.alibaba.com>,
 Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
 Mayuresh Chitale <mchitale@ventanamicro.com>, linux-doc@vger.kernel.org,
 linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-efi@vger.kernel.org,
 linux-arch@vger.kernel.org
From: Samuel Holland <samuel@sholland.org>
Message-ID: <748a2c58-4d69-6457-0aa5-89797cb45a5c@sholland.org>
Date: Sun, 3 Oct 2021 20:34:10 -0500
User-Agent: Mozilla/5.0 (X11; Linux ppc64; rv:78.0) Gecko/20100101
 Thunderbird/78.10.2
MIME-Version: 1.0
In-Reply-To: <20210929145113.1935778-5-alexandre.ghiti@canonical.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: samuel@sholland.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sholland.org header.s=fm3 header.b=EjcmciBX;       dkim=pass
 header.i=@messagingengine.com header.s=fm1 header.b=YC6izWu0;       spf=pass
 (google.com: domain of samuel@sholland.org designates 64.147.123.18 as
 permitted sender) smtp.mailfrom=samuel@sholland.org
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

On 9/29/21 9:51 AM, Alexandre Ghiti wrote:
> By adding a new 4th level of page table, give the possibility to 64bit
> kernel to address 2^48 bytes of virtual address: in practice, that offers
> 128TB of virtual address space to userspace and allows up to 64TB of
> physical memory.
> 
> If the underlying hardware does not support sv48, we will automatically
> fallback to a standard 3-level page table by folding the new PUD level into
> PGDIR level. In order to detect HW capabilities at runtime, we
> use SATP feature that ignores writes with an unsupported mode.
> 
> Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> ---
>  arch/riscv/Kconfig                      |   4 +-
>  arch/riscv/include/asm/csr.h            |   3 +-
>  arch/riscv/include/asm/fixmap.h         |   1 +
>  arch/riscv/include/asm/kasan.h          |   2 +-
>  arch/riscv/include/asm/page.h           |  10 +
>  arch/riscv/include/asm/pgalloc.h        |  40 ++++
>  arch/riscv/include/asm/pgtable-64.h     | 108 ++++++++++-
>  arch/riscv/include/asm/pgtable.h        |  13 +-
>  arch/riscv/kernel/head.S                |   3 +-
>  arch/riscv/mm/context.c                 |   4 +-
>  arch/riscv/mm/init.c                    | 237 ++++++++++++++++++++----
>  arch/riscv/mm/kasan_init.c              |  91 +++++++--
>  drivers/firmware/efi/libstub/efi-stub.c |   2 +
>  13 files changed, 453 insertions(+), 65 deletions(-)
> 
> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> index 13e9c4298fbc..69c5533955ed 100644
> --- a/arch/riscv/Kconfig
> +++ b/arch/riscv/Kconfig
> @@ -149,7 +149,7 @@ config PAGE_OFFSET
>  	hex
>  	default 0xC0000000 if 32BIT
>  	default 0x80000000 if 64BIT && !MMU
> -	default 0xffffffe000000000 if 64BIT
> +	default 0xffffc00000000000 if 64BIT
>  
>  config ARCH_FLATMEM_ENABLE
>  	def_bool !NUMA
> @@ -197,7 +197,7 @@ config FIX_EARLYCON_MEM
>  
>  config PGTABLE_LEVELS
>  	int
> -	default 3 if 64BIT
> +	default 4 if 64BIT
>  	default 2
>  
>  config LOCKDEP_SUPPORT
> diff --git a/arch/riscv/include/asm/csr.h b/arch/riscv/include/asm/csr.h
> index 87ac65696871..3fdb971c7896 100644
> --- a/arch/riscv/include/asm/csr.h
> +++ b/arch/riscv/include/asm/csr.h
> @@ -40,14 +40,13 @@
>  #ifndef CONFIG_64BIT
>  #define SATP_PPN	_AC(0x003FFFFF, UL)
>  #define SATP_MODE_32	_AC(0x80000000, UL)
> -#define SATP_MODE	SATP_MODE_32
>  #define SATP_ASID_BITS	9
>  #define SATP_ASID_SHIFT	22
>  #define SATP_ASID_MASK	_AC(0x1FF, UL)
>  #else
>  #define SATP_PPN	_AC(0x00000FFFFFFFFFFF, UL)
>  #define SATP_MODE_39	_AC(0x8000000000000000, UL)
> -#define SATP_MODE	SATP_MODE_39
> +#define SATP_MODE_48	_AC(0x9000000000000000, UL)
>  #define SATP_ASID_BITS	16
>  #define SATP_ASID_SHIFT	44
>  #define SATP_ASID_MASK	_AC(0xFFFF, UL)
> diff --git a/arch/riscv/include/asm/fixmap.h b/arch/riscv/include/asm/fixmap.h
> index 54cbf07fb4e9..58a718573ad6 100644
> --- a/arch/riscv/include/asm/fixmap.h
> +++ b/arch/riscv/include/asm/fixmap.h
> @@ -24,6 +24,7 @@ enum fixed_addresses {
>  	FIX_HOLE,
>  	FIX_PTE,
>  	FIX_PMD,
> +	FIX_PUD,
>  	FIX_TEXT_POKE1,
>  	FIX_TEXT_POKE0,
>  	FIX_EARLYCON_MEM_BASE,
> diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
> index a2b3d9cdbc86..1dcf5fa93aa0 100644
> --- a/arch/riscv/include/asm/kasan.h
> +++ b/arch/riscv/include/asm/kasan.h
> @@ -27,7 +27,7 @@
>   */
>  #define KASAN_SHADOW_SCALE_SHIFT	3
>  
> -#define KASAN_SHADOW_SIZE	(UL(1) << ((CONFIG_VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
> +#define KASAN_SHADOW_SIZE	(UL(1) << ((VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))

Does this change belong in patch 1, where you remove CONFIG_VA_BITS?

Regards,
Samuel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/748a2c58-4d69-6457-0aa5-89797cb45a5c%40sholland.org.
