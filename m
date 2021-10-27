Return-Path: <kasan-dev+bncBCRKNY4WZECBB4NW46FQMGQEKHVRPVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C6B943D729
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 01:06:27 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e10-20020a92194a000000b00258acd999afsf2821553ilm.16
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Oct 2021 16:06:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635375986; cv=pass;
        d=google.com; s=arc-20160816;
        b=VwQ0GHZ0linRB+MhGkZ1Vq2PebxjXHNrFG7tDbfuSjgbThVHzMMI9mjz3XMxnG5ZEH
         esQ/M6mNAyVxLMIpcR2QpBLGKU13EJqLaDGl5IJktq4zSL+zHl9QMOQTYRt4bTnpkgFp
         CoD8XGN+xS8PkGbFc/D7r+u/JVkV0jw6OsEBhrkMNJeOPaV6Oyaeu+Zai2ovPTr/fHKV
         enRQRDNNG1cF6OLI8j3C/hBtkSqsPJKn5OWATtaXIZVDNdZSC5+7E+wjSLBcSgmRv66b
         Nrwqi3WsuBkU99nbdmK9MEaaov15f8/fbP+awoiYnZjjZ5hjT2br5teuYy2rXQXOmPz+
         pa5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=nG1HURXkh99wlnCIfykDiMj8zwKdvJdpcBQiSzZwkFI=;
        b=gNKE+XxGbLSubOd99ZmzpX87W3JSAjkppG4wDQfhAs5IkZXF0Nt7jObnSFDagqcwu6
         EQUxvL8yEvdhyVHu+wJD1/yAnawkkVOksoRo17/LjPQpCqVSkabpyofFh6CCGNd/RvWU
         mvPHvn8ams4vD3bCmkpnd1OjN+YeEcw42LiEBUnFnTxZPZDzB/AZBfAjEd8QEFjnt+q7
         tDVkph7iLthynv6FrCAsehydLUvFfoK6ERGeQb0KZ3pAmuMV64y4Y2LI/p9fjTaY/h/l
         MYEh3OiwakmRAxiM11qCJyh5GI3tZ4/7OaYX7axzJ+gwOrcQf0uzSort0j314S1+RpUA
         nsLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=7y5UZL3r;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nG1HURXkh99wlnCIfykDiMj8zwKdvJdpcBQiSzZwkFI=;
        b=OCsOMlOy41i3wVHUl2DErPEcJG/39pRL15eAxHvxYYqB+4ChDEgaoq6EAde2vNz4Ow
         vSTz+MFRi7e+1CiA1BfJ2H1dDBBhtg8t1HFcgnQ1EQ0w7ZQmZrZmL/5b+Z9Z+qMHeFMk
         B8P/7EK13jZJ8u1ikSLb3R5V1LSPi0ndApRcvzB2mI2NY9bZ4IUHoLHi6o4CtblWvJkN
         fX1muoFVcTS0VCQhb1G3su/RfOG3tDfJVBNjZjr5CjeQ0GL5hxlv0FVxUEZaOQz5BSUL
         Sow1+rnuiNn27vlb9NEZPqPR4rc8WecLkdvec2NDs/XYP8T0fsvJoPQykM2YIHiGWEus
         /GUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nG1HURXkh99wlnCIfykDiMj8zwKdvJdpcBQiSzZwkFI=;
        b=3ZU6fWJmaIqZNnkv57qNT4rfPcNrWjpi6Eenyd/Wc2By/HDELV75leSM05K/a8TIEp
         VZbsgaNxmWfwECsS1D3oQVMjO6IEM/ERQN2C2g7u1zIcsypj587Qt3k+g9HEk3vp79O9
         u5eTy4WXyfABLIpU4egMdf2Cj1AK3E7m+jU8dAD1UZP7qbDN4+MhJB+yz+LSkdyaAf9h
         FO7fWqqKz61SUMn5VKMXgdvrhxJDsvOvU57cPbsQ5PyCNtVikKfqlVtRaaT7dfoEfpmK
         HXjBZkUaDcNmfYzI/YadGsDjk1JHHOxxlKkK+HUfxhT0WSgESsyyS4f1QAR+wWGtd440
         Ibbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XnOVj/W8OSH1v4Cc4vgzOTK2QBbpTBMA5/E3dKg+FB+IUSM1v
	ZseJKXeb712GeB1oNa8V6zk=
X-Google-Smtp-Source: ABdhPJzp8MrQtx6NVdk9fNOFMpsvK24uWJPw9WdksPZbu436upby46YxjwWbeo9CRU+cS6OLKir2HA==
X-Received: by 2002:a05:6638:168e:: with SMTP id f14mr528386jat.134.1635375985891;
        Wed, 27 Oct 2021 16:06:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a61:: with SMTP id w1ls384679ilv.9.gmail; Wed, 27
 Oct 2021 16:06:25 -0700 (PDT)
X-Received: by 2002:a05:6e02:12e2:: with SMTP id l2mr491033iln.202.1635375985509;
        Wed, 27 Oct 2021 16:06:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635375985; cv=none;
        d=google.com; s=arc-20160816;
        b=CU+OZ6zIWShAlHKyIRsywYuEzK8AoljU+QrjLrCdnxhvQ5DGAi49kxo0Sy2Ow8buVw
         1W3SEoraakkriocl8Oy6rgtFj6r4uxj/pTNoRLsjbCivxRt51UFM7nvZbnUIY4HhV4ff
         9aa1hA2o2GdRg9aXjeHyK+vxkhlT6spYWUvjTzncuyxbbCYYW4rbhv9zmvlW6jhld5i/
         r/YrrEkvdIElJ2VNun7KTtPw9hnSPLu0xnh84JEhT6k8+iP8rGRK+s7dsbbS+5u9OzIv
         VBHYZamka1kUnlTzycFKTAmhgl4CWuaGYgVUJElRgelJ4fXloVxeydaU/E2n9HLjqijY
         nc9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=qq3Zte+b3gvW8aVUSoj11hufNXWtcNy5WKvRt4opsbo=;
        b=EoUe4KMIhVS82CmsoZ5SDBWasfP0Hl1c+4VqxBqg4E4+rXl+6E4Qgb4+8wtTWdmr2n
         G9Yql9+viToBTnh+obvfc0JJgtumPHSAZRKRuQedZ4K0UEPKNKOSs0RQpIXVtAH4ZRrk
         4qwKfWS9Yi8dspG6sH4u2G9G6b7ukZ9jcj8GQkCRmywYFs9IuU2zEWyXQTV5X6ZFMrn0
         ha8DCzin6xiHDh34KM03CwTre/+bfQ+7Nq9rE/qmGIj+x4vEVOM3uNIU6+AXEg7ZlO8C
         8fC8kZpFICRl2BiFsMcwuwwfuH82mQ+00+C0pfv1ZU5Jlw7iwzptNjO0va4+gY3rf7Pm
         8pRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=7y5UZL3r;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id d20si127861ioy.2.2021.10.27.16.06.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Oct 2021 16:06:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id m21so4425423pgu.13
        for <kasan-dev@googlegroups.com>; Wed, 27 Oct 2021 16:06:25 -0700 (PDT)
X-Received: by 2002:a63:84c6:: with SMTP id k189mr479739pgd.245.1635375984652;
        Wed, 27 Oct 2021 16:06:24 -0700 (PDT)
Received: from localhost ([2620:0:1000:5e10:60fc:a50:6d27:9fd3])
        by smtp.gmail.com with ESMTPSA id j1sm751742pgb.5.2021.10.27.16.06.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Oct 2021 16:06:24 -0700 (PDT)
Date: Wed, 27 Oct 2021 16:06:24 -0700 (PDT)
Subject: Re: [PATCH 1/2] riscv: Fix asan-stack clang build
In-Reply-To: <20211027045843.1770770-1-alexandre.ghiti@canonical.com>
CC: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
  linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
  alexandre.ghiti@canonical.com, nathan@kernel.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alexandre.ghiti@canonical.com
Message-ID: <mhng-41b64d3e-5a5a-4d59-86fc-80f2148823e8@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b=7y5UZL3r;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Tue, 26 Oct 2021 21:58:42 PDT (-0700), alexandre.ghiti@canonical.com wrote:
> Nathan reported that because KASAN_SHADOW_OFFSET was not defined in
> Kconfig, it prevents asan-stack from getting disabled with clang even
> when CONFIG_KASAN_STACK is disabled: fix this by defining the
> corresponding config.
>
> Reported-by: Nathan Chancellor <nathan@kernel.org>
> Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> ---
>  arch/riscv/Kconfig             | 6 ++++++
>  arch/riscv/include/asm/kasan.h | 3 +--
>  arch/riscv/mm/kasan_init.c     | 3 +++
>  3 files changed, 10 insertions(+), 2 deletions(-)
>
> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> index c1abbc876e5b..79250b1ed54e 100644
> --- a/arch/riscv/Kconfig
> +++ b/arch/riscv/Kconfig
> @@ -162,6 +162,12 @@ config PAGE_OFFSET
>  	default 0xffffffff80000000 if 64BIT && MAXPHYSMEM_2GB
>  	default 0xffffffe000000000 if 64BIT && MAXPHYSMEM_128GB
>
> +config KASAN_SHADOW_OFFSET
> +	hex
> +	depends on KASAN_GENERIC
> +	default 0xdfffffc800000000 if 64BIT
> +	default 0xffffffff if 32BIT

I thought I posted this somewhere, but this is exactly what my first 
guess was.  The problem is that it's hanging on boot for me.  I don't 
really have anything exotic going on, it's just a defconfig with 
CONFIG_KASAN=y running in QEMU.

Does this boot for you?

> +
>  config ARCH_FLATMEM_ENABLE
>  	def_bool !NUMA
>
> diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
> index a2b3d9cdbc86..b00f503ec124 100644
> --- a/arch/riscv/include/asm/kasan.h
> +++ b/arch/riscv/include/asm/kasan.h
> @@ -30,8 +30,7 @@
>  #define KASAN_SHADOW_SIZE	(UL(1) << ((CONFIG_VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
>  #define KASAN_SHADOW_START	KERN_VIRT_START
>  #define KASAN_SHADOW_END	(KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
> -#define KASAN_SHADOW_OFFSET	(KASAN_SHADOW_END - (1ULL << \
> -					(64 - KASAN_SHADOW_SCALE_SHIFT)))
> +#define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>
>  void kasan_init(void);
>  asmlinkage void kasan_early_init(void);
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index d7189c8714a9..8175e98b9073 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -17,6 +17,9 @@ asmlinkage void __init kasan_early_init(void)
>  	uintptr_t i;
>  	pgd_t *pgd = early_pg_dir + pgd_index(KASAN_SHADOW_START);
>
> +	BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
> +		KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
> +
>  	for (i = 0; i < PTRS_PER_PTE; ++i)
>  		set_pte(kasan_early_shadow_pte + i,
>  			mk_pte(virt_to_page(kasan_early_shadow_page),

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-41b64d3e-5a5a-4d59-86fc-80f2148823e8%40palmerdabbelt-glaptop.
