Return-Path: <kasan-dev+bncBAABBOPTXCGQMGQELUW5NNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id C20D646A14F
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 17:26:33 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id s16-20020a2ea710000000b0021b674e9347sf3669016lje.8
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 08:26:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638807993; cv=pass;
        d=google.com; s=arc-20160816;
        b=hXOtPYUxwAWfNEB59imn/DEEBq/8NAwnuLrlnQE+KL+YsdU+z3em4GOpiVSsG6fVsG
         lYA4lNpQi+mX0DJi79XBor3LrQUoIey7Eii7sHVlps/kaIX2oULtyFBXWukRYVo/balC
         iF28G5/JFNHLFKn93VNjCc7a3mj35Igxs29npjIBoFf1eH0y+vum839QwA0JqgWJQ92n
         DqsQN2xbxTr6SMJFexpLNqQM1ngIlN1ekiWBRX2aaurDN+MbefpQ2VCCVD4hcdfzNl3j
         FsPQ+hfG1ym0QTQd1PU36clOSK9OIrv8RV0RIYvRoOdqeY5eo7jqnNN/7Athenl137uo
         poAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:mime-version:references
         :in-reply-to:subject:cc:to:from:date:sender:dkim-signature;
        bh=0jCTXe5S4aey+rXqRNC45tcdOnPTxLser0eO4fZpwok=;
        b=fgtiUqod02LpsSmIVOYuOnelh6XaCDe7b2Y/IsDBAGh05erZjMg1m26kLcXLTUXD/9
         4dXlW31ac/YxkGJBL2sXtXU0bSMY7SG/URclQyLFdL0DlEKwF5CPqukwQs3S3SwFlmM7
         M1Jw+W20vRjByfO6TfqkXnf0qrFDVxPI3FMEx962WHitBC6o5YhE6jrrZ6S1sz8C1+SN
         VpQDmrRYy1aC36kV/jccZO7O4JFFcLoTbgGsg/PBtRtGVs9Y0FBQCi5OIwIWNyMR62RG
         kwaxjjhBZSwQWDngKxzK8z5JZGgGQY/ID6rSFHuYyva/hdAdW+UEngzgFXPfPmXCCp3t
         B9Yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sckZAMuU;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:in-reply-to:references:mime-version
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0jCTXe5S4aey+rXqRNC45tcdOnPTxLser0eO4fZpwok=;
        b=Wo8y+CHBbY5azfCvLytfjp6RAP9GWrDBKp/ZQ/gFu9CwMhN+5u6JxXOprtlDHSUefQ
         0RGuxt3lxXK8NNTyT0ZSjxHa/lHcha7COEu0FcxOz59FzVV8QfvHdWwyF8tBEiM+MT/8
         5V7k6YmzK5/KhvTtNkykP/pYyI1grtvLtyhriONNLmTjHkBeWPj1PtCGUhKwCtBuRifZ
         GTtF/0SV4Hwh/K+9re5RHy4T+Cp7W73aUMWk/X9jYCcjBGdPGa/PeYLYKf4K9IZxOdsC
         qXgQarqRp0WB6rh639/AXWXao2mjB5bSfP3QrPKGmlMvGRUJgcdJSJ/gOU7Um6DHJcvh
         olKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :references:mime-version:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0jCTXe5S4aey+rXqRNC45tcdOnPTxLser0eO4fZpwok=;
        b=inM7bk0peqHq8yUS8FYl+hoFnYBXVDWGyhkUwWgk7HHTz/R8VrC4h7IDWaTkvJ4OAU
         6CYuzdpdWH4TKyulU75C4mbY99AsyFwKAqKm+aFsoBMd3P1UFNeG4JxkCgfqMlU/1nUZ
         I0JS/ZagYIyd6iosYsjRSXGOJQ4QOSnmsBm9uKu+y1xGsZWO+4Bk0ZIM59q+4Ub88DSg
         dB/E0bQ7F4E9crfGfxRFRZ/35QwzSa6ozw8IsBSNCGuSDjx8FiytHnBXVFqJl7CdoDaK
         8rQnI3LkZaaYm/IVaorayhDGwjYHq+MIc6q82etQCvzKTRdPO3Yrpe3c1yheiFQuWixu
         jdqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+irRyv6gHvD+vdRpHeFahvKSNe4/NzVZDFldfOAvMBMWPqnRG
	ne02cD/eGhty6TfMa0G7uAo=
X-Google-Smtp-Source: ABdhPJxKRgaECAs6JeD19sOlgDW8jI/hAlY6OsFTsAQOYfss9bE9Eye0VL+GgQm1FHYdoaM+qRm6Rw==
X-Received: by 2002:a05:6512:344d:: with SMTP id j13mr38268160lfr.347.1638807993332;
        Mon, 06 Dec 2021 08:26:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc09:: with SMTP id b9ls2687101ljf.2.gmail; Mon, 06 Dec
 2021 08:26:32 -0800 (PST)
X-Received: by 2002:a05:651c:4c9:: with SMTP id e9mr37728652lji.10.1638807992516;
        Mon, 06 Dec 2021 08:26:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638807992; cv=none;
        d=google.com; s=arc-20160816;
        b=y6NcXVjTalWwoN4D4m1/8u/jt4Zk6XABQyLaFsrAf7g+RC+bCgiZA1BX52hSZceLOE
         tjW6FPFjW31P46i/a8U9g4xjLIYjgihMLm7cC+fLXVOk0BYGx2NSR9pHUkBVasiHZZ8J
         0LcdjnuSA2TNF/nPzkpsUtJI408o/nT6M/ELJax86Jyjie+vm1o4ctgK4YFw3MH8GSC/
         yzs5+jiTF2ox+3ZEr67d5TiIGwdcIU89wuMHO87JXWQnnAh/RSBEvIt0wJi0wzdC9bl9
         Mq6DEq4DqERGpY7Lpa55RQzbfhsnmeab1Cjnub5GSY6GS8ValNssMxAXjs4gYpHrnrzH
         jGcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:content-transfer-encoding:mime-version:references
         :in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=iXAzfbTSlU6SRN8zIk+0x0/o02jMqQ65ltDM0wm5akw=;
        b=EYliqCmd9pzvAS1HkhWdveZTYgOPAUXKa0Qymxprd24Ta4mbKQOeXWd1o3T0/wPEFW
         v7tQ1yAEyRDUto+zdmzPkfTrxiJmCXZQHp7jmd0D5SfOGLj2SnEaEkW1RviQPCyXZWD3
         grgW02YEuOS5KqzsvFLTDgArt5YYwEzADfcXRXdoMco+3YNHWXa9hJ9yhbSu+7krgLPZ
         Og2vXSj7I6o+GpvYSNXkpCx3A5Rd6HmoueocqrgOKUICxVp0Fzie5yEVk4ZLZqCAZ0a9
         1WySriA7XyazhkpX76CU8LH3bJCC+E5g0DY/j/KLdwE9tY35lwK9Xj7S2jL3JcAUmi7M
         JyMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sckZAMuU;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id u13si132316lff.9.2021.12.06.08.26.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 06 Dec 2021 08:26:32 -0800 (PST)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 9080DB81118;
	Mon,  6 Dec 2021 16:26:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F1EF4C341C2;
	Mon,  6 Dec 2021 16:26:24 +0000 (UTC)
Date: Tue, 7 Dec 2021 00:18:54 +0800
From: Jisheng Zhang <jszhang@kernel.org>
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Jonathan Corbet <corbet@lwn.net>, Paul Walmsley
 <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou
 <aou@eecs.berkeley.edu>, Zong Li <zong.li@sifive.com>, Anup Patel
 <anup@brainfault.org>, Atish Patra <Atish.Patra@rivosinc.com>, Christoph
 Hellwig <hch@lst.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander
 Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Ard Biesheuvel <ardb@kernel.org>, Arnd
 Bergmann <arnd@arndb.de>, Kees Cook <keescook@chromium.org>, Guo Ren
 <guoren@linux.alibaba.com>, Heinrich Schuchardt
 <heinrich.schuchardt@canonical.com>, Mayuresh Chitale
 <mchitale@ventanamicro.com>, panqinglin2020@iscas.ac.cn,
 linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-efi@vger.kernel.org, linux-arch@vger.kernel.org
Subject: Re: [PATCH v3 01/13] riscv: Move KASAN mapping next to the kernel
 mapping
In-Reply-To: <20211206104657.433304-2-alexandre.ghiti@canonical.com>
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
	<20211206104657.433304-2-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20211206162624.F1EF4C341C2@smtp.kernel.org>
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=sckZAMuU;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon,  6 Dec 2021 11:46:45 +0100
Alexandre Ghiti <alexandre.ghiti@canonical.com> wrote:

> Now that KASAN_SHADOW_OFFSET is defined at compile time as a config,
> this value must remain constant whatever the size of the virtual address
> space, which is only possible by pushing this region at the end of the
> address space next to the kernel mapping.
> 
> Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> ---
>  Documentation/riscv/vm-layout.rst | 12 ++++++------
>  arch/riscv/Kconfig                |  4 ++--
>  arch/riscv/include/asm/kasan.h    |  4 ++--
>  arch/riscv/include/asm/page.h     |  6 +++++-
>  arch/riscv/include/asm/pgtable.h  |  6 ++++--
>  arch/riscv/mm/init.c              | 25 +++++++++++++------------
>  6 files changed, 32 insertions(+), 25 deletions(-)
> 
> diff --git a/Documentation/riscv/vm-layout.rst b/Documentation/riscv/vm-layout.rst
> index b7f98930d38d..1bd687b97104 100644
> --- a/Documentation/riscv/vm-layout.rst
> +++ b/Documentation/riscv/vm-layout.rst
> @@ -47,12 +47,12 @@ RISC-V Linux Kernel SV39
>                                                                | Kernel-space virtual memory, shared between all processes:
>    ____________________________________________________________|___________________________________________________________
>                      |            |                  |         |
> -   ffffffc000000000 | -256    GB | ffffffc7ffffffff |   32 GB | kasan
> -   ffffffcefee00000 | -196    GB | ffffffcefeffffff |    2 MB | fixmap
> -   ffffffceff000000 | -196    GB | ffffffceffffffff |   16 MB | PCI io
> -   ffffffcf00000000 | -196    GB | ffffffcfffffffff |    4 GB | vmemmap
> -   ffffffd000000000 | -192    GB | ffffffdfffffffff |   64 GB | vmalloc/ioremap space
> -   ffffffe000000000 | -128    GB | ffffffff7fffffff |  124 GB | direct mapping of all physical memory
> +   ffffffc6fee00000 | -228    GB | ffffffc6feffffff |    2 MB | fixmap
> +   ffffffc6ff000000 | -228    GB | ffffffc6ffffffff |   16 MB | PCI io
> +   ffffffc700000000 | -228    GB | ffffffc7ffffffff |    4 GB | vmemmap
> +   ffffffc800000000 | -224    GB | ffffffd7ffffffff |   64 GB | vmalloc/ioremap space
> +   ffffffd800000000 | -160    GB | fffffff6ffffffff |  124 GB | direct mapping of all physical memory
> +   fffffff700000000 |  -36    GB | fffffffeffffffff |   32 GB | kasan
>    __________________|____________|__________________|_________|____________________________________________________________
>                                                                |
>                                                                |
> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> index 6d5b63bd4bd9..6cd98ade5ebc 100644
> --- a/arch/riscv/Kconfig
> +++ b/arch/riscv/Kconfig
> @@ -161,12 +161,12 @@ config PAGE_OFFSET
>  	default 0xC0000000 if 32BIT && MAXPHYSMEM_1GB
>  	default 0x80000000 if 64BIT && !MMU
>  	default 0xffffffff80000000 if 64BIT && MAXPHYSMEM_2GB
> -	default 0xffffffe000000000 if 64BIT && MAXPHYSMEM_128GB
> +	default 0xffffffd800000000 if 64BIT && MAXPHYSMEM_128GB
>  
>  config KASAN_SHADOW_OFFSET
>  	hex
>  	depends on KASAN_GENERIC
> -	default 0xdfffffc800000000 if 64BIT
> +	default 0xdfffffff00000000 if 64BIT
>  	default 0xffffffff if 32BIT
>  
>  config ARCH_FLATMEM_ENABLE
> diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
> index b00f503ec124..257a2495145a 100644
> --- a/arch/riscv/include/asm/kasan.h
> +++ b/arch/riscv/include/asm/kasan.h
> @@ -28,8 +28,8 @@
>  #define KASAN_SHADOW_SCALE_SHIFT	3
>  
>  #define KASAN_SHADOW_SIZE	(UL(1) << ((CONFIG_VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
> -#define KASAN_SHADOW_START	KERN_VIRT_START
> -#define KASAN_SHADOW_END	(KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
> +#define KASAN_SHADOW_START	(KASAN_SHADOW_END - KASAN_SHADOW_SIZE)
> +#define KASAN_SHADOW_END	MODULES_LOWEST_VADDR
>  #define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>  
>  void kasan_init(void);
> diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/page.h
> index 109c97e991a6..e03559f9b35e 100644
> --- a/arch/riscv/include/asm/page.h
> +++ b/arch/riscv/include/asm/page.h
> @@ -33,7 +33,11 @@
>   */
>  #define PAGE_OFFSET		_AC(CONFIG_PAGE_OFFSET, UL)
>  
> -#define KERN_VIRT_SIZE (-PAGE_OFFSET)
> +/*
> + * Half of the kernel address space (half of the entries of the page global
> + * directory) is for the direct mapping.
> + */
> +#define KERN_VIRT_SIZE		((PTRS_PER_PGD / 2 * PGDIR_SIZE) / 2)
>  
>  #ifndef __ASSEMBLY__
>  
> diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
> index 39b550310ec6..d34f3a7a9701 100644
> --- a/arch/riscv/include/asm/pgtable.h
> +++ b/arch/riscv/include/asm/pgtable.h
> @@ -39,8 +39,10 @@
>  
>  /* Modules always live before the kernel */
>  #ifdef CONFIG_64BIT
> -#define MODULES_VADDR	(PFN_ALIGN((unsigned long)&_end) - SZ_2G)
> -#define MODULES_END	(PFN_ALIGN((unsigned long)&_start))
> +/* This is used to define the end of the KASAN shadow region */
> +#define MODULES_LOWEST_VADDR	(KERNEL_LINK_ADDR - SZ_2G)
> +#define MODULES_VADDR		(PFN_ALIGN((unsigned long)&_end) - SZ_2G)
> +#define MODULES_END		(PFN_ALIGN((unsigned long)&_start))
>  #endif
>  
>  /*
> diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
> index c0cddf0fc22d..4224e9d0ecf5 100644
> --- a/arch/riscv/mm/init.c
> +++ b/arch/riscv/mm/init.c
> @@ -103,6 +103,9 @@ static void __init print_vm_layout(void)
>  	print_mlm("lowmem", (unsigned long)PAGE_OFFSET,
>  		  (unsigned long)high_memory);
>  #ifdef CONFIG_64BIT
> +#ifdef CONFIG_KASAN
> +	print_mlm("kasan", KASAN_SHADOW_START, KASAN_SHADOW_END);
> +#endif

I think we'd better avoid #ifdef usage as much as possible.
For this KASAN case, we can make both KASAN_SHADOW_START and KASAN_SHADOW_END
always visible as x86 does, then above code can be
if (IS_ENABLED(CONFIG_KASAN))
	print_mlm("kasan", KASAN_SHADOW_START, KASAN_SHADOW_END);

Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206162624.F1EF4C341C2%40smtp.kernel.org.
