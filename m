Return-Path: <kasan-dev+bncBCXLBLOA7IGBBYOJV7TAKGQEQVPBOXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id F26E312808
	for <lists+kasan-dev@lfdr.de>; Fri,  3 May 2019 08:51:13 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id b17sf670656lfj.9
        for <lists+kasan-dev@lfdr.de>; Thu, 02 May 2019 23:51:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556866273; cv=pass;
        d=google.com; s=arc-20160816;
        b=ewHl8NVY9kMYiSUByn5Mk5EGEMlQ26HvAgoxb1paOgZ+boS4V+ECD71NFJGOdnudS4
         jCTLl2KHdfkf/deMuOSIbBS9krhrse1rZuWQjdm7SuJN7a8aHcHWidYne/d7pknGUk2L
         C1m6O/KoYnxR9xedSc/3d/a4IwoyDGZlA7BWJhDACBxlzDg1+rDQa1QZFeO88/gOWZxW
         49rXMP7RmT82Q+/t3270yuNruwdpiMrCZXKHZn3/pBXcIb8kmm2wrWIfZ2FgtBhIzJuC
         pauWMud74oZRXeUeRw/fwuELtqS+RebSsdofiXYxZfERmPsVRXYfDEvntY4bqXj2YHtz
         v6EQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:from:subject:sender:dkim-signature;
        bh=5DcHyst/d540sHYgjgQVrPloHE73tzB3Eqgp9Akgd50=;
        b=CzqwG1YvmfmRxFZURcJyoWg5b9MIXYbLkgRchYOkS96Va/Yok+BDxa2/duOfNgjNzQ
         BVPs5bytfAHRrzE78VxqUF3ocNw+RN1YJM3nbAqg6NSjujmUMmjO2O11spG9I1beo3br
         7LRJiaKMqFq3jqbrdzrXfHtwlPu4lXo8MSVuBECRXOvJShPApVubupBE/GhhpSSKDg6Q
         o+F2zK4r0tP77wn9W9JgqqCs9ftn67ZOF7Xb2T2cmlWMR4fhB29F5HvbRLM9NrPuDZut
         FRCb24H+mhXX37XGbON+FPX2XACGMSnCv0MIiul+HUDvNcIC68PfC839lc8DUqZzzxJ1
         vxag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=c9VxYGjC;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5DcHyst/d540sHYgjgQVrPloHE73tzB3Eqgp9Akgd50=;
        b=nKjjCkidYdrg21IfbL0oe7yCFfD4N4b46lkSuDFFIjQHjbBViwH+Xcb7qtgS05EuHU
         vkMUv49i8RxTQDjJix9/o3vfpmxekbG04g5F1D8u4uTzdTuKJZBPD+UuXlMn0UZIagN2
         0O50xPQH8GQ2NOHMHLL+PhQLFqtjuK096sX/36m5SDsIwYVYF7HjD3llE5zAeSg4qOWz
         ie218vWLTWXUWVGjfEksKIErmviSTQ5Xh1x9Zn5BOZnFOMn+Ux7635kLNQciQpN/sHns
         q2Jxd6DxPblDT7ZcIF1pETGAmKVJPeodRkS3Ery1vK6hv8bnDxQ1UNejRzLYNi68dKUY
         vccA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5DcHyst/d540sHYgjgQVrPloHE73tzB3Eqgp9Akgd50=;
        b=ZyWdIUsORHL8q363pAURTyF6MlFohw7mfSaTUX0ZsX5wA3kVGqbop4vyZYKruV03Cu
         gOZ/Wqj5VQ7iwfJ4t91y7HnYTLkw3OLT0iSiSzRSBsvPmeIoXhwTnvDd6J4tbubYu5nI
         7EzJ6H+LkNZo7FFTpDhaUjy6xpsHcBcJtfU5H4nRSCh/FForTtcPaz8Td4quwPdb0/gq
         Dz2+jUh5aECR0JSHzioQofw/5cpQAIrBaggOq2QNgdaHU7vY3Yv7AeWSRl5Ps7UbdEJo
         egF8iltai0fNR98+vQ8hNDhyJYCbY5a7PLqzETRwG2GwrR2VIydnF5/tQh137lo0xfM1
         kooQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVqhpfbdvsuldGvr/Q4B+YZdrgmtp9V5t/wIDrsJJpsb6BS3dlf
	eX1K4LkOg0TO9pi0kOGSlWA=
X-Google-Smtp-Source: APXvYqymHlErssVHI5VMUClDsxRrW5XzuXudkslAq36lqTzlcMgknyikpMUb382lD4nB+HUjb3fIAg==
X-Received: by 2002:a05:651c:155:: with SMTP id c21mr4253753ljd.10.1556866273487;
        Thu, 02 May 2019 23:51:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:410a:: with SMTP id b10ls396362lfi.16.gmail; Thu, 02 May
 2019 23:51:12 -0700 (PDT)
X-Received: by 2002:ac2:4217:: with SMTP id y23mr778133lfh.134.1556866272957;
        Thu, 02 May 2019 23:51:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556866272; cv=none;
        d=google.com; s=arc-20160816;
        b=a78vDlz5E+UY9k7T6hIMgrRVwXljGmdXJPgrFh7sZzpCaOLM5/cuc/7KDKU3glsuXG
         kx0BGHDUl3d/ozJqocaL/Jwf26nkicZJrJ1YZgwluUr3ednCLoyohX4cAKwZlTpcG6sB
         211bb/JAzv/E7o76wa8svG3rKElJ47zCanDlRWMtwM9OnDngsxWXVSvFle73RkKTqtrr
         fmexXWOrErVFBRqoYjtm8ZGz4r49Et6NVIWG+qozVqe8rGEMLN7Ffnnu8Ux0CbXs3ax6
         JBodt3YMQhk+Gjd1z+he1a1wvgUTmTbGvqEmG2eOxThty4jXvfMk7WegJ2XxiM9cQo2v
         1ltA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:cc:to:from:subject
         :dkim-signature;
        bh=GT99LV8Z525zndega9MtAhPQMhcaNvpNWfMKvpkHrw4=;
        b=XbrSVJWILWtD/UTnJXs9ZPWJDl4iG/vyuIxVjRP+uCi9Hw0Aqo7ljAFVe06EH0ooap
         db5NRQigbqEcOWnDI0GqzzGNiS+9adMCpkblV7r+KGWH3tg290TE2XH3Y3dZ73KLd9IE
         R1njH8odCwW/dL+aFw27i5ah3iswLbk42PyAZChGLUejX2dYzrtnd6P6jJwLryBW05yY
         lUoDdxun0GsTv8xDc85KwIMNruhEWoV724AGWXKW6P1uxkOiaWb+SUbxEQjJuXUEDjvW
         HpjtlXYweULmT0qX2DbxUT53abU2jQTMZq6OOFLd80GjPoZ2HzUW7EyFu/FjqZdvTBFh
         vfEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=c9VxYGjC;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id j7si55478ljc.0.2019.05.02.23.51.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 May 2019 23:51:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 44wN7z1Y1bz9v0XS;
	Fri,  3 May 2019 08:51:11 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id KXN4wYVtsAaN; Fri,  3 May 2019 08:51:11 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 44wN7z0PPJz9tytc;
	Fri,  3 May 2019 08:51:11 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id EFF948B825;
	Fri,  3 May 2019 08:51:11 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id nc1kRj3E7n09; Fri,  3 May 2019 08:51:11 +0200 (CEST)
Received: from PO15451 (po15451.idsi0.si.c-s.fr [172.25.231.6])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id B404E8B819;
	Fri,  3 May 2019 08:51:11 +0200 (CEST)
Subject: Re: [PATCH v11 10/13] powerpc/32: Add KASAN support
From: Christophe Leroy <christophe.leroy@c-s.fr>
To: Benjamin Herrenschmidt <benh@kernel.crashing.org>,
 Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>,
 Nicholas Piggin <npiggin@gmail.com>,
 "Aneesh Kumar K.V" <aneesh.kumar@linux.ibm.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Daniel Axtens <dja@axtens.net>
Cc: linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <cover.1556295459.git.christophe.leroy@c-s.fr>
 <c08fe3fee59343ebf76fd7ea0de11f4ad07a1d6e.1556295461.git.christophe.leroy@c-s.fr>
Message-ID: <e3b1f65f-6b3b-1ae8-3a3c-13b750bcc810@c-s.fr>
Date: Fri, 3 May 2019 08:51:11 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.6.1
MIME-Version: 1.0
In-Reply-To: <c08fe3fee59343ebf76fd7ea0de11f4ad07a1d6e.1556295461.git.christophe.leroy@c-s.fr>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=c9VxYGjC;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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



Le 26/04/2019 =C3=A0 18:23, Christophe Leroy a =C3=A9crit=C2=A0:
> This patch adds KASAN support for PPC32. The following patch
> will add an early activation of hash table for book3s. Until
> then, a warning will be raised if trying to use KASAN on an
> hash 6xx.
>=20
> To support KASAN, this patch initialises that MMU mapings for
> accessing to the KASAN shadow area defined in a previous patch.
>=20
> An early mapping is set as soon as the kernel code has been
> relocated at its definitive place.
>=20
> Then the definitive mapping is set once paging is initialised.
>=20
> For modules, the shadow area is allocated at module_alloc().
>=20
> Signed-off-by: Christophe Leroy <christophe.leroy@c-s.fr>
> ---
>   arch/powerpc/Kconfig                  |   1 +
>   arch/powerpc/include/asm/kasan.h      |   9 ++
>   arch/powerpc/kernel/head_32.S         |   3 +
>   arch/powerpc/kernel/head_40x.S        |   3 +
>   arch/powerpc/kernel/head_44x.S        |   3 +
>   arch/powerpc/kernel/head_8xx.S        |   3 +
>   arch/powerpc/kernel/head_fsl_booke.S  |   3 +
>   arch/powerpc/kernel/setup-common.c    |   3 +
>   arch/powerpc/mm/Makefile              |   1 +
>   arch/powerpc/mm/init_32.c             |   3 +
>   arch/powerpc/mm/kasan/Makefile        |   5 ++

Looks like the above Makefile is missing in powerpc/next ???

Christophe

>   arch/powerpc/mm/kasan/kasan_init_32.c | 156 +++++++++++++++++++++++++++=
+++++++
>   12 files changed, 193 insertions(+)
>   create mode 100644 arch/powerpc/mm/kasan/Makefile
>   create mode 100644 arch/powerpc/mm/kasan/kasan_init_32.c
>=20
> diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
> index a7c80f2b08b5..1a2fb50126b2 100644
> --- a/arch/powerpc/Kconfig
> +++ b/arch/powerpc/Kconfig
> @@ -173,6 +173,7 @@ config PPC
>   	select GENERIC_TIME_VSYSCALL
>   	select HAVE_ARCH_AUDITSYSCALL
>   	select HAVE_ARCH_JUMP_LABEL
> +	select HAVE_ARCH_KASAN			if PPC32
>   	select HAVE_ARCH_KGDB
>   	select HAVE_ARCH_MMAP_RND_BITS
>   	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if COMPAT
> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/=
kasan.h
> index 05274dea3109..296e51c2f066 100644
> --- a/arch/powerpc/include/asm/kasan.h
> +++ b/arch/powerpc/include/asm/kasan.h
> @@ -27,5 +27,14 @@
>  =20
>   #define KASAN_SHADOW_SIZE	(KASAN_SHADOW_END - KASAN_SHADOW_START)
>  =20
> +#ifdef CONFIG_KASAN
> +void kasan_early_init(void);
> +void kasan_mmu_init(void);
> +void kasan_init(void);
> +#else
> +static inline void kasan_init(void) { }
> +static inline void kasan_mmu_init(void) { }
> +#endif
> +
>   #endif /* __ASSEMBLY */
>   #endif
> diff --git a/arch/powerpc/kernel/head_32.S b/arch/powerpc/kernel/head_32.=
S
> index 40aec3f00a05..6e85171e513c 100644
> --- a/arch/powerpc/kernel/head_32.S
> +++ b/arch/powerpc/kernel/head_32.S
> @@ -969,6 +969,9 @@ start_here:
>    * Do early platform-specific initialization,
>    * and set up the MMU.
>    */
> +#ifdef CONFIG_KASAN
> +	bl	kasan_early_init
> +#endif
>   	li	r3,0
>   	mr	r4,r31
>   	bl	machine_init
> diff --git a/arch/powerpc/kernel/head_40x.S b/arch/powerpc/kernel/head_40=
x.S
> index a9c934f2319b..efa219d2136e 100644
> --- a/arch/powerpc/kernel/head_40x.S
> +++ b/arch/powerpc/kernel/head_40x.S
> @@ -848,6 +848,9 @@ start_here:
>   /*
>    * Decide what sort of machine this is and initialize the MMU.
>    */
> +#ifdef CONFIG_KASAN
> +	bl	kasan_early_init
> +#endif
>   	li	r3,0
>   	mr	r4,r31
>   	bl	machine_init
> diff --git a/arch/powerpc/kernel/head_44x.S b/arch/powerpc/kernel/head_44=
x.S
> index 37117ab11584..34a5df827b38 100644
> --- a/arch/powerpc/kernel/head_44x.S
> +++ b/arch/powerpc/kernel/head_44x.S
> @@ -203,6 +203,9 @@ _ENTRY(_start);
>   /*
>    * Decide what sort of machine this is and initialize the MMU.
>    */
> +#ifdef CONFIG_KASAN
> +	bl	kasan_early_init
> +#endif
>   	li	r3,0
>   	mr	r4,r31
>   	bl	machine_init
> diff --git a/arch/powerpc/kernel/head_8xx.S b/arch/powerpc/kernel/head_8x=
x.S
> index 03c73b4c6435..d25adb6ef235 100644
> --- a/arch/powerpc/kernel/head_8xx.S
> +++ b/arch/powerpc/kernel/head_8xx.S
> @@ -853,6 +853,9 @@ start_here:
>   /*
>    * Decide what sort of machine this is and initialize the MMU.
>    */
> +#ifdef CONFIG_KASAN
> +	bl	kasan_early_init
> +#endif
>   	li	r3,0
>   	mr	r4,r31
>   	bl	machine_init
> diff --git a/arch/powerpc/kernel/head_fsl_booke.S b/arch/powerpc/kernel/h=
ead_fsl_booke.S
> index 32332e24e421..567e0ed45ca8 100644
> --- a/arch/powerpc/kernel/head_fsl_booke.S
> +++ b/arch/powerpc/kernel/head_fsl_booke.S
> @@ -268,6 +268,9 @@ set_ivor:
>   /*
>    * Decide what sort of machine this is and initialize the MMU.
>    */
> +#ifdef CONFIG_KASAN
> +	bl	kasan_early_init
> +#endif
>   	mr	r3,r30
>   	mr	r4,r31
>   	bl	machine_init
> diff --git a/arch/powerpc/kernel/setup-common.c b/arch/powerpc/kernel/set=
up-common.c
> index 1729bf409562..15afb01b4374 100644
> --- a/arch/powerpc/kernel/setup-common.c
> +++ b/arch/powerpc/kernel/setup-common.c
> @@ -67,6 +67,7 @@
>   #include <asm/livepatch.h>
>   #include <asm/mmu_context.h>
>   #include <asm/cpu_has_feature.h>
> +#include <asm/kasan.h>
>  =20
>   #include "setup.h"
>  =20
> @@ -871,6 +872,8 @@ static void smp_setup_pacas(void)
>    */
>   void __init setup_arch(char **cmdline_p)
>   {
> +	kasan_init();
> +
>   	*cmdline_p =3D boot_command_line;
>  =20
>   	/* Set a half-reasonable default so udelay does something sensible */
> diff --git a/arch/powerpc/mm/Makefile b/arch/powerpc/mm/Makefile
> index dd945ca869b2..01afb10a7b33 100644
> --- a/arch/powerpc/mm/Makefile
> +++ b/arch/powerpc/mm/Makefile
> @@ -53,6 +53,7 @@ obj-$(CONFIG_PPC_COPRO_BASE)	+=3D copro_fault.o
>   obj-$(CONFIG_SPAPR_TCE_IOMMU)	+=3D mmu_context_iommu.o
>   obj-$(CONFIG_PPC_PTDUMP)	+=3D ptdump/
>   obj-$(CONFIG_PPC_MEM_KEYS)	+=3D pkeys.o
> +obj-$(CONFIG_KASAN)		+=3D kasan/
>  =20
>   # Disable kcov instrumentation on sensitive code
>   # This is necessary for booting with kcov enabled on book3e machines
> diff --git a/arch/powerpc/mm/init_32.c b/arch/powerpc/mm/init_32.c
> index 80cc97cd8878..5b61673e7eed 100644
> --- a/arch/powerpc/mm/init_32.c
> +++ b/arch/powerpc/mm/init_32.c
> @@ -46,6 +46,7 @@
>   #include <asm/sections.h>
>   #include <asm/hugetlb.h>
>   #include <asm/kup.h>
> +#include <asm/kasan.h>
>  =20
>   #include "mmu_decl.h"
>  =20
> @@ -179,6 +180,8 @@ void __init MMU_init(void)
>   	btext_unmap();
>   #endif
>  =20
> +	kasan_mmu_init();
> +
>   	setup_kup();
>  =20
>   	/* Shortly after that, the entire linear mapping will be available */
> diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makef=
ile
> new file mode 100644
> index 000000000000..6577897673dd
> --- /dev/null
> +++ b/arch/powerpc/mm/kasan/Makefile
> @@ -0,0 +1,5 @@
> +# SPDX-License-Identifier: GPL-2.0
> +
> +KASAN_SANITIZE :=3D n
> +
> +obj-$(CONFIG_PPC32)           +=3D kasan_init_32.o
> diff --git a/arch/powerpc/mm/kasan/kasan_init_32.c b/arch/powerpc/mm/kasa=
n/kasan_init_32.c
> new file mode 100644
> index 000000000000..42617fcad828
> --- /dev/null
> +++ b/arch/powerpc/mm/kasan/kasan_init_32.c
> @@ -0,0 +1,156 @@
> +// SPDX-License-Identifier: GPL-2.0
> +
> +#define DISABLE_BRANCH_PROFILING
> +
> +#include <linux/kasan.h>
> +#include <linux/printk.h>
> +#include <linux/memblock.h>
> +#include <linux/sched/task.h>
> +#include <linux/vmalloc.h>
> +#include <asm/pgalloc.h>
> +#include <asm/code-patching.h>
> +#include <mm/mmu_decl.h>
> +
> +static void kasan_populate_pte(pte_t *ptep, pgprot_t prot)
> +{
> +	unsigned long va =3D (unsigned long)kasan_early_shadow_page;
> +	phys_addr_t pa =3D __pa(kasan_early_shadow_page);
> +	int i;
> +
> +	for (i =3D 0; i < PTRS_PER_PTE; i++, ptep++)
> +		__set_pte_at(&init_mm, va, ptep, pfn_pte(PHYS_PFN(pa), prot), 0);
> +}
> +
> +static int kasan_init_shadow_page_tables(unsigned long k_start, unsigned=
 long k_end)
> +{
> +	pmd_t *pmd;
> +	unsigned long k_cur, k_next;
> +
> +	pmd =3D pmd_offset(pud_offset(pgd_offset_k(k_start), k_start), k_start)=
;
> +
> +	for (k_cur =3D k_start; k_cur !=3D k_end; k_cur =3D k_next, pmd++) {
> +		pte_t *new;
> +
> +		k_next =3D pgd_addr_end(k_cur, k_end);
> +		if ((void *)pmd_page_vaddr(*pmd) !=3D kasan_early_shadow_pte)
> +			continue;
> +
> +		new =3D pte_alloc_one_kernel(&init_mm);
> +
> +		if (!new)
> +			return -ENOMEM;
> +		kasan_populate_pte(new, PAGE_KERNEL_RO);
> +		pmd_populate_kernel(&init_mm, pmd, new);
> +	}
> +	return 0;
> +}
> +
> +static void __ref *kasan_get_one_page(void)
> +{
> +	if (slab_is_available())
> +		return (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
> +
> +	return memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> +}
> +
> +static int __ref kasan_init_region(void *start, size_t size)
> +{
> +	unsigned long k_start =3D (unsigned long)kasan_mem_to_shadow(start);
> +	unsigned long k_end =3D (unsigned long)kasan_mem_to_shadow(start + size=
);
> +	unsigned long k_cur;
> +	int ret;
> +	void *block =3D NULL;
> +
> +	ret =3D kasan_init_shadow_page_tables(k_start, k_end);
> +	if (ret)
> +		return ret;
> +
> +	if (!slab_is_available())
> +		block =3D memblock_alloc(k_end - k_start, PAGE_SIZE);
> +
> +	for (k_cur =3D k_start; k_cur < k_end; k_cur +=3D PAGE_SIZE) {
> +		pmd_t *pmd =3D pmd_offset(pud_offset(pgd_offset_k(k_cur), k_cur), k_cu=
r);
> +		void *va =3D block ? block + k_cur - k_start : kasan_get_one_page();
> +		pte_t pte =3D pfn_pte(PHYS_PFN(__pa(va)), PAGE_KERNEL);
> +
> +		if (!va)
> +			return -ENOMEM;
> +
> +		__set_pte_at(&init_mm, k_cur, pte_offset_kernel(pmd, k_cur), pte, 0);
> +	}
> +	flush_tlb_kernel_range(k_start, k_end);
> +	return 0;
> +}
> +
> +static void __init kasan_remap_early_shadow_ro(void)
> +{
> +	kasan_populate_pte(kasan_early_shadow_pte, PAGE_KERNEL_RO);
> +
> +	flush_tlb_kernel_range(KASAN_SHADOW_START, KASAN_SHADOW_END);
> +}
> +
> +void __init kasan_mmu_init(void)
> +{
> +	int ret;
> +	struct memblock_region *reg;
> +
> +	for_each_memblock(memory, reg) {
> +		phys_addr_t base =3D reg->base;
> +		phys_addr_t top =3D min(base + reg->size, total_lowmem);
> +
> +		if (base >=3D top)
> +			continue;
> +
> +		ret =3D kasan_init_region(__va(base), top - base);
> +		if (ret)
> +			panic("kasan: kasan_init_region() failed");
> +	}
> +}
> +
> +void __init kasan_init(void)
> +{
> +	kasan_remap_early_shadow_ro();
> +
> +	clear_page(kasan_early_shadow_page);
> +
> +	/* At this point kasan is fully initialized. Enable error messages */
> +	init_task.kasan_depth =3D 0;
> +	pr_info("KASAN init done\n");
> +}
> +
> +#ifdef CONFIG_MODULES
> +void *module_alloc(unsigned long size)
> +{
> +	void *base =3D vmalloc_exec(size);
> +
> +	if (!base)
> +		return NULL;
> +
> +	if (!kasan_init_region(base, size))
> +		return base;
> +
> +	vfree(base);
> +
> +	return NULL;
> +}
> +#endif
> +
> +void __init kasan_early_init(void)
> +{
> +	unsigned long addr =3D KASAN_SHADOW_START;
> +	unsigned long end =3D KASAN_SHADOW_END;
> +	unsigned long next;
> +	pmd_t *pmd =3D pmd_offset(pud_offset(pgd_offset_k(addr), addr), addr);
> +
> +	BUILD_BUG_ON(KASAN_SHADOW_START & ~PGDIR_MASK);
> +
> +	kasan_populate_pte(kasan_early_shadow_pte, PAGE_KERNEL);
> +
> +	do {
> +		next =3D pgd_addr_end(addr, end);
> +		pmd_populate_kernel(&init_mm, pmd, kasan_early_shadow_pte);
> +	} while (pmd++, addr =3D next, addr !=3D end);
> +
> +	if (early_mmu_has_feature(MMU_FTR_HPTE_TABLE))
> +		WARN(true, "KASAN not supported on hash 6xx");
> +}
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e3b1f65f-6b3b-1ae8-3a3c-13b750bcc810%40c-s.fr.
For more options, visit https://groups.google.com/d/optout.
