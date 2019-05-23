Return-Path: <kasan-dev+bncBCXLBLOA7IGBB47UTDTQKGQEIVG4YSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 10F65275EC
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 08:15:16 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id m2sf958658ljj.13
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 23:15:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558592115; cv=pass;
        d=google.com; s=arc-20160816;
        b=ndR39n6uIdvVo+65Jgh1FQ0ItgbA1RfWDqDq8jgiGL8gWL47R8hAij8Lyuz8mm2koL
         6LqIOFSqmEW+nK4Y4pv+rYig2FqurxaOTYaZp1mrts19aYzsz8idggHfhLL3n/ULF5k0
         vcjJ29y1xXHLs/UTq7rJZvNab/e0WeJxpf821Go8g5R8YymhCTgzFqRo1QA3YEE226c/
         cVsBztz0zhHK0FAQbi02bE2aqN94uwdI4TktPk6bhsBH3B4rlkKu4VLVQGKHncH95b9E
         61KjPLn0UZa9fK+B6RTBmudXNHQnHD3YwIj17timgS/XrsGfaOb6FrSKeCy8ziAOW89h
         FP8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=Jgogtynkck0foDvPyBVDchhJxI3AZKEScGwEkopnyoQ=;
        b=UkKFwg/i2qUeE7RMWdjuyHSfgPML3dSKKmhNGrNhD8os2J1t1QLtU2JEZ1orpTNI0/
         mZXApKXN020TZ/iu9oiu4g+1jFxbIvKAdO+8ixomsIbZekdUCdI8QYXKrCBQVRV4Bo7W
         Ogj2Nh+tnffjmYSoBvvmPI9UZG2/1n8TwnF18L65V9nLHXjlQ+cWNbS0/0p90G3qM0Ko
         HKPQ8sjLAD96A1rPMu/s0qVKT8tyPt2e/7766ybXefOhlJAXFlmaycFJCkEQYpof3f/1
         05gz+/R6R131dmTULHHb2zoeyS+849DpAom2/OCs7gwtPEAJXuUd9V13JqlwFGTQkgl7
         joqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=AAAP5YCZ;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jgogtynkck0foDvPyBVDchhJxI3AZKEScGwEkopnyoQ=;
        b=o6V6u7+TIITjFehRAxAH7bZIppJl+BagIrjC97BTQSsRFgaslWQfGRL3lzymg8tJPc
         roRhkwV5nLrdsnXzg41vvEv0pD1CcFb1WZ4iF6h6Xm4GHt/cqRK6UXBKtt6dv0DFx8EA
         KojdWk6YYitPBWwaaXteFZZgc/NgVXwdKcC6qrohO3IS6MBjxAsaGahJIqav/hTUoypI
         sdKLgou6jL2pDcr+Hb/H/5c2BFeKQUB7ad1TT+wh1ji8FmmTrqFdvLP8UfX1N3aTzfdl
         hc7vCPdY0tSmHfRCw5j4ArIMLIeE8Ssyx2xaK/59SQuuHiqsO6WSjsiNmyfOiorrtxrP
         uFrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jgogtynkck0foDvPyBVDchhJxI3AZKEScGwEkopnyoQ=;
        b=nf2IsGMeZ0XGSwEGYD35GtUbpVy1Q6n/RJxXjY9Lvqwjm7EEtdGXsOuDQC7YOgzLgi
         OLuaWV6WaRbc4QsPDFZPEORnUZm9PTcVB1wt+f91OYzo6RkK+u9n/Q0wRLpyhTZWjXRE
         OmIFdqQgnEw1MCq4UU051IqAv40tSdOENBU9okmpfXm6013aGqx9agfNDkGAHdw1T5aE
         2vx3cGl/KOXafKcB+a9qlhtuJFDrRckABTSHYVYa1mujAtLZVcBzGy00LpRPzCPJboG9
         ANA1lFNWNboXpfGLSyiqKUY4Bb5TH8H4+gYMRJkAeP9T8PYeNw77ViTJUu9C+S+XphQ8
         9QvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWx5DyBZcBA0gEDxwmAE7oUDNrV96Q6++REMwyhaTQeT2DvEoYw
	9rJTTeiI+0igJaQeh9PvFz0=
X-Google-Smtp-Source: APXvYqwMIcJcHspddVark4Af4Rz+R08Wgy+Q0Wii0YvXf/daJo/nbFSNmVJ+gMCGR3CO9CmGlju5OA==
X-Received: by 2002:ac2:434c:: with SMTP id o12mr3673811lfl.128.1558592115595;
        Wed, 22 May 2019 23:15:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9f4a:: with SMTP id v10ls505538ljk.9.gmail; Wed, 22 May
 2019 23:15:15 -0700 (PDT)
X-Received: by 2002:a2e:90d0:: with SMTP id o16mr20671444ljg.200.1558592115078;
        Wed, 22 May 2019 23:15:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558592115; cv=none;
        d=google.com; s=arc-20160816;
        b=BxQjcbMv0R/r3XHtZK2X70XYeBmpxS0R5q/YAhVByBTlU069ou9l3f+YQn8jclY3Zf
         qtTyZlqccpqG5GEUGEg+HsN/0Iqi3evH/piRxL9qOLYP5xBrwZEn+d++yGeVfvTKqt59
         w03M7ytR3EiSr3b8yece/jvDkCrZziiXGjXFDtctWw7DFPtIPgadBEt9KcBbMrhOz9Sv
         0BSp2a6yavgot2qzkKPQC7Tj35zHk3oHaNO+DiC7EVMxn4Ja9TieR6amp7B9vJXN/hYZ
         StoyD6DgFU/SpcXkeV+G7enF1M/GRYthI8Fc+cMy3WF899fFcBV4WuI2Flh7z+S45mZG
         rJNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=Jlz88m5HjbbbihdN5bCiI9iVmTNf3S1GrBwNBWdxKZo=;
        b=VcbOEJFvGCmSgjuouapZfH66XDRajCOi50VWFzTknXVyk7DjLk9FD2H8h9rL7xEhe6
         sC3a0dykF2LKdvN+cF0uTff96XuOXgWIYHpoICsgjoNmSwIrLEEN5lwxZ2HGJcon1csC
         sNI8oP9UnPMQl1HF5i0vR528xsEeZAvAjutHUQUrpMWwIKfm0jh1t50LEstukt6k7tQV
         Dj0CN6r/CeIaiKaAJ3cbOaW9BGqFODZqDCjRCd6n5NqT68wbcXTtSmMDIVKz1iN+zLHh
         nfgKYjS+0ucDbwgAB8TV4BAuVnfk3jK2k768FLZQFUfgJ5fUCdW+NjdvaQWPMU+s20Bl
         AYLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=AAAP5YCZ;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id z22si1796447lfe.1.2019.05.22.23.15.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 23:15:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 458fPC2ydfz9v1Qb;
	Thu, 23 May 2019 08:15:11 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id A52yZXVVQ62A; Thu, 23 May 2019 08:15:11 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 458fPC0ZHTz9v1QZ;
	Thu, 23 May 2019 08:15:11 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id EF2438B77D;
	Thu, 23 May 2019 08:15:11 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id kPF6yfx94bkP; Thu, 23 May 2019 08:15:11 +0200 (CEST)
Received: from PO15451 (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 69A7D8B75A;
	Thu, 23 May 2019 08:15:11 +0200 (CEST)
Subject: Re: [RFC PATCH 4/7] powerpc: KASAN for 64bit Book3E
To: Daniel Axtens <dja@axtens.net>, aneesh.kumar@linux.ibm.com,
 bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com,
 "Aneesh Kumar K . V" <aneesh.kumar@linux.vnet.ibm.com>
References: <20190523052120.18459-1-dja@axtens.net>
 <20190523052120.18459-5-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <8046c75a-6b05-3c6a-2520-3b9b48d3cdc8@c-s.fr>
Date: Thu, 23 May 2019 08:15:11 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.6.1
MIME-Version: 1.0
In-Reply-To: <20190523052120.18459-5-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=AAAP5YCZ;       spf=pass (google.com:
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



Le 23/05/2019 =C3=A0 07:21, Daniel Axtens a =C3=A9crit=C2=A0:
> Wire up KASAN. Only outline instrumentation is supported.
>=20
> The KASAN shadow area is mapped into vmemmap space:
> 0x8000 0400 0000 0000 to 0x8000 0600 0000 0000.
> To do this we require that vmemmap be disabled. (This is the default
> in the kernel config that QorIQ provides for the machine in their
> SDK anyway - they use flat memory.)
>=20
> Only the kernel linear mapping (0xc000...) is checked. The vmalloc and
> ioremap areas (also in 0x800...) are all mapped to the zero page. As
> with the Book3S hash series, this requires overriding the memory <->
> shadow mapping.
>=20
> Also, as with both previous 64-bit series, early instrumentation is not
> supported.  It would allow us to drop the check_return_arch_not_ready()
> hook in the KASAN core, but it's tricky to get it set up early enough:
> we need it setup before the first call to instrumented code like printk()=
.
> Perhaps in the future.
>=20
> Only KASAN_MINIMAL works.

See https://patchwork.ozlabs.org/patch/1068260/ for a full implementation

Christophe

>=20
> Tested on e6500. KVM, kexec and xmon have not been tested.
>=20
> The test_kasan module fires warnings as expected, except for the
> following tests:
>=20
>   - Expected/by design:
> kasan test: memcg_accounted_kmem_cache allocate memcg accounted object
>=20
>   - Due to only supporting KASAN_MINIMAL:
> kasan test: kasan_stack_oob out-of-bounds on stack
> kasan test: kasan_global_oob out-of-bounds global variable
> kasan test: kasan_alloca_oob_left out-of-bounds to left on alloca
> kasan test: kasan_alloca_oob_right out-of-bounds to right on alloca
> kasan test: use_after_scope_test use-after-scope on int
> kasan test: use_after_scope_test use-after-scope on array
>=20
> Thanks to those who have done the heavy lifting over the past several
> years:
>   - Christophe's 32 bit series: https://lists.ozlabs.org/pipermail/linuxp=
pc-dev/2019-February/185379.html
>   - Aneesh's Book3S hash series: https://lwn.net/Articles/655642/
>   - Balbir's Book3S radix series: https://patchwork.ozlabs.org/patch/7952=
11/
>=20
> Cc: Christophe Leroy <christophe.leroy@c-s.fr>
> Cc: Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
> Cc: Balbir Singh <bsingharora@gmail.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> [- Removed EXPORT_SYMBOL of the static key
>   - Fixed most checkpatch problems
>   - Replaced kasan_zero_page[] by kasan_early_shadow_page[]
>   - Reduced casting mess by using intermediate locals
>   - Fixed build failure on pmac32_defconfig]
> Signed-off-by: Christophe Leroy <christophe.leroy@c-s.fr>
> ---
>   arch/powerpc/Kconfig                         |  1 +
>   arch/powerpc/Kconfig.debug                   |  2 +-
>   arch/powerpc/include/asm/kasan.h             | 71 ++++++++++++++++++++
>   arch/powerpc/mm/kasan/Makefile               |  1 +
>   arch/powerpc/mm/kasan/kasan_init_book3e_64.c | 50 ++++++++++++++
>   arch/powerpc/mm/nohash/Makefile              |  5 ++
>   6 files changed, 129 insertions(+), 1 deletion(-)
>   create mode 100644 arch/powerpc/mm/kasan/kasan_init_book3e_64.c
>=20
> diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
> index 6a66a2da5b1a..4e266b019dd7 100644
> --- a/arch/powerpc/Kconfig
> +++ b/arch/powerpc/Kconfig
> @@ -170,6 +170,7 @@ config PPC
>   	select HAVE_ARCH_AUDITSYSCALL
>   	select HAVE_ARCH_JUMP_LABEL
>   	select HAVE_ARCH_KASAN			if PPC32
> +	select HAVE_ARCH_KASAN			if PPC_BOOK3E_64 && !SPARSEMEM_VMEMMAP
>   	select HAVE_ARCH_KGDB
>   	select HAVE_ARCH_MMAP_RND_BITS
>   	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if COMPAT
> diff --git a/arch/powerpc/Kconfig.debug b/arch/powerpc/Kconfig.debug
> index c59920920ddc..23a37facc854 100644
> --- a/arch/powerpc/Kconfig.debug
> +++ b/arch/powerpc/Kconfig.debug
> @@ -396,5 +396,5 @@ config PPC_FAST_ENDIAN_SWITCH
>  =20
>   config KASAN_SHADOW_OFFSET
>   	hex
> -	depends on KASAN
> +	depends on KASAN && PPC32
>   	default 0xe0000000
> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/=
kasan.h
> index 296e51c2f066..ae410f0e060d 100644
> --- a/arch/powerpc/include/asm/kasan.h
> +++ b/arch/powerpc/include/asm/kasan.h
> @@ -21,12 +21,15 @@
>   #define KASAN_SHADOW_START	(KASAN_SHADOW_OFFSET + \
>   				 (PAGE_OFFSET >> KASAN_SHADOW_SCALE_SHIFT))
>  =20
> +#ifdef CONFIG_PPC32
>   #define KASAN_SHADOW_OFFSET	ASM_CONST(CONFIG_KASAN_SHADOW_OFFSET)
>  =20
>   #define KASAN_SHADOW_END	0UL
>  =20
>   #define KASAN_SHADOW_SIZE	(KASAN_SHADOW_END - KASAN_SHADOW_START)
>  =20
> +#endif /* CONFIG_PPC32 */
> +
>   #ifdef CONFIG_KASAN
>   void kasan_early_init(void);
>   void kasan_mmu_init(void);
> @@ -36,5 +39,73 @@ static inline void kasan_init(void) { }
>   static inline void kasan_mmu_init(void) { }
>   #endif
>  =20
> +#ifdef CONFIG_PPC_BOOK3E_64
> +#include <asm/pgtable.h>
> +#include <linux/jump_label.h>
> +
> +/*
> + * We don't put this in Kconfig as we only support KASAN_MINIMAL, and
> + * that will be disabled if the symbol is available in Kconfig
> + */
> +#define KASAN_SHADOW_OFFSET	ASM_CONST(0x6800040000000000)
> +
> +#define KASAN_SHADOW_SIZE	(KERN_VIRT_SIZE >> KASAN_SHADOW_SCALE_SHIFT)
> +
> +extern struct static_key_false powerpc_kasan_enabled_key;
> +extern unsigned char kasan_early_shadow_page[];
> +
> +static inline bool kasan_arch_is_ready_book3e(void)
> +{
> +	if (static_branch_likely(&powerpc_kasan_enabled_key))
> +		return true;
> +	return false;
> +}
> +#define kasan_arch_is_ready kasan_arch_is_ready_book3e
> +
> +static inline void *kasan_mem_to_shadow_book3e(const void *ptr)
> +{
> +	unsigned long addr =3D (unsigned long)ptr;
> +
> +	if (addr >=3D KERN_VIRT_START && addr < KERN_VIRT_START + KERN_VIRT_SIZ=
E)
> +		return kasan_early_shadow_page;
> +
> +	return (void *)(addr >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET=
;
> +}
> +#define kasan_mem_to_shadow kasan_mem_to_shadow_book3e
> +
> +static inline void *kasan_shadow_to_mem_book3e(const void *shadow_addr)
> +{
> +	/*
> +	 * We map the entire non-linear virtual mapping onto the zero page so i=
f
> +	 * we are asked to map the zero page back just pick the beginning of th=
at
> +	 * area.
> +	 */
> +	if (shadow_addr >=3D (void *)kasan_early_shadow_page &&
> +	    shadow_addr < (void *)(kasan_early_shadow_page + PAGE_SIZE))
> +		return (void *)KERN_VIRT_START;
> +
> +	return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET) <<
> +			KASAN_SHADOW_SCALE_SHIFT);
> +}
> +#define kasan_shadow_to_mem kasan_shadow_to_mem_book3e
> +
> +static inline bool kasan_addr_has_shadow_book3e(const void *ptr)
> +{
> +	unsigned long addr =3D (unsigned long)ptr;
> +
> +	/*
> +	 * We want to specifically assert that the addresses in the 0x8000...
> +	 * region have a shadow, otherwise they are considered by the kasan
> +	 * core to be wild pointers
> +	 */
> +	if (addr >=3D KERN_VIRT_START && addr < (KERN_VIRT_START + KERN_VIRT_SI=
ZE))
> +		return true;
> +
> +	return (ptr >=3D kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
> +}
> +#define kasan_addr_has_shadow kasan_addr_has_shadow_book3e
> +
> +#endif /* CONFIG_PPC_BOOK3E_64 */
> +
>   #endif /* __ASSEMBLY */
>   #endif
> diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makef=
ile
> index 6577897673dd..f8f164ad8ade 100644
> --- a/arch/powerpc/mm/kasan/Makefile
> +++ b/arch/powerpc/mm/kasan/Makefile
> @@ -3,3 +3,4 @@
>   KASAN_SANITIZE :=3D n
>  =20
>   obj-$(CONFIG_PPC32)           +=3D kasan_init_32.o
> +obj-$(CONFIG_PPC_BOOK3E_64)   +=3D kasan_init_book3e_64.o
> diff --git a/arch/powerpc/mm/kasan/kasan_init_book3e_64.c b/arch/powerpc/=
mm/kasan/kasan_init_book3e_64.c
> new file mode 100644
> index 000000000000..f116c211d83c
> --- /dev/null
> +++ b/arch/powerpc/mm/kasan/kasan_init_book3e_64.c
> @@ -0,0 +1,50 @@
> +// SPDX-License-Identifier: GPL-2.0
> +
> +#define DISABLE_BRANCH_PROFILING
> +
> +#include <linux/kasan.h>
> +#include <linux/printk.h>
> +#include <linux/memblock.h>
> +#include <linux/sched/task.h>
> +#include <asm/pgalloc.h>
> +
> +DEFINE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
> +
> +static void __init kasan_init_region(struct memblock_region *reg)
> +{
> +	void *start =3D __va(reg->base);
> +	void *end =3D __va(reg->base + reg->size);
> +	unsigned long k_start, k_end, k_cur;
> +
> +	if (start >=3D end)
> +		return;
> +
> +	k_start =3D (unsigned long)kasan_mem_to_shadow(start);
> +	k_end =3D (unsigned long)kasan_mem_to_shadow(end);
> +
> +	for (k_cur =3D k_start; k_cur < k_end; k_cur +=3D PAGE_SIZE) {
> +		void *va =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> +
> +		map_kernel_page(k_cur, __pa(va), PAGE_KERNEL);
> +	}
> +	flush_tlb_kernel_range(k_start, k_end);
> +}
> +
> +void __init kasan_init(void)
> +{
> +	struct memblock_region *reg;
> +
> +	for_each_memblock(memory, reg)
> +		kasan_init_region(reg);
> +
> +	/* map the zero page RO */
> +	map_kernel_page((unsigned long)kasan_early_shadow_page,
> +			__pa(kasan_early_shadow_page), PAGE_KERNEL_RO);
> +
> +	/* Turn on checking */
> +	static_branch_inc(&powerpc_kasan_enabled_key);
> +
> +	/* Enable error messages */
> +	init_task.kasan_depth =3D 0;
> +	pr_info("KASAN init done (64-bit Book3E)\n");
> +}
> diff --git a/arch/powerpc/mm/nohash/Makefile b/arch/powerpc/mm/nohash/Mak=
efile
> index 33b6f6f29d3f..310149f217d7 100644
> --- a/arch/powerpc/mm/nohash/Makefile
> +++ b/arch/powerpc/mm/nohash/Makefile
> @@ -16,3 +16,8 @@ endif
>   # This is necessary for booting with kcov enabled on book3e machines
>   KCOV_INSTRUMENT_tlb.o :=3D n
>   KCOV_INSTRUMENT_fsl_booke.o :=3D n
> +
> +ifdef CONFIG_KASAN
> +CFLAGS_fsl_booke_mmu.o		+=3D -DDISABLE_BRANCH_PROFILING
> +CFLAGS_tlb.o			+=3D -DDISABLE_BRANCH_PROFILING
> +endif
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/8046c75a-6b05-3c6a-2520-3b9b48d3cdc8%40c-s.fr.
For more options, visit https://groups.google.com/d/optout.
