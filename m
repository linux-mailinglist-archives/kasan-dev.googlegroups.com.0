Return-Path: <kasan-dev+bncBAABB2FXU64AMGQEXWFLMGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C86299B006
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Oct 2024 04:16:10 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-71e1e989aa2sf3527420b3a.3
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 19:16:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728699369; cv=pass;
        d=google.com; s=arc-20240605;
        b=dfz4dT6CEYiyvAGgedZTtPSMeAS2dNj1h2NOJe0Xh4HB0Q67xqo9Vp5wQ1tW9gPj29
         YBQU8+/KysoFhSIw3BZj/0HEChnvqCv6bJITSn5FhN491UtyMlqudkrD7wWAlYNySc2G
         cCwIO0+qciWErddH7YAMdm4fQMqd258YlxNYsijW6l+Wl/iplWcOZFIELKTeXbkL2VHW
         t8MIs0aEFRAjm7jUj4kI7XqV7U6F18issXGl0u6AqYFq/QYGgIfeWFISe7gH7RMs1wL0
         KsaS6RRC+MZhBUw+vRtjb+5uVKEkW4bI0JFSyj2192kFv2mlCXkZIabc3cAHU2Q/KLgs
         P88w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aj2gL86XtPZ5esJoMmxvrXidT9B5Xw9hntMNNFGqtt8=;
        fh=4onvDOnp3y/QThQkHHC8OKmfUS38R4mXIKNEtR9fGbQ=;
        b=MEcUkMs1RMdS32BcGEmVbb7gedOVKFo37ZcjiGqCvR7CFb7OjE11CDc+UZ8jTUAagO
         +tetq4CqcaNtVVTyAOTvLh1B45+bffsTF/pPbdcTZvOn6fL7dsHymbwEJMkQbv+TVX+n
         Gq/8tQqmqB4zFEcn+3TNyw2V+EwrbD9LOpaYcXVIsAGw34pkFfOkva+UxqWWHPB+SgSw
         yaKPrW4Bi0XKEy8oIZ4a8+hiuyHkwU4l27tCS44eucFK9qCzYcrwYVcJbAIsXPeCmc7L
         lNRq7mSx1balsd+kCUqh7MBMGRvGlN6PcdZz2Mi8gNJL7g4FjI+E7V95HCzZaxZupQNR
         2EHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iu0MTPvZ;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728699369; x=1729304169; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aj2gL86XtPZ5esJoMmxvrXidT9B5Xw9hntMNNFGqtt8=;
        b=W7Nin7y7+EF0JIHIQ/AWsRZ46bPp0pWp3iZahbcwSQmT/RlhV6XZy1W22QnTvskX3R
         Hp3xcuJXNhJn7vc8OBbOhQwkOnsS7Jvv/F/Dtq0cp+6RqihPfm6E0L5mcAGXHxANavSi
         qwPVA4j8ssr52uv7ShoK6Nfn5F/CI8AhG2IhTSj8cp166aiRjA0g6yTyKypk0LTYws60
         /kqJslcSVok7F9chcxwQLKm20wkOKeUdt8P7BHW7owJMOLt9z1QrgNqb1vvjn5JO07CN
         4QKAwmYaTqCJsEYj12LFTm5HG/oILkr1kEyIVSo+LBoC8maXdeFAmH+3c7NGt/alc1g9
         WQbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728699369; x=1729304169;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=aj2gL86XtPZ5esJoMmxvrXidT9B5Xw9hntMNNFGqtt8=;
        b=lqv5diNHcvJmVY9xZ6Xa5RU6ahTkGclcfL1dzMYX+A0K21UPClNchaTAYA0cq8875i
         CCZIpbfwtZb++QH/RsJqyrhUsRtPO7I2ifLrRkVN85iDM3lXWWiNyEIezaEgWWDmVM9b
         pox29/OoGjcGM3ovALbc/HZ3pz0/jnLBZilic/7Q0Pm0SpeKV9s/UcHr/+xWDqwdF7OT
         rin7wFi60IPq5snBWozFLdQ7pvdGGSyU93V1Kg/Ysbgt7yHqXsYREB+NtktZNxo1TTgD
         11o0wEvc9a4RP9/XEN7Qf3XhrMdU/fNO2YMNNFhcNc9dfIn+1r5aOR0gXag3fMfY/TM2
         ap4w==
X-Forwarded-Encrypted: i=2; AJvYcCVjom7BbptsKksKjbt9pyUwbgP20mT5nQvvVF/ghwqtkmWmYPifjHbl1qClb8y0QoHZSrG6lg==@lfdr.de
X-Gm-Message-State: AOJu0Yz5jj5X1Nek5ZXJeN2xjgvJwIRVUGXsEpI/gRoLj9Oe0jDYB442
	A71soCgIvmxeWfgUwbc/xRnQtsC7cMrpqIr9HQsoQjb4BGxF5NNz
X-Google-Smtp-Source: AGHT+IHgQ3LRqjBjnS22Iz66sRyayy4c5geJAfJG2CdZ4Alfwc1kQHVLUWIRhZ/oBrctjIXOTWUibA==
X-Received: by 2002:a05:6a00:23d1:b0:71e:3b51:e850 with SMTP id d2e1a72fcca58-71e4c13939bmr2185278b3a.2.1728699368746;
        Fri, 11 Oct 2024 19:16:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8c04:0:b0:71e:4de3:36df with SMTP id d2e1a72fcca58-71e4de33c19ls186394b3a.1.-pod-prod-04-us;
 Fri, 11 Oct 2024 19:16:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXJIvMqEUMq/NgAofXOA63h41lRP4wl3MW0mAzJu1TnrrYBcBuDmVGkHNTkS/pUOAz8x8Y57P/xxC0=@googlegroups.com
X-Received: by 2002:a05:6a21:1786:b0:1d7:84f:f6f9 with SMTP id adf61e73a8af0-1d8c96c473bmr1654244637.48.1728699367636;
        Fri, 11 Oct 2024 19:16:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728699367; cv=none;
        d=google.com; s=arc-20240605;
        b=luTBl7DPaskPSE7an1b2Sh0ST6YwEKu5XJVihEfpgqy76Ryet+eGd3ijVdC7QtMHNq
         T4kqJWRz4JEhv5G1td+8BV36vlxWmPrxf/m/ruWT7IrmUSuESgfgdti7sDXkIkI6Nvnl
         uTDEQD2oP54nqK7hkLG7hbZkX1c72Yf2dhyua+Ae/F51NhvCSJxE2SegV1FVdAqOhWd6
         BY93+Cgr2fNHlu0wtyu8StH5LtDs3d+oc8rV6XmB2we7QO7k8XlQwMMN5DHPbnkAEUE+
         oXELPXYxyCoisHhE87TWyOLEPGqJqgFG6zpjpNHml2S3X8EzLee5j161oi4Z6Ng6w3lS
         /+DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5BqJR1DRisdo6nbRH5DioK+PKwu4x6E53fp43hUwjRM=;
        fh=HP+EAjRIv3x5rVpfrqMO44btU28Yr+bDUPWN3qyW46E=;
        b=I3kyVnNNMocwJyuvFYEwCoeAVKKxSAjTdNAPjMfPiT3gr2U6eyyP3HzgznvcZjL4vR
         +bxZo5CyG/HgAYkmtn17RcYfGvkfh0WQWtS0hVNnScMaPX4aK2C9dEpg772QGd1xmnvP
         crj6t2IB4rgWibdhvIxx5aN6RWURynTpFLPFI0DUvF1VrwpthynCNfujjil/IZnuezYH
         LDDm/g+WXCyK9tW4qQHfjdLIvAzOSgfYJffJayV8h43H9vpoi8Fw1WUuLKydy6Sc2D9P
         plH81lU/Bw8xRQJhsY5EXGNyl3G6WxOEHJUvqMW5oo85oRmTqEiq/ZM0Zdl9ps9Z3o3L
         aPSw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iu0MTPvZ;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7ea6dc0fcdcsi20707a12.3.2024.10.11.19.16.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Oct 2024 19:16:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 969DF5C5E62
	for <kasan-dev@googlegroups.com>; Sat, 12 Oct 2024 02:16:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 34FDAC4CED3
	for <kasan-dev@googlegroups.com>; Sat, 12 Oct 2024 02:16:06 +0000 (UTC)
Received: by mail-ej1-f44.google.com with SMTP id a640c23a62f3a-a9952ea05c5so395817366b.2
        for <kasan-dev@googlegroups.com>; Fri, 11 Oct 2024 19:16:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU6M2xbuarr+9dtx5sD+AHOfP/7XPn3vHuOEhgbQvwnzez5MhfpEBjae2FkFOnceX+DT2QpSn4aNJk=@googlegroups.com
X-Received: by 2002:a17:907:368d:b0:a99:5466:2556 with SMTP id
 a640c23a62f3a-a99b966b636mr417240566b.61.1728699364644; Fri, 11 Oct 2024
 19:16:04 -0700 (PDT)
MIME-Version: 1.0
References: <20241010035048.3422527-1-maobibo@loongson.cn> <20241010035048.3422527-2-maobibo@loongson.cn>
In-Reply-To: <20241010035048.3422527-2-maobibo@loongson.cn>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 12 Oct 2024 10:15:51 +0800
X-Gmail-Original-Message-ID: <CAAhV-H4q_P1HL74k5k+er9QEvZjMaa2kTYz8N+7aJ1vDii=GKQ@mail.gmail.com>
Message-ID: <CAAhV-H4q_P1HL74k5k+er9QEvZjMaa2kTYz8N+7aJ1vDii=GKQ@mail.gmail.com>
Subject: Re: [PATCH 1/4] LoongArch: Set pte entry with PAGE_GLOBAL for kernel space
To: Bibo Mao <maobibo@loongson.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iu0MTPvZ;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Huacai Chen <chenhuacai@kernel.org>
Reply-To: Huacai Chen <chenhuacai@kernel.org>
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

Hi, Bibo,

On Thu, Oct 10, 2024 at 11:50=E2=80=AFAM Bibo Mao <maobibo@loongson.cn> wro=
te:
>
> Unlike general architectures, there are two pages for one TLB entry
> on LoongArch system. For kernel space, it requires both two pte
> entries with PAGE_GLOBAL set, else HW treats it as non-global tlb,
> there will be potential problems if tlb entry for kernel space is
> not global. Such as fail to flush kernel tlb with function
> local_flush_tlb_kernel_range() which only flush tlb with global bit.
>
> Here function kernel_pte_init() is added, it can be used to init
> pte table when it is created, so the default inital pte is
> PAGE_GLOBAL rather than zero at beginning.
I think kernel_pte_init() is also needed in zero_pmd_populate() in
mm/kasan/init.c. And moreover, the second patch should be squashed in
this one because they should be as a whole. Though the second one
touches the common code, I can merge it with mm maintainer's acked-by.


Huacai

>
> Kernel space areas includes fixmap, percpu, vmalloc and kasan areas
> set default pte entry with PAGE_GLOBAL set.
>
> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
> ---
>  arch/loongarch/include/asm/pgalloc.h | 13 +++++++++++++
>  arch/loongarch/include/asm/pgtable.h |  1 +
>  arch/loongarch/mm/init.c             |  4 +++-
>  arch/loongarch/mm/kasan_init.c       |  4 +++-
>  arch/loongarch/mm/pgtable.c          | 22 ++++++++++++++++++++++
>  5 files changed, 42 insertions(+), 2 deletions(-)
>
> diff --git a/arch/loongarch/include/asm/pgalloc.h b/arch/loongarch/includ=
e/asm/pgalloc.h
> index 4e2d6b7ca2ee..b2698c03dc2c 100644
> --- a/arch/loongarch/include/asm/pgalloc.h
> +++ b/arch/loongarch/include/asm/pgalloc.h
> @@ -10,8 +10,21 @@
>
>  #define __HAVE_ARCH_PMD_ALLOC_ONE
>  #define __HAVE_ARCH_PUD_ALLOC_ONE
> +#define __HAVE_ARCH_PTE_ALLOC_ONE_KERNEL
>  #include <asm-generic/pgalloc.h>
>
> +static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm)
> +{
> +       pte_t *pte;
> +
> +       pte =3D (pte_t *) __get_free_page(GFP_KERNEL);
> +       if (!pte)
> +               return NULL;
> +
> +       kernel_pte_init(pte);
> +       return pte;
> +}
> +
>  static inline void pmd_populate_kernel(struct mm_struct *mm,
>                                        pmd_t *pmd, pte_t *pte)
>  {
> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/includ=
e/asm/pgtable.h
> index 9965f52ef65b..22e3a8f96213 100644
> --- a/arch/loongarch/include/asm/pgtable.h
> +++ b/arch/loongarch/include/asm/pgtable.h
> @@ -269,6 +269,7 @@ extern void set_pmd_at(struct mm_struct *mm, unsigned=
 long addr, pmd_t *pmdp, pm
>  extern void pgd_init(void *addr);
>  extern void pud_init(void *addr);
>  extern void pmd_init(void *addr);
> +extern void kernel_pte_init(void *addr);
>
>  /*
>   * Encode/decode swap entries and swap PTEs. Swap PTEs are all PTEs that
> diff --git a/arch/loongarch/mm/init.c b/arch/loongarch/mm/init.c
> index 8a87a482c8f4..9f26e933a8a3 100644
> --- a/arch/loongarch/mm/init.c
> +++ b/arch/loongarch/mm/init.c
> @@ -198,9 +198,11 @@ pte_t * __init populate_kernel_pte(unsigned long add=
r)
>         if (!pmd_present(pmdp_get(pmd))) {
>                 pte_t *pte;
>
> -               pte =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> +               pte =3D memblock_alloc_raw(PAGE_SIZE, PAGE_SIZE);
>                 if (!pte)
>                         panic("%s: Failed to allocate memory\n", __func__=
);
> +
> +               kernel_pte_init(pte);
>                 pmd_populate_kernel(&init_mm, pmd, pte);
>         }
>
> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_ini=
t.c
> index 427d6b1aec09..34988573b0d5 100644
> --- a/arch/loongarch/mm/kasan_init.c
> +++ b/arch/loongarch/mm/kasan_init.c
> @@ -152,6 +152,8 @@ static void __init kasan_pte_populate(pmd_t *pmdp, un=
signed long addr,
>                 phys_addr_t page_phys =3D early ?
>                                         __pa_symbol(kasan_early_shadow_pa=
ge)
>                                               : kasan_alloc_zeroed_page(n=
ode);
> +               if (!early)
> +                       kernel_pte_init(__va(page_phys));
>                 next =3D addr + PAGE_SIZE;
>                 set_pte(ptep, pfn_pte(__phys_to_pfn(page_phys), PAGE_KERN=
EL));
>         } while (ptep++, addr =3D next, addr !=3D end && __pte_none(early=
, ptep_get(ptep)));
> @@ -287,7 +289,7 @@ void __init kasan_init(void)
>                 set_pte(&kasan_early_shadow_pte[i],
>                         pfn_pte(__phys_to_pfn(__pa_symbol(kasan_early_sha=
dow_page)), PAGE_KERNEL_RO));
>
> -       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> +       kernel_pte_init(kasan_early_shadow_page);
>         csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_CSR_PGDH);
>         local_flush_tlb_all();
>
> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtable.c
> index eb6a29b491a7..228ffc1db0a3 100644
> --- a/arch/loongarch/mm/pgtable.c
> +++ b/arch/loongarch/mm/pgtable.c
> @@ -38,6 +38,28 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
>  }
>  EXPORT_SYMBOL_GPL(pgd_alloc);
>
> +void kernel_pte_init(void *addr)
> +{
> +       unsigned long *p, *end;
> +       unsigned long entry;
> +
> +       entry =3D (unsigned long)_PAGE_GLOBAL;
> +       p =3D (unsigned long *)addr;
> +       end =3D p + PTRS_PER_PTE;
> +
> +       do {
> +               p[0] =3D entry;
> +               p[1] =3D entry;
> +               p[2] =3D entry;
> +               p[3] =3D entry;
> +               p[4] =3D entry;
> +               p +=3D 8;
> +               p[-3] =3D entry;
> +               p[-2] =3D entry;
> +               p[-1] =3D entry;
> +       } while (p !=3D end);
> +}
> +
>  void pgd_init(void *addr)
>  {
>         unsigned long *p, *end;
> --
> 2.39.3
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H4q_P1HL74k5k%2Ber9QEvZjMaa2kTYz8N%2B7aJ1vDii%3DGKQ%40mail.=
gmail.com.
