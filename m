Return-Path: <kasan-dev+bncBD4IBNO3YAGRB6FZ6CYQMGQENSJBNBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 308AD8C08A0
	for <lists+kasan-dev@lfdr.de>; Thu,  9 May 2024 02:46:50 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6a0e381e63csf4089446d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 08 May 2024 17:46:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715215609; cv=pass;
        d=google.com; s=arc-20160816;
        b=vpbcTelEkFX/++B0zBOYKApq0v4lSWfeVHCqi2yFZ0wJbege/qPokjNWQXuCXlHOTS
         0TIjzPyT8BCB4Vm4rtd9jz22dq4acCcW19DXGxW9Nrw+dlszLdkPfqMV5LC9RDA8rCsV
         V30i3xVrSREfyIq0+o92UutLBwwmAwO0T1T+wuiRNT3B8WgXCEDf50rk7VlSEFGrkv/v
         KRpIuiDs9P6hhi/Lu4oqVF4XzveTq4A2icrNQ/SL6TLgCcABZjsP6j23Juz6R5xqndsF
         zK7xpyzqFLm9byGZMgifgxBPs+ndMosbhTVH9snMI77dL4sOPGu6uTOJzg+qBN9GQw1r
         qJxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=WKipWfxOjU+ZDGL/RwVFBokl7Gj4071tODrkPy9qJp0=;
        fh=AFHRe6w5L67VbUQIEGHvxYkQIRa5mZb7hnrqpUPr4v0=;
        b=XXIYJHkn9KKmDYd9CKtCKCuNNK4bFEU1lwEEB0xWmW0hzKP5HLRTMDYWlQuv2BB9iX
         2g25/YqWAx0RosQ9rluHh/idS1Z+fPovl47SzILhr1ojKk6BVIfckVnhSf+kc/0MIq3b
         iJ6GCR6AiQV4zZmVKr5e4grAyUKPUwV/zwcvUVDBE9CbF0kRkyYJNWM1n7poYVTYWl0L
         nF4N9uKL9+FTUXx+CYCqhpfmy3QHWgll+SUWa9c6kdka/e+l1ImHw5P4Y3e/6iBXAoiW
         phCDEGstE0STipDnENjHvRhe9rufi3k7V/nsIdOXPGAaWeDAKOGijqLx/dz6/Xvhd9Gy
         OyDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=B2t+qzBu;
       spf=pass (google.com: domain of 21cnbao@gmail.com designates 2607:f8b0:4864:20::a2d as permitted sender) smtp.mailfrom=21cnbao@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715215609; x=1715820409; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WKipWfxOjU+ZDGL/RwVFBokl7Gj4071tODrkPy9qJp0=;
        b=BLzimhGrYz8XZ54FpcfMScyMGBqQv4Q7QbeqT/zczc8yXbOaRG95YIZ+YfERfoKdLv
         AXrmmA23ugT1UzQFLIsn5AyESrkiUabG1BLTAS9e3LU8pG140ezg/67ZLrpie2dDQDBJ
         DDQp/s/HEyyHDUNJrzI82Q9852dVcGYUjcVKBUYGVp0WY4RFbmXkP8lSaxoewdfV4NzB
         8pW+7ihDEelnEDr1RL4mjDVZVN7QhnUWALSGcqNLExBbA0Gh823Jx9PluQptzqT+WMzf
         ZZ3mKS2UaoCI6K9yU52FKHEP9klT+4oOdvAPpuBCr/sdEPiAyxm1pffSAmebM6EeBqbE
         VavQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1715215609; x=1715820409; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WKipWfxOjU+ZDGL/RwVFBokl7Gj4071tODrkPy9qJp0=;
        b=FhBChEvjNZ0jtOd9dcBpM62rBd47ftciIWRwi5uzqqvtcFyDGVTjng/0S/QancQxAM
         /+PLpy/FQehNaFO/pU66zfKI+6H5hv0+ItXJxDls6zCj/Y7Ad18QU6XQVk436dEJMRFB
         wusGH3YjPRAzNS+NxgQKxZx6jUSwj4rxJshWNM4JnryIdMkyVNaaFmjgLC0GOxOAfxv9
         FSWuGzpJ9nf36PMgqDjrjGOD0682ROtbDH+QfcQCBD3u6Fc7CVuwSY0WvCGdOVUmJN9I
         w1U/6qSkp1qYJmL8/dx7n9eqUuGQZYLfKxjXKQ23lmz4BpD4GymTXGOI8l94kCqVmVcM
         iHqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715215609; x=1715820409;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=WKipWfxOjU+ZDGL/RwVFBokl7Gj4071tODrkPy9qJp0=;
        b=Dpc0atNV2rxXXngotguzaxcDTkfPoWyiH3Zkx76BZ2uQW2iZkffkvwEtpRciqyXOgz
         BTyxcdnmoHOxhP8b0JFl9m503XjHhw1bX1rgS//jxIah0hYK/bDYvfRjAp9xa0OSoL/A
         4Z9quQozOiKIpa+eqGSh0tanXOnebB/8L72FzYQ6OHrZ+mkU0dfGqseIyqyQMOqv5w7z
         U0qJ6SiApyUaaqCeAiWUGvAJ6Yfo5ejnrOI392P7uDNCsdrDTJ6DgLn9STSNp23X9YbB
         yCH4F8etoVsxkog3oQSKunZX+ZYwFdk6Y2m4NODj/2Gom8LF83CYcjwUF/EP5CTrf0AE
         ly2A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVBqeXlM5FRyEGcM2GTY/ezy23IcEwUa3ap/GCL92mSq5T2lAJNrwwO7FbuacYnIJoGLLSt7GCSi82X7Ost1hAQuz+DT7MFMQ==
X-Gm-Message-State: AOJu0YyCZfeu/172rzV0QvtmysuPeTu0t3lb6CWhVp15Tnz1ybqazfrT
	T7yRSr2ih3fvoB/qlS4QSnf4VBKMB9yMgXfY7S28hmzc+Njt3Lb3
X-Google-Smtp-Source: AGHT+IHpe8VgpHe4EXS43lmVP49eOBT57pCVGw0MoeqfxJY1TOJMIPliFztKM2fkd7Jy6gxKJ5tGTg==
X-Received: by 2002:ad4:5be8:0:b0:6a0:48c3:52ac with SMTP id 6a1803df08f44-6a1514bdd33mr48364666d6.45.1715215608640;
        Wed, 08 May 2024 17:46:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1cc4:b0:6a0:dbcb:706 with SMTP id
 6a1803df08f44-6a15d4471f3ls3608986d6.1.-pod-prod-02-us; Wed, 08 May 2024
 17:46:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW5tFOghR7B0BeJSRKnRTpctEHzMJxtulinl+Xzx2CbQjGxlUzTwzBc24l1KV6NRxWYFgQxoyBxfQrYfrVDAY4IYUl9qjLoqeuvfg==
X-Received: by 2002:ad4:5ca2:0:b0:6a0:d312:2ba5 with SMTP id 6a1803df08f44-6a1514eb132mr60290316d6.61.1715215608004;
        Wed, 08 May 2024 17:46:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715215607; cv=none;
        d=google.com; s=arc-20160816;
        b=tPA9JyMSzHbl/WWYvBaF7XD1uhKE+G4FoZmnm7awJiEwIFpHhIqV9xn3tO+mgLDT8/
         Ip6ntEBw8TTpt8Fx0EErRwLUYI/xaNuWeFZcVWqiZy5EHSDE9g/p9DLpLhKBYf+TdUQ0
         0UWXGdVHTJk96GOjUfFKCy66UHH6YsiXJgDJsj1GQh0ml0xrRYzVC4oUxF1sgAMRSc6X
         Fh4lkLSDko+PutrUCjVL985m8Loon/xjVUh+Fdz5vRt2o70RUPVTkhFia5k68OKShp/0
         VwkhBCygC0ed75/vQPK6iFbn8dGg48uIRAmJmgmPUBpoVcYrJTc0M+RIhvfNIVRGykVA
         I1ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1HutaMr4YNAQdV0piVG8U9fxjw32ZuJHu11VAl/8knE=;
        fh=/Ce5aD47EqAqaKiu9MtezlkhlqTwIsQy1YKcayUSkI8=;
        b=O8Fp624WjSv+cqEMEaoeh9BmMMlTZSEV3l11W/i0svF4bOQ6IpTSAvZIUgTkmYZfRF
         4549HE+FypVTf04w8k8mnklBx9B8lgfCjrslODhmK2p6mbU4UEN9Ku1rEVY1odsd5nJ/
         sUEu7l1v9dr82oNbkwKRglqUhpu3qoomxzBJY6R+jrmOLk0q7zbDWfqDAikrm+Iqqyr8
         W80iyL0J/lm5gaKLHcEMqFbbr0cbzhopgkP7TQ2iqpwda7F05xaG1tZsYimVQ/Us5frv
         BRgUD3nKTOMRmu2gaD3oQsKeWb0pjAa5YqRipYUXnGzz8mG0hNqthhDjrg8O2SNsUlQc
         Mmlw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=B2t+qzBu;
       spf=pass (google.com: domain of 21cnbao@gmail.com designates 2607:f8b0:4864:20::a2d as permitted sender) smtp.mailfrom=21cnbao@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vk1-xa2d.google.com (mail-vk1-xa2d.google.com. [2607:f8b0:4864:20::a2d])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6a15f3540c8si195366d6.7.2024.05.08.17.46.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 May 2024 17:46:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 21cnbao@gmail.com designates 2607:f8b0:4864:20::a2d as permitted sender) client-ip=2607:f8b0:4864:20::a2d;
Received: by mail-vk1-xa2d.google.com with SMTP id 71dfb90a1353d-4df37a78069so138381e0c.1
        for <kasan-dev@googlegroups.com>; Wed, 08 May 2024 17:46:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUhk4F1DReAZyKzu5SffpJjx4YLY9vxIo+8MvSM/gSkZqo9/U0zhnCVBhlNTnxj2JainotEvu3yIQ9AJOGxmcPlsR1yxf1T79AonA==
X-Received: by 2002:a05:6122:7cb:b0:4d8:797b:94df with SMTP id
 71dfb90a1353d-4df6929c091mr4383063e0c.2.1715215607538; Wed, 08 May 2024
 17:46:47 -0700 (PDT)
MIME-Version: 1.0
References: <20240508191931.46060-1-alexghiti@rivosinc.com> <20240508191931.46060-2-alexghiti@rivosinc.com>
In-Reply-To: <20240508191931.46060-2-alexghiti@rivosinc.com>
From: Barry Song <21cnbao@gmail.com>
Date: Thu, 9 May 2024 12:46:35 +1200
Message-ID: <CAGsJ_4xayC4D4y0d7SPXxCvuW4-rJQUCa_-OUDSsOGm_HyPm1w@mail.gmail.com>
Subject: Re: [PATCH 01/12] mm, arm64: Rename ARM64_CONTPTE to THP_CONTPTE
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: Ryan Roberts <ryan.roberts@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Ard Biesheuvel <ardb@kernel.org>, Anup Patel <anup@brainfault.org>, 
	Atish Patra <atishp@atishpatra.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-riscv@lists.infradead.org, linux-efi@vger.kernel.org, 
	kvm@vger.kernel.org, kvm-riscv@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 21cnbao@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=B2t+qzBu;       spf=pass
 (google.com: domain of 21cnbao@gmail.com designates 2607:f8b0:4864:20::a2d as
 permitted sender) smtp.mailfrom=21cnbao@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, May 9, 2024 at 7:20=E2=80=AFAM Alexandre Ghiti <alexghiti@rivosinc.=
com> wrote:
>
> The ARM64_CONTPTE config represents the capability to transparently use
> contpte mappings for THP userspace mappings, which will be implemented
> in the next commits for riscv, so make this config more generic and move
> it to mm.
>
> Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
> ---
>  arch/arm64/Kconfig               | 9 ---------
>  arch/arm64/include/asm/pgtable.h | 6 +++---
>  arch/arm64/mm/Makefile           | 2 +-
>  mm/Kconfig                       | 9 +++++++++
>  4 files changed, 13 insertions(+), 13 deletions(-)
>
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index ac2f6d906cc3..9d823015b4e5 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -2227,15 +2227,6 @@ config UNWIND_PATCH_PAC_INTO_SCS
>         select UNWIND_TABLES
>         select DYNAMIC_SCS
>
> -config ARM64_CONTPTE
> -       bool "Contiguous PTE mappings for user memory" if EXPERT
> -       depends on TRANSPARENT_HUGEPAGE
> -       default y
> -       help
> -         When enabled, user mappings are configured using the PTE contig=
uous
> -         bit, for any mappings that meet the size and alignment requirem=
ents.
> -         This reduces TLB pressure and improves performance.
> -
>  endmenu # "Kernel Features"
>
>  menu "Boot options"
> diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pg=
table.h
> index 7c2938cb70b9..1758ce71fae9 100644
> --- a/arch/arm64/include/asm/pgtable.h
> +++ b/arch/arm64/include/asm/pgtable.h
> @@ -1369,7 +1369,7 @@ extern void ptep_modify_prot_commit(struct vm_area_=
struct *vma,
>                                     unsigned long addr, pte_t *ptep,
>                                     pte_t old_pte, pte_t new_pte);
>
> -#ifdef CONFIG_ARM64_CONTPTE
> +#ifdef CONFIG_THP_CONTPTE

Is it necessarily THP? can't be hugetlb or others? I feel THP_CONTPTE
isn't a good name.

>
>  /*
>   * The contpte APIs are used to transparently manage the contiguous bit =
in ptes
> @@ -1622,7 +1622,7 @@ static inline int ptep_set_access_flags(struct vm_a=
rea_struct *vma,
>         return contpte_ptep_set_access_flags(vma, addr, ptep, entry, dirt=
y);
>  }
>
> -#else /* CONFIG_ARM64_CONTPTE */
> +#else /* CONFIG_THP_CONTPTE */
>
>  #define ptep_get                               __ptep_get
>  #define set_pte                                        __set_pte
> @@ -1642,7 +1642,7 @@ static inline int ptep_set_access_flags(struct vm_a=
rea_struct *vma,
>  #define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
>  #define ptep_set_access_flags                  __ptep_set_access_flags
>
> -#endif /* CONFIG_ARM64_CONTPTE */
> +#endif /* CONFIG_THP_CONTPTE */
>
>  int find_num_contig(struct mm_struct *mm, unsigned long addr,
>                     pte_t *ptep, size_t *pgsize);
> diff --git a/arch/arm64/mm/Makefile b/arch/arm64/mm/Makefile
> index 60454256945b..52a1b2082627 100644
> --- a/arch/arm64/mm/Makefile
> +++ b/arch/arm64/mm/Makefile
> @@ -3,7 +3,7 @@ obj-y                           :=3D dma-mapping.o extabl=
e.o fault.o init.o \
>                                    cache.o copypage.o flush.o \
>                                    ioremap.o mmap.o pgd.o mmu.o \
>                                    context.o proc.o pageattr.o fixmap.o
> -obj-$(CONFIG_ARM64_CONTPTE)    +=3D contpte.o
> +obj-$(CONFIG_THP_CONTPTE)      +=3D contpte.o
>  obj-$(CONFIG_HUGETLB_PAGE)     +=3D hugetlbpage.o
>  obj-$(CONFIG_PTDUMP_CORE)      +=3D ptdump.o
>  obj-$(CONFIG_PTDUMP_DEBUGFS)   +=3D ptdump_debugfs.o
> diff --git a/mm/Kconfig b/mm/Kconfig
> index c325003d6552..fd4de221a1c6 100644
> --- a/mm/Kconfig
> +++ b/mm/Kconfig
> @@ -984,6 +984,15 @@ config ARCH_HAS_CACHE_LINE_SIZE
>  config ARCH_HAS_CONTPTE
>         bool
>
> +config THP_CONTPTE
> +       bool "Contiguous PTE mappings for user memory" if EXPERT
> +       depends on ARCH_HAS_CONTPTE && TRANSPARENT_HUGEPAGE
> +       default y
> +       help
> +         When enabled, user mappings are configured using the PTE contig=
uous
> +         bit, for any mappings that meet the size and alignment requirem=
ents.
> +         This reduces TLB pressure and improves performance.
> +
>  config ARCH_HAS_CURRENT_STACK_POINTER
>         bool
>         help
> --
> 2.39.2

Thanks
Barry

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAGsJ_4xayC4D4y0d7SPXxCvuW4-rJQUCa_-OUDSsOGm_HyPm1w%40mail.gmail.=
com.
