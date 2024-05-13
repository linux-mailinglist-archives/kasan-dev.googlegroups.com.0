Return-Path: <kasan-dev+bncBDXY7I6V6AMRBCFCRCZAMGQEYPA5WFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 400BE8C416F
	for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 15:09:30 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-34e0d47c9b7sf2259559f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 06:09:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715605770; cv=pass;
        d=google.com; s=arc-20160816;
        b=dbL0gAKVikQ9wsj+3agwr49WPY19P1Z6bhEy/FOqUieNZNzpOGzFGOTfHLuewNBuIi
         Un8C73UoQMHxqhWmzdMnZ+sL7Rj6KQU3z65ilgbuIDKc1oEC5pICUOtsJaMjWSWzh5Rh
         QrizSIc9VkoWOiMtXDJl3o8xQjy4bsbPW7IplXvt6WwgjBvWrv7K5Ms4PuEo5nb+GB9S
         ZVNtkdY5Tr7GeXKAwX3zB6AUKYgD/revUgIr4e2XMrzCEGbFPv1Rh8j0JLUavmAcVdiQ
         kXFj9CHFj01/F/pmm92eL+CHDEA7rzNRlzQFnwknyEinGCqTgtQKs/8t4iDpzL/fmzL8
         WPdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=4yzWwqsGlHce/PTOWBQezxuoR2UyuEndYqjbobgYsgM=;
        fh=SHnZvlOdaordyhvnydPlRl8D1GYtUExLuScWaQojImo=;
        b=KoMbtSPnRoikpCbWledcxXMbQYY3+bwKzZ4ptCpzlY8YziPt6LlnE9dGG2kr9TPKsK
         qUflODl0WOOszpRbs7ysgWYx5HSOR6nUkWiP8KW05q14IOrQCmMp0frEBzdX+riTpMmr
         3W1vDKXNuhed/QkDwV4HVvc3HR1J9GppwUIJNqJtSbbgV+3P5rAnzZuPLjUJ4H2VjFHS
         2G5gB6WDCi8xaZO4RiOUncmO59ocKfk8nu3/C+DKTa3MK6qR/Ldd7QBG/Tjz9Cd2nhIE
         xwfIT1CfII6uj0UNZg/Xp0Ui+uZ7qNX4swhj09lxBauBk9Dp2+zynWGIK7iWYBQxSWps
         9skA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=2KNjVWzH;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715605770; x=1716210570; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4yzWwqsGlHce/PTOWBQezxuoR2UyuEndYqjbobgYsgM=;
        b=nawybI8OGDhplRLa3Q2egme1O5FPmmNvLIYyhXx9LYsaK5AbWUwln/6CxJ19K/rLSc
         7TYg+whO+/TYJ3FKuQZICiz6x/ZhVnOdznHMOGJbcawf1Ed/ZsLzrKqI56DLpWceMb9u
         bILn/nvbN+1Vh5h02XwHbeX7ETscTwWYuGtzyJ/OPCoJlUUridmXWfmgy2XlX6DSuJBa
         3xnQfwbK6JaI6qhFRmzkf4RQBRMNi6nrUfKlaxriM5DhSTIWpbGZO323MGOZi7+SpcW2
         Fgg+DEZuVuWdhL/iL9WK4Ixrr7aW+j9cMKcIzYS/9SNfULfmCNzke7yKqYFi8gpGOVku
         t/dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715605770; x=1716210570;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4yzWwqsGlHce/PTOWBQezxuoR2UyuEndYqjbobgYsgM=;
        b=i+XaOLstj8Wkvtzh6unUd4tqC2s6nSrOn637FpCdnH/BQbhZIZGiKtuyNU4KytlRUH
         NO/Waa8vDNo1MOXNFM4NGxDfbyJy1D1m5ltg446pQqKeSwYGOvUl+2JET2sfDfArVeEk
         3exjVCGh2geEWvPC/ySNlPms3P2PdD7t2ANPiWkLuBoCVYo1eauk3nhJ6afbcjXwEcf8
         /1AqiGB/K1h6fiS1gPvbC28GWqeMrIwmEpflq0YrBHtcyrB72kBAEMOmaDXs8dw0GIZr
         eocgyW0bdyf5etueqhuN6p+pCiw3oYp5ZuIUIrjDDJ962WW6gsEp+kAz2St7Vq1KVxU3
         vwUw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV3s/XEtgEBpTJ5yLJ0vIp9SYyx2CU0yamCVTC9feF7suFChq5MUvUmuHpgsiSUm1c3mvf/xN8VyOuDwJvrCpJo7fnjaI7cdA==
X-Gm-Message-State: AOJu0Yy8TOryOqfvuhTuUEW0J1QMkCUsvUlREivlmBN8tIcEvU23RydS
	mhoWjBSKOPlIgyJhTmyWzNjfvbvqdcapljpuzlG30hzPT1UN2HJf
X-Google-Smtp-Source: AGHT+IG010ZBtxa+Ga7Nc2nuYlBUbGMBDELrlPL/w1JgeudI2Bg6R7fd7LRiUbcD4UGfeMC0l03wyw==
X-Received: by 2002:adf:f0c1:0:b0:34d:10a9:3a22 with SMTP id ffacd0b85a97d-35049bbf691mr7629115f8f.32.1715605769148;
        Mon, 13 May 2024 06:09:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4985:0:b0:34c:f87b:f9ef with SMTP id ffacd0b85a97d-3501c68e920ls1238406f8f.0.-pod-prod-00-eu;
 Mon, 13 May 2024 06:09:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUsUKuUh5lIDQpRtgJYfEUDZvzNJ5Y3PRbZEV+t1x1SUz42EDzNuGyjigwvqzl3j0LxYP36VfuS4B5QMZXVVoBYeNLRwN/dvNQBMQ==
X-Received: by 2002:a5d:4744:0:b0:34f:33b4:b951 with SMTP id ffacd0b85a97d-350186eacabmr11575271f8f.29.1715605767302;
        Mon, 13 May 2024 06:09:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715605767; cv=none;
        d=google.com; s=arc-20160816;
        b=VM3Sy0LxLg4m9/7+aP/mtydtQiqPVf26Rq7dfg/KN2YjFMvTbP0194Rku+btzXOzhI
         AtFqkYN4Qhfmuag/fGXxnBwH9Cn8Cl75CTev8aJ77KOMB7QjHKmSB6SzJsn/YBscHfW7
         IIwIPvSZZjMV5Dn412RWRIQzfJ3DL7V9izB072eu9+Fwg4hYCGOJHWsdGIXoqT7FkzLU
         MkluhdnI8Dhw/gRpo3fer85GN3cqclBagiKVfbE/H/Fn+Em5kAu29o6ehHkFiuzLKH9z
         COG23kPYPzDMO8tF9ZsxShsfxcz8S/JyGe8kTx4Luiz83uQ/RURHqi3YfsPDKdXEw951
         esgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5MKXjMChMNLDQEAHfT5KxNeT5FU7Py9gH+YOnRbraDE=;
        fh=zFbN/bpIkcByHMtltp3ECC+IfxXiYSlxttVMUFcqvI4=;
        b=KNyIuTycCNxk8RUFrnx3jPGFVfApdF/GHskc5iLg1YA7f407CReazLyMhoKI+PSJFt
         +lYNtmv86orxoBXOoKAiZUDqI7OZTcWa7EGwB0cDqfTLKmAUClE1+4Kk9FaT2OREpkyd
         7Hgj/zNVTDJ/KTX9IJDXC2LOtVUB70YNI3JgaU1EFUAjkz7DW6hYSSK6XMKI5K0xgVnr
         +qOn/kD1ZPHN1V/rS22NmpYoGbrVAh56lfhcRE/uAYLv1N+qeq3KlSqCIUdP99sFbSmW
         wqKlEPUx1dLLZb8euqiWN5ZY23MNQv4dhNcuR6RIFOiyx1F/HsCKOSeO4XY9sbRSEUDb
         698Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=2KNjVWzH;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-ej1-x630.google.com (mail-ej1-x630.google.com. [2a00:1450:4864:20::630])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-41fdfe566easi5642885e9.1.2024.05.13.06.09.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 May 2024 06:09:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::630 as permitted sender) client-ip=2a00:1450:4864:20::630;
Received: by mail-ej1-x630.google.com with SMTP id a640c23a62f3a-a59ce1e8609so926446066b.0
        for <kasan-dev@googlegroups.com>; Mon, 13 May 2024 06:09:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW8BAVKdc7T7CydHVgCIQpFTB18Vhq01wI0PN6cN15eh9HR/0Gdnb2VyFGvumNyjcc6j/Iano2J9M2U+5609eSOKf0xQ2IEpEUCRw==
X-Received: by 2002:a17:906:ca8e:b0:a5a:7b88:8672 with SMTP id
 a640c23a62f3a-a5a7b888747mr3863166b.16.1715605766892; Mon, 13 May 2024
 06:09:26 -0700 (PDT)
MIME-Version: 1.0
References: <20240508191931.46060-1-alexghiti@rivosinc.com>
 <20240508191931.46060-2-alexghiti@rivosinc.com> <CAGsJ_4xayC4D4y0d7SPXxCvuW4-rJQUCa_-OUDSsOGm_HyPm1w@mail.gmail.com>
In-Reply-To: <CAGsJ_4xayC4D4y0d7SPXxCvuW4-rJQUCa_-OUDSsOGm_HyPm1w@mail.gmail.com>
From: Alexandre Ghiti <alexghiti@rivosinc.com>
Date: Mon, 13 May 2024 15:09:15 +0200
Message-ID: <CAHVXubiOo3oe0=-qU2kBaFXebPJvmnc+-1UOPEHS2spcCeMzsw@mail.gmail.com>
Subject: Re: [PATCH 01/12] mm, arm64: Rename ARM64_CONTPTE to THP_CONTPTE
To: Barry Song <21cnbao@gmail.com>
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
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=2KNjVWzH;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

Hi Barry,

On Thu, May 9, 2024 at 2:46=E2=80=AFAM Barry Song <21cnbao@gmail.com> wrote=
:
>
> On Thu, May 9, 2024 at 7:20=E2=80=AFAM Alexandre Ghiti <alexghiti@rivosin=
c.com> wrote:
> >
> > The ARM64_CONTPTE config represents the capability to transparently use
> > contpte mappings for THP userspace mappings, which will be implemented
> > in the next commits for riscv, so make this config more generic and mov=
e
> > it to mm.
> >
> > Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
> > ---
> >  arch/arm64/Kconfig               | 9 ---------
> >  arch/arm64/include/asm/pgtable.h | 6 +++---
> >  arch/arm64/mm/Makefile           | 2 +-
> >  mm/Kconfig                       | 9 +++++++++
> >  4 files changed, 13 insertions(+), 13 deletions(-)
> >
> > diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> > index ac2f6d906cc3..9d823015b4e5 100644
> > --- a/arch/arm64/Kconfig
> > +++ b/arch/arm64/Kconfig
> > @@ -2227,15 +2227,6 @@ config UNWIND_PATCH_PAC_INTO_SCS
> >         select UNWIND_TABLES
> >         select DYNAMIC_SCS
> >
> > -config ARM64_CONTPTE
> > -       bool "Contiguous PTE mappings for user memory" if EXPERT
> > -       depends on TRANSPARENT_HUGEPAGE
> > -       default y
> > -       help
> > -         When enabled, user mappings are configured using the PTE cont=
iguous
> > -         bit, for any mappings that meet the size and alignment requir=
ements.
> > -         This reduces TLB pressure and improves performance.
> > -
> >  endmenu # "Kernel Features"
> >
> >  menu "Boot options"
> > diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/=
pgtable.h
> > index 7c2938cb70b9..1758ce71fae9 100644
> > --- a/arch/arm64/include/asm/pgtable.h
> > +++ b/arch/arm64/include/asm/pgtable.h
> > @@ -1369,7 +1369,7 @@ extern void ptep_modify_prot_commit(struct vm_are=
a_struct *vma,
> >                                     unsigned long addr, pte_t *ptep,
> >                                     pte_t old_pte, pte_t new_pte);
> >
> > -#ifdef CONFIG_ARM64_CONTPTE
> > +#ifdef CONFIG_THP_CONTPTE
>
> Is it necessarily THP? can't be hugetlb or others? I feel THP_CONTPTE
> isn't a good name.

This does not target hugetlbfs (see my other patchset for that here
https://lore.kernel.org/linux-riscv/7504a525-8211-48b3-becb-a6e838c1b42e@ar=
m.com/T/#m57d273d680fc531b3aa1074e6f8558a52ba5badc).

What could be "others" here?

Thanks for your comment,

Alex

>
> >
> >  /*
> >   * The contpte APIs are used to transparently manage the contiguous bi=
t in ptes
> > @@ -1622,7 +1622,7 @@ static inline int ptep_set_access_flags(struct vm=
_area_struct *vma,
> >         return contpte_ptep_set_access_flags(vma, addr, ptep, entry, di=
rty);
> >  }
> >
> > -#else /* CONFIG_ARM64_CONTPTE */
> > +#else /* CONFIG_THP_CONTPTE */
> >
> >  #define ptep_get                               __ptep_get
> >  #define set_pte                                        __set_pte
> > @@ -1642,7 +1642,7 @@ static inline int ptep_set_access_flags(struct vm=
_area_struct *vma,
> >  #define __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
> >  #define ptep_set_access_flags                  __ptep_set_access_flags
> >
> > -#endif /* CONFIG_ARM64_CONTPTE */
> > +#endif /* CONFIG_THP_CONTPTE */
> >
> >  int find_num_contig(struct mm_struct *mm, unsigned long addr,
> >                     pte_t *ptep, size_t *pgsize);
> > diff --git a/arch/arm64/mm/Makefile b/arch/arm64/mm/Makefile
> > index 60454256945b..52a1b2082627 100644
> > --- a/arch/arm64/mm/Makefile
> > +++ b/arch/arm64/mm/Makefile
> > @@ -3,7 +3,7 @@ obj-y                           :=3D dma-mapping.o exta=
ble.o fault.o init.o \
> >                                    cache.o copypage.o flush.o \
> >                                    ioremap.o mmap.o pgd.o mmu.o \
> >                                    context.o proc.o pageattr.o fixmap.o
> > -obj-$(CONFIG_ARM64_CONTPTE)    +=3D contpte.o
> > +obj-$(CONFIG_THP_CONTPTE)      +=3D contpte.o
> >  obj-$(CONFIG_HUGETLB_PAGE)     +=3D hugetlbpage.o
> >  obj-$(CONFIG_PTDUMP_CORE)      +=3D ptdump.o
> >  obj-$(CONFIG_PTDUMP_DEBUGFS)   +=3D ptdump_debugfs.o
> > diff --git a/mm/Kconfig b/mm/Kconfig
> > index c325003d6552..fd4de221a1c6 100644
> > --- a/mm/Kconfig
> > +++ b/mm/Kconfig
> > @@ -984,6 +984,15 @@ config ARCH_HAS_CACHE_LINE_SIZE
> >  config ARCH_HAS_CONTPTE
> >         bool
> >
> > +config THP_CONTPTE
> > +       bool "Contiguous PTE mappings for user memory" if EXPERT
> > +       depends on ARCH_HAS_CONTPTE && TRANSPARENT_HUGEPAGE
> > +       default y
> > +       help
> > +         When enabled, user mappings are configured using the PTE cont=
iguous
> > +         bit, for any mappings that meet the size and alignment requir=
ements.
> > +         This reduces TLB pressure and improves performance.
> > +
> >  config ARCH_HAS_CURRENT_STACK_POINTER
> >         bool
> >         help
> > --
> > 2.39.2
>
> Thanks
> Barry

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHVXubiOo3oe0%3D-qU2kBaFXebPJvmnc%2B-1UOPEHS2spcCeMzsw%40mail.gm=
ail.com.
