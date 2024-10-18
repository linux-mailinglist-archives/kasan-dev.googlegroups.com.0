Return-Path: <kasan-dev+bncBAABB5N7Y64AMGQEMYGXMSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id EF0379A33AD
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 06:11:35 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-71e51a31988sf1732650b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 21:11:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729224694; cv=pass;
        d=google.com; s=arc-20240605;
        b=exvQ/x4e2rOnTKdrj6VzF3PGscWYLVhwb9RzAvOgJkzKkH21+rRkEaPIOZMtsGaoSx
         FE3NSTXTB7oZkn0jtzPv08vWqjoZ0Ze1L7/g0sbTf87YuQP7c2z58Akpgm8nf6+rKzwc
         NrFDVw7N72TFZNbN1kEWlKABfABIgrTOJbVU0+JYD4FfxpgSmX+GPez1w9pItZJ537fH
         jDKvtnHI7qO6uZU4cWt/BmrIT+LmHLrgJrvgyYdemcxeuQB9KPhsKKu7dC4n/Xa5FUvj
         CwNByQOpwzAUO1JeJTp2y650d5lmyA60vTMQbHWczFpeMcFKVi53IMaN239AE9SDHfxq
         Av1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=voZA5xUHZxVIoene/zr/68noZo8FvxP6vDONSg1sfkY=;
        fh=QeIYMh/XP1eje9aOZaCeq8KUfogDzYYThh9UPey/n8o=;
        b=hNVurtwwstB2ynDp/CQk3uMsX3zwFVopvS0IcK6C5xbZnp3f959z3Jq4/DM9GN86op
         Fil9KlrbPK7PLBTfHq15yQMGqQuRREP6eQK/p+06WGIItZmRKmK8DIslf6Ogfk/AKz0E
         3GVhM639nojAJreJMC8dCRT6SJB4OJk1O3o9xWIqNNQZ6IO70Zn/l05BwZ7Y5AX94uV9
         2FxAsegpF4rnm65HWqT1U4ArdafUShXPoDlvJB4HD59CgZdvcq5lycdvrhQt6rbkxXlW
         gdn3YWPpUNnP87szduSnZ9RdeRrT86kKkSeOEGJfTf6uZLtwXV1VIA9vty5nJkHCCgX7
         faXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pO2C0poX;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729224694; x=1729829494; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=voZA5xUHZxVIoene/zr/68noZo8FvxP6vDONSg1sfkY=;
        b=IyfkGpNWsKjzoIeVFhP5bZztuKsKBt+S21KyKvQBpcaKBycaHQtS/mgHInySmVRwOW
         AYvEsp9pz8bdwsrz8giPCKogDeRcCLSYf05Cy5WWxA+yLmqI3G4w8TE9GUXqhH0vIBf8
         Pzj1xNOFtyL9wn2iEttwn4p5wT7dhLnh3XhF7loCabEQbQQF3sUofpvZdC/nuMPebM6K
         m4GVUhVcZW0US1tKW9txQNvjP7TwZ7YEwh8aiujRYM46BMTooOxMvb/EfZKo9eH6T1Pp
         teZ1RKvawRRUsxfTXwrPsMpQEYCSzj2TBprjzHwpQ/4xM3GwY2dJY0YYNQ5g8ZaHEb3z
         lndA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729224694; x=1729829494;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=voZA5xUHZxVIoene/zr/68noZo8FvxP6vDONSg1sfkY=;
        b=nrZi7Q4nAdWW3YK2WBJyvyVvHRMviuzMo+VEuE39/SuyoLthwtEaD2OdC6db1zC5Qc
         XkBcMLIIeAo4339Oh9pKzk5JpFUdtn7r1E02vpE6Doxov1TDuvjKMenp+wLez98WIbVc
         kxZRBLp9TA8kKWrQBsIDhT0XxfmkGXGMbs6of6osseeqMRZUDbTr0O1zHvnZ8fiV22Lg
         jRdvWfGjr78vOfWdABRcVFzEF2y9AzDJsLzGVrVKDT8HkISwqvCMw68dIi3hmV5IbnEc
         2qtcu5hcg3P12YaIlG8vEUeaaCudN748Wezdu6q8WNDb1UNaR2I5ye0NVcocss3fNdU/
         ZkTw==
X-Forwarded-Encrypted: i=2; AJvYcCXpuHgLQyfqVyoh4IM5VrjlnLUZgTE6Lp9YPasefm6O64YtvEEqdd5Gedec44WeJzYJyFaKdw==@lfdr.de
X-Gm-Message-State: AOJu0YyaCJC9wd6TOiH1LHUZ/s/ie7Kq/DqhG1cx1XIRFubQxA3hGxdE
	GhMcfGGf10hZPJri5EM9rziqSe4Xf7P55K5Lxy+RWqUoOoV0YW4P
X-Google-Smtp-Source: AGHT+IFniGsYFFYKswHfaL9mnxVQLW73fFTh80h0zOHDg1E9tGX0Dn3IaDABUzBMm2iWgaqEnbAGdQ==
X-Received: by 2002:a05:6a00:2e86:b0:71d:eb7d:20ed with SMTP id d2e1a72fcca58-71ea3151a93mr2186902b3a.12.1729224693740;
        Thu, 17 Oct 2024 21:11:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2296:b0:71e:7647:8d88 with SMTP id
 d2e1a72fcca58-71e8f88765fls1562543b3a.0.-pod-prod-05-us; Thu, 17 Oct 2024
 21:11:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVHM8jtl7WyXVtCY+kM9ZmgSxpwS6/2XR4K7bCOv12D/qugpQmZyNkJTECosZx6n3cUASW4gtCbCmU=@googlegroups.com
X-Received: by 2002:a05:6a21:4781:b0:1d9:7f2:a3c8 with SMTP id adf61e73a8af0-1d92c5089aamr1960253637.22.1729224690943;
        Thu, 17 Oct 2024 21:11:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729224690; cv=none;
        d=google.com; s=arc-20240605;
        b=BjxsH8U45sbkFatgMeznGP8H9D0KX03c3njachoCJ+qYPR44RC1pIyaCE+SsqKDXPh
         JxrIgv4c8Pp+IW7djNlKoqscQo5/KrkkqcXPbXU5ax/PX8uPv1EHRoqdJniNVdCIaLEh
         TfeH89zFq7DUOVXAsywUtBP/bovb4HSaWO0oKqbKfvBRY2Yne49qRMmYg45ah2cDlWj3
         KWeK9XLaiJfhmEudl826Sa6KsOPV80WZSsZg0O0N8fL/A8ZrHpTEU0fDg8qNMYLk4oxu
         eEnxZK8aJpi6dITCWlsNBSbiAGpOQVmJns9R93XG7CsWDMW4bIYbbGBWBQM+sR1bughb
         Zn1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rZx4DZh7P3DyqOBYKKHdbOTFwvkzjhmn6fCLhYo2Jyo=;
        fh=uAEXvSVRkfBd2Upq0vrYpArJavZnowiVOhF7Gh5Ms2I=;
        b=NJrazbe8J6RMPGnrIaCcOqKTxxYDKDEX1SkCM1XMzYVFIDzwqzZzW93B1dTpeyphgm
         urwfQBuSBVTm7dPdsZ7qpE2Htqjw2tRRxTc4mItI4+fU9DF9lDBc+DwkiRgCgcRxcuL/
         UirKhyVxkO4XhlGJdOHwlWv8GAU1oCDcHEbTeOynAGl5YY1+Q4F3U1iRpvPgfTaiUwPs
         1QK/j66mnYF7Kda8QH2abze1oBpItUkTJHTAKEs5Yue1Lmv58+3kEcXswwRmWVJvmFEl
         1/sb1BHJDyBiWgWHTq17cIQaVNaJSfRaQM/8Ezyp8vNsyUkcMTShb5Z+3+gHw0Xt2+yr
         5tAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pO2C0poX;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7eacbf42abcsi38126a12.0.2024.10.17.21.11.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Oct 2024 21:11:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id A3FC9A445D5
	for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 04:11:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 336B7C4CED8
	for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 04:11:28 +0000 (UTC)
Received: by mail-wr1-f46.google.com with SMTP id ffacd0b85a97d-37d473c4bb6so1443033f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2024 21:11:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX74CRPJU40IVVA/uB/OnWLvCX3sW8BzxCvphS4VVD+E2p7KJmlPU0R6U2fWGssFSgpFY+QQFQiiqE=@googlegroups.com
X-Received: by 2002:a5d:4d01:0:b0:37c:cc4b:d1d6 with SMTP id
 ffacd0b85a97d-37eab2e3550mr868073f8f.27.1729224686670; Thu, 17 Oct 2024
 21:11:26 -0700 (PDT)
MIME-Version: 1.0
References: <20241014035855.1119220-1-maobibo@loongson.cn> <20241014035855.1119220-2-maobibo@loongson.cn>
 <CAAhV-H5QkULWp6fciR1Lnds0r00fUdrmj86K_wBuxd0D=RkaXQ@mail.gmail.com> <f3089991-fd49-8d55-9ede-62ab1555c9fa@loongson.cn>
In-Reply-To: <f3089991-fd49-8d55-9ede-62ab1555c9fa@loongson.cn>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Oct 2024 12:11:04 +0800
X-Gmail-Original-Message-ID: <CAAhV-H7yX6qinPL5E5tmNVpJk_xdKqFaSicUYy2k8NGM1owucw@mail.gmail.com>
Message-ID: <CAAhV-H7yX6qinPL5E5tmNVpJk_xdKqFaSicUYy2k8NGM1owucw@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] LoongArch: Set initial pte entry with PAGE_GLOBAL
 for kernel space
To: maobibo <maobibo@loongson.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=pO2C0poX;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 147.75.193.91 as
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

On Fri, Oct 18, 2024 at 11:44=E2=80=AFAM maobibo <maobibo@loongson.cn> wrot=
e:
>
>
>
> On 2024/10/18 =E4=B8=8A=E5=8D=8811:14, Huacai Chen wrote:
> > Hi, Bibo,
> >
> > I applied this patch but drop the part of arch/loongarch/mm/kasan_init.=
c:
> > https://git.kernel.org/pub/scm/linux/kernel/git/chenhuacai/linux-loongs=
on.git/commit/?h=3Dloongarch-next&id=3D15832255e84494853f543b4c70ced50afc40=
3067
> >
> > Because kernel_pte_init() should operate on page-table pages, not on
> > data pages. You have already handle page-table page in
> > mm/kasan/init.c, and if we don't drop the modification on data pages
> > in arch/loongarch/mm/kasan_init.c, the kernel fail to boot if KASAN is
> > enabled.
> >
> static inline void set_pte(pte_t *ptep, pte_t pteval)
>   {
>         WRITE_ONCE(*ptep, pteval);
> -
> -       if (pte_val(pteval) & _PAGE_GLOBAL) {
> -               pte_t *buddy =3D ptep_buddy(ptep);
> -               /*
> -                * Make sure the buddy is global too (if it's !none,
> -                * it better already be global)
> -                */
> -               if (pte_none(ptep_get(buddy))) {
> -#ifdef CONFIG_SMP
> -                       /*
> -                        * For SMP, multiple CPUs can race, so we need
> -                        * to do this atomically.
> -                        */
> -                       __asm__ __volatile__(
> -                       __AMOR "$zero, %[global], %[buddy] \n"
> -                       : [buddy] "+ZB" (buddy->pte)
> -                       : [global] "r" (_PAGE_GLOBAL)
> -                       : "memory");
> -
> -                       DBAR(0b11000); /* o_wrw =3D 0b11000 */
> -#else /* !CONFIG_SMP */
> -                       WRITE_ONCE(*buddy, __pte(pte_val(ptep_get(buddy))=
 | _PAGE_GLOBAL));
> -#endif /* CONFIG_SMP */
> -               }
> -       }
> +       DBAR(0b11000); /* o_wrw =3D 0b11000 */
>   }
>
> No, please hold on. This issue exists about twenty years, Do we need be
> in such a hurry now?
>
> why is DBAR(0b11000) added in set_pte()?
It exists before, not added by this patch. The reason is explained in
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?=
h=3Dv6.12-rc3&id=3Df93f67d06b1023313ef1662eac490e29c025c030

Huacai

>
> Regards
> Bibo Mao
> > Huacai
> >
> > On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loongson.cn>=
 wrote:
> >>
> >> Unlike general architectures, there are two pages in one TLB entry
> >> on LoongArch system. For kernel space, it requires both two pte
> >> entries with PAGE_GLOBAL bit set, else HW treats it as non-global
> >> tlb, there will be potential problems if tlb entry for kernel space
> >> is not global. Such as fail to flush kernel tlb with function
> >> local_flush_tlb_kernel_range() which only flush tlb with global bit.
> >>
> >> With function kernel_pte_init() added, it can be used to init pte
> >> table when it is created for kernel address space, and the default
> >> initial pte value is PAGE_GLOBAL rather than zero at beginning.
> >>
> >> Kernel address space areas includes fixmap, percpu, vmalloc, kasan
> >> and vmemmap areas set default pte entry with PAGE_GLOBAL set.
> >>
> >> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
> >> ---
> >>   arch/loongarch/include/asm/pgalloc.h | 13 +++++++++++++
> >>   arch/loongarch/include/asm/pgtable.h |  1 +
> >>   arch/loongarch/mm/init.c             |  4 +++-
> >>   arch/loongarch/mm/kasan_init.c       |  4 +++-
> >>   arch/loongarch/mm/pgtable.c          | 22 ++++++++++++++++++++++
> >>   include/linux/mm.h                   |  1 +
> >>   mm/kasan/init.c                      |  8 +++++++-
> >>   mm/sparse-vmemmap.c                  |  5 +++++
> >>   8 files changed, 55 insertions(+), 3 deletions(-)
> >>
> >> diff --git a/arch/loongarch/include/asm/pgalloc.h b/arch/loongarch/inc=
lude/asm/pgalloc.h
> >> index 4e2d6b7ca2ee..b2698c03dc2c 100644
> >> --- a/arch/loongarch/include/asm/pgalloc.h
> >> +++ b/arch/loongarch/include/asm/pgalloc.h
> >> @@ -10,8 +10,21 @@
> >>
> >>   #define __HAVE_ARCH_PMD_ALLOC_ONE
> >>   #define __HAVE_ARCH_PUD_ALLOC_ONE
> >> +#define __HAVE_ARCH_PTE_ALLOC_ONE_KERNEL
> >>   #include <asm-generic/pgalloc.h>
> >>
> >> +static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm)
> >> +{
> >> +       pte_t *pte;
> >> +
> >> +       pte =3D (pte_t *) __get_free_page(GFP_KERNEL);
> >> +       if (!pte)
> >> +               return NULL;
> >> +
> >> +       kernel_pte_init(pte);
> >> +       return pte;
> >> +}
> >> +
> >>   static inline void pmd_populate_kernel(struct mm_struct *mm,
> >>                                         pmd_t *pmd, pte_t *pte)
> >>   {
> >> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/inc=
lude/asm/pgtable.h
> >> index 9965f52ef65b..22e3a8f96213 100644
> >> --- a/arch/loongarch/include/asm/pgtable.h
> >> +++ b/arch/loongarch/include/asm/pgtable.h
> >> @@ -269,6 +269,7 @@ extern void set_pmd_at(struct mm_struct *mm, unsig=
ned long addr, pmd_t *pmdp, pm
> >>   extern void pgd_init(void *addr);
> >>   extern void pud_init(void *addr);
> >>   extern void pmd_init(void *addr);
> >> +extern void kernel_pte_init(void *addr);
> >>
> >>   /*
> >>    * Encode/decode swap entries and swap PTEs. Swap PTEs are all PTEs =
that
> >> diff --git a/arch/loongarch/mm/init.c b/arch/loongarch/mm/init.c
> >> index 8a87a482c8f4..9f26e933a8a3 100644
> >> --- a/arch/loongarch/mm/init.c
> >> +++ b/arch/loongarch/mm/init.c
> >> @@ -198,9 +198,11 @@ pte_t * __init populate_kernel_pte(unsigned long =
addr)
> >>          if (!pmd_present(pmdp_get(pmd))) {
> >>                  pte_t *pte;
> >>
> >> -               pte =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> >> +               pte =3D memblock_alloc_raw(PAGE_SIZE, PAGE_SIZE);
> >>                  if (!pte)
> >>                          panic("%s: Failed to allocate memory\n", __fu=
nc__);
> >> +
> >> +               kernel_pte_init(pte);
> >>                  pmd_populate_kernel(&init_mm, pmd, pte);
> >>          }
> >>
> >> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_=
init.c
> >> index 427d6b1aec09..34988573b0d5 100644
> >> --- a/arch/loongarch/mm/kasan_init.c
> >> +++ b/arch/loongarch/mm/kasan_init.c
> >> @@ -152,6 +152,8 @@ static void __init kasan_pte_populate(pmd_t *pmdp,=
 unsigned long addr,
> >>                  phys_addr_t page_phys =3D early ?
> >>                                          __pa_symbol(kasan_early_shado=
w_page)
> >>                                                : kasan_alloc_zeroed_pa=
ge(node);
> >> +               if (!early)
> >> +                       kernel_pte_init(__va(page_phys));
> >>                  next =3D addr + PAGE_SIZE;
> >>                  set_pte(ptep, pfn_pte(__phys_to_pfn(page_phys), PAGE_=
KERNEL));
> >>          } while (ptep++, addr =3D next, addr !=3D end && __pte_none(e=
arly, ptep_get(ptep)));
> >> @@ -287,7 +289,7 @@ void __init kasan_init(void)
> >>                  set_pte(&kasan_early_shadow_pte[i],
> >>                          pfn_pte(__phys_to_pfn(__pa_symbol(kasan_early=
_shadow_page)), PAGE_KERNEL_RO));
> >>
> >> -       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> >> +       kernel_pte_init(kasan_early_shadow_page);
> >>          csr_write64(__pa_symbol(swapper_pg_dir), LOONGARCH_CSR_PGDH);
> >>          local_flush_tlb_all();
> >>
> >> diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtable.c
> >> index eb6a29b491a7..228ffc1db0a3 100644
> >> --- a/arch/loongarch/mm/pgtable.c
> >> +++ b/arch/loongarch/mm/pgtable.c
> >> @@ -38,6 +38,28 @@ pgd_t *pgd_alloc(struct mm_struct *mm)
> >>   }
> >>   EXPORT_SYMBOL_GPL(pgd_alloc);
> >>
> >> +void kernel_pte_init(void *addr)
> >> +{
> >> +       unsigned long *p, *end;
> >> +       unsigned long entry;
> >> +
> >> +       entry =3D (unsigned long)_PAGE_GLOBAL;
> >> +       p =3D (unsigned long *)addr;
> >> +       end =3D p + PTRS_PER_PTE;
> >> +
> >> +       do {
> >> +               p[0] =3D entry;
> >> +               p[1] =3D entry;
> >> +               p[2] =3D entry;
> >> +               p[3] =3D entry;
> >> +               p[4] =3D entry;
> >> +               p +=3D 8;
> >> +               p[-3] =3D entry;
> >> +               p[-2] =3D entry;
> >> +               p[-1] =3D entry;
> >> +       } while (p !=3D end);
> >> +}
> >> +
> >>   void pgd_init(void *addr)
> >>   {
> >>          unsigned long *p, *end;
> >> diff --git a/include/linux/mm.h b/include/linux/mm.h
> >> index ecf63d2b0582..6909fe059a2c 100644
> >> --- a/include/linux/mm.h
> >> +++ b/include/linux/mm.h
> >> @@ -3818,6 +3818,7 @@ void *sparse_buffer_alloc(unsigned long size);
> >>   struct page * __populate_section_memmap(unsigned long pfn,
> >>                  unsigned long nr_pages, int nid, struct vmem_altmap *=
altmap,
> >>                  struct dev_pagemap *pgmap);
> >> +void kernel_pte_init(void *addr);
> >>   void pmd_init(void *addr);
> >>   void pud_init(void *addr);
> >>   pgd_t *vmemmap_pgd_populate(unsigned long addr, int node);
> >> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> >> index 89895f38f722..ac607c306292 100644
> >> --- a/mm/kasan/init.c
> >> +++ b/mm/kasan/init.c
> >> @@ -106,6 +106,10 @@ static void __ref zero_pte_populate(pmd_t *pmd, u=
nsigned long addr,
> >>          }
> >>   }
> >>
> >> +void __weak __meminit kernel_pte_init(void *addr)
> >> +{
> >> +}
> >> +
> >>   static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
> >>                                  unsigned long end)
> >>   {
> >> @@ -126,8 +130,10 @@ static int __ref zero_pmd_populate(pud_t *pud, un=
signed long addr,
> >>
> >>                          if (slab_is_available())
> >>                                  p =3D pte_alloc_one_kernel(&init_mm);
> >> -                       else
> >> +                       else {
> >>                                  p =3D early_alloc(PAGE_SIZE, NUMA_NO_=
NODE);
> >> +                               kernel_pte_init(p);
> >> +                       }
> >>                          if (!p)
> >>                                  return -ENOMEM;
> >>
> >> diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
> >> index edcc7a6b0f6f..c0388b2e959d 100644
> >> --- a/mm/sparse-vmemmap.c
> >> +++ b/mm/sparse-vmemmap.c
> >> @@ -184,6 +184,10 @@ static void * __meminit vmemmap_alloc_block_zero(=
unsigned long size, int node)
> >>          return p;
> >>   }
> >>
> >> +void __weak __meminit kernel_pte_init(void *addr)
> >> +{
> >> +}
> >> +
> >>   pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long add=
r, int node)
> >>   {
> >>          pmd_t *pmd =3D pmd_offset(pud, addr);
> >> @@ -191,6 +195,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud,=
 unsigned long addr, int node)
> >>                  void *p =3D vmemmap_alloc_block_zero(PAGE_SIZE, node)=
;
> >>                  if (!p)
> >>                          return NULL;
> >> +               kernel_pte_init(p);
> >>                  pmd_populate_kernel(&init_mm, pmd, p);
> >>          }
> >>          return pmd;
> >> --
> >> 2.39.3
> >>
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H7yX6qinPL5E5tmNVpJk_xdKqFaSicUYy2k8NGM1owucw%40mail.gmail.=
com.
