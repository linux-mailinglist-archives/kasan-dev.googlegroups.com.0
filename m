Return-Path: <kasan-dev+bncBAABBQXWWK4AMGQE2JIQ2DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E55199C00E
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 08:33:39 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-45b172569a2sf53528941cf.0
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 23:33:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728887618; cv=pass;
        d=google.com; s=arc-20240605;
        b=OVEq0YLPjDeqgFLntS/0dTAxApGL4jAJUuP5oGNRA+5p2OBso6rXphWHijLkxfOrVq
         kbZiaXVPDp7uW8vfkvqTGA73wz2caDQTHe5NwvMH3WNSFsdlhtLonZ3VGLwWdLD6R/z0
         PKuXvJJKPpGRn7WJnUuQ8D8SI9UPTN2YcADlKX0zfZeP1+oyD9sM0GQ3EIinSruQv7to
         ISPPRRVvsycJ5/NJeP2K2EDwYmRGqCWsgZYjpPZv7/lL0xnWLftsKGz3siT1mr1cDk4e
         kg5uM/IekZodwUIGk1Nt5Zf+gc+3/qSElZWyKp1OxQV4/6fgJIrUVzfbgNlazYAOex72
         FraQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZwgHhgV4iahE5+3/qKNhpdDrOH6XgJsfHBhONql7Gz8=;
        fh=uBHADduQCE/GfPFrjijl2EGxoo8aMVaXZnDACttYTA8=;
        b=jYuBttpdc+bomsQ3FRD3Fepv0VIONK+pTCjAniSQ2WFMdvnKC9L6xDI/sA+OQJQrVx
         6PPq7EaCoT20ket6ubcVov55NOFRUlv1UAqSo37LUS2t018W95jDsEVRfWIeZvFoMFoh
         jipmEUplI6yFnz5OckXFTdFbUmbNJ15eNy9DGOIFMgh/3nhE7pNg7wjP+iTZwVF6oQgd
         phwD3FaxTtkiUaGE/qHOe8KTyZHM2k90oOYb8sCATMWotCLwyaPQ/QzXyMsLS4EbEPKy
         SvzYhk0MINUAIKETF9ubUCfEb46c1eG9bZoxchiHrnpQQZH7Vig/AX0BKzT9M+mV4fZl
         I/tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=inT2a268;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728887618; x=1729492418; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZwgHhgV4iahE5+3/qKNhpdDrOH6XgJsfHBhONql7Gz8=;
        b=WOFFYfB+b/x9d02kI9ERwlNFgxy7biDxkKAbPuEM1y7BwJu0rV16A/VpndmyM9PPAj
         y0fCo4lKIn2cQbclDMAxaN+Q5RQpggR+fw9ANVnEedLgKY8VTQkEYwvjSqclerOtTOgI
         WGghCATtbT7anwCkqKxBXgkul4u/yR/El8IZtiCcWqrHylowz4SBDgZZqjRRgoAAh3Ow
         FJrs59Y05Vf4qdjfDqXWqWy1cY2ECIjdYZY3ImKvrg4EWPFNxm5jVeqoFKO+0QF4/S1W
         WSS9kNY1yXBMbkQO4gy9ViZomsEPrtOV8qLmO9Wku37s6JBtsVRv81ZJJJFx/w2/Tu9M
         88OQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728887618; x=1729492418;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ZwgHhgV4iahE5+3/qKNhpdDrOH6XgJsfHBhONql7Gz8=;
        b=SHvst0mlrSuBnhWHAOtRBEPsRCUBhoJyJhxHMSMwbvZn/1A/tBmASZbqq6/s5q3Gu9
         G+C+EGs4oelR0eQ+wC/06njY9Hf3TNCzuqiSsE/3yyxvr3k+Id1HGAoejyd2cCrwz/vS
         FulMR2hfgAqg0YAGqI1m8uboL18Ob9701DUWt/JATi0SDBvTKgCeQ6yTw3JyqBk0puda
         IvmlmFy8bZsG9edHSjABBTPM1mnGw3x3mXJ2hlYgkHRwkfRwxu+gdFn0hpcx/24PrsQP
         eYwBMxab2crFZBALuTUTISpkdgWAeTfx0vszkZfTezvEmJGWRBb8rNSVVwmVL51cNSOY
         V+wQ==
X-Forwarded-Encrypted: i=2; AJvYcCW+pUBee2yMsgignIDLZba6xTLlB1QPuYkzr8LgkclU2FlwK07wy9oue23N67lxpCIcydqLMw==@lfdr.de
X-Gm-Message-State: AOJu0YymQ1clGnIUi7+2dtLFGDZDWBQzJB/CTOT0oW2de7Xn5DV/6Csa
	5UmQYbtSEEnT5Gx63rJEOfIPgCv3Jr5nrPcSqAcEr6MIfm4JqbJg
X-Google-Smtp-Source: AGHT+IGm6BDYvrNAHpXDffd1og6Z5WLMLnlVH7APg7htIQDBTQf3INUsWpa9fXoRQ9924Vk80f26+w==
X-Received: by 2002:ad4:5192:0:b0:6cb:f345:8bcf with SMTP id 6a1803df08f44-6cbf3458de4mr147497496d6.46.1728887618250;
        Sun, 13 Oct 2024 23:33:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:21e4:b0:6b0:8881:bc19 with SMTP id
 6a1803df08f44-6cbe565a703ls72769496d6.1.-pod-prod-08-us; Sun, 13 Oct 2024
 23:33:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXv1osYrlDHYA86a0e2TLgC+f2oql6n2R5O4T/n8PzoBx+N3/QG0VTWJHmOovX6duQJbcpG06OVseQ=@googlegroups.com
X-Received: by 2002:a05:6122:178c:b0:503:db9f:5a3f with SMTP id 71dfb90a1353d-50d1f5a081fmr4625212e0c.12.1728887617631;
        Sun, 13 Oct 2024 23:33:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728887617; cv=none;
        d=google.com; s=arc-20240605;
        b=gaZQWIRdLKhGlFUWxLyfPCGtBWBGTDoEj7k/d/+qSCbm52kgEjUPe82yZkEYOvdIWK
         2TA4boA/SHvuGHr9pmsJrOC6vG2Ks1++15+VW36FFDjYylzk6lL7eHH+cmMxY+dqMz2S
         fAGV1qR1PTmHmjlWZWHPwt4jPfkmKlJ86YARiROJl5PKAZNdtzZW6bSFxh98QdBMoA5p
         7N3/hwZtPHCDmdrOdIrsTg/gPBW37rJ3ZW0imNx9krGda6rx6Xw12KHRJOnvDB02esM/
         uy9noJkzMSV+akFd+naig5tQ5CTDoAdsOi2lVcaDHru4t4BEFA4vBWp40SwRklyRS0Tw
         5nNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dHL7qSQDr4q3t54MX6F81H3RUEf2/M8zrpm3YnELdw8=;
        fh=juaIrkS5ZcIebx8p7T+Jdc8+NBMQ1CCYhSFMtAlUIfk=;
        b=HVeXsaSMshsGRGsy86drBzWctSN6ibNYYsRhOiNj2afG1YWm5Dg2guAGTmumoMB333
         M11nYcMBnmQfo6GT/Iu7OSv+njQJ/vL0QpFsA9ZOmmn/pHsaIt4mOwpon5j06XtQzfyY
         VEqzPBhuqw99b3xla5ce9XoQr+CjhgcLB32Ryw9jqJjzK/Ji40g4+hzBEQ7IvwMAnVH9
         erJPHWAZr/erh87axIj/q1J3ZDR/iN0mCN8ZXMJmghPO26AkI/dcRVnenC9DBJj2MTZl
         lsRC32rKOqZ2oGty6y7dAUEQf+lwIXDbYiNDGHlv5at11szq6UEQSK/cK6pCXhMVzBl7
         ZyPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=inT2a268;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-50d08a78eacsi575597e0c.5.2024.10.13.23.33.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 13 Oct 2024 23:33:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id CB7AF5C5A49
	for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 06:33:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DFD7DC4CECE
	for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 06:33:36 +0000 (UTC)
Received: by mail-ej1-f52.google.com with SMTP id a640c23a62f3a-a99c0beaaa2so457013766b.1
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 23:33:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW5ZLW32kCu1NzFsfl8u0uXStX6VIHTq1sZCdzDEVEgziHYTNBO6k2W/ot5iRAHrk/GKitc9vdjQ8g=@googlegroups.com
X-Received: by 2002:a17:907:368d:b0:a99:5466:2556 with SMTP id
 a640c23a62f3a-a99b966b636mr1020625266b.61.1728887615477; Sun, 13 Oct 2024
 23:33:35 -0700 (PDT)
MIME-Version: 1.0
References: <20241014035855.1119220-1-maobibo@loongson.cn> <20241014035855.1119220-4-maobibo@loongson.cn>
In-Reply-To: <20241014035855.1119220-4-maobibo@loongson.cn>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Oct 2024 14:33:24 +0800
X-Gmail-Original-Message-ID: <CAAhV-H4-OQ4rmyztsRVsOuPra7xbzy9vcckerP8NG-7ti8jKwg@mail.gmail.com>
Message-ID: <CAAhV-H4-OQ4rmyztsRVsOuPra7xbzy9vcckerP8NG-7ti8jKwg@mail.gmail.com>
Subject: Re: [PATCH v2 3/3] LoongArch: Remove pte buddy set with set_pte and
 pte_clear function
To: Bibo Mao <maobibo@loongson.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=inT2a268;       spf=pass
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

The old code tries to fix the same problem in the first patch, so this
patch can also be squashed to the first one (and it is small enough
now).

Others look good to me.

Huacai

On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loongson.cn> wro=
te:
>
> For kernel address space area on LoongArch system, both two consecutive
> page table entries should be enabled with PAGE_GLOBAL bit. So with
> function set_pte() and pte_clear(), pte buddy entry is checked and set
> besides its own pte entry. However it is not atomic operation to set both
> two pte entries, there is problem with test_vmalloc test case.
>
> With previous patch, all page table entries are set with PAGE_GLOBAL
> bit at beginning. Only its own pte entry need update with function
> set_pte() and pte_clear(), nothing to do with pte buddy entry.
>
> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
> ---
>  arch/loongarch/include/asm/pgtable.h | 35 ++++------------------------
>  1 file changed, 5 insertions(+), 30 deletions(-)
>
> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/includ=
e/asm/pgtable.h
> index 22e3a8f96213..bc29c95b1710 100644
> --- a/arch/loongarch/include/asm/pgtable.h
> +++ b/arch/loongarch/include/asm/pgtable.h
> @@ -325,40 +325,15 @@ extern void paging_init(void);
>  static inline void set_pte(pte_t *ptep, pte_t pteval)
>  {
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
>  }
>
>  static inline void pte_clear(struct mm_struct *mm, unsigned long addr, p=
te_t *ptep)
>  {
> -       /* Preserve global status for the pair */
> -       if (pte_val(ptep_get(ptep_buddy(ptep))) & _PAGE_GLOBAL)
> -               set_pte(ptep, __pte(_PAGE_GLOBAL));
> -       else
> -               set_pte(ptep, __pte(0));
> +       pte_t pte;
> +
> +       pte =3D ptep_get(ptep);
> +       pte_val(pte) &=3D _PAGE_GLOBAL;
> +       set_pte(ptep, pte);
>  }
>
>  #define PGD_T_LOG2     (__builtin_ffs(sizeof(pgd_t)) - 1)
> --
> 2.39.3
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H4-OQ4rmyztsRVsOuPra7xbzy9vcckerP8NG-7ti8jKwg%40mail.gmail.=
com.
