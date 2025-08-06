Return-Path: <kasan-dev+bncBDAOJ6534YNBBJVYZPCAMGQET3ELQ2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id EDB4CB1BF9F
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 06:38:22 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-458b301d9ccsf22299945e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 21:38:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754455079; cv=pass;
        d=google.com; s=arc-20240605;
        b=by9vQ04+vYYambCdOoBhNYHKM8Ai1UQrh/runIsvaFlHTnNoBdKtfZUEqO+rsVK6zn
         ggHWzWPlCyWMbTAg025uUplftlUCoJjyjPeH/X01XPrruTSdxqnk/LG1MbkQ0ZYkaGFJ
         O5CBwAVa1HgcGTqx/m/SZIe1iUMDxxMqE/M5yPpS6jKWMsiJVvklzMHMd5THn68LUCeO
         eF8ZN0syXNJKTI5oae71KHzTSVzQi0j5gQy3BrqCBqk3SGYdKt8sbQuSrE8YzUoH6gvh
         ydS7CCD3xedXXhE5JuIk7obyy2EBNIm/eULV4hmLBppZNxsBtg7p0WFZFuT25tj8EgVE
         R9oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=+iseM5wNv2ljQUsAU6hhns2FJ3NZmFsOfcMVDJtzZn0=;
        fh=YFBu+tayFHqO+23QoyAqfqyTBf3+LG1SPG2B1tZ9djU=;
        b=RjnqxHqvmKT5cqIQ/FEWX0BF3YLvqpgf0elnBJGL4c6Qdp4GN3S+a1vMfKbe9IgTl/
         kdQ77R61QzWcHf3b28Nj2yI0B7OVwbud4woNKvVfEdJa39apsGx23NE35YzzWsICj28J
         0Buuf1Fzy6ykI447U1sgFj87E0ThLTUnrAv53yZ02Gl3aLsHBKIsFxTkADyW8OwBEHe5
         xkPV/ChnGcUX+lIxPRHXNh75/aLdErJaJ0ivA1kyBXvWKdf5Mj0e9GtPhsbKHNbQdDIf
         6KAV2N/sy3Y9OwTDzqoXPPHo3BEF5sFWcXWMsStUzimZASa2n8BEudpan4i/8YNGUvfY
         jb0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dpe5chB5;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754455079; x=1755059879; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+iseM5wNv2ljQUsAU6hhns2FJ3NZmFsOfcMVDJtzZn0=;
        b=AXd7WAm1uVLehSe1pe728yytLncbbnm/5V1ZzhPP/Y4QsDFVib2vjoMlg9xvca4nun
         jm0/f1KlHhgMNTTYjtwqH/uTh8nFXu+3/d3cW6MDaq8oSrfhyYcIGueIpEcvgcAyG+Ur
         bD/u1dJr9/QublAcvedVBcZOnxUVsvFEPxlOMuH7VQNzEqt7CydCLacn5fc/PEQDSuPa
         rnY/qzrvlCHMJJvgSstp443+5EJg+Pds3CY2yp39FvGaWuZHY0xDNLujCkYJc9jSCS5E
         u+Tq0lQLw7AOWCVRaSHoi9CRnufFUx7ik47Hd5eqKROJMgB5mQbxsY5WL2wsKUvjMYUr
         xQYQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754455079; x=1755059879; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+iseM5wNv2ljQUsAU6hhns2FJ3NZmFsOfcMVDJtzZn0=;
        b=PyMGV6nwzqKT3gmcehHJQUyOoA471aQFQjljEMrUKJuNMXqBoORERr67ClefRXFsS5
         o7cya+nJhB7mlxoxpVwaEbVcFKj3a+V6p18BfLksswHOCJkBlO4Y6Y4cJruuvhnHgsNq
         olPRGwTp/U/O+rMvJgjHgt4Kbcg28Br7wmRqjROaSd4h+SkEh2/ouzOYg1Ws1ErBTWWc
         0RS5HEdREI1meuZRq5uY4bh+R42MZmDuK27cqZgC6WrJ9oCtZLwzSOoe1srrVpgVntft
         wqXv4sJYUQlvFhyIJ/2817CaCm5O48TTlWFkL5j03EFngs1BTh5485yXbUcV90W3azKI
         8G2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754455079; x=1755059879;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+iseM5wNv2ljQUsAU6hhns2FJ3NZmFsOfcMVDJtzZn0=;
        b=iwEW6H5uYtvSxcmUp+DtubHQkyP0YdWupWITnN8iC9fbUPOsOCs+N9tz3pV8oPq5kr
         zc30G1kyofKlFe9dlphP9ne5ZY7831FqZ1kKwzQFf7EjNz4p5N5eyUja+v0Sir/QzRbU
         6uZfWcKuRDin4rhlb+RaKBFMUzoCxwWEJ4Iqz7BOKiCVXWcs4QSG0GZrVrWyHEJsnsbC
         O0T036YnyC/+1CglwdfXCHBZ/wkjojaaT7BpaoUwAYBhdmr+ZIPxMq4O5iusO+wpxYFA
         cEbTmKhkyAupCoJIWj58QNGkUaqqEbbn68jif6c22Gz7PitxgJY3GEkebt8v6xeGZoHS
         lXSQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW3gbmj1WMzBoTqLORIWNkOrNvqPd/ry5jRuE7NryF8ioNhD5/6QVVvSRz3IBDu+Csnu64Pdg==@lfdr.de
X-Gm-Message-State: AOJu0Yzxzi5SXM7OCrwIc/E89kN4/LCvKaDF4tH5gySABxxzzi0ZuYw9
	T9ZioJfZyNqqJePDovcDBrAB/5PPFnV4sw+jZKY6Ixa5Aj6k5hAK5++j
X-Google-Smtp-Source: AGHT+IEhX0ei4p4tBLHO70TNj0Qne0xnoiso71iQrOs6eKcOGLO4g/MHbfs4HdLi5SgtYn5MNSCVqQ==
X-Received: by 2002:a05:600c:5494:b0:459:d6a6:77c with SMTP id 5b1f17b1804b1-459e7136b2dmr7120835e9.33.1754455078845;
        Tue, 05 Aug 2025 21:37:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd6RQhUna1+xwJIOlwzGmnYBvP2G/qaP0HSoepKJGyY2Q==
Received: by 2002:a05:6000:2f8a:b0:3b7:94bc:473c with SMTP id
 ffacd0b85a97d-3b79c35c8f8ls2930204f8f.0.-pod-prod-06-eu; Tue, 05 Aug 2025
 21:37:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU47Q2g1+aN6A5I98t45WCyMuCcnKQOOviZLeEYeqLMvDNCKVcBgbSeUijTFkXELmYrB3/DYhxVx3s=@googlegroups.com
X-Received: by 2002:a05:6000:2204:b0:3a6:d93e:5282 with SMTP id ffacd0b85a97d-3b8f420f197mr866755f8f.59.1754455076097;
        Tue, 05 Aug 2025 21:37:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754455076; cv=none;
        d=google.com; s=arc-20240605;
        b=ii/Opzf/rDfjL5/DGhvG0tldQiQENZzKsaHYDBj2hwF2owL/kSbcZVwlOpISzPh1Ln
         CPFXQU+kXEeFBHBMGsc4Uv6RtzEDrcu4SHlEA73Cv4FpEgdX93ZkA2mL9Ev97F+dQCjP
         cOpNv4Jv95Ai8BqUft7uSIkdoFvoBkBarwlkEI21se7VlwcQK7DlWmpPhMPcrc0SwAe0
         XIPxzy0w/WXnWtkXJ8XjUwxe7Ea8V0NTbXlWLn09ebnPDxuVysLEaHJYw5FP7zhbxlcY
         dyUtyo7w5ZnX770DoHyfIbU88wmFNgfAIR3wX9e1WD9bTxa0YGHu/VOZvjwltJzC7ko7
         yXUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Qo/Viw2qcvpv/MoBS3iI99BxX9ghV/qd2Tz3ezwRf/E=;
        fh=HhQLYHv2p5rapDIOsTrtIA45J8WJdTrtoufxXQFGsPI=;
        b=YBc0DyNkUoHPDlMKoUkEriBHjD51LB4l2zrUC+PPkCG9chQO8RoRAJJ6iYgTcnzvr1
         X4TRwVAP9oR4TAW2Jn8pf/pafFnkDUoystE3EHtN21zq3003DzhVONNUW6pdnw2fhedC
         W5dmLOHs/8e4CgMLtiiqGZSfogcgTjNh2MLuOrbfmpRjgHrp38a4Bk2FBCOj7gIDA5cn
         nUh9zZ0C4A20n5d9I+h61D4+W7X1OTErxL/bwhy96vAt2hrhxekHAMgdD3ejbbeqNGCx
         Zsd+Xl7jYURVVuhqF2giDNuKOFL/UH+eqq+bJt+S35wdn+ziJCizHNuP0NKjwVQxHFJf
         u76Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dpe5chB5;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79c4791easi391610f8f.6.2025.08.05.21.37.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 21:37:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id 38308e7fff4ca-332612dc0d1so26097841fa.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 21:37:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW/RYM4jM0O3JQ7AtM1ahehGM8Ybv4HQHpw2h53KojZIjOfW0XYlE3qCCpqCHRGku9aiKHeR7cMGZk=@googlegroups.com
X-Gm-Gg: ASbGncvt8D/zXeNb4MeHf8aGPY8HE/vhyEYlpLmTQxOL0+7Y7aoIlVOj4u1dM/9gl6l
	QH/eN5l/kYFO+vzC3qOcVOhGZCqfhqywq/ouYL+SZidMZoCe9kk/5r50C83aoszGvnfbCqyZeRQ
	nJkQ0i2SXO6nrubVTH5ltGSqaG+m8tWIa7b2WkHSBFy99eIWHuRmsdp77pu8xYhU2Ufo+1jlWl+
	iHlWwU=
X-Received: by 2002:a05:651c:1509:b0:32a:739d:fac with SMTP id
 38308e7fff4ca-3338144cd8fmr3796161fa.36.1754455075078; Tue, 05 Aug 2025
 21:37:55 -0700 (PDT)
MIME-Version: 1.0
References: <20250805142622.560992-1-snovitoll@gmail.com> <20250805142622.560992-6-snovitoll@gmail.com>
 <e15e1012-566f-45a7-81d5-fd504af780da@gmail.com>
In-Reply-To: <e15e1012-566f-45a7-81d5-fd504af780da@gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Wed, 6 Aug 2025 09:37:38 +0500
X-Gm-Features: Ac12FXyJN7pElMlaw_o-aZoTkQ3byDjTMvUiVf1-1J0u8uF_nrAwTbgiBAXxjhE
Message-ID: <CACzwLxj0nOQT0+Z+AFDG3Cvun5jGaET6C3mp9PnLbCHjdw51Pg@mail.gmail.com>
Subject: Re: [PATCH v4 5/9] kasan/loongarch: select ARCH_DEFER_KASAN and call kasan_init_generic
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: hca@linux.ibm.com, christophe.leroy@csgroup.eu, andreyknvl@gmail.com, 
	agordeev@linux.ibm.com, akpm@linux-foundation.org, zhangqing@loongson.cn, 
	chenhuacai@loongson.cn, trishalfonso@google.com, davidgow@google.com, 
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, loongarch@lists.linux.dev, 
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=dpe5chB5;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::233
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Aug 5, 2025 at 10:18=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gmail=
.com> wrote:
>
>
>
> On 8/5/25 4:26 PM, Sabyrzhan Tasbolatov wrote:
> > LoongArch needs deferred KASAN initialization as it has a custom
> > kasan_arch_is_ready() implementation that tracks shadow memory
> > readiness via the kasan_early_stage flag.
> >
> > Select ARCH_DEFER_KASAN to enable the unified static key mechanism
> > for runtime KASAN control. Call kasan_init_generic() which handles
> > Generic KASAN initialization and enables the static key.
> >
> > Replace kasan_arch_is_ready() with kasan_enabled() and delete the
> > flag kasan_early_stage in favor of the unified kasan_enabled()
> > interface.
> >
> > Note that init_task.kasan_depth =3D 0 is called after kasan_init_generi=
c(),
> > which is different than in other arch kasan_init(). This is left
> > unchanged as it cannot be tested.
> >
> > Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D217049
> > Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> > ---
> > Changes in v4:
> > - Replaced !kasan_enabled() with !kasan_shadow_initialized() in
> >   loongarch which selects ARCH_DEFER_KASAN (Andrey Ryabinin)
> > ---
> >  arch/loongarch/Kconfig             | 1 +
> >  arch/loongarch/include/asm/kasan.h | 7 -------
> >  arch/loongarch/mm/kasan_init.c     | 8 ++------
> >  3 files changed, 3 insertions(+), 13 deletions(-)
> >
> > diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
> > index f0abc38c40a..f6304c073ec 100644
> > --- a/arch/loongarch/Kconfig
> > +++ b/arch/loongarch/Kconfig
> > @@ -9,6 +9,7 @@ config LOONGARCH
> >       select ACPI_PPTT if ACPI
> >       select ACPI_SYSTEM_POWER_STATES_SUPPORT if ACPI
> >       select ARCH_BINFMT_ELF_STATE
> > +     select ARCH_DEFER_KASAN
> >       select ARCH_DISABLE_KASAN_INLINE
> >       select ARCH_ENABLE_MEMORY_HOTPLUG
> >       select ARCH_ENABLE_MEMORY_HOTREMOVE
> > diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/includ=
e/asm/kasan.h
> > index 62f139a9c87..0e50e5b5e05 100644
> > --- a/arch/loongarch/include/asm/kasan.h
> > +++ b/arch/loongarch/include/asm/kasan.h
> > @@ -66,7 +66,6 @@
> >  #define XKPRANGE_WC_SHADOW_OFFSET    (KASAN_SHADOW_START + XKPRANGE_WC=
_KASAN_OFFSET)
> >  #define XKVRANGE_VC_SHADOW_OFFSET    (KASAN_SHADOW_START + XKVRANGE_VC=
_KASAN_OFFSET)
> >
> > -extern bool kasan_early_stage;
> >  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
> >
> >  #define kasan_mem_to_shadow kasan_mem_to_shadow
> > @@ -75,12 +74,6 @@ void *kasan_mem_to_shadow(const void *addr);
> >  #define kasan_shadow_to_mem kasan_shadow_to_mem
> >  const void *kasan_shadow_to_mem(const void *shadow_addr);
> >
> > -#define kasan_arch_is_ready kasan_arch_is_ready
> > -static __always_inline bool kasan_arch_is_ready(void)
> > -{
> > -     return !kasan_early_stage;
> > -}
> > -
> >  #define addr_has_metadata addr_has_metadata
> >  static __always_inline bool addr_has_metadata(const void *addr)
> >  {
> > diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_i=
nit.c
> > index d2681272d8f..57fb6e98376 100644
> > --- a/arch/loongarch/mm/kasan_init.c
> > +++ b/arch/loongarch/mm/kasan_init.c
> > @@ -40,11 +40,9 @@ static pgd_t kasan_pg_dir[PTRS_PER_PGD] __initdata _=
_aligned(PAGE_SIZE);
> >  #define __pte_none(early, pte) (early ? pte_none(pte) : \
> >  ((pte_val(pte) & _PFN_MASK) =3D=3D (unsigned long)__pa(kasan_early_sha=
dow_page)))
> >
> > -bool kasan_early_stage =3D true;
> > -
> >  void *kasan_mem_to_shadow(const void *addr)
> >  {
> > -     if (!kasan_arch_is_ready()) {
> > +     if (!kasan_shadow_initialized()) {
> >               return (void *)(kasan_early_shadow_page);
> >       } else {
> >               unsigned long maddr =3D (unsigned long)addr;
> > @@ -298,8 +296,6 @@ void __init kasan_init(void)
> >       kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_S=
TART),
> >                                       kasan_mem_to_shadow((void *)KFENC=
E_AREA_END));
> >
> > -     kasan_early_stage =3D false;
> > -
>
> There is a reason for this line to be here.
> Your patch will change the result of the follow up kasan_mem_to_shadow() =
call and
> feed the wrong address to kasan_map_populate()

Thanks, I've missed it. Here the upcoming v5 for this:

diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.=
c
index d2681272d8f..0e6622b57ce 100644
--- a/arch/loongarch/mm/kasan_init.c
+++ b/arch/loongarch/mm/kasan_init.c
@@ -40,11 +40,9 @@ static pgd_t kasan_pg_dir[PTRS_PER_PGD] __initdata
__aligned(PAGE_SIZE);
#define __pte_none(early, pte) (early ? pte_none(pte) : \
((pte_val(pte) & _PFN_MASK) =3D=3D (unsigned long)__pa(kasan_early_shadow_p=
age)))
-bool kasan_early_stage =3D true;
-
void *kasan_mem_to_shadow(const void *addr)
{
- if (!kasan_arch_is_ready()) {
+ if (!kasan_shadow_initialized()) {
return (void *)(kasan_early_shadow_page);
} else {
unsigned long maddr =3D (unsigned long)addr;
@@ -298,7 +296,10 @@ void __init kasan_init(void)
kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
kasan_mem_to_shadow((void *)KFENCE_AREA_END));
- kasan_early_stage =3D false;
+ /* Enable KASAN here before kasan_mem_to_shadow() which checks
+ * if kasan_shadow_initialized().
+ */
+ kasan_init_generic();
/* Populate the linear mapping */
for_each_mem_range(i, &pa_start, &pa_end) {
@@ -329,5 +330,4 @@ void __init kasan_init(void)
/* At this point kasan is fully initialized. Enable error messages */
init_task.kasan_depth =3D 0;
- pr_info("KernelAddressSanitizer initialized.\n");
}
--=20
2.34.1

>
>
> >       /* Populate the linear mapping */
> >       for_each_mem_range(i, &pa_start, &pa_end) {
> >               void *start =3D (void *)phys_to_virt(pa_start);
> > @@ -329,5 +325,5 @@ void __init kasan_init(void)
> >
> >       /* At this point kasan is fully initialized. Enable error message=
s */
> >       init_task.kasan_depth =3D 0;
> > -     pr_info("KernelAddressSanitizer initialized.\n");
> > +     kasan_init_generic();
> >  }
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxj0nOQT0%2BZ%2BAFDG3Cvun5jGaET6C3mp9PnLbCHjdw51Pg%40mail.gmail.com.
