Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDHLV76QKGQES2OTHCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 191482AF38B
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 15:30:38 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id u3sf1508029qvb.19
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 06:30:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605105037; cv=pass;
        d=google.com; s=arc-20160816;
        b=JwP/91+xC5uVgmth2yCi5iw9DcsQbT9X3+jCGFyGZyO4Higf1h8xhN+6z1Sw7x1mmG
         JpKdUcCVUdtyQECiWOwP5I+V3r1Jt+ppPXeq5xQRV+K2ad43n1QdfYDQ7iN+SD+gk640
         +P5RD0T4YlM+nqAr5R0pZZg1+rgwmaW80s4TUG+DfbC6sPt76sbiGDG9ARsofMEi9W5S
         oTbX/BBmBm0Hp5tkeEjKCtvFb/lNKaQNCDKxVXpac9gxkOPmWK7fpctaMOIEt6UGuGxQ
         mjPUsiL2fvCRL3DtlQrQ5+/poX7XA8hCU7BqwSWhvoazRnl3f0tb+BdJwmxabAPC5Jle
         E6dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6tYch30lMtuPHwpNYJyTEI1oWcxYXEcK7ePfa5dPWXQ=;
        b=wp2c8mkKT/zQ5u2SpV6nKA1iNEECNjG960aZj/1MPQiDFqa2hF/hoVF5gqJnbR9dko
         RPm+Gb49zVNpJaj/mWEtapyPYWIF3nfA8gLccPJ8TOh5QGWPmie4GmNwwqq15mUjD1kP
         2cBmYTLDuFsTU0QJ3bnKQOBlF/ROrzRf+iZMCFWpsFF+VacdThKuOOqzHJSoOVERsKX9
         HqFBpHWieyg4BCI3RiH6wUKlApbHlh5eneajACQwcItFXADaYX7lkI15Ca1dtLQz6dtj
         Vm1wAw+VvxUPBlJIxoEuGCR2GS6I5c1wIVeQIiI6GVhFP7AGtFim6v8sNkq8h0lOKmvO
         HHLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jvL+NTnB;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=6tYch30lMtuPHwpNYJyTEI1oWcxYXEcK7ePfa5dPWXQ=;
        b=gP5KS6OMO1M6RvHlj7mscPjo4t++TCb4LkWQuLUjKGfcg0mkChvn+OY9RSBqk7jQvj
         /PAH3AQmtguxzGhUMdFvTiv4mw1ZJQXzkBn9Goyhr4byA7mq80XX4OOHT2d/Xby8vRL4
         IRMYyo5LHdSf7GRaPlJojiC6FrY5r2yinbIxMi17iH9LD3N6gs/W2D9Qphx+ftaSh3W4
         wSN/Fq4qy9ZG/R7BSXZ6pK8T87R5jI4qCVvpv11BmW96ImEhgCo8HckSt+Z2jSge8wPk
         A0KJAI+saINM/WWjU184kc9/mr8cN3XMsZAHTnE6ssyqh+YfMXKInqzsmGwGwXYWwEPy
         DU4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6tYch30lMtuPHwpNYJyTEI1oWcxYXEcK7ePfa5dPWXQ=;
        b=uKtdOust9t4Hyr1JzkHoPxSlj6u46xiXRH+YVqZbkrU6evjL75pfA8e8b4BK7LJZo3
         1XzMoaXi8JE1chXnD8HLIgVNbaj/jSkON12Ye87EJJ/8MXNqY2YQOJrX8c6UFjVGdg3N
         tEsJtX2kQLSJPSPQOH38H2K65hhd6sZFGJoB3JXURoX1EbblZ1fBWgxawpckQhS/GVzu
         V4yz6Tc0Do7FNh0uKGMsUdY2QL/SNEkCx53gtVEUTa6l8wBQvUIq7kHth7B8ZOGkGybI
         Gvc1HV1JW4D84F3QylFuogQSXTS3+7nih7APC5Pub181/JQdBlkyeqK0dbW/V/PzHeNP
         ZJBA==
X-Gm-Message-State: AOAM531pdcdNCHvbzkSdNDyNRTTotX94r3sDG0bOsbdOV9SXFHI6AA4n
	ILtsqfxmnfCvB/ZsULCZp3A=
X-Google-Smtp-Source: ABdhPJxGCL2RTHVRnW8megZM7+a6oI6mDC4xeUsw8wu/SC7OaNB8hRQRpjTkkovdv/vTKEO2Hens1w==
X-Received: by 2002:a37:f706:: with SMTP id q6mr18971740qkj.234.1605105037027;
        Wed, 11 Nov 2020 06:30:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7006:: with SMTP id l6ls446381qkc.5.gmail; Wed, 11 Nov
 2020 06:30:36 -0800 (PST)
X-Received: by 2002:a37:b9c3:: with SMTP id j186mr25816945qkf.327.1605105036051;
        Wed, 11 Nov 2020 06:30:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605105035; cv=none;
        d=google.com; s=arc-20160816;
        b=mpmxqR8jpHjXAsM055IY2ECin8uDyRmuCgZ8iYeCT8qnvAnaU4VNfjkMWFMdIqpuEp
         Fp7Ob3rjNWJdfp+Br/YF2Vu9XYITCDCv5Ok+meg2OhKhw31plpEvM07zEbCpIW5IfUVz
         wpxUtshkZeT7bgpXSLpjHTo270sns/tKQj32PP2JVWlS2G7qHecSHdzRqe4k96jd9skQ
         04vLaiTuTdkIG+0HySfoMsBTNOC0RKQE5oaCF+nlr4FK8qmaGqr117n8ffNSs/WETeYK
         CPHyKWX22F/syJ8KFjFV21InA4So73gb0z50s9kw/HXUxTDUaueQqPJiAMcY6sMZ/CpD
         G5NA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Z/BqGgtubdX37tmwe08Rq/1pXj9l2Bza+T3BZlmbJiM=;
        b=hVoaO2mlBC++zuNFRMlIflE6DpZMFkjJctoGaewjzhfDFaxgNZiEFEuBcIwxasudm5
         zTA6Tek95mpMsz/j/IJknw2Tic47tAvQksMj/1gNiCTLqBPuvTHixMcSy6mZfNwg2j3m
         XGc6f1XbApUJKqD70O+0qcmKNIuAyyM7cOH8/vgKe8Yjmh9E59LsB5wmoYfD5ZLe21Tw
         Va8UmyuVmieutt9Ew6Lu0iciEOpbmFa586tzHzyIKmIPF4UNzgkIzOOAsvp+NHplo6h/
         61iniG7iFJIFClkNZm1fYlgFH29A2cEeY6FhcHY9zpATVdC0sytvTNlepniTVk7iKEO4
         ymcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jvL+NTnB;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id w30si125097qkw.2.2020.11.11.06.30.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 06:30:35 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id r7so1800989qkf.3
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 06:30:35 -0800 (PST)
X-Received: by 2002:a37:b545:: with SMTP id e66mr8296564qkf.392.1605105035446;
 Wed, 11 Nov 2020 06:30:35 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <3aae3b3f931618b4418af7992bff1e258e4eb1ad.1605046192.git.andreyknvl@google.com>
In-Reply-To: <3aae3b3f931618b4418af7992bff1e258e4eb1ad.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 15:30:23 +0100
Message-ID: <CAG_fn=Vze9yV7Hy6rf-Sy+F0NP-bPPZZ8QYa3QQu5J8a1q=5hw@mail.gmail.com>
Subject: Re: [PATCH v9 15/44] kasan, arm64: only init shadow for software modes
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jvL+NTnB;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::744 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
>
> Hardware tag-based KASAN won't be using shadow memory. Only initialize
> it when one of the software KASAN modes are enabled.
>
> No functional changes for software modes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
> ---
> Change-Id: I055e0651369b14d3e54cdaa8c48e6329b2e8952d
> ---
>  arch/arm64/include/asm/kasan.h |  8 ++++++--
>  arch/arm64/mm/kasan_init.c     | 15 ++++++++++++++-
>  2 files changed, 20 insertions(+), 3 deletions(-)
>
> diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasa=
n.h
> index b0dc4abc3589..f7ea70d02cab 100644
> --- a/arch/arm64/include/asm/kasan.h
> +++ b/arch/arm64/include/asm/kasan.h
> @@ -13,6 +13,12 @@
>  #define arch_kasan_get_tag(addr)       __tag_get(addr)
>
>  #ifdef CONFIG_KASAN
> +void kasan_init(void);
> +#else
> +static inline void kasan_init(void) { }
> +#endif
> +
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>
>  /*
>   * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
> @@ -33,12 +39,10 @@
>  #define _KASAN_SHADOW_START(va)        (KASAN_SHADOW_END - (1UL << ((va)=
 - KASAN_SHADOW_SCALE_SHIFT)))
>  #define KASAN_SHADOW_START      _KASAN_SHADOW_START(vabits_actual)
>
> -void kasan_init(void);
>  void kasan_copy_shadow(pgd_t *pgdir);
>  asmlinkage void kasan_early_init(void);
>
>  #else
> -static inline void kasan_init(void) { }
>  static inline void kasan_copy_shadow(pgd_t *pgdir) { }
>  #endif
>
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index b24e43d20667..ffeb80d5aa8d 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -21,6 +21,8 @@
>  #include <asm/sections.h>
>  #include <asm/tlbflush.h>
>
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> +
>  static pgd_t tmp_pg_dir[PTRS_PER_PGD] __initdata __aligned(PGD_SIZE);
>
>  /*
> @@ -208,7 +210,7 @@ static void __init clear_pgds(unsigned long start,
>                 set_pgd(pgd_offset_k(start), __pgd(0));
>  }
>
> -void __init kasan_init(void)
> +static void __init kasan_init_shadow(void)
>  {
>         u64 kimg_shadow_start, kimg_shadow_end;
>         u64 mod_shadow_start, mod_shadow_end;
> @@ -269,6 +271,17 @@ void __init kasan_init(void)
>
>         memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
>         cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
> +}
> +
> +#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) */
> +
> +static inline void __init kasan_init_shadow(void) { }
> +
> +#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> +
> +void __init kasan_init(void)
> +{
> +       kasan_init_shadow();
>
>         /* At this point kasan is fully initialized. Enable error message=
s */
>         init_task.kasan_depth =3D 0;
> --
> 2.29.2.222.g5d2a92d10f8-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVze9yV7Hy6rf-Sy%2BF0NP-bPPZZ8QYa3QQu5J8a1q%3D5hw%40mail.=
gmail.com.
