Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZP2V76QKGQE2CY5TMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id EF8072AF456
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:04:06 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id h6sf2691718ybk.4
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 07:04:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605107046; cv=pass;
        d=google.com; s=arc-20160816;
        b=g0zF5wh7xfK9P1o5gou1uHLRKR5eG4prx+D0LpEC61+UyH0iXtLKdNzwGHbHiZtbG3
         cz4jPnRZSg/ZN0rWAecNdxFx6/+uUFZKvj8ktR0KP1R6oOEPRnwcK3v1AVdVhyDKy9IY
         TBw2elJxKZaUVbqpf6TMdI+wnNXZOEEid5jBhC86psECpvBca6Wa19PcdYQ4TUOZl0pT
         sE520P0/mm3vX3QoSvnh5fr4eeMOM3pGMuzNQEP/ZdtYcpHr3dAWrQqL7pO9fLZWXLA6
         hSV9YZa0cBmeQZLnFpLxmZOXyiRviNc577OuGlSz/Efr3iu8qAiRkdnMZ5ozdcuIFFe+
         kYiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eLV0Z82K1zHej8wezOIPDa8zapkZQGBd4c0EvAC2zSk=;
        b=QW49LzyRFSksQiYX5e5RfiF2SfiZb0ia4+KLb4+H/Np3ixfC67tILiyWucu/LqXrzS
         iglNAe5JwhnWaGfz7O/fQNis1j0Hq0BJDZT95XkqlS1B7CPt8/SAjaxog2/FQog5VhIW
         Nu6qemCeCYl16CIkiFcuqTz49e6jmuo5C/CYUf8M1++vTfC5l3DHs39F2RaTdbmYIQ2U
         79F6Tf8CCA149hQZz+fKpucDHApNhEFIXDNjcf9YyoXQFO0dvvIG2Ms7ItCyHGZVEsi3
         qfFGTtysSp8nazE7etzJjUiQkGDQJ+t2oQf3p8HPyoRJiv9i5YKHfWUIkr31RiGxkxq6
         FvWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uipkPj5W;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=eLV0Z82K1zHej8wezOIPDa8zapkZQGBd4c0EvAC2zSk=;
        b=Di2JzDUignUGG4e8786dwkh49Y2ov7n60Dd/h9sBR/q4mDsFD8Kc1PEhFddwAbp0ox
         YZW0BhSaSHRTYit/x7DTbG+FuuX1VSF3+5MLEeDmxqoBQuPwFO2Lc6xpG/ZmxJULA/uL
         ZrqsxNe4qXOFxyI3/yuHmV9gc++yqjbNPckGhnTuYoc2jHpRGlg0H8wdac105q9SpHNx
         Ay7xp656GrLsxglbnZzjAiloQCW6CLpZv1J3VFFbcLNmpvFnpkS4WDNhhLBRMG5k7DtR
         W5+4JkZ1CHeBYnGydkmUq83YrCyWAWP5oaY1c6mEwm9/UgodL51hEIr9zOkNavL0ixKF
         ojaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eLV0Z82K1zHej8wezOIPDa8zapkZQGBd4c0EvAC2zSk=;
        b=Xvcqep9S5IW73bmmBqwrvG4SJEi+/F8VH7iXkW3Pj0qkXI/RQMEQXN3vCoYe4Rw7SV
         dxIesUjdqMPC3w9s3zsSHZ55ReZkojYow7yXt+ZsljapqL3aoIvaMrK/1yKubwPQrQne
         nxb8kR/T1n1Cs6dZXVHYLtAqv7GjmjsbUlMbOyTh9VfWxx9g8IJGRjN0Ka9IN/BLr9/O
         Bkv5VLaHbDYuxumT4bjx+j5qQ6CvFVPQfUrI6Fu+hgJ2lx+G92Nspl2IvH678PONgkhs
         87DIOFvLvIFNQMldfrOpxmUoy/XbO4I8XrYhRudvbTZdikS7QPOFJf2GB7PAkT8kvD46
         4h5g==
X-Gm-Message-State: AOAM533DmaUxa3nrKWW1YCfaY0eKk/s2w+p9WdkbefD2+E4LJAmESNgh
	X+rZA6/RDWaKPu6NTLp42YQ=
X-Google-Smtp-Source: ABdhPJywXmHhEWlIxw1rYWMaKCUn3+poA8lQIt3dqGm+MUEcbmwfYoP4fay6U+Goi6DUQ+6+hmtsvg==
X-Received: by 2002:a25:d10f:: with SMTP id i15mr35467999ybg.60.1605107046038;
        Wed, 11 Nov 2020 07:04:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:705:: with SMTP id k5ls55734ybt.4.gmail; Wed, 11
 Nov 2020 07:04:05 -0800 (PST)
X-Received: by 2002:a25:9302:: with SMTP id f2mr35301369ybo.352.1605107045519;
        Wed, 11 Nov 2020 07:04:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605107045; cv=none;
        d=google.com; s=arc-20160816;
        b=dI8GyccLhDMAfKL3UBHQ8aHtLPphc0QS9rB6CUo2WCTXD69T8LIsITQzTAIdhc2Z49
         v0Hp31l6pVyBrSxUiETVmP5EW79utNQnAacn3NANoyxqR3E9tA0Tyjr/Nqb8joLy1OHa
         KATJXnhIfn/C6fL/szH4CXUI3Tr+uVcIRw6miW1PV6X3LPVcnISIdjNWDzDLNzNZKI9S
         vPlzbX+KRxC2DM6Vbc6A+L5rRpG3UVq7dqqDNmLQc1YnOn/MYIr2N0W7h1mVgV0X2KQv
         oBlyNDJy6pnTi7r1wY9/ahu9eZKkoArguskndVw58G8mnz1XNwACKoH0cOTZNR+AbGP6
         M9Dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=T/yXDCUDWYrYlUTbV+JUoEICw4sgibdbwn70JC0Gn9g=;
        b=aeSd3QpcMI5GVbTyiR0dUGYhRf78R/WlMQvGLID7hKXnWuO2d2c6chCWBuUGF1dOw3
         3XBu520xT7UXmnyhZRI+LDAeLCWMUyVvufnPjD9DhxGJX6n0gUtysW7iElUg0RUq9J7u
         f3bWu2KOFDbT5rVVxZHVYnLRJyn5wDgpVF2oXcCGXYQx5mZXYP//ysqd2er8cOpDacs+
         LyZRbD8XGCxgKG4ryXCzuWdEYcB2pOfC/h/JqfNc7e6lk5b91MyIrSt2iqd8MqVJMBLR
         oS4yZWVgOmosi7gMvTzKxRNG+hF7c4dJaHuxQosSRAs7jvby+pTWUxBOMvqp6HrPKrsY
         0IzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uipkPj5W;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id i188si162842yba.4.2020.11.11.07.04.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 07:04:05 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id j31so1446167qtb.8
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 07:04:05 -0800 (PST)
X-Received: by 2002:ac8:4884:: with SMTP id i4mr24115822qtq.300.1605107044904;
 Wed, 11 Nov 2020 07:04:04 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <619cb0edad35d946c4796976c25bddb5b3eb0c56.1605046192.git.andreyknvl@google.com>
In-Reply-To: <619cb0edad35d946c4796976c25bddb5b3eb0c56.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 16:03:52 +0100
Message-ID: <CAG_fn=UKSp8shtYujRbM=8ndhLg_Ccdpk9eSfOeb=KpwNi7HBg@mail.gmail.com>
Subject: Re: [PATCH v9 17/44] kasan, arm64: move initialization message
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
 header.i=@google.com header.s=20161025 header.b=uipkPj5W;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::844 as
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
> Software tag-based KASAN mode is fully initialized with kasan_init_tags()=
,
> while the generic mode only requires kasan_init(). Move the
> initialization message for tag-based mode into kasan_init_tags().
>
> Also fix pr_fmt() usage for KASAN code: generic.c doesn't need it as it
> doesn't use any printing functions; tag-based mode should use "kasan:"
> instead of KBUILD_MODNAME (which stands for file name).
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> ---
> Change-Id: Iddca9764b30ff0fab1922f26ca9d4f39b6f22673
> ---
>  arch/arm64/include/asm/kasan.h |  9 +++------
>  arch/arm64/mm/kasan_init.c     | 13 +++++--------
>  mm/kasan/generic.c             |  2 --
>  mm/kasan/sw_tags.c             |  4 +++-
>  4 files changed, 11 insertions(+), 17 deletions(-)
>
> diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasa=
n.h
> index f7ea70d02cab..0aaf9044cd6a 100644
> --- a/arch/arm64/include/asm/kasan.h
> +++ b/arch/arm64/include/asm/kasan.h
> @@ -12,14 +12,10 @@
>  #define arch_kasan_reset_tag(addr)     __tag_reset(addr)
>  #define arch_kasan_get_tag(addr)       __tag_get(addr)
>
> -#ifdef CONFIG_KASAN
> -void kasan_init(void);
> -#else
> -static inline void kasan_init(void) { }
> -#endif
> -
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>
> +void kasan_init(void);
> +
>  /*
>   * KASAN_SHADOW_START: beginning of the kernel virtual addresses.
>   * KASAN_SHADOW_END: KASAN_SHADOW_START + 1/N of kernel virtual addresse=
s,
> @@ -43,6 +39,7 @@ void kasan_copy_shadow(pgd_t *pgdir);
>  asmlinkage void kasan_early_init(void);
>
>  #else
> +static inline void kasan_init(void) { }
>  static inline void kasan_copy_shadow(pgd_t *pgdir) { }
>  #endif
>
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index 5172799f831f..e35ce04beed1 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -278,17 +278,14 @@ static void __init kasan_init_depth(void)
>         init_task.kasan_depth =3D 0;
>  }
>
> -#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) */
> -
> -static inline void __init kasan_init_shadow(void) { }
> -
> -static inline void __init kasan_init_depth(void) { }
> -
> -#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> -
>  void __init kasan_init(void)
>  {
>         kasan_init_shadow();
>         kasan_init_depth();
> +#if defined(CONFIG_KASAN_GENERIC)
> +       /* CONFIG_KASAN_SW_TAGS also requires kasan_init_tags(). */
>         pr_info("KernelAddressSanitizer initialized\n");
> +#endif
>  }

Cannot we have a single kasan_init() function that will call
tool-specific initialization functions and print the message at the
end?

> +
> +#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index e1af3b6c53b8..adb254df1b1d 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -9,8 +9,6 @@
>   *        Andrey Konovalov <andreyknvl@gmail.com>
>   */
>
> -#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
> -
>  #include <linux/export.h>
>  #include <linux/interrupt.h>
>  #include <linux/init.h>
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index b2638c2cd58a..d25f8641b7cd 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -6,7 +6,7 @@
>   * Author: Andrey Konovalov <andreyknvl@google.com>
>   */
>
> -#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
> +#define pr_fmt(fmt) "kasan: " fmt
>
>  #include <linux/export.h>
>  #include <linux/interrupt.h>
> @@ -41,6 +41,8 @@ void kasan_init_tags(void)
>
>         for_each_possible_cpu(cpu)
>                 per_cpu(prng_state, cpu) =3D (u32)get_cycles();
> +
> +       pr_info("KernelAddressSanitizer initialized\n");
>  }
>
>  /*
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
kasan-dev/CAG_fn%3DUKSp8shtYujRbM%3D8ndhLg_Ccdpk9eSfOeb%3DKpwNi7HBg%40mail.=
gmail.com.
