Return-Path: <kasan-dev+bncBDW2JDUY5AORBKGIVPFQMGQEAT6I33A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A69DD38B32
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Jan 2026 02:21:46 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-59b6a97e566sf2398913e87.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 17:21:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768612905; cv=pass;
        d=google.com; s=arc-20240605;
        b=gDRwAR/xol+/c712nvwJZC/ngqyQEB7O1YiOFUoGJw+2haRvtnFb35I/LF2HA9gceG
         EhAHDkxNM4IJJjL6kVS5KyIOIKfmAzllh/8NysFPzjQwzhV7EbXw91McMv4t/w8tbBDL
         s1nMerlqrsjUvLRMhRqN6uPAA4y/A/ODF+qsRZAelpWFycNKGfAV6Orx6AWGJeGO/2dk
         FWWQDlLVGiC6DXMdaJvAGI9LKyMUe32bkUs2ahhmHG1pK8Oe8XrHLJz8JXr8APaU4EGB
         E+8sfkjqXtIN3Kohgf9bgnZJ72dqJ1YPCrSMamTVNm2pyXZOaHEg1eb6IX/yByqdJ8ZH
         oC0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=22EKCGmB9JUVTbr+gYaHX3Zykltu1d6atA93hy2q7SU=;
        fh=TG9jl3JwRvM927dJEKFV0wrgKwbu3DgfM3bdj5qkFo4=;
        b=PkMzaWUK0UfqRqKtvXVofO/b+qyfdtvjjw9/zxPZza7IbyA4gCaZgk+90ZIzNdrmrk
         bwXSMVwXFCiVo8jSUHHondVdLxs/N1H5I/msHwVb6NStuJy7Q0aVW2hG45Fah7d71EEB
         KSG+KPzEyiocwNisczTrGb1cEVpgXYlzMcgWLyjNfsw0nBTYQx9v259TqQ1KfVdL/B+R
         xlW9h9d7oYNtKKNfobMyU6J7gHIR6sMOUIIDnsRb8RHqSnqunSIh1I1KBlFzH2Q4phEg
         g1jfVnEl0JdggJYGaeXubJ5hsbhhOUsQWDuvYk7FuVRMii9BGBpvr4LJpaJKgsGFR1/d
         zh+w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="cyJt/FsY";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768612905; x=1769217705; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=22EKCGmB9JUVTbr+gYaHX3Zykltu1d6atA93hy2q7SU=;
        b=nnQcx4UirLm4KPcOM3EgT7y8yKFwGWhvsNt6AYDj/2h5VChpF/N4fXshKTFMAmqk2s
         XhfV3P2kKHcrKySGySpldJqSlMNRenF5ueAXTbg6whNjWKxKHrgN77l3cOU0I0sle65w
         P9H2d+Dve2WG8WTQIGNXa30QisS5bTCTlTfwfcYPddt+V+8UDPhww13O8yZhk1FSUsmp
         t+YLdL2v1Aib9lanfjAWi1dwRh1QQocLPOwC8f6TG0Do5iepWe2g+FN4c97rB+nSUuur
         Fx4LJF+KhfJCVOVBnpENzUHBr+iKfpKZDZUPgDcTcndirgw85jzW8GqWbJ9yRVLwdKgm
         tEVQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768612905; x=1769217705; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=22EKCGmB9JUVTbr+gYaHX3Zykltu1d6atA93hy2q7SU=;
        b=llJyaveiWNH0Cv2hlnYzn8+KhPMZWtbf0jz1QH4j5oQhne0ZQ+aGLYPviuZSdhCcPe
         vSzIOpklw6m4T9WOTPobDO3yDqr94FjzLZSCEtm4q6mFfxKgd9du7jw1wmaT2eyC0og1
         onnssVditPrycNA4eIxhXu7r8aEoY17dORFDhEjz6UBzxujs9VZMUEJWsGSRVHHTKwf0
         xX5yHetwsl9AO5Uhyiomua6r4lV+s9ARlIiz95JIsmDU9Dy4QZ58+Ma3U6bddbzmVeOL
         M2pwIGBJBVHYAR/XoI24O2YhibCB4ZCLgd2SCPGEuCTFNWsj6KeY8Uy0nSJShfXvSH5o
         mt0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768612905; x=1769217705;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=22EKCGmB9JUVTbr+gYaHX3Zykltu1d6atA93hy2q7SU=;
        b=f47x8+PETELWQAUI4nrqwZxeZbjQ2P/Hu9ZyQWGXzeCQ6Li9JhrFF65RufrRzy2qOP
         +tRO9DnDD4JoRofBS+OEduEvAWq2+7LHG0c0h283xi9hso/YCI+fkIRQVJknGD0TfQax
         7US9J/a8aHTwcgKLB7x13qU8FOLC0FZ6GRFR/CiRFyPSFx/cTdakq7oXotzZHP2STE6A
         ZuLU7S8rGVU77V/ZfUYejviHC63yKVlIpJ9t9KHpzjdS+yuyL7b6oVWfT9dPRtaVyfOR
         p7LIK+pOcvJfvqUhNNAhgoWliycrKLikBuW+zD/QAs9bWh1f3vArrtcG4nyn5mqVhX9p
         HVkA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWPtwMT6A9prTFhHh09MhE0Bgg3njBbp95o73xKRRjffhE2wIx9NitDIW/kN/gWzNK0FQjxnA==@lfdr.de
X-Gm-Message-State: AOJu0YxPiKPR2wSQxdwnowxWUnW3IZVpnJWjiaqbqyCdaxyiqLW+JC0T
	ofJ4Zwag8jLTLbs9apIgj2SMs6f+l4C5c1/ud2KJOaklC5ojtDjkCeiL
X-Received: by 2002:a05:6512:1191:b0:59b:af9f:33f5 with SMTP id 2adb3069b0e04-59bafb87d4fmr1516838e87.0.1768612905283;
        Fri, 16 Jan 2026 17:21:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F7pgGXxweetMc686/q8IYsUOLIQVjCkvAgKaC3usfDCQ=="
Received: by 2002:a05:6512:3409:b0:598:e361:cc93 with SMTP id
 2adb3069b0e04-59ba6b00f98ls830212e87.0.-pod-prod-05-eu; Fri, 16 Jan 2026
 17:21:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV4rF1k9122vjkzhOHzzjilXoIm74FecIEnVhtMGKEfQ9Cp23eAp8ZrRVuFUF4R8uHa+Xj34VToNW4=@googlegroups.com
X-Received: by 2002:a2e:be0e:0:b0:383:1994:8d with SMTP id 38308e7fff4ca-38386c5da7dmr15271271fa.40.1768612902681;
        Fri, 16 Jan 2026 17:21:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768612902; cv=none;
        d=google.com; s=arc-20240605;
        b=YirFS/wERxY9PGi2hS9yjzFO1LXMqV7Xqn/djN2kaGzBDlRGwyZdgvTC6FoCCNI2/c
         2RlEBse2g/w4owp+gHh5/K3MSIYrxXX3ggBptNQZMq5arl6WirjR54biXKYpVL6A+lDa
         XnqYP7xP/ls0rJ0j1Dgo8EMCKZQddeXNr0W1JHDGm8RNUxjyFOXj8EXmkdP3AXS67U+7
         mqS8bVtPc9a4yWkemQVswmpaMste/+a93iFNI+bRorcoY8QuosYEPIjkz7dHT3MR+YiD
         x8enRCFZa8u5ll1Bl3rwANppB+9wVKeTlyu9Aul9KffckcewBtwKdIF9hggrg74hOpaR
         3QOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4ZoieeAq320wYXZiN7yy2TmOrY+yh5Mr8oDFBIEecDc=;
        fh=VbOHIuO4E7q1oZjxY8luZBHqaEZaEz2AMJNrzoszr1o=;
        b=dQjyk9MNbJKCoT3+zLsKtPZzp+WbJoV6gzJykHEQVIRW0tsFWdHvNWqumrraexy406
         zuHFZhUbuycQ7W71yOu8uPFrVEyu55uI/cf1kU8yz+wYsa5GHjwzFg6rx9KHV3QtskmI
         PLU9C/3q9ROutLDBuaPCZW6B0KPZUfwLdH4d08GdvgYLiL30+9bz2pZG/Qigf+wr3eov
         F5aWcowa6A02iIeSjZgH7OmCJaihzf0mG9Ge83HEjfbKYPBA8vJznWHYxfDvqoMOakU1
         P/thcrkXILl8BLSykZ5rTWGRGRvyhSGVO93/zRgv7GGBNXhmZONtkKnOUIGv/UGrwxs5
         yekg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="cyJt/FsY";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384d35eabsi700971fa.3.2026.01.16.17.21.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 17:21:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-432d256c2a9so2560343f8f.3
        for <kasan-dev@googlegroups.com>; Fri, 16 Jan 2026 17:21:42 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVIi5cA+QTRXvd7EZZa8Z56FLqnYUx93wkpf3q24EHiS4ihml+2dgf5vWOh73dSfjgp0FU6VY930ws=@googlegroups.com
X-Gm-Gg: AY/fxX4TzF71/Uc1SUaqtM99nFVejBl9h8lZk2qpjwD6uaoHiFRLjZLY+oakTq3nzxP
	uLJW79F+JtO5j4TFU1z8EvOcltk1+KZcuWUdNnOaT3OIP2PuYszLOQudGiuNPvtVKFO1t1ZWWde
	Lx3cJs6ybL9a37XG9YhICtNezWF+6Kee6T4ByHv4ym8JJBEwol6aG5a7v+JGRou18yE8gE53y4E
	QnkYtq04S0cGsLRAic06bGBZB/638f4WRd1sYub3IYjv/sJOZ/Nk/eN9JaKhmODCY1is+X5FW7a
	/9Veoi24GdZjkI5IUJy7QkqOcMcA
X-Received: by 2002:a05:6000:1861:b0:42b:4267:83e3 with SMTP id
 ffacd0b85a97d-4356a0330a6mr6681825f8f.5.1768612902135; Fri, 16 Jan 2026
 17:21:42 -0800 (PST)
MIME-Version: 1.0
References: <cover.1768233085.git.m.wieczorretman@pm.me> <b1dcc32aa58fd94196885842e0e7f7501182a7c4.1768233085.git.m.wieczorretman@pm.me>
 <CA+fCnZd+ANJ2w4R7ww7GTM=92UGGFKpaL1h56iRMN2Lr14QN5w@mail.gmail.com>
 <aWfDiNl9-9bVrc7U@wieczorr-mobl1.localdomain> <CA+fCnZd4rJvKzdMPmpYmNSto_dbJ_v6fdNYv-13_vC2+bu-4bg@mail.gmail.com>
 <aWkVn8iY27APFYy_@wieczorr-mobl1.localdomain>
In-Reply-To: <aWkVn8iY27APFYy_@wieczorr-mobl1.localdomain>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 17 Jan 2026 02:21:31 +0100
X-Gm-Features: AZwV_Qg_yxoV1caCuXx4uiUVJpxmUSikYvM_SoJc_MuJvTE1bQn56yiQmf6n8wA
Message-ID: <CA+fCnZewHBm+qR=zeJ4DG6RJ-mHhLhF9G7f_xSaNt_PAogJv2A@mail.gmail.com>
Subject: Re: [PATCH v8 13/14] x86/kasan: Logical bit shift for kasan_mem_to_shadow
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="cyJt/FsY";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Thu, Jan 15, 2026 at 5:43=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> x86 was easy to do because the kasan_mem_to_shadow() was already in the
> asm/kasan.h. arm64 took a bit more changes since I had to write the
> arch_kasan_non_canonical_hook in a separate file that would import the
> linux/kasan.h header in order to use kasan_mem_to_shadow(). Anyway below =
are the
> relevant bits from the patch - does that look okay? Or would you prefer s=
ome
> different names/placements?

One comment below, otherwise looks fine to me, thanks!

>
> diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasa=
n.h
> index b167e9d3da91..16b1f2ca3ea8 100644
> --- a/arch/arm64/include/asm/kasan.h
> +++ b/arch/arm64/include/asm/kasan.h
> @@ -17,6 +17,8 @@
>
>  asmlinkage void kasan_early_init(void);
>  void kasan_init(void);
> +bool __arch_kasan_non_canonical_hook(unsigned long addr);
> +#define arch_kasan_non_canonical_hook(addr) __arch_kasan_non_canonical_h=
ook(addr)
>
>  #else
>  static inline void kasan_init(void) { }
>
> diff --git a/arch/arm64/mm/Makefile b/arch/arm64/mm/Makefile
> index c26489cf96cd..a122ea67eced 100644
> --- a/arch/arm64/mm/Makefile
> +++ b/arch/arm64/mm/Makefile
> @@ -15,4 +15,6 @@ obj-$(CONFIG_ARM64_GCS)               +=3D gcs.o
>  KASAN_SANITIZE_physaddr.o      +=3D n
>
>  obj-$(CONFIG_KASAN)            +=3D kasan_init.o
> +obj-$(CONFIG_KASAN)            +=3D kasan.o
>  KASAN_SANITIZE_kasan_init.o    :=3D n
> +KASAN_SANITIZE_kasan.o         :=3D n
> diff --git a/arch/arm64/mm/kasan.c b/arch/arm64/mm/kasan.c
> new file mode 100644
> index 000000000000..b94d5fb480ca
> --- /dev/null
> +++ b/arch/arm64/mm/kasan.c
> @@ -0,0 +1,31 @@
> +// SPDX-License-Identifier: GPL-2.0-only
> +/*
> + * This file contains ARM64 specific KASAN code.
> + */
> +
> +#include <linux/kasan.h>
> +
> +bool __arch_kasan_non_canonical_hook(unsigned long addr) {
> +       /*
> +        * For Software Tag-Based KASAN, kasan_mem_to_shadow() uses the
> +        * arithmetic shift. Normally, this would make checking for a pos=
sible
> +        * shadow address complicated, as the shadow address computation
> +        * operation would overflow only for some memory addresses. Howev=
er, due
> +        * to the chosen KASAN_SHADOW_OFFSET values and the fact the
> +        * kasan_mem_to_shadow() only operates on pointers with the tag r=
eset,
> +        * the overflow always happens.
> +        *
> +        * For arm64, the top byte of the pointer gets reset to 0xFF. Thu=
s, the
> +        * possible shadow addresses belong to a region that is the resul=
t of
> +        * kasan_mem_to_shadow() applied to the memory range
> +        * [0xFF000000000000, 0xFFFFFFFFFFFFFFFF]. Despite the overflow, =
the
> +        * resulting possible shadow region is contiguous, as the overflo=
w
> +        * happens for both 0xFF000000000000 and 0xFFFFFFFFFFFFFFFF.
> +        */
> +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS)) {
> +               if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0x=
FFULL << 56)) ||
> +                   addr > (unsigned long)kasan_mem_to_shadow((void *)(~0=
ULL)))
> +                       return true;
> +       }
> +       return false;
> +}
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 9c6ac4b62eb9..146eecae4e9c 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> ...
> @@ -403,6 +409,13 @@ static __always_inline bool kasan_check_byte(const v=
oid *addr)
>         return true;
>  }
>
> +#ifndef arch_kasan_non_canonical_hook
> +static inline bool arch_kasan_non_canonical_hook(unsigned long addr)
> +{
> +       return false;
> +}
> +#endif

Let's put this next to kasan_non_canonical_hook declaration.

> +
>  #else /* CONFIG_KASAN */
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 62c01b4527eb..1c4893729ff6 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -642,10 +642,19 @@ void kasan_non_canonical_hook(unsigned long addr)
>         const char *bug_type;
>
>         /*
> -        * All addresses that came as a result of the memory-to-shadow ma=
pping
> -        * (even for bogus pointers) must be >=3D KASAN_SHADOW_OFFSET.
> +        * For Generic KASAN, kasan_mem_to_shadow() uses the logical righ=
t shift
> +        * and never overflows with the chosen KASAN_SHADOW_OFFSET values=
. Thus,
> +        * the possible shadow addresses (even for bogus pointers) belong=
 to a
> +        * single contiguous region that is the result of kasan_mem_to_sh=
adow()
> +        * applied to the whole address space.
>          */
> -       if (addr < KASAN_SHADOW_OFFSET)
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +               if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0U=
LL)) ||
> +                   addr > (unsigned long)kasan_mem_to_shadow((void *)(~0=
ULL)))
> +                       return;
> +       }
> +
> +       if(arch_kasan_non_canonical_hook(addr))
>                 return;
>
> --
> Kind regards
> Maciej Wiecz=C3=B3r-Retman
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZewHBm%2BqR%3DzeJ4DG6RJ-mHhLhF9G7f_xSaNt_PAogJv2A%40mail.gmail.com.
