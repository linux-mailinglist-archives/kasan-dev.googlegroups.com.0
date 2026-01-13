Return-Path: <kasan-dev+bncBDW2JDUY5AORBIF4S3FQMGQEM65PWPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 58EEDD1624A
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 02:21:37 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-43102ac1da8sf5617817f8f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 17:21:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768267297; cv=pass;
        d=google.com; s=arc-20240605;
        b=VVmTXBP9AUVPT1Itfo5iOv63iHM1jiVVTyTTxtR1VXEL45CxEBoT4Gs+KaRmJ4/n/J
         6+02Ee8T71awXmS1yqBosBIp8EU1GOi9Vl30DxK4WoGTY5G6KiXWVIE/WeJurbWjU22F
         i8kZIsa8UmAuSizWuAK2gJQOEcyNgcOzaRVVsx8AbOyNDuRqapl9vYQfTyexhAn/awl+
         tb8TZ8eElMLF/743tUCuXdKZPZW/ljvQO+cGwbxDuwSj54YmugqalOdyGUdkFLYCp0fj
         ejK5Eqpk5CWfInDNNIFQnSjZ2iuMG31BbBAU2DXg1GgGXu43JuujcvDQsDOpYO3U5L9W
         xJBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=BU/bjBgRBgJeu8pfioPHwkfKEC1T+97orudRd/Ig2R4=;
        fh=OpVoWqNDLjPvu057ypPCwrAhBKwkO3tCBUbfC+dtwb4=;
        b=lQyXTrku5tz7dyTZmPPBpK0gQ7iC9S8m05RyFXBcVzDHCg5uTamZH17137ZePAiosO
         qmYI+vZAtUBvBnPH0QxkHsilupOEg0LpIF07nnDGEsXUdFsKwYnMBvuJ27o6apiFsded
         J7PesdTLlfS1SlS/8Plo3L60T494MCvBqOGUXQELU5ojLxO/KD/ZIe/GO2KXWoA5L+Be
         EGs4SbFbjNX/+p1TVXE1pvv3Z9HwNW2owKqnQZx+N5TgH0e1gA3lDc99Lky0ChQZOevP
         FzR3eObJDmT9RhHCvHpzwGc71xpRLOlrUWSu1QMEDJvjkS6beR8kBHOZ6nu2qcuLm3/f
         wFpQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BmAKw5Y1;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768267297; x=1768872097; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BU/bjBgRBgJeu8pfioPHwkfKEC1T+97orudRd/Ig2R4=;
        b=GdreS5z9Z4AdsSVfMIfQxU8fG0uv9SfD5d344VD7F3TEZ1Lh4CiK6Kz8CANHhoi0rv
         Rhry7qJy1ArMuwKkNCxJfxQrv0yUcxoyqQD/t1bc1EoAm6qlCUOT9b2o3H9FoGbSLm0K
         IuSOGhkjjQKS2e8Zh7g1E+f+nHi1Y53D5CYpFMfN3uUHIaTSf3Jq1zuWkRDQ4Bupp4/J
         bQXNdptt1Wq9/yIrkCkCIRpk1Rv06yL4uiSjpma4zY2f8xaEQd7oAMZyiel/w8Fb8rr3
         4kSYgcWIwQc/dCzk7Mm9YD0dtnThmSdfZV9hlqtGv5GJzv723flHlSQYKqEs96XHPy0U
         G5+g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768267297; x=1768872097; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BU/bjBgRBgJeu8pfioPHwkfKEC1T+97orudRd/Ig2R4=;
        b=e5BfBOMkQN1Vh7JEVeVNQMIFTNOJM0rHRIQeMztINnLuIhSvyicOjE3uFEnnLHB6iZ
         d1N8ENpv7hshc9pWwMjbfbM+Ut7AmdiligYa4sCJK8B8sql1sQRmOZ6mxEY7VSGTnAYc
         rb2QRP0cxugwlQydiN0a5Q1+6LHhbcA0GySUv8nUVrrOXW173LyXPEf9/Mf+tQMOcAEB
         qyWvlfH87YIXTHMSOHiuxFKJ8X1i8DDz9nlf+2X+ve6Q6ei1xJnSYE/W4GXTsYVZ/N2m
         5y3m/a6auk9Ks9ii24Opdh2fjf/ShQr8hHs4tzcib+R05CDf5wsJB6jZUJhOp6EYEQGE
         8gCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768267297; x=1768872097;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BU/bjBgRBgJeu8pfioPHwkfKEC1T+97orudRd/Ig2R4=;
        b=pb8np0IxU/502Dz7qQ/G3wXmFcO6AYx6S3lvNsI1XXjkiYSEAjDcQMPdNGwmpyJJSL
         sFWjeoAcpIYAaOzhYf6VTKyBnT5jaNkNPAxvLrTrtfT/JsaNhykZhq0vz0IUJWlX6Ld0
         ARwhXLwqcG2LJPv0YX0smDoAI+7BtimfaCpsYgP5En9mpdAywl4vZC9Zy2KPD4cucJDk
         xTyywIgI/uKc7EexpTGZp8FeYflp+6HMMCOvxsgcQdksDmChN/UoJX7fpHuqK2/z9fJ3
         rpMQ9EV/d72cFkIH19OmDyJtxl6KJ9/r0cKDOQqNpLbrEbMiSFv38Pd60jL5d4r92LJX
         LJLQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU4NcRSiufu6P4ppdhnWhUoOhXefa7fup1Db+U2XUN3G5Fa703a0WSONpxUFFHkyjwOX4leAw==@lfdr.de
X-Gm-Message-State: AOJu0YyAgleDCCFMlVFUXPegsS0/oAZ7NkQxM1K8L4Sk1W3TQIwgNDOH
	1anElZugPRMHg5HJEl+DFr5drAVci00mAqj7a19gxn3wo6FuoccJ+14D
X-Google-Smtp-Source: AGHT+IGKALpaL1MLX9tkhh4F4kNq5z5m9YnJUEVYVUnTHOZTYdTZfiMasT3RF/XBUSmuVgeNLxW7zg==
X-Received: by 2002:a05:6000:1449:b0:430:fa58:a03d with SMTP id ffacd0b85a97d-432c37a9c79mr25173756f8f.63.1768267296807;
        Mon, 12 Jan 2026 17:21:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EKqmivF7jreZgIYxL0o6DpaP6ZVHm8ElY+w+EY1zZ95w=="
Received: by 2002:a05:6000:22c7:b0:432:84f4:e9dc with SMTP id
 ffacd0b85a97d-432bc921e0dls4157466f8f.1.-pod-prod-09-eu; Mon, 12 Jan 2026
 17:21:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXeCt+U45FQiOhlGwDgrkyFqqnkvhym3goPXmOWsTgZFGclk4Z2s+zEsp2d/6Kid2jDoo6og3FsqyA=@googlegroups.com
X-Received: by 2002:a05:6000:18a8:b0:430:fd0f:28fe with SMTP id ffacd0b85a97d-432c3798243mr21908257f8f.31.1768267294431;
        Mon, 12 Jan 2026 17:21:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768267294; cv=none;
        d=google.com; s=arc-20240605;
        b=ei0OTaIL55SL71CcKkbuDpxsKpoIQzSi1IUCJ7IZ27G4ijvh8qfIktEEDkeq26HUwP
         Ci/BJe2IwWfy07w/0huo49baiTjj+MXEoQD6rZ/zHpA1qgvpYUawRDfFMS6w5DV2UYdV
         9Fxl8ZavZI42oDc8g/C7RVq4YDrRtrNPMQME65rJAcmcdObJnmFKFwArhJz5+AeQBKFD
         InYinNbm/WYuVx04IvQOaQfi3PkpfU58MIa7QL214hb+DlrhYoEuhSnLRgYne++MzOUW
         IYGhxblXAyEBjOVwBIwIRNBqBW1HSxKpSN881Il8a6XppPo/P8ktYpOwsmqBLeTHD4wg
         PlOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+kYsG3mV0sbzUWkAERcIglZDWBTvQOS7pyKTkWEtOSo=;
        fh=f3LdlHSnkdWYLo4tGCU5rdewAkHDhpztx60wSE3Atqc=;
        b=S+62auKkpoM7HCIPEDE0RWS0KfMXEWSh8THKEqgpoe3lH7COnYpA7EQHMSEfO/UuIP
         SM5zcdGTJmSnqj/AzaGcYj5TqJRVLG0rbmYCraduBkBNTXV5o7ecr3GhK6Fje673b94z
         1uMyz0jzVSgY4QZtmBE59iinW38HnXjEuMGUgBriscNVmdiJZgpFrCvp3UbSoTuGVInL
         rIhHYhZMsBz/oTm5ad6qqIMSHnW47ciYFNlfsJ43yV67m69jk8+ZKsl0YhnVEcmTBtZQ
         DAKkxa72TieVybtny/numiRwS+pYZ1bjPLKjH0KeKmx6Q213CIkODcoZGd035InFKJyy
         4LWw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BmAKw5Y1;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432c1a1bca1si293194f8f.5.2026.01.12.17.21.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jan 2026 17:21:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-430fbb6012bso5661419f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Jan 2026 17:21:34 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUDwqiBD7JhXcAWotj0vMp05dhOZRocP8zM5MxpFlsXXMZI5feJBNJoW/qZWWorxsFYJiQtUunyLXs=@googlegroups.com
X-Gm-Gg: AY/fxX7RgBi/3Y59Dz+GiEgLAfQx8fMFI97aTRRDX11nJ72m67a4UMHaH6TLyjihD/3
	Bhwnfx2E0cqMQYiqgGom58ZBMrmgDK86PEjkfN4eANs/a5+zBIstbcK784hfJNzAL2Cr2yEk/L9
	tvKhsw1Wkt7yQbaPny72j/AN5aKIfuNM5XFw4eppT/tzsNYay3kak5djYLV8K9cNStyAg8VMt3U
	7lTe4oaaojiaWfEGPRhqppYCpBI31OhlRwwmFj0dDWcYLwt34w2/nxFc92IFXSRqv7LPeCG4Cmg
	j28224VjETQhj0aR4t7eoLncn5EELA==
X-Received: by 2002:a05:6000:2304:b0:430:fdb8:8516 with SMTP id
 ffacd0b85a97d-432c37983camr23147516f8f.35.1768267293759; Mon, 12 Jan 2026
 17:21:33 -0800 (PST)
MIME-Version: 1.0
References: <cover.1768233085.git.m.wieczorretman@pm.me> <b1dcc32aa58fd94196885842e0e7f7501182a7c4.1768233085.git.m.wieczorretman@pm.me>
In-Reply-To: <b1dcc32aa58fd94196885842e0e7f7501182a7c4.1768233085.git.m.wieczorretman@pm.me>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 13 Jan 2026 02:21:22 +0100
X-Gm-Features: AZwV_Qi7NcaRI_4PWis1HHKIe5umJhGkHSO55_zW27-aOrJoc50Q2vucvefyxkc
Message-ID: <CA+fCnZd+ANJ2w4R7ww7GTM=92UGGFKpaL1h56iRMN2Lr14QN5w@mail.gmail.com>
Subject: Re: [PATCH v8 13/14] x86/kasan: Logical bit shift for kasan_mem_to_shadow
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=BmAKw5Y1;       spf=pass
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

On Mon, Jan 12, 2026 at 6:28=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
> The tag-based KASAN adopts an arithemitc bit shift to convert a memory
> address to a shadow memory address. While it makes a lot of sense on
> arm64, it doesn't work well for all cases on x86 - either the
> non-canonical hook becomes quite complex for different paging levels, or
> the inline mode would need a lot more adjustments. Thus the best working
> scheme is the logical bit shift and non-canonical shadow offset that x86
> uses for generic KASAN, of course adjusted for the increased granularity
> from 8 to 16 bytes.
>
> Add an arch specific implementation of kasan_mem_to_shadow() that uses
> the logical bit shift.
>
> The non-canonical hook tries to calculate whether an address came from
> kasan_mem_to_shadow(). First it checks whether this address fits into
> the legal set of values possible to output from the mem to shadow
> function.
>
> Tie both generic and tag-based x86 KASAN modes to the address range
> check associated with generic KASAN.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v7:
> - Redo the patch message and add a comment to __kasan_mem_to_shadow() to
>   provide better explanation on why x86 doesn't work well with the
>   arithemitc bit shift approach (Marco).
>
> Changelog v4:
> - Add this patch to the series.
>
>  arch/x86/include/asm/kasan.h | 15 +++++++++++++++
>  mm/kasan/report.c            |  5 +++--
>  2 files changed, 18 insertions(+), 2 deletions(-)
>
> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
> index eab12527ed7f..9b7951a79753 100644
> --- a/arch/x86/include/asm/kasan.h
> +++ b/arch/x86/include/asm/kasan.h
> @@ -31,6 +31,21 @@
>  #include <linux/bits.h>
>
>  #ifdef CONFIG_KASAN_SW_TAGS
> +/*
> + * Using the non-arch specific implementation of __kasan_mem_to_shadow()=
 with a
> + * arithmetic bit shift can cause high code complexity in KASAN's non-ca=
nonical
> + * hook for x86 or might not work for some paging level and KASAN mode
> + * combinations. The inline mode compiler support could also suffer from=
 higher
> + * complexity for no specific benefit. Therefore the generic mode's logi=
cal
> + * shift implementation is used.
> + */
> +static inline void *__kasan_mem_to_shadow(const void *addr)
> +{
> +       return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
> +               + KASAN_SHADOW_OFFSET;
> +}
> +
> +#define kasan_mem_to_shadow(addr)      __kasan_mem_to_shadow(addr)
>  #define __tag_shifted(tag)             FIELD_PREP(GENMASK_ULL(60, 57), t=
ag)
>  #define __tag_reset(addr)              (sign_extend64((u64)(addr), 56))
>  #define __tag_get(addr)                        ((u8)FIELD_GET(GENMASK_UL=
L(60, 57), (u64)addr))
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index b5beb1b10bd2..db6a9a3d01b2 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -642,13 +642,14 @@ void kasan_non_canonical_hook(unsigned long addr)
>         const char *bug_type;
>
>         /*
> -        * For Generic KASAN, kasan_mem_to_shadow() uses the logical righ=
t shift
> +        * For Generic KASAN and Software Tag-Based mode on the x86
> +        * architecture, kasan_mem_to_shadow() uses the logical right shi=
ft
>          * and never overflows with the chosen KASAN_SHADOW_OFFSET values=
 (on
>          * both x86 and arm64). Thus, the possible shadow addresses (even=
 for
>          * bogus pointers) belong to a single contiguous region that is t=
he
>          * result of kasan_mem_to_shadow() applied to the whole address s=
pace.
>          */
> -       if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC) || IS_ENABLED(CONFIG_X86_64)=
) {

Not a functionality but just a code organization related concern:

Here, we embed the CONFIG_X86_64 special case in the core KASAN code,
but the __kasan_mem_to_shadow definition to use the logical shift
exists in the x86-64 arch code, and it just copy-pastes one of the
cases from the core kasan_mem_to_shadow definition.

Should we just move the x86-64 special case to the core KASAN code too
then? I.e., change the kasan_mem_to_shadow definition in
include/linux/kasan.h to check for IS_ENABLED(CONFIG_X86_64)).

And we could also add a comment there explaining how using the logical
shift for SW_TAGS benefits some architectures (just arm64 for now, but
riscv in the future as well). And put your comment about why it's not
worth it for x86 there as well.

I don't have a strong preference, just an idea.

Any thoughts?

>                 if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0U=
LL)) ||
>                     addr > (unsigned long)kasan_mem_to_shadow((void *)(~0=
ULL)))
>                         return;

There's also a comment lower in the function that needs to be updated
to mention Software Tag-Based mode on arm64 specifically.




> --
> 2.52.0
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZd%2BANJ2w4R7ww7GTM%3D92UGGFKpaL1h56iRMN2Lr14QN5w%40mail.gmail.com.
