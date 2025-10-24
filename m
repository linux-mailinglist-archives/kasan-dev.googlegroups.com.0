Return-Path: <kasan-dev+bncBDW2JDUY5AORBSNI5PDQMGQEYBD52PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id C9614C04020
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 03:20:10 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-362de25dbc4sf7431891fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 18:20:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761268810; cv=pass;
        d=google.com; s=arc-20240605;
        b=GQLKA6ZC+P0fXcCL7OiQto0ZWGeQeTR2All6puz3dypPHNDh91oxKRfJrWXr3dZk3t
         H1bYRm7X+i76HweJa7tqmLDqGh7MD/OcL51MhrJqxhG3VXjcA3mpkc2JJRWT3U4sT3mT
         QxGrMq7P5cu2y8VyQr7xFEopDnyEf9p703UokJcN8WwirjjsfIh24Hc00iRtzKicq5WC
         Gal8NrNpYQ8iROA7civLFg4skMNYLIa1pkNpKMNEs/RKj1uchN3/OimUW8jiozWpqhgb
         SxpSmHzO54JnlpNyynAXHKJ6x/tH1ial+ayDWWLtuocL+O6gRV4d3uouew/HB8vtT/bG
         aizw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=eB/FFzlX9+kXye/fjD+QprqHpkTVUlUtsodnF5Ik8Tk=;
        fh=oT6iEtQfyjFTTG7qrSCjcUeYuT6jBl/VPQ9eqA1nIAo=;
        b=it4f9STdT0HUYZXELUBDi80JHxSCMjLeUn+tVDXCjeLPA72ovovetIOYNfIGNBGVJc
         09dg3ASi45IcvIP5lvcwKCN2/OWP3ODpY/8bGuUoSD4akBFKwIegyD8kmwBWn/7rSu5h
         HuCSr6lGcWHZsDvg/Qt0y538qXVHT3Wdh+h6kXzn1iFwo6WNPtU3IK3mWy20qUSozUtC
         iV6MpLqokJPjVCE2wUfzELOsNG4CLcKGycfBXRNDrm6eSpJIAWVO4V4njeeaejKmDfj+
         PiBPMmB/tmCYB7dEKeXESFILhbIG4uESLwV9BJAOJ1KrH/Y63dX9nbvaRfUZXaiG03d5
         NNSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cm3TSU3P;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761268810; x=1761873610; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=eB/FFzlX9+kXye/fjD+QprqHpkTVUlUtsodnF5Ik8Tk=;
        b=bRMG43WfoHXY33xYeinJ/prqP/Q/4NX8dGMDPdF/iMvGpMCvJKXXmm/wZgYpDtiP8a
         7RS4UwzY/PVjMsPbXtNIpt5GxPXqd3atNSSf/0j31exSjEqmPSDwa7JkHcOifmHq6Ran
         WDhpHHD9w6DE3Jg1336F4jOYg/Pawudq4RhCYZm319oCGx+NvX4xxLqaTCxuKWEn7FbA
         u8GiJf5YRp7vdyk2MWYDWbPcShviReB72W36mQ2g/enMDkERaIUM8gbIeuLysMxcuu+U
         0YgHREoqBD1AJd1b98CVqUJy6QwEP31eaR0i8jcBBQ4C0RRsKJh8Vwjgi85THJWcsXDc
         gaug==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761268810; x=1761873610; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=eB/FFzlX9+kXye/fjD+QprqHpkTVUlUtsodnF5Ik8Tk=;
        b=JNOP9jJ9vHMd8qi4CUOGjfY0h2lxL+pNK+EafTipd1r9kGIvR36wNwiqWTXLh+cYBG
         Xu9TbwJAzK839Sul8DE5B7ntOV77cTYQQOGo3jLUuJdI/r2A0DlqkfF178SYJDtEmhDV
         Bj1zbfSPyg3vQEcsQruvidoQZFGHriD/MZTueThApcGE9k+Pi+h2kqJa6Am20JD0HV+5
         sGWLmkerEmMhIFRAnDy0c7upbnC3xsCHym8ztZbWGqME89N/p5WlMzBm1AffvDFLxYvi
         un8NJl5ikuKGzSSOD2V7Wp7X1sbJZPM/xqFwzVIb8dW4u9VcBdmJmIYIIFbGsIVQh3gT
         Wcvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761268810; x=1761873610;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=eB/FFzlX9+kXye/fjD+QprqHpkTVUlUtsodnF5Ik8Tk=;
        b=XlkfDd63Lc2TX6NZx9vzJvDDNK9otQC4Lp+4wAs2fZpIqraQS3xwZlVMqgy4seu1dg
         tkz2kSghz9PEvPGtYGcgPUPGvewo2VFHc3QOVf0EB63bjLLDLoD3lik+ePD9Y2B9iqqt
         DMUwAKhaDsi11cm1V7tInJLQa/lX/30aerbDO4LVuIZb4uPomwkqRuWfkBVaf53SmVtS
         Wi++C/CuBXJcriZQlPWsd652QZnQ0NsDAHnThcXi9M9QrjS4aIH3qxRbNEkO92s0+HZr
         1lYxGKX0o5a7WvATyo9QFWyCmUBtQjLOeN6RlkxKNSoVDyEnY33T2RQC/Js4ifpRFZ4b
         iuqQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWMSr/+l08ZBXifZ2C/hSlD3bp1DwwlIj+1nZHb1l5V9nDgc0cYpJyk+6bcM9CG/QVwyDMq4w==@lfdr.de
X-Gm-Message-State: AOJu0Yy6vlNyi3BMkM7d2qMOF6TfzC4NlVvaR+q/U7x49K7hzNDAHgSz
	SAjpxf6b66jRVff/DPTV9n4/jUPsqE4RlFf+DZFXZ54D5PYTFQOfrgsU
X-Google-Smtp-Source: AGHT+IEAXHGnjVUBCawe/FRS8/8wyvocLAxuBNdwD+NjszRRGQ/QmDC1Eulnusg8mbHoxDO2JpgfFg==
X-Received: by 2002:a05:6512:3f13:b0:57c:830c:2f97 with SMTP id 2adb3069b0e04-591d8575475mr8875424e87.50.1761268809735;
        Thu, 23 Oct 2025 18:20:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Ylh6oTaiEkRZvwJ8TpHvY0ztjb9OXq6GYkXdBQt+yY0w=="
Received: by 2002:ac2:4647:0:b0:592:f85a:163e with SMTP id 2adb3069b0e04-592f85a1741ls329768e87.2.-pod-prod-05-eu;
 Thu, 23 Oct 2025 18:20:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXvAAH+xhBblnFfATjxIX6TAmqiWG6myNAf0NaXdVVOyoWngSocMv2Y6GIuFnrD6PTgp7K7oavavPQ=@googlegroups.com
X-Received: by 2002:a05:6512:6cd:b0:592:fa97:e167 with SMTP id 2adb3069b0e04-592fa97e51emr726785e87.51.1761268806726;
        Thu, 23 Oct 2025 18:20:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761268806; cv=none;
        d=google.com; s=arc-20240605;
        b=IGpHBW25M01r+Bq12EG2qA/UBKDTkm1hUwPt7pdA1Wvh/aivQ3SjRuMVkIy5YhEV1d
         1JmqwUVZGb2JcBACADy6ZIQ0X08/QimsvrSJpr2AqQryjudJfU3Jb78oQtWLoK5qyUER
         nAYmQUmS8ONpTBVHh4QZcPd4eOWKkmu52/1IsLxqng/kIBGFhybJO/QEk1nQ5+Bc6SzI
         RuVCcVtVvxN0Uu/AoUYSGrAhOTgBAokxmW2MAd1o9ivVNjGY2kHsCSiwxFao7wUGDtG3
         wwz0EBmfn7U6kbNsUOdZQ4u/EZFgl4NO4c74ZNnCWZvZtL9Mzlseypqu8itUOoc01/8M
         yE+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=YvyUZmMO8VPiZdlgVO/IJ2704hYsi6LPcWtQZ//HkFI=;
        fh=OzFFAVLYY/PKX/dm6AVc+lu3UiTMiJoW2Qqfzm+MtTY=;
        b=CPS802VqP/8iB2uhypX56Ta2kHZowdu9oKKHZJ/ETipDrk+pWO37Te0XLXWRl42jTl
         znCReX6Ri20vIP1CfxSdnjDr4nVGk0fFOw8jR29JypCao5KwWDYopuIwAtKpUsDRxwCG
         vRTr51i8zAK76caLssFTtsmS0CGvSLkzBda6UfBcFhX5XZ6x2/gg7sJYR6BKA95/0hAd
         HbFjPhXVpFNuKPOW+mSrmpL1ooJ4h1aezzUF3cCnMqM8bqf5neIMVbfuOLLxEkO9gbeM
         YS5LwJXOv/McX691ejVopuDcf5FL5YeFZJhJhBq7TceI1XZlkdhe+50fR5HlEHG0EE1g
         dscw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cm3TSU3P;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-592f4cd5d02si92366e87.1.2025.10.23.18.20.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Oct 2025 18:20:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id ffacd0b85a97d-4298bada5bdso1071805f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 23 Oct 2025 18:20:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVDJuSnFARuzoizXKnvKakblrs1nwDCimgB8PlSEXSpVN5LHfiIene1mRyQ9zjD14GcSd9TMeCYOAE=@googlegroups.com
X-Gm-Gg: ASbGncuPhfzjOaQ+CEFBvCrbEaNH/YA92jk/G79iRTCLJymR4BMk+JGx495ORAzDwym
	9ZMmzJG0xqJFTA0hQ4EIgNatrteIQ8BNH3dqHvHSWSgtdD9jNjqlb94dBwEs1ryx7ckZAM2Y+CK
	QMpjU/paqLqb6ObuADr/olSHmUh9YCq6IzPYJl0IFh8zINyZN7CHlHDwHCBqfpMiPNh9SlC3QBH
	WB+MZ9+RQz7Pv0Gj+6U0VBvZUnYvbH0Vd2R7HABOgXuRPTlE0N9GSh86OS39hFu2kzYR+zGpmfy
	Js2GMd0UzNsZgwMHmkD3lZ/iT7WDDw==
X-Received: by 2002:a5d:5d0a:0:b0:426:ff46:93b8 with SMTP id
 ffacd0b85a97d-42704d8444amr14973841f8f.8.1761268805783; Thu, 23 Oct 2025
 18:20:05 -0700 (PDT)
MIME-Version: 1.0
References: <20251023131600.1103431-1-harry.yoo@oracle.com>
In-Reply-To: <20251023131600.1103431-1-harry.yoo@oracle.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 24 Oct 2025 03:19:54 +0200
X-Gm-Features: AWmQ_bn7k-8N3nBX8QuM-JrNgQDPCvNlJAZ7mTQNODGDz59t7Iwz4Fszp2T7gmY
Message-ID: <CA+fCnZfJjXez_bq-jnmPTP40tPuq9XUc3Z2MtSgU7TnPz0bWyQ@mail.gmail.com>
Subject: Re: [PATCH] mm/slab: ensure all metadata in slab object are word-aligned
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, David Rientjes <rientjes@google.com>, 
	Alexander Potapenko <glider@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Feng Tang <feng.79.tang@gmail.com>, 
	Christoph Lameter <cl@gentwo.org>, Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cm3TSU3P;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a
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

On Thu, Oct 23, 2025 at 3:16=E2=80=AFPM Harry Yoo <harry.yoo@oracle.com> wr=
ote:
>
> When the SLAB_STORE_USER debug flag is used, any metadata placed after
> the original kmalloc request size (orig_size) is not properly aligned
> on 64-bit architectures because its type is unsigned int. When both KASAN
> and SLAB_STORE_USER are enabled, kasan_alloc_meta is misaligned.
>
> Because not all architectures support unaligned memory accesses,
> ensure that all metadata (track, orig_size, kasan_{alloc,free}_meta)
> in a slab object are word-aligned. struct track, kasan_{alloc,free}_meta
> are aligned by adding __aligned(sizeof(unsigned long)).
>
> For orig_size, use ALIGN(sizeof(unsigned int), sizeof(unsigned long)) to
> make clear that its size remains unsigned int but it must be aligned to
> a word boundary. On 64-bit architectures, this reserves 8 bytes for
> orig_size, which is acceptable since kmalloc's original request size
> tracking is intended for debugging rather than production use.
>
> Cc: <stable@vger.kernel.org>
> Fixes: 6edf2576a6cc ("mm/slub: enable debugging memory wasting of kmalloc=
")
> Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
> ---
>  mm/kasan/kasan.h |  4 ++--
>  mm/slub.c        | 16 +++++++++++-----
>  2 files changed, 13 insertions(+), 7 deletions(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 129178be5e64..d4ea7ecc20c3 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -265,7 +265,7 @@ struct kasan_alloc_meta {
>         struct kasan_track alloc_track;
>         /* Free track is stored in kasan_free_meta. */
>         depot_stack_handle_t aux_stack[2];
> -};
> +} __aligned(sizeof(unsigned long));
>
>  struct qlist_node {
>         struct qlist_node *next;
> @@ -289,7 +289,7 @@ struct qlist_node {
>  struct kasan_free_meta {
>         struct qlist_node quarantine_link;
>         struct kasan_track free_track;
> -};
> +} __aligned(sizeof(unsigned long));
>
>  #endif /* CONFIG_KASAN_GENERIC */
>
> diff --git a/mm/slub.c b/mm/slub.c
> index a585d0ac45d4..b921f91723c2 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -344,7 +344,7 @@ struct track {
>         int cpu;                /* Was running on cpu */
>         int pid;                /* Pid context */
>         unsigned long when;     /* When did the operation occur */
> -};
> +} __aligned(sizeof(unsigned long));
>
>  enum track_item { TRACK_ALLOC, TRACK_FREE };
>
> @@ -1196,7 +1196,7 @@ static void print_trailer(struct kmem_cache *s, str=
uct slab *slab, u8 *p)
>                 off +=3D 2 * sizeof(struct track);
>
>         if (slub_debug_orig_size(s))
> -               off +=3D sizeof(unsigned int);
> +               off +=3D ALIGN(sizeof(unsigned int), sizeof(unsigned long=
));
>
>         off +=3D kasan_metadata_size(s, false);
>
> @@ -1392,7 +1392,8 @@ static int check_pad_bytes(struct kmem_cache *s, st=
ruct slab *slab, u8 *p)
>                 off +=3D 2 * sizeof(struct track);
>
>                 if (s->flags & SLAB_KMALLOC)
> -                       off +=3D sizeof(unsigned int);
> +                       off +=3D ALIGN(sizeof(unsigned int),
> +                                    sizeof(unsigned long));
>         }
>
>         off +=3D kasan_metadata_size(s, false);
> @@ -7820,9 +7821,14 @@ static int calculate_sizes(struct kmem_cache_args =
*args, struct kmem_cache *s)
>                  */
>                 size +=3D 2 * sizeof(struct track);
>
> -               /* Save the original kmalloc request size */
> +               /*
> +                * Save the original kmalloc request size.
> +                * Although the request size is an unsigned int,
> +                * make sure that is aligned to word boundary.
> +                */
>                 if (flags & SLAB_KMALLOC)
> -                       size +=3D sizeof(unsigned int);
> +                       size +=3D ALIGN(sizeof(unsigned int),
> +                                     sizeof(unsigned long));
>         }
>  #endif
>
> --
> 2.43.0
>

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfJjXez_bq-jnmPTP40tPuq9XUc3Z2MtSgU7TnPz0bWyQ%40mail.gmail.com.
