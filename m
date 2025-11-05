Return-Path: <kasan-dev+bncBDW2JDUY5AORBIGJVLEAMGQEXMUKLNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 47C3AC3399C
	for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 02:13:06 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-35f62a3c170sf35059031fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Nov 2025 17:13:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762305185; cv=pass;
        d=google.com; s=arc-20240605;
        b=X8nQ3n4ri+Hd6X+QOrJlREGLG4ehd2OVmFwp6Tc9RBHK3NE1/5Nns8xsbfgws7+na+
         I/oPohbyKQDABE24Dqr9k650I8rF4JTQL4MTG29iDK75KSf18ZsKxGaDqoetmgqdi3f8
         1ihf0HhlWS3buULlOYqG2B6M5TmKrjTSXVdAsnjMwFovj4YS7G/eYr2Dw68Rv4nVvqFU
         4QJO0HaqetJ/4nTYKU3mEToPzP9gVj/0abpNgCgagw9xPNu3BJhYQR2y3cbITd2XlxXi
         lKoiumHi2CUphEwzsqYvF10CcVuijk85Us27S2CYSYj3n0iJ7CjrtnMWu+uKktJPeKtb
         TaOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Ub8jOaoM5XJO5JxXLLBWq9ZUqZoFiKAlrhqYcGKT5q8=;
        fh=3PPpVEDSbjSkuFszry7ERfWnASLBt6Mi/2L6PjsVMPY=;
        b=OzdrIIUCKj0Cr9IOPtWmFjWgjfLFl2tTIR+8jyuF6f+VA3eVxWkeHnJE7Iwa8VbiZL
         YyoZOMp6OI+6bRddoE9anbgePesiKpxUPiQ1KBJz2t/e7jebiaGTsMPr8O9dcOZfSKrM
         yvr3O+acU+QajsMJ80kapyj5wrw3ZfYxaWfyfPjJJ4v6UGAVUb8KvaXT468KXcU+Cr2W
         Wn03/NXDD1fegEkV++Zvxev+Qc9JzvFptXiLQHuJTJDGld3PXaGYzS/0u0w/EEAQ/utG
         xCXO6wZPt02pP+pZV8fc88pzHmMoQP+2lFLvuKzmo5k1L8gZabuu4EPvMiNzYszDq4iE
         prQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZOZ+JaqQ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762305185; x=1762909985; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Ub8jOaoM5XJO5JxXLLBWq9ZUqZoFiKAlrhqYcGKT5q8=;
        b=frV/M0RN+F9SQXUvKu2e3UgfzcgAFkK6W/SYU+YG37s/fZ8rPRAAaxBx6LlsNd37YZ
         HFILe6yjCIlQW8ffdgFkElUPBscMa0ZotsnZpZNvIpXKrMBhz29Vk73kR51p45Dy0tUa
         dqOeisJDE9cLsT2ne2yQc8804123/+H++kc32nu8RYIn8FXZGpt4s9IFV3PUemKFi3Tt
         Y7UM6za9+cUZqh8d1R+hoUSSDUSV7Lk3LlUtcD0GbdzsXtWHn2cOAkKseH+6e7TdShYJ
         K7T9xqp8ZTvz59t6YXFbMmsPiCiRBJbUszWDP90b2s85Cv0B3GP5eXBRmIAKnYko1Fxx
         ONcw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762305185; x=1762909985; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ub8jOaoM5XJO5JxXLLBWq9ZUqZoFiKAlrhqYcGKT5q8=;
        b=HWiDqzHRr2muHJhmI//nZYGGgoY1QmLiKegE13g/nI9HPGEI71Rr8ziOGatq3geO81
         Kf/DJqYD/TbinuTxTATn3Q2ztshDVN6iJVRzf7UGxZkak48dPRL9LjEfTepCiPG79IUl
         EHE2Ipn+h12T2eTwLA55jywMehxMCoXJ9pKNJUCqUd/xAkc6BQkR/Ccgw6P4f1GU9M68
         f+3e92Q9AEVD+YrYJ3Z9bdV7H89v1K6QYzxMGLU5cowZ5iInIze65RNJA0/zWD4s5CdN
         DsA2aRHcbstj1+SzbfXCQDudJBRl2DVOQ1q7lII0JZVjxAUWydNI3uISlnNXl+g/wwQ5
         fnBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762305185; x=1762909985;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ub8jOaoM5XJO5JxXLLBWq9ZUqZoFiKAlrhqYcGKT5q8=;
        b=OHZTCi8ZBpU0yDVV2H8tgnuOZGJPzxtXDsQlYDbQtKOVZAR8a+EZQjFJ15FAN7RjSA
         EgruaH7uYj3WvLJPHvAwLN4bxNsxN49BCbOtpxwNHwxOPRrLplAr5GM99zj9fBRY0iPs
         o3PWm8G0km05Sz9qzVjQCZQdizx/MciFPRwhd5uFXVPQfqtyLyaSdmjhe2YFCWTWkX4a
         +ZkcSSpYeWQULOkrWoboybhy6sXnp0tH97kHsrXipJbHdhIxQrMsSkvO4cliJ2Y3tLOe
         AxVE34BxXjsNgcFsibnvvS6luxm+yafvb/c4CD1OcimkIVZfdwad8xMXW9oqg2HnuTUO
         GynQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVb2nA7cqW2O/kq9dHI8qmqtYDxl3FyKOrvHLbGJe4T6ZXYxQsK4sZxvGprKk0oEaTpmyO87Q==@lfdr.de
X-Gm-Message-State: AOJu0YwTDj3f5289Vm4B80QLEDTeQCNOXnKaUmTTgsgXpfyuivggkrzf
	Qd4MkJ+SN213XfvpEPBG44XVIHyxh7rlc47Hax2IUjODOk66+/Odr8tz
X-Google-Smtp-Source: AGHT+IF/jqfHpreKpsXrXWDNDupECE2DPfEpCBkkawAhqNm4b9ZpmbN7SdrZIzx3H2MKCOG9+4VH0w==
X-Received: by 2002:a2e:82c3:0:b0:37a:2bb3:7f5e with SMTP id 38308e7fff4ca-37a51477fecmr2985951fa.28.1762305184943;
        Tue, 04 Nov 2025 17:13:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+blCzKiWyq/Q0mGiWKPcbte0QjtP3uMCCKotzmqx4rt9g=="
Received: by 2002:a05:651c:2354:10b0:336:aebe:27fd with SMTP id
 38308e7fff4ca-37a10a63dacls10333191fa.2.-pod-prod-09-eu; Tue, 04 Nov 2025
 17:13:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVA0hx+xLekesmWoKizQbYfu6ZCMgs02HeL+bUoXRYOT6vfRbSwNnkSi9c+hb7xieRnZo1wDwdXrtk=@googlegroups.com
X-Received: by 2002:a05:6512:61b3:b0:594:2d3a:ac3a with SMTP id 2adb3069b0e04-5943d7da333mr345685e87.50.1762305181610;
        Tue, 04 Nov 2025 17:13:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762305181; cv=none;
        d=google.com; s=arc-20240605;
        b=S7PL/9utpa1w0fI+jQ4bpCQzHb5I6qUbODTRU5hvO3KghKsEZH7mhxIv1mdIK1J1RJ
         DWe7hTEodoUfrFVigkKABF2cCdhScY5OOGexin8HaSU7/G+EZPZoo1Aa4i6JgJOul4nX
         U3kh8xqYqwxXO032OiCcd5A2rEVPkxmdMmLcU02d7YB9gV64lgHFi7xRBK0s0DVNpZ5I
         mlnJa03HS1aapkqEdXg5GkHGqTrdX1wBsAwbPeu7YDYWWdEM09odaEMtGIiZHZR/SPt6
         HiIj4Usojb3LCm1OZwn8AoUZ+9csDOJMRadyI0ylUwQMoCugUEPMk13dM0PQw0k9dPh0
         CqyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=EEppFMrKLaYig4LQcDZc9JttD0i9i7R12SVoQFz4438=;
        fh=Gzjs31Zp2nXcG+lPLsJuL3RiUsJ8pW1OEWOush8z0AM=;
        b=iNuCvFTj38UgT87RPx5eJk6TleH8KRjNUus5TPbBoSXlMGDt0Pj0kxSiN6pQOz/ZsJ
         MaWmpILr1LZ2F1a6lzGE90KhohRmuk0AoWNKE/1nmunnm2d1eGx/bt3xVO3cdvsuDKxe
         8ml1/5Pq0aptrFlaVb+qPwCc+UR3lyTYJD4MAoQInpT/Y9cix/68658xZvz9MacSVADP
         AkCj+fzfwHPmRem8Owff9fzMNVE6AbJDu60UA973KOetlGxZ6qBetaK/0Mos3AgOtXK/
         +xTcsuoZ7iPAbymbO8GIM352J3TatCHuguGQhksmSJrrzmvT4rZR2B8+XxC5S+nWeHjI
         17zg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZOZ+JaqQ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5943437edc6si69837e87.2.2025.11.04.17.13.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Nov 2025 17:13:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id ffacd0b85a97d-429c19b5de4so1034136f8f.3
        for <kasan-dev@googlegroups.com>; Tue, 04 Nov 2025 17:13:01 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV3qTNEAKJ3I3YBAoh0nlO0DgX+kxoJXqq5cjPNkPVsijUp45n2xKq6gy4CvSuLjHSxiSq0cZvPMgs=@googlegroups.com
X-Gm-Gg: ASbGncsu6wkKHl2BoHfdrW+6lprtJD3Pt/o1aE1NIE4jIHXAjNlle8i/3ZQ5eZRDnJe
	wpqCx2q19O/7gbv4/4hMwnPsEPv11YPOtsiSyHwDms2sx7IECv12CdE6u1EnoFoXFzY20zHsNgc
	sGxjOUUoaqj0Zp7a/cE2HDRAYdjAs2/PO7EhQiJnrI7T9OCPnMXuxxqLcCA362R3Vp35Eor+GXv
	bQXhMQC1nbmIgyhrx6fnh5DGM1ggGpnnn6CPQn47vq3DsHDEVSL13Ria8rq/50sMViKydjoSNxA
	Wi9bgT79sj/5ZuAShQE=
X-Received: by 2002:a05:6000:310a:b0:425:76e3:81c5 with SMTP id
 ffacd0b85a97d-429e32e9294mr950863f8f.17.1762305180706; Tue, 04 Nov 2025
 17:13:00 -0800 (PST)
MIME-Version: 1.0
References: <cover.1762267022.git.m.wieczorretman@pm.me> <821677dd824d003cc5b7a77891db4723e23518ea.1762267022.git.m.wieczorretman@pm.me>
In-Reply-To: <821677dd824d003cc5b7a77891db4723e23518ea.1762267022.git.m.wieczorretman@pm.me>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 5 Nov 2025 02:12:49 +0100
X-Gm-Features: AWmQ_bnQFmPxXQdMPzkfEOvXBlnPN2_-SgGdaVU5DLbX3hNjDp0f9mJkSXaOTEE
Message-ID: <CA+fCnZefD8F7rMu3-M4uDTbWR5R8y7qfLzjrB34sK3bz4di03g@mail.gmail.com>
Subject: Re: [PATCH v1 1/2] kasan: Unpoison pcpu chunks with base address tag
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	Marco Elver <elver@google.com>, stable@vger.kernel.org, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, Baoquan He <bhe@redhat.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZOZ+JaqQ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d
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

On Tue, Nov 4, 2025 at 3:49=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
> A KASAN tag mismatch, possibly causing a kernel panic, can be observed
> on systems with a tag-based KASAN enabled and with multiple NUMA nodes.
> It was reported on arm64 and reproduced on x86. It can be explained in
> the following points:
>
>         1. There can be more than one virtual memory chunk.
>         2. Chunk's base address has a tag.
>         3. The base address points at the first chunk and thus inherits
>            the tag of the first chunk.
>         4. The subsequent chunks will be accessed with the tag from the
>            first chunk.
>         5. Thus, the subsequent chunks need to have their tag set to
>            match that of the first chunk.
>
> Refactor code by moving it into a helper in preparation for the actual
> fix.
>
> Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
> Cc: <stable@vger.kernel.org> # 6.1+
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> Tested-by: Baoquan He <bhe@redhat.com>
> ---
> Changelog v1 (after splitting of from the KASAN series):
> - Rewrite first paragraph of the patch message to point at the user
>   impact of the issue.
> - Move helper to common.c so it can be compiled in all KASAN modes.
>
>  include/linux/kasan.h | 10 ++++++++++
>  mm/kasan/common.c     | 11 +++++++++++
>  mm/vmalloc.c          |  4 +---
>  3 files changed, 22 insertions(+), 3 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index d12e1a5f5a9a..b00849ea8ffd 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -614,6 +614,13 @@ static __always_inline void kasan_poison_vmalloc(con=
st void *start,
>                 __kasan_poison_vmalloc(start, size);
>  }
>
> +void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms);
> +static __always_inline void kasan_unpoison_vmap_areas(struct vm_struct *=
*vms, int nr_vms)
> +{
> +       if (kasan_enabled())
> +               __kasan_unpoison_vmap_areas(vms, nr_vms);
> +}
> +
>  #else /* CONFIG_KASAN_VMALLOC */
>
>  static inline void kasan_populate_early_vm_area_shadow(void *start,
> @@ -638,6 +645,9 @@ static inline void *kasan_unpoison_vmalloc(const void=
 *start,
>  static inline void kasan_poison_vmalloc(const void *start, unsigned long=
 size)
>  { }
>
> +static inline void kasan_unpoison_vmap_areas(struct vm_struct **vms, int=
 nr_vms)
> +{ }
> +
>  #endif /* CONFIG_KASAN_VMALLOC */
>
>  #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && =
\
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index d4c14359feaf..c63544a98c24 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -28,6 +28,7 @@
>  #include <linux/string.h>
>  #include <linux/types.h>
>  #include <linux/bug.h>
> +#include <linux/vmalloc.h>
>
>  #include "kasan.h"
>  #include "../slab.h"
> @@ -582,3 +583,13 @@ bool __kasan_check_byte(const void *address, unsigne=
d long ip)
>         }
>         return true;
>  }
> +
> +void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
> +{
> +       int area;
> +
> +       for (area =3D 0 ; area < nr_vms ; area++) {
> +               kasan_poison(vms[area]->addr, vms[area]->size,
> +                            arch_kasan_get_tag(vms[area]->addr), false);

The patch description says this patch is a refactoring, but the patch
changes the logic of the code.

We don't call __kasan_unpoison_vmalloc() anymore and don't perform all
the related checks. This might be OK, assuming the checks always
succeed/fail, but this needs to be explained (note that there two
versions of __kasan_unpoison_vmalloc() with different checks).

And also we don't assign a random tag anymore - we should.

Also, you can just use get/set_tag(), no need to use the arch_ version
(and in the following patch too).





> +       }
> +}
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 798b2ed21e46..934c8bfbcebf 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -4870,9 +4870,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned=
 long *offsets,
>          * With hardware tag-based KASAN, marking is skipped for
>          * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
>          */
> -       for (area =3D 0; area < nr_vms; area++)
> -               vms[area]->addr =3D kasan_unpoison_vmalloc(vms[area]->add=
r,
> -                               vms[area]->size, KASAN_VMALLOC_PROT_NORMA=
L);
> +       kasan_unpoison_vmap_areas(vms, nr_vms);
>
>         kfree(vas);
>         return vms;
> --
> 2.51.0
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZefD8F7rMu3-M4uDTbWR5R8y7qfLzjrB34sK3bz4di03g%40mail.gmail.com.
