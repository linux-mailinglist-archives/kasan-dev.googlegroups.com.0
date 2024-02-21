Return-Path: <kasan-dev+bncBDW2JDUY5AORBSOD3GXAMGQEHN7W3MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1318D85E93A
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 21:49:14 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-411e53af2adsf11146375e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 12:49:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708548553; cv=pass;
        d=google.com; s=arc-20160816;
        b=NsJq9nZO/tMrWsdDMLM37kX8A5vSPwShQbqinygqjbM3W3FJBPjOW0Pryd53cp9BiN
         oCuTuKZ8XreqigfRhl5JssFrRLsduhrUXvbFIuBSRo0LAn8zEtKfDwkpD1eLw0sjoO+b
         TOg2vw+RrnpfUG82v6R/hWuXJokdGiNrvxkGrhYi/cEv6enkyQ8QqeZYW8t+iJp/TsyZ
         0sld6Wwguwl4XEfhZMnYMLtEESERGmW37a45/lqO5n043x0dLe3sfO2y+qH+UhdlhaqN
         w8A0JqFgSzKyGYuncoAXqwWHH/7Ij7xavw5NHLI+h849OQ7hdxtldMktkP9x6BZF4GiK
         qhJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Osm+qe3C/O8kokJdewkysyM2p5HadCO6gYc7lDd6vtA=;
        fh=OQaVU3omjdT/PMxvDMriUuLE8uMt6QD47obej5OhPgw=;
        b=bbBgaAEc/Ir7pq0SZURUYV9TaAcblaTOa5RZe52YPJFYpqy+HcPIuap/UuzLa3sd9D
         UE3cTz3D5Yd/kpSlrLLfKaeZlcM7qfa80vSr7GanFLTfHFCOcdf1PFrYJchVhKdKaZxg
         rN2LRthlAVAYVKYxqf0emtvpD0UPFl9Mem8exk2SzorCKTVQMBT2fJMaacGDwgaKhr1x
         vfQh9NMNzhownE0/vKGlJYbxBPezc1aC66rn0ZGCU9ZqgBV5/Lbf6eUlLzo31TQKFLYB
         SD9Di3h1AHuQAyIkdaM2pY0CnRVZkBOGRzUEyNtSDGHggMqCxPrYrLXqUj8eUQmipeHE
         cLgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kjOaDfUE;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708548553; x=1709153353; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Osm+qe3C/O8kokJdewkysyM2p5HadCO6gYc7lDd6vtA=;
        b=O4Ba2brYKUuRKBAZX6J88sDhBXHxxP5aMFqzFTVkcROHzIZ1k4pMhW0ADf+9CZe4JI
         37DPhBOF5r1igt/6qrlBoBxtiQKqcZ+v/AC6Xul7u50S+G4O3Vjsi9bfhSfpEqp9jClU
         +jIEUho3YubRqRRt4lVi2HN4zC7AJkp+C1N1AHe2g+pZDgF0m5D36rRsJvF7vEgcdrc7
         ctSvlNP4KlqjgmOpCBlvt94r7PtVpsmOwLlfBVKRpb6dD79uJow1Jx2RAO058Q+2wLgL
         wXjxriebZyCFIUpVkxLHwMGHqRHaS5IhCQFWOVEOowuAO0aRI1ofklsiacN5vARcJTe0
         9rZg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1708548553; x=1709153353; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Osm+qe3C/O8kokJdewkysyM2p5HadCO6gYc7lDd6vtA=;
        b=Ct2iqQ6sRmn99MU9S6iH+/qCcKOfcG7L/xsXrDx+WinM2oosf5Sb1RatL0EIrdz4yy
         TQNABkZ09VTEEBsOg3yxhFprIRNhDlD7G1+ESfi0eEd2tS36Vq1j05Mkl6FWOY22MskF
         3s0yFZgEUQbbNaaEjTvXhbjLIsSZXs33AIG17IkVyOed6rymnzt4KXEiQjnaMgeyUmVA
         fLR8FoDrs+aCovFWMyBUt7DXCkfv7ZV9LnJR7kR+WgLsFfH947xYAQ26YycQiW77o2wO
         1ZxcIFupeMNapSO9R7JVKUP6v2Z9vA4dCPBkuyVdRE9yTpIfO97VxFTY9qoenABwRELC
         Ko2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708548553; x=1709153353;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Osm+qe3C/O8kokJdewkysyM2p5HadCO6gYc7lDd6vtA=;
        b=W6s+DanqKVvGBk5s74XGli6OfuyK8wG8Q5tt38I8GIiujvFtESJAcJ9+n6qDfX4qlq
         SuNGzVtEJMz95CLUGMKm2tJnFI+JXZlNXCiJ9Y/Z4y2Z30VlbuQa412lR3KV31Iqlcpi
         iXBbwq2KXxfujMMRfM7N50jjAYcXBxIlHXZah3Tcs9qTvNVhSnQ7ocp7+VxTSmFyk4jC
         nVpEg+rJzQ1iRyxHyydJ0oW0M67vM/jO7dxf5bHpzDHvwWiOuOjLVqnIhlzZj09pFOF1
         TmsrrWE18Vv2Njco2kCO3cz+HoQvL2q6CB9Ey2TlfHFqrxPTqkw7Cfyvc29rEp/JfpHd
         N9Nw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW3DbqENctZUsqY5dhEkehCNKOJKJZHDIIyKEIVbRaJUG6loS880D5FPw7P/6q2NA59xUo9jETJoFdpCtmi/JN1S0g70VC6tw==
X-Gm-Message-State: AOJu0Yz16IGhAouppG6x/bHgGYC0T5fXT0ZzTijBR90LT5nlSbZnrQo3
	tLo8RLUNFXjLpSoEMA0BZJK/z97k8/gdkSKOt0Oi2CnHGpAjsMBs
X-Google-Smtp-Source: AGHT+IEK1mVmVA1Sm02kxakNQTNVqkTs/nDAZ9b2NUoYa17qmVgrsCxb3nYcwdZEyDqVsSZ5eIaoPA==
X-Received: by 2002:a05:600c:3b94:b0:412:5f44:65b0 with SMTP id n20-20020a05600c3b9400b004125f4465b0mr8489757wms.4.1708548553395;
        Wed, 21 Feb 2024 12:49:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d90:b0:412:7920:38f with SMTP id
 p16-20020a05600c1d9000b004127920038fls320931wms.1.-pod-prod-08-eu; Wed, 21
 Feb 2024 12:49:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUbQ79qtPDMM5KhK/+LNRiyhb5KeUjuIsWHObjjr0la9b4FIQ6iBYPsAoSs4XnSjzP0rj2tVavasGO82abeUrLnnvJwCTZ9/git1g==
X-Received: by 2002:a05:600c:4513:b0:411:b1c7:3291 with SMTP id t19-20020a05600c451300b00411b1c73291mr14928199wmo.18.1708548551410;
        Wed, 21 Feb 2024 12:49:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708548551; cv=none;
        d=google.com; s=arc-20160816;
        b=dQDz8lwpi9KdjsxLbQaaQRaCZn2glSmb4Y/W3qymRiWxChSZuvKX5EKzqXShF3DoW7
         ju1+8O7RXfWpfW1JHQULIl02wPosNt6C5krRYd9R9yjQps14wdWEz5wTVZom3VJP5LIF
         cfK1jmo2lSRzdHb4Vg564+x/WAvT04WwOXWdQmlLdgF092aylaQf1jeRqiHuM33tZVjn
         vHTA5ULTJ3Y43+EI9oUPFgQJIR7ETiKWjEnEtwhIDX7P5mmbuo3dSJBdkOjRM0QohPT5
         jr29QrZgbJ+y1xe7f+g4T/qOp2Vy6HiYd1JKLeoYp36a4HVGAFe+kdidauxXl3z8MapI
         7g/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=SFWkqH9yqFlq6IROzTMH9jhnehwNcliel89qplM6at4=;
        fh=LLS739lcE0VfqKbAQcJJu41o9Sk8Wign9dgW8kp5fI4=;
        b=1EBexyd149KI/mxqWdCqS3gsx64n7Jw+9t2Z/BWlzT/BLoSvQ96AJyF5JDZ2kdpqHm
         Rxs8GkrrOFglhbCQ6Ne37hfv4I3gCxf8YWYQ3+MGF+YSXJMdRRUC3bDx49pPMfYQtTsz
         YU9AZynNYATLTxYliKJTHQ7lirQZ9MWwaJRq8f8SiCeo+2F6s8odjse/kw4OQwiLOfUu
         6z55QXGyhmtP7OOB2TTL+Vc7Fwz68+pH3qRO7HUuxDx9mPViba3zC1qT7KxEahDqYNjK
         9YFC8RFUA/VOSIhclI5X0ZY8ntRjGyAhQpz3vm6MguYBVdY44727oI8W52+Vjh+HdXhq
         Xzaw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kjOaDfUE;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id p1-20020a05600c1d8100b0040ff8f0e6acsi125236wms.0.2024.02.21.12.49.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 12:49:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-41278553215so6719365e9.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 12:49:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUZ1kdqBaXvjfu9FaZOaLBq7l6JqF6S+ZZaZgmBLkYl4SmfDY0b0TzwDTvbOFuybuSgH/SL7PVpcfYICj3cAlwuJiURJlveh/GYFg==
X-Received: by 2002:a05:600c:1f8b:b0:412:4a57:388f with SMTP id
 je11-20020a05600c1f8b00b004124a57388fmr10806274wmb.15.1708548550675; Wed, 21
 Feb 2024 12:49:10 -0800 (PST)
MIME-Version: 1.0
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz> <20240220-slab-cleanup-flags-v1-3-e657e373944a@suse.cz>
In-Reply-To: <20240220-slab-cleanup-flags-v1-3-e657e373944a@suse.cz>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 21 Feb 2024 21:48:59 +0100
Message-ID: <CA+fCnZcDf13ZgzUTUYSrEwEhGVT-8zTYLVJZ0UfONSnma8vodw@mail.gmail.com>
Subject: Re: [PATCH 3/3] mm, slab, kasan: replace kasan_never_merge() with SLAB_NO_MERGE
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Zheng Yejian <zhengyejian1@huawei.com>, 
	Xiongwei Song <xiongwei.song@windriver.com>, Chengming Zhou <chengming.zhou@linux.dev>, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=kjOaDfUE;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::334
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Feb 20, 2024 at 5:58=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> The SLAB_KASAN flag prevents merging of caches in some configurations,
> which is handled in a rather complicated way via kasan_never_merge().
> Since we now have a generic SLAB_NO_MERGE flag, we can instead use it
> for KASAN caches in addition to SLAB_KASAN in those configurations,
> and simplify the SLAB_NEVER_MERGE handling.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  include/linux/kasan.h |  6 ------
>  mm/kasan/generic.c    | 16 ++++------------
>  mm/slab_common.c      |  2 +-
>  3 files changed, 5 insertions(+), 19 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index dbb06d789e74..70d6a8f6e25d 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -429,7 +429,6 @@ struct kasan_cache {
>  };
>
>  size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object);
> -slab_flags_t kasan_never_merge(void);
>  void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>                         slab_flags_t *flags);
>
> @@ -446,11 +445,6 @@ static inline size_t kasan_metadata_size(struct kmem=
_cache *cache,
>  {
>         return 0;
>  }
> -/* And thus nothing prevents cache merging. */
> -static inline slab_flags_t kasan_never_merge(void)
> -{
> -       return 0;
> -}
>  /* And no cache-related metadata initialization is required. */
>  static inline void kasan_cache_create(struct kmem_cache *cache,
>                                       unsigned int *size,
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index df6627f62402..d8b78d273b9f 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -334,14 +334,6 @@ DEFINE_ASAN_SET_SHADOW(f3);
>  DEFINE_ASAN_SET_SHADOW(f5);
>  DEFINE_ASAN_SET_SHADOW(f8);
>
> -/* Only allow cache merging when no per-object metadata is present. */
> -slab_flags_t kasan_never_merge(void)
> -{
> -       if (!kasan_requires_meta())
> -               return 0;
> -       return SLAB_KASAN;
> -}
> -
>  /*
>   * Adaptive redzone policy taken from the userspace AddressSanitizer run=
time.
>   * For larger allocations larger redzones are used.
> @@ -372,13 +364,13 @@ void kasan_cache_create(struct kmem_cache *cache, u=
nsigned int *size,
>         /*
>          * SLAB_KASAN is used to mark caches that are sanitized by KASAN
>          * and that thus have per-object metadata.
> -        * Currently this flag is used in two places:
> +        * Currently this flag is used in one place:
>          * 1. In slab_ksize() to account for per-object metadata when
>          *    calculating the size of the accessible memory within the ob=
ject.
> -        * 2. In slab_common.c via kasan_never_merge() to prevent merging=
 of
> -        *    caches with per-object metadata.

Let's reword this to:

SLAB_KASAN is used to mark caches that are sanitized by KASAN and that
thus have per-object metadata. Currently, this flag is used in
slab_ksize() to account for per-object metadata when calculating the
size of the accessible memory within the object.

> +        * Additionally, we use SLAB_NO_MERGE to prevent merging of cache=
s
> +        * with per-object metadata.
>          */
> -       *flags |=3D SLAB_KASAN;
> +       *flags |=3D SLAB_KASAN | SLAB_NO_MERGE;
>
>         ok_size =3D *size;
>
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 238293b1dbe1..7cfa2f1ce655 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -50,7 +50,7 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
>   */
>  #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER =
| \
>                 SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
> -               SLAB_FAILSLAB | SLAB_NO_MERGE | kasan_never_merge())
> +               SLAB_FAILSLAB | SLAB_NO_MERGE)
>
>  #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
>                          SLAB_CACHE_DMA32 | SLAB_ACCOUNT)
>
> --
> 2.43.1
>

Otherwise, looks good to me.

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcDf13ZgzUTUYSrEwEhGVT-8zTYLVJZ0UfONSnma8vodw%40mail.gmai=
l.com.
