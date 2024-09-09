Return-Path: <kasan-dev+bncBDW2JDUY5AORBQ6C7S3AMGQE5UWY6MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9314C971F11
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Sep 2024 18:24:37 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-5356d0f6cdcsf4137000e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Sep 2024 09:24:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725899077; cv=pass;
        d=google.com; s=arc-20240605;
        b=WlRNbELzPD/SQkl01fHpRV+LJvvDA5PhPi0M3JCsLmfAFXgZe87z+kuRaei3o9sZB9
         rv3tVdfvB0P1gJ0+juqYnaZ9N+2UyeRMEyeNOHRKxnN/yMftKqMie1/1AGVqIT4zyFHx
         A4RHqyQu+ZnK83uxbt+w0RivBHO7c2ZP6okOUJmqUvhzXLjcc/64Vt7gsgjkkgxEZ7HO
         Y8+n1wNVx22qM4+QQPvHj1mxNOHl1gHBGsxTe5sDwkaTRv7wrEds9a+J0MIfetvpPSix
         U85J6AnD4eIuI+w2Cuz9vdd/d0jD12f6VNreOScB790Rd8WBw8dqpG84CIlx7yBpBKcI
         +Swg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=qsTaqymX6BdxiC1QyRpCzusTYvIsyFHx925a8CrA4iQ=;
        fh=bNtC63ZuEoM1YZZrOaOXFwWUm1AhvE3iMjIh5YJ9qEw=;
        b=bJqI+Zcicv4jfhJzsitDEKaTsPM0Gton9OdiZDqUdIaBzbIi8bne2pQvHFww9aIca/
         fT0EJKqnbbYZB0ltKD8y5vFXXUs0VI2rNjjoeUX54ahxK7yyqRsiD+PkpLDHcz58hs3u
         xmQqUY4cxJzGw0+TO5O3W9if6WKgpteKBSX7mGwhR3R488NGK5PckXCpl0XtHG/LYyck
         CDrDx8H02Dk92y57Yy9CDn0Cn1CMRmEtj1Wsth65hVtwJQs2dGLCLsBHxMxgkmjpRaHR
         Gy9L6iMJzDet8MtQ2lFOqJPmiLrayN/iRGdWP7Tjx+B2JDTbQ6QZTfe2Lal28yWjIj2x
         S+qQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ijoFx6zx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725899077; x=1726503877; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qsTaqymX6BdxiC1QyRpCzusTYvIsyFHx925a8CrA4iQ=;
        b=aV8HHd/BGf0lYQxgL7qxi9oqJmnrIr2ho0Olkz+8ChrsdxlGOAwO+KrrrLyTSjmYK0
         cqqoaKFpFGS2fhp9y5JA5dRIdhRjGw9iMK98PwkAQE+F9t8WVsAoj0bXrEXBmexGtlvW
         n85yppLLWz9QZuW2U3b971YKTvkoDCRAG8GWTl807QYElSKVYvvYn6MZokQf9/p9G4pE
         23q3ZBTjlDF9sT02FRkatgAWapBW9I7ghRcSLUC+bts5TQ/3gGkku0bZR+3aqDK0f5VP
         GasWCl5rpTJt9xLRBMX3NPWXeb91LFT1V3FfK4zQvPoqwOoz9pdAgg43jWo6snBUYuyy
         g2iw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1725899077; x=1726503877; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qsTaqymX6BdxiC1QyRpCzusTYvIsyFHx925a8CrA4iQ=;
        b=ZGLMNnjRKY8S+aFxmI/zDAuIL8ucno2x1kYlsWuF4rminyTQbfi7K8DtQC7DMztxw0
         Wr26CyM1O0WErnnrQmKnlmzS4jSoL1ZNz/4HQG56bFNn0rpLX1jt+6y1BfHQbGaOEpOu
         KmWpTIGvz8Ky2oOL0ufKKCQvEkVwIJ9xsVUbD8eWGIe1ugvGlAvBwMBZJW8TnTBfR+UA
         5Qf/YB+PPVRdh1hNRs5LvqpHfMiQkPGObBbHm2eMm9RqsZQ+C+YqpK/dxyYXn5+OmXKv
         K4FA5S2PiMxMIXpCXjgvfFPeSY4ZBDMu32hz6fLVDC/SP5PXuFxfHbA6pHWQ5TL11CuG
         0pXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725899077; x=1726503877;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qsTaqymX6BdxiC1QyRpCzusTYvIsyFHx925a8CrA4iQ=;
        b=PHTC8OhKJeEo7y4win1m0MuCd49LGcZcU1ibXFXwpvsQzNBXKO5+2E/s2Po3MseH+G
         PLbmMIroUmHCT+1TLeGEqDbTkrGV0KD2ClqKMFLPCrxxU6i+DgWpuwXYB7AxVSqWzRqw
         K1LrjGNCWNvOLG6QRxAc0PcMkCwQy4XHUWQi0+M9HI6LZ95U+T3CwWoWdQeEOHMi7cwF
         UJi4Ted7eG/VV+kNTGEMerB69XlcOpePfwzp//Y92z2GB++LBuUoD7Uib3vDJbbN7epL
         fJ+Vv1OgaZ02EAqpRYnTKiWPf1qHw0c+enPSvhfAIUGkkT+54ZGUEar4GMDrezvatk1/
         NfEA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWy3KRq2Sqpk9fqW7wbSsQGJisUx17Voot98BUX74R3ECmyAzJndr9VhCHF0TsPg7b4lXmtmg==@lfdr.de
X-Gm-Message-State: AOJu0YxHh9i6KAKVYMhfS5M31wPykxNdxTjLamt3Tjx6y3YsuXs3poQT
	vyvRo6v7F/M27vf21ZAWiDqS4GSpvtVnSzRNgepm+bofCArTvk1l
X-Google-Smtp-Source: AGHT+IEsBvfU4fmqvYcle3b888swxMJoAVQK5CTURY6nmGUbQ34ajs8ZHv/F3yN65R97S8vKeZf1BA==
X-Received: by 2002:a05:6512:3d89:b0:52e:933f:f1fa with SMTP id 2adb3069b0e04-53658818d02mr7962254e87.61.1725899075724;
        Mon, 09 Sep 2024 09:24:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1392:b0:533:482f:afc3 with SMTP id
 2adb3069b0e04-536572fe2e0ls75935e87.0.-pod-prod-05-eu; Mon, 09 Sep 2024
 09:24:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXiisOGD7bYa+kfFiggeWuONjDTL563TBRAK41OK3KU1lSJMpPRfWwzpbbNHhr4pfWWI81lu0M+V5w=@googlegroups.com
X-Received: by 2002:a05:6512:3ca2:b0:533:45c9:67fe with SMTP id 2adb3069b0e04-5365880bbbemr11277002e87.48.1725899073612;
        Mon, 09 Sep 2024 09:24:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725899073; cv=none;
        d=google.com; s=arc-20240605;
        b=QjQ/CRgSCOuRti27THpeSlkEODQ75F0EIUYYNUjQLeIoDaidZapVKMnZgFT3PaHvQk
         4MsDW2ueCvgWs9KuCu07x8LWezxqitmdugv6WImKFHYdoEX3QrkZPs4QKI/P+fs2Aybm
         14XgWoWWrQNEX9s+R1fAfuZvkSLIpdMSp2gqkuIpsmijlx+Xxm0DIiy6unKSf2wc5Q4e
         1COU/aR2uZR8AAKg2cPPAbrAYBp/fePumE5h3PUrAanV37qYwbpviS7bFQeXXeysVmGX
         3OUVuSiZq/kQr33Bg9DD/bbXPmurqfr6ATNiTBoWCxdvRA4Yn8ZT30Gd50WeZnRFcll2
         HDMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=bTdPIISC7QCFQ1CliKh1ID7iwFPfjIWMG7u/QhygHqE=;
        fh=TR/8b8k/XX0HQ9CcMxWwCwQG+eLfO8zYFGRlm06Y/PI=;
        b=VyuKIpfRTqNfLlIIfnqWr4lkiy6nfiJ06MMT+S6V30BcT5GHhGP+ficXAHXc7oSIN2
         7bwRa9xvQmxkzymtZS6eK2Eic15QpzDJ2VdXVnsnkRFgmf+W0FE3l9hcP4krLmz2Ga7p
         kk5+JNhNX+Gxu8YHBmJkdh4pFVijii5ZQJ1amZosqiLDnDw9CI50Y2e10GxGJGNjVh5/
         5go1lYyaCgSbbYe5g6oA8x/aS/VqdvTlZRIC1a7hSDDEeLwLPq7/DUgcpIWNvvzfz98B
         qd3dUOxAZdlh7tEPQEYSlVkiC2+XoT6XTJCRO0s5Dz0XZAhU5qvGUK02Lmv7bXidqEEo
         GsTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ijoFx6zx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a8d25b59bc7si12320666b.1.2024.09.09.09.24.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Sep 2024 09:24:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id 5b1f17b1804b1-42cb6f3a5bcso15585765e9.2
        for <kasan-dev@googlegroups.com>; Mon, 09 Sep 2024 09:24:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVcqwttctB/A7i5fFYhjpHvui57iBJje/sMlzBh8vOg4gAAsJZQNuQTEvXGTQuxAQnADuzExERnSn4=@googlegroups.com
X-Received: by 2002:a05:600c:4753:b0:42b:ac3d:3abc with SMTP id
 5b1f17b1804b1-42c9f9e08famr102166945e9.24.1725899072151; Mon, 09 Sep 2024
 09:24:32 -0700 (PDT)
MIME-Version: 1.0
References: <20240909012958.913438-1-feng.tang@intel.com> <20240909012958.913438-2-feng.tang@intel.com>
In-Reply-To: <20240909012958.913438-2-feng.tang@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 9 Sep 2024 18:24:21 +0200
Message-ID: <CA+fCnZcqnsAFEHKcPDag60FR_UbpOQpJidF+wqgZzUZUe6MPVQ@mail.gmail.com>
Subject: Re: [PATCH 1/5] mm/kasan: Don't store metadata inside kmalloc object
 when slub_debug_orig_size is on
To: Feng Tang <feng.tang@intel.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Marco Elver <elver@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, David Gow <davidgow@google.com>, 
	Danilo Krummrich <dakr@kernel.org>, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ijoFx6zx;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32a
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

On Mon, Sep 9, 2024 at 3:30=E2=80=AFAM Feng Tang <feng.tang@intel.com> wrot=
e:
>
> For a kmalloc object, when both kasan and slub redzone sanity check
> are enabled, they could both manipulate its data space like storing
> kasan free meta data and setting up kmalloc redzone, and may affect
> accuracy of that object's 'orig_size'.
>
> As an accurate 'orig_size' will be needed by some function like
> krealloc() soon, save kasan's free meta data in slub's metadata area
> instead of inside object when 'orig_size' is enabled.
>
> This will make it easier to maintain/understand the code. Size wise,
> when these two options are both enabled, the slub meta data space is
> already huge, and this just slightly increase the overall size.
>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---
>  mm/kasan/generic.c |  5 ++++-
>  mm/slab.h          |  6 ++++++
>  mm/slub.c          | 17 -----------------
>  3 files changed, 10 insertions(+), 18 deletions(-)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 6310a180278b..cad376199d47 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -393,8 +393,11 @@ void kasan_cache_create(struct kmem_cache *cache, un=
signed int *size,
>          *    be touched after it was freed, or
>          * 2. Object has a constructor, which means it's expected to
>          *    retain its content until the next allocation.

Nit: ", or" above.

> +        * 3. It is from a kmalloc cache which enables the debug option
> +        *    to store original size.
>          */
> -       if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor) {
> +       if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor ||
> +            slub_debug_orig_size(cache)) {
>                 cache->kasan_info.free_meta_offset =3D *size;
>                 *size +=3D sizeof(struct kasan_free_meta);
>                 goto free_meta_added;
> diff --git a/mm/slab.h b/mm/slab.h
> index 90f95bda4571..7a0e9b34ba2a 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -689,6 +689,12 @@ void __kmem_obj_info(struct kmem_obj_info *kpp, void=
 *object, struct slab *slab)
>  void __check_heap_object(const void *ptr, unsigned long n,
>                          const struct slab *slab, bool to_user);
>
> +static inline bool slub_debug_orig_size(struct kmem_cache *s)
> +{
> +       return (kmem_cache_debug_flags(s, SLAB_STORE_USER) &&
> +                       (s->flags & SLAB_KMALLOC));
> +}
> +
>  #ifdef CONFIG_SLUB_DEBUG
>  void skip_orig_size_check(struct kmem_cache *s, const void *object);
>  #endif
> diff --git a/mm/slub.c b/mm/slub.c
> index 23761533329d..996a72fa6f62 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -230,12 +230,6 @@ static inline bool kmem_cache_debug(struct kmem_cach=
e *s)
>         return kmem_cache_debug_flags(s, SLAB_DEBUG_FLAGS);
>  }
>
> -static inline bool slub_debug_orig_size(struct kmem_cache *s)
> -{
> -       return (kmem_cache_debug_flags(s, SLAB_STORE_USER) &&
> -                       (s->flags & SLAB_KMALLOC));
> -}
> -
>  void *fixup_red_left(struct kmem_cache *s, void *p)
>  {
>         if (kmem_cache_debug_flags(s, SLAB_RED_ZONE))
> @@ -760,21 +754,10 @@ static inline void set_orig_size(struct kmem_cache =
*s,
>                                 void *object, unsigned int orig_size)
>  {
>         void *p =3D kasan_reset_tag(object);
> -       unsigned int kasan_meta_size;
>
>         if (!slub_debug_orig_size(s))
>                 return;
>
> -       /*
> -        * KASAN can save its free meta data inside of the object at offs=
et 0.
> -        * If this meta data size is larger than 'orig_size', it will ove=
rlap
> -        * the data redzone in [orig_size+1, object_size]. Thus, we adjus=
t
> -        * 'orig_size' to be as at least as big as KASAN's meta data.
> -        */
> -       kasan_meta_size =3D kasan_metadata_size(s, true);
> -       if (kasan_meta_size > orig_size)
> -               orig_size =3D kasan_meta_size;
> -
>         p +=3D get_info_end(s);
>         p +=3D sizeof(struct track) * 2;
>
> --
> 2.34.1
>

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcqnsAFEHKcPDag60FR_UbpOQpJidF%2BwqgZzUZUe6MPVQ%40mail.gm=
ail.com.
