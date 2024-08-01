Return-Path: <kasan-dev+bncBDW2JDUY5AORB5VKVO2QMGQE5MEYMJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 32674943B19
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Aug 2024 02:23:19 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-42809eb7b99sf8263595e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2024 17:23:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722471799; cv=pass;
        d=google.com; s=arc-20160816;
        b=S+cMoAVANtwSvd3jppAYzoflF3CN/qNDlvk6auhGf6UtNzbn1jJALt+FRLPv9/f/6G
         jz05YRd50JNcQS5cFGOSXa5GyR8PQhgTmZXh1R2HZBiyR0trCOx7xND7R5Z4EYihM6oW
         Ly9bv0IH4JWrM/CcjemBQ1k8d8rjyD9gy6GFZ4TvWm/EgwrqZJCtjZng1nsBnSxfIVtk
         +vCDWGEAzu/KQTGXEbDdTDKgGtsZLHSqb2MQI/EVjbFv+KuOw5Vu62x7unij+V0pxJaB
         meA7hpCsCjpapnj1EK6trpsHubsA6sQorS/2F62g8thkMYtMY8p24duhkiRX9jC++JXw
         VLKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=1rszz0BCNp6XT+6UkeO87e+l2kYM1InNtcXt1BpU99M=;
        fh=t46DM6TglSxrkBtdaubc+RfrXfsOVTilelbkdBQKN1A=;
        b=CY2PygeTrqlbS5ojbM9XdYNXWqVKyAb6E2noRIrIf4eFy0Wy9reeAtdtUlIWPFnaV1
         bSrkHog6YtwPdzwLz9V38Gb9/p2EYlxdIspeGodN9XHDTh61G38NrOQlx5J4xoyC5P/m
         rFf7UjFAHmFbBLy3SpSm7hjmGYzdzmNb7UGwgxK6OZeGkU+EnVgLCHlPTjJ+4xOBsHQH
         BlhE1GoaICKiWcU4psoGFMQb5G97STPU9cYOzr1GZSP1e7lhbmBlnRg4feFzpsVNPzHK
         jAOcdnMnhTqs25S8kyKMiMhIKLiDEPyzx3HmmqJ0+H0LVDGNT4NQ/QpH8hT9zOHmf5ar
         dQlg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TeUoIuSY;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722471799; x=1723076599; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1rszz0BCNp6XT+6UkeO87e+l2kYM1InNtcXt1BpU99M=;
        b=HbcTaGnFapDUeeYChkR/YozvRfnT4iFNIpSwAbuYFFXZUklaEQF0sXSY7pruXYgbTh
         MDEGI/hx/XzkXWKrz6trVtgsgrISqeLdhDXdCngmkRPLvhi+XMzvK7AztL2KYsVCh9QM
         ZJlFg/mUdf1se+f2TDC2hhQIiGzpjWTyaXEKctZgmLHk0g8wNm4YsNZyU/0Bi/Bp5vFf
         IYHc6+aGQ8Mtr3uUf0inyoX0wKEOAlsiJgw3R0gnWTDgQtl3vkviyAUf+euW8i9jm4Jj
         GFREMRhAnGPLZjzV52lTkSwYFxihujluMz6j8YC/FVty8nn8CRZssnv4I0TnjrYdXAsh
         alKg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722471799; x=1723076599; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1rszz0BCNp6XT+6UkeO87e+l2kYM1InNtcXt1BpU99M=;
        b=UAbCoz7WnsHkkZ2Kx3iaYXeg6tisX7jyW6/AthiojVYFqIpBG78CRc6mEmV1Qd4/n5
         mPqozesIOUIm24uh5FqTCRxcWpX0LS8ZZpBLrzWjP0ZsUKU/i1/nFKxiagi7cL5x3B7R
         YllbIF31b0DHhv3G62qj65xBxdRlBH+tWXsoG4kPNuBxGQ21lzuspixQU91+il8mokZW
         x24/AHSlW5XCn6zmxhb1wCq+P1IE6sYhRoVlY5jlT0Uouqye/32QBPss8QI7fP4DKwM7
         EcVnJBW0tCRjvK+DY5gl+URf2mEg/D9iskVcRLJ9Bwu0mkUEXON2RIeopOHYkMX0VJ1c
         WOjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722471799; x=1723076599;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1rszz0BCNp6XT+6UkeO87e+l2kYM1InNtcXt1BpU99M=;
        b=WcAv4rjNi29y+xH/jTVxYHYO42uMDAglKWVUn+SU08EykWQykGISI9iJhneEZxHYKG
         1g+BZFGLmz0JDnvjXvXzTWVagcgfXns3lCmw9yP2dIHa5MwJydcYLoTizdCeJoTi9Sre
         nSEtgHJ+Oi7E04HKQ5h4hcCJxtLGHvDIuxXe++5aDRHCMkJNLKQa09S/VnWu2xhoArT3
         HL3ibdoDJ/Rlq7K1fcc4gkrv3q6DCAsTowzvcShRYJiQI2nFDRedKIJbOJPEbEyKa286
         0T5KnwAN9ihH6PYd095OY/E8gTdp/0jPU5IizVBX3CHVa2TtXMEGm17AEqOAGjMiJudc
         2tNw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW15qbo2vKBC+GsqWhP/dl9eFVYPDgUVrdXN7oFpWkrZLscIR++0/ZObqrv6jCvgI0SGF7U2Q==@lfdr.de
X-Gm-Message-State: AOJu0YyNySSQYFN0iLMb4atlhylfN1/U3T765gjyCQ+RyGyblp4Gb9zV
	w6+MevJQEaVx+apWN9xgQavy39hv3CAs9cQzq40Ilmh20EcvAp7p
X-Google-Smtp-Source: AGHT+IGaxWfz8XSgQfhCk59Ys4jKRsxKyIwA0QKF7fsSfm/owAefgqAPwasAaKLen2T9L0zdSwE59Q==
X-Received: by 2002:a05:600c:4f54:b0:426:6eb6:1374 with SMTP id 5b1f17b1804b1-42824390747mr51651625e9.0.1722471798264;
        Wed, 31 Jul 2024 17:23:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5118:b0:428:9f15:7820 with SMTP id
 5b1f17b1804b1-4289f157de6ls1573795e9.0.-pod-prod-00-eu; Wed, 31 Jul 2024
 17:23:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUYKLgbKEKw9IUsPC2AppJNbo9ygsN7aQQO8OiQTlsseA22sZ4SCZNWaw+sLNpWKS+0nEd3bv8QTLU=@googlegroups.com
X-Received: by 2002:a05:600c:444e:b0:424:8dbe:817d with SMTP id 5b1f17b1804b1-42824403d2dmr54587465e9.10.1722471796357;
        Wed, 31 Jul 2024 17:23:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722471796; cv=none;
        d=google.com; s=arc-20160816;
        b=toCgJW48YjL7dXtT19ujJYA0/dvwoVJmDSlg7AZwqOdE01ncMVDNI+3mZEYdlgP53f
         GfnHQ2PGRHdaVnIKKH/HnqNv7RABQ6dUjc1dpJyMDT2jPcl35BrSVavlPo/Wgfqk0S98
         3s8hEKdzEYgZrVnyq+6XDazXgtO3Klui9Pc5MfsJLsMVEIGbxK3h26nwnb7CZYVCjkTJ
         +D0cXSdiu43sKCCOpyRxVYk4G2ydridHqYHVxS5U+jx+2C5LFP9DodXDBYGjN8/KBl2Z
         kzRAmu9ZDa9aXBINwbTNEzjXSHb1gTrkoLc5fbE0kBrAM1Dc+7jnUpz2QGvFSD2pKcYP
         UWPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+/OWgCrKT8FaN/NojJFZkZVtPfuI+fAkVxQk1yUAr8I=;
        fh=qv+eANdr8IS+fPcRKJXaVK5vqVtYtqhQN9c1uZhCZiA=;
        b=epjja/fPCQmiRSkbGpJcz2OTl1mUPIaVOlVxwU2XkhUGjO1Nsg6iXhxgyASHucXihb
         /XSjmWfPdCH7jjP3i7uQrtNNsAygEmtTzMHLJUqNMfLkwBAn5LXX2fiesXOT2f0fUDcO
         sLzvIPNRzm52Y1S9pqzaYwDKh6bcNcTPwNWAlxtAoX8AlhLv1ZXw+rjGfd+GCRAMTYbl
         +QxQqH3ZDmsCgI0Fho+eaLPfx5jGmT1l+2BB7Cl51KDR7JcsZf6vonWP1BJ02BcfrrXQ
         QApy9c5XLMFxflP+VovLrvbUoOlfMQDrwlADTEOZEUkVtnPgbhMoTJPD3Wa8DiL+S6yO
         5MEg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TeUoIuSY;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42824af684dsi3843235e9.1.2024.07.31.17.23.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Jul 2024 17:23:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 5b1f17b1804b1-428035c0bb2so8848805e9.1
        for <kasan-dev@googlegroups.com>; Wed, 31 Jul 2024 17:23:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXdOABu7tHy9QjOMYEVcd0qRBDn1bbUnRkplG+wXOdQUeQV5RfnSz09cVUVH5eV0E3ueXEGkxsVl2U=@googlegroups.com
X-Received: by 2002:a05:600c:4688:b0:426:698b:791f with SMTP id
 5b1f17b1804b1-428243e1dcemr46512705e9.3.1722471795367; Wed, 31 Jul 2024
 17:23:15 -0700 (PDT)
MIME-Version: 1.0
References: <20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com> <20240730-kasan-tsbrcu-v5-2-48d3cbdfccc5@google.com>
In-Reply-To: <20240730-kasan-tsbrcu-v5-2-48d3cbdfccc5@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 1 Aug 2024 02:23:04 +0200
Message-ID: <CA+fCnZeq8JGSkFwGitwSc3DbeuoXnoyvC7RgWh6XSG1CoWH=Zg@mail.gmail.com>
Subject: Re: [PATCH v5 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Jann Horn <jannh@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=TeUoIuSY;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f
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

On Tue, Jul 30, 2024 at 1:06=E2=80=AFPM Jann Horn <jannh@google.com> wrote:
>
> Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_RC=
U
> slabs because use-after-free is allowed within the RCU grace period by
> design.
>
> Add a SLUB debugging feature which RCU-delays every individual
> kmem_cache_free() before either actually freeing the object or handing it
> off to KASAN, and change KASAN to poison freed objects as normal when thi=
s
> option is enabled.
>
> For now I've configured Kconfig.debug to default-enable this feature in t=
he
> KASAN GENERIC and SW_TAGS modes; I'm not enabling it by default in HW_TAG=
S
> mode because I'm not sure if it might have unwanted performance degradati=
on
> effects there.
>
> Note that this is mostly useful with KASAN in the quarantine-based GENERI=
C
> mode; SLAB_TYPESAFE_BY_RCU slabs are basically always also slabs with a
> ->ctor, and KASAN's assign_tag() currently has to assign fixed tags for
> those, reducing the effectiveness of SW_TAGS/HW_TAGS mode.
> (A possible future extension of this work would be to also let SLUB call
> the ->ctor() on every allocation instead of only when the slab page is
> allocated; then tag-based modes would be able to assign new tags on every
> reallocation.)
>
> Signed-off-by: Jann Horn <jannh@google.com>

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

But see a comment below.

> ---
>  include/linux/kasan.h | 11 +++++---
>  mm/Kconfig.debug      | 30 ++++++++++++++++++++
>  mm/kasan/common.c     | 11 ++++----
>  mm/kasan/kasan_test.c | 46 +++++++++++++++++++++++++++++++
>  mm/slab_common.c      | 12 ++++++++
>  mm/slub.c             | 76 +++++++++++++++++++++++++++++++++++++++++++++=
------
>  6 files changed, 169 insertions(+), 17 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 34cb7a25aacb..0b952e11c7a0 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -194,28 +194,30 @@ static __always_inline bool kasan_slab_pre_free(str=
uct kmem_cache *s,
>  {
>         if (kasan_enabled())
>                 return __kasan_slab_pre_free(s, object, _RET_IP_);
>         return false;
>  }
>
> -bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init);
> +bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init,
> +                      bool after_rcu_delay);

What do you think about renaming this argument to poison_rcu? I think
it makes the intention more clear from the KASAN's point of view.

>  /**
>   * kasan_slab_free - Possibly handle slab object freeing.
>   * @object: Object to free.

@poison_rcu - Whether to skip poisoning for SLAB_TYPESAFE_BY_RCU caches.

And also update the reworded comment from the previous patch:

This function poisons a slab object and saves a free stack trace for
it, except for SLAB_TYPESAFE_BY_RCU caches when @poison_rcu is false.



>   *
>   * This hook is called from the slab allocator to give KASAN a chance to=
 take
>   * ownership of the object and handle its freeing.
>   * kasan_slab_pre_free() must have already been called on the same objec=
t.
>   *
>   * @Return true if KASAN took ownership of the object; false otherwise.
>   */
>  static __always_inline bool kasan_slab_free(struct kmem_cache *s,
> -                                               void *object, bool init)
> +                                               void *object, bool init,
> +                                               bool after_rcu_delay)
>  {
>         if (kasan_enabled())
> -               return __kasan_slab_free(s, object, init);
> +               return __kasan_slab_free(s, object, init, after_rcu_delay=
);
>         return false;
>  }
>
>  void __kasan_kfree_large(void *ptr, unsigned long ip);
>  static __always_inline void kasan_kfree_large(void *ptr)
>  {
> @@ -405,13 +407,14 @@ static inline void *kasan_init_slab_obj(struct kmem=
_cache *cache,
>
>  static inline bool kasan_slab_pre_free(struct kmem_cache *s, void *objec=
t)
>  {
>         return false;
>  }
>
> -static inline bool kasan_slab_free(struct kmem_cache *s, void *object, b=
ool init)
> +static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
> +                                  bool init, bool after_rcu_delay)
>  {
>         return false;
>  }
>  static inline void kasan_kfree_large(void *ptr) {}
>  static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
>                                    gfp_t flags, bool init)
> diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
> index afc72fde0f03..8e440214aac8 100644
> --- a/mm/Kconfig.debug
> +++ b/mm/Kconfig.debug
> @@ -67,12 +67,42 @@ config SLUB_DEBUG_ON
>           equivalent to specifying the "slab_debug" parameter on boot.
>           There is no support for more fine grained debug control like
>           possible with slab_debug=3Dxxx. SLUB debugging may be switched
>           off in a kernel built with CONFIG_SLUB_DEBUG_ON by specifying
>           "slab_debug=3D-".
>
> +config SLUB_RCU_DEBUG
> +       bool "Enable UAF detection in TYPESAFE_BY_RCU caches (for KASAN)"
> +       depends on SLUB_DEBUG
> +       depends on KASAN # not a real dependency; currently useless witho=
ut KASAN
> +       default KASAN_GENERIC || KASAN_SW_TAGS
> +       help
> +         Make SLAB_TYPESAFE_BY_RCU caches behave approximately as if the=
 cache
> +         was not marked as SLAB_TYPESAFE_BY_RCU and every caller used
> +         kfree_rcu() instead.
> +
> +         This is intended for use in combination with KASAN, to enable K=
ASAN to
> +         detect use-after-free accesses in such caches.
> +         (KFENCE is able to do that independent of this flag.)
> +
> +         This might degrade performance.
> +         Unfortunately this also prevents a very specific bug pattern fr=
om
> +         triggering (insufficient checks against an object being recycle=
d
> +         within the RCU grace period); so this option can be turned off =
even on
> +         KASAN builds, in case you want to test for such a bug.
> +
> +         If you're using this for testing bugs / fuzzing and care about
> +         catching all the bugs WAY more than performance, you might want=
 to
> +         also turn on CONFIG_RCU_STRICT_GRACE_PERIOD.
> +
> +         WARNING:
> +         This is designed as a debugging feature, not a security feature=
.
> +         Objects are sometimes recycled without RCU delay under memory p=
ressure.
> +
> +         If unsure, say N.
> +
>  config PAGE_OWNER
>         bool "Track page owner"
>         depends on DEBUG_KERNEL && STACKTRACE_SUPPORT
>         select DEBUG_FS
>         select STACKTRACE
>         select STACKDEPOT
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 8cede1ce00e1..0769b23a9d5f 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -227,43 +227,44 @@ static bool check_slab_allocation(struct kmem_cache=
 *cache, void *object,
>         }
>
>         return false;
>  }
>
>  static inline void poison_slab_object(struct kmem_cache *cache, void *ob=
ject,
> -                                     bool init)
> +                                     bool init, bool after_rcu_delay)
>  {
>         void *tagged_object =3D object;
>
>         object =3D kasan_reset_tag(object);
>
>         /* RCU slabs could be legally used after free within the RCU peri=
od. */
> -       if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
> +       if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_d=
elay)
>                 return;
>
>         kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_S=
IZE),
>                         KASAN_SLAB_FREE, init);
>
>         if (kasan_stack_collection_enabled())
>                 kasan_save_free_info(cache, tagged_object);
>  }
>
>  bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
>                                 unsigned long ip)
>  {
>         if (!kasan_arch_is_ready() || is_kfence_address(object))
>                 return false;
>         return check_slab_allocation(cache, object, ip);
>  }
>
> -bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init=
)
> +bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init=
,
> +                      bool after_rcu_delay)
>  {
>         if (!kasan_arch_is_ready() || is_kfence_address(object))
>                 return false;
>
> -       poison_slab_object(cache, object, init);
> +       poison_slab_object(cache, object, init, after_rcu_delay);
>
>         /*
>          * If the object is put into quarantine, do not let slab put the =
object
>          * onto the freelist for now. The object's metadata is kept until=
 the
>          * object gets evicted from quarantine.
>          */
> @@ -517,13 +518,13 @@ bool __kasan_mempool_poison_object(void *ptr, unsig=
ned long ip)
>
>         slab =3D folio_slab(folio);
>
>         if (check_slab_allocation(slab->slab_cache, ptr, ip))
>                 return false;
>
> -       poison_slab_object(slab->slab_cache, ptr, false);
> +       poison_slab_object(slab->slab_cache, ptr, false, false);
>         return true;
>  }
>
>  void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned lo=
ng ip)
>  {
>         struct slab *slab;
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 7b32be2a3cf0..567d33b493e2 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -993,12 +993,57 @@ static void kmem_cache_invalid_free(struct kunit *t=
est)
>          */
>         kmem_cache_free(cache, p);
>
>         kmem_cache_destroy(cache);
>  }
>
> +static void kmem_cache_rcu_uaf(struct kunit *test)
> +{
> +       char *p;
> +       size_t size =3D 200;
> +       struct kmem_cache *cache;
> +
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB_RCU_DEBUG);
> +
> +       cache =3D kmem_cache_create("test_cache", size, 0, SLAB_TYPESAFE_=
BY_RCU,
> +                                 NULL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> +
> +       p =3D kmem_cache_alloc(cache, GFP_KERNEL);
> +       if (!p) {
> +               kunit_err(test, "Allocation failed: %s\n", __func__);
> +               kmem_cache_destroy(cache);
> +               return;
> +       }
> +       *p =3D 1;
> +
> +       rcu_read_lock();
> +
> +       /* Free the object - this will internally schedule an RCU callbac=
k. */
> +       kmem_cache_free(cache, p);
> +
> +       /*
> +        * We should still be allowed to access the object at this point =
because
> +        * the cache is SLAB_TYPESAFE_BY_RCU and we've been in an RCU rea=
d-side
> +        * critical section since before the kmem_cache_free().
> +        */
> +       READ_ONCE(*p);
> +
> +       rcu_read_unlock();
> +
> +       /*
> +        * Wait for the RCU callback to execute; after this, the object s=
hould
> +        * have actually been freed from KASAN's perspective.
> +        */
> +       rcu_barrier();
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*p));
> +
> +       kmem_cache_destroy(cache);
> +}
> +
>  static void empty_cache_ctor(void *object) { }
>
>  static void kmem_cache_double_destroy(struct kunit *test)
>  {
>         struct kmem_cache *cache;
>
> @@ -1934,12 +1979,13 @@ static struct kunit_case kasan_kunit_test_cases[]=
 =3D {
>         KUNIT_CASE(workqueue_uaf),
>         KUNIT_CASE(kfree_via_page),
>         KUNIT_CASE(kfree_via_phys),
>         KUNIT_CASE(kmem_cache_oob),
>         KUNIT_CASE(kmem_cache_double_free),
>         KUNIT_CASE(kmem_cache_invalid_free),
> +       KUNIT_CASE(kmem_cache_rcu_uaf),
>         KUNIT_CASE(kmem_cache_double_destroy),
>         KUNIT_CASE(kmem_cache_accounted),
>         KUNIT_CASE(kmem_cache_bulk),
>         KUNIT_CASE(mempool_kmalloc_oob_right),
>         KUNIT_CASE(mempool_kmalloc_large_oob_right),
>         KUNIT_CASE(mempool_slab_oob_right),
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 40b582a014b8..df09066d56fe 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -539,12 +539,24 @@ static void slab_caches_to_rcu_destroy_workfn(struc=
t work_struct *work)
>                 kmem_cache_release(s);
>         }
>  }
>
>  static int shutdown_cache(struct kmem_cache *s)
>  {
> +       if (IS_ENABLED(CONFIG_SLUB_RCU_DEBUG) &&
> +           (s->flags & SLAB_TYPESAFE_BY_RCU)) {
> +               /*
> +                * Under CONFIG_SLUB_RCU_DEBUG, when objects in a
> +                * SLAB_TYPESAFE_BY_RCU slab are freed, SLUB will interna=
lly
> +                * defer their freeing with call_rcu().
> +                * Wait for such call_rcu() invocations here before actua=
lly
> +                * destroying the cache.
> +                */
> +               rcu_barrier();
> +       }
> +
>         /* free asan quarantined objects */
>         kasan_cache_shutdown(s);
>
>         if (__kmem_cache_shutdown(s) !=3D 0)
>                 return -EBUSY;
>
> diff --git a/mm/slub.c b/mm/slub.c
> index 0c98b6a2124f..f0d0e3c30837 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2197,45 +2197,78 @@ static inline bool memcg_slab_post_alloc_hook(str=
uct kmem_cache *s,
>  static inline void memcg_slab_free_hook(struct kmem_cache *s, struct sla=
b *slab,
>                                         void **p, int objects)
>  {
>  }
>  #endif /* CONFIG_MEMCG */
>
> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +static void slab_free_after_rcu_debug(struct rcu_head *rcu_head);
> +
> +struct rcu_delayed_free {
> +       struct rcu_head head;
> +       void *object;
> +};
> +#endif
> +
>  /*
>   * Hooks for other subsystems that check memory allocations. In a typica=
l
>   * production configuration these hooks all should produce no code at al=
l.
>   *
>   * Returns true if freeing of the object can proceed, false if its reuse
> - * was delayed by KASAN quarantine, or it was returned to KFENCE.
> + * was delayed by CONFIG_SLUB_RCU_DEBUG or KASAN quarantine, or it was r=
eturned
> + * to KFENCE.
>   */
>  static __always_inline
> -bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
> +bool slab_free_hook(struct kmem_cache *s, void *x, bool init,
> +                   bool after_rcu_delay)
>  {
>         kmemleak_free_recursive(x, s->flags);
>         kmsan_slab_free(s, x);
>
>         debug_check_no_locks_freed(x, s->object_size);
>
>         if (!(s->flags & SLAB_DEBUG_OBJECTS))
>                 debug_check_no_obj_freed(x, s->object_size);
>
>         /* Use KCSAN to help debug racy use-after-free. */
> -       if (!(s->flags & SLAB_TYPESAFE_BY_RCU))
> +       if (!(s->flags & SLAB_TYPESAFE_BY_RCU) || after_rcu_delay)
>                 __kcsan_check_access(x, s->object_size,
>                                      KCSAN_ACCESS_WRITE | KCSAN_ACCESS_AS=
SERT);
>
>         if (kfence_free(x))
>                 return false;
>
>         /*
>          * Give KASAN a chance to notice an invalid free operation before=
 we
>          * modify the object.
>          */
>         if (kasan_slab_pre_free(s, x))
>                 return false;
>
> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +       if ((s->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_delay) {
> +               struct rcu_delayed_free *delayed_free;
> +
> +               delayed_free =3D kmalloc(sizeof(*delayed_free), GFP_NOWAI=
T);
> +               if (delayed_free) {
> +                       /*
> +                        * Let KASAN track our call stack as a "related w=
ork
> +                        * creation", just like if the object had been fr=
eed
> +                        * normally via kfree_rcu().
> +                        * We have to do this manually because the rcu_he=
ad is
> +                        * not located inside the object.
> +                        */
> +                       kasan_record_aux_stack_noalloc(x);
> +
> +                       delayed_free->object =3D x;
> +                       call_rcu(&delayed_free->head, slab_free_after_rcu=
_debug);
> +                       return false;
> +               }
> +       }
> +#endif /* CONFIG_SLUB_RCU_DEBUG */
> +
>         /*
>          * As memory initialization might be integrated into KASAN,
>          * kasan_slab_free and initialization memset's must be
>          * kept together to avoid discrepancies in behavior.
>          *
>          * The initialization memset's clear the object and the metadata,
> @@ -2253,42 +2286,42 @@ bool slab_free_hook(struct kmem_cache *s, void *x=
, bool init)
>                         memset(kasan_reset_tag(x), 0, s->object_size);
>                 rsize =3D (s->flags & SLAB_RED_ZONE) ? s->red_left_pad : =
0;
>                 memset((char *)kasan_reset_tag(x) + inuse, 0,
>                        s->size - inuse - rsize);
>         }
>         /* KASAN might put x into memory quarantine, delaying its reuse. =
*/
> -       return !kasan_slab_free(s, x, init);
> +       return !kasan_slab_free(s, x, init, after_rcu_delay);
>  }
>
>  static __fastpath_inline
>  bool slab_free_freelist_hook(struct kmem_cache *s, void **head, void **t=
ail,
>                              int *cnt)
>  {
>
>         void *object;
>         void *next =3D *head;
>         void *old_tail =3D *tail;
>         bool init;
>
>         if (is_kfence_address(next)) {
> -               slab_free_hook(s, next, false);
> +               slab_free_hook(s, next, false, false);
>                 return false;
>         }
>
>         /* Head and tail of the reconstructed freelist */
>         *head =3D NULL;
>         *tail =3D NULL;
>
>         init =3D slab_want_init_on_free(s);
>
>         do {
>                 object =3D next;
>                 next =3D get_freepointer(s, object);
>
>                 /* If object's reuse doesn't have to be delayed */
> -               if (likely(slab_free_hook(s, object, init))) {
> +               if (likely(slab_free_hook(s, object, init, false))) {
>                         /* Move object to the new freelist */
>                         set_freepointer(s, object, *head);
>                         *head =3D object;
>                         if (!*tail)
>                                 *tail =3D object;
>                 } else {
> @@ -4474,40 +4507,67 @@ static __fastpath_inline
>  void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>                unsigned long addr)
>  {
>         memcg_slab_free_hook(s, slab, &object, 1);
>         alloc_tagging_slab_free_hook(s, slab, &object, 1);
>
> -       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
> +       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), f=
alse)))
>                 do_slab_free(s, slab, object, object, 1, addr);
>  }
>
>  #ifdef CONFIG_MEMCG
>  /* Do not inline the rare memcg charging failed path into the allocation=
 path */
>  static noinline
>  void memcg_alloc_abort_single(struct kmem_cache *s, void *object)
>  {
> -       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
> +       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), f=
alse)))
>                 do_slab_free(s, virt_to_slab(object), object, object, 1, =
_RET_IP_);
>  }
>  #endif
>
>  static __fastpath_inline
>  void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
>                     void *tail, void **p, int cnt, unsigned long addr)
>  {
>         memcg_slab_free_hook(s, slab, p, cnt);
>         alloc_tagging_slab_free_hook(s, slab, p, cnt);
>         /*
>          * With KASAN enabled slab_free_freelist_hook modifies the freeli=
st
>          * to remove objects, whose reuse must be delayed.
>          */
>         if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt)))
>                 do_slab_free(s, slab, head, tail, cnt, addr);
>  }
>
> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
> +{
> +       struct rcu_delayed_free *delayed_free =3D
> +                       container_of(rcu_head, struct rcu_delayed_free, h=
ead);
> +       void *object =3D delayed_free->object;
> +       struct slab *slab =3D virt_to_slab(object);
> +       struct kmem_cache *s;
> +
> +       if (WARN_ON(is_kfence_address(rcu_head)))
> +               return;
> +
> +       /* find the object and the cache again */
> +       if (WARN_ON(!slab))
> +               return;
> +       s =3D slab->slab_cache;
> +       if (WARN_ON(!(s->flags & SLAB_TYPESAFE_BY_RCU)))
> +               return;
> +
> +       /* resume freeing */
> +       if (!slab_free_hook(s, object, slab_want_init_on_free(s), true))
> +               return;
> +       do_slab_free(s, slab, object, object, 1, _THIS_IP_);
> +       kfree(delayed_free);
> +}
> +#endif /* CONFIG_SLUB_RCU_DEBUG */
> +
>  #ifdef CONFIG_KASAN_GENERIC
>  void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr=
)
>  {
>         do_slab_free(cache, virt_to_slab(x), x, x, 1, addr);
>  }
>  #endif
>
> --
> 2.46.0.rc1.232.g9752f9e123-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeq8JGSkFwGitwSc3DbeuoXnoyvC7RgWh6XSG1CoWH%3DZg%40mail.gm=
ail.com.
