Return-Path: <kasan-dev+bncBDW2JDUY5AORBEMPWW2QMGQEHR4P56Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id BC38B9464AD
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2024 22:54:42 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2ef244cdd30sf84880311fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Aug 2024 13:54:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722632082; cv=pass;
        d=google.com; s=arc-20160816;
        b=OlT69dhjYIjfuWh4GWaVD9q42eLFeYK9I9H3HvSY+RPoBNWJwL3RTK15WRMH8KjZ38
         Z3mcsQrCur9LaOfgdwh1ncrwFMFd8ATb/Pqc36wYJCzxQTddIp2xq1ESgFpLrgXbInMK
         EZboNh2VH1yilfSwlNku4GrAQI0uz4PXIgEXbuIC1rR2THu59OlRJqHqQ2+3XFZQya04
         p2SJmuh/McyLeK1Gr9t4P3VejflmVJAUrFm4RxuynVbzi2DH91m9cEsBIjIXwTU1YQ/W
         dcBmCfJmXgdmfJd1JRkT2y1Z0VjJu7dU6WVHflnl8GkvF1DtzdjvT6lKq2TSzRnASkdD
         4ldA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=OFPc/0mHEyXZwDor8+UVlIfovtYj67uNABn2qwUqtXI=;
        fh=vriotpRvvSju9xJCMVN3o+HN9UIJLs6leuCmyHG9FsU=;
        b=hjnEWFozhgxhB/nfvSVIslAZxItUc7guu8IgAI+GTtAUy7KAwoqB0gL8gKlosopQo7
         fgsBHdkIyTV2fyyDJSIgDh7ZpIM1hZAPPA25DFgAooveiUTT8M2tsCz66hOcnPpBK7BB
         DpgD9paI6Z3FAzjKrXz4Je2pRpmPw8CUplom608yox/1CfM7P5gMAdaYpM48DhSwt5NY
         elWFpgVdgERiWNsvSgg4dxh4iAtW+HTqzRvHG+XOiE3FiHekoJ6Och4QUIaOhkUe24s7
         gnHYKryvkN/7Er0I3iLx6ebGmOQkukeEDmt5w23CDQtpZs0Mv8jpCuqywqJYm+DbqyMk
         MzsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Mi2tjFfq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722632082; x=1723236882; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OFPc/0mHEyXZwDor8+UVlIfovtYj67uNABn2qwUqtXI=;
        b=nknifo0XgpyXQuxpDwxWkcYr8ACTND4FQKU+yNMDWRgASkd/eTnFNYXvdmNSHRI3hv
         NeFM+SeNvzh1DtHKJvOSIo9MBezRV4mCU/E72s3+LutGOoP+dJO4y72DoEHkl76/FM6w
         W8mHC/kveorViL8Kt5SDf7b2ACxqEbsxQd/NlWZi3BG0chtvUanuF9ftq8d9fl6TDL/j
         xrhNWcKRSqLQw3WoIcLyQjm6FiJchKdHoCPni+3a/6vLNofw9+puHu1OV6+SaTrA3dL8
         5ihuo+07czDYj15KS3rerjQemoaPHKHcSoBE8i7dMIWZCiW3nhHgCcyrfJHf0KR0diHb
         hWqg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722632082; x=1723236882; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OFPc/0mHEyXZwDor8+UVlIfovtYj67uNABn2qwUqtXI=;
        b=ivdKKbXnhoKNb5dF3PlDmskX86TvkSdiY3IjBNusCtIqC0xokVJISLn5Ek/ZS4SVO2
         VO/LGoN8rH0ArzD7+c2UX4MjofMfDk5T9UcV3M/n5aulPn4BOBkgk4VEXL56R+4Pk9bM
         WzOliDfnDE498F08fBMqms7oOPOalcIVElfZzjp9q8GCiFnCZWjiH1RZkCwJtRYXRYaM
         ZN8/zX2CGQ4rRzsr2rx2VR8/YKcwAHhiG1XrVCybYagsQF++OpIChXhBdJU5PFEkrxiK
         P8/V8Pw2+SkNm9xg7o9hTFFApicrg3ZOP9AQnImJ6ZfAzHgy5lmIsThTuyoiiagMDImn
         CDBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722632082; x=1723236882;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OFPc/0mHEyXZwDor8+UVlIfovtYj67uNABn2qwUqtXI=;
        b=ZTy5q7IEZiD5FQ3nLwkpYyKrsKRh8zHGG42aFlvjqRhAbs5RLwM0iiYP+hM2bpizVR
         1eQvsYEH+UPr8i8OW0FzmPdM5/NjGguDyhncMhHY3d6sUDyw2/wNFBZW6mdwe1o/3NqK
         sdvq25uImjytKroOBFBpnBpdwsgLrZHYe5wZJ5dijM1e20RdSrfGY6On635wRT0twFCH
         WhKHlIOkon4ZmSlWjsrc2VsE/Gfs3kGE9BcZjxpPoxRT7l7n9w53OdRiPwrQYbULBf93
         tBFK5S2aOAk0aBLWajo0TNJSNUgAUnka27ONUHicTFhCGjoHWg4JGvRp3KvThSfSXZyj
         /Ycw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXXql5xtt2XeTk7sSftakTxOcsfG01tJQAnI+kx5OobCCBnOrBWBqmBTGpjiSEyhpFgx12Fto1o/OKq4v52lKyCjJhbGmZZIg==
X-Gm-Message-State: AOJu0YyURHy1qZfP8H3LEgEVL3jYS0POX4wxC96DSfb/Ek6EvK4c2/oX
	RmzAITGNdu8V1R53g19LBWqqyKsdk2Te33BMOWTHEyW36i/bf2XA
X-Google-Smtp-Source: AGHT+IH7HhF+ZPWEDROQOV9LT6Pq5kQ5Y35NvD8eS7vA7SBxcDVnkW9y0JTJ/DQiICNSBtWprmI+9Q==
X-Received: by 2002:a2e:6a1a:0:b0:2ef:295b:4946 with SMTP id 38308e7fff4ca-2f15aa87067mr32962511fa.4.1722632081328;
        Fri, 02 Aug 2024 13:54:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:1f09:0:b0:2f0:1cb8:9ecd with SMTP id 38308e7fff4ca-2f16a312bfels1559731fa.0.-pod-prod-04-eu;
 Fri, 02 Aug 2024 13:54:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXtmYtdwQMBpInrNcrxSTu6kfYJfm4u/DyGWi6EA4F+zG9YEZtB4OPOEEWahOeRmz10I373k0uqRcNqhRnjrp5wCK9Hh4ODhAnYwA==
X-Received: by 2002:a05:6512:4003:b0:530:ac0a:15db with SMTP id 2adb3069b0e04-530bb3626b0mr3091626e87.5.1722632078931;
        Fri, 02 Aug 2024 13:54:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722632078; cv=none;
        d=google.com; s=arc-20160816;
        b=wPpmcfgAV6a3ScWryEmvGVp1ctz/gHrgjOpwrZZx6bC6U7Xe5D4cNGrVqmas6XJPjd
         xR20H+XwI5ciQRWVqbEgfiOO+PXGATifGenAyuyNaJMZOL1bn7NNK7XU4V+knsgnQiZE
         yTZMu9Fs+oku/WTawJDYjsGMOmjtDcETAXJn7blNrxPTUbtPUX9WL3yGJviLsDzzxL3j
         QQ8sNy4x7Bj3NQRBvoJdhyM+j7Ok6Q0JUK2fYjQp+mDQIdsg0GciyUBKbJX5vKyI+VKA
         0uPae3qg4lXdQkkKA5i7EgE0tw5HgVNxC+lYZkXKPsFf7jLzJMkoMjGKCDVoyHWVv7P2
         J3zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xf8GJ1zLNQJB8KzN1/W/mx1wF5oK7IkwRl10EcOWGNo=;
        fh=2y+Ph6Z53P9yDHwb3ZaCSaRpVR924rNLPIHnA32bfjY=;
        b=TpjU+NLf9lVjulkXo5jC1aGB8iQfqx8pL9ZHzyNO41T+EDbJQ+uGybA/82VHRSJXze
         Q6h+FTYLqmr1t5/XlGttmop4s6LLeI+WhkslvSTTNipaTMCnNNnOOWTrzaPA7+3lD47i
         b2LP0TnBATu1HSytxI/iki9/+YKr8oAL+pSfnYBXvkai+NWbOK+/MdNxftEMiwgbSmRL
         IQNCBbIHK36/CFHlwhzF8F4KyzmcCtoZt7gKGJxUqc7fQ04uLaADdgA9Y4n/FVx6fpBB
         r1+Tdn/wNJJO9xux63b86MQA5YZHyYX6n+VhxPJtMDBO6MoTAmnEta/CSr3pMXCjF+Ns
         /yQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Mi2tjFfq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-530bba2732bsi108785e87.8.2024.08.02.13.54.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Aug 2024 13:54:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-426526d30aaso56907685e9.0
        for <kasan-dev@googlegroups.com>; Fri, 02 Aug 2024 13:54:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVrUU7xh7kzPZJJAt6aWEjrLu6y18YCfgqYVKIqwzIcr8kHo0bs3iEqyYJDZVnJzUqpypIHJbMPtzUm0CZuKMFhwz7uvXOvhCT36A==
X-Received: by 2002:a5d:47ce:0:b0:367:9828:f42d with SMTP id
 ffacd0b85a97d-36bbc190693mr3711275f8f.53.1722632077654; Fri, 02 Aug 2024
 13:54:37 -0700 (PDT)
MIME-Version: 1.0
References: <20240802-kasan-tsbrcu-v6-0-60d86ea78416@google.com> <20240802-kasan-tsbrcu-v6-2-60d86ea78416@google.com>
In-Reply-To: <20240802-kasan-tsbrcu-v6-2-60d86ea78416@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 2 Aug 2024 22:54:26 +0200
Message-ID: <CA+fCnZeaphqQvZTdmJ2EFDXx2V26Fut_R1Lt2DmPC0osDL0wyA@mail.gmail.com>
Subject: Re: [PATCH v6 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Jann Horn <jannh@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Mi2tjFfq;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e
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

On Fri, Aug 2, 2024 at 10:32=E2=80=AFPM Jann Horn <jannh@google.com> wrote:
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
> Tested-by: syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
> Signed-off-by: Jann Horn <jannh@google.com>
> ---
>  include/linux/kasan.h | 17 +++++++----
>  mm/Kconfig.debug      | 30 +++++++++++++++++++
>  mm/kasan/common.c     | 11 +++----
>  mm/kasan/kasan_test.c | 46 ++++++++++++++++++++++++++++++
>  mm/slab_common.c      | 12 ++++++++
>  mm/slub.c             | 79 +++++++++++++++++++++++++++++++++++++++++++++=
------
>  6 files changed, 176 insertions(+), 19 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 1570c7191176..00a3bf7c0d8f 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -193,40 +193,44 @@ static __always_inline bool kasan_slab_pre_free(str=
uct kmem_cache *s,
>  {
>         if (kasan_enabled())
>                 return __kasan_slab_pre_free(s, object, _RET_IP_);
>         return false;
>  }
>
> -bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init);
> +bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init,
> +                      bool still_accessible);
>  /**
>   * kasan_slab_free - Poison, initialize, and quarantine a slab object.
>   * @object: Object to be freed.
>   * @init: Whether to initialize the object.
> + * @still_accessible: Whether the object contents are still accessible.
>   *
>   * This function informs that a slab object has been freed and is not
> - * supposed to be accessed anymore, except for objects in
> - * SLAB_TYPESAFE_BY_RCU caches.
> + * supposed to be accessed anymore, except when @still_accessible is set
> + * (indicating that the object is in a SLAB_TYPESAFE_BY_RCU cache and an=
 RCU
> + * grace period might not have passed yet).
>   *
>   * For KASAN modes that have integrated memory initialization
>   * (kasan_has_integrated_init() =3D=3D true), this function also initial=
izes
>   * the object's memory. For other modes, the @init argument is ignored.
>   *
>   * This function might also take ownership of the object to quarantine i=
t.
>   * When this happens, KASAN will defer freeing the object to a later
>   * stage and handle it internally until then. The return value indicates
>   * whether KASAN took ownership of the object.
>   *
>   * This function is intended only for use by the slab allocator.
>   *
>   * @Return true if KASAN took ownership of the object; false otherwise.
>   */
>  static __always_inline bool kasan_slab_free(struct kmem_cache *s,
> -                                               void *object, bool init)
> +                                               void *object, bool init,
> +                                               bool still_accessible)
>  {
>         if (kasan_enabled())
> -               return __kasan_slab_free(s, object, init);
> +               return __kasan_slab_free(s, object, init, still_accessibl=
e);
>         return false;
>  }
>
>  void __kasan_kfree_large(void *ptr, unsigned long ip);
>  static __always_inline void kasan_kfree_large(void *ptr)
>  {
> @@ -416,13 +420,14 @@ static inline void *kasan_init_slab_obj(struct kmem=
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
> +                                  bool init, bool still_accessible)
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
> index f26bbc087b3b..ed4873e18c75 100644
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
> +                                     bool init, bool still_accessible)
>  {
>         void *tagged_object =3D object;
>
>         object =3D kasan_reset_tag(object);
>
>         /* RCU slabs could be legally used after free within the RCU peri=
od. */
> -       if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
> +       if (unlikely(still_accessible))
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
> +                      bool still_accessible)
>  {
>         if (!kasan_arch_is_ready() || is_kfence_address(object))
>                 return false;
>
> -       poison_slab_object(cache, object, init);
> +       poison_slab_object(cache, object, init, still_accessible);
>
>         /*
>          * If the object is put into quarantine, do not let slab put the =
object
>          * onto the freelist for now. The object's metadata is kept until=
 the
>          * object gets evicted from quarantine.
>          */
> @@ -515,13 +516,13 @@ bool __kasan_mempool_poison_object(void *ptr, unsig=
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

Ah, notice another thing: this test might fail of someone enables
CONFIG_SLUB_RCU_DEBUG with HW_TAGS, right? I think we need another
check here.

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
> index 0c98b6a2124f..a89f2006d46e 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2197,45 +2197,81 @@ static inline bool memcg_slab_post_alloc_hook(str=
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
> +       /* Are the object contents still accessible? */
> +       bool still_accessible =3D (s->flags & SLAB_TYPESAFE_BY_RCU) && !a=
fter_rcu_delay;
> +
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
> +       if (!still_accessible)
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
> +       if (still_accessible) {
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
> @@ -2253,42 +2289,42 @@ bool slab_free_hook(struct kmem_cache *s, void *x=
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
> +       return !kasan_slab_free(s, x, init, still_accessible);
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
> @@ -4474,40 +4510,67 @@ static __fastpath_inline
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
> +       if (WARN_ON(is_kfence_address(object)))
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
> 2.46.0.rc2.264.g509ed76dc8-goog
>

Otherwise:

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Let's see if syzbot finds something new with this change :)

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeaphqQvZTdmJ2EFDXx2V26Fut_R1Lt2DmPC0osDL0wyA%40mail.gmai=
l.com.
