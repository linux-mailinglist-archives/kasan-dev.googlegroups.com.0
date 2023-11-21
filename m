Return-Path: <kasan-dev+bncBDW2JDUY5AORBFF66OVAMGQEX5Z3WQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CC327F342A
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 17:47:17 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-1f938874ff3sf2508642fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 08:47:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700585236; cv=pass;
        d=google.com; s=arc-20160816;
        b=couE1n3xwPIiNiR+OBZyYbPQeqEvRSKa8KSYvIDHbAhaAk/w1kkXpzJ/Q83ZLf/ySy
         wl7grmJET56c/nYYq6qBuDMGZYwdEME+1mcXiNb/7gD4slBseO73pBMNta+rQ+1H1n5K
         ApW6ppiRyLMp6Iz+uAn4ZLre9VZlfJAJ+ZI6AeF9IrJ6zw1KDd1uj4NdKCvMxUdb+nNS
         ByQwWG4aBPSaV7+JJ8HMhilaWZjrT3MAnNVc0H0GVsCFPtbzA1Fpz/7A9RWq/oLTUs3N
         Ek/lEFykCaNqryZnUNTamkgCDHI8MEytjJfTrdWZhb8zrO4vgeDZYHHfcT/N4FMtlIYy
         WGsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=aUszJCYp8p5+YmnH+VPU+sdf7XjGQ69iN8cGoGaB90g=;
        fh=mgiYqFMMLDYnPM/L5CQVqfnAGbSFJjlpMiK/q7So1D4=;
        b=I6TMniLP0f3ntALNLFQ1Gx3BYaiz6KXnS/XcnHuxZlHipRapt7n5esKQbG8Poy7mIo
         SL7PcCvse4wOJ/FBjmr78B567Qr34u1ReFiVt6W6tRFpDIoZttSQ3A4OwUbDH3ij+r6G
         8mplyAxJmsiQhs6gOf3jXnJZ866NT0dzH8YGsUqiHVXTI/cwq3Q6gu0SXXlOLp/dzzUm
         hJ/LCDh5knw0pb6zPC0WmrcJBsslCp4Mg65ovKwHNzuaoo66CHb/boK8kvPiypeOZeJ0
         KDoFW65atuqLuHu7dKCWfG0lAaDBVETIcA2VTZ5wxEUvfAC//1F83Nw52uRAm4U5plm1
         I8IQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Cs24nNsa;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700585236; x=1701190036; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=aUszJCYp8p5+YmnH+VPU+sdf7XjGQ69iN8cGoGaB90g=;
        b=Slz/l0BQx4HXY75rnQt0GOrzP5isJJJhyv9Bf467hM+gi2QQy2ZSqvKwjoKtVx0/xJ
         jDRKLYmYDVy/SXykOmByvItC6ce7YlxHHOCWJftja0ouDTTMhQ+UZG7Cx/yqPEgcvWLR
         RfZ4LIzEl5l4BUxzN9n+xQ3QRSO/y0U2wyP+uYPRK0ZEEYhONRHpAVafgcHP+UWskVak
         c9cKxUX+sxLpVwC3r0pTaSqUtdxxNRmeMsZdpjsAJD+hLxanv05f7AixoQWE0ec3VFmV
         bnJ41nkw6XeDLcNgEPVTKxkhqn2WnBfKFrSj/dxoFC0G4cxaXEJ11rVfS/KgOmU8W1nd
         L4vw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1700585236; x=1701190036; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aUszJCYp8p5+YmnH+VPU+sdf7XjGQ69iN8cGoGaB90g=;
        b=iqqn2vlz2ETPOWHgqOajUBYibtKEzu+FNm9XQPpQKW9nxoGIs0oXtK7qWA/zd/op+E
         aifluCD05rwVATCV2j7JzGCmsJP7qxy7SJ4U1B4q85aKrBS2r0x9zCu9IyU5HeZHdvhe
         1YuKClsL/87uVbxV3EPfqy/AXI3fWPDdA+VyT3+tzVZzrP83Zxcv9o0Zh9HRG3IujaWS
         p8hIVtfjSUx5AsOuGj8ofe+KGrsCVmxY8ODvSJoix8kehejZy3aa2S43ttVBgfpxKGNX
         xVtD9FMwG69uLaUlV5F+YLnFKd9UIMH/c8SjpgFr/bkWeRaunbZ2bgFoGEHLlELaoaB6
         ZIDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700585236; x=1701190036;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=aUszJCYp8p5+YmnH+VPU+sdf7XjGQ69iN8cGoGaB90g=;
        b=gsuZVvz91M9GgyT/NEi1NAhq2DlDctaszHjZgnSJh9ktD7rMvxuAFuLa+fHsbURG1J
         w2TMgN4E07CMwqqWn1geVgcX0lnNxjGOeRtsdJIShfcr5DIHrUvNCDbe02KpzJ2RLeIs
         FWC5RSli/YrFL24xJRQKfZL/1njuzElGta7yHj0GiiJgcutYqk9bUPVflHChuFStFyPm
         sg8Pk8zYlLTCW4hf0wztZrW5cBTN6qv5JK+sOudjow2d4ZoDNlrBeF7QFYIm7JwIWBRQ
         9qln0Vbc1hbOox3FsJVa1mVoSFKbezUfdqGIHyVvAMywaT9jR4enxlP6MKEfeFSjIV/7
         Xdtw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwWhy7PsFRR6XHtAxMgE0ZjqiFhQnIZymA9P4hGoV/5vPtOHBzD
	z57AK/kyjqFnGMXxKmZbAYw=
X-Google-Smtp-Source: AGHT+IH7AAlgrKPg05rKw9YnPsUhLduIJ7YUyYuX/6v9U3cUtiy35T6xZ4DDQ/uATL/HmI4l3olcVw==
X-Received: by 2002:a05:6870:a10b:b0:1e9:b840:9c4b with SMTP id m11-20020a056870a10b00b001e9b8409c4bmr14489365oae.26.1700585236118;
        Tue, 21 Nov 2023 08:47:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3284:b0:1f5:ba60:d17c with SMTP id
 q4-20020a056870328400b001f5ba60d17cls594696oac.1.-pod-prod-08-us; Tue, 21 Nov
 2023 08:47:15 -0800 (PST)
X-Received: by 2002:a05:6871:6102:b0:1d5:a72e:154e with SMTP id ra2-20020a056871610200b001d5a72e154emr12418545oab.36.1700585235567;
        Tue, 21 Nov 2023 08:47:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700585235; cv=none;
        d=google.com; s=arc-20160816;
        b=gXcoizCZL7qDP0eVMvmtGQAiyKx2U6rZbVAnQkl3bLZJg+TtSYOdq3t5juybnJ9RON
         GCkqTUGiMB82sY7MYaeCeLZywCif7Je5CHWAeGBCd7rnC2qUJvbvEv4sty6nTT0wy3WV
         i9C+kGZa51ptBy+jWMPiIVjCsITnTVTnvkQPmVLtC/7Gc/oqNx11Ml6n0thMlN2Lbfcz
         4vafsIYkVDqNsxAxaWHqzxXsExGi7DhoUAWmSBzSQ8YJgSE8wRrV+OK2PasK29ObKAco
         JGk8QWhkQRQUqahOyE0MPBVo4An+t2iSuVP/in8Vy0A7JsCcdpyFT2OrRYEKKWT8Qdql
         OWpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=4pN2u4fGcywnuJpGPzQlph9Q+P1Toihu44zlYs+cFFQ=;
        fh=mgiYqFMMLDYnPM/L5CQVqfnAGbSFJjlpMiK/q7So1D4=;
        b=YlsNnpJ2ynOrnumoRL8pGKKkWWd+SUBTbDccWfmux5jzTAO4ixi5zxYz46Xv1ArnnC
         PDbJC00iirqKSUCfRt22hx7tYDvyL8acwJ/1dNXrAcqHaq4zYCJ2H30H/jGmL/h+va86
         QjQNiETCLn+rOhZHxF+fwDu2qQxjSZA63/VqGzdFmUeeGo2fR1NjW+w7Dh0JQB/q2bkP
         Vnskz3MwQgOGoTHL5Vb64WHwNX6I0aXkEpCEeDyr+20aXfxn6VdFkvMvd9UHX5xLCmlF
         7obH/aN03aDtu/Kk/DoXu+GL8ZHmPzBsLrHkdR98F0Nx6UL1GTqo0qXM/yyeBZVGD+TH
         IK7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Cs24nNsa;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id fp42-20020a05687065aa00b001dcf3f50667si895413oab.0.2023.11.21.08.47.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Nov 2023 08:47:15 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 41be03b00d2f7-5bcfc508d14so4516730a12.3
        for <kasan-dev@googlegroups.com>; Tue, 21 Nov 2023 08:47:15 -0800 (PST)
X-Received: by 2002:a17:90a:4411:b0:280:18bd:ffe7 with SMTP id
 s17-20020a17090a441100b0028018bdffe7mr9875785pjg.48.1700585234819; Tue, 21
 Nov 2023 08:47:14 -0800 (PST)
MIME-Version: 1.0
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz> <20231120-slab-remove-slab-v2-3-9c9c70177183@suse.cz>
In-Reply-To: <20231120-slab-remove-slab-v2-3-9c9c70177183@suse.cz>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 21 Nov 2023 17:47:03 +0100
Message-ID: <CA+fCnZdwLn_h3rsamXZMPcjcvqY3TwDmd+3gRUtjkfEad445Nw@mail.gmail.com>
Subject: Re: [PATCH v2 03/21] KASAN: remove code paths guarded by CONFIG_SLAB
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, Michal Hocko <mhocko@kernel.org>, 
	Shakeel Butt <shakeelb@google.com>, Muchun Song <muchun.song@linux.dev>, 
	Kees Cook <keescook@chromium.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
	linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Cs24nNsa;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52e
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

On Mon, Nov 20, 2023 at 7:34=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> With SLAB removed and SLUB the only remaining allocator, we can clean up
> some code that was depending on the choice.
>
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/kasan/common.c     | 13 ++-----------
>  mm/kasan/kasan.h      |  3 +--
>  mm/kasan/quarantine.c |  7 -------
>  3 files changed, 3 insertions(+), 20 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 256930da578a..5d95219e69d7 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -153,10 +153,6 @@ void __kasan_poison_object_data(struct kmem_cache *c=
ache, void *object)
>   * 2. A cache might be SLAB_TYPESAFE_BY_RCU, which means objects can be
>   *    accessed after being freed. We preassign tags for objects in these
>   *    caches as well.
> - * 3. For SLAB allocator we can't preassign tags randomly since the free=
list
> - *    is stored as an array of indexes instead of a linked list. Assign =
tags
> - *    based on objects indexes, so that objects that are next to each ot=
her
> - *    get different tags.
>   */
>  static inline u8 assign_tag(struct kmem_cache *cache,
>                                         const void *object, bool init)
> @@ -171,17 +167,12 @@ static inline u8 assign_tag(struct kmem_cache *cach=
e,
>         if (!cache->ctor && !(cache->flags & SLAB_TYPESAFE_BY_RCU))
>                 return init ? KASAN_TAG_KERNEL : kasan_random_tag();
>
> -       /* For caches that either have a constructor or SLAB_TYPESAFE_BY_=
RCU: */
> -#ifdef CONFIG_SLAB
> -       /* For SLAB assign tags based on the object index in the freelist=
. */
> -       return (u8)obj_to_index(cache, virt_to_slab(object), (void *)obje=
ct);
> -#else
>         /*
> -        * For SLUB assign a random tag during slab creation, otherwise r=
euse
> +        * For caches that either have a constructor or SLAB_TYPESAFE_BY_=
RCU,
> +        * assign a random tag during slab creation, otherwise reuse
>          * the already assigned tag.
>          */
>         return init ? kasan_random_tag() : get_tag(object);
> -#endif
>  }
>
>  void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8b06bab5c406..eef50233640a 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -373,8 +373,7 @@ void kasan_set_track(struct kasan_track *track, gfp_t=
 flags);
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t=
 flags);
>  void kasan_save_free_info(struct kmem_cache *cache, void *object);
>
> -#if defined(CONFIG_KASAN_GENERIC) && \
> -       (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> +#ifdef CONFIG_KASAN_GENERIC
>  bool kasan_quarantine_put(struct kmem_cache *cache, void *object);
>  void kasan_quarantine_reduce(void);
>  void kasan_quarantine_remove_cache(struct kmem_cache *cache);
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index ca4529156735..138c57b836f2 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -144,10 +144,6 @@ static void qlink_free(struct qlist_node *qlink, str=
uct kmem_cache *cache)
>  {
>         void *object =3D qlink_to_object(qlink, cache);
>         struct kasan_free_meta *meta =3D kasan_get_free_meta(cache, objec=
t);
> -       unsigned long flags;
> -
> -       if (IS_ENABLED(CONFIG_SLAB))
> -               local_irq_save(flags);
>
>         /*
>          * If init_on_free is enabled and KASAN's free metadata is stored=
 in
> @@ -166,9 +162,6 @@ static void qlink_free(struct qlist_node *qlink, stru=
ct kmem_cache *cache)
>         *(u8 *)kasan_mem_to_shadow(object) =3D KASAN_SLAB_FREE;
>
>         ___cache_free(cache, object, _THIS_IP_);
> -
> -       if (IS_ENABLED(CONFIG_SLAB))
> -               local_irq_restore(flags);
>  }
>
>  static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cach=
e)
>
> --
> 2.42.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Very nice to see SLAB-induced complexity being gone :)

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdwLn_h3rsamXZMPcjcvqY3TwDmd%2B3gRUtjkfEad445Nw%40mail.gm=
ail.com.
