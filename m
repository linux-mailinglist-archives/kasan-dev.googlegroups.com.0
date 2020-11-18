Return-Path: <kasan-dev+bncBCCMH5WKTMGRBE742T6QKGQE7KYNTSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F8E82B8084
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 16:30:29 +0100 (CET)
Received: by mail-ua1-x938.google.com with SMTP id w19sf601249uap.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 07:30:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605713428; cv=pass;
        d=google.com; s=arc-20160816;
        b=nDS8ygSkjgA6OjqHg5cxM7OyE2DQ8OT4HG0gx4KIq++T59lBlD1cRSn/eAA+s4nS2C
         d1HEyTNKXgNpKoU8roq9t3C79euIicRXYrAxLNmTpMyJ7mcQkNv4W0Vj4BfAQJlJU5M3
         sq/HsTbBwYwEThZ4ZgG4QLX0c1ti12XkU0+HDUuMgzTtO1LxLsfCe0z28RfBodweFuaH
         lw1VOqDYXCSWCCyNnfJyNyDlzB903ug9Y5w7UDY215pnkIKJ4yJreSOTA6F0oHjOX3Qc
         F1HDGFZEWJ8sX2siVkr9CYwL1Uu08xdZnFVnQ4HVRa22iOjAHDp0QkOgipj3i2YEst2d
         6/fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=taJzlbGVg+ZbyV2PfWW9i3nGadUYUNB3W+LZWQSpztk=;
        b=hsi1oe75ENXByUifcvOP31mqiMSC0uTnOKmBesE4+7mJMCa9UVk3CEOA5mLGXhVIlK
         KheNHTxqr15pgB+yx8U7MpY4+qTz0teWLk8DBWzGzGsHkYnC9ry/i2jIYmQNYmouBH66
         oaLy8F5XZqmAtY3jwelC4kWbEvpl9kC3/zStFb0RRbbx4Yx/7UDGSs3PW9gAN3ggvukJ
         OxCidUEa26Yu4FAAt5Nw8F+ONqJzVm8VwNTV4ky0E962PltSiKsTInsqlL2RvVk16TdS
         T7/lOJNW7KP1+7fMRgKcMneaV/UEQXvjCrrfiUQKm3UYN6fddJGYsfQA5iyb6z023IhT
         av0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Rx3USm/E";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=taJzlbGVg+ZbyV2PfWW9i3nGadUYUNB3W+LZWQSpztk=;
        b=OurM1sK5BKRjlzfiItsILojl+jQ6oi6dQfch5iOkcc0sPPWvDqbvG5JqkcZ1zFNYrx
         07r+SDBdp/idTsKPuakYn78Fzw1JExOp4Ckmhrdm4XRlAPQroe5irIhGgAxI2o1JVd+K
         h0aTwpb+vn/HscD1JTxIf2oyIqcGt368FoIGGC6/TbMxUGImfOs0s+V7XmuVEbjw+vHs
         Erl8586uxG5K6GQ1obkdOeCZ9bw4lTLLmFxIqFoHj4A5DHrE80gqw6a0dF+vj9WLlS7B
         diX9jAzeOoIWh5qmRBK1ZCq4ZbVkX9v5uEWQ8gzi3/xixAOJeret6NTSW7fcMQqEToyG
         LD3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=taJzlbGVg+ZbyV2PfWW9i3nGadUYUNB3W+LZWQSpztk=;
        b=S8uKTWX1wbg5IInAL0MLeZLmZDT+VUZVlnCGqTiw9SxjrFTa1X+1CWVsTZ70muV80f
         ft9AwO3egRv96RMxAKg/exAf47RVnz/qlAmApOID1OUdxWTs0Tb5dFqpsanKDiZirJm+
         HxpUnEnnHhdKxfQ15gbf4pP6MZoMr1LUw4pWofklxt3IhNDflcXhrbL8W1KV8E24Vu2x
         frEQLiks3RKeGsn+nr138AkgENLDAHELD6ldvsvmMjbah2Zmme2rG11WSumQlyncZalh
         0kadMQpru31vRaRf3sBKFSioljALqUGq/48H7j+XAjCvRFbKYiGGmaMaaG6vyK/7ROAn
         HGHQ==
X-Gm-Message-State: AOAM530LXaphkyKgKeGs/0lYXIzWgqm/W8qXbfmSgOvS1P4GXtVr33d8
	Hw6Y8i2g3ZN0B8y3lok4lko=
X-Google-Smtp-Source: ABdhPJwugMsVXXnMm2CpvsK+WHe8/LD8ZDeBhNItjvPaaoP+N7mIZfOWq9eEY8veeZOrskOhpEyNHQ==
X-Received: by 2002:a67:f80b:: with SMTP id l11mr1457257vso.26.1605713427840;
        Wed, 18 Nov 2020 07:30:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3b19:: with SMTP id i25ls1468037uah.5.gmail; Wed, 18 Nov
 2020 07:30:27 -0800 (PST)
X-Received: by 2002:ab0:6dd1:: with SMTP id r17mr3760479uaf.108.1605713427279;
        Wed, 18 Nov 2020 07:30:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605713427; cv=none;
        d=google.com; s=arc-20160816;
        b=ckz5Li7JMu9cSxQBrgmP8tK2ogh2c+zdOVwD0ZTSNVMjAK8CGzQDMa3ask1pTXxHkB
         zY5G153cDFMIYdH+BJu6RrLlwDTin6a9DXLs56zs/bl/lVRQthTl8aCSpbKOGktdO4gl
         9U9tijQyieXNZa1qXZyTbl+WpkZtBQ3RhPZtauhcBbClLflxCCgPfitNbxkBpKTkR0Qb
         O0+jJHKEBp6wagSrYM+PQBug+YU7ljJn5S+Tj+f+pzU0k5j8BKu6G6McblzHpLdhUaWd
         dDr+JH0XC4wnt603layoOHBE46VBATEMKOadYB6DJ0VAZp1W7h3SBr0fj/SUMJvCCbGz
         ua6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wonpByTzbuJxA+M2ARgOF+/g8Val/wioKkFNzzsy6gU=;
        b=fa7WnpxVZRW7ssaQP2HN3A9M5F9rJuKM5o8+eKXkWs86xTHoiju4kwJXoiKOzLrX8P
         NoIONEMgE6sJIzHjomqQz4+FE1tVqJ/Jrp12FW0yIbSva6cd5cCj2Go05WdtFufXUoP1
         hNww9FVsRWsJvtbK58J5z4qbwULHGvv12od1oYEh/U9gOgsPtWe9RhGx9nD1zwkh8ncY
         Tsr58bVoyAiX30fP/u6Aj8RAjKwC1Zmdyug+1F30mPYaRRf3ISheJD3Vmb0gTCUemuSr
         TaydlCnLr3a50nG4rJZ9hAP6Ekn1J+i4mBlfAzgGVmeQrKlKdoSSfDQ9oIQxI5Nts0Rt
         QirQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Rx3USm/E";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf41.google.com (mail-qv1-xf41.google.com. [2607:f8b0:4864:20::f41])
        by gmr-mx.google.com with ESMTPS id m17si1755532vsk.0.2020.11.18.07.30.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Nov 2020 07:30:27 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) client-ip=2607:f8b0:4864:20::f41;
Received: by mail-qv1-xf41.google.com with SMTP id x13so1180211qvk.8
        for <kasan-dev@googlegroups.com>; Wed, 18 Nov 2020 07:30:27 -0800 (PST)
X-Received: by 2002:a0c:c583:: with SMTP id a3mr5176021qvj.2.1605713426500;
 Wed, 18 Nov 2020 07:30:26 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com> <c305a433db6fe8ef194cddf8615db0ef7a3b0355.1605305705.git.andreyknvl@google.com>
In-Reply-To: <c305a433db6fe8ef194cddf8615db0ef7a3b0355.1605305705.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Nov 2020 16:30:15 +0100
Message-ID: <CAG_fn=Wy7fLJd46=N9U-yQAQreioEf2ny+CGNmhUVYpbWiXA1Q@mail.gmail.com>
Subject: Re: [PATCH mm v10 05/42] kasan: rename (un)poison_shadow to (un)poison_range
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Rx3USm/E";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f41 as
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

On Fri, Nov 13, 2020 at 11:16 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
>
> The new mode won't be using shadow memory. Rename external annotation
> kasan_unpoison_shadow() to kasan_unpoison_range(), and introduce internal
> functions (un)poison_range() (without kasan_ prefix).
>
> Co-developed-by: Marco Elver <elver@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: Ia359f32815242c4704e49a5f1639ca2d2f8cba69
> ---
>  include/linux/kasan.h |  6 +++---
>  kernel/fork.c         |  4 ++--
>  mm/kasan/common.c     | 49 ++++++++++++++++++++++++-------------------
>  mm/kasan/generic.c    | 23 ++++++++++----------
>  mm/kasan/kasan.h      |  3 ++-
>  mm/kasan/tags.c       |  2 +-
>  mm/slab_common.c      |  2 +-
>  7 files changed, 47 insertions(+), 42 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 26f2ab92e7ca..d237051dca58 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -71,7 +71,7 @@ extern void kasan_enable_current(void);
>  /* Disable reporting bugs for current task */
>  extern void kasan_disable_current(void);
>
> -void kasan_unpoison_shadow(const void *address, size_t size);
> +void kasan_unpoison_range(const void *address, size_t size);
>
>  void kasan_unpoison_task_stack(struct task_struct *task);
>
> @@ -108,7 +108,7 @@ struct kasan_cache {
>  size_t __ksize(const void *);
>  static inline void kasan_unpoison_slab(const void *ptr)
>  {
> -       kasan_unpoison_shadow(ptr, __ksize(ptr));
> +       kasan_unpoison_range(ptr, __ksize(ptr));
>  }
>  size_t kasan_metadata_size(struct kmem_cache *cache);
>
> @@ -117,7 +117,7 @@ void kasan_restore_multi_shot(bool enabled);
>
>  #else /* CONFIG_KASAN */
>
> -static inline void kasan_unpoison_shadow(const void *address, size_t siz=
e) {}
> +static inline void kasan_unpoison_range(const void *address, size_t size=
) {}
>
>  static inline void kasan_unpoison_task_stack(struct task_struct *task) {=
}
>
> diff --git a/kernel/fork.c b/kernel/fork.c
> index 15f189bb8ec4..bee52236f09b 100644
> --- a/kernel/fork.c
> +++ b/kernel/fork.c
> @@ -225,8 +225,8 @@ static unsigned long *alloc_thread_stack_node(struct =
task_struct *tsk, int node)
>                 if (!s)
>                         continue;
>
> -               /* Clear the KASAN shadow of the stack. */
> -               kasan_unpoison_shadow(s->addr, THREAD_SIZE);
> +               /* Mark stack accessible for KASAN. */
> +               kasan_unpoison_range(s->addr, THREAD_SIZE);
>
>                 /* Clear stale pointers from reused stack. */
>                 memset(s->addr, 0, THREAD_SIZE);
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index f5739be60edc..6adbf5891aff 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -109,7 +109,7 @@ void *memcpy(void *dest, const void *src, size_t len)
>   * Poisons the shadow memory for 'size' bytes starting from 'addr'.
>   * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
>   */
> -void kasan_poison_shadow(const void *address, size_t size, u8 value)
> +void poison_range(const void *address, size_t size, u8 value)
>  {
>         void *shadow_start, *shadow_end;
>
> @@ -130,7 +130,7 @@ void kasan_poison_shadow(const void *address, size_t =
size, u8 value)
>         __memset(shadow_start, value, shadow_end - shadow_start);
>  }
>
> -void kasan_unpoison_shadow(const void *address, size_t size)
> +void unpoison_range(const void *address, size_t size)
>  {
>         u8 tag =3D get_tag(address);
>
> @@ -149,7 +149,7 @@ void kasan_unpoison_shadow(const void *address, size_=
t size)
>         if (is_kfence_address(address))
>                 return;
>
> -       kasan_poison_shadow(address, size, tag);
> +       poison_range(address, size, tag);
>
>         if (size & KASAN_SHADOW_MASK) {
>                 u8 *shadow =3D (u8 *)kasan_mem_to_shadow(address + size);
> @@ -161,12 +161,17 @@ void kasan_unpoison_shadow(const void *address, siz=
e_t size)
>         }
>  }
>
> +void kasan_unpoison_range(const void *address, size_t size)
> +{
> +       unpoison_range(address, size);
> +}
> +
>  static void __kasan_unpoison_stack(struct task_struct *task, const void =
*sp)
>  {
>         void *base =3D task_stack_page(task);
>         size_t size =3D sp - base;
>
> -       kasan_unpoison_shadow(base, size);
> +       unpoison_range(base, size);
>  }
>
>  /* Unpoison the entire stack for a task. */
> @@ -185,7 +190,7 @@ asmlinkage void kasan_unpoison_task_stack_below(const=
 void *watermark)
>          */
>         void *base =3D (void *)((unsigned long)watermark & ~(THREAD_SIZE =
- 1));
>
> -       kasan_unpoison_shadow(base, watermark - base);
> +       unpoison_range(base, watermark - base);
>  }
>
>  void kasan_alloc_pages(struct page *page, unsigned int order)
> @@ -199,13 +204,13 @@ void kasan_alloc_pages(struct page *page, unsigned =
int order)
>         tag =3D random_tag();
>         for (i =3D 0; i < (1 << order); i++)
>                 page_kasan_tag_set(page + i, tag);
> -       kasan_unpoison_shadow(page_address(page), PAGE_SIZE << order);
> +       unpoison_range(page_address(page), PAGE_SIZE << order);
>  }
>
>  void kasan_free_pages(struct page *page, unsigned int order)
>  {
>         if (likely(!PageHighMem(page)))
> -               kasan_poison_shadow(page_address(page),
> +               poison_range(page_address(page),
>                                 PAGE_SIZE << order,
>                                 KASAN_FREE_PAGE);
>  }
> @@ -297,18 +302,18 @@ void kasan_poison_slab(struct page *page)
>
>         for (i =3D 0; i < compound_nr(page); i++)
>                 page_kasan_tag_reset(page + i);
> -       kasan_poison_shadow(page_address(page), page_size(page),
> -                       KASAN_KMALLOC_REDZONE);
> +       poison_range(page_address(page), page_size(page),
> +                    KASAN_KMALLOC_REDZONE);
>  }
>
>  void kasan_unpoison_object_data(struct kmem_cache *cache, void *object)
>  {
> -       kasan_unpoison_shadow(object, cache->object_size);
> +       unpoison_range(object, cache->object_size);
>  }
>
>  void kasan_poison_object_data(struct kmem_cache *cache, void *object)
>  {
> -       kasan_poison_shadow(object,
> +       poison_range(object,
>                         round_up(cache->object_size, KASAN_SHADOW_SCALE_S=
IZE),
>                         KASAN_KMALLOC_REDZONE);
>  }
> @@ -424,7 +429,7 @@ static bool __kasan_slab_free(struct kmem_cache *cach=
e, void *object,
>         }
>
>         rounded_up_size =3D round_up(cache->object_size, KASAN_SHADOW_SCA=
LE_SIZE);
> -       kasan_poison_shadow(object, rounded_up_size, KASAN_KMALLOC_FREE);
> +       poison_range(object, rounded_up_size, KASAN_KMALLOC_FREE);
>
>         if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
>                         unlikely(!(cache->flags & SLAB_KASAN)))
> @@ -467,9 +472,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache=
, const void *object,
>                 tag =3D assign_tag(cache, object, false, keep_tag);
>
>         /* Tag is ignored in set_tag without CONFIG_KASAN_SW_TAGS */
> -       kasan_unpoison_shadow(set_tag(object, tag), size);
> -       kasan_poison_shadow((void *)redzone_start, redzone_end - redzone_=
start,
> -               KASAN_KMALLOC_REDZONE);
> +       unpoison_range(set_tag(object, tag), size);
> +       poison_range((void *)redzone_start, redzone_end - redzone_start,
> +                    KASAN_KMALLOC_REDZONE);
>
>         if (cache->flags & SLAB_KASAN)
>                 kasan_set_track(&get_alloc_info(cache, object)->alloc_tra=
ck, flags);
> @@ -508,9 +513,9 @@ void * __must_check kasan_kmalloc_large(const void *p=
tr, size_t size,
>                                 KASAN_SHADOW_SCALE_SIZE);
>         redzone_end =3D (unsigned long)ptr + page_size(page);
>
> -       kasan_unpoison_shadow(ptr, size);
> -       kasan_poison_shadow((void *)redzone_start, redzone_end - redzone_=
start,
> -               KASAN_PAGE_REDZONE);
> +       unpoison_range(ptr, size);
> +       poison_range((void *)redzone_start, redzone_end - redzone_start,
> +                    KASAN_PAGE_REDZONE);
>
>         return (void *)ptr;
>  }
> @@ -542,7 +547,7 @@ void kasan_poison_kfree(void *ptr, unsigned long ip)
>                         kasan_report_invalid_free(ptr, ip);
>                         return;
>                 }
> -               kasan_poison_shadow(ptr, page_size(page), KASAN_FREE_PAGE=
);
> +               poison_range(ptr, page_size(page), KASAN_FREE_PAGE);
>         } else {
>                 __kasan_slab_free(page->slab_cache, ptr, ip, false);
>         }
> @@ -728,7 +733,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsign=
ed long size)
>          * // vmalloc() allocates memory
>          * // let a =3D area->addr
>          * // we reach kasan_populate_vmalloc
> -        * // and call kasan_unpoison_shadow:
> +        * // and call unpoison_range:
>          * STORE shadow(a), unpoison_val
>          * ...
>          * STORE shadow(a+99), unpoison_val     x =3D LOAD p
> @@ -763,7 +768,7 @@ void kasan_poison_vmalloc(const void *start, unsigned=
 long size)
>                 return;
>
>         size =3D round_up(size, KASAN_SHADOW_SCALE_SIZE);
> -       kasan_poison_shadow(start, size, KASAN_VMALLOC_INVALID);
> +       poison_range(start, size, KASAN_VMALLOC_INVALID);
>  }
>
>  void kasan_unpoison_vmalloc(const void *start, unsigned long size)
> @@ -771,7 +776,7 @@ void kasan_unpoison_vmalloc(const void *start, unsign=
ed long size)
>         if (!is_vmalloc_or_module_addr(start))
>                 return;
>
> -       kasan_unpoison_shadow(start, size);
> +       unpoison_range(start, size);
>  }
>
>  static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index d6a386255007..cdc2d8112f3e 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -203,11 +203,11 @@ static void register_global(struct kasan_global *gl=
obal)
>  {
>         size_t aligned_size =3D round_up(global->size, KASAN_SHADOW_SCALE=
_SIZE);
>
> -       kasan_unpoison_shadow(global->beg, global->size);
> +       unpoison_range(global->beg, global->size);
>
> -       kasan_poison_shadow(global->beg + aligned_size,
> -               global->size_with_redzone - aligned_size,
> -               KASAN_GLOBAL_REDZONE);
> +       poison_range(global->beg + aligned_size,
> +                    global->size_with_redzone - aligned_size,
> +                    KASAN_GLOBAL_REDZONE);
>  }
>
>  void __asan_register_globals(struct kasan_global *globals, size_t size)
> @@ -286,13 +286,12 @@ void __asan_alloca_poison(unsigned long addr, size_=
t size)
>
>         WARN_ON(!IS_ALIGNED(addr, KASAN_ALLOCA_REDZONE_SIZE));
>
> -       kasan_unpoison_shadow((const void *)(addr + rounded_down_size),
> -                             size - rounded_down_size);
> -       kasan_poison_shadow(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
> -                       KASAN_ALLOCA_LEFT);
> -       kasan_poison_shadow(right_redzone,
> -                       padding_size + KASAN_ALLOCA_REDZONE_SIZE,
> -                       KASAN_ALLOCA_RIGHT);
> +       unpoison_range((const void *)(addr + rounded_down_size),
> +                      size - rounded_down_size);
> +       poison_range(left_redzone, KASAN_ALLOCA_REDZONE_SIZE,
> +                    KASAN_ALLOCA_LEFT);
> +       poison_range(right_redzone, padding_size + KASAN_ALLOCA_REDZONE_S=
IZE,
> +                    KASAN_ALLOCA_RIGHT);
>  }
>  EXPORT_SYMBOL(__asan_alloca_poison);
>
> @@ -302,7 +301,7 @@ void __asan_allocas_unpoison(const void *stack_top, c=
onst void *stack_bottom)
>         if (unlikely(!stack_top || stack_top > stack_bottom))
>                 return;
>
> -       kasan_unpoison_shadow(stack_top, stack_bottom - stack_top);
> +       unpoison_range(stack_top, stack_bottom - stack_top);
>  }
>  EXPORT_SYMBOL(__asan_allocas_unpoison);
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index ac499456740f..42ab02c61331 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -150,7 +150,8 @@ static inline bool addr_has_shadow(const void *addr)
>         return (addr >=3D kasan_shadow_to_mem((void *)KASAN_SHADOW_START)=
);
>  }
>
> -void kasan_poison_shadow(const void *address, size_t size, u8 value);
> +void poison_range(const void *address, size_t size, u8 value);
> +void unpoison_range(const void *address, size_t size);
>
>  /**
>   * check_memory_region - Check memory region, and report if invalid acce=
ss.
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 5c8b08a25715..c0b3f327812b 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -153,7 +153,7 @@ EXPORT_SYMBOL(__hwasan_storeN_noabort);
>
>  void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
>  {
> -       kasan_poison_shadow((void *)addr, size, tag);
> +       poison_range((void *)addr, size, tag);
>  }
>  EXPORT_SYMBOL(__hwasan_tag_memory);
>
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 479d17b90155..0b5ae1819a8b 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1179,7 +1179,7 @@ size_t ksize(const void *objp)
>          * We assume that ksize callers could use whole allocated area,
>          * so we need to unpoison this area.
>          */
> -       kasan_unpoison_shadow(objp, size);
> +       kasan_unpoison_range(objp, size);
>         return size;
>  }
>  EXPORT_SYMBOL(ksize);
> --
> 2.29.2.299.gdc1121823c-goog
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
kasan-dev/CAG_fn%3DWy7fLJd46%3DN9U-yQAQreioEf2ny%2BCGNmhUVYpbWiXA1Q%40mail.=
gmail.com.
