Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOPHWWLAMGQEP6SFQFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id A645F571AE5
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 15:14:34 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id x15-20020a9f3e8f000000b0038306827c33sf2092392uai.5
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 06:14:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657631673; cv=pass;
        d=google.com; s=arc-20160816;
        b=r5NRaw3lq2II75J1rM691rkBwiduEIK5uKwTQPVkz1CZQLJlra6Nv1i54D4BAEzy/b
         HdEp1/Eprstq06EKlovp81rfsfZIhUBZAbUkapCXjdVrFxqiYKH/NbUh1FTM1qFeLlSq
         kiVjU2X04BEehVh+aA5K3ZkgwkzOziwFHRIzAP9e84Q/+qOLjGzNjtIWf3pSmv2z4NXh
         pjsVBrCtHOrsrOuUFkrdQrns29G8Edp2KlFt0foCSI/JQhcWXXIwr5JYt+F2CXy9xyVE
         Vf/8GdUoTFaixMBwzf6Y2s9ygZsOZMK69IEpYL+nLFQ/TcxZl6K0XpRiPBfLJePYC0dQ
         zFWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zsRr3u9wJOMHldkM42SYo1CMwkwtf6iAL/k5fVGfctg=;
        b=f+E2/6yi5kLKy/K35D5LDkqAX5fQYEFM2WKdT9xNaC06z8HyJmRYjUqZUnJ0uGE6t/
         oD5Y1yTPI9HmKsr6VUUPPWMR9m6mwjLc9KyHcElwuRbfNH6v3N/0wNgnAX3n5FtsK4V9
         +zulik8Bbcfwk0IzWJD2AI3B+bY8AdbYZ6rO+wc6T/0K97+e0IG07puCi7QEiZbxXihg
         9WCzk7YhebzyzA8I9bF7FDo65Moe4mC47sQEQSTlggeG5JfFj5rkcuIumMPtopY2hdHZ
         oNnoDuPDv2/pII8j1CUT0s/Pz+x0GhYNGriJdUEJW2Io//NlXDTLrWMbrU4mUJGmpF6w
         bXJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ei+65oY0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zsRr3u9wJOMHldkM42SYo1CMwkwtf6iAL/k5fVGfctg=;
        b=f4fgl9Cryu0gtQB5tARbZFlkc1gbVf9jNjdwno4U1Q3JaBTtN5IpD7ye5HxiQHoiJs
         E7h/xaZxsaXtuDvHfNyVZFci1J+SAhrqrgxa8ChyhPDfRnS6KG8ACEI4AE84ssjov13R
         nrnGWJjQJ7bLNL0rBDiNkIp0dhB2+w2sw62VtmrYTNzfIcS6DhQnsHyqL80WxIDy2uk8
         +rlFGdg+2MsiXIFhWWGlCr9t+E3s5ryfMUogQDpIPhXWsavCQ54UdOWVf5jjRWnxjVM9
         US41qnijy3zxwg39Vl7nIBBk01uIgBEU0v2yGyE+9tUn6tN+fqo9MGyhQ2tlgZDXYRHx
         8NKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zsRr3u9wJOMHldkM42SYo1CMwkwtf6iAL/k5fVGfctg=;
        b=es0XUjcN1/41lzG7f4RygjRbbm2bcI7I9Uxi7YVjW2a5lJU6hIbJpnsqbtp6/u5o8l
         q9geiYnRIyC6sfSEXWhyH56hEo9Cl0NJnVgKxHGe3qOlVQYWljgW9+MzbHz4GbYHaibp
         StjfcXPfAYOb2sxMagTrqJy3NiPg6hZtlDGjXpKyfzEUHp4OUebRC/maGttLI27tSsbq
         fSePr7wyD/f8plNpCFQFazPlcOr0HM0BXAe4F9ZUu8G3iGYfDD/Jh3VEP/7rkIpEYa4U
         PZTOoCMBWOzwaoJ7uKSTtMs4ZAGKX3mh+f58r+BSYgkshz4Cr2JFSPnaWtsnu2JZTnu9
         3c0g==
X-Gm-Message-State: AJIora+G1QVPoV5wLoU/kS8YvTUxU2vUrnoojXCXANk7e/4DUvk2GOlS
	B8qgJatxxHsleWNh3Sy14gE=
X-Google-Smtp-Source: AGRyM1v7Ei1Z0wielC7KMfZh5spCQLNCRiQ88b8gpJ2lfZRNCEbmhxrXQotO64oyVvabHMfhyo65wA==
X-Received: by 2002:a67:ab46:0:b0:356:d01b:e357 with SMTP id k6-20020a67ab46000000b00356d01be357mr8156916vsh.55.1657631673422;
        Tue, 12 Jul 2022 06:14:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:1cc7:0:b0:356:7111:46d0 with SMTP id c190-20020a671cc7000000b00356711146d0ls487604vsc.0.gmail;
 Tue, 12 Jul 2022 06:14:31 -0700 (PDT)
X-Received: by 2002:a05:6102:b16:b0:357:5533:ded4 with SMTP id b22-20020a0561020b1600b003575533ded4mr4377166vst.36.1657631671763;
        Tue, 12 Jul 2022 06:14:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657631671; cv=none;
        d=google.com; s=arc-20160816;
        b=JT1ELRWXbXFTq3Bwzfn3LaDXDR2ldLL4NH895LcT69sIdq959N0uaBYxreMMxxp5d1
         TJihINspPBhMyo2w+jqdNxpg3+KBUeMgtvd3wDIMpNi5elhTc9t1S8AXmqUoCyHbOkYQ
         KKRjDbLdc/dI3PnTcmOZs3W7c74LZu0vz7+fx3ThegpkG0D2FtAVrsn4Otfz977TqffA
         xDAnuLufyA5ENVtM9tawI0L0sZVTE4ukmzM3+fLRyGzWvJicK9bu07eF7TbqokUk4EKW
         rpktwF+HfvpOPIMs8/OQA+/5QOee3vpl8XxVfBaDDp5c2bANzunVpvoSmtlHyiRv1jVE
         S7qA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BonEn6uOwekFl3zwAk2Kis9tLSCC45eUpmb7zWo4VJI=;
        b=zHSAZL+4CaBvZZwQWk+rPwZbEnea3Ft4VVjvyTndfT7R3CLTzrEolIyMeVMTC1nbbj
         6YlLJ0v/SD1tVUJkcBoTf6A31DaPsYefnatGryLZ7rF62zRz/Kd/voIaoAlh3kQgmJnA
         D5SSsbZxWTZV230G70tpC/jFXPVqKK3XhHkH6Am2C7QMLpIbk9E2TvHrFhi+mbhWk4CJ
         EtNQ3gzW181QASVhtW7mCZUJZmcd1dDb+NWIkdwVjs9CocQz9sD4/eOvWAGf1CXQgyOJ
         Sp8pI2wsvsClpeNjiimvaRDXooJQngd/CIxLpGZKj6BywPvRs/RrZn5WweCJ+KnstHp/
         Pe7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ei+65oY0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id l21-20020a1fa215000000b00374b7d48bf7si211725vke.4.2022.07.12.06.14.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 06:14:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id y195so13912346yby.0
        for <kasan-dev@googlegroups.com>; Tue, 12 Jul 2022 06:14:31 -0700 (PDT)
X-Received: by 2002:a25:2d59:0:b0:66e:32d3:7653 with SMTP id
 s25-20020a252d59000000b0066e32d37653mr22288782ybe.625.1657631671169; Tue, 12
 Jul 2022 06:14:31 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-16-glider@google.com>
In-Reply-To: <20220701142310.2188015-16-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jul 2022 15:13:55 +0200
Message-ID: <CANpmjNOJ-2xim3KM=9O=sfSgQXZi81R6PQj=antfHnejaOOogg@mail.gmail.com>
Subject: Re: [PATCH v4 15/45] mm: kmsan: call KMSAN hooks from SLUB code
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ei+65oY0;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 1 Jul 2022 at 16:23, 'Alexander Potapenko' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> In order to report uninitialized memory coming from heap allocations
> KMSAN has to poison them unless they're created with __GFP_ZERO.
>
> It's handy that we need KMSAN hooks in the places where
> init_on_alloc/init_on_free initialization is performed.
>
> In addition, we apply __no_kmsan_checks to get_freepointer_safe() to
> suppress reports when accessing freelist pointers that reside in freed
> objects.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Marco Elver <elver@google.com>

But see comment below.

> ---
> v2:
>  -- move the implementation of SLUB hooks here
>
> v4:
>  -- change sizeof(type) to sizeof(*ptr)
>  -- swap mm: and kmsan: in the subject
>  -- get rid of kmsan_init(), replace it with __no_kmsan_checks
>
> Link: https://linux-review.googlesource.com/id/I6954b386c5c5d7f99f48bb6cbcc74b75136ce86e
> ---
>  include/linux/kmsan.h | 57 ++++++++++++++++++++++++++++++
>  mm/kmsan/hooks.c      | 80 +++++++++++++++++++++++++++++++++++++++++++
>  mm/slab.h             |  1 +
>  mm/slub.c             | 18 ++++++++++
>  4 files changed, 156 insertions(+)
>
> diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
> index 699fe4f5b3bee..fd76cea338878 100644
> --- a/include/linux/kmsan.h
> +++ b/include/linux/kmsan.h
> @@ -15,6 +15,7 @@
>  #include <linux/types.h>
>
>  struct page;
> +struct kmem_cache;
>
>  #ifdef CONFIG_KMSAN
>
> @@ -72,6 +73,44 @@ void kmsan_free_page(struct page *page, unsigned int order);
>   */
>  void kmsan_copy_page_meta(struct page *dst, struct page *src);
>
> +/**
> + * kmsan_slab_alloc() - Notify KMSAN about a slab allocation.
> + * @s:      slab cache the object belongs to.
> + * @object: object pointer.
> + * @flags:  GFP flags passed to the allocator.
> + *
> + * Depending on cache flags and GFP flags, KMSAN sets up the metadata of the
> + * newly created object, marking it as initialized or uninitialized.
> + */
> +void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags);
> +
> +/**
> + * kmsan_slab_free() - Notify KMSAN about a slab deallocation.
> + * @s:      slab cache the object belongs to.
> + * @object: object pointer.
> + *
> + * KMSAN marks the freed object as uninitialized.
> + */
> +void kmsan_slab_free(struct kmem_cache *s, void *object);
> +
> +/**
> + * kmsan_kmalloc_large() - Notify KMSAN about a large slab allocation.
> + * @ptr:   object pointer.
> + * @size:  object size.
> + * @flags: GFP flags passed to the allocator.
> + *
> + * Similar to kmsan_slab_alloc(), but for large allocations.
> + */
> +void kmsan_kmalloc_large(const void *ptr, size_t size, gfp_t flags);
> +
> +/**
> + * kmsan_kfree_large() - Notify KMSAN about a large slab deallocation.
> + * @ptr: object pointer.
> + *
> + * Similar to kmsan_slab_free(), but for large allocations.
> + */
> +void kmsan_kfree_large(const void *ptr);
> +
>  /**
>   * kmsan_map_kernel_range_noflush() - Notify KMSAN about a vmap.
>   * @start:     start of vmapped range.
> @@ -138,6 +177,24 @@ static inline void kmsan_copy_page_meta(struct page *dst, struct page *src)
>  {
>  }
>
> +static inline void kmsan_slab_alloc(struct kmem_cache *s, void *object,
> +                                   gfp_t flags)
> +{
> +}
> +
> +static inline void kmsan_slab_free(struct kmem_cache *s, void *object)
> +{
> +}
> +
> +static inline void kmsan_kmalloc_large(const void *ptr, size_t size,
> +                                      gfp_t flags)
> +{
> +}
> +
> +static inline void kmsan_kfree_large(const void *ptr)
> +{
> +}
> +
>  static inline void kmsan_vmap_pages_range_noflush(unsigned long start,
>                                                   unsigned long end,
>                                                   pgprot_t prot,
> diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
> index 070756be70e3a..052e17b7a717d 100644
> --- a/mm/kmsan/hooks.c
> +++ b/mm/kmsan/hooks.c
> @@ -26,6 +26,86 @@
>   * skipping effects of functions like memset() inside instrumented code.
>   */
>
> +void kmsan_slab_alloc(struct kmem_cache *s, void *object, gfp_t flags)
> +{
> +       if (unlikely(object == NULL))
> +               return;
> +       if (!kmsan_enabled || kmsan_in_runtime())
> +               return;
> +       /*
> +        * There's a ctor or this is an RCU cache - do nothing. The memory
> +        * status hasn't changed since last use.
> +        */
> +       if (s->ctor || (s->flags & SLAB_TYPESAFE_BY_RCU))
> +               return;
> +
> +       kmsan_enter_runtime();
> +       if (flags & __GFP_ZERO)
> +               kmsan_internal_unpoison_memory(object, s->object_size,
> +                                              KMSAN_POISON_CHECK);
> +       else
> +               kmsan_internal_poison_memory(object, s->object_size, flags,
> +                                            KMSAN_POISON_CHECK);
> +       kmsan_leave_runtime();
> +}
> +EXPORT_SYMBOL(kmsan_slab_alloc);
> +
> +void kmsan_slab_free(struct kmem_cache *s, void *object)
> +{
> +       if (!kmsan_enabled || kmsan_in_runtime())
> +               return;
> +
> +       /* RCU slabs could be legally used after free within the RCU period */
> +       if (unlikely(s->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)))
> +               return;
> +       /*
> +        * If there's a constructor, freed memory must remain in the same state
> +        * until the next allocation. We cannot save its state to detect
> +        * use-after-free bugs, instead we just keep it unpoisoned.
> +        */
> +       if (s->ctor)
> +               return;
> +       kmsan_enter_runtime();
> +       kmsan_internal_poison_memory(object, s->object_size, GFP_KERNEL,
> +                                    KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
> +       kmsan_leave_runtime();
> +}
> +EXPORT_SYMBOL(kmsan_slab_free);
> +
> +void kmsan_kmalloc_large(const void *ptr, size_t size, gfp_t flags)
> +{
> +       if (unlikely(ptr == NULL))
> +               return;
> +       if (!kmsan_enabled || kmsan_in_runtime())
> +               return;
> +       kmsan_enter_runtime();
> +       if (flags & __GFP_ZERO)
> +               kmsan_internal_unpoison_memory((void *)ptr, size,
> +                                              /*checked*/ true);
> +       else
> +               kmsan_internal_poison_memory((void *)ptr, size, flags,
> +                                            KMSAN_POISON_CHECK);
> +       kmsan_leave_runtime();
> +}
> +EXPORT_SYMBOL(kmsan_kmalloc_large);
> +
> +void kmsan_kfree_large(const void *ptr)
> +{
> +       struct page *page;
> +
> +       if (!kmsan_enabled || kmsan_in_runtime())
> +               return;
> +       kmsan_enter_runtime();
> +       page = virt_to_head_page((void *)ptr);
> +       KMSAN_WARN_ON(ptr != page_address(page));
> +       kmsan_internal_poison_memory((void *)ptr,
> +                                    PAGE_SIZE << compound_order(page),
> +                                    GFP_KERNEL,
> +                                    KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
> +       kmsan_leave_runtime();
> +}
> +EXPORT_SYMBOL(kmsan_kfree_large);
> +
>  static unsigned long vmalloc_shadow(unsigned long addr)
>  {
>         return (unsigned long)kmsan_get_metadata((void *)addr,
> diff --git a/mm/slab.h b/mm/slab.h
> index db9fb5c8dae73..d0de8195873d8 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -752,6 +752,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
>                         memset(p[i], 0, s->object_size);
>                 kmemleak_alloc_recursive(p[i], s->object_size, 1,
>                                          s->flags, flags);
> +               kmsan_slab_alloc(s, p[i], flags);
>         }
>
>         memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
> diff --git a/mm/slub.c b/mm/slub.c
> index b1281b8654bd3..b8b601f165087 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -22,6 +22,7 @@
>  #include <linux/proc_fs.h>
>  #include <linux/seq_file.h>
>  #include <linux/kasan.h>
> +#include <linux/kmsan.h>
>  #include <linux/cpu.h>
>  #include <linux/cpuset.h>
>  #include <linux/mempolicy.h>
> @@ -359,6 +360,17 @@ static void prefetch_freepointer(const struct kmem_cache *s, void *object)
>         prefetchw(object + s->offset);
>  }
>
> +/*
> + * When running under KMSAN, get_freepointer_safe() may return an uninitialized
> + * pointer value in the case the current thread loses the race for the next
> + * memory chunk in the freelist. In that case this_cpu_cmpxchg_double() in
> + * slab_alloc_node() will fail, so the uninitialized value won't be used, but
> + * KMSAN will still check all arguments of cmpxchg because of imperfect
> + * handling of inline assembly.
> + * To work around this problem, we apply __no_kmsan_checks to ensure that
> + * get_freepointer_safe() returns initialized memory.
> + */
> +__no_kmsan_checks
>  static inline void *get_freepointer_safe(struct kmem_cache *s, void *object)
>  {
>         unsigned long freepointer_addr;
> @@ -1709,6 +1721,7 @@ static inline void *kmalloc_large_node_hook(void *ptr, size_t size, gfp_t flags)
>         ptr = kasan_kmalloc_large(ptr, size, flags);
>         /* As ptr might get tagged, call kmemleak hook after KASAN. */
>         kmemleak_alloc(ptr, size, 1, flags);
> +       kmsan_kmalloc_large(ptr, size, flags);
>         return ptr;
>  }
>
> @@ -1716,12 +1729,14 @@ static __always_inline void kfree_hook(void *x)
>  {
>         kmemleak_free(x);
>         kasan_kfree_large(x);
> +       kmsan_kfree_large(x);
>  }
>
>  static __always_inline bool slab_free_hook(struct kmem_cache *s,
>                                                 void *x, bool init)
>  {
>         kmemleak_free_recursive(x, s->flags);
> +       kmsan_slab_free(s, x);
>
>         debug_check_no_locks_freed(x, s->object_size);
>
> @@ -3756,6 +3771,7 @@ int kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags, size_t size,
>          */
>         slab_post_alloc_hook(s, objcg, flags, size, p,
>                                 slab_want_init_on_alloc(flags, s));
> +

Remove unnecessary whitespace change.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOJ-2xim3KM%3D9O%3DsfSgQXZi81R6PQj%3DantfHnejaOOogg%40mail.gmail.com.
