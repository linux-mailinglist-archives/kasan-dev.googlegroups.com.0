Return-Path: <kasan-dev+bncBCMIZB7QWENRB77PYLUAKGQEXELQLNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E01B50A08
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2019 13:46:08 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id r58sf16729679qtb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2019 04:46:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561376767; cv=pass;
        d=google.com; s=arc-20160816;
        b=MMKIfPfHCF4NvAelY0ZQCmb8YrGrJ8POTZFnMur02/IY+gDJviFJgBAnKptuxTzsXo
         iXZ4dnVzLx8ug8NtcDtbN+TjLr67KSVTpKkw1zcydybC1ZJundfExFED3Twa8mdaJAre
         yAt3KWytuekZt68HV3/hxHhytFgiRPRSk0mHTLlHG47776u0OLq0m829TXD9cctK+LTu
         rF0gKnQkWykldjMfulxS2+9piwNeGSEGK0uBIvEJ1AFK/J3LHp146gnQ1RQopIHFtgFn
         ydGxMxEJSLU/ASFnyH+4HBl7O8rV+ySeiRbd0R2og8MMstQJkfNfqEA2ORnHuVwFkJUF
         j9Dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gXBnwpottI0rnjsrsmQyS2D1UGb6jYQJ8W2UQ+sE6NY=;
        b=rAaQ6tlE8nSiM48PIFJI2oZib/dDYTPZOJmsQygBpuwg3jL7G5w8HnYXbvmjXqKwxj
         BOftA6x8zkZnf/gsALOa2hPq2pzdQd22NGcog+szkww6FZjPTyDIzSlQMP7sb0aqhZ3a
         0Cly5GS3JtJhUyyAAx4ZOSR82XDN269Z+dtXbhJze9aDFc3nhJDg59sWyaVerPNvbj17
         eSMYmislG+gqckdAQVXCgb9JnvUAXkIOD9j9ZUYqUgoikVu0UkPWqkukOoOaroxtrXyc
         AgOWb+IUq6E81tYA6t0CkXvzGr6yfPdDedcytE52h8DRKCMCKurBVm0FFYL7f7TrOAzu
         iyCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="c/f5f/Ez";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gXBnwpottI0rnjsrsmQyS2D1UGb6jYQJ8W2UQ+sE6NY=;
        b=hQ7+1fXK3+N9KtczE1Xtup67ECLh1656E5swp+AeWyvh0uz4TlbO+WMQ2vmLWzsAl2
         WoNyP2gqXjXdz611rQhmq7sMjU5AySJZ8DtsubwPPCtpkh7Fn/FcPGN3E1UqdmQefrIg
         CAUnuNAFjK6vEkbyfFUGh/4KWVyTmUDPXBNU3KKb4CzF7tWlNuSt/GPcrOc0avY5c/HF
         542y3lx/ajAYoaTAQ9NRDACqa0A+pfJEFaPuJ/2HClh6Vv4tNBAdR5OJZuFjljkTxu+E
         +SAFmZiQLoPSmYa7lqwlzfED6KWZaQNbpJtem3k1M0yLBVkBhX8Ub53L9EXRknOZtnKV
         aCgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gXBnwpottI0rnjsrsmQyS2D1UGb6jYQJ8W2UQ+sE6NY=;
        b=bCJyHkTQXKBxUKgYI2qJgPtVzLErV647tNYRsWa9XoHEgNljk2Xuolqg1jO9yNyEZ/
         wTvySU8YXk0f1It1M8HSUuV/io5OlF6/yLMNfziUtkKIRm+F6akbqs0UdwXs3ZzahvV9
         svtfbgANlJ6JpAY+e+BZY0yA1S/+eGmU5anqSddEnROWwJu+tw1q6XaK98+C4Pf5d3jU
         e1lSMppGWsm2G6xBX8udW73gtbwhIn0+Sll1ZWWQ+bzBFSwZocpSt+p2+Dn0L5rvoXX6
         Yn1LeqZpEYVUACwS2Pd86MzBbZdbDo178Xm4FTN1oiKzbR9tvM87J6Q+eObLIrWJMSt1
         IUXA==
X-Gm-Message-State: APjAAAWym+Vkc1fv+aTb46CiJYeHzVkHu1bt1VK4FVOB4nuf9Ih27iAt
	YpZbJxXtUlFoxIjkiJOBYv0=
X-Google-Smtp-Source: APXvYqxEoTBFSkgY4mNaYC1I/iBnX/1TbP0cu9S5FMqXiTQ9LXBCERaGxFOOAQyFuCYEzzXsyEfj1Q==
X-Received: by 2002:ae9:df07:: with SMTP id t7mr119465576qkf.193.1561376767142;
        Mon, 24 Jun 2019 04:46:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9741:: with SMTP id z62ls672842qkd.12.gmail; Mon, 24 Jun
 2019 04:46:06 -0700 (PDT)
X-Received: by 2002:ae9:c108:: with SMTP id z8mr60218478qki.57.1561376766929;
        Mon, 24 Jun 2019 04:46:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561376766; cv=none;
        d=google.com; s=arc-20160816;
        b=wXop3GUjKa7iri3wauVXMTIGbbTAcfuqPi2LupDML8YgpT7NvIjMRBmDYhQ90XePex
         09/bHSK2UOSgbABjU+WAjqiWEPSRxQb0lHaaxUxH7ONNzLOljhJ6ypullORcf47Qyr3p
         ++aQ8K5AHtqVBk+DSZOIf70y44z2WOYUPGUmHxcSl1WhA07cEAm8Q3/xn38GYNJKD0cr
         30nRke4icJ3byy0Fv0bmpbNDsBsmqj7vtumbmDVWgKAxiYVpyFGj+94O2ghKkWQ39zNt
         VhMAdf3Zlg7lsxW6EdtN52a3QZAw5nB/oG+4uhth64bhYdBFxpI16ULZV6fEq7LVAdQ6
         yP2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xjyC1woOCk6QoSm3J7dmvFYHQ65jTUd0WwHup6buLdA=;
        b=oJZgM29HLXJceYUelQRqb9S1GR2N85GcewtRPE61Js3FpbNkmERkF6B05ERB7I3MuD
         89NCYeJ/B23pvfc1zABe1O5Gjct8MHN/A8isJ+3KbY6v7WF8Tnm0MBlF8F5ya3m9+URM
         MqMBR/ZYoammtWRf3gU9xHZ9ABZ1ovGgL5dZWbgWzO/Wrpgt5NJFFlP8ipozEQGvfTH+
         KM0CJIQm/9KLmXnPxOQgh5AyXCRgTzjBCKMog83CRU9iGevcdxPyof2ucvaasn9c/Nju
         +z86S1ed6rJI/WZWej1b2qxPdfUds4ov0V519NgsR60AQAV+fLeF5p/rO2bZmBChUUWG
         Mlmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="c/f5f/Ez";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd41.google.com (mail-io1-xd41.google.com. [2607:f8b0:4864:20::d41])
        by gmr-mx.google.com with ESMTPS id u124si780628qkb.5.2019.06.24.04.46.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jun 2019 04:46:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d41 as permitted sender) client-ip=2607:f8b0:4864:20::d41;
Received: by mail-io1-xd41.google.com with SMTP id e3so824156ioc.12
        for <kasan-dev@googlegroups.com>; Mon, 24 Jun 2019 04:46:06 -0700 (PDT)
X-Received: by 2002:a6b:4101:: with SMTP id n1mr14151102ioa.138.1561376765960;
 Mon, 24 Jun 2019 04:46:05 -0700 (PDT)
MIME-Version: 1.0
References: <20190624110532.41065-1-elver@google.com>
In-Reply-To: <20190624110532.41065-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Jun 2019 13:45:53 +0200
Message-ID: <CACT4Y+ZP4gkLh5zbwSLzV+ZwJCq_zSrsaQE+1Y94iU0JJzJNqw@mail.gmail.com>
Subject: Re: [PATCH] mm/kasan: Add shadow memory validation in ksize()
To: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="c/f5f/Ez";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d41
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, Jun 24, 2019 at 1:05 PM Marco Elver <elver@google.com> wrote:
>
> ksize() has been unconditionally unpoisoning the whole shadow memory region
> associated with an allocation. This can lead to various undetected bugs,
> for example, double-kzfree().
>
> kzfree() uses ksize() to determine the actual allocation size, and
> subsequently zeroes the memory. Since ksize() used to just unpoison the
> whole shadow memory region, no invalid free was detected.
>
> This patch addresses this as follows:
>
> 1. For each SLAB and SLUB allocators: add a check in ksize() that the
>    pointed to object's shadow memory is valid, and only then unpoison
>    the memory region.
>
> 2. Update kasan_unpoison_slab() to explicitly unpoison the shadow memory
>    region using the size obtained from ksize(); it is possible that
>    double-unpoison can occur if the shadow was already valid, however,
>    this should not be the general case.
>
> Tested:
> 1. With SLAB allocator: a) normal boot without warnings; b) verified the
>    added double-kzfree() is detected.
> 2. With SLUB allocator: a) normal boot without warnings; b) verified the
>    added double-kzfree() is detected.
>
> Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=199359
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Cc: Christoph Lameter <cl@linux.com>
> Cc: Pekka Enberg <penberg@kernel.org>
> Cc: David Rientjes <rientjes@google.com>
> Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-kernel@vger.kernel.org
> Cc: linux-mm@kvack.org
> ---
>  include/linux/kasan.h | 20 +++++++++++++++++++-
>  lib/test_kasan.c      | 17 +++++++++++++++++
>  mm/kasan/common.c     | 15 ++++++++++++---
>  mm/slab.c             | 12 ++++++++----
>  mm/slub.c             | 11 +++++++----
>  5 files changed, 63 insertions(+), 12 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index b40ea104dd36..9778a68fb5cf 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -63,6 +63,14 @@ void * __must_check kasan_krealloc(const void *object, size_t new_size,
>
>  void * __must_check kasan_slab_alloc(struct kmem_cache *s, void *object,
>                                         gfp_t flags);
> +
> +/**
> + * kasan_shadow_invalid - Check if shadow memory of object is invalid.
> + * @object: The pointed to object; the object pointer may be tagged.
> + * @return: true if shadow is invalid, false if valid.
> + */
> +bool kasan_shadow_invalid(const void *object);
> +
>  bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
>
>  struct kasan_cache {
> @@ -77,7 +85,11 @@ int kasan_add_zero_shadow(void *start, unsigned long size);
>  void kasan_remove_zero_shadow(void *start, unsigned long size);
>
>  size_t ksize(const void *);
> -static inline void kasan_unpoison_slab(const void *ptr) { ksize(ptr); }
> +static inline void kasan_unpoison_slab(const void *ptr)
> +{
> +       /* Force unpoison: ksize() only unpoisons if shadow of ptr is valid. */
> +       kasan_unpoison_shadow(ptr, ksize(ptr));
> +}
>  size_t kasan_metadata_size(struct kmem_cache *cache);
>
>  bool kasan_save_enable_multi_shot(void);
> @@ -133,6 +145,12 @@ static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
>  {
>         return object;
>  }
> +
> +static inline bool kasan_shadow_invalid(const void *object)
> +{
> +       return false;
> +}
> +
>  static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
>                                    unsigned long ip)
>  {
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 7de2702621dc..9b710bfa84da 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -623,6 +623,22 @@ static noinline void __init kasan_strings(void)
>         strnlen(ptr, 1);
>  }
>
> +static noinline void __init kmalloc_pagealloc_double_kzfree(void)
> +{
> +       char *ptr;
> +       size_t size = 16;
> +
> +       pr_info("kmalloc pagealloc allocation: double-free (kzfree)\n");

This does not have anything to do with pagealloc, right?
If so, remove pagealloc here and in the function name. kzfree also
implies kmalloc, so this could be just double_kzfree().

> +       ptr = kmalloc(size, GFP_KERNEL);
> +       if (!ptr) {
> +               pr_err("Allocation failed\n");
> +               return;
> +       }
> +
> +       kzfree(ptr);
> +       kzfree(ptr);
> +}
> +
>  static int __init kmalloc_tests_init(void)
>  {
>         /*
> @@ -664,6 +680,7 @@ static int __init kmalloc_tests_init(void)
>         kasan_memchr();
>         kasan_memcmp();
>         kasan_strings();
> +       kmalloc_pagealloc_double_kzfree();
>
>         kasan_restore_multi_shot(multishot);
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 242fdc01aaa9..357e02e73163 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -413,10 +413,20 @@ static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
>                 return tag != (u8)shadow_byte;
>  }
>
> +bool kasan_shadow_invalid(const void *object)
> +{
> +       u8 tag = get_tag(object);
> +       s8 shadow_byte;
> +
> +       object = reset_tag(object);
> +
> +       shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(object));
> +       return shadow_invalid(tag, shadow_byte);
> +}
> +
>  static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>                               unsigned long ip, bool quarantine)
>  {
> -       s8 shadow_byte;
>         u8 tag;
>         void *tagged_object;
>         unsigned long rounded_up_size;
> @@ -435,8 +445,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>         if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
>                 return false;
>
> -       shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(object));
> -       if (shadow_invalid(tag, shadow_byte)) {
> +       if (kasan_shadow_invalid(tagged_object)) {
>                 kasan_report_invalid_free(tagged_object, ip);
>                 return true;
>         }
> diff --git a/mm/slab.c b/mm/slab.c
> index f7117ad9b3a3..3595348c401b 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -4226,10 +4226,14 @@ size_t ksize(const void *objp)
>                 return 0;
>
>         size = virt_to_cache(objp)->object_size;
> -       /* We assume that ksize callers could use the whole allocated area,
> -        * so we need to unpoison this area.
> -        */
> -       kasan_unpoison_shadow(objp, size);
> +
> +       if (!kasan_shadow_invalid(objp)) {
> +               /*
> +                * We assume that ksize callers could use the whole allocated
> +                * area, so we need to unpoison this area.
> +                */
> +               kasan_unpoison_shadow(objp, size);
> +       }
>
>         return size;
>  }
> diff --git a/mm/slub.c b/mm/slub.c
> index cd04dbd2b5d0..28231d30358e 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3921,10 +3921,13 @@ static size_t __ksize(const void *object)
>  size_t ksize(const void *object)
>  {
>         size_t size = __ksize(object);
> -       /* We assume that ksize callers could use whole allocated area,
> -        * so we need to unpoison this area.
> -        */
> -       kasan_unpoison_shadow(object, size);
> +       if (!kasan_shadow_invalid(object)) {


I am thinking if we should call kasan_check_read(object, 1) here...
This would not produce a double-free error (use-after-free read
instead), but conceptually why we would allow calling ksize on freed
objects? But more importantly, we just skip unpoisoning shadow, but we
still smash the object contents on the second kzfree, right? This
means that the heap is corrupted after running the tests. As far as I
remember we avoided corrupting heap in tests and in particular a
normal double-free does not. As of now we've smashed the quarantine
link, but if we move the free metadata back into the object (e.g. to
resolve https://bugzilla.kernel.org/show_bug.cgi?id=198437) we also
smash free metadata before we print the double free report (at the
very least we will fail to print free stack, and crash at worst).

Doing kasan_check_read() in ksize() will cause a report _before_ we
smashed the object at the cost of an imprecise report title.
And fixing all of the issues will require changing kzfree I think.


> +               /*
> +                * We assume that ksize callers could use whole allocated area,
> +                * so we need to unpoison this area.
> +                */
> +               kasan_unpoison_shadow(object, size);
> +       }
>         return size;
>  }
>  EXPORT_SYMBOL(ksize);
> --
> 2.22.0.410.gd8fdbe21b5-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZP4gkLh5zbwSLzV%2BZwJCq_zSrsaQE%2B1Y94iU0JJzJNqw%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
