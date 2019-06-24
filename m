Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEPQYLUAKGQE4HB3FSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id D916250A0A
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2019 13:46:26 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id p43sf16595867qtk.23
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2019 04:46:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561376786; cv=pass;
        d=google.com; s=arc-20160816;
        b=TAQEgPk6lElO+WWOHYcU6FJ3ghxzkl/Kq93J2PcUD0FkIM4GK2O2napzxijD2wYMd2
         COrZnaAe3cqKbZK4k+7aZ9K/18n1/X2FYlad4sZ09JCXPztF1CsAyKdUazqEczuSMkNB
         hHMLtBzhBeSB2Gpftv0rOvbAIq91Pmmo+k2bW/FpHR23QuF7HkA6siKAM7Jq4kvKB9Xb
         zPqFKCANXNBeC6ijzMMc2/SqG801fy3Hc43cphh36lwlPUAOOAlA4mzh+HuyIXilwUj6
         mNgPXEcCv2LoYYhfqkFafQOm+572Koq8il+zUE+ECmxRZFUb4Bbc9eTa3wFmd4Co+9jU
         LaCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=EaMVcFKXjPt0x3tG5emV6FHKNHdv+TJX+5PpGqRYGOw=;
        b=wmdV6FxSD0OaLScF3g9+msTOVrolcKpFllb5e2i0pLIuCiVFhDRlaD3MiThb93AYAo
         KU3RuzzGQq6oNsWrbE9uRKRiAI4iUlynquviuubb9P7nqavu+71uXhsVPcNyS872071c
         zX7Nm80wfNutmbwsrKJZT4TzV6JGY+ubiFQVzaPi3UMInrb0rSzaaqmwh6vkq7yaRAWm
         oh0OsX8IpcBhZZWa27rbljLoLdh7V/ZIIYHFT9bMdltdUKNafB8+tWWrlueo6sSa/siR
         vPcwptOfBKtfdpZBWeT9R5P6LNg0SJdRMCOVuSEi2ijkJLPQZuq1AnqQ1w08UZ3I5nL2
         q2Jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sm2RVRXA;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EaMVcFKXjPt0x3tG5emV6FHKNHdv+TJX+5PpGqRYGOw=;
        b=fVao7dFFArVTBLSw7fcgQz+dPXwrbv9+svjeJpAFoXCuEzNjCc3QwDLGQIZwjyjJtx
         EE0qxJXl2STrqMkI2LMN/dxfMjfFtTevOck4bvuo3pVoATM48Gwwlr75lXuzF86QyPqk
         aFTuB6aM4wtLvORFaymbWoiZILUWseU2c/6T5j7dGpwaoWiBeb0lW2YHlYQQFwQiMStY
         PbnlwqhpwvJHGqYUsRpq19rSsRlJhOrFalFXU+wrh7nzcVtJ8upL0gycNPQ4spjX4jGO
         wbvhEf5JNXCxOnSHOoV06vdQ+on2cf8+trlQ3m1WI2KOnJ9VVlzdnYrOx09s1LCwfMsO
         ss2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EaMVcFKXjPt0x3tG5emV6FHKNHdv+TJX+5PpGqRYGOw=;
        b=p28sCvpqTxExgm0x6sLQKAs+BEfZ58Vwh9skCH2ICsUgdrFDakJ43w7JUyNGRnM1KY
         7MMswOvrAFabBGDmVfRw2IuQg9nkt8wsU4kNIQw17QMck/MP+5EJ8P2PIR6giiL1CEnY
         aHCqdu4VMrhAt1dxI/C6kuDxJDShGMeScWLPL4DtS2k0VpQXMZ02u3qnkC6bhQxzYp10
         3dkMmaIos7yzF2BO+5OY8Q1K+esfLvqz9lLWKD99/H5B+qiIfwVFlMDy+G1FrhVNnCsc
         zmdD6lQq7Wh8DsYmuEM/oTLFcvUIWmnDtdRcqfbLkAj+iqnXSN5+ETLw80mU8MKUyde1
         wUMQ==
X-Gm-Message-State: APjAAAX9AJFGAMOE7aK5a2GxYhIzgmCFBgMEjdx06euogl1PgtMHJ+yP
	igE//wYKC02BrfAlXu72+Ho=
X-Google-Smtp-Source: APXvYqzLZEs5YCgPMRPbOEBDjN54savplpGqJYoBOIebPIuiEiqHA0UeNlJmmx4cnyYm8gZdFTmNFA==
X-Received: by 2002:a05:620a:522:: with SMTP id h2mr94802444qkh.329.1561376785967;
        Mon, 24 Jun 2019 04:46:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4f85:: with SMTP id d127ls669675qkb.4.gmail; Mon, 24 Jun
 2019 04:46:25 -0700 (PDT)
X-Received: by 2002:a37:2750:: with SMTP id n77mr17125770qkn.370.1561376785736;
        Mon, 24 Jun 2019 04:46:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561376785; cv=none;
        d=google.com; s=arc-20160816;
        b=xzRp5hF5KEPr5icmo/8pBebUnb/ZjqnkAKO54TF0zvcJ/UiRAk8LgkUxHBAZB0UCTQ
         aAmPk31Ur6+5jg77M7cGKkYZKiFLbrIjmj6A+jf/tnBlvayVxB8TdqrU1oXJ+1UWynVy
         DhTBDcs0aMvn98vXOYaU0tPZEog8QR/P7l5xPQwKkrtdxeJ6UYnFeNlp7v0pofCrk0Jk
         GQoNdIg9r8VE/7w6EBhfgUFLnv0T6L1sFp3+1Z5pa6727YjgPEf2HyE0ldX4NPHtAH4j
         rG+1G8CusfDFe3bHUQH4dPFRrUcNPez7TTBxD0+3/3CNA9L7H+v8SdE7eyyd/itVOyhA
         6ZVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4sCioPXlb29uCUXcWaSeu3ouKfJt5j/bFJ2w/CyNw2c=;
        b=Jsgfui/mWCadrB9FrcHHMie4ELN+r5JldDdZrnW0JJtNvM9NEzbr9ps1jTUe2C2XBB
         sVUoZxc5c+Y/npIbWs//H+tQHNT6OEDipXVa2OOsEQsqmPJGzuDBpGUHtHIg/VlnFsbx
         /uCK61Signu4hOJ50ptTKtDVsXSQ4qweamIm/5AT1FXC32GiQXg6j6cH+F3YK+ASBzyW
         sY2wINzXLzTirqsdP+X47qBh6V6JYD746+62B08GCCGrVRKWFDlKJDJZhtBDyl+kzaSC
         Acpi7ckfsqjz3OL6bU3g8uq8jPbU7tbncKhDv2LSr+brjdbuKaww8otlecFRJj52Dr8W
         xDNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sm2RVRXA;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id a79si818202qkb.1.2019.06.24.04.46.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jun 2019 04:46:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id c14so6744831plo.0
        for <kasan-dev@googlegroups.com>; Mon, 24 Jun 2019 04:46:25 -0700 (PDT)
X-Received: by 2002:a17:902:4183:: with SMTP id f3mr31396406pld.336.1561376784423;
 Mon, 24 Jun 2019 04:46:24 -0700 (PDT)
MIME-Version: 1.0
References: <20190624110532.41065-1-elver@google.com>
In-Reply-To: <20190624110532.41065-1-elver@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Jun 2019 13:46:12 +0200
Message-ID: <CAAeHK+w5oNt+3wvHr2W2+ikd8J=psk2YSjRSARF4P+W7UgUX_Q@mail.gmail.com>
Subject: Re: [PATCH] mm/kasan: Add shadow memory validation in ksize()
To: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sm2RVRXA;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::644
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

The tag variable is not used any more in this function, right? If so,
it can be removed.

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
> +               /*
> +                * We assume that ksize callers could use whole allocated area,
> +                * so we need to unpoison this area.
> +                */
> +               kasan_unpoison_shadow(object, size);
> +       }

I think it's better to add a kasan_ksize() hook that implements this
logic. This way we don't have to duplicate it for SLAB and SLUB.

In this case we also don't need an exported kasan_shadow_invalid()
hook, and its logic can be moved into shadow_invalid().

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw5oNt%2B3wvHr2W2%2Bikd8J%3Dpsk2YSjRSARF4P%2BW7UgUX_Q%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
