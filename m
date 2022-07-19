Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5NQ3KLAMGQEVWQSJXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D9045798A8
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 13:41:43 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id e11-20020a17090301cb00b0016c3375abd3sf8437498plh.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 04:41:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658230902; cv=pass;
        d=google.com; s=arc-20160816;
        b=CbLURwbYREVNNL864HkW2ft0InAZV7CIuSBtpl1oM/JZcejBRghNlaSKixiXMhQoLh
         nFsfl8BM3j+p9+57169BOVBb76XIAxoXLJu+S1XiNcHRNlUnYWy/Tq9nKtA35k6AN9Ol
         4TKkwf124nXbjGgZWL8HZY++tuCn5XpfLGcom/vVE6LQeIwchVbGrXgCYT6BLgH8mUUE
         QBdJ6SXQw/vD/27cd072FYDcyA5XvMleYXbMJIlv2NJb4yRcB9Sz4xkTFrerG/dQGn6L
         GqaKvDP3AfJFR1ekLpwH1e7yWTPUlVsWODbIoGORq7yOMsOen8yUfbu503GUXmmu1+FZ
         wtNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GxiX2gKATU8V5/WO37MOxpWN8WbYo5Z6tS/fvGQCMAQ=;
        b=yg4QHf00Y0rsH2mh+o9PG4j+yVvRZYQlopFVQFNAgQh4oS/EOUSPAA3PTU9nrR2KrW
         KZys1yic22kS1mdK7K11LHLvqakIRowEkEmfDSKWOIVE0vHgXVSaTLZXpBRfRiXL5qsQ
         ImdVmSMpISMk66J/mMgOZHwmmi4ts3wUX52EuKMvDexL7K2wqoGLlPdZpPQdCuk83C9U
         Hj4+/Z8Otom+uwXXbY4/tAXvP6y6tjIaJYuOdrzsWwLfJ8PGK2Q0NS2y9YDkiQbFNRY9
         eEaSEzvJvA7n6MULvuwf5ayyZsXR6SznoQKL4Qhz7imfPYutM8mLnUh6ySFcbHz5RwT/
         KF1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mXoGlvDq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GxiX2gKATU8V5/WO37MOxpWN8WbYo5Z6tS/fvGQCMAQ=;
        b=nrRb4k8zHul6T/NrHyz1h572yNDN0O/DBlQd71enlwTV8ks8SdWzER9A9V/ZCr2Xdv
         ItGFhPX0diC4MPBnh09wZBW7hWDs4Qj+SVcee8iz8mSLUiiqUKiehEmyp/vIyKxPFdwT
         jFjOOZLzEmE+yFgGJ4W7wEFE/0hQM3XYawGGX914fWekR/FV6lZRTcFBARaIsYEi4RRw
         815LDfacS8cfeeCLjGf1sUzgZp1WX0eWR9sv+HiVzn6O238oOlcKiIZ9/m88M1TFungh
         qcb0EKE0Zp+jT/EDMIIqxkU4lSY/O7XWjzzljgovZh8+CKZoCxvyli7kaiXggocXkiKY
         FR4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GxiX2gKATU8V5/WO37MOxpWN8WbYo5Z6tS/fvGQCMAQ=;
        b=yvCWwD15xC5tEFuakXs5/Wq+FyHsiFXzVkvxARAh7bn8veSd7AfhHk5MOK3BlPIuSx
         jNKKxWIn1TQ6+DpNngoowFRAWyL+KMa/Q/Ki8cWipF+7qQlSKuJT7tirpfB9WiUmhxJS
         sEgB/V6n9MZX3NmJG312uZQYZkFgMBRgQjm8xARJr4C3b0FHb5z29tRJ3hz+K0P1TI7m
         Y7iEJ9KFdfS71+/t9yjsF7uFZxpnogVGDH97sKzDYpa42qjjebgESWCeygR2EaehWCjz
         eqKyInoA38MK5zzpF55LMVKe8SPuXslCJFoq84o9h5GVny9NMe4v8SDSl8GcFG9fBvI1
         htSw==
X-Gm-Message-State: AJIora9Nvnh4LSWoFSASspfn84YsITKm4OdZS9Blxq15wUNdMUnv3YtF
	bp12z+AvIPr8Urv1vaIF6Bo=
X-Google-Smtp-Source: AGRyM1uQD3ubo15wTaJvYHyoG5h4ciiQxMZG9MopDcQbWqY1LY8QjwqgPROzPr8E3yWicxpX4jrkmw==
X-Received: by 2002:a17:90b:2241:b0:1f0:2fa5:184f with SMTP id hk1-20020a17090b224100b001f02fa5184fmr44340951pjb.97.1658230901589;
        Tue, 19 Jul 2022 04:41:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:864a:0:b0:419:d02c:289b with SMTP id x71-20020a63864a000000b00419d02c289bls4695262pgd.9.gmail;
 Tue, 19 Jul 2022 04:41:40 -0700 (PDT)
X-Received: by 2002:a05:6a00:1d26:b0:528:3a25:ea3c with SMTP id a38-20020a056a001d2600b005283a25ea3cmr33030337pfx.67.1658230900690;
        Tue, 19 Jul 2022 04:41:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658230900; cv=none;
        d=google.com; s=arc-20160816;
        b=cMa/7SpC+unhWqFfwogbOYXU2ct1FYNAlzbzL1JTnRxk/KlIViLym2XJzy5uUR3Vm4
         n+BhVU4/E6f1UEh6ObExExff/Z31Bqru+p3MQ3R4moPOc0dTZSXWGzb5i3j4UQlh6ypF
         puCArrlT4Q9aIdGenvWqi9rK85wRXdM+FgV9/Q1TP2PDw0zEjeuAoYQw1Lsl9NUueDxI
         ISDe4HIePFarHvTKlbXkjAcwWCGyT4vVxSt0T6lZFoAyaVxGv4+CD5aztcSr1oX0IhM/
         PMfIr8I0rrps//QWzb+CZxp9YvKUaUU64b1sS7iJ+2Jnt1yCM97UixN2mqSgOIg9EszG
         dZQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xi609iWd+t1xpxJ70rNlw8Yfb5LgcoJNw18fVkapUSc=;
        b=a2Huuw2+suH+VAAViF/h6bdH4/fAz+n3gImXg203owOaMO0b2ZcBRfxQ7jN+pUVpZU
         DWOJwnatEzoCzobsK6H8ekE5SL7p89S320lda1vDgnT0LDZji4VtEGiW9gnmmh88ekU2
         kZoT+Q/B67U9/c6z3Xn3V0CwVJcV3hK8uR8PYbckthI3mW5hzeUDfqXFDgyUfv7EYGRq
         iod8btfpi9ZfZugbPi+guL7bORXnceCiup3nxKQEvfRNXljVjqIZPAEyGR4bC4Q9oOXZ
         fDFaqUmud/W14ndEnaE66+sEaPwZxJY3oueSYLdgYdehzIAn/wa0FZVGUZEAH/M/M3GZ
         rV3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mXoGlvDq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1134.google.com (mail-yw1-x1134.google.com. [2607:f8b0:4864:20::1134])
        by gmr-mx.google.com with ESMTPS id p28-20020a056a0026dc00b0052b62393657si272971pfw.4.2022.07.19.04.41.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jul 2022 04:41:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) client-ip=2607:f8b0:4864:20::1134;
Received: by mail-yw1-x1134.google.com with SMTP id 00721157ae682-31d85f82f0bso137427187b3.7
        for <kasan-dev@googlegroups.com>; Tue, 19 Jul 2022 04:41:40 -0700 (PDT)
X-Received: by 2002:a0d:e60d:0:b0:31c:8046:8ff with SMTP id
 p13-20020a0de60d000000b0031c804608ffmr36027909ywe.412.1658230900185; Tue, 19
 Jul 2022 04:41:40 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1658189199.git.andreyknvl@google.com> <0e910197bfbcf505122f6dae2ee9b90ff8ee31f7.1658189199.git.andreyknvl@google.com>
In-Reply-To: <0e910197bfbcf505122f6dae2ee9b90ff8ee31f7.1658189199.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jul 2022 13:41:04 +0200
Message-ID: <CANpmjNMrwXxU0YCwvHo59RFDkoxA-MtdrRCSPoRW+KYG2ez-NQ@mail.gmail.com>
Subject: Re: [PATCH mm v2 30/33] kasan: implement stack ring for tag-based modes
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mXoGlvDq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as
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

On Tue, 19 Jul 2022 at 02:15, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Implement storing stack depot handles for alloc/free stack traces for
> slab objects for the tag-based KASAN modes in a ring buffer.
>
> This ring buffer is referred to as the stack ring.
>
> On each alloc/free of a slab object, the tagged address of the object and
> the current stack trace are recorded in the stack ring.
>
> On each bug report, if the accessed address belongs to a slab object, the
> stack ring is scanned for matching entries. The newest entries are used to
> print the alloc/free stack traces in the report: one entry for alloc and
> one for free.
>
> The number of entries in the stack ring is fixed in this patch, but one of
> the following patches adds a command-line argument to control it.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> ---
>
> Changes v1->v2:
> - Only use the atomic type for pos, use READ/WRITE_ONCE() for the rest.
> - Rename KASAN_STACK_RING_ENTRIES to KASAN_STACK_RING_SIZE.
> - Rename object local variable in kasan_complete_mode_report_info() to
>   ptr to match the name in kasan_stack_ring_entry.
> - Detect stack ring entry slots that are being written to.
> - Use read-write lock to disallow reading half-written stack ring entries.
> - Add a comment about the stack ring being best-effort.
> ---
>  mm/kasan/kasan.h       | 21 ++++++++++++
>  mm/kasan/report_tags.c | 76 ++++++++++++++++++++++++++++++++++++++++++
>  mm/kasan/tags.c        | 50 +++++++++++++++++++++++++++
>  3 files changed, 147 insertions(+)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 7df107dc400a..cfff81139d67 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -2,6 +2,7 @@
>  #ifndef __MM_KASAN_KASAN_H
>  #define __MM_KASAN_KASAN_H
>
> +#include <linux/atomic.h>
>  #include <linux/kasan.h>
>  #include <linux/kasan-tags.h>
>  #include <linux/kfence.h>
> @@ -233,6 +234,26 @@ struct kasan_free_meta {
>
>  #endif /* CONFIG_KASAN_GENERIC */
>
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> +
> +struct kasan_stack_ring_entry {
> +       void *ptr;
> +       size_t size;
> +       u32 pid;
> +       depot_stack_handle_t stack;
> +       bool is_free;
> +};
> +
> +#define KASAN_STACK_RING_SIZE (32 << 10)
> +
> +struct kasan_stack_ring {
> +       rwlock_t lock;
> +       atomic64_t pos;
> +       struct kasan_stack_ring_entry entries[KASAN_STACK_RING_SIZE];
> +};
> +
> +#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
> +
>  #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>  /* Used in KUnit-compatible KASAN tests. */
>  struct kunit_kasan_status {
> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
> index 5cbac2cdb177..a996489e6dac 100644
> --- a/mm/kasan/report_tags.c
> +++ b/mm/kasan/report_tags.c
> @@ -4,8 +4,12 @@
>   * Copyright (c) 2020 Google, Inc.
>   */
>
> +#include <linux/atomic.h>
> +
>  #include "kasan.h"
>
> +extern struct kasan_stack_ring stack_ring;
> +
>  static const char *get_bug_type(struct kasan_report_info *info)
>  {
>         /*
> @@ -24,5 +28,77 @@ static const char *get_bug_type(struct kasan_report_info *info)
>
>  void kasan_complete_mode_report_info(struct kasan_report_info *info)
>  {
> +       unsigned long flags;
> +       u64 pos;
> +       struct kasan_stack_ring_entry *entry;
> +       void *ptr;
> +       u32 pid;
> +       depot_stack_handle_t stack;
> +       bool is_free;
> +       bool alloc_found = false, free_found = false;
> +
>         info->bug_type = get_bug_type(info);
> +
> +       if (!info->cache || !info->object)
> +               return;
> +       }
> +
> +       write_lock_irqsave(&stack_ring.lock, flags);
> +
> +       pos = atomic64_read(&stack_ring.pos);
> +
> +       /*
> +        * The loop below tries to find stack ring entries relevant to the
> +        * buggy object. This is a best-effort process.
> +        *
> +        * First, another object with the same tag can be allocated in place of
> +        * the buggy object. Also, since the number of entries is limited, the
> +        * entries relevant to the buggy object can be overwritten.
> +        */
> +
> +       for (u64 i = pos - 1; i != pos - 1 - KASAN_STACK_RING_SIZE; i--) {
> +               if (alloc_found && free_found)
> +                       break;
> +
> +               entry = &stack_ring.entries[i % KASAN_STACK_RING_SIZE];
> +
> +               /* Paired with smp_store_release() in save_stack_info(). */
> +               ptr = (void *)smp_load_acquire(&entry->ptr);
> +
> +               if (kasan_reset_tag(ptr) != info->object ||
> +                   get_tag(ptr) != get_tag(info->access_addr))
> +                       continue;
> +
> +               pid = READ_ONCE(entry->pid);
> +               stack = READ_ONCE(entry->stack);
> +               is_free = READ_ONCE(entry->is_free);
> +
> +               /* Try detecting if the entry was changed while being read. */
> +               smp_mb();
> +               if (ptr != (void *)READ_ONCE(entry->ptr))
> +                       continue;

I thought the re-validation is no longer needed because of the rwlock
protection?

The rest looks fine now.

> +               if (is_free) {
> +                       /*
> +                        * Second free of the same object.
> +                        * Give up on trying to find the alloc entry.
> +                        */
> +                       if (free_found)
> +                               break;
> +
> +                       info->free_track.pid = pid;
> +                       info->free_track.stack = stack;
> +                       free_found = true;
> +               } else {
> +                       /* Second alloc of the same object. Give up. */
> +                       if (alloc_found)
> +                               break;
> +
> +                       info->alloc_track.pid = pid;
> +                       info->alloc_track.stack = stack;
> +                       alloc_found = true;
> +               }
> +       }
> +
> +       write_unlock_irqrestore(&stack_ring.lock, flags);
>  }
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 39a0481e5228..07828021c1f5 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -6,6 +6,7 @@
>   * Copyright (c) 2020 Google, Inc.
>   */
>
> +#include <linux/atomic.h>
>  #include <linux/init.h>
>  #include <linux/kasan.h>
>  #include <linux/kernel.h>
> @@ -16,11 +17,60 @@
>  #include <linux/types.h>
>
>  #include "kasan.h"
> +#include "../slab.h"
> +
> +/* Non-zero, as initial pointer values are 0. */
> +#define STACK_RING_BUSY_PTR ((void *)1)
> +
> +struct kasan_stack_ring stack_ring;
> +
> +static void save_stack_info(struct kmem_cache *cache, void *object,
> +                       gfp_t gfp_flags, bool is_free)
> +{
> +       unsigned long flags;
> +       depot_stack_handle_t stack;
> +       u64 pos;
> +       struct kasan_stack_ring_entry *entry;
> +       void *old_ptr;
> +
> +       stack = kasan_save_stack(gfp_flags, true);
> +
> +       /*
> +        * Prevent save_stack_info() from modifying stack ring
> +        * when kasan_complete_mode_report_info() is walking it.
> +        */
> +       read_lock_irqsave(&stack_ring.lock, flags);
> +
> +next:
> +       pos = atomic64_fetch_add(1, &stack_ring.pos);
> +       entry = &stack_ring.entries[pos % KASAN_STACK_RING_SIZE];
> +
> +       /* Detect stack ring entry slots that are being written to. */
> +       old_ptr = READ_ONCE(entry->ptr);
> +       if (old_ptr == STACK_RING_BUSY_PTR)
> +               goto next; /* Busy slot. */
> +       if (!try_cmpxchg(&entry->ptr, &old_ptr, STACK_RING_BUSY_PTR))
> +               goto next; /* Busy slot. */
> +
> +       WRITE_ONCE(entry->size, cache->object_size);
> +       WRITE_ONCE(entry->pid, current->pid);
> +       WRITE_ONCE(entry->stack, stack);
> +       WRITE_ONCE(entry->is_free, is_free);
> +
> +       /*
> +        * Paired with smp_load_acquire() in kasan_complete_mode_report_info().
> +        */
> +       smp_store_release(&entry->ptr, (s64)object);
> +
> +       read_unlock_irqrestore(&stack_ring.lock, flags);
> +}
>
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
>  {
> +       save_stack_info(cache, object, flags, false);
>  }
>
>  void kasan_save_free_info(struct kmem_cache *cache, void *object)
>  {
> +       save_stack_info(cache, object, GFP_NOWAIT, true);
>  }
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMrwXxU0YCwvHo59RFDkoxA-MtdrRCSPoRW%2BKYG2ez-NQ%40mail.gmail.com.
