Return-Path: <kasan-dev+bncBC7OBJGL2MHBBENV36AAMGQEDAJZZAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id 749D530A593
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 11:40:18 +0100 (CET)
Received: by mail-ua1-x939.google.com with SMTP id c46sf5519342uad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 02:40:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612176017; cv=pass;
        d=google.com; s=arc-20160816;
        b=M9rD1vUMWaPT50plMGS3fK+HiJ6tjUNDm09qvzUHTs/CpnF9GR6Jb5w+Rx/jLIrPYz
         fSjvS0awVZjy82ahM31tc9LZB2B1SrxA6FlptSxvIaakZfy3yzokHKI7SPeGHraPiKz6
         emKg77ii7CEH5M0SJNYlFTEbwJU73A/jzLTVXEKJETCLc1RBfwTEDXWNqYduSvo0Umu+
         5pxeHJLrbubsOah1e95Z8BTqv1dBLReXMqoJsJl82tPqM7ygQy7Qg8OrvPlk41Edr+Lq
         lsk7dKZiOSVkgagtBhBNNOqsY94fyycBeUupYUK0qRDl5YGj+IcLfYNgFs9D4nPGe5Js
         frMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uYgY0ug8w9qEcldyKyE5KNHkmiK/9HUO8m/mEbSXbCI=;
        b=smKjnxGFKdnMVGvnfwiq0SbGD42NNBi8aS/hKBh6pWH16JDpNbt5teqwSyXUiLmsRD
         L71pKtdZ48GnmtRw8KI1CrzymVhUh1gdSaHZypVNzEjEu93bfn72kDNjiZMfrMM6o9kq
         SZnMcfzizt9yTLTye1KFdhExJxuPz9mzr6TYXBsjE5+N3NFiIpv8k3r8XFZJeBX9y4JY
         T59QfpofdcbPBK/QH0LeeT7sxueK/U5nF5JKfDuqTGCFn+oB3KJ0JMgxv+cefuuvXjQ/
         0mru1OUaV/jLL5ke1N1oH6C2m0NHxiUoE3DBRSpHjiO9w670dqumUdoiRSOKFo59pYHr
         tU8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="J+G/5cHA";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uYgY0ug8w9qEcldyKyE5KNHkmiK/9HUO8m/mEbSXbCI=;
        b=A9pLbfERKVzz8XL40I+EuoghdSGCJUs6WsHvUziiX5hDUcsmjbSmAQ7MDLuV75JThq
         dyRPojEq0SteDqXHGkZQC4qGfayzfyE4jTq8gefeMGv4efpcjz5qYVqkzRE17Y1snZc/
         cLx9cCzWko6V5mQk646BIY6QZTYou6CeW3QxNxsVMO2cVXMnI9yu2WS7NACpkRtuCoKu
         kQtvldN/URfIbfQJchySaxZWKAl/g6j2MZaHCqvKjULeb7oHcIIMRLs/lA9hvFHykiWo
         cBhOacm2gcbhn1rx9yqlWrMG+eAh2AZcAGV8MGnSW0/8jqJcSIS+51xFJGZAtu3VFI/W
         g+7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uYgY0ug8w9qEcldyKyE5KNHkmiK/9HUO8m/mEbSXbCI=;
        b=i9J4Y3vWk/UCJfYhoTn/7AuWFSDp/E6PFeWIEYhH3GzqW2VB7OqPIOvCbmRmGr8CE3
         HibqF7yx5sVdR5WgHpP+13F04hV6/1A3YBKzXoiqZ6FPkpVIW0FJem6Udq2xmHy7WcSG
         q0fOcFGKN1ucB5r0XMONtuBNs9SCeh9wFJvUXJZ0nPo3VjoYoJ7a7JeAigAp55eLkmjV
         uT8NTzusLVfPMMImpWQhGTWKU5DVal+Z7+IKhCUjJffXRZBqNhU99Nxd896N4l53UiOM
         avoff+P32YRK4xAnWLULk4JG4CWIk2TwiINsVnbpASV34e19Nrw2hRfb5ux+mVWewYHq
         6vLQ==
X-Gm-Message-State: AOAM533E0Jqliyg5qSeyinjFep28OexgRvk1Sovlqs32AW3xNFp7QktE
	NNqDYD5SyDthbHUqSj1X+5w=
X-Google-Smtp-Source: ABdhPJz3lWWjN66FrXmROfQmIQSNood/IPDGi14xrr3nXBs3Yc1bF8BY/sh7P395Vux/e8PJjtAoDA==
X-Received: by 2002:a67:ea05:: with SMTP id g5mr8351916vso.47.1612176017519;
        Mon, 01 Feb 2021 02:40:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3641:: with SMTP id s1ls1210766uad.10.gmail; Mon, 01 Feb
 2021 02:40:17 -0800 (PST)
X-Received: by 2002:ab0:6cf3:: with SMTP id l19mr8497304uai.55.1612176016997;
        Mon, 01 Feb 2021 02:40:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612176016; cv=none;
        d=google.com; s=arc-20160816;
        b=UxEB6fwc9sF48tdYxEL2A3Tpc0Vs/PP7Kmryp5/RJ5iRU+gpLrsJ4V9BS/t6qEshSr
         5ppCuDWKw5zprEsDhpFPNu85+OwEClnt1fzaOY2pNc5+5ZMiMFpH/PUMZDC/LWZi4Dmi
         NJPbzV+JveHuPD83aOv95H7mEquQqr++YBMHeI0yJ5Bq6BJkkOAS4M6UQy/BzBCMtG3v
         OIwXGN5nGF5EBhPxqAjqmYetgFSbqoixMJ3mHXVK0YFuSB3dKKvLy7+5Z8Pu8RCxQa3X
         anYy1m35HTOlestPR+kTlZzRl+HqePi40YaDlUwQmLOtXuI2yzaRnlUzBjYZx4zvx7A+
         W2OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eZ3P7u3TRYoNHUYZqgM31be6IdJ5ULeRL5Xx+spxYug=;
        b=lHqu61LzHILjRV0FBAfPPAtH2GXoNqhWTuTtlhjLZD9r2gEgU+Xs4oioV9KrPKdm/e
         EL6c4o8kHRJFQoDS6vg66iJfgdN6nnObgV6aNAe+oWz/u4wDqrjIEDx6JK4VhuwRhUDj
         aGS+2A8peu75ylWvtR8eQ8tiZXaQylB5mMtvRIKa/d/uliJJ86JngO9H8fCdeG3tu032
         3p/9MiFlaPJybxgHLriomCwdHKyXrAdunyl0kCo2UYW1BKmM1TZgB1t4YzK/5IInLiu2
         9esPM1/ScZN4tMIvSL7gqYs1GiK8iJA1KGKLZDl7IJ7Dw7fpkbexPxHsc/rXE6+nll0V
         H0IA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="J+G/5cHA";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32b.google.com (mail-ot1-x32b.google.com. [2607:f8b0:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id h123si886064vkg.0.2021.02.01.02.40.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 02:40:16 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) client-ip=2607:f8b0:4864:20::32b;
Received: by mail-ot1-x32b.google.com with SMTP id f6so15736615ots.9
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 02:40:16 -0800 (PST)
X-Received: by 2002:a9d:4687:: with SMTP id z7mr11570191ote.233.1612176016311;
 Mon, 01 Feb 2021 02:40:16 -0800 (PST)
MIME-Version: 1.0
References: <9dc196006921b191d25d10f6e611316db7da2efc.1611946152.git.andreyknvl@google.com>
In-Reply-To: <9dc196006921b191d25d10f6e611316db7da2efc.1611946152.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 1 Feb 2021 11:40:05 +0100
Message-ID: <CANpmjNMWVHttcMsWs0g_US1FsXM_Fwi9A3GzW_gfitnVkR66SA@mail.gmail.com>
Subject: Re: [PATCH mm] kasan: untag addresses for KFENCE
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="J+G/5cHA";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as
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

On Fri, 29 Jan 2021 at 19:50, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> KFENCE annotations operate on untagged addresses.
>
> Untag addresses in KASAN runtime where they might be tagged.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

Thank you!

> ---
>
> This can be squashed into:
>
> revert kasan-remove-kfence-leftovers
> kfence, kasan: make KFENCE compatible with KASA
>
> ---
>  mm/kasan/common.c |  2 +-
>  mm/kasan/kasan.h  | 12 +++++++++---
>  2 files changed, 10 insertions(+), 4 deletions(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index a390fae9d64b..fe852f3cfa42 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -416,7 +416,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
>         if (unlikely(object == NULL))
>                 return NULL;
>
> -       if (is_kfence_address(object))
> +       if (is_kfence_address(kasan_reset_tag(object)))
>                 return (void *)object;
>
>         redzone_start = round_up((unsigned long)(object + size),
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 11c6e3650468..4fb8106f8e31 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -320,22 +320,28 @@ static inline u8 kasan_random_tag(void) { return 0; }
>
>  static inline void kasan_poison(const void *address, size_t size, u8 value)
>  {
> +       address = kasan_reset_tag(address);
> +
>         /* Skip KFENCE memory if called explicitly outside of sl*b. */
>         if (is_kfence_address(address))
>                 return;
>
> -       hw_set_mem_tag_range(kasan_reset_tag(address),
> +       hw_set_mem_tag_range((void *)address,
>                         round_up(size, KASAN_GRANULE_SIZE), value);
>  }
>
>  static inline void kasan_unpoison(const void *address, size_t size)
>  {
> +       u8 tag = get_tag(address);
> +
> +       address = kasan_reset_tag(address);
> +
>         /* Skip KFENCE memory if called explicitly outside of sl*b. */
>         if (is_kfence_address(address))
>                 return;
>
> -       hw_set_mem_tag_range(kasan_reset_tag(address),
> -                       round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
> +       hw_set_mem_tag_range((void *)address,
> +                       round_up(size, KASAN_GRANULE_SIZE), tag);
>  }
>
>  static inline bool kasan_byte_accessible(const void *addr)
> --
> 2.30.0.365.g02bc693789-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMWVHttcMsWs0g_US1FsXM_Fwi9A3GzW_gfitnVkR66SA%40mail.gmail.com.
