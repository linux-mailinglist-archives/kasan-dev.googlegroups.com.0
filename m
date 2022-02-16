Return-Path: <kasan-dev+bncBDW2JDUY5AORBQNPWSIAMGQE2PDW6PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 8341D4B8C5B
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 16:26:58 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id g15-20020a92520f000000b002bec6a02012sf1390508ilb.18
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 07:26:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645025217; cv=pass;
        d=google.com; s=arc-20160816;
        b=fx78oAfBN2ZxHHLlEaTRxXXzBHzUSKEFTorG8FXtvZRaoZkBnDBqy4YhTKcNNmORyn
         4cIKqK6QbYnq5kKX1iaeVSdpsauEIqC5eT/bsopemgB3vCWXfxfftL97ZSnTPaovBq9U
         j4r7mmgOUxdGLDZxjvgK9DrdTuz2XEtG7gl3Y3UU3kvrW6yyZV6USwkFuZjMWRZwQ4jw
         mHQtqtgmZBKTQV7QmgeJ/ZKUdd1amFCpxSi8czLGxRQ6SRF6xIAWuqulB2cHxt0J9wST
         IMise8WqS7jzoKXANBVk94zcNsETzJfWjkvPS7lwHtqKBNIavumqFzCTq8bVLcPlaxh9
         IvTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=WNpfn/l+j5JQEPnkewdN3qopmoYi3NNOvYj9iJ9GD9Y=;
        b=n97uJpyUmXE0TYXvta6WsH+t6rykguzNuWs3VD9zjXAC900uP1t0EGQ2lFMz9aPmbc
         GUtU5weidRawLd+5oUZJ4lrUeMPqyjc/foLeXDYUUxuMMK4NvZsru9otR9KlGr2N13Lh
         vvJ/oVZXdq1rxLqYndXzx+33bPFFY7rb6dnKnsuSmhxOSNHe1a9vK6chTS6ge7RV1neR
         3LKOxz6u8MzFkRS+YUZ7oRnI/wvwnzX/+/CDEHIApPb8OuO5QyxHcDn/F2USD0PKsadf
         XnqD+1KT9KCY5wz0lriYLGMrplzKQoR5L4sFhUcrh8MvfVyNCQQvfACF7BZ5Rw+rryL8
         +M4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=auojpY6R;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WNpfn/l+j5JQEPnkewdN3qopmoYi3NNOvYj9iJ9GD9Y=;
        b=PiV0qO7R04IrJ54Yj82q/DMXRxVpfnnVMZe+YQzDt8pBINcDh9Em4BTJ1Ab8VkgASL
         xztvrvKuLcevNvX8+JjXpvx0CkkJNFgeA3Nv0e3U+6qaBdbVwD9EdAAv/e3e5WrVNV9x
         4SYBmYf/nhxOiI7EsX9shfrXoyZgCYoGjjvCYR3VkGXaDtH5C0Ghd/RhZgZgww5yrTxz
         HMDcQbWkBgdTcN97lsy9LPLZnmZPq8v8kpJwruWKoPoONcwQrqTfLmQ9A3+AmON+l8Fb
         UPji1z4EoPAYfT/FONUllQNAKZtEME8jQDXkuiZprO7yikCxOdnu/Mr+8q1qUjpDOexh
         OnNg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WNpfn/l+j5JQEPnkewdN3qopmoYi3NNOvYj9iJ9GD9Y=;
        b=n5mINsFwN42zDyAxfzeuJyi6+EspWk8xznQS2knh5uNaFaToVwEH09ncfLKh8sFquE
         yXjZHBViimVZsHG1CqTITXwJrdQNJdv4sLgTktfPoqPui6XsA2Q5BTaaI4YKVYTrNTTY
         TWfmLe/VS29GP6JO8Lj+M693BmkTCrD3G0Me3cEGWMLEEP7TN/24x6kC4DIsael+cKbh
         b88qrfYvLZRVNXnyypwn0MEwxIOV9DhnrDpTky5SNz2BGFxCJ2tuCinSJWJFaCQj7I7O
         DwSZbsll8ARB1+XZhhc7h8NQ69ddYNOWhe0cOJymcXz/cZteIHP9QhU4bzNlpamNTM80
         ZK1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WNpfn/l+j5JQEPnkewdN3qopmoYi3NNOvYj9iJ9GD9Y=;
        b=C8oA9JMBvwRIY0Roy+K5Mt8PqvhmC8ZhaX9pM+CfgpKK9jqHwmCYO19BW4WTKHuR0f
         3fj+Hkyhvp8cHvzrrj97UmMkBc5wOs/9j1fGPm9FeV7OcoNS+ee/A4txzScLojJ6U1BU
         nsCIQy8jk0+E3+sgPPwK6VNvdTPJEdDqR2BGB3sMP9EuV7QqZ0FCoucFbqJDh/P7AtTw
         9caANLGzxLcai9J7xGNLagqhcHVafiU5g7oMshlRcnm99vuEwQJuOUblbyiKleXIfU1S
         oaKvjnzMCHGTVbJ5G4RELrnnw4YKqJ19GbQaWRtVoiEiR7s2U5CAXm6MjfMMzqEkszpc
         8ELQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531sF8iOs3EfjWLe3jDlT2/bmSCw6D7lcFShnuh+EtrTPKgeO77l
	ZLz+3Ccd+HsjLgHTEDtqivg=
X-Google-Smtp-Source: ABdhPJz9tVjRYKeR/0LstXNMx7bbZd6IxIDsj0VH0Q73TFoNsojbk3+4sdjyzCR46m5XpmUoRCySnw==
X-Received: by 2002:a05:6e02:1985:b0:2be:1909:ede5 with SMTP id g5-20020a056e02198500b002be1909ede5mr2071673ilf.151.1645025217538;
        Wed, 16 Feb 2022 07:26:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c8d:: with SMTP id w13ls1193123ill.4.gmail; Wed,
 16 Feb 2022 07:26:57 -0800 (PST)
X-Received: by 2002:a05:6e02:1d13:b0:2bf:ab6b:bf15 with SMTP id i19-20020a056e021d1300b002bfab6bbf15mr2154327ila.131.1645025217148;
        Wed, 16 Feb 2022 07:26:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645025217; cv=none;
        d=google.com; s=arc-20160816;
        b=kb3r7y+HPOQaYF+Myzu+Lx1lr/3sXocHWV/4Bu9XfULngNfbz6XdYw9xrVoHO67erN
         5ykAWTfijHkmLd35V/uZUjrxa/AzTX17KHYAbNzChNTs5P24l2PEX4+UDTLTcislG29h
         LND++diPz89YVUUepZwpLrDNt0wZbReoQocdfT4YNY4ArX9Bv/43mHtpyMumXtkKG5HH
         RhD/1Po4rEHFqSgvt65EENS1w3BvglDF4GZnnxFKS7fQapAsyv8iJgDoJ/8bbVK35K++
         SsQol/qFPc0KofoJz40gOlkUr5p6ZALvtZo5xWeteV/9w+/srimmc4dmg+yK0B7ACkdI
         0mfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RX1MiZpwQpJ0b3L1gArX38pH7r/Ihc4JwK8Scpn15pk=;
        b=y73QnFnn3Peero4sXBJ/GWrVubB1yvZsrNEtCJJGedBkkn8tvTR4lr44v/xWNTpddD
         5rGsjkTudTdnrpOi/YP4D6T2zaNpgnlb2fwS7melyLhFHoN/Z2jhlshmfeWJRkPx4juH
         HkAvWV7RuJ+GZ+teLAuoBJvpwG5GwHzmm1uOyzSUEKy9y/iHJ+sucZRYLkEXucJd8yod
         3tSPB+I7iLbKw2YmhcLfhG2FP5/K8IeL/XCPlMWVxadCq5C04uQXzOs6GMl3QjzClT65
         KJeaKvLXouH3tRNbPcT5EEtLQuBWBxy3xkfA/1/glYliH1/gahbttPDrWLEcQk9vtkCM
         mj+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=auojpY6R;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd35.google.com (mail-io1-xd35.google.com. [2607:f8b0:4864:20::d35])
        by gmr-mx.google.com with ESMTPS id n11si276845jat.6.2022.02.16.07.26.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Feb 2022 07:26:57 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) client-ip=2607:f8b0:4864:20::d35;
Received: by mail-io1-xd35.google.com with SMTP id 24so36864ioe.7
        for <kasan-dev@googlegroups.com>; Wed, 16 Feb 2022 07:26:57 -0800 (PST)
X-Received: by 2002:a05:6638:3799:b0:30f:cc82:ebc4 with SMTP id
 w25-20020a056638379900b0030fcc82ebc4mr2090155jal.117.1645025216948; Wed, 16
 Feb 2022 07:26:56 -0800 (PST)
MIME-Version: 1.0
References: <20220213183232.4038718-1-keescook@chromium.org>
In-Reply-To: <20220213183232.4038718-1-keescook@chromium.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 16 Feb 2022 16:26:46 +0100
Message-ID: <CA+fCnZfOSD56Uvetqd=ofv-Wxw6LOOZv3sUDcEuX2F3u-MgL9Q@mail.gmail.com>
Subject: Re: [PATCH] kasan: test: Silence allocation warnings from GCC 12
To: Kees Cook <keescook@chromium.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=auojpY6R;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35
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

On Sun, Feb 13, 2022 at 7:32 PM Kees Cook <keescook@chromium.org> wrote:
>
> GCC 12 is able to see more problems with allocation sizes at compile
> time, so these must be silenced so the runtime checks will still be
> available. Use OPTIMIZER_HIDE_VAR() to silence the new warnings:
>
> lib/test_kasan.c: In function 'ksize_uaf':

Hm, the warning mentions ksize_uaf, but none of the changes touch it.

> lib/test_kasan.c:781:61: warning: array subscript 120 is outside array bounds of 'void[120]' [-Warray-bounds]
>   781 |         KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
>       |                                       ~~~~~~~~~~~~~~~~~~~~~~^~~~~~
> lib/test_kasan.c:96:9: note: in definition of macro 'KUNIT_EXPECT_KASAN_FAIL'
>    96 |         expression;                                                     \
>       |         ^~~~~~~~~~
> In function 'kmalloc',
>     inlined from 'ksize_uaf' at lib/test_kasan.c:775:8:
> ./include/linux/slab.h:581:24: note: at offset 120 into object of size 120 allocated by 'kmem_cache_alloc_trace'
>   581 |                 return kmem_cache_alloc_trace(
>       |                        ^~~~~~~~~~~~~~~~~~~~~~~
>   582 |                                 kmalloc_caches[kmalloc_type(flags)][index],
>       |                                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
>   583 |                                 flags, size);
>       |                                 ~~~~~~~~~~~~
>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
>  lib/test_kasan.c | 4 ++++
>  1 file changed, 4 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 26a5c9007653..a19b3d608e3e 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -124,6 +124,7 @@ static void kmalloc_oob_right(struct kunit *test)
>
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +       OPTIMIZER_HIDE_VAR(ptr);
>
>         /*
>          * An unaligned access past the requested kmalloc size.
> @@ -185,6 +186,7 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
>
>         kfree(ptr);
> @@ -265,6 +267,7 @@ static void kmalloc_large_oob_right(struct kunit *test)
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> +       OPTIMIZER_HIDE_VAR(ptr);
>         KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
>         kfree(ptr);
>  }
> @@ -748,6 +751,7 @@ static void ksize_unpoisons_memory(struct kunit *test)
>
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +       OPTIMIZER_HIDE_VAR(ptr);
>         real_size = ksize(ptr);
>
>         /* This access shouldn't trigger a KASAN report. */
> --
> 2.30.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfOSD56Uvetqd%3Dofv-Wxw6LOOZv3sUDcEuX2F3u-MgL9Q%40mail.gmail.com.
