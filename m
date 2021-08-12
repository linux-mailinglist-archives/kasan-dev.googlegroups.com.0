Return-Path: <kasan-dev+bncBC7OBJGL2MHBB46E2OEAMGQEUU5T4GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 493923EA11A
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 10:57:25 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id c63-20020a25e5420000b0290580b26e708asf5490187ybh.12
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 01:57:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628758644; cv=pass;
        d=google.com; s=arc-20160816;
        b=OU9Rw1FJlWRVZmu7gfNFdYP7r7uTky6NTP8pe2pnoJ9AjPRHkAmXTizI6SH0epZATh
         v8L3cgoKGegAENy5bdgwooj8MC1pqCTOyezpO7H9uSOhlZVj8pVq+oBA2OjW+gPYZ6BB
         tCR8ILb0nb+JUR6pWRFUIfaLdFIUBzycyYZE3OFIfO9zTx/JVnMXKR3q8kINRGSISZo0
         0RPcce66oKyxxCOWxBqtYYjTp0yr+REoLpvLsa8XUt86Tc+gG9ZnR58mr1NFsKl1cUE3
         waLYQMOoctIpx+YcaS3P0echLQe3DjA9YYVBjjYbE+euWFTLbIXnhe44GOIwu1x+HJUU
         mEIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NeGFMcfyGRBgcQIWlLsiX3WzqevkTdyxciWEPJFWjoY=;
        b=UItd/me5Ha13YeePCSu3eqb3icK+vak+77vH/KWbfR1s7Tm10GykpVWKTlnUBQq9X2
         XxUkHXbvRfkJNQZO9tbtpB2D4ii9yJlOy4cfY9gc/5Nll2AtG8GKN0ywS3lpFFzIGjQJ
         MSdf2kXy0Bf0EZaAgpNO/JKeoE02yN7YdZwWRPIPjt8AY/8zXEDtYAdDZiNSSFQa7e+P
         TeXTRQV5HH/sy4GGalaZHFQu+ZBcitS32ufc7YMtCBUvnWYFWyRkzkofIAgA0KnMFYQa
         m982vk6KJYfHk09ORT9psvdRp5k0xESUfbKuamHSPdggzQe8rJxSqnFwVH+S3HFzYAVp
         U5MA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jTu6zz6R;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NeGFMcfyGRBgcQIWlLsiX3WzqevkTdyxciWEPJFWjoY=;
        b=tTbpMR/xpvL5iviO8dEw9xV+mK6JEb03JMlBQeax29b81gRcuJSp3zB0SW2K5m12qt
         qnSHhEt1V6J/6BfowFBmt9mz8yTMq3H6Szy7tNDBFbe7p+JplFkderXWqiEA3PhQ5Ofy
         xCejuI8qttG65GnZBO4BQhYeTGPUHZnv1bynalkBXsa0Vpqjc/r6PU/BF/0Q/6fZxdiL
         QIOPrcpbpgny3ZrTD5+SqlLi4BOSMpKfEMFes9M9G7Anezb7As3eIuLfMsG6LlIYrqIn
         EUTOIovm/7YQaU60jbeCvDY3KwET1sLuwDRMA3fPBS5CkWQf1N/1WQmwbkAZA7gEJZpY
         ny7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NeGFMcfyGRBgcQIWlLsiX3WzqevkTdyxciWEPJFWjoY=;
        b=j/IE+oBuw87aq35ULidroe+Ku7l61BF/McIBg8D7md45VYyQOAmS0mBTUhalJw1y7q
         wDjRSoG6Arab/Xa/2cUJcBwbx/ye308Zi1on8KmwR4kTr1YnKRNM2L9Nqt7+bpJRl8Xx
         +K2qGmNs3vGwO687w34X+FMnTxoPt9ll+0ooTLIz2CQD7g4j4nVX+8YyeqXqqk+bmdZ2
         EEg0Z6coaVYa3rE0rFPRwSo8vRk0s8/Q4iizgUeyeDPKP2+ocy/Gg+HutgywnIvzpaz4
         WwbVFxiymAlYhsZ19IPTH9Z2MyDdTNXPkoKLeCq35KbuWLe8w6UL2awBSFHW6ffSW+oT
         E4vg==
X-Gm-Message-State: AOAM532NBUvgJDf0n6iFDeIYcnG44vQGc2ZY5otJOLdNKlXB+GxJIcX3
	b1f/bB+Nwl1l4gIp1e4vT+0=
X-Google-Smtp-Source: ABdhPJy1pZB5V9cug8XQIit3A9xco/VRv5ktZl11JVdoZPnYdD4zi9Z8YFqSGqsrEUPGY66GLzA6iw==
X-Received: by 2002:a5b:791:: with SMTP id b17mr2047790ybq.286.1628758643597;
        Thu, 12 Aug 2021 01:57:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6e04:: with SMTP id j4ls99629ybc.7.gmail; Thu, 12 Aug
 2021 01:57:23 -0700 (PDT)
X-Received: by 2002:a25:b18e:: with SMTP id h14mr2977646ybj.441.1628758643040;
        Thu, 12 Aug 2021 01:57:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628758643; cv=none;
        d=google.com; s=arc-20160816;
        b=KnmhP8NFvqmuqZQEv/xu1NVp7ZyszsIUZgaFB0+Ujr8V5/b849BfXaCmfjuzYc3xh8
         X4pkrIUCnQ+HTGusgjfDKaD0PsDPJBm7X1nbFDiCPWyW4bn1aAILQ5TC7jE3Lftx2G1U
         JVW0j7P4/qszFSZ6G6SZeKemzBAiRrI7p5QwG5aAb5jBbZaRlz/WedqvUL3+9Onfcs2s
         UDU0A8Hbeg+sUmm2OExIo7gGq6+BHFy+bUCGXYnqCSsMnc3BsDbBCJ0pd1L6V7pAnZOm
         BkQoURkFNubGJnrJt07KVnP403pdtQFhziJs4RNFNA6YcGYRwydH4Z9BykIWpwEsbGg8
         G6WA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Gv+4JbEnb1Tuank6FYqN4BwpsesLnaVYrFHSVUYTt60=;
        b=AQz2HHEalh7jGaj5WJDt4oeHKDlhkLoHqjgunkPUQQMj4aTis9awiE5k3TLJ7umu1z
         Qnw/ObB5j3PuaS5Bwl4rgntOF/MUKszBFj5kSF3+nhb07iXiFQkNYU65970a/DrL++Gt
         LHz6ylMe3dhCjj62R5W793cIPw54RSCbZlZCmrpDgpR4OZE5RPAZQh/2UP8Tywe4JyXL
         gxoZ4CQvHbeE2It1CWuLPy35PkLPtEQOmmx9lPC9fB98n4HxTkUN80dn4+uzf/rRok5a
         aqgpaL3qi8DO9ee5iLdZnAfzqQwvVhgHSe5f0kE00+erJY9oje04KWnkcB49Ih1xblxD
         JBHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jTu6zz6R;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id e137si169888ybf.2.2021.08.12.01.57.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Aug 2021 01:57:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id z9-20020a9d62c90000b0290462f0ab0800so6851273otk.11
        for <kasan-dev@googlegroups.com>; Thu, 12 Aug 2021 01:57:23 -0700 (PDT)
X-Received: by 2002:a9d:6f99:: with SMTP id h25mr2624406otq.17.1628758642497;
 Thu, 12 Aug 2021 01:57:22 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1628709663.git.andreyknvl@gmail.com> <c3cd2a383e757e27dd9131635fc7d09a48a49cf9.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <c3cd2a383e757e27dd9131635fc7d09a48a49cf9.1628709663.git.andreyknvl@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Aug 2021 10:57:11 +0200
Message-ID: <CANpmjNM6hn8UrozaptUacuNJ7EtsprDJWDmOk-F6BaNZ6Hgchg@mail.gmail.com>
Subject: Re: [PATCH 2/8] kasan: test: avoid writing invalid memory
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jTu6zz6R;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
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

On Wed, 11 Aug 2021 at 21:21, <andrey.konovalov@linux.dev> wrote:
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> Multiple KASAN tests do writes past the allocated objects or writes to
> freed memory. Turn these writes into reads to avoid corrupting memory.
> Otherwise, these tests might lead to crashes with the HW_TAGS mode, as it
> neither uses quarantine nor redzones.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

Reviewed-by: Marco Elver <elver@google.com>

although if you need a write primitive somewhere that doesn't corrupt
memory, you could use atomic_add() or atomic_or() of 0. Although
technically that's a read-modify-write. For generic mode one issue is
that these are explicitly instrumented and not through the compiler,
which is only a problem if you're testing the compiler emits the right
instrumentation.


> ---
>  lib/test_kasan.c | 14 +++++++-------
>  1 file changed, 7 insertions(+), 7 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 1bc3cdd2957f..c82a82eb5393 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -167,7 +167,7 @@ static void kmalloc_node_oob_right(struct kunit *test)
>         ptr = kmalloc_node(size, GFP_KERNEL, 0);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
> +       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
>         kfree(ptr);
>  }
>
> @@ -203,7 +203,7 @@ static void kmalloc_pagealloc_uaf(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>         kfree(ptr);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
> +       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
>  }
>
>  static void kmalloc_pagealloc_invalid_free(struct kunit *test)
> @@ -237,7 +237,7 @@ static void pagealloc_oob_right(struct kunit *test)
>         ptr = page_address(pages);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
> +       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
>         free_pages((unsigned long)ptr, order);
>  }
>
> @@ -252,7 +252,7 @@ static void pagealloc_uaf(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>         free_pages((unsigned long)ptr, order);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
> +       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
>  }
>
>  static void kmalloc_large_oob_right(struct kunit *test)
> @@ -514,7 +514,7 @@ static void kmalloc_uaf(struct kunit *test)
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
>         kfree(ptr);
> -       KUNIT_EXPECT_KASAN_FAIL(test, *(ptr + 8) = 'x');
> +       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8]);
>  }
>
>  static void kmalloc_uaf_memset(struct kunit *test)
> @@ -553,7 +553,7 @@ static void kmalloc_uaf2(struct kunit *test)
>                 goto again;
>         }
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ptr1[40] = 'x');
> +       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40]);
>         KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
>
>         kfree(ptr2);
> @@ -700,7 +700,7 @@ static void ksize_unpoisons_memory(struct kunit *test)
>         ptr[size] = 'x';
>
>         /* This one must. */
> -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[real_size] = 'y');
> +       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size]);
>
>         kfree(ptr);
>  }
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c3cd2a383e757e27dd9131635fc7d09a48a49cf9.1628709663.git.andreyknvl%40gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM6hn8UrozaptUacuNJ7EtsprDJWDmOk-F6BaNZ6Hgchg%40mail.gmail.com.
