Return-Path: <kasan-dev+bncBDW2JDUY5AORBPXZ2OGAMGQEHG36QPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 668B44546C6
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 13:59:43 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id z10-20020ac83e0a000000b002a732692afasf1877852qtf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 04:59:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637153982; cv=pass;
        d=google.com; s=arc-20160816;
        b=TL5KO0nXk6wrFlIdp3WwPtCUfsdEjC+BnxSWWZ5ttBI2LQr0hn4fBTrjVL4Wp3Grga
         rGlpCPwNbKDZ8+3U/HFRYQAepQAWXBnFj22LbmwSNbR3V+tu1U5cBsJ8awnQ3auqxT4l
         VvAEScDrHwVqVNWud83Ax13pSm0nlNcTG76LRpTh9RU36gJJZ8aKMRsmwF838wcu4kSu
         zAFE675aoq1en9jRLoxB5BVfUq8JqR5qyylYCoVTNE2Wonaj//fcvJeH5AlG9hDkpNPq
         o7nNIHL3saSkfGOLyQKWijXb2F8qO+QWwN3hbYRTA+cJQSqgZMmSR44t2ebEXNoKdoEZ
         EIlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=tQ3Q17APPhD6CgJbeYKfzBkPaNpyXOj9Apg1G93zG04=;
        b=l3R8ru5VZ+S0D5OYMzrcLBNmEJXd06yYHihcVqDWIegfY4phtDPCqzl//GPtf1gzFM
         bFjYqQ3HXl60DkDukJmzIHznhhTKRm+lo7rcCXLlbE5LqdQxbzYkMKJAH6hf0fgM5r78
         DrciK+VKee4UvfSAO/iUyRQ2qMzKjhjk6+A04jE+DCN74Ws9BRg2L7wvjfSQLZ65BPwM
         US2NVWDXXiH59qVSmiDsjaV28wAOOWvrf6hv7oRTNrE1DAoo6lRfUgwzOMj1CGKUNzJu
         8MUulW0QSxCZd47tYgcx1wYIx05zN0C+0ABLkZy+qBYavYK8Vom9aDHOsO0K3aMrmQ93
         uJYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=T0SLV5Va;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::129 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tQ3Q17APPhD6CgJbeYKfzBkPaNpyXOj9Apg1G93zG04=;
        b=SqJsUpz1fU7AFryYcw7kCPIXU085CLV8YTBSx8vWcc+KlK56wzLiwQ0c/rXw2ApWKO
         wdrCILpqKpRAHXRdiCKFZRq/2K/SP1/TJ/7MbynHKrTZfcG9Yf02l4NI3gbnN7KO883Z
         wAUTERlqGCrqzmGj4xagCx9K9VKrEltyekYGnGGXnlsms3Or5cZYvHjSBhzigQZzFepo
         yZcJzQYA6v3UW47pDDwDw4VqTabtrhJH5YxEpje3xfsR+BxRn9yuisxPNxhYgnJFU4Pc
         xaAUEMzhJVeO2be2zIl4aq1+wyj5WcOwgkfzf8Rz3l1mKBQo1ipKaJ9HnEgjQckQUqTK
         P0bw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tQ3Q17APPhD6CgJbeYKfzBkPaNpyXOj9Apg1G93zG04=;
        b=UqulMNkla/B067epKnHtBAB+43jLQIT8eO1qF5m+i7dJQlxMocsyuhYnx5COZpvBmz
         PpCfmPvgDYUqirfqAQN4wqFS25ucnFDgnZg8h20HiRojzwMXgE82nQNjuUrqD+8mwnvm
         j0MFMTnZY0m0Zqf1Nab5ApngXrKDCDMglYDfst6EGKpHRVnOsF0T8OJefRrFYuwaYiR8
         J8B4qVThe3v0qZSWtymvyuOAy6Vrzaps/dOGwVQTVlJn9sPesgicTDFebMBFS/uzVN9W
         ZFl8pR4UJG/nDzt+ceI/A7DLZoWtQuLdIbJhLMZLFBLxdaRlcPIdDHWimERYO3q8/fxs
         6hJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tQ3Q17APPhD6CgJbeYKfzBkPaNpyXOj9Apg1G93zG04=;
        b=yAE2uhjtu1S1ppY6800Mt7954Is/9RlkoNPC3wKEUPWJXkhxe+Jwr/LIi7m9JnRGL2
         HkXcQNa/Ul9zmp+k/qj6Wc57xHBUmfS/g3RKLI5ykrXu4gYHUyniUr0bMnegb0m59IX4
         RC/aKNFGk3qfTuZlSCQyMq5vbDYLahn0LqDMV6BZcNmsXpZR+BXkTE8A92o88qJ1RHkO
         6gn47UhaI02qrLa0eYlczm97dOgpb3Xes1MAIdmCxBGVYSvmbrl4nAhpjbD+Q30cBYGX
         YgEK1vTjIg478YcjGfJ24Leole9xl/MsmFef8e7CY+8u7GoUNS+PucNayfuybIk9FJss
         lZ6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533gaHp7qNgOQZdM7b969/EIwtR7z2Liujwp3dQpLncz/cjsfq7V
	nkSvxkcwJT7to8uNke7bdFw=
X-Google-Smtp-Source: ABdhPJxkNullWXHd4hF9tofiN/zm3kOikv8Yv4+8dW453K90Inh0XnS2c46JTlgQWqTwziciQ4weVQ==
X-Received: by 2002:ac8:5c50:: with SMTP id j16mr16959519qtj.255.1637153982297;
        Wed, 17 Nov 2021 04:59:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1a10:: with SMTP id fh16ls6996160qvb.0.gmail; Wed,
 17 Nov 2021 04:59:41 -0800 (PST)
X-Received: by 2002:ad4:5e8c:: with SMTP id jl12mr54838397qvb.58.1637153981884;
        Wed, 17 Nov 2021 04:59:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637153981; cv=none;
        d=google.com; s=arc-20160816;
        b=J666sCmetdQKZqckG2soFIzt5KUDKJPtINI9Z0dJIqk/8wdjhIcrcT5J3BRSTAqMwj
         94cj+dYDegKf/x2fFgiSJFPa7zwkcWI7SXXLvz5CnxKCLcBhgGVjH6kUqNFDLOG+dZAv
         6iGCUEzWyPRzfbv1xg9jIrJLI2KU9AuYMUOeVpPGjma/TYCnq0G64B4xfoipf6d1Kdgf
         XfMRG9LhV4tfoOumaIof3/SD6wl0ew9k5tM+1bWWWL7dvIGKX8w/ye6wNWCxtoRPHmfv
         h3CvZ7IFyGGe6l9SrzwQm3bJI54txXcSN8uDVOIYck5qoUxapt7Puf47RBhQkkunhAVM
         ulrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FT+WTgntcUcOhdQh68NQbpJcx5eGcrjyuCTdifDbfTc=;
        b=eo2rEBEwoHI/TYk7k0jzd15jIZQod2cBX+9UFiVOWKzY8n0MrrWY10hbxXjJt1g7Ow
         0YILQ4gRKDduHXJNDO6yOhjXxM5qp728i52PKXe41QMPlfKs2PiZW+caeeVYHn0c5Izh
         0Qgp8/YN4DDbJ4wXEnrPghdhJ6iGnREidTZ92YYsdpbb2JgQDIkBRYSYvSqQaKFF9DLn
         /moXDFoOKwiP05GwTrGhWSTIyYIG9aQJxVoTckpZ/hlIedQeF+RZe0kReud9SprO9Zc6
         QzaekTsfZOw3M9fCd5cQbfXa7drUJoLB2aREsy/WLu/kRw4cdN4DCTzUvt0oem5Md8Lp
         XHbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=T0SLV5Va;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::129 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x129.google.com (mail-il1-x129.google.com. [2607:f8b0:4864:20::129])
        by gmr-mx.google.com with ESMTPS id w22si321349qkp.2.2021.11.17.04.59.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Nov 2021 04:59:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::129 as permitted sender) client-ip=2607:f8b0:4864:20::129;
Received: by mail-il1-x129.google.com with SMTP id h23so2649720ila.4
        for <kasan-dev@googlegroups.com>; Wed, 17 Nov 2021 04:59:41 -0800 (PST)
X-Received: by 2002:a05:6e02:1525:: with SMTP id i5mr10012820ilu.81.1637153981523;
 Wed, 17 Nov 2021 04:59:41 -0800 (PST)
MIME-Version: 1.0
References: <20211117110916.97944-1-elver@google.com>
In-Reply-To: <20211117110916.97944-1-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 17 Nov 2021 13:59:30 +0100
Message-ID: <CA+fCnZcp3dFd3rwpLx6VUi2Yv9uqsWQyQNB6d3X-A7VgTjXUpw@mail.gmail.com>
Subject: Re: [PATCH] kasan: test: add globals left-out-of-bounds test
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=T0SLV5Va;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::129
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

On Wed, Nov 17, 2021 at 12:09 PM Marco Elver <elver@google.com> wrote:
>
> Add a test checking that KASAN generic can also detect out-of-bounds
> accesses to the left of globals.
>
> Unfortunately it seems that GCC doesn't catch this (tested GCC 10, 11).
> The main difference between GCC's globals redzoning and Clang's is that
> GCC relies on using increased alignment to producing padding, where
> Clang's redzoning implementation actually adds real data after the
> global and doesn't rely on alignment to produce padding. I believe this
> is the main reason why GCC can't reliably catch globals out-of-bounds in
> this case.
>
> Given this is now a known issue, to avoid failing the whole test suite,
> skip this test case with GCC.
>
> Reported-by: Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
> Signed-off-by: Marco Elver <elver@google.com>

Hi Marco,

> ---
>  lib/test_kasan.c | 18 ++++++++++++++++--
>  1 file changed, 16 insertions(+), 2 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 67ed689a0b1b..69c32c91420b 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -700,7 +700,7 @@ static void kmem_cache_bulk(struct kunit *test)
>
>  static char global_array[10];
>
> -static void kasan_global_oob(struct kunit *test)
> +static void kasan_global_oob_right(struct kunit *test)
>  {
>         /*
>          * Deliberate out-of-bounds access. To prevent CONFIG_UBSAN_LOCAL_BOUNDS
> @@ -723,6 +723,19 @@ static void kasan_global_oob(struct kunit *test)
>         KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>  }
>
> +static void kasan_global_oob_left(struct kunit *test)
> +{
> +       char *volatile array = global_array;
> +       char *p = array - 3;
> +
> +       /*
> +        * GCC is known to fail this test, skip it.
> +        */

Please link the KASAN bugzilla issue here.

> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_CC_IS_CLANG);
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
> +       KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
> +}
> +
>  /* Check that ksize() makes the whole object accessible. */
>  static void ksize_unpoisons_memory(struct kunit *test)
>  {
> @@ -1160,7 +1173,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>         KUNIT_CASE(kmem_cache_oob),
>         KUNIT_CASE(kmem_cache_accounted),
>         KUNIT_CASE(kmem_cache_bulk),
> -       KUNIT_CASE(kasan_global_oob),
> +       KUNIT_CASE(kasan_global_oob_right),
> +       KUNIT_CASE(kasan_global_oob_left),
>         KUNIT_CASE(kasan_stack_oob),
>         KUNIT_CASE(kasan_alloca_oob_left),
>         KUNIT_CASE(kasan_alloca_oob_right),
> --
> 2.34.0.rc2.393.gf8c9666880-goog
>

Otherwise:

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcp3dFd3rwpLx6VUi2Yv9uqsWQyQNB6d3X-A7VgTjXUpw%40mail.gmail.com.
