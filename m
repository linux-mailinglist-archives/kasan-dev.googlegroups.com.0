Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO7YZ2HQMGQENSAPUXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id CC66E49F6A6
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 10:49:48 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id jo10-20020a056214500a00b00421ce742399sf5630412qvb.14
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 01:49:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643363387; cv=pass;
        d=google.com; s=arc-20160816;
        b=keryv2Ug8HM498I1BdzcUGYLJF0XeJn8XYNa5Qd0t9ommnxW084vTwqlWGd5pH+Tqd
         MbJ1571A5/tOQvTxXk/QCmO+URNY8OnF1eHIK27JXTa2y7urrphu3Ez7u3NQOqqMm4Fh
         HO64YlSj77gVVvhdRDtuc1/em5bfjwEc8C3ZP9fHD7xI4P7M1IgOJvACGRt9ll2KTS39
         1PtEmi63sUw9a27Subyyq+m+7Ksyfm+Jki5FoMW1Eu0p2jMjzFWcMMQRkn+BkqFA9GEZ
         swcDNW8Gldi6DNXw3LmGhelr1OIzogTsKN1qe52nlj0nOOuxShjKOQcqAYJPeQ8zY8Vj
         sqSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=i9qx7cMNy9lHG+iJMp/9hfRxcCJrnZfXzm6svjjS3wk=;
        b=FI9NK0dePpFiUUA1MCddU057v2P7D1SIqRu61gO6D2xyLLZjZtRjN6eORJOGlpxp6W
         bd1s3fOZTxWmbpwJ5lb8QvQwMads1eEjmPX7zpHyY1EMxh9OpPdGMMAum8zKFUzj6aGH
         jtxIvIb3RJQ7prFBx1GkVuvkwWbNjpDESixs2iWSA52l5nHXHrbKFcw43vczkHVuQgw0
         CdRZDx/VCPJC2Ty6rF76HW7Lmmp9nRRidK1yW2VFfpe8AIL66mrd+CIlfzu+0A6QnbNs
         mjT5heANdIl5zrQEZcqNrrgVp5GScx5cnmApLvjA+0FeupV7hbDfo228jcWw56FgFoZW
         QNWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FQzQLz7w;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i9qx7cMNy9lHG+iJMp/9hfRxcCJrnZfXzm6svjjS3wk=;
        b=taTuEzW7UGHNm8Skb8pXuM5iMmDim1sySbzCZtA06X37KvWrNcwDl3qZ364A95x6Ak
         9h6V6INNtgCeWOIyh22YJDms21QJtdNsVQPZKVwZxybacWOjjqSxZ0f6M0l8pDw385Ri
         qYv4RxrQ9ZwT3j6tHbQePwXnS8Xn1HwDeBnhuomRBBwWYPW1OZFp44u/UKfc2woxp0nq
         AW1OVVHmwVvoaMDo5Z7oUdptW/yURfag/5gFQJgDNFP9JhxakJ9UPj+hOIhfHXviiuiD
         Ti5iNAb/8dtEs8Ay8nAGm0jaF54RVxNRA/o01fACaH7CvpfLenymOpghkE8IUtqn57eO
         K4zQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i9qx7cMNy9lHG+iJMp/9hfRxcCJrnZfXzm6svjjS3wk=;
        b=aK3yd00OrWS+Yj6nOMByL7uMpt3sttZ7RzvtIAKySR9cCIebPZb3uK7ffi6q2tIIW7
         fXyrg99Eo4lD7yPUS5gyPnkVazdps0QhL2pp9vY9ZcFtnz8u25J2UMmq3PQiVy+Vf4f3
         03V/wf3Hj+kcoPXrvTgQVwwPzYhZw70xdLbrmmvB1BCAUMX45FKoUHBd38Isf722zVSK
         F/csiLEsfpxrnBaW7y2nrYzmDsLa8c4bO8UARjGQ9hS7KEXRLwbn68JtvXbBcJK0wU9S
         0XHbn1u7MN27Mf022qGICaIUAA9MxZ7ida5IPLB9fjjetPGTJWiloYfoHREEtd3NvNTh
         Hxjg==
X-Gm-Message-State: AOAM533TiLbJznRiQF2bdapMAPI+/wHUB+cURZUTdVi7wIvR7/NcLDmP
	csxvwVhf9AQtr53iCDAhqkU=
X-Google-Smtp-Source: ABdhPJyO/6c1gfOtChLG2TCGNj7JlQUDPdLLwK1SKCfr6CQjbgyZMdHs3HI/8qojlK1Do1O/fiYhMA==
X-Received: by 2002:a05:622a:1756:: with SMTP id l22mr5232220qtk.415.1643363387612;
        Fri, 28 Jan 2022 01:49:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4e54:: with SMTP id e20ls4314772qtw.5.gmail; Fri, 28 Jan
 2022 01:49:47 -0800 (PST)
X-Received: by 2002:a05:622a:514:: with SMTP id l20mr5612096qtx.187.1643363387089;
        Fri, 28 Jan 2022 01:49:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643363387; cv=none;
        d=google.com; s=arc-20160816;
        b=CLNfPvEmTnKJvgokteT1iUlzSk7vvdiY3e+jCNvjof23TiRHTbTiX6Lg/gB7p/cWz1
         MOTWM1nxIlGLj+QepT45wAs88ccNEv2ncXaV8G7qVgWW3p9DkRG+oDU2852xX1sZfDj1
         k+pNLtPcgBNg0DD74AhacAtHY2VTOuqoKK+mK+CyMW7Nvul71u0iT+81mYhVZ8GtJJA1
         fJI4kFavvRdIpjaPFVe0c3lfsb333ysgKvUrinTQ2kA3lnQGC+A10LimqDrOHGORJoYF
         bywLxjDVeKk4XrwIp1FUnHlNFOhofe7sxOj1iiZ4hUTyU1M4MqXiKSPfykFWZniiNQbP
         tF+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KD2MpvTo6d8AcZYWRzGbZANNSm7u8StOzxLlvpWuXTM=;
        b=AmPNVV038mYxd6g5aVw1EXluTeWdG99SMU/gysUfPHS4Yt+UedT1l9t8bfszwKlZzV
         t0oEg8xDAqPY0brQGbP7Zta803G1RYHBYnelV9zVUNi4mLLMyarl5SrwC20s2wqRemkI
         RZuO+4ckcui4s5ChAlFfy5Ii6UTZjaeIDRb7nGo2Wbpu2Laxo9c9HH6/OrFdEnrzufoK
         3MuXQBkrVo7zNnMmac7QvgMCmr3kNDgc0St5t27cd+WWomdExRwA+4GZoEU+IgFN98OB
         LRUjbqpOnUK7qBFD7cDmgDnungyhwka7SQmTFsnPzmhV95abnwb7m4xighHzrU4LvXKK
         VWeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FQzQLz7w;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x234.google.com (mail-oi1-x234.google.com. [2607:f8b0:4864:20::234])
        by gmr-mx.google.com with ESMTPS id d2si662823qtj.4.2022.01.28.01.49.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Jan 2022 01:49:47 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as permitted sender) client-ip=2607:f8b0:4864:20::234;
Received: by mail-oi1-x234.google.com with SMTP id s127so11368898oig.2
        for <kasan-dev@googlegroups.com>; Fri, 28 Jan 2022 01:49:47 -0800 (PST)
X-Received: by 2002:a05:6808:1901:: with SMTP id bf1mr5020470oib.197.1643363386387;
 Fri, 28 Jan 2022 01:49:46 -0800 (PST)
MIME-Version: 1.0
References: <20220128015752.931256-1-liupeng256@huawei.com>
In-Reply-To: <20220128015752.931256-1-liupeng256@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Jan 2022 10:49:34 +0100
Message-ID: <CANpmjNP+J-Ztz_sov0LPXS8nGCf-2oJFs0OJp1LQMBeaL00CBQ@mail.gmail.com>
Subject: Re: [PATCH v2] kfence: Make test case compatible with run time set
 sample interval
To: Peng Liu <liupeng256@huawei.com>
Cc: glider@google.com, dvyukov@google.com, corbet@lwn.net, 
	sumit.semwal@linaro.org, christian.koenig@amd.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linaro-mm-sig@lists.linaro.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FQzQLz7w;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::234 as
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

On Fri, 28 Jan 2022 at 02:41, Peng Liu <liupeng256@huawei.com> wrote:
> The parameter kfence_sample_interval can be set via boot parameter
> and late shell command, which is convenient for automatical tests

s/automatical/automated/

> and KFENCE parameter optimation. However, KFENCE test case just use

s/optimation/optimization/

> compile time CONFIG_KFENCE_SAMPLE_INTERVAL, this will make KFENCE
> test case not run as user desired. This patch will make KFENCE test
> case compatible with run-time-set sample interval.

I'm not too particular about it, but "This patch" is usually bad style:
https://www.kernel.org/doc/html/latest/process/submitting-patches.html#describe-your-changes

> v1->v2:
> - Use EXPORT_SYMBOL_GPL replace EXPORT_SYMBOL

Changelog is usually placed after '---', because it's mostly redundant
once committed. Often maintainers include a "Link" to the original
patch which then has history and discussion.

> Signed-off-by: Peng Liu <liupeng256@huawei.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  include/linux/kfence.h  | 2 ++
>  mm/kfence/core.c        | 3 ++-
>  mm/kfence/kfence_test.c | 8 ++++----
>  3 files changed, 8 insertions(+), 5 deletions(-)
>
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 4b5e3679a72c..f49e64222628 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -17,6 +17,8 @@
>  #include <linux/atomic.h>
>  #include <linux/static_key.h>
>
> +extern unsigned long kfence_sample_interval;
> +
>  /*
>   * We allocate an even number of pages, as it simplifies calculations to map
>   * address to metadata indices; effectively, the very first page serves as an
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 5ad40e3add45..13128fa13062 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -47,7 +47,8 @@
>
>  static bool kfence_enabled __read_mostly;
>
> -static unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
> +unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
> +EXPORT_SYMBOL_GPL(kfence_sample_interval); /* Export for test modules. */
>
>  #ifdef MODULE_PARAM_PREFIX
>  #undef MODULE_PARAM_PREFIX
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index a22b1af85577..50dbb815a2a8 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -268,13 +268,13 @@ static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocat
>          * 100x the sample interval should be more than enough to ensure we get
>          * a KFENCE allocation eventually.
>          */
> -       timeout = jiffies + msecs_to_jiffies(100 * CONFIG_KFENCE_SAMPLE_INTERVAL);
> +       timeout = jiffies + msecs_to_jiffies(100 * kfence_sample_interval);
>         /*
>          * Especially for non-preemption kernels, ensure the allocation-gate
>          * timer can catch up: after @resched_after, every failed allocation
>          * attempt yields, to ensure the allocation-gate timer is scheduled.
>          */
> -       resched_after = jiffies + msecs_to_jiffies(CONFIG_KFENCE_SAMPLE_INTERVAL);
> +       resched_after = jiffies + msecs_to_jiffies(kfence_sample_interval);
>         do {
>                 if (test_cache)
>                         alloc = kmem_cache_alloc(test_cache, gfp);
> @@ -608,7 +608,7 @@ static void test_gfpzero(struct kunit *test)
>         int i;
>
>         /* Skip if we think it'd take too long. */
> -       KFENCE_TEST_REQUIRES(test, CONFIG_KFENCE_SAMPLE_INTERVAL <= 100);
> +       KFENCE_TEST_REQUIRES(test, kfence_sample_interval <= 100);
>
>         setup_test_cache(test, size, 0, NULL);
>         buf1 = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
> @@ -739,7 +739,7 @@ static void test_memcache_alloc_bulk(struct kunit *test)
>          * 100x the sample interval should be more than enough to ensure we get
>          * a KFENCE allocation eventually.
>          */
> -       timeout = jiffies + msecs_to_jiffies(100 * CONFIG_KFENCE_SAMPLE_INTERVAL);
> +       timeout = jiffies + msecs_to_jiffies(100 * kfence_sample_interval);
>         do {
>                 void *objects[100];
>                 int i, num = kmem_cache_alloc_bulk(test_cache, GFP_ATOMIC, ARRAY_SIZE(objects),
> --
> 2.18.0.huawei.25
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP%2BJ-Ztz_sov0LPXS8nGCf-2oJFs0OJp1LQMBeaL00CBQ%40mail.gmail.com.
