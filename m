Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK7PZOMQMGQESNI7VKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 810875EC400
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 15:16:28 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id e15-20020a056402190f00b0044f41e776a0sf7743279edz.0
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 06:16:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664284588; cv=pass;
        d=google.com; s=arc-20160816;
        b=CYJEE0vggU93zJEQRTGVJY0XubxXnvkCkUHniLSf7WJszf4BOLblIz7/I7RmElS/AG
         JUeO8V45g77pWCASmM8bcmhCDrOMGklYZsmpyCCzpZnxWwNQoZnF/XaZTf8XtP9cZm09
         Wvg6GjbDWi3nrFX6Sf/qW6cN6iWyJDRBmE9o7Mk4PykL4Q9qrvQceSWQXZCAsMNJW5xr
         3omGC/qpq5qm6LzM9WHOZ3DAKZv89uqSevqHMcryMULjiPuBQPMoIhqRVZgezkA2zVx5
         ON5YRkz+9myEV0QeX6DDDsfVpZ39YQeYa5nPRQ5Q0Nvchi4uYopQowTrbMTKi+LANINI
         28+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=u8VHWaaxsaXRcUK0cYK9Oc1zHbwOToef8Qnr3YWzpfc=;
        b=CbRP2qan9b1HWOz1cAnc1TSc/LFEiKToE/mxe4DP4SPyA0bBTEAAopSZJkfSeRbkT3
         K9Es4Tw8UBYHeTdpvOtM/6AyixNv+2d4hHYsoIx1d2UVOvBKmK0GM9H3VwtWSyvw307E
         WwdSigyDKDPmCRsuRptAQAW2BorHVIsbIK+irgFectNNnYjjTiXEqfdDp9/PT0hX4yMu
         Xqoh/sR+3OYBopYRo1G8AD9QSlTk+QF9HbQWLNSf3DTIdcajgrX4lFEWl839d5hDT6Pu
         phM6ew6TIFJ2hDHMLgNgNkPw7yPUWiIBs5cmrom7Hss3s/3eLVhGWjzrfCSs0XtvfD3p
         uR3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WAFjLp8r;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date;
        bh=u8VHWaaxsaXRcUK0cYK9Oc1zHbwOToef8Qnr3YWzpfc=;
        b=IwnuePwrwxE9C591mZpeVGRtj3TE08lMg1+lDpjhFE15jXMR6Bk5rSdVsWn96ilixo
         guD5JKwtWklNQNSTSH59yhYh4L+cH3RlqQE6wj+RFQ3bZlLDHOZTLZOfKWTN51MmGh6B
         M2VeCR62QVRVPPiPQPCf4/Pi2u3caI3y1IKiPiPW81j+QVtykhPmvXcwP4oxPV9W1Kvg
         Zi5/3kT9nZgiqxPP9jGy9GrM1j7vshyPhmOjbkyFYpik8//dpIAaNyt0TmArZDjAWEfH
         e5xNrjSJlBZTzRNClB2rkadXRiBhITlWXDBJjrhRO0Bk8z3T44BdnwDqhjfYO8l5q0wq
         q2EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=u8VHWaaxsaXRcUK0cYK9Oc1zHbwOToef8Qnr3YWzpfc=;
        b=5U03gftHIN0SqQ4s3vndqGua7msRMLtoCsfApsVUarrIbHpGMpoECGcWHPrJP94LdZ
         eFywujZxilODtesOvOPoHtHP5yxFvs65NW+5+gwH6rZbAA4PEHxbK2VKkoUFj91b+lQi
         qdieERy9a2lpQKZ0PD//u88QQEOCSWRl/V5YisjopAfCfBwxN9lSVX2EBsYa5eYnLtTT
         ypxnK3RvItwqy43Ji1PeHP5AXAoPK4tPL7bOvi/NVtXkFVUU+gqzx73wqJEANAkR8ulz
         mmqCEkiHp1X5cGlf6yY+o9llb3ouPUbBBLt/PG4DbeHpBTlIJOKI6nUnKojPhcdsFJsn
         sTjA==
X-Gm-Message-State: ACrzQf0+IqduYNahNpXX6D+zDOhRQLMXfOKRGamiD/EIQxXbSIS0jnZJ
	NsmA3/anCFrrdAmkFZ22BRA=
X-Google-Smtp-Source: AMsMyM7Lfl9RXUhB2DrDxQy6E0eC8V1ZN4z/MpVqIEJz+BQkfgWA7Byv/CfrIIipW4gxmAiuXyMbaw==
X-Received: by 2002:a17:907:60c7:b0:77c:7f13:7da3 with SMTP id hv7-20020a17090760c700b0077c7f137da3mr22259373ejc.210.1664284588055;
        Tue, 27 Sep 2022 06:16:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2551:b0:44e:93b9:21c8 with SMTP id
 l17-20020a056402255100b0044e93b921c8ls1963825edb.1.-pod-prod-gmail; Tue, 27
 Sep 2022 06:16:26 -0700 (PDT)
X-Received: by 2002:a05:6402:450c:b0:443:6279:774f with SMTP id ez12-20020a056402450c00b004436279774fmr27828317edb.11.1664284586689;
        Tue, 27 Sep 2022 06:16:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664284586; cv=none;
        d=google.com; s=arc-20160816;
        b=eDLOr565qht4caUZoIawugV6AWYV8+ofQTC5IpUdLQqM3Pg9nkxl7MIZXtkQ0Y5/bV
         i/D+QFCg+Lnp2onHHruDnG2QQsS6oNPqycLOUk/97Nev7hMZLVxQAwLgWVuXKanoQvZL
         KbxyUGMim7cVI2gYUACGeVj0TFqHEUBYylIs3wyg8YldHovkgWvKsPFaEqnkuiQWZTJj
         qGVOgrr4QebkYYzXXTbxlKWKP71j8HQjWJv5DrHDfFhi3t2b0o1qJIbbKOtw0Qhix5Wr
         vQploaxGMEqlosuiRYVDAjRDtahROGN75cKsttGY2QBMGZgdGFchUYyyiYNDCRs228xY
         o1Dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=gOghRmjXnciU76OT1A5CBEYlu/dhJhD2q5qbX7Y7RKE=;
        b=Xg6H6netzn8mhoNVie/30HduR0pdrEfInur4JtWiT4elj3YtekFu5vFLqTmdvJ26/n
         8GfeQsHFucpbYV7UUWRdyFY6ScPryxOF1/4+RJPlKbDcSwayMeLT5EVu7RpzpBsyLSa9
         OJGXnyeITzE30JkhqKQ2EcC7nsSlvcSNJx69N9K+VKw3HRWWKK0tOYkp9Vf6WGOVQxuS
         ogFpd9Fk8QsV+UXeam28SeK0fukdChwOeiK/HtTi6Eel+50ae+ngabO8wiIFoXNNbs3E
         w4+46Jl6mhHPXqoVA0cZmA1xKGWesYqeStZrKW9VIJ77WRm5q9qfTgbwYtftEm9k6SpG
         Dqtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WAFjLp8r;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x62c.google.com (mail-ej1-x62c.google.com. [2a00:1450:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id my7-20020a1709065a4700b0073d9d812170si72790ejc.1.2022.09.27.06.16.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Sep 2022 06:16:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62c as permitted sender) client-ip=2a00:1450:4864:20::62c;
Received: by mail-ej1-x62c.google.com with SMTP id dv25so20561706ejb.12
        for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 06:16:26 -0700 (PDT)
X-Received: by 2002:a17:906:8a6f:b0:780:96b4:d19e with SMTP id hy15-20020a1709068a6f00b0078096b4d19emr22599889ejc.624.1664284586284;
        Tue, 27 Sep 2022 06:16:26 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:693c:15a1:a531:bb4e])
        by smtp.gmail.com with ESMTPSA id u24-20020a056402065800b004571907240asm1270416edx.36.2022.09.27.06.16.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Sep 2022 06:16:25 -0700 (PDT)
Date: Tue, 27 Sep 2022 15:16:20 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm 2/3] kasan: migrate kasan_rcu_uaf test to kunit
Message-ID: <YzL3pIi/0vlAYCUB@elver.google.com>
References: <653d43e9a6d9aad2ae148a941dab048cb8e765a8.1664044241.git.andreyknvl@google.com>
 <bc3b1d29d8addd24738982c44b717fbbe6dff8e9.1664044241.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bc3b1d29d8addd24738982c44b717fbbe6dff8e9.1664044241.git.andreyknvl@google.com>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=WAFjLp8r;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::62c as
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

On Sat, Sep 24, 2022 at 08:31PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Migrate the kasan_rcu_uaf test to the KUnit framework.
> 
> Changes to the implementation of the test:
> 
> - Call rcu_barrier() after call_rcu() to make that the RCU callbacks get
>   triggered before the test is over.
> 
> - Cast pointer passed to rcu_dereference_protected as __rcu to get rid of
>   the Sparse warning.
> 
> - Check that KASAN prints a report via KUNIT_EXPECT_KASAN_FAIL.
> 
> Initially, this test was intended to check that Generic KASAN prints
> auxiliary stack traces for RCU objects. Nevertheless, the test is enabled
> for all modes to make that KASAN reports bad accesses in RCU callbacks.
> 
> The presence of auxiliary stack traces for the Generic mode needs to be
> inspected manually.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/kasan_test.c        | 37 ++++++++++++++++++++++++++++++++++++
>  mm/kasan/kasan_test_module.c | 30 -----------------------------
>  2 files changed, 37 insertions(+), 30 deletions(-)
> 
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 3a2886f85e69..005776325e20 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -1134,6 +1134,42 @@ static void kmalloc_double_kzfree(struct kunit *test)
>  	KUNIT_EXPECT_KASAN_FAIL(test, kfree_sensitive(ptr));
>  }
>  
> +static struct kasan_rcu_info {
> +	int i;
> +	struct rcu_head rcu;
> +} *global_rcu_ptr;
> +
> +static void rcu_uaf_reclaim(struct rcu_head *rp)
> +{
> +	struct kasan_rcu_info *fp =
> +		container_of(rp, struct kasan_rcu_info, rcu);
> +
> +	kfree(fp);
> +	((volatile struct kasan_rcu_info *)fp)->i;
> +}
> +
> +/*
> + * Check that Generic KASAN prints auxiliary stack traces for RCU callbacks.
> + * The report needs to be inspected manually.
> + *
> + * This test is still enabled for other KASAN modes to make sure that all modes
> + * report bad accesses in tested scenarios.
> + */
> +static void rcu_uaf(struct kunit *test)
> +{
> +	struct kasan_rcu_info *ptr;
> +
> +	ptr = kmalloc(sizeof(struct kasan_rcu_info), GFP_KERNEL);
> +	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +
> +	global_rcu_ptr = rcu_dereference_protected(
> +				(struct kasan_rcu_info __rcu *)ptr, NULL);
> +
> +	KUNIT_EXPECT_KASAN_FAIL(test,
> +		call_rcu(&global_rcu_ptr->rcu, rcu_uaf_reclaim);
> +		rcu_barrier());
> +}
> +
>  static void vmalloc_helpers_tags(struct kunit *test)
>  {
>  	void *ptr;
> @@ -1465,6 +1501,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>  	KUNIT_CASE(kasan_bitops_generic),
>  	KUNIT_CASE(kasan_bitops_tags),
>  	KUNIT_CASE(kmalloc_double_kzfree),
> +	KUNIT_CASE(rcu_uaf),
>  	KUNIT_CASE(vmalloc_helpers_tags),
>  	KUNIT_CASE(vmalloc_oob),
>  	KUNIT_CASE(vmap_tags),
> diff --git a/mm/kasan/kasan_test_module.c b/mm/kasan/kasan_test_module.c
> index e4ca82dc2c16..4688cbcd722d 100644
> --- a/mm/kasan/kasan_test_module.c
> +++ b/mm/kasan/kasan_test_module.c
> @@ -62,35 +62,6 @@ static noinline void __init copy_user_test(void)
>  	kfree(kmem);
>  }
>  
> -static struct kasan_rcu_info {
> -	int i;
> -	struct rcu_head rcu;
> -} *global_rcu_ptr;
> -
> -static noinline void __init kasan_rcu_reclaim(struct rcu_head *rp)
> -{
> -	struct kasan_rcu_info *fp = container_of(rp,
> -						struct kasan_rcu_info, rcu);
> -
> -	kfree(fp);
> -	((volatile struct kasan_rcu_info *)fp)->i;
> -}
> -
> -static noinline void __init kasan_rcu_uaf(void)
> -{
> -	struct kasan_rcu_info *ptr;
> -
> -	pr_info("use-after-free in kasan_rcu_reclaim\n");
> -	ptr = kmalloc(sizeof(struct kasan_rcu_info), GFP_KERNEL);
> -	if (!ptr) {
> -		pr_err("Allocation failed\n");
> -		return;
> -	}
> -
> -	global_rcu_ptr = rcu_dereference_protected(ptr, NULL);
> -	call_rcu(&global_rcu_ptr->rcu, kasan_rcu_reclaim);
> -}
> -
>  static noinline void __init kasan_workqueue_work(struct work_struct *work)
>  {
>  	kfree(work);
> @@ -130,7 +101,6 @@ static int __init test_kasan_module_init(void)
>  	bool multishot = kasan_save_enable_multi_shot();
>  
>  	copy_user_test();
> -	kasan_rcu_uaf();
>  	kasan_workqueue_uaf();
>  
>  	kasan_restore_multi_shot(multishot);
> -- 
> 2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzL3pIi/0vlAYCUB%40elver.google.com.
