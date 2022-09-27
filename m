Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX7PZOMQMGQEATOXUWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 639805EC411
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 15:17:20 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id i132-20020a1c3b8a000000b003b339a8556esf5538414wma.4
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 06:17:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664284640; cv=pass;
        d=google.com; s=arc-20160816;
        b=J+ccPJx32FNPvACJClA+Y3U22P6jztMrMh7ApdbmrTUHFxP7jSGMX8iYa5q/6Cghzk
         /I7hU2OKTjogp41K8q4HIy9hUY3GulM6jqg3V45/w4hfS5lFcxlx0F/MueMzFySRGQOC
         tDBMVojL8B6LVxxPwEcaXh1zJ8/wUlSbQ4EGCJCTVTQkigydr/ULLfya+jtBx+3kSvDR
         8ykqmAfIiQ5crBg2c+MZuVYfgBH4iaubAvYshGvguRtQd8Qy5hBT7X6MQSho/jqexNzg
         HEchDW2AMS9xhKBLdpuKHiwcnm03+dedOAo1+rtrmH/fRcUl1cZM9xYLnlDEjX23gmv3
         nPvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=xlb1w3d0JIj89BfEEzlET1kLuexz097VPMzO9E+yx58=;
        b=xQ1YiA8Si9mbcWUFSKjTtZ2WjKC/HnWvIphR1h0Nhj6MI1xMSPC2noduC339zbEjub
         9IABaDOZU9elquvLBWNaOo2MZM/1PCpKkvEx5H7jr24dnLHjQ9BpP5kdjwznzi1ZGtOA
         R2M2e7NOtqR1rfKofcm4dNIDLc3sx39SWCNQFyOtEQcrID1c6S5d99SA2v3HVNMSMBXw
         lpzEhctKdgENnb3HcBvlj4ppcZ7ZXXXQdkli+ES2idtPJwVGNH8kctILElyM0Xqae5ST
         +GFpZh67jUnsQjl9echn8B2inulPUKDTye5HRaVqWHIESDF67qi8f94eYMwon6o/3LyP
         I/og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MPWNC1rE;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date;
        bh=xlb1w3d0JIj89BfEEzlET1kLuexz097VPMzO9E+yx58=;
        b=X9ylMh6SCPx2A1NWdl2cQ/ykwe41xaZTcIR91y4YFiGkJg8gntDPNe5vBK2Ubh2jHo
         1kF0/eFnRxMhGbysnDzXNC0e+SOyRMQKYAjQL6CyOYIsyFwbbc+HKsJyJC0wHkr/pfjt
         EcTvunTHSBDsx3xvYcoE9kINvp9Y8e7SzunF3JtPlpxbeU3Zp9SHMTElDzMuL3ioHSOz
         qRR5eVxCNScwm264FIclaAd0ChsODJgdHNkvYYM9J6Th3txWd/KV4nOABuleIBt/CQGi
         ElM/3xCuiRJwJi9deTY6pewYA/Ug15NACIOcffORo9ss/IMA4NZhSJNtMW7JG2Vk4epp
         an1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=xlb1w3d0JIj89BfEEzlET1kLuexz097VPMzO9E+yx58=;
        b=w6Wp7smjEfVwWBbYPIJQfFhlYTfVPFfCilgruT8ZWbmGTZvfUdpfeD5dqHoLWHWYOT
         bj5OOk2VTYZyNoJbyfUrYbPzenJZA2UIGLvNPOh5xXwvZgEZWAiHJjDfASGQpTpVQICu
         EPsuJP48c0wJ11tVUKL+j6RAN9hXjCIlN3YJKCfJ4zlVXLEUsIIt4dyZMSTcYUX3M7lV
         dyqSdpr166mfkoGgEUEJQkytQqCskqww7JEogC3BQBRvx4BpjYnR3ndc7a/8NBKaOn9o
         5zRR5gWkQ7inHhLQ7DUUhkloT2RRT/wdBCKBCddMUoEc7nLHrt5uCvOi5nyaIPDidLoh
         ybew==
X-Gm-Message-State: ACrzQf2DKqd18Duu40q79Inio4z/4vfdntLDX9m8oC8YeufXBiKySMSE
	1xGf3OlQztsksTlrzO6AYk8=
X-Google-Smtp-Source: AMsMyM6CjDMvEnudoVg7xDcxc3Wth8vv2UPNoWMV6GB8IGlH9JFHp4D+plmSe6eexByzcwc24x3xSg==
X-Received: by 2002:a5d:50c1:0:b0:228:d77e:4b33 with SMTP id f1-20020a5d50c1000000b00228d77e4b33mr16435898wrt.677.1664284639953;
        Tue, 27 Sep 2022 06:17:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6002:b0:3b4:fe03:c8a2 with SMTP id
 az2-20020a05600c600200b003b4fe03c8a2ls4839347wmb.0.-pod-canary-gmail; Tue, 27
 Sep 2022 06:17:18 -0700 (PDT)
X-Received: by 2002:a05:600c:3ac9:b0:3b4:bed4:d69 with SMTP id d9-20020a05600c3ac900b003b4bed40d69mr2720132wms.131.1664284638680;
        Tue, 27 Sep 2022 06:17:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664284638; cv=none;
        d=google.com; s=arc-20160816;
        b=CBUQ7kTxGjpnZuuGN+xmp+nmu4vONOxgaTq+eFfs1OBZ+GL/20Qf0qEIg82k3IDWMT
         rTlcUzCiT0KqwkX2M0+R5Nq8iuJKvbu7L3YTN7msIVmTdsFFCmytEt06zkIhkVW19z9L
         33Lz6dj4sF207pidJfA+XElb8ead5o4yyASIMIoLzWOpKSluo7yycX/1e+ugGUcY5ngf
         0EzWu/JTXsYE3lsnUlxrFcTzrrHfD4mD2TSewt33a7PutcDdjpZS2bL5njPbnyN8JyOD
         /gwIi4bwztRgabPUV7t9VNom+1ifbGIPOWEt9m/T2sI9/i69OlmEs4iUZhslEZV7f9Ey
         pypQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=In1vsB/Xjfh9ZnfNvqM8dWCAty6NwecZWkJggwcWzrI=;
        b=ps/r9Q7K92/toyMNyX4ShmK7mSMzwpCh1JQefQ0HICLp3s5btVgT/i34U0D+JEjLVb
         z3M4rxzr0zD60jjaNJbJfuSPjBtIo8ahvVnRDaJKXN15FIlWvkV0RqXaUqFigUb7O0Re
         cc0ZuSBL1PnYU93WXxVKp0BI5JI/3qwSir7gb+hCjBE9ucEqmpiROdHcNOxi6oY2aeaB
         6oKsGRl2OrhFEMyMa/C1jD9KARpe7nULXVUNh8uPU2NHidguBgW2YzROSZAMOqCFOsR7
         9EAokJbv8OHQCD7z8lnkb0/sbo6IzdyneNs80ft0iPtyubhuH0yF0tKKAbiID0s7qiD3
         lFQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MPWNC1rE;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id n42-20020a05600c502a00b003a54f1563c9si451957wmr.0.2022.09.27.06.17.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Sep 2022 06:17:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id m3so13126640eda.12
        for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 06:17:18 -0700 (PDT)
X-Received: by 2002:aa7:cc8a:0:b0:446:7668:2969 with SMTP id p10-20020aa7cc8a000000b0044676682969mr27808864edt.206.1664284638152;
        Tue, 27 Sep 2022 06:17:18 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:693c:15a1:a531:bb4e])
        by smtp.gmail.com with ESMTPSA id 22-20020a170906311600b0077fbef08212sm100359ejx.22.2022.09.27.06.17.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Sep 2022 06:17:17 -0700 (PDT)
Date: Tue, 27 Sep 2022 15:17:10 +0200
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
Subject: Re: [PATCH mm 3/3] kasan: migrate workqueue_uaf test to kunit
Message-ID: <YzL31u9qOOPRVVHM@elver.google.com>
References: <653d43e9a6d9aad2ae148a941dab048cb8e765a8.1664044241.git.andreyknvl@google.com>
 <2815073f2be37e554f7f0fd7b1d10e9742be6ce3.1664044241.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <2815073f2be37e554f7f0fd7b1d10e9742be6ce3.1664044241.git.andreyknvl@google.com>
User-Agent: Mutt/2.2.7 (2022-08-07)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=MPWNC1rE;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::530 as
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
> Migrate the workqueue_uaf test to the KUnit framework.
> 
> Initially, this test was intended to check that Generic KASAN prints
> auxiliary stack traces for workqueues. Nevertheless, the test is enabled
> for all modes to make that KASAN reports bad accesses in the tested
> scenario.
> 
> The presence of auxiliary stack traces for the Generic mode needs to be
> inspected manually.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/kasan_test.c        | 40 +++++++++++++++++++++++++++++-------
>  mm/kasan/kasan_test_module.c | 30 ---------------------------
>  2 files changed, 33 insertions(+), 37 deletions(-)
> 
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 005776325e20..71cb402c404f 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -1134,6 +1134,14 @@ static void kmalloc_double_kzfree(struct kunit *test)
>  	KUNIT_EXPECT_KASAN_FAIL(test, kfree_sensitive(ptr));
>  }
>  
> +/*
> + * The two tests below check that Generic KASAN prints auxiliary stack traces
> + * for RCU callbacks and workqueues. The reports need to be inspected manually.
> + *
> + * These tests are still enabled for other KASAN modes to make sure that all
> + * modes report bad accesses in tested scenarios.
> + */
> +
>  static struct kasan_rcu_info {
>  	int i;
>  	struct rcu_head rcu;
> @@ -1148,13 +1156,6 @@ static void rcu_uaf_reclaim(struct rcu_head *rp)
>  	((volatile struct kasan_rcu_info *)fp)->i;
>  }
>  
> -/*
> - * Check that Generic KASAN prints auxiliary stack traces for RCU callbacks.
> - * The report needs to be inspected manually.
> - *
> - * This test is still enabled for other KASAN modes to make sure that all modes
> - * report bad accesses in tested scenarios.
> - */
>  static void rcu_uaf(struct kunit *test)
>  {
>  	struct kasan_rcu_info *ptr;
> @@ -1170,6 +1171,30 @@ static void rcu_uaf(struct kunit *test)
>  		rcu_barrier());
>  }
>  
> +static void workqueue_uaf_work(struct work_struct *work)
> +{
> +	kfree(work);
> +}
> +
> +static void workqueue_uaf(struct kunit *test)
> +{
> +	struct workqueue_struct *workqueue;
> +	struct work_struct *work;
> +
> +	workqueue = create_workqueue("kasan_workqueue_test");
> +	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, workqueue);
> +
> +	work = kmalloc(sizeof(struct work_struct), GFP_KERNEL);
> +	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, work);
> +
> +	INIT_WORK(work, workqueue_uaf_work);
> +	queue_work(workqueue, work);
> +	destroy_workqueue(workqueue);
> +
> +	KUNIT_EXPECT_KASAN_FAIL(test,
> +		((volatile struct work_struct *)work)->data);
> +}
> +
>  static void vmalloc_helpers_tags(struct kunit *test)
>  {
>  	void *ptr;
> @@ -1502,6 +1527,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>  	KUNIT_CASE(kasan_bitops_tags),
>  	KUNIT_CASE(kmalloc_double_kzfree),
>  	KUNIT_CASE(rcu_uaf),
> +	KUNIT_CASE(workqueue_uaf),
>  	KUNIT_CASE(vmalloc_helpers_tags),
>  	KUNIT_CASE(vmalloc_oob),
>  	KUNIT_CASE(vmap_tags),
> diff --git a/mm/kasan/kasan_test_module.c b/mm/kasan/kasan_test_module.c
> index 4688cbcd722d..7be7bed456ef 100644
> --- a/mm/kasan/kasan_test_module.c
> +++ b/mm/kasan/kasan_test_module.c
> @@ -62,35 +62,6 @@ static noinline void __init copy_user_test(void)
>  	kfree(kmem);
>  }
>  
> -static noinline void __init kasan_workqueue_work(struct work_struct *work)
> -{
> -	kfree(work);
> -}
> -
> -static noinline void __init kasan_workqueue_uaf(void)
> -{
> -	struct workqueue_struct *workqueue;
> -	struct work_struct *work;
> -
> -	workqueue = create_workqueue("kasan_wq_test");
> -	if (!workqueue) {
> -		pr_err("Allocation failed\n");
> -		return;
> -	}
> -	work = kmalloc(sizeof(struct work_struct), GFP_KERNEL);
> -	if (!work) {
> -		pr_err("Allocation failed\n");
> -		return;
> -	}
> -
> -	INIT_WORK(work, kasan_workqueue_work);
> -	queue_work(workqueue, work);
> -	destroy_workqueue(workqueue);
> -
> -	pr_info("use-after-free on workqueue\n");
> -	((volatile struct work_struct *)work)->data;
> -}
> -
>  static int __init test_kasan_module_init(void)
>  {
>  	/*
> @@ -101,7 +72,6 @@ static int __init test_kasan_module_init(void)
>  	bool multishot = kasan_save_enable_multi_shot();
>  
>  	copy_user_test();
> -	kasan_workqueue_uaf();
>  
>  	kasan_restore_multi_shot(multishot);
>  	return -EAGAIN;
> -- 
> 2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzL31u9qOOPRVVHM%40elver.google.com.
