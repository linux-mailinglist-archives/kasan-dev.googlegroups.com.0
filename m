Return-Path: <kasan-dev+bncBAABBCHPR34AKGQEMH43JEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D54B216277
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Jul 2020 01:45:13 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id h10sf12518087uar.6
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Jul 2020 16:45:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594079112; cv=pass;
        d=google.com; s=arc-20160816;
        b=If+lHmFBQ1MfjjKNj56ICZ0yGnioj2Iu3XEnTCyfulS7oMEJlCQymyeke72obJKcHF
         6L99QgjWa6lxffT+NQS+SvLTDJjOyxLb/SjtYo1mYlNzzh20Avujc9B3nTRk1Dzx+ikK
         9NiEDRxGw/+BqqcpfEootGvoF9Zavk57wZK3Gejq9PQMzAzAmfxkXg2Gbp51yD0rEhPB
         kMa2fspLJ8lbaiEtJgRYD5iYW6gSYjMzbwocyT8nnnds+19jnxuwyaZCBP1TlhlutWQW
         gNlbvMg+/xdUyb8Bc4E0vnnYhawPPt++2M/VBlf5Rxo/ZvqrvbrumJjf2AePEwluhnKw
         6dDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=c3Utc8xeM1Hv63lSwAkisdYKGoC9MbIyi87xHT96v0s=;
        b=c1E5+0yV3wLYB+T4TalVGYwPOtUsI4KhMcAkQhEvMlVisxjRdu+Edok+9pmD9tBeiw
         nNYAB3eyNe98x3HBAJL1wwfnNyWVY2tERxdltmjZnX4JkM8xdRShGzDg4aMTY3j940S4
         L8DqG8e2sNyfawh1AStshlDztq/2lNxp1V3fjXjBbsuaPkqCmakIQNXSxy7MaI456QmZ
         6Ik/wbQUxKfB/AUhhnDJ4BHSOiFiV39Y3VE9bPz2gTXBSaj28SPb+ID4jQKhaEcUie5P
         wKYqMvF02J6rQdqe1LNaaHN1CBJnRai0fnwpXgGYiKAcwRH2RNagKBynx69iFoA7Wz21
         TRIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=MSK20KXa;
       spf=pass (google.com: domain of srs0=6sad=ar=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6SaD=AR=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c3Utc8xeM1Hv63lSwAkisdYKGoC9MbIyi87xHT96v0s=;
        b=ODwBfQ6R5ZYEjr8YyKLsBwvWxCozvaRzuzlGVqmPSWWcqJcf2aD98QF6D9td0GEg9+
         a1vNwOosUo+0UripDITkmkLx3C8NElB0ge34JUcCGYOMcCf2o0XJ+30v91aBqArOiuJz
         4klU1ODsqfWTpUMQlkeQ/YOoD4xgTGJ+XtrZ6daYaDcNbDadEbGjYNL6bXMQIuCMokwA
         9zDeunAtlxElql0W19xbKrjQVkqsrYzfPqZ4wzKO0CyB0IeXe4WCzD8oQniYoCpeVJ0Z
         qSkUs+8A54ge0nC5J9dxAmS6pKSdDD6r5Zu/6IjC+imoZEgainW4IGOsibQZWmZGCihA
         BNOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=c3Utc8xeM1Hv63lSwAkisdYKGoC9MbIyi87xHT96v0s=;
        b=fi9uGxFJt8v3AC54hMoyskGRxz8iOJcpgPz8cR6SYR/+oLSwm4V4jcosAOU3E4Xxo6
         f7yUfTmtiH41oQiu1S+0z3IIC8QDv5RtS0kpJqvXcjaSGKo8nAARwE2UCOkPi8woPLdd
         zfoQMhJLYeuGl7pJQQ+mvyGhykDMBh0klURpoHV+pO53sfd6XusVwQt8VDfqZNlrJpCs
         7rx0FgCKI3+xWQzy2vxAJSBvYNRRMkvKO4R99BicrqmtZRByaKgG1nvD/0bn2InjH4MR
         PqxJhe+lACg+OWZaOFEAQ18GA139gx4gA//Q+be51rkim+S3h9O65CKImiectd2g6Gax
         2U6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Ple+STJZD+aaLYqs7BZVRs+U/gn4/KPsiX/DHP+CfBGgwvqIA
	faD8EYbsZsKaWh75KS8tNz4=
X-Google-Smtp-Source: ABdhPJyKGj85emhf22QPWnWHY+piWNyc9/07/W35kqxnl7LpA0LS2pcqDIMXtNf5E35wSKn6JeROUg==
X-Received: by 2002:ab0:7858:: with SMTP id y24mr19366414uaq.89.1594079112425;
        Mon, 06 Jul 2020 16:45:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3e05:: with SMTP id o5ls1246420uai.8.gmail; Mon, 06 Jul
 2020 16:45:12 -0700 (PDT)
X-Received: by 2002:ab0:498e:: with SMTP id e14mr29228582uad.38.1594079112126;
        Mon, 06 Jul 2020 16:45:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594079112; cv=none;
        d=google.com; s=arc-20160816;
        b=zr+sfy3aqvtzwvAHtLEJBIItXKf0nWXTngOl9hQyyRV6htbQO2SBjpHZKQgBTCM+Sc
         MXkS093tQ0X5b1oWYRzjt0RnaM+sPXBBmYrvPVq9RM6gBnCMcGZD8FvngcPIXyWa46m7
         wZTscZ6ZWgFswaDjZFF+EUBOWCssquuQxricrPAfmIZbDeHbpdWl09xerjohpOgdTNq1
         cGMTVv/dcBYGE3f5wdekOE4G5mSaJQWdhORyC8YBGJmCdLSbk29OH3WmjECPT3arwFzO
         4RE0OrWtLQVWo2h9AUi9kVwc4htVhkZ9yhF0KVLfZniGDhu6GC/AhmXjqoA1dy4v+ozF
         8n7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=hSPhFUoLN5sov8or4QhsPzGqRYZdf27efRzR3KAiFcA=;
        b=dVZP/BLlKEeIgYV8SK/gxpPNBgrDIPs2F14Gwq8PWbp6wGMHalB00nKiOkIQhkmc4z
         dRJNePqL0rk1MFOgDL9MhwNM5NU4f2nRvPAxvuFXDFb8mA77w9UPHBOEeRxKU2CApYjM
         1Kn0hl7m25yg6XbyQ1bwBv/P7M+8AsCWbKWHDijw/mkb69Yi4mb0axS+ZEpmxjR7nHHu
         9UhWO2SEYUUHpyCWHZaMb871PPzDW5359JrHv8jKH+5rKYHhkZOiAibWszq767gWryv0
         E5RCNEIQo5uYJkTbJ0QhdecX6kTbAs5McILzCaKCBRtypCz8oIs/zuny5ZDV0LpsI87g
         tOHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=MSK20KXa;
       spf=pass (google.com: domain of srs0=6sad=ar=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6SaD=AR=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t26si919194uap.0.2020.07.06.16.45.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 06 Jul 2020 16:45:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6sad=ar=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-111-31.bvtn.or.frontiernet.net [50.39.111.31])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1DC34206E9;
	Mon,  6 Jul 2020 23:45:11 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 054F93522637; Mon,  6 Jul 2020 16:45:11 -0700 (PDT)
Date: Mon, 6 Jul 2020 16:45:11 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 3/3] kcsan: Add atomic builtin test case
Message-ID: <20200706234510.GA20540@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200703134031.3298135-1-elver@google.com>
 <20200703134031.3298135-3-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200703134031.3298135-3-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=MSK20KXa;       spf=pass
 (google.com: domain of srs0=6sad=ar=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6SaD=AR=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Jul 03, 2020 at 03:40:31PM +0200, Marco Elver wrote:
> Adds test case to kcsan-test module, to test atomic builtin
> instrumentation works.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Applied all three, thank you!!!

							Thanx, Paul

> ---
>  kernel/kcsan/kcsan-test.c | 63 +++++++++++++++++++++++++++++++++++++++
>  1 file changed, 63 insertions(+)
> 
> diff --git a/kernel/kcsan/kcsan-test.c b/kernel/kcsan/kcsan-test.c
> index fed6fcb5768c..721180cbbab1 100644
> --- a/kernel/kcsan/kcsan-test.c
> +++ b/kernel/kcsan/kcsan-test.c
> @@ -390,6 +390,15 @@ static noinline void test_kernel_seqlock_writer(void)
>  	write_sequnlock_irqrestore(&test_seqlock, flags);
>  }
>  
> +static noinline void test_kernel_atomic_builtins(void)
> +{
> +	/*
> +	 * Generate concurrent accesses, expecting no reports, ensuring KCSAN
> +	 * treats builtin atomics as actually atomic.
> +	 */
> +	__atomic_load_n(&test_var, __ATOMIC_RELAXED);
> +}
> +
>  /* ===== Test cases ===== */
>  
>  /* Simple test with normal data race. */
> @@ -852,6 +861,59 @@ static void test_seqlock_noreport(struct kunit *test)
>  	KUNIT_EXPECT_FALSE(test, match_never);
>  }
>  
> +/*
> + * Test atomic builtins work and required instrumentation functions exist. We
> + * also test that KCSAN understands they're atomic by racing with them via
> + * test_kernel_atomic_builtins(), and expect no reports.
> + *
> + * The atomic builtins _SHOULD NOT_ be used in normal kernel code!
> + */
> +static void test_atomic_builtins(struct kunit *test)
> +{
> +	bool match_never = false;
> +
> +	begin_test_checks(test_kernel_atomic_builtins, test_kernel_atomic_builtins);
> +	do {
> +		long tmp;
> +
> +		kcsan_enable_current();
> +
> +		__atomic_store_n(&test_var, 42L, __ATOMIC_RELAXED);
> +		KUNIT_EXPECT_EQ(test, 42L, __atomic_load_n(&test_var, __ATOMIC_RELAXED));
> +
> +		KUNIT_EXPECT_EQ(test, 42L, __atomic_exchange_n(&test_var, 20, __ATOMIC_RELAXED));
> +		KUNIT_EXPECT_EQ(test, 20L, test_var);
> +
> +		tmp = 20L;
> +		KUNIT_EXPECT_TRUE(test, __atomic_compare_exchange_n(&test_var, &tmp, 30L,
> +								    0, __ATOMIC_RELAXED,
> +								    __ATOMIC_RELAXED));
> +		KUNIT_EXPECT_EQ(test, tmp, 20L);
> +		KUNIT_EXPECT_EQ(test, test_var, 30L);
> +		KUNIT_EXPECT_FALSE(test, __atomic_compare_exchange_n(&test_var, &tmp, 40L,
> +								     1, __ATOMIC_RELAXED,
> +								     __ATOMIC_RELAXED));
> +		KUNIT_EXPECT_EQ(test, tmp, 30L);
> +		KUNIT_EXPECT_EQ(test, test_var, 30L);
> +
> +		KUNIT_EXPECT_EQ(test, 30L, __atomic_fetch_add(&test_var, 1, __ATOMIC_RELAXED));
> +		KUNIT_EXPECT_EQ(test, 31L, __atomic_fetch_sub(&test_var, 1, __ATOMIC_RELAXED));
> +		KUNIT_EXPECT_EQ(test, 30L, __atomic_fetch_and(&test_var, 0xf, __ATOMIC_RELAXED));
> +		KUNIT_EXPECT_EQ(test, 14L, __atomic_fetch_xor(&test_var, 0xf, __ATOMIC_RELAXED));
> +		KUNIT_EXPECT_EQ(test, 1L, __atomic_fetch_or(&test_var, 0xf0, __ATOMIC_RELAXED));
> +		KUNIT_EXPECT_EQ(test, 241L, __atomic_fetch_nand(&test_var, 0xf, __ATOMIC_RELAXED));
> +		KUNIT_EXPECT_EQ(test, -2L, test_var);
> +
> +		__atomic_thread_fence(__ATOMIC_SEQ_CST);
> +		__atomic_signal_fence(__ATOMIC_SEQ_CST);
> +
> +		kcsan_disable_current();
> +
> +		match_never = report_available();
> +	} while (!end_test_checks(match_never));
> +	KUNIT_EXPECT_FALSE(test, match_never);
> +}
> +
>  /*
>   * Each test case is run with different numbers of threads. Until KUnit supports
>   * passing arguments for each test case, we encode #threads in the test case
> @@ -891,6 +953,7 @@ static struct kunit_case kcsan_test_cases[] = {
>  	KCSAN_KUNIT_CASE(test_assert_exclusive_access_scoped),
>  	KCSAN_KUNIT_CASE(test_jiffies_noreport),
>  	KCSAN_KUNIT_CASE(test_seqlock_noreport),
> +	KCSAN_KUNIT_CASE(test_atomic_builtins),
>  	{},
>  };
>  
> -- 
> 2.27.0.212.ge8ba1cc988-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200706234510.GA20540%40paulmck-ThinkPad-P72.
