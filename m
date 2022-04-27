Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4PTUSJQMGQEEKIPEYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0030F5116E2
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 14:41:21 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 26-20020a05600c021a00b003940660c053sf475403wmi.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 05:41:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651063281; cv=pass;
        d=google.com; s=arc-20160816;
        b=EuZMlW3FUeUVxPIueWMz8l+1AoCV5Xed+QLEuqbuSokTkTd/V2jmGqXK+36wq+Sm5Q
         pjzHY6QAcHu8QkDDK10tbChP29lNINQoBcei0B3JSDAwZI1+c4IcAz7UuvH+d56Xr08P
         I3RvEccW0bt7txJ7S351Vnc/LdLEUAXBT9QmlDsK50Hy6tClAHCQGhDIUlYV4w6sCbcK
         2nmGWHkulJTqnsTbbUpT/45T0frFwJNY1Dyy7FklNxHEg+WabZDG11OQZe28yIOyZC7/
         99USRcYxgupvgeUV92uzKPgG1OOtwotOms/Eu85GUGcfPkjwfiOBwFrSAB6WvmXWR0g/
         IzCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=bfUy24/ZwTBX9uE/dNRiYVdMGwfdFoIWJss2FCSDEwg=;
        b=cUI1w8dHqSN2A2+pBHdS6calMjW49RTRIOYWwr+/rGsujmcTuQQ3PA/9A2JUTrQU4k
         6Fqdpw5hB0wmUdGP3rkb/xwH9PP80UGisstFuDTv/OT2XHAOs5PHY/SYmeJbkjJ48mOR
         RTC2EMPeJPXULsozc/G4Cr6JIDhNdecudQsgUdlmn09U1/ovCTvBWhz/FVrpRSkfhp9k
         ghVo0ouU6k9eGEJWTbpJfwcSk6ve2VAI62U6v8Jo4l17Pczdpw5cwTjqe4g68UZhjxyY
         UXx4ZPJwf8WtBJLGvQUKXrpS8bTCre4s8EC1+rvwyfMJlUBqrF4yirtp8+YfK9U5SjXP
         yi3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ElTn2Yk9;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=bfUy24/ZwTBX9uE/dNRiYVdMGwfdFoIWJss2FCSDEwg=;
        b=F/I8w5eP4Q83O937Dymd6W1N9WRiVH7xl20Dhar1+JoB5jBcB/1YA1YECl+thaneUM
         +ldNinDB9n+PQdGMkqnBrMDsSTmqSmZQdB5F6Aq/nIy/kELP2h6NH/TbE3jd4vB7cn6X
         8RIdOaYJrQIo/CQ+7qWSjZQ/3EXtKaeN7yVYhZGN7ukFHjmAx1KoQHVrHMEOWfAvm1a0
         P18vpf/JxonRVpxVplEw5n+Dt0ZB6kfKYdbDuLk/zh2Mz6by8ciCpIDi97tkRj1S0SF4
         u4RBPKV6SyTbBYLw90A1laALzyBqB2UncDDhsQp9pliW3ZPYlxLV5ko1uQ7zC2/kOauJ
         CGww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bfUy24/ZwTBX9uE/dNRiYVdMGwfdFoIWJss2FCSDEwg=;
        b=oKCuKoWsz378tgJEIdytkMYZbOLpdEpEv6pSWvB26Cpzgw4vX3VbeE2wfsb8VwZdGe
         Vy3kjpxe/2HDDRFci2GhtvyE9HrstYpVxpT6iCkq9n3wJp3Y7L2fw2uy7lkZWxKxMs35
         3RwDgZBdHUtrhzr9ou1dzRyDbu1ksmWLxAYlmafESy5ku49DHk3sL0BYeO7wNSB1oA3j
         EJ+lqghCjWrn0S6TPTcDhSAKnyGTqxcSw1+6KxD2B72Hd4azmFtRSfcQKbWhay3MXdYZ
         s0x6gMPhpfiisqK2RhM9hyyhgi+OmNWhqDJlSyxlxO2dULlmPVwklOoWicLLqEs8gzmp
         AV4w==
X-Gm-Message-State: AOAM533XlRGf3WcXbOMaxmH3dBfhvX0cnloH6YoCm1xdY5B0lu8geQrk
	NPwcKwqy6nzZXqV+IwHyVVU=
X-Google-Smtp-Source: ABdhPJyfMdzdqDE+uNM8i8scXGeSR9bT76Yuz4lpdNL7uYk0YEvZK5tmEJ3gjcE7q9Dl1bDR8HwV2Q==
X-Received: by 2002:a1c:4d0d:0:b0:394:4de:539 with SMTP id o13-20020a1c4d0d000000b0039404de0539mr2186176wmh.124.1651063281560;
        Wed, 27 Apr 2022 05:41:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:34ce:b0:393:e84e:a015 with SMTP id
 d14-20020a05600c34ce00b00393e84ea015ls1007302wmq.0.canary-gmail; Wed, 27 Apr
 2022 05:41:20 -0700 (PDT)
X-Received: by 2002:a05:600c:22d2:b0:393:f4be:ea1f with SMTP id 18-20020a05600c22d200b00393f4beea1fmr8461570wmg.51.1651063280343;
        Wed, 27 Apr 2022 05:41:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651063280; cv=none;
        d=google.com; s=arc-20160816;
        b=TqvbZjiGdvcp3fO7OdMzoD32KbUraVE8cfrGt64mX8cVxmTCzqEnDo2mSBuSj4gMq6
         m4sREzBkUDM2rreLAdCwo0f7jOY0J2VNCcHeNBLDVoAPlRk+u9li7aMpIw3S4MH64PTi
         AW1aKuAW6FKxzq3GJMpv4tyRqPFQweWRMb7rps2uya09ahgkMSz34SD0d1VxoFuzt1i3
         hvxriUa1DnAAuJT2Sld+odUMjNpxkDYLMi2wJ/uU/aFAfXeU8ZX1L2/D2b7dxvZ+aS7T
         og0ht2pOmugL3FBHU8+5Ll7yJikNaDCFFCs6U9rEwlTTX2JQiRppuSblFMal0lUU25WH
         ZI4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=cbbrke0Y/62FpKxLP1THZreWJJ7JOW3ZusoLqpF2UmQ=;
        b=oYVgnc0rA0uaNDHeZpTS6i8H9gxFWFXCQ2wO9tCFb+S7YLFQbZ+bl2wQjgyzkqbsCu
         PzH3wonSd4Rfb1CUAHxlaLqZEPLvGcUhYQfPaz1il9FM5mhI2HuVMW37CE3h7YNaRltb
         RyX6aT2QDBV8S6V4RHRQ8Kv+8ACe+tQzFz2qnif/irJhm6Y4dtR2wEZXJKy2GzVrYjFQ
         V3+kXGo6wIP2nK40SVjQhGXU/ZN4PDAIHP6JVioLbmYN8emEjWUUMFvmfkia9BX0inqf
         3vTt6NtVoZ3khmOjsZ6YkW5eVtqGchCfMQ4J7cY38VebIXZJrjnZ2GjxGoYy6h1jAMXd
         N0Wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ElTn2Yk9;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id d10-20020a05600c34ca00b00393ed6e46d8si99759wmq.2.2022.04.27.05.41.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Apr 2022 05:41:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 1-20020a05600c248100b00393fbf11a05so2337133wms.3
        for <kasan-dev@googlegroups.com>; Wed, 27 Apr 2022 05:41:20 -0700 (PDT)
X-Received: by 2002:a05:600c:3d0e:b0:38f:f83b:e7dc with SMTP id bh14-20020a05600c3d0e00b0038ff83be7dcmr34426400wmb.29.1651063279745;
        Wed, 27 Apr 2022 05:41:19 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:493f:cd0f:324a:323c])
        by smtp.gmail.com with ESMTPSA id p1-20020a1c7401000000b0038ed3bb00c9sm1471152wmc.6.2022.04.27.05.41.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Apr 2022 05:41:18 -0700 (PDT)
Date: Wed, 27 Apr 2022 14:41:13 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Daniel Latypov <dlatypov@google.com>
Cc: brendanhiggins@google.com, davidgow@google.com,
	linux-kernel@vger.kernel.org, kunit-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org, skhan@linuxfoundation.org,
	kasan-dev@googlegroups.com, glider@google.com
Subject: Re: [PATCH 3/3] kfence: test: use new suite_{init/exit} support, add
 .kunitconfig
Message-ID: <Ymk56YygGUU52CHG@elver.google.com>
References: <20220426181925.3940286-1-dlatypov@google.com>
 <20220426181925.3940286-3-dlatypov@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220426181925.3940286-3-dlatypov@google.com>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ElTn2Yk9;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::331 as
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

On Tue, Apr 26, 2022 at 11:19AM -0700, 'Daniel Latypov' via kasan-dev wrote:
> Currently, the kfence test suite could not run via "normal" means since
> KUnit didn't support per-suite setup/teardown. So it manually called
> internal kunit functions to run itself.
> This has some downsides, like missing TAP headers => can't use kunit.py
> to run or even parse the test results (w/o tweaks).
> 
> Use the newly added support and convert it over, adding a .kunitconfig
> so it's even easier to run from kunit.py.
> 
> People can now run the test via
> $ ./tools/testing/kunit/kunit.py run --kunitconfig=mm/kfence --arch=x86_64
> ...
> [11:02:32] Testing complete. Passed: 23, Failed: 0, Crashed: 0, Skipped: 2, Errors: 0
> [11:02:32] Elapsed time: 43.562s total, 0.003s configuring, 9.268s building, 34.281s running
> 
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Daniel Latypov <dlatypov@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kfence/.kunitconfig  |  6 ++++++
>  mm/kfence/kfence_test.c | 31 +++++++++++++------------------
>  2 files changed, 19 insertions(+), 18 deletions(-)
>  create mode 100644 mm/kfence/.kunitconfig
> 
> diff --git a/mm/kfence/.kunitconfig b/mm/kfence/.kunitconfig
> new file mode 100644
> index 000000000000..f3d65e939bfa
> --- /dev/null
> +++ b/mm/kfence/.kunitconfig
> @@ -0,0 +1,6 @@
> +CONFIG_KUNIT=y
> +CONFIG_KFENCE=y
> +CONFIG_KFENCE_KUNIT_TEST=y
> +
> +# Additional dependencies.
> +CONFIG_FTRACE=y
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 1b50f70a4c0f..96206a4ee9ab 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -826,14 +826,6 @@ static void test_exit(struct kunit *test)
>  	test_cache_destroy();
>  }
>  
> -static struct kunit_suite kfence_test_suite = {
> -	.name = "kfence",
> -	.test_cases = kfence_test_cases,
> -	.init = test_init,
> -	.exit = test_exit,
> -};
> -static struct kunit_suite *kfence_test_suites[] = { &kfence_test_suite, NULL };
> -
>  static void register_tracepoints(struct tracepoint *tp, void *ignore)
>  {
>  	check_trace_callback_type_console(probe_console);
> @@ -847,11 +839,7 @@ static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
>  		tracepoint_probe_unregister(tp, probe_console, NULL);
>  }
>  
> -/*
> - * We only want to do tracepoints setup and teardown once, therefore we have to
> - * customize the init and exit functions and cannot rely on kunit_test_suite().
> - */
> -static int __init kfence_test_init(void)
> +static int kfence_suite_init(struct kunit_suite *suite)
>  {
>  	/*
>  	 * Because we want to be able to build the test as a module, we need to
> @@ -859,18 +847,25 @@ static int __init kfence_test_init(void)
>  	 * won't work here.
>  	 */
>  	for_each_kernel_tracepoint(register_tracepoints, NULL);
> -	return __kunit_test_suites_init(kfence_test_suites);
> +	return 0;
>  }
>  
> -static void kfence_test_exit(void)
> +static void kfence_suite_exit(struct kunit_suite *suite)
>  {
> -	__kunit_test_suites_exit(kfence_test_suites);
>  	for_each_kernel_tracepoint(unregister_tracepoints, NULL);
>  	tracepoint_synchronize_unregister();
>  }
>  
> -late_initcall_sync(kfence_test_init);
> -module_exit(kfence_test_exit);
> +static struct kunit_suite kfence_test_suite = {
> +	.name = "kfence",
> +	.test_cases = kfence_test_cases,
> +	.init = test_init,
> +	.exit = test_exit,
> +	.suite_init = kfence_suite_init,
> +	.suite_exit = kfence_suite_exit,
> +};
> +
> +kunit_test_suites(&kfence_test_suite);

Much nicer!

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ymk56YygGUU52CHG%40elver.google.com.
