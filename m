Return-Path: <kasan-dev+bncBAABBSETTX2AKGQEHFJE4BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id B906F19D938
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Apr 2020 16:35:53 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id s126sf6755593oih.6
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Apr 2020 07:35:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585924552; cv=pass;
        d=google.com; s=arc-20160816;
        b=QBm3EZbz2QUAmgtFsAy6qRck5FWypzQc2CwHI7x1Etlzg8e3TmmMAsIOiSgHpL6Ip3
         4JQmzlv1WAlnRtfpTi44Q+hoFFn73vtem3d1uHvJP6kSLvVFUibAvFLQ8SMQM32D+Uxw
         SDbqNAtxfsN8ENfFFkp0UZqgfuYugqYTEGjmxOeYzAoUkm3N+LqED7odneS7qOh26cK+
         Ync/2Fn7l+Bh9uUip4LDKsm9vpDGVsnP3Y6JgPnZeLG0rfQvd15M3QLSU6n2tzF/rHRZ
         WeQQq7r09s6f29S7/gIb7Ws5/8zpu89J4GJq89f3bmLGOfKrL3eF1v6Iwt7VGUUVOMV+
         +alA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=QCUeU/nS2w0ldlsF+SSJwvzaj6FJBU4mFilI1xe+8o8=;
        b=HZYQmghla7P/3Gyaho4cMR+HYGyDC8eX1dswUd1sS+Tf+qLKg2nFOlEyXZ2HAsdt0v
         01YwXekSDxtpE668Oh7rhtCaD0vGFRieaciaBrEXaVor7n/uJzqqU3d2Yn80BBLzOVEz
         ESJMMCBxrY+uCmFm8MhyJeLjT9zXlC/abkqED8ANyaSK5qqE+Zdn1lhUuXbKJNeRHbqm
         3OLvHk2OlAdQxIHCc9j0kA8VXy0rCcNntcVLoRfTWQ885WjaTwKW4wKuUpbT2teDGuOp
         0JYXUkyY16wNhuESn724tpf/6k2FV0XrCzr8AC5ACm8ic8hHASjs363OIQPmn5y2N+V/
         8Enw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b="Rl/ErqpV";
       spf=pass (google.com: domain of alan.maguire@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QCUeU/nS2w0ldlsF+SSJwvzaj6FJBU4mFilI1xe+8o8=;
        b=lARbG4v9rDKja2dUkQXtDBwxqz/5KFNais8NjoXMjaecFvo7Dpbs1iUmQB7RHBArsk
         7sx0OUUAsw5Oww1BR3/t0qQ3My2RguWiuQzxuSxRh7K9CizNgbfUxNf10WxDZ999F5be
         szy81EB/QPonpxA0Nubg8Ni5NyUzIqhILWkXuvsLaf3WKnGEbJ/6hd/jcqq4/OI2BHf9
         XR2+8+qDya1D2KxU4zxIJbfp0Pspi1MPzQtxbfl8XZ5TDJSWoi2FBeEl2qKfF9HnDsFo
         rOvYkFbVVzOKOsHnQqTFnSG+105+BKFVHajt6e5dNULvEoIHLfDhP2ZASAl2ZbHTnmjH
         gFmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QCUeU/nS2w0ldlsF+SSJwvzaj6FJBU4mFilI1xe+8o8=;
        b=gVIKMxgVp5tT5hHD1qbzqR3CZsZPUxX9+kp54/FOl8BZB2yAG06a/e6ggCazchJO/g
         rKc7OCXZ6QWQCffZP97y8Ch5gZ6DRSXv2arO6G0eHz80SL/vDpgJmyG6yTCJPWb4ase4
         nXZDZfLCbVObTg/Z2SD5Q0/fkmXJiU7PleqYLxj5UZlRRGfvdp+Ki8LGUY/wGkV2nJi0
         Zk+lc+JaXE89QLl35cEm6rJXJAW7uAMiUG2k2Tg/7oNYdqkDJVJIlvK+34/H6ft6HZyG
         CiTY6k3Tds4rWtefX18kk5zknWhPNoQCaVk84HyVOIJ893yRUjxAvwOuCijoGJn1sLQG
         XoBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuaimrHPORAgaTXV/KAI8AwvD69z9K9CJn0pUK0ov6AN9UnDnMlh
	r9Um7Ang4Z8som+Cj/I5u1I=
X-Google-Smtp-Source: APiQypIKVQuMWn5feDRkZBwZFrPG23Qfrq30OY4OtKj+Oq8JOLeEYmDsFcTEO/wIzCsBpt9ftHoqKg==
X-Received: by 2002:a9d:306:: with SMTP id 6mr6971693otv.185.1585924552576;
        Fri, 03 Apr 2020 07:35:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5606:: with SMTP id k6ls3433944oib.1.gmail; Fri, 03 Apr
 2020 07:35:52 -0700 (PDT)
X-Received: by 2002:aca:5712:: with SMTP id l18mr3218623oib.178.1585924552151;
        Fri, 03 Apr 2020 07:35:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585924552; cv=none;
        d=google.com; s=arc-20160816;
        b=X2vbFKb0X7XB9FRvZ4hfQnS11Pfe6cDXYJWI8SkbG11KKWrhwrBziiT2DNk/u/5uO9
         y3nB0RVFT3l7pVwpXRVxqMkqFOll8WGelMaqnr1iBWHA6QXhhrER/hwGukbl9wWVdzc3
         5gsmPslXBon+CkaFz4VlT9wFPX1UMgJDQjdIrPPO4Loz3LR4cKnWwJkaBEhVeKQ0yP8S
         qblG6XKy5IsJ/0TknS249NR3ZyIsv0Y2ycpEKY7W95xbrunB9oS6W17Rc4FLRQjSszAz
         ZJXq64IG3AaiChVLD5SjdLEj4wyacpm3W1JxIDqCX5xI9tKcmr/iECjrJ7Zw+e6YpOA9
         03YA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature;
        bh=v2VPJBmV/wf+bKML1xDBcfICL0eqxAMEV+JWda6o6PE=;
        b=JgcKDnmMyorQpHtKLa/jMYM6C+QDTTaH1wfOZNEJqqUeyQ6GxsdavHZIPb67PDKjXQ
         EXQQbHJCci/ABA5Hz8NxW7MDu7bG7tx6+iBUEtAIoJ0zNEYc1xnQ6ijiZjMfUCW4vr28
         uj4ZVAjSmSY2xntmiF5NSHCvpeJLLhuqsP0TvulpbE07+Dfb6P5LXK8aEpxfJh8qkxb/
         5Tq1LpYPt/z4Da0YstgB37Y5Dq53FffTkA77raOvtNBvr5gzDB/RuAldZJUdgX3fGlmj
         U5TJ0J4gTvZ0c6fdv7znbCZbvP7nzHKVOPuJw2qUenLli8ZNk9HHDnLJrQ4vU68lbPwo
         Vsiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b="Rl/ErqpV";
       spf=pass (google.com: domain of alan.maguire@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from aserp2120.oracle.com (aserp2120.oracle.com. [141.146.126.78])
        by gmr-mx.google.com with ESMTPS id d11si517107otk.5.2020.04.03.07.35.51
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 Apr 2020 07:35:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of alan.maguire@oracle.com designates 141.146.126.78 as permitted sender) client-ip=141.146.126.78;
Received: from pps.filterd (aserp2120.oracle.com [127.0.0.1])
	by aserp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 033EXYIY031824;
	Fri, 3 Apr 2020 14:35:47 GMT
Received: from aserp3020.oracle.com (aserp3020.oracle.com [141.146.126.70])
	by aserp2120.oracle.com with ESMTP id 303yunm0jx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 03 Apr 2020 14:35:47 +0000
Received: from pps.filterd (aserp3020.oracle.com [127.0.0.1])
	by aserp3020.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 033EXCZl011078;
	Fri, 3 Apr 2020 14:35:46 GMT
Received: from userv0122.oracle.com (userv0122.oracle.com [156.151.31.75])
	by aserp3020.oracle.com with ESMTP id 304sjsyr1p-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 03 Apr 2020 14:35:46 +0000
Received: from abhmp0014.oracle.com (abhmp0014.oracle.com [141.146.116.20])
	by userv0122.oracle.com (8.14.4/8.14.4) with ESMTP id 033EZbX3019744;
	Fri, 3 Apr 2020 14:35:43 GMT
Received: from dhcp-10-175-200-49.vpn.oracle.com (/10.175.200.49)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Fri, 03 Apr 2020 07:35:37 -0700
Date: Fri, 3 Apr 2020 15:35:27 +0100 (BST)
From: Alan Maguire <alan.maguire@oracle.com>
X-X-Sender: alan@localhost
To: Patricia Alfonso <trishalfonso@google.com>
cc: davidgow@google.com, brendanhiggins@google.com, aryabinin@virtuozzo.com,
        dvyukov@google.com, mingo@redhat.com, peterz@infradead.org,
        juri.lelli@redhat.com, vincent.guittot@linaro.org,
        linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
        kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org
Subject: Re: [PATCH v4 2/4] KUnit: KASAN Integration
In-Reply-To: <20200402204639.161637-2-trishalfonso@google.com>
Message-ID: <alpine.LRH.2.21.2004031529080.17071@localhost>
References: <20200402204639.161637-1-trishalfonso@google.com> <20200402204639.161637-2-trishalfonso@google.com>
User-Agent: Alpine 2.21 (LRH 202 2017-01-01)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9579 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 bulkscore=0 adultscore=0 mlxscore=0
 malwarescore=0 phishscore=0 suspectscore=1 mlxlogscore=999 spamscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2003020000
 definitions=main-2004030129
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9579 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 lowpriorityscore=0
 malwarescore=0 adultscore=0 priorityscore=1501 mlxlogscore=999 bulkscore=0
 suspectscore=1 mlxscore=0 spamscore=0 impostorscore=0 clxscore=1011
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2003020000
 definitions=main-2004030129
X-Original-Sender: alan.maguire@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b="Rl/ErqpV";
       spf=pass (google.com: domain of alan.maguire@oracle.com designates
 141.146.126.78 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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

On Thu, 2 Apr 2020, Patricia Alfonso wrote:

> Integrate KASAN into KUnit testing framework.
>         - Fail tests when KASAN reports an error that is not expected
>         - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN
> 	tests
>         - Expected KASAN reports pass tests and are still printed when run
>         without kunit_tool (kunit_tool still bypasses the report due to the
>         test passing)
>         - KUnit struct in current task used to keep track of the current
> 	test from KASAN code
> 
> Make use of "[PATCH v3 kunit-next 1/2] kunit: generalize
> kunit_resource API beyond allocated resources" and "[PATCH v3
> kunit-next 2/2] kunit: add support for named resources" from Alan
> Maguire [1]
>         - A named resource is added to a test when a KASAN report is
>          expected
>         - This resource contains a struct for kasan_data containing
>         booleans representing if a KASAN report is expected and if a
>         KASAN report is found
> 
> [1] (https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-send-email-alan.maguire@oracle.com/T/#t)
> 
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> ---
>  include/kunit/test.h  |  5 ++++
>  include/linux/kasan.h |  6 +++++
>  lib/kunit/test.c      | 13 ++++++----
>  lib/test_kasan.c      | 56 +++++++++++++++++++++++++++++++++++++++----
>  mm/kasan/report.c     | 30 +++++++++++++++++++++++
>  5 files changed, 101 insertions(+), 9 deletions(-)
> 
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index ac59d18e6bab..1dc3d118f64b 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -225,6 +225,11 @@ struct kunit {
>  	struct list_head resources; /* Protected by lock. */
>  };
>  
> +static inline void kunit_set_failure(struct kunit *test)
> +{
> +	WRITE_ONCE(test->success, false);
> +}
> +
>  void kunit_init_test(struct kunit *test, const char *name, char *log);
>  
>  int kunit_run_tests(struct kunit_suite *suite);
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 5cde9e7c2664..148eaef3e003 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -14,6 +14,12 @@ struct task_struct;
>  #include <asm/kasan.h>
>  #include <asm/pgtable.h>
>  
> +/* kasan_data struct is used in KUnit tests for KASAN expected failures */
> +struct kunit_kasan_expectation {
> +	bool report_expected;
> +	bool report_found;
> +};
> +
>  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>  extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
>  extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index 2cb7c6220a00..030a3281591e 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -10,16 +10,12 @@
>  #include <linux/kernel.h>
>  #include <linux/kref.h>
>  #include <linux/sched/debug.h>
> +#include <linux/sched.h>
>  
>  #include "debugfs.h"
>  #include "string-stream.h"
>  #include "try-catch-impl.h"
>  
> -static void kunit_set_failure(struct kunit *test)
> -{
> -	WRITE_ONCE(test->success, false);
> -}
> -
>  static void kunit_print_tap_version(void)
>  {
>  	static bool kunit_has_printed_tap_version;
> @@ -288,6 +284,10 @@ static void kunit_try_run_case(void *data)
>  	struct kunit_suite *suite = ctx->suite;
>  	struct kunit_case *test_case = ctx->test_case;
>  
> +#if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT))
> +	current->kunit_test = test;
> +#endif /* IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT) */
> +
>  	/*
>  	 * kunit_run_case_internal may encounter a fatal error; if it does,
>  	 * abort will be called, this thread will exit, and finally the parent
> @@ -603,6 +603,9 @@ void kunit_cleanup(struct kunit *test)
>  		spin_unlock(&test->lock);
>  		kunit_remove_resource(test, res);
>  	}
> +#if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT))
> +	current->kunit_test = NULL;
> +#endif /* IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT)*/
>  }
>  EXPORT_SYMBOL_GPL(kunit_cleanup);
>  
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 3872d250ed2c..dbfa0875ee09 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -23,12 +23,60 @@
>  
>  #include <asm/page.h>
>  
> -/*
> - * Note: test functions are marked noinline so that their names appear in
> - * reports.
> +#include <kunit/test.h>
> +
> +static struct kunit_resource resource;
> +static struct kunit_kasan_expectation fail_data;
> +static bool multishot;
> +static int orig_panic_on_warn;
> +
> +static int kasan_test_init(struct kunit *test)
> +{
> +	/*
> +	 * Temporarily enable multi-shot mode and set panic_on_warn=0.
> +	 * Otherwise, we'd only get a report for the first case.
> +	 */
> +	multishot = kasan_save_enable_multi_shot();
> +
> +	orig_panic_on_warn = panic_on_warn;
> +	panic_on_warn = 0;
> +

When I build kunit and test_kasan as a module, I'm seeing

ERROR: "panic_on_warn" [lib/test_kasan.ko] undefined!

Looks like this variable isn't exported (unlike
panic_timeout).

Is there an in-kernel API to read sysctl values we could
use here that would be safe for module and builtin access
maybe? 

Alan

> +	return 0;
> +}
> +
> +static void kasan_test_exit(struct kunit *test)
> +{
> +	kasan_restore_multi_shot(multishot);
> +
> +	/* Restore panic_on_warn */
> +	panic_on_warn = orig_panic_on_warn;
> +}
> +
> +/**
> + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> + * not cause a KASAN error. This uses a KUnit resource named "kasan_data." Do
> + * Do not use this name for a KUnit resource outside here.
> + *
>   */
> +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
> +	struct kunit_resource *res; \
> +	struct kunit_kasan_expectation *kasan_data; \
> +	fail_data.report_expected = true; \
> +	fail_data.report_found = false; \
> +	kunit_add_named_resource(test, \
> +				NULL, \
> +				NULL, \
> +				&resource, \
> +				"kasan_data", &fail_data); \
> +	condition; \
> +	res = kunit_find_named_resource(test, "kasan_data"); \
> +	kasan_data = res->data; \
> +	KUNIT_EXPECT_EQ(test, \
> +			kasan_data->report_expected, \
> +			kasan_data->report_found); \
> +	kunit_put_resource(res); \
> +} while (0)
>  
> -static noinline void __init kmalloc_oob_right(void)
>  {
>  	char *ptr;
>  	size_t size = 123;
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 5ef9f24f566b..497477c4b679 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -32,6 +32,8 @@
>  
>  #include <asm/sections.h>
>  
> +#include <kunit/test.h>
> +
>  #include "kasan.h"
>  #include "../slab.h"
>  
> @@ -455,12 +457,35 @@ static bool report_enabled(void)
>  	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
>  }
>  
> +#if IS_ENABLED(CONFIG_KUNIT)
> +void kasan_update_kunit_status(struct kunit *cur_test)
> +{
> +	struct kunit_resource *resource;
> +	struct kunit_kasan_expectation *kasan_data;
> +
> +	if (!kunit_find_named_resource(cur_test, "kasan_data")) {
> +		kunit_set_failure(cur_test);
> +		return;
> +	}
> +
> +	resource = kunit_find_named_resource(cur_test, "kasan_data");
> +	kasan_data = resource->data;
> +	kasan_data->report_found = true;
> +}
> +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> +
>  void kasan_report_invalid_free(void *object, unsigned long ip)
>  {
>  	unsigned long flags;
>  	u8 tag = get_tag(object);
>  
>  	object = reset_tag(object);
> +
> +#if IS_ENABLED(CONFIG_KUNIT)
> +	if (current->kunit_test)
> +		kasan_update_kunit_status(current->kunit_test);
> +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> +
>  	start_report(&flags);
>  	pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
>  	print_tags(tag, object);
> @@ -481,6 +506,11 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
>  	if (likely(!report_enabled()))
>  		return;
>  
> +#if IS_ENABLED(CONFIG_KUNIT)
> +	if (current->kunit_test)
> +		kasan_update_kunit_status(current->kunit_test);
> +#endif /* IS_ENABLED(CONFIG_KUNIT) */
> +
>  	disable_trace_on_warning();
>  
>  	tagged_addr = (void *)addr;
> -- 
> 2.26.0.292.g33ef6b2f38-goog
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.LRH.2.21.2004031529080.17071%40localhost.
