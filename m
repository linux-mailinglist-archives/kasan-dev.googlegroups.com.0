Return-Path: <kasan-dev+bncBAABBHPS5DZQKGQEV2KYOVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7257B1916C0
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 17:45:18 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id g201sf1844100vkf.19
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 09:45:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585068317; cv=pass;
        d=google.com; s=arc-20160816;
        b=VH+6BfIcCrLlrAoWO0ZhApjktg7KXbMv7UW/TefvR8uLPjXhdq8XnMDloChhDb6j8P
         gbwf0unLLv19D8+uNejf70i5nDHo3mBKe3NQeApu0KLKuQfEN8VBffJcsZfwh5ceeVb5
         xx3znQNTaueZdnh+94NVoY16NklCKjdFg4aRRwGXN/Zb/WGz2sbOvlzuOb1bcR2WqCqv
         rLLSYTLbvEoYR6gF4IfZ4M/fHLQYA/7Kaklob/fbsVr1l7DdxA8cMwcaLAig0W7q/RmI
         kvY87AsBM1YA/Ows/v2Q+KBvff0vBICVlO5qQC3NNzH04c5Hci205XfC1ZUg+/foxlz3
         4IXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=cPqXatxWU2RL7sqEnnp1nE+pM1ratBQ/qQyXRwzGk7U=;
        b=IBkd5brb+jJRgeVH66ZBMMzhzunt2AZCVlsuqQO9I5R2ANDx5D+I7SIkZhpy/of4W5
         dmnUZyoafYrImi+wEA+9TCjhsyVkdaqSCEXCGYdhAfVFVFqrrrXqwXEOb8QXrWG72Dnw
         i5xsC8CpjlD+fyFj5+YDz4Au1v0Pg7FXgQJVICV/s9t5N2I2d2/jm9M+VheoOSGm4F7i
         AXT58VeXIRCIsaHceckizePMvYTip3X1EtwvMKJH31pv4OAUEFmmqDuuULLZZo+9R5c9
         rPJ9g9J6Wug3tXySg433A5Mya/NWJj/ggUPGxd42/Kl+jXid56TtOptbUcthA0wcGL0P
         NVaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=omve0INn;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cPqXatxWU2RL7sqEnnp1nE+pM1ratBQ/qQyXRwzGk7U=;
        b=X5dYIDzf5GwL+zeirtt4ceRpqmQsyBe3ybymiOonX3rBfDq3Mo37JGP3X8piR6TpNE
         1PJtGdwpP4vFsak7zwONq851MMYOFrJK8M98NoUcgVApsLudk8MKMzLs828sAwcYSfwH
         lB+59fWoMPDV0H1oUctOly2JHhwb1vbJ8/zbl8isbQiL4FkWwZu5lCWGA+GUBpIo1IkN
         w27sRBGBWhYPwT02xPqnXQVmW33K1YHmt43Ng0eUibxqnLpqGscn4FZiUAuL1G5eofB3
         Qx3ZI25kOAn6Vlj1i5CFklAXie9BDjWduVpjn74y2hDVcm1Az+ijbd1Qdr/mOj3Mld/+
         0b3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cPqXatxWU2RL7sqEnnp1nE+pM1ratBQ/qQyXRwzGk7U=;
        b=WDBik4p4EznajEPxwQb0M4QgipV5sjNFDwxdJcFF8Uiako+V33izHuS03c6TInKtTK
         Xkb4EfhPwHGovTjFcToEI/p04O6D2Cr6WklN/5am9Q6WSiBI8H4y1bhb5uW2K97O35CT
         TYjGucYxWDneHP0VWcqFWNDDUg+j+rkPlr0U6pDKaYjmIvc4fCQxE2JND3Wd9q7xMeRy
         lbMMABClq7rBot7a5KKfF62IyAwjWkRPKDS01sabi1wGWrKd0RtoZki3BGG9gkyyA2Bz
         k8N/h9ZdjjyYhWnl5mj1q/CSkOYT9eKSAx5M/KzIkCQzTK3/fCxEj234opKU8tX9Syp1
         Bwdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1Gmth+Rn98NJ++ZaIRltB9+DA6El1533U4CG2cWBgcDjgNUlXG
	waJsMJ+8p/38eUGqIY42td4=
X-Google-Smtp-Source: ADFU+vsuifaY6rIkXY5R9JPeR714XYHnZifzfenZ1NZ6KqHTlGoGNQbntOU50tzpEPxPAuZTCqbKSA==
X-Received: by 2002:ab0:18a8:: with SMTP id t40mr19334033uag.115.1585068317441;
        Tue, 24 Mar 2020 09:45:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c01d:: with SMTP id v29ls2381610vsi.6.gmail; Tue, 24 Mar
 2020 09:45:17 -0700 (PDT)
X-Received: by 2002:a67:f88d:: with SMTP id h13mr11091780vso.116.1585068317080;
        Tue, 24 Mar 2020 09:45:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585068317; cv=none;
        d=google.com; s=arc-20160816;
        b=dlP/Xs56To52CUDIjfLkqs0ZkFd2SkUQnpVbwMYcvh0en8pkqREHc3xePdiKkc2OgA
         HsEqVj1QlZYJ6wulGfEi9aM36UMF0VGFwoFcjFi977efts3X/7+RxXvDMvSCTnLMlNn2
         gATYehu/LFGkcbaZXaIDgrMAigN98O0xJD8HqtZkRtTKSyTBDvwrnqYhR/Y4TqJXbLrM
         CY8iU6reEcBtzYSPadZTPycPeO/XLwxmkeUC1t+P9Nvl8WRIXi1NzI9GivP0ani2LNcN
         59IAa19usWbo38llo8ywD/q+5BPSV95DkRsTz9PbQ3T4a5FGWlCTxUCLmTufVJ75asgf
         lERw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature;
        bh=5b9wb3f2bzObgWbQdpgaIklwxUsss6rC628mYngDBJc=;
        b=j7SovrP7/5U/y/fH/+77NGme3edt8ooD0gUPANnt9OZsSHgAEIOWMVtHT987bCW16U
         zFzfQ5PeIWs8jrF/jIkCuP6xsMiS5OyN6qdpujZuwRUjRCOzHIQ18gcD05JNdkoTFKdG
         eYH71HqCkmapYBfI2JXxX873bmKes4hSW0I4vOOh07FYJlURUgkFTQvyGHhadSUa2H2D
         50ZB7b1nVrEcJTnPFoMEFfhtoOAQ1GIwx//sqttR+pbSzCkK+qlLBwI8NwCbylu2FbkO
         ZhvbKXp3Q3ATEJauwjJ9cONSeQEeLT7mcKv0MhUZLJ4Z1Wxwyrvl2GaCCgVFnVKAYgNO
         mF6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2020-01-29 header.b=omve0INn;
       spf=pass (google.com: domain of alan.maguire@oracle.com designates 141.146.126.78 as permitted sender) smtp.mailfrom=alan.maguire@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from aserp2120.oracle.com (aserp2120.oracle.com. [141.146.126.78])
        by gmr-mx.google.com with ESMTPS id 205si1097274vkw.2.2020.03.24.09.45.16
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 24 Mar 2020 09:45:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of alan.maguire@oracle.com designates 141.146.126.78 as permitted sender) client-ip=141.146.126.78;
Received: from pps.filterd (aserp2120.oracle.com [127.0.0.1])
	by aserp2120.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 02OGh2EU102497;
	Tue, 24 Mar 2020 16:45:14 GMT
Received: from userp3030.oracle.com (userp3030.oracle.com [156.151.31.80])
	by aserp2120.oracle.com with ESMTP id 2ywavm5enc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 24 Mar 2020 16:45:14 +0000
Received: from pps.filterd (userp3030.oracle.com [127.0.0.1])
	by userp3030.oracle.com (8.16.0.42/8.16.0.42) with SMTP id 02OGgEWr139025;
	Tue, 24 Mar 2020 16:45:13 GMT
Received: from aserv0122.oracle.com (aserv0122.oracle.com [141.146.126.236])
	by userp3030.oracle.com with ESMTP id 2yxw4pmwqk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 24 Mar 2020 16:45:13 +0000
Received: from abhmp0004.oracle.com (abhmp0004.oracle.com [141.146.116.10])
	by aserv0122.oracle.com (8.14.4/8.14.4) with ESMTP id 02OGjBBr015605;
	Tue, 24 Mar 2020 16:45:11 GMT
Received: from dhcp-10-175-162-99.vpn.oracle.com (/10.175.162.99)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Tue, 24 Mar 2020 09:45:11 -0700
Date: Tue, 24 Mar 2020 16:45:06 +0000 (GMT)
From: Alan Maguire <alan.maguire@oracle.com>
X-X-Sender: alan@localhost
To: Patricia Alfonso <trishalfonso@google.com>
cc: davidgow@google.com, brendanhiggins@google.com, aryabinin@virtuozzo.com,
        dvyukov@google.com, mingo@redhat.com, peterz@infradead.org,
        juri.lelli@redhat.com, vincent.guittot@linaro.org,
        linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
        kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org
Subject: Re: [RFC PATCH v2 2/3] KUnit: KASAN Integration
In-Reply-To: <20200319164227.87419-3-trishalfonso@google.com>
Message-ID: <alpine.LRH.2.21.2003241640150.30637@localhost>
References: <20200319164227.87419-1-trishalfonso@google.com> <20200319164227.87419-3-trishalfonso@google.com>
User-Agent: Alpine 2.21 (LRH 202 2017-01-01)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9570 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 suspectscore=1
 spamscore=0 mlxlogscore=999 adultscore=0 phishscore=0 mlxscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2003020000 definitions=main-2003240088
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9570 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 malwarescore=0
 priorityscore=1501 mlxscore=0 bulkscore=0 clxscore=1015 impostorscore=0
 phishscore=0 suspectscore=1 mlxlogscore=999 spamscore=0 lowpriorityscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2003020000
 definitions=main-2003240088
X-Original-Sender: alan.maguire@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2020-01-29 header.b=omve0INn;
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


On Thu, 19 Mar 2020, Patricia Alfonso wrote:

> Integrate KASAN into KUnit testing framework.
> 	- Fail tests when KASAN reports an error that is not expected
>      	- Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
>      	- Expected KASAN reports pass tests and are still printed when run
>      	without kunit_tool (kunit_tool still bypasses the report due to the
> 	test passing)
>      	- KUnit struct in current task used to keep track of the current test
>      	from KASAN code
> 
> Make use of "[RFC PATCH kunit-next 1/2] kunit: generalize
> kunit_resource API beyond allocated resources" and "[RFC PATCH
> kunit-next 2/2] kunit: add support for named resources" from Alan
> Maguire [1]
> 	- A named resource is added to a test when a KASAN report is
> 	 expected
>         - This resource contains a struct for kasan_data containing
>         booleans representing if a KASAN report is expected and if a
>         KASAN report is found
> 
> [1] (https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-send-email-alan.maguire@oracle.com/T/#t)
> 
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> ---
>  include/kunit/test.h | 10 ++++++++++
>  lib/kunit/test.c     | 10 +++++++++-
>  lib/test_kasan.c     | 37 +++++++++++++++++++++++++++++++++++++
>  mm/kasan/report.c    | 33 +++++++++++++++++++++++++++++++++
>  4 files changed, 89 insertions(+), 1 deletion(-)
> 
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index 70ee581b19cd..2ab265f4f76c 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -19,9 +19,19 @@
>  
>  struct kunit_resource;
>  
> +#ifdef CONFIG_KASAN
> +/* kasan_data struct is used in KUnit tests for KASAN expected failures */
> +struct kunit_kasan_expectation {
> +	bool report_expected;
> +	bool report_found;
> +};
> +#endif /* CONFIG_KASAN */
> +

Above should be moved to mm/kasan/kasan.h I think.

>  typedef int (*kunit_resource_init_t)(struct kunit_resource *, void *);
>  typedef void (*kunit_resource_free_t)(struct kunit_resource *);
>  
> +void kunit_set_failure(struct kunit *test);
> +

Can you explain a bit more about why we need this exported?
I see where it's used but I'd just like to make sure I
understand what you're trying to do. Thanks!

>  /**
>   * struct kunit_resource - represents a *test managed resource*
>   * @data: for the user to store arbitrary data.
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index 86a4d9ca0a45..3f927ef45827 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -10,11 +10,12 @@
>  #include <linux/kernel.h>
>  #include <linux/kref.h>
>  #include <linux/sched/debug.h>
> +#include <linux/sched.h>
>  
>  #include "string-stream.h"
>  #include "try-catch-impl.h"
>  
> -static void kunit_set_failure(struct kunit *test)
> +void kunit_set_failure(struct kunit *test)
>  {
>  	WRITE_ONCE(test->success, false);
>  }
> @@ -237,6 +238,10 @@ static void kunit_try_run_case(void *data)
>  	struct kunit_suite *suite = ctx->suite;
>  	struct kunit_case *test_case = ctx->test_case;
>  
> +#if (IS_ENABLED(CONFIG_KASAN) && IS_BUILTIN(CONFIG_KUNIT))
> +	current->kunit_test = test;
> +#endif /* IS_ENABLED(CONFIG_KASAN) && IS_BUILTIN(CONFIG_KUNIT) */
> +
>  	/*
>  	 * kunit_run_case_internal may encounter a fatal error; if it does,
>  	 * abort will be called, this thread will exit, and finally the parent
> @@ -590,6 +595,9 @@ void kunit_cleanup(struct kunit *test)
>  		spin_unlock(&test->lock);
>  		kunit_remove_resource(test, res);
>  	}
> +#if (IS_ENABLED(CONFIG_KASAN) && IS_BUILTIN(CONFIG_KUNIT))
> +	current->kunit_test = NULL;

As per patch 1, I'd suggest changing here and elsewhere to 
"IS_ENABLED(CONFIG_KUNIT)".

> +#endif /* IS_ENABLED(CONFIG_KASAN) && IS_BUILTIN(CONFIG_KUNIT)*/
>  }
>  EXPORT_SYMBOL_GPL(kunit_cleanup);
>  
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 3872d250ed2c..cf73c6bee81b 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -23,6 +23,43 @@
>  
>  #include <asm/page.h>
>  
> +#include <kunit/test.h>
> +
> +struct kunit_resource resource;
> +struct kunit_kasan_expectation fail_data;
> +
> +#define KUNIT_SET_KASAN_DATA(test) do { \
> +	fail_data.report_expected = true; \
> +	fail_data.report_found = false; \
> +	kunit_add_named_resource(test, \
> +				NULL, \
> +				NULL, \
> +				&resource, \
> +				"kasan_data", &fail_data); \
> +} while (0)
> +
> +#define KUNIT_DO_EXPECT_KASAN_FAIL(test, condition) do { \
> +	struct kunit_resource *resource; \
> +	struct kunit_kasan_expectation *kasan_data; \
> +	condition; \
> +	resource = kunit_find_named_resource(test, "kasan_data"); \
> +	kasan_data = resource->data; \
> +	KUNIT_EXPECT_EQ(test, \
> +			kasan_data->report_expected, \
> +			kasan_data->report_found); \
> +	kunit_put_resource(resource); \
> +} while (0)
> +
> +/**
> + * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
> + * not cause a KASAN error.
> + *
> + */
> +#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
> +	KUNIT_SET_KASAN_DATA(test); \
> +	KUNIT_DO_EXPECT_KASAN_FAIL(test, condition); \
> +} while (0)
> +
>  /*
>   * Note: test functions are marked noinline so that their names appear in
>   * reports.
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 5ef9f24f566b..ef3d0f54097e 100644
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
> @@ -455,12 +457,38 @@ static bool report_enabled(void)
>  	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
>  }
>  
> +#if IS_BUILTIN(CONFIG_KUNIT)

again we could tweak this to IS_ENABLED(CONFIG_KUNIT); BTW
the reason we can compile kunit as a module for these tests
is the KASAN tests are tristate themselves. If they were
builtin only it wouldn't be possible to build kunit as
a module.

> +void kasan_update_kunit_status(struct kunit *cur_test)
> +{
> +	struct kunit_resource *resource;
> +	struct kunit_kasan_expectation *kasan_data;
> +
> +	if (kunit_find_named_resource(cur_test, "kasan_data")) {
> +		resource = kunit_find_named_resource(cur_test, "kasan_data");
> +		kasan_data = resource->data;
> +		kasan_data->report_found = true;
> +
> +		if (!kasan_data->report_expected)
> +			kunit_set_failure(current->kunit_test);
> +		else
> +			return;
> +	} else
> +		kunit_set_failure(current->kunit_test);
> +}
> +#endif /* IS_BUILTIN(CONFIG_KUNIT) */
> +
>  void kasan_report_invalid_free(void *object, unsigned long ip)
>  {
>  	unsigned long flags;
>  	u8 tag = get_tag(object);
>  
>  	object = reset_tag(object);
> +
> +#if IS_BUILTIN(CONFIG_KUNIT)

same comment as above.
 
> +	if (current->kunit_test)
> +		kasan_update_kunit_status(current->kunit_test);
> +#endif /* IS_BUILTIN(CONFIG_KUNIT) */
> +
>  	start_report(&flags);
>  	pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
>  	print_tags(tag, object);
> @@ -481,6 +509,11 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
>  	if (likely(!report_enabled()))
>  		return;
>  
> +#if IS_BUILTIN(CONFIG_KUNIT)

here too.

> +	if (current->kunit_test)
> +		kasan_update_kunit_status(current->kunit_test);
> +#endif /* IS_BUILTIN(CONFIG_KUNIT) */
> +
>  	disable_trace_on_warning();
>  
>  	tagged_addr = (void *)addr;
> -- 
> 2.25.1.696.g5e7596f4ac-goog
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.LRH.2.21.2003241640150.30637%40localhost.
