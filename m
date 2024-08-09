Return-Path: <kasan-dev+bncBDK7LR5URMGRBH4F3G2QMGQED3J4TEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id A0BAD94D49E
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2024 18:24:00 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-42803f47807sf1034485e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2024 09:24:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723220640; cv=pass;
        d=google.com; s=arc-20240605;
        b=LgJ7d0x8p9vNeYmyxHoT937H6TfjUPAbX4GiFIfYaaTBwgvQvX9X2VY68sorvcWR5G
         O6uLD8+jsr7e3pxeEvaoNjkXStzMKGMqdnrN4/kQOsbiRPSuK4zyTJuRjdsB8KeslavM
         oNDdSG6OGL82GKbT/0iycghgasexHHSrdeRQyEC2G7ARZe74gWgAkNXg+Og57cmzBTCB
         gJRVRI15okpbjz/IsceicwZlVOJmRD5tn0ccJE9tRjvyJ6KNItGUP8PotxznU6nhORye
         kT4yBj+sS782RhrKh5zsiNa7QTaQOAM4J0M4n1AFxOpcXCObOhdQwQZ7JGIsUkBPzoOX
         9uFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=yZvS4H7EiZunH1uiW+MVaTy3CTbP41rRTtU8ssmBn1c=;
        fh=8pFwBIK5HIe9zxy+EWHzGQs9nu2qgn2NuUj+kviGZ7Q=;
        b=Fw8kXiIzxo5HsPnPtphZKNsOVRvLoJleqeL81y2gnJKWZCjWHtTFLee73rzS6FWZwq
         i8QFTMI50eIvbhSB/bxsTa62RwMVROCj+q90I/CnluDUbu88HeD6wQnZv4Wg4ubTMKSb
         zI/u5o+k3e8bpOfz96d/c8bdQjsq779JaRrxiEX/HIePv94EJW4IkgF//khGt3XICio0
         Vkkb6Kp8yOGSVJ884yRfUvGnsaHvvvGfgQ5382iuyil1Wk4OKwd8Vnvml72hsuNaZM6r
         igIeCnmBUFrHyrzOQ/eQ02c9dOETVwi2+BP+JOd7OZiijnnMhvwEHv8IwV70MN/2lb02
         e64Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=L3OlXNV5;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723220640; x=1723825440; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yZvS4H7EiZunH1uiW+MVaTy3CTbP41rRTtU8ssmBn1c=;
        b=mCpxj4FZyuhA6P/LcfLyKcGtRN766V2poC0sWIMnxwRhOCt33H+t8fTGoCkaBfAJcf
         C5idur4wyG0uvOTL3k66Icp+hqcVkusHW8ph5ZpXdw+hZotuvzuxti7ettJUEoFbHF1z
         IdGro6Jx4Qk44+TzL8pF1jnzYJdLsPuYdcMOmaMlcSeRdU4zBf9h6WCbyn24lsHzHBdJ
         p7SSA9YV+JI/f/4aIUf5mzBCGOShxWpRmOsRpg+lYIC/BBoHlgqjhull1H+WPslU41/q
         a/IPS5zYfCtFCaKt0495bjOApXGzVA5sTtlZVfTKMHqhPzW/X7vrqKw+DE5v8dSgarbn
         o6Mw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723220640; x=1723825440; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=yZvS4H7EiZunH1uiW+MVaTy3CTbP41rRTtU8ssmBn1c=;
        b=mDH6EpU1N44/+JlKHh+RCRrbC9zdWmLN91dS0MrO0JDDVGk+3ByPMkz/Bmn3q2Q0xM
         3IatEWRYb2/jkPq6W+8wGds8M+ibUwSeK2vivrIxWHpYqhUtUHifx9LS2uQuS/s1rHgu
         X0KOTa79RC0ezj1mWEf6tYZrR67iAk3FCHJBIyqh84yaNcXZrPuRtqWkJTxBLTgTU0MA
         5QjRq5KctclCKwN7wAENwF9IXVpwaaKz4ZrFJ8DW8Dq8MHT/ajXronpwqIHgfFDqCKpH
         tnWr0HQNff6+wyAd3vIooh/LUMPxAIb/CGgmLD9PxUDk+w5U3R35XhyI30S+cs1UdpFX
         HKLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723220640; x=1723825440;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yZvS4H7EiZunH1uiW+MVaTy3CTbP41rRTtU8ssmBn1c=;
        b=WM25Tg9A5GFWCxC+QVyOfO9G1TRDfB1DyMA+10cj5bgKRgMnNEBPt59x1zZ+vSv0nE
         y0DxkblFgY+SwlOT9kzxCeoz58ZywpNOGa3fIOKNJKfBr/kDYIMBQ10sM7ri7r5DpI6z
         tmvVT9eGNcp6TlY4S+NH5Bu5m/m+WwJsiyrhQYTyStaBVbCMIWzseN/AMCgMOJExnpX8
         kTQbss1mndOt+6dvtgYunsDWsiOvPkfMrqEoyjuqTvPPsV1qocPfpvOWL/CFDIS3qjuX
         PiAxI/HNPqG+FPiID1ubWPSZvQWY1YMvsTAUXdlISUkq5a086xvXd+Tb0pfZGFbEsx/e
         L0PQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX1ztqt8S89SVw33Aw0KotLUy54RkdkMBv3znYTCyulaI5+8lNlXMHtcNSNI0w8qujJmQrxXslIoc9vSKGtMzxf4EhYmVw0sg==
X-Gm-Message-State: AOJu0YydFJsvvL1BdZyrtHuh2E2Fa0aHPw9NafXA5hrLv5rfO5nIUxxj
	YJrVMRgcMQl3FBvSvb3LgORyB7k+ItelpMKovKG5WQZ3ynrTs8mf
X-Google-Smtp-Source: AGHT+IEn3R90IuI+eGULognqayqhGtBRAUKjQJh0IwjJYLsapyMhGpIMStQGT7hwqKsN1/df5SsCtw==
X-Received: by 2002:a05:600c:3d87:b0:424:898b:522b with SMTP id 5b1f17b1804b1-429c233e454mr1530595e9.1.1723220639489;
        Fri, 09 Aug 2024 09:23:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:681:b0:428:3de:a7f5 with SMTP id
 5b1f17b1804b1-429028a66c1ls7864255e9.2.-pod-prod-00-eu-canary; Fri, 09 Aug
 2024 09:23:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV3lVoDQu0LVgxlCL7Yttlac/15QVC1EAqLzn8mIdTdEtdOGfSR2MDjz+jdhxn39f8mHHxuUhC2pNF4VoXPKgvHzJPhLF3LLuq2oA==
X-Received: by 2002:a05:600c:46c3:b0:428:f0fc:4e54 with SMTP id 5b1f17b1804b1-4290b8ac7abmr47052795e9.11.1723220637731;
        Fri, 09 Aug 2024 09:23:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723220637; cv=none;
        d=google.com; s=arc-20160816;
        b=WOo3RIoCdWrzXx+weo0MpeRi1XneOCn9FIcyjT6V8MoKOC+erJxaCtFZ74L4Xaw+uL
         VNERnbB5HuxL/7LdIBPA6XhIwrGSmP4E7RyroN60J+EWz0sJGEOXc6f/r+6ljzTTlVhR
         uEilD8FESwBFCPA1wtrQCV9tAf9vtKI17RN0aJGDxPFB6HAilbB8Q2xEfVqFa7XrL46E
         ogvjdsHB9tV/mXAYhNJvjGj9/Z+8TrRmorU1JvIWAiLT2rvvWlLzq/Whe01SBThwODlC
         w4nsaVkTKOvTHgo3zgWqjY0fgs8lnqeLhjSogBXNB2AxuD7WBC+/jGSVtBuZv7bGL2us
         r24w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=urwFjYIe54BX21GUD0rDONyqjA52hcZTxeP+KnuDeBc=;
        fh=+sFeqM0lzk7sdBGIgJa8b9KotjaT48b6IiDubRS10LY=;
        b=yG6mxjaasRqCR/Nj2yd5IFacN5a01swgFdsvJ4VQAJfDEhKmv3T43++ciYmI0+CMJX
         pNaiuKjWMEX5NxXfJM0VdeRRWZNLopMMQ0kV5ok3eMZbiskhdiYbZeTsUroSiknfF6Me
         0VMMpnCJa+zWcmQXQ9fc7YvicrV4x2OjXGCisl4MXVfKIb2e/RR5tB/QTWY4xy4Gl/7m
         TAeJ681v3679YxP4TYkgL4D+p/XZOwn8Vu2eQd4hng7vK75XMbZSn5dK7E21gmnVVksh
         iLsJYa/x4HOTA0p9BOZYtohK7XTgm1w08dPd8Tag7CoLAdGzreEA5Wq5Iczq3sN3NlBO
         z1zg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=L3OlXNV5;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12f.google.com (mail-lf1-x12f.google.com. [2a00:1450:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429c199f5cbsi1666065e9.0.2024.08.09.09.23.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Aug 2024 09:23:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12f as permitted sender) client-ip=2a00:1450:4864:20::12f;
Received: by mail-lf1-x12f.google.com with SMTP id 2adb3069b0e04-52f01613acbso3563737e87.1
        for <kasan-dev@googlegroups.com>; Fri, 09 Aug 2024 09:23:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU7NtKwsb9ABFZ50LoTn2D82dbsXIoMJ4fYnc+hecPy8LUDPPRfv42+9K7YFhhmOweBvsf/XORJx2sYt0iYh+LtvKJTy1CgcuAJpw==
X-Received: by 2002:a05:6512:3e28:b0:52e:fd8f:624b with SMTP id 2adb3069b0e04-530e5de775emr1601552e87.29.1723220632467;
        Fri, 09 Aug 2024 09:23:52 -0700 (PDT)
Received: from pc636 (host-90-233-216-8.mobileonline.telia.com. [90.233.216.8])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-530de3e313csm1030750e87.55.2024.08.09.09.23.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Aug 2024 09:23:52 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Fri, 9 Aug 2024 18:23:48 +0200
To: Vlastimil Babka <vbabka@suse.cz>,
	"Paul E. McKenney" <paulmck@kernel.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Boqun Feng <boqun.feng@gmail.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Zqiang <qiang.zhang1211@gmail.com>,
	Julia Lawall <Julia.Lawall@inria.fr>,
	Jakub Kicinski <kuba@kernel.org>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>,
	Mateusz Guzik <mjguzik@gmail.com>
Subject: Re: [PATCH v2 7/7] kunit, slub: add test_kfree_rcu() and
 test_leak_destroy()
Message-ID: <ZrZClPolptzUgSr8@pc636>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-7-ea79102f428c@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240807-b4-slab-kfree_rcu-destroy-v2-7-ea79102f428c@suse.cz>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=L3OlXNV5;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12f as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Aug 07, 2024 at 12:31:20PM +0200, Vlastimil Babka wrote:
> Add a test that will create cache, allocate one object, kfree_rcu() it
> and attempt to destroy it. As long as the usage of kvfree_rcu_barrier()
> in kmem_cache_destroy() works correctly, there should be no warnings in
> dmesg and the test should pass.
> 
> Additionally add a test_leak_destroy() test that leaks an object on
> purpose and verifies that kmem_cache_destroy() catches it.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  lib/slub_kunit.c | 31 +++++++++++++++++++++++++++++++
>  1 file changed, 31 insertions(+)
> 
> diff --git a/lib/slub_kunit.c b/lib/slub_kunit.c
> index e6667a28c014..6e3a1e5a7142 100644
> --- a/lib/slub_kunit.c
> +++ b/lib/slub_kunit.c
> @@ -5,6 +5,7 @@
>  #include <linux/slab.h>
>  #include <linux/module.h>
>  #include <linux/kernel.h>
> +#include <linux/rcupdate.h>
>  #include "../mm/slab.h"
>  
>  static struct kunit_resource resource;
> @@ -157,6 +158,34 @@ static void test_kmalloc_redzone_access(struct kunit *test)
>  	kmem_cache_destroy(s);
>  }
>  
> +struct test_kfree_rcu_struct {
> +	struct rcu_head rcu;
> +};
> +
> +static void test_kfree_rcu(struct kunit *test)
> +{
> +	struct kmem_cache *s = test_kmem_cache_create("TestSlub_kfree_rcu",
> +				sizeof(struct test_kfree_rcu_struct),
> +				SLAB_NO_MERGE);
> +	struct test_kfree_rcu_struct *p = kmem_cache_alloc(s, GFP_KERNEL);
> +
> +	kfree_rcu(p, rcu);
> +	kmem_cache_destroy(s);
> +
> +	KUNIT_EXPECT_EQ(test, 0, slab_errors);
> +}
> +
>
Thank you for this test case!

I used this series to test _more_ the barrier and came to conclusion that it is
not enough, i.e. i had to extend it to something like below:

<snip>
+       snprintf(name, sizeof(name), "test-slub-%d", current->pid);
+
+       for (i = 0; i < test_loop_count; i++) {
+               s = test_kmem_cache_create(name, sizeof(struct test_kfree_rcu_struct),
+                       SLAB_NO_MERGE);
+
+               if (!s)
+                       BUG();
+
+               get_random_bytes(&nr_to_alloc, sizeof(nr_to_alloc));
+               nr_to_alloc = nr_to_alloc % 1000000;
+               INIT_LIST_HEAD(&local_head);
+
+               for (j = 0; j < nr_to_alloc; j++) {
+                       p = kmem_cache_alloc(s, GFP_KERNEL);
+
+                       if (p)
+                               list_add(&p->list, &local_head);
+               }
+
+               list_for_each_entry_safe(p, n, &local_head, list)
+                       kfree_rcu(p, rcu);
+
+               kmem_cache_destroy(s);
+       }
<snip>

by using this(~11 parallel jobs) i could trigger a warning that a freed
cache still has some objects and i have already figured out why. I will
send a v2 of barrier implementation with a fix.

Thanks!

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZrZClPolptzUgSr8%40pc636.
