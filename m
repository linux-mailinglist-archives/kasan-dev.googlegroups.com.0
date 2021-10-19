Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXV4XKFQMGQEAQSOKEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id DEE7D433383
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Oct 2021 12:30:54 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id x5-20020a50f185000000b003db0f796903sf17159510edl.18
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Oct 2021 03:30:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634639454; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cl9i1XvPcVs4GBoFSOV/fkyf2JVc2K6lutmqoLZdv+9IhEoZEvUHDhxFQR8/iXKSD2
         c7hZa0QEoe4WYxeDeCm1k8h7OlWvyc9vPxq6gt4Ve0ufLqMhMwzWhO7yZNMD4HZuHzQD
         lg3/R07Ksc+w59JJUeoe++F6mrltPq9OfdgLxALbnELP2SMYkcO9KBljZEffrTHAC6K+
         B+Kc+uB/b+4flKulmjdV1q9/80fcJEAuqqAyiTBZNryNiJjBsEfTzKYh5l0vZwK4aIdC
         5Zqrn8g3pKc1AImy4eJDyyHTIK4EwrYpNxI68s11reEIE8j/hhZ9W4ub+23QhW6aXNOU
         uEdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=i7Htgh2uq6SuugHMnBcn6iihY272sf3qiEWZlNUnyOg=;
        b=RhTkHFx5Y6463FuptMHsat1dbmQ77bOpzrPfSyi8cQemcd299I4NlUy09Pr7Nqeq4l
         0HicasNMRIL1xVxdPAKWwGtK7L/q/Y/QhSl/+H76QeU5eBmoCPYsgC3RC6BJNE5h6T1h
         q51nvHhxwkcgpQf0m/fPk+BkRJcsss5P87+LA+4IqIqoXQlg6nk7eBhcQQb/xjsBTxmY
         VDFXqoF0qn0p6N7wEC/NbBbbM9UVZorwFF8ADpwUaRii0Bz76eK87eILSv4l5AyMOQVf
         at8f0xSG9J5FXCTwyCYoEOVMhEuzTOR/sZLN/OsxU8VEQD6rzxz7HMaMD6nEZmswPfLF
         k0pA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="jS26q/AK";
       spf=pass (google.com: domain of 3h51uyqukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3H51uYQUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i7Htgh2uq6SuugHMnBcn6iihY272sf3qiEWZlNUnyOg=;
        b=gZqS5jZ93twY6DajBGiJmqsekOZ4jACk8hN8RS+UQqtDp9mdn23myTkIP3/mj8YQLE
         hSxPC5Jemfy0+YozWm58NAyGsn7D4kMaeADi74KZYG2GuVfRTqk8FFsR8o9hCZDIZz9Y
         y6NsPFYJjsdWeFnsv8kmiCrZkTvEpYliH3lt59pKCKmGqCUZpvOA8PQQdoi20CP8o8t8
         iUxZWWOe5d3Ds9gfi2vjMErPtAJ/SvGTYt07woX4P8eZHroGAvpB5bi+nnbogXoqHqPe
         m4UkNSP8DygPA2Nt0DLWjF+Rhf5kiah73/bAzt8jrOB+STaTyWcWtC0iUM6PwxGqBUfC
         TtTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i7Htgh2uq6SuugHMnBcn6iihY272sf3qiEWZlNUnyOg=;
        b=wVg3lE29F5JYu5AweK7teCFiW0BnAFd+F0SGd7CO6LTnOas+0NRnl/NwAAkuAAQiaw
         CO/YjYweAqmy2YLb1nlyHzbHhoZ5DVnkS27y4noMjxDquXIUiplynWQ7CnaKaaCg2F9N
         Ovr8qyw4NOjUVwCYF3uDyJuFNzAplUe76fdwUjc1GBDrrD4QmGjznNR8bcQNnQ0GcXRy
         WTYdwsesC8MsfvNsqaQzh/tzeJ149evZbHyREoY62KQNjqJbxjUcGOJnLy84K10b3amm
         mAqyt2y5M5B5EwQstThlv2iPDoV24RGsk8y9Diw1djp1Lm12Dtj3r5d2mz6K0z+ZBzz2
         JSpw==
X-Gm-Message-State: AOAM531yBC8aZ3xegFwAe0VG1FBlZrLC47/RMXI9oSdcInUdIlGtggNu
	wmIetfGdfxGAhIfSzGdGDC0=
X-Google-Smtp-Source: ABdhPJwqlSiKH+GMHEch8q3sbHHuZcvGgOpfienrovrSbIyTn1Dzddtd2iBk4AhufltPi3aNTHoRCw==
X-Received: by 2002:a05:6402:370:: with SMTP id s16mr49119448edw.1.1634639454581;
        Tue, 19 Oct 2021 03:30:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:18c:: with SMTP id r12ls1369056edv.3.gmail; Tue, 19
 Oct 2021 03:30:53 -0700 (PDT)
X-Received: by 2002:aa7:dcc2:: with SMTP id w2mr51301447edu.192.1634639453518;
        Tue, 19 Oct 2021 03:30:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634639453; cv=none;
        d=google.com; s=arc-20160816;
        b=EL18AB7J8zop8tuwdyfxyKciUcq1iZBQ+HOgv3rk1naM89ViG/CebxK2SHFZ28MaKn
         dhU1aKmD1kKeB5JpBGmiIXcGKoyykE8ThPAKTO8jW9QjRBQCOFT56yMaKYVE6Vjbdk8x
         7qmpA6zzHUOO/QwOmbMMNtvF/hTt3/xkg/cu74pqW2BRGl2HDcoEPeWTTTyl/9Gv/wIH
         tKuIQ6ln4kBnbndPLGi8epkeGXOxTtAAPJxg74dVNmQ11cypbiromLJMlkddgHEfgH4y
         3HaKQDEFLMXmuUp3/iQ6Su+dTKNJgLvqYCgDyKmP/+mruNrB0UCpkhWq94Z429gOdp3c
         qCng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=18QmBkB8I+n5qxxUGXdyzfTsY7V9PS8kg83ueXyuZCk=;
        b=HtNEk3yyIDb+eDdt33pk9svgHGc6R7vyUsQdkJbpbMgQye4REDXfkh1pVt85YfDNI4
         yGoQUm47zLNRR6Nk3jbUThRJSF86IEXwMMbEL6th5JWBkknt3gwfatY8Im4pzTXvFrU1
         bQUKSfIbTU2IRu4huuRBeZ5oSkPUnM1nl6QCcUBi493nYzIzydLeBTHA5HrKwCCdOO8j
         eiv9IRYlLL0TcupKvlF2ZRowwcmyhAfXuEnZmRseIYvWh0xyoCmPivQGlr9y7B4VQjqP
         9S9pzvTh2ZWtlkgNPTLLdp9n2uJyVt88luHCgFl5yROxOwtCfBvU4W5P7usS/2vC93xy
         Oq4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="jS26q/AK";
       spf=pass (google.com: domain of 3h51uyqukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3H51uYQUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id s19si1069559edi.1.2021.10.19.03.30.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Oct 2021 03:30:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3h51uyqukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id t18-20020a056402021200b003db9e6b0e57so17172675edv.10
        for <kasan-dev@googlegroups.com>; Tue, 19 Oct 2021 03:30:53 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:feca:f6ef:d785:c732])
 (user=elver job=sendgmr) by 2002:a17:907:1044:: with SMTP id
 oy4mr36797913ejb.308.1634639135257; Tue, 19 Oct 2021 03:25:35 -0700 (PDT)
Date: Tue, 19 Oct 2021 12:25:24 +0200
In-Reply-To: <20211019102524.2807208-1-elver@google.com>
Message-Id: <20211019102524.2807208-2-elver@google.com>
Mime-Version: 1.0
References: <20211019102524.2807208-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.1079.g6e70778dc9-goog
Subject: [PATCH 2/2] kfence: default to dynamic branch instead of static keys mode
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="jS26q/AK";       spf=pass
 (google.com: domain of 3h51uyqukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3H51uYQUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

We have observed that on very large machines with newer CPUs, the static
key/branch switching delay is on the order of milliseconds. This is due
to the required broadcast IPIs, which simply does not scale well to
hundreds of CPUs (cores). If done too frequently, this can adversely
affect tail latencies of various workloads.

One workaround is to increase the sample interval to several seconds,
while decreasing sampled allocation coverage, but the problem still
exists and could still increase tail latencies.

As already noted in the Kconfig help text, there are trade-offs:  at
lower sample intervals the dynamic branch results in better performance;
however, at very large sample intervals, the static keys mode can result
in better performance -- careful benchmarking is recommended.

Our initial benchmarking showed that with large enough sample intervals
and workloads stressing the allocator, the static keys mode was slightly
better. Evaluating and observing the possible system-wide side-effects
of the static-key-switching induced broadcast IPIs, however, was a blind
spot (in particular on large machines with 100s of cores).

Therefore, a major downside of the static keys mode is, unfortunately,
that it is hard to predict performance on new system architectures and
topologies, but also making conclusions about performance of new
workloads based on a limited set of benchmarks.

Most distributions will simply select the defaults, while targeting a
large variety of different workloads and system architectures. As such,
the better default is CONFIG_KFENCE_STATIC_KEYS=n, and re-enabling it is
only recommended after careful evaluation.

For reference, on x86-64 the condition in kfence_alloc() generates
exactly 2 instructions in the kmem_cache_alloc() fast-path:

 | ...
 | cmpl   $0x0,0x1a8021c(%rip)  # ffffffff82d560d0 <kfence_allocation_gate>
 | je     ffffffff812d6003      <kmem_cache_alloc+0x243>
 | ...

which, given kfence_allocation_gate is infrequently modified, should
be well predicted by most CPUs.

Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kfence.rst | 12 ++++++++----
 lib/Kconfig.kfence                 | 26 +++++++++++++++-----------
 2 files changed, 23 insertions(+), 15 deletions(-)

diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
index d45f952986ae..ac6b89d1a8c3 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -231,10 +231,14 @@ Guarded allocations are set up based on the sample interval. After expiration
 of the sample interval, the next allocation through the main allocator (SLAB or
 SLUB) returns a guarded allocation from the KFENCE object pool (allocation
 sizes up to PAGE_SIZE are supported). At this point, the timer is reset, and
-the next allocation is set up after the expiration of the interval. To "gate" a
-KFENCE allocation through the main allocator's fast-path without overhead,
-KFENCE relies on static branches via the static keys infrastructure. The static
-branch is toggled to redirect the allocation to KFENCE.
+the next allocation is set up after the expiration of the interval.
+
+When using ``CONFIG_KFENCE_STATIC_KEYS=y``, KFENCE allocations are "gated"
+through the main allocator's fast-path by relying on static branches via the
+static keys infrastructure. The static branch is toggled to redirect the
+allocation to KFENCE. Depending on sample interval, target workloads, and
+system architecture, this may perform better than the simple dynamic branch.
+Careful benchmarking is recommended.
 
 KFENCE objects each reside on a dedicated page, at either the left or right
 page boundaries selected at random. The pages to the left and right of the
diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index e641add33947..912f252a41fc 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -25,17 +25,6 @@ menuconfig KFENCE
 
 if KFENCE
 
-config KFENCE_STATIC_KEYS
-	bool "Use static keys to set up allocations"
-	default y
-	depends on JUMP_LABEL # To ensure performance, require jump labels
-	help
-	  Use static keys (static branches) to set up KFENCE allocations. Using
-	  static keys is normally recommended, because it avoids a dynamic
-	  branch in the allocator's fast path. However, with very low sample
-	  intervals, or on systems that do not support jump labels, a dynamic
-	  branch may still be an acceptable performance trade-off.
-
 config KFENCE_SAMPLE_INTERVAL
 	int "Default sample interval in milliseconds"
 	default 100
@@ -56,6 +45,21 @@ config KFENCE_NUM_OBJECTS
 	  pages are required; with one containing the object and two adjacent
 	  ones used as guard pages.
 
+config KFENCE_STATIC_KEYS
+	bool "Use static keys to set up allocations" if EXPERT
+	depends on JUMP_LABEL
+	help
+	  Use static keys (static branches) to set up KFENCE allocations. This
+	  option is only recommended when using very large sample intervals, or
+	  performance has carefully been evaluated with this option.
+
+	  Using static keys comes with trade-offs that need to be carefully
+	  evaluated given target workloads and system architectures. Notably,
+	  enabling and disabling static keys invoke IPI broadcasts, the latency
+	  and impact of which is much harder to predict than a dynamic branch.
+
+	  Say N if you are unsure.
+
 config KFENCE_STRESS_TEST_FAULTS
 	int "Stress testing of fault handling and error reporting" if EXPERT
 	default 0
-- 
2.33.0.1079.g6e70778dc9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211019102524.2807208-2-elver%40google.com.
