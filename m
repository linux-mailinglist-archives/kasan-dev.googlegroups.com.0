Return-Path: <kasan-dev+bncBCV5TUXXRUIBBCMY4P3AKGQEAG57UFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id BCF9D1EE25E
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 12:25:14 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id q19sf1840188uad.21
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 03:25:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591266313; cv=pass;
        d=google.com; s=arc-20160816;
        b=DRFCYw2X8QJyUHZIFA4KKQXSalOcTuhoP62aNcM4Th61MuQOVFcqtVxyeheyzogjqk
         XXK1N3BIcM/6Oxv1nQkmuoGMu/BB80nuuYwtawrv5irK1nHyrQ608G22cHFNuD49tW+v
         evdMi8UCTpQ3+pXwchulsHg5ukBP2ODeYQkRDHQ3aO+xRPWc5gUW+tyHE8BVLMwt3K9R
         b/K6Fo7VjAym1HCnfsOTnXq7eZ8q92Z1x+ZGQMUFmoXrFYC/4VGRhcFwQRGJdvzNB3Nh
         d1meKIcCn7scv1wj9L93b8A9RQqcferLC8bRuEKH/K4DEeCdF6GZR9qh5PMXgey7FNTw
         rlYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=gq9RWczGZIvBo697oxkVY468AlixomrjPyPi+vEMsyU=;
        b=Cb93RDy6jdn2X7BCRHwrkGhXQP+9eqPy/Qxz3SWengqL4D/as6GVeVjhr8Y1IRnaB3
         PAulF1udYGQdjlOTY8GaeN4HInyS11F3/LwaVJKZzWr37lSWu4CuqaMsQp8HhWG/tyt3
         qKGM1VZ2B396To8mBww2VdxKWbXxkqdqi9d2xip6KarJlmYNggwhuMkGNzar+Wydu5n4
         L0yRu9WY+Unq59+ClQh3tg1J/v2nqpIYtU/ndH22K+CZG1leZgLyLw93D0gtO2Z+WOlZ
         LrzzAoqMpgLQzM8bAnJKmk03xT3O7YqS1Dx+LqoJ3T2rRglXBm+T4Oh3TmQW8EH86r3L
         ybcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=AOpABfpS;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gq9RWczGZIvBo697oxkVY468AlixomrjPyPi+vEMsyU=;
        b=Tt9l1ddlVXydRz1KE3/2NLA054JBWmIuB8z9xIVuXRzJ1ixtlpgIt/RxVaFlL457Zs
         fQMvgHCcvOpvXILpsAHClvYLq6ASzb/hfgGaoWMrysKXN5D/NiNpwpw2gf22DrGBB/Mq
         iMeu1GCBr6MWZdFWF3nF1VWkNk/xYfaN9LbEDNL6R2dXtRzDxj5evotj5JKOav4FYGZ2
         slq7QZACFPVde9SXC7gnVvbNyVWC+nt/OajDPhztjJemTAOq/5GTm94M0TpduTEUBfMv
         GfbW7bMFLD5fiFLYheORkROLxdsDSwM3LJdwNgI1/zLGHfSFVtAqXKRJq0ciTzV2WXhB
         oiuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gq9RWczGZIvBo697oxkVY468AlixomrjPyPi+vEMsyU=;
        b=dlRYb48sNIP7785a2KtaTwgZ1jvW58F+6TvmhLqruYtikTGQjnIebUfVHjkhroXKsT
         TM12y7vi1DRRYE5mIpYnN269fACqUicXqxzdItRKv1qqZUod5aSpSsqP45k+Mw1IRm1X
         bNaPii0ucI96e96NDq14CAbvGLKwwTXafxdUeFkRHE6+mIW4nL0PU7L9MB5x717Bk1R2
         Vdmo3nbFooEJbZSXO86q2ZoYd+PtH5lzdNa5razabo88DLREwbRNz/6pxVzyfWLiPKeO
         hWqENpAPJ5ZG8/VQxY9y5qzEkkrN2CsmOj/NJldks5Nhi6qsicAjAs2atEuUdfATPZqu
         oqeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533fQjhyMke+G0LzMVV+fBAGjy9Z7ILf8CQq99Q4kezi9zzf7qe1
	zoEmX7GscS4YSQ1KnCCDclQ=
X-Google-Smtp-Source: ABdhPJx+zKTgDv6t+7BYK9dFkVpU6/um46ao5uZ60goowZs3d8SZ+4wIBM2drdlUEPXmxp3B1n1vdw==
X-Received: by 2002:a1f:9a16:: with SMTP id c22mr2610318vke.83.1591266313417;
        Thu, 04 Jun 2020 03:25:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8717:: with SMTP id j23ls662433vsd.11.gmail; Thu, 04 Jun
 2020 03:25:13 -0700 (PDT)
X-Received: by 2002:a67:8c3:: with SMTP id 186mr2750717vsi.203.1591266313082;
        Thu, 04 Jun 2020 03:25:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591266313; cv=none;
        d=google.com; s=arc-20160816;
        b=aiGZSXNrQmFghOMJ0ZyxQCq41L9HgrJXLfPK7isPsOTuToXmedIN6iDO95pGr4Uc0I
         LvNgS+V2Lm7qV6MfYkTwiriJWEsScKZvFGNJZRkEB3W6sqdobhyGD+JecgbV4tBoynB1
         IYfwfZUa6C4HTeQA2xCyQRxU7pH9Km2vu2XPROx24c0A95IIPvrroxyY8krOHY4kcNm0
         1XLKo4xLnnEvbdbGLx/J4M5VdFD+IhJHiR1ekgM6nMUfeEuyGv8UBtFeO6Xv+CneTDX7
         oIfOEuqIP0st6+1nRBKJ//BbOh/XKsKuKRhmRpyFD1xxrhW8uuwO3PcUuUF5B+nNOIuW
         7yHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=zk2YSNLVDIg6CzFc7dqGugTGjUQyn9Y1fCSXYdtV1Fs=;
        b=xjo4RTOLP4+fOK8el1d3X75oS3tHMlMus6sVE8S0zRHdY8SDHRF0n4/Js37B6LPm4w
         YFVDAEgYjLd7Cr8R0v9ct9Hv068fF2gFjZDXtjdQgL+t1lWKK5zgqK62qCmlm6pn7nEq
         iPQvD5CEvmajP0o0Rrsk76UFDWEGHLKeIX9IuCAnOiZEdZw/mzbWwhLEW2BXR6NiQ2+Q
         0ktKzt3gYDeC8FXuxVC8G0S1+BEyHF/eYwtAFHNOmK3h5qfTpROhbPdW6Ggjst0m8cz6
         +cTrob57ZpUIMvgt8SPF+OIgxJLd6ZI7U9YW6vRwanbLuCy29+I11aPS8HhKQGT+bmWy
         DWyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=AOpABfpS;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id q20si234401uas.1.2020.06.04.03.25.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jun 2020 03:25:12 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgn3d-0001cD-M5; Thu, 04 Jun 2020 10:25:09 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id F03B0306064;
	Thu,  4 Jun 2020 12:25:07 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id DE92D20CAE764; Thu,  4 Jun 2020 12:25:07 +0200 (CEST)
Message-ID: <20200604102428.135635542@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 04 Jun 2020 12:22:45 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org,
 will@kernel.org,
 dvyukov@google.com,
 glider@google.com,
 andreyknvl@google.com,
 Nick Desaulniers <ndesaulniers@google.com>
Subject: [PATCH 4/8] kasan: Bump required compiler version
References: <20200604102241.466509982@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=AOpABfpS;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

From: Marco Elver <elver@google.com>

Adds config variable CC_HAS_WORKING_NOSANITIZE_ADDRESS, which will be
true if we have a compiler that does not fail builds due to
no_sanitize_address functions. This does not yet mean they work as
intended, but for automated build-tests, this is the minimum
requirement.

For example, we require that __always_inline functions used from
no_sanitize_address functions do not generate instrumentation. On GCC <=
7 this fails to build entirely, therefore we make the minimum version
GCC 8.

Suggested-by: Peter Zijlstra <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
Acked-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://lkml.kernel.org/r/20200602175859.GC2604@hirez.programming.kicks-ass.net
---
Apply after:
https://lkml.kernel.org/r/20200602173103.931412766@infradead.org

v2:
* No longer restrict UBSAN (and KCSAN), since the attributes behave
  differently for different sanitizers. For UBSAN the above case with GCC
  <= 7 actually works fine (no compiler error). So it seems that only
  KASAN is affected by this -- let's limit our restriction to KASAN.
---
 lib/Kconfig.kasan |    4 ++++
 1 file changed, 4 insertions(+)

--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -15,11 +15,15 @@ config CC_HAS_KASAN_GENERIC
 config CC_HAS_KASAN_SW_TAGS
 	def_bool $(cc-option, -fsanitize=kernel-hwaddress)
 
+config CC_HAS_WORKING_NOSANITIZE_ADDRESS
+	def_bool !CC_IS_GCC || GCC_VERSION >= 80000
+
 config KASAN
 	bool "KASAN: runtime memory debugger"
 	depends on (HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
 		   (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
+	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
 	help
 	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
 	  designed to find out-of-bounds accesses and use-after-free bugs.


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604102428.135635542%40infradead.org.
