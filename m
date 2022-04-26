Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQGDUCJQMGQEHYUQMHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id AE6AE510405
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:52 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id n186-20020a1c27c3000000b00392ae974ca1sf865992wmn.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991552; cv=pass;
        d=google.com; s=arc-20160816;
        b=fiH5FiT2Eh6ku/jLGCVxfCAImFr7059yH05yfnKokJUEZHyJxl9hMFJPuL7sPvMjUE
         p5Ef0uDaG1Qvhn+QxNLiWyHHIHN1CkO1Tiqckcg7HwUyBA4sBM1oel0bY5bskeyrAeIE
         sgxFfAGjberc0XrCkxMequOBOhiRnnPoCkpWSou23xRcURQj5ZvZCT96hmdJNEsb7ufB
         JAl1GYK45GshhjE9DSJLC6EDoHMMtx035aQ3r6VIMUDQkQOJqlFFkrK0xqvJ2Gjp4Ohg
         0HA5YOJJPsbZzwlyNPQGUsx2Kh8KV2xErMv7zjDSkSZWfHqihjoXi+Jd6WwQxk7Mg8uX
         VL7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=zOXH0eGwY9De2mVFm4EZWxw8qvbNnSe5LuoTB0iYsaw=;
        b=XJJycbYa4frb42mC/4iu3s1qhxlUmB41ny9xypRKAnEQfWpyLqOzW6GKFbeplzj44+
         jUVjpb2sU7UyFhuqS88hh37QtEXQQAkoSUR5lF72GDeRdbRk1ARvUHbLgkrK2s2Gt6T3
         r0MAjWmQNPg5gyJz7e3VViWCEP/vDl505Rko/VJ+Vd3UNhJ0QoZ12wtGpz0/0DFFeypI
         UwBJpaXm9sgjBLQP5fT6qc77hnSiSskRdKoKrHref+6cUILKbL/B7pIGyu7ljtcbeUKY
         UOLW05UPrKkExWIrfCkTRYs8XXp+GpFkyMgGGFbd+Ny7gAvKA8YNlR0A71u0X55D1QtJ
         sn1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fRwDF91C;
       spf=pass (google.com: domain of 3vifoygykcbshmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3viFoYgYKCbshmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zOXH0eGwY9De2mVFm4EZWxw8qvbNnSe5LuoTB0iYsaw=;
        b=b1cwrtddr9+Q/NE/XZgDYunE8b91QkrWGfWatnmSMdiosF/MKKlFURchFu8XuK97GO
         U8A4YXrJesB7ZPwbINhE0Q6gPXVqqnoX5FsRVm/c9o4xX1gfwr4csgqENNHfYr3Ajw/N
         aXg116t3IadnNTSrcASCocPuqW6yfHhA8z/5EFOhf4QPV8uAmcpIlBRHFO41esonb6KW
         YGz3btpzfRBwMfcnKZ4iF6Qq19tURewk2kMunrt/lDdYlfxKYVMp/EJTsfklgFnkIFVy
         +eLTO/J7mrUNPue+mh18pho9ah937yHmg+EtM++eVg/XqQeN0lhca7qU7RukTo4pZhfM
         icmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zOXH0eGwY9De2mVFm4EZWxw8qvbNnSe5LuoTB0iYsaw=;
        b=feszREyQA2HHA41bQtTcpd9658+UdAyB/J72YFrD9+pUkYMQNnQ+kIgE8wRu+KqVOt
         Kq2M/4OlOLLF0eTmaNVRuxKm4XgfXg3e2s2Zix/xl3nywBRwRhGanStQBgk2q6jEpkLO
         g+mfA7405ic43IsvB6pBC4M2YMfAE9s9nW1IuE6hG9KcXAT/lCOo4jyYAdqDRNWw02Tb
         NvU0Ah9EmJFMbLpr3TG7GrZkCkCLlfP2ZVvKwWSXoLzwHSRfwPzAbp8YEEtYTHLT3dsv
         DYsM8CkCVsW3P6vtGMuvSSzME44R+Dd9QNs0gGweFEsYSVn6h2aRPjB3mGiZtdO7JdSW
         8pPA==
X-Gm-Message-State: AOAM531pir2C0iPMRu3CHo5EgkhGICh28dZUMJUdJbp8G7ODfmXp2xRo
	QhRoWC05zKaIYEJLE7et/so=
X-Google-Smtp-Source: ABdhPJwz43c/Fb1rbkWByZEVRkoVhdGqk1NZtMlrpl5CcbAP4cji36EW/GgxUp59jfqhzBw2boe/Kw==
X-Received: by 2002:a5d:474f:0:b0:20a:cb5c:bbd7 with SMTP id o15-20020a5d474f000000b0020acb5cbbd7mr16714497wrs.21.1650991552353;
        Tue, 26 Apr 2022 09:45:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c26:b0:393:e7d4:b644 with SMTP id
 j38-20020a05600c1c2600b00393e7d4b644ls3952273wms.2.gmail; Tue, 26 Apr 2022
 09:45:51 -0700 (PDT)
X-Received: by 2002:a05:600c:9:b0:393:ea67:1c68 with SMTP id g9-20020a05600c000900b00393ea671c68mr12106831wmc.92.1650991551417;
        Tue, 26 Apr 2022 09:45:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991551; cv=none;
        d=google.com; s=arc-20160816;
        b=UPzXkzJZcxGt74lph02Yod3DlAarNgKpRGrSpVAlOkxHCpMr3023gVzz8On6O62p1U
         lPIKOQUWwWf6Ovh0YCKgLNYoYSYxjWucjD58ym/UK8DicngadSmfhcBkHK/yY2o53Th6
         UHjoUBz2u3JCWDCfJrbGFlk+G2uF4BJkJ4nqAsRHig0v7u4zs3NC4EKMs0oTiV0KoosX
         5Ivww1HpHoHOTbSFmHfe4jIunuGoqltUwtULW/DGahuBtM//yz4ATo5QGy91bwHvjRms
         3jMDpn6LSIzVhFrfZNp1RPddAvTThRU3m500rGPkY+McIwX1JvlSMvi0awSOt0odtdCF
         36eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=qfycs5WHoOJISCgVkz4aOXJI06Vi4G56am9I/vqcS5Q=;
        b=a6IR6oRyiCfCw73HuxGgGRCsY3ZE/Wy0Ag1HxzTaTShKDDOqK3Szg6ecKiNIGz3bU+
         GXlDFyibL1m4cOX9y1QdmUJnmlRGNu0QP/IIAQNXvOY/7e6oAGjJghIYH6Gq+oTwY+f2
         Lngal8jPITTEwLM4xXt2CfVly5P/P5ixJhHN9fuXWckGtfarIG1hIjfBFEWg+MF+Tyhs
         8sX50bmdfEJx6UgsA800MulUv7UeHr/6Ovh8aQawMMP84diwr1aGtSlW3plzHEl+Dt76
         TJ3IEtdugtMiKhKiaAV3qZnuXkvS9839qfDkGNjw3w4I+77h+XeJ1ZBHFBqsD/F8ltFn
         WMKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fRwDF91C;
       spf=pass (google.com: domain of 3vifoygykcbshmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3viFoYgYKCbshmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id b22-20020a05600c4e1600b00393ead5dc00si173963wmq.2.2022.04.26.09.45.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vifoygykcbshmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id k13-20020a50ce4d000000b00425e4447e64so3792457edj.22
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:51 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a17:906:a08b:b0:6b9:2e20:f139 with SMTP id
 q11-20020a170906a08b00b006b92e20f139mr23252089ejy.463.1650991550999; Tue, 26
 Apr 2022 09:45:50 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:43:04 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-36-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 35/46] security: kmsan: fix interoperability with auto-initialization
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fRwDF91C;       spf=pass
 (google.com: domain of 3vifoygykcbshmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3viFoYgYKCbshmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Heap and stack initialization is great, but not when we are trying
uses of uninitialized memory. When the kernel is built with KMSAN,
having kernel memory initialization enabled may introduce false
negatives.

We disable CONFIG_INIT_STACK_ALL_PATTERN and CONFIG_INIT_STACK_ALL_ZERO
under CONFIG_KMSAN, making it impossible to auto-initialize stack
variables in KMSAN builds. We also disable CONFIG_INIT_ON_ALLOC_DEFAULT_ON
and CONFIG_INIT_ON_FREE_DEFAULT_ON to prevent accidental use of heap
auto-initialization.

We however still let the users enable heap auto-initialization at
boot-time (by setting init_on_alloc=1 or init_on_free=1), in which case
a warning is printed.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I86608dd867018683a14ae1870f1928ad925f42e9
---
 mm/page_alloc.c            | 4 ++++
 security/Kconfig.hardening | 4 ++++
 2 files changed, 8 insertions(+)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 35b1fedb2f09c..4c89729cac7ac 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -849,6 +849,10 @@ void init_mem_debugging_and_hardening(void)
 	else
 		static_branch_disable(&init_on_free);
 
+	if (IS_ENABLED(CONFIG_KMSAN) &&
+	    (_init_on_alloc_enabled_early || _init_on_free_enabled_early))
+		pr_info("mem auto-init: please make sure init_on_alloc and init_on_free are disabled when running KMSAN\n");
+
 #ifdef CONFIG_DEBUG_PAGEALLOC
 	if (!debug_pagealloc_enabled())
 		return;
diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index ded4d7c0d1322..d6cce64899d13 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
@@ -106,6 +106,7 @@ choice
 	config INIT_STACK_ALL_PATTERN
 		bool "pattern-init everything (strongest)"
 		depends on CC_HAS_AUTO_VAR_INIT_PATTERN
+		depends on !KMSAN
 		help
 		  Initializes everything on the stack (including padding)
 		  with a specific debug value. This is intended to eliminate
@@ -124,6 +125,7 @@ choice
 	config INIT_STACK_ALL_ZERO
 		bool "zero-init everything (strongest and safest)"
 		depends on CC_HAS_AUTO_VAR_INIT_ZERO
+		depends on !KMSAN
 		help
 		  Initializes everything on the stack (including padding)
 		  with a zero value. This is intended to eliminate all
@@ -218,6 +220,7 @@ config STACKLEAK_RUNTIME_DISABLE
 
 config INIT_ON_ALLOC_DEFAULT_ON
 	bool "Enable heap memory zeroing on allocation by default"
+	depends on !KMSAN
 	help
 	  This has the effect of setting "init_on_alloc=1" on the kernel
 	  command line. This can be disabled with "init_on_alloc=0".
@@ -230,6 +233,7 @@ config INIT_ON_ALLOC_DEFAULT_ON
 
 config INIT_ON_FREE_DEFAULT_ON
 	bool "Enable heap memory zeroing on free by default"
+	depends on !KMSAN
 	help
 	  This has the effect of setting "init_on_free=1" on the kernel
 	  command line. This can be disabled with "init_on_free=0".
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-36-glider%40google.com.
