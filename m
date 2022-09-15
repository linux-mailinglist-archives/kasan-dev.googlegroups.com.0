Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWP6RSMQMGQE3EAIG4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 543055B9E26
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:06:02 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id o21-20020a056512053500b0049c6aae1c40sf2285779lfc.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:06:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254362; cv=pass;
        d=google.com; s=arc-20160816;
        b=aF1tJRRSOJTilYedcPJ1pBMhW2hO1LXtfQvTPvCvrWSKmXb7rVYAaKcZHbFofB/dpp
         VIN4xsISboycScKzk+xcMbCgaLUFXoNagpJO7TnUSHzBUN2Q9dL7XGBmu3nLV4A/Y4E4
         2XnT9zZ/UBSLgMWFLDtobgdfNI36lNV63C2gUV0kuNQPE015nm4BnfueX3BX7cxKYo8D
         Hb1WXJ4/55HgyYYqywolWHPm6lSF1klvFtheABDXPVAP/z1felS5CARCSz/xSOMSP+ay
         TDVT9Sm7JZgfQLjnOvuKTUjnjlyZk92k24aDWYQYEicz9ZTHV1t5/1b2POSV0c/zSoxs
         XEWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=8TdXTGnoj6Glxt6OhgFd6AT6xVAqFXqZDIgmYQ8Jq3Q=;
        b=HNb12G3cwGZwyTKUC501o8BXGhc6y9yRHACo6E/xszhALJoQGsp+uo93S1PaVNczz2
         92QNohxbIjovS1g+QlIdhouCg1lqSNUv5AnPOaogzgWzaYIovt120XJLR9vtI5CngJrK
         CQAbnPX+Yc1iLrdImFFhJR1PUWgDTfcrw6X1kGDqyro4lLpTVwm0A0Fa24fOzU9kXoy1
         AGqBRdKs/06k0coHlPmZGO5W6xouHAiSRUWAT2MZnaeIWN0PKnKNk8av6RagPgMxNlqp
         v40TUomXb9wd9aFGq0M+YVkdyYnYJ+uGbCPglR5BWhDeQ4blsveLr4OQXGNSjFsE/mzU
         Do4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kplPwV+L;
       spf=pass (google.com: domain of 3vz8jywykcyimrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Vz8jYwYKCYImrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=8TdXTGnoj6Glxt6OhgFd6AT6xVAqFXqZDIgmYQ8Jq3Q=;
        b=KRBDHxRwC8mOOhKc7IHe67r1pfDYcQQInnZ0jY8Bb8SURa9xKpQArR1O6q/t4OYD70
         4q/j7QLlcB9jsj0rHTL4tA17jxU3d2nvEMbPhoV7HKRZGPUspuLtMgelCpnUjGE5dSx3
         6o2ycb2+7mxHIx6XRlg3Itw6pAn5ds2EqxkbQUtsprwRlfR5p0XNea2ISrfHWbRemkbc
         mUSV7VRwNEFJH0ijYeNVlkHcNSRonuo6FXXpcUBI4HmE/BQvW1sI/PrIa6YNKY+mIL9E
         7Wl7M/j6VWmhkhIkjC1BvPhJxSRVirmwkqFQUYLBQLh9+2xKQ6YwE3k/SjvD9CuYpiOm
         UfBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=8TdXTGnoj6Glxt6OhgFd6AT6xVAqFXqZDIgmYQ8Jq3Q=;
        b=T3thVAjeBJ/tZgBDhZbXa/8a+8vjDdzf2q/rwcu9AQxuGHfFsuPBRlUCDX2S75fR0H
         7gE4HwL//Q0YEDDJ9YSxmfuIZXpbo/beeY6LJTx3j4af7bCygbvOvCljCg2hdJjietcz
         uyxU0bk5eX8W8y/Klv9redIdjQYZXByuckVnBtQXGgKxVKy2yd79hk9aqtmR8SChCzon
         IlbQIM4BiXGwd/4iy4FPZhHlssU/Erf8uyleMxYBfZU/HqLlIeJcRANqpx6cGnR2J6em
         DxyJ+hLVG0E6KEwc0JuG3yFqRRC7UGS2R/qP/03OgC202jEMHFCRitkbOXdNjyAOMNF0
         RDgg==
X-Gm-Message-State: ACrzQf3z5o17XOMEUTx4jFLer1bJUmE7BJlv3B4OTej4d5SSd/2BEtHx
	iPoDEG1zRVvFuUeWnqw3Imo=
X-Google-Smtp-Source: AMsMyM5O6gCx91xYGlAhGXXRc48LLdsHX25ZawODai3lJObdoOfnOe5/yFSIeNnHUtprnx8BQVK8AQ==
X-Received: by 2002:a2e:8344:0:b0:263:8194:9a83 with SMTP id l4-20020a2e8344000000b0026381949a83mr63140ljh.368.1663254361294;
        Thu, 15 Sep 2022 08:06:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5e24:0:b0:49a:b814:856d with SMTP id o4-20020ac25e24000000b0049ab814856dls1229002lfg.1.-pod-prod-gmail;
 Thu, 15 Sep 2022 08:06:00 -0700 (PDT)
X-Received: by 2002:a05:6512:b1c:b0:492:8835:1e4c with SMTP id w28-20020a0565120b1c00b0049288351e4cmr112092lfu.442.1663254360270;
        Thu, 15 Sep 2022 08:06:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254360; cv=none;
        d=google.com; s=arc-20160816;
        b=rbVV9Kr/ess2G305d1N/Zt/nc0Pkw2xNM4BPQTWfEli8Sphx1sDL+SQEpLDMbMhptN
         rATzt0us0DXlQHNibPxAuIOlQgrjAEhlxnGiwL5Km8ofOBbc2IpZCleCLmx7EEw0kJ5b
         oZo1cbyGMm1eKQymkYsk7suHzdB7+cJm6Yl9y5TzxvDBvV9OQWNzygR3xXVZl2ZLo9Cc
         7MGpJALRn+i9ng58t3o0MmYpGnQ+NMNeBIuR8twQaANSuy91PZB37N7/sahowW81Jalc
         1JRHhM5Rg61QmqiQMc5DLkB3PkFQIXRwQVPn6AkSYoqISKggN8jEwABZYuFiZlUKo3vd
         bV2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=gorYk6QZYQqsbqX3c5FquLgSIgOkVhkBb0FBAlBlnNE=;
        b=NbSQIuMeKSgmpx1PlAHhJvNr976x1uTObrcccR0h3buYxeICVY8aHP7aG4NQ9QjvNc
         ++tSw0kGTCxAxnWs+dB8CEEF8yeu3sv3LK6AFxex3eiN+WDHqmBkICpoi15SyZaRZWre
         JtzjuQJstVlMoWiaYvmjpuIyjzjXsMmvZAQyIgouw1EEbuC6qgut2yOQX0S/7Pl2PCvv
         acIHoiAaxiJ8Z2CQnRy2MCf6TduAKI+BfOHgmSItdH8x1+qmdLOIQ856YI/TVzsUud71
         tojVHkGoQcQAqi77TsQFDJbp6yzscyTkIaoYgsYeWacxvRx1nDQhmWCPh2pOxsDxVHNS
         KNbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kplPwV+L;
       spf=pass (google.com: domain of 3vz8jywykcyimrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Vz8jYwYKCYImrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id p22-20020a2eba16000000b00261e5b01fe0si489163lja.6.2022.09.15.08.06.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:06:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vz8jywykcyimrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id xc12-20020a170907074c00b007416699ea14so7704195ejb.19
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:06:00 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a05:6402:2201:b0:44f:443e:2a78 with SMTP id
 cq1-20020a056402220100b0044f443e2a78mr293434edb.76.1663254359888; Thu, 15 Sep
 2022 08:05:59 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:04:04 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-31-glider@google.com>
Subject: [PATCH v7 30/43] security: kmsan: fix interoperability with auto-initialization
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kplPwV+L;       spf=pass
 (google.com: domain of 3vz8jywykcyimrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Vz8jYwYKCYImrojkxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--glider.bounces.google.com;
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
index b28093e3bb42a..e5eed276ee41d 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -936,6 +936,10 @@ void init_mem_debugging_and_hardening(void)
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
index bd2aabb2c60f9..2739a6776454e 100644
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-31-glider%40google.com.
