Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSX7QL5QKGQEHDOAPZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id A05FB26A62C
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 15:21:15 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id m9sf468543lfr.11
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 06:21:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600176075; cv=pass;
        d=google.com; s=arc-20160816;
        b=R7ccFpNEe6dOcC2x3rCKkpb8P01TFWFF8kPMuN7+VYPITCzoqIlQCOJ9p/H3y0hbs7
         8XzkqANz8iAxwTtjyGi97akzJ6UGxwMfgnKPjcs2gjFY5WuqnLNPLef90Y5A0C+Z2y5C
         OHTx5k19tdKHC7Im9aHC6hD5L2fzinXCGe0B9kTwsWouPXLeUK7DjyPltkNpbUUZGxFw
         uU1DqQ1XLvCNeOD38odVVCvGiMqtKG7kM2M5Kipa5Zyk+PpHzlsBDLnmSoiNS3afbj90
         jAMM84NK14Xf4BhPleIs+VwDYCjS0YP9V6YNkpiW8IIRnT9TY4MjhHjd9AMhRKHq5OOF
         6q+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=dVP2MNOXne+3FHUAgzQeNKQrp3OTv7Pp9KwK6i3edyo=;
        b=NJkUu6joDICrl5IbC1s+KERF2VJmZZob9yFQVaBiA029sWhyi3kqkwp1MZroniykDg
         dzLiWH4QIoH6sU5PM7oqsDRem+T524aHGpzcnUaSTWQ47ffCsQeeb5+U05cvk/tKRm4a
         JW23py3VpwMwAfrS4F4hkR22Al5HnR6Dq45aGssg2wOVjZ/42DzRjHlJXGVc1OH/GXIX
         EYk+kC2Z2o6faqCvkvCQYlpOsEwlNhL84ZRMOnZU0xE8kt7PfxABpIzKguPpYx9cCqv5
         Rjsml56ygeA4igDZQfPw2KbE9UYpmwoMmw31r6CGfgtjLoydjDAg9Ffb26HhrFofIoay
         dzjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d3vnLLe0;
       spf=pass (google.com: domain of 3yb9gxwukccww3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3yb9gXwUKCcww3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dVP2MNOXne+3FHUAgzQeNKQrp3OTv7Pp9KwK6i3edyo=;
        b=FPiC6funFlMo6uHM1IXh7w5sBLmi4rJrbHom0SdSVd1XRUqy3V+vsDdlyw8BEad+zd
         pB0K4hF+Zkzi7xNcu4hyJCII6yQeozvLCSYKzSb3ymaRAx7MAnE6Mb9sfvJP88OJLUIn
         D/GYSFOJI9kcoWGnbrG6blG4659Ehonpq5logetqeK7FQvZgQpFjDb32pRl/xVeVCqdH
         NG3RI7vMTzLnPdUAYLkey6Ot11biG709YSd0BckddcnJhG02O34lNh4ciE/eVs54/QnD
         +6T5fwOAE5HKjNlauwRZZLtMHeoZLU/XWnUCcQD8cc0MBu4oF38AYb7+vqOntoaKwXn4
         xBFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dVP2MNOXne+3FHUAgzQeNKQrp3OTv7Pp9KwK6i3edyo=;
        b=KyeRq2dOaiTlwNTMzqV4NhXutFkmnONr2/AysWLFyMGcxvNj6x6qJouOScAcGjqnRJ
         WwG/QeEwXIjXJOqplfYPzidX2r7bKL9MJ2INcz8KATD3gSeaBeBMiIjlOVFZLTvKfLWR
         mVri3lqp/9Z7WmLXD9niSR8dsjo2we2QrUZW3DIpOgnitvl7KmWP3mrHE7FkCWMDiXqp
         jURAA2eYc6duwb22FoYPOPyICCUbGfuWyVzYkSDlvxW8meKx4fNRVvHi3ON/k7MHENCT
         gK2pWOtJCL2fwKVqVvdCBNTxCT6sF4om7C/sQ3qs6FHt4qruFiCysx/Qj1ohHW3Dd8vL
         ZGww==
X-Gm-Message-State: AOAM533YGtNppc1DhJygF8/7buSoT2Hzv27WfXqTBo2ghdRNGzM3VhJA
	GvsPGYdEl7xDvyU1AYjeLdg=
X-Google-Smtp-Source: ABdhPJzXkvtOpBsHbkizIDiz2H0RyUHzW2CBxOQ8PEim9wsIzji+DfZ0xj4ungHD4oiXG8N7eTeSwA==
X-Received: by 2002:a05:651c:1397:: with SMTP id k23mr7679149ljb.263.1600176075197;
        Tue, 15 Sep 2020 06:21:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c7c8:: with SMTP id x191ls1192923lff.0.gmail; Tue, 15
 Sep 2020 06:21:14 -0700 (PDT)
X-Received: by 2002:ac2:560f:: with SMTP id v15mr6771405lfd.550.1600176074003;
        Tue, 15 Sep 2020 06:21:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600176074; cv=none;
        d=google.com; s=arc-20160816;
        b=WDwEdxPc2dJ5kfKfIdnZ4txd0Esh7owDKE020j2aOv+3flrLufMaxgB9Mlwz8VLhu+
         3NTWp/jqq+QoHPEpumVKbii/wFQhOaRFrKU7++c9REOhiB+IihBYbwtElJkqWvXKPx09
         +DmUBPFDevE5TJnY+AZgimyY+7H6eaalXP0l87HyWJimwzpYjYd4x9jG30V32NsH7+ii
         M7YJxJppbLkLGcVOTKEmBj45OZo+84CEuqxbeerXFUgkalZIX4zPVxQ7S7W13WuSbBCM
         ZpSK+1fMSJczhTj3aC0w+EbOYAGSNuZ91T3Elribg4zcpcYwhC3WJ3mDgnFYQe2p22vM
         D6EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=PB2wGlTtPDen/ye2PAmCBJ5c7LyFB91+1y/zC60t16Q=;
        b=pZqGD6kLQrRKoJi4BkfMznBvo9aYp5v6Cc5CYdpyyiERyrRFhuTngCD1bjdMi4DiTb
         bhQ2plD15+Rv8SbBq98V+BwIdytvYw2I6QLSFjDvDkf+CMFOQ6AwswxAdVeW2UbwylUX
         EPQ6jS1fH508a+IwVUeWe1bd8BeUk0fi/qktponCdc+dZyOl0Mur7DJVZS95pZKK4o/L
         2cHwA1IMAL9gO0XEqbEzjteou+wjvrBgav6Q5hy8iEqIkBgApWCWHTuE1sSge3LHCB20
         EfkCR1sH9otG5cD8MV8BvSOQKRkb+TuDjqWTfMAWK7QYzsTlRppQMv7KbvWcJkoDDhw5
         SLUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d3vnLLe0;
       spf=pass (google.com: domain of 3yb9gxwukccww3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3yb9gXwUKCcww3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id q20si337236lji.2.2020.09.15.06.21.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 06:21:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yb9gxwukccww3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id qn7so1272972ejb.15
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 06:21:13 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a17:907:264c:: with SMTP id
 ar12mr20711635ejc.80.1600176073238; Tue, 15 Sep 2020 06:21:13 -0700 (PDT)
Date: Tue, 15 Sep 2020 15:20:42 +0200
In-Reply-To: <20200915132046.3332537-1-elver@google.com>
Message-Id: <20200915132046.3332537-7-elver@google.com>
Mime-Version: 1.0
References: <20200915132046.3332537-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 06/10] kfence, kasan: make KFENCE compatible with KASAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com, 
	Jonathan.Cameron@huawei.com, corbet@lwn.net, iamjoonsoo.kim@lge.com, 
	keescook@chromium.org, mark.rutland@arm.com, penberg@kernel.org, 
	peterz@infradead.org, cai@lca.pw, tglx@linutronix.de, vbabka@suse.cz, 
	will@kernel.org, x86@kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=d3vnLLe0;       spf=pass
 (google.com: domain of 3yb9gxwukccww3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3yb9gXwUKCcww3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
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

From: Alexander Potapenko <glider@google.com>

We make KFENCE compatible with KASAN for testing KFENCE itself. In
particular, KASAN helps to catch any potential corruptions to KFENCE
state, or other corruptions that may be a result of freepointer
corruptions in the main allocators.

To indicate that the combination of the two is generally discouraged,
CONFIG_EXPERT=y should be set. It also gives us the nice property that
KFENCE will be build-tested by allyesconfig builds.

Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 lib/Kconfig.kfence | 2 +-
 mm/kasan/common.c  | 7 +++++++
 2 files changed, 8 insertions(+), 1 deletion(-)

diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index 6a90fef41832..872bcbdd8cc4 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -10,7 +10,7 @@ config HAVE_ARCH_KFENCE_STATIC_POOL
 
 menuconfig KFENCE
 	bool "KFENCE: low-overhead sampling-based memory safety error detector"
-	depends on HAVE_ARCH_KFENCE && !KASAN && (SLAB || SLUB)
+	depends on HAVE_ARCH_KFENCE && (!KASAN || EXPERT) && (SLAB || SLUB)
 	depends on JUMP_LABEL # To ensure performance, require jump labels
 	select STACKTRACE
 	help
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 950fd372a07e..f5c49f0fdeff 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -18,6 +18,7 @@
 #include <linux/init.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
+#include <linux/kfence.h>
 #include <linux/kmemleak.h>
 #include <linux/linkage.h>
 #include <linux/memblock.h>
@@ -396,6 +397,9 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	tagged_object = object;
 	object = reset_tag(object);
 
+	if (is_kfence_address(object))
+		return false;
+
 	if (unlikely(nearest_obj(cache, virt_to_head_page(object), object) !=
 	    object)) {
 		kasan_report_invalid_free(tagged_object, ip);
@@ -444,6 +448,9 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	if (unlikely(object == NULL))
 		return NULL;
 
+	if (is_kfence_address(object))
+		return (void *)object;
+
 	redzone_start = round_up((unsigned long)(object + size),
 				KASAN_SHADOW_SCALE_SIZE);
 	redzone_end = round_up((unsigned long)object + cache->object_size,
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200915132046.3332537-7-elver%40google.com.
