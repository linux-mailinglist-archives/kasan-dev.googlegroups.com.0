Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHGUUL5QKGQE4ZNFVUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id AD874272563
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 15:26:53 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id z40sf12826727ybi.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 06:26:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600694812; cv=pass;
        d=google.com; s=arc-20160816;
        b=F5nrB2942zX1FOLqOEvlYDCysxgmkw/oD27BefSEx73veEhUpqk4x3d7qEFiPxKQu4
         Nw1PpHkkz2kdpJfu7VhqdMQrT35qIRRGwmYltAT95Bi0N1ai1vcEyacAFxVG7/Xe2RPu
         IQXpeHLanS+W0rwUXYPgSR+L4eyRcMExqkFbj2qmHhEapPOHIMXA6FhwwDZaxvLPtg5x
         Zrle8FCImTy0monI26sWputs+VPdzz7RNDRySVd8dtpMVl36RiNhLjT5jigZZDLJcmZa
         haVPemTLM0ArJPvrCxwoYcERAgIoraWZS1EeHmzxFuyJrzgGAoQUfb4iRqu62nETt32s
         hnSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=PzcNOdQ/uGcU+oGtQ9KbUkbMQBgslqZFAEjo4tuM9Hg=;
        b=nyhOhCN91AUnUawhdt+jysTVFsyog+fuRwMnTiwxqbea4GQBRVlPonXU0oJHi1nWaY
         Vpcao6ESWjQWiM6OMs0jVMn9TGZJ4Sw3AJ4x0SGgvKXEQRe7nDFZgCrYxwHc6kkdHiJo
         3T3rNzaGwAcNjmP94PnoBib9/TReL5Q+WSlYnju+3pYDUyhPvYgh+IPNavJf4R4+cEGm
         0SbYA8ZgCXOgPwj0SCpQcg5kKO60OxVOpDk74nKzpiCcLSpgBN7weuQjlVpOhALe0gIq
         srNxlge5eK5mZt+E9bwQ4TgA8VdPs1tt0ssY1l9xEozv0MArrnEWEM5oUY9Lo01Lv7l8
         cFtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=h0DABlib;
       spf=pass (google.com: domain of 3g6poxwukcrqy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3G6poXwUKCRQy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PzcNOdQ/uGcU+oGtQ9KbUkbMQBgslqZFAEjo4tuM9Hg=;
        b=dNYkaK6U2JTfbpmneB4cg0zWdxhGFlh8vKxkc1He6p3WzDg7Amr2tc9xV2bwW2fhhr
         9iTH7Tb2/Wr1LL03XzuRwqlgVjCYlrYaCjHg0YjiczMz+7ocodKFEh4E5rnes1cJIwj2
         61uFlE8NO4xC+jbSAiLkCQCH4ipAj2PHotPiKvkSalRfDeDkB2AmN81uu+FaxNvWb8Pv
         Wcnqj9shILmnVFo7fYoSj87WWc50Ppnc7hXy4JdeGshdwfa8SdmGLmspKVJlXJQakPDg
         fVzAZHT5TpsGYSVU8vKSrt2OBvf18pkp/gsCJuGNUARXx/zDh1Y0rMyofG3l4jVOP70v
         22mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PzcNOdQ/uGcU+oGtQ9KbUkbMQBgslqZFAEjo4tuM9Hg=;
        b=OnbQ0LFaTubjSwW87nXOlZOJr5xd5fwAcBHnfXEaazKo+Gs7kTSI1ul8BwB7T93H1K
         91u79jisZmbs3zjb3ZRv49Xw80Y3ShzibLOkBEpH6yDjwTNSOgLZnc6Ai21LPBx5iHAj
         upiLJSjB70lGXOmJVqqbFe1h4Mmcq8NUP9GjmKphio8XhUpc/AWjwz5Okt76Z7AGEZp4
         lX/cv2kRLXmkNHngmAZ8XcyFk/bKFCbT0LUHe4EoQrhrWirdFCycb/qVc8kTGNN46f+p
         U+onhWLldpsSsmp8eFCdiaqm0TfXV3KPkpVTiDv7zw81g54KCcVIrLnjRTPb/mQBhrm/
         f2UA==
X-Gm-Message-State: AOAM531BoSuDdCODXqJXrmg6tbd4JVJ9fh4Oc7+coqsVa/aHxEB6AXpN
	c6uGpV1PN8s386ZNKBE2DtA=
X-Google-Smtp-Source: ABdhPJxbHTyEP8f300hmJn612n+AhRmreuP2voeyuQjWkKM0jyGCyd2YtWzjviuNGEqsYNvAvBWePA==
X-Received: by 2002:a25:6994:: with SMTP id e142mr31107898ybc.470.1600694812746;
        Mon, 21 Sep 2020 06:26:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:511:: with SMTP id x17ls3610304ybs.11.gmail; Mon,
 21 Sep 2020 06:26:52 -0700 (PDT)
X-Received: by 2002:a25:8546:: with SMTP id f6mr20094579ybn.476.1600694812247;
        Mon, 21 Sep 2020 06:26:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600694812; cv=none;
        d=google.com; s=arc-20160816;
        b=Guul1lnoiGXlUvjV2D5AmTMn4mP563Sg3nJnnQwun6mGv0mm6OMx31+4ZvarMp6Y9U
         Gk+NQqX+bnBAx+APbY8Fj8ubvRl7kbCxkqsp6Q3UgqF6QJQvZzP9R15POaoMK6JsTfN/
         kpVPRxcCwz82KCsTqaay0PzjsPZwolcGdBfImvYJB4DtOF7AHlhvXxTZFmC5kPNWogoo
         ZjpPc6kxK7vuMBL7T/WIu1PYpyA76DkvnIH41EdUnmZf0J8ROKh8x8txL0erkBIosaPt
         qsdKGXp6mVO1p9AGPvUXrHS9JPD+IJk0FYlzHyiidAzqrcMpFZt5OMkUK6EUJdxkQbfT
         rgSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=k1T9dYB7DJoZ+u+nVe3kaxMkFtqFlEoHZfLN0p/pvEE=;
        b=i9Y9sW7pAvCVoCwM3a4+876Ao3G1IRxRWRjhyBp1uhJeOrv/b2RxoG7v25xZwHnDth
         dIotIObITJ6u15lsFGkmt6O9y5CBEBsIv2hXsq3OWLXBt5D4EXSnCKudKOBcPhfRHg27
         MelMm2XpTXlTl3OOWVclbAkp2cU8/sf62SPZTURT/C3uHdmlZzll3qKOzntrCJTONxgu
         C5qLn7nekjqAUfS4iNHZ9BgZ5xj4LfhDznplMyMZvpxFv3MceosW7zgQtFj8GQjJCchf
         JU6UDeWqJEHH9/w68oz+k1/dQw6CTKbZtd3neKrAFWlkJ0GFprIDf78NrLEAOdcy2osy
         QvNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=h0DABlib;
       spf=pass (google.com: domain of 3g6poxwukcrqy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3G6poXwUKCRQy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id s69si622898ybc.4.2020.09.21.06.26.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Sep 2020 06:26:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3g6poxwukcrqy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id e6so12858616qtg.13
        for <kasan-dev@googlegroups.com>; Mon, 21 Sep 2020 06:26:52 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:ad4:4af4:: with SMTP id cp20mr30110353qvb.40.1600694811561;
 Mon, 21 Sep 2020 06:26:51 -0700 (PDT)
Date: Mon, 21 Sep 2020 15:26:07 +0200
In-Reply-To: <20200921132611.1700350-1-elver@google.com>
Message-Id: <20200921132611.1700350-7-elver@google.com>
Mime-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 06/10] kfence, kasan: make KFENCE compatible with KASAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, keescook@chromium.org, mark.rutland@arm.com, 
	penberg@kernel.org, peterz@infradead.org, sjpark@amazon.com, 
	tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=h0DABlib;       spf=pass
 (google.com: domain of 3g6poxwukcrqy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3G6poXwUKCRQy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
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

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 lib/Kconfig.kfence | 2 +-
 mm/kasan/common.c  | 7 +++++++
 2 files changed, 8 insertions(+), 1 deletion(-)

diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index 4c2ea1c722de..6825c1c07a10 100644
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
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200921132611.1700350-7-elver%40google.com.
