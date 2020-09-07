Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBPR3D5AKGQEWTQIDUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 6638325FB91
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Sep 2020 15:41:26 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id b1sf2136996eje.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Sep 2020 06:41:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599486086; cv=pass;
        d=google.com; s=arc-20160816;
        b=REPtAnZ8GvID7BemTF5Blt1r+oB5+Ex3eiYndExo3oHGUO/5T0TSBZBAR6HLOPhf+A
         Qmq6y8zX19eLmRsQueAVHUhyf7GwG5OadrWnt73qPXFhDVi8Lqrl7RHoSVVANwWZI33X
         m8Xq2J6vExBeMc/XplGuLNcsuQZjCyLA9JV+LiKMHy6ZVtpzb2E9f23zC9o3KZlkKnEq
         t/YMTMLgkCYblG2hfOGel/JUqBLIU++4BQeMnhpKM3xbZyJBV8C1YxTLUwV9/Gpwkroc
         vVarg05sYBPC2r4TvlB+7bIcRufYrv24qhETmuM6LieLULpTJSae15O2QU72FUo9cVDo
         eoBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=TMYdPVujyLUCCLynLucxvtzvfLGlammU4+qdjN1bDmo=;
        b=lnBqcQdWosQ2i6aPnZMclY4CT6G711aLYCdwx6DR+Rke4xc06PMwvvvtKwAeBogCSK
         AWKqq80wbMhtloTwB0MMDrhN1EsXmyEAgT0X0Hpi2XIiR9JuGaxPnacjH76GxQmMOSCN
         2DHLnYkpFLUk7QLTcZ75hpHQ1lmfTIT281LIzdh+Zi4jnWFUZt/EDkSUfwZnv7fLFYYN
         lncSI5/3QvhZLkVoRySv+UMQVAQlx/clsWP+JetuYV+GMfvNPvp1Aa7f80TUhzxj3iAh
         G4VqfDIEwItIORguLflvbnRUtTf59kWSmKBa6apgbkJd0ZtRAQK1oROnOclJjt6WdF6Z
         SEgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="W3a/pmyA";
       spf=pass (google.com: domain of 3gzhwxwukcu4u1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3gzhWXwUKCU4u1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TMYdPVujyLUCCLynLucxvtzvfLGlammU4+qdjN1bDmo=;
        b=NZhTMth77XFY+0P09g08U4FsJZq+h6bDFRKZVIstzE6qfdKgssj9DDoaIfW1atOVqE
         LaZJNrJRBwzMJ96a4OqfzfNCcYfHkNHohZmDn2JWobEdgNnAWaNo9hAtk/rPekHCTG2t
         REty5gUMP28O7qI+wlw6mXexia/5xr5AwrTj+HfhAiooQm96JB3z5JFkGbbu9v5+52LD
         5/CWAZwuV5PgUIIjKLfcWVLT8Xp4XpkJA0mW0+amEjbnQLYKSMlqi4mpiZ7p63sbwp3+
         gN5UZgtAI/pioxtjkGzCKNZDuFT9SP8P/iVjp9/z2Pz0wOA4pyIvW5JfzeFp+QsCJv+q
         ECNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TMYdPVujyLUCCLynLucxvtzvfLGlammU4+qdjN1bDmo=;
        b=gU9nYD+eGGcBs10MKSY+jncOLb5NDiJgAYbvAc5Bp4SpvgyoUpDtT4WMHyq9sz1BKH
         47obfaICFOwURcYrej8fCfJUTzl42oIDCj69rDQsTStAo/rFnvVCqdJB6J+T9DbliwRk
         yQA1Qdtqej5JGpPYguUnX/3LPwES7tzM7MOcyzH3IFMsLAHCDewHUSmRTDCEKW8nox8u
         xtId/aCLaTZpA/eLA/XJ7euLJ/ajcSUHm891ZQ38mUijFlWbdKzPdysRSskmkDQ/PKrH
         w9bkDXGbqWdkN1hNynBiTWb3pfsO15+tElGnKmJ1lq6kFQQhfxs4ElAAZQyzB0bcDg2B
         zrfA==
X-Gm-Message-State: AOAM530WUYIPntsI3O+1wHlF9RrbzRkWHEuVW8koJfamB/Zs8q/kja9a
	jdTdgqGHbLvaA9bkycx/iK4=
X-Google-Smtp-Source: ABdhPJx28sYs9zmlGfQ1FXvifafcGHTXKklpcRxEfS2XMAv11kqCQx7upnZPjBPFS99CeCJvPEA0UA==
X-Received: by 2002:a17:906:3955:: with SMTP id g21mr21618335eje.69.1599486086099;
        Mon, 07 Sep 2020 06:41:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:387:: with SMTP id ss7ls5616067ejb.5.gmail; Mon, 07
 Sep 2020 06:41:25 -0700 (PDT)
X-Received: by 2002:a17:906:33ca:: with SMTP id w10mr22374669eja.438.1599486085075;
        Mon, 07 Sep 2020 06:41:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599486085; cv=none;
        d=google.com; s=arc-20160816;
        b=kMEt613wxbCuQJFi5d920Typrb88a+qDmpu/bXxUO0IsSDC95uRyHj3PUC1BS3mKOJ
         C2dYYe2Ckwqom+6DqW9+/uAKyhXMX9IakfEQqw/wryufuB7WZvRt7TzjSpQL7QQvfqf9
         oh6Y3LS1qsrmQlv+ePoJJ6APADQkQ0FUgTswO5bSWQ7dMSwVxJJp8NQwX8HTWUmgoItc
         Taxk2RKZsQHFrnYablfFA9OYWvrTQKD7ZX8HT6FJSlpkBZdFM27TW63xU83MID65LRDv
         +LjLQBQ6rjs6fjOyfS3YBUFY7HU315ZUNmOf1aJco2MZ54sHci9MdM934n340HZs4BtJ
         T8xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=sBEgph2pOr6CyODJ1uv8I0m4yR8SDTujVHr8yLlCuyo=;
        b=T7LCL8boLi/oMeB5PNPVmY6k2nL0reZvfpUVAxWpJEFLMs6G/I5ZsvGXR3Nib1Cerz
         AIxFb4qCBZVwnDVOtDVCnOO791qx1fYC05s9lYDSLnO/U1doB4d0fwSufBTuhFsXdn7b
         sBscES0z07z1V3fcsOhcX+nUr6IZJSEFZBCDckzoh1uFheFQtdsLS9ZUBO6HTl0ea84u
         lklOC3ZAPyX1xvLenB4Esh64eFyjxXt7Nx5mOzk1LZb3hGlz8B+QjtfaVXtM7v9C2FWd
         iwflOAfUM2JuNihGv3O0+HzsbZ8xZm4FTyp8l3makFM6oCbfT8npKViZKZdUcZz37SlZ
         PazQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="W3a/pmyA";
       spf=pass (google.com: domain of 3gzhwxwukcu4u1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3gzhWXwUKCU4u1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id k6si442373eds.3.2020.09.07.06.41.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Sep 2020 06:41:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gzhwxwukcu4u1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id w7so2154941wrp.2
        for <kasan-dev@googlegroups.com>; Mon, 07 Sep 2020 06:41:25 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a7b:c019:: with SMTP id c25mr9339wmb.0.1599486083942;
 Mon, 07 Sep 2020 06:41:23 -0700 (PDT)
Date: Mon,  7 Sep 2020 15:40:51 +0200
In-Reply-To: <20200907134055.2878499-1-elver@google.com>
Message-Id: <20200907134055.2878499-7-elver@google.com>
Mime-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.526.ge36021eeef-goog
Subject: [PATCH RFC 06/10] kfence, kasan: make KFENCE compatible with KASAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, glider@google.com, akpm@linux-foundation.org, 
	catalin.marinas@arm.com, cl@linux.com, rientjes@google.com, 
	iamjoonsoo.kim@lge.com, mark.rutland@arm.com, penberg@kernel.org
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	dave.hansen@linux.intel.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com, 
	corbet@lwn.net, keescook@chromium.org, peterz@infradead.org, cai@lca.pw, 
	tglx@linutronix.de, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="W3a/pmyA";       spf=pass
 (google.com: domain of 3gzhwxwukcu4u1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3gzhWXwUKCU4u1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
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
index 7ac91162edb0..b080e49e15d4 100644
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
2.28.0.526.ge36021eeef-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200907134055.2878499-7-elver%40google.com.
