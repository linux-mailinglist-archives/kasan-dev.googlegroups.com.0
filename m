Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRMNXT6QKGQEFLUPXHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id A72BC2B2849
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:20:53 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id o28sf1228991lfi.19
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306053; cv=pass;
        d=google.com; s=arc-20160816;
        b=A7H+aEgcJq/cEnyOW76wvKei8y7tN1N2O7SNXDmJj55gjvKEy/yedtTPssEZRgf/77
         DSc6YgC3A/Akxq5btU17vQIpXVa4HQLMVSj9OxNfPSvZsFm9glGsrsIZwm2bBucpkU4l
         dsaCmvVIoAg5jGH84UXQ8iTE19qd7O49hJGjukXtDpRM/Ek6d66v4BwgIR7u5ZNCPhmU
         v5wvegjmW/qvSiZsG9YInqnDLYoGOrQ37GHCAJGBLMw5t8/AYVhQOmGbNmB2KhxJjOUT
         TGC/ZYxniNgqnRU45nT6uX6/HOH9cfIe1CLXQQGAUQGGK80EatFc5JdR+QFPxDvuXWWB
         KUOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=yKhxBuBLd7bJa6w0bAkreuG2pNpBTpIiyVAOiD3x/dU=;
        b=XzvG92VlL1tV3IUXp57rtoS7lG6ax6D0G0TZcG4Ahet89EqaIO1Lct0goTxavr/yhT
         YbzGe3aahnzyQ5JlhaSNhT3Spdgc6y9WCZ3WWRHJ0mx2u2rbqtNWYFxTRVLHg4lrdOlP
         bX1vUVXh5TyOAqp2oATfh4KB3g84pJz3jBBDcjMLCSRzP/uGfjeuLdX5xiMHRiJKFVeF
         gkw7utB/0BK0uZNlIpCq8eStJBUJZNIroBgf3ObX1EwbXIw4ELSl7QuD4wUBNlxLhYI8
         Elv3NDCN7qRZ8whg7CfPlnpf73ycAnJp3SrDokdbrG9a0gZd4KRgtXfU0sfrtRyG885F
         g+OQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gVybcLoF;
       spf=pass (google.com: domain of 3wwavxwokczau7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3wwavXwoKCZAu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yKhxBuBLd7bJa6w0bAkreuG2pNpBTpIiyVAOiD3x/dU=;
        b=QoSKt21yD8DWbcNZmgMNZp0l7KqLllRQpySELfqMNUJJxe0KDf7rkGZoCD1tuytAHj
         LsECrnRYh4pQZNXkFedOCSMu01QkKeWJGezCr6oeVzcMcJRryscuX5IXhyKef2zykyxI
         vuIdWBLiFlTND579I0/GVODSMFFJxWAkn/hVbddSBpBKIka0GOe928uMmZ8MylUQgYe5
         tmTKjPATsect3Pq+lP6oReH/+A+f48w2IMc4iYzuWaUsfk55AfOiIJJrdWn05BLGBwbo
         UdtGDXrRZh3zaUZRuP763/fdfOjlj/wRIhHNkxQBXtyVcA1aqDgTs9eZdxMllG3W43Zl
         +3uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yKhxBuBLd7bJa6w0bAkreuG2pNpBTpIiyVAOiD3x/dU=;
        b=WCDMGr/AnUb3U03TYJmF+Ym3KqvXmSZ5+I9iXseFN42ZVp7KskuukEHawmm0R60OCP
         47PnBNSILP2MIdP5g1YMv6B4geTclqpaE9dxAeswjcrI6GrrBn/LOYT5/gTKXjzk921f
         xZ669GIr+kpiRMGcf5z7ZYRGoALY1UpZ1iBHGhWuH66WH1LNvbEn0IVv3/G9C/WBPkLB
         7KnU+EkOKkgwUBZFLx30w5qEqSECxEX5WmCCiMXkrPLWnH4Fy5qsETUjd7f7PXdos7gL
         LgZr2MYivFPZ7U5HTB8RN82D1WZFtALUJPVsFwfJg36AW+VTUfp2rIDt8CI7CMzyOz9F
         wM8Q==
X-Gm-Message-State: AOAM533+AIbNB9phWE+pyKXCgaqbyMe+CFrOIga8QxCzb4pm/NLVZ2IK
	pYYGO4eNLMbtjrlYkY7CWSc=
X-Google-Smtp-Source: ABdhPJzQ9UqDPQPjjwDrePuhHxCWBowco3q9x3KXQ4CjyS1ZMIQd79zUt6gVvQnk517FijMbntDvNg==
X-Received: by 2002:a2e:b54b:: with SMTP id a11mr1987360ljn.40.1605306053272;
        Fri, 13 Nov 2020 14:20:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9908:: with SMTP id v8ls1496591lji.1.gmail; Fri, 13 Nov
 2020 14:20:52 -0800 (PST)
X-Received: by 2002:a2e:7607:: with SMTP id r7mr1868414ljc.156.1605306052318;
        Fri, 13 Nov 2020 14:20:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306052; cv=none;
        d=google.com; s=arc-20160816;
        b=kHGWddjnmkFDT9Hg01rumgIBgRBCCWgQujo/eDMiWIlkRBLHcUYF14QVMXy29ZlGDU
         gncOfX1CDGgJmDlOymO8fklIe+FoHls/nf1QoEHrkrekOB2vHJIG8rARVBVl2KHp2pK7
         I4zHXs7O8/WxtFnGlLJ1Xz6YF4d82rDRciA1xOHf3DtldIo85dqz7PK5aMIugxIiD93u
         uexFzAVwRV9zZRqLJFB8+WObVdZWKQ80q2EUf3/77lfriX7BxiDrssLjMi2Z+wJAiDqt
         Bep4IdJXM5BEImcnLrinx0qOtDJOHQU9oepeN3fcTFgfRAXQe8gm4zy30UljoFHkBm3Y
         O2FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=FjDCd3uZs5tZgyebUG073A1B5l2RXwE8lidjbcRsCvs=;
        b=MrjmiMs7xxu5A6PpfX435+b9rx1wxO3nuEXF54bj00BoSCKbjYixJvRNP7TvaeGAMI
         hHdaSOlBRGsQMeP2rIg38zyCdmdnDrQvmGlgbKFXZ6DW3mmi0juq6Nu8RIV41icveelc
         EiGUM6oY68mQuhFJTh6S+noY+HOlBcZoC440/G4ryIf2w2rsFz5RNVw6/mKjsjCbBhMO
         4eybB7tdldsOxDZX7L9/hG0yLaFyFupW6/xiLYbpR/eYEZIeuzePJUBcs3ZHpKIYyl0H
         NK+yYqzrmP7XkSbnlbBkzHlDQe3kPyQWsM7d1jma1Yh6IPSD8fOSQ+JJPqAnRZ00v9/I
         qJ+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gVybcLoF;
       spf=pass (google.com: domain of 3wwavxwokczau7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3wwavXwoKCZAu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id o185si337315lfa.12.2020.11.13.14.20.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wwavxwokczau7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 3so4708537wms.9
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:52 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:e74d:: with SMTP id
 c13mr6274338wrn.277.1605306051483; Fri, 13 Nov 2020 14:20:51 -0800 (PST)
Date: Fri, 13 Nov 2020 23:20:05 +0100
In-Reply-To: <cover.1605305978.git.andreyknvl@google.com>
Message-Id: <ec3e1c18c41e0bb8428f21440a1962c322cfe1af.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 15/19] kasan: simplify assign_tag and set_tag calls
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gVybcLoF;       spf=pass
 (google.com: domain of 3wwavxwokczau7xbyi47f508805y.w864ucu7-xyf08805y0b8e9c.w86@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3wwavXwoKCZAu7xByI47F508805y.w864uCu7-xyF08805y0B8E9C.w86@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

set_tag() already ignores the tag for the generic mode, so just call it
as is. Add a check for the generic mode to assign_tag(), and simplify its
call in ____kasan_kmalloc().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/I18905ca78fb4a3d60e1a34a4ca00247272480438
---
 mm/kasan/common.c | 13 +++++++------
 1 file changed, 7 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 1a88e4005181..821678a58ac6 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -234,6 +234,9 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
 static u8 assign_tag(struct kmem_cache *cache, const void *object,
 			bool init, bool keep_tag)
 {
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		return 0xff;
+
 	/*
 	 * 1. When an object is kmalloc()'ed, two hooks are called:
 	 *    kasan_slab_alloc() and kasan_kmalloc(). We assign the
@@ -276,8 +279,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 		__memset(alloc_meta, 0, sizeof(*alloc_meta));
 	}
 
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
-		object = set_tag(object, assign_tag(cache, object, true, false));
+	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
+	object = set_tag(object, assign_tag(cache, object, true, false));
 
 	return (void *)object;
 }
@@ -364,7 +367,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 {
 	unsigned long redzone_start;
 	unsigned long redzone_end;
-	u8 tag = 0xff;
+	u8 tag;
 
 	if (gfpflags_allow_blocking(flags))
 		quarantine_reduce();
@@ -379,9 +382,7 @@ static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
 				KASAN_GRANULE_SIZE);
 	redzone_end = round_up((unsigned long)object + cache->object_size,
 				KASAN_GRANULE_SIZE);
-
-	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
-		tag = assign_tag(cache, object, false, keep_tag);
+	tag = assign_tag(cache, object, false, keep_tag);
 
 	/* Tag is ignored in set_tag without CONFIG_KASAN_SW/HW_TAGS */
 	unpoison_range(set_tag(object, tag), size);
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ec3e1c18c41e0bb8428f21440a1962c322cfe1af.1605305978.git.andreyknvl%40google.com.
