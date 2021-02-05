Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQON6WAAMGQECFKBQ7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AD7D310D44
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:39:46 +0100 (CET)
Received: by mail-ej1-x639.google.com with SMTP id w16sf6938219ejk.7
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:39:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612539586; cv=pass;
        d=google.com; s=arc-20160816;
        b=qn1Dip/k50fM+recg2ocubYGCpLGuuebTPaFFoB8VeXvM/RFJmkS5aanS1ajAi3TK9
         q3Z8PLqs8k8dv6KO32L5RVgHiW8aqP2TCQptw83CrZ3rFTvb33akAUYCU657t+m0shst
         z/OlDvel7peu1Bzf8zTdEyhqk4DEsZ7yZVhEj2k1GFxuOqpAOId5fwaPe95s2aNveKhd
         rOhwnh39YpU4h82bCSFPfTEbSv1FAp5IElKtMwaZAINU1Vy5ziy9jD8EuZXf+moclcbp
         byA2zkoSlZjR8Fm0eMjeKBHgindgfL4/G1wVsT68hK+Q5XO4kmWGVR8cEY+jOKObgRKW
         jdQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=8hbdxSAfMdemv0SpsYxceOwb1oynbsH3bbZDYCF7xvU=;
        b=j9NqgsxVR49QY8BKxnIZOZ473re2vj0/GhWjuLQpttyBrcbY6itMot89KpABBJ8hhH
         afRkltajyBmM4yjDfL+jd7JNPcTeBCyohF7D823k6JQmMu7TKkg3yIYczM5jjj1HiitV
         PwZNYSEwtCwEz6mrRQNKcYVCCDYUAM0uVc7eZK8b9JNd3P9eBtnCaFH6oIUg3DUZZQMX
         vmkaz5djRmiHUQKqGuQrH7BWv9rWPamLxogmZ+99ygdhQx0W2BdWPORDFFmoduWpzdBN
         XCLaa8v0UfiF0aYpoY0RPJmBJdGPu+XnzMnP4XPbmIxvGjlFN/aDVsS3ixlWkVpez1Iu
         JK2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GinXCbIK;
       spf=pass (google.com: domain of 3wgydyaokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3wGYdYAoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8hbdxSAfMdemv0SpsYxceOwb1oynbsH3bbZDYCF7xvU=;
        b=cOExIYi/VUGXwxNGaFXlAuQmiFmq2X+nh1FfUTpv8x+wBseDbE5ABGyBg6nAq5o4Jn
         iKaLF4+whlmXvpdk1ruEoaP+3PnlN4tGpP2gFOViXPPbrSuU5U0ZfYW5ac0TciZBb8X6
         SJcw9feGc9iHVMvwPY4luSWmFmj0jrSgmC3LKVHezdinbAT+IEBXkTHAul5/vjemFd6c
         Ray9bPDUihwMbGb9oYvNfwMkTYZSi3UHzptImSB50fDPc/2aBGRt9ZYI3h4ArLTT0YAI
         DA04yxL0bPYJ23lmHVL/atFF7V91iYi6RdGBi4tuFEbj0Bphz+YThtg+yHMWXp1dHITG
         XC5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8hbdxSAfMdemv0SpsYxceOwb1oynbsH3bbZDYCF7xvU=;
        b=k2qSsno8kHgbqiGGY3hZXup1IRXbsXNYgcf/G3XJM3yWdoWf3LhriLHBYCVXYYZHzv
         sWSOpnKqDNT7f0uSRdbAvM87Y+4YqFw/93nrmMddY2Hs/vbiwdYpPnxORVhjPHk8Ep28
         bwl6EE2MCfqj63NroBRFpDvhAgFz8hmnQjH0b8iC/LOwEkH/mzQG/JCnsiBj5fNrqjqU
         ALDBBwJf2wIu2O9Dhq2STFZgRJbdC214Tqa0FjdzOp1uPDksp6yXa06gKkmJ3xsQv5eb
         l1zMpMVu4tRwb58EZAvOqAaC/XWPNeFEixAFYuHy91K13VTS0It0cR60Q6gppz9KonCf
         34aA==
X-Gm-Message-State: AOAM531sjgFkK2Azq2FSZ3GZWapijYdTWADv9cdyaDxienhzdfi3RIuy
	R5Z4QEkHO9lJQglY74F+Xjk=
X-Google-Smtp-Source: ABdhPJzFZAmuf/iQ4Pvc9C/e7t33LXdn55qeky3MOtDxM4QlcKdWlkOGsV6XlbV3aKgqK1aY3X6+ng==
X-Received: by 2002:a17:906:9401:: with SMTP id q1mr4664703ejx.516.1612539586085;
        Fri, 05 Feb 2021 07:39:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:edce:: with SMTP id sb14ls4781840ejb.0.gmail; Fri,
 05 Feb 2021 07:39:45 -0800 (PST)
X-Received: by 2002:a17:907:3f13:: with SMTP id hq19mr4631919ejc.142.1612539585252;
        Fri, 05 Feb 2021 07:39:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612539585; cv=none;
        d=google.com; s=arc-20160816;
        b=dGjMtoZo0qTVcqsIi4K68ZAaw5yVrlktU1Kr0BcQzmbn1lFJGvEYEkxkbNcB5tRjhY
         7yfp0Hrp5E9ZdPMtqLnVdArIQUHtTyGiOM4mGAKxcodAYUcWFXHMtjT0TNebDnpaez/E
         YNRnDgM2tlycDVD4Vt85/J94d/bW0tiV7tA356cBubQL+UkqryJE4VmDtHqsnfrFQcb/
         wzFS70n3R9ouhfyBDPKrXyEdChoYKQhC/nTReZJ8DdufollZbiOuGqBgCctrGAHhF2JG
         3afBk1HaIi6EYCoU+8+fP8Bh7eOolEA0cg9l/FJ4OYqKtKrfHT8FVc4+rJGqcGF4uSDQ
         iIWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=r9X5DpdR9qKQzOGqj5YPMHvNzUxwchyNv1XRoONrpMQ=;
        b=n/MRYrhJ681AfzKAUL16HqcYHKvPugNwbDDrQ6j01Ui1/vBmFppYjVghimRU4Ahwh0
         UeM9NseBLKnUCPH/cCHn/3px7bpDLFi2Gk8bGxAewrfgebLnIscjqEceQ1JwOZnNfx5f
         ZS3nTxWvz3BcH/WVClS9uqGG5Ikd/AIhpOeiaM02og8Hq0hz2Vqr29M+paM3EcW65Z+g
         ymhkOhWx3zKk/dqD2kL175WV9QokZpKgZJvtYPcdGv1No/XzcXvguSCxFzitLIuMuP59
         wCRKXUNsFLRKyt3pHP06mxPtpICpSWPdPxAO65xyRvanrRHhDC9FY5zROZgmH52hmng8
         9Jxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GinXCbIK;
       spf=pass (google.com: domain of 3wgydyaokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3wGYdYAoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id ce26si539568edb.2.2021.02.05.07.39.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 07:39:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wgydyaokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id y9so3938903wmi.8
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 07:39:45 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a1c:730a:: with SMTP id
 d10mr4025957wmb.53.1612539584906; Fri, 05 Feb 2021 07:39:44 -0800 (PST)
Date: Fri,  5 Feb 2021 16:39:12 +0100
In-Reply-To: <cover.1612538932.git.andreyknvl@google.com>
Message-Id: <182acaae3ed39231e6c3132c6bc7fc6b08ef003f.1612538932.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612538932.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v2 11/12] kasan: inline HW_TAGS helper functions
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GinXCbIK;       spf=pass
 (google.com: domain of 3wgydyaokcqslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3wGYdYAoKCQslyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
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

Mark all static functions in common.c and kasan.h that are used for
hardware tag-based KASAN as inline to avoid unnecessary function calls.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 13 +++++++------
 1 file changed, 7 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 7ffb1e6de2ef..7b53291dafa1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -279,7 +279,8 @@ void __kasan_poison_object_data(struct kmem_cache *cache, void *object)
  *    based on objects indexes, so that objects that are next to each other
  *    get different tags.
  */
-static u8 assign_tag(struct kmem_cache *cache, const void *object, bool init)
+static inline u8 assign_tag(struct kmem_cache *cache,
+					const void *object, bool init)
 {
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
 		return 0xff;
@@ -321,8 +322,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
-			      unsigned long ip, bool quarantine)
+static inline bool ____kasan_slab_free(struct kmem_cache *cache,
+				void *object, unsigned long ip, bool quarantine)
 {
 	u8 tag;
 	void *tagged_object;
@@ -366,7 +367,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 	return ____kasan_slab_free(cache, object, ip, true);
 }
 
-static bool ____kasan_kfree_large(void *ptr, unsigned long ip)
+static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
 {
 	if (ptr != page_address(virt_to_head_page(ptr))) {
 		kasan_report_invalid_free(ptr, ip);
@@ -461,8 +462,8 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 	return tagged_object;
 }
 
-static void *____kasan_kmalloc(struct kmem_cache *cache, const void *object,
-					size_t size, gfp_t flags)
+static inline void *____kasan_kmalloc(struct kmem_cache *cache,
+				const void *object, size_t size, gfp_t flags)
 {
 	unsigned long redzone_start;
 	unsigned long redzone_end;
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/182acaae3ed39231e6c3132c6bc7fc6b08ef003f.1612538932.git.andreyknvl%40google.com.
