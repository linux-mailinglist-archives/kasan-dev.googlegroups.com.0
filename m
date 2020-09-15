Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTP7QL5QKGQECE6K3IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 07F6A26A62D
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 15:21:18 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id s11sf1068439ljh.8
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 06:21:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600176077; cv=pass;
        d=google.com; s=arc-20160816;
        b=LI7vgKMZ6zMGbz+TeWrHAO+9SVVWRvBAFczgwIJnG1aiFiXVurRqP++PjRK2xNh6IE
         LaeN63rlh444haUbPT/BGHlHgDxkDD8OntvTYGwCRX/rKhgLhsuqr/pJriuzu5mP0p4F
         sHiwgwou7lyC91o/kiHog6goS5v9PYDOOVCyHb2CaktIhFTBInDTTNgMr3GW0vWNL6Gh
         zbtgqQtETVZyEafWXdAa+DHO4mOw7bhN2NdyE8lmUZnXQaheVweXfUfrbI1Y8HyaWcs/
         pMPgkY4aaY1Zev+u+rWZ3kxYneJGQP6yvek2d70m++aJWklexf543NnvXjJRZuvHqMfu
         bGVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=d25M9kBKF1vKwsKGxkHOIhAHYke3fTVVWFk1Ir060go=;
        b=CQoR2Zr9+mUGaP3h6xnoYn6+GnRL4rXwg2FKY0DD87LsckaO1X3G7SfwDcA6wwF/YI
         j7T7Far0Nvc2jF1Sjnyw90XJGpimi+JbPEKeGufXj4lKG4RHV+uAFi540adKKtftYMhc
         MpPa7puOR+j32UsJMHEMYpJzufePDa69wdUd73WVqE0zz5hg0/FkLBSrDkcZeEX1ZfGi
         vwh17NZAeufW2okFTrL4mNoHEtvMLiWaOVjqYgKhCXm+L8FbpF/Yf2qbIXB0xVfUoDEI
         GyxnIfUorpzmHwgWXLENloWhywRWVIuAzh2zphR7PCRD1MLAy4DGe5oK9XWz5o8Uk3k1
         2odg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oYmwUA55;
       spf=pass (google.com: domain of 3y79gxwukcc4y5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3y79gXwUKCc4y5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=d25M9kBKF1vKwsKGxkHOIhAHYke3fTVVWFk1Ir060go=;
        b=pgeND38+dCznIs7fqre5AOplaCH70JncdS7U71g7fZ/1vkm+jZ1pYzuo7xVbolFiuZ
         FV0jrbxJ0vwM3/N/GEcPMoQxWq4wBH3whQZCZ8sR36I1Kk05NLRhQE0Xtd5+SJcIEpqB
         n8O3Ei5UaAd1zHy3tmo99ICJbQ4euVl9re8W/qbiqZtn3k95F6p3iy+cvQTghARPA7xW
         IpzXmr+bFlKa4i+TKc6LoLzdVMhMbB4kl45sIhDgk/QEdlsvxOVENd5YOWm5DNt8Ma4s
         IT2eoa5xQmnTz7zc5P7NPflobqurB929nrm17fR06lEv8becp/4j4H0ig4HehcIiEnxW
         2a3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d25M9kBKF1vKwsKGxkHOIhAHYke3fTVVWFk1Ir060go=;
        b=SxFmgEPQdp5+Y+5orwQf2vdBNZ3PjJbW2L3sAMF5UXBsJFcM7tEeyhLZQArnH40/lX
         KEfOZrtfovUFFuVVUtutjAn8NpKOx8gdKHcH/h0Z4jBlCs+7tA/1LmfhavOqxvKBvHIF
         aFCslgatTKJtTfcR6xQKCf9HRT34DCvrnS3g1/5jfF/G8SD/XrB5XYv8hXK/KfDKrbUy
         Nh4RsPfsKoSuGNdBAfQsaNAomPx9k+4hgw2S44i6Gj69PsNjujp5Zkz74afpQjYYHxkW
         7g3JgfzeFreNvTKxUYbs0w7aNM/jKN80IOCY90c942B6+jF8vkMELMV331RBwyJFwtXI
         i3Ng==
X-Gm-Message-State: AOAM533DPUgfT4Bois8mmMwD5qCdwm8T6sPCgfAzSlnUgGn0EdCTm2T3
	4QxTubLJeVnTf8rF9Tll/l8=
X-Google-Smtp-Source: ABdhPJwyPE1kaQ532UVNVCtPFIEgB43ZLLCVASqGoG+9JFzXVBt7exAcFUUQZKfXQPbRXjWsNIBISw==
X-Received: by 2002:a19:457:: with SMTP id 84mr6059955lfe.205.1600176077582;
        Tue, 15 Sep 2020 06:21:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3c13:: with SMTP id j19ls1946067lja.10.gmail; Tue, 15
 Sep 2020 06:21:16 -0700 (PDT)
X-Received: by 2002:a2e:7819:: with SMTP id t25mr6488516ljc.371.1600176076368;
        Tue, 15 Sep 2020 06:21:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600176076; cv=none;
        d=google.com; s=arc-20160816;
        b=pXnLd+i0TsMgOzrSkUI93r84uDeR41/emm2A0leBAX3aIw5TdXLsP2tCAxwXBk49Ra
         KQm6t14aNe1bxqVQwaREXu3HsmVo3m89BNnJaVB6WLTcDs50R3ppqNrtu8EWO7WFt5M9
         h0gDTLoU4QJPwSnnSX7nYUBInspWdprSJLRGsJYBooOD9BH+ClByfiOGU7IRw7vGV5cp
         +6ceAdbYxkF8P14q+zV0sDKaEVC69CsFRqnH2AV4gh9H/oLosm9WF5n2ykpTEG/Q795x
         Q5V2ix//EwvVpLpkI6S+ihcD+z0lR3eTWCR8GTORPc2mXo5ZfotXY07J0AUa5gvCqpBM
         6h+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=A4TgnPIs4KlOFwMVz2jZ7oTmV4CFA6JHdIybpn/o/fA=;
        b=EYTrGTIkunf/QFbVzVpM1Ujonz1Pri1N6sIjGkQ7wXka/e66a8xRqtu/y0suNJNB2i
         4f0v4EovKrGFs82lbkUw+2zYpcEXFvFr5VUVbsO00uFaW3cAP63+6+cmbtaBVhKmspio
         u0CfpTv0ZyU1JwDiv3sAKUB9QkeoMmJ8UhQm8Y573mac5jRc+1d1L75WrelDVgHWaLCX
         NgvJSnlsAogHPIut9AEf58EtPiK+86Fbdwcgj/i5RtzOFXTGj67efZUKvOWFjRs3GfZx
         iCuy/aHw2krlFMdVysSSolswoi4trP670h/pdjD7nZm6wcwXJKFBeJnn2W0oS4rHoNbv
         Y3sg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oYmwUA55;
       spf=pass (google.com: domain of 3y79gxwukcc4y5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3y79gXwUKCc4y5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id l82si283848lfd.13.2020.09.15.06.21.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 06:21:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3y79gxwukcc4y5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id s19so1169587wme.2
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 06:21:16 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a1c:80cd:: with SMTP id b196mr4760527wmd.104.1600176075555;
 Tue, 15 Sep 2020 06:21:15 -0700 (PDT)
Date: Tue, 15 Sep 2020 15:20:43 +0200
In-Reply-To: <20200915132046.3332537-1-elver@google.com>
Message-Id: <20200915132046.3332537-8-elver@google.com>
Mime-Version: 1.0
References: <20200915132046.3332537-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 07/10] kfence, kmemleak: make KFENCE compatible with KMEMLEAK
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
 header.i=@google.com header.s=20161025 header.b=oYmwUA55;       spf=pass
 (google.com: domain of 3y79gxwukcc4y5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3y79gXwUKCc4y5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
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

Add compatibility with KMEMLEAK, by making KMEMLEAK aware of the KFENCE
memory pool. This allows building debug kernels with both enabled, which
also helped in debugging KFENCE.

Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
* Rework using delete_object_part() [suggested by Catalin Marinas].
---
 mm/kmemleak.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kmemleak.c b/mm/kmemleak.c
index 5e252d91eb14..feff16068e8e 100644
--- a/mm/kmemleak.c
+++ b/mm/kmemleak.c
@@ -97,6 +97,7 @@
 #include <linux/atomic.h>
 
 #include <linux/kasan.h>
+#include <linux/kfence.h>
 #include <linux/kmemleak.h>
 #include <linux/memory_hotplug.h>
 
@@ -1948,6 +1949,11 @@ void __init kmemleak_init(void)
 		      KMEMLEAK_GREY, GFP_ATOMIC);
 	create_object((unsigned long)__bss_start, __bss_stop - __bss_start,
 		      KMEMLEAK_GREY, GFP_ATOMIC);
+#if defined(CONFIG_KFENCE) && defined(CONFIG_HAVE_ARCH_KFENCE_STATIC_POOL)
+	/* KFENCE objects are located in .bss, which may confuse kmemleak. Skip them. */
+	delete_object_part((unsigned long)__kfence_pool, KFENCE_POOL_SIZE);
+#endif
+
 	/* only register .data..ro_after_init if not within .data */
 	if (&__start_ro_after_init < &_sdata || &__end_ro_after_init > &_edata)
 		create_object((unsigned long)__start_ro_after_init,
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200915132046.3332537-8-elver%40google.com.
