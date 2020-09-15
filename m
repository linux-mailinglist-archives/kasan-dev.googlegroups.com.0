Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4G6QT5QKGQE5LR7GOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1747B26AF69
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 23:17:37 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id f18sf1699353wrv.19
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 14:17:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600204656; cv=pass;
        d=google.com; s=arc-20160816;
        b=tdonXkLfO9ACraUv25mAYdUP/wb04KWAvvRCY48WUP4von35ImMTdhY8UNGy/0NdlX
         5aAENLTepbtTwXIwEKI6gR0mD6HWfnA3d44MHV9uWEcp1kQtPvaFBRUve3WzBnD3vdJe
         8z+SdXvqsA0Q1dUI0FEYSBh5c5vf7HAZpLX8ZWK36wPY9QoC/F9sF9nin1m88uF6uDAc
         x4WAgcHEOxJNuIOz21F72ZsKCoeVQoBPBSqLglOFCzMtoFRmC2ZkcqF1lZHcBDc9L3PI
         TofR1XzDzEQlOWoY6OEDCPzP7aXiDf10TlUSIldEyztpRvJH5SHEkgg9ziA4JGW8nxUx
         HM3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ZnSsNizGwfTkgj4d4OYz3wD61DA5ZE9qfw+xYbQXPhE=;
        b=Z2dfs//5cGIFnxd/tX5GU9i+qEzJG0llqzS736tyi7MJg5jlyaHntSWMaLLmQmuvub
         /o1q+ud7FeicqhUHNpMjWjUhCgWrJSksjE+1RwKKIBWyWmDKLJwlx7HV2V4LY30ZUSHq
         u9LwY0GXAq4hPbFPVDdCeLqj1IsOIoBXcPe2lxuasiJImjkwJwzVSHMoNaPbCU38kFfW
         +41HaU+FNHnDXgdhqgo2uZ5CzM3CIrE0spSDRUPKrpVlL2zFa7fLWFGhl0jioooazNEI
         ttBi+g+y+i/P30P88qfsqkkflB0tWrFsbK39iQYi5RXqKyht/mCyWLs9QbdDPpC1v/Rp
         yYog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=et5na2Sr;
       spf=pass (google.com: domain of 3by9hxwokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3by9hXwoKCVQw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZnSsNizGwfTkgj4d4OYz3wD61DA5ZE9qfw+xYbQXPhE=;
        b=ULPuIPo19tWCCB4IoA6KtaAaWRReD3/GTLxmV+ACIcEA9o/+n5ZpYGxbwzUvOntO+v
         6LVgNa4Uwr+521OlbGaNnKa56BH1AZmieRpmPLL3vfl1dPfd4ODsKt7VSCzvaS4K/7ix
         rYVn37XvHlJ/QxUtydp51LuFhXuJXMtWMqvsq/TgOoomTKdgWU6zQPIOMdBq5Il+wCjp
         04B3Dy9kIByWRkpcVIBi2sjP9BByQy0qto1Vu0y39fnfdizUlorfuJ6eM3eDhE/AHuMe
         EYPK+D1kWjKWGdK9K08YbRlIE5gaGL5hD4MeGlWkrICXYlK5KVMr2e8l4VhAqeg7+R4M
         AW3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZnSsNizGwfTkgj4d4OYz3wD61DA5ZE9qfw+xYbQXPhE=;
        b=mhYRaQ9cTu0tf20ExxBONyZ60q4xXr62iAOsoE4JMnNY0sbj3ra50bCafLPaTYciYk
         uqS69n9AIrRIH0j212U75wdLETKPrC3V3wXOduRQArBdyFdhbEpLwb524UnurdssFs5f
         63t78HsmR4Ss2vC7SxuY1TBYz2InM2kIsp4di8F6WjsY6v0JSlYU6XPEx0jxkYo4IvdU
         C05i0J1+e8wc1IJUsPbgYEm/F9upBO9s0rstZfzR4qmrA5gg5FSzDzjEWlf047K0iKnZ
         ygclZ7QCesmQIcVTVwTZ4h8PrHh2KnEFkcNU7GQTWhsJgCRcUkDdydDWvUidkUGy+1Nw
         tqew==
X-Gm-Message-State: AOAM530QZfr5u3fQ30oepEkQSFC1IWju4MZHaKG69BW+g0Ib3PWGUvdI
	+0n2IesfKXFO8IOljr1ypr4=
X-Google-Smtp-Source: ABdhPJxKRMnlfNheb2S768L68G25eS3u1NMwGBWSKMQRq9pHzebz1/9MYQ5yFlmE14pd8XwUhbm25Q==
X-Received: by 2002:adf:ab46:: with SMTP id r6mr21008512wrc.360.1600204656856;
        Tue, 15 Sep 2020 14:17:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:c2c1:: with SMTP id s184ls105412wmf.2.canary-gmail; Tue,
 15 Sep 2020 14:17:36 -0700 (PDT)
X-Received: by 2002:a1c:750d:: with SMTP id o13mr1339609wmc.54.1600204656053;
        Tue, 15 Sep 2020 14:17:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600204656; cv=none;
        d=google.com; s=arc-20160816;
        b=tRhVXsFKL9lh2TwwwKJIbVmXnXeEk7aMNPtNh4F77g1IMMaZ12CbOgHgk9qNGhTMgV
         RFS41oXKn68cYKZJg+FWz5IxF9//QD38+dm7D4f4zqsNuTHWGwpBwUIfOtOMO1WM8efA
         RQO6zukpB5vc2YhT47zTxxDfdyAW/LMuLeNYFzDfpuoZyiTR3pq5isd/vU9Q8/qSOeik
         AcwtKh8uu6xU6xkcJh+s+zSpWpLWXsS9YzZv6F8Lyfd29tUw+BJ2IFnYSOVaPwguY7Fo
         yRp65TyB1PZkE01uOo6IwBAcnzyV5V0wkM/0FsmgcubhvrQJBacpKZLsIYvv/86OfeF9
         HtnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=SMbpusk9UPFJ5bty/4o1CBzmR923bOTqJu4p/yHyDoA=;
        b=zMyXqhivZNBSRoRMesKSokP6fe4SQr0zBuu6Yy/EiBEzoAHZyj41WaDxKLQN8Qkblg
         1Koopv8zyry3MORZrVzwwBOwAWUDrxv78h8sLivhzgLpM579bRpccK8eYKbpw2nN34+w
         /m6UxCZrsR3ufEB4c3Y43F+lma+OH6uzWqAOj0wNyAX8yuYaUc3dbBUHS2dO9zIcO+AE
         ClIz6sZzRLTZmSewKRCHFYFAwJD3vDZVwUmvTrdUDX/TuREzipjL+n/MkuI4/keQA5pd
         WVIm+Dg1X4AhGzLiDQO+Wi9WvHXRMUa3KVtlec2ugLsxzHVXPQkXrAs/1S+PJCha33AP
         CUJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=et5na2Sr;
       spf=pass (google.com: domain of 3by9hxwokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3by9hXwoKCVQw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id v5si478618wrs.0.2020.09.15.14.17.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Sep 2020 14:17:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3by9hxwokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id r16so1693249wrm.18
        for <kasan-dev@googlegroups.com>; Tue, 15 Sep 2020 14:17:36 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:5281:: with SMTP id
 c1mr23095217wrv.184.1600204655669; Tue, 15 Sep 2020 14:17:35 -0700 (PDT)
Date: Tue, 15 Sep 2020 23:16:12 +0200
In-Reply-To: <cover.1600204505.git.andreyknvl@google.com>
Message-Id: <3a3002e1d70f8faf2dfc07176c3ece22450b68a3.1600204505.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v2 30/37] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=et5na2Sr;       spf=pass
 (google.com: domain of 3by9hxwokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3by9hXwoKCVQw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN has granules of MTE_GRANULE_SIZE. Define
KASAN_GRANULE_SIZE to MTE_GRANULE_SIZE for CONFIG_KASAN_HW_TAGS.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: I5d1117e6a991cbca00d2cfb4ba66e8ae2d8f513a
---
 mm/kasan/kasan.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8b43fc163ed1..ba63d8a62968 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -5,7 +5,13 @@
 #include <linux/kasan.h>
 #include <linux/stackdepot.h>
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
+#else
+#include <asm/mte-helpers.h>
+#define KASAN_GRANULE_SIZE	(MTE_GRANULE_SIZE)
+#endif
+
 #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
 
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
-- 
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3a3002e1d70f8faf2dfc07176c3ece22450b68a3.1600204505.git.andreyknvl%40google.com.
