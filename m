Return-Path: <kasan-dev+bncBDX4HWEMTEBRBP6GTX6AKGQEWVRGBSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 24B9828E7F6
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 22:44:49 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id d145sf137698oig.23
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 13:44:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602708288; cv=pass;
        d=google.com; s=arc-20160816;
        b=mYPJoVNfssv8UQFEPRspG5CSwAd0Sj0c50mqDn+t0Xf4m9DqfxXfuIaygGc0L1S6qO
         zFRlZsBJEyQ0Ald8T+c/FIfZpuGcRy27mq/M27TsNqN8Af7P2rEcXeurN3fcw6zpK0l3
         8CHb74Z/WPOntv/caTffDlx45TqtZuu0N4izpDhqhB/uh8M1Tg7t7VG6qlTM7oAKMsVF
         c4/ftIzSv9Sm76gh1gV3YiLaCniorKKYSi8nWcT58GLt7WISmvheyIOprM7OauDZnQrM
         Tt2Ae28ITzOtaW9qDvVYjRZ5HsNhIoFnE2Qs0CJyfqbg/0c/DJJ7b9wT4dvRmLNnUZK2
         Jtpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=eRM5VUbOoLgxFx952bv7iMo19f5DhV47sYb3qwUUQxs=;
        b=dSNLn+BTwPIXCvUtHM4TepJtPr2JjF9UhbrbCel4FlU67l1aoR6UsnnawUko19jmx0
         GV6NP/vvRg2GN9sa2BongThCRbC80sd302T3UoJi+zNPkYBVrYxqs51EkJf5YOW6gj24
         oUOLisLWi/QbhZBQO+G6n5rzmyowOZ73TpGdDVZTuMDNub21IrX03bwIlO3SCl5eF45y
         T6R0fzidoI127ReiGriznqNltsVzjxVgkcZeFGGXzIAC2R9FunSLEM2rkfuc7u8M/xaA
         AFhsqpSJksCERC/7FHhUM+qTmoXHsqhsKKCWi40AcLNA4Ofstz5ERm0vkXT63803bVW6
         pjZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EBGrD6RN;
       spf=pass (google.com: domain of 3pmohxwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3PmOHXwoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eRM5VUbOoLgxFx952bv7iMo19f5DhV47sYb3qwUUQxs=;
        b=avLY9mBv1ve13CLILaIeh0UGUUeZauOQhjK3vebjQPx07CM/RHsiRVT5Nal22ooIcF
         2ayDXxTi6JitmTUyGVbJuRG8hstBH1KyjYMNtcvO8lluEdr08X3M21e3n5nbJERVMPEf
         BEJ/dLu4koL7MIBHzbQ0pLNLFzyBXHCQJZoNqos/L7DjlbLf3uTq8rLsOlvmO2Mtod4Q
         mDHllq845MG98wjM/gdOPN8fulEkCuK8VQiKZHeBch5I4ieWXdyA7KkS2rAPCgwRRYfk
         gmb2Ez3bK760qAr59GXNItKT9honXb3sZwx4NxUPsY+44qwjcFRjf77m13xR03I2uQ55
         KDbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eRM5VUbOoLgxFx952bv7iMo19f5DhV47sYb3qwUUQxs=;
        b=qjUFr0D4J0eCAHM9UBM/iREyaLnBU2u5ct42fsTtArq7nvS5sRx6MZ0lEzCrrTRBGu
         ZiLoftqn66JNgmpSGMR3dtP6SC1vRP0dW+AXj5vBNNOZEbtGcDbdD0ABGOBpmLAYIozT
         ZZWteq53o2mrHFazTchQ2mb1TFKaLwzCOy+N/ypFf0OOYbmZuSz9UvFiYpansqmtd2WR
         uy5QT71xH0T2ebCJmu3FZCnR2BlyMnIFCfsiWE1r9i4IIEFoTZEySFLGeyaogxXsT6Ab
         WpeCvZKxS9enY9giepkbdZBQirPoKt9uAlnsCrDDwdht5Sq1Xw+AR0KgJ+42eCxCl0YK
         HdHA==
X-Gm-Message-State: AOAM530DYChH/DyGHwOWLTxe6sHic/yENFqipWBfaXuUWFB1FnIk1n+D
	rWwddAHz1PppQ+pAKr08/2w=
X-Google-Smtp-Source: ABdhPJw0GAD/ZLiuZSZit9yIQgpRss4TMj+ttO6qbo9DBFPoJI6LzW6C29QutPjyj0wV4m+FfHqFxQ==
X-Received: by 2002:a4a:d622:: with SMTP id n2mr459328oon.23.1602708288005;
        Wed, 14 Oct 2020 13:44:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4bc1:: with SMTP id y184ls71742oia.8.gmail; Wed, 14 Oct
 2020 13:44:47 -0700 (PDT)
X-Received: by 2002:aca:edd2:: with SMTP id l201mr10651oih.20.1602708287260;
        Wed, 14 Oct 2020 13:44:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602708287; cv=none;
        d=google.com; s=arc-20160816;
        b=mP7/lKtVBr8LwNFwEr9KTho7swlD0d3eA8G9jswTlEKLATwdOegRd1cKdWXkPiDyi2
         nypo7VHQ9k44suwDMlCepp7oAYGKlFdrfSyjNhWH0VG+1HwPvq5gYtKDpUQqcJ6Rf5GC
         xFkex1XVaTUwsRGbberdZ4KEnuGQPXW4B9DfOL80YsyYjisEtb6gCzaIdFS1jfuJjL3u
         +mT6nxr3yoG0Wof1DFKy1ebKEnIR0GBt+jYTo2DvZ75pzSyawHlvdWiAlvwbNmZJG/G1
         BtcwrhKNviZTKUm+crhuQ11OTfo1n1DLfYvmh0pyJP8eK/jmTUZxOI/W/qz5zf7olOIT
         NuwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=CjGwVkjALHWoxnEpXUV5lg0pURyX1Lwjm/IxKYecvEk=;
        b=mNpi/MNcGRMIMsM8QVMLWBMYbCYmUzcwh6GKMuaoeHnT0roOXADKjS1qdVqaUaEOUD
         xtXp5Lf91IZPrQyNHzXw2nAj676PoAwNmJ43CQ1lVyVeH96p66Bs3DbXB9YTgF+n1V16
         yd7H3ufmXtowppdcrjRve3qD8pz5sbGdUccRAyyaMkXHOb8gmeOKynj605hnZ25/S/dS
         I04H6xf4syEQHjm/pqT5kQHLMoS1NsCICK0bqKR1tNG6u9udqz2dIk77C0TrkOTBs1cU
         uc+qtNjLbScxF8qtMAOL3I4I49w+X/Q1QFOM8Tgv6avZHqLrlEl5LKNHB2z3mkJv2zAs
         NbtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EBGrD6RN;
       spf=pass (google.com: domain of 3pmohxwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3PmOHXwoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id p17si42380oot.0.2020.10.14.13.44.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 13:44:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pmohxwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id e19so507723qtq.17
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 13:44:47 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5547:: with SMTP id
 v7mr1394100qvy.9.1602708286682; Wed, 14 Oct 2020 13:44:46 -0700 (PDT)
Date: Wed, 14 Oct 2020 22:44:29 +0200
In-Reply-To: <cover.1602708025.git.andreyknvl@google.com>
Message-Id: <42f809a3f36e9ca5b62e6a5b13c90e664d6e2933.1602708025.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH RFC 1/8] kasan: simplify quarantine_put call
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EBGrD6RN;       spf=pass
 (google.com: domain of 3pmohxwokcsuboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3PmOHXwoKCSUBOESFZLOWMHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--andreyknvl.bounces.google.com;
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

Move get_free_info() call into quarantine_put() to simplify the call site.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Iab0f04e7ebf8d83247024b7190c67c3c34c7940f
---
 mm/kasan/common.c     | 2 +-
 mm/kasan/kasan.h      | 5 ++---
 mm/kasan/quarantine.c | 3 ++-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 2bb0ef6da6bd..5712c66c11c1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -308,7 +308,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 
 	kasan_set_free_info(cache, object, tag);
 
-	quarantine_put(get_free_info(cache, object), cache);
+	quarantine_put(cache, object);
 
 	return IS_ENABLED(CONFIG_KASAN_GENERIC);
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 32ddb18541e3..a3bf60ceb5e1 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -214,12 +214,11 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
-void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
+void quarantine_put(struct kmem_cache *cache, void *object);
 void quarantine_reduce(void);
 void quarantine_remove_cache(struct kmem_cache *cache);
 #else
-static inline void quarantine_put(struct kasan_free_meta *info,
-				struct kmem_cache *cache) { }
+static inline void quarantine_put(struct kmem_cache *cache, void *object) { }
 static inline void quarantine_reduce(void) { }
 static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
 #endif
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index 580ff5610fc1..a0792f0d6d0f 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -161,11 +161,12 @@ static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)
 	qlist_init(q);
 }
 
-void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
+void quarantine_put(struct kmem_cache *cache, void *object)
 {
 	unsigned long flags;
 	struct qlist_head *q;
 	struct qlist_head temp = QLIST_INIT;
+	struct kasan_free_meta *info = get_free_info(cache, object);
 
 	/*
 	 * Note: irq must be disabled until after we move the batch to the
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/42f809a3f36e9ca5b62e6a5b13c90e664d6e2933.1602708025.git.andreyknvl%40google.com.
