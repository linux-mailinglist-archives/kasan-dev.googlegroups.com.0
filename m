Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJMOROBAMGQEPZNBCEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 551E632F70B
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Mar 2021 01:04:54 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id p15sf1742124wre.13
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 16:04:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614989094; cv=pass;
        d=google.com; s=arc-20160816;
        b=GVHZHKptDxkfpC53Z+wYwh9tTyYe/NazksVthTy8IFMNF40p1xmqZ1iizUgyp/pXJ3
         qc/ifIaJutMLpnkP4vf1DhOOLOhHPCS0+xxMQOS3Z5wyHlNy7k4GRgAqnuf2ESrMfZTS
         9l7zJzirLSf6iHKd4OH7/T0gOOdVUfFd74OH2LpzdDm+6EOQxRl08q5D3o0cx1eUu5HT
         afbGdDjSPVVojUv7rq7XBOGaHnoYUeKBLfuDgdnknpZTMEEiVn7ytAFGwngDir5HwpBJ
         64HpufHkuEeuJsn6T1ssaVNDZwANkDukQVwL7sQLRtES5HF8HDEN27s21ZCXlyZrp91q
         12zA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=0fjO3uAt27rED3AgP12kr7RFzXQH3PhqqfVra/jN1wI=;
        b=WggTMzHfMATkObXNMfh+vPwTQdIJ9tzaaSYgCoTz7KwJ3jzRXwodUn2yYWNy2/P5oT
         mAjsk3Bl7gcA2JGOnKcyd46ADuVf+/rjsqMFEW+2+trCC+ENXfOS/vtQWqhAIuopjQHi
         hwcgeANKk5yJQ/TFk8plIqX1NTePCQwgDA8wVq5qHrkmPgi0KbAoIRxBvCQrEbJUEcEn
         N63tqRhanD8hSuUr5vK0a2cdk6oRVUf6uitSf63HsPP7/HBjDgqXQP56E3APad+GLop6
         XrZ3bxwqEkU2StspFPl6N6X6FhPZdelieZjSMSz7pfdHIjZJDS4Wg5BMTKsxXV1JAvHh
         mSMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=syUBlHO1;
       spf=pass (google.com: domain of 3jmdcyaokcculyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3JMdCYAoKCcUlyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0fjO3uAt27rED3AgP12kr7RFzXQH3PhqqfVra/jN1wI=;
        b=qSV897jZ4Y9Yy4g5Wib3ooEcurD1KiYyagqJAQHIZR2wEwKigkg6YYYFs0TV9ab02x
         IaUxjGirMLuLApJIoKTJnLyamN/JdMQd6L2FeYebhnpc0kmokNJdsn264dbzMOZqApZ0
         mfhPl1/15nuqL3beBiNCKeDx0rp6+VK43Wcf0Rl3GLvsC3SBBAeX7mHqJF/Jlopo2Sqj
         w5Km/O3JY0FrG0E+kFjpwUkaTVs7zMnai0ei4W+zeNe1b3IuayaA9Kg7xeMhMR4ZL/o5
         F4e/tlFUJuC8EGXe0WlpZMu4LwJtNPitRN1KxQlh20tDo8+V3Hthw4AkfKvlnRyKRY7Y
         xyQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0fjO3uAt27rED3AgP12kr7RFzXQH3PhqqfVra/jN1wI=;
        b=e52fVz55TMkg5rQ64WeiQaTnK/g9L4jD7ktA3+1FfogMXYgfLPm11a1TvFYjtx7Pex
         59QbuZofvx0lq5SUCerc6ofs1r4p/VUe6+k39F6NhSzP0oOEkZ5LuX/u1XpF4QbeeIrI
         FNG73TxouYb7n1cwDbEW1+vBpQlYazvhUHB9XpKzQVv8z2GqrAEzA0K2W32oPxUfzSA0
         rABz9Rnarq2cJ1g0M+wmfGhUB7mlX+8VuW2hQNdgfvqat7E5KtUjNAPwEBpINW/xWmKj
         WsuWkhtwO85jpbUNhtsikyD1iQtgcOzCky0bNMcJKwUwx3zcpOZxBDiweO5yFCvj8vpH
         36wA==
X-Gm-Message-State: AOAM531mrbDyX5G0g3fjLrifRN507ScNGMQx5QMln6VESz8Tc4k4PT7f
	H0XoAqMD7NexFdD2p3Ttcu0=
X-Google-Smtp-Source: ABdhPJylLsiSjvGTbx52ARtV5n1B3EqS0TGuVIE//9WMx2eNZlxerIJQAi0gYI2SCcspQ7EtxmdrTg==
X-Received: by 2002:a05:600c:4ca9:: with SMTP id g41mr4805701wmp.150.1614989094047;
        Fri, 05 Mar 2021 16:04:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cc94:: with SMTP id p20ls5497895wma.0.gmail; Fri, 05 Mar
 2021 16:04:53 -0800 (PST)
X-Received: by 2002:a05:600c:247:: with SMTP id 7mr11187849wmj.116.1614989093250;
        Fri, 05 Mar 2021 16:04:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614989093; cv=none;
        d=google.com; s=arc-20160816;
        b=lNu9mwVXKlt71RPR/n8T/tP9YPVX+pE4Q6o5xsIZP1UN+ollzo4hoOZVCrQopco0iC
         OErUNiIEWDrFnv5fTWheTf8eothTD4WGlNL3vRruVUUFXPYIKgYa+DzP1Ic7URhwWHkN
         Y0bj8SsMgdDQsqwmNANvsvUe1TDfl/o8+n+61cervH7ec0jFe52B1KfYW2nyFGRiSyHp
         vCR/laH9wLzxPUriSICfGwr8yiq9oeOfq0Mv01QfI374NPwa2bKJgEm/tk7lKR/XZY80
         kn/m6POch1rOrozvko8jDsEFhLnPamEVMs0V6ZAE3C0w88YRiUWELUmx/VJ58FjuxLOG
         lxVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=EHP7VMOyCMZT7G8oJ44o5p67301sGJyRfDw3NYRjics=;
        b=rj4mSVmSpBYmRmFR9I6+zB7hOLi01Sn664MKrPk35pfgbcdyn2gFIe1XHHWUNG1/cZ
         wZy6bs9k6lMtq0hFSWDGMu3hyQsPSrZJ9eXHAz9L3iBUlLYqaCCQYNU4mf0uCNhTVFAw
         sqhUi3SkVTEDaoSbZksyQW7vVhGW6o6ZUZtyYJFgg/sszjqPMzm12pMilw8YWuqZa5c8
         ZW6S7W4q0I1zhLrilcVIm3OEykC/j6Jr67XMXEk+CLUe0fQzaJYSib9+gSSLri7Tg30G
         ImYw+FLN1LT9oTTLrbwHKViLR5JEfdheMzagerWzuyvKX72EwopY0tvMtgSAoWrEDHGu
         qeaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=syUBlHO1;
       spf=pass (google.com: domain of 3jmdcyaokcculyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3JMdCYAoKCcUlyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id g137si619316wmg.4.2021.03.05.16.04.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 16:04:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jmdcyaokcculyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id s192so1476303wme.6
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 16:04:53 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:953b:d7cf:2b01:f178])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:4292:: with SMTP id
 v18mr10970532wmc.23.1614989092621; Fri, 05 Mar 2021 16:04:52 -0800 (PST)
Date: Sat,  6 Mar 2021 01:04:49 +0100
Message-Id: <803741293885a20aa5fddb28172ce0a378b7d793.1614989073.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH v3] kasan, mm: fix crash with HW_TAGS and DEBUG_PAGEALLOC
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=syUBlHO1;       spf=pass
 (google.com: domain of 3jmdcyaokcculyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3JMdCYAoKCcUlyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
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

Currently, kasan_free_nondeferred_pages()->kasan_free_pages() is called
after debug_pagealloc_unmap_pages(). This causes a crash when
debug_pagealloc is enabled, as HW_TAGS KASAN can't set tags on an
unmapped page.

This patch puts kasan_free_nondeferred_pages() before
debug_pagealloc_unmap_pages() and arch_free_page(), which can also make
the page unavailable.

Fixes: 94ab5b61ee16 ("kasan, arm64: enable CONFIG_KASAN_HW_TAGS")
Cc: <stable@vger.kernel.org>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Rebase onto mainline.

---
 mm/page_alloc.c | 8 ++++++--
 1 file changed, 6 insertions(+), 2 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 3e4b29ee2b1e..c89ee1ba7034 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1281,6 +1281,12 @@ static __always_inline bool free_pages_prepare(struct page *page,
 
 	kernel_poison_pages(page, 1 << order);
 
+	/*
+	 * With hardware tag-based KASAN, memory tags must be set before the
+	 * page becomes unavailable via debug_pagealloc or arch_free_page.
+	 */
+	kasan_free_nondeferred_pages(page, order);
+
 	/*
 	 * arch_free_page() can make the page's contents inaccessible.  s390
 	 * does this.  So nothing which can access the page's contents should
@@ -1290,8 +1296,6 @@ static __always_inline bool free_pages_prepare(struct page *page,
 
 	debug_pagealloc_unmap_pages(page, 1 << order);
 
-	kasan_free_nondeferred_pages(page, order);
-
 	return true;
 }
 
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/803741293885a20aa5fddb28172ce0a378b7d793.1614989073.git.andreyknvl%40google.com.
