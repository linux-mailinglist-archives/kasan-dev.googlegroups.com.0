Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWWATOAQMGQE5LHWNJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 8695B31A5CD
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 21:08:58 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id j204sf520811wmj.4
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 12:08:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613160538; cv=pass;
        d=google.com; s=arc-20160816;
        b=tAZB4Cxv/hpZmFyxxpy/N4gjFhbcqPjsldWANFd9N7gR74xQx6wR+BBAhJoNxFWdAO
         uEEg7BKsWh3j03F5idxawJk1icxP09NdrAuiQ5PPlFfK1kMB/T/S49QqLqv8MQl+a2hB
         fGb3Naq97ehRnUyJzLALvwQiONUcOzcysJyW/EMhJ0ZDJj/W3ktKK72m3nf8MAdpfxHP
         GGeffqZ5FzhI5669iAmXHF6EQ/GZblGMn1vfhLBZYE+A/LQi0wzRKc0nBiDfZG3kEGGM
         mgkvZLUJx9LL2F95SbKDJXbD1GzcGTb0x9sieawZ4v3E021kqoLswSnDMaSedZANy5lI
         /3mA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=m9PB528eKm0Ig+KCEkCDvC5dXWuSmHmdVsa0elvDb0I=;
        b=t4JODaaEYJw2zNsZfkVwFpCuykYIQRhcvdQPhEhha1AWv1QfEzuHXYQ1vaFdFZHZ2N
         nABFoktC7vJ2uIFI6AF4A3S6aFUTBT4eJd9mnvdQe3dz+7HUA2twdtEdL759ICDNkC69
         6OqSZPt0DWP1+KmU+bKzc4zllnlCuRHIcpnZgbGlJyvjhUKWGYoMwWlUBK8wjiTpNWpk
         oSkQCuXAJO2cjMi2QB7gOYYSl2rh5SXsunFKI88ABaPyUlIfDZwfUNGC7FUvoMvaXVnw
         KNvgiu0etZcaOPEUxm6NXsnoJfZ5kmdEz7ZyJOjos3oQwDXDdxuF9X2l/vdLzpZibd6g
         cWXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ri92KeJx;
       spf=pass (google.com: domain of 3woamyaokcbsboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3WOAmYAoKCbsboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m9PB528eKm0Ig+KCEkCDvC5dXWuSmHmdVsa0elvDb0I=;
        b=LosQZEbPjEk3aO4X87Sq4+FXCJtIos1RNgd7JisBdUCeXviXXgultSBzpc7bMjiZ21
         LV4+pm0z2bg4D93q6h2YXlJyz4DvqOjQ/5XX+1tfS5syaVuAqqox8LaK3olMTjrzIhMz
         dzTpckwYlrnOXZwGVWiJ4bf3Qt846kIVWNpHjI2OCkuHlAuUQUzL8asFlmOAI9Ivjv3F
         j/BCLw4Da9x/v2yoLxxGVo+Rt7lBj0wJJvhMkQnXZph9q3QWghrXrvoQOlL1KYQMyLF6
         cbqX62/c8xzvKQ7gis51u99F1RQf8nUdgimppycAxaxPAxOOB9t5u44gADiK9zF1KOfo
         zZ+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=m9PB528eKm0Ig+KCEkCDvC5dXWuSmHmdVsa0elvDb0I=;
        b=CCMe5zmsfH9gJzqS6BgIHifYOV6LBhhYtwFbg86W2YNOaJ5ZCA3Vu1pAH45fcvUQs9
         blfFvDWEnSvqeeB0Sgxsv9nhbuJwpYWSFDVj8QQjlRYwVGBO/eze6MEmzS6Mj8X8myXm
         njTzKt0i21Upcdd+xkALkDExKs82UQOhzs+yp/gVeO/wj8mvuTPJ0tq1OSqrJpXiHDX2
         UADqDsaPDhWsi3ayZWPaTEO1aDg1pTcSECth3ACfg2UZXzVVLLXXKbJUSGn5esboWfAD
         RJYbF6dwU9u4Fw6Ypsy+6tPM8yOEW3whE87loq1lWyi0rQUseWTWOhR9FIx9BmDO6YHp
         Muqg==
X-Gm-Message-State: AOAM532/pKAtGUGgHcLzqqMcxHfwUn6uIWGfe6vDDlOD42edtQHmGJMA
	joREo3OkruFfrIX+5t3yaC4=
X-Google-Smtp-Source: ABdhPJzWYeirc5HRB9weMYRsvGBp1Y2l2TnKm/BIjJzZBhPxcfPrG3W3pfYgmkiIC0HzTQpLA/umyg==
X-Received: by 2002:a05:600c:35c7:: with SMTP id r7mr131728wmq.37.1613160538231;
        Fri, 12 Feb 2021 12:08:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e6c7:: with SMTP id y7ls1376450wrm.1.gmail; Fri, 12 Feb
 2021 12:08:57 -0800 (PST)
X-Received: by 2002:adf:f00c:: with SMTP id j12mr5244245wro.160.1613160537485;
        Fri, 12 Feb 2021 12:08:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613160537; cv=none;
        d=google.com; s=arc-20160816;
        b=pqTZRVmSiHg3n358RQOHC2cjohrRMyD3aaM9ihjYTOEzacg2ktISlvrC0OlLK3RWuB
         L3yCLh35zOLMw3CTA2HxHEV+PIz+Pycpf2Y0uHi+W44/zjdzC7Z2MbxPsaOF9Io4zjq2
         LbN31V3FTOzx9hNlMcIGYGkA0dGaH5PX8IY6gxh0kkY4qwST8XUtPIjo5w4pYDGv5UdX
         17KcFgnfWUkMwjO3x9KFNeYBoDRmtlfAdoIntCeNeusK8wx5jngP9dkqoReum1/mkdep
         eNpbPD1Fh/9Uw5+yJ0IXhr8/O44CyNf7EzqoslkXT/xXGvDI/1M1tbICEfgtOYKfZbc+
         R3VQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=Yt8QroauzMxSaO8dfOJkOemr7RXc+gc/JDflCqQTAVk=;
        b=TTK3Lxt/bAMRHSK2b0Racz9D3kCpdp9H84yrZw886OvcOa36N99jBZyJ8WrI1O30zZ
         lhVc4iFMgVx3TW3L0OZCOftHb4WPRb6Juz5hZ327A7TqBPHgv7qnq8L+abpDo0lUh86G
         R+v1aogwPcGFGo4Rm467UEAFVdp3YlqjyATrXz9LEc26QkApBDUSmpmqEqtQoZ2w9U7a
         yTbdlRIHYr4GuURIP+yvgqdGmidpvJXYc74hkIuJzmIPRcBbmfo7DXfY7pesMTgd3VPs
         eM5DopzaYmuvO2/ZGs0VTHcb2vx7w8Z9+c9BaP3oDr41Qa2rR7hH78ZHKMn33HDtxisz
         sYcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ri92KeJx;
       spf=pass (google.com: domain of 3woamyaokcbsboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3WOAmYAoKCbsboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id m3si1020566wme.0.2021.02.12.12.08.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Feb 2021 12:08:57 -0800 (PST)
Received-SPF: pass (google.com: domain of 3woamyaokcbsboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id h20so1049150wrb.12
        for <kasan-dev@googlegroups.com>; Fri, 12 Feb 2021 12:08:57 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:19dd:6137:bedc:2fae])
 (user=andreyknvl job=sendgmr) by 2002:a1c:3546:: with SMTP id
 c67mr2778wma.1.1613160536016; Fri, 12 Feb 2021 12:08:56 -0800 (PST)
Date: Fri, 12 Feb 2021 21:08:52 +0100
Message-Id: <e7eeb252da408b08f0c81b950a55fb852f92000b.1613155970.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.478.g8a0d178c01-goog
Subject: [PATCH mm] kasan: export HW_TAGS symbols for KUnit tests
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ri92KeJx;       spf=pass
 (google.com: domain of 3woamyaokcbsboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3WOAmYAoKCbsboesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
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

Currently, building KASAN-KUnit tests as a module fails with:

ERROR: modpost: "mte_enable_kernel" [lib/test_kasan.ko] undefined!
ERROR: modpost: "mte_set_report_once" [lib/test_kasan.ko] undefined!

This change adds KASAN wrappers for mte_enable_kernel() and
mte_set_report_once() and only defines and exports them when KASAN-KUnit
tests are enabled.

The wrappers aren't defined when tests aren't enabled to avoid misuse.
The mte_() functions aren't exported directly to avoid having low-level
KASAN ifdefs in the arch code.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Add wrappers instead of exporting MTE symbols directly.
- Only define and export wrappers when KASAN-KUnit tests are enabled.

---
 lib/test_kasan.c   |  6 +++---
 mm/kasan/hw_tags.c | 16 ++++++++++++++++
 mm/kasan/kasan.h   | 12 ++++++++++++
 3 files changed, 31 insertions(+), 3 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 1328c468fdb5..e5647d147b35 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -53,13 +53,13 @@ static int kasan_test_init(struct kunit *test)
 	}
 
 	multishot = kasan_save_enable_multi_shot();
-	hw_set_tagging_report_once(false);
+	kasan_set_tagging_report_once(false);
 	return 0;
 }
 
 static void kasan_test_exit(struct kunit *test)
 {
-	hw_set_tagging_report_once(true);
+	kasan_set_tagging_report_once(true);
 	kasan_restore_multi_shot(multishot);
 }
 
@@ -97,7 +97,7 @@ static void kasan_test_exit(struct kunit *test)
 			READ_ONCE(fail_data.report_found));	\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {			\
 		if (READ_ONCE(fail_data.report_found))		\
-			hw_enable_tagging();			\
+			kasan_enable_tagging();			\
 		migrate_enable();				\
 	}							\
 } while (0)
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 1dfe4f62a89e..2aad21fda156 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -185,3 +185,19 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 
 	return &alloc_meta->free_track[0];
 }
+
+#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
+
+void kasan_set_tagging_report_once(bool state)
+{
+	hw_set_tagging_report_once(state);
+}
+EXPORT_SYMBOL_GPL(kasan_set_tagging_report_once);
+
+void kasan_enable_tagging(void)
+{
+	hw_enable_tagging();
+}
+EXPORT_SYMBOL_GPL(kasan_enable_tagging);
+
+#endif
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index cc787ba47e1b..3436c6bf7c0c 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -308,6 +308,18 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
+#if defined(CONFIG_KASAN_HW_TAGS) && IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
+
+void kasan_set_tagging_report_once(bool state);
+void kasan_enable_tagging(void);
+
+#else /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
+
+static inline void kasan_set_tagging_report_once(bool state) { }
+static inline void kasan_enable_tagging(void) { }
+
+#endif /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
+
 #ifdef CONFIG_KASAN_SW_TAGS
 u8 kasan_random_tag(void);
 #elif defined(CONFIG_KASAN_HW_TAGS)
-- 
2.30.0.478.g8a0d178c01-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e7eeb252da408b08f0c81b950a55fb852f92000b.1613155970.git.andreyknvl%40google.com.
