Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBMBROBAMGQE6VU4A5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C92D32F6A2
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Mar 2021 00:36:39 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id n12sf104939plf.12
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 15:36:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614987398; cv=pass;
        d=google.com; s=arc-20160816;
        b=t/CRHVXHqMpDo2C+1muvbpLyzegt56XLUKE34AVfbw67v3PpnBcjgvY1dRoOJDdoDi
         QS1MJD2vwjqr8DeHLzeukbnE6spnLMP8G4GWMiOHUiRWZtrnR5RxKLzYYiDo+Q4/4jIw
         aKhK4mxPhjco+WSeaf//f1/bOiuOdqhpjy98K5z1cfT+SY3u/Csf301gcN/i4fmCCOaZ
         EmQAADL0YTurrMMMxPetiuY8/UD2oCEtaVR8A+hYXhNvF2V256WDz53/zfOIMxw1UZay
         Ps/Hzwb5KIaTY56yf65QaBpeyH6SQv1GgB/zLilGVG3/MGoZHUB7X3Zb+QpYrb9Fbrlr
         xsyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=QkSsBydmGkbEf9/YF2/M6/ShzdCKahncyWhxj9xNIKw=;
        b=LhqBkOWSPV0Djr0milHETzKJ16EThB1kyZcHG0usWK2jA1rP1Hkj5IP/QnDzdXpH0/
         Zjf0ozRkYRYD3Dsd2raTT1jPegJSp266O7FTyFFaI0Q4GvSHbqjl2OprduFKB333HVTD
         0XqhNsFpJU+3utkd8hCk2f299XtYzmggEuXN1UdMkPBD0jwZl1R4iWwTYmB6SixIWJPO
         6WsMmYL2HzsYkq3vsszg9uZklP/QjsRefD6F7+qmcvho0rREWWyYFdRrb6F+Qgjo1hfp
         GZSUijRbERR+z7hE3RCjlURBnnm4MZdj2MM5I/qZqhXiHaAAjEH9nK+Ykk5yaKl2QGMp
         +fbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lRxvY4KK;
       spf=pass (google.com: domain of 3hmbcyaokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3hMBCYAoKCRkzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QkSsBydmGkbEf9/YF2/M6/ShzdCKahncyWhxj9xNIKw=;
        b=Y9QdEBG8KFb0M8SU7PpzhPCmm43rONyyVhBwZcYGH8unsck9HqbDCeVEzicn8JDLm/
         oyKGI6aQchfwDIbASw+noOKxwM+67UBx1zcUlB8farzcDAVJ+UOAJhZUEJhY+hVXp3Xy
         ety9U7meSAxGwQlIoBZOZ32Bm1YWceXNdSIXYmjjYNq0I/EFa0kYxHhHmCFHyD/XmofL
         HoN86PGmVZN0jQ9FwdXgsH+xcMUhOLQWU0g17YE0unHrMBuxnLW3HYg/nDPQ9SV6n+Wj
         30mpX7nvGhDuz1aOlUkCdoeI/8hBQh+riA3rnSp9cla+eJ9DHAM8Jm1sAh0kYv745nLF
         3/kA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QkSsBydmGkbEf9/YF2/M6/ShzdCKahncyWhxj9xNIKw=;
        b=pzAREUSGV44csmk+hyur8HEehtfwf9rUGQ5zpzVpEYtuGmYpxmTVs0zGdtl1XwL3Yk
         2cNltfcVM/1AFJoNCxs5MYURjva0fuz/ykrBvaIXdQFZwtYppZ/o+zoot3KCmAzOwLPO
         hOou07owI7QpyW7+s4RsUr0gMXmLp5G0Gv8AIFvi5AZHoQxFUDnPhEAs+KF6yzJo/TUc
         1OdhjgdaRF0aAO0k4byjA9bfMyYAcvs9SQ5iGgZwa5lTk4DvJwoKh3pPpWkqYfe0uCgo
         5OdkSUKNEBET7t0VLcO0H80k/mJ8SSmXY/RpdBRMFbZZC5JFjeSG8P+qNjhkFJbgOQJW
         Y9Fg==
X-Gm-Message-State: AOAM5338tBgDzG6duZ+i5Kh4K79flNYyKoIyL98rg38SwV353re3mz1J
	+7EB681lp4ynFf0OBRw6N2Y=
X-Google-Smtp-Source: ABdhPJzP3CTnbSx3X+o/NYqwXqQaqX4sxiuTCGssf11zj/jnse3jp/NHS8TlrnnzqvWzRQxS48ugGw==
X-Received: by 2002:a17:90a:987:: with SMTP id 7mr12764240pjo.97.1614987397940;
        Fri, 05 Mar 2021 15:36:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:16d6:: with SMTP id y22ls6187428pje.3.gmail; Fri, 05
 Mar 2021 15:36:37 -0800 (PST)
X-Received: by 2002:a17:902:b610:b029:e3:2b1e:34ff with SMTP id b16-20020a170902b610b02900e32b1e34ffmr10459464pls.69.1614987397399;
        Fri, 05 Mar 2021 15:36:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614987397; cv=none;
        d=google.com; s=arc-20160816;
        b=faexex8HSakWfLxcZDhxUV/r8VyXH/pjwEPfZhzhYw6usAjkKB8lOoIUX9gW3Qadhc
         cQqP6WyHMwDjKuuHYPQwWCcOtf2UC0nzqMByaorfl0MCP3PYXmTCQ5JsgnGKQdz7zZbF
         rX9nD5NUOogdoVz1utA7bJMqRe2uVPEchaJwZV2i0pMC2to/vyFrY503W2caq4vbKGbV
         o6OHya663RCnDUsvDMfdpmQaKh2eZoyb7cE+uFz1MeSGI/H1LE30V/lECnbZvPP7hpAe
         esTU0xtoY2+EWimXcMGxVFyULjo9zgVLQDlYng6THu/nFmFXUWDqPGt89ErcjAaXJ3ns
         rljA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=MNZ6L1aoJDnvOEvMxOUk5KgG8S0E1lmCTxqkRycD2ZQ=;
        b=Cv8gif7bBEsBghl4rpOBAlvXXXQuFlzxiF4gAanMtztUukuOuGydCKKQfsu9loIO/s
         QGoxUoLmU06si8BUMhpmF5nDRIt5maDz13nKcJ2VWnktP8bjfmunC8Oaiv9K1t0z5M9d
         bDqnt1cOcbPrwtFrSPi8BLCWBxhfuTwod2epws73xPKuCK7aiv47YxVsVHwm0MeLoo6t
         Xo4P2tuDoc3aiZz8WLz6iP39aOtdOjaJ5ugxf6q1BGggASKiMJWACS1NGWFo1BXW/iJJ
         ioJeWObSO9kkkRtpZKOjffMkNmQWlg4sV9oRtD57FkGeX3kwPJMCHt7SErXyDnEsa0kb
         BqLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lRxvY4KK;
       spf=pass (google.com: domain of 3hmbcyaokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3hMBCYAoKCRkzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id n10si272338pgq.2.2021.03.05.15.36.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 15:36:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hmbcyaokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id u8so2736646qvm.5
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 15:36:37 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:953b:d7cf:2b01:f178])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:1144:: with SMTP id
 b4mr11326208qvt.12.1614987396545; Fri, 05 Mar 2021 15:36:36 -0800 (PST)
Date: Sat,  6 Mar 2021 00:36:33 +0100
Message-Id: <24cd7db274090f0e5bc3adcdc7399243668e3171.1614987311.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH v2] kasan, mm: fix crash with HW_TAGS and DEBUG_PAGEALLOC
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
 header.i=@google.com header.s=20161025 header.b=lRxvY4KK;       spf=pass
 (google.com: domain of 3hmbcyaokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3hMBCYAoKCRkzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
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

Changes v1->v2:
- Move kasan_free_nondeferred_pages() before arch_free_page().

---
 mm/page_alloc.c | 8 ++++++--
 1 file changed, 6 insertions(+), 2 deletions(-)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 969e7012fce0..0efb07b5907c 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1304,6 +1304,12 @@ static __always_inline bool free_pages_prepare(struct page *page,
 
 	kernel_poison_pages(page, 1 << order);
 
+	/*
+	 * With hardware tag-based KASAN, memory tags must be set before the
+	 * page becomes unavailable via debug_pagealloc or arch_free_page.
+	 */
+	kasan_free_nondeferred_pages(page, order, fpi_flags);
+
 	/*
 	 * arch_free_page() can make the page's contents inaccessible.  s390
 	 * does this.  So nothing which can access the page's contents should
@@ -1313,8 +1319,6 @@ static __always_inline bool free_pages_prepare(struct page *page,
 
 	debug_pagealloc_unmap_pages(page, 1 << order);
 
-	kasan_free_nondeferred_pages(page, order, fpi_flags);
-
 	return true;
 }
 
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/24cd7db274090f0e5bc3adcdc7399243668e3171.1614987311.git.andreyknvl%40google.com.
