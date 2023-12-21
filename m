Return-Path: <kasan-dev+bncBAABB3VUSKWAMGQET5M7ZLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 30A8181BF51
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:05:03 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-50e55a909basf1017959e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:05:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189102; cv=pass;
        d=google.com; s=arc-20160816;
        b=VwHXpkRsq0RCkEHkH6HUze6bC2Sg9MM5KKWYi7EQIRH+YsYmHdxrztJqcftDQA6fqq
         13eD7o55Sp1pz03rvCPjMBdrJtacBRpmZ8s3YaEuOIJe3FWS0+Wt9VTFgxWrMl4Lcytm
         W0zLPhjBmtoz58SZTLLitbLyoBbFQ/KSDFHQMjusw2a9d+rmU+8sMVDCnK5wQkNyT011
         fvO6dxiqETBGnfpMJLb8mt+y2nMJCUUlnoTAEenMlLXli1B93ZwxJWKGxToosJ+WfSoC
         jKbXjou9TXcJEH4Wno5vxzztQ/xv/Et32lPybWEEvhmOtbhe3gueNgfJY98sWPJy0SA2
         Yemg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mcaYcun4sCwqMHAT/xv/Tz8n+KxRkBuZ0/VhVtsfybs=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=mG6agIsBqOA5Xy0+DAd1Ixs05MrCImvSA9pMchC07pQ7c3nWZrG3oMfYECcSNKMSop
         BUnLG3g4lsHP3PVagI4gHtbdp7PwcRr3+aRow7i4yf5K7pdA9HB4CcznpDF0nvZdQNxD
         x7MyQt0l7ve+4U5ONEMOWx4EjKiU7F9fqwfckbC0Epc2lxYmSOh3mhiUrYVdZ/vZCFq4
         0hh/WUqhPcx8pN1WwZxqC0FQ5SMfpYMSxUqTE4aIr5OoyVulSLJzcvHx3H8xCmACM6Hp
         UKxPCKNgJe57+BqFHYUv03rq0PUxuZSbxpZsoicTV5v3yfvwiSufBE+dXkJzZBSe3Bql
         HLsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=oUd4oho2;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189102; x=1703793902; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mcaYcun4sCwqMHAT/xv/Tz8n+KxRkBuZ0/VhVtsfybs=;
        b=MUA2y1dFV9Aph2TTEzWR5ij35k3k+Oky1bfSjX4/RhgF1y0tXDu0LNBv4OmxNhNbVs
         ULOA00xLD/ugjMjrBjY39OXDhGFbf5PyhwazjnstZVpyjxoJNTC9g1M1gBZ6vl4lxaEs
         Ntzu5ic4l1QRoF2/SGH3+IhB63Xje9DefONP1gsbJt2EKK/xVdCoBB3hKLpDXxumZeKi
         ZLrkuNmL5ToWg8wbQZAqzfU+b5WlGYHpJQK+TymL56Am2Oo/D6BbdMaK/gpTOpc8SNYB
         qeCTkRx2f+Zg448xWmQd/lndk9+MjyLEoFhBr2a6YPNaeNEoKdBhXLQ8k+Q85ph/NLht
         g3bQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189102; x=1703793902;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mcaYcun4sCwqMHAT/xv/Tz8n+KxRkBuZ0/VhVtsfybs=;
        b=BGkbek+3BL6OZ5Qf+zpzGUqJ0UR/U0kl+5U+i8K9bmVbVVvUCllfoD5Jsq8m12qQcf
         B7S/WOiF7U5Hhka72ah1dni6nWs8l7n9yNKPI780MrqVjhBfYiZtSb+yLTcdeADKXngh
         uH06WLWRcao4hK/iOOXeGRehGotbVZuQY3R3auUbZ/dect2I3wwakf5Xscxlw1VuFQgP
         iWKyjLdJXu+yzTjUh173/eG/BnUzEaFhITKAi0ORhmEdnFHyK2XCqdEsfESuZxjWfcB8
         TCa50aHN4THluQdtggBMhhpasAmDDnzfKkReH64FAkkc/soD/5Q4kHgs8/nKxx3JKvBa
         Zjaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzkdnMNr9giAi3DSAu3+p7qeiw23LC2Inb3ga+OepDVjewMrpnH
	htgf4VkRVvSLIKwjbtPnvr4=
X-Google-Smtp-Source: AGHT+IGTcjI8KzhbPFz/tEBFJDckcqOUeivVSjPx7ykCoq8rsA/Blk+krU+tI4C2236ONViEyXt1pQ==
X-Received: by 2002:a19:5e56:0:b0:50e:39e0:e9ce with SMTP id z22-20020a195e56000000b0050e39e0e9cemr74202lfi.202.1703189102319;
        Thu, 21 Dec 2023 12:05:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b09:b0:50d:170f:6454 with SMTP id
 f9-20020a0565123b0900b0050d170f6454ls600385lfv.2.-pod-prod-02-eu; Thu, 21 Dec
 2023 12:05:01 -0800 (PST)
X-Received: by 2002:a05:6512:398e:b0:50e:4e52:67f6 with SMTP id j14-20020a056512398e00b0050e4e5267f6mr83899lfu.190.1703189100691;
        Thu, 21 Dec 2023 12:05:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189100; cv=none;
        d=google.com; s=arc-20160816;
        b=XNzDuyaChREVrXoVN/joUFiogeY2qVu8hQGAYD8jr3T2anUf9nYwaPWwc0sng60O2b
         Mtfr5keCTfKTUnq2jggfpAQkDQMwJ0lqtTPHdzWBrMRPNDukhfot3uSMW5fEg1EbzzJG
         xCBAJATJp1M8+nHxwe55Ic95UnbGQmj2woqSvCKaP+U70U0Im85hf3ALSURf989dSl/9
         vABCCqKsiuB7MokstooEgEFU0FELkzp14UwBtL+wvyJ12nSDdBk0MHH5IQm+6Q10fMn1
         BRmyWjH8V1fgymiE+HeKhv+r+AS1VsEzE6Ji5PMybNImmsvdkKgnMfXVtq7I6cfw61gm
         LIFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=25+JPAVVR93qloIeZBPh87TvRbXcdeZ++9g3nzTCJ2g=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=WeV00w4V3GHFBTmd4+Dg+O5MC69uuTNQjzTJGM6vUSzZVpzsNJQzNxxN1bxjR82q6m
         BCXAjJyI6JKe6VH2DWDTuDjX8MCU+YDCVvfM/DqCl3NEs2j/4nux7KsOs6W0sI/Zvbis
         lGDTWkFGv7b4+BI2dFsWs/1ya5ycCQMCZkZ96mKAw4td2f5xht/Mc2Gwc6/h4nT863WN
         EmH9CSCN9gRC1dE4HqUdmmNFDcoEbWr9NNNj4/bUI4p6+vQejPnk9OaTJ9FClOCK0sAg
         57NGSeC52QsuOvvsTV0Z1zIKMIOWmk6enuOYrSVU+kXJdac3OPSPxk7qNLP2csPZ4uVy
         D7Iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=oUd4oho2;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-177.mta1.migadu.com (out-177.mta1.migadu.com. [2001:41d0:203:375::b1])
        by gmr-mx.google.com with ESMTPS id n14-20020a05651203ee00b0050e27f0ec11si119512lfq.4.2023.12.21.12.05.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 12:05:00 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::b1 as permitted sender) client-ip=2001:41d0:203:375::b1;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 02/11] mm, kasan: use KASAN_TAG_KERNEL instead of 0xff
Date: Thu, 21 Dec 2023 21:04:44 +0100
Message-Id: <71db9087b0aebb6c4dccbc609cc0cd50621533c7.1703188911.git.andreyknvl@google.com>
In-Reply-To: <cover.1703188911.git.andreyknvl@google.com>
References: <cover.1703188911.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=oUd4oho2;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::b1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Use the KASAN_TAG_KERNEL marco instead of open-coding 0xff in the mm
code. This macro is provided by include/linux/kasan-tags.h, which does
not include any other headers, so it's safe to include it into mm.h
without causing circular include dependencies.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 1 +
 include/linux/mm.h    | 4 ++--
 mm/page_alloc.c       | 2 +-
 3 files changed, 4 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d49e3d4c099e..dbb06d789e74 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -4,6 +4,7 @@
 
 #include <linux/bug.h>
 #include <linux/kasan-enabled.h>
+#include <linux/kasan-tags.h>
 #include <linux/kernel.h>
 #include <linux/static_key.h>
 #include <linux/types.h>
diff --git a/include/linux/mm.h b/include/linux/mm.h
index a422cc123a2d..8b2e4841e817 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1815,7 +1815,7 @@ static inline void vma_set_access_pid_bit(struct vm_area_struct *vma)
 
 static inline u8 page_kasan_tag(const struct page *page)
 {
-	u8 tag = 0xff;
+	u8 tag = KASAN_TAG_KERNEL;
 
 	if (kasan_enabled()) {
 		tag = (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
@@ -1844,7 +1844,7 @@ static inline void page_kasan_tag_set(struct page *page, u8 tag)
 static inline void page_kasan_tag_reset(struct page *page)
 {
 	if (kasan_enabled())
-		page_kasan_tag_set(page, 0xff);
+		page_kasan_tag_set(page, KASAN_TAG_KERNEL);
 }
 
 #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 7ea9c33320bf..51e85760877a 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1059,7 +1059,7 @@ static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
 		return deferred_pages_enabled();
 
-	return page_kasan_tag(page) == 0xff;
+	return page_kasan_tag(page) == KASAN_TAG_KERNEL;
 }
 
 static void kernel_init_pages(struct page *page, int numpages)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/71db9087b0aebb6c4dccbc609cc0cd50621533c7.1703188911.git.andreyknvl%40google.com.
