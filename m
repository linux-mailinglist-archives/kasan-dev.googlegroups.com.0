Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBC7XRPVAKGQEQCJV2EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 046247DE32
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Aug 2019 16:47:41 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id q26sf79347873ioi.10
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Aug 2019 07:47:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564670860; cv=pass;
        d=google.com; s=arc-20160816;
        b=EWtAltPrOW3Ei4MQywwv2KF+rl4iplD5QLDSKSPOSofieRlemFUPBAqHoxTemQmbZP
         PmM6D1Eadb1qS/VV3pgNZhjYdB0jGggzA3Hh2rdGiai3Pj1SGqH6Er+zKWdA3ZcoDGE5
         5K+8NpF2LID15WOknW3zAxLj0e/VK6X7hzjy1EOn4g35j4U9VqozCbbc4kAfCPaT97WF
         j0pbKk0jxg4Ol2+BwlJrvAPPj9sl6QAh6xrJs/km6LmT6Cks9LAYf4mWjIX1Wms2yTTD
         m2S8ILNKGTHjbU1yqTzbOfLqoMK0qYD3EWlR4HCCQgI8QseSJEuEJr6zIBH/0pwjvpwD
         GJDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=AQ1niTeAg13z5PkNdpsrPdpjk689nG64H8qgkfPJr6U=;
        b=jnnD4MatzvOuihocX448/5FJ1ssmgS1WL3SCWQtYwX6waYsUoBCASJRZtXJukZOzCg
         5O7H22spjDTALsU6NPBMvBMozLjTYk8i/JmBq+HbWWaNXV4zllMNpxsa/3drb4FtAjH6
         IefVCJPxHrJgR2eb7gjHP21HkuJAweoxJoZi0usFgvRqYTMWayob66gBJwRWk37lZX4B
         ixI2T7O04OBok8aRApQR2PnxpQXPZrG8nA2VPFv8OROzFhsxP3vk32QhRMfweP6KTlgp
         zK00vi63gj4sLS2pFkczv6XOzk2/zAvZTnfqYTUeNzEG7AOWGLmxtCUKGfL+AGIb7noe
         yExw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=LejEUzoE;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AQ1niTeAg13z5PkNdpsrPdpjk689nG64H8qgkfPJr6U=;
        b=RuN/YpfTuZLDC+oF2myvzo1RcIMNlXFhl+ruWEXukfwcE2tsF6fuJCoCX4nXXsPRU4
         0dw/umC46MhRI+KjPcYpnIprqUHMQiH32/xxgArfqLGSeyXojxtOo6j3f1vph9TKaANy
         9/QNFLTZ4clifWiAyPMK1/QNlbCORCQkm5xFNC4E7NFBMoUcK6AkfB/qFOTq5XR9x/mt
         h3r+PitYX6FxMzdRBHRsLyU/SPl5odSnysg0hW9XTsZqG/WxVxF744sX2t6+afxlkMAq
         JvcxkDq0ysvd59tXlOcL4WZpZuElG9qCWYssdo2EuGMPDmsEkrHhN1ojV+Hj0B6lE1SO
         QU9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AQ1niTeAg13z5PkNdpsrPdpjk689nG64H8qgkfPJr6U=;
        b=PJD7uP8RY4fdFFnwINhl4ObnWr2ACG4GTfQjQmq1dTzhsrvw7WP0mV8hdFQ9vzo1Qj
         DO7DG7Km5LPghyjzDh2AboicDTd1D5k/y7XAcBxO6JIxL3jqhK9o/RZhxsjH4xfkGYD2
         qNfdX55XO2kCcFXQ5oUhMVMjcm/X6HxSYhJsziM9dECOoC/1DjtPudx6W7NTMr5bRZVQ
         7MJS7NsnJE5MWUDZqPreJZYl1q4Zbr0nO/FlRV7nvyqQHnXN89ttIm4rskMUNg6rsRgB
         MsVfWdd/URMssDtIjoIbUSVJ0Xf3iVEm9zM58BcAH8jmuchP1ykvU3u5T9lhHeTR8QlH
         28ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXtVi1V03by8q9qb61Oye0/0Y6OuR1W9pYZk+oBitUKu1qQasUk
	QviUkTZA/kmtBMpqPEj6tTM=
X-Google-Smtp-Source: APXvYqxMtyGGEl70MwQ1fUQv7RPXSzPCf+n934ZLNrM3GGFh2zZ12+ySmYQS7W23P6W6hEYLNeti/Q==
X-Received: by 2002:a6b:5103:: with SMTP id f3mr114355316iob.142.1564670859918;
        Thu, 01 Aug 2019 07:47:39 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:18d:: with SMTP id m13ls18659002ioo.7.gmail; Thu,
 01 Aug 2019 07:47:39 -0700 (PDT)
X-Received: by 2002:a6b:f906:: with SMTP id j6mr35821684iog.26.1564670859646;
        Thu, 01 Aug 2019 07:47:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564670859; cv=none;
        d=google.com; s=arc-20160816;
        b=RGMDDiKlbNNe1Lwa2UOmjXgcM2EST3sYxhGJM6SZd4lBs/fMBvZcVWmdC/jTgqkkYp
         omwaNtJ5uAPsDKAfWFcoY9v5OQiAC/Dx1QmTf8k2Xj++Wa9PylsKCrWJl45GXr0Ga5Pt
         2zIbRMVlcW4f0pfK8pTRy7yHUpEyTMb4g3lsaFo1SKL8CXbK8yqnnZZi7gGI//y1KlRT
         +lXWW3FOxqMvNoVYhmV06eO8QGnm2YtOd2csiZOrRmANALeuc1m019apN9A1bs0yMOtB
         PG6g9hO0jumtTHGvHYkB9jpu7g8SgCF267z4FZ65RMgAEg9danYwvLtFo9OZieYV2kO7
         tQZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from:dkim-signature;
        bh=230s3ChFPRc4aRDJM4ggG97b31ayoZtf71ejiTiSkjo=;
        b=i77fImvCUdxY4LG+fs1kFz+M1C0sTHXkEovhyLJSumeGDZvY7bzg/LNJnHwGFAB34C
         vBL0G3XkhhYeThbrCnP1m7rnz4JLDxFmOac+qqQdma3bc1GsnJMNkcAucp9ff2R9NHfg
         zrujzt5ZKtn0OK1nYc4w5OxWh73QG2f7g3W4SxDwkbY9bcs3Px3scDKOzl8P0BVChofG
         bbu4FQakpj6KzmUCSaF5sdoGAPbXoFfkIxo+lVHEb2rKroafJhJ4i21X4M3naf/+pKwm
         cTntdQvPqJNCs2WsVadj4rzDtLhZpqXNenHSkRFnyzIywHG+7KOLerB3KB7t990Y1XVK
         Xknw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=LejEUzoE;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id m190si2903763iof.3.2019.08.01.07.47.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Aug 2019 07:47:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id r21so52274985qke.2
        for <kasan-dev@googlegroups.com>; Thu, 01 Aug 2019 07:47:39 -0700 (PDT)
X-Received: by 2002:ae9:e30d:: with SMTP id v13mr83907407qkf.148.1564670859058;
        Thu, 01 Aug 2019 07:47:39 -0700 (PDT)
Received: from qcai.nay.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id s11sm29605818qkm.51.2019.08.01.07.47.37
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 01 Aug 2019 07:47:38 -0700 (PDT)
From: Qian Cai <cai@lca.pw>
To: catalin.marinas@arm.com,
	will@kernel.org
Cc: andreyknvl@google.com,
	aryabinin@virtuozzo.com,
	glider@google.com,
	dvyukov@google.com,
	linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Qian Cai <cai@lca.pw>
Subject: [PATCH v2] arm64/mm: fix variable 'tag' set but not used
Date: Thu,  1 Aug 2019 10:47:05 -0400
Message-Id: <1564670825-4050-1-git-send-email-cai@lca.pw>
X-Mailer: git-send-email 1.8.3.1
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=LejEUzoE;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

When CONFIG_KASAN_SW_TAGS=n, set_tag() is compiled away. GCC throws a
warning,

mm/kasan/common.c: In function '__kasan_kmalloc':
mm/kasan/common.c:464:5: warning: variable 'tag' set but not used
[-Wunused-but-set-variable]
  u8 tag = 0xff;
     ^~~

Fix it by making __tag_set() a static inline function the same as
arch_kasan_set_tag() in mm/kasan/kasan.h for consistency because there
is a macro in arch/arm64/include/asm/kasan.h,

 #define arch_kasan_set_tag(addr, tag) __tag_set(addr, tag)

However, when CONFIG_DEBUG_VIRTUAL=n and CONFIG_SPARSEMEM_VMEMMAP=y,
page_to_virt() will call __tag_set() with incorrect type of a
parameter, so fix that as well. Also, still let page_to_virt() return
"void *" instead of "const void *", so will not need to add a similar
cast in lowmem_page_address().

Signed-off-by: Qian Cai <cai@lca.pw>
---

v2: Fix compilation warnings of CONFIG_DEBUG_VIRTUAL=n spotted by Will.

 arch/arm64/include/asm/memory.h | 10 +++++++---
 1 file changed, 7 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index b7ba75809751..fb04f10a78ab 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -210,7 +210,11 @@ static inline unsigned long kaslr_offset(void)
 #define __tag_reset(addr)	untagged_addr(addr)
 #define __tag_get(addr)		(__u8)((u64)(addr) >> 56)
 #else
-#define __tag_set(addr, tag)	(addr)
+static inline const void *__tag_set(const void *addr, u8 tag)
+{
+	return addr;
+}
+
 #define __tag_reset(addr)	(addr)
 #define __tag_get(addr)		0
 #endif
@@ -301,8 +305,8 @@ static inline void *phys_to_virt(phys_addr_t x)
 #define page_to_virt(page)	({					\
 	unsigned long __addr =						\
 		((__page_to_voff(page)) | PAGE_OFFSET);			\
-	unsigned long __addr_tag =					\
-		 __tag_set(__addr, page_kasan_tag(page));		\
+	const void *__addr_tag =					\
+		__tag_set((void *)__addr, page_kasan_tag(page));	\
 	((void *)__addr_tag);						\
 })
 
-- 
1.8.3.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1564670825-4050-1-git-send-email-cai%40lca.pw.
