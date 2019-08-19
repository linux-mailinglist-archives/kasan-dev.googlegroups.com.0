Return-Path: <kasan-dev+bncBC5L5P75YUERBNNX5PVAKGQEDHH5EGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F49194B92
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 19:26:14 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id v15sf5603193wrg.13
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 10:26:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566235573; cv=pass;
        d=google.com; s=arc-20160816;
        b=zYi2Sf9jNDEp+5zQ41/eOKajIfPcgK2rkEYWHwLOYKPuKbq3bHh067/o6v9KctISOZ
         gYmnYji2yHVxURgqWhGZZ69MIey+TsmffEwbKilylGaeD7gqR+dwaFK8/n9rrPLiqN6/
         fJFfF4Gag0CCvN2QPINukpyJgVhEFtv63xbis+LyFcGwYZj1BxHod7PwxxF4gl3bh6Ha
         /DSdSbfeSJoPBXIL6hNfDG25aq06Tjp9epWYyrt5YZpX3rjALjuH29CZNmfmqXDUZyVF
         SGBCPILbLgtlO0H81mkBcOf678LzDlpr3YLirZ1Ft/JFH2+SaVglQ9ivu/2cbfLO3E23
         w7Ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=HDtMbg4yFW+S7Kk1QJrhi2kCTMePCS0y4qC3ke837Lw=;
        b=JDPej/jatUBdRbn5qxVLXucEZ/JWeGZTkcnB73KIBpiKS4DE6QPAymAtzq5FynZOHq
         Ke2myefgVUKxaAfWJNPozezYg3bYZE6TjuBnB/zNvO1p25dIZN6ufrUNiMPEe5E0GDrj
         O+KVJkkt6zjLNpBdxTqVKuJx66SAKWCZgXYXT8b0jemyNaA+Fb0tvf5EBkmyMaGr/2Nd
         KNQs/Qtcl5e1jBUH0H80b6H4rk3LIYVO538BpxyTJ4lhCSojXSUvOCLij1l8h+//Szk+
         NUuTa1t/uV2yzwoRTxFbg213i1Xu8OFzynpYDF0KrJjn+eq0qyb/RdO3S2iHBN1D9DeK
         LDDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HDtMbg4yFW+S7Kk1QJrhi2kCTMePCS0y4qC3ke837Lw=;
        b=JI2AeSH/Cm/1l89u2PdZR89NYPpxptBq/yxO02bqjmvz17S3+ze63zV+mrLvRA3VAo
         wUSA8FUEnA4FU0tK+Gd8WnygDVYQxFpOkkK2V24hKO7L0XlXXuXsz+QkwaRSjpMN6+0c
         atilnJnRZ5A6JX9t7gGoCRrrNQJbe5YW6UAPqo86FRMxiXb1OoTkRM7cDXQHNapjCCxK
         8diAJ5sR+pdeH/v1wZMiZdgYbq1xnO7MOtxkvWlf9zKsRxxcruR2KSsRgtdZv7LrMBUv
         g/6BETOQ7HkMl4Yekux5li7ongBadprQSybrGfxMRREuOgBeocFSC1Lkx9evHUXx5hiW
         okZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HDtMbg4yFW+S7Kk1QJrhi2kCTMePCS0y4qC3ke837Lw=;
        b=JstfcnGFO5vEj+627jiI3tnQe6h7rsClNW1oPIY0aJitf5p6T5pms+P1gKpsT52ZEm
         WbhhXpF6hiMa30tbGOGhP0BkJCe1sG3vyjEdYPIn766w/JF7oDX/jrtUf/Qyw6Sj/g/K
         PBJk3uBud0MG7guX6dR/QlQOSvAvnPk/QbXJQnCoXSswYDGkn6f/BVFEEd1rhjU/IbK+
         nnjCH44iy23RhP6HM/oqKowxqIu/JGO+gaRHsZVBya9dl1suLt4xJQr9eNy280Yhv82K
         2TGPYGnlPl0QboFTu7oQizavqlMGdztZxVtcQ7bpg3QWQHYNdJWyJKEz3u32S/pwk+CF
         Uu1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXjeROX2y9ETY4+AaxT9oZO2fCWOTzT0IkjUY0dmgIjRa3XGce+
	DdwraHCyTEKiTfm7dUK00OE=
X-Google-Smtp-Source: APXvYqy1QZgtTtj9ZZdCSJsjhPFhpDmUCBBcihOm5bwwsjyCgFrPjB335Zc+TnJCokcIJcSqCCtAWA==
X-Received: by 2002:adf:f206:: with SMTP id p6mr30018335wro.216.1566235573695;
        Mon, 19 Aug 2019 10:26:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c411:: with SMTP id k17ls77139wmi.1.gmail; Mon, 19 Aug
 2019 10:26:12 -0700 (PDT)
X-Received: by 2002:a1c:238d:: with SMTP id j135mr22707547wmj.39.1566235572630;
        Mon, 19 Aug 2019 10:26:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566235572; cv=none;
        d=google.com; s=arc-20160816;
        b=B/wpWR997FgnsyA9/d16TZ//ORd5+LD9eHDNOz4Rkpv7L47jQZ2EGxEJxrm5hbp/NY
         byL9ltX96NbRRTl83vN0+Jf28V5vor9Mi3KcOJalc1d/p4teZm4cWLV5lz68U9Yx03Jj
         S715lJ37TASby5xmVa9WVOl+epqwmNWF2BgOcgBjkA8L3oz6VmM6qDLGsZdTAZeYBpk5
         XUZZHUa4wlK6XcgDjhrOOVT6iFBpiYEfh5r1l3txo2U2pbtYjik5K1JVeU8DB9bRnegc
         KYmFaBFjl838fdrm0TJdgfvVirIuO2eyYYbTiW/pXgexgyQvyhbfIYZjFuUFupFnUSWT
         3LWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=B7pUOTXcRdu3L+LzlsavEvZpZkCzgW9N07OWgEA8MgU=;
        b=b9d4awHcZznrLKzOdvmiAdWEZclMCJg1PnnTfx/rpWdfXdAiUPr2tslWuOMqPeACJc
         CUL9b3kKYNDcYVOcffQhLUVYhdhPdbmz9DFaV20c9NKK7tU3jG1vfz5XbS7wx1JqluDX
         2Gxnqy55uU9TcE1/rX7B7jEyRwOYmp/ngnF02Fq8VwXVPbIXK9XqKXi2HkNJJWqbh1K+
         hEXXyD8GhMtBHU2jMKayHWwSjMztf1Wm24beEYkRqJIl4mDfB+igNZ4xYLVqo/2LV/04
         hxBr+FEC7rNYRSk+ubJ8GZAOEnd2/YHczBAoRlcqJUbtpVoF0UZd040jX6U+OezYhtzY
         x9hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id e23si499245wmh.0.2019.08.19.10.26.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Aug 2019 10:26:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5] (helo=i7.sw.ru)
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hzlPx-000240-5o; Mon, 19 Aug 2019 20:26:05 +0300
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Walter Wu <walter-zh.wu@mediatek.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Mark Rutland <mark.rutland@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	stable@vger.kernel.org
Subject: [PATCH] mm/kasan: Fix false positive invalid-free reports with CONFIG_KASAN_SW_TAGS=y
Date: Mon, 19 Aug 2019 20:25:40 +0300
Message-Id: <20190819172540.19581-1-aryabinin@virtuozzo.com>
X-Mailer: git-send-email 2.21.0
MIME-Version: 1.0
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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

The code like this:

	ptr = kmalloc(size, GFP_KERNEL);
	page = virt_to_page(ptr);
	offset = offset_in_page(ptr);
	kfree(page_address(page) + offset);

may produce false-positive invalid-free reports on the kernel with
CONFIG_KASAN_SW_TAGS=y.

In the example above we loose the original tag assigned to 'ptr',
so kfree() gets the pointer with 0xFF tag. In kfree() we check that
0xFF tag is different from the tag in shadow hence print false report.

Instead of just comparing tags, do the following:
 1) Check that shadow doesn't contain KASAN_TAG_INVALID. Otherwise it's
    double-free and it doesn't matter what tag the pointer have.

 2) If pointer tag is different from 0xFF, make sure that tag in the shadow
    is the same as in the pointer.

Fixes: 7f94ffbc4c6a ("kasan: add hooks implementation for tag-based mode")
Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
Reported-by: Walter Wu <walter-zh.wu@mediatek.com>
Reported-by: Mark Rutland <mark.rutland@arm.com>
Cc: <stable@vger.kernel.org>
---
 mm/kasan/common.c | 10 ++++++++--
 1 file changed, 8 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 895dc5e2b3d5..3b8cde0cb5b2 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -406,8 +406,14 @@ static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
 	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
 		return shadow_byte < 0 ||
 			shadow_byte >= KASAN_SHADOW_SCALE_SIZE;
-	else
-		return tag != (u8)shadow_byte;
+
+	/* else CONFIG_KASAN_SW_TAGS: */
+	if ((u8)shadow_byte == KASAN_TAG_INVALID)
+		return true;
+	if ((tag != KASAN_TAG_KERNEL) && (tag != (u8)shadow_byte))
+		return true;
+
+	return false;
 }
 
 static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
-- 
2.21.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190819172540.19581-1-aryabinin%40virtuozzo.com.
