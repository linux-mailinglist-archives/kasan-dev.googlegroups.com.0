Return-Path: <kasan-dev+bncBC5JXFXXVEGRBQ6J5KEQMGQEMISWTZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id B1AA94060CF
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 02:20:20 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id g15-20020a63564f000000b00261998c1b70sf118262pgm.5
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 17:20:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631233219; cv=pass;
        d=google.com; s=arc-20160816;
        b=ENO9YN7hI4ObwzPjDbGDkGtM5Ct4VuTX5yWS9kouLX39a0spI/Zf5DmrdDiiZFzcdy
         1SJjcFW39TYX1pxc3vS0O5Gwv54vRNhSR0FnA0NbTVBDUQI6g7byvb9LMYxGSZ3E8ZxM
         5i6ASr3vmas8++fEPpk0K5LDMFQ5oPyvHWqHcVx0YvHCD6+/LC173II1xryAqAXxSA1b
         piOsvF06kCYJcm3cScS35tctxFtMrqdtvHLZ+36AZ/xNlO5QtuWJsoH09d0qkZPJ4Vt7
         IribHZoJUZLNfo1Er1yUh57abdGqlGJUBlSdR7RZYnATylGcP2qypFtpdBel/uNz+BuG
         sVvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zMWMP4LcRvF/1/QM5amCdzmGV1e+hJY0HiYhwNpmoVQ=;
        b=e6yHHbvhE9yZYz5zKre9cq1vAt1B5l0IEmJo0j0VA8KwX7HYTJwVMXQI9m1F/aI78x
         QBjvgVKVrpWCXDmXX6j8m8POMjrMmLXKQMJtgstdXm8TK33ZHrliQKCpnl1VbbBmYASC
         ANMM3LLGUYiG3a33bKctHxmOKfsbYfoYMZvyAXtwi/+ohGrltIwfZfVbJqz7gv9dBC8p
         0LpiIaRnOLL2di/BNGsZe3w7Uq/l7A0znfmSEJWdTuiCIaw9k1R/OUwK+GwIjAtRSwvQ
         ZPDPQR0iTqhmF5BQTflJxLFHkx6ma5q7bTVcHj4g2P1xVsD2Sn23BhJAZq/ChAnd7qwE
         J56A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="J6EfC8/Q";
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zMWMP4LcRvF/1/QM5amCdzmGV1e+hJY0HiYhwNpmoVQ=;
        b=Sn3oJCMaipqUHol2ix5Q3pgWphSwfx1IovrW1pQ16OQeggl0uHCEP+6G+HNHHiYX8Q
         PON4hawypI/ezKp0czwlnDeBaSYKscXqnlR9gOYp6mc6laQYSrdsy+ex/RDdC6jdyY7q
         saH2hjS0lYHYX9UP3Jf0uEIV3w1SBTuo855hnbFaHv4AUmgqE0XGidOjTSCcGd4X/JQM
         WJmi5ERxR3IJn+V9FboMkGdDg/LxkpPEh/M4ixEHCm0g+OXnymtewPO5iKeVf9WVWbsN
         Hke+UrEgXo9G1PVMmyfB2J4K/S7n7r9KJ89NW9iGlskVYnKPHJjVpCXk/YZiJmenh5zm
         rXJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zMWMP4LcRvF/1/QM5amCdzmGV1e+hJY0HiYhwNpmoVQ=;
        b=mC7jFh2BtgLUzuvbYQrh+3jSEPrIC5ntLhaA4sblVufzZcsG+9PTczeXgj7AJnxshK
         yOj+CsrDlwyGV60lEU6rQ5Knq0s5HOjhbrsfeY+7PMPL3t6ceLuaK5JUqg/5S+mpy+EB
         tuNFr//oAkLN1lmgmoLNtF/CjEqyEj8+cVdKgE/WIp+apuOyBSHdI+QvxCLsmgm5uAfI
         LABroPndrSpuaAz5lNe38ykfZ4Nx4WDVoU4V3vcN+o+kATeZANKHtMcczp0uG+oHwnld
         750onG4AEHTKrwRbxVqv6yM362F2bKH0YAy1+LjIeXxyCFQMExHgVyDILQ/Vm9RXp0pe
         /gxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5329f948CT8q1sb8C0PRj6sG/WLsI4xk0OkujqWhn+cShbZg+fQc
	zB028nh7lie+2iLjwkcsDN4=
X-Google-Smtp-Source: ABdhPJxoNuYsNpp+LZo3uR+TEeHsOxmOm8NpjMhYHlK9eGls1KwmYLbRTw+IOx4wd96jsaqHVlYEhg==
X-Received: by 2002:a63:1351:: with SMTP id 17mr4934845pgt.173.1631233219406;
        Thu, 09 Sep 2021 17:20:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:494e:: with SMTP id q14ls1552763pgs.10.gmail; Thu, 09
 Sep 2021 17:20:18 -0700 (PDT)
X-Received: by 2002:a63:741b:: with SMTP id p27mr4997344pgc.140.1631233218759;
        Thu, 09 Sep 2021 17:20:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631233218; cv=none;
        d=google.com; s=arc-20160816;
        b=Ij5h4H+oGICpqD2IzjoxjcoYLSWZO1HS/vfVhXdH7lrYt+p+kFyOLdfezemO5P1KN4
         nkLIcEXN8hu2QszsVGf73jzzwIaBka/auvJ9w7rrRWp3tfZRdSgimbe9wcKslpOH2UGo
         hx1u7XSq4Zx8KuZKuYB6vsbkNtz0dg0k0xymMJy0hOt3jZuYMhIDL/MnNsoAAFvTYEfv
         NPhvaBY+2nRScYTBferohZzd5Rzv7QHFr60yfqOUi3pEwszRIpynSZJD44UW1RU53TG/
         QyQQ/whrrj/akbCvOklJ4FV12YWGBAojES30nHmbLRCQrgpeJFus2MIjjNUXv+3XNYJ4
         FfXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=x+9cFk3p63Y/F85HAa9xFLZGDiAGu0aUEPEG7tbDW9U=;
        b=NpQkcoELpxA/MSBZeW6EaVQU11R5t6M5Bnq8+hVYXxMCoYENsejmz/LzdrMdM5vrl9
         Gv8jqRwTzc3dSj5OqmVinXIJXuRe7Svo32RGu0EoIDZhgCdylf1GEZxCe2l+vdtLWwpA
         SXZUCKfFnCgxc5IG/jsHHbWvY2Ljt4toOhhVr2L4LmTJNawxWXzCOlRxSsvx5cmyfbHa
         DvjdntjL7zqqUzUdDrdk5dEW/6cwY9cYhjVyF4n7kDlHT8udCAlqz6wYO2qQS3+av+sc
         VFaR76VXEtTilzzQrG6tQATvF5tJM9s58AyyriK3l9VxMg7iYeAxJsuvuuSEj1JXLYma
         9G6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="J6EfC8/Q";
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g128si314271pfb.1.2021.09.09.17.20.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 17:20:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 643FD611BD;
	Fri, 10 Sep 2021 00:20:17 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.13 83/88] kasan: test: avoid corrupting memory via memset
Date: Thu,  9 Sep 2021 20:18:15 -0400
Message-Id: <20210910001820.174272-83-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210910001820.174272-1-sashal@kernel.org>
References: <20210910001820.174272-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="J6EfC8/Q";       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Andrey Konovalov <andreyknvl@gmail.com>

[ Upstream commit 555999a009aacd90ea51a6690e8eb2a5d0427edc ]

kmalloc_oob_memset_*() tests do writes past the allocated objects.  As the
result, they corrupt memory, which might lead to crashes with the HW_TAGS
mode, as it neither uses quarantine nor redzones.

Adjust the tests to only write memory within the aligned kmalloc objects.

Also add a comment mentioning that memset tests are designed to touch both
valid and invalid memory.

Link: https://lkml.kernel.org/r/64fd457668a16e7b58d094f14a165f9d5170c5a9.1628779805.git.andreyknvl@gmail.com
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan.c | 28 +++++++++++++++++-----------
 1 file changed, 17 insertions(+), 11 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index ba7ba3962949..9a6eb3c9dc49 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -417,64 +417,70 @@ static void kmalloc_uaf_16(struct kunit *test)
 	kfree(ptr1);
 }
 
+/*
+ * Note: in the memset tests below, the written range touches both valid and
+ * invalid memory. This makes sure that the instrumentation does not only check
+ * the starting address but the whole range.
+ */
+
 static void kmalloc_oob_memset_2(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 8;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 7 + OOB_TAG_OFF, 0, 2));
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 1, 0, 2));
 	kfree(ptr);
 }
 
 static void kmalloc_oob_memset_4(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 8;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 5 + OOB_TAG_OFF, 0, 4));
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 3, 0, 4));
 	kfree(ptr);
 }
 
-
 static void kmalloc_oob_memset_8(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 8;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 1 + OOB_TAG_OFF, 0, 8));
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 7, 0, 8));
 	kfree(ptr);
 }
 
 static void kmalloc_oob_memset_16(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 16;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 1 + OOB_TAG_OFF, 0, 16));
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 15, 0, 16));
 	kfree(ptr);
 }
 
 static void kmalloc_oob_in_memset(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 666;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr, 0, size + 5 + OOB_TAG_OFF));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+				memset(ptr, 0, size + KASAN_GRANULE_SIZE));
 	kfree(ptr);
 }
 
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910001820.174272-83-sashal%40kernel.org.
