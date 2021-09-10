Return-Path: <kasan-dev+bncBC5JXFXXVEGRBQWI5KEQMGQEKJC6ROI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9650F4060B0
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 02:18:11 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id l6-20020ab05a06000000b002ad4d17666bsf75155uad.7
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 17:18:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631233090; cv=pass;
        d=google.com; s=arc-20160816;
        b=BgZjDqVLhSWkesQWUAnEkKeL0nrBC/U/Igq76HORBLDN4uxvPShuTbuIEA0QUMzIDf
         EAM2WwLe2+kGGSrGYETEnPqd8JcwQyDgLKMNoYgvmHCcIXrWpRs3HSodWUHYk1iN2BIf
         D/zuSlDc2PW2u3NOUVx6rzfQoEerlZI0fYGnYSsy4DBozo5yYFkc9iFKPBgePpJhnDpt
         wypYSG2OE7Q2nnO9nxbOTUmb3MkdpKOxv7KdoqVUq01vM8qjLf7/FhMdHZ10nxaIyWHN
         SvzTKlNYuJCOv+toxpaVFv7Y1YydV6pK1/T0l5zmR2S6RdiSBdWnpBalgcUZieRtNsFF
         RgEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Qt1b+tIjQpPfajIxNtV/sA+muVChFhLWgzSWLpogA/k=;
        b=L2UO3oawDr9ELrozQK/bOQfn4RzRcU9pa5AQxFWBbhni4ugJMDQ7gCkCaz8xsUNVDU
         oKlWRahlO+17FW3GqjCk3nAqcPsgJh0JY2e0sMlRoTMGiNWEXBu9hD14maAzymtHml3t
         WjSWEQZnb33OwdgtWsuHeer4R4kIBPf05spfLADN2xKgmcuVxjI41PIBQ2hV4U4iP5g8
         A5xYl8GHZrr+BlYV7RG1xqJ8yKXqHrekbvkmsYeyziAUD3qf7QpGWYosGOQRjOmNcC/y
         92jYVxgHPYs6nBSW/1+GDKXblgWT6dl3eenerjNJbA5QQKlcSZS2Vp4BuriK7hozTZ22
         pnfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NTyvjppn;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qt1b+tIjQpPfajIxNtV/sA+muVChFhLWgzSWLpogA/k=;
        b=BuYqh8iV9C82RpH8Fm1JBdzrT+FCVBAu+7U21DTFLF2YilXyf4/1nILPEpO/ulqwMx
         54uQX1NylkSXgdQwVQWGeGfTtQ1iRTS/DeK4BHhKnpf9m7kVQO86mJAYkb5H4OKWX+dM
         cCAZTDtQzpwxJPaysh/ig5UuWG5JXmZ7iPMqG/ZtL8zy92Qx+GhzmQQiSOnT+MXbVDti
         R1MR0eimzRAYqGgXb26thSihfgINhUU3i+7vIfUYiGi9lkx4Wn81wArI/CXYgYxVKxCm
         FhKANRuBFXPmfM/8OwqEDXKos4Q0sKOZQcAgbe6HH4wB7IfPxiPW9OnOM0zrfc6u6I+H
         amUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qt1b+tIjQpPfajIxNtV/sA+muVChFhLWgzSWLpogA/k=;
        b=5eEnHXsUrKgVIEwNvYgXwrjVyhb9YlKHeKTbbKE07SYbrDdVB5TuIvJGumzVFN/whf
         zsOt0d0D7F64RvnJeMDJS9p7c1zJxMwdOaZzj+BIhBu8ZKCuISJqPgbX4ZBDs5Peem/C
         aNpQpj9ozeLQ8sNJZoS8WFvgwdXKBgTiwcEyeWpYe2BkRPKMZ7+zfHsSJG/QwkZ1WsUC
         0caQMO8Bd85JGKT3NzUB3U84Mq4W9B2niXzVuINKDkMuEp2kj7d+D6JAvTxUbX+ZSXIq
         8bGeXBzTC2ZF4ZBQww+AbEvQ1SH7jGD9bAVgXWUqpWj8YF1I8PIeLUZIyz+N+8Rl2Psl
         qMPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530XHz5IT02veuvwqOKsjxsH0G2Kwx3+XCT0KXlf6bFxB1WOGg9k
	EUzzoIFeKkquZgGS2XUsHow=
X-Google-Smtp-Source: ABdhPJz48099HOlgVQJLXIDucIm9Rb0KG6JzGp7ABucT1pW1viRq94VHy/29U+EqkJRbv1nUBRIpBQ==
X-Received: by 2002:a9f:238b:: with SMTP id 11mr3990957uao.91.1631233090385;
        Thu, 09 Sep 2021 17:18:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d18e:: with SMTP id w14ls708231vsi.7.gmail; Thu, 09 Sep
 2021 17:18:09 -0700 (PDT)
X-Received: by 2002:a67:f793:: with SMTP id j19mr4255820vso.28.1631233089729;
        Thu, 09 Sep 2021 17:18:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631233089; cv=none;
        d=google.com; s=arc-20160816;
        b=cNsm1ZMPe7VIKNerubBsIRnAPAKL2un0aekuadIShyOYqs8K7zFlXvtHw64mU5kC7d
         27iWT9uf7mUqvRfzvXvVFPnLcwnF7V0G8U2GqmwQqlTjEnLiu+nf0M1IHZNKtq0G5+g7
         tSgOV6HJ4fff72NMCR6WQwjwKLE2SE4YILqGXpJVGP2V2pB8oMU/TQtpfmWEnJJIKXmW
         1l5PLA/8YG4XWayTCzN0X7wRO5aFcH2181S4iSCbc0LpvZZ9ZmXLSdVRGp8PNliB99fQ
         1DEoMgY9b0iisMeqIy5vnUyAaBctZlnU2FCJoi/+NpHhe7b+ZSd0P1rbI9RzeUJrXdQC
         5cUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AsENQNyW5GuiFq94N7Y7kbLMgH2I1g72ipv8BlmWXE4=;
        b=OsJ71lHH10Vt9Efa7OfcbD8TUGfXanLARq1wGuM/3ZsXHmjcWffvkGoYGtSPCPQITF
         6LqQvTBQW126Qw9q0fO+QhN5YqmIgzvV1TQ3q12CAmM9Idf08hVtuZ4c0L0K1T7U7Ns/
         KJcS1269jem8Pn+f4DOXvvCywE4JBQUOBcjx2JlQI5zi0a9O0LUuc5MQl9Oycqoe9m0o
         Rtvn74YoXBiZFsFbzNSzS5XxeAvNc57an7hHVKQ5vhfnY3y8DR1YaN1f0m59D5m4Fm6o
         wiU2W4JUp9j3f/o6uVSJHPHV93JPU+wDvP2hxQ9es7eydQDHgVA1lozMbG3FWfu4LYiF
         o71A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NTyvjppn;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q26si328322vkn.5.2021.09.09.17.18.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 17:18:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 6CDFE61101;
	Fri, 10 Sep 2021 00:18:07 +0000 (UTC)
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
Subject: [PATCH AUTOSEL 5.14 93/99] kasan: test: avoid writing invalid memory
Date: Thu,  9 Sep 2021 20:15:52 -0400
Message-Id: <20210910001558.173296-93-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210910001558.173296-1-sashal@kernel.org>
References: <20210910001558.173296-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NTyvjppn;       spf=pass
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

[ Upstream commit 8fbad19bdcb4b9be8131536e5bb9616ab2e4eeb3 ]

Multiple KASAN tests do writes past the allocated objects or writes to
freed memory.  Turn these writes into reads to avoid corrupting memory.
Otherwise, these tests might lead to crashes with the HW_TAGS mode, as it
neither uses quarantine nor redzones.

Link: https://lkml.kernel.org/r/c3cd2a383e757e27dd9131635fc7d09a48a49cf9.1628779805.git.andreyknvl@gmail.com
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan.c | 14 +++++++-------
 1 file changed, 7 insertions(+), 7 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 8f7b0b2f6e11..b261fe9f3110 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -151,7 +151,7 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	ptr = kmalloc_node(size, GFP_KERNEL, 0);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
 	kfree(ptr);
 }
 
@@ -187,7 +187,7 @@ static void kmalloc_pagealloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	kfree(ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 }
 
 static void kmalloc_pagealloc_invalid_free(struct kunit *test)
@@ -221,7 +221,7 @@ static void pagealloc_oob_right(struct kunit *test)
 	ptr = page_address(pages);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
 	free_pages((unsigned long)ptr, order);
 }
 
@@ -236,7 +236,7 @@ static void pagealloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	free_pages((unsigned long)ptr, order);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 }
 
 static void kmalloc_large_oob_right(struct kunit *test)
@@ -498,7 +498,7 @@ static void kmalloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	kfree(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, *(ptr + 8) = 'x');
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8]);
 }
 
 static void kmalloc_uaf_memset(struct kunit *test)
@@ -537,7 +537,7 @@ static void kmalloc_uaf2(struct kunit *test)
 		goto again;
 	}
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr1[40] = 'x');
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40]);
 	KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
 
 	kfree(ptr2);
@@ -684,7 +684,7 @@ static void ksize_unpoisons_memory(struct kunit *test)
 	ptr[size] = 'x';
 
 	/* This one must. */
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[real_size] = 'y');
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size]);
 
 	kfree(ptr);
 }
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910001558.173296-93-sashal%40kernel.org.
