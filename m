Return-Path: <kasan-dev+bncBAABBAPM2SEAMGQEWLJ2CLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 64D7C3EA6DE
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 16:53:54 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id m14-20020a0565120a8eb02903bcfae1e320sf1927061lfu.19
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 07:53:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628780034; cv=pass;
        d=google.com; s=arc-20160816;
        b=u0U3qx6enLdbBZQVrs700eNpo4JQRJtp9YaaIwU/jZEpExs97AYOHZNwQx+KinioPP
         npCO9LkFwt9kALzrD4gP7mFHrEjU6pqKgVsFwDLPkLt1WIt5KEe9dothpi7xdGtZvQia
         +GJef6FTlgSZrHpH9iBtekO637zUBEXd8/pzlKQVE9EOU4SvMP08T6o6TCI0CeY5YiBP
         SggfcSc1ERSSlK+9vHO8vfNZQ6VjbEy/0J/5xUARrgHpA5Iw9otAtcxMyjiRWOimRTNS
         pSol1Hbw/Xo3YEDL6OX91XD4Po6TDdR3lOIqv/4yHCeb48DpuzpbFGFhxQTY7aT6juHP
         NovA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=AVuvUdbJcvtkEgtHydRcnKOH0AVtlTebL0vrKVFgp2w=;
        b=iA1dVrWgILmM8c4sRmYujSCpXOUW89Kj78qBq8tCo4IqGhgr+wa2MHvC1NU95sfw3D
         e+Dm385BFhLISvur7hJ0Rh7Y5KtWc2jzDTZYvebAr03/tLMHfwdxcKu/Fqt8ZKd20B4v
         kSBs1A9+8fQHWvxY7z6YlVfM9BIeKCJaisT2wEy4/u5/Up31WW0bbOdyzwhBBD/IdfVF
         X/QHgMMKyk6JljugWbAil60TDdKkgWQ9mfHPHg7Ixr1WmWbmtqPIdnLI6GyAVWt+ru8e
         ZD1eG40jU+bVIeNPYaVKah0QjnL/1+IzPtspfgBSxviv2cpCjepINklpuxjCzBr28xC5
         3oMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DiwUfvRQ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AVuvUdbJcvtkEgtHydRcnKOH0AVtlTebL0vrKVFgp2w=;
        b=KeoR24kZV5WLhokZBn3n+Iux5AiAfm11cVSOGKoBGK37CWSe8l7L8zODLvYUDiZad0
         xC8WcscDSqaZarODsOCoyp6iN8/qVIUez0gFTqx6LSkLqVHIcj/4rWZfPn2DI103FBSm
         ILpu6qYwOGS6E7O1c0UHmQO2e+HbEHQX6VqfaFR+z4FfTREyH9P2grTbVFbxmrUK+7MU
         9RXT6HQDOrfgLtrFbBwxVvFjc9aXFbYyY9V6Rp6+z4ExXgT54Ok4wUZkgr+deja6dkkn
         of5TUgKcX/ELZVYJ56/GJqDWbmq+l86nLLzWm0uhXwvQKACfDHN5eBm2QVWDcZYtV+tp
         J4/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AVuvUdbJcvtkEgtHydRcnKOH0AVtlTebL0vrKVFgp2w=;
        b=IYNWR0QHorq9f5WzjWqeFwUZEX762TWm/kVekb3lmmnL4IiMkebH1Zm4H+396SmIBl
         3f7p8CsNATU3HiIf8VloEJweSE4VxV2b0xWc3qklUNn3e+e/uEKsC4z1SPFlCsqlglkt
         bV6pOCf0SGjgwsusIrOlFug09+UploImK+2naXYzw03hCw8rqb7z8f5YEAY+8zE6yDSb
         UrUqHXT16VLWN86ewfa9i24OS3JgAz9Ivqy3VDpsNqtn6dibPDvBr0NpcRtrNfS4gMAH
         0GljIjNm6KGNdEXgaok6aj7Son6z/lFB9iFxqoauWHkQlSdhoNmjgSP/2qeCmj5zP5E8
         tLVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532cgjPayrdYM5KKYdlox+ow/txjTnjcFEV4PpG2eh6GVmUuYLpO
	3nMLoqhBDXcYvsF83gjTPPA=
X-Google-Smtp-Source: ABdhPJzvCya0/9LRdEt8o1hdbUbsQFXf1qjCnoRXlnaU6lxiIRdgcMCDDKxEXzN9NLadc75lq9ULIw==
X-Received: by 2002:a2e:557:: with SMTP id 84mr3263859ljf.507.1628780034018;
        Thu, 12 Aug 2021 07:53:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5395:: with SMTP id g21ls725459lfh.1.gmail; Thu, 12 Aug
 2021 07:53:53 -0700 (PDT)
X-Received: by 2002:a05:6512:1105:: with SMTP id l5mr2796786lfg.351.1628780033018;
        Thu, 12 Aug 2021 07:53:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628780033; cv=none;
        d=google.com; s=arc-20160816;
        b=Whj0AoPLgMjGHxtk37hsHydGnWBI6DYQRls+H8H4CP+YBLerJwxb7/WCqJT5Ho3P7C
         fGxjNEXiaUeCp8Ncd+QhuE47eNyjoAZ1iRhBb0Xn4Jwv6ibZCDg5yyv1gHM0R7Kops6a
         zOblpwB9CcOXLDGQa9mGhK5UQpEu8agHaDkrcjYfPB+sbItPTImRxzX3vyT3to1LH6rM
         d3m43K1rn/DY442cFDsp8LJaTcVnv/lfqGjBLWhzvAMsJHDplwWzL++C9R89toWPIzNE
         +3BwecnYFN3/zmZKI1KUwUHoss66F9wSbZpy+4o4806s6Fu5ybCUcVnwZ1nCCnVc1T+l
         okhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=67kYwukmo7Ml3X3ud3b8IvQ8hH4hhd8RmqNx/G1meFc=;
        b=ch1vFXFn1N3osBqcBvRqBpNYO/oAKkSuNpZlHYyhlu7k6mZBHXwL85sEHgydvubQIW
         m51au9Xw3bbixVh+0HfUKl8AkzE11QCW9qKIt/OHwWflAF8cRC62aP5b4Ds2aYL4tkWk
         T8tnUxWp2XuAgIypo2aurXIe2or8fRAIjoDzObDISF/U67r158LEI9w5wYr7I+sVgMjy
         7e13TWOyJLisebtvI/M7uerNUUvCjwpNMzXQZJKTjbOmHXJLXw0FJaf3KjG6BvCzGD2e
         FpUCF3wd1dhr9Tg+V4hKGV9TKGwiHQeIShywuXhNCDzu4DRrqO5cixqIgb5qD5j9JoX2
         eGxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DiwUfvRQ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id a21si115995lfk.12.2021.08.12.07.53.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 12 Aug 2021 07:53:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2 2/8] kasan: test: avoid writing invalid memory
Date: Thu, 12 Aug 2021 16:53:29 +0200
Message-Id: <c3cd2a383e757e27dd9131635fc7d09a48a49cf9.1628779805.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628779805.git.andreyknvl@gmail.com>
References: <cover.1628779805.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=DiwUfvRQ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

From: Andrey Konovalov <andreyknvl@gmail.com>

Multiple KASAN tests do writes past the allocated objects or writes to
freed memory. Turn these writes into reads to avoid corrupting memory.
Otherwise, these tests might lead to crashes with the HW_TAGS mode, as it
neither uses quarantine nor redzones.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 lib/test_kasan.c | 14 +++++++-------
 1 file changed, 7 insertions(+), 7 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 1bc3cdd2957f..c82a82eb5393 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -167,7 +167,7 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	ptr = kmalloc_node(size, GFP_KERNEL, 0);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
 	kfree(ptr);
 }
 
@@ -203,7 +203,7 @@ static void kmalloc_pagealloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	kfree(ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 }
 
 static void kmalloc_pagealloc_invalid_free(struct kunit *test)
@@ -237,7 +237,7 @@ static void pagealloc_oob_right(struct kunit *test)
 	ptr = page_address(pages);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
 	free_pages((unsigned long)ptr, order);
 }
 
@@ -252,7 +252,7 @@ static void pagealloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 	free_pages((unsigned long)ptr, order);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = 0);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
 }
 
 static void kmalloc_large_oob_right(struct kunit *test)
@@ -514,7 +514,7 @@ static void kmalloc_uaf(struct kunit *test)
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
 	kfree(ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, *(ptr + 8) = 'x');
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8]);
 }
 
 static void kmalloc_uaf_memset(struct kunit *test)
@@ -553,7 +553,7 @@ static void kmalloc_uaf2(struct kunit *test)
 		goto again;
 	}
 
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr1[40] = 'x');
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40]);
 	KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
 
 	kfree(ptr2);
@@ -700,7 +700,7 @@ static void ksize_unpoisons_memory(struct kunit *test)
 	ptr[size] = 'x';
 
 	/* This one must. */
-	KUNIT_EXPECT_KASAN_FAIL(test, ptr[real_size] = 'y');
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size]);
 
 	kfree(ptr);
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c3cd2a383e757e27dd9131635fc7d09a48a49cf9.1628779805.git.andreyknvl%40gmail.com.
