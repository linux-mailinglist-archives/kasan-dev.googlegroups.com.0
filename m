Return-Path: <kasan-dev+bncBDYZHQ6J7ENRBSWY4OVQMGQEDGJCY4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id B67ED80FB5B
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 00:27:07 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4259c8e6ab7sf13717441cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 15:27:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702423626; cv=pass;
        d=google.com; s=arc-20160816;
        b=nKD+Oa5GuoYpvWt8qjWNJy2gsKxE8MHs8rVJaStu/jPGBMYhImojx8RykMf8wWIHeL
         DJDEn+LfXmKq+7Iu1gOJmhSo2V97ZEc+Yhl03osgvR6ZjWLEr5CM1jNaOnWGbcg6oxJh
         1SyM7WkEgXnHnn2yJMrHaPpLtQc22qcZRfsoy6Qn8S0IV/qHFIZNUo7Op6gb2AaQD6EI
         zB/7yyz6UzWtOH2F9mgYYZAuX2r8pXeZvR2bVJuAsvwRgyULhKq71nnXHVHoVOfMGUyS
         GI8wPG6sRQWCdLtEJjFQjRehHqRXajxLkrDrXoQhBof+GHGobTYFnccOFwHNryC8f/Db
         h6yA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=cUxpQ+T5CpBZTsThDqrJoTfrSDsdjQesmGaW8rtj/Zs=;
        fh=t4pyiPcCBIC9Y+5xkCTP+ifpPVuOKc4r2DwOkdw1hDY=;
        b=zFF0903RMwIQyUmxkrWdhLPkh7pzpSp3gvhB7yCsNy9Eq5MRjgDEhXgyVrbRjpNmDY
         aJHQhpHTLuqKn4TQdLNnqE32CIVv4jBxF0ji/23+p7xyz4/KPDSAs7b/gVQUCwt3ybsA
         PdBP20X/38zAMVOXhFl2sTCcy7qUcx3PePK5vvDjc3GPmUeK8iWIzZGnZJ8OKKeurav6
         QS9HiNfXyE5xA4AwXXopLH1fS0Y2o7pxSvXr38AvH/wo2Urnrb8z60qreGUAhAwiBEjq
         wdBiXludn4GSMkgeo0vHLkYilniRygX08vFXOMLlrBBhqMZGClOX9ahI7wpSMBVzg65F
         nhgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GoGurWP1;
       spf=pass (google.com: domain of npache@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702423626; x=1703028426; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cUxpQ+T5CpBZTsThDqrJoTfrSDsdjQesmGaW8rtj/Zs=;
        b=dw6aAhDdhAnNUj7w5rZsQJ+byXUu6qT9Ik2o4l4jz/E4ME3GZqdgqU9enVxGGbmvGm
         4OB8OhLDfrElYp/r1txoIzzz41mGZWy6gUXNQPMShFnCHQVduJQG92FMqPZlPMVE7kTN
         mXCtEhG8l883sBjbMVYntxgh9XZ5X7GfBdJNh/QDHrUIasei0EyppXUm7UcSg6nbrhay
         na2NeziJrY++ltEX22SwwnhCiXKLltN1kz6/9AtDsuw7wP9rfPjZvKdGqnmUrMEBH7gb
         8xdu1C1LAYi+5WuLPKV/Jifgia11Nr9JiuCNpt67MsXvGiynQu12/0RQVR5PzuyAEEBd
         0BBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702423626; x=1703028426;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cUxpQ+T5CpBZTsThDqrJoTfrSDsdjQesmGaW8rtj/Zs=;
        b=gc+UnW06QjaQqtQMawIpVifX/+K8ZSS/89WE+rSAu2H/vO5qe8dAxnpD69gARzP2+B
         qgmmG5BXzWxETzrN2AGLLAQXW/ueRRqjsYDcqhDMCkiFHLgxulqJPICRQsEH/fQIacgR
         C+7kQtDPSjyMuqPz5QTq6pyWh3oKxFw2RTv7ZdkeVMLFFdZ04oDj/6tADK5IvJDeiHEb
         uGbI9G6BZ+Ek6YLvrhoJO0dpF9opvF+kOE5uJIWflBx2jX31VXkyk+4CirFHnVhBYiBU
         K1QWcFJXq0zIZA8xj/3/EWzWRU5KPDP26QgvTk9yhYb7xZb7n1KkQ8jieV5pJSPdQxOS
         zojw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyy9srCP5mWOGplAnhANfqhcwX8G8jIEDa8wVNm6DTa5+HUVLAD
	zD4MrubxagscE+taVI9GNJY=
X-Google-Smtp-Source: AGHT+IHBPAF24SCd5jQQt+WIrfQw4/VCpCzjxjP6kEAa4LL2HasgMGpJiRptogDMhroX6WJqZldarw==
X-Received: by 2002:ac8:4249:0:b0:423:dbbc:aab7 with SMTP id r9-20020ac84249000000b00423dbbcaab7mr11790660qtm.1.1702423626360;
        Tue, 12 Dec 2023 15:27:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7c44:0:b0:423:8463:9511 with SMTP id o4-20020ac87c44000000b0042384639511ls1458121qtv.2.-pod-prod-00-us;
 Tue, 12 Dec 2023 15:27:05 -0800 (PST)
X-Received: by 2002:a05:620a:1364:b0:77d:6d6e:f328 with SMTP id d4-20020a05620a136400b0077d6d6ef328mr9326066qkl.5.1702423625660;
        Tue, 12 Dec 2023 15:27:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702423625; cv=none;
        d=google.com; s=arc-20160816;
        b=WkpLsbBTInRx4zc4KSz2ADGTGoEYStQp7Nd8Ixy/scXR1VCiKhFWxncaol7kk5wUA6
         SY6+S+5q/VRtda/IGg7BU85y55HQF858GASOXukQY5hXWNICGP5/jJAXZ3J6IWMcxN4N
         jXi3okwJ7GwVRJ1K2971vyESdbiHNFI1Uz7D8gqNMouER74DWogClpbq3HLyp82aezPb
         8rpFqnMBKpZ8QVdvInqD0P+xF+kOJeSLVGfFgQ5lpArpecOXTQujo84KMNMUEst/0OrJ
         CfnHt21jKjh6fSVD5qj9ayXP1/exRvbd0oFelwtL+QAxWlsiurSGEuqMhgyCQ2TnOjlO
         lEYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ZwFQ3GQCbPFAax8NUohZK89OPMuLW9MEl5mvS51Lzts=;
        fh=t4pyiPcCBIC9Y+5xkCTP+ifpPVuOKc4r2DwOkdw1hDY=;
        b=XO6tA9nUEywNWddeOEVwIR1W7gDPWcPepYN1s9TCdZ7G1KsdJS4skQm/VGdqlV294Z
         E65coLxg6Z6QTLpusrs/YqIo/okwxnY70CLjM8x54HgD135gqzkISOXYky+LIon+ayri
         f+JOVifeVmMEpleDlx2PcUNu1TX0cE9LCG6DfmatyVsijQ2sHBKkWxyHfVW0XtP862/b
         pqXcPePqn6vIoDpTE6E42u6nToyZT5JyGR05UD7Ny6l3E1CmYa4w7jF+JCN7aR7/Yqtc
         jmeO+JWvnJ1Vq4I0A7+VY/zXxnJg8Oy6aGCkIhhqgLy5qOXYFCEUssN8PHusEiz8c5qa
         NjRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GoGurWP1;
       spf=pass (google.com: domain of npache@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id b11-20020a05620a270b00b0077f0dcac143si720024qkp.6.2023.12.12.15.27.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Dec 2023 15:27:05 -0800 (PST)
Received-SPF: pass (google.com: domain of npache@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-45-6YG-K_zxMJKQP8zTqBW2aQ-1; Tue, 12 Dec 2023 18:27:03 -0500
X-MC-Unique: 6YG-K_zxMJKQP8zTqBW2aQ-1
Received: from smtp.corp.redhat.com (int-mx03.intmail.prod.int.rdu2.redhat.com [10.11.54.3])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id 4552A80BEC1;
	Tue, 12 Dec 2023 23:27:02 +0000 (UTC)
Received: from localhost.localdomain.com (unknown [10.22.34.149])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 800551121306;
	Tue, 12 Dec 2023 23:27:01 +0000 (UTC)
From: Nico Pache <npache@redhat.com>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Cc: akpm@linux-foundation.org,
	vincenzo.frascino@arm.com,
	dvyukov@google.com,
	andreyknvl@gmail.com,
	glider@google.com,
	ryabinin.a.a@gmail.com
Subject: [PATCH] kunit: kasan_test: disable fortify string checker on kmalloc_oob_memset
Date: Tue, 12 Dec 2023 16:26:59 -0700
Message-ID: <20231212232659.18839-1-npache@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.3
X-Original-Sender: npache@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=GoGurWP1;
       spf=pass (google.com: domain of npache@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

similar to commit 09c6304e38e4 ("kasan: test: fix compatibility with
FORTIFY_SOURCE") the kernel is panicing in kmalloc_oob_memset_*.

This is due to the `ptr` not being hidden from the optimizer which would
disable the runtime fortify string checker.

kernel BUG at lib/string_helpers.c:1048!
Call Trace:
[<00000000272502e2>] fortify_panic+0x2a/0x30
([<00000000272502de>] fortify_panic+0x26/0x30)
[<001bffff817045c4>] kmalloc_oob_memset_2+0x22c/0x230 [kasan_test]

Hide the `ptr` variable from the optimizer to fix the kernel panic.
Also define a size2 variable and hide that as well. This cleans up
the code and follows the same convention as other tests.

Signed-off-by: Nico Pache <npache@redhat.com>
---
 mm/kasan/kasan_test.c | 20 ++++++++++++++++----
 1 file changed, 16 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 8281eb42464b..5aeba810ba70 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -493,14 +493,17 @@ static void kmalloc_oob_memset_2(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 128 - KASAN_GRANULE_SIZE;
+	size_t size2 = 2;
 
 	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 1, 0, 2));
+	OPTIMIZER_HIDE_VAR(size2);
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 1, 0, size2));
 	kfree(ptr);
 }
 
@@ -508,14 +511,17 @@ static void kmalloc_oob_memset_4(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 128 - KASAN_GRANULE_SIZE;
+	size_t size2 = 4;
 
 	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 3, 0, 4));
+	OPTIMIZER_HIDE_VAR(size2);
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 3, 0, size2));
 	kfree(ptr);
 }
 
@@ -523,14 +529,17 @@ static void kmalloc_oob_memset_8(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 128 - KASAN_GRANULE_SIZE;
+	size_t size2 = 8;
 
 	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 7, 0, 8));
+	OPTIMIZER_HIDE_VAR(size2);
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 7, 0, size2));
 	kfree(ptr);
 }
 
@@ -538,14 +547,17 @@ static void kmalloc_oob_memset_16(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 128 - KASAN_GRANULE_SIZE;
+	size_t size2 = 16;
 
 	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 15, 0, 16));
+	OPTIMIZER_HIDE_VAR(size2);
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 15, 0, size2));
 	kfree(ptr);
 }
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231212232659.18839-1-npache%40redhat.com.
