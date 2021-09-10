Return-Path: <kasan-dev+bncBC5JXFXXVEGRBQ6I5KEQMGQEASB4YWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B5B884060B1
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 02:18:12 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id t12-20020ad45bcc000000b003772069d04asf548096qvt.19
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 17:18:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631233091; cv=pass;
        d=google.com; s=arc-20160816;
        b=oyYljGNBx/5/SNe3Su1lNTugzULdBadqzySnNcpQVpoIAOWKXVoixpGdiKuFqsy4wS
         0YUj6HOb1VKvjfEgIFNfwxlN42gezEEmatCSnpq7y9YiFpEmls9DgrYXNORl4yZZeGkR
         yaU20tjrBLCBdGwiJixqqTLBRxxN7M+rlHcRJmc5MDDU/grXPHyqLC+Xram0sn8cB2bN
         h+ur4lWn+0es/cbYk5wOakLczhwCcOV5ToBfKlO1iafhVCDWQGvP1wbgre8lozz9tepq
         eGj5OUQkgZcUgykUKPapGiX6PgSFUvQYx6pHbhN43Ctx5F/C24Z57fYrqVqRtvrbd30I
         kO8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QIImFq/8hA1neIIiMwiabgr0FYr6SwnqBSf2XZ3GrBU=;
        b=KFJga+3A6zYE7ZT/4kVOUdfaRcWsbSD7dztYXgkMFOZgd6+glH6zSllIoNMe4cRM4t
         K7s7FYAK50daWtaVPbc1bTlFae9WEw483PLcg+dT7iJ03cvyQhh0aZ6W8zSgJ0vMg7Rj
         7pNNOsF35ybO+Ru9A9/6eKSN0Oq5YyWjc+ETzRP/aWBxAFGdosLRu+oC0GaMOohZ8NCb
         Qm5k77KWj146DydrnQDDsBq+qwZ8qF+xmeUmZ4xQx/q4uqu2xxWSZ7muQ78C3eeui/Qe
         P27zfmUiS85fhN0fb0BxFECz3OC/Y+Y1yN+9jiYSzzXnC6UJh6FaOuHtq0n1ZNy1lYIp
         fgYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Vr82t5lw;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QIImFq/8hA1neIIiMwiabgr0FYr6SwnqBSf2XZ3GrBU=;
        b=rQFYODk26tWahhlxGCOd68oAJG9wMr04OOMEShdXGK4EQA7ubz3bT3Bl2wKrGHqEn6
         nxKX3WEqRo9QbgSxblQKK68fIIIW/JWOZ2zZUQHoZQLCCd0T+BW+sUA8W9g4ndGHda0b
         Tgqi1V9Rt4OnWw0X85o6ydXGarWRnvqO6B3J8+PfXgw5LulIrS58Kmi6e39FGfMlaiyS
         QxFtmuM2RbDnqaZypTj43CyuPVDNNKsHaC6bdumVtXRHtE/vtDw5hXNbl+jbf5vELDaZ
         mrLsmfkh/9NLPg0HnLjUeIqRDMqpE3JViP3VDj20r200DrL59mYLHgQhaQCp3l9Z5tKu
         okqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QIImFq/8hA1neIIiMwiabgr0FYr6SwnqBSf2XZ3GrBU=;
        b=SO+4GL1WR7XLFEnQwrtnL05Au12Z4C15+3bO02KPjuP0kXHm3CORZzVQZMac22uQXR
         K+tToZbgtSgqDl4huWj+c+Cat5XIkfpKNu35qLcuwwb+z7u1FfvljC4qDtoj3GBFz1BG
         G9DN/Sh0eFENE5+fyNPTGdPmi8vttxyMlLs+4uL4yGrEcRss7SbGpTIBFf1Ivdy24yIO
         z/jIpq89iU4865zhf1i9DEo4pFu0pTDWl3tuU8qwX2lzFuNDpXiqAVYOjWQSAZs/wtdG
         +RLIPVOLsVaBG9JBHGgFhcYAX6Ng1ejd+p74auzRiNDHU1FAJTca9AnuE4YBbLa52z1g
         MVKQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531LuhYbTMhcwsiT8/uO6T/wzgohxbisXbuTugcYbFvtpSFAK5Pz
	3xjI5JnmfOZpOYYSnSDrZE4=
X-Google-Smtp-Source: ABdhPJzlPGKV2AhhZvh/MUWIpGrJbqciul0/ZKgNkV67mujoH/rvnQHLDZIR/cFQCYTM+EZV8rv5Rw==
X-Received: by 2002:a05:6214:6aa:: with SMTP id s10mr2821558qvz.56.1631233091725;
        Thu, 09 Sep 2021 17:18:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:710:: with SMTP id 16ls2578472qkc.1.gmail; Thu, 09
 Sep 2021 17:18:11 -0700 (PDT)
X-Received: by 2002:a37:f909:: with SMTP id l9mr5466247qkj.512.1631233091240;
        Thu, 09 Sep 2021 17:18:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631233091; cv=none;
        d=google.com; s=arc-20160816;
        b=e6jKZWDoHbZwAPEijuybMMEC04DwgdBVdYP64uOKyEuNFicr0eydkXGx9oRa7Up6vo
         9o2M2ddy7gI+pdVi+6LvLkKMebQeFAJL5AMhWFHc3rzUZoTAB7qcODF0OBtaELLFyMVQ
         RDtu2GF3U8Kc7u7Vru3cfvUYo3kspr7C3mlwBCCkTXk37Axzehnwh91pdhM208zCs1SY
         R7dSD7i4J1G0KvHhmanGEVS7Gvt78NVi6QrqyqR+pXsnduZbc4AjPhODR0REdUVA2Jbz
         j9dt/Dk8QDTh/ctRfGfxRLskCa7F11GledweJzF37kuKv+e1yR6+jppVL9B1vxWMS4i/
         MFEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6Co1g8f/WeNo1X8/ugGoDWovcQgCtZ2URH/QH31L0io=;
        b=DOroSnvBXMnDdGmsQQ+FKeUVpkCC7sGi0hUTfd90bAOSon1vY6oU8CBhNjihs7WgTU
         Twyuu4hjqBsfjKtbbNAxMKdI7UmkyhSkQ64DVDyflY0lUVcqKAEAfdaXwjNE/ntBHG36
         lVLYfmHXa9cVDWNfUE4ikiAE8aJSYCZoXTLv0hcgrcxlvhyfhpzfiEKsaadfqBVM5D1J
         SYcU84nUspv//aPLAPyyFG62jd+FOt4KF5AOni6AGis0a0KvY7e/msYDnTMfuj8d0F4F
         sEOAVD98/t6Sw8+sHRAqM4anCvY/hw0+5geTYE4qoBfycDawgs+XdhZPW4dgX5ROynL2
         JMGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Vr82t5lw;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 6si253048qkh.3.2021.09.09.17.18.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 17:18:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 1FF506023D;
	Fri, 10 Sep 2021 00:18:09 +0000 (UTC)
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
Subject: [PATCH AUTOSEL 5.14 94/99] kasan: test: avoid corrupting memory via memset
Date: Thu,  9 Sep 2021 20:15:53 -0400
Message-Id: <20210910001558.173296-94-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210910001558.173296-1-sashal@kernel.org>
References: <20210910001558.173296-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Vr82t5lw;       spf=pass
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
index b261fe9f3110..b298edb325ab 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -412,64 +412,70 @@ static void kmalloc_uaf_16(struct kunit *test)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910001558.173296-94-sashal%40kernel.org.
