Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4XM22ZAMGQE4VPN6DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 21E1C8D18E0
	for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 12:48:21 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2e7bbbd9926sf4135281fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 03:48:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716893300; cv=pass;
        d=google.com; s=arc-20160816;
        b=B4Cq2IQ29GIebk5NLZRbsbluMwuXsio0kk0DEERKCE2coJlqcL25Sl/eQxaAXBZlM9
         n1llhbLAZDmGWmBgaGhF0iuuSfls505QC3NYbx4FdjQZLk46E1lrmCqDR2i88Nz/CP4h
         rD1JlrZkzdMIXaC7KLRrp9hZf27s4KXxxiRYAxVnQKMuoONGc2AD9U5G6PYON0oLSnDb
         eegPGTTqSKmeCBckFjxe2H6yiXWXO5xsHI4GHwJHOADdOgw3it7otH9B01JtHQjcCuqc
         3cYmeS3lGQ+5bMKFmZ1Xzj46obRzyGoEkItvOfYV61KtzoxWc4B6G0FyM4bKVg1rB6uA
         PP4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=KB4bxlQya9jdn3YeJDPbQopy/+zvyxZ8nKvto2uRUZQ=;
        fh=2q7LYY1zL79WVc7wM+EGqCjQ6cvW02STV3Hwl5KhsCU=;
        b=aRdhZULgPYL3fnOeFs2UuvhR3n5X1dUO7kVtNDX4+s7rGjio/QBYMxVUfWJVEGj9Cu
         9AYKkICNHr2sef2tvY1ZijYh9oN0CUtZb6nURJMLagB1vAHCAGocTSOwQJbZJ/tnlT5e
         0aSKnyEOTdSUSpBrQR+qnp9A4XHarHLo3DS4DNJrCpjULUVL205GGiWG/YGmdfjk0hqM
         mvN7Bup6YhpryxBrT7ti+Zv0uUlOYLDzQHwtDYPKWWdTbrryV1Unr4b2Sfx0cBN6I4Bi
         doBDQ1mi0O66DLbJXgx7dE1MhV6BzPxYchcF94hOAauesTtBdfi5cxmbudjfaKHgk9G+
         hzKg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=L1V6ySKH;
       spf=pass (google.com: domain of 3b7zvzgykcwwqvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3b7ZVZgYKCWwQVSNObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716893300; x=1717498100; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=KB4bxlQya9jdn3YeJDPbQopy/+zvyxZ8nKvto2uRUZQ=;
        b=AOZdXQTYWrl1Wb+RUucgWDiD03dvs7brGSLRSCxb6T9GBeOX34qzFGs0hQGsfjV3TO
         8qs/zNcafAEJ+bUARJ2wC/uXK4a78gqThbPJQ0UOA6UiyyIczIVVKqKkT8zhMAtHnIiM
         hv3O43ar59HLSoTiCa04V3wrFk7Z7sQhkwL1frJAJlPNF5nXUtHt1J8tdLF5w+/BSJGY
         UOY8zgq/7owFqbusEMjm+Uz+A9wMbnZHI8sShW6YUd5WGqaM/4yVkutJRIPw+CpK/X4P
         ua61EqN0dmrV7OK5gAraZ9rgRgyCuXo2EaKDYPKotS59A/iyaZ6kqzuR85byqVpAai5i
         H13g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716893300; x=1717498100;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KB4bxlQya9jdn3YeJDPbQopy/+zvyxZ8nKvto2uRUZQ=;
        b=QHy5TwFR9jy66iivVvRLFL6oynhIW4GJeGhBypKC3wJfyxQbXjhq//0xnczXBEsEQN
         yX1ttF37bllja1txsqZFzr8FQUeyunsvmzF1vC99Lbsty3cXwkKyRSGaDRFQVGmDudqi
         bQCAc1BN8lR8mBHyBrwCnGG4iw8sDVvc+Lb98OSiR5algq1vsKFbm7seqbBAZ1Vku9SN
         ip6R+IHbuh3vCQqgNP6db8PCRSzcwha2/DGMatGjRw4e3/qHWEjjxk11ijh81gohbit5
         7kwSVyUcGSXnS7CMGu5gfgl0o7qXNwYU9ekdcIT0NnsNZ/GNSw8IQ5wt1GvOc8xp5Pkm
         L+qQ==
X-Forwarded-Encrypted: i=2; AJvYcCXoqZJuV6Y+ybJ26R0a/FJ5Yqjg1L/vu7ArwQdX7q8xfJw937NMlXQglXZnwte4P6XlGJYczHjd7WHB6XV8d3w9sxtJe7B2pQ==
X-Gm-Message-State: AOJu0YzfV6DLa4hwQbPt7EER1Xg0F1pKzvJzwDeCQVbRgbNwVdbYrYa7
	FKMwF4jk2ErDI+ORukHjdlW/gGcuajOm0+C9fsfO3ET3A7Omlo8/
X-Google-Smtp-Source: AGHT+IFTyRFn2nyKBe6+Fg+z0qAQojI5ZY7HPrrI2M8eppuzx6K2rNPg5HIIjrrI7aZJZKqIuv/kqw==
X-Received: by 2002:a05:6512:ac7:b0:523:8f4c:69a with SMTP id 2adb3069b0e04-529a68c96aamr9919283e87.5.1716893298868;
        Tue, 28 May 2024 03:48:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2245:b0:51d:4506:9289 with SMTP id
 2adb3069b0e04-5293090c50els122799e87.0.-pod-prod-08-eu; Tue, 28 May 2024
 03:48:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU1bpA4Nc+JQTJ46S33sMYIQi64ZnkXVcnys6EOpP69xs4X5jjX+uq5fzbvS/p8HeIc23pf/5bpMfAn/50qoDtlMSi3RCRbPE5dcw==
X-Received: by 2002:a05:6512:224c:b0:518:c69b:3a04 with SMTP id 2adb3069b0e04-529612c0598mr15653670e87.0.1716893296709;
        Tue, 28 May 2024 03:48:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716893296; cv=none;
        d=google.com; s=arc-20160816;
        b=ghG35ytbnOU8ctaS5qbWdUzRNWX0NQTWYmASnXLPUHnAYOwUNwAV+xX0DEQOzUEbcQ
         qTOFV4ck030+eBjQbFlZpwY9H6ypBGJ6+iW1VDVsh797PVvnZy+srE9f9t/9StrUVtU2
         CQiLkUkwwFggg5ABx/rCCChJhdBbjHoBixxn2LfoZb24VnFUmGajtE6m8BajgkCc2Uqj
         uJmWsbi/oRuOYyQqTz7lYcimY8KE/3Kg7f7dH5yVuaBMKxDLDVWPIbbv1174AaVai/Xk
         xRyd+/uZqbFw0XwCUVqrec4E6O1daBFDwHPvMoEO4dM8/yvDgpx0tPxy+f2qvayCVDJp
         gT/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=RTgy0iA5o4eiMLkf5DZA1XVIVBf+wcR0MiDC6AwIp5o=;
        fh=uOiW87AZFDAHxQLjGc4CH5X+kz5q5v+rIsluXnHhyPM=;
        b=HElKvSfhyn1SFy539+ZI+Hzy7FeB04vCCGTRwoeBGsocQWt6qSd/E0MqoaCC604w88
         PzV3z+ynFOHTWcwV2i0gN/Uh4A6tfpW2ngsBj3Mex/ji3bRGzzLVPkN7Gbq7dmYPFtvh
         uRgwyKO14lxPsyumbosCj7jfxDQhXI2GfzGkjDQjBVIdSLoFYVYnH9oQPUyd+kaRyC8L
         TfW0Y0XEBqO5iP4JP0y4PqhZ1ovdgswJvznU+uyfEXXLidHureyC2ifrjfvxAmhEwQiv
         NifvqkOYILzpVz6hieRbHhExA0y4cOjEKvZBhY1HH1Xj4G4NG8G2KQYtWtqcR0PxOMek
         oHEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=L1V6ySKH;
       spf=pass (google.com: domain of 3b7zvzgykcwwqvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3b7ZVZgYKCWwQVSNObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-579ccd806c9si101906a12.2.2024.05.28.03.48.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 May 2024 03:48:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3b7zvzgykcwwqvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-a626603837cso35586566b.0
        for <kasan-dev@googlegroups.com>; Tue, 28 May 2024 03:48:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVBBFN4QPHAIklw7MiVxxWsiA1EpDBWVnFVpxGDlv1DhGk0FH5AxYMJDO0AM/uH7vvixpz0zRetKXoYD8irvt1t20Gh11kuVLhEpQ==
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:6416:417e:596:420a])
 (user=glider job=sendgmr) by 2002:a17:906:478c:b0:a61:9678:91e2 with SMTP id
 a640c23a62f3a-a62642e76e2mr1061566b.9.1716893295944; Tue, 28 May 2024
 03:48:15 -0700 (PDT)
Date: Tue, 28 May 2024 12:48:07 +0200
In-Reply-To: <20240528104807.738758-1-glider@google.com>
Mime-Version: 1.0
References: <20240528104807.738758-1-glider@google.com>
X-Mailer: git-send-email 2.45.1.288.g0e0cd299f1-goog
Message-ID: <20240528104807.738758-2-glider@google.com>
Subject: [PATCH 2/2] kmsan: introduce test_unpoison_memory()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: elver@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	bjohannesmeyer@gmail.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=L1V6ySKH;       spf=pass
 (google.com: domain of 3b7zvzgykcwwqvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3b7ZVZgYKCWwQVSNObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

From: Brian Johannesmeyer <bjohannesmeyer@gmail.com>

Add a regression test to ensure that kmsan_unpoison_memory() works the same
as an unpoisoning operation added by the instrumentation.

The test has two subtests: one that checks the instrumentation, and one
that checks kmsan_unpoison_memory(). Each subtest initializes the first
byte of a 4-byte buffer, then checks that the other 3 bytes are
uninitialized.

Signed-off-by: Brian Johannesmeyer <bjohannesmeyer@gmail.com>
Link: https://lore.kernel.org/lkml/20240524232804.1984355-1-bjohannesmeyer@gmail.com/T/
[glider@google.com: change description, remove comment about failing test case]
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/kmsan_test.c | 27 +++++++++++++++++++++++++++
 1 file changed, 27 insertions(+)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 07d3a3a5a9c52..018069aba92be 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -614,6 +614,32 @@ static void test_stackdepot_roundtrip(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
+/*
+ * Test case: ensure that kmsan_unpoison_memory() and the instrumentation work
+ * the same.
+ */
+static void test_unpoison_memory(struct kunit *test)
+{
+	EXPECTATION_UNINIT_VALUE_FN(expect, "test_unpoison_memory");
+	volatile char a[4], b[4];
+
+	kunit_info(
+		test,
+		"unpoisoning via the instrumentation vs. kmsan_unpoison_memory() (2 UMR reports)\n");
+
+	/* Initialize a[0] and check a[1]--a[3]. */
+	a[0] = 0;
+	kmsan_check_memory((char *)&a[1], 3);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+
+	report_reset();
+
+	/* Initialize b[0] and check b[1]--b[3]. */
+	kmsan_unpoison_memory((char *)&b[0], 1);
+	kmsan_check_memory((char *)&b[1], 3);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
 static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_uninit_kmalloc),
 	KUNIT_CASE(test_init_kmalloc),
@@ -637,6 +663,7 @@ static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_memset64),
 	KUNIT_CASE(test_long_origin_chain),
 	KUNIT_CASE(test_stackdepot_roundtrip),
+	KUNIT_CASE(test_unpoison_memory),
 	{},
 };
 
-- 
2.45.1.288.g0e0cd299f1-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240528104807.738758-2-glider%40google.com.
