Return-Path: <kasan-dev+bncBCF5XGNWYQBRBM546SFAMGQEW4Y6W7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 992EF42369F
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 05:55:32 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id 76-20020a9d0152000000b0053b372910bbsf786958otu.14
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 20:55:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633492531; cv=pass;
        d=google.com; s=arc-20160816;
        b=XDgBgxt0n2TEkRwlujNBP70v16lrO69Atbc2Ui99oA6KKC9LXm2HViD92kbdRPIciK
         jdDxj61hQqihpFJQ08dPU8mU1In/AJ83T0OoAarTP7v9Bt6u7+JYCDe1KBlgKY4tu5qa
         jsf9imrZGgRpiD0iXQ7u037YZM7tnTAZ9RuzNxYMdElHlTg/t0W9nuTLb57NGvbWlBp6
         u9gXOruDetcXTLDEi9StYwYiLDxfMP10tZ7XF6t39pJ0NUFwCAzxl/IYD/bV21DUQiph
         jPUdilArxUHQwExePlrZpNccYQmYIDK9R4pnZuUZ0NdTZvByPk7Ry1XcNxyPFm4RDIXq
         MTUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=blicjtg5UrsGveBJTlybuty2eMcKpD/5QApvqWcif/0=;
        b=ukUTa7TzLMKARumBOMD1VadLjzdGoQnDfOaZWXrY8ZXR9X9mzB2UaiTVst+YBbaNNg
         wsg/GYqZ/TTa+vyJv4ROZS/T2I6jfikzzMNnOtb7/8Odxj7fyn5oakTdGxUR0T4zv4cG
         QHLWU/dQhOGM9V2SObnPJ2UEhWd0Phn+0Kizz3u1h2klQzcRcdChTnpB/6TcW0X1+mFR
         QV+eRZUHXYBtGhtg24CjuYK5K3DP7gPw9/5WYZ3FO0TMb8qVStcm0oTynUT6kglax/vv
         XDoDvEfm0hzpEdeFCvvZIYlwaQJtTFtkhnwr+P/ogMQmIwOGbKJnRFEum6BLXe+A7RND
         7yWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="e/eBlfdA";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=blicjtg5UrsGveBJTlybuty2eMcKpD/5QApvqWcif/0=;
        b=gFRkjBpKzMuDO/4DWW0R2jACMqwcxtx1gG3KpMXge/zV3aKZKfkAnmOUZMNxWuEO5o
         tF+ketR86n3C/0mVmEMGL8C+F9KZ1IXyRB6+fThAzGWmIjJfnUL02HDXzvC0cI1XZq1i
         SWY08SDAoKd6UYnCWs3uM9Cfmlpeivuoc4nKYzVpdVZZuao86VzKopqeMk6xFdEyWsRo
         tqPcPmQucrQM98byYCL9gk8cokVNnwesBygoOPGMwEeqcK/OHmlFRtZ1o4b/CWYNM4sc
         AZCpmi0TVVaGfQ5eHiii2oenPQCZAiTdmijQuLcv/BfE+VXpNH4R1KXn/rsZcgUXeqoS
         tOOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=blicjtg5UrsGveBJTlybuty2eMcKpD/5QApvqWcif/0=;
        b=xuFRGwftaOVFUn5zSbPP4/sd0EbTCV/4CLwQQiWd/M5ylBNRUkzMvEQIKlRKRm/3C9
         rb+yiX4syPQLC0NlPq977LgLmIxAMJFrK3EJ/8rkPS9beLWAFltNiH+MmZV9FI8ZO3hH
         DpUFDWAn5Knef1O6kif+QVG4+3XwJqeiicK7/IOGSzCa6Xr3ZBFgl7oyaT2cAuvsy54Q
         Z3PWRKvBICiOz4kJQdGrAejaz+3DeVnyz5eC/WIwPvVKVIUm/5/JwUAIFuPXHtRae2ur
         0zkUPm39SyP8Zsvh75IhcuA6UdnbJfJqKIH2ZzF80E3tz1QxLVskPym0xhg5Q4HIvGAo
         peHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5334fuHz9WLABrmHkt4ErPWx6XXVY9Fcs0f4Tl0dx/AC6MKgPFSS
	MZkGQb1HjyA/RL8DhZwexjY=
X-Google-Smtp-Source: ABdhPJyT5KUraGkVZ+6FGOHTnTKdVzhGkEXFe0QlmGCV5L+HyGQ4OXm7zR5qko1vuuBV4XX7S4jRhg==
X-Received: by 2002:a05:6830:2805:: with SMTP id w5mr18017960otu.248.1633492531427;
        Tue, 05 Oct 2021 20:55:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7257:: with SMTP id a23ls3358166otk.1.gmail; Tue, 05 Oct
 2021 20:55:31 -0700 (PDT)
X-Received: by 2002:a9d:728f:: with SMTP id t15mr5226551otj.247.1633492531065;
        Tue, 05 Oct 2021 20:55:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633492531; cv=none;
        d=google.com; s=arc-20160816;
        b=IUvLVzOslG8/XRRyQA/1xiS5ehmtWRZBwgQCFrTTZFVP2KtbUMBprxthlTYtVz80ST
         NhiYHtrdP8Z08oBPom+49hMX1FVriUGZGTHpy3P0a9l0Aa2ydM//Klx+k/gFiJ68eaXE
         ppfVpHlsa0ahT9jTNEqqg+c3QylfB9q+nI9Jma2ZwaLP8dT/USKvm1KW6jMkm55ANFYr
         ZwmFE5KVRxNFsrvbg8BtwZJELbh/YgYYtmtw/4KDVwxsXhTTFtH4UquNJazbwTwu62qa
         naL+knkYcZeS5NpECAa/stJz31y9DeKSKirAU/YSCPlbAF9TXATgecQR0v0zt+/TJELh
         TFww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Jm638j1gTfOkeKJqLpDPeHPNo/d/3pdWvH0ndHGkMeA=;
        b=ICUkajSF22zMr9SEA0wJjeXi0felEUb6SG59/lnCGAwcTdx0rovzbUZNQy/lbE7gM2
         Sj4bdEYkgWxOHtrWWOFFnFt6CYTXAytRkLI+29mpi7byqydH/FPl9ZawBRyUphltTgNd
         WobfT6GBfl3tD75uX7sx1FLOKi0WuIgwNc82qB4XHv2fcUZ1CLO1ylyLYbG4JG+dxmOp
         9Jk1qo1DlJvFWibLmRt43otgU2cpz1gctbiFbz4M1jdp45THpmFZ92spjyBFyzTQDgUL
         ZkJ7OZeYalugHcpP+PkEUJ8KARtuwPSDOD5FMKkZ+P0aSmsqR39ERnUpDCQbJUhdQnJR
         FZ5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="e/eBlfdA";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id bf17si1749304oib.5.2021.10.05.20.55.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 20:55:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id v11so1245094pgb.8
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 20:55:31 -0700 (PDT)
X-Received: by 2002:a62:52c7:0:b0:44b:d8b4:4b0f with SMTP id g190-20020a6252c7000000b0044bd8b44b0fmr33718189pfb.18.1633492530591;
        Tue, 05 Oct 2021 20:55:30 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id a13sm19071350pfn.24.2021.10.05.20.55.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Oct 2021 20:55:30 -0700 (PDT)
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Kees Cook <keescook@chromium.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH] kasan: test: Bypass __alloc_size checks
Date: Tue,  5 Oct 2021 20:55:22 -0700
Message-Id: <20211006035522.539346-1-keescook@chromium.org>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2968; h=from:subject; bh=xz5c7mcxVXMgC6PuWaLiQPhsapFTq50WqH+V3y1vybk=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBhXR4pBfwWQd8BknEyuHsNzKL6EJMMJ+t/5lz+naGR ScRhzoGJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCYV0eKQAKCRCJcvTf3G3AJrv9EA CiIWV6+I4NncSuJkGCnCGlkPgyk+p7UqmlqsrmltutvhV2n1bw+mbrK83AMOTZfaC2ekROwo8akZ2n C5WDN1UlB/xVK2nV0hDIzRrx/XIuaGAVmqxe7aHQqavhhSAKX1du9cDdyZ90qvNfiJeniohemF9uP+ 8HuDY1RmD4NzD9jnf1h6+ejU331PSf8KUnVRGW63LtkZjCihQ0mA82RMWwpPtInfBYY+bMLnq0vNM8 aBWXizmrHJ176+HSnCdPkHnrE28TRpdwBJG44bKKR4xN5iGtURhER/tIKxqwLKV7T4M7Cm3jjmcWE4 hcN/7Zj/7/GvEOh0zx1QlFn5QBdC3q+KIfWckr0W3bXSizFJkDxgobfjnpexR0JDLXD04kNHIo8AdQ /tcAJfkWaBivfGt6nDzILjo27rOItHRR7SCUKDzpfkJnHt5fxcxfEZCLdMjgbQkYybihKAQQRdP4t6 28ZEAWyyqV4cPyEhrzqaUz8Kqlx5HH1fIInuPBrQq2+skTP74P5UODMHaYgNF4Fj9azNBjNrjZiTqT Vc9Lr7CFZ1PMtpme16WeylGmaLYLn8JJgKeEGZG0DY00pUvgLp/+YRt+xmquCs/N+xT+VaiLTYJp6U drmg7+ypID6pwWPX4SG7yineg2jJBvLoAnb9FDBZemTG2ga/jkun60uDIUVA==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="e/eBlfdA";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::535
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Intentional overflows, as performed by the KASAN tests, are detected
at compile time[1] (instead of only at run-time) with the addition of
__alloc_size. Fix this by forcing the compiler into not being able to
trust the size used following the kmalloc()s.

[1] https://lore.kernel.org/lkml/20211005184717.65c6d8eb39350395e387b71f@linux-foundation.org

Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 lib/test_kasan.c        | 10 +++++-----
 lib/test_kasan_module.c |  2 +-
 2 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 8835e0784578..0e1f8d5281b4 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -435,7 +435,7 @@ static void kmalloc_uaf_16(struct kunit *test)
 static void kmalloc_oob_memset_2(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 128 - KASAN_GRANULE_SIZE;
+	volatile size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
@@ -447,7 +447,7 @@ static void kmalloc_oob_memset_2(struct kunit *test)
 static void kmalloc_oob_memset_4(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 128 - KASAN_GRANULE_SIZE;
+	volatile size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
@@ -459,7 +459,7 @@ static void kmalloc_oob_memset_4(struct kunit *test)
 static void kmalloc_oob_memset_8(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 128 - KASAN_GRANULE_SIZE;
+	volatile size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
@@ -471,7 +471,7 @@ static void kmalloc_oob_memset_8(struct kunit *test)
 static void kmalloc_oob_memset_16(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 128 - KASAN_GRANULE_SIZE;
+	volatile size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
@@ -483,7 +483,7 @@ static void kmalloc_oob_memset_16(struct kunit *test)
 static void kmalloc_oob_in_memset(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 128 - KASAN_GRANULE_SIZE;
+	volatile size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
index 7ebf433edef3..c8cc77b1dcf3 100644
--- a/lib/test_kasan_module.c
+++ b/lib/test_kasan_module.c
@@ -19,7 +19,7 @@ static noinline void __init copy_user_test(void)
 {
 	char *kmem;
 	char __user *usermem;
-	size_t size = 128 - KASAN_GRANULE_SIZE;
+	volatile size_t size = 128 - KASAN_GRANULE_SIZE;
 	int __maybe_unused unused;
 
 	kmem = kmalloc(size, GFP_KERNEL);
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211006035522.539346-1-keescook%40chromium.org.
