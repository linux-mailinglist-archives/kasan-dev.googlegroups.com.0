Return-Path: <kasan-dev+bncBCJZRXGY5YJBB5NARKFAMGQEK4LQ5WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BA0440D0E4
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 02:31:51 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id w5-20020a654105000000b002692534afcesf3562327pgp.8
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 17:31:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631752309; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xz9UXPo2g4dhDESqr9Ll3UQDir23uttOK7axEoh/NJvRW9/KR+Fm8LYmCKEDLnbaET
         WVxYS6o2XZuGlEs6bghJHOXmcJy30nR4YvYzlCLEUBQz9kHrDbUmSNGfVWS3FRjhnJw5
         P4vDRj8SAYWCsO9qdkBkREpBPFTN3nmoQjVlFg5bfppTlnD8NIbtPAD60FDkIaqVJm9l
         9O3ElxN2v6hWuPCrANkzWyMOg7NyQPjl71Qr9bmpcz/Lx61gLWqH/w83x+u0s+LyUDmG
         Xxypp4DVpNxMgOSX7OM9wNSu+zp9kWcWUjjSnowIiCqyxyAFd52k/phbc118H+Lg5Rku
         1LHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=R0J3ow07MreIGEu8EKpsVBqlxC3WnyGi/AiotumDihI=;
        b=JhXbgg4VoXG94kzuDy6w51uIYc11/MyndxNSoLaODYjg8TAm1lpdsfspep0YkQfQD1
         WVJBGZ25U9iGUpgCsqHQSjtp7WWUA4pIewkPjWkHUvA7nJaImDV1GHHYd+XPQhCYIXyF
         PHK+Q9GHVyBQqoJ09Q1bbdjKmxXwuRsH8Hv96CLncxcj0cQmlE2FDeQscLC1PSpfFOHk
         UeJJIi2RK/Y8v4fggC06nxY6/7EuSv2kgvbKVXinPPbsqzffAIGDRRlm2t3604RNeUhA
         PfJG4dyZ5OvXEUoaSwk/L1XWhv8+AJuPhQQuDCmGIBwW/sQ3JOas7e1xnZC6k5/ql6kZ
         FNmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="ri/yOdIv";
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0J3ow07MreIGEu8EKpsVBqlxC3WnyGi/AiotumDihI=;
        b=YDcGVYXEYVVD1xGH4M3LHxhKki9WrqB3h7yYXiHqATNWghmXD4npxZ0vcNwzsO5g/M
         LAjah6lSbelr7WQDSbZNbbtW0vU47AspG7sJ2M8pEEuzp8aSD7qmPiW+rXkO5wEKIH+p
         pWmolLIzPwsaTO/DNaqAVxeiXiArqDSblzgrZJ5NMa9a2FCidrC/wKdWJcmLSHR3VGaI
         yIk2m4z/VEfMHTM5Rm+1zbz4JKJoZJZGwMMcCitK0Wung8bdn4RZOwkc1ThuoDjAS1py
         p1cKrjWIfQ7a/fUVQV5MtDktnOnzsUBYLpUIchFYUWdUYkESlXFdvkEPoUqBurtLtCwQ
         BENQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R0J3ow07MreIGEu8EKpsVBqlxC3WnyGi/AiotumDihI=;
        b=AOxbqx8qMxZVjCR6dZwURrIwZaX0bPvdHvZmL7WjhrpgroHTHIqi9s8gf3goZcppgU
         +Te596cLeOqAhg8P/aMLSm0jcIII4PQWdrzpjng3DJKhSMw5B0V1HStH+SvAeha/k0+n
         oz2GjbSIZuel8lApWAuRghQ8gASfEBXDcAAdj0xtksgzXukjelDv20mrUyH2jtRNlG4G
         MdfLj9WJs9AJhKPlw6l/xAS689S4jQAOngTeVNybWP1slAPI92oe8pUb/wKY0Id3cnRl
         CadeDmBeeFmEu9b5keWgovuw5o7KehuypYTZKPlA1w27fA0HBEpvZqep8ENDlz8eoDZl
         q7bg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Ia6Iq4UAtfkQo1GFZBsS1r2x14+iYehTKflgz2t6o6XycmFpu
	cIt0Le00aX+NVdskSPc+Iuc=
X-Google-Smtp-Source: ABdhPJxcNOVg08eYFsNo/IEPCpBmdkbnWg5hVOLvwr+lUgdC6iuCGzsAqDkgRSpkB8GxEg1ddaP3fw==
X-Received: by 2002:a63:741b:: with SMTP id p27mr2409286pgc.140.1631752309546;
        Wed, 15 Sep 2021 17:31:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b7c1:: with SMTP id v1ls849001plz.2.gmail; Wed, 15
 Sep 2021 17:31:49 -0700 (PDT)
X-Received: by 2002:a17:90b:3901:: with SMTP id ob1mr11537428pjb.136.1631752308942;
        Wed, 15 Sep 2021 17:31:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631752308; cv=none;
        d=google.com; s=arc-20160816;
        b=Lc6H33YHWrlK9B3nIQmkMzmNcgPKnOVudzvnrv9sWlqNAIAnx7eV4vrxMxn7ggs1xS
         OvvP8BiSr9pk0KlDtRYrgKj8GhP2LAwqYX1xrqB99f9JxKsXNO8UoeFKzNXjbe0j7u5t
         th8k4LSUcwMR4ElPsYDygnsxMcKisWz+4FxznFoE3FtDMfdjqv6d9C+uIz933Q1ORTlf
         XUZZpwJ4f1+WwGtOymaFfJqTjsnREA73G46KVdNVEYtMloC/3fcWeqRFWYUDcALWjtJc
         bhEUlnvrpgk5Tb4WD0Q2ZvVJhzc3UemxxswPbYWBiBnjbN8Du5VDw8nvlvO73eMYQILp
         VT8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DnbYKZtOT2fShYLfmL+hqJRNgYzqAiERz43ADAawB14=;
        b=chOcQ/O10xkqxJpIbcVlwZ8x1Ep5X4oJukA570zTsJN9syu9i7Pleugely0oFxQGSc
         hHwThIt9jgv78owjvnMqM9UopVY5fNqwOdDzL1/PiOw54fOAahD9gxFJ2LE4Kc1jGCkM
         VN3VlNB56dRTvYXqkBtt7/B2b22XOkMfSWXN2mHnuD7POk3deWUm4rS/5AWQw6OqPhZ3
         kMeHxRJq10GdkhpTEPOd29u4WCeidKprdbk5AWwFQjnY+xjFDxxHlbHW+udPaYIn7URH
         gop9il6vF8NJwWF994XLc9d5zWuQBfyGLi4fQBZ/AM6dhjkmOaq4O5NdsIcYIVqZfh9n
         lOQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="ri/yOdIv";
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i22si355611pfq.4.2021.09.15.17.31.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Sep 2021 17:31:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 2195B6120F;
	Thu, 16 Sep 2021 00:31:48 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id BBBB55C0B1B; Wed, 15 Sep 2021 17:31:47 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 9/9] kcsan: selftest: Cleanup and add missing __init
Date: Wed, 15 Sep 2021 17:31:46 -0700
Message-Id: <20210916003146.3910358-9-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
References: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="ri/yOdIv";       spf=pass
 (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Make test_encode_decode() more readable and add missing __init.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/selftest.c | 72 +++++++++++++++++------------------------
 1 file changed, 30 insertions(+), 42 deletions(-)

diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
index 7f29cb0f5e63..b4295a3892b7 100644
--- a/kernel/kcsan/selftest.c
+++ b/kernel/kcsan/selftest.c
@@ -18,7 +18,7 @@
 #define ITERS_PER_TEST 2000
 
 /* Test requirements. */
-static bool test_requires(void)
+static bool __init test_requires(void)
 {
 	/* random should be initialized for the below tests */
 	return prandom_u32() + prandom_u32() != 0;
@@ -28,14 +28,18 @@ static bool test_requires(void)
  * Test watchpoint encode and decode: check that encoding some access's info,
  * and then subsequent decode preserves the access's info.
  */
-static bool test_encode_decode(void)
+static bool __init test_encode_decode(void)
 {
 	int i;
 
 	for (i = 0; i < ITERS_PER_TEST; ++i) {
 		size_t size = prandom_u32_max(MAX_ENCODABLE_SIZE) + 1;
 		bool is_write = !!prandom_u32_max(2);
+		unsigned long verif_masked_addr;
+		long encoded_watchpoint;
+		bool verif_is_write;
 		unsigned long addr;
+		size_t verif_size;
 
 		prandom_bytes(&addr, sizeof(addr));
 		if (addr < PAGE_SIZE)
@@ -44,53 +48,37 @@ static bool test_encode_decode(void)
 		if (WARN_ON(!check_encodable(addr, size)))
 			return false;
 
-		/* Encode and decode */
-		{
-			const long encoded_watchpoint =
-				encode_watchpoint(addr, size, is_write);
-			unsigned long verif_masked_addr;
-			size_t verif_size;
-			bool verif_is_write;
-
-			/* Check special watchpoints */
-			if (WARN_ON(decode_watchpoint(
-				    INVALID_WATCHPOINT, &verif_masked_addr,
-				    &verif_size, &verif_is_write)))
-				return false;
-			if (WARN_ON(decode_watchpoint(
-				    CONSUMED_WATCHPOINT, &verif_masked_addr,
-				    &verif_size, &verif_is_write)))
-				return false;
-
-			/* Check decoding watchpoint returns same data */
-			if (WARN_ON(!decode_watchpoint(
-				    encoded_watchpoint, &verif_masked_addr,
-				    &verif_size, &verif_is_write)))
-				return false;
-			if (WARN_ON(verif_masked_addr !=
-				    (addr & WATCHPOINT_ADDR_MASK)))
-				goto fail;
-			if (WARN_ON(verif_size != size))
-				goto fail;
-			if (WARN_ON(is_write != verif_is_write))
-				goto fail;
-
-			continue;
-fail:
-			pr_err("%s fail: %s %zu bytes @ %lx -> encoded: %lx -> %s %zu bytes @ %lx\n",
-			       __func__, is_write ? "write" : "read", size,
-			       addr, encoded_watchpoint,
-			       verif_is_write ? "write" : "read", verif_size,
-			       verif_masked_addr);
+		encoded_watchpoint = encode_watchpoint(addr, size, is_write);
+
+		/* Check special watchpoints */
+		if (WARN_ON(decode_watchpoint(INVALID_WATCHPOINT, &verif_masked_addr, &verif_size, &verif_is_write)))
 			return false;
-		}
+		if (WARN_ON(decode_watchpoint(CONSUMED_WATCHPOINT, &verif_masked_addr, &verif_size, &verif_is_write)))
+			return false;
+
+		/* Check decoding watchpoint returns same data */
+		if (WARN_ON(!decode_watchpoint(encoded_watchpoint, &verif_masked_addr, &verif_size, &verif_is_write)))
+			return false;
+		if (WARN_ON(verif_masked_addr != (addr & WATCHPOINT_ADDR_MASK)))
+			goto fail;
+		if (WARN_ON(verif_size != size))
+			goto fail;
+		if (WARN_ON(is_write != verif_is_write))
+			goto fail;
+
+		continue;
+fail:
+		pr_err("%s fail: %s %zu bytes @ %lx -> encoded: %lx -> %s %zu bytes @ %lx\n",
+		       __func__, is_write ? "write" : "read", size, addr, encoded_watchpoint,
+		       verif_is_write ? "write" : "read", verif_size, verif_masked_addr);
+		return false;
 	}
 
 	return true;
 }
 
 /* Test access matching function. */
-static bool test_matching_access(void)
+static bool __init test_matching_access(void)
 {
 	if (WARN_ON(!matching_access(10, 1, 10, 1)))
 		return false;
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210916003146.3910358-9-paulmck%40kernel.org.
