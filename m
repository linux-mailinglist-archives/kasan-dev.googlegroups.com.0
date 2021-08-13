Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFOS3CEAMGQEO37LWGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id A964B3EB253
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Aug 2021 10:11:02 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id x7-20020a92b0070000b0290223c30afe67sf4601060ilh.21
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Aug 2021 01:11:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628842261; cv=pass;
        d=google.com; s=arc-20160816;
        b=DGbGzGai4aMWTvJxNh9oOiaPEUqrbbQZHuS3FC6gV6WDB61neu1LQICk5Zn5YCMcWx
         foZ3BYRz0o6Nr4CdohYMoTbMSrLI0x+eHvKepvSZtEmt6WyDa9lBdfk15x0fu+fy/jk3
         pWKzfNkyuDdQKIj5j7zNiWF3lFL4Ta3u3BDZodOhrHp9Ebkvgn/cXZtIBAc5beXAozdA
         Co7edVgQLQbFoDNkqrRH+UWjEJ0qQIAQtJKvFXoER2EnUvGmo/f6dXcUJr+K/p/HZyds
         u5TxZdmXz8FakPWV5dUFSIlW1RParC8cBP8Ch7L/V3Ut6JiK5G0FDa3ZKWuk7a4xiLsT
         ye/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=Eyd0pnrYSS3KJ+8b03cB3umW+MHoTRAmQ2VFb8FCD1A=;
        b=RIZCP3MwMuT10Ece1hnLU/pl7ZmkzIlgZp7wJpRAJOvIwAVSWYqXlXcDUzDjkZn9ZY
         EIYC6zo6HtXXI49YT5sI0PIXbCRQbfxDPlkqDyTPYbIkDZ4/5LbF/IYoQwBKnw3MeOhk
         CZEbg+t91dfUpsZNd1nW41ZyNMSqCYivfErROSmBX9I8PpS3ngXnAelCTdusSzVGswKJ
         iYn/jSp8Fhplx48ICd6oLhU0Ld+HE+ib+fKeMlYnZi6vtGb6jB7/r3s3UTeTrqtIYFQ5
         Hu3FqDmj1ZDv38chALNSdNB4SWPbY+Ft65RVxo0YSEdyNMp5HbjFAB6kcuU0NN2dpB5G
         0FKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PWHs269N;
       spf=pass (google.com: domain of 3fckwyqukcc0x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3FCkWYQUKCc0x4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Eyd0pnrYSS3KJ+8b03cB3umW+MHoTRAmQ2VFb8FCD1A=;
        b=XTDVFpxQxa4LYM0qoG5CaLgeUb3j76fsLOO6kgzSb4w1AbZXHWR9rMBG/lIDYPFxe2
         Zt2/i/kIuZeW8Ls9Pa3cMe8iph6n47VgeT8ajBReOVPbos9L/BIrc29L/WzK3Sp89SOB
         yLlh1/56jNb0ONjXMi5YQ2majqJP+LaVIENPVEJN65ZBLBDtwq3Lg5pKiQZ/2HNIg/OK
         Ylofo92jHj6UUJwnWIaUDbnnYCo7dPMYWDZ7E1HsVaPIFBDVZdZkHNWyhYzhd+NhtruU
         lduU45WtGDtmdRFe/yfCynlpXgclq20u7Gm+0TWSibyEnD7v4mTvpAMvQoGPlYSwqvQX
         4efw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Eyd0pnrYSS3KJ+8b03cB3umW+MHoTRAmQ2VFb8FCD1A=;
        b=IHNZDb5s6pmiq8FuosCGmQdUqH1eNncN/sr+6g/J9IYOkIwPdAvaju/D06Vmg3aHjP
         sCkCiw3SJUf4MKP1UZ7NhXr+kJwIPKd2kh38ZVLWFlXi3wN35P61yUxodP/ZmN+BYxkv
         2K/enNUpL3cl39PKa6xspuwYs0tfKPO4wN99iN0MbLHsyutn+pVnrxe4pQZuxojAmdei
         /rc2fQg9rE1BgBbQiP+CSankjfz9Ap+D2mW4lYE/lu2777zSypJh7x+2syOyTRPNWFOf
         WDn8EGWtBUabj097Lq7yYyzuXdYr/uOHbfYwm8NE3B3NF3+B6qSZIEy6/rcQDzpmO0lP
         rB2A==
X-Gm-Message-State: AOAM531uh7+TU0xcd4gnqVg/v5vQVlt0rUFpfawBxN7LxsPNjL4c04zM
	Zf4CeIgwBHomPcmakYztjyU=
X-Google-Smtp-Source: ABdhPJxS0ianNPkejmF9vU2mo0mwe9uh3wQe/SkwoGpSXtM7/JJiqokwhQGu6zNSRCnfOMifsqyGvQ==
X-Received: by 2002:a5d:9eda:: with SMTP id a26mr1148308ioe.166.1628842261314;
        Fri, 13 Aug 2021 01:11:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:6c7:: with SMTP id p7ls142429ils.0.gmail; Fri, 13
 Aug 2021 01:11:01 -0700 (PDT)
X-Received: by 2002:a92:1942:: with SMTP id e2mr1017637ilm.4.1628842260967;
        Fri, 13 Aug 2021 01:11:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628842260; cv=none;
        d=google.com; s=arc-20160816;
        b=jxAS2WMdh1MVNIO9YScW3iE1mcULor9TD9bIqtFeyLtKZscdRUGzYDIWIat54G2pBF
         RfUHh1zldmzbBdvua902ld984a/kQWjeguBDxiBJK99VAAnH48eMt7PaPetQPBX5gaAX
         /WpPDkhJC8+x7AKRv0+dIEnWxnYDZSxWu++7KQ+4QoMpkx01YjxL8CKDewo+dcwUhcV0
         HM43LYNd3tvN9CfdxbNry277IETETDHsvtXSooxReAu4AVILKReJ8++VeALd8aEcpY4B
         4sSsKlqdL2o6emrCrEXFfo0Ww+6DiU2nFvIG5+1VZQOJbrfLTi41jxhORILhzJwHPleN
         aG0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=j24ec91WRmx0ztj0QJuWNPagxwmZnLCi87UE9Mn0dxc=;
        b=k9lk0E8Jjvg9XSsWNME3QWHB5IUUi9ForxueVGfIwrhMqzE4UWywG+fP1N9F50iZmz
         pxRqgEz1pa/djGb3ORSl8UXN11gJMjdLRLDIitwjfmmd4f04GAbNHL3QqfHY22knCas0
         u4QiJ8RVOe343FhCXx42aEcgwppwamxtwGG2i8YOHdCUEQ4A9cYkwzJOTfH6kgMc59Hu
         y+oaylqVBlnfHWIsWeWY9x/UOPoRFGQ6UmtjVZQuOSkmmDDLFh9qBVete7dO1dtQ4Rh1
         zNSSqTpG9HzQQ3YkiJQniqCcClY6jxUyVKs4QFqiKkcp1CikPz+8G+gxkaSg1XwQoxD5
         d29Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PWHs269N;
       spf=pass (google.com: domain of 3fckwyqukcc0x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3FCkWYQUKCc0x4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id e16si48058ilm.3.2021.08.13.01.11.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Aug 2021 01:11:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fckwyqukcc0x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id v1-20020a05622a1441b02902977bfc6bbeso3324055qtx.13
        for <kasan-dev@googlegroups.com>; Fri, 13 Aug 2021 01:11:00 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f52:cd7f:2e57:442e])
 (user=elver job=sendgmr) by 2002:a05:6214:5012:: with SMTP id
 jo18mr1521038qvb.31.1628842260479; Fri, 13 Aug 2021 01:11:00 -0700 (PDT)
Date: Fri, 13 Aug 2021 10:10:55 +0200
Message-Id: <20210813081055.3119894-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.33.0.rc1.237.g0d66db33f3-goog
Subject: [PATCH] kcsan: selftest: Cleanup and add missing __init
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, dvyukov@google.com, glider@google.com, 
	boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PWHs269N;       spf=pass
 (google.com: domain of 3fckwyqukcc0x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3FCkWYQUKCc0x4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Make test_encode_decode() more readable and add missing __init.

Signed-off-by: Marco Elver <elver@google.com>
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
2.33.0.rc1.237.g0d66db33f3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210813081055.3119894-1-elver%40google.com.
