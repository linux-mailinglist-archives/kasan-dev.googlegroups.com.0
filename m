Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBF5GV23QMGQE25AGLKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id BEF7597C2FB
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 04:57:29 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2d8ce69ed4csf590777a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 19:57:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726714648; cv=pass;
        d=google.com; s=arc-20240605;
        b=V4+77ezM5TLpi333UahDMT4fua+CaWt6VMy+BnVzBrbkEFTie10Umbu1o9sxpze8ur
         kTZS52HW0BGrdwlQZjN11Q8s+KxB7s7GVuLaYweixAzhC381npyFeg4RmCBNd9Awg5Ws
         FaKuepmlWzGTLsw4L0e/kIGxEvMnWMTkPB/CJauA+IkxQvlZ8t1EnPXY21TIENpW9ftn
         zy1ZNfCnwILiJdwfNsDLrdHSldBzCx6ygCTMrqDUsXKHn+gqb6SKJu1wogX4ZXDMQhZx
         fyVX0OpEC+LU8G5EVGojcyYn36xghWKcb6eheNqEzBD5Sykpx2ZrLJDVV8CSpX15hWJx
         jjog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=qkdruNRmE1QX5YR9sXzJTAFmb/2tSqB28QL1fPuKmAc=;
        fh=n4JdDK7ltanJzOsRzIXdI0mo+Ank4WM2Os8Wxd5hSXo=;
        b=lOhjSihvO0CA4Vr9l3dKLWF8NQXQ2+1YEHJdvN/AnFIPMntRQXeUAgkqRdeSJ0AiSc
         uBb7AWNcRzkV2vMVpNFtZZPNotwX9N8CoVPCiErPvwEU3imgV1Ymg3iRsNt6k+4SQCda
         rI5+9WY+4SCG/M1H8vnbh3PkXPbL0mlV4PO+3p4xucSUfUsz7ofnQyQczr7nsn+965N3
         AdIXou/WClWslSpfNwXC7CKGrX4IcfjdZrzqjkN18TJvoGAyItwd8e0S1YnI32r/VIpy
         YgYU7W5zHdcZpzIZicobM9Vbtz5J5CUYqy+Me8hk29ci3ZBZs99uf48NB7sF/nZmcxNI
         41SQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Vp0t2arp;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726714648; x=1727319448; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qkdruNRmE1QX5YR9sXzJTAFmb/2tSqB28QL1fPuKmAc=;
        b=gBOVkHwtqgUVMYfui1YCMy4e58C85dR0L22XAIx67V41wCqHn6UIp4Fqigpk81drzg
         mhhjy2vp8l7Wl6qinhOnjWYbyJXrK+uUiftqC6Pp6A27GzDUWy0b270+cKYQO1ZpPR7I
         Esa3CjClnYXhTvvUcb5bi0Ijm12Hb7amdK8DmHpOv3Is+0OLqsrSPn7Zswf3k+R5J+F+
         PaM7xjzj2nLgV2P8UzU9lBju9glBnlVll5rgEbwrOjg1FY6tMaLUWU78NLp+cP40WR7w
         0KGuhDbgNHjWcC13QB8U5uLULmb+r2cOf6cOWNB4lU8FYsx0jDPPG1iUvpGtSmiM4O3S
         2WVA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726714648; x=1727319448; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=qkdruNRmE1QX5YR9sXzJTAFmb/2tSqB28QL1fPuKmAc=;
        b=cVhXy8jfQXfPUGef4LnAAIogV4ZWC9IV//jmZvp9nwYBhpIKze+aC1BClvV7yOcLYS
         EyMjFw4r5FeSZbyz2mQxHH29Rp2bAm9tZoFGspKjQVdpghZmzk4c+LZ9JIoi2JqCF9u3
         lQCKLHV3fmNCDkpDAM+nXgEZPS/fSU3u/EnIq8s3CmnNShIb8spoQ+P1hu2NpIMbiWA2
         GLpX8NK9woM7Aupwjg0Xt9HGPgpdKzRj3iZKpu5An7mkTwFkDdXUfGoH31xX2eiDDZl9
         gAXDhoHr9CmcUjsrTjOPkkxNLFNjsqd0TFGHpDLnPqnM4wZGilvxt4Q7eqtpXeFjoA4c
         BhJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726714648; x=1727319448;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qkdruNRmE1QX5YR9sXzJTAFmb/2tSqB28QL1fPuKmAc=;
        b=SgvKetAC+Q5w9/b8EN2M2bxh5Mb/TeeJWHGnpVKp5jT90V73u24rUoitjk/05Fe0E4
         0PSRVFY60da0/Ox2I6LJVX7vtOGIUqeRacRyOztMnBbaYYlbLDTmb0WVWdL9/6UnYL6u
         FVK4ahgRI30dWZ7KhTKmv2Oa+nh/ku/D2so8ItGkoXmICHIGAdeQg6ffCAXM5gMjuJlC
         ZEXtlLrYtiP9ijy4kquZim5ktAUmzGGe+uIhFBp80qExN7kZhZlvCpew5cFhqI/AT5S5
         tOXbVImeZ54/IpWeZ/+3WpGOXy6RT2VPv5FL/AmaKntAOOmCcde/RYZ8a32WZxwj1nBl
         5/ng==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVcDglF8Xj9Q1r41M9WQ2oD20UKKtdpCkYtS01VRamyCegoEg9lObvYCEOO7AWkWShD2uheJA==@lfdr.de
X-Gm-Message-State: AOJu0YwTIfG1GKVk5EZAMj15Yk9D8XDWc7gsnr0MjYcCkWe60S25AkoD
	94F76LdPNCO6sZtNHoudDYbN6lVseH5d1w+8FE/K5qxrvmJRuOkz
X-Google-Smtp-Source: AGHT+IGM90IGHPOnVIWRt8BvXfCqRj9ZyOElgyzvUcn6Cj3JxNNhrIbDHgaQQlvSS7NnNjk6SB5dWw==
X-Received: by 2002:a17:90b:4c05:b0:2d3:cf20:80bd with SMTP id 98e67ed59e1d1-2dbb9e1cf4amr23363307a91.17.1726714648179;
        Wed, 18 Sep 2024 19:57:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8991:b0:2cb:5feb:a0b6 with SMTP id
 98e67ed59e1d1-2dd6d66d675ls328090a91.2.-pod-prod-05-us; Wed, 18 Sep 2024
 19:57:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVMkmSu36q2KB97BhxjJmiIn3HlbVha6pOmyLCAJ+Wxl3Uceo3Cqr6FkI8lVvJgMemFPWsB1l5Hjt4=@googlegroups.com
X-Received: by 2002:a17:90b:280a:b0:2d8:7f5c:6030 with SMTP id 98e67ed59e1d1-2dbb9f75660mr21533292a91.38.1726714646843;
        Wed, 18 Sep 2024 19:57:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726714646; cv=none;
        d=google.com; s=arc-20240605;
        b=Z+L8O/UOz1Og6x/BTeENPJHl9txH9I/7AW/2WVRzhFurwVYlpN0iY3BNJZTk9loo7f
         i5498kGvBESCe2q0N01j12KyYysixVgz/ZBpYz5E5w5JtUc0gAy+2YIZj+qK7TZICN5z
         UwWkSp1oCYu62vFE5QEhUUtbo1nc+DWpGwsQ6iCdSy7vRZ0/yhIarfUJXVcqdl6lJJpe
         ZmmyaEBtwtYpa3+n8mIQ9tzyCA9TWZSeuempmOHcb0Bri6OsgO/TC2J1BmnGN/B/E1Ib
         i5v7C8afA8Haf3Ul2/JiTJFlL3FVDGrV2IGbk38jYfHGBmH9D2kFOlcpAxhqDdQVhrpp
         Qv7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rG0rlJ7RpNnGy840avhtCY+OIP6FbV4qxEoUkbOoVC0=;
        fh=Tkih6XGT08u7ZIA6gICkCVtTW2V5a6VTb2Q7b2B2WXE=;
        b=RoFf+7kD82xbw5vlPQYhx/T9/vo6mLRnng1oTluGg8hSteWorXfIlWCl4XMZe1WUD1
         lYuvE/TXTV+/FLFPmy2sSvbHG0UtPj/8RMaJBg534LRon0gJUDSQ3zGzns+kdZAMFkbm
         wU0sNqXXn2lrckIFAenjtjmxQhHMnfYdgFTttqOBUmUwkvuIqUWS9fgvsZ6k0mzRC/5j
         3/w8hXiXooAAQijznGjFGpNOR8xN5oT9KBgtDPLJwfwJynvulZxmtQXnz80Ea8TM22lU
         Z02N5k8HgOdgHgB7sa19RNm01jyQT4OjRTKrG1kyvzrD5/y0d3tEWWUpaAqmT7AOPVGw
         NzrA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Vp0t2arp;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2dd6eef6e04si89935a91.3.2024.09.18.19.57.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 19:57:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-20551eeba95so4017505ad.2
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 19:57:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUsWwTOJb4sfCxlWTCyuB6TBdndCNsdlRg29bHncMXv6wjQfM+sawXJMhcoKgisr2rGDCk55pdFIqY=@googlegroups.com
X-Received: by 2002:a17:903:32c9:b0:206:ae39:9f4 with SMTP id d9443c01a7336-20781d5f6fcmr301143135ad.20.1726714646433;
        Wed, 18 Sep 2024 19:57:26 -0700 (PDT)
Received: from dw-tp.. ([171.76.85.129])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207946d2823sm71389105ad.148.2024.09.18.19.57.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 19:57:25 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	Nirjhar Roy <nirjhar@linux.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev@googlegroups.com,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [RFC v2 13/13] book3s64/hash: Early detect debug_pagealloc size requirement
Date: Thu, 19 Sep 2024 08:26:11 +0530
Message-ID: <616bf94910b0c77323ea9ccb86571f78ebfd421b.1726571179.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1726571179.git.ritesh.list@gmail.com>
References: <cover.1726571179.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Vp0t2arp;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62b
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Add hash_supports_debug_pagealloc() helper to detect whether
debug_pagealloc can be supported on hash or not. This checks for both,
whether debug_pagealloc config is enabled and the linear map should
fit within rma_size/4 region size.

This can then be used early during htab_init_page_sizes() to decide
linear map pagesize if hash supports either debug_pagealloc or
kfence.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/mm/book3s64/hash_utils.c | 25 +++++++++++++------------
 1 file changed, 13 insertions(+), 12 deletions(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index b6da25719e37..3ffc98b3deb1 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -329,25 +329,26 @@ static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long idx,
 }
 #endif

+static inline bool hash_supports_debug_pagealloc(void)
+{
+	unsigned long max_hash_count = ppc64_rma_size / 4;
+	unsigned long linear_map_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
+
+	if (!debug_pagealloc_enabled() || linear_map_count > max_hash_count)
+		return false;
+	return true;
+}
+
 #ifdef CONFIG_DEBUG_PAGEALLOC
 static u8 *linear_map_hash_slots;
 static unsigned long linear_map_hash_count;
 static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
 static void hash_debug_pagealloc_alloc_slots(void)
 {
-	unsigned long max_hash_count = ppc64_rma_size / 4;
-
-	if (!debug_pagealloc_enabled())
-		return;
-	linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
-	if (unlikely(linear_map_hash_count > max_hash_count)) {
-		pr_info("linear map size (%llu) greater than 4 times RMA region (%llu). Disabling debug_pagealloc\n",
-			((u64)linear_map_hash_count << PAGE_SHIFT),
-			ppc64_rma_size);
-		linear_map_hash_count = 0;
+	if (!hash_supports_debug_pagealloc())
 		return;
-	}

+	linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
 	linear_map_hash_slots = memblock_alloc_try_nid(
 			linear_map_hash_count, 1, MEMBLOCK_LOW_LIMIT,
 			ppc64_rma_size,	NUMA_NO_NODE);
@@ -1076,7 +1077,7 @@ static void __init htab_init_page_sizes(void)
 	bool aligned = true;
 	init_hpte_page_sizes();

-	if (!debug_pagealloc_enabled() && !kfence_early_init_enabled()) {
+	if (!hash_supports_debug_pagealloc() && !kfence_early_init_enabled()) {
 		/*
 		 * Pick a size for the linear mapping. Currently, we only
 		 * support 16M, 1M and 4K which is the default
--
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/616bf94910b0c77323ea9ccb86571f78ebfd421b.1726571179.git.ritesh.list%40gmail.com.
