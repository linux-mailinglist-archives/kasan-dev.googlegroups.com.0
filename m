Return-Path: <kasan-dev+bncBDAOJ6534YNBBVMKQS4AMGQEK5IF5WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 93E4E99157F
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Oct 2024 11:22:31 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-42caca7215dsf16410575e9.2
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Oct 2024 02:22:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728120151; cv=pass;
        d=google.com; s=arc-20240605;
        b=dPiH3S1VDb3ww3nTeUa5OSTxTx2nMOPWERZ7WGR/hdw3BQrhm2vWdOxBbPLoy3xGNn
         CpOPu6MkbWrbBLPs/3YUA0F3h8MC+pZqwgmd7WrmWbdBRDYYE0kz/ES+2y9YvE8wK8Jw
         YLjLL5VCV7spA7r/RwtEthzuPc4xzCFaOpVkzlsjGqxHJjwiS5Sfj/lFHTNhsAL7Kfr9
         e/THjy44QRQhsqDMcTSD4w2QE5hPfODUCKzs+PIc0HDcd8bM4bDcf5aOEtic+qAihsDI
         WENUbPyqQMtVkTbhbhB6IRHu33DpDrcocDxyyvWTY8xrcmNQuoZu66ermaZB94AjWTgZ
         C2BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=//alFo3dLw0tpmzKpYPpfw1i532swx6fD13a9VFydJQ=;
        fh=rn9a4YtEg/4WTBQUSFjHCAhrvuACG2mlb6+tHMRKXkw=;
        b=asWpIpwyOjdWQ++yxMI2ubDBxbsmLoySk/sWrr8VywX4+35Q+AIINNu10H5iFJJX80
         qwr7yBIA7wRtmHludx3UL8yA7sReCt5X74/Cg++uCBGdtjMldapcuFpqkycvgdDyPAbw
         nYBQYmypTlJA72tfEdHrTWS3d6Jz8EK9Tw2R+32qy+HMgWLVej/gvniAy6th2apIaW5p
         LzA/+cMsIaAtK5Ma8MPTmGNVe8g4heT4v4GyKZeJ3tzYe9fx0ULrw1e+SHvQzwEKXCOZ
         lLhG9YV7zecuez2wOKOKRTcy00TEeBpt60KdAofzqVvUIUHl5mvKbk8bVIpAhsSsBoDn
         e4cQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fb1+yJ1Z;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728120151; x=1728724951; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=//alFo3dLw0tpmzKpYPpfw1i532swx6fD13a9VFydJQ=;
        b=EfJQTPIBfidt9rBJ5SRIX6XAsS44WETumDoagbrBLp0rhlX7A3xWLKLjbzq6Hn0QaQ
         tdLrZs8GFtf7kDGtVSe8RjluMyyO+DwLFUgB4l8CRI6udH2RKFdvAE1Uw8ywZaxX/9II
         NyId0m4obz/jLUtBikA75oL591XCfKEZF4oOO745FXpptcDON6k+rUPdJ7/MhIJsJWI3
         vTuRI4ZLrs4bLpuqVU7x870k0LRsVjWUeyXq5VujBoVqfZUfcWnDATYuWXOGUv1guJwE
         xhgC6QG2ogkfxrreWUOrgPfWV+n4Ix7MCE2S9hqVA8ikWs3GMwrhir6BKKtxkYRTStLt
         SlpA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728120151; x=1728724951; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=//alFo3dLw0tpmzKpYPpfw1i532swx6fD13a9VFydJQ=;
        b=kZhEWSyO6wPBVDUfPekm5BYehDktKq6Q5gWC2jm2t9rloXW91hzKN5mC4U5jVTfXP/
         PT3Vga+EwphnPfC+g5MZbirdvTJb87+67XP9Gvd+Xjy0FbMh8jHulGpdT8FKOAve6e4d
         hhbWuKPP+Ntvel0GrPgG7BoaZLAsqp0D2T1EP09tb/9cPnjRLLvJbs28oYV1rGDZcXRJ
         sk4j2TLwqEhkSjcSYAaMDIaw2v/HIzDZG/5WpwPVf7PG5m5VWWzPbFJVWiBaxFCQdg9y
         0mGfP7R6ddasfUMZWATlXTnF/fu/tMSuAxK3STXpOrrKm2BMNKgh5KF8uptOhzIMreuN
         yV2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728120151; x=1728724951;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=//alFo3dLw0tpmzKpYPpfw1i532swx6fD13a9VFydJQ=;
        b=hBBGEcEPAXb3zCwaXy85M48ct9a78BXPG5pofeH4ClXqUAFkB0+S2bKrYxzS1LYdU+
         6wdx7M284MlZYLptJWhHFZZQ5/8nTGyrIEyODNQ5ACJDn1kmqFXSV1+Z2yY5y42Enwkz
         AqmvyCjylWih5ZH6aOgPU07hZhCIW92NV1hnUHp3hiXV3eHpirbBq27c1dVJeD1Fzrq2
         tRRRuSx2p/bF5wDZuOuoduSWM6lVJ2NFTevP0yXrQtj9GQf2GXyKN8aNhkbHgYJb807N
         vhIi0ZTyS5Z9Bvq0vXGTaVIFdkAb1wvbGY0zoSyTxDfwdzhas9t71lFglvn6JX+oGmXx
         I/3Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU1P99H87krlFidmXvVFTiElBm4TzmfAxwJ/tyywsuLGaEUHnXGolgHVNX+3BW4Yidi+4ggyg==@lfdr.de
X-Gm-Message-State: AOJu0Yw3Q3YYQISprKfxxc+r35NloFztExCC6Jk/jjxMwI6IjqxyEL4J
	MiMPbEWPoNxijzssQC9kcc/gTO6vYk3jzqQnFMhOLHn1GLMcfUUm
X-Google-Smtp-Source: AGHT+IG0U27NeX49+jjRkCw20Urm9Gc2jYGhZnDHibu1oV9zo6ggNHQq0FWMAc422pBeRCOBAbgC4g==
X-Received: by 2002:a05:600c:1c14:b0:42c:a8cb:6a96 with SMTP id 5b1f17b1804b1-42f85af54b1mr39585435e9.31.1728120149753;
        Sat, 05 Oct 2024 02:22:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1912:b0:42c:b037:5fe4 with SMTP id
 5b1f17b1804b1-42f7df74f89ls12159115e9.2.-pod-prod-08-eu; Sat, 05 Oct 2024
 02:22:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUDgvtZ8KOyyr6+27DqMCtVq8adIGNQhsqRwVb8HbHHTkoM8JQLQ46niRwj0zWJ0CwaMCT+E6D4OLI=@googlegroups.com
X-Received: by 2002:a05:600c:1c90:b0:42c:de2f:da27 with SMTP id 5b1f17b1804b1-42f85aa38b9mr38021975e9.2.1728120147411;
        Sat, 05 Oct 2024 02:22:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728120147; cv=none;
        d=google.com; s=arc-20240605;
        b=bXS4lsrNpIqbvrhkuO7HulgnQx2HjQ0m3nDfwCdKbjyWfnsAHwcxMUquPvnCNR53x4
         OAywTMNGIZcK+EkXPJQgoBsqLkh0ah6Feeg16K/3ufsGH88vtiD6sBz4i94NV7y7BbJi
         1dUAHOaVigKLBNMsHYr5sCagGwkyJ6LqAxcQbfd7p50l/uDUly3TFkWlgmKXHV42ivtR
         1wtDm/OCsnW2f9eOzPS9HfK8ogH2RGeQRJ8bqUd3rGFfLq+1LWkGJV0ULJgAo/XB0bBA
         adIwtGh6cPV+qEBecjVhZZ0KXIvYtN8KfDFnXzc2SrrPm5CRpPGEywoHV1uS0y5AXCI5
         bj7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=tBNL0qdzrJKc0pu8ZbalsnWWokUHQrbB6w4+rulqCSc=;
        fh=O2FW1I97G5YvedG2qzZyLzIp9DHr9rYN5DitCwrH5AU=;
        b=BhugCfPplfoJ/fe9IkdnIQ7J8NMyqtZok7SKBNgt9BwUDcDDnFeV4a3Kd6lKiubqpj
         ni+tUYiZrgdZuBmV/ySEf4J2+wODie9nRnE5FB2GCeA4JNhSjeYMt4uY548WB2Hevn0c
         4ZifNwwP9d2cbyf+Ro5Y2t0bzFnoFqUC+RQpwni2KRSiomy/f3YEhNOArxVf2d+VnyzV
         9wzWVoIZbGxOHWq/ZV6Bxk28yUXTrybC/Zf7mNYmq7lQQ9PPce6iCeg51JfttItGzLKz
         AacB9T2VJfK2aGeQCKfcd1WeVGKT3UgUwZuann+RmpWdVKrycWMmASz8ooeG0SHn4V+V
         i0BA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fb1+yJ1Z;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42f85994777si2528125e9.0.2024.10.05.02.22.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 05 Oct 2024 02:22:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-37cea34cb57so1775524f8f.0
        for <kasan-dev@googlegroups.com>; Sat, 05 Oct 2024 02:22:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWNeV3UA+7JkcXxVuAB9rASXChJ3GDWbL3PC71Z9EGs1NLbCIMEkfh/Grx9yDhu++muveWu+iHXIP4=@googlegroups.com
X-Received: by 2002:a5d:43cc:0:b0:37c:d1eb:5527 with SMTP id ffacd0b85a97d-37d0e74be67mr3538265f8f.31.1728120146599;
        Sat, 05 Oct 2024 02:22:26 -0700 (PDT)
Received: from work.. ([94.200.20.179])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-42f89ec63d9sm17725325e9.31.2024.10.05.02.22.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Oct 2024 02:22:26 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: elver@google.com,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	akpm@linux-foundation.org
Cc: vincenzo.frascino@arm.com,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	bpf@vger.kernel.org,
	Sabyrzhan Tasbolatov <snovitoll@gmail.com>,
	syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com
Subject: [PATCH] mm, kmsan: instrument copy_from_kernel_nofault
Date: Sat,  5 Oct 2024 14:23:16 +0500
Message-Id: <20241005092316.2471810-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=fb1+yJ1Z;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::431
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
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

syzbot reported that bpf_probe_read_kernel() kernel helper triggered
KASAN report via kasan_check_range() which is not the expected behaviour
as copy_from_kernel_nofault() is meant to be a non-faulting helper.

Solution is, suggested by Marco Elver, to replace KASAN, KCSAN check in
copy_from_kernel_nofault() with KMSAN detection of copying uninitilaized
kernel memory. In copy_to_kernel_nofault() we can retain
instrument_write() for the memory corruption instrumentation but before
pagefault_disable().

Added KMSAN and modified KASAN kunit tests and tested on x86_64.

This is the part of PATCH series attempting to properly address bugzilla
issue.

Link: https://lore.kernel.org/linux-mm/CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1X7qeeeAp_6yKjwKo8iw@mail.gmail.com/
Suggested-by: Marco Elver <elver@google.com>
Reported-by: syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com
Closes: https://syzkaller.appspot.com/bug?extid=61123a5daeb9f7454599
Closes: https://bugzilla.kernel.org/show_bug.cgi?id=210505
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 mm/kasan/kasan_test_c.c |  8 ++------
 mm/kmsan/kmsan_test.c   | 17 +++++++++++++++++
 mm/maccess.c            |  5 +++--
 3 files changed, 22 insertions(+), 8 deletions(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 0a226ab032d..5cff90f831d 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1954,7 +1954,7 @@ static void rust_uaf(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
 }
 
-static void copy_from_to_kernel_nofault_oob(struct kunit *test)
+static void copy_to_kernel_nofault_oob(struct kunit *test)
 {
 	char *ptr;
 	char buf[128];
@@ -1973,10 +1973,6 @@ static void copy_from_to_kernel_nofault_oob(struct kunit *test)
 		KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
 	}
 
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		copy_from_kernel_nofault(&buf[0], ptr, size));
-	KUNIT_EXPECT_KASAN_FAIL(test,
-		copy_from_kernel_nofault(ptr, &buf[0], size));
 	KUNIT_EXPECT_KASAN_FAIL(test,
 		copy_to_kernel_nofault(&buf[0], ptr, size));
 	KUNIT_EXPECT_KASAN_FAIL(test,
@@ -2057,7 +2053,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(match_all_not_assigned),
 	KUNIT_CASE(match_all_ptr_tag),
 	KUNIT_CASE(match_all_mem_tag),
-	KUNIT_CASE(copy_from_to_kernel_nofault_oob),
+	KUNIT_CASE(copy_to_kernel_nofault_oob),
 	KUNIT_CASE(rust_uaf),
 	{}
 };
diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 13236d579eb..9733a22c46c 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -640,6 +640,22 @@ static void test_unpoison_memory(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
+static void test_copy_from_kernel_nofault(struct kunit *test)
+{
+	long ret;
+	char buf[4], src[4];
+	size_t size = sizeof(buf);
+
+	EXPECTATION_UNINIT_VALUE_FN(expect, "copy_from_kernel_nofault");
+	kunit_info(
+		test,
+		"testing copy_from_kernel_nofault with uninitialized memory\n");
+
+	ret = copy_from_kernel_nofault((char *)&buf[0], (char *)&src[0], size);
+	USE(ret);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
 static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_uninit_kmalloc),
 	KUNIT_CASE(test_init_kmalloc),
@@ -664,6 +680,7 @@ static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_long_origin_chain),
 	KUNIT_CASE(test_stackdepot_roundtrip),
 	KUNIT_CASE(test_unpoison_memory),
+	KUNIT_CASE(test_copy_from_kernel_nofault),
 	{},
 };
 
diff --git a/mm/maccess.c b/mm/maccess.c
index f752f0c0fa3..a91a39a56cf 100644
--- a/mm/maccess.c
+++ b/mm/maccess.c
@@ -31,8 +31,9 @@ long copy_from_kernel_nofault(void *dst, const void *src, size_t size)
 	if (!copy_from_kernel_nofault_allowed(src, size))
 		return -ERANGE;
 
+	/* Make sure uninitialized kernel memory isn't copied. */
+	kmsan_check_memory(src, size);
 	pagefault_disable();
-	instrument_read(src, size);
 	if (!(align & 7))
 		copy_from_kernel_nofault_loop(dst, src, size, u64, Efault);
 	if (!(align & 3))
@@ -63,8 +64,8 @@ long copy_to_kernel_nofault(void *dst, const void *src, size_t size)
 	if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
 		align = (unsigned long)dst | (unsigned long)src;
 
-	pagefault_disable();
 	instrument_write(dst, size);
+	pagefault_disable();
 	if (!(align & 7))
 		copy_to_kernel_nofault_loop(dst, src, size, u64, Efault);
 	if (!(align & 3))
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241005092316.2471810-1-snovitoll%40gmail.com.
