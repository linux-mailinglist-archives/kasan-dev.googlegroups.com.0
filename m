Return-Path: <kasan-dev+bncBAABBYP5WT5AKGQEET3LPCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 061872580AC
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:11 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d3sf1157506pfh.17
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897889; cv=pass;
        d=google.com; s=arc-20160816;
        b=JoSMPji8l+iMsj1LyPIL2JAYm2nlOTbNK0rEWZcWS7pvRt/GUsPgw/3pingXZmaO/f
         V3LWB58ud8iEoD6LjV2m6wwrMXqMHlR0vITywhA02PAGj/UW6UG4N1rJyp+SipcRceR8
         w/AyV5V2qpTMTIUI+XBRpe2Zc0Tu8qIdngdJwjnIBCTBrVmoN8QVQxkLqDD1qS9RPyvn
         aMOGOZEKHq9g5FgIaWRa3nuehvQ6XFrdtz4Htf96f16pmO7VkEiMx2CK90yRHVg2v8Np
         LG5lmWWOHbF1B/xW3/GMFfThVkVCRQ/Q7qYZ1AQ18qS1aey5Wovd5R6niYhieINW5pvi
         puVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=tqu0GOGWTAbwR/Nsk8YI3SDE4DhJIGiAAgOAWgY/Fuo=;
        b=LxrF+sMFWrmtDzuekGxbk8pqZC0pVsMnDTEmTbnbw0RRt7Huw6N9EQb+jns/L/gIvc
         X/o8VomjuJdREg4lgqLDdcbfCIGYLhGoS6tZXcJUxzEFZQAB5Iz50JKaMeM8U7acoa6l
         G481TflRZcLH23eMRroUXPsTAxkBxa5qbpCryzcTaWtK1dnl5XL8DqmcGRa+7JMVQUlT
         jZ03WM56QxuhVyVSpnaAgAjQUIMfycyUAdOh0323AmX0LG/F3rdFGAu2MDBNYDlquWMA
         5OCBEvCOkQ9AWuKiIOAKrXT3zjQLU9JnWxN/Ak5ekKo9OHFs6+5QhuvuS/PJoUH5EJx3
         VI5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=fn8Jyr95;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tqu0GOGWTAbwR/Nsk8YI3SDE4DhJIGiAAgOAWgY/Fuo=;
        b=hRF5hyMMXZD1vOJzS3fK5aF1kNDHc5dwBYX7WgtsJHFUlpaIYMRLhyOXUYE04ybEIA
         xWfO+5/1IcV3wxFoDvMneiDWkYW6df87uIIN3FzZ2HdQdnOXRtmYDvfejqoMPKKi8C24
         5UDcPKHtgDkU21VVsJ2VuQ83ulq+ijiwu/8GkT/lVINlk1jDvJaXhKgoRS980zmZpjZt
         kGOgeoXv64oZjGkmphgBpPKbKnlnx9cJvJz/CUTysvdMmlNtWtqJodxKlS1oq9EWEZ0v
         w82vk5USXNMo+vV/lDP58xWCUcJ9TnuE9kg81X/I3oG5yl5Pnt9iN+pmWYohsnY9jQCE
         mAmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tqu0GOGWTAbwR/Nsk8YI3SDE4DhJIGiAAgOAWgY/Fuo=;
        b=NQo+mkWuwAFuTx06XBq+gV7erRsuRDJiWYw1xtOD7GBRuQqSh1DGUDY4MBooP77gk+
         PEV0FYotuYbee9xc55YwDBM9jJ293Ci38aTUTaizWZAIG/tQhtYuxYB99Iglw2Lg8Bi2
         GNWnaeKu0W7dgWf2gA9eSKS1tMqqrVDXRTdYLGMHwN95/RT3fkUEOEDJX3uIcCrazjKv
         vaZD6AnLsPO86HT9n482RWYJNQJ/5aLiqd6dSXjxTwDoqiV/qzUqSz2lOe+ebV7XnjAI
         QKkENYTx/1GqpCPUltYyRzcQhar/jQXwAiAnKEHfxIqn4mSK167ho41qNQgZx5AbQZC2
         snHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532TYXu8wN4cmKumraL6WcAb59Apoz84xop4L53PzJLC7OA0Hfe2
	dVEWtBzVVfshc0a94Ji9C4Y=
X-Google-Smtp-Source: ABdhPJyCAr9x0rLvTfamVjOss1Hsk5bgmHAdp+c5NZsDDeBedHpl/fq0UE/RrL30GBHUAxgBkVnoMw==
X-Received: by 2002:a63:1464:: with SMTP id 36mr2151007pgu.160.1598897889725;
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:2c47:: with SMTP id s68ls2790901pfs.10.gmail; Mon, 31
 Aug 2020 11:18:09 -0700 (PDT)
X-Received: by 2002:a63:747:: with SMTP id 68mr2156398pgh.90.1598897889385;
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897889; cv=none;
        d=google.com; s=arc-20160816;
        b=X8VRLYzW32KLZgSaAXBKd+02fv+by+pXTTVsUxbDYgttISQL9+ZwLEHcLNQFR3d8dd
         V8TvyfjEHWMDz15TWHfzLtel5ZM0SrGjTK2ZDwKPVWuHLZ6F4SU/FLBuTgdMtl66PoYw
         iCkcrpRIhJTtKQskNy7tGDjWJ5Q6xLkZ///ftWwQk7Wjm3WmtCfI7yQcX8sOXPBUGi7W
         utwL25m4pq/1Uc/ju+iCVTNmr4OFaZm5yG7e9MGA3UDQSX0aDe6svn2BxBs8tYMrmg1B
         7hZZZR0Bzd1Tm3oOaxyKT+mIC73JOQQjFwVqvOqXG8Kiq0uwPAPco4JYMa2w6m5t732o
         Hnyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=UMB4lUtdQATmapfzAIGccl/VB4tFj0pWlVudXIcyeUA=;
        b=cz1h8jqqpvnS3tL9AduAszV08iDX28Bw+0zuxUDQSGGEOXNnJgk1nrMCWFCdZ35jMz
         Qz4UJGP7+coJkIVMrXiCCfs87AvrxcjPRG7Au0URu0emaIIYDZB3wMAJZQlZEbWjxfsF
         EbwElFB2zanoO7iQQ75XcDjJGBXXB13bKLnFk5CIaZjRKEflwy/RY+w6Co8H0sQxXuyj
         P7TKMkSKAZVpyTzD1hJkLNxT3iby2tKTjIT8FvVT4QvXmpAt9voJe9kWWYDrObNfjXSz
         ExZ00BVpV5VnumBWPJPiai3k0uH4GhCNkVuxMPppZcLTbc9RiRp2Q7VdGw38if944vXj
         kNXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=fn8Jyr95;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n2si577538pfo.5.2020.08.31.11.18.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 15A0621527;
	Mon, 31 Aug 2020 18:18:09 +0000 (UTC)
From: paulmck@kernel.org
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
	"Paul E . McKenney" <paulmck@kernel.org>,
	Will Deacon <will@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Daniel Axtens <dja@axtens.net>,
	Michael Ellerman <mpe@ellerman.id.au>,
	linux-arch@vger.kernel.org
Subject: [PATCH kcsan 18/19] bitops, kcsan: Partially revert instrumentation for non-atomic bitops
Date: Mon, 31 Aug 2020 11:18:04 -0700
Message-Id: <20200831181805.1833-18-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=fn8Jyr95;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
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

From: Marco Elver <elver@google.com>

Previous to the change to distinguish read-write accesses, when
CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=y is set, KCSAN would consider
the non-atomic bitops as atomic. We want to partially revert to this
behaviour, but with one important distinction: report racing
modifications, since lost bits due to non-atomicity are certainly
possible.

Given the operations here only modify a single bit, assuming
non-atomicity of the writer is sufficient may be reasonable for certain
usage (and follows the permissible nature of the "assume plain writes
atomic" rule). In other words:

	1. We want non-atomic read-modify-write races to be reported;
	   this is accomplished by kcsan_check_read(), where any
	   concurrent write (atomic or not) will generate a report.

	2. We do not want to report races with marked readers, but -do-
	   want to report races with unmarked readers; this is
	   accomplished by the instrument_write() ("assume atomic
	   write" with Kconfig option set).

With the above rules, when KCSAN_ASSUME_PLAIN_WRITES_ATOMIC is selected,
it is hoped that KCSAN's reporting behaviour is better aligned with
current expected permissible usage for non-atomic bitops.

Note that, a side-effect of not telling KCSAN that the accesses are
read-writes, is that this information is not displayed in the access
summary in the report. It is, however, visible in inline-expanded stack
traces. For now, it does not make sense to introduce yet another special
case to KCSAN's runtime, only to cater to the case here.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Paul E. McKenney <paulmck@kernel.org>
Cc: Will Deacon <will@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: Daniel Axtens <dja@axtens.net>
Cc: Michael Ellerman <mpe@ellerman.id.au>
Cc: <linux-arch@vger.kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 .../asm-generic/bitops/instrumented-non-atomic.h   | 30 +++++++++++++++++++---
 1 file changed, 27 insertions(+), 3 deletions(-)

diff --git a/include/asm-generic/bitops/instrumented-non-atomic.h b/include/asm-generic/bitops/instrumented-non-atomic.h
index f86234c..37363d5 100644
--- a/include/asm-generic/bitops/instrumented-non-atomic.h
+++ b/include/asm-generic/bitops/instrumented-non-atomic.h
@@ -58,6 +58,30 @@ static inline void __change_bit(long nr, volatile unsigned long *addr)
 	arch___change_bit(nr, addr);
 }
 
+static inline void __instrument_read_write_bitop(long nr, volatile unsigned long *addr)
+{
+	if (IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC)) {
+		/*
+		 * We treat non-atomic read-write bitops a little more special.
+		 * Given the operations here only modify a single bit, assuming
+		 * non-atomicity of the writer is sufficient may be reasonable
+		 * for certain usage (and follows the permissible nature of the
+		 * assume-plain-writes-atomic rule):
+		 * 1. report read-modify-write races -> check read;
+		 * 2. do not report races with marked readers, but do report
+		 *    races with unmarked readers -> check "atomic" write.
+		 */
+		kcsan_check_read(addr + BIT_WORD(nr), sizeof(long));
+		/*
+		 * Use generic write instrumentation, in case other sanitizers
+		 * or tools are enabled alongside KCSAN.
+		 */
+		instrument_write(addr + BIT_WORD(nr), sizeof(long));
+	} else {
+		instrument_read_write(addr + BIT_WORD(nr), sizeof(long));
+	}
+}
+
 /**
  * __test_and_set_bit - Set a bit and return its old value
  * @nr: Bit to set
@@ -68,7 +92,7 @@ static inline void __change_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
 {
-	instrument_read_write(addr + BIT_WORD(nr), sizeof(long));
+	__instrument_read_write_bitop(nr, addr);
 	return arch___test_and_set_bit(nr, addr);
 }
 
@@ -82,7 +106,7 @@ static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
-	instrument_read_write(addr + BIT_WORD(nr), sizeof(long));
+	__instrument_read_write_bitop(nr, addr);
 	return arch___test_and_clear_bit(nr, addr);
 }
 
@@ -96,7 +120,7 @@ static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
 {
-	instrument_read_write(addr + BIT_WORD(nr), sizeof(long));
+	__instrument_read_write_bitop(nr, addr);
 	return arch___test_and_change_bit(nr, addr);
 }
 
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-18-paulmck%40kernel.org.
