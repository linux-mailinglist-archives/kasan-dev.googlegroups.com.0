Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLOZ2X4QKGQE4FMR4YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2854D243D8D
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Aug 2020 18:39:11 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id o26sf1680541vkn.21
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Aug 2020 09:39:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597336750; cv=pass;
        d=google.com; s=arc-20160816;
        b=I/1EOPN0pRPEftp5h4+8EtPTKIaQ3sw0SutZ3oGpsC6a4XT9dUUdyUTostX+D4nSc3
         NzZycOR6nwoPk69pcVVJnT6/8TQ9NUDVrNWRE7JsDgBH+HbmOCjio8+4U12i4GdWZLdz
         UrW2XHVsFd4DwaN1NTFKrzcXv0EcHG6GW+DGX0HKmBw1CTWIpjAvg4pdjzXkaoufDlYz
         UQHZAfR5DkSNhIpFjnCfOHceDxOS5jGkXY4JpktzUN5o+/kVfdl1KapbYaTpmmH7RaKK
         J2E2wj7k3qkiuBI+F3NesVoMcGVlzssjYN6ID0b1IQv81qMsWPeTaDANqV5BbDaH95o7
         RUrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=//qQtEzv9kLCnnmUTlbp5lP1q1Lp2br5WHCDO7qChqg=;
        b=mWF2Gi1mjFq8KMzO9wsATZy2IuFFC0gBChFhl8n+yt3BSZIznVYMOS/oIXWHk3B/IR
         rJl9KUwLj51Ve7ZtIS1mDI/MZJR4OuYjbpi5SuFL8fDiJdMC2ypovXYhk/PXSBNYXBxW
         J88KDEx90slop8hoQ2woBPVlW/s+v9VWU0ZeiBug3zVg7TolMUxNvvPUwWXQAeUttOYi
         GC0Fbl4saqcIHQGEhwIpn3+WbSs+hM9MqQ5qIrkow3/Vj/cZ7IUIKlxGYwIU1LmBUUSv
         u69yyLvm0ezGJLHq2262EK39wREcUSurt8g4FPiPOTHyOf7emMeOXIghCzuf7S0EN8Fm
         4RgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kbQXXy2B;
       spf=pass (google.com: domain of 3rgw1xwukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3rGw1XwUKCVs7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=//qQtEzv9kLCnnmUTlbp5lP1q1Lp2br5WHCDO7qChqg=;
        b=tJjLx1U8RrPL+t9RbXocOzHdS5QC9xcpfraoLB8K6z8t5feJgmQQsID2s+pX3wpmhs
         rlZXG4fCMgsInlASlEplGLiqWtbZRMvwP0ARnBUAonn36b2tYnR9iSBXIFXeLJ4o2iUg
         q2pcDBa8x1+dA6tvtn1mGxc7Pyd0bFL7xmjwThzE8dxmC83JeH2S7D4LzOZTGGHSeQZd
         sYG2xbpgO7Moy1DM+e57z6lN+L9wOJL/XSeZDQHoDDSHxzMll+dEJDT0LhNxdzr6Vdkm
         LGVNDFMo54/z8+zWwMCppnST6feiWVeDfw1tWkgqRjqvp4ERwpaBdf8jy7vBQRQsdMKA
         Kwhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=//qQtEzv9kLCnnmUTlbp5lP1q1Lp2br5WHCDO7qChqg=;
        b=NeRzX2v/1q8aS/5tg1w54pY2/GUEvIyFtdzEbRxivdrsh8tk1ciLS39XuZGMBIKELe
         S1D4nmw6BfWrVxFPNxxuqPSDBYSUL0puLa/XxcuqSpChrTxJ+WJD2H8H5D+dbo5D6O/q
         5RhIFEkrjjiGPGnKd/AovTJ5WbZHnDo2S+L+TDXtm6yHqqYT2HThPm5ewz8y7H7SoHwE
         OTzkn/r6b8sIGK3ubocUcbQUztQt79ppE7R5uhVU5ulKyh2eSrcLiB5Pew/i/sbYk8TJ
         tHQAHCT+iw4esTGXYy6PWiSi94pYY6Od+yc2J9KyHJ19MJN+bdm2vI7GU1TSg9jFfRIQ
         rhsA==
X-Gm-Message-State: AOAM532d3Cc2bBmKV+uyZqcbF5vPMUFqaADrDe/YCQvzvC+3Z9k0SuGb
	yzCcs/M+5ocuKmeN3BGRqAU=
X-Google-Smtp-Source: ABdhPJxBf0N6RwJumr9l/bIXUy4Pvn2OtKXIPGe+fCPF+cla8ADUzuqKjn5C0dqVPED0EX7r9ZWyGA==
X-Received: by 2002:a67:f555:: with SMTP id z21mr4209811vsn.187.1597336749911;
        Thu, 13 Aug 2020 09:39:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:6e0b:: with SMTP id j11ls314851vkc.1.gmail; Thu, 13 Aug
 2020 09:39:09 -0700 (PDT)
X-Received: by 2002:a1f:3d97:: with SMTP id k145mr4442509vka.8.1597336749418;
        Thu, 13 Aug 2020 09:39:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597336749; cv=none;
        d=google.com; s=arc-20160816;
        b=ml7t0GTuhVVJ4BHI3O/GtD0CJtEzwxZhVjDLMIdizVDWU/SDqbxRj0IOpCR2fqHw6O
         SwIPGCV/QlO5be3nb1fdxET3crB2HNR3viU6obH07WzYlcVFBQ4vUVltOE6Utr2sIANi
         5ioHy6F7Y2EsEAccrJlyvM6Jb6/3ngNDo1aISx1No7GjIAjsOEfonc0NvpI80+KFJHac
         IGpctQjACydXRj+Lt35tL3jl7y9ShC2YLhOYwkZ8OW9znpxegKLeFBBZt4UUI36YObNC
         mKGYeKbegHx32e2At3T8Q6BHwythbtaEggBxKMZSKoO/GIqToXIqXMYA24covydU3B8R
         fKYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=EXiQM+OwcDwzJXyrdpXsirkqETQSrhVgpmlZfZrdtjc=;
        b=0wsfaBK+/DUKcO5seGrB5mjs3bVvLQJbFWzf4z8c6EbdM9pu0Ur08ZK8B+0ZBdNk/U
         YxCu66dG2zd3AKTV+dPNYdGFQL3oJrq561kCozbl4tenGJJL8PvXwSumDnfUSPXDS8TP
         1rh5pelu7J/xNPF4PqIaTlICXQ96Eg2a+ORwzAXxZV+QyFwfQVbuAI8gBOO+beDYHzV6
         9agi58yOa7FdL3G4j4jBCFB3BZkNkKPYbm5gARa3MZGr1DfuQ31vjSXUtEkipNX/SwvS
         PkOJ7RlbK6f/dvv2USsyeMnt9MNBT9loVczwN0Mak5Mz4GcAlo4g5qAiTxLQwPw0A0wN
         bpDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kbQXXy2B;
       spf=pass (google.com: domain of 3rgw1xwukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3rGw1XwUKCVs7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id p19si460529vsn.2.2020.08.13.09.39.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Aug 2020 09:39:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rgw1xwukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id a14so7295062ybm.13
        for <kasan-dev@googlegroups.com>; Thu, 13 Aug 2020 09:39:09 -0700 (PDT)
X-Received: by 2002:a25:d1ce:: with SMTP id i197mr8653927ybg.100.1597336748940;
 Thu, 13 Aug 2020 09:39:08 -0700 (PDT)
Date: Thu, 13 Aug 2020 18:38:59 +0200
Message-Id: <20200813163859.1542009-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH] bitops, kcsan: Partially revert instrumentation for
 non-atomic bitops
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, arnd@arndb.de, mark.rutland@arm.com, 
	linux-arch@vger.kernel.org, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kbQXXy2B;       spf=pass
 (google.com: domain of 3rgw1xwukcvs7eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3rGw1XwUKCVs7EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
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

Signed-off-by: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Paul E. McKenney <paulmck@kernel.org>
Cc: Will Deacon <will@kernel.org>
---
As discussed, partially reverting behaviour for non-atomic bitops when
KCSAN_ASSUME_PLAIN_WRITES_ATOMIC is selected.

I'd like to avoid more special cases in KCSAN's runtime to cater to
cases like this, not only because it adds more complexity, but it
invites more special cases to be added. If there are other such
primitives, we likely have to do it on a case-by-case basis as well, and
justify carefully for each such case. But currently, as far as I can
tell, the bitops are truly special, simply because we do know each op
just touches a single bit.
---
 .../bitops/instrumented-non-atomic.h          | 30 +++++++++++++++++--
 1 file changed, 27 insertions(+), 3 deletions(-)

diff --git a/include/asm-generic/bitops/instrumented-non-atomic.h b/include/asm-generic/bitops/instrumented-non-atomic.h
index f86234c7c10c..37363d570b9b 100644
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
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200813163859.1542009-1-elver%40google.com.
