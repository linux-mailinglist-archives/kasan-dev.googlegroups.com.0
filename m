Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV4H3P4AKGQEZ7ETTGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 37FE6227D0A
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 12:30:48 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id w19sf9475060edx.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 03:30:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595327448; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ic3tGDNqOlyykCJk0+6Z8Px3mWY5RWpCpakfXIMZ0p7WClEiNZoD1Jg/XHioR6UxhJ
         J/yjicMJutjg8Lo52aSnOlDL6Ew8aM8O55a0xijohGgudPOGdSHPcN4GyUsfv5nk+zh4
         jsx4OtS8q2yPcqk2VN1esqkRS8GRUWtQ1kfKQe00fgHPO/JjDQjk//P1G0E5Iw5Iuil3
         lvqfc9ltePBvn0i785zc22GqIQmlLti5gp3w4OanYxzuSIF7IHJhmfUH2a7lCLijiPdj
         EOWmwMz5KqAXB+7yuNBL2yRu+iKKghTG9exv5WgQkfEjzpRQzm0tg8VAt/kgNTHFIN0O
         abMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=cnLhWKDZQAG8nBhLUQJ/VTcBuApz1RCta6dJLS/dgy0=;
        b=VivX+pZ+tGJkDNIwYw+m0Vrc/9Fh62UAS91fjXSS4gO9jdV6U+t60TDa6Fmf0o2oxi
         GOSU5baPle0HJc2oD8ZQSUtMC3B6kbulBqaPrbq/QwH2ygQkLq2LWaQBmNzKKkxujTuy
         VXfyktkd+VMGRx+jGVl29dISIL3pgIaDdbFH7yL3rMICrHKDyuNOOng5SSH16PpGyLJQ
         Cp4sqjrTw/DBUZt0HqCCpqBDD9pIo5MkanSEKhUBWSqnohBju3ZgTL5NzTjqG3uR6cEY
         vwD/QAcQP0U2eN9C23HynSv4UW3dAcDvwsa2boWwHU92TnIui3CnpmajCpfoBR2lXnIu
         iGvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ll1B1CDJ;
       spf=pass (google.com: domain of 318mwxwukcbgcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=318MWXwUKCbgcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cnLhWKDZQAG8nBhLUQJ/VTcBuApz1RCta6dJLS/dgy0=;
        b=m88+2sOUMrstZWhihnmyQCu86VMkNrPJCYzxtr17gpeWwu/j7Aq7BgoME3v/k4iNd4
         wOOuvTlel8FA26I+1egVBwZ3+KE+aoAl2MPCCqN1+JJrYXAN6rM4pJRy+atSCbh01gD3
         kQxP1S41NW3P7MsnEHaob8reheKGLPQhwghl68Znprfr8TtJ07ThUSZ0HihbumKCGlmQ
         6s7plOAU/u4ifHWwe4uTbmUloxl8mfG1WKUrXYIbH6oIEIhZFJSckWBVS5ahxdgClrAX
         lpmfKDjLC3YcmXmuOz+zfBY7VsGf4YCKkk+Eja4d09kMgBSSwuTXVUQh4o8fydnqpeKo
         xTYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cnLhWKDZQAG8nBhLUQJ/VTcBuApz1RCta6dJLS/dgy0=;
        b=kCwX89cZ2lzRbtXiWXUG0nTK1Jr+cdVREW4sNITsebPF7xSXx9VPD4anDne06ZqK7J
         gDYi592aY+oB9WOFyNa4QJuBA+28ScEV7e2KXb7sWX8NS/8q5WxxsXgiblVy5PD/vWoA
         8erZSgXpeanoAZVUtIueKK6soDAge4Rjb+7eOTw3GkrTksvcK+WVbjJPZOqmrUMjjCkK
         +DmUdbTjmYf0qbMBDjgFCKaIObYYU2wewYrcbkuvJ7tQLNxt6ZxLWeXc0y6u76074iL2
         /zQ0Fs6NQ9pU8lA481n6GzynrJxM1qzm6JQg3K3WA9nzMc2uKWRX3Td4Ei+raC2oolnz
         3Tpg==
X-Gm-Message-State: AOAM5314O2/AR6fqrwZacurkFhF07lZv6pdS2ChkYDnLUvHL7ILXEoMX
	58wX4vIuD4w3CHfyGrNpLvM=
X-Google-Smtp-Source: ABdhPJy/2PywSY8l9X9oAH9wjiVQGwrfHuDjgPsvCRJCBpHOT1X8bBcQZNXgjZk0/h7wKrg8VmRQWg==
X-Received: by 2002:a17:906:abc9:: with SMTP id kq9mr25180245ejb.493.1595327447970;
        Tue, 21 Jul 2020 03:30:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:9147:: with SMTP id y7ls9243691ejw.6.gmail; Tue, 21
 Jul 2020 03:30:47 -0700 (PDT)
X-Received: by 2002:a17:906:1682:: with SMTP id s2mr407097ejd.532.1595327447394;
        Tue, 21 Jul 2020 03:30:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595327447; cv=none;
        d=google.com; s=arc-20160816;
        b=0CsBlnmbVXZDXdOLDhTDw4r0WVt0t2FnjSC6icKxUyhL26hH3RbaW1ItT+PcB8tPw+
         OrFFJ0lZGl/6sMwDVoRUlyB5TjgeT9TW5BLQFi2RI2m+8oeMO/7gwD81kwGPxRCAlQOT
         9VSGB7Hqf2OjEj5Q6vENY9ehlY1jzgRNbb+E8Y159P6BXHQY9fEeVqH1JRXQz61n2B/T
         gEXQsEJ4CMWVNDknmoiiLkuW8vWVw2rYNSJUiLbg9CM4I4tzDNysQNEKger1vMGCdrP+
         DO1Hs3yfqE1b1djIemLxRYH4zfaM9h+CgU++Y7GMbSOrxbkYEUJWaK5SKAAXN07ssNid
         GY6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=+ikYXLHhML1V0ebfQAy4A07GGk0dvPdarKLZgU/LHY8=;
        b=SyhXdSrqfCDaU9nznQNX3TLEU4x+Qme6iPErCd5uACM19MCZeGAzmbsMSaOUidGmYL
         8swHm30zQ/sVYi4L/7WnX4dVwMZi9QQ3yHMV0qd1KaMPiza/sOHQM5iTTDKD9m5ywmdI
         TM7JBA1KpcgQgWlmPx7CwQS7G6eH6lib9tLHd4L11P5w6ILV5vxBjC6LKyqqgyzp/ACv
         aIIo5Er733Hd6NmNAe6BD58j8BF265ojG579BGWr8/C7o9fJ1NPj6k2P+UtzJOGq6yPp
         SKo9d3lm0WZdTQ3IAJB/69btzSkSs1Bf/wmqevFVeH0y90SzElOV+zZtWHVnJKYhs79q
         v5WQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ll1B1CDJ;
       spf=pass (google.com: domain of 318mwxwukcbgcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=318MWXwUKCbgcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id q9si750033ejj.1.2020.07.21.03.30.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jul 2020 03:30:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 318mwxwukcbgcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id f14so2334642wrm.22
        for <kasan-dev@googlegroups.com>; Tue, 21 Jul 2020 03:30:47 -0700 (PDT)
X-Received: by 2002:a7b:cf16:: with SMTP id l22mr3762023wmg.68.1595327447092;
 Tue, 21 Jul 2020 03:30:47 -0700 (PDT)
Date: Tue, 21 Jul 2020 12:30:15 +0200
In-Reply-To: <20200721103016.3287832-1-elver@google.com>
Message-Id: <20200721103016.3287832-8-elver@google.com>
Mime-Version: 1.0
References: <20200721103016.3287832-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.rc0.105.gf9edc3c819-goog
Subject: [PATCH 7/8] asm-generic/bitops: Use instrument_read_write() where appropriate
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de, mark.rutland@arm.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ll1B1CDJ;       spf=pass
 (google.com: domain of 318mwxwukcbgcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=318MWXwUKCbgcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
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

Use the new instrument_read_write() where appropriate.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/asm-generic/bitops/instrumented-atomic.h     | 6 +++---
 include/asm-generic/bitops/instrumented-lock.h       | 2 +-
 include/asm-generic/bitops/instrumented-non-atomic.h | 6 +++---
 3 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/include/asm-generic/bitops/instrumented-atomic.h b/include/asm-generic/bitops/instrumented-atomic.h
index fb2cb33a4013..81915dcd4b4e 100644
--- a/include/asm-generic/bitops/instrumented-atomic.h
+++ b/include/asm-generic/bitops/instrumented-atomic.h
@@ -67,7 +67,7 @@ static inline void change_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
 {
-	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_set_bit(nr, addr);
 }
 
@@ -80,7 +80,7 @@ static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
-	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_clear_bit(nr, addr);
 }
 
@@ -93,7 +93,7 @@ static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
 {
-	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_change_bit(nr, addr);
 }
 
diff --git a/include/asm-generic/bitops/instrumented-lock.h b/include/asm-generic/bitops/instrumented-lock.h
index b9bec468ae03..75ef606f7145 100644
--- a/include/asm-generic/bitops/instrumented-lock.h
+++ b/include/asm-generic/bitops/instrumented-lock.h
@@ -52,7 +52,7 @@ static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
 {
-	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_set_bit_lock(nr, addr);
 }
 
diff --git a/include/asm-generic/bitops/instrumented-non-atomic.h b/include/asm-generic/bitops/instrumented-non-atomic.h
index 20f788a25ef9..f86234c7c10c 100644
--- a/include/asm-generic/bitops/instrumented-non-atomic.h
+++ b/include/asm-generic/bitops/instrumented-non-atomic.h
@@ -68,7 +68,7 @@ static inline void __change_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
 {
-	instrument_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch___test_and_set_bit(nr, addr);
 }
 
@@ -82,7 +82,7 @@ static inline bool __test_and_set_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
-	instrument_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch___test_and_clear_bit(nr, addr);
 }
 
@@ -96,7 +96,7 @@ static inline bool __test_and_clear_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool __test_and_change_bit(long nr, volatile unsigned long *addr)
 {
-	instrument_write(addr + BIT_WORD(nr), sizeof(long));
+	instrument_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch___test_and_change_bit(nr, addr);
 }
 
-- 
2.28.0.rc0.105.gf9edc3c819-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200721103016.3287832-8-elver%40google.com.
