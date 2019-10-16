Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMVPTPWQKGQE5TUCDVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B43FD8B50
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 10:41:24 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id w8sf36753962iol.20
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 01:41:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571215282; cv=pass;
        d=google.com; s=arc-20160816;
        b=GSoI8J+8ZxVUE3mcPdQ9BJwoSSVvts0wTr4ZZGKhfZvU1yuSonlcRQ45e/OYRMyUec
         zGNNQoccMeyfeyWFG+ektDRAOrbzDCvlNwS8gZAkkBmitxOh1xPf/9gfzNamInnmMWAt
         W/cAMbdpyOCN4cNacoEZ8dd8rMgWwMCXsWdEXEZvLKHPY8euzpic25Q3SFzIi8iPCkDK
         pZESmxQbVN0tBbpaYJreItkdywDzHZWyrLvYAZ+vqUo/3kbMLP6EltoTTbBqlRzPejII
         9VdFk0xVkINgh0ycp3uC5wlevzYJcj21ovsxliBpONCc4/J8LcFzUb2iUjpUJYSTkigq
         MyJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=N5gG4QewLlBncFLNQgvDjibfTXcxMNL7Ximd5O44l1g=;
        b=gKz0PW8Z7wF5tZZSA6uigG2X0SKwO7ty0vjfY2kWkvIwMdxUc3MzQsTxUENMhaL/NC
         TzsmYgbbUkc0BU5Ltvug02Dt0Tkj8/M+c2ql2LbWF+wQgySS0FNyzWlUZ5/S1vlsrnrP
         cJAeI2R/PnRRNWfxzc0yn03AxUtKD36ujuXx8xKza0DxplHVhgW3fkj/erO61HlpIod9
         cai72HvmUllKi7us4aN+cNmrhDTiz6W+lPBR0O7Mgb1RtHqVk9QbWWcDNdVhVMylqZYj
         4tQj2qy13VOlYvgwhhTVQOf2ytwIHnFqsaiMJ8nJiRbRL4vIuvw5l/UgtLSAsgnRwylP
         cmkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=drf8mRJE;
       spf=pass (google.com: domain of 3sdemxqukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3sdemXQUKCe4UblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N5gG4QewLlBncFLNQgvDjibfTXcxMNL7Ximd5O44l1g=;
        b=XJ1Dt5TnpLM1IDWPUKUF8S9VFHzGOOgESHA4qtGeEeugi9RRSQIT1HOmC28l8tSTRf
         qMUdKdDhHZJFGhINElbfJo0jkp4JTrIcRKOGS50T59XpgqS+LxSFXKT3L95ba0u2mZ8u
         k9IPmeUNVl/tuja7iETdHO6WPYIDITFfOO0xk4AwW515eQSnVhMxiTAQrcHf7v02X0/K
         VTsy2K5kyGYSuDY1daLtNXw/nwCRFU4zCT5GDAJf49Godln+KlOejD+qLg9f5N5z64Cg
         xDKqvOBwR5KRVG9y8uFEWFdbs5EYXq+xw6kAzrxH4feBIGgGRw9+lo4+2PLISM99cR/J
         psXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=N5gG4QewLlBncFLNQgvDjibfTXcxMNL7Ximd5O44l1g=;
        b=QIT+1bhOSZieG6sv7HkxOqifKQwnaQyZ5ovjqh3ieIC6VbUzFH/YMItu1AcB/ixO2s
         DkmlSKOZe8NrDaHAsi6zkQ2DWM0iAQwQyJijx8vejwUTYD4gyj3l1nLqJ+At6R9HdDKL
         LkVsJHmwyemiPQaGCgcTejSLcTGXvRPhoasLS9tAbpo33LEOu13GPVJvpZACdDt6PY63
         y2WJkL+9ysmvu7+5YciJpH+FL1M/zq20YLSR0TbN5ubQQHlr6l0XhoD96MojsnndY7kV
         ZqHxkY4Krjk+rD2HxCBvpDOeonGftF0hMNzrlMIRSQWruHO6Mba8a6fQ4elly7luP6Sb
         T0+Q==
X-Gm-Message-State: APjAAAWoaKMXRbI+BH0uViGgXRwp3HmqqrAHl9O++8Ytu1aEqevl7dwN
	m6l8NAlns7hBzUa9j7JZv9g=
X-Google-Smtp-Source: APXvYqyBoLYMGSkHr/J7Kh5BNuOwg4mOXAUWSJR9P2HBYCxNg+vBrTMLN/mvHXvjRCWgnCtSbv8lJA==
X-Received: by 2002:a6b:3807:: with SMTP id f7mr18291778ioa.82.1571215282704;
        Wed, 16 Oct 2019 01:41:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9145:: with SMTP id y5ls6292434ioq.11.gmail; Wed, 16 Oct
 2019 01:41:22 -0700 (PDT)
X-Received: by 2002:a6b:730f:: with SMTP id e15mr29014079ioh.279.1571215282355;
        Wed, 16 Oct 2019 01:41:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571215282; cv=none;
        d=google.com; s=arc-20160816;
        b=mHqH1Euyu7PVk74iWvTHE4YD8qHb2P4nJE7qapwxKBqt02i0oOGkgcTubOJNZEmgeu
         OzhLlaoQJoKwehHLe5QbQDYOhZtYv0Exyw8Nfc3CNC3Imy3oS6jEKOnnQBRZBnmnJOWr
         PbU0j5iVrEwzfq8yTJ0jwQIu9t2KypX9jB3PF4Tn7v7zTRK8tpCNNbBXe6gNbB1itZtH
         I0OmsmsZV5aLIGXGd7DHje/PO8Qz2DeocV+GwQ3nP1M7rzLunfuFGqbSPbvu/9FVpFtQ
         Fynnt/5UcIgnnQ/zIrCipoxWa+4ylanCwQqB911w0gv5WbjZI7fv3bJ/BuyIwe713+y0
         TlUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=M8fHJrEZDU8nr2N9+M6QpZBStFZ02E5+Wb/B5OdwNhY=;
        b=X8MA6TMwY5o1bO/zqsEou+upLTeIbto7hxoxsfKHJO6dIN5ZBrtzzNvYopm1i5Ddch
         BenYMqvphkaBqDvRTI3FuuMz8lTVLws/vSTgrgwKVEbZh9fygyBVz5WciJOd6BkVsWDc
         BGAcP2OI4W2U2qZMtb+9+crCqNmh7Kqylgjlib1UB/wlXbk29pYZJ+cC2jdvct2GiotM
         DFsLUcNyofjAecSug+8LtyRUbh9b+/0K64nsHSDsYnm5qnuWfURio4wLsWJaGRq7sL0W
         I9ub3mP6U/uj80aKARLBOCC6PC5TW0AAFMHcU+YqFkJP+8EobByNe1Ss03suKx95eW+h
         RI8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=drf8mRJE;
       spf=pass (google.com: domain of 3sdemxqukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3sdemXQUKCe4UblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa4a.google.com (mail-vk1-xa4a.google.com. [2607:f8b0:4864:20::a4a])
        by gmr-mx.google.com with ESMTPS id s5si570913iol.1.2019.10.16.01.41.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 01:41:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3sdemxqukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) client-ip=2607:f8b0:4864:20::a4a;
Received: by mail-vk1-xa4a.google.com with SMTP id d64so9414332vke.6
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 01:41:22 -0700 (PDT)
X-Received: by 2002:ab0:2456:: with SMTP id g22mr15100034uan.82.1571215281436;
 Wed, 16 Oct 2019 01:41:21 -0700 (PDT)
Date: Wed, 16 Oct 2019 10:39:55 +0200
In-Reply-To: <20191016083959.186860-1-elver@google.com>
Message-Id: <20191016083959.186860-5-elver@google.com>
Mime-Version: 1.0
References: <20191016083959.186860-1-elver@google.com>
X-Mailer: git-send-email 2.23.0.700.g56cf767bdb-goog
Subject: [PATCH 4/8] seqlock, kcsan: Add annotations for KCSAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@linux.ibm.com, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=drf8mRJE;       spf=pass
 (google.com: domain of 3sdemxqukce4ubluhweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3sdemXQUKCe4UblUhWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--elver.bounces.google.com;
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

Since seqlocks in the Linux kernel do not require the use of marked
atomic accesses in critical sections, we teach KCSAN to assume such
accesses are atomic. KCSAN currently also pretends that writes to
`sequence` are atomic, although currently plain writes are used (their
corresponding reads are READ_ONCE).

Further, to avoid false positives in the absence of clear ending of a
seqlock reader critical section (only when using the raw interface),
KCSAN assumes a fixed number of accesses after start of a seqlock
critical section are atomic.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/seqlock.h | 44 +++++++++++++++++++++++++++++++++++++----
 1 file changed, 40 insertions(+), 4 deletions(-)

diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index bcf4cf26b8c8..1e425831a7ed 100644
--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -37,8 +37,24 @@
 #include <linux/preempt.h>
 #include <linux/lockdep.h>
 #include <linux/compiler.h>
+#include <linux/kcsan.h>
 #include <asm/processor.h>
 
+/*
+ * The seqlock interface does not prescribe a precise sequence of read
+ * begin/retry/end. For readers, typically there is a call to
+ * read_seqcount_begin() and read_seqcount_retry(), however, there are more
+ * esoteric cases which do not follow this pattern.
+ *
+ * As a consequence, we take the following best-effort approach for *raw* usage
+ * of seqlocks under KCSAN: upon beginning a seq-reader critical section,
+ * pessimistically mark then next KCSAN_SEQLOCK_REGION_MAX memory accesses as
+ * atomics; if there is a matching read_seqcount_retry() call, no following
+ * memory operations are considered atomic. Non-raw usage of seqlocks is not
+ * affected.
+ */
+#define KCSAN_SEQLOCK_REGION_MAX 1000
+
 /*
  * Version using sequence counter only.
  * This can be used when code has its own mutex protecting the
@@ -115,6 +131,7 @@ static inline unsigned __read_seqcount_begin(const seqcount_t *s)
 		cpu_relax();
 		goto repeat;
 	}
+	kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
 	return ret;
 }
 
@@ -131,6 +148,7 @@ static inline unsigned raw_read_seqcount(const seqcount_t *s)
 {
 	unsigned ret = READ_ONCE(s->sequence);
 	smp_rmb();
+	kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
 	return ret;
 }
 
@@ -183,6 +201,7 @@ static inline unsigned raw_seqcount_begin(const seqcount_t *s)
 {
 	unsigned ret = READ_ONCE(s->sequence);
 	smp_rmb();
+	kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
 	return ret & ~1;
 }
 
@@ -202,7 +221,8 @@ static inline unsigned raw_seqcount_begin(const seqcount_t *s)
  */
 static inline int __read_seqcount_retry(const seqcount_t *s, unsigned start)
 {
-	return unlikely(s->sequence != start);
+	kcsan_atomic_next(0);
+	return unlikely(READ_ONCE(s->sequence) != start);
 }
 
 /**
@@ -225,6 +245,7 @@ static inline int read_seqcount_retry(const seqcount_t *s, unsigned start)
 
 static inline void raw_write_seqcount_begin(seqcount_t *s)
 {
+	kcsan_begin_atomic(true);
 	s->sequence++;
 	smp_wmb();
 }
@@ -233,6 +254,7 @@ static inline void raw_write_seqcount_end(seqcount_t *s)
 {
 	smp_wmb();
 	s->sequence++;
+	kcsan_end_atomic(true);
 }
 
 /**
@@ -262,18 +284,20 @@ static inline void raw_write_seqcount_end(seqcount_t *s)
  *
  *      void write(void)
  *      {
- *              Y = true;
+ *              WRITE_ONCE(Y, true);
  *
  *              raw_write_seqcount_barrier(seq);
  *
- *              X = false;
+ *              WRITE_ONCE(X, false);
  *      }
  */
 static inline void raw_write_seqcount_barrier(seqcount_t *s)
 {
+	kcsan_begin_atomic(true);
 	s->sequence++;
 	smp_wmb();
 	s->sequence++;
+	kcsan_end_atomic(true);
 }
 
 static inline int raw_read_seqcount_latch(seqcount_t *s)
@@ -398,7 +422,9 @@ static inline void write_seqcount_end(seqcount_t *s)
 static inline void write_seqcount_invalidate(seqcount_t *s)
 {
 	smp_wmb();
+	kcsan_begin_atomic(true);
 	s->sequence+=2;
+	kcsan_end_atomic(true);
 }
 
 typedef struct {
@@ -430,11 +456,21 @@ typedef struct {
  */
 static inline unsigned read_seqbegin(const seqlock_t *sl)
 {
-	return read_seqcount_begin(&sl->seqcount);
+	unsigned ret = read_seqcount_begin(&sl->seqcount);
+
+	kcsan_atomic_next(0);  /* non-raw usage, assume closing read_seqretry */
+	kcsan_begin_atomic(false);
+	return ret;
 }
 
 static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
 {
+	/*
+	 * Assume not nested: read_seqretry may be called multiple times when
+	 * completing read critical section.
+	 */
+	kcsan_end_atomic(false);
+
 	return read_seqcount_retry(&sl->seqcount, start);
 }
 
-- 
2.23.0.700.g56cf767bdb-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191016083959.186860-5-elver%40google.com.
