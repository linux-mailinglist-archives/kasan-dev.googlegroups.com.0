Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE7OUHWQKGQEU3JZ75A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3c.google.com (mail-yw1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id E3852DAF60
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 16:13:40 +0200 (CEST)
Received: by mail-yw1-xc3c.google.com with SMTP id n3sf1844817ywh.11
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 07:13:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571321620; cv=pass;
        d=google.com; s=arc-20160816;
        b=EoboNd+dNVSoWC4r7haQU31/SVoiSEJ6B54OXsylIl/AAF4cojhfuIvI/Kxffo7Rk6
         FVUxm+l+MWgynW9IbZsgo9dSEP6oNlhwqSLG83amV+5/uObDZ7mMDtBcVanO65A8mQxp
         IeH3OBLZAsXtyCAlKxEweB4viFRiYy1pb/1NEWpJgWPTXVcM+uHmzzi+oSM2+FJZsxPu
         W856xfQD/V7FbiyZYn94aFPN3zsHfB1Tvxz7vcv3NHsenf9C1MBeZffhEP1u1CTffUTl
         xuS7RyBdPTJTJMP8ODK6qtALiSxEZs5ukmRVJxJ3J10GvPVREJa9NydEjRSw8bG18STO
         mbVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=K1xOfLiJThP7l0G1Bt5O1wI4y0DxrfSeCKyt618kWLo=;
        b=vKM2m8MZi87JXO2ZBFTt1g/IOdjfF23L10mkLz4NOPglSdZHjW3ToMtB0VwVMpcBxa
         FStvBnmc04EcqZNBahzvcBb28Bya2YwKxNMzseylH/7jzLhbR8/D8MeIVfPzKo3Xh/vR
         fP0zMll/o37gDUu7AUxcnahpTgeuUGaEHKn/w5EgWYbyHGH5Sx9toHlTLBCefGf1hY67
         h3QDZsE0y3diZKSqKwJglLay+KMsnCGaZXRBPRQmATI9mmnorAjJaKqbfVRqkbH1V0lI
         KAVtnZvKGS69do1eKX7AxSRL6WHDSLTHGr+by1k+3F/tPgg8uhvidNsJ8b2OrXDC04Gs
         L7Ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AgCEZD8U;
       spf=pass (google.com: domain of 3eneoxqukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3EneoXQUKCZU3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K1xOfLiJThP7l0G1Bt5O1wI4y0DxrfSeCKyt618kWLo=;
        b=UTTcVCFmlXJno+fei4Onuk+aRPMtEPIuLNrgVOLaE8EeYe/46SHvcswjaTSu7gelEy
         FsMKcLrIy2G1SPLjDPdZyjhSRPrWPXy9TucUj4usbIqBzMXRotIaV45VbbmaI7ogG82F
         q9dk1rhcS8x3oOY+oauwm8+QU0F+CwcGy0FKNk//Xe/uDgIoB4nzixXqY+UxZ91uFiu1
         kvsLy50SCxXF6+1bBQ2+9qC8B+f+O2Ot3cD3EUiUT5AgFBqNXrRVpaV8EeNVP19LkJFK
         7FeNTgLEk+ZQkjCEz7DkjAo4sGOGXhnfnlGyiZTIRKUw9PFL/XslYsq3s9jLepiJq542
         xxAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K1xOfLiJThP7l0G1Bt5O1wI4y0DxrfSeCKyt618kWLo=;
        b=adC3La8utM2ipJcUNgSeqWvY+OvxVIUcnIC5Pemv8jlhmd5gPjfGiYOvznke5Z/z3k
         q8OcNbT3RryKMmBESDbfG0po/wRuUjEdlnTylMHp24/lfQ5zrh0U+rBUQD8G1iR9WY07
         C+J9wgm3H6qTqz0G0By39C5ZCL5Xh4mRzrmZ+fS9a8FF1C/kzybOaQEdDgsqxaWug1tB
         je7jAbsPcdhtBwR9ukApNs5G3swIS3aBE0fqwP6fgQA+IKWwNIFublmATgT2c/XaWYZq
         IFzWKAQmExxhRwnAVFmlfGRUklOUEKljExpUSZy3+AA3b9Tm0yqezjIj2D5ota4aSaIP
         VLMw==
X-Gm-Message-State: APjAAAWW9fQPr3tG6tgkAkEKCTZtsZLgFsGC44MXuh8og856Fc22Hifi
	dk2ivjtq6sjPbN6NSJvkPFk=
X-Google-Smtp-Source: APXvYqzbDFgQCYpYS3l2y9Zo7MJZwDNireS+vED7CcirgsjPLs5+UR5tvtQkjGQswFFKmyRL3F8zuw==
X-Received: by 2002:a25:73ce:: with SMTP id o197mr2316339ybc.377.1571321619913;
        Thu, 17 Oct 2019 07:13:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:e81:: with SMTP id 123ls408063ywo.15.gmail; Thu, 17 Oct
 2019 07:13:39 -0700 (PDT)
X-Received: by 2002:a81:4783:: with SMTP id u125mr3110658ywa.440.1571321619576;
        Thu, 17 Oct 2019 07:13:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571321619; cv=none;
        d=google.com; s=arc-20160816;
        b=fccuGG/ITH7BvJ4JEgKkB9r95fuWDeHCbdFeh1wGVSw6K/cXzl0AKG143O9ECnRfy8
         OoUXSJYvcakgS+V/7VGzDPGcczvsCZEooRU5n/uopeq/mtUd7M4GBQWksrzj3iBF9B0P
         8tbPup32LL+RlOOFoM32fhcsJ4cBWQ2v1u7BDiUzEEt0SIUglyDxOjkUSkW5tEWpzf2C
         Nw09r6sa6fKycbXDalY0OqPSCC/9Yw+mzi8ubssmsXtBDCqB6WlyNPSrOBDWI8tY/Fyo
         oddZZ3+fzSpj0puqTCBvt97P86bYqWeoI8U8xbqoqjdSOPIuUNq1yBxUmV6d0cRrpRup
         KWrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ip3P4i20fQEf4b5wirUedHF2574zJ+yd56tKHujm1bg=;
        b=lHHA5lDnfss5k8SJVlaxDxT72iGz25Dz4jltU4+0PfWICS1zRYCcXsDFIADUeIh56m
         eQlB6D5byF2Dmkj6Vf+7x2xdtWtF9a7lh74SdCfxJWzyxrf27Lbst52oZo25t4xE02ZM
         biv5gh+v+X45NnnCQZjGUEDBva1dW2/pAmRUmxzj1RkoC5BjpRxfRzlzjKp348pRmgjq
         0iecHPlXWjN5YZ+xBZF+3P+nqSvhXBGnv9LyA8jY8CBitQ7FuAIuAKjSujlY2newU1It
         jOmCbxbdaiuc/C1n3fmjv43dCocBmqo2cpLS00gvTNWX5HtHYplLpovSXzTir+MQMpiq
         3SEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AgCEZD8U;
       spf=pass (google.com: domain of 3eneoxqukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3EneoXQUKCZU3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id u129si75491ywc.1.2019.10.17.07.13.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Oct 2019 07:13:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3eneoxqukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id n4so2399769qtp.19
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2019 07:13:39 -0700 (PDT)
X-Received: by 2002:a0c:ef85:: with SMTP id w5mr4041664qvr.159.1571321618815;
 Thu, 17 Oct 2019 07:13:38 -0700 (PDT)
Date: Thu, 17 Oct 2019 16:13:01 +0200
In-Reply-To: <20191017141305.146193-1-elver@google.com>
Message-Id: <20191017141305.146193-5-elver@google.com>
Mime-Version: 1.0
References: <20191017141305.146193-1-elver@google.com>
X-Mailer: git-send-email 2.23.0.866.gb869b98d4c-goog
Subject: [PATCH v2 4/8] seqlock, kcsan: Add annotations for KCSAN
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
 header.i=@google.com header.s=20161025 header.b=AgCEZD8U;       spf=pass
 (google.com: domain of 3eneoxqukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3EneoXQUKCZU3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
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
2.23.0.866.gb869b98d4c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191017141305.146193-5-elver%40google.com.
