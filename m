Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMXLQDXAKGQE2N2RW6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3d.google.com (mail-yw1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 724FCEE259
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2019 15:29:08 +0100 (CET)
Received: by mail-yw1-xc3d.google.com with SMTP id y200sf13657430ywg.10
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2019 06:29:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572877747; cv=pass;
        d=google.com; s=arc-20160816;
        b=SFSLZgu4PhrF68kj+QgB59uz9WPw6ajb3QvdBg0OuW/0LDRqVwSmJTEH6tyM2Hi6ch
         6sX2HLEndJrjBDRVWQH1h5DCETyKSl1mYKCgMgaaZcg1EvUdY921Xj+wHDnRB1uk+VLK
         +PQJOefhz1HrCLcD8uGCq/8WQ9yNPq/pNAObOjEGvJ78WHxalEFjFejmjwRkYbPhJQbw
         7hL9HbQwvy8dHEeoaDWNBXWF7sDJAa1+QDscI8NDSok7Y4MTHge/tnf1RFd08rOK9HVk
         Isuqrwzj3JoLhT6lGjvhoIyRVT38jYdzdVesFIirD1GtN/o0R5iRScPGBfVdUGYGtgIv
         BMZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=XS2Y+P4XiG2Eq7ACF8x/sbXzSamCfauzr5AoH4Erw60=;
        b=PzRTvF4dF8Lm/aCXaWbWzLcoZVsJYGvKPbaYExr6K4Cpd4P+52uwF2dNEtBNelZ2jf
         Sp/wJryFGQ0WG5ebtBah+iY1YNgy+vZkFxY65Oirpicx0WFIiCt+WFgzEY6FzckBuHFo
         hm69wSgVvMpUkLb7GUHHvRA7BogFonRNteL7nF3j1fqLW+46qDjrPL+MQZvJw2AYfIyH
         bGIxPgPJcvaH3JLKop7wb1daSYb89MFTJ4fbhC+AwU9s9t/5LxD3LPbLgiJlg6RzAV2H
         +RYC3NzNfcBJdlp7w+X+5mFJfsAG6mFWk90wDeAdRK5hw24FzWtrXlZjYop4bwk9oFpY
         Hs6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XpBlnjzT;
       spf=pass (google.com: domain of 3stxaxqukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3sTXAXQUKCRIw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XS2Y+P4XiG2Eq7ACF8x/sbXzSamCfauzr5AoH4Erw60=;
        b=tBkrftESPagp1hwMtEZAxSRJRmYeZ8KTKdTFGMNKCyxBp68kG2W1irKV8wuMowLjY9
         1FHCBkO3ekNSWWSHfJbz9e5lQqR3wshGzng5IrAxenYFpU/Ap0p4xzDNO3mAyl8xs1Yx
         Us/7JQbxe41luMCMaP53jRb3X/lq4fUQU4EYsVr71jT1YO1RMz/Yqiv2t9LfJB2ltnvB
         lC0DTt/109mCGsD8zTvTSXmLOg+BbwFpkgSJHGdLFjCy0lW1QjZxJxL6pehRtywHEwZk
         FOZIeUa1Wy1sOwiZuflGXoD5QkzcHTnUeF/9GMxCqwWEhpS30FODxlrcus15hb0p2M6T
         CUlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XS2Y+P4XiG2Eq7ACF8x/sbXzSamCfauzr5AoH4Erw60=;
        b=QZVUT92FeJCNnIAodnQc/hGHD4/P1m7zGnG2CJ7Eg7Zi2QBJPjj8i9w54IagIhRm+g
         wESViUwCeAyNDundRFJYWNoCaSIKN23EWOnOdoVAMD9Hp3yYflQKhxz3KHXP5AMI3tJL
         OWGCQfaPlbL8BFVrBFOaa/zDG1/35JBGa3IWS23dBVu39GqBfHqtRHMHPDKH7/3xQEDD
         plkDJt9tBnX/ulNrRb1tjau8BbkM/ln5zMPRegjfY30WW0HQKWhfQGyVayacwAIpXc3J
         kS9Wgio50wc/t2qyCzJOfJoqHdlVHoP2+QiH9c8u4H3AXKBQ58TMEguF+lyBYbYUPIyo
         48Pw==
X-Gm-Message-State: APjAAAXXdmzeV78zffE2CDGTeMQnNqnEG8Wd78dCps9teEezIaHl9YIP
	qsiyiEEDf2eoUZm6cQKzwZo=
X-Google-Smtp-Source: APXvYqxZkTQsj9amvtE7uAPsuwNI/ytRq2JJ46zECo/dskECelPrqzJtJj40IyUC8/E/gODStW0UJA==
X-Received: by 2002:a25:600b:: with SMTP id u11mr23395153ybb.437.1572877747036;
        Mon, 04 Nov 2019 06:29:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:5986:: with SMTP id n128ls2102624ywb.7.gmail; Mon, 04
 Nov 2019 06:29:06 -0800 (PST)
X-Received: by 2002:a81:2fd4:: with SMTP id v203mr8111921ywv.128.1572877746556;
        Mon, 04 Nov 2019 06:29:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572877746; cv=none;
        d=google.com; s=arc-20160816;
        b=keKqWYbRmp0JcaV/RHNLr/7Ht60zNxDtbw7aQN27zLG8UaYG6LCfWYMTkZyM3EZe1m
         cRwIJHd9i+7TuFxOCoJOgDzUz2tbrqbST1xawtLwb4PtInv3MVzE+k2NZEjCKcYY0IpG
         Tv9qFKnow7EauP1b84mzoffNQuTP3sfuj0K0H30HXPxBulDZduqsH6jFqQz4MpQ8NGbt
         LUAENZimgnwfpI14DDbBYCC0CFFvSBJBLAssxuenS8KyWP7PF1oIflAE/zkbnLP3u8Ef
         +HMmL3xFMjpPS2GUd5wuG0NS2o7kevS028wYcZKiQyDCrSyfDuS5XCeD/Fk25T0qOR6/
         cVoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=PnlUsFEddsbKHz2GK+uTFYcWeErcIfLobMYOTI3aPFU=;
        b=wGYeyRteLqQjsGfCEzMCHZb9/PxqEtq4oQ1hbQPo4PCOJ0Gfp3MPDVHfdTfhh7vJLS
         ksVoUjOGt6+W29eJIXlRpgC2TrKoYLigjyG8o8+wNZaTfx6Zse0jrQX/ZV76T3n66XMG
         PB4VlgCOp0hOrGt6vIE9RZ78hRsRyv9aQGf1PQL0WTzR34V/l1KaYwogOerJDPgrB7Oa
         8/32XWdx2GUiFBeCdp3OsiwNGIjLTu6eEnN+E6lb6KbO/HBPwpZozntIOs3hot35otBe
         egRdMnr9wCWM7iYrhnr7TSitvLXjF2cFlu5FfOIGDVgG5DeFm0EIpgbl8T42iHs+ggIy
         ys1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XpBlnjzT;
       spf=pass (google.com: domain of 3stxaxqukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3sTXAXQUKCRIw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe4a.google.com (mail-vs1-xe4a.google.com. [2607:f8b0:4864:20::e4a])
        by gmr-mx.google.com with ESMTPS id 63si56273ybe.4.2019.11.04.06.29.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2019 06:29:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 3stxaxqukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) client-ip=2607:f8b0:4864:20::e4a;
Received: by mail-vs1-xe4a.google.com with SMTP id b3so2797863vsh.0
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2019 06:29:06 -0800 (PST)
X-Received: by 2002:a1f:3249:: with SMTP id y70mr4259895vky.31.1572877745747;
 Mon, 04 Nov 2019 06:29:05 -0800 (PST)
Date: Mon,  4 Nov 2019 15:27:41 +0100
In-Reply-To: <20191104142745.14722-1-elver@google.com>
Message-Id: <20191104142745.14722-6-elver@google.com>
Mime-Version: 1.0
References: <20191104142745.14722-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.rc1.363.gb1bccd3e3d-goog
Subject: [PATCH v3 5/9] seqlock, kcsan: Add annotations for KCSAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@kernel.org, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XpBlnjzT;       spf=pass
 (google.com: domain of 3stxaxqukcriw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3sTXAXQUKCRIw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
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

=== Commentary on design around absence of clear begin/end markings ===
Seqlock usage via seqlock_t follows a predictable usage pattern, where
clear critical section begin/end is enforced. With subtle special cases
for readers needing to be flat atomic regions, e.g. because usage such
as in:
  - fs/namespace.c:__legitimize_mnt - unbalanced read_seqretry
  - fs/dcache.c:d_walk - unbalanced need_seqretry

But, anything directly accessing seqcount_t seems to be unpredictable.
Filtering for usage of read_seqcount_retry not following 'do { .. }
while (read_seqcount_retry(..));':

  $ git grep 'read_seqcount_retry' | grep -Ev 'while \(|seqlock.h|Doc|\* '
  => about 1/3 of the total read_seqcount_retry usage.

Just looking at fs/namei.c, we conclude that it is non-trivial to
prescribe and migrate to an interface that would force clear begin/end
seqlock markings for critical sections.

As such, we concluded that the best design currently, is to simply
ensure that KCSAN works well with the existing code.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Remove comment from raw_seqcount_barrier that should have been in next
  patch.
* Renamed kcsan_{nestable,flat}_atomic_{begin,end}
* Elaborate why clear begin/end cannot be enforced easily.
---
 include/linux/seqlock.h | 40 ++++++++++++++++++++++++++++++++++++++--
 1 file changed, 38 insertions(+), 2 deletions(-)

diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index bcf4cf26b8c8..61232bc223fd 100644
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
+ * As a consequence, we take the following best-effort approach for raw usage
+ * via seqcount_t under KCSAN: upon beginning a seq-reader critical section,
+ * pessimistically mark then next KCSAN_SEQLOCK_REGION_MAX memory accesses as
+ * atomics; if there is a matching read_seqcount_retry() call, no following
+ * memory operations are considered atomic. Usage of seqlocks via seqlock_t
+ * interface is not affected.
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
+	kcsan_nestable_atomic_begin();
 	s->sequence++;
 	smp_wmb();
 }
@@ -233,6 +254,7 @@ static inline void raw_write_seqcount_end(seqcount_t *s)
 {
 	smp_wmb();
 	s->sequence++;
+	kcsan_nestable_atomic_end();
 }
 
 /**
@@ -271,9 +293,11 @@ static inline void raw_write_seqcount_end(seqcount_t *s)
  */
 static inline void raw_write_seqcount_barrier(seqcount_t *s)
 {
+	kcsan_nestable_atomic_begin();
 	s->sequence++;
 	smp_wmb();
 	s->sequence++;
+	kcsan_nestable_atomic_end();
 }
 
 static inline int raw_read_seqcount_latch(seqcount_t *s)
@@ -398,7 +422,9 @@ static inline void write_seqcount_end(seqcount_t *s)
 static inline void write_seqcount_invalidate(seqcount_t *s)
 {
 	smp_wmb();
+	kcsan_nestable_atomic_begin();
 	s->sequence+=2;
+	kcsan_nestable_atomic_end();
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
+	kcsan_flat_atomic_begin();
+	return ret;
 }
 
 static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
 {
+	/*
+	 * Assume not nested: read_seqretry may be called multiple times when
+	 * completing read critical section.
+	 */
+	kcsan_flat_atomic_end();
+
 	return read_seqcount_retry(&sl->seqcount, start);
 }
 
-- 
2.24.0.rc1.363.gb1bccd3e3d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104142745.14722-6-elver%40google.com.
