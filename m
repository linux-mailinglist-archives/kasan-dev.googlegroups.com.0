Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIVOW3XAKGQEXH45QAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 011CFFCC93
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 19:04:19 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id m68sf4382763wme.7
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 10:04:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573754658; cv=pass;
        d=google.com; s=arc-20160816;
        b=n34AtyBK5FHbOjXw2r4gFO+xtrGOr8jH7e90u//wKOtpegWTwA0+sJJI49cVJXvJI0
         TeBvTbID3BYpgYCbSFeJIZtP4JIVzLf1lBjQOzX5jZ0NLiCN4AD85uKhrTc4CQJE3Ufn
         td8CccEm3Xtym1JCZ21cXCa76oekyLN2yIsnlwmAbHO4C56JorqAobVxfTx2d73LevRt
         t0SqAL0lI3GSEx6MTOPucA34u9jT6X5uIlfqultgSBE/2xY+a/mVgBmRNnDNQoP7UC/u
         A9vSWHBCZaf9vwMLNM7fU5Fxa4YOVxWKOt9e26f83C5sVYevOT6q3PdYGXIEM0o97BiP
         D6kQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=A6IAAwwZqE0JxELMTes0fO+8B9/F7rKU54/0imvotBw=;
        b=rOFreXo2P0DY+ImAGP3z5jrgpeE0rTkNRqwHNg8AHRIjDLptN183z6DoJDM5EtGk4A
         gBCHN21VDU+M9vTH+l4t1HfThNcuPQ4qrAMzBUPHBToff/TWpF2AwLoVhcg9Lb6xF3zY
         XeEGsD518M3KEz49OyVCiJ7xA/LK7+GwYLup9HU31zpJn4Imo+EjBv07FfL8QngWVElg
         ltAoZfGHZfzSWRoexYFCTXqGhWhwRiCrZBxwmhCwiFMIMeTIIoxgEHQa2BYMvrUOGzMG
         qNmdn6phW8w4mCAB3rl+anh/bhm8ouJr+BKkYyXhnOVDRV3rN0UwZAabmoh0st7bJ2yl
         drgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IgFzATzy;
       spf=pass (google.com: domain of 3izfnxqukcxocjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3IZfNXQUKCXocjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A6IAAwwZqE0JxELMTes0fO+8B9/F7rKU54/0imvotBw=;
        b=JlJ4tcmTdbMsG4elMtHJ7EAiLq3n80fJb5EQP2Xn9G95F/atb+vtzVLlwjpq5PdHlA
         JZcyiKt/flpOUxgnzf50fp7Qnn5FkqbKrxpsEguUI3YGZrDG1QplLeK7ehHwtBx9iC+l
         kQPxUY+79YNgzV7X5C530tntCTTHrOmDzUenTmFjH6uZUO1YV42UiqMOaL/Ny+0FobaQ
         rpNlKAseXF21p6VxtUJ4AGYATh0Dp8j+8Elr/PyOxqUkkbUhig5apDHZXto2RYG9u7MN
         gcJfw0wBO6TLrbeXIfkDr7NAqrpk8LF8kvI0cvDkurrLM5mD08Eof+V/+/wL+gRdGzxJ
         OaHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A6IAAwwZqE0JxELMTes0fO+8B9/F7rKU54/0imvotBw=;
        b=sF3fXNxnmmJf7SD2vQkYinrlVmzidYQtkeYe68B6Y+MTTjwQyOwx76ps2dBsKo4uuB
         V+k2eXOZGRc+KanrNFh5rm/T24lsOWKtpwamy2wvRoMEu+HIcEW4n4xozTzUkxyIlZkm
         0Bbo/hazJT9mQntFJ/VLOKtse5OntvyI1X+ktpiKPG2Sx/6d4gaBDCB+ixqMyO8n2yCA
         hW7O8r6u0AtdNQv525VxlaUwPqUqLVRrqd9c22NTsGjsi6xfjNRsqNG6ew6rXovqG+5W
         YXlfUMVij+9PTtwkgV3RzULBl2MpfH2rCUD9YVT23iaS6XYXwH2/bPaT/9Tj812lfach
         H8PQ==
X-Gm-Message-State: APjAAAVVKg1VyNiG+OkeALebbc7U7dvWBeKNCOJufEpMvQ9YQh8Y81zd
	L2CtfW7WqAT+tNMvlb1OUv8=
X-Google-Smtp-Source: APXvYqzIQEbKnZSqSDD5xQpc3g0xIDFbQKNiNCDCw10UU4SBf8BxzCOu8ylRVfWOuDpUClSYJDs93w==
X-Received: by 2002:adf:f20f:: with SMTP id p15mr5740138wro.370.1573754658658;
        Thu, 14 Nov 2019 10:04:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:8183:: with SMTP id 3ls8770908wra.12.gmail; Thu, 14 Nov
 2019 10:04:18 -0800 (PST)
X-Received: by 2002:adf:f40c:: with SMTP id g12mr4948258wro.356.1573754657991;
        Thu, 14 Nov 2019 10:04:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573754657; cv=none;
        d=google.com; s=arc-20160816;
        b=0asLSG/gYhyV7Upkrl7zsMJA5yqrQgIgemCB0+X4HIM/m4jXFM1Ne6OaaC2+w2jqt3
         76OP6x+M9THVanWUQ+T5SqamYkONOr5ct9v7mZL4bAfuedO06f1Hkr7DuJ+eO0w0BLXk
         sV7HyaUZZe3hmiPsKqkIvnmeeLu4z9c7v1iPsYfSscoHcBS70+1YWGsk4d46oW4nKixh
         AVELhCUhM+AmhwXdho2fyzPGC1fT81xpg9IDNPVuFoODiTtJyZaRw8PEz2IAJPTuJ7Dp
         YBOdgaIG2Gd87qHn4BRYcLJNW7NkSLPaLVllIBPYqCeIZvR+eguNm1uVmohrsYdMAMjw
         VnBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=nw4zt5zoe17M5yj/GBdsGwidr+1rdIV8qoHlTzgx1R4=;
        b=BTyodnhLpBj41muk97s+NTvE199t0aGT+si4nbd5Q/UsQa7ZwwHVGs3GVQqaHYT8Rp
         tmZ06rEE0IcuOqbAgF0Qek1ajzZLkG1JeeGhi2WA4e7H7yFkJnzFF2DG8OknCth6MLlY
         BQvi1m7Pmc/LtbzX1T3WUF6zGAVXwIHzjbNSHYsaa8C8HHk/Oq6cCf4xSN0KNJ5j8Fi4
         uiHhjqT6qNzN94HTO42hByfWTf1aSn8IJWudZj4VsPP4caB/H+eUpAuBlHMLf68EKNsH
         mpW1+AelMgYkn6hofuztKirx+TIIiShqW1S3Qds12OrtElNRZJzBYGEnUoWjfANqXsH5
         GDpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IgFzATzy;
       spf=pass (google.com: domain of 3izfnxqukcxocjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3IZfNXQUKCXocjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id l37si555532edc.2.2019.11.14.10.04.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 10:04:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 3izfnxqukcxocjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id v8so3738886wml.4
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 10:04:17 -0800 (PST)
X-Received: by 2002:adf:9e92:: with SMTP id a18mr9236334wrf.34.1573754657049;
 Thu, 14 Nov 2019 10:04:17 -0800 (PST)
Date: Thu, 14 Nov 2019 19:02:59 +0100
In-Reply-To: <20191114180303.66955-1-elver@google.com>
Message-Id: <20191114180303.66955-7-elver@google.com>
Mime-Version: 1.0
References: <20191114180303.66955-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.rc1.363.gb1bccd3e3d-goog
Subject: [PATCH v4 06/10] seqlock, kcsan: Add annotations for KCSAN
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
	tglx@linutronix.de, will@kernel.org, edumazet@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-efi@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IgFzATzy;       spf=pass
 (google.com: domain of 3izfnxqukcxocjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3IZfNXQUKCXocjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
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
Acked-by: Paul E. McKenney <paulmck@kernel.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114180303.66955-7-elver%40google.com.
