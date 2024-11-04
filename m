Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFPIUO4QMGQEUQYEOYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id BB96B9BBA21
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2024 17:19:36 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-539e75025f9sf2430444e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2024 08:19:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730737176; cv=pass;
        d=google.com; s=arc-20240605;
        b=egQXGK77+HOT1V8frRMFnsyTXwiJ10tRi8PkjLu7lyzYDhANO9CgF8R+E8NQG6wXja
         /vn4+1Xy8ODnrKCf7NwP3fKopZ/AbtJnJ+w1mqzcihLX39ezQ5DRNaaTEE11F3yOMGXR
         fcTt6dGZJFyW5lBE0CGaGM1p8nFUIx4BKUcZolde0o/2GPXlA/tWr82XixE1n4sxL1HZ
         /QtSMsh53LTTLSXJZZT1Dgrk4IyrEhsJS9nrwIlSrsKOjNsE/E4amyuS1HHnT+dAR66W
         ssMqvEhcx8tYIEp/0fPP5clz33aW9IlFXVSwJzUL9TtMRRmi49iXnfdTxlX0mKjcNV7p
         Gd1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=R/UUrj2bxNw8UFF9UUozuxu+lr4GIfjYZPJsVUTdw9U=;
        fh=MEVrMQjlroxlOMAPNaP65P5yyFcuu+l1rx6AQ2YhvFE=;
        b=auHnS94fl0VH0BC0b3EMaz29mJGzA9K8F1nhaTqWu7dCB/68aNVJBY3qMM3pbbt33/
         CQPNWPTgEU0+R4HKH52Jo9RC8JOQSojckDuzv42hWcBt0ZOrYiCFeJruZJTdCNTCDaeT
         7n3YignyqUfPOXt0nUQJDFHWb+es/piTh+tKB5PHWoz9IWtuiEC4daIpJf5lsuCdsH0i
         NQKPJbqQRpDKo2q3yYADxN5XeZRf3qVeMgUM2y1jSE82Nw2gaqmC8gQ5kUoqNTp9sUra
         WhjbPp5kwHsxscjcjfZjNpQ9XrJGloR+LnvBoZbtEZnGgXMse5UcJalJ+tA5M+x5nxHQ
         PTIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3pziI0Jp;
       spf=pass (google.com: domain of 3e_qozwukcd4elvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3E_QoZwUKCd4ELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730737176; x=1731341976; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=R/UUrj2bxNw8UFF9UUozuxu+lr4GIfjYZPJsVUTdw9U=;
        b=pmlQ+iF5Eik65lkBIDkfFWgmAxCn2QvOCgLb50u8WY99+4vtZV91peKPvxcdZtcKf/
         Lnm70g1FsIiF92yaqUX9aerXLMh9Ze0zpq4eMhHD8b7CLJKPrhClI1ep/wFSVz53xn9m
         6AjpxB6X9xPhnlnROcSLx/t2soBf2vHD0eDDhzeJm5WM+rhpPA8m9umEj/Kbq/yMWc4u
         Mj015R58EdtGLGyWHDC8MBy4qKWtzVzGToGADreKNUMaxfWGiIpX4RTylbOFavsj/0TV
         ZG7Cb3KjkIQrqEX2dSAof40jNEe71N/WEwyfQ71dySs1UwnTqktdBMEaS/KUMIVkV74d
         MIow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730737176; x=1731341976;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=R/UUrj2bxNw8UFF9UUozuxu+lr4GIfjYZPJsVUTdw9U=;
        b=qqZnYebzV//HnM7aXNVIH6AgLimTapNE8ODaDJyEfV0AYMzrArSJxDGkr69nQwY5JA
         GdgWwta8STeexK9kp7wTDyt0/Gx2a8Ig2J+xmZ5o4aRmxCQphUKakZ7C8Ai6ayd9rLra
         nPaWf3ejetdDGah8E6YugnOI7acoZ5fHq11/J4IobE9+DC28/gJWjFAvhyxBTxQDK4EW
         TvtL40j2Jd43xJCrfY7wLzGP939axHJdVlUf1vRxtpiEgihbwoXxI0SofDk0NM/wnVb6
         sJ5CctQV8+jDpFajyBt5KZ9L8naO2u1O+spORTyhZAB/xp2Kci5D1P+QRGvUoSAOxGh/
         anGQ==
X-Forwarded-Encrypted: i=2; AJvYcCUdnBtsT+4plWCFEdyCaQ+P1bGCQ4IwCCkKjPiG2/2Lb/d8YQT46Z7/4hBiGGd54+samFSl0Q==@lfdr.de
X-Gm-Message-State: AOJu0YwUmyLyJfR2uhD1USCUfQuq3ZpYlYQIe0ug9Ep+xOkQpDyR6O/y
	Yc8EixEUBDvm7tPlleQ5cs1KqvPTu3okyBmuZalx3g6QWwSC8ClP
X-Google-Smtp-Source: AGHT+IFAUefeMxXN/WEPeX2/n42nIfmuJBRHzGuN3TL3m4iHHLZj7CMhT4LNsXFUb3Evh2EyJ2kg5w==
X-Received: by 2002:a05:6512:3195:b0:53a:38:7b8c with SMTP id 2adb3069b0e04-53b348e73bfmr15826567e87.34.1730737174190;
        Mon, 04 Nov 2024 08:19:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:acb:b0:53c:75e8:a5d6 with SMTP id
 2adb3069b0e04-53c7973fda9ls439181e87.2.-pod-prod-07-eu; Mon, 04 Nov 2024
 08:19:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXKLUnw4VwN2PchQzJlKv0CFvOP3o0hwQoLIVDrLlwltw99qtSEH7B9+7zj1QcxLiPCq52v24FnBz8=@googlegroups.com
X-Received: by 2002:a05:651c:1a0a:b0:2fb:55f0:2f7b with SMTP id 38308e7fff4ca-2fcbe04f0d2mr158274441fa.35.1730737171732;
        Mon, 04 Nov 2024 08:19:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730737171; cv=none;
        d=google.com; s=arc-20240605;
        b=fkVxjNljvejVsO0BmnXvHhLG1pfxRkwMRo7US4OYYohoSeR/Q3EPNeCOKQD0JsSGv1
         kPIF9GTy6kFcIQ/V7wB0d21tJU0X0OG+cN3tbUOm7YteuIw0Cv0Ph8yck9gBMcB/iL/a
         EJn6BFol4zGSVpdBmOq1CkOn0kVY5nks3bCnPQBoXlCd8ZizRX72iAkYs4kvtgx2sEGH
         nWrgMbQOvvFn0kYMqU/pnaSGCTk8aY66T5r7uFOkD4Ali7Co8R75n6TA7kxikmVeaJGF
         zGj30skpLNwtp9fsN+MslvKwc+RasvHsbU8gJb9UrpP4xC0hjMuvOcpV8J32n9AT1rHV
         82nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=18LLtGEOGzu+73DHRju+ymYzFojyLpzj5nOA/GmHSqU=;
        fh=wLeUZcexHOoCdCU4kjVTFpFdYkkX3YnQdSKAcvzVbAs=;
        b=FUCeBmBfgXF5pIIT+i0H3sKqebjzpWPg217cHv/Xpw9MPfn2HXdaWhMBZt3k3Tert7
         RjY2rnerz0UHSvhKNHdxLfKG0WAxUEin0pkx0cMIsHE00Vhi8/uShd8DaHylQO4gHshl
         U0VLkhGd/GwyQ+ZpaGwJs4feVsUGACL6gMk4AFWqYU5PhpiuhXt/0Rgs12JErFYvFDmB
         PQ8UAAWbNKb2bWoAPzTKrOhHnRoEyH4dpez3NveVQODrKkRDbx4phDCYUGpeAIHSq9i8
         JcUOKj/0xgtPlRveZhri1W869WJ+T3NOhvpKvD5VAQ5IUsiB4N6LErwR0hyVZjtQpEZE
         6H5Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3pziI0Jp;
       spf=pass (google.com: domain of 3e_qozwukcd4elvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3E_QoZwUKCd4ELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5cee6aaa239si691a12.2.2024.11.04.08.19.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2024 08:19:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 3e_qozwukcd4elvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-5c95b050667so4433583a12.2
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2024 08:19:31 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWpBAGIMNUfwB0PdrPbMSVSeScsbruL3ZoSRH+QVEvPDIx6AZVgcSvWDrXou7OU5FLSTO8V7BBnJjU=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:dc4d:3b27:d746:73ee])
 (user=elver job=sendgmr) by 2002:a05:6402:2350:b0:5cb:c081:92b2 with SMTP id
 4fb4d7f45d1cf-5cea966ac74mr5044a12.1.1730737171303; Mon, 04 Nov 2024 08:19:31
 -0800 (PST)
Date: Mon,  4 Nov 2024 16:43:07 +0100
In-Reply-To: <20241104161910.780003-1-elver@google.com>
Mime-Version: 1.0
References: <20241104161910.780003-1-elver@google.com>
X-Mailer: git-send-email 2.47.0.163.g1226f6d8fa-goog
Message-ID: <20241104161910.780003-4-elver@google.com>
Subject: [PATCH v2 3/5] kcsan, seqlock: Support seqcount_latch_t
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will@kernel.org>, Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=3pziI0Jp;       spf=pass
 (google.com: domain of 3e_qozwukcd4elvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3E_QoZwUKCd4ELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

While fuzzing an arm64 kernel, Alexander Potapenko reported:

| BUG: KCSAN: data-race in ktime_get_mono_fast_ns / timekeeping_update
|
| write to 0xffffffc082e74248 of 56 bytes by interrupt on cpu 0:
|  update_fast_timekeeper kernel/time/timekeeping.c:430 [inline]
|  timekeeping_update+0x1d8/0x2d8 kernel/time/timekeeping.c:768
|  timekeeping_advance+0x9e8/0xb78 kernel/time/timekeeping.c:2344
|  update_wall_time+0x18/0x38 kernel/time/timekeeping.c:2360
|  [...]
|
| read to 0xffffffc082e74258 of 8 bytes by task 5260 on cpu 1:
|  __ktime_get_fast_ns kernel/time/timekeeping.c:372 [inline]
|  ktime_get_mono_fast_ns+0x88/0x174 kernel/time/timekeeping.c:489
|  init_srcu_struct_fields+0x40c/0x530 kernel/rcu/srcutree.c:263
|  init_srcu_struct+0x14/0x20 kernel/rcu/srcutree.c:311
|  [...]
|
| value changed: 0x000002f875d33266 -> 0x000002f877416866
|
| Reported by Kernel Concurrency Sanitizer on:
| CPU: 1 UID: 0 PID: 5260 Comm: syz.2.7483 Not tainted 6.12.0-rc3-dirty #78

This is a false positive data race between a seqcount latch writer and a reader
accessing stale data. Since its introduction, KCSAN has never understood the
seqcount_latch interface (due to being unannotated).

Unlike the regular seqlock interface, the seqcount_latch interface for latch
writers never has had a well-defined critical section, making it difficult to
teach tooling where the critical section starts and ends.

Introduce an instrumentable (non-raw) seqcount_latch interface, with
which we can clearly denote writer critical sections. This both helps
readability and tooling like KCSAN to understand when the writer is done
updating all latch copies.

Link: https://lore.kernel.org/all/20241030204815.GQ14555@noisy.programming.kicks-ass.net/
Reported-by: Alexander Potapenko <glider@google.com>
Fixes: 88ecd153be95 ("seqlock, kcsan: Add annotations for KCSAN")
Co-developed-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Introduce new interface, courtesy of Peter Zijlstra. Adjust
  documentation along with its introduction.
---
 Documentation/locking/seqlock.rst |  2 +-
 include/linux/seqlock.h           | 86 +++++++++++++++++++++++++------
 2 files changed, 72 insertions(+), 16 deletions(-)

diff --git a/Documentation/locking/seqlock.rst b/Documentation/locking/seqlock.rst
index bfda1a5fecad..ec6411d02ac8 100644
--- a/Documentation/locking/seqlock.rst
+++ b/Documentation/locking/seqlock.rst
@@ -153,7 +153,7 @@ Use seqcount_latch_t when the write side sections cannot be protected
 from interruption by readers. This is typically the case when the read
 side can be invoked from NMI handlers.
 
-Check `raw_write_seqcount_latch()` for more information.
+Check `write_seqcount_latch()` for more information.
 
 
 .. _seqlock_t:
diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index fffeb754880f..45eee0e5dca0 100644
--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -621,6 +621,23 @@ static __always_inline unsigned raw_read_seqcount_latch(const seqcount_latch_t *
 	return READ_ONCE(s->seqcount.sequence);
 }
 
+/**
+ * read_seqcount_latch() - pick even/odd latch data copy
+ * @s: Pointer to seqcount_latch_t
+ *
+ * See write_seqcount_latch() for details and a full reader/writer usage
+ * example.
+ *
+ * Return: sequence counter raw value. Use the lowest bit as an index for
+ * picking which data copy to read. The full counter must then be checked
+ * with read_seqcount_latch_retry().
+ */
+static __always_inline unsigned read_seqcount_latch(const seqcount_latch_t *s)
+{
+	kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
+	return raw_read_seqcount_latch(s);
+}
+
 /**
  * raw_read_seqcount_latch_retry() - end a seqcount_latch_t read section
  * @s:		Pointer to seqcount_latch_t
@@ -635,9 +652,34 @@ raw_read_seqcount_latch_retry(const seqcount_latch_t *s, unsigned start)
 	return unlikely(READ_ONCE(s->seqcount.sequence) != start);
 }
 
+/**
+ * read_seqcount_latch_retry() - end a seqcount_latch_t read section
+ * @s:		Pointer to seqcount_latch_t
+ * @start:	count, from read_seqcount_latch()
+ *
+ * Return: true if a read section retry is required, else false
+ */
+static __always_inline int
+read_seqcount_latch_retry(const seqcount_latch_t *s, unsigned start)
+{
+	kcsan_atomic_next(0);
+	return raw_read_seqcount_latch_retry(s, start);
+}
+
 /**
  * raw_write_seqcount_latch() - redirect latch readers to even/odd copy
  * @s: Pointer to seqcount_latch_t
+ */
+static __always_inline void raw_write_seqcount_latch(seqcount_latch_t *s)
+{
+	smp_wmb();	/* prior stores before incrementing "sequence" */
+	s->seqcount.sequence++;
+	smp_wmb();      /* increment "sequence" before following stores */
+}
+
+/**
+ * write_seqcount_latch_begin() - redirect latch readers to odd copy
+ * @s: Pointer to seqcount_latch_t
  *
  * The latch technique is a multiversion concurrency control method that allows
  * queries during non-atomic modifications. If you can guarantee queries never
@@ -665,17 +707,11 @@ raw_read_seqcount_latch_retry(const seqcount_latch_t *s, unsigned start)
  *
  *	void latch_modify(struct latch_struct *latch, ...)
  *	{
- *		smp_wmb();	// Ensure that the last data[1] update is visible
- *		latch->seq.sequence++;
- *		smp_wmb();	// Ensure that the seqcount update is visible
- *
+ *		write_seqcount_latch_begin(&latch->seq);
  *		modify(latch->data[0], ...);
- *
- *		smp_wmb();	// Ensure that the data[0] update is visible
- *		latch->seq.sequence++;
- *		smp_wmb();	// Ensure that the seqcount update is visible
- *
+ *		write_seqcount_latch(&latch->seq);
  *		modify(latch->data[1], ...);
+ *		write_seqcount_latch_end(&latch->seq);
  *	}
  *
  * The query will have a form like::
@@ -686,13 +722,13 @@ raw_read_seqcount_latch_retry(const seqcount_latch_t *s, unsigned start)
  *		unsigned seq, idx;
  *
  *		do {
- *			seq = raw_read_seqcount_latch(&latch->seq);
+ *			seq = read_seqcount_latch(&latch->seq);
  *
  *			idx = seq & 0x01;
  *			entry = data_query(latch->data[idx], ...);
  *
  *		// This includes needed smp_rmb()
- *		} while (raw_read_seqcount_latch_retry(&latch->seq, seq));
+ *		} while (read_seqcount_latch_retry(&latch->seq, seq));
  *
  *		return entry;
  *	}
@@ -716,11 +752,31 @@ raw_read_seqcount_latch_retry(const seqcount_latch_t *s, unsigned start)
  *	When data is a dynamic data structure; one should use regular RCU
  *	patterns to manage the lifetimes of the objects within.
  */
-static inline void raw_write_seqcount_latch(seqcount_latch_t *s)
+static __always_inline void write_seqcount_latch_begin(seqcount_latch_t *s)
 {
-	smp_wmb();	/* prior stores before incrementing "sequence" */
-	s->seqcount.sequence++;
-	smp_wmb();      /* increment "sequence" before following stores */
+	kcsan_nestable_atomic_begin();
+	raw_write_seqcount_latch(s);
+}
+
+/**
+ * write_seqcount_latch() - redirect latch readers to even copy
+ * @s: Pointer to seqcount_latch_t
+ */
+static __always_inline void write_seqcount_latch(seqcount_latch_t *s)
+{
+	raw_write_seqcount_latch(s);
+}
+
+/**
+ * write_seqcount_latch_end() - end a seqcount_latch_t write section
+ * @s:		Pointer to seqcount_latch_t
+ *
+ * Marks the end of a seqcount_latch_t writer section, after all copies of the
+ * latch-protected data have been updated.
+ */
+static __always_inline void write_seqcount_latch_end(seqcount_latch_t *s)
+{
+	kcsan_nestable_atomic_end();
 }
 
 #define __SEQLOCK_UNLOCKED(lockname)					\
-- 
2.47.0.163.g1226f6d8fa-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241104161910.780003-4-elver%40google.com.
