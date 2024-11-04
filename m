Return-Path: <kasan-dev+bncBC7OBJGL2MHBBG7IUO4QMGQEQMLLTGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 270C79BBA24
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2024 17:19:41 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-539e0fa6f3dsf3234712e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2024 08:19:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730737180; cv=pass;
        d=google.com; s=arc-20240605;
        b=C3RSlWT6zv/6XOpUHbWUOJoxo2GbjGwcTG8/iTB7lX5Ozh6njgu4W5/CsxqSIJtw6o
         GchXMgSJkWlwAwuuD7Ey7Ht5ZckJ3Wo/awDkt9tE+Rukpp4/A44SArSen9RSnWB0Vugh
         gbKUHj+DO7Zc1bQisXgMsF8rc115p0HiWKS6mJmADDnIIfYMeI9wot3fPe74yIYOmnqW
         416bhmL/t1kq6KuI5crTkyhYKrkrX16NEE16FwjgAbfJtVGAYU2z7/H2Mi+YYC+M1ef9
         JdnCaXpVZHbU9jcLEHr8GHiJ5ZIeKu17csadP4Ji/RVyNH/qOvIWWHi16AZ98yBB7EwJ
         9g7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=NtBVRAHLzxFZjx46ExldehY3AFH6EiW7200aBDJAIE4=;
        fh=P1tKfyVVdNhD9iQze1YRb7xcj0hCKIH0hsXkBjuSZmw=;
        b=YdldzcfdGOOZbNvr2R5HYszXo6ngbdvWkGFxkmfrqV71AxY/WnuLOS6ULAgvkq0q/X
         3xzIm34Pchy9HiZLtCXqdd90ooxL8qkjebPgEgO/w2Of9XbHaKwf1q+5IBYUBrQkvNe/
         N/x1gSln4l8FCYGXTzM3I9Ry/EltqhCh+GiVaEPfr68Nx9Z+3MTXoIcy18XjlssJm3s3
         T29OE/b0QfdhdIwRmRqdv1XaNbHpYQdfr4rwarI1fwNW1l6cPq1kxUJXYyY8rha4JT22
         wBOs76pS9lVK1aIA6a/laosw2UBLef0CIaDrckLDtXjuAWYqB/y1641HUY6Ndn0VJnAB
         zviw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Caj3SneM;
       spf=pass (google.com: domain of 3gpqozwukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3GPQoZwUKCeMJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730737180; x=1731341980; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NtBVRAHLzxFZjx46ExldehY3AFH6EiW7200aBDJAIE4=;
        b=B8bosE/yBwEqWwWrc6iMJ4zUWO/P8V+HrWomBKmB/xznYkWPDVZfV/M3JnL9XK0eBx
         Ec/S4qiRsma4zR3psMUcSq5Qngsw8dSdwDJ9mvFWxB4XNXeafsc1CnpnhHOEovdM5Fzd
         dfdQ9dBEforUaw2ok0sUYgENeImVAgtsVhUUcew9oMZqeTdImEaCYu+1id5YpsaeMaAR
         awQGQrZvku68QN3cAxlZOKh0KdUpvNKmht3FjB6GXtaZQcmMgJ2XNXtXm6d4vYs0mMG7
         /x6+h0+nWmYSRLDIqSPUH4W+CNkwCb9sIvZDsZKMxJezqFKl0YedMVWm0p8z08Cqu8QT
         o25Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730737180; x=1731341980;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NtBVRAHLzxFZjx46ExldehY3AFH6EiW7200aBDJAIE4=;
        b=Ftle0eJ03rMnMlq5eCue/KeWEKcsVZPn2QFNFMOGnMQaQ8arRLxn8DRpqHe5TA/DVR
         WQS1FS+3qV1JCWmgaBsq+6OJI5x4WC4dJyeDgKE3wsFzzWieOAjcwoHQApiEZLdTPghR
         yBqIS7lA8Mpl52NUnk6sVqWtmW71lS8J3DymWUaz/fqKbBG//A8BQGtK4YuiyTQ3YX+0
         DaycmYabJy8hbuJWaCh5ihNkKxOExXkxPGwDLlkGI37T2nSBbsoKvo2R0959pBDVcAjM
         Mjske6605mtIKbr9aoDzvFyv0MK6K+2agDpeQTb60fT0s6XbXeUQisC2PuCbhMYT3XZK
         hCnw==
X-Forwarded-Encrypted: i=2; AJvYcCXyZHFM+tDA1sml+hTB/kqNNoi9QhjXbMt5ECMonji0+NqmkjAm5nOrq8QpWUyvaNVjrrU9Bw==@lfdr.de
X-Gm-Message-State: AOJu0Yye7KNvJS4pgW7fizPOEDhlTKgEz9eMZTL3jjq7ctEchHsqYjKF
	yOk+2F4DtqAZTjngXeVWAj9M+EZlux6QSUVFqeLVVPGRxYQ7nOk9
X-Google-Smtp-Source: AGHT+IHXRVadEryqD7/YomZS2vkPp6xWzfij7YnkcAyJDUJCMIib0Ipr2JLMN6hts+KVj6V+wkSQ7Q==
X-Received: by 2002:a05:6512:e89:b0:53b:4a6c:1849 with SMTP id 2adb3069b0e04-53d65df29fbmr9265495e87.35.1730737179999;
        Mon, 04 Nov 2024 08:19:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ea8:b0:53c:75d1:4f2c with SMTP id
 2adb3069b0e04-53c794ff766ls308348e87.1.-pod-prod-05-eu; Mon, 04 Nov 2024
 08:19:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUDTkxFmABPI9CW0ptfLBVo9MVpP+a/qvSmKfhXphBVogN5bdTJYPxq4SMlxEIjm1aS7my8+WBHiZw=@googlegroups.com
X-Received: by 2002:a05:6512:1590:b0:539:8fbd:5218 with SMTP id 2adb3069b0e04-53d65e168f6mr7806426e87.56.1730737177626;
        Mon, 04 Nov 2024 08:19:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730737177; cv=none;
        d=google.com; s=arc-20240605;
        b=YaT+9gipTu8A78x2lwJdfJyG5ZjF5RpWpnCuYqEQNa2/OcAjoGGlwUZgWLPg/SpMaE
         EcmqiOke0ZsUwJ26Vd79S63hC9b15eEy0ILewYJgNO45u4RBBJjkDaU4thGeRs3SMJBm
         xxKTQtfj/unISlhH1s8FrSuj2xcWhUg2d51ksxGRCI3FHZBTxH7aiEu71T/dG2wAMDV6
         PSC6THcS9ErUcFe8owv0kJRUzm1uQtSPG5yS6FnisTjE8yLGP1NfT/eFMIsvIC/A6PqR
         MTxCMv6SbTXS+/JEld4NXKu2kKzXsz/8GbQCKFlfH+P06LC+BlDCbhYhpKTlgYeFInM0
         UhxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=OKj0s9xjK+saMHMRM1ZIudsUlk4SnRJVysUql1YTd+A=;
        fh=oaxoK/yTsMfYhamzzU88ub6h2w9tBoIzNJYZp9JtxsU=;
        b=NFVZOA45u3HKbMPG1lMOK98k1xiv1rNLewSqOPyj3VU9ZcEg3yIfGj7uHU+XwSPLhu
         0t0Ku3u3dlzMCxoC01khc+QYzTQCuO7sT51c3UQpAZJ62yP+fsfzTZAql54s14HaJI6o
         Uo8FeEyZp+1bmV3qVhShvktmV6rrSjv9xgJPaJHP1CAWfdxGMnfi4oCI8h61eYKkc7cy
         /NCkbZVXMmuujRLzFb8ddKJ2V51QawOreDu5Om5fBj/vp4tVtgaHsgExXEz+AGZEL04l
         x7TUZHprvWlPy5rCbTrZI/GJCijAnBU6FJMtHbU+J1ILov/+AMgg6nnYylFIpeL96otu
         epaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Caj3SneM;
       spf=pass (google.com: domain of 3gpqozwukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3GPQoZwUKCeMJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53c7bca1752si173164e87.7.2024.11.04.08.19.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2024 08:19:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gpqozwukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-37d95264eb4so2307495f8f.2
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2024 08:19:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXytWEdURDTk+bpSJSh/Jbjv7K36UbUnFgWQnELI6z6rVFYHFXL8mjlgu/Jx3REbUs5nd5I5z1Ci9c=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:dc4d:3b27:d746:73ee])
 (user=elver job=sendgmr) by 2002:a5d:44d0:0:b0:37e:d5a2:b104 with SMTP id
 ffacd0b85a97d-381be7cf9ecmr7016f8f.6.1730737176936; Mon, 04 Nov 2024 08:19:36
 -0800 (PST)
Date: Mon,  4 Nov 2024 16:43:09 +0100
In-Reply-To: <20241104161910.780003-1-elver@google.com>
Mime-Version: 1.0
References: <20241104161910.780003-1-elver@google.com>
X-Mailer: git-send-email 2.47.0.163.g1226f6d8fa-goog
Message-ID: <20241104161910.780003-6-elver@google.com>
Subject: [PATCH v2 5/5] kcsan, seqlock: Fix incorrect assumption in read_seqbegin()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will@kernel.org>, Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Caj3SneM;       spf=pass
 (google.com: domain of 3gpqozwukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3GPQoZwUKCeMJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
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

During testing of the preceding changes, I noticed that in some cases,
current->kcsan_ctx.in_flat_atomic remained true until task exit. This is
obviously wrong, because _all_ accesses for the given task will be
treated as atomic, resulting in false negatives i.e. missed data races.

Debugging led to fs/dcache.c, where we can see this usage of seqlock:

	struct dentry *d_lookup(const struct dentry *parent, const struct qstr *name)
	{
		struct dentry *dentry;
		unsigned seq;

		do {
			seq = read_seqbegin(&rename_lock);
			dentry = __d_lookup(parent, name);
			if (dentry)
				break;
		} while (read_seqretry(&rename_lock, seq));
	[...]

As can be seen, read_seqretry() is never called if dentry != NULL;
consequently, current->kcsan_ctx.in_flat_atomic will never be reset to
false by read_seqretry().

Give up on the wrong assumption of "assume closing read_seqretry()", and
rely on the already-present annotations in read_seqcount_begin/retry().

Fixes: 88ecd153be95 ("seqlock, kcsan: Add annotations for KCSAN")
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* New patch.
---
 include/linux/seqlock.h | 12 +-----------
 1 file changed, 1 insertion(+), 11 deletions(-)

diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index 45eee0e5dca0..5298765d6ca4 100644
--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -810,11 +810,7 @@ static __always_inline void write_seqcount_latch_end(seqcount_latch_t *s)
  */
 static inline unsigned read_seqbegin(const seqlock_t *sl)
 {
-	unsigned ret = read_seqcount_begin(&sl->seqcount);
-
-	kcsan_atomic_next(0);  /* non-raw usage, assume closing read_seqretry() */
-	kcsan_flat_atomic_begin();
-	return ret;
+	return read_seqcount_begin(&sl->seqcount);
 }
 
 /**
@@ -830,12 +826,6 @@ static inline unsigned read_seqbegin(const seqlock_t *sl)
  */
 static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
 {
-	/*
-	 * Assume not nested: read_seqretry() may be called multiple times when
-	 * completing read critical section.
-	 */
-	kcsan_flat_atomic_end();
-
 	return read_seqcount_retry(&sl->seqcount, start);
 }
 
-- 
2.47.0.163.g1226f6d8fa-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241104161910.780003-6-elver%40google.com.
