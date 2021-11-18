Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPMV3CGAMGQEPQSQRLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B2E5C455683
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:41 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id bp10-20020a056512158a00b0040376f60e35sf3452117lfb.8
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223101; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hr9aJO9usOsmy6Lwf9lpNEMk5EOs3jhNB+XjrGqBmG1HDfhsyxbKcIeQksaFaI4vow
         s3/jiYF6zTcgKNybxXbdmI47EtKOwmrPA6QilE3KV8sOJ880xEXld5iwjUsVmrOIseXn
         fYxJViVD/tT5JkntW6YgX4Bk650jmXGjUZ3ZF37E18KeLzsbXIrc3H2dGjMjT58IsZzk
         M4qrrVnGGF4Ekaf7maIHGgGu2ZuprUQATdoH+61DCw+ar5xzOcUCA2uaJjRjELal2/Tj
         unDG8Giu1jRCFfsoe5nuD+2Wr7urq3D3hxbHBu/O9ar4XPBJpnBGL+t8c6pZpNHMO/AF
         GUsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=lJOe7maQQZ7oQwEmoc2tMpZCChCtJIFyiB2lwNS+8+Q=;
        b=u8VnIqsi0Anefky40994lgoA1eccalN4q6RwWNf9vRHbz0P3t9HXkthFpXs/srJlzm
         iB4qhXUWN2ljEq48y7yxgj1MZab1Ziik0BKd56DOH7jfFGcCkvX2KbEjSIb0WVrlyIA2
         vBOvkC0T4lurDgHuSIKQMaaeOjY8YKlXK8XXTBcIkAi/QyBgZXu0iwSG2DgGYszMm+h3
         L6MJrN2AXPz5SYL3OnMyYnPNUh6Sd7TdzKvxACUXZLCtVD1BYgVxgVnsAAM7yEVLCnUY
         9ZPYaQDt4Xf5IhIvYe6rx1EBgq2ryArIW+Tpah6YDWO5DbEbw4tG7Cyg/bX/kLmsZvk4
         tgag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KS5G8h98;
       spf=pass (google.com: domain of 3uwqwyqukctwcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3uwqWYQUKCTwcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lJOe7maQQZ7oQwEmoc2tMpZCChCtJIFyiB2lwNS+8+Q=;
        b=BL7pWlvI0f4SwcfyTiL/gbemy5xR7TtoKxHa26gNTGeWWbd+p//RnJXwlrnfAffswi
         FsNB8kV/PVtGZmSc4aPFEskeApT5NLx/pVSiAJO75KRovEjkGMDTY+m5uK9tE20FZ8RW
         4wp3uZNhkpa51D/Zm5w7mk3vjTDngSapPQc52xijkviEB5co4I7ZRJQW5BHxl+wv/Zjw
         uJnsttheGBvRHh5b8ebmVfalYF/nQB4OtlEbrDh7JusPagnxJy958r6G0H8ufG27HMAV
         /BmHhrGUBxc5JgP2YIAzbnTtZlvvSxCI/ak/xu7Q7RYHBlFZj4LDWLmB48Rph3SFmSRz
         etVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lJOe7maQQZ7oQwEmoc2tMpZCChCtJIFyiB2lwNS+8+Q=;
        b=cXNZUx+Qu5LGUvLO66D9sqpnhRxW2nltthvrgrBodTMAX8rD4VkIhgwmYQgELBOGOS
         JqCXPPxROOnDbEMXwgktR9sSQ24UjyDaJGFQcBQYnI5hoe7XKqndtHpYUQZGi8mzsr6l
         zDyZofwVV3V1u6Q1Cp4I9M0SLHbMSz0zl82VXtVYPlgfe0VjgGaUmHGZMmHsjbRl93+M
         whEAd11N46zYnbAL26u1X9ZJSudiSp76o69wqnSK0HOPqKNvYwIdRmdwoMPQeuRaPWuR
         SGYZhUpII8a0j4xv/e107qaFEaItbKpEYgqWwkQPMqujG9UNlt8MwCTYrQh3NMSrwmZ7
         sWNQ==
X-Gm-Message-State: AOAM530OxUikuOaJxGqRUxKI4Ic89z1Eja+ZejTta94kc0zDRmQmU9ZK
	vDdqzjCZMCb0f6/uKL7dblI=
X-Google-Smtp-Source: ABdhPJx3gQs/QfxVa6SPusBDjh0qh8gdr38hYf4tNnICqviGG6flU84L6q9PJnQ6UL6c6bkXUt7pxw==
X-Received: by 2002:a19:4884:: with SMTP id v126mr22571411lfa.178.1637223101344;
        Thu, 18 Nov 2021 00:11:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c4:: with SMTP id x4ls395586ljp.8.gmail; Thu, 18 Nov
 2021 00:11:40 -0800 (PST)
X-Received: by 2002:a2e:6a11:: with SMTP id f17mr14567135ljc.206.1637223100256;
        Thu, 18 Nov 2021 00:11:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223100; cv=none;
        d=google.com; s=arc-20160816;
        b=O54uo/rGj8pHdYFtTNmHGVNJo/pqEtO486rIRssinZQcteLWJraW+ZcqvSn9WcYqEV
         clgN+5S8GU1rGKjHgvyHe5ATBODqubuxBYxiBY9CaykWXz+vDBlj5OExrDg/KChhNcs9
         XkeuPN8IwEKvv2X5uPoG0KqpsYXRgcSN9gJnuDvkPkDmlxo2+mXKbpv+YJdqatOGbyAX
         kPdqpNs2ZsBanzjTyBawXJmcu/YVlXCBy555igzga+90Me9Q6WzX1hM8ftQp79/taB/p
         iIjbeoiT4SMBYrmyYmZnw0zROkBGATTUAfNYP+h1sqBvunJw287LD1DcOO9DwMZS2qMc
         fBVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=JvNCvfwB/M304r5/BDcWOzh3dLnMrHum3apHlfxEx/4=;
        b=ZrJhucXTYuzXkM2ZjaLF7X+/Iu+hyPbqoEeTgz96hqOv9ZhkbtaG+eA4bO7JbmJnEj
         GtKeyM8endYIM3akQdr66l9I3bUZyOYcf0cTOi9W57FoEelXbm+imxVjqTZ4eJCPxaiE
         2bsu5fhydmQsHGFVP03xBFTMYUnDKwigRq7bBgpXtpqR4LRgR0HnNPxzmV0y75/DsSR0
         lvhdyYCgKNszi8UZsN+TrlEGbwCpNyJI43EXNeBqUjPT7QBDj1Eugc9gylWg/H5PGY2X
         TebS0tXXoS3ux+yddo4znNrP0ZE+rymWA5aAU16O1FhL9jMNJewQRETjgMwiUIcUzmH5
         EZMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KS5G8h98;
       spf=pass (google.com: domain of 3uwqwyqukctwcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3uwqWYQUKCTwcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id t18si145231lfp.0.2021.11.18.00.11.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uwqwyqukctwcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id a2-20020a5d4d42000000b0017b3bcf41b9so868955wru.23
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:40 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a05:600c:4f44:: with SMTP id
 m4mr7898634wmq.95.1637223099727; Thu, 18 Nov 2021 00:11:39 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:21 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-18-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 17/23] asm-generic/bitops, kcsan: Add instrumentation for barriers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=KS5G8h98;       spf=pass
 (google.com: domain of 3uwqwyqukctwcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3uwqWYQUKCTwcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
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

Adds the required KCSAN instrumentation for barriers of atomic bitops.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/asm-generic/bitops/instrumented-atomic.h | 3 +++
 include/asm-generic/bitops/instrumented-lock.h   | 3 +++
 2 files changed, 6 insertions(+)

diff --git a/include/asm-generic/bitops/instrumented-atomic.h b/include/asm-generic/bitops/instrumented-atomic.h
index 81915dcd4b4e..c90192b1c755 100644
--- a/include/asm-generic/bitops/instrumented-atomic.h
+++ b/include/asm-generic/bitops/instrumented-atomic.h
@@ -67,6 +67,7 @@ static inline void change_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_set_bit(nr, addr);
 }
@@ -80,6 +81,7 @@ static inline bool test_and_set_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_clear_bit(nr, addr);
 }
@@ -93,6 +95,7 @@ static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr)
  */
 static inline bool test_and_change_bit(long nr, volatile unsigned long *addr)
 {
+	kcsan_mb();
 	instrument_atomic_read_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_test_and_change_bit(nr, addr);
 }
diff --git a/include/asm-generic/bitops/instrumented-lock.h b/include/asm-generic/bitops/instrumented-lock.h
index 75ef606f7145..eb64bd4f11f3 100644
--- a/include/asm-generic/bitops/instrumented-lock.h
+++ b/include/asm-generic/bitops/instrumented-lock.h
@@ -22,6 +22,7 @@
  */
 static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
+	kcsan_release();
 	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	arch_clear_bit_unlock(nr, addr);
 }
@@ -37,6 +38,7 @@ static inline void clear_bit_unlock(long nr, volatile unsigned long *addr)
  */
 static inline void __clear_bit_unlock(long nr, volatile unsigned long *addr)
 {
+	kcsan_release();
 	instrument_write(addr + BIT_WORD(nr), sizeof(long));
 	arch___clear_bit_unlock(nr, addr);
 }
@@ -71,6 +73,7 @@ static inline bool test_and_set_bit_lock(long nr, volatile unsigned long *addr)
 static inline bool
 clear_bit_unlock_is_negative_byte(long nr, volatile unsigned long *addr)
 {
+	kcsan_release();
 	instrument_atomic_write(addr + BIT_WORD(nr), sizeof(long));
 	return arch_clear_bit_unlock_is_negative_byte(nr, addr);
 }
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-18-elver%40google.com.
