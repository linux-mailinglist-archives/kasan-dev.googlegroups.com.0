Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEHIUO4QMGQEISAWXYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 709DC9BBA1C
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2024 17:19:30 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-539e294566dsf2611264e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2024 08:19:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730737170; cv=pass;
        d=google.com; s=arc-20240605;
        b=XwHM7VronfryZ9EWvVWef8MgugsQ6tDFVKT+L8X1rRqBb0j7tIPsT1wb7BumJ+NHZc
         k9WTR8MKAG7qW4L1fPo10jDEUP5KRH6vdtF1Q329Xj2hRBa3WROvkZfAjjcFFLpC6yiD
         Upio1Ay9OOyokp/jTant9C1mFZ6sb7X5xGdU6GD5o+9vBhOQnwT49Y13yiBv0SXPgqCt
         5oWp48zULIuhVjFBf9wp17D7HR73FSNHPkf39qgqiJIs9EH+vvzZXagx/O2O7y4rSZSG
         6SgrZFIti6RqsL+hetjtcSCPzNt6jlZKM5//wQzQ/vFditXMCIg1eGIYUQXVM1PzY91u
         bxLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=VKSarY42vfqKeA8J7v15QpOvTG6mGr7ECgOcNEA2nes=;
        fh=KnVP3TNGIE7QMLZCcaqp5Su1Aw/zxrK71jfcJItrhHA=;
        b=YRfDaqSFmGxVywcfwLBBZc7K2Fp5znNtpdIopNpY4dfB5RwO1+nLvMHEhkwl0yEmCm
         ELnUtGSJ/8GMWdtfBAzlF/nRsZA3icMyU9uJF2PdSIy6SKUK5qxDdQunlQ1cJhHr+EZ+
         EG/6EsZHeaPUEbMHGol8fQEaW7mjZzx+6mip2hZjQGGd4QfR3qvfEGxSW4Cycg4p+Ius
         tgl6gczCzFetUKCRSni2PHv4jvwubrTQQhd52iOWkan45ibyZwwtXfQMGmH8suL+PT8E
         ECh/vGJmHLrk0En++QQYW8Lk1OpnvlEUAVPuiK7hkL2zFMNOFbjKuqY/L4lQbfWeVd34
         zrGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ni7T44lE;
       spf=pass (google.com: domain of 3dfqozwukcdg8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3DfQoZwUKCdg8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730737170; x=1731341970; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VKSarY42vfqKeA8J7v15QpOvTG6mGr7ECgOcNEA2nes=;
        b=GbcxI5wlgcsVm6+9mT7Xs2MWdgLRv1zvR8Yj5UOEMQimlxEKBPNPrQ+fNOJnXnUs8D
         t547pvo2YDlAe8ifvMBV2CSZbUziRNQuRjk+qIe+rojmmPkrZGCFl/pDlpkvqHSy/CWx
         x7B3y673V1u9i/xCgIE741+cvLmNj9uUIhIXiRfPC0xGwyyimG41CYqqAxxw2xUycsXp
         MaJh/7uDc/a0mI/OtFxAKMrWfpVpDuS1Dy1A1E2xoMXG3RdbnVfM7y1vFkU32E8Q5shA
         ut00yYYA3BAHTfc/pi70HM+wQZ9ZVbwgMuUkbWwOHdANeln5eYJwJM017bJoyYAT7Yz5
         eQNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730737170; x=1731341970;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VKSarY42vfqKeA8J7v15QpOvTG6mGr7ECgOcNEA2nes=;
        b=FQO2U0X9j8FdjNvCKnHut5A36/6igfis41LPbk44WulEM1mivdhSVl3Jed2ycD6AHC
         d1sECwdmZ3Z51lKtLts4BQMS7BucWDbDUQgAtBJZMe2JNkuOjKOGsXzJ09/kG6hqjSrh
         j6mH2J4IZJLE8XnD/3MPh9+Wj1X+6MnoJexgmsoy/wRbM1tHxtVgNWupVkfKdECYdqH1
         NU5xLug3D6Fv1yWqQUywNSBY7tMmias/3i75uarG8fCEaxTR1H4EJTk83pZRaMN1H+4I
         XcEkpKmXDzFYwKvIv71eo0l0guuBy5/3uR0lEp0UTCgsjM0v1xzW9wwmLWAfmYGeEgKv
         C43A==
X-Forwarded-Encrypted: i=2; AJvYcCWoODafpQzRsefAX2okhH8xqKE5EfhHznYCGJydij0W8n60Swt418LGXDLmncvvlA+0i5COMw==@lfdr.de
X-Gm-Message-State: AOJu0YxJxwz9kom52AiY3qfJeKwumvOMqEHEqqOdoGdZAlV4FQnoJJrx
	vSMl5MI0zGoj5znPFK/b6wwY5GPTREl/8cBlh7i5c2njq5Lr8E0q
X-Google-Smtp-Source: AGHT+IHzHcahZM8Oiq8BB9ZCyGy83aUl0SoAF66kVJ7+4OAI/Ig9WF0cRUuCxJvRYpC6WhGPFxMsIQ==
X-Received: by 2002:ac2:4e0b:0:b0:539:d2e2:41ff with SMTP id 2adb3069b0e04-53c79e3254amr8348176e87.23.1730737169082;
        Mon, 04 Nov 2024 08:19:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:a84:b0:53c:7504:2de5 with SMTP id
 2adb3069b0e04-53c7971e260ls174495e87.2.-pod-prod-03-eu; Mon, 04 Nov 2024
 08:19:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVZonwvi7s05c3EyCEj+OFuWCOi+ZocEJIFzHviMutJyw/Cqr+3NTORYgpfA2OhymWT8PUi4y4OAn4=@googlegroups.com
X-Received: by 2002:a2e:743:0:b0:2fb:587d:310 with SMTP id 38308e7fff4ca-2fdecbf82eemr55202661fa.30.1730737166754;
        Mon, 04 Nov 2024 08:19:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730737166; cv=none;
        d=google.com; s=arc-20240605;
        b=MfqazsLg1xKpAcftP6xUVyRYWSbkL3iSgJeNkq1a6lpQh8Dxvws6pzxWgamdvR7YrH
         u+gZMapv+TThd0mT+WHHe7ArFoAV2HkC+VjCyTIxXwTwHYXFOKVH8PSMiT04GH28oRaV
         U7fXxLK5TSrLBN7Fz6V1m6XgHkAraZzTNmoKfRB7V/dBHNXrdZQPZ4H4zOtA4OVGi6PP
         KB9cq0vd01KwCq+TE+zDMPKO0//dRbr9e52dm+a1uFAbbZSRIq6vMFMcJHDfx5X2HnAS
         H8sV5mPdCEdCDeWRKubrYXXh5Mi3tqKtNn9xY+lF3dCaq6sRlpYMduyY6VmUC480cq98
         yixg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=P9zIGQ63tMUKGGfo5aLFc1OFxRhvBbjK0JxcXzvrQ2E=;
        fh=TCc8WjabUAKKKGzD+Eerk4heaW1QLxnpuaACmaHdSxo=;
        b=V0PbVNQSSNVfNkN6Sq98pTld8WT02F49H9Hj8r8U3niPY66PkgOfI+TgCD5a5o7Oxs
         MQjwUZbkr8BZpqOJXt212LX1G+vpy9iQiLoyDEhc2dbVMNf9haJw4rC0pOpTckX/7lRJ
         XOxRzsfKAcP0roEqLVav6XW/4kFBqsbnXoZCykfGjpFizLUYhS551hCBAssnEYdFeM/7
         xtIFvIMlUrX1GEmrRstBpq2gz4YabD4IdUafquUWSidV3/WMH5OH/u6bknm8ofPQTfo/
         I5XCUujzZ6zFEwgtfRIwk9GEab4EGNLiype7mmvgxtE/ewtdLv1qnkNuehTfAaLR8MVu
         GEDg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ni7T44lE;
       spf=pass (google.com: domain of 3dfqozwukcdg8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3DfQoZwUKCdg8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2fdef8cf50csi2186341fa.7.2024.11.04.08.19.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2024 08:19:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 3dfqozwukcdg8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4316655b2f1so31552495e9.0
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2024 08:19:26 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVqk/Mfx9bMOPvArSYmmnUCphaUAmD4w+BPiBmxZ6EpRokBwaw1KNlYVLq+8XHk6Gf6paqDEPOlnDM=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:dc4d:3b27:d746:73ee])
 (user=elver job=sendgmr) by 2002:a5d:44d0:0:b0:37e:d5a2:b104 with SMTP id
 ffacd0b85a97d-381be7cf9ecmr7013f8f.6.1730737165815; Mon, 04 Nov 2024 08:19:25
 -0800 (PST)
Date: Mon,  4 Nov 2024 16:43:05 +0100
In-Reply-To: <20241104161910.780003-1-elver@google.com>
Mime-Version: 1.0
References: <20241104161910.780003-1-elver@google.com>
X-Mailer: git-send-email 2.47.0.163.g1226f6d8fa-goog
Message-ID: <20241104161910.780003-2-elver@google.com>
Subject: [PATCH v2 1/5] time/sched_clock: Swap update_clock_read_data() latch writes
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will@kernel.org>, Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Ni7T44lE;       spf=pass
 (google.com: domain of 3dfqozwukcdg8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3DfQoZwUKCdg8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
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

Swap the writes to the odd and even copies to make the writer critical
section look like all other seqcount_latch writers.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* New patch.
---
 kernel/time/sched_clock.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/kernel/time/sched_clock.c b/kernel/time/sched_clock.c
index 68d6c1190ac7..85595fcf6aa2 100644
--- a/kernel/time/sched_clock.c
+++ b/kernel/time/sched_clock.c
@@ -119,9 +119,6 @@ unsigned long long notrace sched_clock(void)
  */
 static void update_clock_read_data(struct clock_read_data *rd)
 {
-	/* update the backup (odd) copy with the new data */
-	cd.read_data[1] = *rd;
-
 	/* steer readers towards the odd copy */
 	raw_write_seqcount_latch(&cd.seq);
 
@@ -130,6 +127,9 @@ static void update_clock_read_data(struct clock_read_data *rd)
 
 	/* switch readers back to the even copy */
 	raw_write_seqcount_latch(&cd.seq);
+
+	/* update the backup (odd) copy with the new data */
+	cd.read_data[1] = *rd;
 }
 
 /*
-- 
2.47.0.163.g1226f6d8fa-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241104161910.780003-2-elver%40google.com.
