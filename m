Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQMV3CGAMGQEJMKZWXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BBAE45568A
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:46 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id l187-20020a1c25c4000000b0030da46b76dasf3986123wml.9
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223105; cv=pass;
        d=google.com; s=arc-20160816;
        b=PAjqbOLN0WfjFrtBRGHRYRTXqq0lKCO9u64qWs1ndlFDcLhZvI2TmSGsXCmhK2XAes
         ik4WDVUhLPC+pq/D7Z/IuAmXoVNtoRz4GQ9CuD+MkMx6O12zo4W6ljQZhyQ4m5LJyA6P
         bA/9fHudU9ja6FbLTan1BSnNkQQIiefMbiCB+fch2p26JA+phjSxNXGhdR9P1tkT7u1V
         ZJBIkzSO/8GKkdwYjfHvg8n7a0aq1qvCZugnF3PKlYBDb8HQZ6XtTW5OiiAyEfJ1G5V+
         zZF1ks0dvMYb+3JDUvuQcOHeiF+bV8UcIKMG95137lcEH6qJwf5gu5UcGRC6iDqBnt3t
         M3pQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=2p3FvFn9aZsvdLlGc4nkw5XQ6LSws5XteeRknwbT1R4=;
        b=fS7dc0tmNh7JpIuwXzKlRLk+Cpk8+e5mYt6kjBKECfIrRZf0X+4xR5jZulfz37PQdt
         dVt1fETAy0zobtNNZt2zlAkt3Ob+8Of+p90rUKVXZgLjUxiOMHmEvDCCb4Maxv07EW2O
         hGdJ4el+14dDQ8tQ696wz4nZyzcF5wYNQBR0//2wg+4gIwQygB8IY4AXHYh8Ia0cmZfK
         NcDKK9qkc29wM8D70TFOv7SbIkyfzOjAO6vlWmCpaVe6umifHfDVJZpPPLpM7xQKntSD
         5Unr1xyljVXnfbUmUb7/Gcp4pud/vbc4uJVemrc1p550b1xzOeaP/0Xlt3gsrKwlhLzC
         G2xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MK2Vd4Yj;
       spf=pass (google.com: domain of 3waqwyqukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3wAqWYQUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2p3FvFn9aZsvdLlGc4nkw5XQ6LSws5XteeRknwbT1R4=;
        b=mr4XQiH4BUD5qj7sjWMr9jVoIwi8cDpzTNy9dCNhiWZ8j6RKDwyvjDGAzdOegOpMkg
         sqT2ssx3hYeDJH9568xjQp2xGzJiUNkzEyZ7ANmdyujknvYBveK0Odnx52c1U0xfSmUS
         AByVjBt37tInSMEgE3A7RRd1FXHzHOAfDqNO6z2SFnKgZQCMRTaPZ0WnyAhq1Cofn9cg
         SSa7jQ6OwxxncMDsf9AHhHNDhWDGji+ZbaXAbXs1cQFWgaof2IF1udxLG+SaNmBONgXK
         TzT1SYUOj8jqh9HMXGakYGQpxV3XPUiRm4mJpCSwi+kF65tB6sdFMYnIFGcLy99A0mnr
         WEnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2p3FvFn9aZsvdLlGc4nkw5XQ6LSws5XteeRknwbT1R4=;
        b=J0nWgEfo9djr50F2Q3T2+ohf6VjttcYM1Dp73hodf7WPyx9JLTefl+bxmjm/3S3umo
         NIIMYy85zZKwSEzpzJNcSiWZoR9U/Z4RPR9qGSqdm1cwfKx8IiHAAqmzuHSllN4kRhqj
         HX0ClkVCZ7VqUngM/zXbw1t/mKJCXLn3jfpgK9uzmmh/NdQexgBxlklqa2FTQmm6LyS+
         5TI5IJRxtbM1wt9IyV15I87UnmZhovtTj8ha+nvlJQHUYvHIvXm8r/KOuruedujcmeSn
         POmmCaTg2VA4zP83E+9rx3cAfMWF5EkcBvDOazrehIC7BIe4l2UlzHP6kpZVKv8kq2qT
         yeeg==
X-Gm-Message-State: AOAM530RXkdYLodTXOxKcFnPmV3le1/E+SRU+UcUGwZLUFy0g6LvmrQD
	VNuzI7bkrnxsGuZQfTzUlYM=
X-Google-Smtp-Source: ABdhPJzrWtPFX4RWLRJKHASw1EM08pySZm4L/+m4FLELohL/41J7lDiVHd2uF4xFGPipypZGE/vK9g==
X-Received: by 2002:a5d:6085:: with SMTP id w5mr27370150wrt.122.1637223105854;
        Thu, 18 Nov 2021 00:11:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:80c3:: with SMTP id b186ls1160675wmd.2.gmail; Thu, 18
 Nov 2021 00:11:44 -0800 (PST)
X-Received: by 2002:a1c:6a04:: with SMTP id f4mr7700575wmc.56.1637223104896;
        Thu, 18 Nov 2021 00:11:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223104; cv=none;
        d=google.com; s=arc-20160816;
        b=ZjE746keLkQ64OmcN90gnzfINd3FwranjmQtqdX2ScWPUscE6DwJi5Vvj0lcBpz66p
         alDAR8XUqCu0JCQR3xLUpx0hT9hzrvlGf9jQtEE3D34Fhv2DZxr01aNRIbiCTuphBtuQ
         Wt2HAM2zUOIuYumlivo22FQUGmrFokGon6edo7gM5DdLczeHjcbvx3htQOTrEgYY3V4+
         zRvjXQv2rueVH5+WZNen2aABjjzvSQPArqUi7JZAEqFxDhMukXH+3maQMRpwPlmBT/66
         0ZNSQ/l1AyywsxxwHXLAr+0kEUWZRDIOK9XKnqsocvhyPRqV74pQmO+VLqRwgRFO2tF9
         MMTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=TQFyZU0v42DaaTkISoD0OFzde9Hlzhfr9CYPS/61CiQ=;
        b=Kq/nUXXXC9JvLpkkvZrrStbRHGYDLpUNmVrhixHjbqYP4cZ8nUowTLjuYVg82U2b2c
         k36BmnjbuzPY8W/uY1z5BVSKctlgDxeTRzLoH+SqgPbQSShEKLBmSAssU3bRPAzUF1zh
         COA6SmlNp7NRW1Rf59ZQLc5c2MzFbRB8Apcl2eGiVJcnBEDJOmNIxaGkMTe1ZZCyCKpT
         MSubjR4Bsq7inEKAn86ynM9MrY1nJpnEubiYBfWug/W8exVgtDAcd75tZbsbG/P/K4Yn
         fZa5ukxTo4J508qSfLmQb+u2wbhVXDSvIhjspWxkItBEIJcMSZu/FuHWXiZbhGJUj3cN
         mLQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MK2Vd4Yj;
       spf=pass (google.com: domain of 3waqwyqukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3wAqWYQUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id p11si527092wms.3.2021.11.18.00.11.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 3waqwyqukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id r129-20020a1c4487000000b00333629ed22dso3991336wma.6
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:44 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a05:600c:1990:: with SMTP id
 t16mr7680724wmq.48.1637223104386; Thu, 18 Nov 2021 00:11:44 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:23 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-20-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 19/23] x86/qspinlock, kcsan: Instrument barrier of pv_queued_spin_unlock()
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
 header.i=@google.com header.s=20210112 header.b=MK2Vd4Yj;       spf=pass
 (google.com: domain of 3waqwyqukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3wAqWYQUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
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

If CONFIG_PARAVIRT_SPINLOCKS=y, queued_spin_unlock() is implemented
using pv_queued_spin_unlock() which is entirely inline asm based. As
such, we do not receive any KCSAN barrier instrumentation via regular
atomic operations.

Add the missing KCSAN barrier instrumentation for the
CONFIG_PARAVIRT_SPINLOCKS case.

Signed-off-by: Marco Elver <elver@google.com>
---
 arch/x86/include/asm/qspinlock.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/x86/include/asm/qspinlock.h b/arch/x86/include/asm/qspinlock.h
index d86ab942219c..d87451df480b 100644
--- a/arch/x86/include/asm/qspinlock.h
+++ b/arch/x86/include/asm/qspinlock.h
@@ -53,6 +53,7 @@ static inline void queued_spin_lock_slowpath(struct qspinlock *lock, u32 val)
 
 static inline void queued_spin_unlock(struct qspinlock *lock)
 {
+	kcsan_release();
 	pv_queued_spin_unlock(lock);
 }
 
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-20-elver%40google.com.
