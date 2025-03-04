Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPEOTO7AMGQEGC4NJ3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 18149A4D81E
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:26:22 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-5493af78444sf2692161e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:26:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080381; cv=pass;
        d=google.com; s=arc-20240605;
        b=fxN6rHre4tvEyZQ7NcHNNzfI5DVfA+BH8CarCNL0pTpy/2KRyb9FLamK3LrkvJL4LL
         sBP6PY6MQfwIVtFIuejTB1q5Cx61wqY8lIdmNrsNMy8j1KB5ZGpzR4YtCECIopZZDdwb
         GbxpZ9nykn5HayluDYipNxb7pMay60MhEs/rHyr8iN8cUwup7H0iP0+pym+b6fatZGZ1
         MLf1xrwUnoRdpPTR43/FAXMNSDbR0VEEKpjAFgN91puhE1DV50QjUaUqtVG3uxaUk+nL
         xOQ6x9KEr2kFX1JjlZYXMMu5+HBv+kc4FRQhy+2LwGXiwF+tnRlARJZ2SLEcSIbQIQ/K
         XS5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=p/GGVvLjajbFQWjUnjlmn1uxrHXGpqiC83Jkah4yugk=;
        fh=/EiUc+n65yim0I8nlkAhGfb9/fmaPtGuxIBh80ns5SU=;
        b=ISMbqsrwXPFIZg5wfm63QrqaapH8bRxiToPg0RDaKdPxwOLsqvi1rXD5PU+jdTKRLU
         cYdA5JiItMY1mVkCgTmgh5JGQEP+JW4+JITc3yDYq8S606I1H/uLuFlY4D7HZjfF+whq
         5X7MeFNXklaVrlwKdZroBfoMx6BuCRyR7Yit3u/ZOMHiXrpkMd6KbD3iJ1tGToWgUAhN
         3Y1a9kJzmILn+q81foNEPPwHe6OlQrqNFnH4o+3ItURbzhWx6oL8yTBcTRu8B+hmJapQ
         UwDw5gZB38iTP8ha4/1ULU1b0lB0Rko2FM7ci/WRtxKNl5T6evRjEy0JXQrr28NEKKg/
         5GUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hrPErXzL;
       spf=pass (google.com: domain of 3ocfgzwukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3OcfGZwUKCSgIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080381; x=1741685181; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=p/GGVvLjajbFQWjUnjlmn1uxrHXGpqiC83Jkah4yugk=;
        b=W0rPGyfal0vIY9lbS7sfCqOUGuDBo1QNEPMNcgtCsf92D872qJlzsbsBLm3rRQSaMv
         n+TJiDLayL+XaxBsF/XIAGN5cAcmqiUceioji6G6ObtCiH6cBFrH8F/zjNo7CGBN/ncX
         6Po8t/eh/0/h3O9djp+OOpPQgWnJZNqpKcTNg6qHI4cOgvqPoamWPV2JsMomLnJpzpBb
         cMbYfovSGcKWMTcv+7vHM6wF0stk8LJjgeLlN9vlEv+3JBqUInJSAStle3k8vx636x5T
         5nZGtcCaqewvNWnXj8/hwtiW2ip+mM5ySECAqjNHqBejInhEkOzLepk1mJfdKn5eQq+f
         ECdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080381; x=1741685181;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=p/GGVvLjajbFQWjUnjlmn1uxrHXGpqiC83Jkah4yugk=;
        b=oJyop6lGu78JP6dlZpwfaTQJ37z8siYYIamfCMp8DmhzucM+1ombm/XUc9/11OXw1h
         IIRVmM6gYDlLreV4UhTNM8V/zrGGqkZjoUdP/a9UPAxg2QwM6JkPp+vXp9OV/u6JVcfs
         0xCBJj3HdDLjTST1BuYm1qkbrPd2WX6rkdHw8/L0/cRYgU5TV3vQeNqVLSpQTtSUSZUb
         ts2mswFpw9HAEOhBXkXrZb8kZjJBcDHOxOKFxcv2k5oDBDVJxcfR3cj0a+UHPXgq2Rdn
         nCNXOlBK+Rv5qK4Z7u5n3r9ZUSJKj7HxMfyBuS9B46jQCFTK+hZmso+ToAEWozaJBpjB
         cYZA==
X-Forwarded-Encrypted: i=2; AJvYcCUtplc6GcassCjrHARQAPz+y1w7r+q0Wc42ZuiwZNWc+g+WBBepSW/pKA1amw73V6MGmRohlQ==@lfdr.de
X-Gm-Message-State: AOJu0YylobtubXSCkeYI5GjnZZbY1y0wY/GcMDf+PUonCpXZwzWSMPgY
	uQYiTySMoOcJVxMYr9jKgi9aamakJ16+df0v2YCg62mPR3bobT3I
X-Google-Smtp-Source: AGHT+IFO1KEa+euqHTyAZyrtKzpUPUjbi5rnkApxT0B0QKrC7r8b9GVaTXXf3ZSB0wUzwz7PyNK49Q==
X-Received: by 2002:a05:6512:1103:b0:545:d54:2ebe with SMTP id 2adb3069b0e04-5494c36c16dmr6286545e87.43.1741080380659;
        Tue, 04 Mar 2025 01:26:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEmZbYDtGpSrGGOVteGwfkrY40J8+Gl95lOSLCUX86gmQ==
Received: by 2002:ac2:52b4:0:b0:549:5db1:d929 with SMTP id 2adb3069b0e04-5495db1daa4ls564946e87.2.-pod-prod-01-eu;
 Tue, 04 Mar 2025 01:26:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXeYk3r74sOXwoxWt3w/+bv7JpACCVWxmHtkUirVNxsgsvSZnmDOXK64uTr4E2utB70Hju+nrNUlSw=@googlegroups.com
X-Received: by 2002:a2e:a7ca:0:b0:30b:ca48:10be with SMTP id 38308e7fff4ca-30bca48157cmr10150591fa.0.1741080377848;
        Tue, 04 Mar 2025 01:26:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080377; cv=none;
        d=google.com; s=arc-20240605;
        b=AL57HPLd6UmVCszuXP5zwGvTU5jTMTzqOBWbLKD/Qm5HdC9+WR1q9lTueB2BEDVN4v
         GjS1GEW4BzNSGI28zPmWfvMRrXlicVUXtHbzlD1+DHlxESY3MXCFgdQGRRqsnJE9fNvI
         4HZeJmyd7B9ZWeOlf4yGnRb8Nnx1NK1xc8slaJLG/BOhXLdM+6M5TbV7YqSmKT2wp9dU
         3v55C9/VTNNbR/3P8GxQgkLi32JyVn7pxeKw67V6jTPB6oaHbCol67EO2spC+zocAfyq
         ZTQKSUAW4yMxZdQhhMdCNgIL/+NCJpzrbpevhOOMGmAL8+9LlMcFlEeVribPvB6b/xeB
         SPnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=FyNUfkRqmSD94utdQtDIE/VXIceiBYCUysEEfDdchTw=;
        fh=reeEQSsbrW60286bpk0yRQ4GtDVzCiFe1XMEonAjC5o=;
        b=ger43O91QF9fb1liM3E+YBcUalg/Z/OvV46bwuYrMQrP28TItLSwMR4lwjJYXx++aa
         OQMixLtcBD90PlRa1eQbUJ//vAB7ntUdFRYKq2a4B1ksVP3BXu6yb/hi/1Dl4VCEHx3n
         6omVYa622yZCh9nQm+cQg3uRkA0NMFEf7YAFPgIcw2NUrloYrSjx152JT8jruUM6d88B
         rpg4g44vnbzqpLD5T6iVkFL1ETE+/qMHz/aqrj12QXBB9xMprnSynPxSyHisXE/rIzVY
         ybYi6Kommjtaaczdt5Idxnf4aDIayeJ3x1PZCpzBEUXLaSGc+kmcG3kZywFW5GgcyNlK
         jDLA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hrPErXzL;
       spf=pass (google.com: domain of 3ocfgzwukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3OcfGZwUKCSgIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30ba2e9c829si1448471fa.1.2025.03.04.01.26.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:26:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ocfgzwukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-5e4b6d23a5fso4602554a12.2
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:26:17 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWohvM4sMLIrR81aqohTUxuSnHYX7eTXnDpIdRdFFP4owq+xF1jaMPP8/Q9E+iU6ng9i7FrLJ1lEeA=@googlegroups.com
X-Received: from edb11.prod.google.com ([2002:a05:6402:238b:b0:5e5:339d:60ab])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:274a:b0:5e4:c235:de10
 with SMTP id 4fb4d7f45d1cf-5e4d6b7b21fmr14799795a12.32.1741080377028; Tue, 04
 Mar 2025 01:26:17 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:24 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-26-elver@google.com>
Subject: [PATCH v2 25/34] compiler: Let data_race() imply disabled capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=hrPErXzL;       spf=pass
 (google.com: domain of 3ocfgzwukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3OcfGZwUKCSgIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
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

Many patterns that involve data-racy accesses often deliberately ignore
normal synchronization rules to avoid taking a lock.

If we have a lock-guarded variable on which we do a lock-less data-racy
access, rather than having to write capability_unsafe(data_race(..)),
simply make the data_race(..) macro imply capability-unsafety. The
data_race() macro already denotes the intent that something subtly
unsafe is about to happen, so it should be clear enough as-is.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* New patch.
---
 include/linux/compiler.h       | 2 ++
 lib/test_capability-analysis.c | 2 ++
 2 files changed, 4 insertions(+)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index 155385754824..c837464369df 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -186,7 +186,9 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
 #define data_race(expr)							\
 ({									\
 	__kcsan_disable_current();					\
+	disable_capability_analysis();					\
 	__auto_type __v = (expr);					\
+	enable_capability_analysis();					\
 	__kcsan_enable_current();					\
 	__v;								\
 })
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index 853fdc53840f..13e7732c38a2 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
@@ -92,6 +92,8 @@ static void __used test_raw_spinlock_trylock_extra(struct test_raw_spinlock_data
 {
 	unsigned long flags;
 
+	data_race(d->counter++); /* no warning */
+
 	if (raw_spin_trylock_irq(&d->lock)) {
 		d->counter++;
 		raw_spin_unlock_irq(&d->lock);
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-26-elver%40google.com.
