Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMPGSXFAMGQEC6EJLPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 887E0CD094A
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:45:54 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-4779b3749a8sf13966875e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:45:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159154; cv=pass;
        d=google.com; s=arc-20240605;
        b=EnAO4OJDqTUspiaWYhQpXOLG+az+RXlvr6LpW1rcAt8idBknB/zdbUKwVu8fuGUtdm
         dQQLcS11dTMxfhQgaIahFbeZv2OXScfn37k+Vh0VJfuQ4kv8jp7Yo1VBfZbwRhJPujlk
         6KCjIBJw1L7KNR0NLdyAGJOj0H2uDRbaJRPi8wsg1zTTlq0VRoxqu74DESTCGgpdVBzh
         ISpVrryNsHf5Q8OVKdKjgRXDOgDgVG0PMLJ0X5UKOsRfx6IPrOLFK+IXXMSjtqti+MXD
         +A9Ym3kYIE2RQmC6WLdtfpVb+FAoG2UacNoI0PiqkAvYIhw+IpQnypaur+8lam2KtDN5
         ONdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=sliLjzG10J43LuBdZ/oEA2qxA8m43hAyO6RZi1rZodc=;
        fh=qT+VTzQje7UKo7J8YJMhmwVG+dNFeDS9TcyNJShE4Zc=;
        b=BV8/gOLF3LZkgkPOE0uy+fo9yArQelxPv7Wz0bTCMU+uIcyvX5+IH1r7jO8GSdKsu3
         jFshAI/RjCRnMUrHn7i89UWfkxgv4r7QCohesJsmvUkVIju28rGoPaJSY9lWzBlOf6v6
         a7R1MVV3+ijA1KrWHjDIgLfY/x2XoWloiavgsUKKtYNTNISdSHzcq3Z0phWp5bIX2Z8p
         COuvQIFpv5nRlGXxa7IJtNPDFJyE26h+FWVj/En7WYpCYJ8kc5cdQcTumzkbSgjmIw7S
         3//tb1LFl5U5zIFH1CBNyVQ7eYPocXlDr/UG4O3e9884CLM6tvXaPj1xF8IE64P8Pme4
         FwAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RgJHJpB7;
       spf=pass (google.com: domain of 3lxnfaqukcxocjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3LXNFaQUKCXocjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159154; x=1766763954; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=sliLjzG10J43LuBdZ/oEA2qxA8m43hAyO6RZi1rZodc=;
        b=HqcDg8T9OdyJG/8+mMu/FXbiXVbrBfOFKR83hnkVGhKUw3MwEXDURYzMhD1i5RMSwz
         Sgj/K/oXjIstuthOmGAAca5b2uyLyX8a4nTpBjrZMO/BiK/OPG37onXc5W3L8yeeK3aW
         p0/LyfxKKuJFqalGj+WYhdTpL4+JQrqIjOLUERpUeLIPBKyLzI0nEra/YMOh79OXB+oF
         nFQP5nuv7YzcDyE9IfNS0Cs8z+nlD7VDtrtEg6OtV1Wzdv7PofygBvsdD2XrFyfVI0Ka
         KC/dPhAvg2iH4FLa2w77mYfltBjoIgg0vEnCyHY03YIlHXkyLMK7esh9oX6fAfl8mbQ5
         rjzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159154; x=1766763954;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sliLjzG10J43LuBdZ/oEA2qxA8m43hAyO6RZi1rZodc=;
        b=nYDCJ25wvtpO0TqI/0SGQ7bK4wa42ZNWgq0/VYsuyf2we7Qxx1KZVDx+offC/BEAUM
         GynjvUlPbd+TNMSsSJCKk9kBF1I5PnL1G7JnLgPjQ9mfnScLDAwoymv/8v8e6s3OqQZY
         iK1/yy5RxlfUT794inZ+Qt6Fu66E709iXPpHidwc7N0LukM+dZszrqk51hCRhaKTBcue
         a1Z1f5ziDgoJg6DAZDXSXyTjjjcrXqmcfdPKj/wz3+Qj3we4qtrDhUspUGoy1lup3zN8
         NErpepWgy1qIo0ZNDC5fWqIydfm2w4tlsJD89gSJCX4tDW4h+28nyymuqg0mLgaKkcoi
         GqLQ==
X-Forwarded-Encrypted: i=2; AJvYcCUDcFnpkSMfebn6RDBzMSNXE5kDXahMClm3wMAthCooGSL2Nt35uRhnhH/hAbiS2YeYMjaq6g==@lfdr.de
X-Gm-Message-State: AOJu0YyIGFi2TGNR//qPMxbjC1EHECNNTPZPKjtQLZT6j6u3CqKJo5uC
	5oS0K30WPtgZM+dp03KJ5UB2jQQdodW2rAmwWwHiXKGMic3T21GJSJG+
X-Google-Smtp-Source: AGHT+IGhcemG3vNWFocN4S1mf53jIzKoxjhbI19rJvfcxiFscmRpEepGjHaUYZ0JLoIwAsgFwGGu0w==
X-Received: by 2002:a05:600c:5248:b0:47a:8154:33e3 with SMTP id 5b1f17b1804b1-47d1958958dmr30741065e9.28.1766159153941;
        Fri, 19 Dec 2025 07:45:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZydRGNWojG4rgYasl/zbs89kYfl7Vma3yMrAUDwO7HtQ=="
Received: by 2002:a05:600c:4ec6:b0:477:5d33:983b with SMTP id
 5b1f17b1804b1-47a8ec638d2ls46566075e9.2.-pod-prod-01-eu; Fri, 19 Dec 2025
 07:45:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUBWLCXDHPKGkPBP80acVjK7t/4y2UhDtV5f8BkymtM9MRjttKBez+8ob9381uNAhKJ0YJBuRVtTpI=@googlegroups.com
X-Received: by 2002:a05:600c:1d1d:b0:479:1348:c61e with SMTP id 5b1f17b1804b1-47d1957d746mr30814125e9.20.1766159150536;
        Fri, 19 Dec 2025 07:45:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159150; cv=none;
        d=google.com; s=arc-20240605;
        b=FymimrcI/tQ70r4nbVZ6P4kD1XA3pUTxNyAy4O/ognzPgN5VqIs04GI6aNB9i9OCO3
         caKmv+gr7zQqWztlT7SXJWPui6MhM/n2Yg3P9Ns2OezX/vtuYfvWlmGZ5Vjmxs/sMxFp
         ftJ6N3RXATnkRYU3RwiOziHOyGRWQevTTkuGwA+eCk5O69+QFlfG3zlqVzm8ziOMEZVV
         PTvq2lneBVmxBUR2mTgtdAVMitSAeSXurwykxR2HJWW2k6/LUpaJOLPmVKchXAGuDp2x
         M0LM5jj5EBYNyxT4dLfZ7dRCpnPGMLoYpafmMpn68NNXsJmnfb/081xUAQdzgm4sd3pt
         Ux3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ppEU3vt21POuxnmNi7TnVPUBkU2y1/pB0srZ9HoiLa4=;
        fh=8EjEHtnMI/xz5HvUzBUuutTO3ySQ+xWzojVr9uEbx2c=;
        b=dn0vDsKO+FFJnasVuqH+Q1u7k8DPg4a/T0OCvwaxWbqj8mRHk2MllGdoz1DKpShSQd
         0Dx6zaRWcprvwndS0KA8QcwRHoHX+iunMSEIkso3P+RYWdFCu1MaqoLbLSKDJP4JvZ8T
         GeYf/F9o4UcFu66kb0hnxpm0+QyLOGBg/K6k0K8hRMRRcjw+2HcXZowt3E4F8BPAdz/9
         6mAO7Z3jOdhjOAoBha7cfeT7Pfw/GjOBXKrTpFi9ESBBg4jfrmvqOBLotARqktzmYn0g
         /Ns+roTB+p1dnga5TERmm0DMaFwDd7B1Nt1MRF5O8eQeg1A59R3skPOIUaU6N3BIZU5W
         aDNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RgJHJpB7;
       spf=pass (google.com: domain of 3lxnfaqukcxocjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3LXNFaQUKCXocjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4324eaa8b0bsi32096f8f.9.2025.12.19.07.45.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:45:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lxnfaqukcxocjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-47a97b7187dso9522705e9.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:45:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVu7XwUiKRgI+oUiaYkuF+Hm63LmLg7wwubPUUEH/7jxM5CUtj4VwmN8sRm4gnDYyXeCfLtTkYSSWY=@googlegroups.com
X-Received: from wmcq18.prod.google.com ([2002:a05:600c:c112:b0:47b:e2a9:2bd3])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:19c8:b0:475:de68:3c30
 with SMTP id 5b1f17b1804b1-47d1955797amr31569585e9.16.1766159149911; Fri, 19
 Dec 2025 07:45:49 -0800 (PST)
Date: Fri, 19 Dec 2025 16:39:56 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-8-elver@google.com>
Subject: [PATCH v5 07/36] lockdep: Annotate lockdep assertions for context analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>, 
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RgJHJpB7;       spf=pass
 (google.com: domain of 3lxnfaqukcxocjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3LXNFaQUKCXocjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
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

Clang's context analysis can be made aware of functions that assert that
locks are held.

Presence of these annotations causes the analysis to assume the context
lock is held after calls to the annotated function, and avoid false
positives with complex control-flow; for example, where not all
control-flow paths in a function require a held lock, and therefore
marking the function with __must_hold(..) is inappropriate.

Signed-off-by: Marco Elver <elver@google.com>
---
v5:
* Rename "context guard" -> "context lock".

v4:
* Rename capability -> context analysis.

v3:
* __assert -> __assume rename
---
 include/linux/lockdep.h | 12 ++++++------
 1 file changed, 6 insertions(+), 6 deletions(-)

diff --git a/include/linux/lockdep.h b/include/linux/lockdep.h
index dd634103b014..621566345406 100644
--- a/include/linux/lockdep.h
+++ b/include/linux/lockdep.h
@@ -282,16 +282,16 @@ extern void lock_unpin_lock(struct lockdep_map *lock, struct pin_cookie);
 	do { WARN_ON_ONCE(debug_locks && !(cond)); } while (0)
 
 #define lockdep_assert_held(l)		\
-	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
+	do { lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD); __assume_ctx_lock(l); } while (0)
 
 #define lockdep_assert_not_held(l)	\
 	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_HELD)
 
 #define lockdep_assert_held_write(l)	\
-	lockdep_assert(lockdep_is_held_type(l, 0))
+	do { lockdep_assert(lockdep_is_held_type(l, 0)); __assume_ctx_lock(l); } while (0)
 
 #define lockdep_assert_held_read(l)	\
-	lockdep_assert(lockdep_is_held_type(l, 1))
+	do { lockdep_assert(lockdep_is_held_type(l, 1)); __assume_shared_ctx_lock(l); } while (0)
 
 #define lockdep_assert_held_once(l)		\
 	lockdep_assert_once(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
@@ -389,10 +389,10 @@ extern int lockdep_is_held(const void *);
 #define lockdep_assert(c)			do { } while (0)
 #define lockdep_assert_once(c)			do { } while (0)
 
-#define lockdep_assert_held(l)			do { (void)(l); } while (0)
+#define lockdep_assert_held(l)			__assume_ctx_lock(l)
 #define lockdep_assert_not_held(l)		do { (void)(l); } while (0)
-#define lockdep_assert_held_write(l)		do { (void)(l); } while (0)
-#define lockdep_assert_held_read(l)		do { (void)(l); } while (0)
+#define lockdep_assert_held_write(l)		__assume_ctx_lock(l)
+#define lockdep_assert_held_read(l)		__assume_shared_ctx_lock(l)
 #define lockdep_assert_held_once(l)		do { (void)(l); } while (0)
 #define lockdep_assert_none_held_once()	do { } while (0)
 
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-8-elver%40google.com.
