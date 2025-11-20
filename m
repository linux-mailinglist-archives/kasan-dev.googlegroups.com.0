Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEXC7TEAMGQEKHGCESA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 77189C74D54
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:17:40 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-594cb7effeasf564761e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:17:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651860; cv=pass;
        d=google.com; s=arc-20240605;
        b=bzsKsTldD0k5ktZC/q5ujkWbeTw0zlmx3FDkkenQl3/zSQYLD/WyQ6dw51NVjxbNbw
         QUVW+yXvirx3vRtz29n6pue26G2UtDJZCf9qaoEx5foSZ163tyUqyG6USGM4BsBZbOMB
         fyLBwPUa7pg0HapZBphYg4BD+0vZaZLk3qsr1ds2YBLtPqokjaoENZbt5/vbNafKLjtn
         sKNTOGo8uPwogK7Ehc8nwtpnwPTfmrXoX57s5RuEvnjR0y+rlxJUMcoTynLNOabrmU+Y
         VP3TC33Fyr6a2Bqspbaw6bgZfjuGaR+faspiRUrTF+mwdedY9ZFfNpjW7kaJ0vXfHBwp
         A8xA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=CRBiAf0gBvsv+XQ7/ZzqLGc+Z0qyzjjmp/l9BrGafRw=;
        fh=x0cWiNtyMRSGZ1ik+N7y/p0fltTZ8rH01GsJwCydmlc=;
        b=OnOlYRqUJY/CE95Q4W4CeI6iRK3MO7LLbxI4gpmfB0tXuZGKdJ8UaU51UftkaxrAnh
         f+civLNKH4GtCy2/YQGxlHuseII6mBEkUMtoYoKop9hj4faiWrt11JVHnilECVKzZ2EK
         thki+LFY928/tpHfJeNtmCYRzxyuvD9FBMny6R3jUQAioZFqfLZ2J2nu/QwPOOv5fmBa
         5veMUd1PfrwFk9soviJ41i07/MUWgRRO8SknEp2BnFJZdkfcQ6zh4L/LHzkV1lPYGMkW
         w3/8zGP9I2fSgnLkKWi3K7q8pZHYz51Yd5y9dvUp3IjxZGtBUphJcw+BwE+n6hzsDuh6
         YPtw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FIsNuOrr;
       spf=pass (google.com: domain of 3tc8faqukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3tC8faQUKCd8FMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651860; x=1764256660; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=CRBiAf0gBvsv+XQ7/ZzqLGc+Z0qyzjjmp/l9BrGafRw=;
        b=MJKbDOLBW5Fr0v62ZYKAVKep1Cj0lQZH3pcdNVcDEF10/2Mu1Jz5BN+59kTtH/clv7
         5awwv9inlWNhjn3H/+pwtGcj6uD+cIphIPUyTZ8r4RT6hfUEcpMlbUnT78niyWH9M4H2
         ckhgqqgKP9Nv+zDuYZ8DCWgrkzXH079jcggvVZIlO9s2OF7K2YuMa1aaEA8L3yKKy9p3
         wQBGe1iKaDFjV9XjnrnQNUI2S7OJx2XRtblIZRCT+REJLSkss/ENX1jXKxkVAU5AF28j
         tveGFsb88r/Wqq+D589te5tUf3jenkMqeQCAlDknpc9ljhytMds1xJ7hIv627q/Wb4Tc
         mxpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651860; x=1764256660;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CRBiAf0gBvsv+XQ7/ZzqLGc+Z0qyzjjmp/l9BrGafRw=;
        b=OVSnYAUhlDnmk0wZsrpsUqNzCRuxAX71O4t8uUiWPkisgTSlTTJpMEX0YxBbCpGlwe
         d3OphRCw2hbHjC24wtSkJ+Hs5LiY7gIE9odJ2+agb8VZZSTOiMyjNE5e9O6URXKXXPnA
         ukhG0MoABmrVHeC3+Y/TxQ4w4Ysb2apDnx5Lk+qbqGNxwpAEv/o1IM758ZXWKVoQr2OD
         RxgDiuFzdCmCtxrMqFcdSir0TZyPiRpP6DaAy/RWXCJgOj5KikGkqZ7rWunyZWAZySHc
         6edStUj3/K3QyStEnGd9oM/x2hOXFHuSvw9kSdp49s/Wta4wgWzwD946Q6SkXQTttTwF
         P/nQ==
X-Forwarded-Encrypted: i=2; AJvYcCW4SJDmjUBpkNUJ7ISn3n1bBMrKOT/XY2LRRoadShNGFsw4PQoXuoIRBaIAOqI/I4NuSfHxmA==@lfdr.de
X-Gm-Message-State: AOJu0Yy41gVqch0ykAvYA/bU3BVlZy4eilrufeTuZ0HwpgFYm75w9zj2
	8KAunYmDPLltKSiJKQMe6nKinz6ZwakRNBXEKw/B3EhGerZ38EzKSpb5
X-Google-Smtp-Source: AGHT+IGtje6fhBo0spt2EQXgwxmj3s7LxRhJT9L+vCdrqH41wULi927/mUii8FZeCdT+yNl27CTIJg==
X-Received: by 2002:a05:6512:1252:b0:595:9da1:500e with SMTP id 2adb3069b0e04-5969e2d05f5mr1230367e87.9.1763651859578;
        Thu, 20 Nov 2025 07:17:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZDoF6/JUPqB8WIjfI1uvfMt8+cY10mbe9W54AWHpkCDw=="
Received: by 2002:ac2:5685:0:b0:595:87c0:a7a2 with SMTP id 2adb3069b0e04-5969dc06674ls387744e87.0.-pod-prod-09-eu;
 Thu, 20 Nov 2025 07:17:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV92ugMqat7mrbJGUvpzGNTXaZqkcwH0yqvoiu2eh6y18jKq0GJm1XdKK1iCsW3PoK+hzSaBN3Z5Ws=@googlegroups.com
X-Received: by 2002:a05:6512:2245:b0:595:90f9:b9bc with SMTP id 2adb3069b0e04-5969e303424mr1063397e87.27.1763651856375;
        Thu, 20 Nov 2025 07:17:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651856; cv=none;
        d=google.com; s=arc-20240605;
        b=ewXaDBBVpjO17TJGeHCR+k+GvOBViuIlydQatgzE4dGGe7XBrUEH3veXd8cvazKLrs
         xgNfwpiag1uEKyqjz95OMeZPD1ydNDMWsHIv5nhRHAQ72YUs0IiKZOMeMvvOPRirDk77
         ZwL3yjith/N5JFMk7kdjqkXdA/nH74SuGDe7h85LX9Q/j8rJFQnTx/+jk8p8akS7tQSK
         76Ofr2Rp/DgpHLw4P7D6+ENVa+/N5mmiiTyW1apL7cGE1uxfWZk9dhlIqzRGhKYu4KFD
         bwOEdI4N9N7nngBwktgY00/4hMhW9wqrDpkbsXpglyJ599CvtTp0jLszNK4+nBNi45bU
         WMBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=sW5aRQBUT1YS/p7X2M8vu94/jdaGEDQWZc189ONsN2k=;
        fh=TJa1Kg14za+yu+zXrTNhhChF2Rjis1PJ/rYGc9hNJyU=;
        b=YmXo757RWS+/nEqU+BOUQsV+0/EHsVbbkz0BkM0ZMZ09OFXwiJ+aztspSXtnRLuTwE
         uQoxYZwLRnIEKe1PsEQ4g6T0QgjHl8gkMg3enbieeVogFX7Btx1NurSLzK1usLIVPS6k
         sHQr9f8s9SyoxMMRlg9M+H2YjcF1iseTKKhZX5QICW2pCJ3b1rWsoglXFILJRkaDn77L
         /ZSh8apMMKUzfXb4a4k4p83FvmtiXY5eCdVQu/vGmkLiSJ2tgM+2TW2GU5X/q4Sooqy0
         NaeW+BisqiyrT5gHWZoPBmTGvPncuAVLpHDTqJSML3CqZRzf4uC05qw203p9L2w2mFVE
         OnDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FIsNuOrr;
       spf=pass (google.com: domain of 3tc8faqukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3tC8faQUKCd8FMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x149.google.com (mail-lf1-x149.google.com. [2a00:1450:4864:20::149])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5969dbb1a4bsi43151e87.7.2025.11.20.07.17.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:17:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 3tc8faqukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::149 as permitted sender) client-ip=2a00:1450:4864:20::149;
Received: by mail-lf1-x149.google.com with SMTP id 2adb3069b0e04-57b9c463726so573642e87.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:17:36 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXK/U2iYIpucLYxUB8wvxbRrxHEJDHWFe9G9aCo+UVIjFsQjxqWIZzrzCKoTa2pwT2bOhoBpPCWV90=@googlegroups.com
X-Received: from wrsz10.prod.google.com ([2002:a5d:4c8a:0:b0:42b:3a01:7808])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:adf:f290:0:b0:42b:3e0a:64b7
 with SMTP id ffacd0b85a97d-42cb9a560c2mr2413997f8f.53.1763651508025; Thu, 20
 Nov 2025 07:11:48 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:32 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-8-elver@google.com>
Subject: [PATCH v4 07/35] lockdep: Annotate lockdep assertions for context analysis
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
 header.i=@google.com header.s=20230601 header.b=FIsNuOrr;       spf=pass
 (google.com: domain of 3tc8faqukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::149 as permitted sender) smtp.mailfrom=3tC8faQUKCd8FMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
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
guard is held after calls to the annotated function, and avoid false
positives with complex control-flow; for example, where not all
control-flow paths in a function require a held lock, and therefore
marking the function with __must_hold(..) is inappropriate.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.

v3:
* __assert -> __assume rename
---
 include/linux/lockdep.h | 12 ++++++------
 1 file changed, 6 insertions(+), 6 deletions(-)

diff --git a/include/linux/lockdep.h b/include/linux/lockdep.h
index 67964dc4db95..2c99a6823161 100644
--- a/include/linux/lockdep.h
+++ b/include/linux/lockdep.h
@@ -282,16 +282,16 @@ extern void lock_unpin_lock(struct lockdep_map *lock, struct pin_cookie);
 	do { WARN_ON_ONCE(debug_locks && !(cond)); } while (0)
 
 #define lockdep_assert_held(l)		\
-	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
+	do { lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD); __assume_ctx_guard(l); } while (0)
 
 #define lockdep_assert_not_held(l)	\
 	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_HELD)
 
 #define lockdep_assert_held_write(l)	\
-	lockdep_assert(lockdep_is_held_type(l, 0))
+	do { lockdep_assert(lockdep_is_held_type(l, 0)); __assume_ctx_guard(l); } while (0)
 
 #define lockdep_assert_held_read(l)	\
-	lockdep_assert(lockdep_is_held_type(l, 1))
+	do { lockdep_assert(lockdep_is_held_type(l, 1)); __assume_shared_ctx_guard(l); } while (0)
 
 #define lockdep_assert_held_once(l)		\
 	lockdep_assert_once(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
@@ -389,10 +389,10 @@ extern int lockdep_is_held(const void *);
 #define lockdep_assert(c)			do { } while (0)
 #define lockdep_assert_once(c)			do { } while (0)
 
-#define lockdep_assert_held(l)			do { (void)(l); } while (0)
+#define lockdep_assert_held(l)			__assume_ctx_guard(l)
 #define lockdep_assert_not_held(l)		do { (void)(l); } while (0)
-#define lockdep_assert_held_write(l)		do { (void)(l); } while (0)
-#define lockdep_assert_held_read(l)		do { (void)(l); } while (0)
+#define lockdep_assert_held_write(l)		__assume_ctx_guard(l)
+#define lockdep_assert_held_read(l)		__assume_shared_ctx_guard(l)
 #define lockdep_assert_held_once(l)		do { (void)(l); } while (0)
 #define lockdep_assert_none_held_once()	do { } while (0)
 
-- 
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-8-elver%40google.com.
