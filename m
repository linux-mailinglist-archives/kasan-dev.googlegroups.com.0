Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB4OTO7AMGQE3SWOBXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 86F96A4D7F9
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:25:29 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-43bbfc1681esf10287525e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:25:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080329; cv=pass;
        d=google.com; s=arc-20240605;
        b=e677TtyRhXhcO+rDxu2j4iZ+XqhdwAmkfSCwr1rmUIhgRhV38DyxsHexKZe/LHGar7
         R2Ytnen5OuvisgtQb+T9XnK8/Mz4Nulq9Zyg9gY0uiESE6HDApmJA1rOMMa44HOLLIbU
         MIjylU+XjQ5izU2kVHjfY3kMcorP7f2lTRGR4So8+giCkhGLuSNnf/GdXngUls96DfIn
         mfJ3khZRB1E8z1r0XjVx+oCZhQ4yprhf4wURrakKdMlJf9+dPzXQQ/7GrZ4hAA/Ormyt
         8fH6favKVWrlo56+YD5yuhvRDeAKb5glzkKtROBY6pyAIGfkQIZ8/0xhG726fU+ZQUKy
         V41w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=NH5yuYzvxo060+wCndbKBGpKB8wRp9VH+losZwPUkhI=;
        fh=y4iqKDOO8m+BKHy9GhGWOFqGvndeCjwvDqMu5r8ySXc=;
        b=NSE/2s+b2Lyki9ayqqpRhzX9uEr4ztVKxLPb777orHjoVji3SvUZKqsI2IRBcxU+JJ
         dgHcAEsWK451CPjx4jJBTpEznEvLeCiRW+vfSTvlH7AEAkAkmLY08oRGlxQlLT8upkqu
         v/SVlYSPCK3S5y4N9Ayk8RvkFC65b4CGGEgGQeSzvjy5wTFjQasCmPYCZE+d44ALqRhq
         38j3V5zY/5aC6xaUaTQPFLTZqFt0KZL/qIppxg/GHXkQap9mU8648VJfl1orvfv/30td
         naObiCbEaDPA6BGhaCQ/DGTSbVLKtNVc/4glCfNqcLyUQfeT1s+HKetoO4YpviyfTQvy
         j0aw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cv1gwc17;
       spf=pass (google.com: domain of 3bcfgzwukcfiyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3BcfGZwUKCfIYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080329; x=1741685129; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NH5yuYzvxo060+wCndbKBGpKB8wRp9VH+losZwPUkhI=;
        b=b2jVbXKuwoo2oty3RkfWkslg4yZtY9t5TKK5LYnEZr8LqOInSNPW5ZZLGzp7z5kA+n
         UbAKRPIQyIwi156Lcw1kdvoO26nwM8r9n2hvC2rKRbZc6GwnTrELRtjaTUdo074ktYMy
         4zOCzZjojHTdvsgkXKbuVbxLFyK3887jPXXB/z6ymnkA01RsoMYz3Hp+y8YPkV8Ty2LI
         6kHUzQS/6Szhe1Eofu+XEnf/1asa17dOutlDQOr+V42z834mHUJ+t61oEKJTG3KLC3UM
         wq3oZJg/YuiR8wsfNV5prF9DQfc3RhTpivBE2JCrLi2FivlOxcv5JruLASJ8LlOgat1B
         KNhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080329; x=1741685129;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NH5yuYzvxo060+wCndbKBGpKB8wRp9VH+losZwPUkhI=;
        b=B+37vi1sqEtGb/mpLqrQjRwKIChqY5w98q9TJA7Bnv9XQhDXKMJQruNCrdNHbWzHqI
         ZfspvbQiFSIAVZRaXdHakmKHU9MN+Smsm9OOSdsRFT7gYFlPQGOEKTnMcDOfWrUHqzm+
         TQCIdKYKxafJGEX6hYV5EPScqyymrrrTaC1t3ZNULyFiL9x0oksqVYF7NVyGOcYygONo
         DheGMctY43IjgU0MCpWigfP7r8Fg0taDxNWXwYRBrNi+lgt3hf/EydXTZ2Ajaq1+nt36
         Qp1OA5xnlavdYdPNTEhXNEJOO0/UPIDAKdJtgK30J+f5mEi5hhl4mUeMS5BDtjA6Eb34
         i00A==
X-Forwarded-Encrypted: i=2; AJvYcCUVWkZsCf0lDMoVeYX92JSDXutuBEXWt64JVXetAgSxwJ0lpQ3tkD07oW1ha4yBveHkJvXVAQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx/ezLUTuDerYinrvnaTnnnbPvZetWkOfNiWd5w65NrnxbFB5Pl
	fzP6bYsCWMcDj/VaEpa0xLQMXS6MDHRNlKs0fUf9myYALKANC3B7
X-Google-Smtp-Source: AGHT+IFhpUKeBkZu7CCwrermNg8Xga9zZpyahxOYIlPSYmohThbMZEIZmecgKErxPnG19oXjHyYfyQ==
X-Received: by 2002:a5d:47a4:0:b0:390:f688:8ce5 with SMTP id ffacd0b85a97d-390f6888dbfmr11655780f8f.8.1741080328178;
        Tue, 04 Mar 2025 01:25:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGVqi1HNXycWoDyv1q0gwdPC6Y0I5xETyskV8dxQxjc7A==
Received: by 2002:adf:9dc6:0:b0:391:65c:1aff with SMTP id ffacd0b85a97d-391065c1c97ls906506f8f.2.-pod-prod-04-eu;
 Tue, 04 Mar 2025 01:25:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVRlJL0bTEOtLaksRH2sFUbDARdo6Xdj7i9zXKH54m5Cp6T+slWDaY1n2W05MITGzRrqQb+YJjByDU=@googlegroups.com
X-Received: by 2002:a5d:64cf:0:b0:38f:3224:6615 with SMTP id ffacd0b85a97d-390ec7caa2cmr12772384f8f.7.1741080325649;
        Tue, 04 Mar 2025 01:25:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080325; cv=none;
        d=google.com; s=arc-20240605;
        b=YpdAyyo7mA/vrhTS1ma3f1rO4UkCv08ns+u1T5eRiXR3C3Axl5ClaEXeXLeqXxTqBK
         hI8jAne8YECx4F/vkMgfA6rKC2+KvkffpY3IEd+YKG8OFEIca/WdLzLlxsZBdSnGdMJT
         h3PDI6q4aOfvewQKTsq40S7w3+BlPlWxnqsTUwylYDUUJw7MyebgIbRSUncUWy1UIM1k
         +Z/WH8KhfLscK6FaCVaYWVL4ySkVrsFngy4Kesyhu71gI0r7AtqRznuncLrRqVlhnz5N
         l0hlIAQq159UAbdiqBeeyo4ERTsUFG04G1EAKwcFPPtkOzd8Qc8eyO3japUn+u6MY/li
         /3zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=07Wov0mqGRdlTFI57GwZAG7K2eg+AiDKRE973TUpU6Y=;
        fh=Tmf7sMOc+LWadV2/ia7F+wpNxILCCoPNFgTW7BVvWOc=;
        b=CJ1IHY5ZDjGPwDHpSb05jhH/7PfZ+dTyMAi9bgNOkd7enJCdudo8lI0jGD3XoxA16p
         3krZS9ZQhDlgCjhg92KJj6Hr3gmD7H3VVPpwt8rD76jG/XXmT1A/MnETKXt+K+5vcJ91
         8krN2hut5vOo4eIfx2bgX/uCgIHWxFqAcP/sp4E68AA0u+419o5GMGwe8OI7vKRDst7X
         Azrdyya7Ef268PFIZ6kJVdSJFiuPfWB0n6KJT07f/ElAJGKhHShYsEhLZKFs3Q/+Plld
         GfdUWByR7wD+i14FgP+j8jmepkeRgfCvuw15+3ITBn87xxz29YDwu2y24VW24NJgiRHK
         pilQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cv1gwc17;
       spf=pass (google.com: domain of 3bcfgzwukcfiyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3BcfGZwUKCfIYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390e482d56csi439441f8f.8.2025.03.04.01.25.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:25:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bcfgzwukcfiyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5e4b6eba254so6168811a12.3
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:25:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU8t89CLC48EHkH9jdKzBIQUMRnfdBW5LiOE/9Uh7aEtWKvQc9c60YtsCBIO6j33gzf98oKBWKsoUM=@googlegroups.com
X-Received: from ejcvg16.prod.google.com ([2002:a17:907:d310:b0:abf:62a3:633f])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:906:2801:b0:abf:4647:a8cb
 with SMTP id a640c23a62f3a-abf4647a9d8mr1347716166b.44.1741080325134; Tue, 04
 Mar 2025 01:25:25 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:05 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-7-elver@google.com>
Subject: [PATCH v2 06/34] cleanup: Basic compatibility with capability analysis
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
 header.i=@google.com header.s=20230601 header.b=cv1gwc17;       spf=pass
 (google.com: domain of 3bcfgzwukcfiyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3BcfGZwUKCfIYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
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

Due to the scoped cleanup helpers used for lock guards wrapping
acquire/release around their own constructors/destructors that store
pointers to the passed locks in a separate struct, we currently cannot
accurately annotate *destructors* which lock was released. While it's
possible to annotate the constructor to say which lock was acquired,
that alone would result in false positives claiming the lock was not
released on function return.

Instead, to avoid false positives, we can claim that the constructor
"asserts" that the taken lock is held. This will ensure we can still
benefit from the analysis where scoped guards are used to protect access
to guarded variables, while avoiding false positives. The only downside
are false negatives where we might accidentally lock the same lock
again:

	raw_spin_lock(&my_lock);
	...
	guard(raw_spinlock)(&my_lock);  // no warning

Arguably, lockdep will immediately catch issues like this.

While Clang's analysis supports scoped guards in C++ [1], there's no way
to apply this to C right now. Better support for Linux's scoped guard
design could be added in future if deemed critical.

[1] https://clang.llvm.org/docs/ThreadSafetyAnalysis.html#scoped-capability

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/cleanup.h | 14 ++++++++++----
 1 file changed, 10 insertions(+), 4 deletions(-)

diff --git a/include/linux/cleanup.h b/include/linux/cleanup.h
index ec00e3f7af2b..93a166549add 100644
--- a/include/linux/cleanup.h
+++ b/include/linux/cleanup.h
@@ -223,7 +223,7 @@ const volatile void * __must_check_fn(const volatile void *val)
  *	@exit is an expression using '_T' -- similar to FREE above.
  *	@init is an expression in @init_args resulting in @type
  *
- * EXTEND_CLASS(name, ext, init, init_args...):
+ * EXTEND_CLASS(name, ext, ctor_attrs, init, init_args...):
  *	extends class @name to @name@ext with the new constructor
  *
  * CLASS(name, var)(args...):
@@ -243,15 +243,18 @@ const volatile void * __must_check_fn(const volatile void *val)
 #define DEFINE_CLASS(_name, _type, _exit, _init, _init_args...)		\
 typedef _type class_##_name##_t;					\
 static inline void class_##_name##_destructor(_type *p)			\
+	__no_capability_analysis					\
 { _type _T = *p; _exit; }						\
 static inline _type class_##_name##_constructor(_init_args)		\
+	__no_capability_analysis					\
 { _type t = _init; return t; }
 
-#define EXTEND_CLASS(_name, ext, _init, _init_args...)			\
+#define EXTEND_CLASS(_name, ext, ctor_attrs, _init, _init_args...)		\
 typedef class_##_name##_t class_##_name##ext##_t;			\
 static inline void class_##_name##ext##_destructor(class_##_name##_t *p)\
 { class_##_name##_destructor(p); }					\
 static inline class_##_name##_t class_##_name##ext##_constructor(_init_args) \
+	__no_capability_analysis ctor_attrs					\
 { class_##_name##_t t = _init; return t; }
 
 #define CLASS(_name, var)						\
@@ -299,7 +302,7 @@ static __maybe_unused const bool class_##_name##_is_conditional = _is_cond
 
 #define DEFINE_GUARD_COND(_name, _ext, _condlock) \
 	__DEFINE_CLASS_IS_CONDITIONAL(_name##_ext, true); \
-	EXTEND_CLASS(_name, _ext, \
+	EXTEND_CLASS(_name, _ext,, \
 		     ({ void *_t = _T; if (_T && !(_condlock)) _t = NULL; _t; }), \
 		     class_##_name##_t _T) \
 	static inline void * class_##_name##_ext##_lock_ptr(class_##_name##_t *_T) \
@@ -371,6 +374,7 @@ typedef struct {							\
 } class_##_name##_t;							\
 									\
 static inline void class_##_name##_destructor(class_##_name##_t *_T)	\
+	__no_capability_analysis					\
 {									\
 	if (_T->lock) { _unlock; }					\
 }									\
@@ -383,6 +387,7 @@ static inline void *class_##_name##_lock_ptr(class_##_name##_t *_T)	\
 
 #define __DEFINE_LOCK_GUARD_1(_name, _type, _lock)			\
 static inline class_##_name##_t class_##_name##_constructor(_type *l)	\
+	__no_capability_analysis __asserts_cap(l)			\
 {									\
 	class_##_name##_t _t = { .lock = l }, *_T = &_t;		\
 	_lock;								\
@@ -391,6 +396,7 @@ static inline class_##_name##_t class_##_name##_constructor(_type *l)	\
 
 #define __DEFINE_LOCK_GUARD_0(_name, _lock)				\
 static inline class_##_name##_t class_##_name##_constructor(void)	\
+	__no_capability_analysis					\
 {									\
 	class_##_name##_t _t = { .lock = (void*)1 },			\
 			 *_T __maybe_unused = &_t;			\
@@ -410,7 +416,7 @@ __DEFINE_LOCK_GUARD_0(_name, _lock)
 
 #define DEFINE_LOCK_GUARD_1_COND(_name, _ext, _condlock)		\
 	__DEFINE_CLASS_IS_CONDITIONAL(_name##_ext, true);		\
-	EXTEND_CLASS(_name, _ext,					\
+	EXTEND_CLASS(_name, _ext, __asserts_cap(l),			\
 		     ({ class_##_name##_t _t = { .lock = l }, *_T = &_t;\
 		        if (_T->lock && !(_condlock)) _T->lock = NULL;	\
 			_t; }),						\
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-7-elver%40google.com.
