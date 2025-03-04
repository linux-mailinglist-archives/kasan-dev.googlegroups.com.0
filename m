Return-Path: <kasan-dev+bncBDBK55H2UQKRBRHQTO7AMGQE7HZQR7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 57AD3A4DE76
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 13:55:34 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-43bca561111sf5566535e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 04:55:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741092934; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mn0U/y0SMzk39M7I7BQq4DNTkmZPeDJUGxXPIYw7ZjuhKEnvwLdd9dbPFn3zJXVSXB
         7h4HMHcLskf/C+6Tl0kNCB3F8TRxetYt9OpZMeC6S6IkwtMUYDnJkNCrTQ1WiPqPK7lI
         3b3X3yi1FdglC99M7B0bwFzbGKaN/jn7qVXfPD6O57RtbtpwsWIu85fm+btsbB7zFgPD
         U471NjL4w1XUFCadV6ud/keaYXzqIkNPs/Z4+KZwtfqMvw2DXhlnpHazryZfYwb9LgBH
         TznyV8/Y63VQ5WOAraOtsoOL1XC4oOruvEfPGYJzUR/nqrcT+RcHxtk4LmWPloWdhxmQ
         fJcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wOqyGhLxXV5K4XAY+T/4TUhHoHXUtFguxNLT/rEHZpk=;
        fh=1Nz86+JUNMaZ4rk4ZOXOpCULYQc+kVc7s3rwujTbaKI=;
        b=KCfQ14LTMApZF+77EP/LZbWBLgqpUb3j/ybUy8cPH8KUB4WpSa20/8USJvpNIYncic
         jgdlAlWz/62StfFWJWRPHHSEpRWVar+HdSmKm8V44bdRm3Rd2ZHFFHoFVmfofdb3Zx3a
         K9aJpsdSehmFLEyt4/EaNnE/jkAi301ucoyJs4qYR6mOJA1JsaXmTMY1ajI5WosUkWH8
         bmVnkLnC6k1geSOwedEf4R65dr1OrhMFIaX5btss0B98g6lgSR0AKgy9D6rYH1Ydqh9a
         pcRH0NEB9xueRtIas0ORdaWK+a6UAbRWXADIbKracwIMtspWjMJ2w0wKxkZAFl9k8YKk
         4iHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=NRcGU9tD;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741092934; x=1741697734; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wOqyGhLxXV5K4XAY+T/4TUhHoHXUtFguxNLT/rEHZpk=;
        b=DMwO/vLSJwX7aX5KGjUSycWsHpHJpVO31QY6bAn4OJj1K//+Jkfh8pMInolvT6eJz9
         0WzDdRREsNJYlYWMkVGpY6yXn2MImK9WtfwruyTj9sVr4hwdJbRLQiTY/zycmvz42Ju/
         y8q7idrVcFRsbVf/WlrJUgPTNJ9z9v/sEJ3Y69uDX+N8Z2507f718v4xtBQwjF2mmJLu
         qRNmp3CYuRU9VDz2EohxMDxlHm/1iEFcViUt7nNNEcCTdLCf9z47XhoJqvdQTUGpdinW
         lXiZlLWWdacFYGh/Mp7n5ck3muBIShb6Skh3NJym5SpOc0/kgqtlJicBW2twFCKmpDAi
         nSCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741092934; x=1741697734;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wOqyGhLxXV5K4XAY+T/4TUhHoHXUtFguxNLT/rEHZpk=;
        b=ugTKonCkpCevmSYESVUv8yLny+JiYxQ+f3yiHHuBiYKo2rPmLAUP3Nq5RLzosCK9y0
         KnGYczFBk9GTMSy/yBF8xk0cf3NzYVk6MlQBTfHa7y3xeTPTtOU87DpEkJVDjJQehI4Y
         pTT0RbvwITvfDYn6a/sTd0NF2yOg2kWR33m9ItDnjgOckrHqYygVHKyzEB8QVa1RE+bf
         AdZ3fLn3ZH/4NL5h4lRwyjQVwlpMIKLcfGU2SOf/rs4n8u9c+4x8agO2bnGW9YVHT/Pk
         sSVbUcMfVmdPdmSmC1Q93cblzW9WNNRhVHi8SAuL0iVxihl6RG5JT5N5BF3eDG6RGCZo
         I1Vg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXF4H3U1KnemcBgfSMYbomBin+bNNqv/+Ne6M5iGhxr6BZr/415QIPNPT6gGTurrJRfpooGiw==@lfdr.de
X-Gm-Message-State: AOJu0YxE2wE5HbHLo5RyPyV2Zh4R4Gswkmw4XpVGgpR82HuJ14pbye1U
	Nscl/FupFT1JkiM2WKmd43CTqKint2LLd/ctoXZgAZ3xq06WBQ7K
X-Google-Smtp-Source: AGHT+IFKFOSX77wPgsLM8LCQD5UIPXBHBoVdxREUt/+OXvVRdr4EcbCLDG+MNmvFLsccvZn+gGHUkw==
X-Received: by 2002:a05:600c:3b18:b0:43b:caac:5934 with SMTP id 5b1f17b1804b1-43bcaac5c6emr30045005e9.10.1741092933210;
        Tue, 04 Mar 2025 04:55:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVE98mQuNCHy1ic7x+oWD9P9J9+j47MXCkP8+XMeN95FWA==
Received: by 2002:a05:6000:400a:b0:38e:f923:e191 with SMTP id
 ffacd0b85a97d-390e11e5a98ls3240506f8f.0.-pod-prod-08-eu; Tue, 04 Mar 2025
 04:55:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVE/XRnhRxg0xST9rbuw5qYQg9UN9nj7q6CO+2s1nxAWRUNRfjYyeuDJF/noLmCGGAWExlCtXgtuwQ=@googlegroups.com
X-Received: by 2002:a05:6000:1f88:b0:391:34:4fa9 with SMTP id ffacd0b85a97d-391003450d4mr8908842f8f.0.1741092930650;
        Tue, 04 Mar 2025 04:55:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741092930; cv=none;
        d=google.com; s=arc-20240605;
        b=DOH1GbtbS/VsVaCdSBuxbV2O8PFVbFSE8REE3nSEdQs62ZoJ+0lwzVqrevfkAIjGgT
         1O7jjkK4cxjd6iF8e0VhlczVUuS9ik7FHobpeayESVNpsAN0spihF9vNSKYG5MLeP1io
         VpWzIgrcsGlVuB/UY9TprY4luqNAfRRtjwJxtzD+dQyJzTU3hTTgUedLx570tZS3r9P9
         vXJKYzK6ihYXNJOk31iKkFvrmLgjXvYPKj+4jc0heq8GpFtLFVrIq5LlqnnqSrlRWbcR
         LZEuRBHVbzuQ3I68hgWPRYdgyGat0Y1zu2VlihAcgtO+v4y+gm2KmOF1hQeWxIya2BGp
         d3uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZOOYa20v84BFJHD1ayfwn3RBGuxwB4d68Xr0Wae/NAo=;
        fh=7TaygT2PzvUByhK1cv83Q8e6MDKw7N3itZdt4LeniwY=;
        b=CWQsI+jbwiY4xs0JJKH16P2m3hWKoBkZVfIJUKC5Pxu++QC7VRdOm+tPDDhU2JHAwQ
         bndePtRIiBJYHL+fN37gCYxtpmrf5G0TfMUpeQhS+YJ60UOWPrV/pzc9Jts3nyv+RGZM
         /91Ptu2uhffTDKownyXirbLfj/BEgmcUNBnXB7aKj0WyZM9OTPxeiFpL2cPhzl6K0kG6
         ogi6KoQpLhtvlMeby25SNdUA1u9hEept7QYX8/xc12rmZQPYNXkJS+52xibKaq/R/6d3
         tH6yEUkNXgb3UiLu86iujPN8YZW+p12yhBUUQqScwhvG3n+S7Qeq7yi9jm9lfKJRRuQ6
         2A3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=NRcGU9tD;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390e47e9283si442169f8f.3.2025.03.04.04.55.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Mar 2025 04:55:30 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1tpRnp-000000002P6-1xXA;
	Tue, 04 Mar 2025 12:55:17 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id B29BB30057E; Tue,  4 Mar 2025 13:55:16 +0100 (CET)
Date: Tue, 4 Mar 2025 13:55:16 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: "David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
	Jiri Slaby <jirislaby@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-serial@vger.kernel.org
Subject: Re: [PATCH v2 06/34] cleanup: Basic compatibility with capability
 analysis
Message-ID: <20250304125516.GF11590@noisy.programming.kicks-ass.net>
References: <20250304092417.2873893-1-elver@google.com>
 <20250304092417.2873893-7-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250304092417.2873893-7-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=NRcGU9tD;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Tue, Mar 04, 2025 at 10:21:05AM +0100, Marco Elver wrote:
> Due to the scoped cleanup helpers used for lock guards wrapping
> acquire/release around their own constructors/destructors that store
> pointers to the passed locks in a separate struct, we currently cannot
> accurately annotate *destructors* which lock was released. While it's
> possible to annotate the constructor to say which lock was acquired,
> that alone would result in false positives claiming the lock was not
> released on function return.
> 
> Instead, to avoid false positives, we can claim that the constructor
> "asserts" that the taken lock is held. This will ensure we can still
> benefit from the analysis where scoped guards are used to protect access
> to guarded variables, while avoiding false positives. The only downside
> are false negatives where we might accidentally lock the same lock
> again:
> 
> 	raw_spin_lock(&my_lock);
> 	...
> 	guard(raw_spinlock)(&my_lock);  // no warning
> 
> Arguably, lockdep will immediately catch issues like this.
> 
> While Clang's analysis supports scoped guards in C++ [1], there's no way
> to apply this to C right now. Better support for Linux's scoped guard
> design could be added in future if deemed critical.

Would definitely be nice to have.


> @@ -383,6 +387,7 @@ static inline void *class_##_name##_lock_ptr(class_##_name##_t *_T)	\
>  
>  #define __DEFINE_LOCK_GUARD_1(_name, _type, _lock)			\
>  static inline class_##_name##_t class_##_name##_constructor(_type *l)	\
> +	__no_capability_analysis __asserts_cap(l)			\
>  {									\
>  	class_##_name##_t _t = { .lock = l }, *_T = &_t;		\
>  	_lock;								\
> @@ -391,6 +396,7 @@ static inline class_##_name##_t class_##_name##_constructor(_type *l)	\
>  
>  #define __DEFINE_LOCK_GUARD_0(_name, _lock)				\
>  static inline class_##_name##_t class_##_name##_constructor(void)	\
> +	__no_capability_analysis					\

Does this not need __asserts_cal(_lock) or somesuch?

GUARD_0 is the one used for RCU and preempt, rather sad if it doesn't
have annotations at all.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304125516.GF11590%40noisy.programming.kicks-ass.net.
