Return-Path: <kasan-dev+bncBDBK55H2UQKRBUFYTS7AMGQENUNOKPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 98FA5A4E339
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 16:29:22 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-43bcddbe698sf2891935e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 07:29:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741102162; cv=pass;
        d=google.com; s=arc-20240605;
        b=QQz2wyLMDSOsdr0pUMdG9hIJwaf+mKZ27tR9l/hI+tgHkHPJVL0iXR2Z1KyA9yYJET
         TaUkEBTiYz59jgCn2RG7K6gLZOhL5L9CYYbBmo8PBEyT2RR36T7STeQb0lEnU4X71acU
         KkfbfFPGapXQNcMQzLBZAvQK2JpZT6Emyjd7QKnIyrwwCzYg2n4jzoLUJu4oSe+rCth9
         OXxwG4gEC6f0NXfSGj8XN8KzI1YYOaB5C39LcFPOnkNc7cEkjpPfJiZG9Tj+mE05xIj5
         z3l4iMQPbyu4MYYW9Ng4s1YyaEMhHsyAUGskXZJ0AjwMZLOnw92eriPs6X79FnW7TOfw
         DDVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=S/ajiYP7AvPAhCHMq1FWFSEqtsDQm1AFeGOrVWBs8q8=;
        fh=8n6pI553JrIDjK+Vd10oJvMGHGFMNTrC0QG7fHYvYCk=;
        b=MU3t6hY1lw/JugAq/qooA7xlNe3fEqGa+UC6OdhYTOIaQqhAMkp4ZuWN1RsMIcedv1
         Rlv3YHXIJBz4GdL13uvNAU+95S5Zk8wJkVi98BKHJLm/5T+YgVVtNYwsBqV89y+IX7oz
         Vlvq41Z9t58iW+hpJQ3ZBOiduhGi2eORl7o/qil/psA3eKDqTDcsIWwxUqbUpF9jUGD7
         /44FVtlPpAwT90lA9qLYmK6FPRqyHHwzIQduOTOs3edyIKZO0D6L2Xw77K8tXDV1TrjY
         dqqQ2iG4pW1CUcudNUAsfA8dhsXkdWZ9RfCy/s/eYvPv4f11haIL1p//BuzcLjiEMy7n
         K+LA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=W1W5CazB;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741102162; x=1741706962; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=S/ajiYP7AvPAhCHMq1FWFSEqtsDQm1AFeGOrVWBs8q8=;
        b=MUoGhuwuVHvX49ZKNdrjjDs6fgGkZr6aZqNaw6ttqoBiXGlUwdymuu8axJSVm8vVYS
         sa+gkxGFsAZdqMoh4+AthH4SlzO9mKHV/uQVk91d+D9kuMj9b4EpG7rODcNv5vbcShVq
         B3F7nKg0e4Qxjnill7Bz90JzV9C3HJdbuNnPB1VPQjqGI7zrivrUwrz7F9z47WfbSqm6
         bEJWgDBVfZ5UcJ0Ox/pB8J8rti51MGiwnETqOf1pO6NsAZxp8yZGYC1UlbQ4axjUMzGO
         KeE2TxPXxqgSCgzwW7qfadkIaoQYMAasrSVGfjIZVaxvUmgoEHbATEaSTBoXzJn+QPK5
         8APg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741102162; x=1741706962;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=S/ajiYP7AvPAhCHMq1FWFSEqtsDQm1AFeGOrVWBs8q8=;
        b=vWtBBf1n6DZMkvM8Tbr4xWyn7eOu1lhc0iz5Gp/HtdXzJvpImqeUrk8lKF+csLO3K3
         iehmtP/RLgFZOHe4xdMFu2rEPqsKUFYH2XhcZoTWHncRNJ98+4A+D5x5XerMj9h5zpr0
         Ntwb73BUYALxISJbx+lq0N8nmdgTulAqJwpysaDX5HqudQ8DjQbBcNieGXeBJQEU7V7K
         HLwG9jO0xN0Xn7ozgG4FjTSWGWyZkssR/nvhU1AV5FtwL1VxDoIlSYAENaAc9POTnjqm
         yrv6Xbx69QtFnQs/gM6JZ7GmX6Y7bf7ejkZ7CG0lzrWXCEzhq564v4grTMLe2t2Hcl9/
         DRZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVu+PyFNC/8TNbgfIeKhU4bebiEOpun1OaH6kpkRbiCsY7tElfYB/uAL/gpxifnORctLHgOfA==@lfdr.de
X-Gm-Message-State: AOJu0Yz914X3rzCrdEMYwdXcGy9YEmXe/08wLBPma/f8QGONaiFVtwXB
	mulujdvNLszRkYg9/LsHxR8A68HBWxa0AyUHFOnwuaY1b6gxL/u/
X-Google-Smtp-Source: AGHT+IEc5V1pAcdLAICTblU/21MkkUnItnBsA8G2XNQKnp+gj84F1cX3WIMiS1bdckgMrryvDnDxiQ==
X-Received: by 2002:a05:600c:5248:b0:439:a093:fffe with SMTP id 5b1f17b1804b1-43ba66e6de9mr151661665e9.7.1741102161163;
        Tue, 04 Mar 2025 07:29:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFq7x656qoGahiZcM0+QBZs0ue5jnKcDv1dYeaF+iO5Aw==
Received: by 2002:a05:600c:3d0a:b0:43b:c596:e809 with SMTP id
 5b1f17b1804b1-43bc596ec8dls8492435e9.1.-pod-prod-01-eu; Tue, 04 Mar 2025
 07:29:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUoUCRvmjCeDQNyoCdRJMcq0XiIwCu+hAlm1Nso6qWeDg7ehvb9fqyEp34yYFompG9zHPz8DXbvaIM=@googlegroups.com
X-Received: by 2002:a05:600c:56d6:b0:43b:b756:f0a9 with SMTP id 5b1f17b1804b1-43bb756f1e3mr91027805e9.11.1741102158589;
        Tue, 04 Mar 2025 07:29:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741102158; cv=none;
        d=google.com; s=arc-20240605;
        b=XMjcttd1p4SYUMH3oSQf9Jb0UIKz9ctNOyBT5ZXfVbcZCGce79RCS84kciodB3rFed
         ffZ1sVPFQRQimhInqSSUMD24m/OaW5CDfPtLEEhvYAq/SY+wmyAcAtcMylDKtlJePhWa
         +LoCvg3URZ+8NqnHX3tSEAR22uklzhf1cImnMySfEtSnYkeTyymg8bl+0AQDqUAzOybr
         ngElgXfqq05WoWCueAOuxzD8FouEra7wmq5FfuJUZnw7h+ltmmr+/6mt4tLrFYVyiCST
         g2gbRVZhG81Pyh5AsAhvFHW626Z+p0k/iSXET2uiahRYK9TK0TDHvZt87B4E7ndbhM8s
         GJ4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=EwH5tL2R1Nh04CIVB45yHJPEmwvHf497lkyWPZPvBAk=;
        fh=7TaygT2PzvUByhK1cv83Q8e6MDKw7N3itZdt4LeniwY=;
        b=WkbWxowXz/M1wfaYdyeIMkFNOmPjLbd0eTySHENF+rUKeW8vEyBxhjahpRZF+K1JYz
         7ak8nocgezkIqXLYloTSoCTPyfoSq/oXu0gK4erjVksvMyoP80E1fUYxQkHZY/OMIeQ8
         1Ez7D6CIWi9Dq2He7wrFSx0hQDPIjk185jpgqmHTdcmhscf3sWcPGCvQgOBo8HLTf2hX
         jY1gEgZyfedgZWSPeUWq91lQNIDCagJ+02BrW3QqezUpzPUqCW0fiDOUlY8Zycccy/QA
         CjZesO3pQw21yIWI8eht5flOoSs8cgBSl/pB9ygS+xcvXt/14hd3YxiGbdn7iOawYmBs
         BU4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=W1W5CazB;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43bbf2f59b3si1125655e9.0.2025.03.04.07.29.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Mar 2025 07:29:18 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1tpUCk-0000000048f-3L3R;
	Tue, 04 Mar 2025 15:29:11 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id D7DFC30049D; Tue,  4 Mar 2025 16:29:09 +0100 (CET)
Date: Tue, 4 Mar 2025 16:29:09 +0100
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
Subject: Re: [PATCH v2 02/34] compiler-capability-analysis: Add
 infrastructure for Clang's capability analysis
Message-ID: <20250304152909.GH11590@noisy.programming.kicks-ass.net>
References: <20250304092417.2873893-1-elver@google.com>
 <20250304092417.2873893-3-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250304092417.2873893-3-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=W1W5CazB;
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

On Tue, Mar 04, 2025 at 10:21:01AM +0100, Marco Elver wrote:

> +# define __asserts_cap(var)			__attribute__((assert_capability(var)))
> +# define __asserts_shared_cap(var)		__attribute__((assert_shared_capability(var)))

> +	static __always_inline void __assert_cap(const struct name *var)				\
> +		__attribute__((overloadable)) __asserts_cap(var) { }					\
> +	static __always_inline void __assert_shared_cap(const struct name *var)				\
> +		__attribute__((overloadable)) __asserts_shared_cap(var) { }				\

Since this does not in fact check -- that's __must_hold(), I would
suggest renaming these like s/assert/assume/.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304152909.GH11590%40noisy.programming.kicks-ass.net.
