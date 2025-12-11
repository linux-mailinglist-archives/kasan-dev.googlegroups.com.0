Return-Path: <kasan-dev+bncBDBK55H2UQKRBY7G5LEQMGQEMILU67A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B316CB5BE3
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 13:04:52 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-477a11d9e67sf5155105e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 04:04:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765454692; cv=pass;
        d=google.com; s=arc-20240605;
        b=AJTM3imlBmMaJBX/DjDeVEv40M48p8LGe9O+3S8ehuQ8dHepxPmppAoRrnTRdEiIPt
         TnFajb4KhdEi+ohwbWDMKGjcSBYZYhBgiWwsYDW53GX3g8YI2gPb3vh6+vw8scMsPpXa
         HB2c8cjHM5VQ1zOdwtiDrvNb6Vf3QB0A+B1g8fuswJ7Efgh9bpXhGCEbXWrFKMRNfYv2
         TvXCxDwiuC9wfOHpv57ZkWbQFhmfNof0tKhANSb9Etq0YBkniCysOXfx47ZXRWLlDWXi
         Y1ZvzSUYwV2U6y37CTRBFKV11lwTbD8aRGuXsRkfyaSRSjB++GxhAMi5FqRepe/Lt5mt
         kkyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=WiXXeRmuHoaqhrO7y8u06xOkHDqBWtNoDUPk4ZthX+4=;
        fh=7AM7Hpc5g16HdhOnoDo4DCU0hOLppdnjfYH8p34r54Q=;
        b=gkkHrSbl1FYlB8uBZE2d+ha45tiFCHZZ6cHUsO3tVG4dBlK8w7m5HH0OPE/VWIbVaW
         OydbfNqcxl1IlswFquJeQpvBiOmqggleGtALxRPefjO/ZKIIxw11aV9CoqKLF8HntMZY
         qDGvuIh9QJzs8FJPASlNspDPlaAy/nqtEAM2fewbl5ndggPaYhdFijp4zDvt5fc/9tI9
         LVrUJR6fawcu3jyhtoVqdhGjlCbklvc5d+/QVAfw52hENM2fBLT3snd388TVVNfMeylE
         XB+bgi11xQPh+N4aM2wl3WxoqDJsfkSUctpDFSjZlrnooA5l1UlHpVArfrbIWatDrbqT
         h4BQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Cm3yzuQq;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765454692; x=1766059492; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WiXXeRmuHoaqhrO7y8u06xOkHDqBWtNoDUPk4ZthX+4=;
        b=FpAg+olyeC/mN40wodswSvMM9t8c995rSCwZBMhCiR/aqqPN8OJy5BAF3X4Uln3o1N
         1JzCWZfrFMx4uZGkBHREmKc8vSKHvdxgo4rduHhv3jmf/QZszhQVqPhJ8qnyQBhKg/sr
         EJAIUTZLEwRLP3dL5k5QUaOpu4cD67VxugXtJ7IXPDGMQticZOgLYdJ8KdbJWsVWcxlA
         5JlPItaqzdOHDm2+9fcogQVkMabCpIHKaqj3aUvG91nXCPG6N0wmXhFwmKxlocUoy2mK
         zA55yT83e7ckRPshTShE/endAoO1YMG1e7OuJ2pn+gi18IRVcjIu2v4Hq1PfI2bFumqK
         vHQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765454692; x=1766059492;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WiXXeRmuHoaqhrO7y8u06xOkHDqBWtNoDUPk4ZthX+4=;
        b=s7bgg/c9LAObhZI+6QhO+5g9MDcZEzLN2raXiIyDofbI2FiEtq59LkAGvXHSCbUjKx
         vWgn/HEM+nk5YdFWUZ7UcpymTBCsxPd1fevrw4ImVBWnttgv4EQdIQC027iH3S26B6NX
         kWs+aTxgIgcuC9eMv0eo8JUJta6KN7jaNdz5RjC6tqaiT0H+AVCFxb+RqVboR4LJAjol
         fVWrxVuAckmABaV+dUUcySt0DTv08iZ2EYgE6cB1LIlvpDc5cXdWrAxHyZf3HsC+tky2
         Q0UGbuSBe2li2HUt3qQ4Yy6J5uFN+9Kcu6AETNFVlgbV5AtlKrjKPXO899ZOWlM2A956
         FnWw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUpL9fm5cRJQm6AFF3+shSv7W1JsvK8Tqzeq4yaST336uM/nyIJywpWMa1YyRTvPdkF66++gA==@lfdr.de
X-Gm-Message-State: AOJu0YzmaY4OVXtzrsYtDElusBchMh28aZuiTJSi2vzpy0zn/bwu4Pps
	opVMeGCuSmwhpt4woFFnxGgB5AvvBF+sLRNRne4f6cTcjALsHnz0CC1I
X-Google-Smtp-Source: AGHT+IHlfvrkO/J1hrUN4IH2C2XpK97vY/o4FJKH6BXggRrDSF2qtPKo9oIiviGL3toledVpPqlj+A==
X-Received: by 2002:a05:600c:190e:b0:47a:7fd0:9f01 with SMTP id 5b1f17b1804b1-47a8380641fmr62309715e9.16.1765454691849;
        Thu, 11 Dec 2025 04:04:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZOb5BufavqUKWrq1oKuA1kFCVQhQ0euevVkDXx1kN+/w=="
Received: by 2002:a05:600c:1f85:b0:477:980b:bafe with SMTP id
 5b1f17b1804b1-47a889aa13els4244815e9.1.-pod-prod-04-eu; Thu, 11 Dec 2025
 04:04:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWv8DD4SW51812lYAkgzIjGSZ40P1cLCSLGYF66I+O522Df/M5pyNBfVIySrQOFT+DEIuiYrNTubYY=@googlegroups.com
X-Received: by 2002:a05:600c:1f8c:b0:475:de14:db1e with SMTP id 5b1f17b1804b1-47a8383c88fmr54414845e9.24.1765454688933;
        Thu, 11 Dec 2025 04:04:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765454688; cv=none;
        d=google.com; s=arc-20240605;
        b=CcEL6rY2ieO4aKI+fltYw50HK1qk2Q/ExspwGAVwRs22ZHwuROhSXx9SFvnPrlNdxe
         6uz4qe1HIYy0XTIVBzoU2XxpcQ6jp2zFS6by7IyzdbUahBiMENOm4MhDU/n+cZrY0BI+
         sjhrMdjh17QoSD1Hk6VykPifSAD+pSoDcbMH20p2O8RQLcRgQC+o/EVBpbq04BJdTM1h
         C67NIqN6vn73O+V0/Anaa2/9TGgJfsuHCi5RNi1Ur1TeHDoq3ivHLgHjsUTVm2rQQrkZ
         eooS0BiGpV3ugXg+T0bNZlIcFbvypXPSWKmM69XvffIqxtU8zuHSwOzC6GLLAGtn99ik
         EZHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=J5QYsGE2XyUV8dMJUaGHOZ/s846nES10yHj06SSwiHE=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=h7QNWzjIBNAzsuay19V2mydF+x1O6ln15qxejqQFy2p1tuk44VPg3Kh/xpHPw5orBI
         P0dRkaEhEMeW8IQZWQ5z/iXszAcMbWFdZ11oU3TrfAiPSWEfwMZrkIm565u+XprevnwO
         /Grmq3mKTBwbb9ntI8YzoUxHONVR0ndYXx2Yfna5wm3UUsrsK5xWBb9Fl/GR2KG3HQ+J
         CKa8L/4s1ImJIrDAKoXON81z3dqrt8tCd2990TNdzhnGwPGXTNHOz4APElM3PuCg5rJr
         5aYNlRfI0HbNQ/Uzpb9uixcAAIPpANRhQyBMxl5uWrxUeHL/Kk2oUAeeSnBr5kF/kQDD
         acvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Cm3yzuQq;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42fa8b980e8si49348f8f.10.2025.12.11.04.04.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Dec 2025 04:04:48 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 2001-1c00-8d85-5700-266e-96ff-fe07-7dcc.cable.dynamic.v6.ziggo.nl ([2001:1c00:8d85:5700:266e:96ff:fe07:7dcc] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vTfPW-0000000ECYb-0fah;
	Thu, 11 Dec 2025 12:04:42 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 803F130301A; Thu, 11 Dec 2025 13:04:41 +0100 (CET)
Date: Thu, 11 Dec 2025 13:04:41 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Johannes Berg <johannes.berg@intel.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, linux-wireless@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org
Subject: Re: [PATCH v4 02/35] compiler-context-analysis: Add infrastructure
 for Context Analysis with Clang
Message-ID: <20251211120441.GG3911114@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120145835.3833031-4-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251120145835.3833031-4-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Cm3yzuQq;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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

On Thu, Nov 20, 2025 at 03:49:04PM +0100, Marco Elver wrote:

> +/**
> + * context_guard_struct() - declare or define a context guard struct
> + * @name: struct name
> + *
> + * Helper to declare or define a struct type that is also a context guard.
> + *
> + * .. code-block:: c
> + *
> + *	context_guard_struct(my_handle) {
> + *		int foo;
> + *		long bar;
> + *	};
> + *
> + *	struct some_state {
> + *		...
> + *	};
> + *	// ... declared elsewhere ...
> + *	context_guard_struct(some_state);
> + *
> + * Note: The implementation defines several helper functions that can acquire
> + * and release the context guard.
> + */
> +# define context_guard_struct(name, ...)								\
> +	struct __ctx_guard_type(name) __VA_ARGS__ name;							\
> +	static __always_inline void __acquire_ctx_guard(const struct name *var)				\
> +		__attribute__((overloadable)) __no_context_analysis __acquires_ctx_guard(var) { }	\
> +	static __always_inline void __acquire_shared_ctx_guard(const struct name *var)			\
> +		__attribute__((overloadable)) __no_context_analysis __acquires_shared_ctx_guard(var) { } \
> +	static __always_inline bool __try_acquire_ctx_guard(const struct name *var, bool ret)		\
> +		__attribute__((overloadable)) __no_context_analysis __try_acquires_ctx_guard(1, var)	\
> +	{ return ret; }											\
> +	static __always_inline bool __try_acquire_shared_ctx_guard(const struct name *var, bool ret)	\
> +		__attribute__((overloadable)) __no_context_analysis __try_acquires_shared_ctx_guard(1, var) \
> +	{ return ret; }											\
> +	static __always_inline void __release_ctx_guard(const struct name *var)				\
> +		__attribute__((overloadable)) __no_context_analysis __releases_ctx_guard(var) { }	\
> +	static __always_inline void __release_shared_ctx_guard(const struct name *var)			\
> +		__attribute__((overloadable)) __no_context_analysis __releases_shared_ctx_guard(var) { } \
> +	static __always_inline void __assume_ctx_guard(const struct name *var)				\
> +		__attribute__((overloadable)) __assumes_ctx_guard(var) { }				\
> +	static __always_inline void __assume_shared_ctx_guard(const struct name *var)			\
> +		__attribute__((overloadable)) __assumes_shared_ctx_guard(var) { }			\
> +	struct name

-typedef struct {
+context_guard_struct(rwlock) {
        struct rwbase_rt        rwbase;
        atomic_t                readers;
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
        struct lockdep_map      dep_map;
 #endif
-} rwlock_t;
+};
+typedef struct rwlock rwlock_t;


I must say I find the 'guard' naming here somewhat confusing. This is
not a guard, but an actual lock type.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251211120441.GG3911114%40noisy.programming.kicks-ass.net.
