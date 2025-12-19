Return-Path: <kasan-dev+bncBD3JNNMDTMEBBVFXS3FAMGQEQ6U4MBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 13C81CD1629
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 19:39:18 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-88233d526basf52643326d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 10:39:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766169556; cv=pass;
        d=google.com; s=arc-20240605;
        b=bScO/XjgZOYqzuF4jJY2VO8JOVwq7a81SwO9jojk18HKiO8AMX6gW1SfGtsnkzVaS+
         1Qth5M1Nrx5+uSvdfma40y5buiEbGDtDeEGKHWYwSaLtwMcxyxlB/kosmq1DSOwjdVRx
         dObOctyeF1mXw3pX/g1kyVJ5XRi0nKoXYUTkk0Ol9FWFschmOLwax0rvxunr7lfnLK+z
         AMesPhsbR12OaxbpMymQmTlROJ6Jr1cmzQ0N9ZFNL/YcC7fiLw1e70TgAE8genMMKcpw
         ILQoBcWUh8Q9+J2si7LcLiRAUEv6DTSsUPHv0M52rc7Y1N5SfIYrofgRNKKayKchc5wr
         jbng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=dtpkn4wHq4A4qk7o3DWSmEWYfRP+4J96puTfNJ1XcI0=;
        fh=YB/TyfACDRH6DR18SrJq3IHDH/v5QuGoiQTJN6LeYDA=;
        b=XG15oXgrBmGiwrwrilCEvnqEUzJ/6qwBAxBtRLQQ5e539wRqyGhK1NORy5bmBxVMU6
         5o/eMAVBoLEBB8NVdMKkRbgqsALZk/+nAPapYv2WhvZYdOxK8tprM6btKsG/gC2gS2GW
         hR8FeM9y7ndI4Bvv4iVqkdKny3cEk3IpT+BWXOq3n5eHujzeQM9v2SpTtntC5rzkBVKE
         8AGYKE5H+Mam2ozO3070wxIBNpcHpwivO4ZLKAV5c2TjQn18HwgnsfgNA3QeqdgAjdaJ
         jZumNXqZmQXQ6DkgghO+AQzSNeAZY1FI5L84s0n//2XgCVo7nXai5WY15EaJ//5DUEwz
         Pzmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=r7Yag90D;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766169556; x=1766774356; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dtpkn4wHq4A4qk7o3DWSmEWYfRP+4J96puTfNJ1XcI0=;
        b=IWOFUFSRpp25lVmkJgyLWNTJanQ0Xck4iQjuDWoPipX2SQVogst94L+iXRiqVBSPyb
         eIzrg6rXT9ED1XXWtfPC140N+tDfWGSAYF93H0tJFmJxX/U0yQosq4QO4l7XkgqAJrDF
         iFouqu1qO1WYsH8F+mAGQs0ZEDEZKgWu6eaKowXR+OOTVPlx17lJwwfmwKs1bN1ZOnM+
         tXmfWJxSVvpyjWgbO0WQeXO8e9y9lGQbdIOdfWPsrUhQ2dIkqNehtP+lg/Z1tplk2pB6
         LT44Lab7JheQbNgiE3pgUiD8gxDTsEAppoMCHsViyRV1ZVFg3Ih0sWFkRRf8hElzhCZo
         nUVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766169556; x=1766774356;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dtpkn4wHq4A4qk7o3DWSmEWYfRP+4J96puTfNJ1XcI0=;
        b=i3jx4sxgm1jJVjk81O/15Q2vHG0Dsh8aaymdWsq8S9h2l4z1yY/qUHuDHGor0yZ56A
         A4DL2VDeSKZAoMRqpDOFRGN4yJGmk+EF+PlLTGD6fGIDHk0H77Eg+4j1t9ol8drEwwLV
         5m8aTkO404QGO4cubui8HUG8/w1q4CCQpLXa89QDcz3hfkbwHbY1DDAVpmCe5VwIuhPn
         S7dkMwVPbx4O60pJVBZigsEUzkDjJtT2UdjaI93BLD4XQ6xD6E3XtLrCm5RjVbAyT2f5
         77vAR+NudnrN0jzS8bC01QUoDLNsKztC31ikcDgCQPAr+112hTNWJYpuhwtTpnl1ENhj
         I+Sw==
X-Forwarded-Encrypted: i=2; AJvYcCWe3Bd3EQTSmyQsaTeqcxgn+FMVGj2RC+ELFL0wGtPwBqXDbRVHwFx5hCwzWChSSfmLKlJuYw==@lfdr.de
X-Gm-Message-State: AOJu0Yyw0H17JNz9dju0Q085CGGv/0FstZkuuaVuC/J+tM2KmB5dx7fl
	96866527NtTrce7v6udMBg8kimjxh3c45fLmak6oOO2qKlS0vuONLUYg
X-Google-Smtp-Source: AGHT+IHc2dmPIhG0Q40MChz6b4Yq7qbgtrJeWaCwYKrakNQ/oH6Yga8ZjS3owryBlmtWUaiabYIDKQ==
X-Received: by 2002:a05:6214:124f:b0:88a:3b83:75c7 with SMTP id 6a1803df08f44-88d85caad49mr67078366d6.24.1766169556482;
        Fri, 19 Dec 2025 10:39:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWb2oDnG7YwuNAQLpXF5AE//GXGglc9UCx7tiabuM22jnA=="
Received: by 2002:a05:6214:519d:b0:882:4764:faad with SMTP id
 6a1803df08f44-8887c9609b8ls78549486d6.0.-pod-prod-06-us; Fri, 19 Dec 2025
 10:39:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWdZEQb3L8Dkqa8Ah+Y1BFp0pQgKeQcfFejMZjLe7g9eEmdonYWRdIHkfP21qibXd3bBDHO6gk4X0Q=@googlegroups.com
X-Received: by 2002:a05:620a:c51:b0:8b2:ea33:389d with SMTP id af79cd13be357-8c08f656641mr574590685a.4.1766169555466;
        Fri, 19 Dec 2025 10:39:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766169555; cv=none;
        d=google.com; s=arc-20240605;
        b=PDqvjapM7ZXBRWJe9FRdO/XnitkDay0Xn4R4WUgMriU/oXcfIY/wOWxjAZBA1T0c9p
         E4kEIxRrzbsxLjkpmzC6A8fiV3f5E3jSLTIENN1Pa4KpSvRj7Hu3lUEsLonO7bcjd7zB
         qyqXeS61EQ9b+9i5d2cWCTurH5YxAfqHo8abEMi7MVt3/pI/2YtVaOgv7D+/qb+mjleA
         tbfhDDRaMKe9zaK3GfptyvpLKzuNZ1lPhNEbn9CtRwppyS5D79vT7xjX+016sx42aPtS
         IqnZxKFObklwp0vtNVHQ9yRsWnOBEQYDx5HLw76RWXM34+dLxmq/hE9chRwIXAIfMezF
         MYnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=dgosp44VAu2P7aU4KenxOvJYazdnvtt9NxyqcaL3Tns=;
        fh=oscsWGUi8qXSCGbxjzWMCAbvCbb+T4RkBriBWr6Vjhk=;
        b=B8akKtm2Rl+d488RpbqBmfoemgoMV+f4an5RRks4eSfuH8H1IaMc7Nk9fVTOqSIGCm
         sbBURykxgHaP12U1oZsDnPy3un8qNIQMkrAtrvBTob9ActqhBcxVs1TkpYkCUwYMJxHS
         v2lbxfMT/ApSYM4jkP88tj/pxZyvRLBxxny1ek6pa1Jm9GfsGP/OBrpKwaTFBwfezkck
         tLX57z1kBkeKbRhHYKDoS+QiAIJLoMvrV+WRNeVy9jOysYW6bnQVBGJQo87318Ald4A+
         YHmJckMP5grioP3vDm2iXa/bKU3JjtceZtX0y7OBdZAwQOz3umBB2VapzkB0Pv717t/Q
         aEsg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=r7Yag90D;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 011.lax.mailroute.net (011.lax.mailroute.net. [199.89.1.14])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8c0972f762bsi12982885a.9.2025.12.19.10.39.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 10:39:15 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted sender) client-ip=199.89.1.14;
Received: from localhost (localhost [127.0.0.1])
	by 011.lax.mailroute.net (Postfix) with ESMTP id 4dXxC64LYVz1XM0pZ;
	Fri, 19 Dec 2025 18:39:14 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 011.lax.mailroute.net ([127.0.0.1])
 by localhost (011.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id lv8AghduxMyN; Fri, 19 Dec 2025 18:39:05 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 011.lax.mailroute.net (Postfix) with ESMTPSA id 4dXxBk4GZrz1XM6Jc;
	Fri, 19 Dec 2025 18:38:54 +0000 (UTC)
Message-ID: <97e832b7-04a9-49cb-973a-bf9870c21c2f@acm.org>
Date: Fri, 19 Dec 2025 10:38:53 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 02/36] compiler-context-analysis: Add infrastructure
 for Context Analysis with Clang
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
 Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>,
 Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
 Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>,
 Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
 Eric Dumazet <edumazet@google.com>, Frederic Weisbecker
 <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>,
 Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>,
 Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>,
 Josh Triplett <josh@joshtriplett.org>, Justin Stitt
 <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
 Kentaro Takeda <takedakn@nttdata.co.jp>,
 Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland
 <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
 kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org,
 linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-3-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20251219154418.3592607-3-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=r7Yag90D;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.1.14 as permitted
 sender) smtp.mailfrom=bvanassche@acm.org;       dmarc=pass (p=REJECT
 sp=QUARANTINE dis=NONE) header.from=acm.org
X-Original-From: Bart Van Assche <bvanassche@acm.org>
Reply-To: Bart Van Assche <bvanassche@acm.org>
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

On 12/19/25 7:39 AM, Marco Elver wrote:
> +#if defined(WARN_CONTEXT_ANALYSIS)
> +
> +/*
> + * These attributes define new context lock (Clang: capability) types.
> + * Internal only.
> + */

How can macros be "internal only" that are defined in a header file that
will be included by almost all kernel code? Please consider changing
"internal only" into something that is more clear, e.g. "should only be
used in the macro definitions in this header file".

> +/*
> + * The below are used to annotate code being checked. Internal only.
> + */

Same comment here about "internal only".

> +/**
> + * context_lock_struct() - declare or define a context lock struct
> + * @name: struct name
> + *
> + * Helper to declare or define a struct type that is also a context lock.
> + *
> + * .. code-block:: c
> + *
> + *	context_lock_struct(my_handle) {
> + *		int foo;
> + *		long bar;
> + *	};
> + *
> + *	struct some_state {
> + *		...
> + *	};
> + *	// ... declared elsewhere ...
> + *	context_lock_struct(some_state);
> + *
> + * Note: The implementation defines several helper functions that can acquire
> + * and release the context lock.
> + */
> +# define context_lock_struct(name, ...)									\
> +	struct __ctx_lock_type(name) __VA_ARGS__ name;							\
> +	static __always_inline void __acquire_ctx_lock(const struct name *var)				\
> +		__attribute__((overloadable)) __no_context_analysis __acquires_ctx_lock(var) { }	\
> +	static __always_inline void __acquire_shared_ctx_lock(const struct name *var)			\
> +		__attribute__((overloadable)) __no_context_analysis __acquires_shared_ctx_lock(var) { } \
> +	static __always_inline bool __try_acquire_ctx_lock(const struct name *var, bool ret)		\
> +		__attribute__((overloadable)) __no_context_analysis __try_acquires_ctx_lock(1, var)	\
> +	{ return ret; }											\
> +	static __always_inline bool __try_acquire_shared_ctx_lock(const struct name *var, bool ret)	\
> +		__attribute__((overloadable)) __no_context_analysis __try_acquires_shared_ctx_lock(1, var) \
> +	{ return ret; }											\
> +	static __always_inline void __release_ctx_lock(const struct name *var)				\
> +		__attribute__((overloadable)) __no_context_analysis __releases_ctx_lock(var) { }	\
> +	static __always_inline void __release_shared_ctx_lock(const struct name *var)			\
> +		__attribute__((overloadable)) __no_context_analysis __releases_shared_ctx_lock(var) { } \
> +	static __always_inline void __assume_ctx_lock(const struct name *var)				\
> +		__attribute__((overloadable)) __assumes_ctx_lock(var) { }				\
> +	static __always_inline void __assume_shared_ctx_lock(const struct name *var)			\
> +		__attribute__((overloadable)) __assumes_shared_ctx_lock(var) { }			\
> +	struct name

I'm concerned that the context_lock_struct() macro will make code harder
to read. Anyone who encounters the context_lock_struct() macro will have
to look up its definition to learn what it does. I propose to split this
macro into two macros:
* One macro that expands into "__ctx_lock_type(name)".
* A second macro that expands into the rest of the above macro.

In other words, instead of having to write 
context_lock_struct(struct_name, { ... }); developers will have to write

struct context_lock_type struct_name {
     ...;
};
context_struct_helper_functions(struct_name);

My opinion is that the alternative that I'm proposing is easier to read.
Additionally, it doesn't break existing tools that support jumping from
the name of a struct to its definition, e.g. ctags and etags.

> +config WARN_CONTEXT_ANALYSIS_ALL
> +	bool "Enable context analysis for all source files"
> +	depends on WARN_CONTEXT_ANALYSIS
> +	depends on EXPERT && !COMPILE_TEST
> +	help
> +	  Enable tree-wide context analysis. This is likely to produce a
> +	  large number of false positives - enable at your own risk.
> +
> +	  If unsure, say N.

Why !COMPILE_TEST?

Thanks,

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/97e832b7-04a9-49cb-973a-bf9870c21c2f%40acm.org.
