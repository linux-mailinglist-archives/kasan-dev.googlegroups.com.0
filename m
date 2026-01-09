Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5G3QXFQMGQEXDKTG4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id D77DDD0C3F7
	for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 22:07:02 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-64d1b2784besf8740436a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 13:07:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767992821; cv=pass;
        d=google.com; s=arc-20240605;
        b=VG87Nl7nXnSn3zS0JTDsu5UeRAVRLcFDqgsAFthaOcdN+sqC94nJIq7hMTW7ZP/Nl9
         TZwotQhcdYVhuTxyxH7+VeeebLuxIWatdI6W9lNTJTibK/emfdZtESENd2wfbuZQFLrQ
         3zH9TihnrbzodMZEvvjUtD8w1ljGFClDtnHE0AEQW0OzS34CUJLZuUVjm4XwuJPO4iks
         5fqRFIoznnrvSSt7lX//2RhP1dfZFVoFouAP5tCPwLRFIAdIvb5sVJuXCNCGgjWfyb6y
         h6M28u74+td98K/L6x/ezrj5gXhgP7mPy5u0II8Zb0xDVE8Q6LAsuZaIu/Rt26ib2T7+
         APHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=D6hcQXl45Svz3KxcptffMNxyYX6MC7Ybxkx5t7FT0qQ=;
        fh=1YRlgh4fUBSNI2FvY3j3yiXmMW4JV2m9nit2cR565MA=;
        b=MlekC5iGOnAPx1gt22ICOFRp41HxQW8Gwu0skaFrhtQjfbB1xakP655pvTNBU0ueuP
         UvIz+fhgSG0Psv0uImNk+qcKC9UbuRwMdBDcYgOBFK8N96bwQKJDRACu8F4Fw0F1UXhK
         KSjynEJ+fcCpwBgjoT2fWSvfJBDCymbJ7BQevwJr3bTHP9PnqiC0l7umuRIUTRtKSx08
         dh/h4e33Tt1fZTggSL5pbm7OUfioRAmTearphuP/HMavxSasnS+1L1wqRKjxEgbqKR0g
         V7m0sJemrsjdNxekgzsept8iAVQcraAPnDIdnuEy4NKk+AKJpkGoH/PTTynjPxZF8q9T
         ru/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=w3I4uem5;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767992821; x=1768597621; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=D6hcQXl45Svz3KxcptffMNxyYX6MC7Ybxkx5t7FT0qQ=;
        b=OaZh+THit8rr1MlVsHa3yUndV00pThS9LsgEDvujJwDS6uv61cmZjyHDSwA2HI9RZH
         BfUlDjTRYF5jJWnPgov9pgzeH4lRUH8n9sq7pi6sXeCRR9r1lVe9X4D6DB5HWlLXMsRH
         L/WVx69R3Y4JXJrCNi0GXo+uaYv+tOMJJ+p8kQtfJ2bBumXENNTFRJ3ChK2mO5McyCfV
         jHi2406I2VtHgaltH2Mx7RH6w92bgZSOQlhFC7jFbRmsbXVE4u4zCqW8MBtBRDiUwByS
         o3whdPUN8rTmRrOU2Lv3cXrHkh+GfjNaXr/siW4W+QjVlf9ol1TSlca4sYZTdGOcx/HJ
         F5gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767992821; x=1768597621;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=D6hcQXl45Svz3KxcptffMNxyYX6MC7Ybxkx5t7FT0qQ=;
        b=oRRAscC5SfnEOIJXJjOUaIHxm/wFDWWIYwu/eDHB84YeHpZqOBmujld6Yt16MqSHhE
         aigip6hS7oiKDYzRVhQD385+8iZveKoMFI++KV0QAt1F8XehVtX/e52mbJ5QgW8WP4It
         geVt9gXBjhg8XxtcRyZnnF1rEYhoEim5lI9oipFK8Au2UgbbqGTbEloIOVGuELYs+Wjw
         IQVIPyxWRY61yLfQWa3oBkWv4tVauh7LJ++Gri+AIFd2fc2SRu7inwM4xEQGAZ9wtpLx
         XFRXc0Ts3C97OsCNN8ZK+rDoTnCkoWIFtUzHCgf3WKqp/1l9jRTqe53qVe8EdiGKnBtU
         ybAg==
X-Forwarded-Encrypted: i=2; AJvYcCWZeLq6A3sbPqy7Z7zdWAo3SyrjitIJl3jrW6gNEQIeGL9h+qlDSl2QSlyOD0UNKvBnE0FjLA==@lfdr.de
X-Gm-Message-State: AOJu0Yxx7CYGJScosLHgGofXiX62/XJpl+T4xrtrRufuOlNYrG14kNN3
	p3o48/kVtU9e0kXWe6QzK+O1Z1POLkEyyQdA3HKIF7hdW8kev8Nnbl4U
X-Google-Smtp-Source: AGHT+IFboY7VgOHnwprDCRI11MY6riDRYi3tj5eKksbdxqb9pXyX8F6RIQfTTTOU4h55uOk2RiY3UA==
X-Received: by 2002:a05:6402:42c4:b0:64d:ab6b:17c9 with SMTP id 4fb4d7f45d1cf-65097ce5c61mr9797575a12.0.1767992821450;
        Fri, 09 Jan 2026 13:07:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FkQ3qjyuJk7LIJgJY7RCc7F9Pxd6C9gsHf7t/P0fWzMg=="
Received: by 2002:aa7:c38c:0:b0:644:fc0e:254 with SMTP id 4fb4d7f45d1cf-6507421e9a7ls4097036a12.0.-pod-prod-04-eu;
 Fri, 09 Jan 2026 13:06:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUXEVlVUcPFB6Rkm2gM2cHUvJj1mHTCgcddG7/9wo09EyUghkITNb2QHZbIndCMG373VgWotArSv7w=@googlegroups.com
X-Received: by 2002:a05:6402:5253:b0:64b:420a:49f6 with SMTP id 4fb4d7f45d1cf-65097e8c0b8mr9880400a12.32.1767992818826;
        Fri, 09 Jan 2026 13:06:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767992818; cv=none;
        d=google.com; s=arc-20240605;
        b=dzp0VVQjrN0rWBvhIEO4o0QWu6quNeuaN8BkygAPLc++vSd0jgDjvY8PM4Np7aoW+4
         T/sk94hhBO9Vz5zw0NhxN3Gq6kTVe7rAfW0wKnj5LWKTlRxwggNigF82qtnVN57bqKqd
         0R2dCRvgy8v1X5Qsqj5Qri+dgAKNQRdguOBXnDaLSEbokl1y7OqgJ9QNzL7iJGg/6ErP
         TPU2hcvaVYDo0xfpYVaZabPIoCloLgmTU6IXnz5d3ZgYRKXmt6u+HfWMTrj1syYyHzjG
         2b9xCxp59SO8+oP0D0xbxVhKfQOHnRcuJoxtOtau2Th7LJij4Fux8hgkG0XOOC2Dj/PM
         HShQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5YiRRXuPlaLabH8Y/4leOeBvuw8o8W+AqfnKT5Dc7EA=;
        fh=saf5CrI0vrk7haOxzJxfjPew/kR8mxnXLkZx3Dej4mc=;
        b=ivARWY8xlSQ6sBLkJFIY4WzFNfgW/KhLYDTCd6Dj/z7ovuyyY04V5E9NCioDUb835w
         0EZM5YJd8mBbIw1uPRV1D9njAyA5phV7ECBaQWF71zOnGBLcxPD3h5tRITAhkzBLX9JB
         CCZlMqXR/mRNegm/WigGFGZt7s9tRKDErC3EvHLjSQhtkVI9U39XAwUxt3eaBC5h4IM4
         R1cAVSW2HjfDv1YrlV0xv6ZtR5MY3xwMRF5qpPBnkNfI4vdgDa6tAzFN22qVyFMdOYZC
         zJ8ZF4Y84Z/kMYVUxpyYAo8e4q3H266u7T6kxiW+AZRn/xjiIC71/Tm29QDJhGN9/C8V
         VFtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=w3I4uem5;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508d71678fsi226541a12.5.2026.01.09.13.06.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Jan 2026 13:06:58 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id ffacd0b85a97d-42fb03c3cf2so2533037f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 09 Jan 2026 13:06:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU2vP2B/v1jA9fIhJd+YpLse/Taa1b9lIY9GkFT0jblZbTUokLr634PeLHhLzr6ucIZ2GjiC9yFhmw=@googlegroups.com
X-Gm-Gg: AY/fxX4tHS5hQEHSOBjc4X58X565oxCfQqTgPhMx33srUnhjbAB1lM/aRcpYz08Srjv
	kW7TK+luxGJHMclEHLySSG2Rx5XcXqfxyGUjZg6HOIbbfotGf+MOeIwIKYWLQK/9r7URbHB6dQ5
	CoHYPS1Rn0DMOiqUol+iZdZl5JY7wqsfX7zlrUI/FUikR2Ga/usEYfvVdbXrGVjZk7f8Nty78uk
	mwryvpeGbiCntZmrp+l70NomZIaGtvO1tiK+iFqvpOKSYTbiPcRn6tyMPqLgnURT2P125UxDueW
	CCRbB6MVmZbwmHqfKU28hU0yM/eeB0yaKxwD46WJxNDYXBO+y5DSP3g0b5tO2ySgkF/jKk6xOko
	gMi02hFcnmnil1wYSY6zxiKmyqknpOor1BJf8fvvpJaRZunJGU84vRSPJIzudVqv70CJAgIRio1
	Anp4VI3TfExyYX0oEeMmtNWAgcClkLDPnmsOBmhAkAi/fA6TEP
X-Received: by 2002:a05:6000:4023:b0:432:b951:e9fc with SMTP id ffacd0b85a97d-432c37636b0mr12665932f8f.47.1767992817879;
        Fri, 09 Jan 2026 13:06:57 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:2965:801e:e18a:cba1])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-432bd5df9c5sm25214398f8f.22.2026.01.09.13.06.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Jan 2026 13:06:57 -0800 (PST)
Date: Fri, 9 Jan 2026 22:06:50 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Bart Van Assche <bvanassche@acm.org>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Christoph Hellwig <hch@lst.de>,
	Dmitry Vyukov <dvyukov@google.com>,
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
Subject: Re: [PATCH v5 20/36] locking/ww_mutex: Support Clang's context
 analysis
Message-ID: <aWFt6hcLaCjQQu2c@elver.google.com>
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-21-elver@google.com>
 <05c77ca1-7618-43c5-b259-d89741808479@acm.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <05c77ca1-7618-43c5-b259-d89741808479@acm.org>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=w3I4uem5;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Jan 09, 2026 at 12:16PM -0800, Bart Van Assche wrote:
> On 12/19/25 8:40 AM, Marco Elver wrote:
> > Add support for Clang's context analysis for ww_mutex.
> > 
> > The programming model for ww_mutex is subtly more complex than other
> > locking primitives when using ww_acquire_ctx. Encoding the respective
> > pre-conditions for ww_mutex lock/unlock based on ww_acquire_ctx state
> > using Clang's context analysis makes incorrect use of the API harder.
> 
> That's a very short description. It should have been explained in the
> patch description how the ww_acquire_ctx changes affect callers of the
> ww_acquire_{init,done,fini}() functions.

How so? The API is the same (now statically enforced), and there's no
functional change at runtime. Or did I miss something?

> >   static inline void ww_acquire_init(struct ww_acquire_ctx *ctx,
> >   				   struct ww_class *ww_class)
> > +	__acquires(ctx) __no_context_analysis
> > [ ... ]
> >   static inline void ww_acquire_done(struct ww_acquire_ctx *ctx)
> > +	__releases(ctx) __acquires_shared(ctx) __no_context_analysis
> >   {
> > [ ... ]
> >   static inline void ww_acquire_fini(struct ww_acquire_ctx *ctx)
> > +	__releases_shared(ctx) __no_context_analysis
> 
> The above changes make it mandatory to call ww_acquire_done() before
> calling ww_acquire_fini(). In Documentation/locking/ww-mutex-design.rst
> there is an example where there is no ww_acquire_done() call between
> ww_acquire_init() and ww_acquire_fini() (see also line 202).

It might be worth updating the example with what the kernel-doc
documentation recommends (below).

> The
> function dma_resv_lockdep() in drivers/dma-buf/dma-resv.c doesn't call
> ww_acquire_done() at all. Does this mean that the above annotations are
> wrong?

If there's 1 out of N ww_mutex users that missed ww_acquire_done()
there's a good chance that 1 case is wrong.

But generally, depends if we want to enforce ww_acquire_done() or not
which itself is no-op in non-lockdep builds, however, with
DEBUG_WW_MUTEXES it's no longer no-op so it might be a good idea to
enforce it to get proper lockdep checking.

> Is there a better solution than removing the __acquire() and
> __release() annotations from the above three functions?

The kernel-doc comment for ww_acquire_done() says:

	/**
	 * ww_acquire_done - marks the end of the acquire phase
	 * @ctx: the acquire context
	 *
>>	 * Marks the end of the acquire phase, any further w/w mutex lock calls using
>>	 * this context are forbidden.
>>	 *
>>	 * Calling this function is optional, it is just useful to document w/w mutex
>>	 * code and clearly designated the acquire phase from actually using the locked
>>	 * data structures.
	 */
	static inline void ww_acquire_done(struct ww_acquire_ctx *ctx)
		__releases(ctx) __acquires_shared(ctx) __no_context_analysis
	{
	#ifdef DEBUG_WW_MUTEXES
		lockdep_assert_held(ctx);

		DEBUG_LOCKS_WARN_ON(ctx->done_acquire);
		ctx->done_acquire = 1;
	#endif
	}

It states it's optional, but it's unclear if that's true with
DEBUG_WW_MUTEXES builds. I'd vote for enforcing use of
ww_acquire_done(). If there's old code that's not using it, it should be
added there to get proper lockdep checking.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aWFt6hcLaCjQQu2c%40elver.google.com.
