Return-Path: <kasan-dev+bncBDBK55H2UQKRBO675LEQMGQE2DQDM4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 10488CB5B16
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 12:49:17 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-5942a78fbccsf649448e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 03:49:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765453756; cv=pass;
        d=google.com; s=arc-20240605;
        b=JWxmxvx4w1odVDve47rF8tED7qLGS6/I0G6t4XQ3b9OFCBe947mtLpgFkfX5U+6sWx
         guXL6KLXyWZKXNuz+c7DPUMGD5XPetMFjLyw6UI42uMqqzx6KQwoRXn4sglWLywKL5qT
         /A9z1IJbBimpMesHeZFMZ/yVPCGOS2ol5+oqj0pZKayC8eux1pfik8JGJD8Kn3MTOGV0
         lb4O8lyuFnvDdJ02SI6W+q/7yE8A5hWL1Jlus68MHh6EKxs10XyCMD6qnjMjnKtxVeO8
         OA+iTNehBv0yBOyNdWg0svIolfrmQKrllsVsVjHNW+Ypirh/9v9q1cohy8PH8ctl0jt4
         SrVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=GgQuSITcCRy4MbKahu4EDI7NgIw5ox1sLEDF5o8DC40=;
        fh=PbB5TiZq4uirrAkEvkeC406kyiO0tUoUVhZQaCThoR8=;
        b=PUwQgChg6ottCwDMb4k6I0QDHBDLJvemPR9IMlcmzqprIn+Kj1yoSgYNmoRlyGaHEc
         Ag2HCI0Mu+DsMUTl0kP5yEx6GZ4lcDiKjN4ypsZ7vcgpcSO3bh/SYgNnJvqinaGFxSl5
         d6WFZ8/iryW4N+TvVy53g6+bPwCq32WS+YHxmII26SV1JogH3N3xxOeminY5fFk6ZQsW
         mSKfdkVtKKhpPXhhlvhZSAkOzEYi6KXUGcyHjCc4HFPmA94/WF3CKaYgSG/3PUhWp/fI
         lKtw1OqkpgI4ZvySZx/9oErcjKbSBBxyamHL53nDv+F8O7wJyK/deOqbUcV6NSNqWJQx
         gipg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=JVN1AzMs;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765453756; x=1766058556; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GgQuSITcCRy4MbKahu4EDI7NgIw5ox1sLEDF5o8DC40=;
        b=cGlFBXco9u9aqhXJgThtxNJ9gfuRccRlt97yAzX7OHULYUEVnC/yzGSsR3zcoKmUkl
         Xuu7Wwoq5nk4aZLHR9691bnkZrfrWF5e6a9lHiMTJuudu0s3DYv7JfLZ7MeV+3exu4Kz
         VIWBoviPAbtInGk7iMTOTxw96jAm32djMqCvQ/3xJXCbgeLgFlJdd3MnyFlH8prHsT9W
         n9WQstvPVsrVymwFOyuaJVOw+dmqD3oXzI5hp7vwCnwXEzmvzgfgBd4x1BrSzb2SEt0B
         ZspStHej8Kfbo3h/roGiZ+iRwrvPd2uzSwl8WkW23Iph0nBARnfQVAqgjcBaC5CRyUpZ
         +Hag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765453756; x=1766058556;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GgQuSITcCRy4MbKahu4EDI7NgIw5ox1sLEDF5o8DC40=;
        b=JtpBRbVUppY0IlNOel6FvPaNfjDiRY095XyRyfNzbKfrWHt1q7SogLyZk7MwRmZr9a
         KlO2otGphmxpzdib0hYd0wPgEZlJMhrctmQiI4qq6FxaqZURy0HK4tb6JqFwlPd4tgaO
         2P8gm6gYmS4NPZbNvOeWOMMeOX0gHWMtqzo2QELSvC4A6zF9NGhL6UMIY8SZA5/a8+qE
         9djdwWfptxZ1WE63VtEys+DIJ+3fLJ7lPYO/jRbrVS/3veDj5QMVJ8tKDctGSUqt7vpq
         60BbxbfdJybmnBpVbtH0eceS6POszGKyinBN190PMmKEq3dKwX5NItEVVcHUvqGjuDtF
         uPxg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW9NtPcAaoCOfE4E0IEedlif55nCLQtDiDbKMaC9EZvFEVFgTDRcI696ZFrPrhOUEwDuNDbLA==@lfdr.de
X-Gm-Message-State: AOJu0Yw3CrUdneY/H4uYAgIZYPPr8Fy2CmXtfX7Mit3GlUw49Z0IT2u5
	7weLokBdVwm3ALLZ6N/TWeM4QhoUS64yEt9WZFxseNVOnWk26/5jrc0C
X-Google-Smtp-Source: AGHT+IF8cfxr1SPQADnWg1Cm3b86h2Fxpe2nnvyrS0gKECtqru/6GbGRJEX4WVoa5a9PZKxQBthVjA==
X-Received: by 2002:a05:6512:2207:b0:598:8f92:c33e with SMTP id 2adb3069b0e04-598ee50ce34mr2083269e87.50.1765453756176;
        Thu, 11 Dec 2025 03:49:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbPB7D6kSwCy2e5xniIFBWTSSCThZ1Rpx8r2BuI57OaDw=="
Received: by 2002:a2e:3607:0:b0:37a:2bb8:e00c with SMTP id 38308e7fff4ca-37fbc934b43ls2143661fa.0.-pod-prod-01-eu;
 Thu, 11 Dec 2025 03:49:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUkljPk/6E9MsnP3LXfn7Z29wQ21qr9wrxYDMAQ9tsL6YFipEGtJbpMyD/clEj9PZtFWXiFw5f3n8s=@googlegroups.com
X-Received: by 2002:a2e:8a89:0:b0:37a:2c11:2c61 with SMTP id 38308e7fff4ca-37fb1fd88fbmr18816981fa.4.1765453752938;
        Thu, 11 Dec 2025 03:49:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765453752; cv=none;
        d=google.com; s=arc-20240605;
        b=fsH8JwtodaJl304pFxpcHsSSYi+Gq3VPjZGlyenTG0CUIJp/rHVJqDxEhFy+7kpce4
         CiYSU+8PUVTX6uxIbKNOWs0AOljj3u/S/GUCoe/iXnrOVeF3inJsIu0zbVrl6OzQNy9z
         zmoHGQamtZOilavMyIO6s62nuZoKU/aU+3tGibMgUss8ZEenQkHzf4kefJLd6/Cpn/Rc
         mlp3S4gLZNlg+MJa2JnRD3LGTg5Wkon1p3rhMhjnk8q6Vw6eywKyk+XpJQDUe6cTHM+E
         xeypjzpcFzitkBWwsesafRgOQCn803qh0mKye5a6ou080S641gGEjUzFJNpa3Ib8E/wy
         01ZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+OT4ivkTtGpyfGWvpgrf0Vr9j9IriXFLaXkwu0GJ6bw=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=B7WiWcXSKlVJ/xVhcy6NUQWrZmcMp4hgHKGkX+mJ2Pv28H/poTvRXmp7qs2AE85o0s
         PN+z56XjeDP5uVXuraGAo+3gWeDscZaSOuBT6IlfR7dgQ2eR8XcF4O64BqCspAesHsoK
         ENaQAXZf/4U2bFYWv0twicgdp+c8JU/UIoMfc7Ir57Rp+1oIDxEILCdOcahqK/IU+s3J
         6V72eQjfVO6Xt1/IeCZpenls6KStH2exneWqUxngUTU9FtKl9rofxXIhTnY7a4eA50B8
         V+kBiFt5myaxRObFlg++3JkZcsunu6GvyQ84ajXUheCY1dgW2uYBF5uUX03q91W7uauY
         tu4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=JVN1AzMs;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37fbca750eesi313751fa.7.2025.12.11.03.49.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Dec 2025 03:49:12 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 2001-1c00-8d85-5700-266e-96ff-fe07-7dcc.cable.dynamic.v6.ziggo.nl ([2001:1c00:8d85:5700:266e:96ff:fe07:7dcc] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vTfAP-0000000EBca-31xd;
	Thu, 11 Dec 2025 11:49:05 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 2CEC930301A; Thu, 11 Dec 2025 12:49:05 +0100 (CET)
Date: Thu, 11 Dec 2025 12:49:05 +0100
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
Subject: Re: [PATCH v4 08/35] locking/rwlock, spinlock: Support Clang's
 context analysis
Message-ID: <20251211114905.GE3911114@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251120151033.3840508-9-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251120151033.3840508-9-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=JVN1AzMs;
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

On Thu, Nov 20, 2025 at 04:09:33PM +0100, Marco Elver wrote:

> To avoid warnings in constructors, the initialization functions mark a
> lock as acquired when initialized before guarded variables.

> diff --git a/include/linux/rwlock.h b/include/linux/rwlock.h
> index 5b87c6f4a243..a2f85a0356c4 100644
> --- a/include/linux/rwlock.h
> +++ b/include/linux/rwlock.h
> @@ -22,23 +22,24 @@ do {								\
>  	static struct lock_class_key __key;			\
>  								\
>  	__rwlock_init((lock), #lock, &__key);			\
> +	__assume_ctx_guard(lock);				\
>  } while (0)
>  #else
>  # define rwlock_init(lock)					\
> -	do { *(lock) = __RW_LOCK_UNLOCKED(lock); } while (0)
> +	do { *(lock) = __RW_LOCK_UNLOCKED(lock); __assume_ctx_guard(lock); } while (0)
>  #endif

This is again somewhat magical and confused the living daylight out of
me. I know (from having looked back on previous discussions) that I was
confused about this before, and clearly it didn't stick.

So obviously I'll be confused again when I look at this code in a years
time or so :/

Can we get a comment near this __assume_ctx_guard() thing (because
putting it all over the lock initializers would probably be duplicating
things too much)?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251211114905.GE3911114%40noisy.programming.kicks-ass.net.
