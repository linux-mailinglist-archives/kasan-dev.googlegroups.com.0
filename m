Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO4P6XFAMGQE5337OUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id B6F48CF9B92
	for <lists+kasan-dev@lfdr.de>; Tue, 06 Jan 2026 18:34:52 +0100 (CET)
Received: by mail-ej1-x63d.google.com with SMTP id a640c23a62f3a-b7387d9bbb2sf60073366b.0
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Jan 2026 09:34:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767720892; cv=pass;
        d=google.com; s=arc-20240605;
        b=f7dFYfVeOZK35AJuz6w9AAqHfEq0zOIJeqAN68uG986KfcxDk05BIfbOUBxBInpbu8
         SvIK9SutcL5Q52xYxBhuWM0+DDNHAu4V6eNqNCA5by8N0t67w3skQJthHL5CEoTG4Ylh
         +HuCwIXznG16wibz8dj0yaePdRgrJ1nHzDsfombtx0+aVGvvy23bgyJE9wc7CQ9WkdbC
         3J7H6KKSCdd36U1o/+3cvhMlvJ/wPOFNGAD0JWPdM/Oyapu0pModwSTawacYzfv5cq48
         FxD5OD8URp1HTmbZEbb1y5Seum2MYK4a4y1RKkcDWFpVtAESU1ZfTL7TB/TbdfIPA0t9
         aKlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=/4rYCpjzfJcYmAyCEZ02mYU6dAGInx+BIidmait5tv4=;
        fh=kXlaD3kPhEwM66N9pjq0aEgPCfjXVdEnOvU6YFzIpaM=;
        b=PuWqJzVRyfjJCpvofuI0ihdmWuVfLwsVMANXXDxXbPUddkVXVVS2w8bx9hgbZ6W3R1
         LZPsyC+ZUw0lhmZRqMW0n0NywFRjXPfWlLDL4QNY8m7X0oSQOWczaEzOcU1KbvCLOFnd
         FP0Z2qMo79pLtGBghTP648c5KGDGIVrvAb9lvv8A43ii+pOkPJ9C+9ZQBAt7NXBoeQhm
         bn1FYbPgqfJipBebdA2V/PoT1LU+x2L0yf2QWOHItTkNUwIM9wUUHuLy6xTonJ+XrIN5
         vg1KZfVjLnN6U8/Q5l8aNCdU/vt1WIwC4DcAcBhv7v1nSPzPaeSTl2M9K/DTXyq1snbI
         V1sg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sczq7HBf;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767720892; x=1768325692; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=/4rYCpjzfJcYmAyCEZ02mYU6dAGInx+BIidmait5tv4=;
        b=qO/tiFUHB9hGwAtIJkxfuFEngFnVjfMtqKYAQxVzhZGB3wvu8yoqNd5ldc+vAUXm0h
         skfB9BZH9eJ6kIwOGpE24zARF2jSN5B6s4ymieFohAxNh+o2H4D7+mo5M6rio8CevW0p
         Jo4vLtTxZUMQuYbuz45lMQpYh7N1i2Gmc7xTIeUSNzgeazb0DZWhmQsMpGbEB0y1SdI7
         jNboWkl0YAqbm6CgP0Z/tnXDFpGumdie7aORyi6DE39sb9dfGFgLVCSE2ajL0u5wkoqE
         RCIdmm5ZT01Y+zS4Ckpbe64uRnC6a3uVNDPNDS8I13FL8dSS7DF85po1xTa0kfltf5tP
         czSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767720892; x=1768325692;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=/4rYCpjzfJcYmAyCEZ02mYU6dAGInx+BIidmait5tv4=;
        b=xSZh+tZ9NGomx8LPMqNJ0yl4TXaI/H7RH53ksr+djDRQ+ojEMKhZEbXYeOMX5eSKDu
         XkjhPdcW+ktRwZhxCIhK1r0mqa5fIWGl8XfmdF7lf63nRJCePIGXDJeyn8l8ewIoQFlV
         h2GXaQYjwAjlse/b+jGJLrU1JsR0pufDk5Jdc7xnTKqphap/AJAm3Z9ZBq+oDYc7oAGJ
         DeBi1iQxnerby5MyFI5WyStVLx+Flw6LkqZRZ2fSsnmnb23aN1SbYxMy6miOSBqcpq05
         sz10PngnHZc5cRyVK385GxsmINERJzdRdybTtTBDX+e6FxIV3tVrTnz1Ta09uFjT6SF6
         g/FQ==
X-Forwarded-Encrypted: i=2; AJvYcCXsvl7r1ffS46P6UllTFtQ1f27W6JLi/Y53cXONR737WYxk0+MR42CWgzwBb1qYOg8cybJ5Bg==@lfdr.de
X-Gm-Message-State: AOJu0YyoM+d1Kbr3ZxacVb3n5rsszyUvT8wpC7IhLyEOb+tIW1IcWL87
	neHSoys7JEBi02Yj/IuMBzPfHwqZFMNoEisWD13LTx5l5XjRAzShy2vs
X-Google-Smtp-Source: AGHT+IEJDapZCiOGV8Ns+CIXtuQBCymAGD1XTupIxyjsmfvvE9Ds9lQ34UE0nfNKiQh/v5a6Cmma3A==
X-Received: by 2002:a17:906:eec7:b0:b73:6b24:14a0 with SMTP id a640c23a62f3a-b8426c61f75mr362372066b.18.1767720891748;
        Tue, 06 Jan 2026 09:34:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZTcXhk3xFOkonUDzyM6MagJBE3BaBkOfT/sebfAGPyDQ=="
Received: by 2002:a05:6402:4610:20b0:649:784c:cac1 with SMTP id
 4fb4d7f45d1cf-650748ec41als283991a12.2.-pod-prod-09-eu; Tue, 06 Jan 2026
 09:34:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX3oT2JHMVmrZUV8ekqEB1xYfJxvlKiszWA6DY6OSc+ATH4RVBB2CFOO4xG8/SlYI0ly4ymC7STjm4=@googlegroups.com
X-Received: by 2002:a05:6402:4316:b0:64b:3b80:a902 with SMTP id 4fb4d7f45d1cf-6507921a63cmr3263003a12.5.1767720889002;
        Tue, 06 Jan 2026 09:34:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767720888; cv=none;
        d=google.com; s=arc-20240605;
        b=AZd2FDQ5oEnYLX61uwwiOq5AtbwCEwe7/QL+2r7fL5USLrdzW6yuKyhMkn4oCyXyg5
         cZI/Ar+7SuySLffQLPaQ8GFIBc1JVeE9V0/GLZch1NzjJpE6aczKua2iCIveo2fJosF2
         GsGEpM7dbKiNzZuDPFp08BbRWFaxgRIhvxp1iMXGLHM7zWNjqXDdS7vtN9I/0RdwCA4m
         JOHpHKTeIA7HYPkP0g6zhTAHtK6TMECfL5zKAFh2g+k1J/fsJZLZAwthXHQSM0KpXfdL
         COl1Os+Y2dAZZfYlGZJguBzTE1p1hlEnt1nOlX7lIbC9r/cY16TVOxVFruCLNMwiCp+p
         JQMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=RXcHtzljW/LEwcnvhUw7B+CYy+kN5WC/pk6M+qEtNI0=;
        fh=7Xe62RQQqQumQYFbsz+aUKjeLTqaxzRNhnO4So+t0KI=;
        b=Pa3TrXDtZt5BlCmFDF0g8Pg6lpRaBCRNZJg3sxB78dfX/kQx8ZCNIyJPuLqjiY8zTc
         7pHUtsYzgwSw57LbC2cNUN5piw9xahNF32cS7aDv9Zx0VzzTw4XXYyv21tc2Q78UhWlV
         jTlxkd5UWJB3iriWO1Npj3SFxwPsBHHbLtmKMKTLr7FXUMQ4oUk9QvakDzZfHNjoIV9q
         hqbcABqAioz+oASMXGg0Gmw8lqaDhRsvxh4xvCkLwnjsTxtjqOd4dG2Fb3khKNh6wwPI
         Xdmo3hm67zAVrTd5Qm792N+SYTG8Ouop8EVyOs5k21GkuoLTkzQSG5RRd0vA56a879QP
         pH8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=sczq7HBf;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508d723064si38032a12.7.2026.01.06.09.34.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Jan 2026 09:34:48 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id 5b1f17b1804b1-477ba2c1ca2so12763295e9.2
        for <kasan-dev@googlegroups.com>; Tue, 06 Jan 2026 09:34:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXtnPrOIsZpSq0k80dudUknSXif94ZPGqZoLHlGlAHfIwv4BcK+3rQB61zyADcP4YJxeMu/0GkhtKU=@googlegroups.com
X-Gm-Gg: AY/fxX47UiqIt7PPWjiYfQHO4ktajb/K5K0mYOuGo1c7aExgXz2hz1xlk9YyJ2oLLlL
	wUUevFQ5RWUrkfULMyt+S9Os6vsGYTUGh+crhNlWAsU5EBdkXLt3C6vTeycH4kZOdWpEIBvZCUT
	HhhBgL/1lsHIU3UzUt3Z2tysRYNhSidZLxYiBBaMIIMQYRhwiRD4yuaj2V6KVyTz5jYtWMvure4
	flMEP5z11qS3aL+4wPGyNdnLfev7/dbMO0Qq09bOLUKKp/RhCEGufQiCXUp3gwRZWCO8F64iW/9
	C1RQyePnHWW7fiyMPnNpYwAxOQjLSwQfGJx+JltgblixvIj5pYhlZTfI7Vj8QGwtljBnd9/vWUr
	H08u20+icEWhYqY4Re8USAup8dv5c6m10vgRQYdSy1wyDwqIZTryYhBhP1uD5gIr24DPhwgx+gS
	oXwno3xhtOD54TqwnlN11f7evcVLta+K7k8f0I+yKmycxOB+iZ
X-Received: by 2002:a05:600c:46ca:b0:477:7a53:f493 with SMTP id 5b1f17b1804b1-47d7f0980e2mr44046495e9.23.1767720888108;
        Tue, 06 Jan 2026 09:34:48 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:4477:8df2:f516:1bd3])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-47d7fb4b3c5sm21868415e9.15.2026.01.06.09.34.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 Jan 2026 09:34:47 -0800 (PST)
Date: Tue, 6 Jan 2026 18:34:39 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
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
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, linux-wireless@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org
Subject: Re: [PATCH v5 06/36] cleanup: Basic compatibility with context
 analysis
Message-ID: <aV1HrwZm6xg8PnRU@elver.google.com>
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-7-elver@google.com>
 <993d381a-c24e-41d2-a0be-c1b0b5d8cbe9@I-love.SAKURA.ne.jp>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <993d381a-c24e-41d2-a0be-c1b0b5d8cbe9@I-love.SAKURA.ne.jp>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=sczq7HBf;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::344 as
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

On Tue, Jan 06, 2026 at 10:21PM +0900, Tetsuo Handa wrote:
> On 2025/12/20 0:39, Marco Elver wrote:
> > Introduce basic compatibility with cleanup.h infrastructure.
> 
> Can Compiler-Based Context- and Locking-Analysis work with conditional guards
> (unlock only if lock succeeded) ?
> 
> I consider that replacing mutex_lock() with mutex_lock_killable() helps reducing
> frequency of hung tasks under heavy load where many processes are preempted waiting
> for the same mutex to become available (e.g.
> https://syzkaller.appspot.com/bug?extid=8f41dccfb6c03cc36fd6 ).
> 
> But e.g. commit f49573f2f53e ("tty: use lock guard()s in tty_io") already replaced
> plain mutex_lock()/mutex_unlock() with plain guard(mutex). If I propose a patch for
> replacing mutex_lock() with mutex_lock_killable(), can I use conditional guards?
> (Would be yes if Compiler-Based Context- and Locking-Analysis can work, would be no
>  if Compiler-Based Context- and Locking-Analysis cannot work) ?

It works for cond guards, so yes. But, only if support for
mutex_lock_killable() is added. At the moment mutex.h only has:

	...
	DEFINE_LOCK_GUARD_1(mutex, struct mutex, mutex_lock(_T->lock), mutex_unlock(_T->lock))
	DEFINE_LOCK_GUARD_1_COND(mutex, _try, mutex_trylock(_T->lock))
	DEFINE_LOCK_GUARD_1_COND(mutex, _intr, mutex_lock_interruptible(_T->lock), _RET == 0)

	DECLARE_LOCK_GUARD_1_ATTRS(mutex,	__acquires(_T), __releases(*(struct mutex **)_T))
	#define class_mutex_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(mutex, _T)
	DECLARE_LOCK_GUARD_1_ATTRS(mutex_try,	__acquires(_T), __releases(*(struct mutex **)_T))
	#define class_mutex_try_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(mutex_try, _T)
	DECLARE_LOCK_GUARD_1_ATTRS(mutex_intr,	__acquires(_T), __releases(*(struct mutex **)_T))
	#define class_mutex_intr_constructor(_T) WITH_LOCK_GUARD_1_ATTRS(mutex_intr, _T)
	...

And we also have a test in lib/test_context-analysis.c checking it
actually works:

	...
	scoped_cond_guard(mutex_try, return, &d->mtx) {
		d->counter++;
	}
	scoped_cond_guard(mutex_intr, return, &d->mtx) {
		d->counter++;
	}
	...

What's missing is a variant for mutex_lock_killable(), but that should
be similar to the mutex_lock_interruptible() variant.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aV1HrwZm6xg8PnRU%40elver.google.com.
