Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVNLUC7AMGQEXCFJIMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D188A4F9A0
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Mar 2025 10:14:00 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-30ba11c14c0sf23771731fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Mar 2025 01:14:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741166039; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZZ+aobw+QJ9yBiROV7LSihV1DNSaZBRbTHSZNCxo30Pnps5of4gyGEag8ZH9AEYJbe
         groaKCmJip3sBIWKloAFLf75a7UAqxEZT4alVdogSfyqgmze/Ip4x/CZa3xOATZL2UxN
         DWfp1bM9VR/05R4W4NVxaVyGmSfWVEa4kxCQSvPzBLBz8o5W20mROcFSa6wbMrhew5Z8
         kel1zPKVg+0CivmKb1mfGyj2vfyzwhqdNz5jieU4AJRSlebOXYZwkP66nvlA1iX74cY6
         WEgwMdEVWbu4hB8WlbIznRBX4mRy/ekNDpb/ixmMcECartZnscjwKQg6VazwY/4isMi9
         jcpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=EyuhToFJPRGHp/Two0rjLqzdn6mBYNFb+mltaEO5uxY=;
        fh=rxGGL+qkhBxHslUivnirruZ3EGVpZJ/qnlZXYFs8Tig=;
        b=IauAkiIiNpLPDAI7Ns1GZJtm1Bcn3O+T61zdA/kb2dA8jnjabk7Ntd9CviAeVyg1bp
         KZvz1AHvKSU8CpJN9nknMsdsZPS7E1H2IpjVLxJLXsNrGN5hhLRIN4XPMZm+fazPeI7Z
         u0lHMmgwUG3HNo5Dwf5eUTXf34FikRSnSQiQeU9PA7Oq5CZPoW1OcfhMY3/XMEvdw23f
         u08SKf0WX1AKkVw0YXwL5cGE2sXjAVm9sCkFMzNL9Nfg+lQua/9kNfTvjJGCLvuzCID/
         hHl5zzYTVl2xxEaEvV82IF3u3xAizBGN8/pF2UFqh5mbNfAV+aqb9g92Hld3MLObIwnc
         MMKQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CmvRgeJ7;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741166039; x=1741770839; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=EyuhToFJPRGHp/Two0rjLqzdn6mBYNFb+mltaEO5uxY=;
        b=L2F5kDSrbg35TKympvDRNgMV+6do3BbrP/q/Tal0tyT/bJ9qlbrcS5MzXPGUMY8nJx
         ZFCjKCcFFm0yfUZI4CspLvgWIjmvxh/gmhueyOhy+583bMwrgkHnI/4thgzkZdSOeKb1
         b/Fd+85hUkN2BYrDiOibKXtagAvcG2KmQ9APGtYGxEdxcpHv/0lAyiZ/IInZ8Wns40d1
         SaNEUohtXMeLGjo4KJA8+VmemaCpp2GyorL3/q1PqiXRWjR2U16SX9l3FnuMQvZujyJ4
         cW7dexC4eyB3SFWzQ1EJJICDHjknBNRsmNrHO2Qf9L6JokS/NzWiw6msalk89XuRnYhe
         78zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741166039; x=1741770839;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=EyuhToFJPRGHp/Two0rjLqzdn6mBYNFb+mltaEO5uxY=;
        b=OCiNeAZoIXiOrSJXxulI0JIlfvsdXMSGjM1pIaorKwrNnoXE3QhCplLaU1gQNyfI2I
         xgq+1G0lNgbnyJ/y0zKM6I1RROE1encXvt1bRTMWc10VwepHGKKoDPjzEgDP/IjtL5pL
         Lir9SEIE80rYnsyAcnYE5DXncBfhQ0mz3CePFklTVxvoV+1VDDZwZUfrkA7nt7v/wD7H
         +44ox/ukEEXEI0jFTmnxIax9owqv8ZnJgdWO9tPkHXDzeuWtTgmRclfbNiAXwToYsB5w
         e98A2GpfZGJgCDKVyOo6T5lhH2AIiHz/4FbxH4FkfnNMNf+ed57yiqFwY3aLOQPxudFL
         6rZw==
X-Forwarded-Encrypted: i=2; AJvYcCVdI/JDrUlsY+Vn25v1PNtuunLZkS2vb68DSmm0v8nZocg2EXzrDn3NuRzSLvsoTwd2vbhC8Q==@lfdr.de
X-Gm-Message-State: AOJu0YxbWO3VG8Jj8TAbyUMy0BKARjPrRZhbeG2j+ke54xN5ggbxzcuN
	CYQItbenFvHnsGjzmqAJUkFf9CWf/7LyemfXaGAjviiJor+gUvbM
X-Google-Smtp-Source: AGHT+IERgbAE65CmF9iTWRjSBkBhQNfzj1dY5JW+05Sy83xJi2mdVb0z8Bq1BllYjK/d0VlmsHy6Mw==
X-Received: by 2002:a2e:b8c5:0:b0:302:2598:de91 with SMTP id 38308e7fff4ca-30bd7a4fb84mr7521091fa.16.1741166037817;
        Wed, 05 Mar 2025 01:13:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEWXekzLLsNzJrODZIYADELgKJYtUQkY8GbYEAtp8u7+w==
Received: by 2002:a05:651c:50d:b0:30a:355a:214a with SMTP id
 38308e7fff4ca-30b847ab638ls2643811fa.1.-pod-prod-03-eu; Wed, 05 Mar 2025
 01:13:55 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUgqLEG8ht/KEkJR0D2HKPOefJtn9dsXjHMebNcjoJUU2Ee8wnZTS/uhhmSR+OeWbgOxULyXOEVWHM=@googlegroups.com
X-Received: by 2002:a05:651c:19a5:b0:308:f827:f8fa with SMTP id 38308e7fff4ca-30bd7b0be07mr8468261fa.27.1741166034653;
        Wed, 05 Mar 2025 01:13:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741166034; cv=none;
        d=google.com; s=arc-20240605;
        b=R6bwrY11nS0P9kuGMescmYGct1+Xwfbgr+wHVqwPN3eGrMgWGZru8hvnlauHnxmSuy
         mbOQ7bNEZY5hYwLtqulsZM/khNEkAtmALsCLULCI12A1iuH62+b9hP/akNlvUCMoATTa
         1ibfWKa0473QDpbOwjr/afxkY0o9iPEZtDWChiOInkiU+eD/MEGgpMaxnWA2HxaA8rrZ
         uHT58MBV4SMVjk+KRgckccIkT7qJd8P5D26LF68LOuk0kDPkUM7gvXBP4SkWQGnluufH
         3oT7Blv0JmFUlfiYDco/Q2XN5OdJ2HiTEKXlyQp33oyCL1tqvaZCr30K4kQfkIFlRAuP
         Wpxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9cBjuy2PLDHX7EYpa/ALszjDhP6sn2qNCfw9I5BYuy8=;
        fh=+e8BUZnAb977KqEPVcNqXNuoj7P2XZAm9wOFYmfNvT8=;
        b=Iao1cVk5Pla96cSY5HLFk8GqM5hGcQUNWBaDLJOhP7MI4QmMXJVJWgyeb2QiUjZo/I
         YM0/ZlPOAEknShX/1CZrW4UIObta1OOCDoHioSatKs9qW04RPBRJMRW2ZQ7AKd12T11T
         h6iLtR3Wfmm7mi+WdZrP4YrUAoh5FFzKmfVl3gWfBKFKmlGLWGAdkcoge+pL+Iti5kpt
         +d1K1CGOxG8dAU2Uep4qAQlX1rvN+OXqmxNVPpck4R084+TqZJ1o/rXJ+ZzgNsOSfwVI
         xeWUmVh8923TYQhdeOQDtnfce79p9J3FaWnh/XvdFaUQfbpM/1tPUtvIryR5RdESy+44
         1dSw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CmvRgeJ7;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30b8eab08bbsi3248511fa.8.2025.03.05.01.13.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Mar 2025 01:13:54 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-4394345e4d5so44403315e9.0
        for <kasan-dev@googlegroups.com>; Wed, 05 Mar 2025 01:13:54 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXonVvPI6W33rHi19l94WZaq4ge9B5AeVzaBYJj3s0zFOy9XRTQfYJQM+ibxGAroT1XRFnL/SibHsE=@googlegroups.com
X-Gm-Gg: ASbGnctWFgURceRRCXW3hs4w39BzOtayxpKV6pyeJWn2AE7idZDgdcBj6N0+dLhjCqF
	RX58US2EH+CizLmVMFJssmLYqBNmOQvXeKhHi68Lh3ANJ5Y7m9K4+jAbHvM1j2QUPNVYrwqVc9l
	wyHCLnAZC30jUSx52+04PNrZOew9cSacrDIFA/qko/NacSJqjNdHERskIVOZz+nAtnfKeL+jI8/
	sECaaBPaXkTupUUkMX6CWq9v2YT7Dz1r2WlsspEnNr40cdFL8+2U8a1s6msQmgX4uuXHJCFRIPn
	u5SLknbhJlDsPdpclIf9LzXUtnjbq3Svmz23PvJpgaUuJ8M2v3LoSlk6HVRXTVxaFgZu1zbA+Aq
	dQHJ9cA==
X-Received: by 2002:a05:600c:190a:b0:43b:cbe2:ec0c with SMTP id 5b1f17b1804b1-43bd29c9377mr14815785e9.27.1741166033783;
        Wed, 05 Mar 2025 01:13:53 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:11d6:a25d:6219:d5fb])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-43bd42c588dsm11275665e9.21.2025.03.05.01.13.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Mar 2025 01:13:52 -0800 (PST)
Date: Wed, 5 Mar 2025 10:13:44 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dan Carpenter <dan.carpenter@linaro.org>
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
	Peter Zijlstra <peterz@infradead.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-serial@vger.kernel.org
Subject: Re: [PATCH v2 01/34] compiler_types: Move lock checking attributes
 to compiler-capability-analysis.h
Message-ID: <Z8gVyLIU71Fg1QWK@elver.google.com>
References: <20250304092417.2873893-1-elver@google.com>
 <20250304092417.2873893-2-elver@google.com>
 <f76a48fe-09da-41e0-be2e-e7f1b939b7e3@stanley.mountain>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f76a48fe-09da-41e0-be2e-e7f1b939b7e3@stanley.mountain>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=CmvRgeJ7;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::335 as
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

On Wed, Mar 05, 2025 at 11:36AM +0300, Dan Carpenter wrote:
> On Tue, Mar 04, 2025 at 10:21:00AM +0100, Marco Elver wrote:
> > +#ifndef _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
> > +#define _LINUX_COMPILER_CAPABILITY_ANALYSIS_H
> > +
> > +#ifdef __CHECKER__
> > +
> > +/* Sparse context/lock checking support. */
> > +# define __must_hold(x)		__attribute__((context(x,1,1)))
> > +# define __acquires(x)		__attribute__((context(x,0,1)))
> > +# define __cond_acquires(x)	__attribute__((context(x,0,-1)))
> > +# define __releases(x)		__attribute__((context(x,1,0)))
> > +# define __acquire(x)		__context__(x,1)
> > +# define __release(x)		__context__(x,-1)
> > +# define __cond_lock(x, c)	((c) ? ({ __acquire(x); 1; }) : 0)
> > +
> 
> The other thing you might want to annotate is ww_mutex_destroy().

We can add an annotation to check the lock is not held:


diff --git a/include/linux/ww_mutex.h b/include/linux/ww_mutex.h
index 63978cb36a98..549d75aee76a 100644
--- a/include/linux/ww_mutex.h
+++ b/include/linux/ww_mutex.h
@@ -372,6 +372,7 @@ extern int __must_check ww_mutex_trylock(struct ww_mutex *lock,
  * this function is called.
  */
 static inline void ww_mutex_destroy(struct ww_mutex *lock)
+	__must_not_hold(lock)
 {
 #ifndef CONFIG_PREEMPT_RT
 	mutex_destroy(&lock->base);
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index 13e7732c38a2..1a466b362373 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
@@ -516,6 +516,8 @@ static void __used test_ww_mutex_lock_noctx(struct test_ww_mutex_data *d)
 	ww_mutex_lock_slow(&d->mtx, NULL);
 	d->counter++;
 	ww_mutex_unlock(&d->mtx);
+
+	ww_mutex_destroy(&d->mtx);
 }
 
 static void __used test_ww_mutex_lock_ctx(struct test_ww_mutex_data *d)
@@ -545,4 +547,6 @@ static void __used test_ww_mutex_lock_ctx(struct test_ww_mutex_data *d)
 
 	ww_acquire_done(&ctx);
 	ww_acquire_fini(&ctx);
+
+	ww_mutex_destroy(&d->mtx);
 }


Probably a fixup for the ww_mutex patch:
https://lore.kernel.org/all/20250304092417.2873893-21-elver@google.com/
Or extra patch depending on when/if Peter decides to take the series.

> I'm happy about the new __guarded_by annotation.

Thanks!

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z8gVyLIU71Fg1QWK%40elver.google.com.
