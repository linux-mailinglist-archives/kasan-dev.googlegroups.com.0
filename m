Return-Path: <kasan-dev+bncBDBK55H2UQKRBWW45LEQMGQEDZZUPVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id C6CA6CB5AD1
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 12:43:23 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-5959d533486sf432122e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 03:43:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765453403; cv=pass;
        d=google.com; s=arc-20240605;
        b=QKx0vL1ajuo3r8+YEMyVO2bKzTw7O8wu/zw/pWRZc8JukbtMMuKCVQP/a7/al3mgCX
         LQpDoXU21kg/vVM1XqkNc2Pa0NbJXQqhECJy2R1SpOtF1tT+Tv4nVLuuRXGr29HusrT6
         wpjzptErwEEJmdrUBsKHVvPVEj7f53keWrxFTxy5+7oVjxSo5O2aFoH9HsT2/MTS1u9J
         oz2EvMksg7UfBZTTCxQc2LuKQqldqu6YQZuTSeHPmyt330nwyLsqVRS0B0CQZJ650K+k
         H1ZAC1ucMa2+TIuX4J4bnWZG++2oPIfGZFajThJgj14JUok3YJF91ukNbISlBe/qhxjF
         sm6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=S+vYMfDF+1TcedhaxDZEc6U8Z1vA3vdu+fcUKU04Qv0=;
        fh=JA2aVkqJUXhQ1IhIw6gqJmiLrC4SrzBmhzz3PHBQiaU=;
        b=cuGE4cN257QcxNk1t/JWey2VPIRV8E9bJnaOCaFXkq5LjpGOoBGfZ8ky3HLGfTzRjT
         PXZEab/yRWgyHi6LQsMLp+6bork0lpXsVqlTgTV/TnVSFL9BALdcXKiYp7HT8kJVOw7y
         0FFoSrmx7fwuZsQaLaUaNXTU5NJHG2XAH03gIci2OrEZYYRkkN4LwHiL/B4IHzMsxFwr
         hpVpUjulaXZNQb1M75vu4bohgygLSscTDPHoVKMqKd8uiBfSaQTEp63q5D9xuJa7n/o1
         9Vj8d4ksjFMzRQsn4cp6v+6+/q4vvXvK9pHWOLGxpet0YbRyjrToWoBkyV+OYIT5Ggg8
         LV5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=gC2D4Nn6;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765453403; x=1766058203; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=S+vYMfDF+1TcedhaxDZEc6U8Z1vA3vdu+fcUKU04Qv0=;
        b=XuF7JGcf/8Qz4YpseCjjAjhx6QCpVhq+7aoJ9mGPJp9c4GTbN8qIkXO6IsmhW1e3gN
         HaQJZXfQhao5BRGEThFZinodD4rzYhp31xPEj4tg5RfQwujhH2qnHpeNpj/WEmtL/Bk0
         NVBc+P0ofJuZMFBJ2VRSBTVhTirLSVSsM00D4BfulPjGXjn3j0AXilnM89/s6bycczYY
         C6hdr62cRbfQoHJqgObVJauC4HouMTdBElu02f9HJIjl2w5b5DUyRw916ugwgGBOiby5
         paD27lwg6dgfVGFBWDbEGvpQn9WH/7QXm1YUGS4otxKYScYu74HCylON8WFPbhsIlLot
         4hMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765453403; x=1766058203;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=S+vYMfDF+1TcedhaxDZEc6U8Z1vA3vdu+fcUKU04Qv0=;
        b=DyK7e40gG1W+83udRzgFT68vQOOtScHJ8ODWvEFo/RDep6fQjh5aF1naK4PqkySwn0
         NMHoy9AdPf3A/D7lj7s6pmf111krmsc4X6a9MaGtbEVawMp7FV3VGUUEgJdlvG0AOzDj
         bGbOz/D7znl8nvHcO1UGH5MPNXMhX6AYQ+EZ2Kp/S/I//ycZyZoN96EM7M42sgq2SLgw
         avjjixTFp8sZQQRqrcxVZmR5j/kfOYJcW0Jr10PtKmizaocjuq100YgqJu3aIWgAjkWT
         X3dr88jjyAEACACCfaChrdDw4KSMWHj3+t097vJOVXDlSx1GfFrpD8TZFh7L7uAOMdj3
         qsCw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVeloTfi6AVr+rIgBznkzJJ26FwiBAEmRQh6GHnk5AXUK4w1353pw0pJS+O+Bpfsa9I/6QuVA==@lfdr.de
X-Gm-Message-State: AOJu0YzjykwJa1opLd3qE2LI01YpXyByY9U5JI5i1wCtajxMd/D4RhQS
	MPx+xsOT0gvqwAa6TwYNnJ3H6UM3VV1AXOjbV7w8SibwOdPh54gAaDh6
X-Google-Smtp-Source: AGHT+IHz/VbeMN4HuwKy/28gTPRxGQIclfxxKLHTqUcnRytAbaJYNWd8XEG8cCfn2osTglSEu9F/MA==
X-Received: by 2002:a05:6512:3b9b:b0:594:346f:4850 with SMTP id 2adb3069b0e04-598ee54eef2mr2354657e87.49.1765453402795;
        Thu, 11 Dec 2025 03:43:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYyab22qi9X/Iln++y6vu4pMco5ZPXP2AVr5EYhQExWtA=="
Received: by 2002:a05:6512:2241:b0:598:f6cd:ee8a with SMTP id
 2adb3069b0e04-598f6cdef29ls122742e87.1.-pod-prod-06-eu; Thu, 11 Dec 2025
 03:43:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVzsfWbTySXU8zb1hwhD4jxE/tjspTXDyts5PWbNmK00Tlax6lUObGB9CY/5H1SduTBbHylOOVAxoE=@googlegroups.com
X-Received: by 2002:a05:6512:b88:b0:594:248d:afa7 with SMTP id 2adb3069b0e04-598ee4e62f6mr2178599e87.13.1765453399392;
        Thu, 11 Dec 2025 03:43:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765453399; cv=none;
        d=google.com; s=arc-20240605;
        b=UEub+JWcFfNabTibjKCGvVSemVOc0SsJ2K3HOTUxqhWXjOgI+fXWRBDgo9wjSSOvbL
         iOD9MQ9HpHwmadWNBcevh1j1Wp/UEVEMfK7b8XPdhewOf7UmGgOORgjYdi62+QMAS3B/
         fQ0kaTIcVJtWW61DYIM3qnOxBS/NiAPPblXcm/YzEt53m6GkWqmpFDiKyxyT7J0oew41
         j+FCIfSpuAf8BIwYqqmURClaJeUMPwyUfjfWD8RHpxaed6/fFPJbqRW3h9QMOH4v6pzS
         o0KyRbb+JWwEvzMkaYpT1S57sheYwRIURioWlPxpiVhTeXxm0H4mZxt8v7LlSPxbkQLP
         z+BQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=uQ1t1in3MNz+55jGFoFlKgze5NqUmk6ITua4X7r2Yeo=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=gUvtGD/N4I8OOlReBW2LXTwQC8u3o4fJdzBjVIhLBiJyQ1LNxLzN/NOxojQxe/ijPf
         U0Owe8WWI+hqbxbyzKedgkUf2zQsPtwT1FpuiQNaSAgmcwo/aoyBosT6WbBsdLAL0S4T
         KIJ2wuU58eUdy7mwtjvYPfDC8Vy0OiVMTwqors9pVR4m3HFFIU4PcjDN1BL7NtK9ynBR
         YFksLJTnm3w9DtBDrtStQUv7FLjX09uhw4W0eHm/Tz63jIjpV4LK04zEMAITkhwbfbOl
         CEtD2EGSnX7J+pvqqkxBb8p9Eayv07kWTD7HS/EZLLBNqflAo4DcOJsJfEtC+eBK5LVK
         /34g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=gC2D4Nn6;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-598f2f7c242si38425e87.7.2025.12.11.03.43.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Dec 2025 03:43:19 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vTf4Z-0000000EBFr-2coJ;
	Thu, 11 Dec 2025 11:43:03 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 29E1230301A; Thu, 11 Dec 2025 12:43:02 +0100 (CET)
Date: Thu, 11 Dec 2025 12:43:02 +0100
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
Subject: Re: [PATCH v4 07/35] lockdep: Annotate lockdep assertions for
 context analysis
Message-ID: <20251211114302.GC3911114@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251120151033.3840508-8-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251120151033.3840508-8-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=gC2D4Nn6;
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

On Thu, Nov 20, 2025 at 04:09:32PM +0100, Marco Elver wrote:

>  include/linux/lockdep.h | 12 ++++++------
>  1 file changed, 6 insertions(+), 6 deletions(-)
> 
> diff --git a/include/linux/lockdep.h b/include/linux/lockdep.h
> index 67964dc4db95..2c99a6823161 100644
> --- a/include/linux/lockdep.h
> +++ b/include/linux/lockdep.h
> @@ -282,16 +282,16 @@ extern void lock_unpin_lock(struct lockdep_map *lock, struct pin_cookie);
>  	do { WARN_ON_ONCE(debug_locks && !(cond)); } while (0)

Since I typically read patches without first reading the Changelog --
because when I read the code later, I also don't see changelogs.

I must admit to getting most terribly confused here -- *again*, as I
then search back to previous discussions and found I was previously also
confused.

As such, I think we want a comment here that explains that assume_ctx
thing.

It is *NOT* (as the clang naming suggests) an assertion of holding the
lock (which is requires_ctx), but rather an annotation that forces the
ctx to be considered held.

>  
>  #define lockdep_assert_held(l)		\
> -	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
> +	do { lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD); __assume_ctx_guard(l); } while (0)
>  
>  #define lockdep_assert_not_held(l)	\
>  	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_HELD)
>  
>  #define lockdep_assert_held_write(l)	\
> -	lockdep_assert(lockdep_is_held_type(l, 0))
> +	do { lockdep_assert(lockdep_is_held_type(l, 0)); __assume_ctx_guard(l); } while (0)
>  
>  #define lockdep_assert_held_read(l)	\
> -	lockdep_assert(lockdep_is_held_type(l, 1))
> +	do { lockdep_assert(lockdep_is_held_type(l, 1)); __assume_shared_ctx_guard(l); } while (0)
>  
>  #define lockdep_assert_held_once(l)		\
>  	lockdep_assert_once(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
> @@ -389,10 +389,10 @@ extern int lockdep_is_held(const void *);
>  #define lockdep_assert(c)			do { } while (0)
>  #define lockdep_assert_once(c)			do { } while (0)
>  
> -#define lockdep_assert_held(l)			do { (void)(l); } while (0)
> +#define lockdep_assert_held(l)			__assume_ctx_guard(l)
>  #define lockdep_assert_not_held(l)		do { (void)(l); } while (0)
> -#define lockdep_assert_held_write(l)		do { (void)(l); } while (0)
> -#define lockdep_assert_held_read(l)		do { (void)(l); } while (0)
> +#define lockdep_assert_held_write(l)		__assume_ctx_guard(l)
> +#define lockdep_assert_held_read(l)		__assume_shared_ctx_guard(l)
>  #define lockdep_assert_held_once(l)		do { (void)(l); } while (0)
>  #define lockdep_assert_none_held_once()	do { } while (0)
>  
> -- 
> 2.52.0.rc1.455.g30608eb744-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251211114302.GC3911114%40noisy.programming.kicks-ass.net.
