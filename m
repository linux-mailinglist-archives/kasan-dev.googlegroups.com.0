Return-Path: <kasan-dev+bncBDBK55H2UQKRBBXR5LEQMGQEGP7OLVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A303CB5D4C
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 13:26:48 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-59427b2fe85sf39353e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 04:26:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765456008; cv=pass;
        d=google.com; s=arc-20240605;
        b=AJaHFmNAXJwLYfWmVbuNvz5laeHWbTRPzdZLxJPaEMyiH9nma5ysSiJHkkfaLxaht8
         /Fy7BWfcj1ISJzVDMETwyBHeldnbnbsiND4niYFewANh9Sf6SEHX9MuxWPWjub8UjFoZ
         GrXve8MTGh/TOx7Ffsi3QNgcCVwtaKNqiE+OchVvSITPHBgWUgbstQIoRwbjoB0slzL3
         fpABv+hrmIZXfpO3ZOKdolPZ6TrswCYvNoJaBd6DXnBUwmIlWj/f5E2J64Wx4K2bqy/h
         tXbq14/fDUXOhrfJwRWyICjz2m9aPu13UDyi+stlifvFGjVeTkVqpmCHSNpTXU+w+caj
         5GwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=SKf9toARA1U9JmbEE8Vq0f+PRQW0VxHrjxNKCwZJudM=;
        fh=/MI0DXiFwcxC15b3mCFGNV5l9Sa5MPR8IGC+7tTEKuo=;
        b=VSb4Ig4q1kDdlZiT5ErDmzGu0iynozLfBVOif1eTql3mwhwOldciMwrbIMg4fN92+j
         BQz0sWLQma9ct9AhGNpdEaMqaj319Ojvp0hXZSn2LQEV79AYZUtpS3rIRmcRmpbxpRx7
         JeA4quhsfV4OiY6AVTUUMaA2bO7Vw+8KEHZhGJtXj7+QgLZVj7xwstJ8vjUSfp/vq/N+
         hsfD4Rx38axj/mR1Hs7i+DDXl1xwtIsWHZqim6d0HOoTfteVUXgkyqn44kRZ03v7sYz5
         cR4Z5f7P1IGO3n3FoiMxhYx3lTRK/gzF73VA7TCKdsuRT5Ce4alh9FUYyJSrY1vqaHBW
         EqJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=K0YdkMUJ;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765456008; x=1766060808; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SKf9toARA1U9JmbEE8Vq0f+PRQW0VxHrjxNKCwZJudM=;
        b=P9o5wSGcInO82oiYejYyI4jQ48hNvC7S/rurb9OGtx2tyWOVNLn/h54g4Iq54dV1B/
         htEK+WlkhJY1dIM30JwjgIFdIsqmC08WBhC2nTY2faWABa4RaoN3FDvJpbQSdDklw4Kp
         pXphszMLtmo+03Vk9DDsk+DwfqXG1C5JYLqvrZY1oN8Li7Xpm6vpV0Z4u8DnO5XuxRFX
         aESS2FPvD8/rk27TSVwwJ+vsJi2syEB/2zg+gADezalK3F74fc0kKLjOWl16Q7a/VJm8
         dz7P2wZp7sFcbQp4FiiaCbGere0+99JxSA+8navRBe8m2qhEv2YdWVqLsnYh//l9uD8/
         mAeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765456008; x=1766060808;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SKf9toARA1U9JmbEE8Vq0f+PRQW0VxHrjxNKCwZJudM=;
        b=FTsg0ZyCT6l3xrMNxS42i5UqN8HSezr7pKNJwPe4EVnP0N+aLftgFQIkyoPw38m87x
         SqPY1OFNpsc5M81mfJqkqM0XcXXa+eAH1qWN2iQhCMfsj70+HHyClpEGIB/U+4u8VQpk
         Y9kktOFQS8bORCE5eBln5hqOwsD+ZQYakYXl6dY0VTvi6R4L9dorH5W9zKo5WXiQ6IUT
         l/JszJlSsd4rnaxsNG/fAKSYrnSHl9u660EPqlzlEBruzpLog++zIY6iegdKe7WWADsw
         4w0sK4/6ZLUDvnYPB1/EnxW5uFvolmnV6AbBmCFjGxfz1BcO/p1D/is+NjGc1g+vT6UQ
         lwWA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVzjL6Yj/B76DMmgGQ9gwJVHlYd6we6MpeJkUdBm3XCZf/eSFgOqKzKFOKVxEZnLlqWZhZ+UA==@lfdr.de
X-Gm-Message-State: AOJu0YxIq4OZuGFefQmuVy+pRY04wPy9ckYlyaHzl4DkuK6a9gvc2Ycn
	Efrg/XnUI3QqLtpMR2AhPaYoe5paDOkpRZovNLGhLgCfZ9AHIxjvIl3o
X-Google-Smtp-Source: AGHT+IFMAcA2rkR3T6UytkadJOhKdGciGOZDD8PGdtZhLG5HCReJy9t2UDWF1URI5G5GUiaIQOlBMQ==
X-Received: by 2002:a05:6512:398c:b0:598:e9f9:c02 with SMTP id 2adb3069b0e04-598f4182205mr647848e87.3.1765456007605;
        Thu, 11 Dec 2025 04:26:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWafjqTreooUvPjIralu7DAhMZk49hXXrfz4W4YN8NzM9g=="
Received: by 2002:a05:6512:1505:20b0:596:c362:93b6 with SMTP id
 2adb3069b0e04-598edca3adcls136880e87.2.-pod-prod-00-eu-canary; Thu, 11 Dec
 2025 04:26:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWi1VU6DWRvLE/MXRa5bCDDUDLYSTm+wOG/0iRsuS2WXoalMbR1jbsOO7uvSfGJ0sj5HO+kWaIiTto=@googlegroups.com
X-Received: by 2002:a05:6512:3da0:b0:594:2f72:2f89 with SMTP id 2adb3069b0e04-598f418e314mr744346e87.9.1765456004245;
        Thu, 11 Dec 2025 04:26:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765456004; cv=none;
        d=google.com; s=arc-20240605;
        b=F1jEAeNAqf+yl05Xrlixl1iPpkqpBm0DvcEeeGoYjb3FVSEfYSqtvmMfjW1lNQxR59
         Xic9nsIHO03V0De3+rXU/Igr5VLaS+rKcJyD2S49ucNWIBkpUyctgm8JGtN4G5OCX3ed
         l5mMhMzEDxqofvdOubkBWWGs65ORJkt+zaGSAV9aQA5t1uLYBJsFBhgLC48BTgQNoCKH
         PWZeMhru4oD6O65ADTSrE+gxzkVLbdw6C0MDoMADSSun8y1dqSu38YdLi6ds96pOKV99
         I6vLUUSjk/HPSag0EsY8qfAcQlrFMqxoWrsnHepRjZkqewSZFqdrbBR43eW1pEx2hApq
         GZCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=TvaOJBAIvNxAg3dFoJJOVlV+NfsswdVw/SLF3Bn6Td0=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=JnohARKRaLWgXMJ6ZE2DWG9Lx7exeh58QqH6pXV4oRHHW4DFICI4DFmrnTF1f9HTzz
         4oOtwNUEIkdY3IJJ1iJyz0dyvk+BGR/o5Gt57gnPEHSLFkGU2rCIUlnywS/d1YBUwOnk
         d4oB9kPo5WmcT9p5VUB4P5RVFJUzzyjbCo41RUxpGXx19Vfbs/dtQagjmcOohH72CkTk
         Cc2vPHpGMrBNFmBYrOBCXGeiBulXCFTEUuL1XBGfg7qIJKLhLihWPt991MwL0rPp2E6G
         bLubWD7TE99/Hxqw9h1egKAxu4agbbpponsHLysJH8O1Xqz/J0SJsi5Jq/5s6OHI33Aj
         ag0Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=K0YdkMUJ;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-598f2f73c39si57938e87.6.2025.12.11.04.26.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Dec 2025 04:26:44 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 2001-1c00-8d85-5700-266e-96ff-fe07-7dcc.cable.dynamic.v6.ziggo.nl ([2001:1c00:8d85:5700:266e:96ff:fe07:7dcc] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vTetE-0000000EuI9-0zph;
	Thu, 11 Dec 2025 11:31:20 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 9A28A30301A; Thu, 11 Dec 2025 13:26:36 +0100 (CET)
Date: Thu, 11 Dec 2025 13:26:36 +0100
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
Subject: Re: [PATCH v4 16/35] kref: Add context-analysis annotations
Message-ID: <20251211122636.GI3911114@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251120151033.3840508-17-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251120151033.3840508-17-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=K0YdkMUJ;
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

On Thu, Nov 20, 2025 at 04:09:41PM +0100, Marco Elver wrote:
> Mark functions that conditionally acquire the passed lock.
> 
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/kref.h | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/include/linux/kref.h b/include/linux/kref.h
> index 88e82ab1367c..9bc6abe57572 100644
> --- a/include/linux/kref.h
> +++ b/include/linux/kref.h
> @@ -81,6 +81,7 @@ static inline int kref_put(struct kref *kref, void (*release)(struct kref *kref)
>  static inline int kref_put_mutex(struct kref *kref,
>  				 void (*release)(struct kref *kref),
>  				 struct mutex *mutex)
> +	__cond_acquires(true, mutex)
>  {
>  	if (refcount_dec_and_mutex_lock(&kref->refcount, mutex)) {
>  		release(kref);
> @@ -102,6 +103,7 @@ static inline int kref_put_mutex(struct kref *kref,
>  static inline int kref_put_lock(struct kref *kref,
>  				void (*release)(struct kref *kref),
>  				spinlock_t *lock)
> +	__cond_acquires(true, lock)
>  {
>  	if (refcount_dec_and_lock(&kref->refcount, lock)) {
>  		release(kref);
> -- 
> 2.52.0.rc1.455.g30608eb744-goog
> 

Note that both use the underlying refcount_dec_and_*lock() functions.
Its a bit sad that annotation those isn't sufficient. These are inline
functions after all, the compiler should be able to see through all that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251211122636.GI3911114%40noisy.programming.kicks-ass.net.
