Return-Path: <kasan-dev+bncBDV2D5O34IDRB4XFS7XQKGQEU2WJQKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 12E9C10F74B
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Dec 2019 06:30:28 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id i196sf1486705pfe.6
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Dec 2019 21:30:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575351026; cv=pass;
        d=google.com; s=arc-20160816;
        b=V41waWDLFzq98StBcd2XCeqHmyTqzGZ0+Y7MQLdftjONI6KBVEh5xCvdnteTRndPx1
         8Ph9ZmjCSDqpJ/FkWJwcH2MZGS7wtBB4Xj/+d7O9kYiUtZhrjSrDHngYe5653PVy5oN0
         raL9jKZp0F/ntHuU9POChvv9xgZTobGVWtuy9UXwB+p0Nv1yFKqs/XqGiRXkYjc8pd6F
         8WtAs3psiq9JNoLUSXvZxPa0AkvbGw10LMIEci/Sbh/8fCsHTpjvh72FGxrGNHBEuEL8
         e3vfrLKk5BBXDDfomhiSr1wLGrpwqiAW6zk68lZtXLpY87c/XkB1EjZp4AbvuS2DByyM
         WRgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=ZkkwzW+xtRHW6j3FP/BNd3nO25LsutuMwQVxOQdx8To=;
        b=yEYcpwHKkZ6c9XaYqt6Gy6I9JCZ0v+CyFkpp+KOwoEPmWCI8Xa+fpenOwybweUstD+
         fGqiKNfBGKaFLoj4iAGWyzkRghAQPfPo1ZO8RI3+pIk68ueZPK+hLOiNitFBk2n7DaOF
         Zz5AXdMhty/h7sTRhpUw1EShSumFjGFDcEU1TGzTnH7KpVQc8PaX7VgHJ9ih9TufdUQP
         PWB3e37/BW8bfu4CIIJd8wX3vo4U0nTRC62FZc9QTG3erm3qNqo0bmJJ0dsRACRqflQl
         HZvg6uFNhMCkSoxuqXpXJFxJL7i6nLibR5WAIcwCKaz+zL7ODA9vfwbBBu+L027jujoY
         T5oA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=Eo2Tw1qp;
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZkkwzW+xtRHW6j3FP/BNd3nO25LsutuMwQVxOQdx8To=;
        b=MUcaQ4KLUQH1WTPQnAbIU7wFGzYYPMqpkVW0f6ORKfH0hJkCo4PpHYnF58Nr4X3OZY
         EJP/88jIVMtlVReVRv37hOKuUEcxW07u8bwqz9CYHP/h43QQy2XEQd+yznY1u2odUOIC
         GdGLi0HKKu7Z0tLxniQaKaoqSUBdvkJw7Ij9Wjq4PG1ywgxPGMreZ+L2AKt+ea7blWer
         f7B3y8kV1SIWuldZ6JjnUJtpa1eCcqvsZpcADtHFn2VL+EfD5egFLdPiHtVfQy9M7Zwv
         glEyRmM/kIDlNRpxLk8dSxpdUsuJCIcJTeVnGjRDJEisapqiZn9/CIzDzV/lDWL/uojz
         cF1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZkkwzW+xtRHW6j3FP/BNd3nO25LsutuMwQVxOQdx8To=;
        b=pUk/rw/0LNS9E3I74GIWzZ1hFar7au/P0oZ4oR1JjSGL7IGFdU6OrTS6sbf0L3yzCj
         lLi17Ql5e+Wj8ZJisCtXFW6lEq7bk8HsmgXHSUtCuP30hkv3Nnmn/50i4CIrhy9zD9jX
         Op14R8NN4SbBswmusupmJP0rD668b6LPbRPquQmm0TpO1FcOpkl53xVwYK6mrqvh/IFU
         GZlD8bo4y9xzsSgIAzguua8ml9gV3OaSyJIIeGHtv7Jcv6DkOrnl5CslgTFKmhakdHvB
         Jo6D4MV9LVwxQiFx9fPqYUo59c5CTh4Ak3SYDA0wbqIoRd22t3wmslNATya5yvKa8UJY
         jpLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUK8uPS8ZTt/9u19820B+fbrHp3OvNg4nHYT9iJQRpDWWUOQz2Q
	WsM8yWgu7sCv9itdxv+1qe8=
X-Google-Smtp-Source: APXvYqyr+CLvHRK10mFLoRULVUdrCoFs6P3w8yQhLgpPsbKbbRo7wA9cDWj1Fn/J00zFOqvvyqQLQg==
X-Received: by 2002:a63:fa04:: with SMTP id y4mr3459263pgh.413.1575351026687;
        Mon, 02 Dec 2019 21:30:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:cf8a:: with SMTP id i10ls481887pju.4.canary-gmail;
 Mon, 02 Dec 2019 21:30:26 -0800 (PST)
X-Received: by 2002:a17:902:d717:: with SMTP id w23mr3097804ply.142.1575351026240;
        Mon, 02 Dec 2019 21:30:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575351026; cv=none;
        d=google.com; s=arc-20160816;
        b=0or6oyxW59o3nM0abTdERKZKQt8WJ3E5kgbf1bNdpt17V/08zMxF/DN897Qn09gaS4
         rjTJejLVhhrKQKpf623dWHEn+Hm4CL9WBMdB2pC2DeMV/fl7gRPLfutuF8b4VF12osYb
         f/laBxfAIRHOX9CUBfxnhpx8aBlxAeMbnvGHQdjZVN9jlVx2+N1RPHkUzAPfFTlW/nCv
         ZiO7m0ysDn9J5grxlJgXgFPX8Ypr39HC8A5LuH/CBNIO/qeVg0Vm7SFXuQrnG+vV0InP
         +q9O4vlLkoVnL1DcxYPuyztJ/JLVBf/SQLHNlfw5UQplyh4q5hPLV3rGXWTiih489g9/
         4c2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=fasHx2KRVQANkAag/rtzNmdYDi10qgh4xlJuuHfsM7I=;
        b=hhSNk3pjT++/WdhVB0cNj6SCbClZD0adi/Oci4EgpIOaU1fr/fUFiYoOPbxbDA57kw
         xfRhr6b2FO3xTwBfwdj+zkFyKDrhnEQP7Sjxqcp7q15nf6BkA81teGskm8ytxRzIzaau
         DuOcgFZD2Ws+4kYgqrjoHIEEJGBxu0arU6sv7Yech0CQMYoFEL6wFgPsuu8+wxh5sbor
         Ous5BhN5LE3l642xp/DofsV9mNF89ARQhhCzht8NsbkPRZDcEPqffysYETLE1inSwlSH
         wWbiMedtGMrP9bhX4YZJ9fGWjrAN34ZSa3SVJz9SfTRzt0l0vx8xwmohsep6TPAyA/qn
         h9ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=Eo2Tw1qp;
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id n12si148435pgr.5.2019.12.02.21.30.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Dec 2019 21:30:26 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from [2601:1c0:6280:3f0::5a22]
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1ic0lU-0007lO-O8; Tue, 03 Dec 2019 05:30:24 +0000
Subject: Re: [PATCH v3 3/3] kcsan: Prefer __always_inline for fast-path
To: Marco Elver <elver@google.com>
Cc: mark.rutland@arm.com, paulmck@kernel.org, linux-kernel@vger.kernel.org,
 will@kernel.org, peterz@infradead.org, boqun.feng@gmail.com, arnd@arndb.de,
 dvyukov@google.com, linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
References: <20191126140406.164870-1-elver@google.com>
 <20191126140406.164870-3-elver@google.com>
From: Randy Dunlap <rdunlap@infradead.org>
Message-ID: <00ee3b40-0e37-c9ac-3209-d07b233a0c1d@infradead.org>
Date: Mon, 2 Dec 2019 21:30:22 -0800
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.1
MIME-Version: 1.0
In-Reply-To: <20191126140406.164870-3-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=Eo2Tw1qp;
       spf=pass (google.com: best guess record for domain of
 rdunlap@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
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

On 11/26/19 6:04 AM, Marco Elver wrote:
> Prefer __always_inline for fast-path functions that are called outside
> of user_access_save, to avoid generating UACCESS warnings when
> optimizing for size (CC_OPTIMIZE_FOR_SIZE). It will also avoid future
> surprises with compiler versions that change the inlining heuristic even
> when optimizing for performance.
> 
> Report: http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
> Reported-by: Randy Dunlap <rdunlap@infradead.org>
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Randy Dunlap <rdunlap@infradead.org> # build-tested

Thanks.

> ---
> Rebased on: locking/kcsan branch of tip tree.
> ---
>  kernel/kcsan/atomic.h   |  2 +-
>  kernel/kcsan/core.c     | 16 +++++++---------
>  kernel/kcsan/encoding.h | 14 +++++++-------
>  3 files changed, 15 insertions(+), 17 deletions(-)
> 
> diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
> index 576e03ddd6a3..a9c193053491 100644
> --- a/kernel/kcsan/atomic.h
> +++ b/kernel/kcsan/atomic.h
> @@ -18,7 +18,7 @@
>   * than cast to volatile. Eventually, we hope to be able to remove this
>   * function.
>   */
> -static inline bool kcsan_is_atomic(const volatile void *ptr)
> +static __always_inline bool kcsan_is_atomic(const volatile void *ptr)
>  {
>  	/* only jiffies for now */
>  	return ptr == &jiffies;
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 3314fc29e236..c616fec639cd 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -78,10 +78,8 @@ static atomic_long_t watchpoints[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS-1];
>   */
>  static DEFINE_PER_CPU(long, kcsan_skip);
>  
> -static inline atomic_long_t *find_watchpoint(unsigned long addr,
> -					     size_t size,
> -					     bool expect_write,
> -					     long *encoded_watchpoint)
> +static __always_inline atomic_long_t *
> +find_watchpoint(unsigned long addr, size_t size, bool expect_write, long *encoded_watchpoint)
>  {
>  	const int slot = watchpoint_slot(addr);
>  	const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
> @@ -146,7 +144,7 @@ insert_watchpoint(unsigned long addr, size_t size, bool is_write)
>   *	2. the thread that set up the watchpoint already removed it;
>   *	3. the watchpoint was removed and then re-used.
>   */
> -static inline bool
> +static __always_inline bool
>  try_consume_watchpoint(atomic_long_t *watchpoint, long encoded_watchpoint)
>  {
>  	return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint, CONSUMED_WATCHPOINT);
> @@ -160,7 +158,7 @@ static inline bool remove_watchpoint(atomic_long_t *watchpoint)
>  	return atomic_long_xchg_relaxed(watchpoint, INVALID_WATCHPOINT) != CONSUMED_WATCHPOINT;
>  }
>  
> -static inline struct kcsan_ctx *get_ctx(void)
> +static __always_inline struct kcsan_ctx *get_ctx(void)
>  {
>  	/*
>  	 * In interrupts, use raw_cpu_ptr to avoid unnecessary checks, that would
> @@ -169,7 +167,7 @@ static inline struct kcsan_ctx *get_ctx(void)
>  	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
>  }
>  
> -static inline bool is_atomic(const volatile void *ptr)
> +static __always_inline bool is_atomic(const volatile void *ptr)
>  {
>  	struct kcsan_ctx *ctx = get_ctx();
>  
> @@ -193,7 +191,7 @@ static inline bool is_atomic(const volatile void *ptr)
>  	return kcsan_is_atomic(ptr);
>  }
>  
> -static inline bool should_watch(const volatile void *ptr, int type)
> +static __always_inline bool should_watch(const volatile void *ptr, int type)
>  {
>  	/*
>  	 * Never set up watchpoints when memory operations are atomic.
> @@ -226,7 +224,7 @@ static inline void reset_kcsan_skip(void)
>  	this_cpu_write(kcsan_skip, skip_count);
>  }
>  
> -static inline bool kcsan_is_enabled(void)
> +static __always_inline bool kcsan_is_enabled(void)
>  {
>  	return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
>  }
> diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
> index b63890e86449..f03562aaf2eb 100644
> --- a/kernel/kcsan/encoding.h
> +++ b/kernel/kcsan/encoding.h
> @@ -59,10 +59,10 @@ encode_watchpoint(unsigned long addr, size_t size, bool is_write)
>  		      (addr & WATCHPOINT_ADDR_MASK));
>  }
>  
> -static inline bool decode_watchpoint(long watchpoint,
> -				     unsigned long *addr_masked,
> -				     size_t *size,
> -				     bool *is_write)
> +static __always_inline bool decode_watchpoint(long watchpoint,
> +					      unsigned long *addr_masked,
> +					      size_t *size,
> +					      bool *is_write)
>  {
>  	if (watchpoint == INVALID_WATCHPOINT ||
>  	    watchpoint == CONSUMED_WATCHPOINT)
> @@ -78,13 +78,13 @@ static inline bool decode_watchpoint(long watchpoint,
>  /*
>   * Return watchpoint slot for an address.
>   */
> -static inline int watchpoint_slot(unsigned long addr)
> +static __always_inline int watchpoint_slot(unsigned long addr)
>  {
>  	return (addr / PAGE_SIZE) % CONFIG_KCSAN_NUM_WATCHPOINTS;
>  }
>  
> -static inline bool matching_access(unsigned long addr1, size_t size1,
> -				   unsigned long addr2, size_t size2)
> +static __always_inline bool matching_access(unsigned long addr1, size_t size1,
> +					    unsigned long addr2, size_t size2)
>  {
>  	unsigned long end_range1 = addr1 + size1 - 1;
>  	unsigned long end_range2 = addr2 + size2 - 1;
> 


-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/00ee3b40-0e37-c9ac-3209-d07b233a0c1d%40infradead.org.
