Return-Path: <kasan-dev+bncBAABBX4V2LXQKGQEPX5V3KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FF6E11F0AC
	for <lists+kasan-dev@lfdr.de>; Sat, 14 Dec 2019 08:10:25 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id v17sf1275400qvi.3
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 23:10:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576307424; cv=pass;
        d=google.com; s=arc-20160816;
        b=vj+tKnlthry1t+04nwVJp8SMhqqs5TZHMHL4T7RtAZNEgGtREhnbjDP9OeALPvInwh
         bAsEM+XhG86lgWrCkm3T34Ku+f60yHk3Z0CvttIaBpy1lykntbC+r528/8TCoOl0zH63
         YMZAQ2tt4XFSEyBSiz75mgccNNWLH5zy+3nWlRMqxAchPYrStgXA6WJWM3w/XF4UFv4K
         AiY6hJnljeExu9yA0vutFmeSIEnFQPeAb9VXTVKm+Ds643GvbWzNB2VTR1V8GXUQ+FnE
         kXhNPBMNFApiFvbivHokzosmSYxCSF/RNft3eQscvP0syrDg08DoFpNNw4eaU1NvQ25v
         M3ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=RTKW+OC4ekb+Esopz4YDM+r37f5MhAdnS9SB2untErc=;
        b=P6Hojr+1UrIGL8z4O1/rqKRZW6F/1GDkqahC5/nORPvsgPhs3zyKe7qONWRRushQZp
         lAX4jHf5F75w/7TRH7EHbswjWlnXc7d0wDwzS81761VYCSxILw08EpkBmriliEc0b6Zk
         fPOSWcNnJ4mhmVVppdv3mPxumH64sjBeedCbTCgrwbXOAq2YYBj0wv5WzPNhmQms3s7j
         Pfh8u+tfnuyg2/vA2e0BC9vHTG2AMYk8NSWBmvd67STbS+ndmvBMGbzmX3UFfhgz1dQD
         g2WtPEpxcSSwwRQooaMPpiauYsLG5ctiCbffyFJ6DaaYXXmqFC9K9gjyT8XESDnUWXzo
         J34w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=HSQWPjta;
       spf=pass (google.com: domain of srs0=y4ex=2e=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=y4Ex=2E=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RTKW+OC4ekb+Esopz4YDM+r37f5MhAdnS9SB2untErc=;
        b=LcQlPFhqS+VcEQZD28B0d5SDPtDI3xkcHpjz8XFznV6vMZVFf46vONN279UIRe5V9l
         xB0Flu3yBuYyRHiu3r3ZLa+7duccOmjk5Ex/KzursJ7pQo5Z/go2rE4fCYiWI1rOoE8Q
         gDWt2YSrDIkiQjpd32PjClJAqb3FL+fgPP7CflUB9j8I54F2Zu/yTfc0A7H4RVmsEW1J
         v/KTDVJrRHxBge5zUq5EJaQwINKxbZaI7QVGhlMKZ2MpaEUUf5Oyp2dyyg199jKV4EI+
         Q212/OkT0iRg/1OQUJ/zVUUX9r41SHyGSaewkY7xjiU6EOeMb9K013wcVz0K7ZMxbepW
         YBWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RTKW+OC4ekb+Esopz4YDM+r37f5MhAdnS9SB2untErc=;
        b=N6YMfece/0ZGO5uku4o5+CGgc8NGC5ckZy70EsP4D7ULueX4Ns5nvlZZsGlaO/byus
         Zd3BSzSCyf7wvU1jtsaZ1Qh2i4nCcgNCG/eisWIsx+No/PZzOVx97N4uvEhWz8pynyn4
         pVGSYLfScqCWiW67t+0mZ+RzG2L9GS0Sb+Jot1+BFDtw9RzTKbik4kx+bSY2A+utQIt0
         s8DdmEGbyJP+mc8IoMcVC2u3zazB1QA2JcsUS8MLAY2zda6t+739iIFRZt2FBF40h9yT
         z4vNUktLF2PLDgAD4GHSOMocUPrHxCvYtksrc9yxZGOTrrTDNuPdhg9H70x/+8/GsmU2
         96zw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWU8J/2zCqxU0ril/PrBdboCerdM9UErC1SozxyoNUpMxIW7L39
	yleWCgTSVv5idDOxOscNa+s=
X-Google-Smtp-Source: APXvYqzP2e6XxfbYfCkpwpZDvAXnJBAm64so0CmJzadQGy3OeFWTqeR5CIJMQvfDHikOONX+D6JgsQ==
X-Received: by 2002:a05:620a:133a:: with SMTP id p26mr17515940qkj.50.1576307423662;
        Fri, 13 Dec 2019 23:10:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:110c:: with SMTP id e12ls1893839qvs.3.gmail; Fri,
 13 Dec 2019 23:10:23 -0800 (PST)
X-Received: by 2002:a0c:f404:: with SMTP id h4mr1672548qvl.251.1576307423299;
        Fri, 13 Dec 2019 23:10:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576307423; cv=none;
        d=google.com; s=arc-20160816;
        b=GFmtLYWV1h5tDUUR+O96CQrYSvYDcyWqDcbjzQodowjWdfokuxtc5v4E8xoQj+Tou9
         SfU8UC53lcw5Sfevdw0zZf78UhzJXk+ZGqxE12QCI2QMcAJZCH3gMnwtNmCBhcIrzOmY
         TkTjBIITBjAZanCePk3X32vP+xMJ37PmraeG/nWsggvljwS/v+HuB+mPTuACyIvVm75l
         7mtfbgY8tuU2mIEQ9x3ups9sQYa1fZRENYseDk3vTBCwdPNqFThqew2A9rT48BPM8DAl
         /2lKmvw5UqASPRdngruZadoTy4MSHT6zs22YzuAahbo5X+ZEhQ8+zO04v6WU9hxILOcV
         WJbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=mEHpL/68zEg2GZVyYKydIefjzjK8uwYyruXqtUPzGQo=;
        b=GuV+FntipjjvRwcRsZN018z+Fm48+1XEY9Cdwpj5+kLuyQ1Cj772CdgN8xgEQIUz2O
         iHxr+3QVTEnpE24velqWhWeuDyvRZpnLJJ/RkFHEmr9xsm3f/wy0zl024LkQBiRndxFz
         NYnjkcz4+IoVM2/cpnVUBwtEYAMUhaQ3cABrGYejcmpeBucRRpPUGbFn50bKFJ/OV0A2
         3UnnzRNa7fiTHjqDLSYRlD5+wqbg4nPE11uOa+tSMEKETcIjWpQMyd62IUg83rwVziim
         RoMdNtNWWaUFIj1h1dez+wzU0zeJ5BZLJT11Ebv1tuZmFozwGvzdQs440Ei28hQhoic3
         VQ4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=HSQWPjta;
       spf=pass (google.com: domain of srs0=y4ex=2e=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=y4Ex=2E=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h17si584629qtm.0.2019.12.13.23.10.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 13 Dec 2019 23:10:23 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=y4ex=2e=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 403C120724;
	Sat, 14 Dec 2019 07:10:22 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 05C6F352276B; Fri, 13 Dec 2019 23:10:22 -0800 (PST)
Date: Fri, 13 Dec 2019 23:10:22 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	dvyukov@google.com, Randy Dunlap <rdunlap@infradead.org>
Subject: Re: [PATCH RESEND -rcu/kcsan] kcsan: Prefer __always_inline for
 fast-path
Message-ID: <20191214071021.GJ2889@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20191213204946.251125-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191213204946.251125-1-elver@google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=HSQWPjta;       spf=pass
 (google.com: domain of srs0=y4ex=2e=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=y4Ex=2E=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Dec 13, 2019 at 09:49:46PM +0100, Marco Elver wrote:
> Prefer __always_inline for fast-path functions that are called outside
> of user_access_save, to avoid generating UACCESS warnings when
> optimizing for size (CC_OPTIMIZE_FOR_SIZE). It will also avoid future
> surprises with compiler versions that change the inlining heuristic even
> when optimizing for performance.
> 
> Report: http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
> Reported-by: Randy Dunlap <rdunlap@infradead.org>
> Acked-by: Randy Dunlap <rdunlap@infradead.org> # build-tested
> Signed-off-by: Marco Elver <elver@google.com>

Queued for review and testing, thank you!

							Thanx, Paul

> ---
> Version rebased on -rcu/kcsan.
> 
> There are 3 locations that would conflict with the style cleanup in
> -tip/locking/kcsan:
> https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git/commit/?h=locking/kcsan&id=5cbaefe9743bf14c9d3106db0cc19f8cb0a3ca22
> 
> For the conflicting locations the better style is carried over, so that
> upon eventual merge the resolution should be trivial.
> ---
>  kernel/kcsan/atomic.h   |  2 +-
>  kernel/kcsan/core.c     | 17 ++++++++---------
>  kernel/kcsan/encoding.h | 11 +++++------
>  3 files changed, 14 insertions(+), 16 deletions(-)
> 
> diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
> index c9c3fe628011..466e6777533e 100644
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
> index d9410d58c93e..69870645b631 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -78,9 +78,8 @@ static atomic_long_t watchpoints[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS - 1];
>   */
>  static DEFINE_PER_CPU(long, kcsan_skip);
>  
> -static inline atomic_long_t *find_watchpoint(unsigned long addr, size_t size,
> -					     bool expect_write,
> -					     long *encoded_watchpoint)
> +static __always_inline atomic_long_t *
> +find_watchpoint(unsigned long addr, size_t size, bool expect_write, long *encoded_watchpoint)
>  {
>  	const int slot = watchpoint_slot(addr);
>  	const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
> @@ -150,8 +149,8 @@ static inline atomic_long_t *insert_watchpoint(unsigned long addr, size_t size,
>   *	2. the thread that set up the watchpoint already removed it;
>   *	3. the watchpoint was removed and then re-used.
>   */
> -static inline bool try_consume_watchpoint(atomic_long_t *watchpoint,
> -					  long encoded_watchpoint)
> +static __always_inline bool
> +try_consume_watchpoint(atomic_long_t *watchpoint, long encoded_watchpoint)
>  {
>  	return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint,
>  					       CONSUMED_WATCHPOINT);
> @@ -166,7 +165,7 @@ static inline bool remove_watchpoint(atomic_long_t *watchpoint)
>  	       CONSUMED_WATCHPOINT;
>  }
>  
> -static inline struct kcsan_ctx *get_ctx(void)
> +static __always_inline struct kcsan_ctx *get_ctx(void)
>  {
>  	/*
>  	 * In interrupt, use raw_cpu_ptr to avoid unnecessary checks, that would
> @@ -175,7 +174,7 @@ static inline struct kcsan_ctx *get_ctx(void)
>  	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
>  }
>  
> -static inline bool is_atomic(const volatile void *ptr)
> +static __always_inline bool is_atomic(const volatile void *ptr)
>  {
>  	struct kcsan_ctx *ctx = get_ctx();
>  
> @@ -199,7 +198,7 @@ static inline bool is_atomic(const volatile void *ptr)
>  	return kcsan_is_atomic(ptr);
>  }
>  
> -static inline bool should_watch(const volatile void *ptr, int type)
> +static __always_inline bool should_watch(const volatile void *ptr, int type)
>  {
>  	/*
>  	 * Never set up watchpoints when memory operations are atomic.
> @@ -232,7 +231,7 @@ static inline void reset_kcsan_skip(void)
>  	this_cpu_write(kcsan_skip, skip_count);
>  }
>  
> -static inline bool kcsan_is_enabled(void)
> +static __always_inline bool kcsan_is_enabled(void)
>  {
>  	return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
>  }
> diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
> index e17bdac0e54b..e527e83ce825 100644
> --- a/kernel/kcsan/encoding.h
> +++ b/kernel/kcsan/encoding.h
> @@ -58,9 +58,8 @@ static inline long encode_watchpoint(unsigned long addr, size_t size,
>  		      (addr & WATCHPOINT_ADDR_MASK));
>  }
>  
> -static inline bool decode_watchpoint(long watchpoint,
> -				     unsigned long *addr_masked, size_t *size,
> -				     bool *is_write)
> +static __always_inline bool
> +decode_watchpoint(long watchpoint, unsigned long *addr_masked, size_t *size, bool *is_write)
>  {
>  	if (watchpoint == INVALID_WATCHPOINT ||
>  	    watchpoint == CONSUMED_WATCHPOINT)
> @@ -77,13 +76,13 @@ static inline bool decode_watchpoint(long watchpoint,
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
> -- 
> 2.24.1.735.g03f4e72817-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191214071021.GJ2889%40paulmck-ThinkPad-P72.
