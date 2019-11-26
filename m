Return-Path: <kasan-dev+bncBDV37XP3XYDRBMF26TXAKGQECGNMPBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 98AA9109E25
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 13:40:16 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id u12sf374054wrt.15
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 04:40:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574772016; cv=pass;
        d=google.com; s=arc-20160816;
        b=UbkggFP/bMJmdSZgIn7TnjFdf+/pSipza8jmbvzuOwIMpYchzOAp7l3U4YQmQz/xlE
         9Fbr0j91LraanZ1Rfgh8uzmhT5p7Bp9GkPCYy7PX8OJkD23kL/2r/GAViZ0/PnXgu410
         9yL48UdQHWB6PI9J8AXLUG5msrIj7h4xwz0MwbIqru68FZd57vUlhag/dFAfAVEkyrnF
         m2Ut66UpUL+0x+uxLNxJlC8h0P9xd8cWvCDnBpk+DNPl3q+d2FuRsKpwC3Hpv0pnHWAv
         9umHovLq8l9Df/BNxbWQWxHTBUePLfGILgXGBobUsRrIR44arTLWAL3YuOS4Snne7A/K
         wZog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=f0FkMeW7sTX/KLyFMY1TkW/WrUtt4SrrHBAYjY6+co8=;
        b=LsuxTEAsdatEKk6tNvy5W9hxjMdq+um5DSmG0kVUCVw7NJGyRt04+g/LcJ27vFdP0+
         anWSyQD2rbRw9JCOFEt5GVy6eoTZLYoEOwHCYHHYgzs+uPok+YXFRwK43VQbxHwJf2mZ
         mMCfVeDntkR0v2XVV8NRdk8bTEZfMlb9tAzF9HGlTDSKDVtxra32OX3RgOjEYWzMjO9p
         FpX8SZRK4TtkSu80NKmwLv3dSl8kyi3RneSGGsSbtr3+AgYFJ6e/wLxchSGlQaxxk9Z9
         MT/Z33hkaHAwwq1zSv5FNi7s1BnNkby9FMJ9F5+pGWrLPo+9XoFZ3bm8i3wDHMvj/yd+
         Yz+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=f0FkMeW7sTX/KLyFMY1TkW/WrUtt4SrrHBAYjY6+co8=;
        b=higGUtDpRmJXY+thgzZuER9CbQIgUyu5hmwJcS10AydRCdK7Ybu3zF77bhC0/PIHTW
         rfoU8dejSWcnNPx+I0B5Tya2+UQmaCvXlM9hlVuXRjwPlK93t7HbvAFqGkY2m076I3YN
         b7wvXs/LUM/aMCqux6Ge3n7XrlnLn60QuNJsiVPa2A7Ri7JrnFLCsVoORpWEr5W/eRyQ
         i6NzUTTVy6UyB1yaSOyNp1fC+UF+bPa0b4FMmKzDllHWsCtJoX/MOyk3dQaMmU03veJu
         sSY/OR8xLlUy7GatvgiCq0YTbNQlAZFA9uR/r9KFr0RklkMYtCu5bbmCgp8kFMKD3e6v
         YLwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=f0FkMeW7sTX/KLyFMY1TkW/WrUtt4SrrHBAYjY6+co8=;
        b=g1QIvyWvY+adHS1gVKfiyfIdcdjN0C2zWHR1+KT5gL9Q+oJtowFYJzppWTbfZ21+ul
         JBHx2qDKqj7nSAJ20GSqlZuJd3c+W5s3KwOFvgRCXtoADx8aMl6eURmJqKkZISJ4T/hZ
         vY/cfzAfODyuSOXiYTyYI6F7bGNRgVs0w4bcvTR/2wX1ql+UDdbOVnbrKlqV1KProyq3
         Jmdhj6qzf06+NmZw7BuzrzUoQ+pZYE65jtrdQNTpupv1WevPi174fkXcEXt/eJcgrpg6
         n5tkKpkPBGS1wSl273ELRhi260036/rAg/ViBLP7IxejMIpUZ4NdUopMY6bxGFaJVREg
         X7jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV9QjqV25GJu6r/iEjWCUsU/KHykB4dKHqzOc6R+gx2yUU7n9E+
	f4AzobrHSfyEeYJc7SWnmOQ=
X-Google-Smtp-Source: APXvYqxjUNSISQY7QxK6lAUnHpAk96+lnrJEdtpiEN5ogm2UZyTRIU/XYQXwYhJvkWWTySPpojkAaA==
X-Received: by 2002:adf:e94e:: with SMTP id m14mr38087609wrn.233.1574772016187;
        Tue, 26 Nov 2019 04:40:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:4c17:: with SMTP id z23ls985728wmf.5.gmail; Tue, 26 Nov
 2019 04:40:15 -0800 (PST)
X-Received: by 2002:a7b:c7c7:: with SMTP id z7mr3964043wmk.85.1574772015314;
        Tue, 26 Nov 2019 04:40:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574772015; cv=none;
        d=google.com; s=arc-20160816;
        b=lR9nilyKVRGED2VtfekQU+QtTsvNuvQQSYJYmIsFOah1rA2wLr/cRwscKkKVUCTAiJ
         VBVubUTqh2u4Og2PJI5O/dS8fdmYujdnLUekD/xBs+QqYGAEfHhYhhY8vtPHNXdacElQ
         x1jXnktNAiUh/IJMooHNJ+Rhap/hVQnvFCYmlqe9y8U4lgDTRyE9XW4d+zo62cgdMQ1c
         ZA87iqbks7GItAGt9gwIw3V4YIEHEua2toUYUeUrrgb8F8Kr+kmZkGILS5NLQffG1coM
         e96vM0J4yb8xJ10K3C88tQwXphMDYO/mjMNcj09IJpsK/1Ilh/RjYk8/jnjc3ZtEI6lk
         raEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=zYkPJHQfsM2EXy8p0EbIuNOFlSni1dPaauvpNhO1Zyk=;
        b=PpItZrkmHyiHzjSpgZ0SeVzLR+FftL3b878dBIFzmkMmLHkrhSimcB1Clk1ndyxF6t
         Y5wPnmu3Md8kuWtIfDUZP5G/aEg6uM3bDbYLkx8/xRumdXZxVF0c2AsHS+sVKrvyEnEf
         B7jk0C24hO2khShX9RHs7w5eAhNyfRvuisUvNfepV3+m37/oJAuBgVljKBV4iA+rzJqV
         A2r3QhkKS1pQb1xu9RW4ki5O20RAl1E6x+oRfSq4QaZ64/0UVCznoxee4v7lyWiO0mev
         Ux4/b4WZBUirDgffZxTS27Ud6nZe8xqggCmF3Ca6wQs6ZIBwVEuC9KL6R8MQs91BMCSQ
         Vb+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id g3si356476wrw.5.2019.11.26.04.40.14
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Nov 2019 04:40:15 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 598661FB;
	Tue, 26 Nov 2019 04:40:14 -0800 (PST)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C38C93F52E;
	Tue, 26 Nov 2019 04:40:12 -0800 (PST)
Date: Tue, 26 Nov 2019 12:40:10 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: will@kernel.org, peterz@infradead.org, boqun.feng@gmail.com,
	arnd@arndb.de, dvyukov@google.com, linux-kernel@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com,
	paulmck@kernel.org
Subject: Re: [PATCH v2 2/3] asm-generic/atomic: Use __always_inline for
 fallback wrappers
Message-ID: <20191126124010.GB37833@lakrids.cambridge.arm.com>
References: <20191126114121.85552-1-elver@google.com>
 <20191126114121.85552-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191126114121.85552-2-elver@google.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Tue, Nov 26, 2019 at 12:41:20PM +0100, Marco Elver wrote:
> Use __always_inline for atomic fallback wrappers. When building for size
> (CC_OPTIMIZE_FOR_SIZE), some compilers appear to be less inclined to
> inline even relatively small static inline functions that are assumed to
> be inlinable such as atomic ops. This can cause problems, for example in
> UACCESS regions.
> 
> While the fallback wrappers aren't pure wrappers, they are trivial
> nonetheless, and the function they wrap should determine the final
> inlining policy.
> 
> For x86 tinyconfig we observe:
> - vmlinux baseline: 1315988
> - vmlinux with patch: 1315928 (-60 bytes)
> 
> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Mark Rutland <mark.rutland@arm.com>

Thanks for putting this together!

Mark.

> ---
> v2:
> * Add patch to series.
> ---
>  include/linux/atomic-fallback.h              | 340 ++++++++++---------
>  scripts/atomic/fallbacks/acquire             |   2 +-
>  scripts/atomic/fallbacks/add_negative        |   2 +-
>  scripts/atomic/fallbacks/add_unless          |   2 +-
>  scripts/atomic/fallbacks/andnot              |   2 +-
>  scripts/atomic/fallbacks/dec                 |   2 +-
>  scripts/atomic/fallbacks/dec_and_test        |   2 +-
>  scripts/atomic/fallbacks/dec_if_positive     |   2 +-
>  scripts/atomic/fallbacks/dec_unless_positive |   2 +-
>  scripts/atomic/fallbacks/fence               |   2 +-
>  scripts/atomic/fallbacks/fetch_add_unless    |   2 +-
>  scripts/atomic/fallbacks/inc                 |   2 +-
>  scripts/atomic/fallbacks/inc_and_test        |   2 +-
>  scripts/atomic/fallbacks/inc_not_zero        |   2 +-
>  scripts/atomic/fallbacks/inc_unless_negative |   2 +-
>  scripts/atomic/fallbacks/read_acquire        |   2 +-
>  scripts/atomic/fallbacks/release             |   2 +-
>  scripts/atomic/fallbacks/set_release         |   2 +-
>  scripts/atomic/fallbacks/sub_and_test        |   2 +-
>  scripts/atomic/fallbacks/try_cmpxchg         |   2 +-
>  scripts/atomic/gen-atomic-fallback.sh        |   2 +
>  21 files changed, 192 insertions(+), 188 deletions(-)
> 
> diff --git a/include/linux/atomic-fallback.h b/include/linux/atomic-fallback.h
> index a7d240e465c0..656b5489b673 100644
> --- a/include/linux/atomic-fallback.h
> +++ b/include/linux/atomic-fallback.h
> @@ -6,6 +6,8 @@
>  #ifndef _LINUX_ATOMIC_FALLBACK_H
>  #define _LINUX_ATOMIC_FALLBACK_H
>  
> +#include <linux/compiler.h>
> +
>  #ifndef xchg_relaxed
>  #define xchg_relaxed		xchg
>  #define xchg_acquire		xchg
> @@ -76,7 +78,7 @@
>  #endif /* cmpxchg64_relaxed */
>  
>  #ifndef atomic_read_acquire
> -static inline int
> +static __always_inline int
>  atomic_read_acquire(const atomic_t *v)
>  {
>  	return smp_load_acquire(&(v)->counter);
> @@ -85,7 +87,7 @@ atomic_read_acquire(const atomic_t *v)
>  #endif
>  
>  #ifndef atomic_set_release
> -static inline void
> +static __always_inline void
>  atomic_set_release(atomic_t *v, int i)
>  {
>  	smp_store_release(&(v)->counter, i);
> @@ -100,7 +102,7 @@ atomic_set_release(atomic_t *v, int i)
>  #else /* atomic_add_return_relaxed */
>  
>  #ifndef atomic_add_return_acquire
> -static inline int
> +static __always_inline int
>  atomic_add_return_acquire(int i, atomic_t *v)
>  {
>  	int ret = atomic_add_return_relaxed(i, v);
> @@ -111,7 +113,7 @@ atomic_add_return_acquire(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_add_return_release
> -static inline int
> +static __always_inline int
>  atomic_add_return_release(int i, atomic_t *v)
>  {
>  	__atomic_release_fence();
> @@ -121,7 +123,7 @@ atomic_add_return_release(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_add_return
> -static inline int
> +static __always_inline int
>  atomic_add_return(int i, atomic_t *v)
>  {
>  	int ret;
> @@ -142,7 +144,7 @@ atomic_add_return(int i, atomic_t *v)
>  #else /* atomic_fetch_add_relaxed */
>  
>  #ifndef atomic_fetch_add_acquire
> -static inline int
> +static __always_inline int
>  atomic_fetch_add_acquire(int i, atomic_t *v)
>  {
>  	int ret = atomic_fetch_add_relaxed(i, v);
> @@ -153,7 +155,7 @@ atomic_fetch_add_acquire(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_add_release
> -static inline int
> +static __always_inline int
>  atomic_fetch_add_release(int i, atomic_t *v)
>  {
>  	__atomic_release_fence();
> @@ -163,7 +165,7 @@ atomic_fetch_add_release(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_add
> -static inline int
> +static __always_inline int
>  atomic_fetch_add(int i, atomic_t *v)
>  {
>  	int ret;
> @@ -184,7 +186,7 @@ atomic_fetch_add(int i, atomic_t *v)
>  #else /* atomic_sub_return_relaxed */
>  
>  #ifndef atomic_sub_return_acquire
> -static inline int
> +static __always_inline int
>  atomic_sub_return_acquire(int i, atomic_t *v)
>  {
>  	int ret = atomic_sub_return_relaxed(i, v);
> @@ -195,7 +197,7 @@ atomic_sub_return_acquire(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_sub_return_release
> -static inline int
> +static __always_inline int
>  atomic_sub_return_release(int i, atomic_t *v)
>  {
>  	__atomic_release_fence();
> @@ -205,7 +207,7 @@ atomic_sub_return_release(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_sub_return
> -static inline int
> +static __always_inline int
>  atomic_sub_return(int i, atomic_t *v)
>  {
>  	int ret;
> @@ -226,7 +228,7 @@ atomic_sub_return(int i, atomic_t *v)
>  #else /* atomic_fetch_sub_relaxed */
>  
>  #ifndef atomic_fetch_sub_acquire
> -static inline int
> +static __always_inline int
>  atomic_fetch_sub_acquire(int i, atomic_t *v)
>  {
>  	int ret = atomic_fetch_sub_relaxed(i, v);
> @@ -237,7 +239,7 @@ atomic_fetch_sub_acquire(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_sub_release
> -static inline int
> +static __always_inline int
>  atomic_fetch_sub_release(int i, atomic_t *v)
>  {
>  	__atomic_release_fence();
> @@ -247,7 +249,7 @@ atomic_fetch_sub_release(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_sub
> -static inline int
> +static __always_inline int
>  atomic_fetch_sub(int i, atomic_t *v)
>  {
>  	int ret;
> @@ -262,7 +264,7 @@ atomic_fetch_sub(int i, atomic_t *v)
>  #endif /* atomic_fetch_sub_relaxed */
>  
>  #ifndef atomic_inc
> -static inline void
> +static __always_inline void
>  atomic_inc(atomic_t *v)
>  {
>  	atomic_add(1, v);
> @@ -278,7 +280,7 @@ atomic_inc(atomic_t *v)
>  #endif /* atomic_inc_return */
>  
>  #ifndef atomic_inc_return
> -static inline int
> +static __always_inline int
>  atomic_inc_return(atomic_t *v)
>  {
>  	return atomic_add_return(1, v);
> @@ -287,7 +289,7 @@ atomic_inc_return(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_inc_return_acquire
> -static inline int
> +static __always_inline int
>  atomic_inc_return_acquire(atomic_t *v)
>  {
>  	return atomic_add_return_acquire(1, v);
> @@ -296,7 +298,7 @@ atomic_inc_return_acquire(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_inc_return_release
> -static inline int
> +static __always_inline int
>  atomic_inc_return_release(atomic_t *v)
>  {
>  	return atomic_add_return_release(1, v);
> @@ -305,7 +307,7 @@ atomic_inc_return_release(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_inc_return_relaxed
> -static inline int
> +static __always_inline int
>  atomic_inc_return_relaxed(atomic_t *v)
>  {
>  	return atomic_add_return_relaxed(1, v);
> @@ -316,7 +318,7 @@ atomic_inc_return_relaxed(atomic_t *v)
>  #else /* atomic_inc_return_relaxed */
>  
>  #ifndef atomic_inc_return_acquire
> -static inline int
> +static __always_inline int
>  atomic_inc_return_acquire(atomic_t *v)
>  {
>  	int ret = atomic_inc_return_relaxed(v);
> @@ -327,7 +329,7 @@ atomic_inc_return_acquire(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_inc_return_release
> -static inline int
> +static __always_inline int
>  atomic_inc_return_release(atomic_t *v)
>  {
>  	__atomic_release_fence();
> @@ -337,7 +339,7 @@ atomic_inc_return_release(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_inc_return
> -static inline int
> +static __always_inline int
>  atomic_inc_return(atomic_t *v)
>  {
>  	int ret;
> @@ -359,7 +361,7 @@ atomic_inc_return(atomic_t *v)
>  #endif /* atomic_fetch_inc */
>  
>  #ifndef atomic_fetch_inc
> -static inline int
> +static __always_inline int
>  atomic_fetch_inc(atomic_t *v)
>  {
>  	return atomic_fetch_add(1, v);
> @@ -368,7 +370,7 @@ atomic_fetch_inc(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_inc_acquire
> -static inline int
> +static __always_inline int
>  atomic_fetch_inc_acquire(atomic_t *v)
>  {
>  	return atomic_fetch_add_acquire(1, v);
> @@ -377,7 +379,7 @@ atomic_fetch_inc_acquire(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_inc_release
> -static inline int
> +static __always_inline int
>  atomic_fetch_inc_release(atomic_t *v)
>  {
>  	return atomic_fetch_add_release(1, v);
> @@ -386,7 +388,7 @@ atomic_fetch_inc_release(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_inc_relaxed
> -static inline int
> +static __always_inline int
>  atomic_fetch_inc_relaxed(atomic_t *v)
>  {
>  	return atomic_fetch_add_relaxed(1, v);
> @@ -397,7 +399,7 @@ atomic_fetch_inc_relaxed(atomic_t *v)
>  #else /* atomic_fetch_inc_relaxed */
>  
>  #ifndef atomic_fetch_inc_acquire
> -static inline int
> +static __always_inline int
>  atomic_fetch_inc_acquire(atomic_t *v)
>  {
>  	int ret = atomic_fetch_inc_relaxed(v);
> @@ -408,7 +410,7 @@ atomic_fetch_inc_acquire(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_inc_release
> -static inline int
> +static __always_inline int
>  atomic_fetch_inc_release(atomic_t *v)
>  {
>  	__atomic_release_fence();
> @@ -418,7 +420,7 @@ atomic_fetch_inc_release(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_inc
> -static inline int
> +static __always_inline int
>  atomic_fetch_inc(atomic_t *v)
>  {
>  	int ret;
> @@ -433,7 +435,7 @@ atomic_fetch_inc(atomic_t *v)
>  #endif /* atomic_fetch_inc_relaxed */
>  
>  #ifndef atomic_dec
> -static inline void
> +static __always_inline void
>  atomic_dec(atomic_t *v)
>  {
>  	atomic_sub(1, v);
> @@ -449,7 +451,7 @@ atomic_dec(atomic_t *v)
>  #endif /* atomic_dec_return */
>  
>  #ifndef atomic_dec_return
> -static inline int
> +static __always_inline int
>  atomic_dec_return(atomic_t *v)
>  {
>  	return atomic_sub_return(1, v);
> @@ -458,7 +460,7 @@ atomic_dec_return(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_dec_return_acquire
> -static inline int
> +static __always_inline int
>  atomic_dec_return_acquire(atomic_t *v)
>  {
>  	return atomic_sub_return_acquire(1, v);
> @@ -467,7 +469,7 @@ atomic_dec_return_acquire(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_dec_return_release
> -static inline int
> +static __always_inline int
>  atomic_dec_return_release(atomic_t *v)
>  {
>  	return atomic_sub_return_release(1, v);
> @@ -476,7 +478,7 @@ atomic_dec_return_release(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_dec_return_relaxed
> -static inline int
> +static __always_inline int
>  atomic_dec_return_relaxed(atomic_t *v)
>  {
>  	return atomic_sub_return_relaxed(1, v);
> @@ -487,7 +489,7 @@ atomic_dec_return_relaxed(atomic_t *v)
>  #else /* atomic_dec_return_relaxed */
>  
>  #ifndef atomic_dec_return_acquire
> -static inline int
> +static __always_inline int
>  atomic_dec_return_acquire(atomic_t *v)
>  {
>  	int ret = atomic_dec_return_relaxed(v);
> @@ -498,7 +500,7 @@ atomic_dec_return_acquire(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_dec_return_release
> -static inline int
> +static __always_inline int
>  atomic_dec_return_release(atomic_t *v)
>  {
>  	__atomic_release_fence();
> @@ -508,7 +510,7 @@ atomic_dec_return_release(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_dec_return
> -static inline int
> +static __always_inline int
>  atomic_dec_return(atomic_t *v)
>  {
>  	int ret;
> @@ -530,7 +532,7 @@ atomic_dec_return(atomic_t *v)
>  #endif /* atomic_fetch_dec */
>  
>  #ifndef atomic_fetch_dec
> -static inline int
> +static __always_inline int
>  atomic_fetch_dec(atomic_t *v)
>  {
>  	return atomic_fetch_sub(1, v);
> @@ -539,7 +541,7 @@ atomic_fetch_dec(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_dec_acquire
> -static inline int
> +static __always_inline int
>  atomic_fetch_dec_acquire(atomic_t *v)
>  {
>  	return atomic_fetch_sub_acquire(1, v);
> @@ -548,7 +550,7 @@ atomic_fetch_dec_acquire(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_dec_release
> -static inline int
> +static __always_inline int
>  atomic_fetch_dec_release(atomic_t *v)
>  {
>  	return atomic_fetch_sub_release(1, v);
> @@ -557,7 +559,7 @@ atomic_fetch_dec_release(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_dec_relaxed
> -static inline int
> +static __always_inline int
>  atomic_fetch_dec_relaxed(atomic_t *v)
>  {
>  	return atomic_fetch_sub_relaxed(1, v);
> @@ -568,7 +570,7 @@ atomic_fetch_dec_relaxed(atomic_t *v)
>  #else /* atomic_fetch_dec_relaxed */
>  
>  #ifndef atomic_fetch_dec_acquire
> -static inline int
> +static __always_inline int
>  atomic_fetch_dec_acquire(atomic_t *v)
>  {
>  	int ret = atomic_fetch_dec_relaxed(v);
> @@ -579,7 +581,7 @@ atomic_fetch_dec_acquire(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_dec_release
> -static inline int
> +static __always_inline int
>  atomic_fetch_dec_release(atomic_t *v)
>  {
>  	__atomic_release_fence();
> @@ -589,7 +591,7 @@ atomic_fetch_dec_release(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_dec
> -static inline int
> +static __always_inline int
>  atomic_fetch_dec(atomic_t *v)
>  {
>  	int ret;
> @@ -610,7 +612,7 @@ atomic_fetch_dec(atomic_t *v)
>  #else /* atomic_fetch_and_relaxed */
>  
>  #ifndef atomic_fetch_and_acquire
> -static inline int
> +static __always_inline int
>  atomic_fetch_and_acquire(int i, atomic_t *v)
>  {
>  	int ret = atomic_fetch_and_relaxed(i, v);
> @@ -621,7 +623,7 @@ atomic_fetch_and_acquire(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_and_release
> -static inline int
> +static __always_inline int
>  atomic_fetch_and_release(int i, atomic_t *v)
>  {
>  	__atomic_release_fence();
> @@ -631,7 +633,7 @@ atomic_fetch_and_release(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_and
> -static inline int
> +static __always_inline int
>  atomic_fetch_and(int i, atomic_t *v)
>  {
>  	int ret;
> @@ -646,7 +648,7 @@ atomic_fetch_and(int i, atomic_t *v)
>  #endif /* atomic_fetch_and_relaxed */
>  
>  #ifndef atomic_andnot
> -static inline void
> +static __always_inline void
>  atomic_andnot(int i, atomic_t *v)
>  {
>  	atomic_and(~i, v);
> @@ -662,7 +664,7 @@ atomic_andnot(int i, atomic_t *v)
>  #endif /* atomic_fetch_andnot */
>  
>  #ifndef atomic_fetch_andnot
> -static inline int
> +static __always_inline int
>  atomic_fetch_andnot(int i, atomic_t *v)
>  {
>  	return atomic_fetch_and(~i, v);
> @@ -671,7 +673,7 @@ atomic_fetch_andnot(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_andnot_acquire
> -static inline int
> +static __always_inline int
>  atomic_fetch_andnot_acquire(int i, atomic_t *v)
>  {
>  	return atomic_fetch_and_acquire(~i, v);
> @@ -680,7 +682,7 @@ atomic_fetch_andnot_acquire(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_andnot_release
> -static inline int
> +static __always_inline int
>  atomic_fetch_andnot_release(int i, atomic_t *v)
>  {
>  	return atomic_fetch_and_release(~i, v);
> @@ -689,7 +691,7 @@ atomic_fetch_andnot_release(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_andnot_relaxed
> -static inline int
> +static __always_inline int
>  atomic_fetch_andnot_relaxed(int i, atomic_t *v)
>  {
>  	return atomic_fetch_and_relaxed(~i, v);
> @@ -700,7 +702,7 @@ atomic_fetch_andnot_relaxed(int i, atomic_t *v)
>  #else /* atomic_fetch_andnot_relaxed */
>  
>  #ifndef atomic_fetch_andnot_acquire
> -static inline int
> +static __always_inline int
>  atomic_fetch_andnot_acquire(int i, atomic_t *v)
>  {
>  	int ret = atomic_fetch_andnot_relaxed(i, v);
> @@ -711,7 +713,7 @@ atomic_fetch_andnot_acquire(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_andnot_release
> -static inline int
> +static __always_inline int
>  atomic_fetch_andnot_release(int i, atomic_t *v)
>  {
>  	__atomic_release_fence();
> @@ -721,7 +723,7 @@ atomic_fetch_andnot_release(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_andnot
> -static inline int
> +static __always_inline int
>  atomic_fetch_andnot(int i, atomic_t *v)
>  {
>  	int ret;
> @@ -742,7 +744,7 @@ atomic_fetch_andnot(int i, atomic_t *v)
>  #else /* atomic_fetch_or_relaxed */
>  
>  #ifndef atomic_fetch_or_acquire
> -static inline int
> +static __always_inline int
>  atomic_fetch_or_acquire(int i, atomic_t *v)
>  {
>  	int ret = atomic_fetch_or_relaxed(i, v);
> @@ -753,7 +755,7 @@ atomic_fetch_or_acquire(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_or_release
> -static inline int
> +static __always_inline int
>  atomic_fetch_or_release(int i, atomic_t *v)
>  {
>  	__atomic_release_fence();
> @@ -763,7 +765,7 @@ atomic_fetch_or_release(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_or
> -static inline int
> +static __always_inline int
>  atomic_fetch_or(int i, atomic_t *v)
>  {
>  	int ret;
> @@ -784,7 +786,7 @@ atomic_fetch_or(int i, atomic_t *v)
>  #else /* atomic_fetch_xor_relaxed */
>  
>  #ifndef atomic_fetch_xor_acquire
> -static inline int
> +static __always_inline int
>  atomic_fetch_xor_acquire(int i, atomic_t *v)
>  {
>  	int ret = atomic_fetch_xor_relaxed(i, v);
> @@ -795,7 +797,7 @@ atomic_fetch_xor_acquire(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_xor_release
> -static inline int
> +static __always_inline int
>  atomic_fetch_xor_release(int i, atomic_t *v)
>  {
>  	__atomic_release_fence();
> @@ -805,7 +807,7 @@ atomic_fetch_xor_release(int i, atomic_t *v)
>  #endif
>  
>  #ifndef atomic_fetch_xor
> -static inline int
> +static __always_inline int
>  atomic_fetch_xor(int i, atomic_t *v)
>  {
>  	int ret;
> @@ -826,7 +828,7 @@ atomic_fetch_xor(int i, atomic_t *v)
>  #else /* atomic_xchg_relaxed */
>  
>  #ifndef atomic_xchg_acquire
> -static inline int
> +static __always_inline int
>  atomic_xchg_acquire(atomic_t *v, int i)
>  {
>  	int ret = atomic_xchg_relaxed(v, i);
> @@ -837,7 +839,7 @@ atomic_xchg_acquire(atomic_t *v, int i)
>  #endif
>  
>  #ifndef atomic_xchg_release
> -static inline int
> +static __always_inline int
>  atomic_xchg_release(atomic_t *v, int i)
>  {
>  	__atomic_release_fence();
> @@ -847,7 +849,7 @@ atomic_xchg_release(atomic_t *v, int i)
>  #endif
>  
>  #ifndef atomic_xchg
> -static inline int
> +static __always_inline int
>  atomic_xchg(atomic_t *v, int i)
>  {
>  	int ret;
> @@ -868,7 +870,7 @@ atomic_xchg(atomic_t *v, int i)
>  #else /* atomic_cmpxchg_relaxed */
>  
>  #ifndef atomic_cmpxchg_acquire
> -static inline int
> +static __always_inline int
>  atomic_cmpxchg_acquire(atomic_t *v, int old, int new)
>  {
>  	int ret = atomic_cmpxchg_relaxed(v, old, new);
> @@ -879,7 +881,7 @@ atomic_cmpxchg_acquire(atomic_t *v, int old, int new)
>  #endif
>  
>  #ifndef atomic_cmpxchg_release
> -static inline int
> +static __always_inline int
>  atomic_cmpxchg_release(atomic_t *v, int old, int new)
>  {
>  	__atomic_release_fence();
> @@ -889,7 +891,7 @@ atomic_cmpxchg_release(atomic_t *v, int old, int new)
>  #endif
>  
>  #ifndef atomic_cmpxchg
> -static inline int
> +static __always_inline int
>  atomic_cmpxchg(atomic_t *v, int old, int new)
>  {
>  	int ret;
> @@ -911,7 +913,7 @@ atomic_cmpxchg(atomic_t *v, int old, int new)
>  #endif /* atomic_try_cmpxchg */
>  
>  #ifndef atomic_try_cmpxchg
> -static inline bool
> +static __always_inline bool
>  atomic_try_cmpxchg(atomic_t *v, int *old, int new)
>  {
>  	int r, o = *old;
> @@ -924,7 +926,7 @@ atomic_try_cmpxchg(atomic_t *v, int *old, int new)
>  #endif
>  
>  #ifndef atomic_try_cmpxchg_acquire
> -static inline bool
> +static __always_inline bool
>  atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
>  {
>  	int r, o = *old;
> @@ -937,7 +939,7 @@ atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
>  #endif
>  
>  #ifndef atomic_try_cmpxchg_release
> -static inline bool
> +static __always_inline bool
>  atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
>  {
>  	int r, o = *old;
> @@ -950,7 +952,7 @@ atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
>  #endif
>  
>  #ifndef atomic_try_cmpxchg_relaxed
> -static inline bool
> +static __always_inline bool
>  atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)
>  {
>  	int r, o = *old;
> @@ -965,7 +967,7 @@ atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)
>  #else /* atomic_try_cmpxchg_relaxed */
>  
>  #ifndef atomic_try_cmpxchg_acquire
> -static inline bool
> +static __always_inline bool
>  atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
>  {
>  	bool ret = atomic_try_cmpxchg_relaxed(v, old, new);
> @@ -976,7 +978,7 @@ atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
>  #endif
>  
>  #ifndef atomic_try_cmpxchg_release
> -static inline bool
> +static __always_inline bool
>  atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
>  {
>  	__atomic_release_fence();
> @@ -986,7 +988,7 @@ atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
>  #endif
>  
>  #ifndef atomic_try_cmpxchg
> -static inline bool
> +static __always_inline bool
>  atomic_try_cmpxchg(atomic_t *v, int *old, int new)
>  {
>  	bool ret;
> @@ -1010,7 +1012,7 @@ atomic_try_cmpxchg(atomic_t *v, int *old, int new)
>   * true if the result is zero, or false for all
>   * other cases.
>   */
> -static inline bool
> +static __always_inline bool
>  atomic_sub_and_test(int i, atomic_t *v)
>  {
>  	return atomic_sub_return(i, v) == 0;
> @@ -1027,7 +1029,7 @@ atomic_sub_and_test(int i, atomic_t *v)
>   * returns true if the result is 0, or false for all other
>   * cases.
>   */
> -static inline bool
> +static __always_inline bool
>  atomic_dec_and_test(atomic_t *v)
>  {
>  	return atomic_dec_return(v) == 0;
> @@ -1044,7 +1046,7 @@ atomic_dec_and_test(atomic_t *v)
>   * and returns true if the result is zero, or false for all
>   * other cases.
>   */
> -static inline bool
> +static __always_inline bool
>  atomic_inc_and_test(atomic_t *v)
>  {
>  	return atomic_inc_return(v) == 0;
> @@ -1062,7 +1064,7 @@ atomic_inc_and_test(atomic_t *v)
>   * if the result is negative, or false when
>   * result is greater than or equal to zero.
>   */
> -static inline bool
> +static __always_inline bool
>  atomic_add_negative(int i, atomic_t *v)
>  {
>  	return atomic_add_return(i, v) < 0;
> @@ -1080,7 +1082,7 @@ atomic_add_negative(int i, atomic_t *v)
>   * Atomically adds @a to @v, so long as @v was not already @u.
>   * Returns original value of @v
>   */
> -static inline int
> +static __always_inline int
>  atomic_fetch_add_unless(atomic_t *v, int a, int u)
>  {
>  	int c = atomic_read(v);
> @@ -1105,7 +1107,7 @@ atomic_fetch_add_unless(atomic_t *v, int a, int u)
>   * Atomically adds @a to @v, if @v was not already @u.
>   * Returns true if the addition was done.
>   */
> -static inline bool
> +static __always_inline bool
>  atomic_add_unless(atomic_t *v, int a, int u)
>  {
>  	return atomic_fetch_add_unless(v, a, u) != u;
> @@ -1121,7 +1123,7 @@ atomic_add_unless(atomic_t *v, int a, int u)
>   * Atomically increments @v by 1, if @v is non-zero.
>   * Returns true if the increment was done.
>   */
> -static inline bool
> +static __always_inline bool
>  atomic_inc_not_zero(atomic_t *v)
>  {
>  	return atomic_add_unless(v, 1, 0);
> @@ -1130,7 +1132,7 @@ atomic_inc_not_zero(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_inc_unless_negative
> -static inline bool
> +static __always_inline bool
>  atomic_inc_unless_negative(atomic_t *v)
>  {
>  	int c = atomic_read(v);
> @@ -1146,7 +1148,7 @@ atomic_inc_unless_negative(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_dec_unless_positive
> -static inline bool
> +static __always_inline bool
>  atomic_dec_unless_positive(atomic_t *v)
>  {
>  	int c = atomic_read(v);
> @@ -1162,7 +1164,7 @@ atomic_dec_unless_positive(atomic_t *v)
>  #endif
>  
>  #ifndef atomic_dec_if_positive
> -static inline int
> +static __always_inline int
>  atomic_dec_if_positive(atomic_t *v)
>  {
>  	int dec, c = atomic_read(v);
> @@ -1186,7 +1188,7 @@ atomic_dec_if_positive(atomic_t *v)
>  #endif
>  
>  #ifndef atomic64_read_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_read_acquire(const atomic64_t *v)
>  {
>  	return smp_load_acquire(&(v)->counter);
> @@ -1195,7 +1197,7 @@ atomic64_read_acquire(const atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_set_release
> -static inline void
> +static __always_inline void
>  atomic64_set_release(atomic64_t *v, s64 i)
>  {
>  	smp_store_release(&(v)->counter, i);
> @@ -1210,7 +1212,7 @@ atomic64_set_release(atomic64_t *v, s64 i)
>  #else /* atomic64_add_return_relaxed */
>  
>  #ifndef atomic64_add_return_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_add_return_acquire(s64 i, atomic64_t *v)
>  {
>  	s64 ret = atomic64_add_return_relaxed(i, v);
> @@ -1221,7 +1223,7 @@ atomic64_add_return_acquire(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_add_return_release
> -static inline s64
> +static __always_inline s64
>  atomic64_add_return_release(s64 i, atomic64_t *v)
>  {
>  	__atomic_release_fence();
> @@ -1231,7 +1233,7 @@ atomic64_add_return_release(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_add_return
> -static inline s64
> +static __always_inline s64
>  atomic64_add_return(s64 i, atomic64_t *v)
>  {
>  	s64 ret;
> @@ -1252,7 +1254,7 @@ atomic64_add_return(s64 i, atomic64_t *v)
>  #else /* atomic64_fetch_add_relaxed */
>  
>  #ifndef atomic64_fetch_add_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_add_acquire(s64 i, atomic64_t *v)
>  {
>  	s64 ret = atomic64_fetch_add_relaxed(i, v);
> @@ -1263,7 +1265,7 @@ atomic64_fetch_add_acquire(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_add_release
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_add_release(s64 i, atomic64_t *v)
>  {
>  	__atomic_release_fence();
> @@ -1273,7 +1275,7 @@ atomic64_fetch_add_release(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_add
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_add(s64 i, atomic64_t *v)
>  {
>  	s64 ret;
> @@ -1294,7 +1296,7 @@ atomic64_fetch_add(s64 i, atomic64_t *v)
>  #else /* atomic64_sub_return_relaxed */
>  
>  #ifndef atomic64_sub_return_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_sub_return_acquire(s64 i, atomic64_t *v)
>  {
>  	s64 ret = atomic64_sub_return_relaxed(i, v);
> @@ -1305,7 +1307,7 @@ atomic64_sub_return_acquire(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_sub_return_release
> -static inline s64
> +static __always_inline s64
>  atomic64_sub_return_release(s64 i, atomic64_t *v)
>  {
>  	__atomic_release_fence();
> @@ -1315,7 +1317,7 @@ atomic64_sub_return_release(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_sub_return
> -static inline s64
> +static __always_inline s64
>  atomic64_sub_return(s64 i, atomic64_t *v)
>  {
>  	s64 ret;
> @@ -1336,7 +1338,7 @@ atomic64_sub_return(s64 i, atomic64_t *v)
>  #else /* atomic64_fetch_sub_relaxed */
>  
>  #ifndef atomic64_fetch_sub_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_sub_acquire(s64 i, atomic64_t *v)
>  {
>  	s64 ret = atomic64_fetch_sub_relaxed(i, v);
> @@ -1347,7 +1349,7 @@ atomic64_fetch_sub_acquire(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_sub_release
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_sub_release(s64 i, atomic64_t *v)
>  {
>  	__atomic_release_fence();
> @@ -1357,7 +1359,7 @@ atomic64_fetch_sub_release(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_sub
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_sub(s64 i, atomic64_t *v)
>  {
>  	s64 ret;
> @@ -1372,7 +1374,7 @@ atomic64_fetch_sub(s64 i, atomic64_t *v)
>  #endif /* atomic64_fetch_sub_relaxed */
>  
>  #ifndef atomic64_inc
> -static inline void
> +static __always_inline void
>  atomic64_inc(atomic64_t *v)
>  {
>  	atomic64_add(1, v);
> @@ -1388,7 +1390,7 @@ atomic64_inc(atomic64_t *v)
>  #endif /* atomic64_inc_return */
>  
>  #ifndef atomic64_inc_return
> -static inline s64
> +static __always_inline s64
>  atomic64_inc_return(atomic64_t *v)
>  {
>  	return atomic64_add_return(1, v);
> @@ -1397,7 +1399,7 @@ atomic64_inc_return(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_inc_return_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_inc_return_acquire(atomic64_t *v)
>  {
>  	return atomic64_add_return_acquire(1, v);
> @@ -1406,7 +1408,7 @@ atomic64_inc_return_acquire(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_inc_return_release
> -static inline s64
> +static __always_inline s64
>  atomic64_inc_return_release(atomic64_t *v)
>  {
>  	return atomic64_add_return_release(1, v);
> @@ -1415,7 +1417,7 @@ atomic64_inc_return_release(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_inc_return_relaxed
> -static inline s64
> +static __always_inline s64
>  atomic64_inc_return_relaxed(atomic64_t *v)
>  {
>  	return atomic64_add_return_relaxed(1, v);
> @@ -1426,7 +1428,7 @@ atomic64_inc_return_relaxed(atomic64_t *v)
>  #else /* atomic64_inc_return_relaxed */
>  
>  #ifndef atomic64_inc_return_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_inc_return_acquire(atomic64_t *v)
>  {
>  	s64 ret = atomic64_inc_return_relaxed(v);
> @@ -1437,7 +1439,7 @@ atomic64_inc_return_acquire(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_inc_return_release
> -static inline s64
> +static __always_inline s64
>  atomic64_inc_return_release(atomic64_t *v)
>  {
>  	__atomic_release_fence();
> @@ -1447,7 +1449,7 @@ atomic64_inc_return_release(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_inc_return
> -static inline s64
> +static __always_inline s64
>  atomic64_inc_return(atomic64_t *v)
>  {
>  	s64 ret;
> @@ -1469,7 +1471,7 @@ atomic64_inc_return(atomic64_t *v)
>  #endif /* atomic64_fetch_inc */
>  
>  #ifndef atomic64_fetch_inc
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_inc(atomic64_t *v)
>  {
>  	return atomic64_fetch_add(1, v);
> @@ -1478,7 +1480,7 @@ atomic64_fetch_inc(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_inc_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_inc_acquire(atomic64_t *v)
>  {
>  	return atomic64_fetch_add_acquire(1, v);
> @@ -1487,7 +1489,7 @@ atomic64_fetch_inc_acquire(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_inc_release
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_inc_release(atomic64_t *v)
>  {
>  	return atomic64_fetch_add_release(1, v);
> @@ -1496,7 +1498,7 @@ atomic64_fetch_inc_release(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_inc_relaxed
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_inc_relaxed(atomic64_t *v)
>  {
>  	return atomic64_fetch_add_relaxed(1, v);
> @@ -1507,7 +1509,7 @@ atomic64_fetch_inc_relaxed(atomic64_t *v)
>  #else /* atomic64_fetch_inc_relaxed */
>  
>  #ifndef atomic64_fetch_inc_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_inc_acquire(atomic64_t *v)
>  {
>  	s64 ret = atomic64_fetch_inc_relaxed(v);
> @@ -1518,7 +1520,7 @@ atomic64_fetch_inc_acquire(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_inc_release
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_inc_release(atomic64_t *v)
>  {
>  	__atomic_release_fence();
> @@ -1528,7 +1530,7 @@ atomic64_fetch_inc_release(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_inc
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_inc(atomic64_t *v)
>  {
>  	s64 ret;
> @@ -1543,7 +1545,7 @@ atomic64_fetch_inc(atomic64_t *v)
>  #endif /* atomic64_fetch_inc_relaxed */
>  
>  #ifndef atomic64_dec
> -static inline void
> +static __always_inline void
>  atomic64_dec(atomic64_t *v)
>  {
>  	atomic64_sub(1, v);
> @@ -1559,7 +1561,7 @@ atomic64_dec(atomic64_t *v)
>  #endif /* atomic64_dec_return */
>  
>  #ifndef atomic64_dec_return
> -static inline s64
> +static __always_inline s64
>  atomic64_dec_return(atomic64_t *v)
>  {
>  	return atomic64_sub_return(1, v);
> @@ -1568,7 +1570,7 @@ atomic64_dec_return(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_dec_return_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_dec_return_acquire(atomic64_t *v)
>  {
>  	return atomic64_sub_return_acquire(1, v);
> @@ -1577,7 +1579,7 @@ atomic64_dec_return_acquire(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_dec_return_release
> -static inline s64
> +static __always_inline s64
>  atomic64_dec_return_release(atomic64_t *v)
>  {
>  	return atomic64_sub_return_release(1, v);
> @@ -1586,7 +1588,7 @@ atomic64_dec_return_release(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_dec_return_relaxed
> -static inline s64
> +static __always_inline s64
>  atomic64_dec_return_relaxed(atomic64_t *v)
>  {
>  	return atomic64_sub_return_relaxed(1, v);
> @@ -1597,7 +1599,7 @@ atomic64_dec_return_relaxed(atomic64_t *v)
>  #else /* atomic64_dec_return_relaxed */
>  
>  #ifndef atomic64_dec_return_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_dec_return_acquire(atomic64_t *v)
>  {
>  	s64 ret = atomic64_dec_return_relaxed(v);
> @@ -1608,7 +1610,7 @@ atomic64_dec_return_acquire(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_dec_return_release
> -static inline s64
> +static __always_inline s64
>  atomic64_dec_return_release(atomic64_t *v)
>  {
>  	__atomic_release_fence();
> @@ -1618,7 +1620,7 @@ atomic64_dec_return_release(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_dec_return
> -static inline s64
> +static __always_inline s64
>  atomic64_dec_return(atomic64_t *v)
>  {
>  	s64 ret;
> @@ -1640,7 +1642,7 @@ atomic64_dec_return(atomic64_t *v)
>  #endif /* atomic64_fetch_dec */
>  
>  #ifndef atomic64_fetch_dec
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_dec(atomic64_t *v)
>  {
>  	return atomic64_fetch_sub(1, v);
> @@ -1649,7 +1651,7 @@ atomic64_fetch_dec(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_dec_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_dec_acquire(atomic64_t *v)
>  {
>  	return atomic64_fetch_sub_acquire(1, v);
> @@ -1658,7 +1660,7 @@ atomic64_fetch_dec_acquire(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_dec_release
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_dec_release(atomic64_t *v)
>  {
>  	return atomic64_fetch_sub_release(1, v);
> @@ -1667,7 +1669,7 @@ atomic64_fetch_dec_release(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_dec_relaxed
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_dec_relaxed(atomic64_t *v)
>  {
>  	return atomic64_fetch_sub_relaxed(1, v);
> @@ -1678,7 +1680,7 @@ atomic64_fetch_dec_relaxed(atomic64_t *v)
>  #else /* atomic64_fetch_dec_relaxed */
>  
>  #ifndef atomic64_fetch_dec_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_dec_acquire(atomic64_t *v)
>  {
>  	s64 ret = atomic64_fetch_dec_relaxed(v);
> @@ -1689,7 +1691,7 @@ atomic64_fetch_dec_acquire(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_dec_release
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_dec_release(atomic64_t *v)
>  {
>  	__atomic_release_fence();
> @@ -1699,7 +1701,7 @@ atomic64_fetch_dec_release(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_dec
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_dec(atomic64_t *v)
>  {
>  	s64 ret;
> @@ -1720,7 +1722,7 @@ atomic64_fetch_dec(atomic64_t *v)
>  #else /* atomic64_fetch_and_relaxed */
>  
>  #ifndef atomic64_fetch_and_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_and_acquire(s64 i, atomic64_t *v)
>  {
>  	s64 ret = atomic64_fetch_and_relaxed(i, v);
> @@ -1731,7 +1733,7 @@ atomic64_fetch_and_acquire(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_and_release
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_and_release(s64 i, atomic64_t *v)
>  {
>  	__atomic_release_fence();
> @@ -1741,7 +1743,7 @@ atomic64_fetch_and_release(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_and
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_and(s64 i, atomic64_t *v)
>  {
>  	s64 ret;
> @@ -1756,7 +1758,7 @@ atomic64_fetch_and(s64 i, atomic64_t *v)
>  #endif /* atomic64_fetch_and_relaxed */
>  
>  #ifndef atomic64_andnot
> -static inline void
> +static __always_inline void
>  atomic64_andnot(s64 i, atomic64_t *v)
>  {
>  	atomic64_and(~i, v);
> @@ -1772,7 +1774,7 @@ atomic64_andnot(s64 i, atomic64_t *v)
>  #endif /* atomic64_fetch_andnot */
>  
>  #ifndef atomic64_fetch_andnot
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_andnot(s64 i, atomic64_t *v)
>  {
>  	return atomic64_fetch_and(~i, v);
> @@ -1781,7 +1783,7 @@ atomic64_fetch_andnot(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_andnot_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_andnot_acquire(s64 i, atomic64_t *v)
>  {
>  	return atomic64_fetch_and_acquire(~i, v);
> @@ -1790,7 +1792,7 @@ atomic64_fetch_andnot_acquire(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_andnot_release
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_andnot_release(s64 i, atomic64_t *v)
>  {
>  	return atomic64_fetch_and_release(~i, v);
> @@ -1799,7 +1801,7 @@ atomic64_fetch_andnot_release(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_andnot_relaxed
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_andnot_relaxed(s64 i, atomic64_t *v)
>  {
>  	return atomic64_fetch_and_relaxed(~i, v);
> @@ -1810,7 +1812,7 @@ atomic64_fetch_andnot_relaxed(s64 i, atomic64_t *v)
>  #else /* atomic64_fetch_andnot_relaxed */
>  
>  #ifndef atomic64_fetch_andnot_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_andnot_acquire(s64 i, atomic64_t *v)
>  {
>  	s64 ret = atomic64_fetch_andnot_relaxed(i, v);
> @@ -1821,7 +1823,7 @@ atomic64_fetch_andnot_acquire(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_andnot_release
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_andnot_release(s64 i, atomic64_t *v)
>  {
>  	__atomic_release_fence();
> @@ -1831,7 +1833,7 @@ atomic64_fetch_andnot_release(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_andnot
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_andnot(s64 i, atomic64_t *v)
>  {
>  	s64 ret;
> @@ -1852,7 +1854,7 @@ atomic64_fetch_andnot(s64 i, atomic64_t *v)
>  #else /* atomic64_fetch_or_relaxed */
>  
>  #ifndef atomic64_fetch_or_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_or_acquire(s64 i, atomic64_t *v)
>  {
>  	s64 ret = atomic64_fetch_or_relaxed(i, v);
> @@ -1863,7 +1865,7 @@ atomic64_fetch_or_acquire(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_or_release
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_or_release(s64 i, atomic64_t *v)
>  {
>  	__atomic_release_fence();
> @@ -1873,7 +1875,7 @@ atomic64_fetch_or_release(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_or
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_or(s64 i, atomic64_t *v)
>  {
>  	s64 ret;
> @@ -1894,7 +1896,7 @@ atomic64_fetch_or(s64 i, atomic64_t *v)
>  #else /* atomic64_fetch_xor_relaxed */
>  
>  #ifndef atomic64_fetch_xor_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_xor_acquire(s64 i, atomic64_t *v)
>  {
>  	s64 ret = atomic64_fetch_xor_relaxed(i, v);
> @@ -1905,7 +1907,7 @@ atomic64_fetch_xor_acquire(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_xor_release
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_xor_release(s64 i, atomic64_t *v)
>  {
>  	__atomic_release_fence();
> @@ -1915,7 +1917,7 @@ atomic64_fetch_xor_release(s64 i, atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_fetch_xor
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_xor(s64 i, atomic64_t *v)
>  {
>  	s64 ret;
> @@ -1936,7 +1938,7 @@ atomic64_fetch_xor(s64 i, atomic64_t *v)
>  #else /* atomic64_xchg_relaxed */
>  
>  #ifndef atomic64_xchg_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_xchg_acquire(atomic64_t *v, s64 i)
>  {
>  	s64 ret = atomic64_xchg_relaxed(v, i);
> @@ -1947,7 +1949,7 @@ atomic64_xchg_acquire(atomic64_t *v, s64 i)
>  #endif
>  
>  #ifndef atomic64_xchg_release
> -static inline s64
> +static __always_inline s64
>  atomic64_xchg_release(atomic64_t *v, s64 i)
>  {
>  	__atomic_release_fence();
> @@ -1957,7 +1959,7 @@ atomic64_xchg_release(atomic64_t *v, s64 i)
>  #endif
>  
>  #ifndef atomic64_xchg
> -static inline s64
> +static __always_inline s64
>  atomic64_xchg(atomic64_t *v, s64 i)
>  {
>  	s64 ret;
> @@ -1978,7 +1980,7 @@ atomic64_xchg(atomic64_t *v, s64 i)
>  #else /* atomic64_cmpxchg_relaxed */
>  
>  #ifndef atomic64_cmpxchg_acquire
> -static inline s64
> +static __always_inline s64
>  atomic64_cmpxchg_acquire(atomic64_t *v, s64 old, s64 new)
>  {
>  	s64 ret = atomic64_cmpxchg_relaxed(v, old, new);
> @@ -1989,7 +1991,7 @@ atomic64_cmpxchg_acquire(atomic64_t *v, s64 old, s64 new)
>  #endif
>  
>  #ifndef atomic64_cmpxchg_release
> -static inline s64
> +static __always_inline s64
>  atomic64_cmpxchg_release(atomic64_t *v, s64 old, s64 new)
>  {
>  	__atomic_release_fence();
> @@ -1999,7 +2001,7 @@ atomic64_cmpxchg_release(atomic64_t *v, s64 old, s64 new)
>  #endif
>  
>  #ifndef atomic64_cmpxchg
> -static inline s64
> +static __always_inline s64
>  atomic64_cmpxchg(atomic64_t *v, s64 old, s64 new)
>  {
>  	s64 ret;
> @@ -2021,7 +2023,7 @@ atomic64_cmpxchg(atomic64_t *v, s64 old, s64 new)
>  #endif /* atomic64_try_cmpxchg */
>  
>  #ifndef atomic64_try_cmpxchg
> -static inline bool
> +static __always_inline bool
>  atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
>  {
>  	s64 r, o = *old;
> @@ -2034,7 +2036,7 @@ atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
>  #endif
>  
>  #ifndef atomic64_try_cmpxchg_acquire
> -static inline bool
> +static __always_inline bool
>  atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
>  {
>  	s64 r, o = *old;
> @@ -2047,7 +2049,7 @@ atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
>  #endif
>  
>  #ifndef atomic64_try_cmpxchg_release
> -static inline bool
> +static __always_inline bool
>  atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
>  {
>  	s64 r, o = *old;
> @@ -2060,7 +2062,7 @@ atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
>  #endif
>  
>  #ifndef atomic64_try_cmpxchg_relaxed
> -static inline bool
> +static __always_inline bool
>  atomic64_try_cmpxchg_relaxed(atomic64_t *v, s64 *old, s64 new)
>  {
>  	s64 r, o = *old;
> @@ -2075,7 +2077,7 @@ atomic64_try_cmpxchg_relaxed(atomic64_t *v, s64 *old, s64 new)
>  #else /* atomic64_try_cmpxchg_relaxed */
>  
>  #ifndef atomic64_try_cmpxchg_acquire
> -static inline bool
> +static __always_inline bool
>  atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
>  {
>  	bool ret = atomic64_try_cmpxchg_relaxed(v, old, new);
> @@ -2086,7 +2088,7 @@ atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
>  #endif
>  
>  #ifndef atomic64_try_cmpxchg_release
> -static inline bool
> +static __always_inline bool
>  atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
>  {
>  	__atomic_release_fence();
> @@ -2096,7 +2098,7 @@ atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
>  #endif
>  
>  #ifndef atomic64_try_cmpxchg
> -static inline bool
> +static __always_inline bool
>  atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
>  {
>  	bool ret;
> @@ -2120,7 +2122,7 @@ atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
>   * true if the result is zero, or false for all
>   * other cases.
>   */
> -static inline bool
> +static __always_inline bool
>  atomic64_sub_and_test(s64 i, atomic64_t *v)
>  {
>  	return atomic64_sub_return(i, v) == 0;
> @@ -2137,7 +2139,7 @@ atomic64_sub_and_test(s64 i, atomic64_t *v)
>   * returns true if the result is 0, or false for all other
>   * cases.
>   */
> -static inline bool
> +static __always_inline bool
>  atomic64_dec_and_test(atomic64_t *v)
>  {
>  	return atomic64_dec_return(v) == 0;
> @@ -2154,7 +2156,7 @@ atomic64_dec_and_test(atomic64_t *v)
>   * and returns true if the result is zero, or false for all
>   * other cases.
>   */
> -static inline bool
> +static __always_inline bool
>  atomic64_inc_and_test(atomic64_t *v)
>  {
>  	return atomic64_inc_return(v) == 0;
> @@ -2172,7 +2174,7 @@ atomic64_inc_and_test(atomic64_t *v)
>   * if the result is negative, or false when
>   * result is greater than or equal to zero.
>   */
> -static inline bool
> +static __always_inline bool
>  atomic64_add_negative(s64 i, atomic64_t *v)
>  {
>  	return atomic64_add_return(i, v) < 0;
> @@ -2190,7 +2192,7 @@ atomic64_add_negative(s64 i, atomic64_t *v)
>   * Atomically adds @a to @v, so long as @v was not already @u.
>   * Returns original value of @v
>   */
> -static inline s64
> +static __always_inline s64
>  atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
>  {
>  	s64 c = atomic64_read(v);
> @@ -2215,7 +2217,7 @@ atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
>   * Atomically adds @a to @v, if @v was not already @u.
>   * Returns true if the addition was done.
>   */
> -static inline bool
> +static __always_inline bool
>  atomic64_add_unless(atomic64_t *v, s64 a, s64 u)
>  {
>  	return atomic64_fetch_add_unless(v, a, u) != u;
> @@ -2231,7 +2233,7 @@ atomic64_add_unless(atomic64_t *v, s64 a, s64 u)
>   * Atomically increments @v by 1, if @v is non-zero.
>   * Returns true if the increment was done.
>   */
> -static inline bool
> +static __always_inline bool
>  atomic64_inc_not_zero(atomic64_t *v)
>  {
>  	return atomic64_add_unless(v, 1, 0);
> @@ -2240,7 +2242,7 @@ atomic64_inc_not_zero(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_inc_unless_negative
> -static inline bool
> +static __always_inline bool
>  atomic64_inc_unless_negative(atomic64_t *v)
>  {
>  	s64 c = atomic64_read(v);
> @@ -2256,7 +2258,7 @@ atomic64_inc_unless_negative(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_dec_unless_positive
> -static inline bool
> +static __always_inline bool
>  atomic64_dec_unless_positive(atomic64_t *v)
>  {
>  	s64 c = atomic64_read(v);
> @@ -2272,7 +2274,7 @@ atomic64_dec_unless_positive(atomic64_t *v)
>  #endif
>  
>  #ifndef atomic64_dec_if_positive
> -static inline s64
> +static __always_inline s64
>  atomic64_dec_if_positive(atomic64_t *v)
>  {
>  	s64 dec, c = atomic64_read(v);
> @@ -2292,4 +2294,4 @@ atomic64_dec_if_positive(atomic64_t *v)
>  #define atomic64_cond_read_relaxed(v, c) smp_cond_load_relaxed(&(v)->counter, (c))
>  
>  #endif /* _LINUX_ATOMIC_FALLBACK_H */
> -// 25de4a2804d70f57e994fe3b419148658bb5378a
> +// baaf45f4c24ed88ceae58baca39d7fd80bb8101b
> diff --git a/scripts/atomic/fallbacks/acquire b/scripts/atomic/fallbacks/acquire
> index e38871e64db6..ea489acc285e 100755
> --- a/scripts/atomic/fallbacks/acquire
> +++ b/scripts/atomic/fallbacks/acquire
> @@ -1,5 +1,5 @@
>  cat <<EOF
> -static inline ${ret}
> +static __always_inline ${ret}
>  ${atomic}_${pfx}${name}${sfx}_acquire(${params})
>  {
>  	${ret} ret = ${atomic}_${pfx}${name}${sfx}_relaxed(${args});
> diff --git a/scripts/atomic/fallbacks/add_negative b/scripts/atomic/fallbacks/add_negative
> index e6f4815637de..03cc2e07fac5 100755
> --- a/scripts/atomic/fallbacks/add_negative
> +++ b/scripts/atomic/fallbacks/add_negative
> @@ -8,7 +8,7 @@ cat <<EOF
>   * if the result is negative, or false when
>   * result is greater than or equal to zero.
>   */
> -static inline bool
> +static __always_inline bool
>  ${atomic}_add_negative(${int} i, ${atomic}_t *v)
>  {
>  	return ${atomic}_add_return(i, v) < 0;
> diff --git a/scripts/atomic/fallbacks/add_unless b/scripts/atomic/fallbacks/add_unless
> index 792533885fbf..daf87a04c850 100755
> --- a/scripts/atomic/fallbacks/add_unless
> +++ b/scripts/atomic/fallbacks/add_unless
> @@ -8,7 +8,7 @@ cat << EOF
>   * Atomically adds @a to @v, if @v was not already @u.
>   * Returns true if the addition was done.
>   */
> -static inline bool
> +static __always_inline bool
>  ${atomic}_add_unless(${atomic}_t *v, ${int} a, ${int} u)
>  {
>  	return ${atomic}_fetch_add_unless(v, a, u) != u;
> diff --git a/scripts/atomic/fallbacks/andnot b/scripts/atomic/fallbacks/andnot
> index 9f3a3216b5e3..14efce01225a 100755
> --- a/scripts/atomic/fallbacks/andnot
> +++ b/scripts/atomic/fallbacks/andnot
> @@ -1,5 +1,5 @@
>  cat <<EOF
> -static inline ${ret}
> +static __always_inline ${ret}
>  ${atomic}_${pfx}andnot${sfx}${order}(${int} i, ${atomic}_t *v)
>  {
>  	${retstmt}${atomic}_${pfx}and${sfx}${order}(~i, v);
> diff --git a/scripts/atomic/fallbacks/dec b/scripts/atomic/fallbacks/dec
> index 10bbc82be31d..118282f3a5a3 100755
> --- a/scripts/atomic/fallbacks/dec
> +++ b/scripts/atomic/fallbacks/dec
> @@ -1,5 +1,5 @@
>  cat <<EOF
> -static inline ${ret}
> +static __always_inline ${ret}
>  ${atomic}_${pfx}dec${sfx}${order}(${atomic}_t *v)
>  {
>  	${retstmt}${atomic}_${pfx}sub${sfx}${order}(1, v);
> diff --git a/scripts/atomic/fallbacks/dec_and_test b/scripts/atomic/fallbacks/dec_and_test
> index 0ce7103b3df2..f8967a891117 100755
> --- a/scripts/atomic/fallbacks/dec_and_test
> +++ b/scripts/atomic/fallbacks/dec_and_test
> @@ -7,7 +7,7 @@ cat <<EOF
>   * returns true if the result is 0, or false for all other
>   * cases.
>   */
> -static inline bool
> +static __always_inline bool
>  ${atomic}_dec_and_test(${atomic}_t *v)
>  {
>  	return ${atomic}_dec_return(v) == 0;
> diff --git a/scripts/atomic/fallbacks/dec_if_positive b/scripts/atomic/fallbacks/dec_if_positive
> index c52eacec43c8..cfb380bd2da6 100755
> --- a/scripts/atomic/fallbacks/dec_if_positive
> +++ b/scripts/atomic/fallbacks/dec_if_positive
> @@ -1,5 +1,5 @@
>  cat <<EOF
> -static inline ${ret}
> +static __always_inline ${ret}
>  ${atomic}_dec_if_positive(${atomic}_t *v)
>  {
>  	${int} dec, c = ${atomic}_read(v);
> diff --git a/scripts/atomic/fallbacks/dec_unless_positive b/scripts/atomic/fallbacks/dec_unless_positive
> index 8a2578f14268..69cb7aa01f9c 100755
> --- a/scripts/atomic/fallbacks/dec_unless_positive
> +++ b/scripts/atomic/fallbacks/dec_unless_positive
> @@ -1,5 +1,5 @@
>  cat <<EOF
> -static inline bool
> +static __always_inline bool
>  ${atomic}_dec_unless_positive(${atomic}_t *v)
>  {
>  	${int} c = ${atomic}_read(v);
> diff --git a/scripts/atomic/fallbacks/fence b/scripts/atomic/fallbacks/fence
> index 82f68fa6931a..92a3a4691bab 100755
> --- a/scripts/atomic/fallbacks/fence
> +++ b/scripts/atomic/fallbacks/fence
> @@ -1,5 +1,5 @@
>  cat <<EOF
> -static inline ${ret}
> +static __always_inline ${ret}
>  ${atomic}_${pfx}${name}${sfx}(${params})
>  {
>  	${ret} ret;
> diff --git a/scripts/atomic/fallbacks/fetch_add_unless b/scripts/atomic/fallbacks/fetch_add_unless
> index d2c091db7eae..fffbc0d16fdf 100755
> --- a/scripts/atomic/fallbacks/fetch_add_unless
> +++ b/scripts/atomic/fallbacks/fetch_add_unless
> @@ -8,7 +8,7 @@ cat << EOF
>   * Atomically adds @a to @v, so long as @v was not already @u.
>   * Returns original value of @v
>   */
> -static inline ${int}
> +static __always_inline ${int}
>  ${atomic}_fetch_add_unless(${atomic}_t *v, ${int} a, ${int} u)
>  {
>  	${int} c = ${atomic}_read(v);
> diff --git a/scripts/atomic/fallbacks/inc b/scripts/atomic/fallbacks/inc
> index f866b3ad2353..10751cd62829 100755
> --- a/scripts/atomic/fallbacks/inc
> +++ b/scripts/atomic/fallbacks/inc
> @@ -1,5 +1,5 @@
>  cat <<EOF
> -static inline ${ret}
> +static __always_inline ${ret}
>  ${atomic}_${pfx}inc${sfx}${order}(${atomic}_t *v)
>  {
>  	${retstmt}${atomic}_${pfx}add${sfx}${order}(1, v);
> diff --git a/scripts/atomic/fallbacks/inc_and_test b/scripts/atomic/fallbacks/inc_and_test
> index 4e2068869f7e..4acea9c93604 100755
> --- a/scripts/atomic/fallbacks/inc_and_test
> +++ b/scripts/atomic/fallbacks/inc_and_test
> @@ -7,7 +7,7 @@ cat <<EOF
>   * and returns true if the result is zero, or false for all
>   * other cases.
>   */
> -static inline bool
> +static __always_inline bool
>  ${atomic}_inc_and_test(${atomic}_t *v)
>  {
>  	return ${atomic}_inc_return(v) == 0;
> diff --git a/scripts/atomic/fallbacks/inc_not_zero b/scripts/atomic/fallbacks/inc_not_zero
> index a7c45c8d107c..d9f7b97aab42 100755
> --- a/scripts/atomic/fallbacks/inc_not_zero
> +++ b/scripts/atomic/fallbacks/inc_not_zero
> @@ -6,7 +6,7 @@ cat <<EOF
>   * Atomically increments @v by 1, if @v is non-zero.
>   * Returns true if the increment was done.
>   */
> -static inline bool
> +static __always_inline bool
>  ${atomic}_inc_not_zero(${atomic}_t *v)
>  {
>  	return ${atomic}_add_unless(v, 1, 0);
> diff --git a/scripts/atomic/fallbacks/inc_unless_negative b/scripts/atomic/fallbacks/inc_unless_negative
> index 0c266e71dbd4..177a7cb51eda 100755
> --- a/scripts/atomic/fallbacks/inc_unless_negative
> +++ b/scripts/atomic/fallbacks/inc_unless_negative
> @@ -1,5 +1,5 @@
>  cat <<EOF
> -static inline bool
> +static __always_inline bool
>  ${atomic}_inc_unless_negative(${atomic}_t *v)
>  {
>  	${int} c = ${atomic}_read(v);
> diff --git a/scripts/atomic/fallbacks/read_acquire b/scripts/atomic/fallbacks/read_acquire
> index 75863b5203f7..12fa83cb3a6d 100755
> --- a/scripts/atomic/fallbacks/read_acquire
> +++ b/scripts/atomic/fallbacks/read_acquire
> @@ -1,5 +1,5 @@
>  cat <<EOF
> -static inline ${ret}
> +static __always_inline ${ret}
>  ${atomic}_read_acquire(const ${atomic}_t *v)
>  {
>  	return smp_load_acquire(&(v)->counter);
> diff --git a/scripts/atomic/fallbacks/release b/scripts/atomic/fallbacks/release
> index 3f628a3802d9..730d2a6d3e07 100755
> --- a/scripts/atomic/fallbacks/release
> +++ b/scripts/atomic/fallbacks/release
> @@ -1,5 +1,5 @@
>  cat <<EOF
> -static inline ${ret}
> +static __always_inline ${ret}
>  ${atomic}_${pfx}${name}${sfx}_release(${params})
>  {
>  	__atomic_release_fence();
> diff --git a/scripts/atomic/fallbacks/set_release b/scripts/atomic/fallbacks/set_release
> index 45bb5e0cfc08..e5d72c717434 100755
> --- a/scripts/atomic/fallbacks/set_release
> +++ b/scripts/atomic/fallbacks/set_release
> @@ -1,5 +1,5 @@
>  cat <<EOF
> -static inline void
> +static __always_inline void
>  ${atomic}_set_release(${atomic}_t *v, ${int} i)
>  {
>  	smp_store_release(&(v)->counter, i);
> diff --git a/scripts/atomic/fallbacks/sub_and_test b/scripts/atomic/fallbacks/sub_and_test
> index 289ef17a2d7a..6cfe4ed49746 100755
> --- a/scripts/atomic/fallbacks/sub_and_test
> +++ b/scripts/atomic/fallbacks/sub_and_test
> @@ -8,7 +8,7 @@ cat <<EOF
>   * true if the result is zero, or false for all
>   * other cases.
>   */
> -static inline bool
> +static __always_inline bool
>  ${atomic}_sub_and_test(${int} i, ${atomic}_t *v)
>  {
>  	return ${atomic}_sub_return(i, v) == 0;
> diff --git a/scripts/atomic/fallbacks/try_cmpxchg b/scripts/atomic/fallbacks/try_cmpxchg
> index 4ed85e2f5378..c7a26213b978 100755
> --- a/scripts/atomic/fallbacks/try_cmpxchg
> +++ b/scripts/atomic/fallbacks/try_cmpxchg
> @@ -1,5 +1,5 @@
>  cat <<EOF
> -static inline bool
> +static __always_inline bool
>  ${atomic}_try_cmpxchg${order}(${atomic}_t *v, ${int} *old, ${int} new)
>  {
>  	${int} r, o = *old;
> diff --git a/scripts/atomic/gen-atomic-fallback.sh b/scripts/atomic/gen-atomic-fallback.sh
> index 1bd7c1707633..b6c6f5d306a7 100755
> --- a/scripts/atomic/gen-atomic-fallback.sh
> +++ b/scripts/atomic/gen-atomic-fallback.sh
> @@ -149,6 +149,8 @@ cat << EOF
>  #ifndef _LINUX_ATOMIC_FALLBACK_H
>  #define _LINUX_ATOMIC_FALLBACK_H
>  
> +#include <linux/compiler.h>
> +
>  EOF
>  
>  for xchg in "xchg" "cmpxchg" "cmpxchg64"; do
> -- 
> 2.24.0.432.g9d3f5f5b63-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191126124010.GB37833%40lakrids.cambridge.arm.com.
