Return-Path: <kasan-dev+bncBDV37XP3XYDRBJGRZXUAKGQEM3CSXLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id CF4FF56999
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 14:44:20 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id w11sf1011280wrl.7
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 05:44:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561553060; cv=pass;
        d=google.com; s=arc-20160816;
        b=lrIPCnZCvwehk198zBKoTHTjbtHF++aPoV2/8aZ3PtiaofhrVx5xXU+UC23obEJ1Kb
         xKSESFieHMpS6u0Meko5fF+0aqFaJUxa97ZfVCDRJmru2lLS7/qTom//M0ERmLaR7lw/
         90mhX6VedzZhJRnh5rvJo1H+TPrSMNa7xFL71ZhQHossKI/apbSa+5IiJBIx/Hi7pt4S
         sm17UE2vzWoph47ps6FxgF5ijS0BZXs+oai/Sc0Ia+MOSD9tR3WBHlwaPyrFk+Sj0xH7
         VcFE5xwt3KUj3n74mNxRlz1rsWCusJT6q/v0239TaMdkIUKfBuN9nkixuArzXWLZu1aW
         vtlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=oc/XlCs/P1/H9b/IBphOmmT13UTDfFBwyckslBBSJwc=;
        b=HmobYYlv676HzX3gLGjzMUZIbgi55n3G+7Im2hM3ynfet/lBrKx0SbqMuPlDS6wxDX
         nP6S0+5eeyAK3vt7ouBRBMmzO0BWpYanqU9Sf2fM0laAc9ybJ4ycY3LJEA38Ng5AGSdG
         T3w8Kk6Syarq+4H+WH55eP4uy0QvhijUerTs9dpIAmraOSBFwZgnia+yH3ubKj72GVfm
         D16tZFpbBSyKhT205auInlQmkSuf1qoPCT2qtUlenY+1i2DQAh4jhEeiR+E8XlD1OMH8
         Yj276evJ9LDLym1L3b8XHqicHN0bD8dUlvGS1+qoR0sFGYfFfmoUFF5hDBjdstPj/Mhe
         QK/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oc/XlCs/P1/H9b/IBphOmmT13UTDfFBwyckslBBSJwc=;
        b=kbfPlSmD3BzG2o8XA10EBoyiE/tsPF6WjQNNM+B/NUO7J+s19eQN5DyME4IVAMZBUx
         b4n/Qe1H7MEXPMuewHZ+KI2+uYjDm2v/H6fxPRLC21+ush6o0+oqORw3gc0/NezQWEgG
         06k12/aa3NKescrvuLB/C/L4F3FphjxDvGoy8VA+KFnkmiKehHGSL8iiibLfScN12DiA
         HwkfVT40O3NIVbHCgVec4hwVoskXOEv/CiKEOlBK/U7iY6N7hxaG7N6Ayv4WyaMwbARY
         ofYLcLD/2l6NOYzNNmRmNkZPFxqNGW6XsNvxMI5TZlMmCN3oXbE58hM/ht15dUlXVobq
         bUUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oc/XlCs/P1/H9b/IBphOmmT13UTDfFBwyckslBBSJwc=;
        b=n2TZNWEZ1AU0SXlJXS5X4hLeZnZvMBLh+RBmuGMoPsIyMg7vRRm0BbOOZVtYfQgIUB
         tooxdHwkgkOX6bIPdGsDW/+zHs24mc980Q/vUoUcLcItdiMHytg8TS3EwZvRdsP99lBa
         CIoyEFIjaU39qB5XAg/1Oy7l/IpCJC+jtH8YLwpYiVjPFBI8Aj+mFBpk78bv1kf2/ZGn
         4aVSKkeI4k0hQJ+1uO3uZnKPe0t2SPXKAjQuFIh10+rW1Q+vmhurft3IgfiCpxfOC5aI
         GE8B+JSk4OfrxhLgz7i6jdqN4A4Tmxh3n/bZnTgqqbEejxy2y8y7fRMak+RGgyYfRabR
         iSaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWupJj38Of0x5vWbrVEY/Qbe9w2qnugS7i6EhZjD2M+8mq+n78P
	q8FuFQVmEnPaxo5blbxXaLY=
X-Google-Smtp-Source: APXvYqwioo47net4bu1g0kgJmsD4zvuCSvAe5hUItR/oMOM17lC2V7JrPfErf4Tj2kOtS+i7IGFYgQ==
X-Received: by 2002:a1c:67c2:: with SMTP id b185mr2527109wmc.98.1561553060454;
        Wed, 26 Jun 2019 05:44:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ec02:: with SMTP id x2ls524997wrn.6.gmail; Wed, 26 Jun
 2019 05:44:19 -0700 (PDT)
X-Received: by 2002:adf:d843:: with SMTP id k3mr3660393wrl.332.1561553059930;
        Wed, 26 Jun 2019 05:44:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561553059; cv=none;
        d=google.com; s=arc-20160816;
        b=ZeFTQjdgrPHCZLHJdhGPDPmqpLgJiX+rDtU6Nsfe2+m1gPHHbAVOCQB02Z4RrORssS
         PRyx+wGpVDEXxAjk+9AnRw97wE1xmWmHbjqDi1zwbsuk8IHqtz1fz6JtZr5gmTRQFm/s
         P/cFROWT6ct2mMVyFNdkdLkr1RXq+E9VaNFPuYkIzsSa1zGjrmqtLvecLx4SmUlH0gT9
         C1bU7t0rzooxyN/hOZ/T5pBwLo73Pa1ZOuSrXCWA0pXx8m6lB97nqWpu1xz7IDRtBmHF
         AzjnnJG6CZdT2aLOVQe/TTjgFQ7eM4K0xeSIeb7awOXO/sOqe9HnM7Pk6hsgF4OJLokN
         uOIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Hh3iEuxn6hEhKWsSgpsz8EJOK5lvnGFrZoMaN8JZB0E=;
        b=uAchSDO8BVZYrVZqzMlbFs+IhZmVIdcKppgt8XPILhARi3SLQHWkzCtMqiqnhySV5K
         Vmr5VgDyGRRfCxmvUdUIvOss83tmEc58Le+29DWXQtLYdPJ6jfhFxrzMmfbJpU+NIzlW
         +rLT39LpwO1rSmNlCcEUK7p1Uz09/x25Lk1lDVSiqd+MXYdZoNYy14bJXhE409gQEuSC
         rez6txEokdTEDUbFTkypu0p2J3IGqNl2tRV6SkjL9k2aLRbhdkc34HyqAccF4S2EHJOW
         ++TtMoRcwhCoOm5xLNwYbhSQRd816ig/pNA3tgg3ke4W4nfno8uUJNZNxESOKE+qwoEv
         wgbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j4si89905wme.3.2019.06.26.05.44.19
        for <kasan-dev@googlegroups.com>;
        Wed, 26 Jun 2019 05:44:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9535DD6E;
	Wed, 26 Jun 2019 05:44:18 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E28603F718;
	Wed, 26 Jun 2019 05:44:16 -0700 (PDT)
Date: Wed, 26 Jun 2019 13:44:14 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: aryabinin@virtuozzo.com, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com, linux-kernel@vger.kernel.org,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: Re: [PATCH v2 1/4] mm/kasan: Introduce __kasan_check_{read,write}
Message-ID: <20190626124414.GC20635@lakrids.cambridge.arm.com>
References: <20190626122018.171606-1-elver@google.com>
 <20190626122018.171606-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190626122018.171606-2-elver@google.com>
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

On Wed, Jun 26, 2019 at 02:20:16PM +0200, Marco Elver wrote:
> This introduces __kasan_check_{read,write} which return a bool if the
> access was valid or not. __kasan_check functions may be used from
> anywhere, even compilation units that disable instrumentation
> selectively. For consistency, kasan_check_{read,write} have been changed
> to also return a bool.
> 
> This change eliminates the need for the __KASAN_INTERNAL definition.

I'm very happy to see __KASAN_INTERNAL go away!

It might be worth splitting that change from the return type change,
since the two are logically unrelated.

> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Cc: Christoph Lameter <cl@linux.com>
> Cc: Pekka Enberg <penberg@kernel.org>
> Cc: David Rientjes <rientjes@google.com>
> Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-kernel@vger.kernel.org
> Cc: linux-mm@kvack.org
> ---
>  include/linux/kasan-checks.h | 35 ++++++++++++++++++++++++++++-------
>  mm/kasan/common.c            | 14 ++++++--------
>  mm/kasan/generic.c           | 13 +++++++------
>  mm/kasan/kasan.h             | 10 +++++++++-
>  mm/kasan/tags.c              | 12 +++++++-----
>  5 files changed, 57 insertions(+), 27 deletions(-)
> 
> diff --git a/include/linux/kasan-checks.h b/include/linux/kasan-checks.h
> index a61dc075e2ce..b8cf8a7cad34 100644
> --- a/include/linux/kasan-checks.h
> +++ b/include/linux/kasan-checks.h
> @@ -2,14 +2,35 @@
>  #ifndef _LINUX_KASAN_CHECKS_H
>  #define _LINUX_KASAN_CHECKS_H
>  
> -#if defined(__SANITIZE_ADDRESS__) || defined(__KASAN_INTERNAL)
> -void kasan_check_read(const volatile void *p, unsigned int size);
> -void kasan_check_write(const volatile void *p, unsigned int size);
> +/*
> + * __kasan_check_*: Always available when KASAN is enabled. This may be used
> + * even in compilation units that selectively disable KASAN, but must use KASAN
> + * to validate access to an address.   Never use these in header files!
> + */
> +#ifdef CONFIG_KASAN
> +bool __kasan_check_read(const volatile void *p, unsigned int size);
> +bool __kasan_check_write(const volatile void *p, unsigned int size);
>  #else
> -static inline void kasan_check_read(const volatile void *p, unsigned int size)
> -{ }
> -static inline void kasan_check_write(const volatile void *p, unsigned int size)
> -{ }
> +static inline bool __kasan_check_read(const volatile void *p, unsigned int size)
> +{ return true; }
> +static inline bool __kasan_check_write(const volatile void *p, unsigned int size)
> +{ return true; }
> +#endif
> +
> +/*
> + * kasan_check_*: Only available when the particular compilation unit has KASAN
> + * instrumentation enabled. May be used in header files.
> + */
> +#ifdef __SANITIZE_ADDRESS__
> +static inline bool kasan_check_read(const volatile void *p, unsigned int size)
> +{ return __kasan_check_read(p, size); }
> +static inline bool kasan_check_write(const volatile void *p, unsigned int size)
> +{ return __kasan_check_read(p, size); }
> +#else
> +static inline bool kasan_check_read(const volatile void *p, unsigned int size)
> +{ return true; }
> +static inline bool kasan_check_write(const volatile void *p, unsigned int size)
> +{ return true; }

As the body doesn't fit on the same line as the prototype, please follow
the usual coding style:

#ifdef ____SANITIZE_ADDRESS__
static inline bool kasan_check_read(const volatile void *p, unsigned int size)
{
	return __kasan_check_read(p, size);
}

static inline bool kasan_check_write(const volatile void *p, unsigned int size)
{
	return __kasan_check_read(p, size);
}
#else
static inline bool kasan_check_read(const volatile void *p, unsigned int size)
{
	return true;
}

static inline bool kasan_check_write(const volatile void *p, unsigned int size)
{
	return true;
}
#endif

... or use __is_defined() to do the check within the body, .e.g

static inline bool kasan_check_read(const volatile void *p, unsigned int size)
{
	if (__is_defined(__SANITIZE_ADDRESS__))
		return __kasan_check_read(p, size);
	else
		return true;
}

Thanks,
Mark.

>  #endif
>  
>  #endif
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 242fdc01aaa9..2277b82902d8 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -14,8 +14,6 @@
>   *
>   */
>  
> -#define __KASAN_INTERNAL
> -
>  #include <linux/export.h>
>  #include <linux/interrupt.h>
>  #include <linux/init.h>
> @@ -89,17 +87,17 @@ void kasan_disable_current(void)
>  	current->kasan_depth--;
>  }
>  
> -void kasan_check_read(const volatile void *p, unsigned int size)
> +bool __kasan_check_read(const volatile void *p, unsigned int size)
>  {
> -	check_memory_region((unsigned long)p, size, false, _RET_IP_);
> +	return check_memory_region((unsigned long)p, size, false, _RET_IP_);
>  }
> -EXPORT_SYMBOL(kasan_check_read);
> +EXPORT_SYMBOL(__kasan_check_read);
>  
> -void kasan_check_write(const volatile void *p, unsigned int size)
> +bool __kasan_check_write(const volatile void *p, unsigned int size)
>  {
> -	check_memory_region((unsigned long)p, size, true, _RET_IP_);
> +	return check_memory_region((unsigned long)p, size, true, _RET_IP_);
>  }
> -EXPORT_SYMBOL(kasan_check_write);
> +EXPORT_SYMBOL(__kasan_check_write);
>  
>  #undef memset
>  void *memset(void *addr, int c, size_t len)
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 504c79363a34..616f9dd82d12 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -166,29 +166,30 @@ static __always_inline bool memory_is_poisoned(unsigned long addr, size_t size)
>  	return memory_is_poisoned_n(addr, size);
>  }
>  
> -static __always_inline void check_memory_region_inline(unsigned long addr,
> +static __always_inline bool check_memory_region_inline(unsigned long addr,
>  						size_t size, bool write,
>  						unsigned long ret_ip)
>  {
>  	if (unlikely(size == 0))
> -		return;
> +		return true;
>  
>  	if (unlikely((void *)addr <
>  		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
>  		kasan_report(addr, size, write, ret_ip);
> -		return;
> +		return false;
>  	}
>  
>  	if (likely(!memory_is_poisoned(addr, size)))
> -		return;
> +		return true;
>  
>  	kasan_report(addr, size, write, ret_ip);
> +	return false;
>  }
>  
> -void check_memory_region(unsigned long addr, size_t size, bool write,
> +bool check_memory_region(unsigned long addr, size_t size, bool write,
>  				unsigned long ret_ip)
>  {
> -	check_memory_region_inline(addr, size, write, ret_ip);
> +	return check_memory_region_inline(addr, size, write, ret_ip);
>  }
>  
>  void kasan_cache_shrink(struct kmem_cache *cache)
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 3ce956efa0cb..e62ea45d02e3 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -123,7 +123,15 @@ static inline bool addr_has_shadow(const void *addr)
>  
>  void kasan_poison_shadow(const void *address, size_t size, u8 value);
>  
> -void check_memory_region(unsigned long addr, size_t size, bool write,
> +/**
> + * check_memory_region - Check memory region, and report if invalid access.
> + * @addr: the accessed address
> + * @size: the accessed size
> + * @write: true if access is a write access
> + * @ret_ip: return address
> + * @return: true if access was valid, false if invalid
> + */
> +bool check_memory_region(unsigned long addr, size_t size, bool write,
>  				unsigned long ret_ip);
>  
>  void *find_first_bad_addr(void *addr, size_t size);
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 63fca3172659..0e987c9ca052 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -76,7 +76,7 @@ void *kasan_reset_tag(const void *addr)
>  	return reset_tag(addr);
>  }
>  
> -void check_memory_region(unsigned long addr, size_t size, bool write,
> +bool check_memory_region(unsigned long addr, size_t size, bool write,
>  				unsigned long ret_ip)
>  {
>  	u8 tag;
> @@ -84,7 +84,7 @@ void check_memory_region(unsigned long addr, size_t size, bool write,
>  	void *untagged_addr;
>  
>  	if (unlikely(size == 0))
> -		return;
> +		return true;
>  
>  	tag = get_tag((const void *)addr);
>  
> @@ -106,22 +106,24 @@ void check_memory_region(unsigned long addr, size_t size, bool write,
>  	 * set to KASAN_TAG_KERNEL (0xFF)).
>  	 */
>  	if (tag == KASAN_TAG_KERNEL)
> -		return;
> +		return true;
>  
>  	untagged_addr = reset_tag((const void *)addr);
>  	if (unlikely(untagged_addr <
>  			kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
>  		kasan_report(addr, size, write, ret_ip);
> -		return;
> +		return false;
>  	}
>  	shadow_first = kasan_mem_to_shadow(untagged_addr);
>  	shadow_last = kasan_mem_to_shadow(untagged_addr + size - 1);
>  	for (shadow = shadow_first; shadow <= shadow_last; shadow++) {
>  		if (*shadow != tag) {
>  			kasan_report(addr, size, write, ret_ip);
> -			return;
> +			return false;
>  		}
>  	}
> +
> +	return true;
>  }
>  
>  #define DEFINE_HWASAN_LOAD_STORE(size)					\
> -- 
> 2.22.0.410.gd8fdbe21b5-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190626124414.GC20635%40lakrids.cambridge.arm.com.
For more options, visit https://groups.google.com/d/optout.
