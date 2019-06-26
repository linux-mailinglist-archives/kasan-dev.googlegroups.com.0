Return-Path: <kasan-dev+bncBDV37XP3XYDRBMNVZ3UAKGQEAX33D6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 38B3B56E8F
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 18:17:54 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id l9sf1281370wrr.0
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 09:17:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561565874; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ddnzgdjb5VisqFlTyZGroGT++Vc7CR5QmC5wa8z40CwlEtrlkwP0+anjLsD2GFXuHQ
         g7FuqRKK4mGn9L5BHj4XW2zZPTwom7PCC4e7qTi8x+y0hEnmSbqAV8SCWxwIeS6YkVpU
         RTBItwCpZzwE//CzUBw6UzezwuWoR+OGSYGXfpc0vQ9U0prxnXkiCA/S26S7Y61zbYpu
         /mRMlMB2P4yPt20LFBGd2Rhbo4GbdcblFwP8TtPRrLo3dfYkhPBVoFwcK27VS/PwHmXc
         pFma1RWb3CEvXFRRJ0woMt7u8FjUIuKBOvF4hyo5Xlqq5iTOle9VK2p6kRNYZtDXgutN
         +8Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=6AHTMAo6kHv4zGZWB0gm5kT7lPqNHXrdpKDSVVQMXKo=;
        b=eXPlhDWITX9g8kD2RVdpZ59gn/iGm3/XYABbnShl7C3gBlMncM/z/K8/zm6Cn/rrSX
         9U4ahODFknbLbrbk6NJMNLoWFCOk+eAQr+JdgBxNj2geZu361lFg/bMbjyB0cZ/HXBra
         Ll4QDoJOfGGOqrQeCmrVW7iSFZTQuNUHSBSLayrjl/qVJhWshRRPKvBEpupygBWmOPEc
         FiUjwoePNH9SIL+4NgExSvmVGx26mRFCFifATP9nfxqf5iy2hztx6/zOPKuSJYdZUZ2E
         OSPaYUE3xwRZ3COOx4p2DJCOWZglv0GAptJ76IbgwHCZPXLya9uRBIcZ7EOzrNzE87YB
         OVMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6AHTMAo6kHv4zGZWB0gm5kT7lPqNHXrdpKDSVVQMXKo=;
        b=VY5KyTvFRFma0BZEoN0rYrLil2m9lnk5SrAOdPnn9fGiHN33yKmLdHLOil8IkQOXac
         odBVyBaFliJXyWKgPEYPUjLW+pbAdyoexVgYjuhsAVnu9uxxpv48P64x7QAKhgZ1paEY
         dIrN75JnWMmf9c08Fs3ohF1MoHmyBGzfdOisLxciIxU9WVdKDMY2a4JiWt/Ll0ks5b8N
         q9KFMn94nyib24O6eb+bZbGp1NsOx5kYr9qq0K/dZxcjQybZz4DmXlRfRmUKEw+YRUt4
         urYIWYRdlIE6U3EWkNw1ffTxP+GQ/3I1j3jG2m+mHq1ogNI1RXlPdW/SSa7mLfnD0AqB
         nQGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6AHTMAo6kHv4zGZWB0gm5kT7lPqNHXrdpKDSVVQMXKo=;
        b=sc75IvKr8gZkjhEXBgnEPaoXEwzCsjHb26dBmNuKdpo3UG/yp1t8AlBPvCvSH04ocG
         xlNJ8oivsiykducqFm0LNrFuOoDjPTuMQ6/HjDag0THWewr50rcxf+7nyzVZE1oJxlq/
         fptFU7hYFRrWjefF2LnwKxHFz2dJUDTEjURLbFP/j6HVDkPhWSGx7XsuYGjJGlw/bZ+2
         yvcZ2NT02EX/8W8KdW9Tno7p8rZB71bPjunSk+QGsABMP5h1X2AlXI60Io1b4SkwhqeV
         AT5RZqzTh2kbdoBz+AQ1MOnUyEMur6amajRVwhnM+99Bzt6pQC5QBgy8jfAyUUpqoliJ
         mPug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU4n8itoukfJXuul3XIH7akl2JpYu0mgqblnNIX8f4tpCC24MvF
	2EFRTB11+2B8bk0hzHJYZdw=
X-Google-Smtp-Source: APXvYqxTihMc55N2awrKXZ5znYRDjPTVVUN45LEy/ORcspJpXtVkxRXalAesg6vlCmoWZGp5wDuXRQ==
X-Received: by 2002:adf:dc4b:: with SMTP id m11mr4691590wrj.51.1561565873952;
        Wed, 26 Jun 2019 09:17:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2d11:: with SMTP id t17ls1735354wmt.0.gmail; Wed, 26 Jun
 2019 09:17:53 -0700 (PDT)
X-Received: by 2002:a1c:20cf:: with SMTP id g198mr3377951wmg.88.1561565873142;
        Wed, 26 Jun 2019 09:17:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561565873; cv=none;
        d=google.com; s=arc-20160816;
        b=qwTJ89EibyIuBeGCKEDdahG0clBJNrzvrcM0dO018CO7GDhPqCInjDO0yehr9MBxa7
         dx3hSmtrTqxDV77cqsyIOpL84Ai89cvh8XszHjkru7SKb/QpXeTxuBB/QKjr1y3sV10j
         wwmx2AfEtRkOuS+2eOmkv5BMIsVV4CXJL3e/mn66OkCFGIXB6cDRQkqDrm1y9ZPgJaza
         rslQFjOmJMGmYVv91l1D9NCCz4GE229UKxvEmopYYDyu0dyFKYIlhU2x0E43aQ3BkSyp
         Y3leASm6ro+GMwDsTnx+C544oywOifDPN+br6kRwihZzukd5k+DSCzVTQBNAG4lZTVTe
         Q3ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=QcBn4cqu94i8F4ufUBZvWRMGOwZ2fc5S8X3LYrAGys8=;
        b=CcgsLIM8nwjXbbUsveKgAVif5CNIB7A64MYq6iyNf3YsLo3i/eo5d/V54VkTjOaZMa
         ASkpp9P+DYv8Q6ajIXyARvD/W7bXncthmyazpS2J99MI8HbVUn4uyj5XcyGsFVNMpChc
         rgGetQ3CqHbLj9JQmxuuA8KPThrDnJRIiCJcCiCfEve+fJsyWyT3pGCViyFM+aUXFdxq
         DSPZwxkSFiWw1INjyUPJV86PQsETWtOJ6pEQNNmFmulO5Gd3kxBs8vUYFzneNDPl1s+p
         h6P6+KT6Pe0SiAWw5tk6Xc2ILfwKSeknHgUzMOhl4qruaAe5yTk6yA2xFHHEvdLqvaep
         SxIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id v3si1423139wrg.3.2019.06.26.09.17.52
        for <kasan-dev@googlegroups.com>;
        Wed, 26 Jun 2019 09:17:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 458BE2B;
	Wed, 26 Jun 2019 09:17:52 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 93CED3F706;
	Wed, 26 Jun 2019 09:17:50 -0700 (PDT)
Date: Wed, 26 Jun 2019 17:17:48 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: Re: [PATCH v3 1/5] mm/kasan: Introduce __kasan_check_{read,write}
Message-ID: <20190626161748.GH20635@lakrids.cambridge.arm.com>
References: <20190626142014.141844-1-elver@google.com>
 <20190626142014.141844-2-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190626142014.141844-2-elver@google.com>
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

On Wed, Jun 26, 2019 at 04:20:10PM +0200, Marco Elver wrote:
> This introduces __kasan_check_{read,write}. __kasan_check functions may
> be used from anywhere, even compilation units that disable
> instrumentation selectively.
> 
> This change eliminates the need for the __KASAN_INTERNAL definition.
> 
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
> Cc: Mark Rutland <mark.rutland@arm.com>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-kernel@vger.kernel.org
> Cc: linux-mm@kvack.org

Logically this makes sense to me, so FWIW:

Acked-by: Mark Rutland <mark.rutland@arm.com>

Thanks,
Mark.

> ---
> v3:
> * Fix Formatting and split introduction of __kasan_check_* and returning
>   bool into 2 patches.
> ---
>  include/linux/kasan-checks.h | 31 ++++++++++++++++++++++++++++---
>  mm/kasan/common.c            | 10 ++++------
>  2 files changed, 32 insertions(+), 9 deletions(-)
> 
> diff --git a/include/linux/kasan-checks.h b/include/linux/kasan-checks.h
> index a61dc075e2ce..19a0175d2452 100644
> --- a/include/linux/kasan-checks.h
> +++ b/include/linux/kasan-checks.h
> @@ -2,9 +2,34 @@
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
> +void __kasan_check_read(const volatile void *p, unsigned int size);
> +void __kasan_check_write(const volatile void *p, unsigned int size);
> +#else
> +static inline void __kasan_check_read(const volatile void *p, unsigned int size)
> +{ }
> +static inline void __kasan_check_write(const volatile void *p, unsigned int size)
> +{ }
> +#endif
> +
> +/*
> + * kasan_check_*: Only available when the particular compilation unit has KASAN
> + * instrumentation enabled. May be used in header files.
> + */
> +#ifdef __SANITIZE_ADDRESS__
> +static inline void kasan_check_read(const volatile void *p, unsigned int size)
> +{
> +	__kasan_check_read(p, size);
> +}
> +static inline void kasan_check_write(const volatile void *p, unsigned int size)
> +{
> +	__kasan_check_read(p, size);
> +}
>  #else
>  static inline void kasan_check_read(const volatile void *p, unsigned int size)
>  { }
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 242fdc01aaa9..6bada42cc152 100644
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
> +void __kasan_check_read(const volatile void *p, unsigned int size)
>  {
>  	check_memory_region((unsigned long)p, size, false, _RET_IP_);
>  }
> -EXPORT_SYMBOL(kasan_check_read);
> +EXPORT_SYMBOL(__kasan_check_read);
>  
> -void kasan_check_write(const volatile void *p, unsigned int size)
> +void __kasan_check_write(const volatile void *p, unsigned int size)
>  {
>  	check_memory_region((unsigned long)p, size, true, _RET_IP_);
>  }
> -EXPORT_SYMBOL(kasan_check_write);
> +EXPORT_SYMBOL(__kasan_check_write);
>  
>  #undef memset
>  void *memset(void *addr, int c, size_t len)
> -- 
> 2.22.0.410.gd8fdbe21b5-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190626161748.GH20635%40lakrids.cambridge.arm.com.
For more options, visit https://groups.google.com/d/optout.
