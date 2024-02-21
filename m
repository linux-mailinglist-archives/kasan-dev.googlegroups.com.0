Return-Path: <kasan-dev+bncBCX55RF23MIRBJEE3GXAMGQE4DHQ3LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A13385E61B
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 19:34:13 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-4126c262040sf265875e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 10:34:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708540453; cv=pass;
        d=google.com; s=arc-20160816;
        b=EzavFUXQI3OVAAu+5aR+jTaIphtlfemHOL6DTFu5Li6WrUQkd/fJRSRN9ICvhcg/Ul
         mRl46pj6cDJksv7kVB5jS3jZHxG6f2/4s5yoqdmfwZBUdvwYHoZSGsiwQ4zse4Xm5xbW
         Bd0d+GML/Mpc7ys8DpDU1HLHWlAvoSdATTMXUi3I5XQVcaXMyQp1yttCez3PM8v7oD+Z
         G3exYHD0DdbDppjOzXJ3m9y9WZvTPK2EYZzZn9PuJ/yzQzY1I0EroQYppBRvKcodIsmZ
         crmFPI14GA+/ecvVVLtcYKBklanrWWka/wvUhNDR7XAFMEeCLduzeevhZPe7W4/gyXYe
         mYZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=K6pCQ/5kuuF50vKacJTCqsau2HKLqAP3cN/0XdOmmNk=;
        fh=dGbLXXva0XiEUhAFBNpRcp93a1dZ4x+LSJVQOpHr/ms=;
        b=LHNukHNuf9E8JwJxQqN14r9us/2Wn7Xtw4fWTeMMko5qhEj5yMBRj0ZlpfgIy0cTaB
         XQi8lSiN4SQWsrJ4bwNdrX+htyNT43oi0TAVoVtzP/hvBB7QdTyM1usM/vjxlQJT1brG
         omVFMVJpyCasZF/mTqVq1a/+m6HssnwmIGpYhvqULWzrohHN5Sqa+jgbIQLqsgHWfV4z
         tbbwDJAskt5QewfaHifJoJZfUFMfVi1QJHCGggdERr2WDH2njgmFCt6uzVHOK70Ozs9q
         0ycadZZ9DN0g3rf/+wwOBjnVvRk/sDgcRChHOT+gCM1e+HyzQZcVpaPgjFP3FE1qzqxy
         FQvQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Z+qxW5XT;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 91.218.175.176 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708540453; x=1709145253; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=K6pCQ/5kuuF50vKacJTCqsau2HKLqAP3cN/0XdOmmNk=;
        b=AiHgIwLvxYPr7UyyZgpOebCF1xMr50WA4P99aP/4ilePn8/XsxhM2IwMhO5D3as267
         7UB7BkemHicULeu0nC9QxcBQBCSZlCnkkB9j+zJClx1ouAk5+ygLfeIR32NnqdqA5tj4
         QyiQyT0/o9ljBFdINjLeVDbzdukWiU5WItzXnJjnHE+vUrbX5IdaHFESqmGN0NnT4e3Q
         rWx16jik2Gvz2tlKyp7XIJSgVCSD6O6T6JjQIz++fMq4jPIdPEjZMG9cqI5uYXDtykSD
         QDG0iCjQSB2Pcw3rR2izLIHxpbNHZ3OznpIG43a99xQwui4uIFhzlnR5LzvHjiAaH5GQ
         B6sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708540453; x=1709145253;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=K6pCQ/5kuuF50vKacJTCqsau2HKLqAP3cN/0XdOmmNk=;
        b=PRIZZAXZZpJ+aFRqgEqhk9xdpiNLB85rr5CeHcm5rMnCp3An/KaTml8mFELz/Z08Ib
         2F3sZjcEnviMfpIxSRHwSxRky9iKIe4OSH/pYu+bOS/Ooj8901sH/TRHfJTGncp+8KFD
         ECZBiH2vTAO5gPXC5u/mVEfT4EymZdJCR22/V0gKfeUDEqGmVJ9tAw1bDDXk+tqD/78J
         ke+URY+fGy/aHLcseDrkzcVmSQXTo4CG0lUVpKBk8AL3hcRl91hQM6h48kdb4xqGoCQr
         zP+U9FwJGj7NcSzoE/rEBK3maUk9k9ch9DSRwXAWxG60vf7DH9NdT/rliKx0T6wT8EDC
         aolQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUfCrbKKtjPd/zJavksy4lugeQe4ly4NTS02fqzzk1GQvW5VyxzFMQtMxuIYQZQ7ERGvY8uRFDG2KPrqslnfyRAm6MOYy58Mw==
X-Gm-Message-State: AOJu0YyZMg4r3ns+7qsKkDz/a5455+IyNICJL9+SdzfENiZjrPKV74Ky
	W56yj+xbrwk7+VlBENumwpy8S/61+B/1T4XCLZbkRTFcbY8A0DDb
X-Google-Smtp-Source: AGHT+IF8A00F7rJj4zN24+7C0sg40j/hd7bjqqgV9+4QUwD2dS/wNPOK1ZzQ7GdmpHJqChehDcmuig==
X-Received: by 2002:a05:600c:1da4:b0:412:5a8f:3dd7 with SMTP id p36-20020a05600c1da400b004125a8f3dd7mr314692wms.5.1708540452659;
        Wed, 21 Feb 2024 10:34:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:6022:b0:412:7a11:5376 with SMTP id
 az34-20020a05600c602200b004127a115376ls18984wmb.0.-pod-prod-00-eu; Wed, 21
 Feb 2024 10:34:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWr7NSJ+YbGmSWxXWz9pAMMn/d6iTITqpDIlridBIXc46+9LgtU2TJ08megUBMiYrrTWNu86xYgSJB4qJaLdGLdZ7LNnUf8HJkDcA==
X-Received: by 2002:a05:600c:4ecc:b0:412:6c5f:d96d with SMTP id g12-20020a05600c4ecc00b004126c5fd96dmr301877wmq.11.1708540450947;
        Wed, 21 Feb 2024 10:34:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708540450; cv=none;
        d=google.com; s=arc-20160816;
        b=PVmEs/CtnslCxD5x1HgtG24guhoKOdJxDbjjQDuEKf9RnGhwALveXy2XkvEoUPfR9R
         sWBtJbPtWIZ8WfJnMPDLchSv3BvUGp/0Wz2gOsgcnwWECtU7Fgrk2OdbZj2xouImwWq5
         moImU91nynUL1YLYb+60/U6K9mMDoHLNi0I1+WV8cHO+HV0f6B/38Ju+LPGPRBdLMYQb
         0q84jfmc7dnJ0eoz/K70gfLzodXicTZaWXEWfFebFdG/QvybiMjRkXAN9Fml4V5VcR4f
         VHjfmI7YcBAWfYJaCrZJI5crVYCfjl5DoHGhrVzJkzqzSkwKVL5uSB/w1obT97RqYS0P
         H9fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=5ZfYq+o4HUAg6zk4DYlNdaruLQWY+JIsadSfBudqmUQ=;
        fh=2TnW9QHUS0LKdBPmX+w6zVMGJLN5yZLyrD5C4PFNldw=;
        b=CRrXhVU7Vl+Zl3500SyP19QXMowxZyeNZkDQC3RyK3r/90Tf1Xm8IYFt2BxU6WZ3QH
         GiUzFer0e6N3ojzbcN2L3gALgh9TGMltL7nLy9I2SUKZnzv12RpJc+7CIBLHKbQwGm43
         fYTBra/I56+CBeXupEmbvgsiEctGFQu6gix967h8For0Us7uI6OGsiVDcaV+YYOa9+TS
         /vHCRFoHcWky9vkn+RjzOydAPDfgAHJYPIxn87yGcTCVCURJ1oc694e8HPrhqiIwCdOm
         LFVSXsiOqB4gMfLVwRQ0rGRjIRsyGTJ8u04zXYI28fV3zEMRDXrp2Ts6/Gdbv9o+AmhR
         4Gdg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Z+qxW5XT;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 91.218.175.176 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-176.mta0.migadu.com (out-176.mta0.migadu.com. [91.218.175.176])
        by gmr-mx.google.com with ESMTPS id p1-20020a05600c1d8100b0040ff8f0e6acsi114074wms.0.2024.02.21.10.34.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Feb 2024 10:34:10 -0800 (PST)
Received-SPF: pass (google.com: domain of roman.gushchin@linux.dev designates 91.218.175.176 as permitted sender) client-ip=91.218.175.176;
Date: Wed, 21 Feb 2024 10:33:48 -0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Roman Gushchin <roman.gushchin@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Zheng Yejian <zhengyejian1@huawei.com>,
	Xiongwei Song <xiongwei.song@windriver.com>,
	Chengming Zhou <chengming.zhou@linux.dev>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 2/3] mm, slab: use an enum to define SLAB_ cache creation
 flags
Message-ID: <ZdZCDEFX4_UuHSWR@P9FQF9L96D.corp.robot.car>
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
 <20240220-slab-cleanup-flags-v1-2-e657e373944a@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240220-slab-cleanup-flags-v1-2-e657e373944a@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: roman.gushchin@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Z+qxW5XT;       spf=pass
 (google.com: domain of roman.gushchin@linux.dev designates 91.218.175.176 as
 permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Tue, Feb 20, 2024 at 05:58:26PM +0100, Vlastimil Babka wrote:
> The values of SLAB_ cache creation flagsare defined by hand, which is
> tedious and error-prone. Use an enum to assign the bit number and a
> __SF_BIT() macro to #define the final flags.
> 
> This renumbers the flag values, which is OK as they are only used
> internally.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  include/linux/slab.h | 81 ++++++++++++++++++++++++++++++++++++++--------------
>  mm/slub.c            |  6 ++--
>  2 files changed, 63 insertions(+), 24 deletions(-)
> 
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 6252f44115c2..f893a132dd5a 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -21,29 +21,68 @@
>  #include <linux/cleanup.h>
>  #include <linux/hash.h>
>  
> +enum _slab_flag_bits {
> +	_SLAB_CONSISTENCY_CHECKS,
> +	_SLAB_RED_ZONE,
> +	_SLAB_POISON,
> +	_SLAB_KMALLOC,
> +	_SLAB_HWCACHE_ALIGN,
> +	_SLAB_CACHE_DMA,
> +	_SLAB_CACHE_DMA32,
> +	_SLAB_STORE_USER,
> +	_SLAB_PANIC,
> +	_SLAB_TYPESAFE_BY_RCU,
> +	_SLAB_TRACE,
> +#ifdef CONFIG_DEBUG_OBJECTS
> +	_SLAB_DEBUG_OBJECTS,
> +#endif
> +	_SLAB_NOLEAKTRACE,
> +	_SLAB_NO_MERGE,
> +#ifdef CONFIG_FAILSLAB
> +	_SLAB_FAILSLAB,
> +#endif
> +#ifdef CONFIG_MEMCG_KMEM
> +	_SLAB_ACCOUNT,
> +#endif
> +#ifdef CONFIG_KASAN_GENERIC
> +	_SLAB_KASAN,
> +#endif
> +	_SLAB_NO_USER_FLAGS,
> +#ifdef CONFIG_KFENCE
> +	_SLAB_SKIP_KFENCE,
> +#endif
> +#ifndef CONFIG_SLUB_TINY
> +	_SLAB_RECLAIM_ACCOUNT,
> +#endif
> +	_SLAB_OBJECT_POISON,
> +	_SLAB_CMPXCHG_DOUBLE,
> +	_SLAB_FLAGS_LAST_BIT
> +};
> +
> +#define __SF_BIT(nr)	((slab_flags_t __force)(1U << (nr)))

I'd rename it to (__)SLAB_FLAG_BIT(), as SF is a bit cryptic, but not a strong
preference. Otherwise looks really good to me, nice cleanup.

Reviewed-by: Roman Gushchin <roman.gushchin@linux.dev>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZdZCDEFX4_UuHSWR%40P9FQF9L96D.corp.robot.car.
