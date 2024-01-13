Return-Path: <kasan-dev+bncBCV4DBW44YLRBROMQ6WQMGQEEI2FBPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id F262A82C8AD
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Jan 2024 02:24:27 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-204e4adcf72sf10520665fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Jan 2024 17:24:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705109061; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ch6OjExBksCUN6Szu+NJWugev78Hx8+B8n5s6hXUkO3VGRm1miggvzQdaiBMuPase4
         kTKufX+rLc9YL5yLkbxfmSWHHCFwEbcgU3CtkIfIm9IphxkBVzXD6TDnBq/61b9ZN9M+
         UHx7A7XfAhS/xxAAYB9Pa87SwqzPi+/9MJWeNLAdc4ndE9eHQCnHgN05TMiHytTfGLFW
         QaEpmKfzheRVqe7kqs4zs8TkbmY8uZaKx4aVqXktN2q+5ktCACukhdL657B4TIKqJ3BK
         MszIruud5xEAWgHDQfPJoDDSDwSa/zFQe11ErO8NJM69sIdo3pqWBCLBfGMXl426nDke
         ORmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=PkDF8nh5fy/qRrbJ3ASvwfm8H/Nic9y9zn7vz+MDqhc=;
        fh=ONaZ8uza6Q326KbPaYGMvUxVeaUBtspBHRgl2IaUgF0=;
        b=xN+QGZSi9AHyPIZ2peaYk+ykVZ2Ho1k8HP1MdacGH3qQ294LX4raqc5RWHs/HCx+NC
         4bIz+XBnXThOIaTYoIDxBhbQtIYqO0JSD1lcoYwRjktAALDu2DpakB7OkfglMdkZea0P
         rPUq8+Cd2B05eknpLvnT5CgqVylb7VAoj+GoLlYfqzgGx/lIeJ/ky9lxTDbAWeTK2B4G
         dLnL/4/rXUj/ZDnAUoPwNf1HZL0va+pDVY1IWW38UfUkS9w8zRSU1n8gtUaRxB/7QoE3
         C4NqE1qDX4uGWijUBRpGy0GbFfaOApy+VaF/qIXXt9JUFuLhghCahv5W6GgRafUpNVUq
         Py0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DN0nOVJG;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=ak@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705109061; x=1705713861; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PkDF8nh5fy/qRrbJ3ASvwfm8H/Nic9y9zn7vz+MDqhc=;
        b=Awd1Zhmd2vVpftyuz2MfEeiWIM6qiCc9bomjLTPJuYKFmgNDCs1+eYD3pdE/rPSaew
         7xfRNA3PeUYWW7tXP4kFecuNLQURLF6YCq6a/7LfsmbhNhAfTmJ7urgrEFma6mv3eLXD
         HyS6sD1u+iE9y8K6q8T8GevEFFW/P+IBxkjiB/eLL70jEE1XVh/zwtArNP0Sjjs4uIoT
         NsX/EKTmMRTNg9iR++xs4+z5MJRhcncZk8OtHnt/g+NHi1CUpi7+ml4MTTlE0W6b3teb
         DUR5Qm/8lLf0zmorAlrapX7H+F0j12NpXMyc56cmRs5Im8/y/I4syRt/nNgHIzRnjVZo
         m4ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705109061; x=1705713861;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PkDF8nh5fy/qRrbJ3ASvwfm8H/Nic9y9zn7vz+MDqhc=;
        b=D6QDisMubwUwEfWmoMoUBMPUL+IEWfw6zuwv0IjrZRqA+fdv7bW5vTwRMfe4aNcp/Z
         S5QI1wgKJf83emtiCQ73sNxyTh1Cmk5j4LfdvpL84psgnqpF/PItMKcnMw0mxbyLyMvE
         vXR7V+7EtS7nH4hu7AV+doJW3oEBKZIBMmu8Z/xP+LnxQ9E1I1GLrlDzVjq1dFdAUBxo
         We7e7sAEj4rwHLlSdzXKZAiSWVg3YloWAIH7JTFJOEyhkKNNGm8qZgaPYuLPsWUk0BOb
         rZrH9tJDvC17NIQ8OFECsB3YhvQP6pQNK3a2cE/p6PNmnayOJPuzV+iOC1gNkEN5+dZl
         auqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyUcPDQG7+sHzwRM/MmHeZsxJ1QDjiu6T78/RssA4lzOWT0Qj55
	qS5+xByj02GgEBKz3ZfCgaE=
X-Google-Smtp-Source: AGHT+IGweyJLZG2vAMJfMLF+FQx894ZlSGpxhCTPIZK7wb28R+JjfnDm0oHVGqjVTXKZJRj4emfWzA==
X-Received: by 2002:a05:6871:458a:b0:206:c836:66a1 with SMTP id nl10-20020a056871458a00b00206c83666a1mr1734587oab.41.1705109061053;
        Fri, 12 Jan 2024 17:24:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:e78c:b0:206:9c61:8284 with SMTP id
 qb12-20020a056871e78c00b002069c618284ls1369975oac.0.-pod-prod-09-us; Fri, 12
 Jan 2024 17:24:20 -0800 (PST)
X-Received: by 2002:a05:6808:bcf:b0:3bc:10b:f016 with SMTP id o15-20020a0568080bcf00b003bc010bf016mr2717045oik.82.1705109060526;
        Fri, 12 Jan 2024 17:24:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705109060; cv=none;
        d=google.com; s=arc-20160816;
        b=KIyabZFpTHD0m4WNaR0rhNJRqJ6CdFlfBYYuyEBqtp7ccHUDxqWqntpZJa3M7d2WIL
         m6xtWWO0uXLdpNQODpdymRdj2zPzcHj7a1OKJdxvxi5UQNm/E0CiI90yxOHF+EpWcI4W
         ysVEMxgmQNpjIU8/vNaaR6Pb3KDbhBBr6LKMuckQjNBdigefjdWyYtvLJUoHf0E0HqS5
         Z9PtvDH8bApT5aNPmac4G+BBs52if0wLrIQBiUXT8zH9QPDP4dHYvIs8qMIkPcEgTeA2
         FdQCGthBpcHNXasWgA9sDSARBZxt+/f2ZQWX9UtT4e0PnRkQxe3fmeB9YdygF5eCB7E9
         xjMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=UTweowvWT8P4eBLJ96VK7hlF7ZWJNG5C3dJzcCptNCo=;
        fh=ONaZ8uza6Q326KbPaYGMvUxVeaUBtspBHRgl2IaUgF0=;
        b=ERaB7O/FApNyD32niez6QoyvLVA5onppgFK0QhN9H7HASW42O/fo7E5AeS7uKWAG1/
         h0GShliOQLIBQBjwolMp2DRcCNsGJdAtvxozMt8hpAzzkU/Pe3LLnvNyJ70IonB15sw+
         7sijEKmH1qJi6WDbIcQNb3gV/ENsGnmjQOhO04UpXK0HqpGSMyug/9ZnnWZP+mX17c7P
         PqXKxJwZPJf/YjNcCYo6VRcAXPCWCViiIwMd1mp087YVM4xiPt2MrnE0+Jt0KpcPIMnk
         2/hbLR+GH8oMaWZI+/DQqbPIfr65dfd/tdIUW9H0yihST4BdXkBCi3QcurG8XOMCoh43
         tLKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=DN0nOVJG;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=ak@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.9])
        by gmr-mx.google.com with ESMTPS id ju4-20020a170903428400b001d3536821fdsi310078plb.11.2024.01.12.17.24.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Jan 2024 17:24:20 -0800 (PST)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.198.163.9;
X-IronPort-AV: E=McAfee;i="6600,9927,10951"; a="6088494"
X-IronPort-AV: E=Sophos;i="6.04,191,1695711600"; 
   d="scan'208";a="6088494"
Received: from orsmga001.jf.intel.com ([10.7.209.18])
  by fmvoesa103.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Jan 2024 17:24:18 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10951"; a="817264197"
X-IronPort-AV: E=Sophos;i="6.04,191,1695711600"; 
   d="scan'208";a="817264197"
Received: from tassilo.jf.intel.com (HELO tassilo) ([10.54.38.190])
  by orsmga001-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Jan 2024 17:24:18 -0800
Date: Fri, 12 Jan 2024 17:24:17 -0800
From: Andi Kleen <ak@linux.intel.com>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Oscar Salvador <osalvador@suse.de>, andrey.konovalov@linux.dev,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v4 12/22] lib/stackdepot: use read/write lock
Message-ID: <ZaHmQU5DouedI9kS@tassilo>
References: <cover.1700502145.git.andreyknvl@google.com>
 <9f81ffcc4bb422ebb6326a65a770bf1918634cbb.1700502145.git.andreyknvl@google.com>
 <ZZUlgs69iTTlG8Lh@localhost.localdomain>
 <87sf34lrn3.fsf@linux.intel.com>
 <CANpmjNNdWwGsD3JRcEqpq_ywwDFoxsBjz6n=6vL5YksNsPyqHw@mail.gmail.com>
 <ZZ_gssjTCyoWjjhP@tassilo>
 <ZaA8oQG-stLAVTbM@elver.google.com>
 <CA+fCnZeS=OrqSK4QVUVdS6PwzGrpg8CBj8i2Uq=VMgMcNg1FYw@mail.gmail.com>
 <CANpmjNOoidtyeQ76274SWtTYR4zZPdr1DnxhLaagHGXcKwPOhA@mail.gmail.com>
 <ZaG56XTDwPfkqkJb@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZaG56XTDwPfkqkJb@elver.google.com>
X-Original-Sender: ak@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=DN0nOVJG;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=ak@linux.intel.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Fri, Jan 12, 2024 at 11:15:05PM +0100, Marco Elver wrote:
> +		/*
> +		 * Stack traces of size 0 are never saved, and we can simply use
> +		 * the size field as an indicator if this is a new unused stack
> +		 * record in the freelist.
> +		 */
> +		stack->size = 0;

I would use WRITE_ONCE here too, at least for TSan.

> +		return NULL;
> +
> +	/*
> +	 * We maintain the invariant that the elements in front are least
> +	 * recently used, and are therefore more likely to be associated with an
> +	 * RCU grace period in the past. Consequently it is sufficient to only
> +	 * check the first entry.
> +	 */
> +	stack = list_first_entry(&free_stacks, struct stack_record, free_list);
> +	if (stack->size && !poll_state_synchronize_rcu(stack->rcu_state))

READ_ONCE (also for TSan, and might be safer long term in case the
compiler considers some fancy code transformation)

> +		return NULL;
>  
> +		stack = depot_pop_free();
> +		if (WARN_ON(!stack))

Won't you get nesting problems here if this triggers due to the print?
I assume the nmi safe printk won't consider it like an NMI.

>  	counters[DEPOT_COUNTER_FREELIST_SIZE]++;
>  	counters[DEPOT_COUNTER_FREES]++;
>  	counters[DEPOT_COUNTER_INUSE]--;
> +
> +	printk_deferred_exit();

Ah this handles the WARN_ON? Should be ok then.

-Andi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZaHmQU5DouedI9kS%40tassilo.
