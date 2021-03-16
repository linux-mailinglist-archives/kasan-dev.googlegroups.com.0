Return-Path: <kasan-dev+bncBDDL3KWR4EBRBBMLYSBAMGQEXZRJ6AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id A90B733DD4F
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 20:22:46 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id v5sf24001415ioq.19
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 12:22:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615922565; cv=pass;
        d=google.com; s=arc-20160816;
        b=omyCShGAt1RGWGsG8dj2Jmp3kbDSUF11mw/LV3GVOuiC9QMHEEtM2A+uJlpn/hH6SU
         XfBsJ6L3rWLij58BRVR5qFh568GrCiizL6aMQamO6KEEWTNojqkkHz0b+bZZtTca3dpJ
         bJxfBypN6Za3bzzwrqtjaSIrQVkXHX0Lpsm1fuI96E4soa+3+YplN/EeyoFpPTVdsYy3
         xqM9//2dh2A/XtdCALS6JNGXWmnDUQm1Ypv/7RAMydUNIr1QPEBOjZa9UqYBzL0ogesD
         IyVCYPcquUuI4GQeuwW2bAKr10jMN0/snALkdZa/XIv5a59YamBimbA14rAAkTUctv4J
         vJhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=bgXd8CwOrkz8AmBC+GqZU/U4zZ1B2gKm2jCscN0qUFY=;
        b=i5gj51XcMLjqcLL1Bc7yGp2kTR3go5FMQxLY/pvgb+Ys/DsT1XNbYtwBB83IX9RFHo
         aKcNf/jYLhlTbXZrf1Gh1XyrLuQWMse/O8S/2Mz9px3dqO4Gt2/tmWfU7+QWwdjcpKQ2
         b2g/40i93x56Eajr/7jAzDEPFY4v3QCuFGlIucxyVXaaKgN2R+yw9SVUG+Oz/5SAe2Pm
         1hHkXmnZz3yYKn88urEQUo1IGBaTThS47v4yvq/Xqq/mWGpuA3s4+fALlwsIgWVwAiKm
         pX4dOOA/0j5JPMa+k82KB7Hovllwz3y2ai6vQjGrtU98lqgmJMIjeSpRBk98y3IH6NWM
         SOPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bgXd8CwOrkz8AmBC+GqZU/U4zZ1B2gKm2jCscN0qUFY=;
        b=kON+7G7LQY/X+thoodwJFCqRPspEugkyEBEeStl9365VMXbAydoThh9sFQvpvK/rOm
         Sl9p37ifZJ2NJA2qBZHc+qfPInPd6nXy5bCvHGFr+zS/PSYNydEJnUau7l4sz8BTFZh+
         KhGVrJ2E3S7Lmdz84jgqDR93Ia9UcNB3W2onlay7zpXC9S0uYBV26G4CsUiFsJ/ug9SZ
         3gWnYBfVsN0AB3iASNqP95QBzRwvIbhHeNEPMsFp60EWjE+Cc7ec0Sxc7Kga1rmzoTt5
         YKGSrZJ9/BSm5HdHbsv0Wx1iGxeiHhy0hlc3SurDgn+4z8CsvG01ccoJvilu98XXqeyU
         Q9Sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bgXd8CwOrkz8AmBC+GqZU/U4zZ1B2gKm2jCscN0qUFY=;
        b=NRrcCQS5emlrwvyK0I9C25TNoGZv9t2vN1l3538DUhWpovYKehPHoxvNvVuSiXaRPm
         xm7VMC4Nu2NgA/frglpoffiUz7TUssCounI5PmUYNDFmuYW4bSlanQOsIg+CGA2Gqkz8
         vAXnemocvh/woY8cbv6ctCc1/rMx+fb2496BvbxJjpmKT+p7Ohu4KfC6n9uGuig2SduQ
         dD5SJO5qZXXWfCYWWGE718O+qwC7Fu7SUHzp2vgO7yhsfOW2qf91KLpgXk14VRYp0lpA
         zqGiynZFnFKt0bh2ZBF/qHnTd/UG307KhfzlTTo4ho1QuoiAn4Iwbj8zqnHb4LXtGedY
         NQow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532PqWGJww3i2vn4GuAA3omMS2Qf7V1YPOfxHw9Ryo2T6Pw4QNc3
	X2Iipia/zByJ26d2MaQFP5w=
X-Google-Smtp-Source: ABdhPJxZbDaQdG++aA//vAnB1s+c9p+FteAZesRMWigxpyguHftFHVONWgSj5Gt+UaZIxkuReS4JwQ==
X-Received: by 2002:a92:c690:: with SMTP id o16mr5197575ilg.256.1615922565433;
        Tue, 16 Mar 2021 12:22:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:3046:: with SMTP id u6ls2673969jak.8.gmail; Tue, 16
 Mar 2021 12:22:45 -0700 (PDT)
X-Received: by 2002:a05:6638:3a8:: with SMTP id z8mr183656jap.111.1615922565127;
        Tue, 16 Mar 2021 12:22:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615922565; cv=none;
        d=google.com; s=arc-20160816;
        b=Sqt6uz8/WIOBdvSw2f3BnUD0O8mw5DjiHA42cc/WDDp99E6dIRmxzzLLmFxzUfRWDr
         yV6iCbN8Bd7/bKePi7vZgo4R8NqTMuYBgGeKUSgon6xdJHnlIzVFcswtjua0nH0UXzND
         lRfveLwd6CyqDDWS87ompgTZ8CcdqajOTrwu97n+idbrNIU6vzHvOI5HWfaUD/4zUvRH
         2J6rsMo520fhb8S6anJXJlQMAQzu1G5Vqglm+/ol5jdU7Yt/uwMPmgTPCuIZYVn5Tgy9
         r6Z8rRC90+Yrt0MHKq7nyq+Qft6D+V3eJ51UtzidKXAelmYB2zzJsjMcYJmA7hBAc0xc
         mcFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=ma94Z6Q3aLPBbVkToLQTi1asTgK2QMtjqNCaTaW2dvM=;
        b=T/xADR9Bnqqg9Zo+N4uirmCAyoM0dhhztz51o+uRz/6M3rXVmqtBvCrz6mLkeQlGCm
         8wgONmbmCNkZNyc4xXb73OHDVFA2nLlNnbhjUsI/C1jJe+cBGuWaNLBYGiRnR5eJLqHW
         EPNPCFkRXwO4orK1uYygsX2hIj3EB9YF+O0gYbJyY5FPQfTSvUWGTgNWxqVdUA1Bw2ML
         A+pzDmjhN3FtTiMN/LWF0KzBHkU61JfIsH2Qxj0VctP00kOE+zPO65fTxUK+5EjxWvd5
         /2YK4rtCWYKSxgYE1xsdB248uChs5qSiYQ3tcBfHIPWGR9onVisWvw3q/NggRxWBhG1m
         LZYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r19si785207iov.3.2021.03.16.12.22.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Mar 2021 12:22:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id C7A6A6505E;
	Tue, 16 Mar 2021 19:22:42 +0000 (UTC)
Date: Tue, 16 Mar 2021 19:22:40 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Marco Elver <elver@google.com>
Cc: Luis Henriques <lhenriques@suse.de>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: Issue with kfence and kmemleak
Message-ID: <20210316192240.GC28565@arm.com>
References: <YFDf6iKH1p/jGnM0@suse.de>
 <YFDrGL45JxFHyajD@elver.google.com>
 <20210316181938.GA28565@arm.com>
 <YFD9JEdQNI1TqSuL@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFD9JEdQNI1TqSuL@elver.google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Mar 16, 2021 at 07:47:00PM +0100, Marco Elver wrote:
> One thing I've just run into: "BUG: KFENCE: out-of-bounds read in
> scan_block+0x6b/0x170 mm/kmemleak.c:1244"
> 
> Probably because kmemleak is passed the rounded size for the size-class,
> and not the real allocation size. Can this be fixed with
> kmemleak_ignore() only called on the KFENCE guard pages?

If it's only on the occasional object, you can do a
kmemleak_scan_area() but some care needed as this in turn allocates
memory for kmemleak internal metadata.

> I'd like kmemleak to scan the valid portion of an object allocated
> through KFENCE, but no further than that.
> 
> Or do we need to fix the size if it's a kfence object:
> 
> diff --git a/mm/kmemleak.c b/mm/kmemleak.c
> index c0014d3b91c1..fe6e3ae8e8c6 100644
> --- a/mm/kmemleak.c
> +++ b/mm/kmemleak.c
> @@ -97,6 +97,7 @@
>  #include <linux/atomic.h>
>  
>  #include <linux/kasan.h>
> +#include <linux/kfence.h>
>  #include <linux/kmemleak.h>
>  #include <linux/memory_hotplug.h>
>  
> @@ -589,7 +590,7 @@ static struct kmemleak_object *create_object(unsigned long ptr, size_t size,
>  	atomic_set(&object->use_count, 1);
>  	object->flags = OBJECT_ALLOCATED;
>  	object->pointer = ptr;
> -	object->size = size;
> +	object->size = kfence_ksize((void *)ptr) ?: size;
>  	object->excess_ref = 0;
>  	object->min_count = min_count;
>  	object->count = 0;			/* white color initially */
> 
> The alternative is to call kfence_ksize() in slab_post_alloc_hook() when
> calling kmemleak_alloc.

One of these is probably the easiest. If kfence only works on slab
objects, better to pass the right size from slab_post_alloc_hook(). If
you plan to expand it later to vmalloc(), just fix the size in
create_object().

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210316192240.GC28565%40arm.com.
