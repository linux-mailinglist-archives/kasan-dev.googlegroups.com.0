Return-Path: <kasan-dev+bncBCS4VDMYRUNBB4UMYKZQMGQE7HQPDRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C59790BA29
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 20:54:44 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-705dc6af37dsf3658872b3a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 11:54:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718650482; cv=pass;
        d=google.com; s=arc-20160816;
        b=KNNlI0dgNnfpPycivJVqSp6UzZLtvi42scTzPrgsHjKwr5TjtnVjLrSD8pBKHCC02m
         YXJQFjMUVAN85Io8gO0FIthtEUu51f35xyEabxZc7Zft+ySwIcy9ecgN/xpd0SRCBtme
         wkeyh2xsIysCbouQ9R5SoEsFj7JohkzxPnUnlfmyDUKLVQITTUcHCaRdOgfRgkVyuWzy
         qpEWNhNwq6CFcIe4sEIaN7rTSohGsSjOP8GVOewmcXKebq18QPu4gvyHpCQSvyxqmn0r
         pDQlRmgTLaAHm2AnNDKQpVhOk94OwPhhKg/YYRirV4ILTFMme3g/rSy3V112vtO+vi4O
         fUAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=J3+IRDTslMX8BUvVyCuMAqt3BIrdOfJs/gvDCT6njo4=;
        fh=ELgbo7NrwKxLT1TYWuT6LaWuhGq3X4sSyPn3u091sDw=;
        b=d4Zauve6ZytEIVfS9MQZ+xWLqUnK0YFxOAIPsa8M/SKaiSNNOb2m76ibLoMtkqQLF7
         G1IL9rC9kZoPDulIsObI4ZRTYhVuXqFr7xevIU9Pbp7tCNGsV5bjN2HKIb9fqFvwdtX9
         Ie2LpqTOyrKenPlPlGEjnj2ualu8Y07CLBMoFRMPWV5HY3MmIuReFj18ZXO0jpaWRuRD
         9VymGAJCNbFpuC7u/WTK+uumWj44dBOpVat1B+I5vNVdO/LuMR4LELwTCQjrioxyiEp4
         NwxL8DljVBCzWMycefL6M8IK9Xe0XIt6ZZhR5SAz5+vJMaGfv9PqD3mqSzrvHxpQZqy2
         WU2Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=htDly1vi;
       spf=pass (google.com: domain of srs0=fwn3=nt=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=fWN3=NT=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718650482; x=1719255282; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=J3+IRDTslMX8BUvVyCuMAqt3BIrdOfJs/gvDCT6njo4=;
        b=wz/gFj7Qz6uij2d5GPaZtcZJO778iZc/QJLgIVhTIkCnCWCgs8z1s0kKPHr3+/tOwj
         kXC/tNZ+WxruhcLn1QEv2ZOUqGhf6VdJw9N4M7PSO35Trq/a5DoJ+vmGiKOkmVl58QLn
         r6zUkWJb1ToNBB/ROFsORvKpTpOIYwBM21k8JyAULTU4QoqYvQWpemGkzyRMi6i56fod
         WTANNkvMy/2aiXkMwbSuVIIW9GpMQbneUNVPf7VPbO/aTh2dMRMMFPEj3SojVZcMGYHC
         QID+5aWZl8FbTBUts8lMJ7jnnJiwfEPr2dR1qFaC2pOHAR56XX1df2neD7yo4P+3oxYS
         6l5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718650482; x=1719255282;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=J3+IRDTslMX8BUvVyCuMAqt3BIrdOfJs/gvDCT6njo4=;
        b=CNlGCH5CREwbnLjAmFLAx7bMOza4kdrah5GCSSMNxSjT9RUe7eXBqDJpsbWXTNk5bF
         r3WtGoX3XKTKlPye3cfWJPWUab+lCgW5AfAI7ZjG5GQGkHEhDsJSfLNmTCxPTIrZORbL
         h6rkrhEDHg2pOrcrZnvzbPS5mfsZdVewT2yICqZm5kD11RIL3u7TLLoCHLaSYnGCexLB
         A8A9D4pZ/zRC9nb5Na+oNbFIxEEYCbofptXR40IvjVxMGIn1rjpbcEX3YKG5RxKT5vdE
         BApKLSWyJfho9uKzoGgOj1fOneoHd+bgmX75zsaFh2b3V9OKliPKJExS4zupWQk5/rVQ
         Eh2A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUOqZPYSM4nxcjWdm3oFpMbfMN1vdJOntTqqztufjB+WYqWS9jXqeDxrHTsF2UHYhOOtdpdVR7YmtjEagFoCCNVAYDbOF6OjA==
X-Gm-Message-State: AOJu0Yw5Iix3b5+0G2SZx4pHLzYNYAzK2vf5esKlT9MEktobGzLStfbd
	1zVeTpQoslvWgVyTYTJp3QRygr9JOyrYY4Mn/006SrkwbGkABBhz
X-Google-Smtp-Source: AGHT+IFAmL7za0VTuKB9Ns7vd5f9bAKvr+Su5mROBFlnapasY6Poxd5PhDpiEnHIW24R67CG0mjq7w==
X-Received: by 2002:aa7:8a47:0:b0:6ed:d8d2:5040 with SMTP id d2e1a72fcca58-705d71bd78dmr12825227b3a.21.1718650482373;
        Mon, 17 Jun 2024 11:54:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1829:b0:705:a28b:24fd with SMTP id
 d2e1a72fcca58-705c94a20bfls3766228b3a.2.-pod-prod-08-us; Mon, 17 Jun 2024
 11:54:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVpLDlj33OvOykuaeMyB8OW51yv2VK5h1TZokTmkpOQLeNgRltyRQC80sC2EpAmkuvG5SIRG+YjZeXOptTcC5/T8AryGuo8updVoQ==
X-Received: by 2002:a17:90a:5996:b0:2c3:195d:8cc1 with SMTP id 98e67ed59e1d1-2c4dbb41a95mr11348230a91.37.1718650480951;
        Mon, 17 Jun 2024 11:54:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718650480; cv=none;
        d=google.com; s=arc-20160816;
        b=BTwyF4MQBQiU3f7hZFXR4C9y9d21TLEjCygDe0BrH9McM0ovxhNStEnDQotQfW612J
         bbVPiVQCuqz/lOGucuSmWFg5sjuDXgHBO/fSGqWo+ByxXDbpZ5rBdCEKWMhXQ5k4JOhM
         EBfae2kxOr9aIFwoKq8GA+6H9Dm1a0qU+fvjBABMC0IZ1e8ZAwnyx28rC4tfmzVRYhJ6
         LCjbWkFx10er8j+HMj8W3xmUMNZX9J/6x4GcWMHxV9NNYS9wJVfZ55WQpmPFsDtw3A+B
         k2LMC/dx769/ok9qY5ce755Hx3pStXboWSKEWd7hTdjIRE6MgEqO6Dsnryrrv9TLnDxI
         9vQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=v3cSuPoG5wrHHpvxnhj3Hj6DsZJDWIl+1yVDpnmg0RE=;
        fh=5twfeSx/70O7JVCGMxOXQAYvXeaup0AC7eQXbApX4l0=;
        b=SjIFki1fbge0sA4UMpX88v9X90ymc+qw/iZx4lMZxSG4gsADrZxiXXuOLkQgIazkO6
         22cGbc+iW4vNhuXLaz4v+sPyHn8Sd/NTuHuhNz45ZEL+4NzyMwNhBIA4HFEJP9WuNUUn
         EnHBBDuK63rOl941q0+BAy7UqwcgLs/AAilVjE0c1TtKf0Rjt6ybhY8B60hyTtW31jRl
         vJtEXGUqJKJg3F8hbcn9bIHjcx71xDDd6f3MmO39I4SbxSngyFi8e1q7sgiOIp4hGYDB
         fquO0rTBVn9aF8HBO9/Cx3WVra4uHrBZq2dNA6UcMSfjzvGV6qDraFVKgMRsqAAV+8Nd
         0r1w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=htDly1vi;
       spf=pass (google.com: domain of srs0=fwn3=nt=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=fWN3=NT=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c5291effb0si225511a91.0.2024.06.17.11.54.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Jun 2024 11:54:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=fwn3=nt=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 3602661257;
	Mon, 17 Jun 2024 18:54:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D4D7BC2BD10;
	Mon, 17 Jun 2024 18:54:39 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 80EC9CE09DB; Mon, 17 Jun 2024 11:54:39 -0700 (PDT)
Date: Mon, 17 Jun 2024 11:54:39 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>,
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Julia Lawall <Julia.Lawall@inria.fr>, linux-block@vger.kernel.org,
	kernel-janitors@vger.kernel.org, bridge@lists.linux.dev,
	linux-trace-kernel@vger.kernel.org,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	kvm@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Nicholas Piggin <npiggin@gmail.com>, netdev@vger.kernel.org,
	wireguard@lists.zx2c4.com, linux-kernel@vger.kernel.org,
	ecryptfs@vger.kernel.org, Neil Brown <neilb@suse.de>,
	Olga Kornievskaia <kolga@netapp.com>, Dai Ngo <Dai.Ngo@oracle.com>,
	Tom Talpey <tom@talpey.com>, linux-nfs@vger.kernel.org,
	linux-can@vger.kernel.org, Lai Jiangshan <jiangshanlai@gmail.com>,
	netfilter-devel@vger.kernel.org, coreteam@netfilter.org,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 00/14] replace call_rcu by kfree_rcu for simple
 kmem_cache_free callback
Message-ID: <1755282b-e3f5-4d18-9eab-fc6a29ca5886@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20240609082726.32742-1-Julia.Lawall@inria.fr>
 <20240612143305.451abf58@kernel.org>
 <baee4d58-17b4-4918-8e45-4d8068a23e8c@paulmck-laptop>
 <Zmov7ZaL-54T9GiM@zx2c4.com>
 <Zmo9-YGraiCj5-MI@zx2c4.com>
 <08ee7eb2-8d08-4f1f-9c46-495a544b8c0e@paulmck-laptop>
 <Zmrkkel0Fo4_g75a@zx2c4.com>
 <e926e3c6-05ce-4ba6-9e2e-e5f3b37bcc23@suse.cz>
 <3b6fe525-626c-41fb-8625-3925ca820d8e@paulmck-laptop>
 <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=htDly1vi;       spf=pass
 (google.com: domain of srs0=fwn3=nt=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=fWN3=NT=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Mon, Jun 17, 2024 at 07:23:36PM +0200, Vlastimil Babka wrote:
> On 6/17/24 6:12 PM, Paul E. McKenney wrote:
> > On Mon, Jun 17, 2024 at 05:10:50PM +0200, Vlastimil Babka wrote:
> >> On 6/13/24 2:22 PM, Jason A. Donenfeld wrote:
> >> > On Wed, Jun 12, 2024 at 08:38:02PM -0700, Paul E. McKenney wrote:
> >> >> o	Make the current kmem_cache_destroy() asynchronously wait for
> >> >> 	all memory to be returned, then complete the destruction.
> >> >> 	(This gets rid of a valuable debugging technique because
> >> >> 	in normal use, it is a bug to attempt to destroy a kmem_cache
> >> >> 	that has objects still allocated.)
> >> 
> >> This seems like the best option to me. As Jason already said, the debugging
> >> technique is not affected significantly, if the warning just occurs
> >> asynchronously later. The module can be already unloaded at that point, as
> >> the leak is never checked programatically anyway to control further
> >> execution, it's just a splat in dmesg.
> > 
> > Works for me!
> 
> Great. So this is how a prototype could look like, hopefully? The kunit test
> does generate the splat for me, which should be because the rcu_barrier() in
> the implementation (marked to be replaced with the real thing) is really
> insufficient. Note the test itself passes as this kind of error isn't wired
> up properly.

;-) ;-) ;-)

Some might want confirmation that their cleanup efforts succeeded,
but if so, I will let them make that known.

> Another thing to resolve is the marked comment about kasan_shutdown() with
> potential kfree_rcu()'s in flight.

Could that simply move to the worker function?  (Hey, had to ask!)

> Also you need CONFIG_SLUB_DEBUG enabled otherwise node_nr_slabs() is a no-op
> and it might fail to notice the pending slabs. This will need to change.

Agreed.

Looks generally good.  A few questions below, to be taken with a
grain of salt.

							Thanx, Paul

> ----8<----
> diff --git a/lib/slub_kunit.c b/lib/slub_kunit.c
> index e6667a28c014..e3e4d0ca40b7 100644
> --- a/lib/slub_kunit.c
> +++ b/lib/slub_kunit.c
> @@ -5,6 +5,7 @@
>  #include <linux/slab.h>
>  #include <linux/module.h>
>  #include <linux/kernel.h>
> +#include <linux/rcupdate.h>
>  #include "../mm/slab.h"
>  
>  static struct kunit_resource resource;
> @@ -157,6 +158,26 @@ static void test_kmalloc_redzone_access(struct kunit *test)
>  	kmem_cache_destroy(s);
>  }
>  
> +struct test_kfree_rcu_struct {
> +	struct rcu_head rcu;
> +};
> +
> +static void test_kfree_rcu(struct kunit *test)
> +{
> +	struct kmem_cache *s = test_kmem_cache_create("TestSlub_kfree_rcu",
> +				sizeof(struct test_kfree_rcu_struct),
> +				SLAB_NO_MERGE);
> +	struct test_kfree_rcu_struct *p = kmem_cache_alloc(s, GFP_KERNEL);
> +
> +	kasan_disable_current();
> +
> +	KUNIT_EXPECT_EQ(test, 0, slab_errors);
> +
> +	kasan_enable_current();
> +	kfree_rcu(p, rcu);
> +	kmem_cache_destroy(s);

Looks like the type of test for this!

> +}
> +
>  static int test_init(struct kunit *test)
>  {
>  	slab_errors = 0;
> @@ -177,6 +198,7 @@ static struct kunit_case test_cases[] = {
>  
>  	KUNIT_CASE(test_clobber_redzone_free),
>  	KUNIT_CASE(test_kmalloc_redzone_access),
> +	KUNIT_CASE(test_kfree_rcu),
>  	{}
>  };
>  
> diff --git a/mm/slab.h b/mm/slab.h
> index b16e63191578..a0295600af92 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -277,6 +277,8 @@ struct kmem_cache {
>  	unsigned int red_left_pad;	/* Left redzone padding size */
>  	const char *name;		/* Name (only for display!) */
>  	struct list_head list;		/* List of slab caches */
> +	struct work_struct async_destroy_work;
> +
>  #ifdef CONFIG_SYSFS
>  	struct kobject kobj;		/* For sysfs */
>  #endif
> @@ -474,7 +476,7 @@ static inline bool is_kmalloc_cache(struct kmem_cache *s)
>  			      SLAB_NO_USER_FLAGS)
>  
>  bool __kmem_cache_empty(struct kmem_cache *);
> -int __kmem_cache_shutdown(struct kmem_cache *);
> +int __kmem_cache_shutdown(struct kmem_cache *, bool);
>  void __kmem_cache_release(struct kmem_cache *);
>  int __kmem_cache_shrink(struct kmem_cache *);
>  void slab_kmem_cache_release(struct kmem_cache *);
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 5b1f996bed06..c5c356d0235d 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -44,6 +44,8 @@ static LIST_HEAD(slab_caches_to_rcu_destroy);
>  static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work);
>  static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
>  		    slab_caches_to_rcu_destroy_workfn);
> +static void kmem_cache_kfree_rcu_destroy_workfn(struct work_struct *work);
> +
>  
>  /*
>   * Set of flags that will prevent slab merging
> @@ -234,6 +236,7 @@ static struct kmem_cache *create_cache(const char *name,
>  
>  	s->refcount = 1;
>  	list_add(&s->list, &slab_caches);
> +	INIT_WORK(&s->async_destroy_work, kmem_cache_kfree_rcu_destroy_workfn);
>  	return s;
>  
>  out_free_cache:
> @@ -449,12 +452,16 @@ static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work)
>  	}
>  }
>  
> -static int shutdown_cache(struct kmem_cache *s)
> +static int shutdown_cache(struct kmem_cache *s, bool warn_inuse)
>  {
>  	/* free asan quarantined objects */
> +	/*
> +	 * XXX: is it ok to call this multiple times? and what happens with a
> +	 * kfree_rcu() in flight that finishes after or in parallel with this?
> +	 */
>  	kasan_cache_shutdown(s);
>  
> -	if (__kmem_cache_shutdown(s) != 0)
> +	if (__kmem_cache_shutdown(s, warn_inuse) != 0)
>  		return -EBUSY;
>  
>  	list_del(&s->list);
> @@ -477,6 +484,32 @@ void slab_kmem_cache_release(struct kmem_cache *s)
>  	kmem_cache_free(kmem_cache, s);
>  }
>  
> +static void kmem_cache_kfree_rcu_destroy_workfn(struct work_struct *work)
> +{
> +	struct kmem_cache *s;
> +	int err = -EBUSY;
> +	bool rcu_set;
> +
> +	s = container_of(work, struct kmem_cache, async_destroy_work);
> +
> +	// XXX use the real kmem_cache_free_barrier() or similar thing here
> +	rcu_barrier();
> +
> +	cpus_read_lock();
> +	mutex_lock(&slab_mutex);
> +
> +	rcu_set = s->flags & SLAB_TYPESAFE_BY_RCU;
> +
> +	err = shutdown_cache(s, true);

This is currently the only call to shutdown_cache()?  So there is to be
a way for the caller to have some influence over the value of that bool?

> +	WARN(err, "kmem_cache_destroy %s: Slab cache still has objects",
> +	     s->name);

Don't we want to have some sort of delay here?  Or is this the
21-second delay and/or kfree_rcu_barrier() mentioned before?

> +	mutex_unlock(&slab_mutex);
> +	cpus_read_unlock();
> +	if (!err && !rcu_set)
> +		kmem_cache_release(s);
> +}
> +
>  void kmem_cache_destroy(struct kmem_cache *s)
>  {
>  	int err = -EBUSY;
> @@ -494,9 +527,9 @@ void kmem_cache_destroy(struct kmem_cache *s)
>  	if (s->refcount)
>  		goto out_unlock;
>  
> -	err = shutdown_cache(s);
> -	WARN(err, "%s %s: Slab cache still has objects when called from %pS",
> -	     __func__, s->name, (void *)_RET_IP_);
> +	err = shutdown_cache(s, false);
> +	if (err)
> +		schedule_work(&s->async_destroy_work);
>  out_unlock:
>  	mutex_unlock(&slab_mutex);
>  	cpus_read_unlock();
> diff --git a/mm/slub.c b/mm/slub.c
> index 1617d8014ecd..4d435b3d2b5f 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -5342,7 +5342,8 @@ static void list_slab_objects(struct kmem_cache *s, struct slab *slab,
>   * This is called from __kmem_cache_shutdown(). We must take list_lock
>   * because sysfs file might still access partial list after the shutdowning.
>   */
> -static void free_partial(struct kmem_cache *s, struct kmem_cache_node *n)
> +static void free_partial(struct kmem_cache *s, struct kmem_cache_node *n,
> +			 bool warn_inuse)
>  {
>  	LIST_HEAD(discard);
>  	struct slab *slab, *h;
> @@ -5353,7 +5354,7 @@ static void free_partial(struct kmem_cache *s, struct kmem_cache_node *n)
>  		if (!slab->inuse) {
>  			remove_partial(n, slab);
>  			list_add(&slab->slab_list, &discard);
> -		} else {
> +		} else if (warn_inuse) {
>  			list_slab_objects(s, slab,
>  			  "Objects remaining in %s on __kmem_cache_shutdown()");
>  		}
> @@ -5378,7 +5379,7 @@ bool __kmem_cache_empty(struct kmem_cache *s)
>  /*
>   * Release all resources used by a slab cache.
>   */
> -int __kmem_cache_shutdown(struct kmem_cache *s)
> +int __kmem_cache_shutdown(struct kmem_cache *s, bool warn_inuse)
>  {
>  	int node;
>  	struct kmem_cache_node *n;
> @@ -5386,7 +5387,7 @@ int __kmem_cache_shutdown(struct kmem_cache *s)
>  	flush_all_cpus_locked(s);
>  	/* Attempt to free all objects */
>  	for_each_kmem_cache_node(s, node, n) {
> -		free_partial(s, n);
> +		free_partial(s, n, warn_inuse);
>  		if (n->nr_partial || node_nr_slabs(n))
>  			return 1;
>  	}
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1755282b-e3f5-4d18-9eab-fc6a29ca5886%40paulmck-laptop.
