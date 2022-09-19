Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBFFXUGMQMGQEMRY3J2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id D4A7A5BCB6B
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 14:07:49 +0200 (CEST)
Received: by mail-vk1-xa3c.google.com with SMTP id 200-20020a1f18d1000000b003a0a4957a50sf6279765vky.10
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 05:07:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663589269; cv=pass;
        d=google.com; s=arc-20160816;
        b=LIz2+jVNQ+f+/qebLLJt3vAxJjqNVDN9G6X+XYvm/wtivEBeMOE36rBME9hp3qY2Ml
         Krhc5ze47d0ug36qufPOjpgZodCX5g97XHgBmwtdVhZDFs+e54PfiDJg597MCldEroPF
         NoqWYueJe929nedo4QNvUF7BFP6nxfuTIo16ksRB3T1Z5codFLcvPNFBSxGFBZwaZnMt
         R0k4QrHL8VFVaeQUyoQ3K6ug/gQtH9l5bmx6DvmelZH+jz+H/nCQKp8dvXDwB1jTkOLg
         BdG9L0NUrVZAn+yF68fTrRqxMs4JN1gf5RqhKcSZ5zSAbbW6tilwlAOEnpq7ldluYG20
         eILw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=q00yyGHAZqJgKZ2vpGc9ai+Xmw0e1m/dYNAOlEHaUog=;
        b=ox4y2c6MxkEAkauzEGQ++wfPykshiaskWVVcX2H+9OR2AxEQTvbPj6Q0p/37wxIfju
         EJ1SNhUP99BLq6wZzllyYut7JgFXTxnx8RD6QHJm0uyNpJs7KCdcehu5g4lqtSM+c3ZV
         bhz9RLmbL/43oCCwubQxxHrDl271a8BlckSMK9OYH1J89K67w6p3iG7Mke5ut51B/B/g
         leahQNbZyETt7AZmOeAUSE/XL7d+icAPsuymNxhNNTiZnzZhsyMSd+NItMHyUYhBuEBO
         bk+3JphLxBUcLI/NG+HbuarKn6ij2i6dgzwzVKy6Upc9GSTRyrQtiyqabDWReJcnfLUX
         ol/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Uy179iTK;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=q00yyGHAZqJgKZ2vpGc9ai+Xmw0e1m/dYNAOlEHaUog=;
        b=iZoFjwFy0kNgJsVzHhoEhbvPHVavwxWl/aQIR+YkyTZSeRjL+IcvJ0dMUbguUWxfWG
         UiKz4t76CYQah5GnrCR/5ddhV75leGlzMjI3lbGb8jF0vTPkCpGMdaec4VS1736Pm8CE
         icxvCob7vhViW0Y7tIgx50KWaDtT9n2fYBLkVFG07YsKRBe5hKItRmjrqQNET2mYPEGG
         DWqQz7pA/6R3p5UD1CZmQh4n0RzQTgI7hrRghXZVt7IMMVdIFUtr6fAk9za4IoW0HR3x
         DMFuEHTOm5V4fyckWKmIuNM0bKqX9cZPtMYJT2z3MQxIvk6VdMCPrdit5j+zAtIRIFoG
         JUYQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date;
        bh=q00yyGHAZqJgKZ2vpGc9ai+Xmw0e1m/dYNAOlEHaUog=;
        b=Y144ma3KhTEBMQeJcVv3dHzt6RSf092NQ9OU4m0uamUKOu1QynFevTaIpNjntLZObO
         E7dbbQVFlIY2znBLW2J3AbMcvZDN26wcvmmnPOw0oEjR0B3As8UQlkb7VdGO3vYoIYSH
         J8flSJ5UoTImWnH/WF/IBwMadE/09MhBXkL/65DVIpy41uxu26Xw8RqL9hNzYwvzXeLj
         wfoGXwTllPEFyMAGTqX1Fk9aBPjQ/g+QmqlGO9YkVjfgQpYrsZ3lNoqG+oulaD5tjf4/
         1jMK2T1cooZ36k2PEPK6y2VPT2LyBfXenDDJga2Vumf6jITp2mWDGBCGL/HA2gMcIVQm
         97gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=q00yyGHAZqJgKZ2vpGc9ai+Xmw0e1m/dYNAOlEHaUog=;
        b=Dd80RDPZNZ8w+1CKtxlucABsFepN8beD7yB1FK+v1vfdmnmrbsZMqOisCnSllYWILQ
         knNJsUI0EHza/Qo/hrM0uDFPXb27nHMq4ueysZVi1Yb0GgqrfrVPwgAGXk90FgPqTaJc
         jHckCJ7AYfS1USdRgKirZoOFk/YvVs97KlNPPwVPmS9DvxtE4qLFDkyoIRLt007lpOVV
         ZLPStl17MGOEkDvRSa2ISfaW2X0N54caKHbiPgBKNN6sR8gjvEbM5cBLFprdA+Uog6Tr
         XItHttSuR5PkCGzqunuLLra7A/XBF8kNYbbSq9cySQcpos2MMi92XfQsT/CRQLsjdPEN
         2Bgw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1Eyf0V1JS0by8cbuGyQTg8YtFUk4bI+h3Mnp9aqg0mEcRMTdv5
	A5pt7z818DkGk05RGvVp6bQ=
X-Google-Smtp-Source: AMsMyM4PL5DjTpDGmLXhBBLK6A4de6Li716SSsh6B3ePCt1eRxiZz1DeYRvLWG0Lz/0A4V7SFgVgzA==
X-Received: by 2002:a67:c005:0:b0:39a:ffd9:30b1 with SMTP id v5-20020a67c005000000b0039affd930b1mr1723091vsi.65.1663589268900;
        Mon, 19 Sep 2022 05:07:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:1384:0:b0:3a2:b7c1:635c with SMTP id 126-20020a1f1384000000b003a2b7c1635cls374305vkt.2.-pod-prod-gmail;
 Mon, 19 Sep 2022 05:07:48 -0700 (PDT)
X-Received: by 2002:a1f:1d14:0:b0:3a3:27c8:e359 with SMTP id d20-20020a1f1d14000000b003a327c8e359mr2659319vkd.1.1663589268292;
        Mon, 19 Sep 2022 05:07:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663589268; cv=none;
        d=google.com; s=arc-20160816;
        b=mpr0+pGeZpb6ff8qyC+nDBgccm7Najwgi7OLYbpv07zIl3Hho3tB8hHdrWgHJEgH4w
         TmNutEDNXD1z5xNPt0s+20JgxySIrfs+ChBWVjX7b+Ehv928Enhqa8FEo5Sbl+Vjs0te
         COkwzJyJGVvFsw/BFuz0BhPMc2ASimh9AukfC/2wT9P+VRK3Nkg4oYv42JNlaaef0M3/
         zOwpolStuH42UKWHt+s2VYl1fE6ifwFwtscdKf4ufWdl/7jyagks284QmZ6kPv0nir0n
         khaeRHZlbvEYCcSWA6f5zmjVDXN4e/JUwGhUPAmqiO0u+d9ZJDwx4/jLDmVB0jmQyxqx
         u75Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=EVK8PXwi2Ipbx2nYX9NE/Drl0fbix3hzVw5SYu8VoBw=;
        b=XbAqCwhWmjGZCWimET1LMVoYRqxQcO3zVFbhLsfkYTUECkPr78Mcvsh3jVaQmrvYNa
         yZZGZmQOvl3Hcj10+eJw3P/Eo7XlnvikRUxU+hYewQuKmEWjZdIX2WosBI7AQ0qd8G/8
         z6bsyovFG0bKd+tVwCcbSujCtXneFd75w6WB5b/Nlm1o+rXQqNsMWXgjA9L45zDRX3HO
         r6g0Ij9jiAtfnbY3gsFj2pqFoesb72r8y3wwbMX6aPgPiJMnXBr4VIeR087YS8DicVLO
         RMwaGKT5ggViQOlOGoXVKYHtBBgLAEnEMHcVK1W5E+YnlEnyMxar2A74mLoZngqP/ArP
         SaWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Uy179iTK;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id h16-20020a67ec90000000b003882da6dea8si1024234vsp.0.2022.09.19.05.07.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Sep 2022 05:07:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id p18so27690101plr.8
        for <kasan-dev@googlegroups.com>; Mon, 19 Sep 2022 05:07:48 -0700 (PDT)
X-Received: by 2002:a17:902:f7ca:b0:178:9c90:b010 with SMTP id h10-20020a170902f7ca00b001789c90b010mr5985752plw.149.1663589267834;
        Mon, 19 Sep 2022 05:07:47 -0700 (PDT)
Received: from hyeyoo ([114.29.91.56])
        by smtp.gmail.com with ESMTPSA id x5-20020a628605000000b00540d75197f2sm20956047pfd.143.2022.09.19.05.07.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 05:07:46 -0700 (PDT)
Date: Mon, 19 Sep 2022 21:07:41 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Feng Tang <feng.tang@intel.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Andrew Morton <akpm@linux-foundation.org>,
	Waiman Long <longman@redhat.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH] mm/slab_common: fix possiable double free of kmem_cache
Message-ID: <YyhbjUG3SqU8A5Me@hyeyoo>
References: <20220919031241.1358001-1-feng.tang@intel.com>
 <e38cc728-f5e5-86d1-d6a1-c3e99cc02239@suse.cz>
 <YyhY7RBLxCEuSHp9@hyeyoo>
 <e736ad09-e29d-7a76-6823-55e14fec87c1@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e736ad09-e29d-7a76-6823-55e14fec87c1@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Uy179iTK;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62a
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Sep 19, 2022 at 02:03:15PM +0200, Vlastimil Babka wrote:
> On 9/19/22 13:56, Hyeonggon Yoo wrote:
> > On Mon, Sep 19, 2022 at 11:12:38AM +0200, Vlastimil Babka wrote:
> >> On 9/19/22 05:12, Feng Tang wrote:
> >> > When doing slub_debug test, kfence's 'test_memcache_typesafe_by_rcu'
> >> > kunit test case cause a use-after-free error:
> >> >
> > 
> > If I'm not mistaken, I think the subject should be:
> > s/double free/use after free/g
> 
> Well, it's both AFAICS. By the initial use-after-free we can read a wrong
> s->flags that was modified since we freed for the first time, and it can
> lead to another kmem_cache_release() which is basically a double free.
>

Yeah, I realized that just after sending the mail ;)
it is use-after-free bug that can potentially lead to double free.

Thank you for correction!

> >> >   BUG: KASAN: use-after-free in kobject_del+0x14/0x30
> >> >   Read of size 8 at addr ffff888007679090 by task kunit_try_catch/261
> >> > 
> >> >   CPU: 1 PID: 261 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc5-next-20220916 #17
> >> >   Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
> >> >   Call Trace:
> >> >    <TASK>
> >> >    dump_stack_lvl+0x34/0x48
> >> >    print_address_description.constprop.0+0x87/0x2a5
> >> >    print_report+0x103/0x1ed
> >> >    kasan_report+0xb7/0x140
> >> >    kobject_del+0x14/0x30
> >> >    kmem_cache_destroy+0x130/0x170
> >> >    test_exit+0x1a/0x30
> >> >    kunit_try_run_case+0xad/0xc0
> >> >    kunit_generic_run_threadfn_adapter+0x26/0x50
> >> >    kthread+0x17b/0x1b0
> >> >    </TASK>
> >> > 
> >> > The cause is inside kmem_cache_destroy():
> >> > 
> >> > kmem_cache_destroy
> >> >     acquire lock/mutex
> >> >     shutdown_cache
> >> >         schedule_work(kmem_cache_release) (if RCU flag set)
> >> >     release lock/mutex
> >> >     kmem_cache_release (if RCU flag set)
> >> 
> >> 				      ^ not set
> >> 
> >> I've fixed that up.
> >> 
> >> > 
> >> > in some certain timing, the scheduled work could be run before
> >> > the next RCU flag checking which will get a wrong state.
> >> > 
> >> > Fix it by caching the RCU flag inside protected area, just like 'refcnt'
> > 
> > Very nice catch, thanks!
> > 
> > Otherwise (and with Vlastimil's fix):
> > 
> > Looks good to me.
> > Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> > 
> >> > 
> >> > Signed-off-by: Feng Tang <feng.tang@intel.com>
> >> 
> >> Thanks!
> >> 
> >> > ---
> >> > 
> >> > note:
> >> > 
> >> > The error only happens on linux-next tree, and not in Linus' tree,
> >> > which already has Waiman's commit:
> >> > 0495e337b703 ("mm/slab_common: Deleting kobject in kmem_cache_destroy()
> >> > without holding slab_mutex/cpu_hotplug_lock")
> >> 
> >> Actually that commit is already in Linus' rc5 too, so I will send your fix
> >> this week too. Added a Fixes: 0495e337b703 (...) too.
> >> 
> >> >  mm/slab_common.c | 5 ++++-
> >> >  1 file changed, 4 insertions(+), 1 deletion(-)
> >> > 
> >> > diff --git a/mm/slab_common.c b/mm/slab_common.c
> >> > index 07b948288f84..ccc02573588f 100644
> >> > --- a/mm/slab_common.c
> >> > +++ b/mm/slab_common.c
> >> > @@ -475,6 +475,7 @@ void slab_kmem_cache_release(struct kmem_cache *s)
> >> >  void kmem_cache_destroy(struct kmem_cache *s)
> >> >  {
> >> >  	int refcnt;
> >> > +	bool rcu_set;
> >> >  
> >> >  	if (unlikely(!s) || !kasan_check_byte(s))
> >> >  		return;
> >> > @@ -482,6 +483,8 @@ void kmem_cache_destroy(struct kmem_cache *s)
> >> >  	cpus_read_lock();
> >> >  	mutex_lock(&slab_mutex);
> >> >  
> >> > +	rcu_set = s->flags & SLAB_TYPESAFE_BY_RCU;
> >> > +
> >> >  	refcnt = --s->refcount;
> >> >  	if (refcnt)
> >> >  		goto out_unlock;
> >> > @@ -492,7 +495,7 @@ void kmem_cache_destroy(struct kmem_cache *s)
> >> >  out_unlock:
> >> >  	mutex_unlock(&slab_mutex);
> >> >  	cpus_read_unlock();
> >> > -	if (!refcnt && !(s->flags & SLAB_TYPESAFE_BY_RCU))
> >> > +	if (!refcnt && !rcu_set)
> >> >  		kmem_cache_release(s);
> >> >  }
> >> >  EXPORT_SYMBOL(kmem_cache_destroy);
> >> 
> > 
> 

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YyhbjUG3SqU8A5Me%40hyeyoo.
