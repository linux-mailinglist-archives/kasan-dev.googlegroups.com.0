Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBBNVUGMQMGQE3TRK5RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id BF4135BCB60
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 14:03:18 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id by40-20020a05651c1a2800b0026c4246ce71sf626226ljb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 05:03:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663588998; cv=pass;
        d=google.com; s=arc-20160816;
        b=wvUhN3ycacCToXqHmjFIgonJOHac1ATT/65Nra+5A1QFbqShKP73WIRSAiDYvqPYxU
         yHce61j7pmPVATN0mPQmGZy3SXVqLqT/6QirLv6fMenBSsymMHq+Ala6kBv2JAZayY0O
         j8cQ3eq0173JxivWm4V8/j31VJJtnjeuKbztmQXrKksoxCI2IYyCvBYspARx8dzX1EUW
         FOZyq7k7tAMRVrZxhyiLHGaxTuU8q/0OMEcdUpZoPMrfqPRH4Q0XAqgyApoLt1N9nBPJ
         oQut8UtvCTyslSjB671C5bqSJCMxa/IH6TBIhOf47LRe6OxKZR/6AShPi2/xxJcQ+jCi
         tYLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=IVwx822Y3JH4ljA8BLXdwEQmL7mwFlkL0tQ53jEqWMk=;
        b=RcGCw6CqwwOtDpcyAU/4k27FhnLLRDKeIoPb9QuuPvErocnPGjBn2cSDPpYMjWGZ4Q
         A/vwKsTkwkU/rrd1Peav1M77XIhYgeeNT/HFPBBvb5p3zW4l9HikrrxcUkl79hIb9Fxa
         nxWTSTEjFxLNnlZCfCG+B1pt2TO5rlm5SUcsidfvltpmSplmbUEVbLg9a9jzXZLOe//a
         HCC31wN+rzVG2pP/kwO1+nAfXR84PhBi5G9qp7sHePKlYf5ZMJ0xlgAy7pmD+2KGLuNw
         itry0rbfXrryDcZg7E/pd4scd/V2a8Jj3AH1hXZ+rSWzKsYVBnQp+QbJcUBHZfz5O17Z
         X6bQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1VEiDjt3;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=TmALi3dK;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date;
        bh=IVwx822Y3JH4ljA8BLXdwEQmL7mwFlkL0tQ53jEqWMk=;
        b=k7Rkqa7fvToAqNcqEm9eQAY4EVehtz8mVkrUwiA4iMFo6MZm02pzqiXQOHgnJpkJdF
         JT7rzNTwJb+7T6SRnoA9RUn8dw2Jx/41H3zheQqTJ26KlV7ir/Mt8vtLDo1/dqUBQvRR
         tFm6m8KTGu/NaRlPZuiEX0R+gw0beVeCNga59ii2hjCNHR+Nh9idUBuL8/KK/5kaWPxl
         lCdYTYWn258FKiATiov3eucMDq6qlqyzHPMLrj30+FSJDjWQOU+DY85zwmYDullnw0dF
         g5P84s8RIS4/F1pL+E6ijspAz0NZyvfFqyvoWYv8fPZNUCE6spRD0JptzWzxtUT1wzw5
         PlcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=IVwx822Y3JH4ljA8BLXdwEQmL7mwFlkL0tQ53jEqWMk=;
        b=0K0yvxPVvwEnQ/XJ0XdfQyZLieX9xcRJwtxBrzvZEKFDJSNahMO6gZ7dejnSol0wck
         v9rLa/eP0YXwuTtOWY5hRiUzH/+khgqYwDvhmkocOHOpOOvbY6ptT2PyaA/SJg3MxaSP
         1f/4wGErSBYy9cSYyXA5iWVj/D5zampzsdmL2FDlzgosdtsQRsZBngdb6si/UViSn7j8
         5LR+cgIczscQAIVjUxEuQHX5g6PiV5TKYghlljZZtKfEjMWgnZiD6nYtSdF8u1402Ahe
         FZe5Y5IQhdx9fTpD2teNa0cG1WM56CHWTFGxR+Dxm5hxoOaEHFQQpKRBx+tSWbQ9XBSn
         1y8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3INdzNZOPevcjBSUJKHlHg1PCVRERB1QfWmjutF5ILotFlSEos
	sZC7aZExuJKKkYDorwYHeXo=
X-Google-Smtp-Source: AMsMyM6ksB6Ck/TZf86XCaIgipb5ZU7gulJ6VgJtQM9Ohvd9ouzGD/jJean3NcL04/c7gjuQWeptmg==
X-Received: by 2002:a05:6512:2294:b0:49e:f3d0:4cef with SMTP id f20-20020a056512229400b0049ef3d04cefmr5754933lfu.183.1663588998205;
        Mon, 19 Sep 2022 05:03:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0:b0:49b:8c05:71a5 with SMTP id
 v16-20020a05651203b000b0049b8c0571a5ls713702lfp.0.-pod-prod-gmail; Mon, 19
 Sep 2022 05:03:16 -0700 (PDT)
X-Received: by 2002:ac2:5d26:0:b0:494:6d31:4c5b with SMTP id i6-20020ac25d26000000b004946d314c5bmr6289516lfb.358.1663588996702;
        Mon, 19 Sep 2022 05:03:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663588996; cv=none;
        d=google.com; s=arc-20160816;
        b=mrmXml1jMaMBUNuxPbW+8xYsf9PaAoM2LcQvGZYEPdKAwDYdfLaRBRBM0gAKQbGOxv
         8GjNAMEycdaugxv4Lyfya3nBki3OoOb98bTSrLo2wJlmQag21y1hcA2FOFmif9oH8zF4
         ZgQyn3dK5QhVHtXmZThOkMkCoULATathEg9EwD2yxoJm+Hdb00O8eYXyePgSZ7AYOR4J
         beGl/0O97sedw9N3iwzom+RWn4N1/PrnXzGSwEIWXFa/zBnALV3KOeDiHI9RQwDtbcg3
         bhOGyO3BV7IaU/pQMvlpkIkJT0Ve5QrNp3jYa0bKsTj5hh/sJBM/W1lSQVPR8eb1elWu
         R/dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=ManmE5V1ehdOvXYbh2CMRxzGTWmNKmsd43FJKsh3l20=;
        b=kd8qIFYXZQGUJZ5zsmMgLfwhejGj8Wz9GN5KG/F8+gfS96mAXhNQ+QiBzexBRTI4vA
         WsfhQ/exDx2kn+oG20z0OiqJ0xl3j4Ss49v+dIJlXO0yeZ/Qliw3FxglHr8GJ4YqcIt/
         /p7KO/d3g+esX5RT3IhNUsfEF+nRFVzHjFKeHn7YWfgUnSYd/t8oDV2F8pxhs89ITrwL
         eOhWwVWbsmRulSTTLJJc/+m1TycDXGlz4DfHjSZLMKBBusli04VRS85Qwb8NV64Y72rt
         uMNj7lE+aK7puPiTDmSpulQJ5pTR7kzQ9Sz5Q+1Ky+Nu0dgC3XGcj5W/jclIBkOxLzBV
         yIIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1VEiDjt3;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=TmALi3dK;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id v22-20020a05651203b600b00492ea683e72si805199lfp.2.2022.09.19.05.03.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 05:03:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id ED3041F979;
	Mon, 19 Sep 2022 12:03:15 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id BE6F813ABD;
	Mon, 19 Sep 2022 12:03:15 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id +dPELYNaKGOxHQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 19 Sep 2022 12:03:15 +0000
Message-ID: <e736ad09-e29d-7a76-6823-55e14fec87c1@suse.cz>
Date: Mon, 19 Sep 2022 14:03:15 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.2.2
Subject: Re: [PATCH] mm/slab_common: fix possiable double free of kmem_cache
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Feng Tang <feng.tang@intel.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>, Waiman Long <longman@redhat.com>,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20220919031241.1358001-1-feng.tang@intel.com>
 <e38cc728-f5e5-86d1-d6a1-c3e99cc02239@suse.cz> <YyhY7RBLxCEuSHp9@hyeyoo>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <YyhY7RBLxCEuSHp9@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=1VEiDjt3;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=TmALi3dK;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/19/22 13:56, Hyeonggon Yoo wrote:
> On Mon, Sep 19, 2022 at 11:12:38AM +0200, Vlastimil Babka wrote:
>> On 9/19/22 05:12, Feng Tang wrote:
>> > When doing slub_debug test, kfence's 'test_memcache_typesafe_by_rcu'
>> > kunit test case cause a use-after-free error:
>> >
> 
> If I'm not mistaken, I think the subject should be:
> s/double free/use after free/g

Well, it's both AFAICS. By the initial use-after-free we can read a wrong
s->flags that was modified since we freed for the first time, and it can
lead to another kmem_cache_release() which is basically a double free.

>> >   BUG: KASAN: use-after-free in kobject_del+0x14/0x30
>> >   Read of size 8 at addr ffff888007679090 by task kunit_try_catch/261
>> > 
>> >   CPU: 1 PID: 261 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc5-next-20220916 #17
>> >   Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
>> >   Call Trace:
>> >    <TASK>
>> >    dump_stack_lvl+0x34/0x48
>> >    print_address_description.constprop.0+0x87/0x2a5
>> >    print_report+0x103/0x1ed
>> >    kasan_report+0xb7/0x140
>> >    kobject_del+0x14/0x30
>> >    kmem_cache_destroy+0x130/0x170
>> >    test_exit+0x1a/0x30
>> >    kunit_try_run_case+0xad/0xc0
>> >    kunit_generic_run_threadfn_adapter+0x26/0x50
>> >    kthread+0x17b/0x1b0
>> >    </TASK>
>> > 
>> > The cause is inside kmem_cache_destroy():
>> > 
>> > kmem_cache_destroy
>> >     acquire lock/mutex
>> >     shutdown_cache
>> >         schedule_work(kmem_cache_release) (if RCU flag set)
>> >     release lock/mutex
>> >     kmem_cache_release (if RCU flag set)
>> 
>> 				      ^ not set
>> 
>> I've fixed that up.
>> 
>> > 
>> > in some certain timing, the scheduled work could be run before
>> > the next RCU flag checking which will get a wrong state.
>> > 
>> > Fix it by caching the RCU flag inside protected area, just like 'refcnt'
> 
> Very nice catch, thanks!
> 
> Otherwise (and with Vlastimil's fix):
> 
> Looks good to me.
> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> 
>> > 
>> > Signed-off-by: Feng Tang <feng.tang@intel.com>
>> 
>> Thanks!
>> 
>> > ---
>> > 
>> > note:
>> > 
>> > The error only happens on linux-next tree, and not in Linus' tree,
>> > which already has Waiman's commit:
>> > 0495e337b703 ("mm/slab_common: Deleting kobject in kmem_cache_destroy()
>> > without holding slab_mutex/cpu_hotplug_lock")
>> 
>> Actually that commit is already in Linus' rc5 too, so I will send your fix
>> this week too. Added a Fixes: 0495e337b703 (...) too.
>> 
>> >  mm/slab_common.c | 5 ++++-
>> >  1 file changed, 4 insertions(+), 1 deletion(-)
>> > 
>> > diff --git a/mm/slab_common.c b/mm/slab_common.c
>> > index 07b948288f84..ccc02573588f 100644
>> > --- a/mm/slab_common.c
>> > +++ b/mm/slab_common.c
>> > @@ -475,6 +475,7 @@ void slab_kmem_cache_release(struct kmem_cache *s)
>> >  void kmem_cache_destroy(struct kmem_cache *s)
>> >  {
>> >  	int refcnt;
>> > +	bool rcu_set;
>> >  
>> >  	if (unlikely(!s) || !kasan_check_byte(s))
>> >  		return;
>> > @@ -482,6 +483,8 @@ void kmem_cache_destroy(struct kmem_cache *s)
>> >  	cpus_read_lock();
>> >  	mutex_lock(&slab_mutex);
>> >  
>> > +	rcu_set = s->flags & SLAB_TYPESAFE_BY_RCU;
>> > +
>> >  	refcnt = --s->refcount;
>> >  	if (refcnt)
>> >  		goto out_unlock;
>> > @@ -492,7 +495,7 @@ void kmem_cache_destroy(struct kmem_cache *s)
>> >  out_unlock:
>> >  	mutex_unlock(&slab_mutex);
>> >  	cpus_read_unlock();
>> > -	if (!refcnt && !(s->flags & SLAB_TYPESAFE_BY_RCU))
>> > +	if (!refcnt && !rcu_set)
>> >  		kmem_cache_release(s);
>> >  }
>> >  EXPORT_SYMBOL(kmem_cache_destroy);
>> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e736ad09-e29d-7a76-6823-55e14fec87c1%40suse.cz.
