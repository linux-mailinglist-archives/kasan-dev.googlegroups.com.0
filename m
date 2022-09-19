Return-Path: <kasan-dev+bncBCKJJ7XLVUBBB5NRUGMQMGQEMYFTT3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 066555BCB42
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 13:56:39 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id g15-20020aa7874f000000b0053e8b9630c7sf17232400pfo.19
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 04:56:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663588597; cv=pass;
        d=google.com; s=arc-20160816;
        b=tPB7BwWthc+WE9df77Fqpf9wJ/n43SFm+4a/LZXCs80apNi0KWGH4WLVo+/VbeQjDx
         h2h26/6+lqyYz7so1peeSXvuqwklQLYQmnAWOcVyKNtbY77SiXW4Vz20oYYZHNqpGnaq
         Ptj6KNXwHhYOGVS2vFZii3GDQzNdOhZN+7iMd8DpHaZToKzM7jJC746Ondye0JX3GvoV
         MaLUxl/f90yw+FD+pMrRwtGG2R6ZvVerAW4hCRbkq5LWSwnJMq2crpaxxV6562A4iX0g
         qSlfTBXXOTl4ogYKy9UjtFhPeJjwjJ9VwwzlSbidqEddN2Ch6KZDqT7iTz7CbhfZdoBT
         j4lQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=1eZTjX9YI0K3cd+VZd6pEGu6EuYmRCaDwvOVXAD4LAg=;
        b=Kb0/OC0heYjvIdLSMdiQ5x5vzN1fvatgmZh3nqIorjiIZYw4YbdXi7B1mKNvFVTPJp
         g4LEDpngks5Q5+qeDiEIcFt5sLlohlrOixsK3k/4lZcx/0UuTRLaAHZ4GN95xwIbswWl
         j2d278x7Ft43pSswPheGxHYGbP98HW9PpNFG3rz8vR8i5wqniiveCnfJ9GpQKjTXr7Nq
         C1sIycshZmfum9Lwv5UKlw2Dg3EfDIknyEDpIm0u6FlkrebwCQE6EP4giFjpY5XUEIOX
         zLeReJpb8I5Em2Rl3LEKifQAPkYrGpegbRZKqv4HNpSOFKO6pPwckVUVnUPOOhkux6cY
         eBYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=NaOuw8SS;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=1eZTjX9YI0K3cd+VZd6pEGu6EuYmRCaDwvOVXAD4LAg=;
        b=WWoa4PSOKei3SSJzhWEzP5aavbv9HqNjwOB3TeXGB+lXMLSRK4zRSZkWPO9CuiB7gg
         B90Kf3VhS4p9BU6SyJgBF1D237mKGV0SG4F56132pK2aX6x14yGy2xoVuEq1jtmimhd6
         o6YSs8uYhS9C34ADYmxNEi/FyLHBj0zy6N2N4RFEU1rAZIK7SMYsMWHiSbq/PNV4Dnd1
         NZIQyY+7ptTITIktI0cMtVJSEp5voRnwqY/C4Fl0M5f56iqG1m2RJFkttBXdGxQgP2pJ
         4C8tMXUVBylWXVKMEmPYAPV1Mrte6Q18ToqiLXVCgdVVI18w4EHbcuHLQQ2GU+xeMzgJ
         wHNQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date;
        bh=1eZTjX9YI0K3cd+VZd6pEGu6EuYmRCaDwvOVXAD4LAg=;
        b=mqCqQf/A5eJJIAndDZ+c1EL91bB6wD0fNtiyK7APZ/zlU88kEzSWeZ1cTwp+mhbd9p
         E2tb/D0VtpU+xTdXQuqDi4pzVxggXAo278k7ZoZpxJsthn1SEnrQRlgSZd5qDmPuuJWB
         XYDasPAwckA2yVx/LQ3/JwSIfkNIh88iBh2LK262QxjrLvn15rttkVcdATzeNBmX12M3
         n9uqWvXqBpykqb5scR3IV1+rVEdtjtlkgjiwvj96ICHAU9YxSeYSNZ6AoKERwikAbw3y
         ySTj8hUtVMMCXKvGbdZA7vkRNDK6qI5fSwnA9xmME//7Jrx0NQpn0RW0x1MTur7D+P4n
         pkWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=1eZTjX9YI0K3cd+VZd6pEGu6EuYmRCaDwvOVXAD4LAg=;
        b=GdxP6aH7uQbrU/HK0b9sWU5PPzT3FwUvkU85mqO/sQHS7MKWYTob07IKmgengu64Cv
         Z8X5+youRfWOFr5ore1/ea9V9mcmRfR1m47dvh1fVhKcRu4RDDKxixfm/tjIaDgoBUJV
         B2a8B49roPaTBWkGFj9ANkyLIexcPENgCasRJfTs/UjPk4yjVUChj+5v88n1D3waJVF0
         LUwP1mpFbI0Ef9407uccRxq3ox1qvVY5W0S+ptjMDubN1ypFbjbhPjrY+w5cFLd2AB4V
         doc4T+1J+v/rbiSpLSBYq9Ls+uhHAJPjyrLEsSX0F2Qq8zHiosSO0Ic+7//eKWYOXfJq
         36PQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf338bwlGbCW2atewhkFayKsj5etpDoTqqYsaXGUZ90Xtz9nw+oi
	IM1BZYNS9QZ+iVIoqvujB6U=
X-Google-Smtp-Source: AMsMyM7WHe+A90588bT8pyGGaw8facJ2SkAGXAWWVDyN7t73TB202RzP2ATm24MgFlVyxYEddtxQ6A==
X-Received: by 2002:a17:903:514:b0:172:dab0:b228 with SMTP id jn20-20020a170903051400b00172dab0b228mr12307767plb.170.1663588597225;
        Mon, 19 Sep 2022 04:56:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4:0:b0:430:622d:4e7b with SMTP id 4-20020a630004000000b00430622d4e7bls2536719pga.9.-pod-prod-gmail;
 Mon, 19 Sep 2022 04:56:36 -0700 (PDT)
X-Received: by 2002:a65:6693:0:b0:434:a2ca:2330 with SMTP id b19-20020a656693000000b00434a2ca2330mr15180689pgw.227.1663588596390;
        Mon, 19 Sep 2022 04:56:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663588596; cv=none;
        d=google.com; s=arc-20160816;
        b=PgMgkIaJjeurlX7Yfgkl085evHFDx8DYDd0Fjj7RaHJUIGWKYgGSo+3TFIAv5GIuyO
         k1kd9QwZQEJ9qHuksJJyhpgRr1xw9OqtNpr13uvs9OADahcQlWATyn6PLm0DHfjsozvE
         ws3450M575hNvZV/zzxeYhAnyrcHjVfdvSbd8AIEwtATvStVaYbrcY0l52iACbwOqX7b
         X4uziq7WORiIeEqTdkX+suPHbSXkOoFbx3V8o/k0zUdX6C+aZs1gCor/BmMwQ/IN20z8
         tNfZnyaDrrO/n+z/P0Ay/Yml1MF+5bcrJ+aEVuXweRfo/jqqFe+qpb0zdh2L3K2Uqm/F
         DmCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=w+dFo8W95tIbaQBNJMj5wAl0o5DxVWuVKQ51rqkGwCY=;
        b=QJSG/4qxzgy03wUFCMnH5r+Ye1psGipEV0ARQKH/utc14m8pZ3vEocqiopMV5yxPR4
         Rps21ckt7QJesaTuuyz2fz6TqHejIBB+OwPxWXAqSZiqhqVVPxihlwODlq8cDsyIq8V6
         QLXdWIScUmybRkKD0p9J+0w4dwcgbfeXvpHTDn/EVX4ZdsaXe+C7Zt7O5MVxCERFF4fH
         H/wHCI9N1ZWD4CGDAxvpi7mxR09j2TTU+3cRBaLDApXR9i92OOtdAwyM4jJjXQDFE/r3
         721AnkYNw/+wOi5ivUbtkWacJETwuSx/+k7hDGTHI9OCgbU+dhea4vs9nYJ6L5cxkrql
         M5tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=NaOuw8SS;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id e18-20020a637452000000b00423291dc756si823256pgn.5.2022.09.19.04.56.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Sep 2022 04:56:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id j12so27810013pfi.11
        for <kasan-dev@googlegroups.com>; Mon, 19 Sep 2022 04:56:36 -0700 (PDT)
X-Received: by 2002:a63:ed4d:0:b0:438:8ba7:e598 with SMTP id m13-20020a63ed4d000000b004388ba7e598mr15031564pgk.226.1663588596054;
        Mon, 19 Sep 2022 04:56:36 -0700 (PDT)
Received: from hyeyoo ([114.29.91.56])
        by smtp.gmail.com with ESMTPSA id e2-20020a17090301c200b001754e086eb3sm20543948plh.302.2022.09.19.04.56.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 04:56:35 -0700 (PDT)
Date: Mon, 19 Sep 2022 20:56:29 +0900
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
Message-ID: <YyhY7RBLxCEuSHp9@hyeyoo>
References: <20220919031241.1358001-1-feng.tang@intel.com>
 <e38cc728-f5e5-86d1-d6a1-c3e99cc02239@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e38cc728-f5e5-86d1-d6a1-c3e99cc02239@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=NaOuw8SS;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::42b
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

On Mon, Sep 19, 2022 at 11:12:38AM +0200, Vlastimil Babka wrote:
> On 9/19/22 05:12, Feng Tang wrote:
> > When doing slub_debug test, kfence's 'test_memcache_typesafe_by_rcu'
> > kunit test case cause a use-after-free error:
> >

If I'm not mistaken, I think the subject should be:
s/double free/use after free/g

> >   BUG: KASAN: use-after-free in kobject_del+0x14/0x30
> >   Read of size 8 at addr ffff888007679090 by task kunit_try_catch/261
> > 
> >   CPU: 1 PID: 261 Comm: kunit_try_catch Tainted: G    B            N 6.0.0-rc5-next-20220916 #17
> >   Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
> >   Call Trace:
> >    <TASK>
> >    dump_stack_lvl+0x34/0x48
> >    print_address_description.constprop.0+0x87/0x2a5
> >    print_report+0x103/0x1ed
> >    kasan_report+0xb7/0x140
> >    kobject_del+0x14/0x30
> >    kmem_cache_destroy+0x130/0x170
> >    test_exit+0x1a/0x30
> >    kunit_try_run_case+0xad/0xc0
> >    kunit_generic_run_threadfn_adapter+0x26/0x50
> >    kthread+0x17b/0x1b0
> >    </TASK>
> > 
> > The cause is inside kmem_cache_destroy():
> > 
> > kmem_cache_destroy
> >     acquire lock/mutex
> >     shutdown_cache
> >         schedule_work(kmem_cache_release) (if RCU flag set)
> >     release lock/mutex
> >     kmem_cache_release (if RCU flag set)
> 
> 				      ^ not set
> 
> I've fixed that up.
> 
> > 
> > in some certain timing, the scheduled work could be run before
> > the next RCU flag checking which will get a wrong state.
> > 
> > Fix it by caching the RCU flag inside protected area, just like 'refcnt'

Very nice catch, thanks!

Otherwise (and with Vlastimil's fix):

Looks good to me.
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

> > 
> > Signed-off-by: Feng Tang <feng.tang@intel.com>
> 
> Thanks!
> 
> > ---
> > 
> > note:
> > 
> > The error only happens on linux-next tree, and not in Linus' tree,
> > which already has Waiman's commit:
> > 0495e337b703 ("mm/slab_common: Deleting kobject in kmem_cache_destroy()
> > without holding slab_mutex/cpu_hotplug_lock")
> 
> Actually that commit is already in Linus' rc5 too, so I will send your fix
> this week too. Added a Fixes: 0495e337b703 (...) too.
> 
> >  mm/slab_common.c | 5 ++++-
> >  1 file changed, 4 insertions(+), 1 deletion(-)
> > 
> > diff --git a/mm/slab_common.c b/mm/slab_common.c
> > index 07b948288f84..ccc02573588f 100644
> > --- a/mm/slab_common.c
> > +++ b/mm/slab_common.c
> > @@ -475,6 +475,7 @@ void slab_kmem_cache_release(struct kmem_cache *s)
> >  void kmem_cache_destroy(struct kmem_cache *s)
> >  {
> >  	int refcnt;
> > +	bool rcu_set;
> >  
> >  	if (unlikely(!s) || !kasan_check_byte(s))
> >  		return;
> > @@ -482,6 +483,8 @@ void kmem_cache_destroy(struct kmem_cache *s)
> >  	cpus_read_lock();
> >  	mutex_lock(&slab_mutex);
> >  
> > +	rcu_set = s->flags & SLAB_TYPESAFE_BY_RCU;
> > +
> >  	refcnt = --s->refcount;
> >  	if (refcnt)
> >  		goto out_unlock;
> > @@ -492,7 +495,7 @@ void kmem_cache_destroy(struct kmem_cache *s)
> >  out_unlock:
> >  	mutex_unlock(&slab_mutex);
> >  	cpus_read_unlock();
> > -	if (!refcnt && !(s->flags & SLAB_TYPESAFE_BY_RCU))
> > +	if (!refcnt && !rcu_set)
> >  		kmem_cache_release(s);
> >  }
> >  EXPORT_SYMBOL(kmem_cache_destroy);
> 

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YyhY7RBLxCEuSHp9%40hyeyoo.
