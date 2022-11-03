Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBEXGR6NQMGQEDZAAQHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 642C861856C
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Nov 2022 17:57:55 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id c18-20020adfa312000000b002364fabf2cesf672451wrb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Nov 2022 09:57:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667494675; cv=pass;
        d=google.com; s=arc-20160816;
        b=NH3xXgFLg3vFRphMYctwIMSfmRQpfj82TGdsP92HY3V3FNJqgtFDoKghhkLNiXzbCZ
         8VaKmkvQ7Cn01tgPN3cL3DEubc9T6sH7Tqg2CcoBI+uLCOX8E33ut2LWAS7UdcWo++Kv
         CAkoRr70/GRHMGTibGMtlOVhq5k0a6a1zcffc/vvSFypSXhf+EJ11XgMx/IqzS4JGAcQ
         dYaNcYn8WBwLO956Bh1MLq9ksg+Vl42Ki4XGNKUzInAW8hyJ6I0cJS47rlfpfPUXm9cN
         B0tCUp72M4/svWHcNa2yz+2cgZpRixL4aPiRLNVZSrVoisWJEcEIfW7RhLg25NCoUF1E
         jWZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=S0Wi4SfLnqbikTpcczxDHam1gD2eGgqgpbNV2ivOD0o=;
        b=FdQ9Ugux3+/nI0pp5Tb4rE9MvCuHxCYl0e/nEAFH5TSE+CJWTSavGGQTZICvLFAwxN
         Ndgk1bXAZjt9Yw6NoolvF5KXS+ME1hEB3ksC7kENQNYNHKW7clUzftrQkqH9W0vOFqag
         R6a+2VTMg0p6L6Vwz/jXBxQz5E8B6LvX7xo3gD9tYxgPEH27dJYyA1d0SHy4ih+RZwjI
         a95AeNfZJ2GSsBfJljsrK4R41puQV+MHzCW5pWncr04S4+85RuEGEWF3Uku3/pPLjBte
         hwu65nCOyAKhT6BMyFHPi1C9LaDQI6knRt0NGxfs0xsV1BRPc35fPkgCydX0+bKCVwI+
         SNIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qWVIpBAf;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=3wj4J8Vy;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=S0Wi4SfLnqbikTpcczxDHam1gD2eGgqgpbNV2ivOD0o=;
        b=Cu5ge6msc9FzZBq4qN+KKdQOR/11urPbMlAmujTDR38NALxDH01uXlDiEDBUZYhIOd
         PYi1gv7usIn1xfhLYZpPCNsfSQ2oufqWb2DCUT2cpAvrNUzhyF1/0qOUw9puNqqvZj3D
         hjA1gcTrJAsgSYRVdlYQGPOEEKPGbx1scANqfd2w99sD/zNJjZBJPGgKuLU67LhRXCBQ
         6k10RuVJiViEztc5l/RS101qspqNxpujEBnImHCJHexfql7K1fdmRTMApzmeb2Y6JkmI
         bbtM2WjAPnOJgHX96sHSzM3o93/8aG5u2tN/mEhQYvElvXgeVdvbN+dxIQlw4zxcgyVx
         em2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=S0Wi4SfLnqbikTpcczxDHam1gD2eGgqgpbNV2ivOD0o=;
        b=xnarA9kNtGtSqCG+4gkJEfOmkeVCcR1QfZd3IvTh9t58XKx2g2yfSpNJM0K0lgHHi6
         d88NQpUH+FtH5CbgfNKWPrdpNmrR8FYNuAx4PKm+f4Th/r8X8PP5k6x+4sYQF+HscpDH
         jiDhcsJuSFbOHxQobBz5dBCCGsZRtqhSHydJoCBEDSXRbEi9qg+nrruxIsjUXcBAc+fQ
         LlQ1Kh0v6SnJYBD9Kgr/lDmezuihZyN21sRC+7G9cDZ+YKoytzHzoRGkcpeTZNcGOobv
         gMKZZ3IuICUaiVkM/TTUXSIHouAapUrIT8RmTtvjFXfP3VcBxNNOZHRnEbsAKxh9GaaZ
         o8+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2plIusIo9oim04OJxmcO7tJPxZLpXXirxBmgAZKHPT+sqMRAIH
	q7PGwhUlqfbciTShV5jR9R0=
X-Google-Smtp-Source: AMsMyM5aFqHr1spUKJipuj6klRpCMWJB/vQuHlCQhb82lLY49HT4SMMfUrM4ohL4/+NUiUtop8aOXw==
X-Received: by 2002:a7b:cc8c:0:b0:3cf:7b8c:d18a with SMTP id p12-20020a7bcc8c000000b003cf7b8cd18amr12131675wma.0.1667494674872;
        Thu, 03 Nov 2022 09:57:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:238:b0:22c:d34e:768c with SMTP id
 l24-20020a056000023800b0022cd34e768cls1040507wrz.0.-pod-prod-gmail; Thu, 03
 Nov 2022 09:57:53 -0700 (PDT)
X-Received: by 2002:a5d:61c8:0:b0:236:b893:9d83 with SMTP id q8-20020a5d61c8000000b00236b8939d83mr18054545wrv.354.1667494673586;
        Thu, 03 Nov 2022 09:57:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667494673; cv=none;
        d=google.com; s=arc-20160816;
        b=qXK3vrP5J0LJ6uJWThcMPCAl059CcPOt00J8hDQpzXQCHOxKMTZKUAB+XH9l/aHwdT
         fTCAQzeH7Py35KtWB21euB/tTeKbUB82mGWX1jxRfYFuBy6ICNzQNkliKqTDxMV+Eiyf
         eAQ3R211hcmCkRQuHkPJiFhmVc0aswj7Amcu40fqj5iupHxL+6ihnd7TCvS0EqmVj3Qk
         zfwebq+RNdGEazjf5E4Gkpmy7HAoQzWZi7juFfu9YQRW4TW2NbMjhoqnPy/Oy0YDfCWn
         YBeRpUYR4aa+d9p17GVtfj8DmKoHrzQbt1KOOOmSIsftcBbG+C32pyCJIC4e29dyYrfT
         TDwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=kPajYb9QcCfgn85MBno6QGeeo7jki/qMqTDWc2NpTcs=;
        b=noR2nsr2wRTpX1r6NrOoDKFdgfIOAHAOxWKXj9/W884t8FrGPhF0o2LAQzPiTcHgUW
         evNPojqSsYXeGZ5Wc3FmmsXFHb/UB4mTjy1jHfoktNAxDXPnns7lKdUBekeySUy5aKKj
         4dMDjC+QxDEF5RSeaGcPUboVBM2REpqKy2TdripM6ZQczwcnACB2G3QHnO/2HJDGb76m
         JoUyC0B4DpX/KXSo7SzJ9w7ZpRzNPgxvo1K4HZ7bUBZnEh+tROXB9nTd5E6Mg2kDlLyr
         ObMQj83jtpmldM+Sfg6eKYND46BcNb6QtpcoYsHW4jRZLLhumh1KcnjLRjBi/JFJoyxh
         x+Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qWVIpBAf;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=3wj4J8Vy;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id n23-20020a7bc5d7000000b003cf1536d24dsi23813wmk.0.2022.11.03.09.57.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 03 Nov 2022 09:57:53 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 41D2021BFF;
	Thu,  3 Nov 2022 16:57:53 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id D1E2113AAF;
	Thu,  3 Nov 2022 16:57:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id /Y+PMhDzY2M+UwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 03 Nov 2022 16:57:52 +0000
Message-ID: <8f2cc14c-d8b3-728d-7d12-13f2c1b0d8a0@suse.cz>
Date: Thu, 3 Nov 2022 17:57:52 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.0
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of
 kmalloc
Content-Language: en-US
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Feng Tang <feng.tang@intel.com>
Cc: John Thomson <lists@johnthomson.fastmail.com.au>,
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Dmitry Vyukov
 <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>,
 Andrey Konovalov <andreyknvl@gmail.com>, "Hansen, Dave"
 <dave.hansen@intel.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 Robin Murphy <robin.murphy@arm.com>, John Garry <john.garry@huawei.com>,
 Kefeng Wang <wangkefeng.wang@huawei.com>,
 Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
 "linux-mips@vger.kernel.org" <linux-mips@vger.kernel.org>
References: <Y1+0sbQ3R4DB46NX@feng-clx>
 <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
 <Y2DReuPHZungAGsU@feng-clx>
 <53b53476-bb1e-402e-9f65-fd7f0ecf94c2@app.fastmail.com>
 <Y2DngwUc7cLB0dG7@hyeyoo>
 <29271a2b-cf19-4af9-bfe5-5bcff8a23fda@app.fastmail.com>
 <097d8fba-bd10-a312-24a3-a4068c4f424c@suse.cz> <Y2NXiiAF6V2DnBrB@feng-clx>
 <f88a5d34-de05-25d7-832d-36b3a3eddd72@suse.cz> <Y2PNLENnxxpqZ74g@feng-clx>
 <Y2PR45BW2mgLLMwC@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <Y2PR45BW2mgLLMwC@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=qWVIpBAf;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=3wj4J8Vy;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does
 not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/3/22 15:36, Hyeonggon Yoo wrote:
> On Thu, Nov 03, 2022 at 10:16:12PM +0800, Feng Tang wrote:
>> On Thu, Nov 03, 2022 at 09:33:28AM +0100, Vlastimil Babka wrote:
>> [...]
>> > >> AFAICS before this patch, we "survive" "kmem_cache *s" being NULL as
>> > >> slab_pre_alloc_hook() will happen to return NULL and we bail out from
>> > >> slab_alloc_node(). But this is a side-effect, not an intended protection.
>> > >> Also the CONFIG_TRACING variant of kmalloc_trace() would have called
>> > >> trace_kmalloc dereferencing s->size anyway even before this patch.
>> > >> 
>> > >> I don't think we should add WARNS in the slab hot paths just to prevent this
>> > >> rare error of using slab too early. At most VM_WARN... would be acceptable
>> > >> but still not necessary as crashing immediately from a NULL pointer is
>> > >> sufficient.
>> > >> 
>> > >> So IMHO mips should fix their soc init, 
>> > > 
>> > > Yes, for the mips fix, John has proposed to defer the calling of prom_soc_init(),
>> > > which looks reasonable.
>> > > 
>> > >> and we should look into the
>> > >> CONFIG_TRACING=n variant of kmalloc_trace(), to pass orig_size properly.
>> > > 
>> > > You mean check if the pointer is NULL and bail out early. 
>> > 
>> > No I mean here:
>> > 
>> > #else /* CONFIG_TRACING */
>> > /* Save a function call when CONFIG_TRACING=n */
>> > static __always_inline __alloc_size(3)                                   
>> > void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
>> > {       
>> >         void *ret = kmem_cache_alloc(s, flags);
>> >                     
>> >         ret = kasan_kmalloc(s, ret, size, flags);
>> >         return ret;
>> > }
>> > 
>> > we call kmem_cache_alloc() and discard the size parameter, so it will assume
>> > s->object_size (and as the side-effect, crash if s is NULL). We shouldn't
>> > add "s is NULL?" checks, but fix passing the size - probably switch to
>> > __kmem_cache_alloc_node()? and in the following kmalloc_node_trace() analogically.
>>  
>> Got it, thanks! I might have missed it during some rebasing for the
>> kmalloc wastage debug patch.
> 
> That was good catch and I missed too!
> But FYI I'm suggesting to drop CONFIG_TRACING=n variant:
> 
> https://lore.kernel.org/linux-mm/20221101222520.never.109-kees@kernel.org/T/#m20ecf14390e406247bde0ea9cce368f469c539ed
> 
> Any thoughts?

I'll get to it, also I think we were pondering that within your series too,
but I wanted to postpone in case somebody objects to the extra function call
it creates.
But that would be for 6.2 anyway while I'll collect the fix here for 6.1.

>> 
>> How about the following fix?
>> 
>> Thanks,
>> Feng
>> 
>> ---
>> From 9f9fa9da8946fd44625f873c0f51167357075be1 Mon Sep 17 00:00:00 2001
>> From: Feng Tang <feng.tang@intel.com>
>> Date: Thu, 3 Nov 2022 21:32:10 +0800
>> Subject: [PATCH] mm/slub: Add missing orig_size parameter for wastage debug
>> 
>> commit 6edf2576a6cc ("mm/slub: enable debugging memory wasting of
>> kmalloc") was introduced for debugging kmalloc memory wastage,
>> and it missed to pass the original request size for kmalloc_trace()
>> and kmalloc_node_trace() in CONFIG_TRACING=n path.
>> 
>> Fix it by using __kmem_cache_alloc_node() with correct original
>> request size.
>> 
>> Fixes: 6edf2576a6cc ("mm/slub: enable debugging memory wasting of kmalloc")
>> Suggested-by: Vlastimil Babka <vbabka@suse.cz>
>> Signed-off-by: Feng Tang <feng.tang@intel.com>
>> ---
>>  include/linux/slab.h | 9 +++++++--
>>  1 file changed, 7 insertions(+), 2 deletions(-)
>> 
>> diff --git a/include/linux/slab.h b/include/linux/slab.h
>> index 90877fcde70b..9691afa569e1 100644
>> --- a/include/linux/slab.h
>> +++ b/include/linux/slab.h
>> @@ -469,6 +469,9 @@ void *__kmalloc_node(size_t size, gfp_t flags, int node) __assume_kmalloc_alignm
>>  							 __alloc_size(1);
>>  void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node) __assume_slab_alignment
>>  									 __malloc;
>> +void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node,
>> +				size_t orig_size, unsigned long caller) __assume_slab_alignment
>> +									 __malloc;
>>  
>>  #ifdef CONFIG_TRACING
>>  void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
>> @@ -482,7 +485,8 @@ void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
>>  static __always_inline __alloc_size(3)
>>  void *kmalloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
>>  {
>> -	void *ret = kmem_cache_alloc(s, flags);
>> +	void *ret = __kmem_cache_alloc_node(s, flags, NUMA_NO_NODE,
>> +					    size, _RET_IP_);
>>  
>>  	ret = kasan_kmalloc(s, ret, size, flags);
>>  	return ret;
>> @@ -492,7 +496,8 @@ static __always_inline __alloc_size(4)
>>  void *kmalloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
>>  			 int node, size_t size)
>>  {
>> -	void *ret = kmem_cache_alloc_node(s, gfpflags, node);
>> +	void *ret = __kmem_cache_alloc_node(s, gfpflags, node,
>> +					    size, _RET_IP_);
>>  
>>  	ret = kasan_kmalloc(s, ret, size, gfpflags);
>>  	return ret;
>> -- 
>> 2.34.1
>> 
>> 
>> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8f2cc14c-d8b3-728d-7d12-13f2c1b0d8a0%40suse.cz.
