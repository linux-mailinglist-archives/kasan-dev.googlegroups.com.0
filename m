Return-Path: <kasan-dev+bncBDXYDPH3S4OBBX5EUGVQMGQELSCOMVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E1C87FEB9E
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Nov 2023 10:14:09 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-50bca4c8dd7sf896670e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Nov 2023 01:14:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701335648; cv=pass;
        d=google.com; s=arc-20160816;
        b=YguQJAohXV8T3RtP0uqVHUgkrdvOGopSZ23aPEBaVVX+vCOUBp4YBwDmgdEBpbnPCV
         Sa0TAjPJcgR0jMSOa2QiYQxvgzfZr19WR5XFTZH3mdLYelux9JI8AdZCU6K4AC2V4odb
         KQuntB/9vxEtYEkW2wLT/gA3NcHiHXwnOu8UbqWNREyO2eSmwI7Z1BmWMNl/aWItEfzo
         GJIFEy/4V8zcAdkh8l2r3VGqoHUwE6OoIh7vIhF0LJ35u4c+t34cJdvSpLsUR+13rYl0
         eKQQI9xjTLY8uI61Hb4UYzyx9bemRKfafBNFgVI7oNibp+1TMapvdARbS4Az3X7GgQ+t
         ZDgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=f/hJn9wdO7pNv0zpweHGZtQzP7PEC+UUwVg9TEzQg4U=;
        fh=IqoG/Q43KwGDHJLdGpM0sloqIMOuGjCMFkz9t/Fk49o=;
        b=VpGQeRPi8T1gWmCuWioqU6tS1LFXyALlVINYCcVa8aRNH/F8K43NWdYBFEagALq4xv
         WyX0gY7LdyatmnIGj42T6qNJI+xsfw0RNF3dbD86rqvsbwDGgj0NgqsorlaZoaVr3Y7a
         63HnilnKS5ubW1L+bsKKNiY9dJ7g7W8frBYY9pwjkLpZCkPg7+6oWl+83MQyfBbvuPFo
         bIamHSIbYAxzBkBHRPjLxdHi0xd7U51xjShYLLmBic7GExJCwEZ59q8QqSbooZhezYBs
         BLCTQsGifko0SuFcdc4MauMaX4cwq7b9SyNPDLXGFBNEoTyZ0V47EPHNyUYkUkOlp8cO
         oQnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701335648; x=1701940448; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=f/hJn9wdO7pNv0zpweHGZtQzP7PEC+UUwVg9TEzQg4U=;
        b=WrZB03N4FNHbVTuBBWcySgrPff6w68oGnx5WbEh2NIS+v0AFRTKJtkzXHk19E+oYdO
         RJsSbncKUpRZumUnUQSo8ZH/aZaaKHB1fiZZPcdTTrxBGxilJd3eH1H1An1rZGrBtlwL
         /ZvAE8JJ8kicM6k26CBR2sCIFWt6Mc5NktrJ0OfFURlVm8b/Ol/CHs7QJNF9Ed4VcY2y
         YQmWFeHTKHINxyWXxMRwOglx774em4Irly0RBa9UWF2ec864DSrujY0eyydax116VdS/
         htjw9JbUp5SioD4IV2JbW9cgJEgT9POGFsEyzzMF7F6j825DaHu/YQYcMje/FKtQWSq3
         FKUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701335648; x=1701940448;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=f/hJn9wdO7pNv0zpweHGZtQzP7PEC+UUwVg9TEzQg4U=;
        b=LXhM8OhtScfU96g1GUExHPjK2YhpCeGFxFNNvGdrJ4cxhrGeg6w+1mpgtWw8o/MN6Z
         f5PbPpsTFowIhxrH6R7AXJ7AlrvkDkwNt4NCqqBkYEmpxH2EBrIqk5aGuuGmr4YFEQuM
         l7uWbpl5H4c358w+LCiHImLBQK+rZjo/GDMlLHYCZRCjP51O18+FsTnsg8f7I+Iq6SUX
         6kbay+UtrH46d3OisSw5KiKdjM0SFZvJ9PyW0ez/11pbVFMmRQDQ9nYfPZyeQM7UW4sT
         /bWIKG6Uck+LS4M2huei7YRIe2sQUWM8juKfuu9ZnYAWytgMBUVolc7Q7n6ibvncU+1D
         6VUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw5XsPMC5Ja453khhrlQ3bg3osbgIvVitjjzdxvK4XT0y/v2fNo
	+VkveMqiEDcj6Geqq3Jm1w8=
X-Google-Smtp-Source: AGHT+IGiTpzdE+GqTBYFXVYRhhTShO0Yj5+bIhSnW9cMJa+sWy7iDVFFuMca7ME98kznqqsY0/A5hQ==
X-Received: by 2002:a05:6512:3f0f:b0:50a:a14e:92c5 with SMTP id y15-20020a0565123f0f00b0050aa14e92c5mr17224787lfa.45.1701335647927;
        Thu, 30 Nov 2023 01:14:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:5d5:b0:50a:a571:5cda with SMTP id
 o21-20020a05651205d500b0050aa5715cdals173314lfo.2.-pod-prod-02-eu; Thu, 30
 Nov 2023 01:14:06 -0800 (PST)
X-Received: by 2002:a2e:9e03:0:b0:2c9:c31c:bfe8 with SMTP id e3-20020a2e9e03000000b002c9c31cbfe8mr2237466ljk.52.1701335645862;
        Thu, 30 Nov 2023 01:14:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701335645; cv=none;
        d=google.com; s=arc-20160816;
        b=M8jfgWRioMrKPFYDoC6rNNKJam3bqMFE8h5ROox/I6V138h+XJVc2z74etHzSjLVYZ
         U0wUw5niRxmuYTOyvXQYmfV5ahILjjiVRA81drrhiv9mM7r+3f6wCNd6jSj/199QLbnr
         6yv0y+VnwnJOK7jZ3xFilYoh8OQyduo8L+ZMV+N8hDDviou32+3CqNx/5kG29GOQDraf
         XaHw3Vjx89fpi2erJ8zk/iC1s63vf6A66PmvnzxTrSAUOr1c8cpTTVNLY2ghBJVmoIw3
         Qt5uKvt2ZZcONoh5+QC7KUoiBg/+tMQrYsBwO7MZPMXN5LQStjCzeLCGsizxO/EmI4cF
         REag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=6wHEp4Y1hTNAzDfV2irjriE4iDC85aq39PBbbkS7X3M=;
        fh=IqoG/Q43KwGDHJLdGpM0sloqIMOuGjCMFkz9t/Fk49o=;
        b=zdI3LJuNX4r8KDL9iu59hZGKwtloYe+RZfeNQUkKdRxoTZLZNm/jxhoEW+HY/mKnRN
         TcU8cfrCib5KpzIeeqAmT4z2PIzDyxj0+faZ4iTPCWLlKYJQOVPtqVLP7/Eu9eFERS3e
         ptJHc/LZx8Ioj7sOOeIqCk/ofpUAFZtHz+PQi9GZj9Y0M5bJsFg9u2LdRNpJIAktUgwt
         CewogmrEMmC2PUjdMoE5XEnqpW0eTdgNE2Aqgh7niYHFARBzCNm290imq1UNI1QL6+SL
         KF0aEbzHlsTVD4X/C6ZMY8TBFAVfojrVEVX0Eza+YfLpRT83a1VDLiXzCeZRCG13FTt0
         PMcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id y18-20020a2eb012000000b002c9ba61d807si42390ljk.3.2023.11.30.01.14.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 30 Nov 2023 01:14:05 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id DAEAE1FBF2;
	Thu, 30 Nov 2023 09:14:04 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id BBE6D1342E;
	Thu, 30 Nov 2023 09:14:04 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id jDaELVxSaGUJewAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 30 Nov 2023 09:14:04 +0000
Message-ID: <dbc38932-8a68-6feb-2148-615f5c2a446e@suse.cz>
Date: Thu, 30 Nov 2023 10:14:04 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH RFC v3 0/9] SLUB percpu array caches and maple tree nodes
Content-Language: en-US
To: "Christoph Lameter (Ampere)" <cl@linux.com>
Cc: Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, Matthew Wilcox <willy@infradead.org>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, maple-tree@lists.infradead.org,
 kasan-dev@googlegroups.com
References: <20231129-slub-percpu-caches-v3-0-6bcf536772bc@suse.cz>
 <b51bfc04-d770-3385-736a-01aa733c4622@linux.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <b51bfc04-d770-3385-736a-01aa733c4622@linux.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Rspamd-Server: rspamd2
X-Spamd-Result: default: False [-4.00 / 50.00];
	 TAGGED_RCPT(0.00)[];
	 REPLY(-4.00)[]
X-Spam-Score: -4.00
X-Rspamd-Queue-Id: DAEAE1FBF2
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/29/23 21:16, Christoph Lameter (Ampere) wrote:
> On Wed, 29 Nov 2023, Vlastimil Babka wrote:
> 
>> At LSF/MM I've mentioned that I see several use cases for introducing
>> opt-in percpu arrays for caching alloc/free objects in SLUB. This is my
>> first exploration of this idea, speficially for the use case of maple
>> tree nodes. The assumptions are:
> 
> Hohumm... So we are not really removing SLAB but merging SLAB features 
> into SLUB.

Hey, you've tried a similar thing back in 2010 too :)
https://lore.kernel.org/all/20100521211541.003062117@quilx.com/

In addition to per cpu slabs, we now have per cpu queues.

But importantly, it's very consciously opt-in. Whether the caches using
percpu arrays can also skip per cpu (partial) slabs, remains to be seen.

>> - percpu arrays will be faster thank bulk alloc/free which needs
>>  relatively long freelists to work well. Especially in the freeing case
>>  we need the nodes to come from the same slab (or small set of those)
> 
> Percpu arrays require the code to handle individual objects. Handling 
> freelists in partial SLABS means that numerous objects can be handled at 
> once by handling the pointer to the list of objects.
> 
> In order to make the SLUB in page freelists work better you need to have 
> larger freelist and that comes with larger page sizes. I.e. boot with
> slub_min_order=5 or so to increase performance.

In the freeing case, you might still end up with objects mixed from
different slab pages, so the detached freelist building will be inefficient.

> Also this means increasing TLB pressure. The in page freelists of SLUB 
> cause objects from the same page be served. The SLAB queueing approach
> results in objects being mixed from any address and thus neighboring 
> objects may require more TLB entries.

As Willy noted, we have 1GB entries in directmap. Also we found out that
even if there are actions that cause it to fragment, it's not worth trying
to minimize the fragmentations - https://lwn.net/Articles/931406/

>> - preallocation for the worst case of needed nodes for a tree operation
>>  that can't reclaim due to locks is wasteful. We could instead expect
>>  that most of the time percpu arrays would satisfy the constained
>>  allocations, and in the rare cases it does not we can dip into
>>  GFP_ATOMIC reserves temporarily. So instead of preallocation just
>>  prefill the arrays.
> 
> The partial percpu slabs could already do the same.

Possibly for the prefill, but efficient freeing will always be an issue.

>> - NUMA locality of the nodes is not a concern as the nodes of a
>>  process's VMA tree end up all over the place anyway.
> 
> NUMA locality is already controlled by the user through the node 
> specification for percpu slabs. All objects coming from the same in page 
> freelist of SLUB have the same NUMA locality which simplifies things.
> 
> If you would consider NUMA locality for the percpu array then you'd be
> back to my beloved alien caches. We were not able to avoid that when we 
> tuned SLAB for maximum performance.

True, it's easier not to support NUMA locality.

>> Patch 5 adds the per-cpu array caches support. Locking is stolen from
>> Mel's recent page allocator's pcplists implementation so it can avoid
>> disabling IRQs and just disable preemption, but the trylocks can fail in
>> rare situations - in most cases the locks are uncontended so the locking
>> should be cheap.
> 
> Ok the locking is new but the design follows basic SLAB queue handling.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dbc38932-8a68-6feb-2148-615f5c2a446e%40suse.cz.
