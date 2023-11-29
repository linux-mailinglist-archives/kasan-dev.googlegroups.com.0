Return-Path: <kasan-dev+bncBAABBYEVTSVQMGQERZN5UVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5162D7FD35C
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 10:56:50 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-6c7c69e4367sf7426185b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 01:56:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701251809; cv=pass;
        d=google.com; s=arc-20160816;
        b=D9jVsNDU3BN3zFI2UE29fEQOE5Mgd5gMfOgWx5MHU0IPeOVlf1K3BIOZSBfhbNCZ+P
         6AztyjwkcLEhAgxdU84VCtAY+iZz7Fiin4n+p95BftvWb9QozIf/xThOtObdcORTnbGb
         /EVJZFqXfXUwufK/pG215WqqO2VBtP5I6KE3Nh3CPqVY1fOYN04BSKU04723S/KF9Ng2
         S90GF7CnEsc+rH9RwmDSjWpvonjTXh/S122PDC+VkuRSA648aQDYrvwGbdfqZx057Gsb
         bo8Wi4LlQGvFdmDQovq/1TzXSwlUGeACY1CKEwf/53o9sGJqXtsQYKWKS+d+Qk+BSrB/
         14/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:mime-version:message-id:date
         :subject:from:sender:dkim-signature;
        bh=hk88JcMw5vA6ah4vkXVcWnwbqZXL302pcPVsxI9jgIo=;
        fh=uYnIsWZ9n80gkcnhZMgoujzKtxA7UEl4GQvTBFLbimw=;
        b=IouBE3ENMUqySzFRV3tXCurtKuLlYKFG11MIHOC5pS6+tnne/HBrGyH39fP3yqNRYl
         og5/Y3brtrEHlN//eWqGPKvrJlGoVaW32dP6Ntb+3msxmWWlrZ5TP4fVvo+wsRlbhEC5
         6g/Xsll+lZfXFuSS4PgNUyYiNl3F8Qspf6ouAg6lTE17HIBWySpyvj4iEREP0ibIU/3+
         aUrLgVKh9NLJZB6Zz9CB+3OEO1FQo2Xjjn/MA5mq4l8T/dCkk5pQnx+ucr9qveDMHBkL
         /c3UEZieuD4/XvFKz7GkB/7RqiRTUTQWBvlw+XpAzdfXmOJdJ75aKmK0L/va6iUJcWJ2
         W7gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DhAjX4+x;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=AFGProdn;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701251809; x=1701856609; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=hk88JcMw5vA6ah4vkXVcWnwbqZXL302pcPVsxI9jgIo=;
        b=JzgMcC0Vxf2OFNmh6ZwbY/mL6jFiTwdbtbDo7MUxt2eUYkii/bkYE7GoCa6dnq60rY
         0w7/21wm8IfNaJ+81Oqkle6DD+fXSRhnvk0AnM36SA1l5kMx5yYDY3kfC24ZVCtEAvV1
         Z/DuGmlwXPlgSl29o6aHkB+gOk4njqLfqu/edZixKumt4625pITm6pQd9lTk07YvhSdO
         5VWmVrV49nQsrnMqXSP9whLUlqQEHAYjJqNJu4i0W08uLa5pFTBxkHhBhNd53qSyFBM/
         PuOBGAbKccN4MKOHZ3qy2ClIPmKzNlxbhBdMm9iDWeh2tlg3kFhGFxi0iFncTkEFbPsv
         tozA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701251809; x=1701856609;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:mime-version:message-id:date:subject:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hk88JcMw5vA6ah4vkXVcWnwbqZXL302pcPVsxI9jgIo=;
        b=clgK9LrdRbKXWAJrUpbGa7LT8lMoAJI7uEydqCuslnLFbq6IOJgVz43YNjak5SAtD9
         f2ZgmbZ1Ti3qX+1LUpjDaTexHYTEY6tjwI5WQEtwLamOpiUgh3/KA97YuoSSZQXBNfsB
         2zXaryQGtMeVYsKR1tGTXH9wrpb/IRyuV4QjO0NyHd8jsBlfy/Rakhe36Jbg2/hw4y1o
         Pz36KNpQpnbwPN3PV0C+lCB4KDqnjjsJGqj/7yvhsyCjg0YBkNwdxbsn5PJ36DVqVGAO
         3oPTYZvesnCnj2UDDqELAOAyKMKWBuTiGVttkU/AIMWhtAIxK+9hQmh4ktlEciiiJLEa
         2MIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyWH3oHVdakhQ/8oMjpBCeOIOicKNJsdKyuhCWQIIzYyWeMJKzq
	lQOZTBiL2gBTon3W+ZIm9PE=
X-Google-Smtp-Source: AGHT+IEVDTJKacKx0zCJJUBNb03WgcWLYHEe5EpKlSoFRjkJuYer6sII9xGVCuRJ03jDnE03G2ePAg==
X-Received: by 2002:aa7:9a49:0:b0:6cd:d0f4:cd3c with SMTP id x9-20020aa79a49000000b006cdd0f4cd3cmr1390042pfj.23.1701251808890;
        Wed, 29 Nov 2023 01:56:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1398:b0:6cb:4a9a:4f33 with SMTP id
 t24-20020a056a00139800b006cb4a9a4f33ls579202pfg.0.-pod-prod-02-us; Wed, 29
 Nov 2023 01:56:48 -0800 (PST)
X-Received: by 2002:a05:6a00:3927:b0:690:2fa3:9769 with SMTP id fh39-20020a056a00392700b006902fa39769mr4768803pfb.5.1701251808283;
        Wed, 29 Nov 2023 01:56:48 -0800 (PST)
Received: by 2002:a05:620a:2410:b0:778:a9dc:3cb2 with SMTP id af79cd13be357-77d641b56c2ms85a;
        Wed, 29 Nov 2023 01:53:40 -0800 (PST)
X-Received: by 2002:a05:6512:308d:b0:50b:a689:1fbc with SMTP id z13-20020a056512308d00b0050ba6891fbcmr12475128lfd.6.1701251618826;
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701251618; cv=none;
        d=google.com; s=arc-20160816;
        b=gPgrCP/W2nj3JeuIbMXhlhjquYSgvdT0Ii2bzRv+a1yriKe2EnqAhyC2T0phoYOF+v
         /txhC7EPmDr4eL3Mv5ECueBwVFdULrN6b1iRgC8i6QRCB0eu6IT66icRNsK1fQ0ABDMO
         H9NBoCE6ArSPHSyTBfkGR62OH3mrXmLyJH0zlHZsNUnnc/WjW1ikbyLy1td7xMB9JgTb
         D0gTwd6uX80J7i3lo8wuX2V1K56FCOoKa5NQNJg0ovGDiao5v+GzWZs84WLsjalzL4S/
         UC9vwno9YIH1O5PWNzgNujInV1IfDd87Jt/RMxVO85SeQhaIN3y3sypOS3Zb991h/AdE
         ghWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature:dkim-signature;
        bh=eoFLVBeLcmc4evqkljz3fngHIKUUCOgba17WIJPWQ+0=;
        fh=uYnIsWZ9n80gkcnhZMgoujzKtxA7UEl4GQvTBFLbimw=;
        b=G9vCbmggs8CO77VweViTnuyAlc8OgHQpFrrei59Gqlm17VdkDEYNU3SGz+o8f+aKT3
         3j3fxMgHhuPOdosfIfDG69P4Rx/wvmmZewhnDgsmL8qPUVsDeTAt6XVKlzhtTSzrISwC
         UOhbQFKy9sfKf9MSgWxsvNEBj2EpRw/W2bLU8tjMeQlBlYnAMgEvtuQhDeE1qK6SO/1u
         pUReLiOZsav5tUOhIydZGRG3afwUSIDFGqCzh9MLQGJy5AVX47QFk/SM3JqhS1BOPRB5
         urC2k5Vvr9ZNTmyoCyhrW3J5juSn9PsQtqrZFucXAo6WXEXKWYqT7UR6XzJMWcGjGxpY
         ZZbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DhAjX4+x;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=AFGProdn;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id f15-20020a05651232cf00b005098ece8aa9si824683lfg.12.2023.11.29.01.53.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id CA5F72198B;
	Wed, 29 Nov 2023 09:53:36 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id AC1FA1388B;
	Wed, 29 Nov 2023 09:53:36 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 8pWoKSAKZ2UrfQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Nov 2023 09:53:36 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH RFC v3 0/9] SLUB percpu array caches and maple tree nodes
Date: Wed, 29 Nov 2023 10:53:25 +0100
Message-Id: <20231129-slub-percpu-caches-v3-0-6bcf536772bc@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIABUKZ2UC/z2MQQ6CMBAAv0L27JJuIQU8mZj4AK/GQymLNCo0X
 SFGwt9tPHicSWZWEI6eBfbZCpEXL34aExS7DNxgxxuj7xKDVrog0jXKY24xcHRhRmfdwIJNWVL
 daEXUVZDCELn379/0AufTEa5J9nF64muIbP8/VZMiUxhd5UYrgw0urW3v9iCzcO4+sG1fIbWTd
 aAAAAA=
To: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
 Matthew Wilcox <willy@infradead.org>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, maple-tree@lists.infradead.org, 
 kasan-dev@googlegroups.com, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Flag: NO
X-Spam-Level: 
X-Spamd-Result: default: False [-2.80 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 BAYES_HAM(-3.00)[100.00%];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[17];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,gmail.com,google.com,kvack.org,vger.kernel.org,lists.infradead.org,googlegroups.com,suse.cz];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: -2.80
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=DhAjX4+x;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=AFGProdn;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Also in git [1]. Changes since v2 [2]:

- empty cache refill/full cache flush using internal bulk operations
- bulk alloc/free operations also use the cache
- memcg, KASAN etc hooks processed when the cache is used for the
  operation - now fully transparent
- NUMA node-specific allocations now explicitly bypass the cache

[1] https://git.kernel.org/vbabka/l/slub-percpu-caches-v3r2
[2] https://lore.kernel.org/all/20230810163627.6206-9-vbabka@suse.cz/

----

At LSF/MM I've mentioned that I see several use cases for introducing
opt-in percpu arrays for caching alloc/free objects in SLUB. This is my
first exploration of this idea, speficially for the use case of maple
tree nodes. The assumptions are:

- percpu arrays will be faster thank bulk alloc/free which needs
  relatively long freelists to work well. Especially in the freeing case
  we need the nodes to come from the same slab (or small set of those)

- preallocation for the worst case of needed nodes for a tree operation
  that can't reclaim due to locks is wasteful. We could instead expect
  that most of the time percpu arrays would satisfy the constained
  allocations, and in the rare cases it does not we can dip into
  GFP_ATOMIC reserves temporarily. So instead of preallocation just
  prefill the arrays.

- NUMA locality of the nodes is not a concern as the nodes of a
  process's VMA tree end up all over the place anyway.

Patches 1-4 are preparatory, but should also work as standalone fixes
and cleanups, so I would like to add them for 6.8 after review, and
probably rebasing on top of the current series in slab/for-next, mainly
SLAB removal, as it should be easier to follow than the necessary
conflict resolutions.

Patch 5 adds the per-cpu array caches support. Locking is stolen from
Mel's recent page allocator's pcplists implementation so it can avoid
disabling IRQs and just disable preemption, but the trylocks can fail in
rare situations - in most cases the locks are uncontended so the locking
should be cheap.

Then maple tree is modified in patches 6-9 to benefit from this. From
that, only Liam's patches make sense and the rest are my crude hacks.
Liam is already working on a better solution for the maple tree side.
I'm including this only so the bots have something for testing that uses
the new code. The stats below thus likely don't reflect the full
benefits that can be achieved from cache prefill vs preallocation.

I've briefly tested this with virtme VM boot and checking the stats from
CONFIG_SLUB_STATS in sysfs.

Patch 5:

slub per-cpu array caches implemented including new counters but maple
tree doesn't use them yet

/sys/kernel/slab/maple_node # grep . alloc_cpu_cache alloc_*path free_cpu_cache free_*path cpu_cache* | cut -d' ' -f1
alloc_cpu_cache:0
alloc_fastpath:20213
alloc_slowpath:1741
free_cpu_cache:0
free_fastpath:10754
free_slowpath:9232
cpu_cache_flush:0
cpu_cache_refill:0

Patch 7:

maple node cache creates percpu array with 32 entries,
not changed anything else

majority alloc/free operations are satisfied by the array, number of
flushed/refilled objects is 1/3 of the cached operations so the hit
ratio is 2/3. Note the flush/refill operations also increase the
fastpath/slowpath counters, thus the majority of those indeed come from
the flushes and refills.

alloc_cpu_cache:11880
alloc_fastpath:4131
alloc_slowpath:587
free_cpu_cache:13075
free_fastpath:437
free_slowpath:2216
cpu_cache_flush:4336
cpu_cache_refill:3216

Patch 9:

This tries to replace maple tree's preallocation with the cache prefill.
Thus should reduce all of the counters as many of the preallocations for
the worst-case scenarios are not needed in the end. But according to
Liam it's not the full solution, which probably explains why the
reduction is only modest.

alloc_cpu_cache:11540
alloc_fastpath:3756
alloc_slowpath:512
free_cpu_cache:12775
free_fastpath:388
free_slowpath:1944
cpu_cache_flush:3904
cpu_cache_refill:2742

---
Liam R. Howlett (2):
      tools: Add SLUB percpu array functions for testing
      maple_tree: Remove MA_STATE_PREALLOC

Vlastimil Babka (7):
      mm/slub: fix bulk alloc and free stats
      mm/slub: introduce __kmem_cache_free_bulk() without free hooks
      mm/slub: handle bulk and single object freeing separately
      mm/slub: free KFENCE objects in slab_free_hook()
      mm/slub: add opt-in percpu array cache of objects
      maple_tree: use slub percpu array
      maple_tree: replace preallocation with slub percpu array prefill

 include/linux/slab.h                    |   4 +
 include/linux/slub_def.h                |  12 +
 lib/maple_tree.c                        |  46 ++-
 mm/Kconfig                              |   1 +
 mm/slub.c                               | 561 +++++++++++++++++++++++++++++---
 tools/include/linux/slab.h              |   4 +
 tools/testing/radix-tree/linux.c        |  14 +
 tools/testing/radix-tree/linux/kernel.h |   1 +
 8 files changed, 578 insertions(+), 65 deletions(-)
---
base-commit: b85ea95d086471afb4ad062012a4d73cd328fa86
change-id: 20231128-slub-percpu-caches-9441892011d7

Best regards,
-- 
Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231129-slub-percpu-caches-v3-0-6bcf536772bc%40suse.cz.
