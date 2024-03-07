Return-Path: <kasan-dev+bncBCS2NBWRUIFBBYEJVCXQMGQE67XY3RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 111C58755F9
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Mar 2024 19:18:10 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-412eeff0d9esf58105e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Mar 2024 10:18:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709835489; cv=pass;
        d=google.com; s=arc-20160816;
        b=P+rIfemt3tO7/1OOvysLqvltqqAhQeuGHKrx2QSXBP9jYrdbfTFSadBEe3cz9QVd9d
         Dag6ENdakaR1doLs+CCw8mfvf2VJXSuRZsAfYbtES8/GNcqI6F+WUrUqPCc4txqNgL32
         YK2HT03uuUzhwGIBYSleuMz0M1egzbYTngfh/1nG1n1NgX+sLfMwiJIFdo1e2MU7pdeG
         VPXnZkQJCg1EnpL1yZws2BIIJiVhTG6gR6oLAss5juYeoMyzlMrWpa3MpQtiyaq/XiLL
         O4mdCXrqBLsDgjv+l2F5UYyuv1zjqG/B6SGv07IjrTdaANrrcTqklca06D69Kkotkd2Q
         T46g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=NhMfMTy2wsz1X7gzyKEBK09UFWBD+UOuwaRgAxI/Q5k=;
        fh=+EQbaG22HAgFAwaoC/4YtB+hoisSNHWwbq5Vvuk6YIU=;
        b=jJzPfgxnZMt7Mm/GDXy0QYagy6FoHNg6qJg8emmAE5evNgjRI7VFWAsn7RwivNavzQ
         93x4f62rAkNFQtZDnbltS51pb6WLW6pDZMFxvXXMaBnmlQZ6SyCNwMij7sxvltKKX0PO
         z11oxX+udwJHWXgqKcF7qa5RpxXphI/noD5mFFe3hxP5GrlefgfLfQ4p085HJJGSH8ql
         5gvFOV9Jk1x1D4gY7drkG0AFVsYGgvNNGkcITELO2rj9s2ynmEULOCZIdACbYwXkf6HG
         raLooJ1vYtpKuWNd/0GDE6lux+XQxgkvqyyHfCgIawccPiXVIuflhN54G1y2m1Rt62Ct
         Sbbg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=H5aOzJ+M;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.175 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709835489; x=1710440289; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NhMfMTy2wsz1X7gzyKEBK09UFWBD+UOuwaRgAxI/Q5k=;
        b=m+51uq2cREGTmK3clmc+N9DXfpjrXjG81gD9CMu7gAB8sL4LtiOtImjSRQ/r2PccPj
         sFXmzzBEZMIJoiWfJctJb7QkLrokMUsEGX/u3FtHuWpwcbe1We0EpAtCAIZQpoI34Y9n
         mlQgyzW3BcplM1L/iP3MkY9jVioAmC0FCwuVJRVRiiRO1H0AbTe+DfTVFjqdRidY0umu
         XqdlkyHR+d4/buwTrfzL34BdT0fNphtlGCCP/WZ1en9moQCi2oX9UWxYPp5tmsjXK9Yo
         e5j32wxHr1zMHvdvvaB52Y1fYPHEWsgT5qYlS5RCd613SMQB17u0lCyrDcCRWxsJDLLG
         QBZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709835489; x=1710440289;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NhMfMTy2wsz1X7gzyKEBK09UFWBD+UOuwaRgAxI/Q5k=;
        b=oHnZvEmp0yDu3QJ7M7DR2zRdm7ZXef/RGN+UN56GzcYppdFCt7Kxv/nTRo5krCF5cr
         YqPj4Ur7TtbbrNSPr6beRiBaWwfFO/5uTUqI/pz9M8Ppf0qPp3EACArqMJNWeA19qRkH
         vfyUaN4RC+vIIeaNXnI8SvGRngVfJBrG5zqVpnQtGkaFD2yoqI71UOY0ReJVGMuWHfQP
         exs/jhx/4rSYnG7GXIal1z4x8urb6JYC7KPKg0QaEdLspAQkEI8COnogvrw/7CoW+bD+
         Ego9xvo5idG0JVPL3sXeukySCqr8jrSjRYdL6Dmtfm+kTheWAWznA1XDSGzR753g0ONI
         PECw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVTH0ix2AznB5vD0a+z8o4FeG1IKKYk0HgAFZGjhsx4ciVDrqZVA4RqZHdrvZrbBBhmQwFsriB6wEGZPhQ+5IuI+lBVkB6OwA==
X-Gm-Message-State: AOJu0Yz8RYAxfrPSitpitk8rtLYRKxZ5NFnk5I424uU3ATF8l5fVX3pN
	mOexVlQHoterRyh8+e/1QPFigkjIgdEy/6uawjQiZkfjQKsipgtp
X-Google-Smtp-Source: AGHT+IGXsM1xKLJqtysmfPjbbpIHgJG0qGI2ivnAyKpRS8llq6g9MWuT+7D/IUJOU4cy7OwxLOCMsg==
X-Received: by 2002:a05:600c:4896:b0:412:c9d7:72ff with SMTP id j22-20020a05600c489600b00412c9d772ffmr259944wmp.4.1709835488349;
        Thu, 07 Mar 2024 10:18:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b99:b0:413:1688:25c5 with SMTP id
 n25-20020a05600c3b9900b00413168825c5ls21914wms.0.-pod-prod-08-eu; Thu, 07 Mar
 2024 10:18:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUbrZGnS8Tv9BA28ZiSiCaaVV6mx9j4jaC0cTaumm4SG9zShXv/EYKm4x2j9pcIpuCWIWye8wKP5eL/vP50RYH40Wr0c9KEnNeI9A==
X-Received: by 2002:a05:600c:444d:b0:412:ff72:a6f1 with SMTP id v13-20020a05600c444d00b00412ff72a6f1mr3475759wmn.38.1709835486315;
        Thu, 07 Mar 2024 10:18:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709835486; cv=none;
        d=google.com; s=arc-20160816;
        b=yU2IPU9g6IitQ+u2YJLEiAV2eC+PIz/zNXX71cMbZzcPI/dJblrOblmeW1/M/fsGYS
         140Dr4GLvNhgnI6hD6vGTeEBHwnn71A5w6oA2kHo1deVrkHC5IdU2JEK7XMdAVUtVjjt
         tIlWCflZZ1/VHM8Kbpyrqle/LsPW5CxXnBqB0BBnA2INReXhZKzM6c5XpshKh3AW1JdG
         nd+TbdYi+9JaN8bTa0HHndWGyWCAh4zheGDmqKoUv61mMNFEIEQMU8rhIsOVksSUnrLx
         1ts2Z/rmA9k8jHFAWlzNt6zkhxDRWNtugdFQRQzm8oWbu6pl4Fwnm7BHIXffPknfZwCA
         3+Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=iHaIxY/+BiJn46m1UxNdZN63kb5NNOFAVQARDvBki5g=;
        fh=FsnSm+GOq/wVsP+lve324Rei+JublQJ0B26xncKEPoM=;
        b=0NtXNRiZv0nVV5asMG8Pq5E9CMXz68wjjJxuG9ISB3vmYsfzl5s0Vtj46OuZtHdXVW
         tjaTD+pq2oBwY07Pn4Xso0lOcVPU+V3GExehOxL7HVbJVPiGYkXqvPK+VkND+P+sQRDp
         ftv2hxoiA5HYUZnE0jAwvf6gLkAbC5xXV4oJVQKuq9W2zDYDeZWXfiJn+Q8+5IxI4aJ1
         THSU6Hh2D/bzKFxfxSICa+RdAuG5H9cu7Yzp6Ox7I+ire+ug1Il3FRomyDo6D9qzpaKT
         ldIlrxwUCuA3ENx2wzMoH8lPrw0F1TB6QfLmoKUJfUGSUDrwPP/91JQeUxmakMkevMPE
         9uIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=H5aOzJ+M;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.175 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-175.mta0.migadu.com (out-175.mta0.migadu.com. [91.218.175.175])
        by gmr-mx.google.com with ESMTPS id b18-20020a05600c4e1200b00412df138480si286214wmq.1.2024.03.07.10.18.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Mar 2024 10:18:06 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.175 as permitted sender) client-ip=91.218.175.175;
Date: Thu, 7 Mar 2024 13:17:48 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Randy Dunlap <rdunlap@infradead.org>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, 
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, 
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, 
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	aliceryhl@google.com, rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, 
	linux-mm@kvack.org, linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Subject: Re: [PATCH v5 37/37] memprofiling: Documentation
Message-ID: <hsyclfp3ketwzkebjjrucpb56gmalixdgl6uld3oym3rvssyar@fmjlbpdkrczv>
References: <20240306182440.2003814-1-surenb@google.com>
 <20240306182440.2003814-38-surenb@google.com>
 <10a95079-86e4-41bf-8e82-e387936c437d@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <10a95079-86e4-41bf-8e82-e387936c437d@infradead.org>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=H5aOzJ+M;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.175 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
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

On Wed, Mar 06, 2024 at 07:18:57PM -0800, Randy Dunlap wrote:
> Hi,
> This includes some editing suggestions and some doc build fixes.
> 
> 
> On 3/6/24 10:24, Suren Baghdasaryan wrote:
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> > 
> > Provide documentation for memory allocation profiling.
> > 
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > ---
> >  Documentation/mm/allocation-profiling.rst | 91 +++++++++++++++++++++++
> >  1 file changed, 91 insertions(+)
> >  create mode 100644 Documentation/mm/allocation-profiling.rst
> > 
> > diff --git a/Documentation/mm/allocation-profiling.rst b/Documentation/mm/allocation-profiling.rst
> > new file mode 100644
> > index 000000000000..8a862c7d3aab
> > --- /dev/null
> > +++ b/Documentation/mm/allocation-profiling.rst
> > @@ -0,0 +1,91 @@
> > +.. SPDX-License-Identifier: GPL-2.0
> > +
> > +===========================
> > +MEMORY ALLOCATION PROFILING
> > +===========================
> > +
> > +Low overhead (suitable for production) accounting of all memory allocations,
> > +tracked by file and line number.
> > +
> > +Usage:
> > +kconfig options:
> > + - CONFIG_MEM_ALLOC_PROFILING
> > + - CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> > + - CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > +   adds warnings for allocations that weren't accounted because of a
> > +   missing annotation
> > +
> > +Boot parameter:
> > +  sysctl.vm.mem_profiling=0|1|never
> > +
> > +  When set to "never", memory allocation profiling overheads is minimized and it
> 
>                                                       overhead is
> 
> > +  cannot be enabled at runtime (sysctl becomes read-only).
> > +  When CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=y, default value is "1".
> > +  When CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=n, default value is "never".
> > +
> > +sysctl:
> > +  /proc/sys/vm/mem_profiling
> > +
> > +Runtime info:
> > +  /proc/allocinfo
> > +
> > +Example output:
> > +  root@moria-kvm:~# sort -g /proc/allocinfo|tail|numfmt --to=iec
> > +        2.8M    22648 fs/kernfs/dir.c:615 func:__kernfs_new_node
> > +        3.8M      953 mm/memory.c:4214 func:alloc_anon_folio
> > +        4.0M     1010 drivers/staging/ctagmod/ctagmod.c:20 [ctagmod] func:ctagmod_start
> > +        4.1M        4 net/netfilter/nf_conntrack_core.c:2567 func:nf_ct_alloc_hashtable
> > +        6.0M     1532 mm/filemap.c:1919 func:__filemap_get_folio
> > +        8.8M     2785 kernel/fork.c:307 func:alloc_thread_stack_node
> > +         13M      234 block/blk-mq.c:3421 func:blk_mq_alloc_rqs
> > +         14M     3520 mm/mm_init.c:2530 func:alloc_large_system_hash
> > +         15M     3656 mm/readahead.c:247 func:page_cache_ra_unbounded
> > +         55M     4887 mm/slub.c:2259 func:alloc_slab_page
> > +        122M    31168 mm/page_ext.c:270 func:alloc_page_ext
> > +===================
> > +Theory of operation
> > +===================
> > +
> > +Memory allocation profiling builds off of code tagging, which is a library for
> > +declaring static structs (that typcially describe a file and line number in
> 
>                                   typically
> 
> > +some way, hence code tagging) and then finding and operating on them at runtime
> 
>                                                                         at runtime,
> 
> > +- i.e. iterating over them to print them in debugfs/procfs.
> 
>   i.e., iterating

i.e. latin id est, that is: grammatically my version is fine

> 
> > +
> > +To add accounting for an allocation call, we replace it with a macro
> > +invocation, alloc_hooks(), that
> > + - declares a code tag
> > + - stashes a pointer to it in task_struct
> > + - calls the real allocation function
> > + - and finally, restores the task_struct alloc tag pointer to its previous value.
> > +
> > +This allows for alloc_hooks() calls to be nested, with the most recent one
> > +taking effect. This is important for allocations internal to the mm/ code that
> > +do not properly belong to the outer allocation context and should be counted
> > +separately: for example, slab object extension vectors, or when the slab
> > +allocates pages from the page allocator.
> > +
> > +Thus, proper usage requires determining which function in an allocation call
> > +stack should be tagged. There are many helper functions that essentially wrap
> > +e.g. kmalloc() and do a little more work, then are called in multiple places;
> > +we'll generally want the accounting to happen in the callers of these helpers,
> > +not in the helpers themselves.
> > +
> > +To fix up a given helper, for example foo(), do the following:
> > + - switch its allocation call to the _noprof() version, e.g. kmalloc_noprof()
> > + - rename it to foo_noprof()
> > + - define a macro version of foo() like so:
> > +   #define foo(...) alloc_hooks(foo_noprof(__VA_ARGS__))
> > +
> > +It's also possible to stash a pointer to an alloc tag in your own data structures.
> > +
> > +Do this when you're implementing a generic data structure that does allocations
> > +"on behalf of" some other code - for example, the rhashtable code. This way,
> > +instead of seeing a large line in /proc/allocinfo for rhashtable.c, we can
> > +break it out by rhashtable type.
> > +
> > +To do so:
> > + - Hook your data structure's init function, like any other allocation function
> 
> maybe end the line above with a '.' like the following line.
> 
> > + - Within your init function, use the convenience macro alloc_tag_record() to
> > +   record alloc tag in your data structure.
> > + - Then, use the following form for your allocations:
> > +   alloc_hooks_tag(ht->your_saved_tag, kmalloc_noprof(...))
> 
> 
> Finally, there are a number of documentation build warnings in this patch.
> I'm no ReST expert, but the attached patch fixes them for me.
> 
> -- 
> #Randy


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/hsyclfp3ketwzkebjjrucpb56gmalixdgl6uld3oym3rvssyar%40fmjlbpdkrczv.
