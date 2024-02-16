Return-Path: <kasan-dev+bncBCS2NBWRUIFBBCOAXSXAMGQE3YVMBSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 5675D8577D6
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 09:42:50 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2d099291380sf3433141fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 00:42:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708072969; cv=pass;
        d=google.com; s=arc-20160816;
        b=M7W5BJYacUK2m/QTrahWBPTkYrii+CequSCSWGI3UsYVFvW+pX0zl2BTRp4kwJ8DcI
         8sg8Gfoq4FO5d0MfqqANBpmSzy26Cb4e+TqvfRcY9shWhXtLVvp0csDGacqON87MZXLj
         Ap1WzP7hxZCw1h4NRNDZprMwgBUH/5y0+m2fIqLI5489Yc1097aRvvRr1NBeONBmtSIx
         KP3g1F60x9BN+n0BAqYoItErYrxfOE3y20Sm05FW58SpUzjx0x6wDpGUqixqeQNwcUUm
         loEnSXtCBmst7w/sqqroIjoX7PbQT0jOfYwCwuxd3RDcS8Ixkq1uE7Iun7/FaJfthN1W
         syDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Zot81TQUg3zQc7167DWTDWuu3XlgPbzHtU4RReVlxeg=;
        fh=AIEXLdZ0n+tasImraFzlJeLuxqEHdnxwUUvToc2q6vw=;
        b=vyuv5cvKQKhAuI8c2DU5K2EjqZ9jCqQkP0TxCEWpJQ8yeshPU5IluOc/bTOSf7Ewej
         cFQ+0AP1wXCqkb3dvmkbTGr4NU+2ZxTugJE0iyLwLnGgWmTAmry7DCwe/tJF9j7RGBRD
         s/mDBVGlrwdnYBapDrxFhTZiZ0u99QmQ9roZP4UFrpFDOYUew5CI1ZotQSuz3YqPvZDg
         HE3vnhI3McLMybqkMhiiIM2+/1T3BFFCBWsTgBWbYWcnGRl32UNgSaA+tWbRVMKwRIOh
         Vy2vcP5uobEQQTrIeOKELni5epiEtA6jMvHInk2B+rEh7X/QrqgAQ/BAwLjzDSzM8KYF
         ZR6A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XBAf9glz;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.173 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708072969; x=1708677769; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Zot81TQUg3zQc7167DWTDWuu3XlgPbzHtU4RReVlxeg=;
        b=mMj7RqcKATTnLR7l4c+Qlexlb2a6bWOdRkK1xY76PJI7FpcLXyusk4I5rqCilDdl45
         VpgZShf0BcCkRwI8pjgF+xI5vx6DAVdRnHy6I2E9X9Qe282C4fl9Ff4AZDJSOm1tF1GA
         ZwfWMPywjodog9WwIwS72DCQZVpxGxOtk+acXJ+wuqKNBSkNsLCzG6z+UM9BLX5+NeIc
         Eb+/+xMGEtc6BEeEVrEqaAfZvsXWc4NJTsEB+ogp29A0u+Xv2AJl6LaQNAx6JukpKIaX
         IoEVOPdQi9ckzONi2fkPSNBKXFhJQ79Rlzs6tzEzA/0CiRpvPjBzoJfbp4yXRYI1XGnB
         iVVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708072969; x=1708677769;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Zot81TQUg3zQc7167DWTDWuu3XlgPbzHtU4RReVlxeg=;
        b=jbl4kskTrQHNrVNoG29Ozm8dShIjt7Jcka7PaA6mUaOfjrybs9ZT1ZCxMYZHxoK5FU
         VrG90DR/5r93pHyx7xv8GiI369cEaiaheINAXHBMBaIGogjgLueMQHW9ou3cElqB8SCj
         fRfLxJGEz6cchC83tiQjK5Ijub1bUn72Ikmqa8NIdQPZPetXNNyxHaHa/VPV+trd4q7Q
         HCZHOEBSHJOCjvdlRG0mHFPBaV2LHHKKM19RKIBqnXg8NwFUTYEzdvCggdO2KtYrnSI0
         XlFfPrH3hVhDdJlMTQt2AlD4ZIWlu7llf6ItJwPd3AIEQ8ubHtTeifD8BuTs7ANDQ0eu
         B/mA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUk+x0+4XZ36pyi/4NvhnCqpXRiAfAhgxMgh11/L0Dq3b1CeMHDUfsPe8I1KEVVcZwdQ7T71l69Xk/Fqi/YvXQlvffqimN1KA==
X-Gm-Message-State: AOJu0YxoLoZQabWcQx6tb4fquLarq8LfcTci3ZNTwk+ZZ0ySfyE0nG/E
	L/Ekxykxi/mK81fsmpbww3k8p00768UYK8R+egsXpOcSYJjNaYA/
X-Google-Smtp-Source: AGHT+IFJxwB3GOT9ZLTrrjrCSdmW/idFXsdZzj/jwasDICHoMw63IeWK7LeoKZYCkYWQPSvRRoUikw==
X-Received: by 2002:a05:651c:1051:b0:2d0:a469:8a43 with SMTP id x17-20020a05651c105100b002d0a4698a43mr3205279ljm.18.1708072969335;
        Fri, 16 Feb 2024 00:42:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1245:b0:2cd:eb51:129a with SMTP id
 h5-20020a05651c124500b002cdeb51129als207557ljh.2.-pod-prod-04-eu; Fri, 16 Feb
 2024 00:42:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUloWzOPJnphKEb9QNl+pAgJpD8ZtA7QL2DXmkBUctxJLSrS35Y2tko00qCOtPDpADR+k/ewL3dHZ5VxcWqJWcIfES9Rm0nPoYKqA==
X-Received: by 2002:a2e:8186:0:b0:2d2:178a:4f96 with SMTP id e6-20020a2e8186000000b002d2178a4f96mr848312ljg.14.1708072967407;
        Fri, 16 Feb 2024 00:42:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708072967; cv=none;
        d=google.com; s=arc-20160816;
        b=OH2vXcGkVdHnL97EJDf2Kxm4LFsD+uXTXLaaMrQyI29pwqy4IjR5xPAZCZ5EUolcgY
         pDrOqe0OvBT7FxEg3kqf+z+fqcJHxgaViLLuE6QgZHkSjGtcOzworO4UQbVg/9jjOr+P
         sdG2yrrriTBbhJKlS6UMWj3rflktOlMSoHgJVEv6/ArTTQaQso0jt4APwPLfdFiJexXR
         hQnPh/PzVxqDEkUkmZLxj+VjRVGkgEF7BZTHd2f4nFiPAuL9mN1bMH/fhGr6VhDkKc2+
         wCSp/qPofGZIMn2GGGy23O+N1VBW6rN/AgdCB6vSY59nrqaGmBmqUZPtrpno8hzMp64d
         StLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=iD3JwaVQ74VDSKWCWZ1B7FlzTV5HffeulQedls0mqs0=;
        fh=WoZqr1SgrrX4muY/wam9Zo0CDv1ALm+SvLshpvAInU4=;
        b=GAUoOXSbe9qhAdNYmX/NQQSb2uRuNxCg2RkhGkUUNyfgGZRPfpRYsEmMr2eDYYFH1H
         hEKs/eO2x7XY9lpVeV0P3J7TqPyo6qnPxtKU0vSUG9okVWkc+z/kBYI8bHtRKgpEynsk
         GjqDaaJWZd1cvK3DDHH8Xidxe4FUy0kIOHVd3iABrHzZIJmTL3V9pnrFGhOhT/8XNcxK
         s5/C66BpJYLwKl6JpMW34YgM3GbS4TnYvWFEL1uMj0G30dIhjjtD0VqzGzqE5+g4eS8d
         ZRevDZUSZBnspAEPkaf0NC/0XNPrZXYwRZcwWUaK7OJHsMcHHwnmRQXI6Q/vaTh5vhzY
         4msA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XBAf9glz;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.173 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-173.mta0.migadu.com (out-173.mta0.migadu.com. [91.218.175.173])
        by gmr-mx.google.com with ESMTPS id n25-20020a05600c3b9900b00411c092ef0fsi41749wms.1.2024.02.16.00.42.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Feb 2024 00:42:47 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.173 as permitted sender) client-ip=91.218.175.173;
Date: Fri, 16 Feb 2024 03:42:35 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Jani Nikula <jani.nikula@linux.intel.com>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, 
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, 
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
Message-ID: <plijmr6acz2cvrfokgc46bt5budre5d5ed3alpapu4gvhkqkmn@55yhfdhigjp3>
References: <20240212213922.783301-1-surenb@google.com>
 <87sf1s4xef.fsf@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87sf1s4xef.fsf@intel.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=XBAf9glz;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.173 as
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

On Fri, Feb 16, 2024 at 10:38:00AM +0200, Jani Nikula wrote:
> On Mon, 12 Feb 2024, Suren Baghdasaryan <surenb@google.com> wrote:
> > Memory allocation, v3 and final:
> >
> > Overview:
> > Low overhead [1] per-callsite memory allocation profiling. Not just for debug
> > kernels, overhead low enough to be deployed in production.
> >
> > We're aiming to get this in the next merge window, for 6.9. The feedback
> > we've gotten has been that even out of tree this patchset has already
> > been useful, and there's a significant amount of other work gated on the
> > code tagging functionality included in this patchset [2].
> 
> I wonder if it wouldn't be too much trouble to write at least a brief
> overview document under Documentation/ describing what this is all
> about? Even as follow-up. People seeing the patch series have the
> benefit of the cover letter and the commit messages, but that's hardly
> documentation.
> 
> We have all these great frameworks and tools but their discoverability
> to kernel developers isn't always all that great.

commit f589b48789de4b8f77bfc70b9f3ab2013c01eaf2
Author: Kent Overstreet <kent.overstreet@linux.dev>
Date:   Wed Feb 14 01:13:04 2024 -0500

    memprofiling: Documentation
    
    Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

diff --git a/Documentation/mm/allocation-profiling.rst b/Documentation/mm/allocation-profiling.rst
new file mode 100644
index 000000000000..d906e9360279
--- /dev/null
+++ b/Documentation/mm/allocation-profiling.rst
@@ -0,0 +1,68 @@
+.. SPDX-License-Identifier: GPL-2.0
+
+===========================
+MEMORY ALLOCATION PROFILING
+===========================
+
+Low overhead (suitable for production) accounting of all memory allocations,
+tracked by file and line number.
+
+Usage:
+kconfig options:
+ - CONFIG_MEM_ALLOC_PROFILING
+ - CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
+ - CONFIG_MEM_ALLOC_PROFILING_DEBUG
+   adds warnings for allocations that weren't accounted because of a
+   missing annotation
+
+sysctl:
+  /proc/sys/vm/mem_profiling
+
+Runtime info:
+  /proc/allocinfo
+
+Example output:
+  root@moria-kvm:~# sort -h /proc/allocinfo|tail
+   3.11MiB     2850 fs/ext4/super.c:1408 module:ext4 func:ext4_alloc_inode
+   3.52MiB      225 kernel/fork.c:356 module:fork func:alloc_thread_stack_node
+   3.75MiB      960 mm/page_ext.c:270 module:page_ext func:alloc_page_ext
+   4.00MiB        2 mm/khugepaged.c:893 module:khugepaged func:hpage_collapse_alloc_folio
+   10.5MiB      168 block/blk-mq.c:3421 module:blk_mq func:blk_mq_alloc_rqs
+   14.0MiB     3594 include/linux/gfp.h:295 module:filemap func:folio_alloc_noprof
+   26.8MiB     6856 include/linux/gfp.h:295 module:memory func:folio_alloc_noprof
+   64.5MiB    98315 fs/xfs/xfs_rmap_item.c:147 module:xfs func:xfs_rui_init
+   98.7MiB    25264 include/linux/gfp.h:295 module:readahead func:folio_alloc_noprof
+    125MiB     7357 mm/slub.c:2201 module:slub func:alloc_slab_page
+
+
+Theory of operation:
+
+Memory allocation profiling builds off of code tagging, which is a library for
+declaring static structs (that typcially describe a file and line number in
+some way, hence code tagging) and then finding and operating on them at runtime
+- i.e. iterating over them to print them in debugfs/procfs.
+
+To add accounting for an allocation call, we replace it with a macro
+invocation, alloc_hooks(), that
+ - declares a code tag
+ - stashes a pointer to it in task_struct
+ - calls the real allocation function
+ - and finally, restores the task_struct alloc tag pointer to its previous value.
+
+This allows for alloc_hooks() calls to be nested, with the most recent one
+taking effect. This is important for allocations internal to the mm/ code that
+do not properly belong to the outer allocation context and should be counted
+separately: for example, slab object extension vectors, or when the slab
+allocates pages from the page allocator.
+
+Thus, proper usage requires determining which function in an allocation call
+stack should be tagged. There are many helper functions that essentially wrap
+e.g. kmalloc() and do a little more work, then are called in multiple places;
+we'll generally want the accounting to happen in the callers of these helpers,
+not in the helpers themselves.
+
+To fix up a given helper, for example foo(), do the following:
+ - switch its allocation call to the _noprof() version, e.g. kmalloc_noprof()
+ - rename it to foo_noprof()
+ - define a macro version of foo() like so:
+   #define foo(...) alloc_hooks(foo_noprof(__VA_ARGS__))

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/plijmr6acz2cvrfokgc46bt5budre5d5ed3alpapu4gvhkqkmn%4055yhfdhigjp3.
