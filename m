Return-Path: <kasan-dev+bncBDM4BTMC5MIBBSEYWSXAMGQED2KWFLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C166E8552B8
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 19:54:01 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-68058b0112csf1454686d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 10:54:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707936841; cv=pass;
        d=google.com; s=arc-20160816;
        b=i6v+F+agmrfh8fDm7+bdM0lNsRt09ZQbTJGyCzguIe9S4ff52W3/u4M0CIANOT9HTk
         2XrCgm7/FZ9f29hVDUrAbjGbnAHRDIOY3Gl3QnudZRXyKMZ0Ke1x1bGXkamJ/sv0Dgu/
         r9BW8RWYvUI+ImOZucS4HiLBqqnqL0SiRODsqB6LVKFfnLvCdeGoSdPhk8olyPsd2Uv/
         AcUCU7kgwXyOYlmZFNuFZ3zBfOG66b9lKV5XujGMuVkF1ZABi/gyEdWF1RhcaQDLAZIQ
         yWpU9zInjv0g1AJI/XlXUgAfzpa9VuYhCjhy8Zse1jCU5t8houps8YJq214OyO3TZ7TS
         WVPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=TrUx1V6dPtQewsiGHZJpCGJIz+9IFgsOdjGWKuAiGyg=;
        fh=bh3RHqS2AZjNpsrLHXWe7f3XWccI5HS3F0OYbSmw+is=;
        b=zSh6EdzwqPRIFdcIg3ufbYADKOdxcJzlwvGFgVbz4Z0udiT5s6CnoKc66ZUtCPUWJY
         krH7KARL+mHnWFrIslDjakymNOtxzb6EfsdojcnEtsoomd77fe6vwZkwZJz3f/JCadPy
         riJFxVIEzTdoaFr97c40nYhaMC8Nr2qmglukHrHDmweRTq9vwlfs3f/VhCWZXqNYZwRL
         IeJDwcA/Tv+JHoRGeVfqFlZLMJa0xjf1ygH1jks+x9MtGNuDiwrAKFz4VaBtEn1l8dQq
         1mVRHx9Ly8jEsRTSuGaFP3KnihtvhIOYdMkmWS3zm/r5lVnnLosd8kLcPp31lHCsycO/
         0EiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ObjzzCqA;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=tim.c.chen@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707936841; x=1708541641; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TrUx1V6dPtQewsiGHZJpCGJIz+9IFgsOdjGWKuAiGyg=;
        b=vFRmus3rlUye1JM5wzvSHt2PNEusI5LRrPebsqGXXe1E9t1v3o+8uRQgwgvg26Wl2/
         CCrOMANR5pNoqwAiUmnEp11dEcSgKUUffxyaMD5Toprz0/bRn5EjhLaU0MsNIOOBCucg
         rkjpuX3Ui1VX9urwGf+rTbgfNysF4Noej99QtdRP8VYiq/J03/3HuIYrg5zJym5DJUMC
         vfk+hFnAMdDaYs6cLQyRhZ8CdAmSsiiSZ6DlF6UEvgLb3ZMQ49ymkspBnskppmCK9WXH
         Ihd7l/nBNq9tHp/K58tJgovM3FQBY812KBsQJzb3/XpG0U7zHtnrvq2a3yHv1VWLMIrN
         3H2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707936841; x=1708541641;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=TrUx1V6dPtQewsiGHZJpCGJIz+9IFgsOdjGWKuAiGyg=;
        b=swCPLwj/J8jmVHK1Tvzz345bJzgmG6ADKmq82q2uQG626auMsTMLAe1cWsLWRC6bAp
         21NJRqpwxRBf1SBiX8q6zbFgIPhowTj0FTzFyL3y1Y9/RWqeHwYqwaJW5xlKG4KKN7MJ
         yFKB0WxocSmCElZn1YUB1pCekgKzjyqWyJTwt1o2g/hjKV589yf3MBYUkL81EbUxxFqo
         X/qWmuV8DioPFAZQwUxJA65wLqMbeL6Z/NZQpehwiC5puTabzdcwQaKzZXfeP3IXhhIK
         Yae0H6MzJ89cTfqwYIdD6/va28L4dyCjaGjdzXdRYbXF4KrcWqX6h289V0y2rb/yKV45
         vi1w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWxpLVOce9vwLf5VTutTYGkIkSHSbfDnaOoXkpHuler0RczcTtc/hHRrBWkpnCRV8qEyPYxij+cbAX2TK928r0kFPChK/CuUg==
X-Gm-Message-State: AOJu0YwM9Lkt/r3lr+D9ZyelxU9yBoSSY0YU42GyKSxUNxXVG0m/6iDi
	V0bY3/oF+T6oakywspKHZ16wiyRWRgQ9Bx6rMoLG393MVswMeyZo
X-Google-Smtp-Source: AGHT+IFnQ/VGDoS4SCB3rBDLEC3Uwy/cOrMOczNAPS4NakSlAIZUFksemanmq5eTmQWlL+sd8vfjrg==
X-Received: by 2002:a05:6214:268f:b0:68d:1886:c02f with SMTP id gm15-20020a056214268f00b0068d1886c02fmr3842352qvb.33.1707936840726;
        Wed, 14 Feb 2024 10:54:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2a4c:b0:68d:14b3:ae2f with SMTP id
 jf12-20020a0562142a4c00b0068d14b3ae2fls3270888qvb.1.-pod-prod-06-us; Wed, 14
 Feb 2024 10:54:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXvYDH4mnYEzW5Xm/7WmYJP5/nQI1/g74d26WXi9BZW5NpSiJsVRQN9A8u1asl1LGGpXCRdtU3XFfXw6sjGcGC9UhtlcYxMfOXhHg==
X-Received: by 2002:ad4:5e8b:0:b0:685:3e78:8723 with SMTP id jl11-20020ad45e8b000000b006853e788723mr4381853qvb.28.1707936840094;
        Wed, 14 Feb 2024 10:54:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707936840; cv=none;
        d=google.com; s=arc-20160816;
        b=tCXx1Kwa/fIeqsbHsb31Oanufir0EzCcqS+QNL7e6Xz+pfUw7nAXEVymd28CGKhDU5
         KMi5Owqrpd8fpZJHGelhEjm+4ZSzC0G+QURDgUcb1RlVxW8MooG6xBMgkdZM94E5foVn
         lmv/QcDOCkIT3K1TcXDuZgb+0qALiVlhGf+f8mjgv/VbpvLXfM6wNL13Gf+ihoEV4vU6
         2PFazqDoGA9JeZsc0jh6LijjcaCm4125FQ6kmW308pX/mlIcJP/T6MyJYeoo3I6l5ntu
         Vgb5X7w/ZglC2YCL7H6bZgwcYEFfw6kLcQkVo/7g0uCkISYX6vrrFUwAC19V4vqEatTJ
         4+6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=ayqKIy57g474KnPKPtvb1DVuaBRuSrVHN7NlOSx6BdM=;
        fh=07nT92mttZE41mnVeV872pUBgO+Wrw3J87rJulhlhXQ=;
        b=BP4TOzi5kd7NhJvyvqOoNwt8db1HQxDn1SLILahrNXFPiLdtPLBBZ8iFKwtGUN+u+r
         paYSTIzs2Wx9hihFDhD4y9R7KP9eFBS8d6tCPkYKBuWCj2UVrPFyjz+0eGcyJgJz0kT3
         hOohM0/JqN1pWexjbf0tmfF4iAHlRiyTvSTDHD2V3VkToP/Qr7fbV3zejl6BhpcA3t/Z
         xXXKPMub81H9yN1MKVL08X1G2c/2c+i5zoTUPXA4wtFNo72qtCxG/9ieP/Ea9psTxkwy
         qcQg1wN4cN8W0ksfG5VS4Lb1AMDOjVVe50tYIM9zSy0sbxYs68hCjU00eHMv+x291XG9
         tKYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ObjzzCqA;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=tim.c.chen@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
X-Forwarded-Encrypted: i=1; AJvYcCV+5bExiKgm01ZRAqcGPvznMpvQeXX/sC70YQkYaOrpCnNwdcdUCYTkeGtb4w3FjlVUkDJD29SY6uQGMEqbIfXnEENhS/M/v4/M8Q==
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.18])
        by gmr-mx.google.com with ESMTPS id f11-20020a05621400cb00b0068e17706429si301288qvs.1.2024.02.14.10.53.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 14 Feb 2024 10:53:59 -0800 (PST)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.198.163.18;
X-IronPort-AV: E=McAfee;i="6600,9927,10984"; a="1873591"
X-IronPort-AV: E=Sophos;i="6.06,160,1705392000"; 
   d="scan'208";a="1873591"
Received: from fmviesa005.fm.intel.com ([10.60.135.145])
  by fmvoesa112.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Feb 2024 10:53:58 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.06,160,1705392000"; 
   d="scan'208";a="7891287"
Received: from wfaimone-mobl.amr.corp.intel.com (HELO [10.209.29.231]) ([10.209.29.231])
  by fmviesa005-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Feb 2024 10:53:54 -0800
Message-ID: <4f24986587b53be3f9ece187a3105774eb27c12f.camel@linux.intel.com>
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
From: Tim Chen <tim.c.chen@linux.intel.com>
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net,  willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com,  peterz@infradead.org,
 juri.lelli@redhat.com, catalin.marinas@arm.com,  will@kernel.org,
 arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com,  axboe@kernel.dk, mcgrof@kernel.org,
 masahiroy@kernel.org, nathan@kernel.org,  dennis@kernel.org, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org,  paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com,  yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
 keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com,  elver@google.com, dvyukov@google.com,
 shakeelb@google.com,  songmuchun@bytedance.com, jbaron@akamai.com,
 rientjes@google.com,  minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com,  linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org,  linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com,  cgroups@vger.kernel.org
Date: Wed, 14 Feb 2024 10:53:53 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
References: <20240212213922.783301-1-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.4 (3.44.4-2.fc36)
MIME-Version: 1.0
X-Original-Sender: tim.c.chen@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ObjzzCqA;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=tim.c.chen@linux.intel.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=intel.com
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

On Mon, 2024-02-12 at 13:38 -0800, Suren Baghdasaryan wrote:
> Memory allocation, v3 and final:
> 
> Overview:
> Low overhead [1] per-callsite memory allocation profiling. Not just for debug
> kernels, overhead low enough to be deployed in production.
> 
> We're aiming to get this in the next merge window, for 6.9. The feedback
> we've gotten has been that even out of tree this patchset has already
> been useful, and there's a significant amount of other work gated on the
> code tagging functionality included in this patchset [2].
> 
> Example output:
>   root@moria-kvm:~# sort -h /proc/allocinfo|tail
>    3.11MiB     2850 fs/ext4/super.c:1408 module:ext4 func:ext4_alloc_inode
>    3.52MiB      225 kernel/fork.c:356 module:fork func:alloc_thread_stack_node
>    3.75MiB      960 mm/page_ext.c:270 module:page_ext func:alloc_page_ext
>    4.00MiB        2 mm/khugepaged.c:893 module:khugepaged func:hpage_collapse_alloc_folio
>    10.5MiB      168 block/blk-mq.c:3421 module:blk_mq func:blk_mq_alloc_rqs
>    14.0MiB     3594 include/linux/gfp.h:295 module:filemap func:folio_alloc_noprof
>    26.8MiB     6856 include/linux/gfp.h:295 module:memory func:folio_alloc_noprof
>    64.5MiB    98315 fs/xfs/xfs_rmap_item.c:147 module:xfs func:xfs_rui_init
>    98.7MiB    25264 include/linux/gfp.h:295 module:readahead func:folio_alloc_noprof
>     125MiB     7357 mm/slub.c:2201 module:slub func:alloc_slab_page
> 
> Since v2:
>  - tglx noticed a circular header dependency between sched.h and percpu.h;
>    a bunch of header cleanups were merged into 6.8 to ameliorate this [3].
> 
>  - a number of improvements, moving alloc_hooks() annotations to the
>    correct place for better tracking (mempool), and bugfixes.
> 
>  - looked at alternate hooking methods.
>    There were suggestions on alternate methods (compiler attribute,
>    trampolines), but they wouldn't have made the patchset any cleaner
>    (we still need to have different function versions for accounting vs. no
>    accounting to control at which point in a call chain the accounting
>    happens), and they would have added a dependency on toolchain
>    support.
> 
> Usage:
> kconfig options:
>  - CONFIG_MEM_ALLOC_PROFILING
>  - CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
>  - CONFIG_MEM_ALLOC_PROFILING_DEBUG
>    adds warnings for allocations that weren't accounted because of a
>    missing annotation
> 
> sysctl:
>   /proc/sys/vm/mem_profiling
> 
> Runtime info:
>   /proc/allocinfo
> 
> Notes:
> 
> [1]: Overhead
> To measure the overhead we are comparing the following configurations:
> (1) Baseline with CONFIG_MEMCG_KMEM=n
> (2) Disabled by default (CONFIG_MEM_ALLOC_PROFILING=y &&
>     CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=n)
> (3) Enabled by default (CONFIG_MEM_ALLOC_PROFILING=y &&
>     CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=y)
> (4) Enabled at runtime (CONFIG_MEM_ALLOC_PROFILING=y &&
>     CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=n && /proc/sys/vm/mem_profiling=1)
> (5) Baseline with CONFIG_MEMCG_KMEM=y && allocating with __GFP_ACCOUNT
> 

Thanks for the work on this patchset and it is quite useful.
A clarification question on the data:

I assume Config (2), (3) and (4) has CONFIG_MEMCG_KMEM=n, right?
If so do you have similar data for config (2), (3) and (4) but with
CONFIG_MEMCG_KMEM=y for comparison with (5)?

Tim

> Performance overhead:
> To evaluate performance we implemented an in-kernel test executing
> multiple get_free_page/free_page and kmalloc/kfree calls with allocation
> sizes growing from 8 to 240 bytes with CPU frequency set to max and CPU
> affinity set to a specific CPU to minimize the noise. Below are results
> from running the test on Ubuntu 22.04.2 LTS with 6.8.0-rc1 kernel on
> 56 core Intel Xeon:
> 
>                         kmalloc                 pgalloc
> (1 baseline)            6.764s                  16.902s
> (2 default disabled)    6.793s (+0.43%)         17.007s (+0.62%)
> (3 default enabled)     7.197s (+6.40%)         23.666s (+40.02%)
> (4 runtime enabled)     7.405s (+9.48%)         23.901s (+41.41%)
> (5 memcg)               13.388s (+97.94%)       48.460s (+186.71%)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4f24986587b53be3f9ece187a3105774eb27c12f.camel%40linux.intel.com.
