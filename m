Return-Path: <kasan-dev+bncBDV2D5O34IDRBRHEUSXQMGQEZGWUAOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 57A1A8746A3
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Mar 2024 04:19:34 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id 3f1490d57ef6-dc64b659a9csf712040276.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 19:19:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709781573; cv=pass;
        d=google.com; s=arc-20160816;
        b=O/1EWKSHEPkCItOeTp/gUBoqh3W7y2l73Pa6WlCEXZ5xqnfi1bQF0kldz/8P4zKVrb
         cNKXDjXJ5pNkmbtdtnwGUVCgZAaCfmE3qzcqwO6NKMfzZFakY7CpT7HuTJiTe8iiHacX
         VJ+QaaQpD90VNofkg5HmIKh3YPF2mQBv+2OGNMzJ/VwbiincWVWDgdLajYFcOPfB+Wz8
         lDMZe+vbQnr7T/d5IyWhdT4mtfiML5Lsw1X6vKc0MJpkJ5wdEavzKH1xyn+3aNd7ZLDB
         /9hmjEZu8MYEeZkMC/HvDECMKQ/z7DoRM3zZqnePGeLmi7XxN0GLOqr2HE4nbRepbX57
         qaEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language
         :references:cc:to:subject:from:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=ccJcUu4f/oxtqt41szkwyeU5juZHcqTtZhREOKw8ZBE=;
        fh=btwnpZHbYMzJv3EJniO+CRRs35+IP9adGgmc0jERmaM=;
        b=HCKjFvzekM3USkEm3a6OlAcc3Qizpyjmbcn6CENHDt9L/ae+5HSWvVqe6gLsaRPKXf
         10ESu/TgZdJpLDJRb1gko7ZJTXe58pxgDoNhYKHwMB2tzR9SAGgV2+FvYGSQoZOwY1sw
         /qc4YgLrYFgpLZdpRF9zT98eafJLUDT/TbkJDEZI1uqWJvprb5dNdgL35G8hpg0Arh9t
         y87jcRLJCgpRRzHiZ1B/Y8OkQ8DJnqn8XDDM/uDPtJdkPmAtWCNp+ydIml7dXKckVcGE
         iT1+DHTzVJiZd6Z9kOqGl1qj1lvZBRQE1WEcCBODlUdrt26BKE12JDLNnoKG7CnaScnE
         oRmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=ychUmlpI;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709781573; x=1710386373; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:references:cc:to
         :subject:from:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ccJcUu4f/oxtqt41szkwyeU5juZHcqTtZhREOKw8ZBE=;
        b=spgkTTX8Rj4wYcR+dnBnQ2Tvw17/xrAFLLHQvxxRLXkHsxb/UOgocpK5BqEuubdlpK
         l1xSr/85E0zB47hV7ASKfQNm+9M4B9dOxFyBx9lCMgosPdWuTQ4ZEq4N+KVT437WpROl
         GMLA+FPaEOQ1llCo9hoAPU+U6n44Ibhk6U+zwEhQGI330p35BrbfuI+xBI6Qv6ndXu7U
         eWO08XQF298R4F/8e8krDizNnAxfb5tgihsB1pyN4r378DZVpUe+HULGHJgo3Rp3iWoS
         ZTa5qENyw74YE+W+XEGyyLlt5WOuODGF9UMfPSM4sMJAjjrwOQG+X7TD6XesXipQxVOE
         01gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709781573; x=1710386373;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:references:cc:to:subject:from:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ccJcUu4f/oxtqt41szkwyeU5juZHcqTtZhREOKw8ZBE=;
        b=DZH+4apnWyByF2Sn0Kve9bvwW9MudFXdEVVsHBWJ6V/avcc3KP1J7sEq2vf0qBPFJC
         XT2OQwyRKCZHpbKPFUEjSVmkSe7BvO864jQmmBd6HxJFF3dMZz6n+06XfKNj3q3yNpsc
         DUQyCM9RAm7AJE4po457iFRk/L1s3v/QPCeS2OKXGStwpwF+hPL/tLPJF+kLoruaRP0S
         x0ErNyy92UldRzslq0qfeHpF4ZBq4YxTks26ixkT5aIxFwePIQO1gNExSCvoA/YvJasv
         2dVerNnw/hARn5Xx7FuCGKNW7nJkx1NyvfhPj47aUo/0OqRsbPfGi9gggN8ogWW6HNy6
         SWEQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXWnMEC7WxOJj21/LJJa7TVGOTvkROPYCXQgKupQPjwOIoI4/Fo6KqM3Ul4JvAxSpQ1ukBfw16/qRQehpRijNteuVmucPGjyw==
X-Gm-Message-State: AOJu0YzrxeF4xeoX5Vim8ZKzIScYsEIGSbdsFdAhXDvXMzI6tSxbb4h1
	tchqYFYxHj030lC5C/ZTZv6tIKJBho1C+uwqsBcZZqJto8GF+ksEo7w=
X-Google-Smtp-Source: AGHT+IErgw0pNg9PTtlm59neR23oQdBLnw4atsj5TNTVNwywbeSc2o+fPwB7OHQ6qWjd9Ahm9vU1BQ==
X-Received: by 2002:a5b:5d1:0:b0:dc6:9d35:f9aa with SMTP id w17-20020a5b05d1000000b00dc69d35f9aamr14399957ybp.19.1709781573090;
        Wed, 06 Mar 2024 19:19:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6986:0:b0:dcd:202d:6be8 with SMTP id e128-20020a256986000000b00dcd202d6be8ls591965ybc.2.-pod-prod-08-us;
 Wed, 06 Mar 2024 19:19:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVIqzQbsIwXg0GpI53hN+xYwBg79Dz110MQNY21uauIJf2WSLoSAHWEABZD4G2HRBlzFc0GRtzKwDXEoVArhS6SfmAeEulalUZNew==
X-Received: by 2002:a81:9483:0:b0:604:92e1:14fd with SMTP id l125-20020a819483000000b0060492e114fdmr18981417ywg.45.1709781571940;
        Wed, 06 Mar 2024 19:19:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709781571; cv=none;
        d=google.com; s=arc-20160816;
        b=ZirZTwrtmNDekfHBv/USp5vlKW/7c9s5ZzZhRKk1/tXqpcrBxEyd9k6nKu01coG0HZ
         v5QhLkGXT1u5/rkNPXH+IPU+T5pGPrU+9f3t5cjzbbIYD9HoBBmQxuhGlxEo0QpeGrtx
         Vwrnml3Brz8GKOuCHMc9fYvjhbjM8dQAQLt4evBbhDmRIl61GbXOnB2vMPWqhKzHereQ
         l26TnddBx+h/BdYuBIQMTG29Toe6aJyKAyfvBo5+TacXhmI3QuF4HryUf/Vlz1o1j5kn
         29klWOAQPhBllYPRW8dKOH37/FV9fcSUjNKzyLZyc2R4Kelkj9W1zmkrCctGq2x7KThk
         K06Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-language:references:cc:to:subject:from
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=K3TldHFnOYBYmyA+ZpDycxvkU6EpB6K91tOzErQkNoI=;
        fh=/nvJXuKiu0cTT25o8gmuchKnMBq0ySRTG4O4steqi58=;
        b=bE68WugudrKWawOOzKGjPhSpB4ym5XzCfRKQ3/15eTPWCwn328vOLtSkACJxufKYTE
         1MAd9pyd/lyDDxzs2wrJ8US65sCHfvd5Ywy3Z8Rce38NxZcLjh1/N4bazrfZqLJUwdNS
         8SJry+3EzrGQdDU4R2egT0a1oPAFCA7APrOf/H6fxkDfRgjvkJymXWkdNBZqZTKTTD4I
         T984SS+qkTZc8EfMOVq4oc/n/UuP6JBgVF94z499lju+I7VTHqvI+DNNDgQfFSxsj1CZ
         ICCBWm6YlSnhlpEF7wgardLGrXVUy0+Wt6eqeaImBj/dI5UtmqzQzu4e6iWaoeMxc0Pc
         sJIw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=ychUmlpI;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id y200-20020a0dd6d1000000b00609da8cc7ebsi254441ywd.3.2024.03.06.19.19.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Mar 2024 19:19:31 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [50.53.50.0] (helo=[192.168.254.15])
	by bombadil.infradead.org with esmtpsa (Exim 4.97.1 #2 (Red Hat Linux))
	id 1ri4Hf-00000002oO9-0yJC;
	Thu, 07 Mar 2024 03:19:03 +0000
Content-Type: multipart/mixed; boundary="------------oaFa8uBlfstuVB17zCaypWJR"
Message-ID: <10a95079-86e4-41bf-8e82-e387936c437d@infradead.org>
Date: Wed, 6 Mar 2024 19:18:57 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
From: Randy Dunlap <rdunlap@infradead.org>
Subject: Re: [PATCH v5 37/37] memprofiling: Documentation
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
 keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 aliceryhl@google.com, rientjes@google.com, minchan@google.com,
 kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
References: <20240306182440.2003814-1-surenb@google.com>
 <20240306182440.2003814-38-surenb@google.com>
Content-Language: en-US
In-Reply-To: <20240306182440.2003814-38-surenb@google.com>
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=ychUmlpI;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=rdunlap@infradead.org
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

This is a multi-part message in MIME format.
--------------oaFa8uBlfstuVB17zCaypWJR
Content-Type: text/plain; charset="UTF-8"

Hi,
This includes some editing suggestions and some doc build fixes.


On 3/6/24 10:24, Suren Baghdasaryan wrote:
> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> Provide documentation for memory allocation profiling.
> 
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
>  Documentation/mm/allocation-profiling.rst | 91 +++++++++++++++++++++++
>  1 file changed, 91 insertions(+)
>  create mode 100644 Documentation/mm/allocation-profiling.rst
> 
> diff --git a/Documentation/mm/allocation-profiling.rst b/Documentation/mm/allocation-profiling.rst
> new file mode 100644
> index 000000000000..8a862c7d3aab
> --- /dev/null
> +++ b/Documentation/mm/allocation-profiling.rst
> @@ -0,0 +1,91 @@
> +.. SPDX-License-Identifier: GPL-2.0
> +
> +===========================
> +MEMORY ALLOCATION PROFILING
> +===========================
> +
> +Low overhead (suitable for production) accounting of all memory allocations,
> +tracked by file and line number.
> +
> +Usage:
> +kconfig options:
> + - CONFIG_MEM_ALLOC_PROFILING
> + - CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> + - CONFIG_MEM_ALLOC_PROFILING_DEBUG
> +   adds warnings for allocations that weren't accounted because of a
> +   missing annotation
> +
> +Boot parameter:
> +  sysctl.vm.mem_profiling=0|1|never
> +
> +  When set to "never", memory allocation profiling overheads is minimized and it

                                                      overhead is

> +  cannot be enabled at runtime (sysctl becomes read-only).
> +  When CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=y, default value is "1".
> +  When CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=n, default value is "never".
> +
> +sysctl:
> +  /proc/sys/vm/mem_profiling
> +
> +Runtime info:
> +  /proc/allocinfo
> +
> +Example output:
> +  root@moria-kvm:~# sort -g /proc/allocinfo|tail|numfmt --to=iec
> +        2.8M    22648 fs/kernfs/dir.c:615 func:__kernfs_new_node
> +        3.8M      953 mm/memory.c:4214 func:alloc_anon_folio
> +        4.0M     1010 drivers/staging/ctagmod/ctagmod.c:20 [ctagmod] func:ctagmod_start
> +        4.1M        4 net/netfilter/nf_conntrack_core.c:2567 func:nf_ct_alloc_hashtable
> +        6.0M     1532 mm/filemap.c:1919 func:__filemap_get_folio
> +        8.8M     2785 kernel/fork.c:307 func:alloc_thread_stack_node
> +         13M      234 block/blk-mq.c:3421 func:blk_mq_alloc_rqs
> +         14M     3520 mm/mm_init.c:2530 func:alloc_large_system_hash
> +         15M     3656 mm/readahead.c:247 func:page_cache_ra_unbounded
> +         55M     4887 mm/slub.c:2259 func:alloc_slab_page
> +        122M    31168 mm/page_ext.c:270 func:alloc_page_ext
> +===================
> +Theory of operation
> +===================
> +
> +Memory allocation profiling builds off of code tagging, which is a library for
> +declaring static structs (that typcially describe a file and line number in

                                  typically

> +some way, hence code tagging) and then finding and operating on them at runtime

                                                                        at runtime,

> +- i.e. iterating over them to print them in debugfs/procfs.

  i.e., iterating

> +
> +To add accounting for an allocation call, we replace it with a macro
> +invocation, alloc_hooks(), that
> + - declares a code tag
> + - stashes a pointer to it in task_struct
> + - calls the real allocation function
> + - and finally, restores the task_struct alloc tag pointer to its previous value.
> +
> +This allows for alloc_hooks() calls to be nested, with the most recent one
> +taking effect. This is important for allocations internal to the mm/ code that
> +do not properly belong to the outer allocation context and should be counted
> +separately: for example, slab object extension vectors, or when the slab
> +allocates pages from the page allocator.
> +
> +Thus, proper usage requires determining which function in an allocation call
> +stack should be tagged. There are many helper functions that essentially wrap
> +e.g. kmalloc() and do a little more work, then are called in multiple places;
> +we'll generally want the accounting to happen in the callers of these helpers,
> +not in the helpers themselves.
> +
> +To fix up a given helper, for example foo(), do the following:
> + - switch its allocation call to the _noprof() version, e.g. kmalloc_noprof()
> + - rename it to foo_noprof()
> + - define a macro version of foo() like so:
> +   #define foo(...) alloc_hooks(foo_noprof(__VA_ARGS__))
> +
> +It's also possible to stash a pointer to an alloc tag in your own data structures.
> +
> +Do this when you're implementing a generic data structure that does allocations
> +"on behalf of" some other code - for example, the rhashtable code. This way,
> +instead of seeing a large line in /proc/allocinfo for rhashtable.c, we can
> +break it out by rhashtable type.
> +
> +To do so:
> + - Hook your data structure's init function, like any other allocation function

maybe end the line above with a '.' like the following line.

> + - Within your init function, use the convenience macro alloc_tag_record() to
> +   record alloc tag in your data structure.
> + - Then, use the following form for your allocations:
> +   alloc_hooks_tag(ht->your_saved_tag, kmalloc_noprof(...))


Finally, there are a number of documentation build warnings in this patch.
I'm no ReST expert, but the attached patch fixes them for me.

-- 
#Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/10a95079-86e4-41bf-8e82-e387936c437d%40infradead.org.

--------------oaFa8uBlfstuVB17zCaypWJR
Content-Type: text/x-patch; charset=UTF-8;
 name="docum-mm-alloc-profiling-fix403.patch"
Content-Disposition: attachment;
 filename="docum-mm-alloc-profiling-fix403.patch"
Content-Transfer-Encoding: base64

U2lnbmVkLW9mZi1ieTogUmFuZHkgRHVubGFwIDxyZHVubGFwQGluZnJhZGVhZC5vcmc+Ci0t
LQogRG9jdW1lbnRhdGlvbi9tbS9hbGxvY2F0aW9uLXByb2ZpbGluZy5yc3QgfCAgIDI4ICsr
KysrKysrKystLS0tLS0tLS0tCiBEb2N1bWVudGF0aW9uL21tL2luZGV4LnJzdCAgICAgICAg
ICAgICAgICB8ICAgIDEgCiAyIGZpbGVzIGNoYW5nZWQsIDE2IGluc2VydGlvbnMoKyksIDEz
IGRlbGV0aW9ucygtKQoKZGlmZiAtLSBhL0RvY3VtZW50YXRpb24vbW0vYWxsb2NhdGlvbi1w
cm9maWxpbmcucnN0IGIvRG9jdW1lbnRhdGlvbi9tbS9hbGxvY2F0aW9uLXByb2ZpbGluZy5y
c3QKLS0tIGEvRG9jdW1lbnRhdGlvbi9tbS9hbGxvY2F0aW9uLXByb2ZpbGluZy5yc3QKKysr
IGIvRG9jdW1lbnRhdGlvbi9tbS9hbGxvY2F0aW9uLXByb2ZpbGluZy5yc3QKQEAgLTksMTEg
KzksMTEgQEAgdHJhY2tlZCBieSBmaWxlIGFuZCBsaW5lIG51bWJlci4KIAogVXNhZ2U6CiBr
Y29uZmlnIG9wdGlvbnM6Ci0gLSBDT05GSUdfTUVNX0FMTE9DX1BST0ZJTElORwotIC0gQ09O
RklHX01FTV9BTExPQ19QUk9GSUxJTkdfRU5BQkxFRF9CWV9ERUZBVUxUCi0gLSBDT05GSUdf
TUVNX0FMTE9DX1BST0ZJTElOR19ERUJVRwotICAgYWRkcyB3YXJuaW5ncyBmb3IgYWxsb2Nh
dGlvbnMgdGhhdCB3ZXJlbid0IGFjY291bnRlZCBiZWNhdXNlIG9mIGEKLSAgIG1pc3Npbmcg
YW5ub3RhdGlvbgorLSBDT05GSUdfTUVNX0FMTE9DX1BST0ZJTElORworLSBDT05GSUdfTUVN
X0FMTE9DX1BST0ZJTElOR19FTkFCTEVEX0JZX0RFRkFVTFQKKy0gQ09ORklHX01FTV9BTExP
Q19QUk9GSUxJTkdfREVCVUcKK2FkZHMgd2FybmluZ3MgZm9yIGFsbG9jYXRpb25zIHRoYXQg
d2VyZW4ndCBhY2NvdW50ZWQgYmVjYXVzZSBvZiBhCittaXNzaW5nIGFubm90YXRpb24KIAog
Qm9vdCBwYXJhbWV0ZXI6CiAgIHN5c2N0bC52bS5tZW1fcHJvZmlsaW5nPTB8MXxuZXZlcgpA
QCAtMjksNyArMjksOCBAQCBzeXNjdGw6CiBSdW50aW1lIGluZm86CiAgIC9wcm9jL2FsbG9j
aW5mbwogCi1FeGFtcGxlIG91dHB1dDoKK0V4YW1wbGUgb3V0cHV0OjoKKwogICByb290QG1v
cmlhLWt2bTp+IyBzb3J0IC1nIC9wcm9jL2FsbG9jaW5mb3x0YWlsfG51bWZtdCAtLXRvPWll
YwogICAgICAgICAyLjhNICAgIDIyNjQ4IGZzL2tlcm5mcy9kaXIuYzo2MTUgZnVuYzpfX2tl
cm5mc19uZXdfbm9kZQogICAgICAgICAzLjhNICAgICAgOTUzIG1tL21lbW9yeS5jOjQyMTQg
ZnVuYzphbGxvY19hbm9uX2ZvbGlvCkBAIC00MiwyMSArNDMsMjIgQEAgRXhhbXBsZSBvdXRw
dXQ6CiAgICAgICAgICAxNU0gICAgIDM2NTYgbW0vcmVhZGFoZWFkLmM6MjQ3IGZ1bmM6cGFn
ZV9jYWNoZV9yYV91bmJvdW5kZWQKICAgICAgICAgIDU1TSAgICAgNDg4NyBtbS9zbHViLmM6
MjI1OSBmdW5jOmFsbG9jX3NsYWJfcGFnZQogICAgICAgICAxMjJNICAgIDMxMTY4IG1tL3Bh
Z2VfZXh0LmM6MjcwIGZ1bmM6YWxsb2NfcGFnZV9leHQKKwogPT09PT09PT09PT09PT09PT09
PQogVGhlb3J5IG9mIG9wZXJhdGlvbgogPT09PT09PT09PT09PT09PT09PQogCiBNZW1vcnkg
YWxsb2NhdGlvbiBwcm9maWxpbmcgYnVpbGRzIG9mZiBvZiBjb2RlIHRhZ2dpbmcsIHdoaWNo
IGlzIGEgbGlicmFyeSBmb3IKIGRlY2xhcmluZyBzdGF0aWMgc3RydWN0cyAodGhhdCB0eXBj
aWFsbHkgZGVzY3JpYmUgYSBmaWxlIGFuZCBsaW5lIG51bWJlciBpbgotc29tZSB3YXksIGhl
bmNlIGNvZGUgdGFnZ2luZykgYW5kIHRoZW4gZmluZGluZyBhbmQgb3BlcmF0aW5nIG9uIHRo
ZW0gYXQgcnVudGltZQotLSBpLmUuIGl0ZXJhdGluZyBvdmVyIHRoZW0gdG8gcHJpbnQgdGhl
bSBpbiBkZWJ1Z2ZzL3Byb2Nmcy4KK3NvbWUgd2F5LCBoZW5jZSBjb2RlIHRhZ2dpbmcpIGFu
ZCB0aGVuIGZpbmRpbmcgYW5kIG9wZXJhdGluZyBvbiB0aGVtIGF0IHJ1bnRpbWUsCitpLmUu
LCBpdGVyYXRpbmcgb3ZlciB0aGVtIHRvIHByaW50IHRoZW0gaW4gZGVidWdmcy9wcm9jZnMu
CiAKIFRvIGFkZCBhY2NvdW50aW5nIGZvciBhbiBhbGxvY2F0aW9uIGNhbGwsIHdlIHJlcGxh
Y2UgaXQgd2l0aCBhIG1hY3JvCi1pbnZvY2F0aW9uLCBhbGxvY19ob29rcygpLCB0aGF0Ci0g
LSBkZWNsYXJlcyBhIGNvZGUgdGFnCi0gLSBzdGFzaGVzIGEgcG9pbnRlciB0byBpdCBpbiB0
YXNrX3N0cnVjdAotIC0gY2FsbHMgdGhlIHJlYWwgYWxsb2NhdGlvbiBmdW5jdGlvbgotIC0g
YW5kIGZpbmFsbHksIHJlc3RvcmVzIHRoZSB0YXNrX3N0cnVjdCBhbGxvYyB0YWcgcG9pbnRl
ciB0byBpdHMgcHJldmlvdXMgdmFsdWUuCitpbnZvY2F0aW9uLCBhbGxvY19ob29rcygpLCB0
aGF0OgorLSBkZWNsYXJlcyBhIGNvZGUgdGFnCistIHN0YXNoZXMgYSBwb2ludGVyIHRvIGl0
IGluIHRhc2tfc3RydWN0CistIGNhbGxzIHRoZSByZWFsIGFsbG9jYXRpb24gZnVuY3Rpb24K
Ky0gYW5kIGZpbmFsbHksIHJlc3RvcmVzIHRoZSB0YXNrX3N0cnVjdCBhbGxvYyB0YWcgcG9p
bnRlciB0byBpdHMgcHJldmlvdXMgdmFsdWUuCiAKIFRoaXMgYWxsb3dzIGZvciBhbGxvY19o
b29rcygpIGNhbGxzIHRvIGJlIG5lc3RlZCwgd2l0aCB0aGUgbW9zdCByZWNlbnQgb25lCiB0
YWtpbmcgZWZmZWN0LiBUaGlzIGlzIGltcG9ydGFudCBmb3IgYWxsb2NhdGlvbnMgaW50ZXJu
YWwgdG8gdGhlIG1tLyBjb2RlIHRoYXQKZGlmZiAtLSBhL0RvY3VtZW50YXRpb24vbW0vaW5k
ZXgucnN0IGIvRG9jdW1lbnRhdGlvbi9tbS9pbmRleC5yc3QKLS0tIGEvRG9jdW1lbnRhdGlv
bi9tbS9pbmRleC5yc3QKKysrIGIvRG9jdW1lbnRhdGlvbi9tbS9pbmRleC5yc3QKQEAgLTI2
LDYgKzI2LDcgQEAgc2VlIHRoZSA6ZG9jOmBhZG1pbiBndWlkZSA8Li4vYWRtaW4tZ3VpZAog
ICAgcGFnZV9jYWNoZQogICAgc2htZnMKICAgIG9vbQorICAgYWxsb2NhdGlvbi1wcm9maWxp
bmcKIAogTGVnYWN5IERvY3VtZW50YXRpb24KID09PT09PT09PT09PT09PT09PT09Cg==

--------------oaFa8uBlfstuVB17zCaypWJR--
