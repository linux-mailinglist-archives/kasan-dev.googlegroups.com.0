Return-Path: <kasan-dev+bncBC7OD3FKWUERBPPKUKXQMGQEJIU5X2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 01EC2873EAB
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:26:07 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-5a12b5cc6casf3166368eaf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:26:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749566; cv=pass;
        d=google.com; s=arc-20160816;
        b=VhulQoIuGyVg/F/g7n3cElAMa64+eVsioUm2PtgJSWZD89w4kAHjGj5AmheTfp06XE
         2atWGIuKQB09genabYbpYCTyi+RV4rlH7eTOzuxV3FWc/H8++J2ILHpUx4RZkkhHOQaX
         AYuIFIzl+QGvmOgk65qHrXgOuu1qZ+xMfjY2iVBdj9rrAytOiShXsW7f7yJBiSFsTe+g
         /fz2N8Tcy/JR+fXZyCkNmKLyN1EeKbGH+ivDJUXvgvLJF+YHZON7o30RNqqZ1W33rYou
         KqOrggbna7keutdjI5L39ncTyttFWQMnWLoIc5IxVN50brzsYS7J4vyvkMpo/CCN7BvL
         1KVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=XoGxK9OlLBHQi8po+aozfZD1tCO32tYaqDPV5xeklgA=;
        fh=mset/y25KVp/mC7c5yZseeSxnjmcvtDE5JOCz2Hf4rE=;
        b=h4aiICaEvkXvXXmROcGU+lI0aeWoyBGYNF861cfnRuYTmL8dmJyoJPENd8HD560MfJ
         ypbZPjwUev+98SX9s/hvxuRrcBYbVwfkHwy8oequg6mzr0P0tEKkHrcfwJLtNi67qmWb
         uFY17PCUOc2CTw4y/PoLOthZtw7AcB98mNPhiRdcX+CJzMKAxfAWPVI5SFlmknUSCg7B
         dDK/tMXrhWgDrmpzyAYXmsw51xwx8AuPtR7deQQAmiHOFb+8ZPJALN/gur6dzY1K+DyD
         BqmlMTef2PXNHOdbhI7zmRzipyHdH4BpBwP/44zyIjxD+FQEoSm2xGBB+1nY4oJED2a8
         6Z8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iW+zI3dr;
       spf=pass (google.com: domain of 3o7xozqykcx4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3O7XoZQYKCX4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749566; x=1710354366; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XoGxK9OlLBHQi8po+aozfZD1tCO32tYaqDPV5xeklgA=;
        b=aVPFCLOADRtvGe1ZphIDS2k5Pz5fiBgaTto6BwfXT8f35lYyejLapp+ehFnpNZIZGm
         Q9Oqwe3raDkpGkXlf/PTikimUAuUF0InKtenTp63z+PnrRIEA90a+RMFwG3rPqBl8Qxi
         hULc6mYh1/6WnK13SLwU6jvgyUCAKgdjB4RYsP0osr7y7B75hNTz2+xcIvUQ7jOqCp29
         WdjZtxHl979MDNAnSYbox4u2ZZXehRolfM59hxdRufoL4C/VVT1COMHkE35COdErP++y
         yrXW3ec3lstu6BWqa5O8boqfsh1/ekn6rud9zwuiM2q4L/a8um3totAIBybhLRSxG01n
         dXqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749566; x=1710354366;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XoGxK9OlLBHQi8po+aozfZD1tCO32tYaqDPV5xeklgA=;
        b=QdqRy/woPNCOwC/5KMdjB64q9jli8og8wSIoozzwXtdAIuUc0i38LjvqA2iHmy2BzO
         SGbhAeYChZoT2RnX2TObTMlyCSs2RCFyl9i8QExjp2XiyP46GUKslvlEawRqERlMcCOM
         df+JwNWsfhBYKQqIt2w0YfIBAJVuWiKh3AOp+W1aewHNqf34YNVhkfajyPvzYvvz9TJb
         NAGYSpjUbDIO3Gj/0O0C0gqDNxLcNo2JL3WPw/1/4G9NrsMsxo9rn5296xybHTz77O+7
         x6s/3A7qdh6Ys6svdnO4DnAZgdYVNzj2ib1wUR2HHfvffnGVhDxyiqy2QsJFwXB5IU4D
         XNHg==
X-Forwarded-Encrypted: i=2; AJvYcCXhikHrJZdMy6HFuurhM2q2swjDEx9Bexfy6bJ5YOKT5bioBXZGMBR4iY2yvJQ7iSZ9c1zk4HfozCFY5n+x177nfFy6tnPiQg==
X-Gm-Message-State: AOJu0YxNRxGbx7gcJ6zGHxDESBUeRBNBVifvG2ZPULyItYw15rTxuCj2
	nhcBg19Jr0Ab0U2GuRuoa1lX+twhQlFHFZsAxKPxuxtky83ZUK1Y
X-Google-Smtp-Source: AGHT+IF87zd7CWNmyQm1JkXZfXyHVhBnSD3vXsdBKXyavSP9uGKmv5y4X27WJcIJGNw4nJs4pK/K5w==
X-Received: by 2002:a05:6820:296:b0:5a1:2a9f:c7a6 with SMTP id q22-20020a056820029600b005a12a9fc7a6mr5387856ood.0.1709749565835;
        Wed, 06 Mar 2024 10:26:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5808:0:b0:5a1:79e4:2081 with SMTP id f8-20020a4a5808000000b005a179e42081ls117405oob.0.-pod-prod-04-us;
 Wed, 06 Mar 2024 10:26:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXFGYCtwdROdiqqW5alWNWTZELZGkGUtClF50U0s/igfJtHHP2nOJ1Fhk85uklNVQwHbVeNaZM/E2UifuxAtxCReIBn/n1iW39CXQ==
X-Received: by 2002:a05:6820:1505:b0:5a1:2173:1a15 with SMTP id ay5-20020a056820150500b005a121731a15mr7085093oob.8.1709749564630;
        Wed, 06 Mar 2024 10:26:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749564; cv=none;
        d=google.com; s=arc-20160816;
        b=oJwXJ423p3kT6OGZfXWKOTSdN2PFsWk8H7zirtavpPm7LYC2bmstvNghT9hKHQeCyJ
         G/p3DraxFqnguYzAA+7uzAmIJOloYuXomNuImGT0b5GXH2JFk6PQhc67QWpiOJU/q1gH
         tKeM5qmlFlIJWvsJpTpbK0zQ0wtMW9w5ux0iREORu6tysufvTllF1Kcpp3bXMl/pwOPl
         MWfM1yU92pVqIYkClFvUDgo6EhBw7sgbuD3OqMfuEDmYwkTwaYOJuLhaaFjhPEhI2WBR
         QhEoEoFV/wlWRGPgFPjYnTPcsx+fFUHSFXBd1WD/nx6qY47NJBWhGh5eoL01jAlT7I/G
         +mlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=yGhey761h+yk0goaaYaIkNpiVVUjQ3rocN1HojLD7sY=;
        fh=j+wV26OucJvewQky+IiYSxlm0x3+d93eC32zIe7xuXM=;
        b=ABYe7LHZGMw2KaLRmWV9MQWic9+ObpL+Gbq0O8iPw7onNlWyu+Ewf0zT0Aoh1Vd/vR
         1ufHJqc8zPwKIChpZ0UrqjkqMiZpSwvsvtJKPsnGplTe17aUSVofz9+eHhSlVz3UMrZQ
         B96pPoFIXs825xCedz2Zv4vtThr7BWpbVWlhIky1iqLP4Q6HRmGYgdwhJGuQ1qg9Zjw8
         5VJA0b+L70Lycy9xbapylgMCoqpxwG5tIE85JyPWTGzEMHU+BsUn18Ep8uUb/oZ3IqaA
         gVKGcq9OGKytt1oCizj4oQEFlbvIcLh60HML/4oE5n2VYdOfLbZzr9y+MEAYjBQCGHlC
         ZBDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iW+zI3dr;
       spf=pass (google.com: domain of 3o7xozqykcx4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3O7XoZQYKCX4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id z16-20020a0568301db000b006e4b3e2c386si841433oti.2.2024.03.06.10.26.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:26:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3o7xozqykcx4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dc6b26783b4so8971304276.0
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:26:04 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVyg9ZZ2BzdxoR0EaMN4zH5Gl1dwtdztcEWVrVLiTM0ZzXIeFce4I5km83RiXHbbxCQPBdvLTGkW3+zUBDyMl6WH/2F19DuanNZ5A==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a25:2fc1:0:b0:dc6:ebd4:cca2 with SMTP id
 v184-20020a252fc1000000b00dc6ebd4cca2mr528159ybv.11.1709749563843; Wed, 06
 Mar 2024 10:26:03 -0800 (PST)
Date: Wed,  6 Mar 2024 10:24:35 -0800
In-Reply-To: <20240306182440.2003814-1-surenb@google.com>
Mime-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-38-surenb@google.com>
Subject: [PATCH v5 37/37] memprofiling: Documentation
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
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
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=iW+zI3dr;       spf=pass
 (google.com: domain of 3o7xozqykcx4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3O7XoZQYKCX4uwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

Provide documentation for memory allocation profiling.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 Documentation/mm/allocation-profiling.rst | 91 +++++++++++++++++++++++
 1 file changed, 91 insertions(+)
 create mode 100644 Documentation/mm/allocation-profiling.rst

diff --git a/Documentation/mm/allocation-profiling.rst b/Documentation/mm/allocation-profiling.rst
new file mode 100644
index 000000000000..8a862c7d3aab
--- /dev/null
+++ b/Documentation/mm/allocation-profiling.rst
@@ -0,0 +1,91 @@
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
+Boot parameter:
+  sysctl.vm.mem_profiling=0|1|never
+
+  When set to "never", memory allocation profiling overheads is minimized and it
+  cannot be enabled at runtime (sysctl becomes read-only).
+  When CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=y, default value is "1".
+  When CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=n, default value is "never".
+
+sysctl:
+  /proc/sys/vm/mem_profiling
+
+Runtime info:
+  /proc/allocinfo
+
+Example output:
+  root@moria-kvm:~# sort -g /proc/allocinfo|tail|numfmt --to=iec
+        2.8M    22648 fs/kernfs/dir.c:615 func:__kernfs_new_node
+        3.8M      953 mm/memory.c:4214 func:alloc_anon_folio
+        4.0M     1010 drivers/staging/ctagmod/ctagmod.c:20 [ctagmod] func:ctagmod_start
+        4.1M        4 net/netfilter/nf_conntrack_core.c:2567 func:nf_ct_alloc_hashtable
+        6.0M     1532 mm/filemap.c:1919 func:__filemap_get_folio
+        8.8M     2785 kernel/fork.c:307 func:alloc_thread_stack_node
+         13M      234 block/blk-mq.c:3421 func:blk_mq_alloc_rqs
+         14M     3520 mm/mm_init.c:2530 func:alloc_large_system_hash
+         15M     3656 mm/readahead.c:247 func:page_cache_ra_unbounded
+         55M     4887 mm/slub.c:2259 func:alloc_slab_page
+        122M    31168 mm/page_ext.c:270 func:alloc_page_ext
+===================
+Theory of operation
+===================
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
+
+It's also possible to stash a pointer to an alloc tag in your own data structures.
+
+Do this when you're implementing a generic data structure that does allocations
+"on behalf of" some other code - for example, the rhashtable code. This way,
+instead of seeing a large line in /proc/allocinfo for rhashtable.c, we can
+break it out by rhashtable type.
+
+To do so:
+ - Hook your data structure's init function, like any other allocation function
+ - Within your init function, use the convenience macro alloc_tag_record() to
+   record alloc tag in your data structure.
+ - Then, use the following form for your allocations:
+   alloc_hooks_tag(ht->your_saved_tag, kmalloc_noprof(...))
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-38-surenb%40google.com.
