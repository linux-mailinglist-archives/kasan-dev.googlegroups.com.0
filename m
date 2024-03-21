Return-Path: <kasan-dev+bncBC7OD3FKWUERBB6F6GXQMGQESOI5TKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 20224885DD6
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:38:33 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id ca18e2360f4ac-7cbfd4781fcsf105671939f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:38:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039112; cv=pass;
        d=google.com; s=arc-20160816;
        b=HnRGOBMr156R/ayOgg5gKRDd0MUuGeYgSPjdKTazmgLTzTRb75EQfjONMBykBlgsSK
         +e02HA1NYQyENqMV98O5eNbPqAHuYaq+IBc/jU8J/VcenjTFFFhCnXnb4NC+zrJJofG5
         B4COzLu++lpsz6wLZhV8bgM7DZGEIrpn84kfiKbRtJ7jUlONugnoHq2KPWHRj1jLdCgU
         5sykOM3kEJdJXWAOdYtfASr0dNNYCFs2iPA08MvOCgr6WylqKzZhN7vTH29vQkZVz/c1
         NSBAIjw8xLVg4jF2nrSfJjCSLGas9GCcppoKFhfyg+UfC8MfFoG+k4XavsE0d4usz6pb
         vphg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=B/Z18nbZOB66PGWjY9NVFeBuGDiFPAMtKX51Nm2DJVk=;
        fh=zkG8O1BuVu38kQcBQziYT85yiEhE/B/2b0tRmeIhyUs=;
        b=bPqQvw845PqQn+WWEJltZQfaAIo9lEhfnlp9aHEUhGHzP2XtcSJ1eMfhfBBXfMP+XI
         muPAkFRWgNJQkOVg4izGhkOQ8BpCauXaWCzHzCaUlPQdE5W/znUSL0zM2U+I0R9RAPOj
         NghBh0rPvygQD/4q/UWiytWjed2pNRK17pbc36Gp1vhtaBUq/quXAjx8nWkpddz7QU9f
         EHT9bh12w29IaBoHBjRqZ5cVv6PV+IV8QY8+QQS26gbolcIMjcr8Wu7DaqMujBkksVMT
         0GvC0ZZyXhkG3HhCm1siImr0kwYrxE+lzZhCoKeb5X9W+BJQUnxP/pFm2IzzzvTm3gCo
         DYUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D89PWcEo;
       spf=pass (google.com: domain of 3hml8zqykcxmjlivesxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3hmL8ZQYKCXMjliVeSXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039112; x=1711643912; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=B/Z18nbZOB66PGWjY9NVFeBuGDiFPAMtKX51Nm2DJVk=;
        b=CGR32LkXEmwqh9qlGuWo5xyM+d4PuocU+XOHf76j+s/b2suUYcylun46qhkNf1UhBG
         rThJO+8p/vJ9rCu61K227isu9EU5WxgiTFFvnq+1JZP2gAXNo8w3aBHYxzSljwtOdYS6
         6Lehk9bzVcETSIMCfDNiRc0HnI8IcZhNx8sJsRyeJDicLMTliyyIphbW4ptdCQ2Epx37
         yDDx3wT09gn5EUWQE8/FJYduffhF09qruzBN2Fd+flnN7bTR8Jxsb38dy1rvY3AemBLQ
         ydWk5a5igKciJn8nIG0vV7jtIMuEX2/mTWFMPXFP0TO8xjjvAcndZzoCzmE3iyFQJwfO
         Pbew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039112; x=1711643912;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=B/Z18nbZOB66PGWjY9NVFeBuGDiFPAMtKX51Nm2DJVk=;
        b=c/TQMdAQFXQbQ+pVC5vfxfNNS0B7ZODIXDb/yQqYBe+1Xh3kpjRa6uAChEHQpt2XrT
         XulVPDYZL3JBK1RgeClwwQNosK25elBxLWcD3d7qTRefWKEORB7L67FsVpqgEwMSS3xE
         8BdNY1ZZXMx8vAD9vUYEeP0Zhc8iqiYAG1+FO16GwsqtRDk9akPDZS7Pg0sZT/bSWpnl
         HNh7Fv5QCq0fc7dLVFC3Uwt3xNTLUhN+2beC4qEvfbiBzzK4hDLfEDtUn6hbyrY8RWeg
         DvXnPe2kEFlOzjNoOSMYZYe9hTqC7Y9nPxs7lVRXLHfT32uQcX0hPHw2QA0kEum9kzU6
         KxYw==
X-Forwarded-Encrypted: i=2; AJvYcCUHeNt3493coJQJJ9DSIdwaXJBnRSTn35Js9XFsWuWavLTOnH4bUN96ubeBvVGemIV/0hCAm4Ino1W6RZnSBYEnovsQO5mcWg==
X-Gm-Message-State: AOJu0YzyIV6lWzRqJgI52L9MP2kV87Lylg7CITAxCv99kqR0/0fFxz2N
	S8i+nauCIOx8cWsjBVpvtsMA17KHSx+m21aVcRJJRn8+QVrR7jiZ
X-Google-Smtp-Source: AGHT+IF2GsSu31LoRjl0Ue91rm9a95d8LMvV+dTBEnwEpzzvb/MecG/6/oN6gV/z3UsNbebvRLoJ9Q==
X-Received: by 2002:a92:c6cf:0:b0:366:b8b0:708c with SMTP id v15-20020a92c6cf000000b00366b8b0708cmr26142ilm.16.1711039111938;
        Thu, 21 Mar 2024 09:38:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d0e:b0:366:c498:96e2 with SMTP id
 i14-20020a056e021d0e00b00366c49896e2ls794047ila.0.-pod-prod-07-us; Thu, 21
 Mar 2024 09:38:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWIg8Y3OntCee9uGSqKULNxDdGXuJqnBAnTMbi/J5wRNThJ1uhgcShzhyvvGpS14wca4YS94nsk3fMah+T3lm14XQ/8tohjaOEA1g==
X-Received: by 2002:a92:903:0:b0:366:1e4:d19e with SMTP id y3-20020a920903000000b0036601e4d19emr14365ilg.30.1711039110715;
        Thu, 21 Mar 2024 09:38:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039110; cv=none;
        d=google.com; s=arc-20160816;
        b=x2pKMcYPKenvJ4zry+W5VN3BYJfxnt9f81O9JxmfvyhQVat24hvQfxtjc1mOUykVA2
         bBrgk9PT1+Uw37wCK3wgj6aW+NEvCUbOMA0+xo0CK2v13HVptawjQd8nQcqO3rsEe5EL
         DDyLi7h+TbrUZYSzrONQXWGuHbBP2chWxsA1eYMvvJr2FMMJNdKtstHLTnxNgDc7OioH
         uFkAvjfG9rsB4fpVWJYWCz5Saf2DJk6bGvkwA0OGzw4r+1ueyrWZJzw6x0PuZNNgoiRd
         kdNX8ou3XTPyX5kl9relEDwbDn8XC4gxHvQCOeTb1fm3/So4l3U6NEjQWSuzPlotXDEM
         Q1zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=zMtv/wiplx2DxF9seTFx3IcU+R2+PFSDAr6m0+A1ntI=;
        fh=GscYYVS1WZ/jCnp9FTnwjXHJ3taz3BeQoLjPxd3D348=;
        b=qxl9s3A7dpcNJ/7HtFwFJNStyXZ6yEw889zlaR5J/xBTrp1ubpSLcPMXHW1GcuDr5G
         SE/FMYuZmLbzUA8Sr55t5kGU9+s1X9nahwbi2BKYAO5kXQLATc6dc3Gs67lC2WWXSX8p
         9yeUZbCCtBjFk5TFmW6JpECNJB5WaJ45JY4wPSZBwJoE/IMq9eXwqAmn1B67r4RoQ9uO
         lJrOH3cTzF1GRiJIH7WGCc5RVE3JWcLkryvdcoxlSdkUs0cpOigBp44Hy6Il6IMMijCY
         Yr5plQ2duNx1KBkaBMK6Xirwy8rjqGNB+xlkJA6MfiAZPiPo8krYsx6E3Gk6D+EyitxH
         Isqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D89PWcEo;
       spf=pass (google.com: domain of 3hml8zqykcxmjlivesxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3hmL8ZQYKCXMjliVeSXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id g6-20020a92c7c6000000b0036503a50b98si6828ilk.4.2024.03.21.09.38.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:38:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hml8zqykcxmjlivesxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dbf618042daso1830978276.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:38:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUn4WaEmQ2Qj8GTassE+gsT5Ks24IehPpYGuceQaOfJ3UN2ts/z0tjHhpoxVkWj05F1bd7FgxG/1aV9TeLGBKMDv8F5JCvZ7Cw6jw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:240e:b0:dc2:5273:53f9 with SMTP id
 dr14-20020a056902240e00b00dc2527353f9mr1211362ybb.1.1711039110014; Thu, 21
 Mar 2024 09:38:30 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:59 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-38-surenb@google.com>
Subject: [PATCH v6 37/37] memprofiling: Documentation
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
	glider@google.com, elver@google.com, dvyukov@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=D89PWcEo;       spf=pass
 (google.com: domain of 3hml8zqykcxmjlivesxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3hmL8ZQYKCXMjliVeSXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--surenb.bounces.google.com;
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
 Documentation/mm/allocation-profiling.rst | 100 ++++++++++++++++++++++
 Documentation/mm/index.rst                |   1 +
 2 files changed, 101 insertions(+)
 create mode 100644 Documentation/mm/allocation-profiling.rst

diff --git a/Documentation/mm/allocation-profiling.rst b/Documentation/mm/allocation-profiling.rst
new file mode 100644
index 000000000000..d3b733b41ae6
--- /dev/null
+++ b/Documentation/mm/allocation-profiling.rst
@@ -0,0 +1,100 @@
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
+- CONFIG_MEM_ALLOC_PROFILING
+
+- CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
+
+- CONFIG_MEM_ALLOC_PROFILING_DEBUG
+  adds warnings for allocations that weren't accounted because of a
+  missing annotation
+
+Boot parameter:
+  sysctl.vm.mem_profiling=0|1|never
+
+  When set to "never", memory allocation profiling overhead is minimized and it
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
+Example output::
+
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
+
+===================
+Theory of operation
+===================
+
+Memory allocation profiling builds off of code tagging, which is a library for
+declaring static structs (that typically describe a file and line number in
+some way, hence code tagging) and then finding and operating on them at runtime,
+- i.e. iterating over them to print them in debugfs/procfs.
+
+To add accounting for an allocation call, we replace it with a macro
+invocation, alloc_hooks(), that
+- declares a code tag
+- stashes a pointer to it in task_struct
+- calls the real allocation function
+- and finally, restores the task_struct alloc tag pointer to its previous value.
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
+- switch its allocation call to the _noprof() version, e.g. kmalloc_noprof()
+
+- rename it to foo_noprof()
+
+- define a macro version of foo() like so:
+
+  #define foo(...) alloc_hooks(foo_noprof(__VA_ARGS__))
+
+It's also possible to stash a pointer to an alloc tag in your own data structures.
+
+Do this when you're implementing a generic data structure that does allocations
+"on behalf of" some other code - for example, the rhashtable code. This way,
+instead of seeing a large line in /proc/allocinfo for rhashtable.c, we can
+break it out by rhashtable type.
+
+To do so:
+- Hook your data structure's init function, like any other allocation function.
+
+- Within your init function, use the convenience macro alloc_tag_record() to
+  record alloc tag in your data structure.
+
+- Then, use the following form for your allocations:
+  alloc_hooks_tag(ht->your_saved_tag, kmalloc_noprof(...))
diff --git a/Documentation/mm/index.rst b/Documentation/mm/index.rst
index 31d2ac306438..48b9b559ca7b 100644
--- a/Documentation/mm/index.rst
+++ b/Documentation/mm/index.rst
@@ -26,6 +26,7 @@ see the :doc:`admin guide <../admin-guide/mm/index>`.
    page_cache
    shmfs
    oom
+   allocation-profiling
 
 Legacy Documentation
 ====================
-- 
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-38-surenb%40google.com.
