Return-Path: <kasan-dev+bncBC7OD3FKWUERBGNE3GXAMGQEV7TESXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 175CB85E7A2
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:42:19 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-68f747e0ec4sf36183856d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:42:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544538; cv=pass;
        d=google.com; s=arc-20160816;
        b=hRisjugSge+8JEzTlfjQd5vwqQxTBIWqNJNVm10d7SgVYOkCxPihM0HcaSyoU4mmQB
         DJlXMLx5HGuWDn2R/tgd66M+7SAfIwfJwYIONRZCl+X29a6btw/14B+b8P5Wb5iGCDnT
         VKkURAVJCFIfmH456IRUvkvVb1Xa/KEPbJ58zQQCYiDL0nBoTDeAJ7Jqb7eHZXtC0lFE
         sLt3gwUnk6OXobD15QSpXR2hMO/kdC5idLV0fidAaejYUk/Dii+cW2dM6AhSEYWt9Aa4
         RISxJG87kAz8v09MIVWKYKOjFNpRD7JLRVxbW5ItNqGbZPinsNmJi02eU/8rCDuItgtH
         BRMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=NjFVC8WRIhjz3I5JKB1hrT6B2Ki42Pcb/0TIDcutmfo=;
        fh=3f2GwOMSMnbT4TTL5Erxwb2VDtz8stfhcFMP+IwWWbQ=;
        b=osMA6z9tw5efxQEOzkTCjmimcQk+X3Abe9zC954LfX25p4L5QT9eTkvtGQAc0GUNsf
         ghBXj7Lqgkc03GOF9peCbQgypqX47X42O7Ignh3yNi0uqyuHjjprdGtG52Pte5G/B7fw
         nuGh/PFBJqKAQYyFq/rW84vva+eMUktjVwdNWe8RVTxDWLTGsTccb0AkeK7Btw7iFm3g
         G3bUWXDmrKab3ds9ZFy3S/j34XZuP5soWlC2CjR3MXUumwVr97exvJsxZ0Nd1ifQb/xt
         putVrV72xRKum6b45ouYt77kWs4ALJZTecUy2TabhJFfhUhOJQDRjMX3OM2yUp7ixB7X
         7eZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ywXaIkgq;
       spf=pass (google.com: domain of 3gflwzqykcus574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3GFLWZQYKCUs574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544538; x=1709149338; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NjFVC8WRIhjz3I5JKB1hrT6B2Ki42Pcb/0TIDcutmfo=;
        b=sI0N4xCVKmIuKIpLRJ/R3/gaZEVolMwTPqDYXHfPGU+AeoI1j8vUIDx8XUbpmFTToP
         HfIR6w18/bRYstG/P0Btm3tW+su3Ii7q0RANmcLI8sRh4Qz5pClRV5bu918hxGJNymBD
         8xDw6pmhu/AOEfx1sNeOcV5tUz/ZIe96j+Xlc9SBuYDteP93Ysm0S9CY4ozLncLyG0rv
         KrOXzJRGENZUCIjWNOX+qzvERlGphHNFwkm3TuVMwrkCjvKaFeOuHax7ko7RmM0VyRA1
         4/Q2JaykKU1VxedLrSywT2HllLXomfuSAdBwk65911FbFdY01ccz3a+C2exfzEM7HM+A
         9PBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544538; x=1709149338;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NjFVC8WRIhjz3I5JKB1hrT6B2Ki42Pcb/0TIDcutmfo=;
        b=Y07+oBUUDQGZZE8qQiy69x23QhWOyZKeyMt07gTR9RcLDaMGHAIda3+7NsllgdaxYd
         xRV+l2zxNy/S2HvNGVk/Afl7WU6TAFth7aiVKCvCfwLcwBY/H6Ytqu6yz90WhKcP/jss
         fvcc7yRvqZ4dsrLC71X1qNzo3kxElar/twEczn3tpLNyn032nX6x92viXMhpT/MdqbgL
         vfD8aIfA8AMHCSf2JbiUNWrJMdCELUYKUUOVi0kZNkk2C4ROoblClpjzflkOobN/QGIK
         yPsVv/X4cgi09t0ATVKTyLfhgBS+PRdr6t0S5cOgxD09Ff7n5AVPlhTsTM5e2uoGjf6P
         Ux+g==
X-Forwarded-Encrypted: i=2; AJvYcCV3I2RaX1ZncFEy5kt+LPZGNy9nTyZBD7duXFIaKiMDON8RZgtOUdQ4OkBqh4AqmcwwqNMeAuK2FYeYeYmnxFYZ6j5OxG2P6Q==
X-Gm-Message-State: AOJu0Yy+qxKpx4MRc9XLt4t/dFDaqkY/wCgIkbUtUrxr1so/+ZSaiECo
	TzfKelHXxcP/yLZIQMxioXRQpnAXcbHuRrB0ueoHtfMTW1doStzC
X-Google-Smtp-Source: AGHT+IHfZYodab+jtRB6s9J3MpL6e98A+YbDekucB4/OTC2QQ6dvLlXpqaSYNkQbNF8jtXR63iWpsA==
X-Received: by 2002:a0c:f506:0:b0:68f:39bf:35ff with SMTP id j6-20020a0cf506000000b0068f39bf35ffmr12220118qvm.58.1708544537974;
        Wed, 21 Feb 2024 11:42:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3015:b0:68c:d864:e37c with SMTP id
 ke21-20020a056214301500b0068cd864e37cls832976qvb.0.-pod-prod-02-us; Wed, 21
 Feb 2024 11:42:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVs4vSVmHxQUvtDegY+5kbo5kLLVoB0nEFPjEeJc0oytUODYkMlZO7HjXuJf+rHs3xhxGe2GHPsZJVOXSXQIlhXcmZajW5IYxuZ1A==
X-Received: by 2002:a1f:6d04:0:b0:4cb:2662:3651 with SMTP id i4-20020a1f6d04000000b004cb26623651mr9708542vkc.6.1708544537167;
        Wed, 21 Feb 2024 11:42:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544537; cv=none;
        d=google.com; s=arc-20160816;
        b=yWUvzHOaQmzK/4OhaBbYcICkVePEQ7PPVIaJIb+KWkizuXNBlqiD0VqsjHhNKFcDA8
         NQSmet7IDOIQ4JcU9CWFmtprjKRE2u0c+QSUD8MtB0z7rwgK9mlrcfwcp6mS4PjS9IBJ
         X5CHEngs11i/ldAukMZYlciYRp0tX4GcjkXlFrXEvjqWQldKmshdYRQ01K6Eva+xnCDb
         eN4kuczR03Lx+NHpppX85wIfGJB8L5DyvvHdaoo/5IHQXt3oerL2eybCCVD+ASoWMQgY
         7EsTSi1Eki9GxTiyeJggoOXfQaPxSHdKOCmTe/SJ7EDSod//xDpOISy3cBB0A/nSykT0
         Pi0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=iHJNBSQgY470Nm1vo9kQv1HWTlhW4/9LqFry/+3J5f0=;
        fh=EEp5lWcqe3PG+ukvJjwddVjzYSU/kaQNgKUtUDPwd9E=;
        b=p8k9+R36ZFuj5HA0lOkj+a1r3mM5+dW4ACMkbG9AfSe10d3H8KkPTEJ+IkT2QygESy
         3RFIFKdGubW4QjZI/jneSh1Ps+20m3wbP8rymT6ObenRTxtBzFb1ZdIwzEY/XTqrnoso
         OsBl7xeNEf1YUKJURJ3q/cFgYmNXPG5swcOOevWaqkLyYHIrTCX0CCy8V4YFwWwbkxA3
         7Do3s/yCmDjar0FSnJAn7ByT9cQoczMeuB5RAEVOdLDQAP0XpnChhN1BZAYet4s+esW9
         clSVT3Ic1vn8fekbqo0PGaJNZ2pfVD9d1242JtnA/wejKq29h7OAsmIv3vWkeAkL4LsM
         LXyA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ywXaIkgq;
       spf=pass (google.com: domain of 3gflwzqykcus574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3GFLWZQYKCUs574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id p4-20020a0cfd84000000b0068f38ebf524si962888qvr.1.2024.02.21.11.42.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:42:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gflwzqykcus574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dc6b5d1899eso214545276.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:42:17 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUBqelOoUn/7leZhEqB/tCtcCrTQXJOTfimjUJ2IKlSCwpqglBBLCktvn2Y2QjJSJp3ZPDnJ6KX99q7xC81BLIz46iiIqonJ6zp/Q==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a05:6902:1008:b0:dc6:e884:2342 with SMTP id
 w8-20020a056902100800b00dc6e8842342mr25280ybt.5.1708544536561; Wed, 21 Feb
 2024 11:42:16 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:49 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-37-surenb@google.com>
Subject: [PATCH v4 36/36] memprofiling: Documentation
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
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ywXaIkgq;       spf=pass
 (google.com: domain of 3gflwzqykcus574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3GFLWZQYKCUs574r0ot11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--surenb.bounces.google.com;
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
 Documentation/mm/allocation-profiling.rst | 86 +++++++++++++++++++++++
 1 file changed, 86 insertions(+)
 create mode 100644 Documentation/mm/allocation-profiling.rst

diff --git a/Documentation/mm/allocation-profiling.rst b/Documentation/mm/allocation-profiling.rst
new file mode 100644
index 000000000000..2bcbd9e51fe4
--- /dev/null
+++ b/Documentation/mm/allocation-profiling.rst
@@ -0,0 +1,86 @@
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
+  sysctl.vm.mem_profiling=1
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
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-37-surenb%40google.com.
