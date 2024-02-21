Return-Path: <kasan-dev+bncBC7OD3FKWUERB2FD3GXAMGQELUY7GTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3504185E77D
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 20:41:29 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-42e4030ebbfsf7404761cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 11:41:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708544488; cv=pass;
        d=google.com; s=arc-20160816;
        b=VqmTr8/5Xi9eGplEprdIzNYcexmt8Nbc5ZAq/yAJs601R2pZAKqOjv2164HGCpkOMr
         ATVujjc4SZelaQUlt7sU+tTtyOQ7qKrdrN0Icv3z/XDwG4ZUeUW+H/8eecjgiu11uxYV
         IY8IEWV+ht86uRRRnDDAW4laEEPYxFpfguUp+0IvXktCTlfAsp7Zp/hsTkiUAevxyfGn
         M1F0d+roFwRRkCOneT5GXYzTKYqeTzru+SFe5JOGBH4JMq0iqGA3TTGYG5DEPoyZFgGd
         y5s/5ExAvQbzkGEy4xnVM2p+Yn1yCo4LVYkHb+IlDtnF2W5y1rlO6w+MWYRQcyr03O3L
         cmaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=vnMNyWukjyWTwulUHqN9Wi4Y1vxsH8fae0cTedV8RoM=;
        fh=BmfcGPqMaDoSNr7/vY8x+jjMqXfnhCQPcCEZKrZH15M=;
        b=Pa2CqomewTByCbug23tFcys4aAmQ7py/rZWP+X5oJjgz4YBf3Zh2DOeOMLN5qg9flJ
         ah0ethzBeBVqBNsFSEW5hI8CUkaeXkoA5mSt27MiGTQkqTMs4rdELrrm5DeYqRtUmIxF
         mUDJpc+ARonKY1nCwsREHcsHQudqvEAlajkCp9TTQLm6O3R76cbHqZR8D1FEReGb/ijv
         1oCJa17gS5XEEPxsh4BK4s+K8XIGNEfpwAQ/I/GBo8OYbYNiNfQY62EPCxgIkSGOE4/8
         Wr/LsJTT8tipZIqH/09/iC1byGfT+h+mhG88gFtCBoOsvOwJE0BzyAjX5jrHdbn8dqP/
         SSGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XB+18l+Q;
       spf=pass (google.com: domain of 351hwzqykcroikh4d16ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=351HWZQYKCRoIKH4D16EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708544488; x=1709149288; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=vnMNyWukjyWTwulUHqN9Wi4Y1vxsH8fae0cTedV8RoM=;
        b=pWWhoT1xK542OJrZzxOo0IeAoja7E10pTocjBUwsRCV8kTwcbVAe72JiLXoMuE7N6R
         CVkTmdAqHpxfasmTRM4SYrsCFarPDe5w/J6bdF9cvmhsHdTfcVoeQcqrXn4m3pOFxHnM
         huDoqXyhpzBno3OHOqPv51uHjMedeIh+mBKyFXqbxmOJv+vS70WTU1p4R65b2PH3ovwZ
         52jj0ghkWidHbNX8of3OQVOLa5YSMofM/u34JKYCJ9EOt14fmLuqni8NGB+/RrOLaH2k
         wYlf+3AMnhynAUSU5B8jr2rxV3YTGacvBaLB/wrpttayfZO3BVXN7sTLk2OZobj0ilga
         TzUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708544488; x=1709149288;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vnMNyWukjyWTwulUHqN9Wi4Y1vxsH8fae0cTedV8RoM=;
        b=taRmZtZzfaDWMFSfLE4TvRboFxOsRJ9w0SprUnyctRq5HsGSI09Cupi9Tt4E8JXTP1
         G/dlnEH6ro2KF5mG9NrlvaSLTt3W+4+InP+VLRyE0v20vJZvGxf7teyQT3RYXbWAKq69
         dkZFEt77Q2RsaBM52Z+ihfbz/HvhqJsO5MGA4TTbDSbD4qhZEZFchYRshf57IRmnQfcq
         Rf46dq7klbXdoHCJ0NX0rtsC0n//tvLUTBvcnr+ZIJH0sINjUop7zjG7FqQ0QMTt26XI
         SPMLA5n34twIE2X6Hox1/NHtCLuuYKJlVSfLoVaFqLwkBrNna/JJq72RG4fz9UmnW9nc
         QrrA==
X-Forwarded-Encrypted: i=2; AJvYcCWG75FnhAIwB4KbY2T8Ba7Twq25eIxfP7D0hHL86q8LRi0mgrJ9YrKhoK6vJVgBoF2XxMqET6leVvldiWTOjZpSOSDGDCNEvA==
X-Gm-Message-State: AOJu0Yy1qmBUTI5jjj3JX9bQLoC0uhKxBgf4AnE8GT009Qm805leNOW9
	CtyklS4Zozjw/yELjmKjqg9L09G8lG0FXXRI0l6RBAAKoUVzs44EIKQ=
X-Google-Smtp-Source: AGHT+IFSsGPH3i9FencAiqup7XK2YzKVQinrJbIrOV9ySb2OAZdgrKz4uaesA4ZE4qZ4iiliMXBZIw==
X-Received: by 2002:a05:622a:13d1:b0:42d:e87a:9645 with SMTP id p17-20020a05622a13d100b0042de87a9645mr16502528qtk.47.1708544488172;
        Wed, 21 Feb 2024 11:41:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5b81:0:b0:42e:490d:91e7 with SMTP id a1-20020ac85b81000000b0042e490d91e7ls6476qta.2.-pod-prod-07-us;
 Wed, 21 Feb 2024 11:41:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXyYQkk33/eWC/cFNa7KfMyRN/bJjzQgDC7X8nJ3fy88fhrmbEY1kTTEhCaHDKaj8t8/Gbz17lizBriOOEKlw7taGtYbtTQEogPhA==
X-Received: by 2002:a05:6102:2822:b0:470:5792:9260 with SMTP id ba2-20020a056102282200b0047057929260mr8725515vsb.19.1708544487591;
        Wed, 21 Feb 2024 11:41:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708544487; cv=none;
        d=google.com; s=arc-20160816;
        b=fBqAxlPZvTQQO1smpvyfepxaOg8g+/WjBwnZNhGlPzco5R/cMSPH5e1922AJrMO12L
         tZ6SrkVZo7XBcu9zVD5+5klf3I3pgc7PvGf5K7UKK0nQOgSWNbWwET7qyQ7yGJJ77BPa
         hhCunEmYdIztxLfYHaB6RrbB1Gi7Ou8qI0jFbZ+6oGs2yJSNqnvljm+20EOAzDMadZ66
         038jl4oqHf5ikfe6KiwaPZmSgn9BNYIPTolujhcCpAY4YTeHGwStaeaVa+OTAPFWOcd8
         ZW+OsyrJLT7Lfst1HqNqJLOM6v+5UGsf/nOsyBqeaqEkT3xV49HJ8tdDTMAXg1ae2ugT
         5VTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=JrVRrtoAzVQVUCD8y1+sVdT1Uw826vby3bEDKcnM+kE=;
        fh=EvSzXBeg+ssng9HuRF0y0u/habnC3AkWk0nMUtkfgBs=;
        b=eC/a9Nz4il1FaY+jUwqRJ4s13CnRKO1G8O02BH5yYMgEs1v5UxwbsqPOzMHw1mXerp
         usMi9B4s2EbeFm3K4+jiM1j0EjMpVHy9K1tPKVjZmB5YK1TD1n/oBMy1oVBpVjqaZ9QH
         yrRIiw0+GN7WB2Mhct22JteZbPaid6AcaDTOfg3cvQv/Ccyj4qtyLUeU/FUKj3HRwufh
         YfSGPaqe4w+tkC+DgGXRCnwneddw9kU3O1KS9BoIolxrS3h9eiCYdWWGYHL64VsO7MKP
         KMiROv6osZnZXRyOhkArmJPsqe3nk/i1G8+fxQtuZyBFiH0IpkIDj3l0pbwOVfkkQrKJ
         v1gQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XB+18l+Q;
       spf=pass (google.com: domain of 351hwzqykcroikh4d16ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=351HWZQYKCRoIKH4D16EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id o7-20020a0561023f8700b00471b755bb08si33761vsv.1.2024.02.21.11.41.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 11:41:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 351hwzqykcroikh4d16ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-608084ce3c3so17020927b3.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 11:41:27 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUNj1vPirJ7kMG9nJtlyFfBbS+fMBEV4E7ewFD7/fwJbgXI/VITnrahbLqZ71jMbZ4hldY4xLpPLlSCTIiERMtsx/cDxNHEaFMDDQ==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:953b:9a4e:1e10:3f07])
 (user=surenb job=sendgmr) by 2002:a0d:df4b:0:b0:608:5e12:ba68 with SMTP id
 i72-20020a0ddf4b000000b006085e12ba68mr1532689ywe.4.1708544487045; Wed, 21 Feb
 2024 11:41:27 -0800 (PST)
Date: Wed, 21 Feb 2024 11:40:27 -0800
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Mime-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.rc0.258.g7320e95886-goog
Message-ID: <20240221194052.927623-15-surenb@google.com>
Subject: [PATCH v4 14/36] lib: add allocation tagging support for memory
 allocation profiling
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
 header.i=@google.com header.s=20230601 header.b=XB+18l+Q;       spf=pass
 (google.com: domain of 351hwzqykcroikh4d16ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=351HWZQYKCRoIKH4D16EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--surenb.bounces.google.com;
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

Introduce CONFIG_MEM_ALLOC_PROFILING which provides definitions to easily
instrument memory allocators. It registers an "alloc_tags" codetag type
with /proc/allocinfo interface to output allocation tag information when
the feature is enabled.
CONFIG_MEM_ALLOC_PROFILING_DEBUG is provided for debugging the memory
allocation profiling instrumentation.
Memory allocation profiling can be enabled or disabled at runtime using
/proc/sys/vm/mem_profiling sysctl when CONFIG_MEM_ALLOC_PROFILING_DEBUG=n.
CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT enables memory allocation
profiling by default.

Signed-off-by: Suren Baghdasaryan <surenb@google.com>
Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 Documentation/admin-guide/sysctl/vm.rst |  16 +++
 Documentation/filesystems/proc.rst      |  29 +++++
 include/asm-generic/codetag.lds.h       |  14 +++
 include/asm-generic/vmlinux.lds.h       |   3 +
 include/linux/alloc_tag.h               | 144 +++++++++++++++++++++++
 include/linux/sched.h                   |  24 ++++
 lib/Kconfig.debug                       |  25 ++++
 lib/Makefile                            |   2 +
 lib/alloc_tag.c                         | 149 ++++++++++++++++++++++++
 scripts/module.lds.S                    |   7 ++
 10 files changed, 413 insertions(+)
 create mode 100644 include/asm-generic/codetag.lds.h
 create mode 100644 include/linux/alloc_tag.h
 create mode 100644 lib/alloc_tag.c

diff --git a/Documentation/admin-guide/sysctl/vm.rst b/Documentation/admin-guide/sysctl/vm.rst
index c59889de122b..e86c968a7a0e 100644
--- a/Documentation/admin-guide/sysctl/vm.rst
+++ b/Documentation/admin-guide/sysctl/vm.rst
@@ -43,6 +43,7 @@ Currently, these files are in /proc/sys/vm:
 - legacy_va_layout
 - lowmem_reserve_ratio
 - max_map_count
+- mem_profiling         (only if CONFIG_MEM_ALLOC_PROFILING=y)
 - memory_failure_early_kill
 - memory_failure_recovery
 - min_free_kbytes
@@ -425,6 +426,21 @@ e.g., up to one or two maps per allocation.
 The default value is 65530.
 
 
+mem_profiling
+==============
+
+Enable memory profiling (when CONFIG_MEM_ALLOC_PROFILING=y)
+
+1: Enable memory profiling.
+
+0: Disable memory profiling.
+
+Enabling memory profiling introduces a small performance overhead for all
+memory allocations.
+
+The default value depends on CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT.
+
+
 memory_failure_early_kill:
 ==========================
 
diff --git a/Documentation/filesystems/proc.rst b/Documentation/filesystems/proc.rst
index 104c6d047d9b..8150dc3d689c 100644
--- a/Documentation/filesystems/proc.rst
+++ b/Documentation/filesystems/proc.rst
@@ -688,6 +688,7 @@ files are there, and which are missing.
  ============ ===============================================================
  File         Content
  ============ ===============================================================
+ allocinfo    Memory allocations profiling information
  apm          Advanced power management info
  bootconfig   Kernel command line obtained from boot config,
  	      and, if there were kernel parameters from the
@@ -953,6 +954,34 @@ also be allocatable although a lot of filesystem metadata may have to be
 reclaimed to achieve this.
 
 
+allocinfo
+~~~~~~~
+
+Provides information about memory allocations at all locations in the code
+base. Each allocation in the code is identified by its source file, line
+number, module (if originates from a loadable module) and the function calling
+the allocation. The number of bytes allocated and number of calls at each
+location are reported.
+
+Example output.
+
+::
+
+    > sort -rn /proc/allocinfo
+   127664128    31168 mm/page_ext.c:270 func:alloc_page_ext
+    56373248     4737 mm/slub.c:2259 func:alloc_slab_page
+    14880768     3633 mm/readahead.c:247 func:page_cache_ra_unbounded
+    14417920     3520 mm/mm_init.c:2530 func:alloc_large_system_hash
+    13377536      234 block/blk-mq.c:3421 func:blk_mq_alloc_rqs
+    11718656     2861 mm/filemap.c:1919 func:__filemap_get_folio
+     9192960     2800 kernel/fork.c:307 func:alloc_thread_stack_node
+     4206592        4 net/netfilter/nf_conntrack_core.c:2567 func:nf_ct_alloc_hashtable
+     4136960     1010 drivers/staging/ctagmod/ctagmod.c:20 [ctagmod] func:ctagmod_start
+     3940352      962 mm/memory.c:4214 func:alloc_anon_folio
+     2894464    22613 fs/kernfs/dir.c:615 func:__kernfs_new_node
+     ...
+
+
 meminfo
 ~~~~~~~
 
diff --git a/include/asm-generic/codetag.lds.h b/include/asm-generic/codetag.lds.h
new file mode 100644
index 000000000000..64f536b80380
--- /dev/null
+++ b/include/asm-generic/codetag.lds.h
@@ -0,0 +1,14 @@
+/* SPDX-License-Identifier: GPL-2.0-only */
+#ifndef __ASM_GENERIC_CODETAG_LDS_H
+#define __ASM_GENERIC_CODETAG_LDS_H
+
+#define SECTION_WITH_BOUNDARIES(_name)	\
+	. = ALIGN(8);			\
+	__start_##_name = .;		\
+	KEEP(*(_name))			\
+	__stop_##_name = .;
+
+#define CODETAG_SECTIONS()		\
+	SECTION_WITH_BOUNDARIES(alloc_tags)
+
+#endif /* __ASM_GENERIC_CODETAG_LDS_H */
diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
index 5dd3a61d673d..c9997dc50c50 100644
--- a/include/asm-generic/vmlinux.lds.h
+++ b/include/asm-generic/vmlinux.lds.h
@@ -50,6 +50,8 @@
  *               [__nosave_begin, __nosave_end] for the nosave data
  */
 
+#include <asm-generic/codetag.lds.h>
+
 #ifndef LOAD_OFFSET
 #define LOAD_OFFSET 0
 #endif
@@ -366,6 +368,7 @@
 	. = ALIGN(8);							\
 	BOUNDED_SECTION_BY(__dyndbg_classes, ___dyndbg_classes)		\
 	BOUNDED_SECTION_BY(__dyndbg, ___dyndbg)				\
+	CODETAG_SECTIONS()						\
 	LIKELY_PROFILE()		       				\
 	BRANCH_PROFILE()						\
 	TRACE_PRINTKS()							\
diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
new file mode 100644
index 000000000000..be3ba955846c
--- /dev/null
+++ b/include/linux/alloc_tag.h
@@ -0,0 +1,144 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * allocation tagging
+ */
+#ifndef _LINUX_ALLOC_TAG_H
+#define _LINUX_ALLOC_TAG_H
+
+#include <linux/bug.h>
+#include <linux/codetag.h>
+#include <linux/container_of.h>
+#include <linux/preempt.h>
+#include <asm/percpu.h>
+#include <linux/cpumask.h>
+#include <linux/static_key.h>
+
+struct alloc_tag_counters {
+	u64 bytes;
+	u64 calls;
+};
+
+/*
+ * An instance of this structure is created in a special ELF section at every
+ * allocation callsite. At runtime, the special section is treated as
+ * an array of these. Embedded codetag utilizes codetag framework.
+ */
+struct alloc_tag {
+	struct codetag			ct;
+	struct alloc_tag_counters __percpu	*counters;
+} __aligned(8);
+
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+
+static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
+{
+	return container_of(ct, struct alloc_tag, ct);
+}
+
+#ifdef ARCH_NEEDS_WEAK_PER_CPU
+/*
+ * When percpu variables are required to be defined as weak, static percpu
+ * variables can't be used inside a function (see comments for DECLARE_PER_CPU_SECTION).
+ */
+#error "Memory allocation profiling is incompatible with ARCH_NEEDS_WEAK_PER_CPU"
+#endif
+
+#define DEFINE_ALLOC_TAG(_alloc_tag)						\
+	static DEFINE_PER_CPU(struct alloc_tag_counters, _alloc_tag_cntr);	\
+	static struct alloc_tag _alloc_tag __used __aligned(8)			\
+	__section("alloc_tags") = {						\
+		.ct = CODE_TAG_INIT,						\
+		.counters = &_alloc_tag_cntr };
+
+DECLARE_STATIC_KEY_MAYBE(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT,
+			mem_alloc_profiling_key);
+
+static inline bool mem_alloc_profiling_enabled(void)
+{
+	return static_branch_maybe(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT,
+				   &mem_alloc_profiling_key);
+}
+
+static inline struct alloc_tag_counters alloc_tag_read(struct alloc_tag *tag)
+{
+	struct alloc_tag_counters v = { 0, 0 };
+	struct alloc_tag_counters *counter;
+	int cpu;
+
+	for_each_possible_cpu(cpu) {
+		counter = per_cpu_ptr(tag->counters, cpu);
+		v.bytes += counter->bytes;
+		v.calls += counter->calls;
+	}
+
+	return v;
+}
+
+static inline void __alloc_tag_sub(union codetag_ref *ref, size_t bytes)
+{
+	struct alloc_tag *tag;
+
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+	WARN_ONCE(ref && !ref->ct, "alloc_tag was not set\n");
+#endif
+	if (!ref || !ref->ct)
+		return;
+
+	tag = ct_to_alloc_tag(ref->ct);
+
+	this_cpu_sub(tag->counters->bytes, bytes);
+	this_cpu_dec(tag->counters->calls);
+
+	ref->ct = NULL;
+}
+
+static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)
+{
+	__alloc_tag_sub(ref, bytes);
+}
+
+static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes)
+{
+	__alloc_tag_sub(ref, bytes);
+}
+
+static inline void alloc_tag_ref_set(union codetag_ref *ref, struct alloc_tag *tag)
+{
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+	WARN_ONCE(ref && ref->ct,
+		  "alloc_tag was not cleared (got tag for %s:%u)\n",\
+		  ref->ct->filename, ref->ct->lineno);
+
+	WARN_ONCE(!tag, "current->alloc_tag not set");
+#endif
+	if (!ref || !tag)
+		return;
+
+	ref->ct = &tag->ct;
+	/*
+	 * We need in increment the call counter every time we have a new
+	 * allocation or when we split a large allocation into smaller ones.
+	 * Each new reference for every sub-allocation needs to increment call
+	 * counter because when we free each part the counter will be decremented.
+	 */
+	this_cpu_inc(tag->counters->calls);
+}
+
+static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag, size_t bytes)
+{
+	alloc_tag_ref_set(ref, tag);
+	this_cpu_add(tag->counters->bytes, bytes);
+}
+
+#else /* CONFIG_MEM_ALLOC_PROFILING */
+
+#define DEFINE_ALLOC_TAG(_alloc_tag)
+static inline bool mem_alloc_profiling_enabled(void) { return false; }
+static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes) {}
+static inline void alloc_tag_sub_noalloc(union codetag_ref *ref, size_t bytes) {}
+static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
+				 size_t bytes) {}
+
+#endif /* CONFIG_MEM_ALLOC_PROFILING */
+
+#endif /* _LINUX_ALLOC_TAG_H */
diff --git a/include/linux/sched.h b/include/linux/sched.h
index ffe8f618ab86..eede1f92bcc6 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -770,6 +770,10 @@ struct task_struct {
 	unsigned int			flags;
 	unsigned int			ptrace;
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+	struct alloc_tag		*alloc_tag;
+#endif
+
 #ifdef CONFIG_SMP
 	int				on_cpu;
 	struct __call_single_node	wake_entry;
@@ -810,6 +814,7 @@ struct task_struct {
 	struct task_group		*sched_task_group;
 #endif
 
+
 #ifdef CONFIG_UCLAMP_TASK
 	/*
 	 * Clamp values requested for a scheduling entity.
@@ -2183,4 +2188,23 @@ static inline int sched_core_idle_cpu(int cpu) { return idle_cpu(cpu); }
 
 extern void sched_set_stop_task(int cpu, struct task_struct *stop);
 
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *tag)
+{
+	swap(current->alloc_tag, tag);
+	return tag;
+}
+
+static inline void alloc_tag_restore(struct alloc_tag *tag, struct alloc_tag *old)
+{
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+	WARN(current->alloc_tag != tag, "current->alloc_tag was changed:\n");
+#endif
+	current->alloc_tag = old;
+}
+#else
+#define alloc_tag_save(_tag)			NULL
+#define alloc_tag_restore(_tag, _old)		do {} while (0)
+#endif
+
 #endif
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index 0be2d00c3696..78d258ca508f 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -972,6 +972,31 @@ config CODE_TAGGING
 	bool
 	select KALLSYMS
 
+config MEM_ALLOC_PROFILING
+	bool "Enable memory allocation profiling"
+	default n
+	depends on PROC_FS
+	depends on !DEBUG_FORCE_WEAK_PER_CPU
+	select CODE_TAGGING
+	help
+	  Track allocation source code and record total allocation size
+	  initiated at that code location. The mechanism can be used to track
+	  memory leaks with a low performance and memory impact.
+
+config MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
+	bool "Enable memory allocation profiling by default"
+	default y
+	depends on MEM_ALLOC_PROFILING
+
+config MEM_ALLOC_PROFILING_DEBUG
+	bool "Memory allocation profiler debugging"
+	default n
+	depends on MEM_ALLOC_PROFILING
+	select MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
+	help
+	  Adds warnings with helpful error messages for memory allocation
+	  profiling.
+
 source "lib/Kconfig.kasan"
 source "lib/Kconfig.kfence"
 source "lib/Kconfig.kmsan"
diff --git a/lib/Makefile b/lib/Makefile
index 6b48b22fdfac..859112f09bf5 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -236,6 +236,8 @@ obj-$(CONFIG_OF_RECONFIG_NOTIFIER_ERROR_INJECT) += \
 obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
 
 obj-$(CONFIG_CODE_TAGGING) += codetag.o
+obj-$(CONFIG_MEM_ALLOC_PROFILING) += alloc_tag.o
+
 lib-$(CONFIG_GENERIC_BUG) += bug.o
 
 obj-$(CONFIG_HAVE_ARCH_TRACEHOOK) += syscall.o
diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
new file mode 100644
index 000000000000..f09c8a422bc2
--- /dev/null
+++ b/lib/alloc_tag.c
@@ -0,0 +1,149 @@
+// SPDX-License-Identifier: GPL-2.0-only
+#include <linux/alloc_tag.h>
+#include <linux/fs.h>
+#include <linux/gfp.h>
+#include <linux/module.h>
+#include <linux/proc_fs.h>
+#include <linux/seq_buf.h>
+#include <linux/seq_file.h>
+
+static struct codetag_type *alloc_tag_cttype;
+
+DEFINE_STATIC_KEY_MAYBE(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT,
+			mem_alloc_profiling_key);
+
+static void *allocinfo_start(struct seq_file *m, loff_t *pos)
+{
+	struct codetag_iterator *iter;
+	struct codetag *ct;
+	loff_t node = *pos;
+
+	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
+	m->private = iter;
+	if (!iter)
+		return NULL;
+
+	codetag_lock_module_list(alloc_tag_cttype, true);
+	*iter = codetag_get_ct_iter(alloc_tag_cttype);
+	while ((ct = codetag_next_ct(iter)) != NULL && node)
+		node--;
+
+	return ct ? iter : NULL;
+}
+
+static void *allocinfo_next(struct seq_file *m, void *arg, loff_t *pos)
+{
+	struct codetag_iterator *iter = (struct codetag_iterator *)arg;
+	struct codetag *ct = codetag_next_ct(iter);
+
+	(*pos)++;
+	if (!ct)
+		return NULL;
+
+	return iter;
+}
+
+static void allocinfo_stop(struct seq_file *m, void *arg)
+{
+	struct codetag_iterator *iter = (struct codetag_iterator *)m->private;
+
+	if (iter) {
+		codetag_lock_module_list(alloc_tag_cttype, false);
+		kfree(iter);
+	}
+}
+
+static void alloc_tag_to_text(struct seq_buf *out, struct codetag *ct)
+{
+	struct alloc_tag *tag = ct_to_alloc_tag(ct);
+	struct alloc_tag_counters counter = alloc_tag_read(tag);
+	s64 bytes = counter.bytes;
+
+	seq_buf_printf(out, "%12lli %8llu ", bytes, counter.calls);
+	codetag_to_text(out, ct);
+	seq_buf_putc(out, ' ');
+	seq_buf_putc(out, '\n');
+}
+
+static int allocinfo_show(struct seq_file *m, void *arg)
+{
+	struct codetag_iterator *iter = (struct codetag_iterator *)arg;
+	char *bufp;
+	size_t n = seq_get_buf(m, &bufp);
+	struct seq_buf buf;
+
+	seq_buf_init(&buf, bufp, n);
+	alloc_tag_to_text(&buf, iter->ct);
+	seq_commit(m, seq_buf_used(&buf));
+	return 0;
+}
+
+static const struct seq_operations allocinfo_seq_op = {
+	.start	= allocinfo_start,
+	.next	= allocinfo_next,
+	.stop	= allocinfo_stop,
+	.show	= allocinfo_show,
+};
+
+static void __init procfs_init(void)
+{
+	proc_create_seq("allocinfo", 0444, NULL, &allocinfo_seq_op);
+}
+
+static bool alloc_tag_module_unload(struct codetag_type *cttype,
+				    struct codetag_module *cmod)
+{
+	struct codetag_iterator iter = codetag_get_ct_iter(cttype);
+	struct alloc_tag_counters counter;
+	bool module_unused = true;
+	struct alloc_tag *tag;
+	struct codetag *ct;
+
+	for (ct = codetag_next_ct(&iter); ct; ct = codetag_next_ct(&iter)) {
+		if (iter.cmod != cmod)
+			continue;
+
+		tag = ct_to_alloc_tag(ct);
+		counter = alloc_tag_read(tag);
+
+		if (WARN(counter.bytes,
+			 "%s:%u module %s func:%s has %llu allocated at module unload",
+			 ct->filename, ct->lineno, ct->modname, ct->function, counter.bytes))
+			module_unused = false;
+	}
+
+	return module_unused;
+}
+
+static struct ctl_table memory_allocation_profiling_sysctls[] = {
+	{
+		.procname	= "mem_profiling",
+		.data		= &mem_alloc_profiling_key,
+#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
+		.mode		= 0444,
+#else
+		.mode		= 0644,
+#endif
+		.proc_handler	= proc_do_static_key,
+	},
+	{ }
+};
+
+static int __init alloc_tag_init(void)
+{
+	const struct codetag_type_desc desc = {
+		.section	= "alloc_tags",
+		.tag_size	= sizeof(struct alloc_tag),
+		.module_unload	= alloc_tag_module_unload,
+	};
+
+	alloc_tag_cttype = codetag_register_type(&desc);
+	if (IS_ERR_OR_NULL(alloc_tag_cttype))
+		return PTR_ERR(alloc_tag_cttype);
+
+	register_sysctl_init("vm", memory_allocation_profiling_sysctls);
+	procfs_init();
+
+	return 0;
+}
+module_init(alloc_tag_init);
diff --git a/scripts/module.lds.S b/scripts/module.lds.S
index bf5bcf2836d8..45c67a0994f3 100644
--- a/scripts/module.lds.S
+++ b/scripts/module.lds.S
@@ -9,6 +9,8 @@
 #define DISCARD_EH_FRAME	*(.eh_frame)
 #endif
 
+#include <asm-generic/codetag.lds.h>
+
 SECTIONS {
 	/DISCARD/ : {
 		*(.discard)
@@ -47,12 +49,17 @@ SECTIONS {
 	.data : {
 		*(.data .data.[0-9a-zA-Z_]*)
 		*(.data..L*)
+		CODETAG_SECTIONS()
 	}
 
 	.rodata : {
 		*(.rodata .rodata.[0-9a-zA-Z_]*)
 		*(.rodata..L*)
 	}
+#else
+	.data : {
+		CODETAG_SECTIONS()
+	}
 #endif
 }
 
-- 
2.44.0.rc0.258.g7320e95886-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221194052.927623-15-surenb%40google.com.
