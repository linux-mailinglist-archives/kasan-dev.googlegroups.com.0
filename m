Return-Path: <kasan-dev+bncBC7OD3FKWUERB3XJUKXQMGQEGTXRPSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D89D873E6C
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 19:24:48 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-42ef611a12asf18491cf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Mar 2024 10:24:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709749487; cv=pass;
        d=google.com; s=arc-20160816;
        b=qmHL8gLHr8hg6kB/E66MOSQZNloK0JHbMrzf8hMOdGuwHjqFiLLa5ToO9nYGceY/kl
         ky+aQA/UpmJz0yHdhB01+tDzY0iDI+mQ4QNrc7hUioR+rPq2fgJEMCWH+rWsYqVqxenN
         +US3x7Yaus3uuzA9oKI6QBs5DIhBZ2w6GSIWAhgcT3gq9j8JC/B0K/COFzEYVHKABHUs
         hIJsVyNGSiLKRVZKVZn5duj+HTPB3CC2nvXiLaehG1g67Q3ORYe6Tu3x/JkrqPZm+5bk
         pIlCHcmHseMZTMUQ7kKYwSIBvl3WW//gXHpTSpYhKGjAP/1pgNsE7QYUIjkxxmNXOKT8
         TaTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=xvjE41p9FNSM58PI/DF83aZMrqhPIZxmg4tv0oQ0z58=;
        fh=+IcSrFpj5s0PiE6UOOxl135d0YeNsK1GRhZN1ToVozM=;
        b=isRQqz8Ocb3N7cTfdx8EnS0NfG/8BKLvbZMInE0xdPjcN9UbChC1bj3cUcYrQmfnSl
         3m9KlowW21bjbAhu2l6tYQ8QYtaUGczkRFgzW2bBPxVZs/w29PyQPMU1XCmPDAYKH76r
         gyV2NSUe3PnZHqBxJofT79P5geP6m/kjtOZg3h72a9Cwe00pCUqWEcGO8odkim2G3XUh
         P9SKWYo1aZvTOMVjSpMwAPB4BELD7e1kp2NxF56hbaVX4m9G8TjmajZ+qQClHjimnUkD
         QgQpC+kekg0DBiPmpD5cbOlfISEE8BrDX4Vpdzm8SEzTTx3aVZkC06lsogHV0H7yz5sX
         eKvg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=C4fo74Vz;
       spf=pass (google.com: domain of 37ltozqykcs8dfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=37LToZQYKCS8dfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709749487; x=1710354287; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xvjE41p9FNSM58PI/DF83aZMrqhPIZxmg4tv0oQ0z58=;
        b=hvp2nwGxJUoNqP4lAUknY+eHsvA+lM1HAKRCxV0duOXCwzUR+OsyELBzWUHwli9tIs
         j+0ypBQnW7Vbt9dZD3TnMmftEOaRb8B8mx0Gkug2HtCG5O49RJ6unjo03kLIySYjQL1D
         f53RTirbOPn+DEt6J2Q6lCsRW1ldb+/Kvlx8tizuFkkpr3saDsgjef0zsllhOLjYu56V
         xHKUtpQNpEZxOHCVbAsKBGEMH2jxoxuKGzPEQtCOI8F8ZwQCTe93m4YFquh4QztCOKZZ
         /wr8tBhSK8YsU6KOQE0GL2S78rGS0XHHQgWZHN0qNsyYRn38yHyN5sKkjFZRrOtjBFTs
         jbGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709749487; x=1710354287;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xvjE41p9FNSM58PI/DF83aZMrqhPIZxmg4tv0oQ0z58=;
        b=RSRHfnz8hcWradHZ0FrHer7DO7KNF8rz5FOb7pP8h+6OLHgauwQNtf3B6PGSVUO2O0
         BDuMRx/sLa+nBJVmEr2M6NJ7WWooinsZKYmxwgK14GBntOKeZJ8uk3yqgkW/Zlh7HzZn
         G0PPImR0NVajjC/TMFK00YNOZnNCCncH8/dhxbD6/X9fhp9XlFSs4Ej4BjislXB/6/05
         h9qXNyQ9Z5XaPJS+Wv2Z/PsdBAPbXOHlXkPtB8tg2srkecdXsSUYGmiIZXyILW0fxvNn
         9H07Sjn20ARrCiWwxSfRx3ZfDFQlveMnRizzNLPIeMefLnV0JIKp8eb5U8Vjy2D3ksFX
         YQSg==
X-Forwarded-Encrypted: i=2; AJvYcCWk5ZPIktzxPA/Vm01EwSMB4qM/9d+22phlVOODiLLLKgRquYoPhCCGh0yKUDVY/ayTbe0XwUeyi0sxYIx2NPkFDmEZKTGF4Q==
X-Gm-Message-State: AOJu0Yw9RjibfELm3hdYCd7mUAHYbDqfq6XcMWIX0yMTW4mImqx2pUbI
	3lBpJolpjyKub6c3ianbVryHD82C63ibPcw6Fd/Nz2U76OfdeN+8
X-Google-Smtp-Source: AGHT+IHLf9aJ+piVsRhIcV/8EX5MDBgokApDvl1QyShHWncdLX+lWHn7Kc82GZxHj8MWai5nAIXXLw==
X-Received: by 2002:a05:622a:5288:b0:42e:d8fb:8ab5 with SMTP id dr8-20020a05622a528800b0042ed8fb8ab5mr49141qtb.5.1709749487031;
        Wed, 06 Mar 2024 10:24:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:842:0:b0:dcc:f46b:129d with SMTP id 63-20020a250842000000b00dccf46b129dls68455ybi.2.-pod-prod-03-us;
 Wed, 06 Mar 2024 10:24:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXCfXCSHaKqUr0BtKOanzKmUbd1gYvWKxnLnZPCuann4QgR5UF6XZ0pIfzqZj3LrxVqGaD50HFzz9KtOOGVhe2r8Afka4W7s0Rz6A==
X-Received: by 2002:a25:2690:0:b0:dc6:ff12:13d7 with SMTP id m138-20020a252690000000b00dc6ff1213d7mr10339600ybm.60.1709749485267;
        Wed, 06 Mar 2024 10:24:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709749485; cv=none;
        d=google.com; s=arc-20160816;
        b=m5hWZ5I3LMFU/nnv9BSvSYMigqbK+KnBRwbPTwsCv1j+C6oiTUPkFjSMJGvBxKwVza
         996zF+FuUAs6k377mwv78ie0u+5xaHrNdXqFo2IRTFcr9RMKshVqxAsNt8DLZoV8q7a/
         DJXffw32JXw0ikggMeE6h6sES9wr+0NgpuLBzCwYS0a3yqDk1ctz39C+ve2KGKE1b0u0
         0HqdisI9gIx1QIDwc/uZf1hJe7S8ao2Po2x3RmsEJgmv9AFroPHerwYhhAxR5NFPdPAu
         wnPVlvTB8IUFk9DT0Kw+RaodLKYHHAVKQyLcJDR1siXuSkLzs85MEiRZBoYfCJgSVoQt
         UpUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=RyFy+o939hhJJtOBz2smMq9dZDCMxXVMPA36WKy2XKs=;
        fh=WFiJ3cuxzR78R562t/JyrGuCSZMTFML8iC0AkuNfueU=;
        b=GHTQ3C7VFn0CGPrMf87vuLBzUnFFZB4UgPZl43olD/PIfh0g+U2DVNsif3IkJTP5Eb
         vn0gS5mNASMoPWcN3esHABSegc9VmsrzFmJ4lSt1U3h9NhfubLgPr1HfV47IUx239qDq
         jkruraLZG00+NStc6gl4ciwydBVDQPJL/YdwIUvZFYi7kLoUxRFxqXXXre4GzYcWvDRp
         Oev1WH3AEzM982KpQl2kK1HicMd2baC83wO5kLFUEdzvmV2FBMI2tYLIt6xYuyQdFBvJ
         oayzbHNa+sdH+tt0m2RtuPnY87TEjZSoPIOer/FrOZYN5NMZlbozdjIfctODligjTrxO
         ViOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=C4fo74Vz;
       spf=pass (google.com: domain of 37ltozqykcs8dfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=37LToZQYKCS8dfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id v68-20020a252f47000000b00dcc3d9efcb7si1108537ybv.3.2024.03.06.10.24.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Mar 2024 10:24:45 -0800 (PST)
Received-SPF: pass (google.com: domain of 37ltozqykcs8dfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-dce775fa8adso12665443276.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Mar 2024 10:24:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWL7m2HchN5n8DyPjYedkU0eLol0sPSYbjAhapOvYsSWIdQvWjIoSFvxE7QxCNwJBF5BiWNHSppdfFbyFV1s7TUrLg6RptlM2B43A==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:85f0:e3db:db05:85e2])
 (user=surenb job=sendgmr) by 2002:a05:6902:1004:b0:dc2:3441:897f with SMTP id
 w4-20020a056902100400b00dc23441897fmr3842720ybt.6.1709749484713; Wed, 06 Mar
 2024 10:24:44 -0800 (PST)
Date: Wed,  6 Mar 2024 10:23:58 -0800
Mime-Version: 1.0
X-Mailer: git-send-email 2.44.0.278.ge034bb2e1d-goog
Message-ID: <20240306182440.2003814-1-surenb@google.com>
Subject: [PATCH v5 00/37] Memory allocation profiling
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
 header.i=@google.com header.s=20230601 header.b=C4fo74Vz;       spf=pass
 (google.com: domain of 37ltozqykcs8dfcpymrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=37LToZQYKCS8dfcPYMRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--surenb.bounces.google.com;
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

Rebased over mm-unstable.

Overview:
Low overhead [1] per-callsite memory allocation profiling. Not just for
debug kernels, overhead low enough to be deployed in production.

Example output:
  root@moria-kvm:~# sort -rn /proc/allocinfo
   127664128    31168 mm/page_ext.c:270 func:alloc_page_ext
    56373248     4737 mm/slub.c:2259 func:alloc_slab_page
    14880768     3633 mm/readahead.c:247 func:page_cache_ra_unbounded
    14417920     3520 mm/mm_init.c:2530 func:alloc_large_system_hash
    13377536      234 block/blk-mq.c:3421 func:blk_mq_alloc_rqs
    11718656     2861 mm/filemap.c:1919 func:__filemap_get_folio
     9192960     2800 kernel/fork.c:307 func:alloc_thread_stack_node
     4206592        4 net/netfilter/nf_conntrack_core.c:2567 func:nf_ct_alloc_hashtable
     4136960     1010 drivers/staging/ctagmod/ctagmod.c:20 [ctagmod] func:ctagmod_start
     3940352      962 mm/memory.c:4214 func:alloc_anon_folio
     2894464    22613 fs/kernfs/dir.c:615 func:__kernfs_new_node
     ...

Since v4 [2]:
 - Added Reviewed-by, per Pasha Tatashin, Vlastimil Babka, Alice Ryhl
 - Changed slab_free_freelist_hook() to use __fastpath_inline,
   per Pasha Tatashin
 - Removed [3] as it is already Ack'ed and merged into in mm-unstable
 - Moved alloc_slab_obj_exts(), prepare_slab_obj_exts_hook() and
   alloc_tagging_slab_free_hook() into slub.c, per Vlastimil Babka
 - Removed drive-by spacing fixups, per Vlastimil Babka
 - Restored early memcg_kmem_online() check before calling
   free_slab_obj_exts(), per Vlastimil Babka
 - Added pr_warn() when module can't be unloaded, per Vlastimil Babka
 - Dropped __alloc_tag_sub() and alloc_tag_sub_noalloc(),
   per Vlastimil Babka
 - Fixed alloc_tag_add() to check for tag to be valid, per Vlastimil Babka
 - Moved alloc_tag_ref_set() where it's first used
 - Added a patch introducing a tristate early boot parameter,
   per Vlastimil Babka
 - Updated description for page splitting patch, per Vlastimil Babka
 - Added a patch fixing non-compound page accounting in __free_pages(),
   per Vlastimil Babka
 - Added early mem_alloc_profiling_enabled() checks in
   alloc_tagging_slab_free_hook() and prepare_slab_obj_exts_hook(),
   per Vlastimil Babka
 - Moved rust krealloc() helper patch before krealloc() is redefined,
   per Alice Ryhl
 - Replaced printk(KERN_NOTICE...) with pr_notice(), per Vlastimil Babka
 - Fixed codetag_{un}load_module() redefinition for CONFIG_MODULE=n,
   per kernel test robot
 - Updated documentation to describe new early boot parameter
 - Rebased over mm-unstable

Usage:
kconfig options:
 - CONFIG_MEM_ALLOC_PROFILING
 - CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
 - CONFIG_MEM_ALLOC_PROFILING_DEBUG
   adds warnings for allocations that weren't accounted because of a
   missing annotation

sysctl:
  /proc/sys/vm/mem_profiling

Runtime info:
  /proc/allocinfo

Notes:

[1]: Overhead
To measure the overhead we are comparing the following configurations:
(1) Baseline with CONFIG_MEMCG_KMEM=n
(2) Disabled by default (CONFIG_MEM_ALLOC_PROFILING=y &&
    CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=n)
(3) Enabled by default (CONFIG_MEM_ALLOC_PROFILING=y &&
    CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=y)
(4) Enabled at runtime (CONFIG_MEM_ALLOC_PROFILING=y &&
    CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=n && /proc/sys/vm/mem_profiling=1)
(5) Baseline with CONFIG_MEMCG_KMEM=y && allocating with __GFP_ACCOUNT
(6) Disabled by default (CONFIG_MEM_ALLOC_PROFILING=y &&
    CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=n)  && CONFIG_MEMCG_KMEM=y
(7) Enabled by default (CONFIG_MEM_ALLOC_PROFILING=y &&
    CONFIG_MEM_ALLOC_PROFILING_BY_DEFAULT=y) && CONFIG_MEMCG_KMEM=y

Performance overhead:
To evaluate performance we implemented an in-kernel test executing
multiple get_free_page/free_page and kmalloc/kfree calls with allocation
sizes growing from 8 to 240 bytes with CPU frequency set to max and CPU
affinity set to a specific CPU to minimize the noise. Below are results
from running the test on Ubuntu 22.04.2 LTS with 6.8.0-rc1 kernel on
56 core Intel Xeon:

                        kmalloc                 pgalloc
(1 baseline)            6.764s                  16.902s
(2 default disabled)    6.793s  (+0.43%)        17.007s (+0.62%)
(3 default enabled)     7.197s  (+6.40%)        23.666s (+40.02%)
(4 runtime enabled)     7.405s  (+9.48%)        23.901s (+41.41%)
(5 memcg)               13.388s (+97.94%)       48.460s (+186.71%)
(6 def disabled+memcg)  13.332s (+97.10%)       48.105s (+184.61%)
(7 def enabled+memcg)   13.446s (+98.78%)       54.963s (+225.18%)

Memory overhead:
Kernel size:

   text           data        bss         dec         diff
(1) 26515311	      18890222    17018880    62424413
(2) 26524728	      19423818    16740352    62688898    264485
(3) 26524724	      19423818    16740352    62688894    264481
(4) 26524728	      19423818    16740352    62688898    264485
(5) 26541782	      18964374    16957440    62463596    39183

Memory consumption on a 56 core Intel CPU with 125GB of memory:
Code tags:           192 kB
PageExts:         262144 kB (256MB)
SlabExts:           9876 kB (9.6MB)
PcpuExts:            512 kB (0.5MB)

Total overhead is 0.2% of total memory.

Benchmarks:

Hackbench tests run 100 times:
hackbench -s 512 -l 200 -g 15 -f 25 -P
      baseline       disabled profiling           enabled profiling
avg   0.3543         0.3559 (+0.0016)             0.3566 (+0.0023)
stdev 0.0137         0.0188                       0.0077


hackbench -l 10000
      baseline       disabled profiling           enabled profiling
avg   6.4218         6.4306 (+0.0088)             6.5077 (+0.0859)
stdev 0.0933         0.0286                       0.0489

stress-ng tests:
stress-ng --class memory --seq 4 -t 60
stress-ng --class cpu --seq 4 -t 60
Results posted at: https://evilpiepirate.org/~kent/memalloc_prof_v4_stress-ng/

[2] https://lore.kernel.org/all/20240221194052.927623-1-surenb@google.com/
[3] https://lore.kernel.org/all/20240221194052.927623-7-surenb@google.com/

Kent Overstreet (13):
  fix missing vmalloc.h includes
  asm-generic/io.h: Kill vmalloc.h dependency
  mm/slub: Mark slab_free_freelist_hook() __always_inline
  scripts/kallysms: Always include __start and __stop symbols
  fs: Convert alloc_inode_sb() to a macro
  rust: Add a rust helper for krealloc()
  mempool: Hook up to memory allocation profiling
  mm: percpu: Introduce pcpuobj_ext
  mm: percpu: Add codetag reference into pcpuobj_ext
  mm: vmalloc: Enable memory allocation profiling
  rhashtable: Plumb through alloc tag
  MAINTAINERS: Add entries for code tagging and memory allocation
    profiling
  memprofiling: Documentation

Suren Baghdasaryan (24):
  mm: introduce slabobj_ext to support slab object extensions
  mm: introduce __GFP_NO_OBJ_EXT flag to selectively prevent slabobj_ext
    creation
  mm/slab: introduce SLAB_NO_OBJ_EXT to avoid obj_ext creation
  slab: objext: introduce objext_flags as extension to
    page_memcg_data_flags
  lib: code tagging framework
  lib: code tagging module support
  lib: prevent module unloading if memory is not freed
  lib: add allocation tagging support for memory allocation profiling
  lib: introduce support for page allocation tagging
  lib: introduce early boot parameter to avoid page_ext memory overhead
  mm: percpu: increase PERCPU_MODULE_RESERVE to accommodate allocation
    tags
  change alloc_pages name in dma_map_ops to avoid name conflicts
  mm: enable page allocation tagging
  mm: create new codetag references during page splitting
  mm: fix non-compound multi-order memory accounting in __free_pages
  mm/page_ext: enable early_page_ext when
    CONFIG_MEM_ALLOC_PROFILING_DEBUG=y
  lib: add codetag reference into slabobj_ext
  mm/slab: add allocation accounting into slab allocation and free paths
  mm/slab: enable slab allocation tagging for kmalloc and friends
  mm: percpu: enable per-cpu allocation tagging
  lib: add memory allocations report in show_mem()
  codetag: debug: skip objext checking when it's for objext itself
  codetag: debug: mark codetags for reserved pages as empty
  codetag: debug: introduce OBJEXTS_ALLOC_FAIL to mark failed slab_ext
    allocations

 Documentation/admin-guide/sysctl/vm.rst       |  16 +
 Documentation/filesystems/proc.rst            |  29 ++
 Documentation/mm/allocation-profiling.rst     |  91 +++++
 MAINTAINERS                                   |  17 +
 arch/alpha/kernel/pci_iommu.c                 |   2 +-
 arch/alpha/lib/checksum.c                     |   1 +
 arch/alpha/lib/fpreg.c                        |   1 +
 arch/alpha/lib/memcpy.c                       |   1 +
 arch/arm/kernel/irq.c                         |   1 +
 arch/arm/kernel/traps.c                       |   1 +
 arch/arm64/kernel/efi.c                       |   1 +
 arch/loongarch/include/asm/kfence.h           |   1 +
 arch/mips/jazz/jazzdma.c                      |   2 +-
 arch/powerpc/kernel/dma-iommu.c               |   2 +-
 arch/powerpc/kernel/iommu.c                   |   1 +
 arch/powerpc/mm/mem.c                         |   1 +
 arch/powerpc/platforms/ps3/system-bus.c       |   4 +-
 arch/powerpc/platforms/pseries/vio.c          |   2 +-
 arch/riscv/kernel/elf_kexec.c                 |   1 +
 arch/riscv/kernel/probes/kprobes.c            |   1 +
 arch/s390/kernel/cert_store.c                 |   1 +
 arch/s390/kernel/ipl.c                        |   1 +
 arch/x86/include/asm/io.h                     |   1 +
 arch/x86/kernel/amd_gart_64.c                 |   2 +-
 arch/x86/kernel/cpu/sgx/main.c                |   1 +
 arch/x86/kernel/irq_64.c                      |   1 +
 arch/x86/mm/fault.c                           |   1 +
 drivers/accel/ivpu/ivpu_mmu_context.c         |   1 +
 drivers/gpu/drm/gma500/mmu.c                  |   1 +
 drivers/gpu/drm/i915/gem/i915_gem_pages.c     |   1 +
 .../gpu/drm/i915/gem/selftests/mock_dmabuf.c  |   1 +
 drivers/gpu/drm/i915/gt/shmem_utils.c         |   1 +
 drivers/gpu/drm/i915/gvt/firmware.c           |   1 +
 drivers/gpu/drm/i915/gvt/gtt.c                |   1 +
 drivers/gpu/drm/i915/gvt/handlers.c           |   1 +
 drivers/gpu/drm/i915/gvt/mmio.c               |   1 +
 drivers/gpu/drm/i915/gvt/vgpu.c               |   1 +
 drivers/gpu/drm/i915/intel_gvt.c              |   1 +
 drivers/gpu/drm/imagination/pvr_vm_mips.c     |   1 +
 drivers/gpu/drm/mediatek/mtk_drm_gem.c        |   1 +
 drivers/gpu/drm/omapdrm/omap_gem.c            |   1 +
 drivers/gpu/drm/v3d/v3d_bo.c                  |   1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_binding.c       |   1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_cmd.c           |   1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_devcaps.c       |   1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_drv.c           |   1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_execbuf.c       |   1 +
 drivers/gpu/drm/vmwgfx/vmwgfx_ioctl.c         |   1 +
 drivers/gpu/drm/xen/xen_drm_front_gem.c       |   1 +
 drivers/hwtracing/coresight/coresight-trbe.c  |   1 +
 drivers/iommu/dma-iommu.c                     |   2 +-
 .../marvell/octeon_ep/octep_pfvf_mbox.c       |   1 +
 .../net/ethernet/microsoft/mana/hw_channel.c  |   1 +
 drivers/parisc/ccio-dma.c                     |   2 +-
 drivers/parisc/sba_iommu.c                    |   2 +-
 drivers/platform/x86/uv_sysfs.c               |   1 +
 drivers/scsi/mpi3mr/mpi3mr_transport.c        |   2 +
 drivers/staging/media/atomisp/pci/hmm/hmm.c   |   2 +-
 drivers/vfio/pci/pds/dirty.c                  |   1 +
 drivers/virt/acrn/mm.c                        |   1 +
 drivers/virtio/virtio_mem.c                   |   1 +
 drivers/xen/grant-dma-ops.c                   |   2 +-
 drivers/xen/swiotlb-xen.c                     |   2 +-
 include/asm-generic/codetag.lds.h             |  14 +
 include/asm-generic/io.h                      |   1 -
 include/asm-generic/vmlinux.lds.h             |   3 +
 include/linux/alloc_tag.h                     | 205 +++++++++++
 include/linux/codetag.h                       |  81 +++++
 include/linux/dma-map-ops.h                   |   2 +-
 include/linux/fortify-string.h                |   5 +-
 include/linux/fs.h                            |   6 +-
 include/linux/gfp.h                           | 126 ++++---
 include/linux/gfp_types.h                     |  11 +
 include/linux/memcontrol.h                    |  56 ++-
 include/linux/mempool.h                       |  73 ++--
 include/linux/mm.h                            |   9 +
 include/linux/mm_types.h                      |   4 +-
 include/linux/page_ext.h                      |   1 -
 include/linux/pagemap.h                       |   9 +-
 include/linux/pds/pds_common.h                |   2 +
 include/linux/percpu.h                        |  27 +-
 include/linux/pgalloc_tag.h                   | 134 +++++++
 include/linux/rhashtable-types.h              |  11 +-
 include/linux/sched.h                         |  24 ++
 include/linux/slab.h                          | 175 +++++-----
 include/linux/string.h                        |   4 +-
 include/linux/vmalloc.h                       |  60 +++-
 include/rdma/rdmavt_qp.h                      |   1 +
 init/Kconfig                                  |   4 +
 kernel/dma/mapping.c                          |   4 +-
 kernel/kallsyms_selftest.c                    |   2 +-
 kernel/module/main.c                          |  29 +-
 lib/Kconfig.debug                             |  31 ++
 lib/Makefile                                  |   3 +
 lib/alloc_tag.c                               | 243 +++++++++++++
 lib/codetag.c                                 | 283 +++++++++++++++
 lib/rhashtable.c                              |  28 +-
 mm/compaction.c                               |   7 +-
 mm/debug_vm_pgtable.c                         |   1 +
 mm/filemap.c                                  |   6 +-
 mm/huge_memory.c                              |   2 +
 mm/kfence/core.c                              |  14 +-
 mm/kfence/kfence.h                            |   4 +-
 mm/memcontrol.c                               |  56 +--
 mm/mempolicy.c                                |  52 +--
 mm/mempool.c                                  |  36 +-
 mm/mm_init.c                                  |  13 +-
 mm/nommu.c                                    |  64 ++--
 mm/page_alloc.c                               |  77 +++--
 mm/page_ext.c                                 |  13 +
 mm/page_owner.c                               |   2 +-
 mm/percpu-internal.h                          |  26 +-
 mm/percpu.c                                   | 120 +++----
 mm/show_mem.c                                 |  26 ++
 mm/slab.h                                     |  51 ++-
 mm/slab_common.c                              |   6 +-
 mm/slub.c                                     | 327 +++++++++++++++---
 mm/util.c                                     |  44 +--
 mm/vmalloc.c                                  |  88 ++---
 rust/helpers.c                                |   8 +
 scripts/kallsyms.c                            |  13 +
 scripts/module.lds.S                          |   7 +
 sound/pci/hda/cs35l41_hda.c                   |   1 +
 123 files changed, 2305 insertions(+), 657 deletions(-)
 create mode 100644 Documentation/mm/allocation-profiling.rst
 create mode 100644 include/asm-generic/codetag.lds.h
 create mode 100644 include/linux/alloc_tag.h
 create mode 100644 include/linux/codetag.h
 create mode 100644 include/linux/pgalloc_tag.h
 create mode 100644 lib/alloc_tag.c
 create mode 100644 lib/codetag.c


base-commit: b38c34939fe4735b8716511f0a98814be3865a1b
-- 
2.44.0.278.ge034bb2e1d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240306182440.2003814-1-surenb%40google.com.
