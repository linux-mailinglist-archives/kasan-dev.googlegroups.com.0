Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBOUSUO2QMGQE5B44ITI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 94E14941033
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 13:06:36 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2ef23b417bcsf42787541fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 04:06:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722337596; cv=pass;
        d=google.com; s=arc-20160816;
        b=BsXTOd5+ZUfT7cdHh1Fc1l7AG849ZT6FnBAyLew8rGAKh7aQ6ctN8NgGySfv4VSMxo
         LOImhupwBKq62Zm+CH214sWGq8NcJfbaSJpAXe2fP9yxbz8rL+dgD0+GhO6Qp5AYDbbc
         hDZdz/y9kXs1wkHQCx5+C5acFp97PE+C/79XDT7xnE+Z56YUzSH6HU9zBzzt72JHRqP2
         meRS/wV0+0W2VfF9a/xsSh9fdmwsgfTHyIZIByIR9+7q1C2HU86QkyThBeisGXKhGbIn
         ua69SE+6rJWHKQH0CrrNal5IQEkZBVa/tbxfILC5E3OBwZPAA/RAsETGk9goUk4bCmbY
         UZLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:mime-version
         :message-id:date:subject:from:dkim-signature;
        bh=euKlAdi9NovVAuXS1vz+SRpGixCPSViISLtZansAPGE=;
        fh=cHnQ0bV1JSS2/DpL3Qxq0Bjakhr7iPP6NZjEu2mHM+o=;
        b=LtzmSeFrjPApLAWYMwew6VHi2Pjxyc5iAlKwvZYiQVfrMgWHIuZ9LSBmWQuzyP2PgT
         Ph5AfusuXLeR5plmhTzg4ztTcJT8itbvKR9pVRTrTuKu/rgc/IljSUDb/L3AzcPuLSP1
         5UFLwaJ2UPLaGxqTxRwXOFBGAgItwwU53IH982ovdAuMyu9oQYh+U7eGjDJk7Z9Cipt4
         tJDkvBnEmfj2W7/aEV9x/OW3Rr9lrlKackgEr0cNl9wB3LpC30CLxh6C6LB9lRF6tTqQ
         v2r2TBNKcc+I+lv36msH8+Y3YlJI0RuqUhCrirCgkTzDPVCFdF1ri/fNaklLqPWzHTk+
         EugQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=avT0YYTb;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722337596; x=1722942396; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=euKlAdi9NovVAuXS1vz+SRpGixCPSViISLtZansAPGE=;
        b=Tv4x0EVzWUNs2JaW7e3vajKWwDw+Qvm7S4XjC8ZzPITuZfB6FvWh1qRbB7GJqKjf3j
         2pHJ7k/kPVf3U/FuRxrXo9D4/VVQ37Od6BIMmWzHCkgwEWrvBBR87Tr9cAF39LeN6hfu
         l3ryz84qvD/5V/KNe+lkFAMPVoqDqpKfqn1KSlT8JqUjs6P5aSHGdkNQPbUvt9YVwMwB
         1SUbS8vR0m0UftYT6iEzBq5YzYNhcAthMfln42c+aq5/dfjbVOAoaiFtN1P4zRsnmtD4
         MnnCaT7tKSL2XSK1G/lU88UhqahNnbEhMXJfM2X3iGsquzowbXs2YQaTd0aYrWBaU15k
         2vNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722337596; x=1722942396;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=euKlAdi9NovVAuXS1vz+SRpGixCPSViISLtZansAPGE=;
        b=xFwFQ42F5QN2wQvDFNUcQDh7/+PYTk3tEKR1SLy+cUNUJd4/u0vGL/ZuF3YbRLBU/9
         jWrxgxn9WbWAJ1wB+iKDBkca4+sysGyPaQDRYlDiRr9m7Bv7b6pP8KByWFdLDRm85TXg
         YwrMj/jEytzM5bUE6+BjgChiSufWOMbqZxHWgm90t3oCwQHTng9WHvbhRmT9PQuBopph
         C7ybQc3oOW3T61qHcJ3qHST9i20goa/Eymj4mBTcf59kVw5SIG/bIgUxD5GBR4Rc+9fF
         gtvQc1mcpinbAF3uXp18va7mbd46+NI5k71aIxKMI1APFJBIJn3ZkN8dgmSHt/lnOgJC
         LfWQ==
X-Forwarded-Encrypted: i=2; AJvYcCU0a5heokrNB6pmIgdIH0W1hsBr6DU35WRPh60KE2F0Ht1hD0mUQMxSMbORnhAkZH+4Rwoztlf83CeYpMpS2mfhCa+a+Ib15Q==
X-Gm-Message-State: AOJu0Yw9dZlvECq42M+6yV/6bHs//NGdm+W/OrK+EFreR8i4F58u0U/y
	7dDoVIJXJp1YWht1O0+6TdUP3Uou4s7ByzlUj+P9cmqoriOdqFjV
X-Google-Smtp-Source: AGHT+IGm3t0tX+LiQCXmo1vXZ2wZ0dAfcMdIPnNF20zU0p3BCU2mIIfQkaV80AvH25g/wIK/1dVtVA==
X-Received: by 2002:a2e:9448:0:b0:2ef:2061:8bf9 with SMTP id 38308e7fff4ca-2f12edf79cbmr69288761fa.1.1722337595173;
        Tue, 30 Jul 2024 04:06:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5114:b0:426:6c3e:18f9 with SMTP id
 5b1f17b1804b1-42803b7a70als921075e9.2.-pod-prod-01-eu; Tue, 30 Jul 2024
 04:06:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX7z4syVuuYX6TGJW8yd6+SicC/2+Bptjh3BJdqruXhiGzqEhCnz3T62lu+qlwccgpu5hAWtLgH3bXc4SiJ6TDjYdT1+Lszag125g==
X-Received: by 2002:a05:600c:19d3:b0:426:5ee3:728b with SMTP id 5b1f17b1804b1-42811d8a829mr70717335e9.13.1722337593355;
        Tue, 30 Jul 2024 04:06:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722337593; cv=none;
        d=google.com; s=arc-20160816;
        b=eaMd+/yQo5VWIILoWE1PJDrebuBdNAfnZNZyvr9Bs1hS/6rQkcE+PO5tXQlpDSi+iC
         dugc7OtspJ39C9SJLo5yEdCxbDZSNoso+qYj+NcqvrX6spkPX5cNwpu5zl4wfjjjHL2p
         b/PH4lssl6WV/w+Auc32sMQpJwmyOUSVwMRldzPPmXqtow4s4+2IJBmNfipQ5f1EEJWS
         qfOwwviZfMTe4fCLrBkiBQSX/8GTn55zpKPRDv4cIxWpY4MwULcX5dMtK+Bg3F3mK8dI
         X4Te4Bsm2hxBnrXFOPE+cifevpGg6QFHGsUxuxK3rUDz26jbRkRRWZNR1whuywGhb+70
         IXlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature;
        bh=lOneSascSLbcuGu52c+hQB2xrAbcWZqG1U/DIZcnB4s=;
        fh=OzlgR2VRDazEpLKjX8ZzSd0hGUiiOQreuEGs4sIIft0=;
        b=v2V2EDYiuYszGsCycmitlupRQSEeFTtyZdvthE0T6Kdn2QYVkhfr/z7i4sXzsHhV8A
         XW32R3S/JPD9XG0fWbOQ4Zjz54GsLnvsLV1tUvZ5zWc+ysUYjYuqVr928fUGFZBZQrZz
         z7Ww/7gzvFmCViIWVVhuJc6nZRpiIW1IxcE380bU2Ri97fTrtjHIoGa8LyO5hc0faj8f
         AFEWn0YK4ZSiT/97mU9ooTgWDOGwMAWtBcCowZ5Dp1aeIOFgEgn5pHLizeAyEsiOK0TV
         55rjWrkiWZNS0tAbv0jY9zwcdyd3FpEA/oWue1Gj0SL7W+lt6UZcth5xBNs+2MNgmbjG
         6JKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=avT0YYTb;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42824af684dsi839175e9.1.2024.07.30.04.06.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jul 2024 04:06:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-428078ebeb9so52545e9.0
        for <kasan-dev@googlegroups.com>; Tue, 30 Jul 2024 04:06:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVw0zgwrgDe3PE9So/wXa00ZWlOJzIt5GQZenGWoorSPp8/3/oDtfWVL0f92JH3HClSiqxO1pZ73SXonVTTD+9sMDQ3e68jovzvrQ==
X-Received: by 2002:a05:600c:3109:b0:426:6edd:61a7 with SMTP id 5b1f17b1804b1-42824a5715cmr857625e9.7.1722337592271;
        Tue, 30 Jul 2024 04:06:32 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:be6a:cd70:bdf:6a62])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-428089c28f0sm195945165e9.28.2024.07.30.04.06.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jul 2024 04:06:30 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: [PATCH v5 0/2] allow KASAN to detect UAF in SLAB_TYPESAFE_BY_RCU
 slabs
Date: Tue, 30 Jul 2024 13:06:02 +0200
Message-Id: <20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIABrJqGYC/2XM3QrCIACG4VsJjzPU+dtR9xEdONNNqhm6pBi79
 9wg2Nbh98HzDiDZ6G0Cx90Aos0++dCVwfY7YFrdNRb6a9mAIEKRIBW86aQ72Kc6mhesBWZaIey
 E4KCQZ7TOv+fc+VJ261Mf4meuZzK9vxBdhzKBCFLmpJKIU8rlqQmhuduDCQ8wlXK11Gyjq6IZN
 oo46TBG+E/TpVYbTSctrJHMOokMX+lxHL9Id5NxJQEAAA==
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
 Jann Horn <jannh@google.com>
X-Mailer: b4 0.15-dev
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=avT0YYTb;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::333 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

Hi!

The purpose of the series is to allow KASAN to detect use-after-free
access in SLAB_TYPESAFE_BY_RCU slab caches, by essentially making them
behave as if the cache was not SLAB_TYPESAFE_BY_RCU but instead every
kfree() in the cache was a kfree_rcu().
This is gated behind a config flag that is supposed to only be enabled
in fuzzing/testing builds where the performance impact doesn't matter.

Output of the new kunit testcase I added to the KASAN test suite:
==================================================================
BUG: KASAN: slab-use-after-free in kmem_cache_rcu_uaf+0x3ae/0x4d0
Read of size 1 at addr ffff888106224000 by task kunit_try_catch/224

CPU: 7 PID: 224 Comm: kunit_try_catch Tainted: G    B            N 6.10.0-00003-g065427d4b87f #430
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-debian-1.16.3-2 04/01/2014
Call Trace:
 <TASK>
 dump_stack_lvl+0x53/0x70
 print_report+0xce/0x670
[...]
 kasan_report+0xa5/0xe0
[...]
 kmem_cache_rcu_uaf+0x3ae/0x4d0
[...]
 kunit_try_run_case+0x1b3/0x490
[...]
 kunit_generic_run_threadfn_adapter+0x80/0xe0
 kthread+0x2a5/0x370
[...]
 ret_from_fork+0x34/0x70
[...]
 ret_from_fork_asm+0x1a/0x30
 </TASK>

Allocated by task 224:
 kasan_save_stack+0x33/0x60
 kasan_save_track+0x14/0x30
 __kasan_slab_alloc+0x6e/0x70
 kmem_cache_alloc_noprof+0xef/0x2b0
 kmem_cache_rcu_uaf+0x10d/0x4d0
 kunit_try_run_case+0x1b3/0x490
 kunit_generic_run_threadfn_adapter+0x80/0xe0
 kthread+0x2a5/0x370
 ret_from_fork+0x34/0x70
 ret_from_fork_asm+0x1a/0x30

Freed by task 0:
 kasan_save_stack+0x33/0x60
 kasan_save_track+0x14/0x30
 kasan_save_free_info+0x3b/0x60
 __kasan_slab_free+0x57/0x80
 slab_free_after_rcu_debug+0xe3/0x220
 rcu_core+0x676/0x15b0
 handle_softirqs+0x22f/0x690
 irq_exit_rcu+0x84/0xb0
 sysvec_apic_timer_interrupt+0x6a/0x80
 asm_sysvec_apic_timer_interrupt+0x1a/0x20

Last potentially related work creation:
 kasan_save_stack+0x33/0x60
 __kasan_record_aux_stack+0x8e/0xa0
 kmem_cache_free+0x10c/0x420
 kmem_cache_rcu_uaf+0x16e/0x4d0
 kunit_try_run_case+0x1b3/0x490
 kunit_generic_run_threadfn_adapter+0x80/0xe0
 kthread+0x2a5/0x370
 ret_from_fork+0x34/0x70
 ret_from_fork_asm+0x1a/0x30

The buggy address belongs to the object at ffff888106224000
 which belongs to the cache test_cache of size 200
The buggy address is located 0 bytes inside of
 freed 200-byte region [ffff888106224000, ffff8881062240c8)

The buggy address belongs to the physical page:
page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x106224
head: order:1 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:0
flags: 0x200000000000040(head|node=0|zone=2)
page_type: 0xffffefff(slab)
raw: 0200000000000040 ffff88810621c140 dead000000000122 0000000000000000
raw: 0000000000000000 00000000801f001f 00000001ffffefff 0000000000000000
head: 0200000000000040 ffff88810621c140 dead000000000122 0000000000000000
head: 0000000000000000 00000000801f001f 00000001ffffefff 0000000000000000
head: 0200000000000001 ffffea0004188901 ffffffffffffffff 0000000000000000
head: 0000000000000002 0000000000000000 00000000ffffffff 0000000000000000
page dumped because: kasan: bad access detected

Memory state around the buggy address:
 ffff888106223f00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
 ffff888106223f80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
>ffff888106224000: fa fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
                   ^
 ffff888106224080: fb fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc
 ffff888106224100: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
==================================================================
    ok 38 kmem_cache_rcu_uaf

Signed-off-by: Jann Horn <jannh@google.com>
---
Changes in v5:
- rebase to latest origin/master (akpm), no other changes from v4
- Link to v4: https://lore.kernel.org/r/20240729-kasan-tsbrcu-v4-0-57ec85ef80c6@google.com

Changes in v4:
- note I kept vbabka's ack for the SLUB changes in patch 1/2 since the
  SLUB part didn't change, even though I refactored a bunch of the
  KASAN parts
- in patch 1/2 (major rework):
  - fix commit message (Andrey)
  - add doc comments in header (Andrey)
  - remove "ip" argument from __kasan_slab_free()
  - rework the whole check_slab_free() thing and move code around (Andrey)
- in patch 2/2:
  - kconfig description and dependency changes (Andrey)
  - remove useless linebreak (Andrey)
  - fix comment style (Andrey)
  - fix do_slab_free() invocation (kernel test robot)
- Link to v3: https://lore.kernel.org/r/20240725-kasan-tsbrcu-v3-0-51c92f8f1101@google.com

Changes in v3:
- in patch 1/2, integrate akpm's fix for !CONFIG_KASAN build failure
- in patch 2/2, as suggested by vbabka, use dynamically allocated
  rcu_head to avoid having to add slab metadata
- in patch 2/2, add a warning in the kconfig help text that objects can
  be recycled immediately under memory pressure
- Link to v2: https://lore.kernel.org/r/20240724-kasan-tsbrcu-v2-0-45f898064468@google.com

Changes in v2:
Patch 1/2 is new; it's some necessary prep work for the main patch to
work, though the KASAN integration maybe is a bit ugly.
Patch 2/2 is a rebased version of the old patch, with some changes to
how the config is wired up, with poison/unpoison logic added as
suggested by dvyukov@ back then, with cache destruction fixed using
rcu_barrier() as pointed out by dvyukov@ and the test robot, and a test
added as suggested by elver@.

---
Jann Horn (2):
      kasan: catch invalid free before SLUB reinitializes the object
      slub: Introduce CONFIG_SLUB_RCU_DEBUG

 include/linux/kasan.h | 50 +++++++++++++++++++++++++++----
 mm/Kconfig.debug      | 30 +++++++++++++++++++
 mm/kasan/common.c     | 60 +++++++++++++++++++++++--------------
 mm/kasan/kasan_test.c | 46 ++++++++++++++++++++++++++++
 mm/slab_common.c      | 12 ++++++++
 mm/slub.c             | 83 ++++++++++++++++++++++++++++++++++++++++++++++-----
 6 files changed, 245 insertions(+), 36 deletions(-)
---
base-commit: 94ede2a3e9135764736221c080ac7c0ad993dc2d
change-id: 20240723-kasan-tsbrcu-b715a901f776
-- 
Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5%40google.com.
