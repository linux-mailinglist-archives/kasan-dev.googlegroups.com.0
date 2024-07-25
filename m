Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB6W7RG2QMGQE47ZRVKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C4A793C66D
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 17:32:11 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-42796b1a892sf746335e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 08:32:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721921531; cv=pass;
        d=google.com; s=arc-20160816;
        b=ofBtl9jFDcSaAJJfKiluHAwUs4jTkA/D2hGvhWXNZwO0kRXGqape6D/BpgFxaw7EaI
         XMW1uQvMYjtVhp9Cwkp15aGSFzb6A52bkDKTQi28ZDAycwmqfJURHjjzL5YvF28tbYu2
         ePvi+HezMI+iOkafr3/mO6YSbU5FES4qgis5F+6wSK70kIPH5cMjDtmGKOaxBCo+ZuYD
         o5j7CfZRca91l3ReWq8yLeXe6pKbYZn5Jkp7rsQTd/i+TEeyn2A/0swwqxFkuyukk+Tt
         0CnDEnUoe3DAOFg/g9WU/OPlsVez4WdQ0E8NCdlQ3J1zECqEmFygSI9pxUu/hmn7+e21
         +cEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:mime-version
         :message-id:date:subject:from:dkim-signature;
        bh=c0B2QmwnBO7vYnDz3WUCl45XVYYl8R8nfqYwXDNUtTg=;
        fh=eVGkRkCP7a2KHgVuCKXtRF1OS4JFqMyHQTFpdqQQt1s=;
        b=sohHdTrHsVydO//yTmw7uskGMjeQlhozUUR0U7/2b0rKi2lWtfRR3fmzcReQXa0AD2
         hlHM9xhx1i+ToIQOiYbpipcvD9MOb8gobS5fMwr6iCKrQ6vDAxX5KTiFxVzEaPi+KuXZ
         fc3Kxb1IrOB82Q7OFaVT8546xcs3c6+Va1xdEDaq2JWjzn/zn4JE6pTrhI0UOxv5vyn/
         bNVmAe8SNPov/etOCvIu/ckaBOzneM+ixJ9dK8YyWZ/4A0IE4e4QCHa5Grkcpa+ZEmn1
         TKs2zPfLBNT9rc7xvTAuYec6lupREHhZ7yyiEtTgacksFYwQKwbmQtabRET+8tUCEgtX
         uLKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yhn51kZJ;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721921531; x=1722526331; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=c0B2QmwnBO7vYnDz3WUCl45XVYYl8R8nfqYwXDNUtTg=;
        b=oyHH3BOP8rYo4afEn6v82HvREbFtES//XN+6pImpBsvkYsUeVNM/1k6s8SjiBoAVHk
         C34VW7JrVCAzX9o4GKJqDvEZYLuwohC+6j4x9QPeploTTRX3tcE1d7XBMSqCLGYFgaHd
         sEQ/lAHEj1Lf8chwY9ZMnyDwGxd5eHD+psXaIGBjMznEtzJFp5HnJxIG/vBXriPirGIh
         EpxTBgwYwFEQbVW3LLh7b1UC38/d1uSfxvuevJoyoP1O79OOp2hWK3bERas0Z7/wzhCS
         A+u1FdAiPprpnrVB3PrYgHjCGCUXT55DS0ju9ZtmJ7pCfzQO31KO32igTzatsBZisxsK
         xdkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721921531; x=1722526331;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=c0B2QmwnBO7vYnDz3WUCl45XVYYl8R8nfqYwXDNUtTg=;
        b=xMgxClL38E8N+Bbln5//J3v3L8IhVOf2b9urj9oiqBYCcoINDrRz9QnBE5y0LvvTJH
         M159TfzQgLaiZNN4mEFqclq5Axhn4np3Qgn7tIJ5mzNYsAD/L1MvvxfNbyQewh2Qe5tR
         UtfP+1WSn/Tnv67BaqqJIBZUH2HyGTqhbQyvx7onUo/5sDDp4SzF7R2pH7khs7TIw6f7
         ESVo6HrOlZteIZkhEoz3Wh2E9qhO2sUISxTHUgZAYP5aFzde+OfnCN8tU2To+7kuxjB9
         DoMhvCx7wa+A3OX3ZP3jlh4oYPEh0gUl37q/aLGmNw0i3gFhTROQpXJA0M673giNeL1u
         V1aQ==
X-Forwarded-Encrypted: i=2; AJvYcCUg7XPuKcTzChr07LH1p5s0guNtThH30PQJnEbhlsz1uZIycm9/swioMQwzFbkkrmDv+FT/PEewBm/vbQa0zDP5Jx/tosVcAQ==
X-Gm-Message-State: AOJu0YziPFwCsfDiGaqMpnhtneMptxlTWt+pAhRbHIZp/aNs51gPyc2C
	i+wgzYQVcBhhex2HglhqsV1pp2+RiOte0RT+5e/qE4Od9UFyz/mi
X-Google-Smtp-Source: AGHT+IHVvvhRuK2pxvjhwnMKzjqXL7EOmpypWmZl+mfCHg3tx3iZgc4cTqE4QxCIS7am2IKmuXz0Cg==
X-Received: by 2002:a05:600c:35ca:b0:426:6413:b681 with SMTP id 5b1f17b1804b1-42804cb0823mr1587145e9.6.1721921530762;
        Thu, 25 Jul 2024 08:32:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc10:0:b0:2ef:2eec:5036 with SMTP id 38308e7fff4ca-2f03aa45b44ls4636241fa.1.-pod-prod-09-eu;
 Thu, 25 Jul 2024 08:32:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDv7wBfigfKtZU/AvAEyBLH2HDJMi/QRs8VyI0eTFQKY/sMiafFQ5q7GrXqn74ruAA5wGUYk9RzQC/xUyejN1QOCUVT9FDvCmeKA==
X-Received: by 2002:a2e:a0d5:0:b0:2ef:29b7:18a7 with SMTP id 38308e7fff4ca-2f03dbdfbd9mr16651001fa.37.1721921528627;
        Thu, 25 Jul 2024 08:32:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721921528; cv=none;
        d=google.com; s=arc-20160816;
        b=l3a8jKZsod3ZEZwKfCpFGOnU6Fe9paKfq7dpjxSky43i+4T7/9wEq/cC4BDfgb6qnO
         LVGD0t0/4FFvJcaDu+vQTJPd0Z2ZLnyHkhCcPUskjyvVups6PUHyyYEL/JAo5DLpv6rJ
         ILZqV1koYcqLDVqPuUUoyGlmBaw8idUr3vUy5zfcRpZ2mgCxayDA+Dc9FlL/AkCmMsd5
         ewEolb59bvC3X6u6A8b4j186fxLUHkAZPvgEe33yiecZfQBsPibAqVpStRYaQJR7M6hR
         HuvR4e1JBePBcw0zltQZNZaM1rOF5VT0Du+KzXpq1Hbddo3T5TzUBR+IcOk4ZRSWK/6I
         nelg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature;
        bh=abZrxQokkz2pYLFW8Emrfi2Wptsc7Kc1VGz7XRPEMEU=;
        fh=35xJ1cukgN+/EFUQUnZgiD26SEuuriEGJi/Uhud4WE0=;
        b=SGs1epBtfDOiyvZnmGqwGhcRnOSfyyi0vcqWQdaRYVOb7BIIY/BAKXniaQpfB2jlhh
         8qfJMgwWF/hw7LcDROaFAaC6/ZnqFbGq1gTZH1Hp0D7H9sfKhr47/TjMHZI2IO15lXFY
         XBOXd5QkTv/+hCY9VeG+D77ODDjWX6Cqh4YvozcVYYwPclsEiMdj8GeytS4GsTuUnjOP
         kaxwiIxaxlLOSkonlgO2hN2oFJkx5W3kpA3AzJ8PKDmY6apeRCdHXu6HFmYGuY8owZZt
         7bk9+A1lf33DP+ix5l5BkgYXhjlNfZTKO+X3QN+6li0qIh/J7AL/+X9oZMkzCl/f+zpj
         hy3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yhn51kZJ;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f03cfff36fsi444371fa.3.2024.07.25.08.32.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Jul 2024 08:32:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-428078ebeb9so33875e9.0
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2024 08:32:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUxKkWHei1MXC3Z+W6keNpQdus8jLQHE0eYfQ7PnSyHtCxLa06Cf8Gy/e0zrbhWLZHaef2XzwE0oYuWazOQm87Cj3e/+EK1owOa/Q==
X-Received: by 2002:a05:600c:3b05:b0:426:5ef2:cd97 with SMTP id 5b1f17b1804b1-42803ffa18amr1547735e9.2.1721921526693;
        Thu, 25 Jul 2024 08:32:06 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:8b71:b285:2625:c911])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-428079448d0sm30274615e9.21.2024.07.25.08.32.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Jul 2024 08:32:06 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: [PATCH v3 0/2] allow KASAN to detect UAF in SLAB_TYPESAFE_BY_RCU
 slabs
Date: Thu, 25 Jul 2024 17:31:33 +0200
Message-Id: <20240725-kasan-tsbrcu-v3-0-51c92f8f1101@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIANVvomYC/1XMQQ7CIBRF0a00fyyGUgq0I/dhOqAIlKhgoBJNw
 97FJg4c3pe8s0HS0ekEY7NB1NklF3yN7tCAWqS3GrlLbSCYUMxJh64ySY/WNEf1RDNvezng1nD
 OoF4eURv32rnzVHtxaQ3xveuZfNcfRP+hTBBGtDdiEJhRysTJhmBv+qjCHaZSyge6iIx9qQAAA
 A==
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
 header.i=@google.com header.s=20230601 header.b=yhn51kZJ;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::329 as
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
Changes in v2:
Patch 1/2 is new; it's some necessary prep work for the main patch to
work, though the KASAN integration maybe is a bit ugly.
Patch 2/2 is a rebased version of the old patch, with some changes to
how the config is wired up, with poison/unpoison logic added as
suggested by dvyukov@ back then, with cache destruction fixed using
rcu_barrier() as pointed out by dvyukov@ and the test robot, and a test
added as suggested by elver@.

Changes in v3:
- in patch 1/2, integrate akpm's fix for !CONFIG_KASAN build failure
- in patch 2/2, as suggested by vbabka, use dynamically allocated
  rcu_head to avoid having to add slab metadata
- in patch 2/2, add a warning in the kconfig help text that objects can
  be recycled immediately under memory pressure
- Link to v2: https://lore.kernel.org/r/20240724-kasan-tsbrcu-v2-0-45f898064468@google.com

---
Jann Horn (2):
      kasan: catch invalid free before SLUB reinitializes the object
      slub: Introduce CONFIG_SLUB_RCU_DEBUG

 include/linux/kasan.h | 30 +++++++++++++++----
 mm/Kconfig.debug      | 29 ++++++++++++++++++
 mm/kasan/common.c     | 60 +++++++++++++++++++++++++++----------
 mm/kasan/kasan_test.c | 44 +++++++++++++++++++++++++++
 mm/slab_common.c      | 12 ++++++++
 mm/slub.c             | 83 ++++++++++++++++++++++++++++++++++++++++++++++-----
 6 files changed, 230 insertions(+), 28 deletions(-)
---
base-commit: 0c3836482481200ead7b416ca80c68a29cfdaabd
change-id: 20240723-kasan-tsbrcu-b715a901f776
-- 
Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240725-kasan-tsbrcu-v3-0-51c92f8f1101%40google.com.
