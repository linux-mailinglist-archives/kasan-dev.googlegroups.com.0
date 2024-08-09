Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBJHP3C2QMGQEVNKXV4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 50CFE94D3AB
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2024 17:37:09 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-426624f4ce3sf14963705e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2024 08:37:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723217829; cv=pass;
        d=google.com; s=arc-20160816;
        b=1Lprj8N2/r3OqZv/kyy116jtLZBjdrcsr9dZv+KocfVUeGzsNN9JBMGpYChHduvv0F
         VSi+QLUKC3jjN/FUjlwHymQoVcR9G3+bt2ApkpufFeKV2vk8Bes+OQN9GaDKgRpLHXRP
         gew9lex3oT5ouZAgrIkwyzTYSbdw9lIf5uL+lLEMchmaQ/vaF+osD916Fiz8ZwYq7F63
         ZnHVWyeBzixU/PnLqXKuKjJciSm9JOieYy/LEQCBC3YegGRjhfoOkneSjCXrKvJtMQHD
         8o2zcCptJegXmFjfKtZCcGWZ1238aDrvGF5kmk4DHACjR4HpA0vB5Vwhg/KEJ/K8KIiy
         8kkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:mime-version
         :message-id:date:subject:from:dkim-signature;
        bh=DJb92HaihbXB1lBR0u8Wzs1p9HNYFM+SQqP6ZaYzlUg=;
        fh=vtSfk7THedgUgeTbaOexBxdCu5RCrgSkP21yOtkgnWY=;
        b=wLcghPsLwb09OZv+LsgcmaK0AkKoze2waOMmxOo7QnaRWslKxLKY52sgJCYvZMdTea
         h5VK+nVFTkifC8CUxX3rFzJYmoBQKGDB+VlBy9PGhRTK3I+/ilFs8Pn2HiqQ5kVCgPr4
         ldVmIpqeT48fXs+26rhPATXxC0y5QmXsCus7iqUXqTOIxjRis2fB9Joz5vQrMwqMaM4X
         yUbSGZt/Mp40eAPO/KEBECryl63YrlHvMwmG/aWDY4h/TQYq9o3GDQwYL1uOeMoTGkiB
         HDiK7NTAa6ISK/+8Khs1j4dxODwtuXuq0SE30/OTqIH8vH/mw61ou2lDdoc6J4YK8Reu
         K1lw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=E59PRCAU;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723217829; x=1723822629; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DJb92HaihbXB1lBR0u8Wzs1p9HNYFM+SQqP6ZaYzlUg=;
        b=C/6oKWjhIGxuhzz7NtZVK69RKe6ZPSujS7Ku8vvxsQHJiX5B4Xwsi8W2KD0Ks34d5V
         Y2MlUMT0k1FMZKB10e9d1IgEkTPnCywIoC9rsymnZ3Fk2V2syZxLhCayklvjMwto3epI
         U6ZIdir1V+jFWTrFlVe7jhs73j7ucxmygt20Gz/9Gd0T9Sb4hlPUO3+Rj93QAg350GT4
         NUgn+shdk/lzcV5mf8788UvpSqjktXnC2eV7ilWGhluWS89aC9So8EczHAL4pqyX61vl
         ZSX7aHdKttIyKv1sFuDKPjU8qSbWreC/Vl7qzeDZae2+mqkTlR9yZzkt2TOBKnTIcRu6
         bXdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723217829; x=1723822629;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=DJb92HaihbXB1lBR0u8Wzs1p9HNYFM+SQqP6ZaYzlUg=;
        b=IuXHXRVydb8l7wqG/z/W6yWmtZ5eJp23y9F054nBGswaClQVXr7IMHdEFNYx8B19It
         M6Hu1+5tQfQyyZJxTFWJgDoOis4U7+lWcaASKDOzNvSBj9B4eJEBsMSGIbb4faopPGuW
         /g9ROo2dFmIHHbZStaKVpXgj2ty+b9tB5jpafU5q458ihfuIZ4H/fi5Hk7fUcjNQgSTA
         nHI3NRHEfMljsS4AWYtAXf4/qlJGmuo/z/PyDNsn/pgWCPxfikMOj1jh0VCIrkPBkhiY
         V3tJjvdYBTkoSwKFWR9lKetJQwlyWdkdcU0K6JckQfEUxRvkIm9IHS3e/2HIJYpUQD6C
         Qtqw==
X-Forwarded-Encrypted: i=2; AJvYcCWermHoiXjMAHpXWbyg0omAk99WvU/1cNPtGjn0KbXFdLHh95amMD9u4p5DX6dPjDL7+StUuXj4u/kqtGYU+bjj5rNTzamqXQ==
X-Gm-Message-State: AOJu0YyFBg/Km3lYTNUUZZGeyR6yD/veeuKBtJeti+PmC6vtQRj6AX1D
	sRB0uQXv0904rmMTub1bgaSNvQoDrXIzlTRmgsFZQxH8yWj/qkEV
X-Google-Smtp-Source: AGHT+IFfx3Mq0Tr5zNOzthQFNHjjvGvLPuQiZnGXGhqBF7sRC+qriwwYjHFJHy7XMfF7DE3+/4A0NQ==
X-Received: by 2002:a05:600c:524a:b0:428:150e:4f13 with SMTP id 5b1f17b1804b1-429c3a58ffamr14601075e9.33.1723217828329;
        Fri, 09 Aug 2024 08:37:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3baa:b0:426:6982:f5de with SMTP id
 5b1f17b1804b1-4290918e871ls10196335e9.1.-pod-prod-08-eu; Fri, 09 Aug 2024
 08:37:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVd+O+AlIm5jJ/p7IJ6yklRS2tqOF1cz8R0w4+qY2hueQpUW2BxgPJIiwTl2dFk05djIH0EK731vh+QWW1jPvPcPeaKnEL6D0QBOw==
X-Received: by 2002:a05:600c:4754:b0:426:554a:e0bf with SMTP id 5b1f17b1804b1-429c3a1c72cmr11954565e9.16.1723217826278;
        Fri, 09 Aug 2024 08:37:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723217826; cv=none;
        d=google.com; s=arc-20160816;
        b=ilX7cZwAwvItfLHbRZol2xjJy+bhGdqE1W16AC9/pYUcbORYX9CU9LS7LGg0BCPoPD
         sMvc9F+AKw71jurxPOpQdHOxzo4lzaIhp04eV/lZ/6Zco508wuNGe12UER75E3Z0oS/V
         RoDmAsjqFBC/VYOWMro+35LO4dm80IcmfccimkjJbbktB2GZ+5bOG5PTy/J/I2S/MY6O
         8kQGwxuhY4wx3qyNcHIMmwPV2RXT3+G+gBkEUp2Et6Pfw7JMzVMqs5CgZD7S0CG88jPv
         W3Mi16kHmN074E2mzPwAB3Ui2QFelsCcWl0e+DTXats+8LWjHt+Imqk/h0UBiZMdfyZV
         tU3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature;
        bh=NwDMdzsGShHJ6e9jLnQFlgFGGOswIylgETD5oLDX1VI=;
        fh=n9c3lep9FtUsv9022Rp34cPaWZLt+xBTT6c7FnqrISQ=;
        b=JLf2XEMmFu+afK91VY9LV1W6KezXNHI5zsXSQCqvHTGHDgBNb9WfdT+rHeNyPp7Z9A
         ujXcALmFetFlvrJQshOA1e8os3yz3lolBdxlAmR6SErdqR5zs+5VW+8qjVrhVYZes1R+
         kdQU/21FTvdfGwOg6Qw3p6KxLVUfj83idsHwOr4b8Or1NQrlB3GVOvd60vZ46uxIJW3G
         5rAibSTd+bghD1Wtwr6kgne0G4XzSnJpOGEd9xwayNpxyIig4uHYBA31Ahy6lF642y79
         zXvAeP+MkgAone9lwJ16BQ8DnGaBkpraDt8akMbUcv50a3aSc3k10jEe6sdU1iJJaTX8
         Q0lQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=E59PRCAU;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429c200de83si1175575e9.1.2024.08.09.08.37.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Aug 2024 08:37:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id 5b1f17b1804b1-42807cb6afdso52025e9.1
        for <kasan-dev@googlegroups.com>; Fri, 09 Aug 2024 08:37:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWVzGVmSkJPIH2vpJlA6Sr6h6mkAW6J0euEGJXNzxkjuujT1+podJ2DMpWdGJOy1X0mzpuQ0ga0r61+LC4fPAzMVgFMAy933oZ+8w==
X-Received: by 2002:a05:600c:1f0a:b0:426:68ce:c97a with SMTP id 5b1f17b1804b1-429c23553ecmr1336575e9.7.1723217824918;
        Fri, 09 Aug 2024 08:37:04 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:1cbc:ea05:2b3e:79e6])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-36d27156c8asm5607035f8f.24.2024.08.09.08.37.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Aug 2024 08:37:04 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: [PATCH v8 0/2] allow KASAN to detect UAF in SLAB_TYPESAFE_BY_RCU
 slabs
Date: Fri, 09 Aug 2024 17:36:54 +0200
Message-Id: <20240809-kasan-tsbrcu-v8-0-aef4593f9532@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIAJY3tmYC/2XOTU7DMBCG4atUXmM0/p+w4h6IhTOxUwuIUVwiU
 JW741RCpM7ys/S84ysrYU6hsKfTlc1hSSXlqQ58ODE6+2kMPA11MwlSg5OKv/niJ34p/UxfvHf
 C+A5EdM6ySj7nENP3LffyWvc5lUuef271RW6vfyF9H1okB65NxA7Bam3xecx5fA+PlD/YVlrUX
 ptGq6qNoE5GjEKAOGi9112j9aZdIDQhIpA9aLPTChpttp/joKgfIhGZg7b/GkE22lZtYUAbvEM
 tjrfdXmOjXdUwgOmAjPbhXq/r+guCXmJx3wEAAA==
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
 David Sterba <dsterba@suse.cz>, Jann Horn <jannh@google.com>, 
 syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1723217820; l=7406;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=uFiBYlbkxdigQenIMp5nAwwqrh4S/9K2gPEQtQ2EsiI=;
 b=W+3X6Fz2LJ4n6j7/pAhLNqx5v9SnrjJHYeGuApT6jH3QQbmWECsCaYqYbZQwG0dttTGpFq8fk
 PYkNcnijIsKCEYeR9ykvHN/3MJdvRUKIXxr+cQnX/95ui/fyc4cIhAg
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=E59PRCAU;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32a as
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
Changes in v8:
- in patch 2/2:
  - move rcu_barrier() out of locked region (vbabka)
  - rearrange code in slab_free_after_rcu_debug (vbabka)
- Link to v7: https://lore.kernel.org/r/20240808-kasan-tsbrcu-v7-0-0d0590c54ae6@google.com

Changes in v7:
- in patch 2/2:
  - clarify kconfig comment (Marco)
  - fix memory leak (vbabka and dsterba)
  - move rcu_barrier() call up into kmem_cache_destroy() to hopefully
    make the merge conflict with vbabka's
    https://lore.kernel.org/all/20240807-b4-slab-kfree_rcu-destroy-v2-1-ea79102f428c@suse.cz/
    easier to deal with
- Link to v6: https://lore.kernel.org/r/20240802-kasan-tsbrcu-v6-0-60d86ea78416@google.com

Changes in v6:
- in patch 1/2:
  - fix commit message (Andrey)
  - change comments (Andrey)
  - fix mempool handling of kfence objects (Andrey)
- in patch 2/2:
  - fix is_kfence_address argument (syzbot and Marco)
  - refactor slab_free_hook() to create "still_accessible" variable
  - change kasan_slab_free() hook argument to "still_accessible"
  - add documentation to kasan_slab_free() hook
- Link to v5: https://lore.kernel.org/r/20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com

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

 include/linux/kasan.h | 63 ++++++++++++++++++++++++++++++++++---
 mm/Kconfig.debug      | 32 +++++++++++++++++++
 mm/kasan/common.c     | 62 ++++++++++++++++++++++---------------
 mm/kasan/kasan_test.c | 46 +++++++++++++++++++++++++++
 mm/slab_common.c      | 16 ++++++++++
 mm/slub.c             | 86 ++++++++++++++++++++++++++++++++++++++++++++++-----
 6 files changed, 267 insertions(+), 38 deletions(-)
---
base-commit: 94ede2a3e9135764736221c080ac7c0ad993dc2d
change-id: 20240723-kasan-tsbrcu-b715a901f776
-- 
Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240809-kasan-tsbrcu-v8-0-aef4593f9532%40google.com.
