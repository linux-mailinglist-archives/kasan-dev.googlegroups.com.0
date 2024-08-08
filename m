Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB3U52S2QMGQEJ25KWYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 56EDD94C456
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Aug 2024 20:31:12 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2ef23969070sf13942431fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Aug 2024 11:31:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723141871; cv=pass;
        d=google.com; s=arc-20160816;
        b=WiZnfTTR20HAjX0f/IhUXr6ojcLsmdb1Geig5tVBsdxFoeESsuHdJupB1MFtlXm49b
         dWGXBrOQO/AMeE9RaMYy3X/M8PSBhnrphYgtCW8Br3NFEZkqqQYEY0MUJnDmW65fMuVT
         Zk5+rS5NisGO06+X3b1zj2O3ak2N72y5qcVqEN7LfF9G5hJpkoO0Fur6jIhjLsZtHihg
         26yEKPS4CAT44H6cpTj60IXJoJHcO0g95DNSIrQXtD1zH4g6tjhlzEH+YDprW4c7+Q5e
         PDO98YPfyZy5Wo0VOUvI6Fnn7vrxr4BjNB+Ml5L65/aPau8LbvuwNqcnR0JSHhvoD5yg
         EykQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:mime-version
         :message-id:date:subject:from:dkim-signature;
        bh=a/NAFwa44tc4ygsEJD8qZLmtw5z6O9NIIta3Fl6n7cs=;
        fh=PciEiI4zVgHGX/wVoVAEgnsz3F+dPhn7nY4kqlx/JZQ=;
        b=w9cRuUQhFLVQ0+FkHRy9EcZ7Yj4LLms/CyIARc6CszE8jWB/YQG71OX1m/AkrlI9eB
         XpOOeKvJbNY/n4913SS/+9FjmEfV0L+ZAEZXrag3KFv/3Bz8ySz3fiXVeH6Oh043VvGI
         N8Vnez8u8m6haQNN7oGs4u0Qhnw1mEo5u8Pyfa071U5TJEc2lN/0kUTfbh6tTJm97q2o
         LpDjBHBZyKhz8sDRTcSjubB5FaDJXXEa37WTkI99lp3fiirhAo263LdnRksFCqbDIsC4
         MU7uJna89GrTcQzFKxRrtyNA0FvuSAXP6f56RHrCKh0UckObuNnoHbz1JqNajafwG8lu
         GpGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JnkeSVu0;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723141871; x=1723746671; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=a/NAFwa44tc4ygsEJD8qZLmtw5z6O9NIIta3Fl6n7cs=;
        b=gb7x8QxwwBwn8BdOT7f6ij/N9UJge6MnpMH7cfUYVuAMMRxh0B+eh3f8bAj3mo0jS7
         Sblrtf3F9bp3AGVOtTk99XTGYLHw5xv91mxrRDflpoWoBUYVBO2gDTlYrlRo9QTze6ew
         cUGlNLJYCyKbK1AdX6xP2f/NIFZ1eJuz6A+Gu9W5RzYfW/nxuW10mAYFiWYAMNwnGDi1
         /FkbdhhSlcoMLyPkuAl34jdAJDyqW7BcMDbOtBRmBlN+UdLStWKf05729zKPwtdwmsjD
         Z2WtFhze3cFazfM6z/FUCS41efhvy/4zrbh7SPUm855V3LsET6kqhDcFQ0U5l4toGo06
         1Z5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723141871; x=1723746671;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=a/NAFwa44tc4ygsEJD8qZLmtw5z6O9NIIta3Fl6n7cs=;
        b=eerQ+o1iPwj2IzkcILqmULJ6BA119tzBcmpLtOj085pH4eB+qeYLjZUjr6h6SRzMNY
         S1voe247uetmyEBb7SW/II3WFB6SsWLUKAEdx6JjvWtAr1WMeUkTgWZlELGbI2cr5i9L
         NqhfXxaUn/90GvOMcGUstXDsp8qYVgHeziY79U6CExi5iOP4QR6X0PLI4hlUL4YIUM+5
         pZsb9WzY603GBpEwhljxk8H09kUGkWLZh+GvAoID24LtEEesmDq+Yq2IFtH1Eng0sIGU
         vnIKVmhKnjnca2kZU07838QIOXqBdI1L2+syBc7g5gXsLA07bUm1QmZ0+RDL+c7+YgLT
         oGRA==
X-Forwarded-Encrypted: i=2; AJvYcCVcklIIcEIGxtZOpmmPPvkEerXwYsvN3unOEavhe2AmwEDCQGHNL4sEiKajUB2sISjdEQq0caT+Q8uDBI4EWy90ttwoTIXMsg==
X-Gm-Message-State: AOJu0YzUjFLqurKJgIT7TRtQQ2sj2HfsbVLNr4RuG4znQWRoYAXxc/MI
	NV2b1yDapCiX6cf7V8dNfKr2s8hhWsLLxioKMANnQy4KY8aPnYVH
X-Google-Smtp-Source: AGHT+IH+tWp1Fk/o/cgc3vCnzcnm4akuG+Z1+ljRiCnb+rNW/EUDU1HKeIrn4oq0XJ9reStVq6sMVw==
X-Received: by 2002:a2e:8e83:0:b0:2ef:2b65:1d03 with SMTP id 38308e7fff4ca-2f19de93513mr22126221fa.49.1723141870362;
        Thu, 08 Aug 2024 11:31:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a43:0:b0:2ef:1eb3:4749 with SMTP id 38308e7fff4ca-2f19bb46901ls5998681fa.0.-pod-prod-05-eu;
 Thu, 08 Aug 2024 11:31:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUe0L15mJzsEiP08o9IxudsqwZyxJBB6F2dms/nuw//IdXn0PqsxMPHuxpr1kXNCDLRdgtZj1Ip+1jrn7V/xOIu7sY0Kh1yIMLwxQ==
X-Received: by 2002:a2e:7a11:0:b0:2ef:2dfd:15db with SMTP id 38308e7fff4ca-2f19de3890bmr22773721fa.19.1723141868013;
        Thu, 08 Aug 2024 11:31:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723141867; cv=none;
        d=google.com; s=arc-20160816;
        b=kN7R7aHViTl8yDL3F9Lfluz1fhXcSQYjMqekwih8BZ/31NOT0awYaY/qcDaeDB0WBH
         2vXEihknlOsX20p+MdvgibLT3WL6GZ6POHwfQws8vY7O8DFdQzegxmOGXWuvsShEHGwK
         4zDdaiVKiqUEpZB7F0pY2MlmaRzWi5kJ+nZZxXLV3n1LyW3lWutdHaFmSLbPnWQH6I4G
         pdrmHkTpf0atRS7B/yBVl75y+CuXcD91POm/Y7+yQW0NxPbgO/1HpPXX/9GKbZ5HM55B
         i0hcHhed+/dDAcQ2yvtCx1vgqR64b8jA0LO27ENgaDQ/CqvldktMLYiwieEPCcJpyNtg
         fNKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature;
        bh=DLW6erLEdD1RJkfioQR08NW01BP8YceiCQUjS50VurI=;
        fh=cW8RM79FeixOSmQ88p7sl0EGiE2jRa/pqEz7K4zgJx4=;
        b=yVZWUSuZjFeHQoY4yX0qdHf2WAGTaxj4j1uoVGJ1K1I05mH5HZTZC8mW7aXJOSxmYJ
         LhXSxm48chHSEVAE58lsTFsnWl46BqnmW3pxM0WEFC3ovpNp9vgoa+9+Xkvn0M1l8Mcc
         Eu08H99NP1r5xJz5BlKXqUw1QhJ5uceXruT0Q3duArf9+uiInkRIXF/84FrY1MEX8/23
         zdTlsbtfwRZGcD2YAZqf/TXJoiyW8EAIYO6IWxkVzNH5Ouwu2MhpXyQcrtS89MBYvKne
         DJFCuE60BJrP3dIXn+9veaxycuwMsglsSJRiqz331rA0Gl4mPjZA/Pb7v9xn7d86sBmq
         so5Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JnkeSVu0;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f16562cc91si2568711fa.2.2024.08.08.11.31.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Aug 2024 11:31:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-42807cb6afdso1785e9.1
        for <kasan-dev@googlegroups.com>; Thu, 08 Aug 2024 11:31:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW01Xy+dI+Fz2I8d4yyYGGk8iprGap752WByh8O9vigSyag5qte6yAiKoszvx0Ud+737/5ypFLi32/ZBKOzHIYPQRYVXg/uIybL5Q==
X-Received: by 2002:a05:600c:1e16:b0:428:31c:5a42 with SMTP id 5b1f17b1804b1-429c17bb78fmr111085e9.3.1723141866523;
        Thu, 08 Aug 2024 11:31:06 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:fc0e:258b:99ae:88ba])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-4290c79f345sm34845495e9.39.2024.08.08.11.31.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Aug 2024 11:31:05 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: [PATCH v7 0/2] allow KASAN to detect UAF in SLAB_TYPESAFE_BY_RCU
 slabs
Date: Thu, 08 Aug 2024 20:30:44 +0200
Message-Id: <20240808-kasan-tsbrcu-v7-0-0d0590c54ae6@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIANQOtWYC/2XOTU7DMBCG4atUXmM0/p+w4h6IhTOxUwuIkV0iU
 JW741RCpMnys/S84yuroaRQ2dPpykqYU015asM9nBid/TQGnoa2mQSpwUnF33z1E7/UvtAX750
 wvgMRnbOskc8SYvq+5V5e2z6nesnl51af5fr6F9L3oVly4NpE7BCs1hafx5zH9/BI+YOtpVltt
 dlp1bQR1MmIUQgQB623uttpvWoXCE2ICGQP2my0gp02689xUNQPkYjMQdt/jSB32jZtYUAbvEM
 t7m8vy/ILNCRnOKEBAAA=
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
X-Developer-Signature: v=1; a=ed25519-sha256; t=1723141862; l=7163;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=ifhhMKUq3wZYmlKPhfOQuDlC/AkSNxHfHxamMzAf6II=;
 b=2aRS0R6BoACVWuuRvijlpPNLmH0ucoBGDBTgCdvc6f0r9/4Ft9gdMXDBQEo9ihbyrZK2ppxJK
 OguwRRT1ftBCFRFsZPbdjylmtvCUY6szc+i4JLXWejdDPMROUVi361k
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=JnkeSVu0;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::330 as
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
 mm/kasan/common.c     | 62 +++++++++++++++++++++---------------
 mm/kasan/kasan_test.c | 46 +++++++++++++++++++++++++++
 mm/slab_common.c      | 12 +++++++
 mm/slub.c             | 87 ++++++++++++++++++++++++++++++++++++++++++++++-----
 6 files changed, 264 insertions(+), 38 deletions(-)
---
base-commit: 94ede2a3e9135764736221c080ac7c0ad993dc2d
change-id: 20240723-kasan-tsbrcu-b715a901f776
-- 
Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240808-kasan-tsbrcu-v7-0-0d0590c54ae6%40google.com.
