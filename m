Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBWWLT62QMGQEU2CDSQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id BA30B93FDD2
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 20:56:27 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2f03d84f79bsf40033681fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 11:56:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722279387; cv=pass;
        d=google.com; s=arc-20160816;
        b=ThnWpp2FZzGyZ2r9GN5xrdhxmwrRlx6IzzBgURKAdb16dzyYxmCmswHcBzFicsydVS
         xm0+bAKd8yqRhnmIb/NScdcmjs6e8pyC0Ecb168Z7D8WXCEvawidKRViB+r8888yeEoC
         Zh1v1ZWRiwrYvzIs2XKYAOTXAW3O8HxWgdurH+VJerd3DmKnrn0RFol/5re0qfP/okVQ
         Z35ANz/oN9O7IxRieYW+d4Iq63dxxbS725nTW4n8nwe2WkXUx4+LqMx6EtozTOlSxb1k
         o0h4ZHsCgbkVITk7tcLFd/2GK10n9jMWn6wjBfvfMPW44C5SoG6+rm6Q+C+kscogVtpa
         JjSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:mime-version
         :message-id:date:subject:from:dkim-signature;
        bh=CvzQ2JD4Px8LKUS1LvPNu7wD1c2N8dWUnW9uQR/sFUo=;
        fh=JS4YZSScukUKTgi2eEnNBQtXxabMnZh+tEzJTt4WH6E=;
        b=BW3vlPMiZFoxTM2ezcuZk9xf8NTEeow6pqTplCrW30Rb62+FpD3j4F1n0yrq3snMSd
         1CfpP+vySaLZCXdLSfKD10JVX1sAxs0/DKJXRagEZ0o2T3WYSlX6iXmJIui5C03dsPkZ
         U4OHbJhmGj0c5+0qDCS4aXYZvLTnBfskLCk1i1yxaVfQ5TxPkzO+UxIaE0LSu95kp6+C
         EHrk3OBzvaloyVhKbN8cLj5Fr5PcagAc0FLNOBCZ7bFY/kqcnvVGOi2xZEWP1XBvZlX8
         i2JHXD+QkzogY4A1mm683o3lQkCKLW/yJjSPa6LR0s0KxkDP3sSKb30dihbGnwwhzxIO
         Xq1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oxi0HbXM;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722279387; x=1722884187; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CvzQ2JD4Px8LKUS1LvPNu7wD1c2N8dWUnW9uQR/sFUo=;
        b=Gnc7THnhwIKS5iGpwsEU7Mq11q6SZYbwornZV6jqhwHJ9fH9Uj1Iirywv39Ek8Fy44
         3a1eIDU20dSj28NKfW/OOekwPD2BC3GQMZnPbB5UW/4oypcipwreCaLxYMnrXrY49NJi
         kpzSBbDz0HIa+uzgomTdwExLC9/dCiQbOKxYiz0nNNZU7hkgNHr2M9qq3gZqpdsdwgUB
         M/ZPFv0UKFaCbIdqhO/TLFps3gwjVA7KexY/X8jcyRg2BzC06Z+r7SFNK21zDeGS52em
         9yGoUNX+hXwn7CYMrsZUNFMnDUV67ip4fsdoUs3IfF5ZSM9xBaqsFsJFUMpimSzoPmFl
         Iytg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722279387; x=1722884187;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=CvzQ2JD4Px8LKUS1LvPNu7wD1c2N8dWUnW9uQR/sFUo=;
        b=H3x6K+mNppa0z2OhOpSpnJNMSe8XESVOPjKd1R+9dSRigQyPx4oGTpGARMMLHE+wza
         M+bsrBGA/qXSAvuHpyGmG7H9w6WWXEYlMXZndPxhspNpsIy+w8c6SY9FxjMs9zSKq2tX
         vBp2sHDkryQgw7LUK7eb9xTBfaEM/aZT1BdZylM4gDAa+nXJqK+cPsXvSs1xHW57efdL
         G5ZAx59/uhb/wfg0nyIO2JchehPgGxst8lwPTrFiIv7IPutSF117hZlG2kinkdL09XQ2
         mxqq403L2TKT4fjj04s69dTagcsPIbmqDOBRbcUSlHQbsbTXjfIKd1BAWL3Fu+3Lnz2z
         TVyg==
X-Forwarded-Encrypted: i=2; AJvYcCUeSfaiH3gkObJzXjtWhkrDQQk+bhBldgOYcJZ8ScPGwvU5YB03rxY4Lunvdb+kp5gvI8pW5wHDZF5yiSVcJ/HD3yYPGHBPgQ==
X-Gm-Message-State: AOJu0YwAB+WxXnJJkXAHq4I3casQnQziNh4bCr7ZRL+r3DzIQ+tDl01b
	LUwjS4bZLD99FQR0eCNlZwEX0xTdJAqiOrKHdZ2fkmYOhDDFWiRq
X-Google-Smtp-Source: AGHT+IHwKtbxCO77/ZMtbQHmjxlIFaL5PL5apcvWksJNTNlKvzsEghzRRJHhJEh59Nawbwurb2KCLw==
X-Received: by 2002:a2e:9619:0:b0:2ef:2e3f:35da with SMTP id 38308e7fff4ca-2f12ee634famr52015821fa.45.1722279386281;
        Mon, 29 Jul 2024 11:56:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a583:0:b0:2ee:89a7:12ac with SMTP id 38308e7fff4ca-2f03aa8ad5els12168571fa.1.-pod-prod-06-eu;
 Mon, 29 Jul 2024 11:56:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVcVo+GPX6qfZaVcyC0q5frgBdG4ele+xNQI12+iNCsEtNmE+PnHAkUVxnaiwVOfnjgLuqLeXZcB7nO59GKOnlmhYErDFAJNO9A7g==
X-Received: by 2002:a2e:9092:0:b0:2ee:87c1:3c94 with SMTP id 38308e7fff4ca-2f12ee6236dmr48203311fa.40.1722279384064;
        Mon, 29 Jul 2024 11:56:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722279384; cv=none;
        d=google.com; s=arc-20160816;
        b=cI1ny5r9E72G5rLYzPY3U8k6mr2DYY6La8gUoYX3UloOgATmQMx/QoiOiGtYXO+5OI
         5M1fKyCnfYex8N+m7AQqHP/CKPyicH39EHagSBAI9xEKwMEL3ztgUNmMvRVOaeESg+CA
         332AOyD8ERDo6Iy67tNdYiEuO44dMC2JkQGXqtSCAg4/4oMl1vhYx3p1/vl0xss5RI9m
         aKi1YcNuJSRaN2uW2rsel4gYE7feNRphKYKAClWAa09KBP2yAADVTheml8zl7QhZpwJd
         7apU8Ylj3O1i2NJIAMCbgPhQxPnpr/9c2lguaZD8kKNTSReY9xhggpOk+02IWl0p/jHg
         DkWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:content-transfer-encoding:mime-version:message-id:date
         :subject:from:dkim-signature;
        bh=OJFBXmp2nnWSyPQ0vZXV6CH2fcDg2DG8vfwkkfKQGv4=;
        fh=qom2nqO9hfpqysDyaXmD8KMUC6vzhs52UTsLI/gdY9E=;
        b=roeCy/Pfwy1TVm7SMSPoDS7Z1hTVx678+J3cbULsO/wB+Trp/XRDOQXY5VncxRDm/+
         swvVBTwCs2d6JvADsbAYcuuh441pdX1B6MeltZQh+e67Wkk9GXWhrfwdFuLxksaDSt4q
         4N2EeT/WIfjZc9l3dB9T1XP32dTtbxa2F+AGStEHDYosAJOJAjasBazljPvpg5AEqBPm
         gYvfto9Zvc1nWgKsEXTyRLLGqi2+ptveIdrBB14sZ3pimAirO8rlOInecpbZGG50rnUk
         J7pReWiQdIUQZ2KhO1W8Y2LAPYCti7xRjMnqq0ZxasrXc5RsrJ8WH9e8+PdmzuXWnosL
         nNNw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=oxi0HbXM;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f03cf0c978si2070261fa.2.2024.07.29.11.56.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jul 2024 11:56:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id 4fb4d7f45d1cf-5a869e3e9dfso3087a12.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2024 11:56:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX6UDXtZ5BGbcL9L0zuFSz5FjdlzKWHSbc+umPkwDUASyopQrdpU0JLUU4V+1Hrhf+mBOZTOuj6gaC6n0AvS09ulC5VDz9f/lOI0w==
X-Received: by 2002:a05:6402:1d4e:b0:57c:c3a7:dab6 with SMTP id 4fb4d7f45d1cf-5b40cede1e6mr72548a12.3.1722279382616;
        Mon, 29 Jul 2024 11:56:22 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:a1f4:32c9:4fcd:ec6c])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-36b36857fdesm13151543f8f.75.2024.07.29.11.56.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Jul 2024 11:56:22 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: [PATCH v4 0/2] allow KASAN to detect UAF in SLAB_TYPESAFE_BY_RCU
 slabs
Date: Mon, 29 Jul 2024 20:56:10 +0200
Message-Id: <20240729-kasan-tsbrcu-v4-0-57ec85ef80c6@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIAMrlp2YC/13M0QrCIBiG4VsZ/3GGOp2uo+4jOnCmm1QauqQYu
 /fcIGgdfh+8zwTJRGcSHKoJoskuueDLYLsK9KB8b5C7lA0UU4YFrdFVJeXRmLqon6gThKsWEyt
 EAyV5RGPda+VO57IHl8YQ36ue6fJ+IbaFMkUYMW5lK3HDWCOPfQj9zex1uMMi5fq35n91XWpOd
 EuttIRgsqnnef4AQdb6v+cAAAA=
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
 header.i=@google.com header.s=20230601 header.b=oxi0HbXM;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as
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
Changes in v4:
- EDITME: describe what is new in this series revision.
- EDITME: use bulletpoints and terse descriptions.
- Link to v3: https://lore.kernel.org/r/20240725-kasan-tsbrcu-v3-0-51c92f8f1101@google.com

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
base-commit: 0c3836482481200ead7b416ca80c68a29cfdaabd
change-id: 20240723-kasan-tsbrcu-b715a901f776
-- 
Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240729-kasan-tsbrcu-v4-0-57ec85ef80c6%40google.com.
