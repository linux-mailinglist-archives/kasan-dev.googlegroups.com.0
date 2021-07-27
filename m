Return-Path: <kasan-dev+bncBDY7XDHKR4OBBCMJ76DQMGQEXMDSXXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 195523D7139
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jul 2021 10:32:11 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id j22-20020a17090a7e96b0290175fc969950sf2449673pjl.4
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jul 2021 01:32:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627374729; cv=pass;
        d=google.com; s=arc-20160816;
        b=ezHlZYr0V2ZfsdQkWC5FP2aD381gdrAPv6Lr9yeeAaJMgs6+hllWfcvGLibu8oY2+G
         SuLrkgniPvuzlrK4uycwZahTbdZnYP776DjntcL1yRRE7pjI6ZWUrXpUUyCjFhDv3ylW
         r4zJ+J8YkKGEGplkZkLlC931LltHg6fFMJLEGwnkcw2ZNsrwLGOIe9sAraHhuprtX1tC
         4Rh7snSps7sAxZsrnMA0G4nelDyavEqrzHIX391MWcL2r7RJGW1BrUf3JkJWxbHHVFMY
         C8hjbjknOo/wD+Msg+VxobEkWMwx8qJa4U7ayn6wcTxy8qnZBlHd1iEz/P7RO1W5i2UE
         Um6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=BUE9Jbptz0loHx+c+1YigY2b5p5wOJGCwKk9X+7Zd8M=;
        b=THf2leJa0Z7sSgCUpcgx6cdhFjuDcfipUWLQ9FGLK+ZkapAmYqa4cPVO1aealLqcP7
         6kKh6aFDA+S7Fh11bglS9wm+LUpaAd6zmatcYZnkqBNATOC9NEtS1zgpnct7VzoeY1q9
         AT1y7phU3p0E2RZ6hgocZX5LifuMdAidJy5l22u25tHas0nrpPtU3Gnxi99wkZ94Gjl+
         xRHqD0UsVpuR40Gm9AXzH+f8a1P2nUY5bjE9wcPj0UvqDciObTH362YkORbLVAZsGGdn
         Y2E8SO1tsHZnODIjzdQAtD3LtprIDy4pqS62V0BovhHttsviJzqY9chHIx5JGYWRmjTz
         1BGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=d2TkR2Vv;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BUE9Jbptz0loHx+c+1YigY2b5p5wOJGCwKk9X+7Zd8M=;
        b=SRreLGuheF4OruOCY4lmwm2KQ24FXR8Kt8smRZ2Ye3p2ldespiVjBlkqYTWySYXT8d
         UZIjj20l7lhdtUP3dAiDK7VuY3uVfTXLBvB8TyL2FxHZdhR9Wu9aigMlxkqJtMVcW37T
         F7ckDtFi2mb1xeXiD64FlSlBisV6zI6PXWqqNxbU2SpBOvizFXh56jDlyfB7xbjMPfbn
         c8IFDQ0exiTLjrhW9bN6zd1fLIV7d1nTyEbcGcYb1giIsEvAEJz3STYue6fg9xRPZkcV
         jZesOr/MpMXX7KeqFveNjbhE9FLc+MP1fybAiLqWChkL4OqXAWzNq75RKIvp9O5Il7C8
         qpvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BUE9Jbptz0loHx+c+1YigY2b5p5wOJGCwKk9X+7Zd8M=;
        b=gP8EuVzFxu9QVssJIPfOsbaxVRt3MHxPN3g+YjuULcBEb9dEmST+YwVvejNe8P30UL
         ldrrr3z0B02bhvcnNqPWL/VOzf4NCX0pHPoxD+Eu0ZYYQBWMtVluN8kSnzo6Zkz9Vh/E
         SwhPopc/5NwQQklJNZvmAWXH/+IziaMifZsHVq+pU46ljCfCb7Pq22JJ5GX1NsQC/HDO
         W7hVEKTlHWrdVEMtGAyvlU3J9wjpqN7YfdBHsgj88w+VEXUwaP/qMxANxjYJawmKrQLh
         D0LNgc90WPRANw9YEUI2xzzyOt2oM3w09FZ49ZGrGAJ7hHSgAWhpMcxxE+dNWEY42AFW
         Wo7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533X81YkeU2jVvGoGrMSSZG+OCsRz98QWggs6x082Spnpj3BFsYG
	5ihoRrZTatN9GsVvhnqX+XU=
X-Google-Smtp-Source: ABdhPJyd+yCEE1JQHs55rQtp82spjHSr7ufs/U3sSxdlEdqqjLOMw/EBusG+cVgBIlRvkTVNaPyb/w==
X-Received: by 2002:aa7:8a04:0:b029:332:950e:d976 with SMTP id m4-20020aa78a040000b0290332950ed976mr22293983pfa.40.1627374729804;
        Tue, 27 Jul 2021 01:32:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ed82:: with SMTP id e2ls10309375plj.2.gmail; Tue, 27
 Jul 2021 01:32:09 -0700 (PDT)
X-Received: by 2002:a17:903:2c2:b029:101:9c88:d928 with SMTP id s2-20020a17090302c2b02901019c88d928mr17933315plk.62.1627374729263;
        Tue, 27 Jul 2021 01:32:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627374729; cv=none;
        d=google.com; s=arc-20160816;
        b=NxOM4VN289ixplrxMPCCqIdrgCfYNHy/rYlxQZNuIwMwinToZbyvReEPbFhUajg3An
         vxpaXaUFHzf+xIGoDr/Wqavt2J4ehh4QLapjhWldipVAJv+BjQM0B2j/HR5R+cHz98qS
         a8Wpxg0r04k/JzYvczAwWnutccxOcDfKkFixvlvWqe+uG8mNcG9GBwhHtpC5fXAtIxu3
         y6hYgKTpRFrdTqVDcu3geDDcPrZpyddSErxPxC2yVkMmAazcWyeZWyc4ZBUuUuvWf8Kh
         7h1xHEk2k1Qy6gX+mwjSGiir9NH39tryLmEJISKzdnVeJCuvtAsUeQUXoo0/vf/8z/gX
         nCMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=K6HRnr73XEh5xE2ceOhDEOAvjV1178SrYS2eQwvfCZI=;
        b=UfT6ATABZvj5ANg+erAm9oOee4QNEccQ1p7MUZBb37De9Kao5UnyeJrBkovss5WQKi
         Xb/LvY0Ypyu+MhuTxIPVW9rXqbR2Br4I640QXQMkSV3CyZKRBOUbLZOKziugSm+lWBiq
         E0Im3TOvRVh1OXrOpBilHgqhXLvm9qbXGG3mmTA2bKSsYeR4m5MxWn+gtotWAgBrYjEB
         CGyxInLM/2+agSYKf1nVTF7GOGK+57Vrp+x260tofiWXtg3fbNDxV6NryWJsdKGXGz+2
         laXX/rhqASSy0XY+NMir09IfuTMhsv6/eT77mGd8gcBxPhR2cAEeLu642ynjpOLf6590
         HADA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=d2TkR2Vv;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id x20si111027pfh.1.2021.07.27.01.32.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Jul 2021 01:32:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: a3a66bdf89734495a39eecb3f067033d-20210727
X-UUID: a3a66bdf89734495a39eecb3f067033d-20210727
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 676963900; Tue, 27 Jul 2021 16:32:03 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs02n1.mediatek.inc (172.21.101.77) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 27 Jul 2021 16:32:02 +0800
Received: from mtksdccf07 (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 27 Jul 2021 16:32:02 +0800
Message-ID: <b6b96caf30e62996fa3b75ae8d146c9cc0dcbbf6.camel@mediatek.com>
Subject: Re: [PATCH 1/2] kasan, mm: reset tag when access metadata
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Marco Elver <elver@google.com>
CC: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang
	<andrew.yang@mediatek.com>, Andrey Konovalov <andreyknvl@gmail.com>, "Andrey
 Ryabinin" <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Chinwen Chang <chinwen.chang@mediatek.com>, Andrew Morton
	<akpm@linux-foundation.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>,
	Catalin Marinas <catalin.marinas@arm.com>, <Kuan-Ying.Lee@mediatek.com>
Date: Tue, 27 Jul 2021 16:32:02 +0800
In-Reply-To: <CANpmjNM03Pag9OvBBVnWnSBePRxsT+BvZtBwrh_61Qzmvp+dvA@mail.gmail.com>
References: <20210727040021.21371-1-Kuan-Ying.Lee@mediatek.com>
	 <20210727040021.21371-2-Kuan-Ying.Lee@mediatek.com>
	 <CANpmjNM03Pag9OvBBVnWnSBePRxsT+BvZtBwrh_61Qzmvp+dvA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=d2TkR2Vv;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Tue, 2021-07-27 at 09:10 +0200, Marco Elver wrote:
> +Cc Catalin
> 
> On Tue, 27 Jul 2021 at 06:00, Kuan-Ying Lee <
> Kuan-Ying.Lee@mediatek.com> wrote:
> > 
> > Hardware tag-based KASAN doesn't use compiler instrumentation, we
> > can not use kasan_disable_current() to ignore tag check.
> > 
> > Thus, we need to reset tags when accessing metadata.
> > 
> > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> 
> This looks reasonable, but the patch title is not saying this is
> kmemleak, nor does the description say what the problem is. What
> problem did you encounter? Was it a false positive?

kmemleak would scan kernel memory to check memory leak.
When it scans on the invalid slab and dereference, the issue
will occur like below.

So I think we should reset the tag before scanning.

# echo scan > /sys/kernel/debug/kmemleak
[  151.905804]
==================================================================
[  151.907120] BUG: KASAN: out-of-bounds in scan_block+0x58/0x170
[  151.908773] Read at addr f7ff0000c0074eb0 by task kmemleak/138
[  151.909656] Pointer tag: [f7], memory tag: [fe]
[  151.910195]
[  151.910876] CPU: 7 PID: 138 Comm: kmemleak Not tainted 5.14.0-rc2-
00001-g8cae8cd89f05-dirty #134
[  151.912085] Hardware name: linux,dummy-virt (DT)
[  151.912868] Call trace:
[  151.913211]  dump_backtrace+0x0/0x1b0
[  151.913796]  show_stack+0x1c/0x30
[  151.914248]  dump_stack_lvl+0x68/0x84
[  151.914778]  print_address_description+0x7c/0x2b4
[  151.915340]  kasan_report+0x138/0x38c
[  151.915804]  __do_kernel_fault+0x190/0x1c4
[  151.916386]  do_tag_check_fault+0x78/0x90
[  151.916856]  do_mem_abort+0x44/0xb4
[  151.917308]  el1_abort+0x40/0x60
[  151.917754]  el1h_64_sync_handler+0xb4/0xd0
[  151.918270]  el1h_64_sync+0x78/0x7c
[  151.918714]  scan_block+0x58/0x170
[  151.919157]  scan_gray_list+0xdc/0x1a0
[  151.919626]  kmemleak_scan+0x2ac/0x560
[  151.920129]  kmemleak_scan_thread+0xb0/0xe0
[  151.920635]  kthread+0x154/0x160
[  151.921115]  ret_from_fork+0x10/0x18
[  151.921717]
[  151.922077] Allocated by task 0:
[  151.922523]  kasan_save_stack+0x2c/0x60
[  151.923099]  __kasan_kmalloc+0xec/0x104
[  151.923502]  __kmalloc+0x224/0x3c4
[  151.924172]  __register_sysctl_paths+0x200/0x290
[  151.924709]  register_sysctl_table+0x2c/0x40
[  151.925175]  sysctl_init+0x20/0x34
[  151.925665]  proc_sys_init+0x3c/0x48
[  151.926136]  proc_root_init+0x80/0x9c
[  151.926547]  start_kernel+0x648/0x6a4
[  151.926987]  __primary_switched+0xc0/0xc8
[  151.927557]
[  151.927994] Freed by task 0:
[  151.928340]  kasan_save_stack+0x2c/0x60
[  151.928766]  kasan_set_track+0x2c/0x40
[  151.929173]  kasan_set_free_info+0x44/0x54
[  151.929568]  ____kasan_slab_free.constprop.0+0x150/0x1b0
[  151.930063]  __kasan_slab_free+0x14/0x20
[  151.930449]  slab_free_freelist_hook+0xa4/0x1fc
[  151.930924]  kfree+0x1e8/0x30c
[  151.931285]  put_fs_context+0x124/0x220
[  151.931731]  vfs_kern_mount.part.0+0x60/0xd4
[  151.932280]  kern_mount+0x24/0x4c
[  151.932686]  bdev_cache_init+0x70/0x9c
[  151.933122]  vfs_caches_init+0xdc/0xf4
[  151.933578]  start_kernel+0x638/0x6a4
[  151.934014]  __primary_switched+0xc0/0xc8
[  151.934478]
[  151.934757] The buggy address belongs to the object at
ffff0000c0074e00
[  151.934757]  which belongs to the cache kmalloc-256 of size 256
[  151.935744] The buggy address is located 176 bytes inside of
[  151.935744]  256-byte region [ffff0000c0074e00, ffff0000c0074f00)
[  151.936702] The buggy address belongs to the page:
[  151.937378] page:(____ptrval____) refcount:1 mapcount:0
mapping:0000000000000000 index:0x0 pfn:0x100074
[  151.938682] head:(____ptrval____) order:2 compound_mapcount:0
compound_pincount:0
[  151.939440] flags:
0xbfffc0000010200(slab|head|node=0|zone=2|lastcpupid=0xffff|kasantag=0x
0)
[  151.940886] raw: 0bfffc0000010200 0000000000000000 dead000000000122
f5ff0000c0002300
[  151.941634] raw: 0000000000000000 0000000000200020 00000001ffffffff
0000000000000000
[  151.942353] page dumped because: kasan: bad access detected
[  151.942923]
[  151.943214] Memory state around the buggy address:
[  151.943896]  ffff0000c0074c00: f0 f0 f0 f0 f0 f0 f0 f0 f0 fe fe fe
fe fe fe fe
[  151.944857]  ffff0000c0074d00: fe fe fe fe fe fe fe fe fe fe fe fe
fe fe fe fe
[  151.945892] >ffff0000c0074e00: f7 f7 f7 f7 f7 f7 f7 f7 f7 f7 f7 fe
fe fe fe fe
[  151.946407]                                                     ^
[  151.946939]  ffff0000c0074f00: fe fe fe fe fe fe fe fe fe fe fe fe
fe fe fe fe
[  151.947445]  ffff0000c0075000: fb fb fb fb fb fb fb fb fb fb fb fb
fb fb fb fb
[  151.947999]
==================================================================
[  151.948524] Disabling lock debugging due to kernel taint
[  156.434569] kmemleak: 181 new suspected memory leaks (see
/sys/kernel/debug/kmemleak)

> 
> Perhaps this should have been "kmemleak, kasan: reset pointer tags to
> avoid false positives" ?

Thanks for the suggestions.
But I think it doesn't belong to false
positive becuase scan block
touched invalid metadata certainly.

Maybe "kmemleak, kasan: reset tags when scanning block"?

> 
> > ---
> >  mm/kmemleak.c | 6 +++---
> >  1 file changed, 3 insertions(+), 3 deletions(-)
> > 
> > diff --git a/mm/kmemleak.c b/mm/kmemleak.c
> > index 228a2fbe0657..73d46d16d575 100644
> > --- a/mm/kmemleak.c
> > +++ b/mm/kmemleak.c
> > @@ -290,7 +290,7 @@ static void hex_dump_object(struct seq_file
> > *seq,
> >         warn_or_seq_printf(seq, "  hex dump (first %zu bytes):\n",
> > len);
> >         kasan_disable_current();
> >         warn_or_seq_hex_dump(seq, DUMP_PREFIX_NONE, HEX_ROW_SIZE,
> > -                            HEX_GROUP_SIZE, ptr, len, HEX_ASCII);
> > +                            HEX_GROUP_SIZE, kasan_reset_tag((void
> > *)ptr), len, HEX_ASCII);
> >         kasan_enable_current();
> >  }
> > 
> > @@ -1171,7 +1171,7 @@ static bool update_checksum(struct
> > kmemleak_object *object)
> > 
> >         kasan_disable_current();
> >         kcsan_disable_current();
> > -       object->checksum = crc32(0, (void *)object->pointer,
> > object->size);
> > +       object->checksum = crc32(0, kasan_reset_tag((void *)object-
> > >pointer), object->size);
> >         kasan_enable_current();
> >         kcsan_enable_current();
> > 
> > @@ -1246,7 +1246,7 @@ static void scan_block(void *_start, void
> > *_end,
> >                         break;
> > 
> >                 kasan_disable_current();
> > -               pointer = *ptr;
> > +               pointer = *(unsigned long *)kasan_reset_tag((void
> > *)ptr);
> >                 kasan_enable_current();
> > 
> >                 untagged_ptr = (unsigned long)kasan_reset_tag((void
> > *)pointer);
> > --
> > 2.18.0
> > 
> > --
> > You received this message because you are subscribed to the Google
> > Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it,
> > send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit 
> > https://urldefense.com/v3/__https://groups.google.com/d/msgid/kasan-dev/20210727040021.21371-2-Kuan-Ying.Lee*40mediatek.com__;JQ!!CTRNKA9wMg0ARbw!wNP4ZkYDM7Xvs9xfzKwYuG1X2h9zFqST8_Vm2jSvZUl9BiS8SPFMTvMp3VAPKCnuWELL7Q$
> >  .

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b6b96caf30e62996fa3b75ae8d146c9cc0dcbbf6.camel%40mediatek.com.
