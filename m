Return-Path: <kasan-dev+bncBCMIZB7QWENRBQEAT2LQMGQEELYPLNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8067758659E
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Aug 2022 09:26:57 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id w22-20020adf8bd6000000b002206311fb96sf357369wra.12
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Aug 2022 00:26:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659338817; cv=pass;
        d=google.com; s=arc-20160816;
        b=dZVVtq4f+qhXPG3d0k0otZhasdxDNrCDjvqZbrxwCKCNDGSwG6MEHaY3nDnUUt8ZY+
         ZKiAlagAZ/Bsfs+ZYgjeu73DYS9MjGoH56O2c3lLnG4Ceh04mw12CLW0BcPnpwCzRqcW
         /inxQkduLhKriXdwzNUJSeN4imoK6P1wRYVvlMEyMCS3H0pzVr12gdqxYZuuEkr7HoHy
         zOZ7sUBFm1nQtCrjGDU/SCsGxX4It0jBzIm5u3kg3k5uxmlJxZ7+XQpOwJy2cAAfu05o
         zB9+up63I73imniGiQXu5AS9de5anl6/2yHbupkMX00uDom8quuyjtGbE4QWIYeJhRBj
         PvLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sTyRNuo/XUxgXLnFpVeSdEKK5XCmM6vfkczK6AlzHn4=;
        b=OO0B3WuxrKnDjAWiRnGYzsRSJbPyjIVrPjStIIwpR1ZHXOZ7pc+teyMWCD+o2M4GZN
         WgONBw//VObU7SQnUi9Ppqp6+VwGVyC0jQj15F6wkIPQFkldf7DZCnVSAsyyjIQPSJ1u
         tZPR4NcZzZWmmIIoRGfpWomoPfmIMhDrotNl2ycWNFZ7O/DpJybY2YaiT1lfNlrZDvwp
         du7k2/0zO7bZeSi0KP2EkQEdOowcdGQta/MAAB9uPyALwqV/D4BlAw+LS1QkKTOUiBLm
         PK++0zHeF91KEkkaK06GyVzX1C+oR/+zgYk1yzFwc3XmzBMWR/CeB2tlRPOsNt0cokKC
         5Lcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YNAy9BJb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sTyRNuo/XUxgXLnFpVeSdEKK5XCmM6vfkczK6AlzHn4=;
        b=XL37d+Nwc7guxksQQagO4PQwLkbaF0V74ArZjMqH3Vh9GZaw5L4BbcXmWbSH5zfcHt
         pmomuhhneCxtG5dGMoiFmsx3wuR9y00KnAr2hbo33+LRsV04AWpNxajlyzITJ2i4wQf4
         qjRwsU6II5l+C99gfwntUTT08RFwxo0DRvBsfndZmN28JVTf9YGeMh8tJvCXI1C7/EX0
         Ps+Mp4xowJ/ErQ2WK2YNuu/WLolwGSFYWMMFFSz7yWfGrwav7vCAvVgZXeE/B2adiypE
         TYGSQIp9FLxIknxkk9n2Xe8a4WlHrMzIyn7qLuawvzEwWBkkarHod0wZA8dVlZ/iH52U
         rQKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sTyRNuo/XUxgXLnFpVeSdEKK5XCmM6vfkczK6AlzHn4=;
        b=AibT12jFVf4ADCn3yozDBOmAgIgrvMNE4w1kaGZGgmUge45dIm9WLKpAY2rnicfsO3
         FVlui2KpnU6wOCKOMqjZGy3I03nsly6aUrqJVF/Tzfi4sCEJ5QpAPpCVhfOhu8toA5m7
         KZJ55wR4o1T/9Q2aJRGamA2FSJyEeqwRYO52JF56jqwngRFBt+0jARFuQjAh7BjbJGhF
         kjisNYUXiubqBTC+6S7ha8WpieLAXs1eSQdpo/+onSFRCaqS+/HkKmR9lKGLcLMMfRqI
         y73hRUEma972zKTh18Cf0XIutiqQs3HWY+neiNh0bJMXqKsq+MvlXLmS0CzuGVzsBuKS
         JeeQ==
X-Gm-Message-State: ACgBeo2IL5NrhuNemVDimsXix7aqz6G3YnQMopgSOhAc882lb+umB3dC
	4dCI5Phsr3ZD8GYGUgJ25l0=
X-Google-Smtp-Source: AA6agR6pxk7X0zeqX6k1CE5tlVxIMhij2hE9y1Z6WRByftuOsYJ5o0oNFBqfH9Q3wl2nHKrw/y8z/w==
X-Received: by 2002:a5d:620a:0:b0:21e:5e56:c8b2 with SMTP id y10-20020a5d620a000000b0021e5e56c8b2mr9310693wru.598.1659338817116;
        Mon, 01 Aug 2022 00:26:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e24:b0:3a3:1964:fb7b with SMTP id
 ay36-20020a05600c1e2400b003a31964fb7bls4246192wmb.0.-pod-canary-gmail; Mon,
 01 Aug 2022 00:26:56 -0700 (PDT)
X-Received: by 2002:a05:600c:34c9:b0:3a3:561d:4f32 with SMTP id d9-20020a05600c34c900b003a3561d4f32mr10081361wmq.30.1659338816134;
        Mon, 01 Aug 2022 00:26:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659338816; cv=none;
        d=google.com; s=arc-20160816;
        b=KLEh+YIltOdvsDBP322yQ0ssdWU91iLF07iQtAFNDihgBaTD3wJDhNVrdcyAqA0fHg
         5k5tRDv3c+DAKqPSjoYCxe97lGk344LjQP1MiurY6C144Duvln+WqXkSwRu1lOItvJA6
         0iAnkXTAQpcG4b4az4zw47tfUD2N5PmlH7hrrNee92a7zBUlBJA6byk6znpyxU2puiid
         I2ZWCt9JugJ83eJJ+1Y9JNBs/DCLQUzMcISOpbVZmkhkAtn0FOvJOwYkVjHCFOD20VRM
         QxYcGzGoCuBARSlaHdi9FLOdER/Ub/5KnZg5nqw2jTzubnXxy5RX/IUp9R84JQCboyTA
         qY5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eev/ngFXyxaHBPDnw/5aZRQGPAhtDNUSAfnzXB2KgQc=;
        b=YSSpmDlRP1kEbUYSBAFsoLQ/1ztln/KkEcXOsmUA4QuVG9Z6C/uGLuTN/Dni/p5AnG
         1FFHiX7+4XSqXlOU71COgi1/g2Cdxuqzi2TeJ/8k2c5aPHk8s7UdxocigR7N5eBHIiAe
         GUG/rtp+K4Luv0oUjYI504/0dLd6xHV4zExV/Td8V9MofMtrnsyGnMBu/lEkMHcsr/Ey
         +BekD5wWtCQCv2w7n5XDsxi1RYi+DjYVyZ49J0IfU46h+4O51fhgAXDd5HIbZMYZSjej
         cYwxC3QPpxELZJH9rdyy2mqa+KdX9Ua2ltHq/S31Shs1c5XA9uZ8m/MQa+EcnSAnWgjo
         Ul5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YNAy9BJb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x130.google.com (mail-lf1-x130.google.com. [2a00:1450:4864:20::130])
        by gmr-mx.google.com with ESMTPS id l5-20020a5d6685000000b0021d9f21dd58si389238wru.6.2022.08.01.00.26.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Aug 2022 00:26:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130 as permitted sender) client-ip=2a00:1450:4864:20::130;
Received: by mail-lf1-x130.google.com with SMTP id y11so15923036lfs.6
        for <kasan-dev@googlegroups.com>; Mon, 01 Aug 2022 00:26:56 -0700 (PDT)
X-Received: by 2002:a05:6512:6c8:b0:48a:f375:9ecc with SMTP id
 u8-20020a05651206c800b0048af3759eccmr1952910lff.206.1659338815344; Mon, 01
 Aug 2022 00:26:55 -0700 (PDT)
MIME-Version: 1.0
References: <20220727071042.8796-4-feng.tang@intel.com> <YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020>
 <YuY6Wc39DbL3YmGi@feng-skl> <Yudw5ge/lJ26Hksk@feng-skl>
In-Reply-To: <Yudw5ge/lJ26Hksk@feng-skl>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 1 Aug 2022 09:26:43 +0200
Message-ID: <CACT4Y+Y5aTQMuUU3j60KbLrH_DoFWq1e7EEF5Ka0c1F9a3FniA@mail.gmail.com>
Subject: Re: [mm/slub] 3616799128: BUG_kmalloc-#(Not_tainted):kmalloc_Redzone_overwritten
To: Feng Tang <feng.tang@intel.com>
Cc: "Sang, Oliver" <oliver.sang@intel.com>, Vlastimil Babka <vbabka@suse.cz>, lkp <lkp@intel.com>, 
	LKML <linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"lkp@lists.01.org" <lkp@lists.01.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, "Hansen, Dave" <dave.hansen@intel.com>, 
	Robin Murphy <robin.murphy@arm.com>, John Garry <john.garry@huawei.com>, 
	Kefeng Wang <wangkefeng.wang@huawei.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YNAy9BJb;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 1 Aug 2022 at 08:22, Feng Tang <feng.tang@intel.com> wrote:
>
> On Sun, Jul 31, 2022 at 04:16:53PM +0800, Tang, Feng wrote:
> > Hi Oliver,
> >
> > On Sun, Jul 31, 2022 at 02:53:17PM +0800, Sang, Oliver wrote:
> > >
> > >
> > > Greeting,
> > >
> > > FYI, we noticed the following commit (built with gcc-11):
> > >
> > > commit: 3616799128612e04ed919579e2c7b0dccf6bcb00 ("[PATCH v3 3/3] mm/slub: extend redzone check to cover extra allocated kmalloc space than requested")
> > > url: https://github.com/intel-lab-lkp/linux/commits/Feng-Tang/mm-slub-some-debug-enhancements/20220727-151318
> > > base: git://git.kernel.org/cgit/linux/kernel/git/vbabka/slab.git for-next
> > > patch link: https://lore.kernel.org/linux-mm/20220727071042.8796-4-feng.tang@intel.com
> > >
> > > in testcase: boot
> > >
> > > on test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
> > >
> > > caused below changes (please refer to attached dmesg/kmsg for entire log/backtrace):
> > >
> > >
> > > If you fix the issue, kindly add following tag
> > > Reported-by: kernel test robot <oliver.sang@intel.com>
> > >
> > >
> > > [   50.637839][  T154] =============================================================================
> > > [   50.639937][  T154] BUG kmalloc-16 (Not tainted): kmalloc Redzone overwritten
> > > [   50.641291][  T154] -----------------------------------------------------------------------------
> > > [   50.641291][  T154]
> > > [   50.643617][  T154] 0xffff88810018464c-0xffff88810018464f @offset=1612. First byte 0x7 instead of 0xcc
> > > [   50.645311][  T154] Allocated in __sdt_alloc+0x258/0x457 age=14287 cpu=0 pid=1
> > > [   50.646584][  T154]  ___slab_alloc+0x52b/0x5b6
> > > [   50.647411][  T154]  __slab_alloc+0x1a/0x22
> > > [   50.648374][  T154]  __kmalloc_node+0x10c/0x1e1
> > > [   50.649237][  T154]  __sdt_alloc+0x258/0x457
> > > [   50.650060][  T154]  build_sched_domains+0xae/0x10e8
> > > [   50.650981][  T154]  sched_init_smp+0x30/0xa5
> > > [   50.651805][  T154]  kernel_init_freeable+0x1c6/0x23b
> > > [   50.652767][  T154]  kernel_init+0x14/0x127
> > > [   50.653594][  T154]  ret_from_fork+0x1f/0x30
> > > [   50.654414][  T154] Slab 0xffffea0004006100 objects=28 used=28 fp=0x0000000000000000 flags=0x1fffc0000000201(locked|slab|node=0|zone=1|lastcpupid=0x3fff)
> > > [   50.656866][  T154] Object 0xffff888100184640 @offset=1600 fp=0xffff888100184520
> > > [   50.656866][  T154]
> > > [   50.658410][  T154] Redzone  ffff888100184630: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  ................
> > > [   50.660047][  T154] Object   ffff888100184640: 00 32 80 00 81 88 ff ff 01 00 00 00 07 00 80 8a  .2..............
> > > [   50.661837][  T154] Redzone  ffff888100184650: cc cc cc cc cc cc cc cc                          ........
> > > [   50.663454][  T154] Padding  ffff8881001846b4: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a              ZZZZZZZZZZZZ
> > > [   50.665225][  T154] CPU: 0 PID: 154 Comm: systemd-udevd Not tainted 5.19.0-rc5-00010-g361679912861 #1
> > > [   50.666861][  T154] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.0-debian-1.16.0-4 04/01/2014
> > > [   50.668694][  T154] Call Trace:
> > > [   50.669331][  T154]  <TASK>
> > > [   50.669832][  T154]  dump_stack_lvl+0x57/0x7d
> > > [   50.670601][  T154]  check_bytes_and_report+0xca/0xfe
> > > [   50.671436][  T154]  check_object+0xdc/0x24d
> > > [   50.672163][  T154]  free_debug_processing+0x98/0x210
> > > [   50.673904][  T154]  __slab_free+0x46/0x198
> > > [   50.675746][  T154]  qlist_free_all+0xae/0xde
> > > [   50.676552][  T154]  kasan_quarantine_reduce+0x10d/0x145
> > > [   50.677507][  T154]  __kasan_slab_alloc+0x1c/0x5a
> > > [   50.678327][  T154]  slab_post_alloc_hook+0x5a/0xa2
> > > [   50.680069][  T154]  kmem_cache_alloc+0x102/0x135
> > > [   50.680938][  T154]  getname_flags+0x4b/0x314
> > > [   50.681781][  T154]  do_sys_openat2+0x7a/0x15c
> > > [   50.706848][  T154] Disabling lock debugging due to kernel taint
> > > [   50.707913][  T154] FIX kmalloc-16: Restoring kmalloc Redzone 0xffff88810018464c-0xffff88810018464f=0xcc
> >
> > Thanks for the report!
> >
> > From the log it happened when kasan is enabled, and my first guess is
> > the data processing from kmalloc redzone handling had some conflict
> > with kasan's in allocation path (though I tested some kernel config
> > with KASAN enabled)
> >
> > Will study more about kasan and reproduce/debug this. thanks
>
> Cc kansan  mail list.
>
> This is really related with KASAN debug, that in free path, some
> kmalloc redzone ([orig_size+1, object_size]) area is written by
> kasan to save free meta info.
>
> The callstack is:
>
>   kfree
>     slab_free
>       slab_free_freelist_hook
>           slab_free_hook
>             __kasan_slab_free
>               ____kasan_slab_free
>                 kasan_set_free_info
>                   kasan_set_track
>
> And this issue only happens with "kmalloc-16" slab. Kasan has 2
> tracks: alloc_track and free_track, for x86_64 test platform, most
> of the slabs will reserve space for alloc_track, and reuse the
> 'object' area for free_track.  The kasan free_track is 16 bytes
> large, that it will occupy the whole 'kmalloc-16's object area,
> so when kmalloc-redzone is enabled by this patch, the 'overwritten'
> error is triggered.
>
> But it won't hurt other kmalloc slabs, as kasan's free meta won't
> conflict with kmalloc-redzone which stay in the latter part of
> kmalloc area.
>
> So the solution I can think of is:
> * skip the kmalloc-redzone for kmalloc-16 only, or
> * skip kmalloc-redzone if kasan is enabled, or
> * let kasan reserve the free meta (16 bytes) outside of object
>   just like for alloc meta

/\/\/\

Please just not the last option. Memory consumption matters.

I would do whatever is the simplest, e.g. skip the check for
kmalloc-16 when KASAN is enabled.
Or does it make sense to prohibit KASAN+SLUB_DEBUG combination? Does
SLUB_DEBUG add anything on top of KASAN?


> I don't have way to test kasan's SW/HW tag configuration, which
> is only enabled on arm64 now. And I don't know if there will
> also be some conflict.
>
> Thanks,
> Feng
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY5aTQMuUU3j60KbLrH_DoFWq1e7EEF5Ka0c1F9a3FniA%40mail.gmail.com.
