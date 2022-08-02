Return-Path: <kasan-dev+bncBCMIZB7QWENRBQUWUOLQMGQE4MYKICQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2ACC358775B
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 08:59:15 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id i17-20020adfaad1000000b0021ecb856a71sf3176806wrc.4
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Aug 2022 23:59:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659423554; cv=pass;
        d=google.com; s=arc-20160816;
        b=mIo3gRCLg5zml6Mz3WnixxdVxlI6m5wEVUb8ogprjIUGqvAq3f7lxUAiOwpsOor1AC
         V5TtKEF72mA3ObCNw56t1iVNLqV39mkKDV72+l2mHSGB9X3ahDGxjjVRNkdwNOk7pSXQ
         ECQTV+5VG0wYjXZdIBmV9CcvWRQma1gREQkjYy0fevrdGnptc1ZrTayXJxBtXQx6E5y5
         K+bg9cYsKBQLPGeUy/Jz7woffmklwrXheRPrL4mELWvJ/kFM01/cGBkgdOuvef3NtQCa
         F0xxg8RBdBc5EqBBVP8Y79VE+vjd7t5EYrcuYHVA9wEIXpEqDmZduuyWaNC5JtlcAJ0v
         1wUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ceErebFOkY+0lZCDp76M78eLJOPpV6wESmXGf1Wed3A=;
        b=evZ+FGmN89czlRQo2bF/zT2XAvgozYVIbivufkZfQ5/fbQLDHGQMANzkOlfHPM135R
         kcbdyXNMXI4BLJuDGbajhtnVnTSpZhDqOI7LlP0yQ0fGlI1BEybeLKmXDFqH7wZDLcpJ
         U6cXq8MA2fW23UhaudW1FFf84uU88J7ISfey4MzPaCxRnOAxUrDgYoz7H/9bD9kNoHkw
         ghK7K/neVk9KHoTF39XnOkqQicZAP/nOV1r39cjdbuOU5qtwFWPc55taK+AKLDAn7dqc
         f2LTgyLQslvEyFbbVEqnTjcV6uvAy5/Yyx41p/cQQUwx1RU2Qw6L4apYnhdUZdD2umyu
         apAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aCdRHTiQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ceErebFOkY+0lZCDp76M78eLJOPpV6wESmXGf1Wed3A=;
        b=OHgswGLJl2QbFu47cDx87vz1KT2/eXve86P6AA/SQayE397advwm4/GhQGzEM85kOo
         CC8NYLzcvWouz98h6zfnbGCcuMfMj6UJ3BS92vKSo4XYEr0uoAlutnna+Dr/+jLeik5F
         PXPojwXHrmnmgp4fMKB1aLQEfqfJXx5k/f6ZfHRN+Q5XhPNrDaN3cPqx723cDJMHiL50
         snLCj+FYS6DHn/q7WVN6wXJohVDZLYdOsicobYk9kPa0anGRIBPZ8yog0z2DwkmtUfXh
         svSUoZJkqZE6HrwJ/GAgEIZQahDxtu9hxzWDFp6RoUoZ4++jsMOxqZk3TKGag6qlyb1z
         yqJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ceErebFOkY+0lZCDp76M78eLJOPpV6wESmXGf1Wed3A=;
        b=bqTBQevbFmX9BFnJnKbkg63gTBIQ+17N5LbKnf8sW2/uIo8aq6Z9TcqdKYsG8tjgHh
         YBFtw+Y3GVpR+8Efp7evqW/2jfBuj2nYFbeKvrtE9S8cl8FlWoq+ETuujdr4MFksP7Bg
         AbUOphv5ksXqYc6UJ6rBHKWcnLW5riN+kDEMhCRCoCJw4iiwrglUHXHCB2PiTC0w3G3n
         ZX3pyveWKoGv9719468MS923TpWJBPit8nIK5W4ahKqsMoQAIHmvJqhpr2t8lOt6ZE4o
         4z5t2sp3xwi1SQO6miB+W5UtlZQE4Rz1gOddYVFQX13mqxjoQPlMMhZ9x7kxPAH0Idck
         BEhw==
X-Gm-Message-State: ACgBeo1mYpUGx5QeuzG7SLSgDXcXzLH+tjCf4DRjKGU52s1pG/OTo4SQ
	7lY2oDXXa5CM1lUsLIBc3Q4=
X-Google-Smtp-Source: AA6agR5unkCYY9Zt4V24J7IXgeIHui204bEsMP+9qz9qXijYW2AeqZiMjuLcoOUJkv7MYycvZAXWAw==
X-Received: by 2002:a5d:5986:0:b0:220:6871:de88 with SMTP id n6-20020a5d5986000000b002206871de88mr3643151wri.469.1659423554755;
        Mon, 01 Aug 2022 23:59:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:605:b0:21e:d303:d51 with SMTP id
 bn5-20020a056000060500b0021ed3030d51ls15640802wrb.2.-pod-prod-gmail; Mon, 01
 Aug 2022 23:59:13 -0700 (PDT)
X-Received: by 2002:a5d:5888:0:b0:21e:5c76:8e18 with SMTP id n8-20020a5d5888000000b0021e5c768e18mr12165653wrf.230.1659423553728;
        Mon, 01 Aug 2022 23:59:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659423553; cv=none;
        d=google.com; s=arc-20160816;
        b=BXbkpk4oF0KZcXHTGPBqeNWFeredIyKJcjRltFahOkCFsQBo2jTgqyTvb9xpFQAxeI
         g9g5qiWnASNBkAhSUTWB2rUdE4wAzpKuufXp9+olWN791gP2on9nIkM77uD1v/HnqSpJ
         q98O0k3eSYMFkKW0+7Png/Wotr34KJ7pq69wNCPWAAYI+VCd4ooFRA6utuQ/hboKAj3h
         POv1Sw8RxoQhrYit0PFmTBghGtxDg966UA5j5h+szBLl4J4J8Jm2f07EKpKn6ljgcvy6
         mEX5MzUWbQDqfqUixPj0Gx0TKv4yUuy6mylgpqt3IoiYWIfDMzuppiRs7jY2c7ZBaPyB
         obrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=O6Pyr8Fl9p6t8WEJ0ab3NlyF43bwbAF4/cHexI37Gdo=;
        b=aqBk3+LcmuQdV+TjeRzy/pjoSR19UXlHvFPA2ZsAsKS2Ob2fdYRgGuTLEPaA11Y7DQ
         SUykTbNTDscV5qOORSUY4NW3ZFhuSGk2UUMlF9IkA0a1vmr9CwmHq4iQJimieEODXDUa
         zkfh/pFqKVP33Qm/IiR3laSags0IE+d+UPYfYpbkkHcVrw+njxAz2WBRaXznfC1LTbIU
         0q0f5st2tkOa1GNTW/f6leV9GKXn1ZiwaUeP+9Q/wAh/9AtDS64hwY66dXUQ6ofCuIO+
         6MeqtiGyF91UfJanYBv1+w3ell2peZtcUc5EWYid2cOx7UANDAjc7OMLcOGAP8QwFbrR
         czlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aCdRHTiQ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x136.google.com (mail-lf1-x136.google.com. [2a00:1450:4864:20::136])
        by gmr-mx.google.com with ESMTPS id bk21-20020a0560001d9500b0021f15aa1a8esi328363wrb.8.2022.08.01.23.59.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Aug 2022 23:59:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136 as permitted sender) client-ip=2a00:1450:4864:20::136;
Received: by mail-lf1-x136.google.com with SMTP id a9so7826956lfm.12
        for <kasan-dev@googlegroups.com>; Mon, 01 Aug 2022 23:59:13 -0700 (PDT)
X-Received: by 2002:a05:6512:c0b:b0:48a:f3e5:4b3e with SMTP id
 z11-20020a0565120c0b00b0048af3e54b3emr3439438lfu.410.1659423552972; Mon, 01
 Aug 2022 23:59:12 -0700 (PDT)
MIME-Version: 1.0
References: <20220727071042.8796-4-feng.tang@intel.com> <YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020>
 <YuY6Wc39DbL3YmGi@feng-skl> <Yudw5ge/lJ26Hksk@feng-skl> <0e545088-d140-4c84-bbb2-a3be669740b2@suse.cz>
In-Reply-To: <0e545088-d140-4c84-bbb2-a3be669740b2@suse.cz>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Aug 2022 08:59:01 +0200
Message-ID: <CACT4Y+bvLj+qVYXf1fQuf_NKdCzkuDWs5+r-PomTdCU2MOkP5g@mail.gmail.com>
Subject: Re: [mm/slub] 3616799128: BUG_kmalloc-#(Not_tainted):kmalloc_Redzone_overwritten
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Feng Tang <feng.tang@intel.com>, "Sang, Oliver" <oliver.sang@intel.com>, lkp <lkp@intel.com>, 
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
 header.i=@google.com header.s=20210112 header.b=aCdRHTiQ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::136
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

On Mon, 1 Aug 2022 at 16:23, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> On 8/1/22 08:21, Feng Tang wrote:
> > On Sun, Jul 31, 2022 at 04:16:53PM +0800, Tang, Feng wrote:
> >> Hi Oliver,
> >>
> >> On Sun, Jul 31, 2022 at 02:53:17PM +0800, Sang, Oliver wrote:
> >> >
> >> >
> >> > Greeting,
> >> >
> >> > FYI, we noticed the following commit (built with gcc-11):
> >> >
> >> > commit: 3616799128612e04ed919579e2c7b0dccf6bcb00 ("[PATCH v3 3/3] mm/slub: extend redzone check to cover extra allocated kmalloc space than requested")
> >> > url: https://github.com/intel-lab-lkp/linux/commits/Feng-Tang/mm-slub-some-debug-enhancements/20220727-151318
> >> > base: git://git.kernel.org/cgit/linux/kernel/git/vbabka/slab.git for-next
> >> > patch link: https://lore.kernel.org/linux-mm/20220727071042.8796-4-feng.tang@intel.com
> >> >
> >> > in testcase: boot
> >> >
> >> > on test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -m 16G
> >> >
> >> > caused below changes (please refer to attached dmesg/kmsg for entire log/backtrace):
> >> >
> >> >
> >> > If you fix the issue, kindly add following tag
> >> > Reported-by: kernel test robot <oliver.sang@intel.com>
> >> >
> >> >
> >> > [   50.637839][  T154] =============================================================================
> >> > [   50.639937][  T154] BUG kmalloc-16 (Not tainted): kmalloc Redzone overwritten
> >> > [   50.641291][  T154] -----------------------------------------------------------------------------
> >> > [   50.641291][  T154]
> >> > [   50.643617][  T154] 0xffff88810018464c-0xffff88810018464f @offset=1612. First byte 0x7 instead of 0xcc
> >> > [   50.645311][  T154] Allocated in __sdt_alloc+0x258/0x457 age=14287 cpu=0 pid=1
> >> > [   50.646584][  T154]  ___slab_alloc+0x52b/0x5b6
> >> > [   50.647411][  T154]  __slab_alloc+0x1a/0x22
> >> > [   50.648374][  T154]  __kmalloc_node+0x10c/0x1e1
> >> > [   50.649237][  T154]  __sdt_alloc+0x258/0x457
> >> > [   50.650060][  T154]  build_sched_domains+0xae/0x10e8
> >> > [   50.650981][  T154]  sched_init_smp+0x30/0xa5
> >> > [   50.651805][  T154]  kernel_init_freeable+0x1c6/0x23b
> >> > [   50.652767][  T154]  kernel_init+0x14/0x127
> >> > [   50.653594][  T154]  ret_from_fork+0x1f/0x30
> >> > [   50.654414][  T154] Slab 0xffffea0004006100 objects=28 used=28 fp=0x0000000000000000 flags=0x1fffc0000000201(locked|slab|node=0|zone=1|lastcpupid=0x3fff)
> >> > [   50.656866][  T154] Object 0xffff888100184640 @offset=1600 fp=0xffff888100184520
> >> > [   50.656866][  T154]
> >> > [   50.658410][  T154] Redzone  ffff888100184630: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  ................
> >> > [   50.660047][  T154] Object   ffff888100184640: 00 32 80 00 81 88 ff ff 01 00 00 00 07 00 80 8a  .2..............
> >> > [   50.661837][  T154] Redzone  ffff888100184650: cc cc cc cc cc cc cc cc                          ........
> >> > [   50.663454][  T154] Padding  ffff8881001846b4: 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a              ZZZZZZZZZZZZ
> >> > [   50.665225][  T154] CPU: 0 PID: 154 Comm: systemd-udevd Not tainted 5.19.0-rc5-00010-g361679912861 #1
> >> > [   50.666861][  T154] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.0-debian-1.16.0-4 04/01/2014
> >> > [   50.668694][  T154] Call Trace:
> >> > [   50.669331][  T154]  <TASK>
> >> > [   50.669832][  T154]  dump_stack_lvl+0x57/0x7d
> >> > [   50.670601][  T154]  check_bytes_and_report+0xca/0xfe
> >> > [   50.671436][  T154]  check_object+0xdc/0x24d
> >> > [   50.672163][  T154]  free_debug_processing+0x98/0x210
> >> > [   50.673904][  T154]  __slab_free+0x46/0x198
> >> > [   50.675746][  T154]  qlist_free_all+0xae/0xde
> >> > [   50.676552][  T154]  kasan_quarantine_reduce+0x10d/0x145
> >> > [   50.677507][  T154]  __kasan_slab_alloc+0x1c/0x5a
> >> > [   50.678327][  T154]  slab_post_alloc_hook+0x5a/0xa2
> >> > [   50.680069][  T154]  kmem_cache_alloc+0x102/0x135
> >> > [   50.680938][  T154]  getname_flags+0x4b/0x314
> >> > [   50.681781][  T154]  do_sys_openat2+0x7a/0x15c
> >> > [   50.706848][  T154] Disabling lock debugging due to kernel taint
> >> > [   50.707913][  T154] FIX kmalloc-16: Restoring kmalloc Redzone 0xffff88810018464c-0xffff88810018464f=0xcc
> >>
> >> Thanks for the report!
> >>
> >> From the log it happened when kasan is enabled, and my first guess is
> >> the data processing from kmalloc redzone handling had some conflict
> >> with kasan's in allocation path (though I tested some kernel config
> >> with KASAN enabled)
> >>
> >> Will study more about kasan and reproduce/debug this. thanks
> >
> > Cc kansan  mail list.
> >
> > This is really related with KASAN debug, that in free path, some
> > kmalloc redzone ([orig_size+1, object_size]) area is written by
> > kasan to save free meta info.
> >
> > The callstack is:
> >
> >   kfree
> >     slab_free
> >       slab_free_freelist_hook
> >           slab_free_hook
> >             __kasan_slab_free
> >               ____kasan_slab_free
> >                 kasan_set_free_info
> >                   kasan_set_track
> >
> > And this issue only happens with "kmalloc-16" slab. Kasan has 2
> > tracks: alloc_track and free_track, for x86_64 test platform, most
> > of the slabs will reserve space for alloc_track, and reuse the
> > 'object' area for free_track.  The kasan free_track is 16 bytes
> > large, that it will occupy the whole 'kmalloc-16's object area,
> > so when kmalloc-redzone is enabled by this patch, the 'overwritten'
> > error is triggered.
> >
> > But it won't hurt other kmalloc slabs, as kasan's free meta won't
> > conflict with kmalloc-redzone which stay in the latter part of
> > kmalloc area.
> >
> > So the solution I can think of is:
> > * skip the kmalloc-redzone for kmalloc-16 only, or
> > * skip kmalloc-redzone if kasan is enabled, or
> > * let kasan reserve the free meta (16 bytes) outside of object
> >   just like for alloc meta
>
> Maybe we could add some hack that if both kasan and SLAB_STORE_USER is
> enabled, we bump the stored orig_size from <16 to 16? Similar to what
> __ksize() does.

This looks like the simplest workaround. And with a proper comment I
think it's fine.


> > I don't have way to test kasan's SW/HW tag configuration, which
> > is only enabled on arm64 now. And I don't know if there will
> > also be some conflict.
> >
> > Thanks,
> > Feng
> >
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbvLj%2BqVYXf1fQuf_NKdCzkuDWs5%2Br-PomTdCU2MOkP5g%40mail.gmail.com.
