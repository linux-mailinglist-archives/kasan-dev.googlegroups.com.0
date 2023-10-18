Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3WGX2UQMGQEDODT7EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id C865D7CD7C1
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 11:20:47 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2c520e0a9a7sf30248311fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 02:20:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697620847; cv=pass;
        d=google.com; s=arc-20160816;
        b=aK/+N6ma3nQy/xw0LhX6QLco5nUPvamNKquADgDQ4WECS1bD3u+7EduJShUQ9aoeTy
         sdqgVu9l/T/ey3awugPXXH6ioYV+1Ur6bq3rS8CLjIEFGiaEUHvfiOXnXWtcThHKXfZm
         5wuk+3lsk74HHBLR6cwn5lc8Hv6X3cBYjcRX1XazKtSmHlINUERMkhmYHmNzy7orl26C
         twFGsvp+VPtd8LD1zn27efI8t3OhaaL8jSIeLtpPotv6ftwj3I5QpcDkf4frg9yMliUo
         l1jaq1iXsNLa/grtIR+UKXyStr5atufeY0BD2uhStlo71bJz78aHH2L8/DhD6zePDK+9
         z8Iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=wUo3nsNMTZ0WnEZBV+gR6pgbxiLAW/uJ+RW1vgX1JeU=;
        fh=0roVdipoeN4r45Hjdg/dZfsCHmuK3kUwdfqvizpdnts=;
        b=f5lRiAIN6owPRlw0vahaonn4TvHkLIAbKLfOgRGhKo7v0cGZp0YxJfA0B3QWbGg2gH
         s3BTFaGf3nVMF+yDyOIGokQ2yHy3iq+SUtJ5ooca8K6CIC0n7y8okX6DzoWh3Nnnblg5
         VBV0bLULZGLjGy7OxRdV+1Z4si787IbzIWXQ9VRXr9NTOTeEWm7PmPMsMQ9hlbrMlPfE
         jbvXI5WzrN69aWBAT0qSoZjQ5xBsWMLuiDM55Sd+YliqcQcBjBB6m6EZLEL0TOlzAqGA
         A3ISViZ9Md9/Y7XSgBAVusCo6uew/rijnTdd4ZROT8Xs621dB1jOwHZvYg66PZz84pLj
         rc+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MMoEyh65;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697620847; x=1698225647; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=wUo3nsNMTZ0WnEZBV+gR6pgbxiLAW/uJ+RW1vgX1JeU=;
        b=Dw3hPxOJ9bTEjbPSIhWoFGsznnDpfeKndwM2HktkZtSz6KHh+ZKcY/HfDZX2Mya+0Y
         b+PC2/W9bn9Lyg1ltglk6W+hfYKmIid9GjFJ6e5jv/+TyvETNsVexVW1eDaKPSeupHgs
         z0sE7rR/9inaqaSyYhn9mSBPE1krk5UByZQ1tpU7rAHu0CO/zIP4UwmlDUAXqoJ+3Ed/
         sL2Eo2dPfWjYYOtXCyxS6YOTkl+bE5OCXcQK3vZfv27pqcZhnBgs02VLXGwo58ht1/u0
         yr8fRiBoSXXtfBbQM6ow+La6QTbCyLtG1cpWA0Kc7j+TzW9njn26m8FGl1oC5JXXhojy
         /0Kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697620847; x=1698225647;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wUo3nsNMTZ0WnEZBV+gR6pgbxiLAW/uJ+RW1vgX1JeU=;
        b=LeE0H4purTCNpOpR4Tcee7lm2iW9RMlgMzclUPHpd0PsjvFoYJr3JaB/GF2+nL1KZN
         HZbc/1BUF2vlMW4RZrr1BgppswL9SMnV2l9Z85KpR4nKLYlkYjK+9+7R+xbw305rp3JE
         37kwgyyAz5gHzaENrPYYVHWaiu6nxW0pW3VS53Va8Oa1c0yICUFVYcSe9HgvIqo9+iSR
         GP1MbbfFnIvarv0LUmT5HPVlYteKZblyl6uwzIXtpmudQvnQ1tcMKp1hfBJPiRXDaVHA
         jjEIaobjeptMfULZ5eUgyXpcmJ+C088IBamzSEn28uZG7c64iJt6sEdP86Gg3UL2QaBv
         I+sg==
X-Gm-Message-State: AOJu0YxDag0f/eb1QR/h7GbTjnnOuCk5wE8V/Xv0DcOhaloUBt30tJ+y
	8uqkFWRgiSr/TJqkHwI9D3A=
X-Google-Smtp-Source: AGHT+IEJRtaHyIge8es+Kkz99lt/e68D8nM2tLUdJbNv0sA6LSs3XklgGuPufsO2yKqy8bvhv5RKOg==
X-Received: by 2002:a2e:5411:0:b0:2c5:d3c:8f4d with SMTP id i17-20020a2e5411000000b002c50d3c8f4dmr3339658ljb.13.1697620846568;
        Wed, 18 Oct 2023 02:20:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8e32:0:b0:2bf:f55d:1df9 with SMTP id r18-20020a2e8e32000000b002bff55d1df9ls137223ljk.1.-pod-prod-05-eu;
 Wed, 18 Oct 2023 02:20:44 -0700 (PDT)
X-Received: by 2002:ac2:46d4:0:b0:503:3421:4ebd with SMTP id p20-20020ac246d4000000b0050334214ebdmr3323027lfo.63.1697620844404;
        Wed, 18 Oct 2023 02:20:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697620844; cv=none;
        d=google.com; s=arc-20160816;
        b=yEAuRLAfjem/llWANrVQI20GTXMw687gsxhVGfIR+731LfzO0OFW0num4dhHxAmqBQ
         MbaU7+UB1/RhoMk0PiwVKrQesCAAwqsdGKsrb9o/0tGzW+Okdv+d2ZfYEDVUQkQQaBY1
         uH/MYFqebd4goEOr2zLIByXxsk39WJmj3yZ94FS5mSVg9W1Ex4SxN1b+7kIoaAYKVa5c
         JXMOsWWy0azsdjJYG+eTtmDjR9MqO0GRWCXdE8tCf4Fd4h5679LNYaVojspCKJVylcfS
         nIsy0yu1eh34/fE9ouiOdq9l9sEKotCaeIzhFUUB1HpkKbaUEFtHnNIoFK80eBFXXPhl
         Sstg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9ewrMPyx4pJfcubjcrEJa/asBuC5oD61em5IsCdml64=;
        fh=0roVdipoeN4r45Hjdg/dZfsCHmuK3kUwdfqvizpdnts=;
        b=EkVG5/4/Z5YSpCgJdl0yxiNqyw5lzRp3vcX9wvNB49ZOYH/eJfKgJot3EhK71spkvF
         x3XwhjhOHS3OCdhe0jjLp0sEAAMyzlxDZRNqH36Z3sXjfGsz/YZqZtL7/qoFnbmjIGQ8
         +urqlQZjHG0z7PHggcckj+lSDxBmRIeEVbgzw806SnLT2CUr1O0Dhc03kb4RagVuSfjo
         0i48QP4foFgZ3dEsyxhQD6j7N54Bd8605GS8cedOS01xjRC6Y/gbakbrM8cGBrzXfUh3
         iWTsLZQpNjV6SHgaPkA4Hpf9ibM4l7tFMEanvPY5AcO0KRcW9eB1n60Op0WZAgmpC2rs
         QXPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MMoEyh65;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id b11-20020ac2562b000000b005056618eed7si122593lff.4.2023.10.18.02.20.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Oct 2023 02:20:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-408002b5b9fso11260335e9.3
        for <kasan-dev@googlegroups.com>; Wed, 18 Oct 2023 02:20:44 -0700 (PDT)
X-Received: by 2002:a05:600c:4f49:b0:405:3b1f:968b with SMTP id m9-20020a05600c4f4900b004053b1f968bmr3664452wmq.21.1697620843537;
        Wed, 18 Oct 2023 02:20:43 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:8d0f:ea49:93ba:ca57])
        by smtp.gmail.com with ESMTPSA id c39-20020a05600c4a2700b0040588d85b3asm1117664wmp.15.2023.10.18.02.20.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Oct 2023 02:20:43 -0700 (PDT)
Date: Wed, 18 Oct 2023 11:20:37 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: syzbot <syzbot+59f37b0ab4c558a5357c@syzkaller.appspotmail.com>,
	Muchun Song <muchun.song@linux.dev>
Cc: akpm@linux-foundation.org, dvyukov@google.com, glider@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, syzkaller-bugs@googlegroups.com,
	Andrey Konovalov <andreyknvl@gmail.com>
Subject: Re: [syzbot] [mm?] [kasan?] WARNING in __kfence_free (3)
Message-ID: <ZS-jZQFcQwb8o8qs@elver.google.com>
References: <000000000000bc90a60607f41fc3@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <000000000000bc90a60607f41fc3@google.com>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MMoEyh65;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Oct 17, 2023 at 07:09PM -0700, syzbot wrote:
> Hello,
> 
> syzbot found the following issue on:
> 
> HEAD commit:    213f891525c2 Merge tag 'probes-fixes-v6.6-rc6' of git://gi..
> git tree:       upstream
> console output: https://syzkaller.appspot.com/x/log.txt?x=14a731f9680000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=a4436b383d761e86
> dashboard link: https://syzkaller.appspot.com/bug?extid=59f37b0ab4c558a5357c
> compiler:       aarch64-linux-gnu-gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40
> userspace arch: arm64
> 
> Unfortunately, I don't have any reproducer for this issue yet.
> 
> Downloadable assets:
> disk image (non-bootable): https://storage.googleapis.com/syzbot-assets/384ffdcca292/non_bootable_disk-213f8915.raw.xz
> vmlinux: https://storage.googleapis.com/syzbot-assets/98b9a78b6226/vmlinux-213f8915.xz
> kernel image: https://storage.googleapis.com/syzbot-assets/8ed2ef54968f/Image-213f8915.gz.xz
> 
> IMPORTANT: if you fix the issue, please add the following tag to the commit:
> Reported-by: syzbot+59f37b0ab4c558a5357c@syzkaller.appspotmail.com
> 
> ------------[ cut here ]------------
> WARNING: CPU: 1 PID: 3252 at mm/kfence/core.c:1147 __kfence_free+0x7c/0xb4 mm/kfence/core.c:1147

This has happened before:
https://lore.kernel.org/all/FC29C538-1446-4A3F-A6FA-857295D7DEB3@linux.dev/T/#u

And is this warning:

	| void __kfence_free(void *addr)
	| {
	| 	struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
	| 
	| #ifdef CONFIG_MEMCG
	| 	KFENCE_WARN_ON(meta->objcg);           <--------
	| #endif

Which is this assembly in the vmlinux provided by syzbot:

	ffff8000802bed9c: 22 40 42 f9   ldr     x2, [x1, #1152]
	ffff8000802beda0: 02 fe ff b4   cbz     x2, 0xffff8000802bed60 <__kfence_free+0x38>
	ffff8000802beda4: 00 00 21 d4   brk     #0x800

So we know the pointer is in x2, and from the below we know it's fcff000006a24ec0.

Muchun, last time you said:

> Maybe we could improve the warning message,
> e.g. print the current value of "meta->objcg".

Does this somehow help you better understand what's going on?

Also this is a KASAN_HW_TAGS instance (using arm64 MTE), not sure that's
relevant though.

> Modules linked in:
> CPU: 1 PID: 3252 Comm: syz-executor.1 Not tainted 6.6.0-rc6-syzkaller-00029-g213f891525c2 #0
> Hardware name: linux,dummy-virt (DT)
> pstate: 81400009 (Nzcv daif +PAN -UAO -TCO +DIT -SSBS BTYPE=--)
> pc : __kfence_free+0x7c/0xb4 mm/kfence/core.c:1147
> lr : kfence_free include/linux/kfence.h:187 [inline]
> lr : __slab_free+0x48c/0x508 mm/slub.c:3614
> sp : ffff800082cebb50
> x29: ffff800082cebb50 x28: f7ff000002c0c400 x27: ffff8000818ca8a8
> x26: ffff8000821f0620 x25: 0000000000000001 x24: ffff00007ffa3000
> x23: 0000000000000001 x22: ffff00007ffa3000 x21: ffff00007ffa3000
> x20: ffff80008004191c x19: fffffc0001ffe8c0 x18: ffffffffffffffff
> x17: ffff800080027b40 x16: ffff800080027a34 x15: ffff800080318514
> x14: ffff8000800469c8 x13: ffff800080011558 x12: ffff800081897ff4
> x11: ffff800081897b28 x10: ffff800080027bfc x9 : 0000000000400cc0
> x8 : ffff800082cebc30 x7 : 0000000000000000 x6 : 0000000000000000
> x5 : ffff80008004191c x4 : ffff00007f869000 x3 : ffff800082420338
> x2 : fcff000006a24ec0 x1 : ffff00007f8a50a0 x0 : ffff00007ffa3000
> Call trace:
>  __kfence_free+0x7c/0xb4 mm/kfence/core.c:1147
>  kfence_free include/linux/kfence.h:187 [inline]
>  __slab_free+0x48c/0x508 mm/slub.c:3614
>  do_slab_free mm/slub.c:3757 [inline]
>  slab_free mm/slub.c:3810 [inline]
>  __kmem_cache_free+0x220/0x230 mm/slub.c:3822
>  kfree+0x5c/0x74 mm/slab_common.c:1072
>  kvm_uevent_notify_change.part.0+0x10c/0x174 arch/arm64/kvm/../../../virt/kvm/kvm_main.c:5908
>  kvm_uevent_notify_change arch/arm64/kvm/../../../virt/kvm/kvm_main.c:5878 [inline]
>  kvm_dev_ioctl_create_vm arch/arm64/kvm/../../../virt/kvm/kvm_main.c:5107 [inline]
>  kvm_dev_ioctl+0x3e8/0x91c arch/arm64/kvm/../../../virt/kvm/kvm_main.c:5131
>  vfs_ioctl fs/ioctl.c:51 [inline]
>  __do_sys_ioctl fs/ioctl.c:871 [inline]
>  __se_sys_ioctl fs/ioctl.c:857 [inline]
>  __arm64_sys_ioctl+0xac/0xf0 fs/ioctl.c:857
>  __invoke_syscall arch/arm64/kernel/syscall.c:37 [inline]
>  invoke_syscall+0x48/0x114 arch/arm64/kernel/syscall.c:51
>  el0_svc_common.constprop.0+0x40/0xe0 arch/arm64/kernel/syscall.c:136
>  do_el0_svc+0x1c/0x28 arch/arm64/kernel/syscall.c:155
>  el0_svc+0x40/0x114 arch/arm64/kernel/entry-common.c:678
>  el0t_64_sync_handler+0x100/0x12c arch/arm64/kernel/entry-common.c:696
>  el0t_64_sync+0x19c/0x1a0 arch/arm64/kernel/entry.S:595
> ---[ end trace 0000000000000000 ]---

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZS-jZQFcQwb8o8qs%40elver.google.com.
