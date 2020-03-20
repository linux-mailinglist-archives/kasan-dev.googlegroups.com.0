Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBFEP2PZQKGQE2FFCSNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F71418CF1B
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Mar 2020 14:39:33 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id n25sf2387352wmi.5
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Mar 2020 06:39:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584711573; cv=pass;
        d=google.com; s=arc-20160816;
        b=ewniYYIczpjIkqCRpXkGbFhzG889UQ/152ccw5UQD8Ujgjr8j5QnTnXFvwvP+w4kCm
         iXWF5JbusvHuVwA9428wJXFx420OxeZYyTLpKa2uKlUbM4ee4W5HWPKGa2D2V+hum3lb
         /uDMU/3de2q3LXncj2HM5E+0FKnnMGMC3q6Ktr+A4NwJvvIj+sbDZqrLY/nOMce2zTl4
         Q1jCuUn2Rizb/844qovul98wgrV9qfcn8L03qVXmkXapfP9BxkbaZcMlRPNkgdScXvbu
         GP9QsnPpnK53kyge2QKVmF3wuRZ8/IWdFZgTOkXXOiTAs1MKR9MamBchvSYMqmvCQ7hw
         HDRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=QqSFIBojoXBcdo2V74Xjyb+S0dACvTlhNN9hW1wCnMw=;
        b=P6oxdzMjXrMj1SikTY2RKG/aAOIlQPbdtm6Nwx3prOc5yz0uDWIcQzZffRccmBBS0F
         Y13GpoSeJu8VgiYy4QzlaBKd2cRyQKL5z7w+5YXbj2sUhzQZeagV3BR93s1GsE5kmPNs
         mncswIl+1lBp3MHvaMHl4j1c1zU/QIVVWJ5fKBeGCnaDjGydMpNExAeDYwpHNk39D/Pq
         axZQLSX/a7DqxgFXdiJ6CQDp2QW//9ZEgXL6xS+nuBqxHRS3kGiHxI8IReRz3734bwHJ
         g4z2MdrwCslf1OCLgEUKzX3+I55WWM7ClDs9Zp8eVW6nfpilITbKejXBc/UVCCaG0aaU
         pN0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QqSFIBojoXBcdo2V74Xjyb+S0dACvTlhNN9hW1wCnMw=;
        b=AC/EXscMa6Wm2eDncmoziKoYvMs/4Gn8TuGFh8fFcx/rzfxrfci3SI7M+sltpMicnW
         399ZgpQ8nolX0nsRsZRmsv9IL4k+F1i1GIFA2Nk+G3xZ+BeDZ/PEkfS7SjymGov9lTDU
         xUD58adJtfH7Uc3kxt8/pifVHahc6PnL1rFcreQLanFa6V+0eRb0xVUpLM7hao0ZcyJp
         2FLBOwdVReL0gfqZQUXVZcpjgfRifKFfJA0c+Tc2huQf1/Xec2Kmw5hW3+KDC1/2PKAH
         HkMnZiYW7LH8m8luqekcSH2NOADAp5Xwn6w26gakMqHQ3Farkib5bzeqHECpDJjPTRLF
         wBqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QqSFIBojoXBcdo2V74Xjyb+S0dACvTlhNN9hW1wCnMw=;
        b=YwvpH7+/OM+MBhs8CgCG557fkgAmRmfuZJkt6BNClnDE9jj60+4c1karrql9mjYzSn
         ob28FK2uyYC1lc8U4WZxqHGD0SRepBKpd4D1szL9pPJIBZAK3vdzDg9Bx88yW8EVAoBg
         m8ytSIHhaNRPlupg4S+RNi7AoPZCSHu8+gBk5jiU+//6fVRE6W70f1b/2Rd7tIh+make
         lhWBtMIxZ36SvEXeETRsOb2KTFOLvNG84zjn1Dz/7bnl5rlnr5wRMBYArAqITBwz7RYO
         UVyHRNalLxCctLHJOAreZYJW2/synZeE2NzJFbMAwUBgGqB9LESkEjy3A+6U+fUOVs3I
         VVCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ23SgkRZ/u6/NbqKclzgJwLS1561C/DfSzrhqdzXL+8NvQXdWiU
	X3xJr6JDG1ijML9kSEU7Xso=
X-Google-Smtp-Source: ADFU+vtwPxmZECmRa4Vhb/iF7nJY7P738OtPmTAktyoVzi8iXd96JwEVyE66AbXQoHOlPPA7QsTv6g==
X-Received: by 2002:a1c:a78a:: with SMTP id q132mr10410476wme.107.1584711572955;
        Fri, 20 Mar 2020 06:39:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c771:: with SMTP id x17ls3006517wmk.2.canary-gmail; Fri,
 20 Mar 2020 06:39:32 -0700 (PDT)
X-Received: by 2002:a1c:b4d4:: with SMTP id d203mr10487480wmf.85.1584711572381;
        Fri, 20 Mar 2020 06:39:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584711572; cv=none;
        d=google.com; s=arc-20160816;
        b=MdODLiErG+B0QtcGoitkmhlrtACmIMC6cD2LgVAcfi9ZOMjafkiTu0vRU0cNFJfGyz
         4Ozrt67Tz6h5+EWw1/qU3D21nZIuPhDkoCKBu77Mwjc9CPpoJoIk1Fkm5ID0cKQJC8eh
         YMhpFyfbqd/k1UvChzDF0eSkhdf4HsBZndzjBjy/RyfggaMrdGM5dM85ICHX77GULlD7
         AWkzG56N8ayh39+L3nxk8n1O4kd5DJ7hPlBwUod+L2lJ3QBoDuej0Jrr0dYi8sSVVBXs
         dMT+l5mYsYjqmkrS3IP8ibPtP/zKc4QPhgt8C7u18MVBXwWFTPlEwnvcX1vsfaJqXhUW
         YH+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=6QStyEp04Y+OksQjkheHdEz6m+Vo0cZGwh70Bhe3HLs=;
        b=ytxYGHGA7vKo57ZvAdTbxzwxqQ2Zl4TWYs/1LqSgXLYt36u6Ao83+TAI033xLw0ETR
         2XoijaFxairDfOCRahpgWfrG3hDwvRqvE/K4BVS3snTnEZBkGEcBlVnfDB7lIklU86z1
         ad0Cr7tDkav0fvzyHBnyKX/fofyOHVKKkjB9Lo8UatU9CEORHOupH8wlPdcIh7XKNeAF
         P54uv2I1nYZYUV6qzzcD1Eivw3l7AwF4S/ic6gUeV4HO5FWF3sMcfLsRgyEZb0TuNfyM
         IWXEaolHdW9nlsCkz50BNlv8pkc+KS0qX3kASbRTkTcZz+8Y0ixQN5XfY7ln7EyCylOJ
         aNOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id y185si206026wmd.2.2020.03.20.06.39.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Mar 2020 06:39:32 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1jFHrn-00Ax8I-UW; Fri, 20 Mar 2020 14:39:16 +0100
Message-ID: <ded22d68e623d2663c96a0e1c81d660b9da747bc.camel@sipsolutions.net>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Jeff Dike
 <jdike@addtoit.com>,  Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Brendan Higgins <brendanhiggins@google.com>,  David Gow
 <davidgow@google.com>, linux-um@lists.infradead.org, LKML
 <linux-kernel@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
Date: Fri, 20 Mar 2020 14:39:13 +0100
In-Reply-To: <CACT4Y+bdxmRmr57JO_k0whhnT2BqcSA=Jwa5M6=9wdyOryv6Ug@mail.gmail.com> (sfid-20200311_183506_748492_1435E277)
References: <20200226004608.8128-1-trishalfonso@google.com>
	 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
	 <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
	 <674ad16d7de34db7b562a08b971bdde179158902.camel@sipsolutions.net>
	 <CACT4Y+bdxmRmr57JO_k0whhnT2BqcSA=Jwa5M6=9wdyOryv6Ug@mail.gmail.com>
	 (sfid-20200311_183506_748492_1435E277)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.4 (3.34.4-1.fc31)
MIME-Version: 1.0
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of johannes@sipsolutions.net
 designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
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

On Wed, 2020-03-11 at 18:34 +0100, Dmitry Vyukov wrote:

> > $ gdb -p ...
> > (gdb) p/x task_size
> > $1 = 0x7fc0000000
> > (gdb) p/x __end_of_fixed_addresses
> > $2 = 0x0
> > (gdb) p/x end_iomem
> > $3 = 0x70000000
> > (gdb) p/x __va_space
> > 
> > #define TASK_SIZE (task_size)
> > #define FIXADDR_TOP        (TASK_SIZE - 2 * PAGE_SIZE)
> > 
> > #define FIXADDR_START      (FIXADDR_TOP - FIXADDR_SIZE)
> > #define FIXADDR_SIZE       (__end_of_fixed_addresses << PAGE_SHIFT)
> > 
> > #define VMALLOC_END       (FIXADDR_START-2*PAGE_SIZE)
> > 
> > #define MODULES_VADDR   VMALLOC_START
> > #define MODULES_END       VMALLOC_END
> > #define VMALLOC_START ((end_iomem + VMALLOC_OFFSET) & ~(VMALLOC_OFFSET-1))
> > #define VMALLOC_OFFSET  (__va_space)
> > #define __va_space (8*1024*1024)
> > 
> > 
> > So from that, it would look like the UML vmalloc area is from
> > 0x  70800000 all the way to
> > 0x7fbfffc000, which obviously clashes with the KASAN_SHADOW_OFFSET being
> > just 0x7fff8000.
> > 
> > 
> > I'm guessing that basically the module loading overwrote the kasan
> > shadow then?
> 
> Well, ok, this is definitely not going to fly :)

Yeah, not with vmalloc/modules at least, but you can't really prevent
vmalloc :)

> I don't know if it's easy to move modules to a different location.

We'd have to not just move modules, but also vmalloc space. They're one
and the same in UML.

> It
> would be nice because 0x7fbfffc000 is the shadow start that's used in
> userspace asan and it allows to faster instrumentation (if offset is
> within first 2 gigs, the instruction encoding is much more compact,
> for >2gigs it will require several instructions).

Wait ... Now you say 0x7fbfffc000, but that is almost fine? I think you
confused the values - because I see, on userspace, the following:

|| `[0x10007fff8000, 0x7fffffffffff]` || HighMem    ||
|| `[0x02008fff7000, 0x10007fff7fff]` || HighShadow ||
|| `[0x00008fff7000, 0x02008fff6fff]` || ShadowGap  ||
|| `[0x00007fff8000, 0x00008fff6fff]` || LowShadow  ||
|| `[0x000000000000, 0x00007fff7fff]` || LowMem     ||


Now, I also don't really understand what UML is doing here -
os_get_top_address() determines some sort of "top address"? But all that
is only on 32-bit, on 64-bit, that's always 0x7fc0000000.

So basically that means it's just _slightly_ higher than what you
suggested as the KASAN_SHADOW_OFFSET now (even if erroneously?), and
shouldn't actually clash (and we can just change the top address value
to be slightly lower anyway to prevent clashing).

> But if it's not really easy, I guess we go with a large shadow start
> (at least initially). A slower but working KASAN is better than fast
> non-working KASAN :)

Indeed, but I can't even get it to work regardless of the offset.

Note that I have lockdep enabled, and at least some crashes appear to be
because of the stack unwinding code that is called by lockdep in various
situations...

> > I tried changing it
> > 
> >  config KASAN_SHADOW_OFFSET
> >         hex
> >         depends on KASAN
> > -       default 0x7fff8000
> > +       default 0x8000000000
> > 
> > 
> > and also put a check in like this:
> > 
> > +++ b/arch/um/kernel/um_arch.c
> > @@ -13,6 +13,7 @@
> >  #include <linux/sched.h>
> >  #include <linux/sched/task.h>
> >  #include <linux/kmsg_dump.h>
> > +#include <linux/kasan.h>
> > 
> >  #include <asm/pgtable.h>
> >  #include <asm/processor.h>
> > @@ -267,9 +268,11 @@ int __init linux_main(int argc, char **argv)
> >         /*
> >          * TASK_SIZE needs to be PGDIR_SIZE aligned or else exit_mmap craps
> >          * out
> >          */
> >         task_size = host_task_size & PGDIR_MASK;
> > 
> > +       if (task_size > KASAN_SHADOW_OFFSET)
> > +               panic("KASAN shadow offset must be bigger than task size");
> > 
> > 
> > but now I just crash accessing the shadow even though it was mapped fine?
> 
> Yes, this is puzzling.
> I noticed that RIP is the same in both cases and it relates to vmap code.
> A support for shadow for vmalloced-memory was added to KASAN recently
> and I suspect it may conflict with UML.

This can't be it - HAVE_ARCH_KASAN_VMALLOC isn't selected, so
KASAN_VMALLOC isn't set.

> What does pte-manipulation code even do under UML?

No idea.

> Looking at the code around, kasan_mem_notifier may be a problem too,
> or at least excessive and confusing. We already have shadow for
> everything, we don't need _any_ of dynamic/lazy shadow mapping.

CONFIG_MEMORY_HOTPLUG is also not supported in ARCH=um, or at least not
used in my config.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ded22d68e623d2663c96a0e1c81d660b9da747bc.camel%40sipsolutions.net.
