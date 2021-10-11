Return-Path: <kasan-dev+bncBCMIZB7QWENRBWVKSGFQMGQEPKXWCCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A61E04292F5
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 17:16:43 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id k1-20020a4a8501000000b0029ac7b9dc82sf10233184ooh.17
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 08:16:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633965402; cv=pass;
        d=google.com; s=arc-20160816;
        b=lZiSpJxbpX3BBfGcbMtxHecf3ti3xXyXM5wEYAnhSZ3ddYkr27+85bAb+1KXAUVjLK
         f7OeTvsYBCuzIn5oOidwlMsGlu+8tU0Qlo+LqrNJ6L2jlqEp1bBIUgplC5EKzBuVT42O
         /JuZF836fCyYK1gWq/VoJPOrOAXufuzDnIdUOXMg3h0I5cnKWb0wm+wU1DbQPYTxqIe2
         j4sSajGxQXRRJDeb3YovLYUV+qZcJO103BtrRkFgZ6x+FBzCmo35cLTlSO5TiQqFSRZM
         m9gxAPmqthco9kr+N9Mrj2uEYCRi0fN1mj4TxxjvKnF9rmgks2VfjaqGjI5CXWCekbuh
         4ayA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AKNMNIM8Rn/30jYa+UBNpcuObpoo6yGhqNFC7WmdkgQ=;
        b=eG5y814JCR00sgjtyrrlczfhzF8FZA5phfZgkm7//OO74Ec6Ytiftif75DuUtJjoGP
         Q+x9xfSWySlKK1CVATMkBOZ22l2ALLGR5v5KRcNhFkBG/q5LpkJY8IlndQY8MufNemqY
         5xK2UIjVp4nrPx2zIXDYx9El17q9jfIhK8Q5JWrhV/CDRQRtXSPZ1u93/mWW5a44ROGv
         S5WEj97sU/CtCzK5NgoOZg8wzeoKRdzMQ3CmJCebCEgw0zXIOuRH+om9uq4xNtcnrnRg
         Q7N7S/eiAJQaYAe6t2vfCCvigUk6KllEB7oLZ/G9z6KBnth/4miI3OxEav1pi0y0aO/8
         yAbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=el38wyOt;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AKNMNIM8Rn/30jYa+UBNpcuObpoo6yGhqNFC7WmdkgQ=;
        b=VtO2ucVpKgzFSVBGy303Au07yBB2lbDE8JW9dV6w/8vJNITK6ZUc3AFMqc1ns2o+9l
         M+0BUUk2jpLABbBrlz96BrCsjySlpr1c7mRK/1Pr6oIXl57OigUZaVKd7LCYm03kJisb
         KfVeW7uG0pLMPZVihRHMygNdutcPfg5eAmhYGhsNiwNOYiHFPFdnH5Nuno4uYjTz+HPs
         Ez38/u60CgNM3efdJ+B092+3BDwM5EKMnSd53YG7PLmR11fasU9EBf6exBLkRZtQFH4g
         nFxC8+3VD0XWeeJYXXIJZO5iE8XDes9eeqnFP4Peehb0Zs2WTqW3Q1cYVdDpvEx3aFBA
         Vk0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AKNMNIM8Rn/30jYa+UBNpcuObpoo6yGhqNFC7WmdkgQ=;
        b=i6v0DKq1M7IYh6jwr1EfWL/17++o2+pWx0nQyRt1zeDs2EyLWVy1TZgeY+/DA1OVwr
         83Dh61s8kbrpKfkpVvvTKIdoLYDkKqWDXra4tlygb5luDkrIYnqVAYrKXOHyRlDLO8V5
         CoBsHmDCJyxvzUfYpAunsek1JWgL2Kh8YEcXZK+RLNKR2eba+wLz4BXdk7XRgkiEA/+u
         kNNTDWLKIv/ZikiLNZ2duhH/aCzRRiVPDfF46R520IZvhM4y4WB1VXAHsDlanuvWgn3z
         h5M+xjQRNYqrSh6W85luiKGvEvb/Er8SfLlk8KFaUfwVUkehHBdDE5sqQ2VoYyRNoZCZ
         f7Yw==
X-Gm-Message-State: AOAM532r369qDkmadL8LuWu8viAIx5OvVY8NtndhcaJ2uFycLZK7s4lM
	VOAbOcN5JyT/6Ntqb6D2De4=
X-Google-Smtp-Source: ABdhPJwFiv+CZR9dZotG0iAYVSSsAkB8Oj0QUn+aKXL+sLeGTnnWVIfO7223fiULsBTt8utQCoSpGw==
X-Received: by 2002:a05:6820:1504:: with SMTP id ay4mr19783096oob.34.1633965402378;
        Mon, 11 Oct 2021 08:16:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6155:: with SMTP id c21ls574948otk.10.gmail; Mon, 11 Oct
 2021 08:16:42 -0700 (PDT)
X-Received: by 2002:a05:6830:78d:: with SMTP id w13mr2684925ots.183.1633965402055;
        Mon, 11 Oct 2021 08:16:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633965402; cv=none;
        d=google.com; s=arc-20160816;
        b=wCgOHu8jh89bxVDuRW9rOu4AQ/2KeGmsZwDgEjT9kausfXNmWLuacsZHIRkTaba67t
         QyNudQHywHYZeolTxZ38YOzS+EKXzd3pRuhok6mUQzB/eal7vRQSQi/VeGUas6jJGVPX
         BXql+32uPr0EYdLOmr/Af49S4du6kBaDVqXYNRu728yYN3POfotGyTa61367IWOo0QVg
         Zvq8IH5MUG8obejDzB8I3xg5sAyUiWIjwP63lB2rNIFKKt8Ff26ihT3bJ3viYvaGmPxc
         ReAas7wzxI+r4ue4a5Shl84bCPWwwbI2K4sCxraJAME96cazWsKmUxw31XcfanLbUgGO
         LWRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=etYgg+h2O5V3SwL5gD13pIM27MsV6K0L3L1sqF1wYTE=;
        b=X0crcpXZdCSR0HXnhONAmXTZ4LJBCRUFFHW8UDdmz4xyUMHEvuwOQsWkc4Oq7moT7r
         Eh+p7Nt9f5vmpovRy+pU2Foh/NSgt1DCuOJCiPBTsIcKdEpZavJWQqKFWMOMsafW4bS8
         AzCmeQQ6q4IaddnW6w2BwkN3laDzu5ukAxiuDZnbixPhn2K9FmI1fJElhvaIKlfL/SKT
         vKDNRrmMxTVYa3MaO+QwQw8r9K3Updy3hB9t+X0DVGThcKAFkbCCsqDxljIBf/wBPggo
         whnMfQT3dRFxiy1rxyfXeIdCo3CVOaGptOP5jyvNR3N8esH5HhmtHhaTk+9vgwwLrA1+
         E4Iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=el38wyOt;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::334 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x334.google.com (mail-ot1-x334.google.com. [2607:f8b0:4864:20::334])
        by gmr-mx.google.com with ESMTPS id bc13si742063oob.2.2021.10.11.08.16.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Oct 2021 08:16:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::334 as permitted sender) client-ip=2607:f8b0:4864:20::334;
Received: by mail-ot1-x334.google.com with SMTP id x33-20020a9d37a4000000b0054733a85462so22029540otb.10
        for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 08:16:42 -0700 (PDT)
X-Received: by 2002:a05:6830:402c:: with SMTP id i12mr7503223ots.319.1633965401529;
 Mon, 11 Oct 2021 08:16:41 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com>
 <YWPaZSX4WyOwilW+@arighi-desktop> <CANpmjNMFFFa=6toZJXqo_9hzv05zoD0aXA4D_K93rfw58cEw3w@mail.gmail.com>
 <YWPjZv7ClDOE66iI@arighi-desktop> <CACT4Y+b4Xmev7uLhASpHnELcteadhaXCBkkD5hO2YNP5M2451g@mail.gmail.com>
 <YWQCknwPcGlOBfUi@arighi-desktop> <YWQJe1ccZ72FZkLB@arighi-desktop>
 <CANpmjNNtCf+q21_5Dj49c4D__jznwFbBFrWE0LG5UnC__B+fKA@mail.gmail.com>
 <YWRNVTk9N8K0RMst@arighi-desktop> <CACT4Y+bZGK75S+cyeQda-oHmeDVeownwOj2imQbPYi0dRY18+A@mail.gmail.com>
 <YWRUBxS0hGGDkeU4@arighi-desktop>
In-Reply-To: <YWRUBxS0hGGDkeU4@arighi-desktop>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Oct 2021 17:16:30 +0200
Message-ID: <CACT4Y+ZATYYpX6wJ_i1ig6ZhA3kwuH_8eC51spkd+0x3ZxX0ow@mail.gmail.com>
Subject: Re: BUG: soft lockup in __kmalloc_node() with KFENCE enabled
To: Andrea Righi <andrea.righi@canonical.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=el38wyOt;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::334
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

On Mon, 11 Oct 2021 at 17:11, Andrea Righi <andrea.righi@canonical.com> wrote:
>
> On Mon, Oct 11, 2021 at 05:00:15PM +0200, Dmitry Vyukov wrote:
> > On Mon, 11 Oct 2021 at 16:42, Andrea Righi <andrea.righi@canonical.com> wrote:
> > >
> > > On Mon, Oct 11, 2021 at 12:03:52PM +0200, Marco Elver wrote:
> > > > On Mon, 11 Oct 2021 at 11:53, Andrea Righi <andrea.righi@canonical.com> wrote:
> > > > > On Mon, Oct 11, 2021 at 11:23:32AM +0200, Andrea Righi wrote:
> > > > > ...
> > > > > > > You seem to use the default 20s stall timeout. FWIW syzbot uses 160
> > > > > > > secs timeout for TCG emulation to avoid false positive warnings:
> > > > > > > https://github.com/google/syzkaller/blob/838e7e2cd9228583ca33c49a39aea4d863d3e36d/dashboard/config/linux/upstream-arm64-kasan.config#L509
> > > > > > > There are a number of other timeouts raised as well, some as high as
> > > > > > > 420 seconds.
> > > > > >
> > > > > > I see, I'll try with these settings and see if I can still hit the soft
> > > > > > lockup messages.
> > > > >
> > > > > Still getting soft lockup messages even with the new timeout settings:
> > > > >
> > > > > [  462.663766] watchdog: BUG: soft lockup - CPU#2 stuck for 430s! [systemd-udevd:168]
> > > > > [  462.755758] watchdog: BUG: soft lockup - CPU#3 stuck for 430s! [systemd-udevd:171]
> > > > > [  924.663765] watchdog: BUG: soft lockup - CPU#2 stuck for 861s! [systemd-udevd:168]
> > > > > [  924.755767] watchdog: BUG: soft lockup - CPU#3 stuck for 861s! [systemd-udevd:171]
> > > >
> > > > The lockups are expected if you're hitting the TCG bug I linked. Try
> > > > to pass '-enable-kvm' to the inner qemu instance (my bad if you
> > > > already have), assuming that's somehow easy to do.
> > >
> > > If I add '-enable-kvm' I can triggering other random panics (almost
> > > immediately), like this one for example:
> > >
> > > [21383.189976] BUG: kernel NULL pointer dereference, address: 0000000000000098
> > > [21383.190633] #PF: supervisor read access in kernel mode
> > > [21383.191072] #PF: error_code(0x0000) - not-present page
> > > [21383.191529] PGD 0 P4D 0
> > > [21383.191771] Oops: 0000 [#1] SMP NOPTI
> > > [21383.192113] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.15-rc4
> > > [21383.192757] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.14.0-2 04/01/2014
> > > [21383.193414] RIP: 0010:wb_timer_fn+0x44/0x3c0
> > > [21383.193855] Code: 41 8b 9c 24 98 00 00 00 41 8b 94 24 b8 00 00 00 41 8b 84 24 d8 00 00 00 4d 8b 74 24 28 01 d3 01 c3 49 8b 44 24 60 48 8b 40 78 <4c> 8b b8 98 00 00 00 4d 85 f6 0f 84 c4 00 00 00 49 83 7c 24 30 00
> > > [21383.195366] RSP: 0018:ffffbcd140003e68 EFLAGS: 00010246
> > > [21383.195842] RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000000000004
> > > [21383.196425] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffff9a3521f4fd80
> > > [21383.197010] RBP: ffffbcd140003e90 R08: 0000000000000000 R09: 0000000000000000
> > > [21383.197594] R10: 0000000000000004 R11: 000000000000000f R12: ffff9a34c75c4900
> > > [21383.198178] R13: ffff9a34c3906de0 R14: 0000000000000000 R15: ffff9a353dc18c00
> > > [21383.198763] FS:  0000000000000000(0000) GS:ffff9a353dc00000(0000) knlGS:0000000000000000
> > > [21383.199558] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> > > [21383.200212] CR2: 0000000000000098 CR3: 0000000005f54000 CR4: 00000000000006f0
> > > [21383.200930] Call Trace:
> > > [21383.201210]  <IRQ>
> > > [21383.201461]  ? blk_stat_free_callback_rcu+0x30/0x30
> > > [21383.202692]  blk_stat_timer_fn+0x138/0x140
> > > [21383.203180]  call_timer_fn+0x2b/0x100
> > > [21383.203666]  __run_timers.part.0+0x1d1/0x240
> > > [21383.204227]  ? kvm_clock_get_cycles+0x11/0x20
> > > [21383.204815]  ? ktime_get+0x3e/0xa0
> > > [21383.205309]  ? native_apic_msr_write+0x2c/0x30
> > > [21383.205914]  ? lapic_next_event+0x20/0x30
> > > [21383.206412]  ? clockevents_program_event+0x94/0xf0
> > > [21383.206873]  run_timer_softirq+0x2a/0x50
> > > [21383.207260]  __do_softirq+0xcb/0x26f
> > > [21383.207647]  irq_exit_rcu+0x8c/0xb0
> > > [21383.208010]  sysvec_apic_timer_interrupt+0x7c/0x90
> > > [21383.208464]  </IRQ>
> > > [21383.208713]  asm_sysvec_apic_timer_interrupt+0x12/0x20
> > >
> > > I think that systemd autotest used to use -enable-kvm, but then they
> > > removed it, because it was introducing too many problems in the nested
> > > KVM context. I'm not sure about the nature of those problems though, I
> > > can investigate a bit and see if I can understand what they were
> > > exactly.
> >
> > This looks like just a plain bug in wb_timer_fn, not something related
> > to virtualization.
> > Do you have this fix?
> > https://syzkaller.appspot.com/bug?extid=aa0801b6b32dca9dda82
>
> Yes, it looks like I have this:
>
>  d152c682f03c block: add an explicit ->disk backpointer to the request_queue

Then there is another bug in wb_timer_fn I guess...

Don't know if this is the same or something else:
https://lore.kernel.org/lkml/CAHbLzkrdGva2dzO36r62LKv_ip5trbMK0BO3vCeSBk2_7OE-zA@mail.gmail.com/

There also were some data races in this function:
https://groups.google.com/g/syzkaller-upstream-moderation/search?q=wb_timer_fn

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZATYYpX6wJ_i1ig6ZhA3kwuH_8eC51spkd%2B0x3ZxX0ow%40mail.gmail.com.
