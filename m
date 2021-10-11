Return-Path: <kasan-dev+bncBDOPF7OU44DRBWE2SGFQMGQEU4PEZEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 31E8442925B
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 16:42:35 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id d11-20020a50cd4b000000b003da63711a8asf16041691edj.20
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 07:42:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633963355; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hq+7Z+nTN/h+2qkcp3CQdmVf1xLKMbasPjreyR6uIvagzVjq/IhByJg6FpZ5cUzytV
         ifXfY5EbJ7ChxDmLm5Wqbh5Zj3kFH0EelPDBatq+krDF5CpWuPzHfNe2jTh4px+Qmbiv
         3APwWgKZQZnKTw31P+YgQ+YocldnkUxQ8BedgwmKaACBG8ovpKFmaSA05eX1JnyTl/zO
         NjZbHuyKPQ10F09euDykZs1AzuIWS8vhl5tuHLJu38PqlUOcADjLzhG0HTVD/qaPC3C8
         FvT2avIXS4mslvTiW5Ere+jVQKbeRcsjLIiqLhmgVEiTioVhuXbF48MuM3DHjYtNvWW9
         oiPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=g+Ovz1ZmUneYyn7T4jlWHyl3fnOAAPqPg4rHMBPMY8Q=;
        b=izx7zXGmQ1HC7FYIUM4Rj/5r2Q3zcTsMxF6rXfiZGyV6r3aytMr3gBKvvtX4sYnkjc
         o8OYcONEZxrcRy8oY8HfNsCNVGR/y5E45XCsoojjEAo3kLMCnXbDhYG4tTOokbKQ5PZV
         9SAkCpdIjHX7Z4y2yig92MGhjU70BBhdbVwD0tz7cvFn03zwSHZ48VfETdGe65FjP7yq
         blX8aKAVt8W930OAjOhrRqnxWIOwUm+m0ui+NfAh+4OjETUW3VldcoN+fBoy5BXzAnQm
         UjLiHhgdmGcKMjkro+2DNrwqOEgU/b7UKmbIjdkRgXtcPgPPxNAo2EU3HxhE/9bVgbz3
         QYvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=uv89gm8O;
       spf=pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=g+Ovz1ZmUneYyn7T4jlWHyl3fnOAAPqPg4rHMBPMY8Q=;
        b=Z4qXSackb9Qwv7pYOxNQDhyrbs5w4tOxQMnYRx4gd9ADY6YaiXqeGQVJ4kDzDyskh5
         gSrLvke6xvvj7RpZhVc3X5V9PVGUSFKRJrPOZqCmofOjqDnn/7waceZIpikZ66Rktp7+
         X12yAMZjREnSLpPB2qLbiVxtM4uEgjPHcYrNvtjNfeifrUORhwbztA0XRsR/tnbdyVVQ
         k9kpAbGpvudH3Rzbc4USSURT56vB3iTF13RDgGAEBVoA9qinKqMOMxGblJ3GR/1ROGVf
         hsa/uYTTPx2Q9YiXy6Zym62+Qrq8aTMrfAhTYzA7TDWXYXO3EzpjeiqYsf1MOMccQ0NV
         cBLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=g+Ovz1ZmUneYyn7T4jlWHyl3fnOAAPqPg4rHMBPMY8Q=;
        b=RSoEANy+zbSLTiWQZJygDrJxmKMV7X8x1C4rt98GzYZq6bcFw8YR4Cuo5zF4XPwy4N
         Apn486jDV1m2Jsh+DtbAcXV9dXs/pd4VlLpp+SD9R5WdBUX0ncz+6yq/R1Q/pP715jY3
         ku/wqW9dI8qqKTxhoAE4Jc97PRW87FSjD8MgScbtHXXED21B5OLoDhKE70sCjvEbLxof
         AIVxfNfbPc9jrvZB4r1jVdDGISr+6ypJnE2ojsIVXceJGj9xc6bvpW0Ykw6VzbxUUcRQ
         KAAPN2haan3zYZefYXm+KqDy6iKkAEICUN0ayL2RTYN/lQ36hOHPEnnDA7crXHRrQ74a
         c4nA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532o9nzAGxw//JL0Yb+SA2t5ichmCHVkqHtuKPBmhTYF1ocwylpe
	wGUnsteCLsd5UVMNXqQRH5s=
X-Google-Smtp-Source: ABdhPJxSPRuqMk+It3Px7kbqgRPdYq9TgiNT0BEI0akFQHPFNmV/Jd+wqKvGBmSf2H6KDUdMSGoXBg==
X-Received: by 2002:a17:907:2d23:: with SMTP id gs35mr25334120ejc.364.1633963352980;
        Mon, 11 Oct 2021 07:42:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:1611:: with SMTP id hb17ls4572918ejc.7.gmail; Mon,
 11 Oct 2021 07:42:32 -0700 (PDT)
X-Received: by 2002:a17:906:e089:: with SMTP id gh9mr26025475ejb.320.1633963352060;
        Mon, 11 Oct 2021 07:42:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633963352; cv=none;
        d=google.com; s=arc-20160816;
        b=pMDU+wuvWYi5RPWOCNiwVE3ydqfoDkwN/VOpaqwVvHNTBzkKa0zyJij3qjFQYhdnAD
         G6/Eszzs6DxlNLEsa6RPmg1P7U6qyvZqV4N/on++qB99F/+Qjoooap2U92cjL/Bj1nOq
         Pa3IOKB0GqXlkMO/XhoLbuuxiv3YgIeFfcJeBsem9UgyXspqtaPR8l2Je25xtfiUeOrT
         330fS9LnooQhbw9G7igIEAfz0LztrtQWXqjmsN2LvVlKkT2DS4vt20hIj1qpIgYYxLS+
         u1+A416uoS9jZX5uWltZO0WEiXWG2vEzKnhbXQFpSQN91vvDmq2w3EWJHYFNzyoIdY9N
         zmSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JMT/HDVAUnQSbtufENFCBQ4ItG4NAMh4DkHJqbVm68E=;
        b=fvmUeHgLwxxqzZoXi5z8zeFgejZIVi3edmFgS8MRg9GwGsjztLUy03PHr6WrLTLH8R
         GMXLBKNY9am0MKg4Gp/03xaycnSUiYiv+8fNRcb4wYm+Qxrj7ix649lmxhjICpRSD12v
         0NHVyZjcJxDpeIKPo1HhDpPijtnhZPk9QgvaiaAPsPM7RbjD0K8eVgreuZ1vI0X/YQYH
         VvjhTODURC8D+NiBTDkONaJLTt4rF3Nv/osVo5Z5BACZb+RhsW0jDyAzlhFlohsZ4S9N
         eY4zzQYmO+Lpm2p3ugeYO+la8mcYQ3PkrSxlYtGefTO2V2PSsih/qkEe9taj20eGgmgc
         6onQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=uv89gm8O;
       spf=pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id r21si597377edq.2.2021.10.11.07.42.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Oct 2021 07:42:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-ed1-f72.google.com (mail-ed1-f72.google.com [209.85.208.72])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 99E8B3FFEF
	for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 14:42:31 +0000 (UTC)
Received: by mail-ed1-f72.google.com with SMTP id 14-20020a508e4e000000b003d84544f33eso16127231edx.2
        for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 07:42:31 -0700 (PDT)
X-Received: by 2002:a17:906:e089:: with SMTP id gh9mr26025338ejb.320.1633963350929;
        Mon, 11 Oct 2021 07:42:30 -0700 (PDT)
X-Received: by 2002:a17:906:e089:: with SMTP id gh9mr26025313ejb.320.1633963350724;
        Mon, 11 Oct 2021 07:42:30 -0700 (PDT)
Received: from localhost ([2001:67c:1560:8007::aac:c1b6])
        by smtp.gmail.com with ESMTPSA id k23sm4333087edv.22.2021.10.11.07.42.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Oct 2021 07:42:30 -0700 (PDT)
Date: Mon, 11 Oct 2021 16:42:29 +0200
From: Andrea Righi <andrea.righi@canonical.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: BUG: soft lockup in __kmalloc_node() with KFENCE enabled
Message-ID: <YWRNVTk9N8K0RMst@arighi-desktop>
References: <YWLwUUNuRrO7AxtM@arighi-desktop>
 <CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com>
 <YWPaZSX4WyOwilW+@arighi-desktop>
 <CANpmjNMFFFa=6toZJXqo_9hzv05zoD0aXA4D_K93rfw58cEw3w@mail.gmail.com>
 <YWPjZv7ClDOE66iI@arighi-desktop>
 <CACT4Y+b4Xmev7uLhASpHnELcteadhaXCBkkD5hO2YNP5M2451g@mail.gmail.com>
 <YWQCknwPcGlOBfUi@arighi-desktop>
 <YWQJe1ccZ72FZkLB@arighi-desktop>
 <CANpmjNNtCf+q21_5Dj49c4D__jznwFbBFrWE0LG5UnC__B+fKA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNtCf+q21_5Dj49c4D__jznwFbBFrWE0LG5UnC__B+fKA@mail.gmail.com>
X-Original-Sender: andrea.righi@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=uv89gm8O;       spf=pass
 (google.com: domain of andrea.righi@canonical.com designates 185.125.188.123
 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

On Mon, Oct 11, 2021 at 12:03:52PM +0200, Marco Elver wrote:
> On Mon, 11 Oct 2021 at 11:53, Andrea Righi <andrea.righi@canonical.com> wrote:
> > On Mon, Oct 11, 2021 at 11:23:32AM +0200, Andrea Righi wrote:
> > ...
> > > > You seem to use the default 20s stall timeout. FWIW syzbot uses 160
> > > > secs timeout for TCG emulation to avoid false positive warnings:
> > > > https://github.com/google/syzkaller/blob/838e7e2cd9228583ca33c49a39aea4d863d3e36d/dashboard/config/linux/upstream-arm64-kasan.config#L509
> > > > There are a number of other timeouts raised as well, some as high as
> > > > 420 seconds.
> > >
> > > I see, I'll try with these settings and see if I can still hit the soft
> > > lockup messages.
> >
> > Still getting soft lockup messages even with the new timeout settings:
> >
> > [  462.663766] watchdog: BUG: soft lockup - CPU#2 stuck for 430s! [systemd-udevd:168]
> > [  462.755758] watchdog: BUG: soft lockup - CPU#3 stuck for 430s! [systemd-udevd:171]
> > [  924.663765] watchdog: BUG: soft lockup - CPU#2 stuck for 861s! [systemd-udevd:168]
> > [  924.755767] watchdog: BUG: soft lockup - CPU#3 stuck for 861s! [systemd-udevd:171]
> 
> The lockups are expected if you're hitting the TCG bug I linked. Try
> to pass '-enable-kvm' to the inner qemu instance (my bad if you
> already have), assuming that's somehow easy to do.

If I add '-enable-kvm' I can triggering other random panics (almost
immediately), like this one for example:

[21383.189976] BUG: kernel NULL pointer dereference, address: 0000000000000098
[21383.190633] #PF: supervisor read access in kernel mode
[21383.191072] #PF: error_code(0x0000) - not-present page
[21383.191529] PGD 0 P4D 0 
[21383.191771] Oops: 0000 [#1] SMP NOPTI
[21383.192113] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 5.15-rc4
[21383.192757] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.14.0-2 04/01/2014
[21383.193414] RIP: 0010:wb_timer_fn+0x44/0x3c0
[21383.193855] Code: 41 8b 9c 24 98 00 00 00 41 8b 94 24 b8 00 00 00 41 8b 84 24 d8 00 00 00 4d 8b 74 24 28 01 d3 01 c3 49 8b 44 24 60 48 8b 40 78 <4c> 8b b8 98 00 00 00 4d 85 f6 0f 84 c4 00 00 00 49 83 7c 24 30 00
[21383.195366] RSP: 0018:ffffbcd140003e68 EFLAGS: 00010246
[21383.195842] RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000000000004
[21383.196425] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffff9a3521f4fd80
[21383.197010] RBP: ffffbcd140003e90 R08: 0000000000000000 R09: 0000000000000000
[21383.197594] R10: 0000000000000004 R11: 000000000000000f R12: ffff9a34c75c4900
[21383.198178] R13: ffff9a34c3906de0 R14: 0000000000000000 R15: ffff9a353dc18c00
[21383.198763] FS:  0000000000000000(0000) GS:ffff9a353dc00000(0000) knlGS:0000000000000000
[21383.199558] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[21383.200212] CR2: 0000000000000098 CR3: 0000000005f54000 CR4: 00000000000006f0
[21383.200930] Call Trace:
[21383.201210]  <IRQ>
[21383.201461]  ? blk_stat_free_callback_rcu+0x30/0x30
[21383.202692]  blk_stat_timer_fn+0x138/0x140
[21383.203180]  call_timer_fn+0x2b/0x100
[21383.203666]  __run_timers.part.0+0x1d1/0x240
[21383.204227]  ? kvm_clock_get_cycles+0x11/0x20
[21383.204815]  ? ktime_get+0x3e/0xa0
[21383.205309]  ? native_apic_msr_write+0x2c/0x30
[21383.205914]  ? lapic_next_event+0x20/0x30
[21383.206412]  ? clockevents_program_event+0x94/0xf0
[21383.206873]  run_timer_softirq+0x2a/0x50
[21383.207260]  __do_softirq+0xcb/0x26f
[21383.207647]  irq_exit_rcu+0x8c/0xb0
[21383.208010]  sysvec_apic_timer_interrupt+0x7c/0x90
[21383.208464]  </IRQ>
[21383.208713]  asm_sysvec_apic_timer_interrupt+0x12/0x20

I think that systemd autotest used to use -enable-kvm, but then they
removed it, because it was introducing too many problems in the nested
KVM context. I'm not sure about the nature of those problems though, I
can investigate a bit and see if I can understand what they were
exactly.

-Andrea

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YWRNVTk9N8K0RMst%40arighi-desktop.
