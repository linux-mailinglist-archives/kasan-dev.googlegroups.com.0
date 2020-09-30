Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQVX2L5QKGQE2J7E2PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A95C27EB6C
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Sep 2020 16:52:51 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id u5sf572532ljl.16
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Sep 2020 07:52:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601477570; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ju39NthGdo0hP8wIZdVx3Gn8eJti2aNP7wajfkUrLrrKY4MHWCA/JdGbBImCadj4VM
         cbmLEiQNZJw8Q2V8BXkgwmRqmLyDhvgds5xRj8r7B2FV+/CV+9ro/vBbHRxFQZg+vDYg
         DfUHmiSlqVov0OMBIsfu6R4sa2OkrW9WPJ4qsFDfjguiq58dH8B5UxU784fMOWdVdUlD
         e/PaoW+eAlNurAJsKY6ZEleLhIjzAT8l9XrOV4KGQRpjtSYq9Nc4TXKQZtn5x1jbA/Lx
         rNt0HJk4rEgTNSaWgNaKtJAqcQcV3Ea2vW1yJRh9deWktT8Y46Q0tkQuITGiTUK5XIPj
         fazg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=94GEfQ7ogQUsDQ7N6hHa7WRXjV8xM6Ui2uiwwZm0bGc=;
        b=Jm5J2c43vvmZYVWCDBSDJm3ziSk7M9A+y8KFl8y6iDeh/BPUtAm1Y5CnMJ1ZWKiZq3
         mVgbaq/JEe3naW/0FQb02cOxRuTocTYsr4TbN273WAcave+Jd4MBS5ExVBFv4DRjFCJV
         Powk5KtBVazQ5odCcQVi+B8GTb+ErhsqKIwNFCkDTzKUsWyI/OOavUw51zjaSrSmshDu
         47aqRS/GZ9XdaOHw7acFboQ5fo4Om6JSqKp3Th4If0a4i+WeLIDdofqHl9Pux0O4GUal
         1Mk77TozGxJCUTj1XpX0EjeFmdn7SUKG6tkikygqYM1XA+vp+t6ejTUuM4PoK4tP/HmJ
         VnpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BYXE0vXL;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=94GEfQ7ogQUsDQ7N6hHa7WRXjV8xM6Ui2uiwwZm0bGc=;
        b=L3Qr1K7l2huzOTrISvlMKJPbvdjvRbbpVi/GdCiiVwhdtXxT26X+ngD+4UJwfr8n8H
         exV3hWnS/DQ1S8GiePW08PVt/sg7lG5I9yxgKSxTU6la26BhUYc44zSzit86E8MAsqzP
         sLxy76ZFAIa9/abWVbRwkietEfvp2rWm3XGM4jQ+axZI/FdY/SScNIRJcs6t2ppPrqPK
         v2PXqvT4z7ZgypD4vtJvVc9jFD79ylBtvGCUcEP55Uz0YNrdlc2sjYgveDOGO/E3ldtA
         +UhSWxtIwl7wtjybo8Tl3eGQzbCVtDmik8Sj1chLqh2jdTwGGR/U/JFDni6V6rE5OqFa
         uxUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=94GEfQ7ogQUsDQ7N6hHa7WRXjV8xM6Ui2uiwwZm0bGc=;
        b=s+l63eUfTyNd4jtgsQG1KZ2NcX6h9B4ne98G2XhtNdl3d12JHGX6HcwMIv1soPljYe
         k9GWfleMG+l4FekWE+Rs2E9qmz76qcUQX29QIoV0eMfBffA/i0KOzd7oCVXompXBYX3c
         PQl6bFNwVLCVGKLpdCwp0VgMXKTbqORW1ZdwCcbz81OAWVzlhfIwVFlZ73Znd4xRgcde
         19LXF1PPtlqnJQb1skp4bvW+EOaICkhSSwrIMJGqD6Tmbgso2C2lW2mc6tGlPvFubQ3c
         RhNcNray2xIf7USo7w9LjuZ8EXzJrz1lWO0o3k7C/K2RnM6d8cyvrzJHWab7a4J0MqI4
         OWwg==
X-Gm-Message-State: AOAM53197pFherYhvBIjBhrCD5IB9xDS839o5/gm5XJ8lTy59UPm9z91
	xiHtpYUtX4bNg7sfVVQp5LY=
X-Google-Smtp-Source: ABdhPJxbpPttR7fF7S6skKRJqMo8Yxr49vKjgz3QB6WppFElOv8T3HS3q8gysrerkc7IZ5n0/dM5mg==
X-Received: by 2002:a2e:7215:: with SMTP id n21mr1016549ljc.438.1601477570561;
        Wed, 30 Sep 2020 07:52:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7c08:: with SMTP id x8ls365782ljc.6.gmail; Wed, 30 Sep
 2020 07:52:49 -0700 (PDT)
X-Received: by 2002:a2e:5849:: with SMTP id x9mr1071909ljd.194.1601477569283;
        Wed, 30 Sep 2020 07:52:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601477569; cv=none;
        d=google.com; s=arc-20160816;
        b=Mw6JiAc/DRieRS+mlYjIWrCZDPh/oCzPkqq8oQuU1MwQzcmA1bL74GZ6fyHX9a7TW5
         d/tuNzZ6AXqimj24sme3RFukU5QeEdD6LDki9i3m2bQHPoYDUu07Ls+wvHJzWFRAuy71
         +xCtNP5be8iW/14VOqjaCCzjHOVd92olFUq4iZh7d5e2KnSV8Z/WR7frGyOWZHLDwvVQ
         8seLKUx1Tx/VjFpQkw5MwT3yLwXTjYhuLc1ChFew5lj3KV9fi8voZvu6vaDjRdcZGMBu
         p3FHp8G4+ASFaP+uOmrs76f3jt5EaNoe6fWvQV6anvARcfxopFPM3W9D+Fxkp0OJ+Qf0
         T3MQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=R8lnyj/dQWok3Luuuae+kPTmb6qYfI7ATT8nF7oG2G4=;
        b=DxHg5YqXw5IopaZxPWc7USz2pF0i1nz0X/Zw+ORzck8tCf8811kkK3O3c+X3t4QxWJ
         UNQDhbzAuiMhsCE6s8ztuLlor2oup8srq/VSgh0WthIZt/wz2mNmEnxkmIGhjnkBfobu
         7I0QUKLTYwFsGF8abJXbNIiBuac/SzD6rcqjRKDnfbYlHTDW/ClxEtKMIrNHk2I/qlqS
         emROgorUmFjnVLN9igYgWVD+oQA5abtHkhyervt+RnSvhd1UbHVIoextbUHbU1VOFkUI
         2UVSzxaTkDAb7OYIG5913ILhFPJ8acAxshq0ayhcey6KXSbiTrDyPNBTdF8xaJCDzCBI
         KHsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BYXE0vXL;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id k10si50887ljj.0.2020.09.30.07.52.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Sep 2020 07:52:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id z1so2157592wrt.3
        for <kasan-dev@googlegroups.com>; Wed, 30 Sep 2020 07:52:49 -0700 (PDT)
X-Received: by 2002:adf:a3d8:: with SMTP id m24mr3576076wrb.418.1601477568479;
        Wed, 30 Sep 2020 07:52:48 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id k8sm3246943wma.16.2020.09.30.07.52.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Sep 2020 07:52:47 -0700 (PDT)
Date: Wed, 30 Sep 2020 16:52:42 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andy Lavr <andy.lavr@gmail.com>,
	Alexander Potapenko <glider@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [v4,01/11] mm: add Kernel Electric-Fence infrastructure
Message-ID: <20200930145242.GA3777666@elver.google.com>
References: <644ba54f-20b5-5864-9c1b-e273c637834c@gmail.com>
 <CANpmjNNBGjjJyv+6QZm9hm=vQ3vHuAOTRYDs-T25X91AQxxyyw@mail.gmail.com>
 <626733c1-7e1b-6e45-69db-f4d6cc67fe97@gmail.com>
 <1fe27f01-d54c-6237-c91a-3731c84e9d33@gmail.com>
 <CANpmjNOQg53dAwuZd4m29vc+cdizFZA-Dgf6DEOJ_=5UR4G+UQ@mail.gmail.com>
 <CAG_fn=XvDEyD+_sWBnXOcvWymhfCGkKwSPtbbUYnsUpSZ3Wx6Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=XvDEyD+_sWBnXOcvWymhfCGkKwSPtbbUYnsUpSZ3Wx6Q@mail.gmail.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BYXE0vXL;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as
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

On Wed, Sep 30, 2020 at 03:54PM +0200, Alexander Potapenko wrote:
> Can you please also share your config? Thanks!
> 
> On Wed, Sep 30, 2020 at 3:39 PM Marco Elver <elver@google.com> wrote:
> > On Wed, 30 Sep 2020 at 15:31, Andy Lavr <andy.lavr@gmail.com> wrote:
> > > Hey,
> > >
> > > So, build linux-next 20200929 + patch KFENCE  (Clang 12 + LTO + IAS)
> > >
> > > If CONFIG_SLUB=y then kernel TRAP, TRAP... HALTED no write log... (
> > >
> > > If CONFIG_SLAB=y then kernel boot fine, if start kde then TRAP and HALTED.
> > >
> > > Attached all log.
> >
> > Nice, thanks for testing!
> >
> > Does this also happen with Clang 11 or GCC 10? I know Clang 12 caused
> > some inexplicable problems for me a couple weeks ago, and switching
> > compiler solved it.

So, I'm unable to reproduce your crashes, but I'm seeing splats on -next
if I enable CONFIG_DEBUG_LIST=y:

	[    9.873638] ------------[ cut here ]------------
	[    9.877180] list_del corruption, ffffefa8d50af608->next is LIST_POISON1 (dead000000000100)
	[    9.878309] WARNING: CPU: 6 PID: 144 at lib/list_debug.c:47 __list_del_entry_valid+0x46/0xa0
	[    9.879435] Modules linked in:
	[    9.879852] CPU: 6 PID: 144 Comm: systemd-journal Tainted: G        W         5.9.0-rc7-next-20200930+ #4
	[    9.881117] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
	[    9.882206] RIP: 0010:__list_del_entry_valid+0x46/0xa0
	[    9.882877] Code: c2 22 48 39 d1 74 29 48 39 31 75 3c b3 01 48 39 70 08 75 4f 89 d8 5b c3 90 31 db 48 c7 c7 10 7f 02 85 31 c0 e8 1b f8 ab ff 90 <0f> 0b 90 90 eb e4 90 31 db 48 c7 c7 46 7f 02 85 31 c0 e8 03 f8 ab
	...
	[    9.895418] PKRU: 55555554
	[    9.895803] Call Trace:
	[    9.896166]  __slab_free+0x29f/0x440
	[    9.896678]  __kfree_skb+0x2c/0xd0
	[    9.897159]  skb_free_datagram+0x15/0x60
	[    9.897719]  unix_dgram_recvmsg+0x417/0x4e0
	[    9.898311]  ? unix_dgram_sendmsg+0xe00/0xe00
	[    9.898925]  ____sys_recvmsg+0x22a/0x250
	[    9.899484]  ? __import_iovec+0x163/0x1e0
	[    9.900047]  ? import_iovec+0x48/0x60
	[    9.900577]  __sys_recvmsg+0x138/0x2c0
	[    9.901111]  ? syscall_trace_enter+0xae/0x190
	[    9.901729]  do_syscall_64+0x34/0x50
	[    9.902239]  entry_SYSCALL_64_after_hwframe+0x44/0xa9
	[    9.902948] RIP: 0033:0x7fd7b39b0dc7
	...
	[    9.912104] CPU: 6 PID: 144 Comm: systemd-journal Tainted: G        W         5.9.0-rc7-next-20200930+ #4
	[    9.913433] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
	[    9.914591] Call Trace:
	[    9.914942]  dump_stack+0xdb/0x10e
	[    9.915431]  __warn+0xdd/0x1a0
	[    9.915864]  ? __list_del_entry_valid+0x46/0xa0
	[    9.916510]  report_bug+0x1bc/0x260
	[    9.917003]  handle_bug+0x43/0x80
	[    9.917478]  exc_invalid_op+0x18/0xb0
	[    9.917995]  asm_exc_invalid_op+0x12/0x20
	[    9.918564] RIP: 0010:__list_del_entry_valid+0x46/0xa0
	...
	[    9.927601]  ? write_ext_msg+0x2a0/0x2a0
	[    9.928161]  __slab_free+0x29f/0x440
	[    9.928672]  __kfree_skb+0x2c/0xd0
	[    9.929154]  skb_free_datagram+0x15/0x60
	[    9.929710]  unix_dgram_recvmsg+0x417/0x4e0
	[    9.930303]  ? unix_dgram_sendmsg+0xe00/0xe00
	[    9.930915]  ____sys_recvmsg+0x22a/0x250
	[    9.931471]  ? __import_iovec+0x163/0x1e0
	[    9.932037]  ? import_iovec+0x48/0x60
	[    9.932562]  __sys_recvmsg+0x138/0x2c0
	[    9.933091]  ? syscall_trace_enter+0xae/0x190
	[    9.933706]  do_syscall_64+0x34/0x50
	[    9.934216]  entry_SYSCALL_64_after_hwframe+0x44/0xa9
	[    9.934925] RIP: 0033:0x7fd7b39b0dc7
	...
	[    9.944079] ---[ end trace 96c97ed373d008a3 ]---

Given your crashes are related to skb allocs/frees, and the above are,
I'm suspecting memory corruption and -next is currently broken.

Can you please test with CONFIG_DEBUG_LIST=y, and see if that results in
splats with and without KFENCE? Without a stable tree as base, testing
KFENCE is pretty useless.

If you still think KFENCE is at fault here, we'd need:

1. The .config.
2. Run your stacktraces through scripts/decode_stacktrace.sh, otherwise
   we don't quite know which accesses are causing your issues.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200930145242.GA3777666%40elver.google.com.
