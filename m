Return-Path: <kasan-dev+bncBC72VC6I3MMBBAEEZ2DAMGQE7XKYLEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 82F743B2093
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 20:48:33 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id z71-20020a63334a0000b029022250d765d3sf2011576pgz.12
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 11:48:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624474112; cv=pass;
        d=google.com; s=arc-20160816;
        b=UzJdL65tq49TwWMJ4BzXA8bAQWGgVEGHlAtdOdLehu8rGXTP6PflJP5nm0u8hEWyvn
         DmehRRAcbpeuXn2Kn74ia7VwhkGp6QOrGbVEqyyA+TXCJJgVdA2G/Lb5pN0K7jUeqY2g
         0LHARbKeWIKIGMYHjeJwBkyTMyHc8a3n9UCeI1j1ZrKIG6O6USHgzLQ8Or6W7NSQQmqv
         sR8DNvD43AQeUtNMabtSeb5epdrtwe/3BQe0lvZm8iB51UaydnGzoYx1/z5YpaI218k5
         p1zsuKU2j+gVxbPQrILMCAzSBNEJDUMA2IGUN9pVLU7sY2nRbclvyMI+K+f0Hqczft7k
         DgFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=uhA/FH+trWYJKnY6w2EIzRAgvU4qcKep1fK3MjP5nZ4=;
        b=MjyKLfT2pA//XK8faDM6R9p6KA8OpL4LGGh8l5OtwWK/E47jIJXE43R1aTNW3E/N2I
         9PkbI+hCReiY6vCMlGQ1Ih+aeH7yeGfD9Dl4dfhRXwyc7IqcMzvtmvDrqTHWLgbtHKh9
         /FF7+jsCU47l505yyMLjzC0S7CMbLUQkhHUmkPlBUkHCrNDCJHlrAc+2jNTZzBNTJ548
         61vnQDHzewy4/NdIaRPwh3P0OcBCgPypK5u6zy580EyxK1+ArUXVQjhtsBE3mAUiq6mc
         e1XXhec/mqlovhRx3++fcd8lGR09QC+dHS2LwrMirW0X1GjAG9rZIuGA4kILOpiZOqP9
         9Ilw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Mx8bYJkW;
       spf=pass (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::e33 as permitted sender) smtp.mailfrom=jim.cromie@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uhA/FH+trWYJKnY6w2EIzRAgvU4qcKep1fK3MjP5nZ4=;
        b=Z1gBwqq6Ex7S8kgvrfOms6KrSRwLa9ibGxYRYMhqI7CcMylZ11x5kv89/QYw05gfWh
         nnerr26Efle4Li+XcNfwLtFO9BIz2Ixy0GBunahs3nYnbToxMGrr/YBWOQGsoF8u8R6u
         sC/bbgHgnC/ejkoPKPnIgr4QslK9QQvEf02N0bpkuBJf/WdMfefn3BPb8/GHPsLKIFXK
         ODWPjxiexCBfyEHeY81jSFwxItGZzdetJxsj+1uPX27l4swM07qr+4fYMXTFSbyTexBb
         Chl21NJIrZ9Z+ya7wSRbc5TU0hqghFmueTnug6lcuMIuMVRoIhKkcifG9sq9xCHH+bzJ
         3RQA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uhA/FH+trWYJKnY6w2EIzRAgvU4qcKep1fK3MjP5nZ4=;
        b=cFz15uofnegEqJMcaOTS0qLLvh9dUql+SWQTJnoCSiJAVQDZPTx9pZevhaJ1xBvJ7I
         z6AHsUpSZ6ts3Hfl/h0COqNMItWRi+0Ak+0o0tKA++ZbseCSEt9odMn5jDlq7MyXldtJ
         y69A3qIpQfwII2fw6++bXyxkei5u3fVkmHG5e1k0R5uReKDnPz7dHvrYxX7GxPZejzf9
         1XLq3uzgwqR3SoNIGxEysriTmCVVvGl/oIbEcg+S3QC0c5fBJOBhJoUfYs76o89LxeZo
         fPVU5kac9CGYvV0UGWIE0YJoKLBf4o2m/7thas77/OVF/in7s2B332ntxkgKu+g06Qmj
         SlFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uhA/FH+trWYJKnY6w2EIzRAgvU4qcKep1fK3MjP5nZ4=;
        b=OC/2hznsUgkaQjMm8E2E2Ik8FWkoVZlMKWusbJAIi7DfDk06V0RmPZv0XufUfLBAYk
         23lco5lRC2RJiYDGmRtqOGvj++IcSBI7zoi4K6hGXsF1qXwarr/45oYjnmSrHy0YVvAA
         AUO/W6QpNNDkdW2TqkkLj8RV7PjklqopcFZFXM3k37Zzx9p1OkcVrVgY3heVGuGw7ESq
         XndVeH0EZtwTNekvmuzNxwsJWoiEmCtjyPmK07YCmVWmu7kAO17NTFEn8QLZZSnnCoCm
         ibxZFKzezmYAv6iKZKpsl5hmVWwoo48CoPjM9Yv+kZ9Nc1MGw1uG2dS9G2QLHF20uJZR
         4jFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533rrMvXnKyOhUrt1GhStSCSwor+NBNtAEV2PT7qvLZwYXtu7uDk
	v1DsnZX/teWECc23twSpyEU=
X-Google-Smtp-Source: ABdhPJyjX7IkxYyCDc9Yqm4J3lcWsQtD23MrKUnop+47bDdGE6oC5dUeWYSdk4823LRllI0iyc9B4A==
X-Received: by 2002:a17:902:c611:b029:122:847c:66e9 with SMTP id r17-20020a170902c611b0290122847c66e9mr862127plr.82.1624474112195;
        Wed, 23 Jun 2021 11:48:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5992:: with SMTP id l18ls4428911pji.1.canary-gmail;
 Wed, 23 Jun 2021 11:48:31 -0700 (PDT)
X-Received: by 2002:a17:90b:23d5:: with SMTP id md21mr1036206pjb.203.1624474111691;
        Wed, 23 Jun 2021 11:48:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624474111; cv=none;
        d=google.com; s=arc-20160816;
        b=ldPG4KgCXEMYw/sPGiKSy0Du2zBuAuj6D5JrCkLVKQthx4D4nMLydTTwYqFWMKMAYT
         u/ZzrSAFHI02Qq2I+ulhWr9nl9ptZao1VCgvdTmobKiR6ZHk1rGZGBsYQ1DPM37YkM85
         VdkUAwmeDqFaq0xPAaRthj5enqpDeVV02bYutRM2SGSMm9Ry/yQ4z85lhQVskf2oPNnU
         kWBZdhiXGPcNXEMAZpkn4JfdGYDQqVSVzymbVTEkzBYQiqteWylxUGudCmwy3+7NeEk4
         iQZLetomMAcvVlOcW04JaylqCuCbflwiBcOu2ZFR2zoXgcrXskOunbQsCkZqXx4ktVA8
         yBVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GLC/zfQwcP3c+pjyiImAKQNlOE1CIfA0BjDJ+QH/E3E=;
        b=M9eZZz2/nu9PdWtMt4mz3ffpBed4hoZ4F9mSZ5Q+Vw+pNhjfNau1OTVxxbgCxcyV8B
         kFKbK5LQUaGlrMgVGJZfcPB7rq5m02+c5EXdoGgNDpvWNJD8gr3Gtdayanm8mrmZcwU9
         +fDRxhFCK5N2EDDalOWP0ACyYT99ZvhD3/wlbH8aT/XpyieyjS5Z/gVgokSsmRMyC5QA
         kTWCePiPOh+WsmsoRwc7pRhmH1QvdQDP0t/HLGYDTKDuZxBmcYY3HMlh19fhs/pqnAZj
         5GwMVtZhCom+jRuydcPDVGCVosVKQX+Z07E34Rb6LiyC4BHoYMG0HkEHGHbXKoeFfe05
         L2wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Mx8bYJkW;
       spf=pass (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::e33 as permitted sender) smtp.mailfrom=jim.cromie@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vs1-xe33.google.com (mail-vs1-xe33.google.com. [2607:f8b0:4864:20::e33])
        by gmr-mx.google.com with ESMTPS id a6si53021pls.4.2021.06.23.11.48.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Jun 2021 11:48:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::e33 as permitted sender) client-ip=2607:f8b0:4864:20::e33;
Received: by mail-vs1-xe33.google.com with SMTP id x12so2001556vsp.4
        for <kasan-dev@googlegroups.com>; Wed, 23 Jun 2021 11:48:31 -0700 (PDT)
X-Received: by 2002:a67:6948:: with SMTP id e69mr1873866vsc.26.1624474111208;
 Wed, 23 Jun 2021 11:48:31 -0700 (PDT)
MIME-Version: 1.0
References: <CAJfuBxxH9KVgJ7k0P5LX3fTSa4Pumcmu2NMC4P=TrGDVXE2ktQ@mail.gmail.com>
 <YNIaFnfnZPGVd1t3@codewreck.org> <CAJfuBxywD3QrsoGszMnVbF2RYcCF7r3h7sCOg6hK7K60E+4qKA@mail.gmail.com>
 <CAJfuBxw-JUpnENT9zNgTq2wdHqH-77pAjNuthoZYbtiCud4T=g@mail.gmail.com>
 <CAJfuBxxsye593-vWtXz5As0vBCYEMm_R9r+JL=YMuD6fg+QGNA@mail.gmail.com> <YNJQBc4dawzwMrhn@codewreck.org>
In-Reply-To: <YNJQBc4dawzwMrhn@codewreck.org>
From: jim.cromie@gmail.com
Date: Wed, 23 Jun 2021 12:48:04 -0600
Message-ID: <CAJfuBxzH7VEDgKLOn7gZThR4pPwMK_oKhbMMAFcE-i7gByPO6A@mail.gmail.com>
Subject: Re: [V9fs-developer] KCSAN BUG report on p9_client_cb / p9_client_rpc
To: Dominique Martinet <asmadeus@codewreck.org>
Cc: kasan-dev@googlegroups.com, v9fs-developer@lists.sourceforge.net, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jim.cromie@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Mx8bYJkW;       spf=pass
 (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::e33
 as permitted sender) smtp.mailfrom=jim.cromie@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Jun 22, 2021 at 3:03 PM Dominique Martinet
<asmadeus@codewreck.org> wrote:
>
> Hi,
>
> let's keep the lists in Cc :)
>
> jim.cromie@gmail.com wrote on Tue, Jun 22, 2021 at 02:55:19PM -0600:
> > heres a fuller report - Im seeing some new stuff here.
>
> Thanks, the one two should be the same as p9_client_cb / p9_client_rpc
> and p9_client_cb / p9_virtio_zc_request are very similar, and also the
> same to the first you had, so the patch didn't really work.
>
> I thought after sending it that it probably needs to be tag =
> READ_ONCE(req->tc.tag) instead of just assigning it... Would you mind
> trying that?
>

I tried it, still getting the reports.
I havent replicated it on a nearby work-tree
and I tried bisecting on the problem work-tree,
got past all my patches and problem remained.
So everything is suspect ...
I'll try to narrow things down.

heres the latest report, for the list

qemu-system-x86_64: warning: 9p: degraded performance: a reasonable
high msize should be chosen on client/guest side (chosen msize is <=
8192). See https://wiki.qemu.org/Documentation/9psetup#msize for
details.
[    8.566576] VFS: Mounted root (9p filesystem) readonly on device 0:22.
qemu-system-x86_64: warning: 9p: Multiple devices detected in same
VirtFS export, which might lead to file ID collisions and severe
misbehaviours on guest! You should either use a separate export for
each device shared from host or use virtfs option 'multidevs=remap'!
[    8.573452] devtmpfs: mounted
[    8.585150] Freeing unused decrypted memory: 2036K
[    8.589527] Freeing unused kernel image (initmem) memory: 3092K
[    8.591756] Write protecting the kernel read-only data: 30720k
[    8.601183] Freeing unused kernel image (text/rodata gap) memory: 2032K
[    8.604040] Freeing unused kernel image (rodata/data gap) memory: 440K
[    8.787167] x86/mm: Checked W+X mappings: passed, no W+X pages found.
[    8.788573] rodata_test: all tests were successful
[    8.789531] x86/mm: Checking user space page tables
[    8.968680] x86/mm: Checked W+X mappings: passed, no W+X pages found.
[    8.969933] Run /bin/sh as init process
[    9.537655] ==================================================================
[    9.538731] BUG: KCSAN: data-race in p9_client_cb / p9_virtio_zc_request
[    9.539873]
[    9.540113] write to 0xffff888005e5d000 of 4 bytes by interrupt on cpu 0:
[    9.541192]  p9_client_cb+0x27/0x110
[    9.541858]  req_done+0xd3/0x130
[    9.542482]  vring_interrupt+0xac/0x130
[    9.543171]  __handle_irq_event_percpu+0x64/0x260
[    9.544042]  handle_irq_event+0x93/0x120
[    9.544717]  handle_edge_irq+0x123/0x400
[    9.545429]  __common_interrupt+0x3e/0xa0
[    9.546001]  common_interrupt+0x7e/0xa0
[    9.546518]  asm_common_interrupt+0x1e/0x40
[    9.547127]  native_safe_halt+0xe/0x10
[    9.547846]  default_idle+0xa/0x10
[    9.548348]  default_idle_call+0x38/0xc0
[    9.548991]  do_idle+0x1e7/0x270
[    9.549548]  cpu_startup_entry+0x19/0x20
[    9.550180]  rest_init+0xd0/0xd2
[    9.550740]  arch_call_rest_init+0xa/0x11
[    9.551493]  start_kernel+0xacb/0xadd
[    9.552035]  secondary_startup_64_no_verify+0xc2/0xcb
[    9.552739]
[    9.552954] read to 0xffff888005e5d000 of 4 bytes by task 185 on cpu 1:
[    9.553986]  p9_virtio_zc_request+0x449/0x7b0
[    9.554586]  p9_client_zc_rpc.constprop.0+0x175/0x770
[    9.555421]  p9_client_read_once+0x24d/0x330
[    9.556013]  p9_client_read+0x81/0xa0
[    9.556518]  v9fs_fid_readpage+0xca/0x310
[    9.557084]  v9fs_vfs_readpage+0x28/0x30
[    9.557785]  filemap_read_page+0x6e/0x1a0
[    9.558337]  filemap_fault+0xc2a/0x1010
[    9.558874]  __do_fault+0x76/0x210
[    9.559343]  __handle_mm_fault+0x16fe/0x2010
[    9.559934]  handle_mm_fault+0x129/0x410
[    9.560472]  do_user_addr_fault+0x1b7/0x670
[    9.561052]  exc_page_fault+0x78/0x160
[    9.561569]  asm_exc_page_fault+0x1e/0x30
[    9.562122]
[    9.562336] Reported by Kernel Concurrency Sanitizer on:
[    9.563054] CPU: 1 PID: 185 Comm: mount Not tainted
5.13.0-rc7-dd7i-00040-g07a2fabfd89c-dirty #131
[    9.564368] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
BIOS 1.14.0-3.fc34 04/01/2014
[    9.565543] ==================================================================
[    9.842861] virtme-init: basic initialization done
[    9.870984] virtme-init: running systemd-tmpfiles
[   10.371613] ==================================================================
[   10.372752] BUG: KCSAN: data-race in p9_client_cb / p9_client_rpc
[   10.373617]
[   10.373832] write to 0xffff888005e5d000 of 4 bytes by interrupt on cpu 0:
[   10.374753]  p9_client_cb+0x27/0x110
[   10.375252]  req_done+0xd3/0x130
[   10.375749]  vring_interrupt+0xac/0x130
[   10.376282]  __handle_irq_event_percpu+0x64/0x260
[   10.376927]  handle_irq_event+0x93/0x120
[   10.377465]  handle_edge_irq+0x123/0x400
[   10.378035]  __common_interrupt+0x3e/0xa0
[   10.378611]  common_interrupt+0x7e/0xa0
[   10.379126]  asm_common_interrupt+0x1e/0x40
[   10.379720]  native_safe_halt+0xe/0x10
[   10.380271]  default_idle+0xa/0x10
[   10.380770]  default_idle_call+0x38/0xc0
[   10.381328]  do_idle+0x1e7/0x270
[   10.381835]  cpu_startup_entry+0x19/0x20
[   10.382358]  rest_init+0xd0/0xd2
[   10.382832]  arch_call_rest_init+0xa/0x11
[   10.383414]  start_kernel+0xacb/0xadd
[   10.383944]  secondary_startup_64_no_verify+0xc2/0xcb
[   10.384660]
[   10.384869] read to 0xffff888005e5d000 of 4 bytes by task 194 on cpu 1:
[   10.385832]  p9_client_rpc+0x1cf/0x860
[   10.386398]  p9_client_readlink+0x3b/0x110
[   10.386972]  v9fs_vfs_get_link_dotl+0x37/0x80
[   10.387568]  step_into+0xa7c/0xb60
[   10.388042]  walk_component+0x8a/0x270
[   10.388558]  path_lookupat+0xca/0x340
[   10.389065]  filename_lookup+0x134/0x2a0
[   10.389628]  user_path_at_empty+0x6d/0x90
[   10.390187]  vfs_statx+0x79/0x1a0
[   10.390681]  __do_sys_newfstatat+0x1e/0x40
[   10.391237]  __x64_sys_newfstatat+0x4e/0x60
[   10.391845]  do_syscall_64+0x42/0x80
[   10.392373]  entry_SYSCALL_64_after_hwframe+0x44/0xae
[   10.393082]
[   10.393310] Reported by Kernel Concurrency Sanitizer on:
[   10.394106] CPU: 1 PID: 194 Comm: systemd-tmpfile Not tainted
5.13.0-rc7-dd7i-00040-g07a2fabfd89c-dirty #131
[   10.395779] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
BIOS 1.14.0-3.fc34 04/01/2014
[   10.397131] ==================================================================
Failed to create directory or subvolume "/var/spool/cups/tmp": Permission denied

[   10.720448] virtme-init: starting udevd
[   10.784768] ==================================================================
[   10.785855] BUG: KCSAN: data-race in p9_client_cb / p9_client_rpc
[   10.786937]
[   10.787152] write to 0xffff888005e5d000 of 4 bytes by interrupt on cpu 0:
[   10.788185]  p9_client_cb+0x27/0x110
[   10.788687]  req_done+0xd3/0x130
[   10.789133]  vring_interrupt+0xac/0x130
[   10.789669]  __handle_irq_event_percpu+0x64/0x260
[   10.790306]  handle_irq_event+0x93/0x120
[   10.790845]  handle_edge_irq+0x123/0x400
[   10.791384]  __common_interrupt+0x3e/0xa0
[   10.791933]  common_interrupt+0x7e/0xa0
[   10.792460]  asm_common_interrupt+0x1e/0x40
[   10.793052]  native_safe_halt+0xe/0x10
[   10.793674]  default_idle+0xa/0x10
[   10.794293]  default_idle_call+0x38/0xc0
[   10.794914]  do_idle+0x1e7/0x270
[   10.795366]  cpu_startup_entry+0x19/0x20
[   10.795909]  rest_init+0xd0/0xd2
[   10.796353]  arch_call_rest_init+0xa/0x11
[   10.796911]  start_kernel+0xacb/0xadd
[   10.797459]  secondary_startup_64_no_verify+0xc2/0xcb
[   10.798153]
[   10.798367] read to 0xffff888005e5d000 of 4 bytes by task 196 on cpu 1:
[   10.799256]  p9_client_rpc+0x185/0x860
[   10.799776]  p9_client_clunk+0x99/0x150
[   10.800300]  v9fs_dentry_release+0x38/0x60
[   10.800863]  __dentry_kill+0x203/0x2b0
[   10.801374]  dput+0x217/0x480
[   10.801788]  path_openat+0x803/0x1860
[   10.802573]  do_filp_open+0x116/0x1f0
[   10.803322]  do_sys_openat2+0x91/0x190
[   10.804215]  __x64_sys_openat+0x9b/0xd0
[   10.805003]  do_syscall_64+0x42/0x80
[   10.805838]  entry_SYSCALL_64_after_hwframe+0x44/0xae
[   10.806854]
[   10.807226] Reported by Kernel Concurrency Sanitizer on:
[   10.808460] CPU: 1 PID: 196 Comm: systemd-udevd Not tainted
5.13.0-rc7-dd7i-00040-g07a2fabfd89c-dirty #131
[   10.810544] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
BIOS 1.14.0-3.fc34 04/01/2014
[   10.812337] ==================================================================
...
[   12.579025] ==================================================================
[   12.580064] BUG: KCSAN: data-race in p9_client_cb / p9_virtio_zc_request
[   12.580978]
[   12.581193] write to 0xffff888005e5d900 of 4 bytes by interrupt on cpu 0:
[   12.582107]  p9_client_cb+0x27/0x110
[   12.582647]  req_done+0xd3/0x130
[   12.583080]  vring_interrupt+0xac/0x130
[   12.583632]  __handle_irq_event_percpu+0x64/0x260
[   12.584335]  handle_irq_event+0x93/0x120
[   12.584899]  handle_edge_irq+0x123/0x400
[   12.585456]  __common_interrupt+0x3e/0xa0
[   12.586028]  common_interrupt+0x43/0xa0
[   12.586537]  asm_common_interrupt+0x1e/0x40
[   12.587179]
[   12.587387] read to 0xffff888005e5d900 of 4 bytes by task 238 on cpu 1:
[   12.588322]  p9_virtio_zc_request+0x449/0x7b0
[   12.588942]  p9_client_zc_rpc.constprop.0+0x175/0x770
[   12.589645]  p9_client_read_once+0x24d/0x330
[   12.590417]  p9_client_read+0x81/0xa0
[   12.590946]  v9fs_fid_readpage+0xca/0x310
[   12.591712]  v9fs_vfs_readpage+0x28/0x30
[   12.592470]  filemap_read_page+0x6e/0x1a0
[   12.593218]  filemap_fault+0xc2a/0x1010
[   12.593922]  __do_fault+0x76/0x210
[   12.594590]  __handle_mm_fault+0x16fe/0x2010
[   12.595219]  handle_mm_fault+0x129/0x410
[   12.596017]  do_user_addr_fault+0x1b7/0x670
[   12.596902]  exc_page_fault+0x78/0x160
[   12.597449]  asm_exc_page_fault+0x1e/0x30
[   12.597999]
[   12.598212] Reported by Kernel Concurrency Sanitizer on:
[   12.598927] CPU: 1 PID: 238 Comm: modprobe Not tainted
5.13.0-rc7-dd7i-00040-g07a2fabfd89c-dirty #131
[   12.600153] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
BIOS 1.14.0-3.fc34 04/01/2014
[   12.601318] ==================================================================
...
[   12.861485] ==================================================================
[   12.862516] BUG: KCSAN: data-race in virtqueue_get_buf_ctx_split+0x62/0x250
[   12.863531]
[   12.863796] race at unknown origin, with read to 0xffff888005dcb942
of 2 bytes by interrupt on cpu 0:
[   12.865289]  virtqueue_get_buf_ctx_split+0x62/0x250
[   12.866190]  virtqueue_get_buf+0x33/0x40
[   12.866890]  req_done+0x6c/0x130
[   12.867376]  vring_interrupt+0xac/0x130
[   12.867913]  __handle_irq_event_percpu+0x64/0x260
[   12.868559]  handle_irq_event+0x93/0x120
[   12.869109]  handle_edge_irq+0x123/0x400
[   12.869663]  __common_interrupt+0x3e/0xa0
[   12.870213]  common_interrupt+0x7e/0xa0
[   12.870840]  asm_common_interrupt+0x1e/0x40
[   12.871444]  native_safe_halt+0xe/0x10
[   12.872046]  default_idle+0xa/0x10
[   12.872628]  default_idle_call+0x38/0xc0
[   12.873214]  do_idle+0x1e7/0x270
[   12.873756]  cpu_startup_entry+0x19/0x20
[   12.874301]  rest_init+0xd0/0xd2
[   12.874855]  arch_call_rest_init+0xa/0x11
[   12.875418]  start_kernel+0xacb/0xadd
[   12.875950]  secondary_startup_64_no_verify+0xc2/0xcb
[   12.876683]
[   12.876893] Reported by Kernel Concurrency Sanitizer on:
[   12.877630] CPU: 0 PID: 0 Comm: swapper/0 Not tainted
5.13.0-rc7-dd7i-00040-g07a2fabfd89c-dirty #131
[   12.878962] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
BIOS 1.14.0-3.fc34 04/01/2014

> > Im running in a vm, using virtme, which uses 9p to share host filesystems
> > since 1st report to you, Ive added --smp 2 to my testing, it seems to
> > have increased reporting
>
> I'm ashamed to say I've just never tried KCSAN... I can give it a try over
> the next few weeks* if that patch + READ_ONCE doesn't cut it
>
> (*sorry)
>
> Thanks,
> --
> Dominique

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJfuBxzH7VEDgKLOn7gZThR4pPwMK_oKhbMMAFcE-i7gByPO6A%40mail.gmail.com.
