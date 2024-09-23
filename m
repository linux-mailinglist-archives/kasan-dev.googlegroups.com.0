Return-Path: <kasan-dev+bncBDV37XP3XYDRBCUOYW3QMGQEHWT3ERY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7140E97EA18
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2024 12:46:36 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2d88c8201bbsf1439944a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2024 03:46:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727088395; cv=pass;
        d=google.com; s=arc-20240605;
        b=fOYVaPY02O8cp00YX4iCP5Xt5Jl1sko0SuyT+bcrwQif+s9Saqq3jZ4mAPuh9vajVv
         bWeSZz2U+Ghken5AghapnrYzAj8aHgc6eUchk50kbuiL6h8So8/v1vHKcjf9oybBWG8Y
         RhJIbWMnU6ieQIR0LpGMI1apLyaClkIfDs++bXeNxdnFBBXUSQt3hSXrBrGguAuOyxEp
         aGaue+zF3wbGT8z9/kj99X+nqNBYWCSzfb43HdsJOXwEOWJywPK8i3SEXeIibirP4A2d
         8AyHwwZNMRaQ5x36eSOTOaBnnEdfaMHzj6CLH+4C7nNHS7Ag7CFsZF+Xy8Nef+nVWBGz
         d6EQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2X/sNLWUC9kU5Vkk3BL7DZCD6abH80hgsOTRlbTCoh4=;
        fh=TkzkfkCS9O2jfNqnTu+4qE8v86rhasCY70lTJgBdXD8=;
        b=g+uiyI8O1FTVDqhTlz44wsuAYc2UHNuCkfqVnfWb0MKu/gZanJqxgyaBr9WFDKo+eH
         lxbu2i+rGulmWa5k2NAh8gV82kOM4wYMswOgo4p68duEbO09HnR61R5UIBOFUBwbpwM1
         nNlFZpsRt7h88I9D5MO3bYEBI0SI++BWMn1ipEAs5kUQ9WL8OCVEuehrEmA0GWDVqh5P
         6D0Mxxyhu4r19rvovOGORlSqJvs7zwECx6hY5+wut0BgRjEfD6o1nxeCe+IGOTL4U2yK
         X+oVUWFEKcof1l1m01tj7DHhyWDqDjG9D3OZjBGzaGDDD+XyzuBQNRasYFiOL01ZM6E9
         MuMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727088395; x=1727693195; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2X/sNLWUC9kU5Vkk3BL7DZCD6abH80hgsOTRlbTCoh4=;
        b=oEPmgdawivM5H3X0RNE3rSgMyZu3fLlHkEHKQvlAfXBrcU7QTQ2/prfRDig/TIs/Sw
         C/tSpKmulKXsmEKzOzStLvnvnuefiOTPpubdZ0f6oU/bOcbq4t05ktaiGelPzYlyiYlx
         fQX8SM+Qu72vhtZwniLZRgFmcdlEzNgQ5xFTYjRoIDjwHBA+ZsQqb0Dvrp5VUk9WYOX3
         2Tdb2EN+pp97i+iE+Wog/8Tp5BdukYtjuJJ/orJjte9VFGuPDhlM9sUGNArOUfQssH/A
         +K7WdSQyNNJEkMPQGxcGPZqYlQtmoBPIZR5I5MZwOGcd7w6JIO0lz8QaIWi8xqP8XHXz
         MxOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727088395; x=1727693195;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2X/sNLWUC9kU5Vkk3BL7DZCD6abH80hgsOTRlbTCoh4=;
        b=rfsdAhyDTkCydVHSpwNsyQlphbiPfynfAB1CkaF9r4i6N7scHbOT+zJCxWClZTlp/v
         slIVtQXW6uJJzdqPa7CXJRxtGGC4JXFnI4g6Dl++hiAaLqqxsIddcybyJmIg0i3cLwrf
         Yn3Nad0BQb7LweuMj1V2APvSVxDGc3VIAtGKrZ8bqzX4NAc/I4OGQHHPCn5Huaep1mYy
         fQtyiRSzhkAVUr5ALMOm6fwCIpJf/9/pko3fdUC14eLcXy+DRVOuMO3HH7SNqHXtv5OV
         gxFqPCfvsAccSRVZAqbuMYyl2Yl2zUQ4JXwCyPjCPK5pOSJ9i9Li8YYlGiyILhBxXD37
         kbvg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXdKga8QS6wn1rGY/0p4I4NrifBPOt5ciB5WgY7L+WknpWUOVtYcURcld4nT1mLM19bTLG3Kw==@lfdr.de
X-Gm-Message-State: AOJu0Yx5zjeeRblrhUAjTPUOi9Z1lrL7t7NsCo208v9uZ97jr/c0ADhZ
	DTXwBQIhINUvDkgLejAv6iZsBmHP5pnYmHz23AuCGXMngKeBuVXH
X-Google-Smtp-Source: AGHT+IFRAqNjPSQLaqUuIF/rbGZHzDzuBJQr89ET7+VvsZYbxbFjIt+IzyCIwnKsdlss01SJ66VZHg==
X-Received: by 2002:a17:90a:bf10:b0:2db:60b:697d with SMTP id 98e67ed59e1d1-2dd7f7621a7mr5824870a91.7.1727088394674;
        Mon, 23 Sep 2024 03:46:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1c84:b0:2d8:8cca:31b4 with SMTP id
 98e67ed59e1d1-2dd6d6489bbls2693793a91.1.-pod-prod-06-us; Mon, 23 Sep 2024
 03:46:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVs9MKBnXBAF92tcCTtG1akCEh6BJOweIcdxC0/MUqPHjjuyBW9qEk2F8eHZ05FOW7ljSmdSpDIyvw=@googlegroups.com
X-Received: by 2002:a17:90b:4ac7:b0:2c9:9f2a:2b20 with SMTP id 98e67ed59e1d1-2dd7f450de3mr13405878a91.22.1727088392553;
        Mon, 23 Sep 2024 03:46:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727088392; cv=none;
        d=google.com; s=arc-20240605;
        b=k1cLa8Jf+hImDygdoJRXUVegrq9MBPhLn2zVoTYp6xd00Q/o0j2Kn6a/fjYYcCgRO/
         zHaEpmXRjizs4om/s2l+3LAUBXvkH9+1hwjHWWrDjbh+wr/dh41hREHw1sdIOAn1M9wu
         S7LPnSBEmBY3BlpKFDfGq2KCl9wUcN4GPDtxJ55wYN5LaKjy85SuogkLjhj8AKtSLr1H
         bmqrqLAVkMTcsZaeDVMxeve9252gCrJdtfxiixORjsT6bPuCH7te8uEnT+AWz+wtV8rg
         O2gmL1DbdMOYJGxyr20lnlt9ARNJ0ZKVThzXb/g2uih+2OirqyYdc2CJTYMACENOIoVT
         fkNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=MYg0eZvW3RzBuK+DJG9LR8HtK9A3cCv0DjsgrUS9oHY=;
        fh=uh2S5qsvQeU65eZak3HLe30IlQt5SVgXNaS+TjDF6es=;
        b=aDmUdnog0/nN4pdoKct5m/jPr54P8qpWu7Y5mYfUgfiiSexcN5LuIGKePi58QJaOEz
         2MMEu23qAOXHn2AWJ9p6+Mcbp+EwvwdAw6GARcf/rAd3tkfaHjrB0WNM2S5qLRGN2lVz
         uwVdw3xwUNdBM3p7xOJ+DSQd9K8vAWyNfnkhYOffXgSU3xBExuUqc/swCa81zkYsfJSO
         fvgxwJ98vJSynItRbGfy5RlW17OOKq/PJtIODGLZ2tbjExLbd5a1PTVRF//owInsxMRI
         vm7+Gg+m34+nb8CUnch50nDnRz/FzZ2NnaVleNrUGb5fWFuHHzzChP/zas8O4SVXqTjP
         Zx9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-2dd52e36330si1073014a91.1.2024.09.23.03.46.32;
        Mon, 23 Sep 2024 03:46:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id ED1E0FEC;
	Mon, 23 Sep 2024 03:47:00 -0700 (PDT)
Received: from J2N7QTR9R3 (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 67ACC3F71A;
	Mon, 23 Sep 2024 03:46:29 -0700 (PDT)
Date: Mon, 23 Sep 2024 11:46:24 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marc Zyngier <maz@kernel.org>
Cc: Will Deacon <will@kernel.org>,
	syzbot <syzbot+908886656a02769af987@syzkaller.appspotmail.com>,
	catalin.marinas@arm.com, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org, syzkaller-bugs@googlegroups.com,
	kasan-dev <kasan-dev@googlegroups.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>
Subject: Re: [syzbot] [arm?] upstream test error: KASAN: invalid-access Write
 in setup_arch
Message-ID: <ZvFGwKfoC4yVjN_X@J2N7QTR9R3>
References: <000000000000f362e80620e27859@google.com>
 <20240830095254.GA7769@willie-the-truck>
 <86wmjwvatn.wl-maz@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <86wmjwvatn.wl-maz@kernel.org>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

[adding KASAN folk]

There appears to be a GCC bug here, analysis below.

The issues with clang are unrelated, and I will follow up with a
separate mail for those.

On Sat, Aug 31, 2024 at 06:52:52PM +0100, Marc Zyngier wrote:
> On Fri, 30 Aug 2024 10:52:54 +0100,
> Will Deacon <will@kernel.org> wrote:
> > 
> > On Fri, Aug 30, 2024 at 01:35:24AM -0700, syzbot wrote:
> > > Hello,
> > > 
> > > syzbot found the following issue on:
> > > 
> > > HEAD commit:    33faa93bc856 Merge branch kvmarm-master/next into kvmarm-m..
> > > git tree:       git://git.kernel.org/pub/scm/linux/kernel/git/kvmarm/kvmarm.git fuzzme
> > 
> > +Marc, as this is his branch.
> >
> > > console output: https://syzkaller.appspot.com/x/log.txt?x=1398420b980000
> > > kernel config:  https://syzkaller.appspot.com/x/.config?x=2b7b31c9aa1397ca
> > > dashboard link: https://syzkaller.appspot.com/bug?extid=908886656a02769af987
> > > compiler:       gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40
> > > userspace arch: arm64
> 
> As it turns out, this isn't specific to this branch. I can reproduce
> it with this config on a vanilla 6.10 as a KVM guest. Even worse,
> compiling with clang results in an unbootable kernel (without any
> output at all).
> 
> Mind you, the binary is absolutely massive (130MB with gcc, 156MB with
> clang), and I wouldn't be surprised if we were hitting some kind of
> odd limit.
> 
> > > 
> > > Downloadable assets:
> > > disk image (non-bootable): https://storage.googleapis.com/syzbot-assets/384ffdcca292/non_bootable_disk-33faa93b.raw.xz
> > > vmlinux: https://storage.googleapis.com/syzbot-assets/9093742fcee9/vmlinux-33faa93b.xz
> > > kernel image: https://storage.googleapis.com/syzbot-assets/b1f599907931/Image-33faa93b.gz.xz
> > > 
> > > IMPORTANT: if you fix the issue, please add the following tag to the commit:
> > > Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
> > > 
> > > Booting Linux on physical CPU 0x0000000000 [0x000f0510]
> > > Linux version 6.11.0-rc5-syzkaller-g33faa93bc856 (syzkaller@syzkaller) (gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #0 SMP PREEMPT now
> > > random: crng init done
> > > Machine model: linux,dummy-virt
> > > efi: UEFI not found.
> > > NUMA: No NUMA configuration found
> > > NUMA: Faking a node at [mem 0x0000000040000000-0x00000000bfffffff]
> > > NUMA: NODE_DATA [mem 0xbfc1d340-0xbfc20fff]
> > > Zone ranges:
> > >   DMA      [mem 0x0000000040000000-0x00000000bfffffff]
> > >   DMA32    empty
> > >   Normal   empty
> > >   Device   empty
> > > Movable zone start for each node
> > > Early memory node ranges
> > >   node   0: [mem 0x0000000040000000-0x00000000bfffffff]
> > > Initmem setup node 0 [mem 0x0000000040000000-0x00000000bfffffff]
> > > cma: Reserved 32 MiB at 0x00000000bba00000 on node -1
> > > psci: probing for conduit method from DT.
> > > psci: PSCIv1.1 detected in firmware.
> > > psci: Using standard PSCI v0.2 function IDs
> > > psci: Trusted OS migration not required
> > > psci: SMC Calling Convention v1.0
> > > ==================================================================
> > > BUG: KASAN: invalid-access in smp_build_mpidr_hash arch/arm64/kernel/setup.c:133 [inline]
> > > BUG: KASAN: invalid-access in setup_arch+0x984/0xd60 arch/arm64/kernel/setup.c:356
> > > Write of size 4 at addr 03ff800086867e00 by task swapper/0
> > > Pointer tag: [03], memory tag: [fe]
> > > 
> > > CPU: 0 UID: 0 PID: 0 Comm: swapper Not tainted 6.11.0-rc5-syzkaller-g33faa93bc856 #0
> > > Hardware name: linux,dummy-virt (DT)
> > > Call trace:
> > >  dump_backtrace+0x204/0x3b8 arch/arm64/kernel/stacktrace.c:317
> > >  show_stack+0x2c/0x3c arch/arm64/kernel/stacktrace.c:324
> > >  __dump_stack lib/dump_stack.c:93 [inline]
> > >  dump_stack_lvl+0x260/0x3b4 lib/dump_stack.c:119
> > >  print_address_description mm/kasan/report.c:377 [inline]
> > >  print_report+0x118/0x5ac mm/kasan/report.c:488
> > >  kasan_report+0xc8/0x108 mm/kasan/report.c:601
> > >  kasan_check_range+0x94/0xb8 mm/kasan/sw_tags.c:84
> > >  __hwasan_store4_noabort+0x20/0x2c mm/kasan/sw_tags.c:149
> > >  smp_build_mpidr_hash arch/arm64/kernel/setup.c:133 [inline]
> > >  setup_arch+0x984/0xd60 arch/arm64/kernel/setup.c:356
> > >  start_kernel+0xe0/0xff0 init/main.c:926
> > >  __primary_switched+0x84/0x8c arch/arm64/kernel/head.S:243
> > > 
> > > The buggy address belongs to stack of task swapper/0
> > > 
> > > Memory state around the buggy address:
> > >  ffff800086867c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> > >  ffff800086867d00: 00 fe fe 00 00 00 fe fe fe fe fe fe fe fe fe fe
> > > >ffff800086867e00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> > >                    ^
> > >  ffff800086867f00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> > >  ffff800086868000: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> > > ==================================================================
> > 
> > I can't spot the issue here. We have a couple of fixed-length
> > (4 element) arrays on the stack and they're indexed by a simple loop
> > counter that runs from 0-3.
> 
> Having trimmed the config to the extreme, I can only trigger the
> warning with CONFIG_KASAN_SW_TAGS (CONFIG_KASAN_GENERIC does not
> scream). Same thing if I use gcc 14.2.0.
> 
> However, compiling with clang 14 (Debian clang version 14.0.6) does
> *not* result in a screaming kernel, even with KASAN_SW_TAGS.
> 
> So I can see two possibilities here:
> 
> - either gcc is incompatible with KASAN_SW_TAGS and the generic
>   version is the only one that works
> 
> - or we have a compiler bug on our hands.
> 
> Frankly, I can't believe the later, as the code is so daft that I
> can't imagine gcc getting it *that* wrong.

It looks like what's happening here is:

(1) With CONFIG_KASAN_SW_TAGS=y we pass the compiler
    `-fsanitize=kernel-hwaddress`.

(2) When GCC is passed `-fsanitize=hwaddress` or
    `-fsanitize=kernel-hwaddress` it ignores
    `__attribute__((no_sanitize_address))`, and instruments functions we
    require are not instrumented.

    I believe this is a compiler bug, as there doesn't seem to be a
    separate attribute to prevent instrumentation in this mode.

(3) In this config, smp_build_mpidr_hash() gets inlined into
    setup_arch(), and as setup_arch() is instrumented, all of the stack
    variables for smp_build_mpidr_hash() are initialized at the start of
    setup_arch(), with calls to __hwasan_tag_memory().

    At this point, we are using the early shadow (where a single page of
    shadow is used for all memory).

(4) In setup_arch(), we call kasan_init() to transition from the early
    shadow to the runtime shadow. This replaces the early shadow memory
    with new shadow memory initialized to KASAN_SHADOW_INIT (0xFE AKA
    KASAN_TAG_INVALID), including the shadow for the stack.

(5) Once the CPU returns back into setup_arch(), it's using the new
    shadow initialized to 0xFE. Subsequent stack accesses which check
    the shadow see 0xFE in the shadow, and fault. Note that in the dump
    of the shadow above, the shadow around ffff800086867d80 and above is
    all 0xFE, while below that functions have managed to clear the
    shadow.

Compiler test case below. Note that this demonstrates the compiler
ignores  `__attribute__((no_sanitize_address))` regardless of
KASAN_STACK, so KASAN_SW_TAGS is generally broken with GCC. All versions
I tried were broken, from 11.3.0 to 14.2.0 inclusive.

I think we have to disable KASAN_SW_TAGS with GCC until this is fixed.

| [mark@lakrids:/mnt/data/tests/kasan-tags]% cat test.c
| #define __nsa           __attribute__((no_sanitize_address))
| 
| long __nsa load_long(long *ptr)
| {
|         return *ptr;
| }
| 
| void __nsa store_long(long *ptr, long val)
| {
|         *ptr = val;
| }
| 
| void extern_func(void);
| 
| long __nsa stack_func(void)
| {
|         volatile long val = 0;
|         extern_func();
|         return val;
| }
| [mark@lakrids:/mnt/data/tests/kasan-tags]% usekorg 12.1.0 aarch64-linux-gcc -c test.c -O2  -fsanitize=kernel-hwaddress
| [mark@lakrids:/mnt/data/tests/kasan-tags]% usekorg 14.2.0 aarch64-linux-objdump -d test.o
| 
| test.o:     file format elf64-littleaarch64
| 
| 
| Disassembly of section .text:
| 
| 0000000000000000 <load_long>:
|    0:   a9be7bfd        stp     x29, x30, [sp, #-32]!
|    4:   910003fd        mov     x29, sp
|    8:   f9000bf3        str     x19, [sp, #16]
|    c:   aa0003f3        mov     x19, x0
|   10:   94000000        bl      0 <__hwasan_load8_noabort>
|   14:   f9400260        ldr     x0, [x19]
|   18:   f9400bf3        ldr     x19, [sp, #16]
|   1c:   a8c27bfd        ldp     x29, x30, [sp], #32
|   20:   d65f03c0        ret
| 
| 0000000000000024 <store_long>:
|   24:   a9be7bfd        stp     x29, x30, [sp, #-32]!
|   28:   910003fd        mov     x29, sp
|   2c:   a90153f3        stp     x19, x20, [sp, #16]
|   30:   aa0003f3        mov     x19, x0
|   34:   aa0103f4        mov     x20, x1
|   38:   94000000        bl      0 <__hwasan_store8_noabort>
|   3c:   f9000274        str     x20, [x19]
|   40:   a94153f3        ldp     x19, x20, [sp, #16]
|   44:   a8c27bfd        ldp     x29, x30, [sp], #32
|   48:   d65f03c0        ret
|   4c:   d503201f        nop
| 
| 0000000000000050 <stack_func>:
|   50:   a9be7bfd        stp     x29, x30, [sp, #-32]!
|   54:   910003fd        mov     x29, sp
|   58:   f9000fff        str     xzr, [sp, #24]
|   5c:   94000000        bl      0 <extern_func>
|   60:   f9400fe0        ldr     x0, [sp, #24]
|   64:   a8c27bfd        ldp     x29, x30, [sp], #32
|   68:   d65f03c0        ret
| [mark@lakrids:/mnt/data/tests/kasan-tags]% usekorg 12.1.0 aarch64-linux-gcc -c test.c -O2  -fsanitize=kernel-hwaddress  --param hwasan-instrument-stack=1
| [mark@lakrids:/mnt/data/tests/kasan-tags]% usekorg 14.2.0 aarch64-linux-objdump -d test.o
| 
| test.o:     file format elf64-littleaarch64
| 
| 
| Disassembly of section .text:
| 
| 0000000000000000 <load_long>:
|    0:   a9be7bfd        stp     x29, x30, [sp, #-32]!
|    4:   910003fd        mov     x29, sp
|    8:   f9000bf3        str     x19, [sp, #16]
|    c:   aa0003f3        mov     x19, x0
|   10:   94000000        bl      0 <__hwasan_load8_noabort>
|   14:   f9400260        ldr     x0, [x19]
|   18:   f9400bf3        ldr     x19, [sp, #16]
|   1c:   a8c27bfd        ldp     x29, x30, [sp], #32
|   20:   d65f03c0        ret
| 
| 0000000000000024 <store_long>:
|   24:   a9be7bfd        stp     x29, x30, [sp, #-32]!
|   28:   910003fd        mov     x29, sp
|   2c:   a90153f3        stp     x19, x20, [sp, #16]
|   30:   aa0003f3        mov     x19, x0
|   34:   aa0103f4        mov     x20, x1
|   38:   94000000        bl      0 <__hwasan_store8_noabort>
|   3c:   f9000274        str     x20, [x19]
|   40:   a94153f3        ldp     x19, x20, [sp, #16]
|   44:   a8c27bfd        ldp     x29, x30, [sp], #32
|   48:   d65f03c0        ret
|   4c:   d503201f        nop
| 
| 0000000000000050 <stack_func>:
|   50:   a9bd7bfd        stp     x29, x30, [sp, #-48]!
|   54:   d2800202        mov     x2, #0x10                       // #16
|   58:   9100c3e0        add     x0, sp, #0x30
|   5c:   910003fd        mov     x29, sp
|   60:   d378fc01        lsr     x1, x0, #56
|   64:   910083e0        add     x0, sp, #0x20
|   68:   11000821        add     w1, w1, #0x2
|   6c:   f9000bf3        str     x19, [sp, #16]
|   70:   94000000        bl      0 <__hwasan_tag_memory>
|   74:   d2e04000        mov     x0, #0x200000000000000          // #144115188075855872
|   78:   8b2063e0        add     x0, sp, x0
|   7c:   f900101f        str     xzr, [x0, #32]
|   80:   94000000        bl      0 <extern_func>
|   84:   d2e04000        mov     x0, #0x200000000000000          // #144115188075855872
|   88:   8b2063e0        add     x0, sp, x0
|   8c:   d2800202        mov     x2, #0x10                       // #16
|   90:   52800001        mov     w1, #0x0                        // #0
|   94:   f9401013        ldr     x19, [x0, #32]
|   98:   910083e0        add     x0, sp, #0x20
|   9c:   94000000        bl      0 <__hwasan_tag_memory>
|   a0:   aa1303e0        mov     x0, x19
|   a4:   f9400bf3        ldr     x19, [sp, #16]
|   a8:   a8c37bfd        ldp     x29, x30, [sp], #48
|   ac:   d65f03c0        ret
| [mark@lakrids:/mnt/data/tests/kasan-tags]%
| [mark@lakrids:/mnt/data/tests/kasan-tags]% usekorg 12.1.0 aarch64-linux-gcc -c test.c -O2  -fsanitize=hwaddress
| [mark@lakrids:/mnt/data/tests/kasan-tags]% usekorg 14.2.0 aarch64-linux-objdump -d test.o
| 
| test.o:     file format elf64-littleaarch64
| 
| 
| Disassembly of section .text:
| 
| 0000000000000000 <load_long>:
|    0:   a9be7bfd        stp     x29, x30, [sp, #-32]!
|    4:   910003fd        mov     x29, sp
|    8:   f9000bf3        str     x19, [sp, #16]
|    c:   aa0003f3        mov     x19, x0
|   10:   94000000        bl      0 <__hwasan_load8>
|   14:   f9400260        ldr     x0, [x19]
|   18:   f9400bf3        ldr     x19, [sp, #16]
|   1c:   a8c27bfd        ldp     x29, x30, [sp], #32
|   20:   d65f03c0        ret
| 
| 0000000000000024 <store_long>:
|   24:   a9be7bfd        stp     x29, x30, [sp, #-32]!
|   28:   910003fd        mov     x29, sp
|   2c:   a90153f3        stp     x19, x20, [sp, #16]
|   30:   aa0003f3        mov     x19, x0
|   34:   aa0103f4        mov     x20, x1
|   38:   94000000        bl      0 <__hwasan_store8>
|   3c:   f9000274        str     x20, [x19]
|   40:   a94153f3        ldp     x19, x20, [sp, #16]
|   44:   a8c27bfd        ldp     x29, x30, [sp], #32
|   48:   d65f03c0        ret
|   4c:   d503201f        nop
| 
| 0000000000000050 <stack_func>:
|   50:   a9bd7bfd        stp     x29, x30, [sp, #-48]!
|   54:   910003fd        mov     x29, sp
|   58:   f9000bf3        str     x19, [sp, #16]
|   5c:   94000000        bl      0 <__hwasan_generate_tag>
|   60:   9100c3e1        add     x1, sp, #0x30
|   64:   d2800202        mov     x2, #0x10                       // #16
|   68:   aa00e033        orr     x19, x1, x0, lsl #56
|   6c:   910083e0        add     x0, sp, #0x20
|   70:   d378fe61        lsr     x1, x19, #56
|   74:   94000000        bl      0 <__hwasan_tag_memory>
|   78:   f81f027f        stur    xzr, [x19, #-16]
|   7c:   94000000        bl      0 <extern_func>
|   80:   f85f0273        ldur    x19, [x19, #-16]
|   84:   910083e0        add     x0, sp, #0x20
|   88:   d2800202        mov     x2, #0x10                       // #16
|   8c:   52800001        mov     w1, #0x0                        // #0
|   90:   94000000        bl      0 <__hwasan_tag_memory>
|   94:   aa1303e0        mov     x0, x19
|   98:   f9400bf3        ldr     x19, [sp, #16]
|   9c:   a8c37bfd        ldp     x29, x30, [sp], #48
|   a0:   d65f03c0        ret
| 
| Disassembly of section .text.startup:
| 
| 0000000000000000 <_sub_I_00099_0>:
|    0:   14000000        b       0 <__hwasan_init>
| [mark@lakrids:/mnt/data/tests/kasan-tags]% usekorg 12.1.0 aarch64-linux-gcc -c test.c -O2  -fsanitize=hwaddress  --param hwasan-instrument-stack=1
| [mark@lakrids:/mnt/data/tests/kasan-tags]% usekorg 14.2.0 aarch64-linux-objdump -d test.o
| 
| test.o:     file format elf64-littleaarch64
| 
| 
| Disassembly of section .text:
| 
| 0000000000000000 <load_long>:
|    0:   a9be7bfd        stp     x29, x30, [sp, #-32]!
|    4:   910003fd        mov     x29, sp
|    8:   f9000bf3        str     x19, [sp, #16]
|    c:   aa0003f3        mov     x19, x0
|   10:   94000000        bl      0 <__hwasan_load8>
|   14:   f9400260        ldr     x0, [x19]
|   18:   f9400bf3        ldr     x19, [sp, #16]
|   1c:   a8c27bfd        ldp     x29, x30, [sp], #32
|   20:   d65f03c0        ret
| 
| 0000000000000024 <store_long>:
|   24:   a9be7bfd        stp     x29, x30, [sp, #-32]!
|   28:   910003fd        mov     x29, sp
|   2c:   a90153f3        stp     x19, x20, [sp, #16]
|   30:   aa0003f3        mov     x19, x0
|   34:   aa0103f4        mov     x20, x1
|   38:   94000000        bl      0 <__hwasan_store8>
|   3c:   f9000274        str     x20, [x19]
|   40:   a94153f3        ldp     x19, x20, [sp, #16]
|   44:   a8c27bfd        ldp     x29, x30, [sp], #32
|   48:   d65f03c0        ret
|   4c:   d503201f        nop
| 
| 0000000000000050 <stack_func>:
|   50:   a9bd7bfd        stp     x29, x30, [sp, #-48]!
|   54:   910003fd        mov     x29, sp
|   58:   f9000bf3        str     x19, [sp, #16]
|   5c:   94000000        bl      0 <__hwasan_generate_tag>
|   60:   9100c3e1        add     x1, sp, #0x30
|   64:   d2800202        mov     x2, #0x10                       // #16
|   68:   aa00e033        orr     x19, x1, x0, lsl #56
|   6c:   910083e0        add     x0, sp, #0x20
|   70:   d378fe61        lsr     x1, x19, #56
|   74:   94000000        bl      0 <__hwasan_tag_memory>
|   78:   f81f027f        stur    xzr, [x19, #-16]
|   7c:   94000000        bl      0 <extern_func>
|   80:   f85f0273        ldur    x19, [x19, #-16]
|   84:   910083e0        add     x0, sp, #0x20
|   88:   d2800202        mov     x2, #0x10                       // #16
|   8c:   52800001        mov     w1, #0x0                        // #0
|   90:   94000000        bl      0 <__hwasan_tag_memory>
|   94:   aa1303e0        mov     x0, x19
|   98:   f9400bf3        ldr     x19, [sp, #16]
|   9c:   a8c37bfd        ldp     x29, x30, [sp], #48
|   a0:   d65f03c0        ret
| 
| Disassembly of section .text.startup:
| 
| 0000000000000000 <_sub_I_00099_0>:
|    0:   14000000        b       0 <__hwasan_init>

Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZvFGwKfoC4yVjN_X%40J2N7QTR9R3.
