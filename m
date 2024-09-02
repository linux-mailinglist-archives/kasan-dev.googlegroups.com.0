Return-Path: <kasan-dev+bncBCXKTJ63SAARB242223AMGQEC7UCJMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CFC2968402
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Sep 2024 12:03:25 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id ca18e2360f4ac-82a124bc41asf514857339f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Sep 2024 03:03:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725271404; cv=pass;
        d=google.com; s=arc-20240605;
        b=BgKhhOMyECdZwIiQWi3s8ow6GHUocQJGpIOOGC66CQhtKUnPzaBVAx+fQYILfScrFf
         7nMhW7P3mXvGxODRXfjxvAUL/tT/Mh3l9rwos20/pY2W2Z+YBc6ev10Drnn6tV0IfCmL
         HCAcIj7iRTSlpaLGW6DHpWKlzrkLR7iUvZuYRoK9VThkmjxmRixoegLFVPO2JaINJ0dy
         qDdOeBjpZpdBF+yrMP837zZGBGS92hjJvoWBf4UdNHrtl9zQdLnVi/xNTa7ERqoP/V39
         aZb/SpiAEot8GDkq5vA7qNjwvLUwYqC2N0c6MSZXM1SWmxIfN0bZYpz3hAW3YthmfOyq
         kIDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NBAAuiCpNEmZxSx1FM+1a4NiZ7AE0ZBtKAon0CY+Mk0=;
        fh=LYwF3fN4CZ7hxWEZlLMBzyPKxkfayM5crWIIjiJSfKs=;
        b=UTAX05oAGSvic20VUgysGBsLLFhxhS6aFTndEOB7BJbH3x9vQ1VgG0QazFDc2FktYP
         XotcNepDs/j03KOmyxYIxMf/3pnNVlec0NqpyHGP+N7uu6NcmXE88F+1FiMNDFJ5NllM
         1njN26l0AyBy5cr7nP8+DogoWj8xFOJL2XGk1UY0Sizi7EOiaUZz/RqWKYqRF0ZzCRxR
         y1yxepJu5d6TVcoyk70+CtHoVkjlBj7LIkIXG5PvUXnldqC11r5FW1ZJd4xv1ux+7TWW
         zeZ51jkACOmop2htQRdNVzIoBEOkNIVlzmrGdJw5zHhwjOYZlgQAzHYPf85xrxAtKjXg
         1ZXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pvBW8q0i;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725271404; x=1725876204; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NBAAuiCpNEmZxSx1FM+1a4NiZ7AE0ZBtKAon0CY+Mk0=;
        b=Uvu25JKaNcGQX554qerKZ08Og6bK1l1grU1TkZKnECRE2/uz6H/sgAMK5caPvRgCE6
         7eu19KT6QiO67UFAif3pjCv5A+t5FIIp7oJkHs0rVuUP40hL1+CbKu8E7ITBiCnZbDFr
         nHbSmw1RwvrSjyM+mvOgUorPVzNrMBPBqPeSxl0nHABdXso3ePTdiyYv60SjlSJdpQxP
         NKmH8gBnnVafMl3Ohu0JG79U9ljWoSuuyn/w7uLcBpvcjD2xg7nekp/EEAcFw4q8rXXP
         xKL5Wi2Cv06gxAATyhNoGPiNGEmc6RwWbHxbsWWj1e+F8rrtsBfVVazuojLJJ3O6jeki
         29cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725271404; x=1725876204;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NBAAuiCpNEmZxSx1FM+1a4NiZ7AE0ZBtKAon0CY+Mk0=;
        b=PiK7zzOuAHzfuKJhjOfRQQCpvIsobnPsqNZHlneZcRMHvqyNc4uM1woXav+9xVfE5O
         rNQZj3uSpoauX0+8v6up1zLo5AfOMyS7Pyp9hEbcp0EKDV4z8GoYRldWAmlXxwMmysqY
         OsbvSg2oVXPptPYqi50XUpxhPFPpPk+193hEcxBFQoiLLTXlJCeFZVj99DKSoV1vAEdu
         kbQfW2bwRRXGQkrwJe6vOL3WKModv2uMuWVOieFSb5K6sjPlSN+0cPbn8ncA6SsJbE7H
         WXCH2G88+364r7Sd0TSps8Zh61whONeh6GejEOTdKRewoEQS4uaJkX/I0CAU2QV8nJjQ
         DgYw==
X-Forwarded-Encrypted: i=2; AJvYcCUDOcSD0WmJDt10uw2SVxkllu8hmKuav3xUblC3gxmBxUq+VfQn8MAkExFKEqk1jhazd51YBw==@lfdr.de
X-Gm-Message-State: AOJu0Yz5GhLRsX+j8OQyi9vMVM9tPUToDziIjJDb00kQdlQy8xqsyvXy
	th69DT0EFWKH96cKd0STlhvQnW8r0GNL+45YmlIip5yDFr70hzUT
X-Google-Smtp-Source: AGHT+IG5fHw2+dNRvaAyznjEwpor5t/F5IMwlBs3brL+l/RqY5MVWyrKzUHczr4cMQtc/ila5fbdBg==
X-Received: by 2002:a05:6e02:194d:b0:39b:37b9:6a8f with SMTP id e9e14a558f8ab-39f377e9e70mr165379085ab.7.1725271403696;
        Mon, 02 Sep 2024 03:03:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:13a7:b0:39d:52b9:5478 with SMTP id
 e9e14a558f8ab-39f37790c54ls15318215ab.0.-pod-prod-01-us; Mon, 02 Sep 2024
 03:03:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU3jrvCxqiQnej30zoPU9ggTTJ+EaWKWZILxFpH/AMJiMtbpQnUQ22OGh2n6Wte4eBfQJAwrjUQz9I=@googlegroups.com
X-Received: by 2002:a05:6e02:170f:b0:39a:1b0a:f0a9 with SMTP id e9e14a558f8ab-39f3786c15bmr168718315ab.23.1725271402785;
        Mon, 02 Sep 2024 03:03:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725271402; cv=none;
        d=google.com; s=arc-20240605;
        b=kmaKm8z6SaDFPwvklCCAz3iTeD99Ap6tEl6o0s8jncpZwKi/BwJZil8dp+oDhgswN3
         I9ePTy/Ctjz62qRNYV1Q4s0y6rKjhvbP/xqQG3LNpG7DHpd0zUwc31tHa5TcwzeO7sVV
         mO1XaVDwar2pflJzE8mRhlXIAOzzX/0ksIpomaVgMQ1jb18tKhfOfMhJ2SxWTP/+Vn8A
         mYJNow1iQoDO0jPF/zJXeudlVNeIb1otTua9dkbJKRp2NtABhvCxSCydGsxwpbRj93D9
         NEWKYoEz/KVmjocMNLD3n6+cZwv3xNoeaIWsE55+WZ8/X2JpKkI8JSnRjLbWy/wQIhDz
         00zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BpCAyKk7PEsq1N0Kwy6IWo8ryAf22vSmQMzbgUPv+rI=;
        fh=ObFiD8lkQU/DbduNiOSwCNxOM8XikMukNRfudkB5jjE=;
        b=lU+8mVEalDTsVPklKfb1J+CB18FUUZMgQLj4Lat2Km8dBeD8EnKInWX+RIH7PZYZDQ
         wrlsNaMDwt3zc6lHTQzB+r03+fiPPG3RPqkCuwEqr9iw2Nq8ku6YoAWqK+QuS3hqhF28
         METsHhA9Fcw5D87iHt2f6hSawXHh7RmlFSkLUq48KddjrcejpAlRjxDXW8b6Tnhd3u6f
         zcGzmdIeTgxEF4bwtciLZh+RKYKeo3W5OW9C5hLyqCOqsvpATFAtWZ4Sk+WI2PpRnQ30
         sEp8FnFVODtWGcF/Q4F9s1VRTOhASsrwILfmBhRZbB93ErNiB26LDEM7N+jwpb11uMLi
         4+pw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pvBW8q0i;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-39f49058af8si2180715ab.2.2024.09.02.03.03.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Sep 2024 03:03:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id d2e1a72fcca58-7141b04e7b5so2383955b3a.2
        for <kasan-dev@googlegroups.com>; Mon, 02 Sep 2024 03:03:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVKQ9tz3gds42n9xKFAOorqElW2ek2kSir4JrRtc4+qED2oFuu+A3EwtIrN0XW1Irg4sh2Z2Ozavyo=@googlegroups.com
X-Received: by 2002:a05:6a21:9214:b0:1c6:ae03:670b with SMTP id
 adf61e73a8af0-1cce0ff25e9mr15098292637.9.1725271401586; Mon, 02 Sep 2024
 03:03:21 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000f362e80620e27859@google.com> <20240830095254.GA7769@willie-the-truck>
 <86wmjwvatn.wl-maz@kernel.org>
In-Reply-To: <86wmjwvatn.wl-maz@kernel.org>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 2 Sep 2024 12:03:10 +0200
Message-ID: <CANp29Y6EJXFTOy6Pd466r+RwzaGHe7JQMTaqMPSO2s7ubm-PKw@mail.gmail.com>
Subject: Re: [syzbot] [arm?] upstream test error: KASAN: invalid-access Write
 in setup_arch
To: Marc Zyngier <maz@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Cc: Will Deacon <will@kernel.org>, 
	syzbot <syzbot+908886656a02769af987@syzkaller.appspotmail.com>, 
	catalin.marinas@arm.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=pvBW8q0i;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::42a as
 permitted sender) smtp.mailfrom=nogikh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

+kasan-dev

On Sat, Aug 31, 2024 at 7:53=E2=80=AFPM 'Marc Zyngier' via syzkaller-bugs
<syzkaller-bugs@googlegroups.com> wrote:
>
> On Fri, 30 Aug 2024 10:52:54 +0100,
> Will Deacon <will@kernel.org> wrote:
> >
> > On Fri, Aug 30, 2024 at 01:35:24AM -0700, syzbot wrote:
> > > Hello,
> > >
> > > syzbot found the following issue on:
> > >
> > > HEAD commit:    33faa93bc856 Merge branch kvmarm-master/next into kvm=
arm-m..
> > > git tree:       git://git.kernel.org/pub/scm/linux/kernel/git/kvmarm/=
kvmarm.git fuzzme
> >
> > +Marc, as this is his branch.
> >
> > > console output: https://syzkaller.appspot.com/x/log.txt?x=3D1398420b9=
80000
> > > kernel config:  https://syzkaller.appspot.com/x/.config?x=3D2b7b31c9a=
a1397ca
> > > dashboard link: https://syzkaller.appspot.com/bug?extid=3D908886656a0=
2769af987
> > > compiler:       gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils f=
or Debian) 2.40
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
> > > disk image (non-bootable): https://storage.googleapis.com/syzbot-asse=
ts/384ffdcca292/non_bootable_disk-33faa93b.raw.xz
> > > vmlinux: https://storage.googleapis.com/syzbot-assets/9093742fcee9/vm=
linux-33faa93b.xz
> > > kernel image: https://storage.googleapis.com/syzbot-assets/b1f5999079=
31/Image-33faa93b.gz.xz
> > >
> > > IMPORTANT: if you fix the issue, please add the following tag to the =
commit:
> > > Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
> > >
> > > Booting Linux on physical CPU 0x0000000000 [0x000f0510]
> > > Linux version 6.11.0-rc5-syzkaller-g33faa93bc856 (syzkaller@syzkaller=
) (gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #0=
 SMP PREEMPT now
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
> > > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > BUG: KASAN: invalid-access in smp_build_mpidr_hash arch/arm64/kernel/=
setup.c:133 [inline]
> > > BUG: KASAN: invalid-access in setup_arch+0x984/0xd60 arch/arm64/kerne=
l/setup.c:356
> > > Write of size 4 at addr 03ff800086867e00 by task swapper/0
> > > Pointer tag: [03], memory tag: [fe]
> > >
> > > CPU: 0 UID: 0 PID: 0 Comm: swapper Not tainted 6.11.0-rc5-syzkaller-g=
33faa93bc856 #0
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
> > > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
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
>
> Who knows enough about KASAN to dig into this?
>
>         M.
>
> --
> Without deviation from the norm, progress is not possible.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANp29Y6EJXFTOy6Pd466r%2BRwzaGHe7JQMTaqMPSO2s7ubm-PKw%40mail.gmai=
l.com.
