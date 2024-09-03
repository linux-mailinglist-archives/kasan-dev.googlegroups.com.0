Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXG33S3AMGQE2MC72CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AD6396A2FD
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2024 17:40:14 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2d87b7618d3sf4639029a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2024 08:40:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725378012; cv=pass;
        d=google.com; s=arc-20240605;
        b=YU4TDOaCcVpzKVQKh/PWhOECli1S6tH0Ye9YEW/SfrSklnA5DF/nRydsqtvdf2csIg
         lWguY/UwsUY/b9e8IA/cPrO9JCUnjz2fMXPL7VexcqifCWLJYC18DEj43EuwQxkBtcal
         8Z1kGEmoQqiy7TCvblegOa7AuVHbWEgWKELbNQ8gp4MWg764d8k05Kwqm3WUE2qgRWJA
         Yv9M4v7bZ8Lrf5mV4ZVG9Gtelipz/aEnSzHAmaFB32dJ4QK/RNDDifsRv8drGJc+BlzC
         LOY8MMWU2C5Ia33KLpgr0HPtHALzKTxM5NBVAoACA9vMNmfZAdbZAc7r3ct/LkQFcHhO
         9K3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xOitdWjw8PWq/v2OmhSyLW2pdRGAU9f6c/9X/k6UNHY=;
        fh=OgWB+z21VHOfE64npyAqVxgEL4dDHeEI64pf6LF44x4=;
        b=TtpCksez05Vg+E4RCM5nC27e/ZIggTH6/CL2tNpy3zAlvmM3Ix6x3WKTyNOmFFsEvU
         ae2YgLrt1rUrY26jxm1zF/HQ4JBc50ihVxgXaF7mBPwOo9Nb7U55OpyH9FoYPKALNvZF
         2g93s8QTRfoJfb3gX5+9lIJq0Oa8gNhzE0Ri2DKIdi/cmL0MbY+jsH73ZMEliUKkn9Cb
         QZCpztK+sjiDGIVq8tT/p8QpebkLnBCyTtVY0q3tP/jofInsKKkUg1ma2l/XpYjPm5o5
         WbB+WOr3GgEgl1oQyq04E6rNNshPaG4lH4cEENV2Rm70N1ux138uYy4LJURgKiHnm/6q
         9gyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zl4ov3ih;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725378012; x=1725982812; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xOitdWjw8PWq/v2OmhSyLW2pdRGAU9f6c/9X/k6UNHY=;
        b=Qrqu+o4HqbomRUlK9bAd6hGDNlFPKyjjRUJaxI31bH51r5ZYxbq/VAV7+OFUCXXnL5
         YgY0MVEh0UVYxMidVKc/5EjfXz88+I+1zF/8G2L36B0nIBpKIYkoA+JwruKHm6Boyhmm
         npp/X7ssqYJSTXKwdxOE8zEDr/XA+bQRDqCM8qNB3gwU1lX+pLW8L5FyKeSeWD9SY0t9
         4EYc0HWkhYrjM/QhRhJQAFGf2StH1Epa3JzPE1u+eA4uruCPJYdfc9W+xLDg8ZQoUx3V
         VVOGiFEh8GW8M6gjHGYIJ/iPuhc5rKBjpV4xRt2FoQNoTNYtW6MDg0XnjfcbQGoshJk7
         YOhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725378012; x=1725982812;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xOitdWjw8PWq/v2OmhSyLW2pdRGAU9f6c/9X/k6UNHY=;
        b=HpImF/YXvRhf0SDwUPy3mVMI1BmMxZJXFTeijLyBL0JaFETRb9PdN0i/xHyD8t2QR3
         xKXn6LwXtX5RncRKN8RSFPI28ytr9zzd4/jGidiT144Bk7v4tTGqdjNZDmsOnCJjLSRb
         v5gtpLtjT37HlKXUGV+W/VjuJsZGjSTkNuUvJIooqvD3n28pjZymrRonaBuSn9leXe1Q
         Y/+vfCsOGuRoJWsejDLhNHTjrGEEzT3LQ2tnzUXTtHRUzRftp2jy3krabDFoq33uSF6p
         tnh826c4YydMbL1v1KaYLTFngNO2E8enjbdvT+bNZLBwFUaKyWn/K+G6atn786XFdGZW
         bDlw==
X-Forwarded-Encrypted: i=2; AJvYcCUZyjE1H4YfFfao+iK8jOpmSPCEFOST7Wuu7yv+Y5zB7MeKE4J5jwGPYWLXGyUAU1XVXDk9kQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy2X/MBX2V7l804PALtTWM8Nn9O43GYD2ZhJvu2sWHWNtlaW7uT
	5us8HUjbkEhgxaAFFMlj8ct5SJuL7f6GqsmsYynwOQTq614vLDp5
X-Google-Smtp-Source: AGHT+IFODI7apHdDpN/yA6mwuTkMCcSPmZ6I7kBa3Dx3oKI0m/X7WoKQ1hkV1/0choPJ+XSoVO/eXg==
X-Received: by 2002:a17:90b:4c12:b0:2da:6367:f1d9 with SMTP id 98e67ed59e1d1-2da6367f38bmr2177772a91.41.1725378012300;
        Tue, 03 Sep 2024 08:40:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b701:b0:2cb:4a85:9588 with SMTP id
 98e67ed59e1d1-2d8548ae775ls3611737a91.1.-pod-prod-03-us; Tue, 03 Sep 2024
 08:40:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVAMMpov5XGn/l6rYB8DMPLFDq1i+eMo5h6mXascCNQJI/NoqcfIaYfCNBtT8F2YrvNsxzpIol05SY=@googlegroups.com
X-Received: by 2002:a17:90b:c12:b0:2d3:b49f:ace3 with SMTP id 98e67ed59e1d1-2d85638576dmr17575624a91.28.1725378011106;
        Tue, 03 Sep 2024 08:40:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725378011; cv=none;
        d=google.com; s=arc-20240605;
        b=QGW1gy6JsVlHyvSkbP6ebI7khNKWtwZ/GcroFn8TCbG+byOwR6ce3KaQpH575w/oBd
         0dMliFMISf5v6QKO7WaFO6YRtcqsNtz+WxlLkR0aQeOxRs8NSw9juxri5yMPg+BnjghJ
         PMZ9dzgG6+XwA9pjZcNORpr3/JB8DWQ7QxE6JnIaO+i2p/5EF7jiv5LOhLmZP93VFg2E
         k3nGJb9JX4kACHQPzhJk8/HTpqXZWQUaf3+RblfCC2tLB4T+I3i9tDjmydEk2kcuJS+T
         MByeycZ0BP5dx3LM63YE1y0o8mwxEe2LIOOEV3rzKkiyHpMUO50RpvtM9k8nHz3vjubm
         PIOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UzXSlxGfKWVyRi9Uw6NqDM+eL1Sfc+odIMySq3e0KgY=;
        fh=nj03YWJF6ZJ4pyv87FJEBeF3XHdmUA1swq4RbuBCeao=;
        b=ZMlq8f8z1G9nmkxkMV+iAhWb4RvAYOySPlAsmbWy5+Fd+T3C7Zl8+aeUex2vbUPbxB
         npA4HGZAB6duUbPWodOeEr6mgu4zI+rlCoLTr3MtyHAFbb0zav222Ee7Nq1KuPmRosku
         1o7ovlc8qmvYtshhEiMQPPjobX42qm/VfEmT66zx+poSORmT1sbqPk99o0oNCi68ClKH
         tdsyLEat97RsGUjGacK5mdlZLUFVZalb7D2CmcRaLLkWIOaU0sao+4LRPDfqPWFmQ/S/
         q/GjCqTLSZro2cu6XC5MQ0N+QmRobje5FpMl8Nzzkx3yKEa34XKMIP9J4yFrKJSg+t5/
         uAXQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zl4ov3ih;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x835.google.com (mail-qt1-x835.google.com. [2607:f8b0:4864:20::835])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2da82d71c63si452a91.2.2024.09.03.08.40.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Sep 2024 08:40:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::835 as permitted sender) client-ip=2607:f8b0:4864:20::835;
Received: by mail-qt1-x835.google.com with SMTP id d75a77b69052e-4568e321224so27175071cf.2
        for <kasan-dev@googlegroups.com>; Tue, 03 Sep 2024 08:40:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUOgsEn9egPAF306sWWHXkoAfQ3Cv6Y7kMQ9GxtMkHXAB9HVI3uwin1zQk3SiNDBIWJyLdrvpOGH+0=@googlegroups.com
X-Received: by 2002:a05:6214:3a89:b0:6c3:6315:f287 with SMTP id
 6a1803df08f44-6c36315f363mr91001986d6.3.1725378010342; Tue, 03 Sep 2024
 08:40:10 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000f362e80620e27859@google.com> <20240830095254.GA7769@willie-the-truck>
 <86wmjwvatn.wl-maz@kernel.org> <CANp29Y6EJXFTOy6Pd466r+RwzaGHe7JQMTaqMPSO2s7ubm-PKw@mail.gmail.com>
In-Reply-To: <CANp29Y6EJXFTOy6Pd466r+RwzaGHe7JQMTaqMPSO2s7ubm-PKw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Sep 2024 17:39:28 +0200
Message-ID: <CAG_fn=UbWvN=FiXjU_QZKm_qDhxU8dZQ4fgELXsRsPCj4YHp9A@mail.gmail.com>
Subject: Re: [syzbot] [arm?] upstream test error: KASAN: invalid-access Write
 in setup_arch
To: samuel.holland@sifive.com, Andrey Konovalov <andreyknvl@gmail.com>
Cc: Marc Zyngier <maz@kernel.org>, Aleksandr Nogikh <nogikh@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Will Deacon <will@kernel.org>, 
	syzbot <syzbot+908886656a02769af987@syzkaller.appspotmail.com>, 
	catalin.marinas@arm.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=zl4ov3ih;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::835 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Mon, Sep 2, 2024 at 12:03=E2=80=AFPM 'Aleksandr Nogikh' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> +kasan-dev
>
> On Sat, Aug 31, 2024 at 7:53=E2=80=AFPM 'Marc Zyngier' via syzkaller-bugs
> <syzkaller-bugs@googlegroups.com> wrote:
> >
> > On Fri, 30 Aug 2024 10:52:54 +0100,
> > Will Deacon <will@kernel.org> wrote:
> > >
> > > On Fri, Aug 30, 2024 at 01:35:24AM -0700, syzbot wrote:
> > > > Hello,
> > > >
> > > > syzbot found the following issue on:
> > > >
> > > > HEAD commit:    33faa93bc856 Merge branch kvmarm-master/next into k=
vmarm-m..
> > > > git tree:       git://git.kernel.org/pub/scm/linux/kernel/git/kvmar=
m/kvmarm.git fuzzme
> > >
> > > +Marc, as this is his branch.
> > >
> > > > console output: https://syzkaller.appspot.com/x/log.txt?x=3D1398420=
b980000
> > > > kernel config:  https://syzkaller.appspot.com/x/.config?x=3D2b7b31c=
9aa1397ca
> > > > dashboard link: https://syzkaller.appspot.com/bug?extid=3D908886656=
a02769af987
> > > > compiler:       gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils=
 for Debian) 2.40
> > > > userspace arch: arm64
> >
> > As it turns out, this isn't specific to this branch. I can reproduce
> > it with this config on a vanilla 6.10 as a KVM guest. Even worse,
> > compiling with clang results in an unbootable kernel (without any
> > output at all).
> >
> > Mind you, the binary is absolutely massive (130MB with gcc, 156MB with
> > clang), and I wouldn't be surprised if we were hitting some kind of
> > odd limit.
> >
> > > >
> > > > Downloadable assets:
> > > > disk image (non-bootable): https://storage.googleapis.com/syzbot-as=
sets/384ffdcca292/non_bootable_disk-33faa93b.raw.xz
> > > > vmlinux: https://storage.googleapis.com/syzbot-assets/9093742fcee9/=
vmlinux-33faa93b.xz
> > > > kernel image: https://storage.googleapis.com/syzbot-assets/b1f59990=
7931/Image-33faa93b.gz.xz
> > > >
> > > > IMPORTANT: if you fix the issue, please add the following tag to th=
e commit:
> > > > Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
> > > >
> > > > Booting Linux on physical CPU 0x0000000000 [0x000f0510]
> > > > Linux version 6.11.0-rc5-syzkaller-g33faa93bc856 (syzkaller@syzkall=
er) (gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) =
#0 SMP PREEMPT now
> > > > random: crng init done
> > > > Machine model: linux,dummy-virt
> > > > efi: UEFI not found.
> > > > NUMA: No NUMA configuration found
> > > > NUMA: Faking a node at [mem 0x0000000040000000-0x00000000bfffffff]
> > > > NUMA: NODE_DATA [mem 0xbfc1d340-0xbfc20fff]
> > > > Zone ranges:
> > > >   DMA      [mem 0x0000000040000000-0x00000000bfffffff]
> > > >   DMA32    empty
> > > >   Normal   empty
> > > >   Device   empty
> > > > Movable zone start for each node
> > > > Early memory node ranges
> > > >   node   0: [mem 0x0000000040000000-0x00000000bfffffff]
> > > > Initmem setup node 0 [mem 0x0000000040000000-0x00000000bfffffff]
> > > > cma: Reserved 32 MiB at 0x00000000bba00000 on node -1
> > > > psci: probing for conduit method from DT.
> > > > psci: PSCIv1.1 detected in firmware.
> > > > psci: Using standard PSCI v0.2 function IDs
> > > > psci: Trusted OS migration not required
> > > > psci: SMC Calling Convention v1.0
> > > > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > BUG: KASAN: invalid-access in smp_build_mpidr_hash arch/arm64/kerne=
l/setup.c:133 [inline]
> > > > BUG: KASAN: invalid-access in setup_arch+0x984/0xd60 arch/arm64/ker=
nel/setup.c:356
> > > > Write of size 4 at addr 03ff800086867e00 by task swapper/0
> > > > Pointer tag: [03], memory tag: [fe]
> > > >
> > > > CPU: 0 UID: 0 PID: 0 Comm: swapper Not tainted 6.11.0-rc5-syzkaller=
-g33faa93bc856 #0
> > > > Hardware name: linux,dummy-virt (DT)
> > > > Call trace:
> > > >  dump_backtrace+0x204/0x3b8 arch/arm64/kernel/stacktrace.c:317
> > > >  show_stack+0x2c/0x3c arch/arm64/kernel/stacktrace.c:324
> > > >  __dump_stack lib/dump_stack.c:93 [inline]
> > > >  dump_stack_lvl+0x260/0x3b4 lib/dump_stack.c:119
> > > >  print_address_description mm/kasan/report.c:377 [inline]
> > > >  print_report+0x118/0x5ac mm/kasan/report.c:488
> > > >  kasan_report+0xc8/0x108 mm/kasan/report.c:601
> > > >  kasan_check_range+0x94/0xb8 mm/kasan/sw_tags.c:84
> > > >  __hwasan_store4_noabort+0x20/0x2c mm/kasan/sw_tags.c:149
> > > >  smp_build_mpidr_hash arch/arm64/kernel/setup.c:133 [inline]
> > > >  setup_arch+0x984/0xd60 arch/arm64/kernel/setup.c:356
> > > >  start_kernel+0xe0/0xff0 init/main.c:926
> > > >  __primary_switched+0x84/0x8c arch/arm64/kernel/head.S:243
> > > >
> > > > The buggy address belongs to stack of task swapper/0
> > > >
> > > > Memory state around the buggy address:
> > > >  ffff800086867c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> > > >  ffff800086867d00: 00 fe fe 00 00 00 fe fe fe fe fe fe fe fe fe fe
> > > > >ffff800086867e00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> > > >                    ^
> > > >  ffff800086867f00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> > > >  ffff800086868000: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
> > > > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > >
> > > I can't spot the issue here. We have a couple of fixed-length
> > > (4 element) arrays on the stack and they're indexed by a simple loop
> > > counter that runs from 0-3.
> >
> > Having trimmed the config to the extreme, I can only trigger the
> > warning with CONFIG_KASAN_SW_TAGS (CONFIG_KASAN_GENERIC does not
> > scream). Same thing if I use gcc 14.2.0.
> >
> > However, compiling with clang 14 (Debian clang version 14.0.6) does
> > *not* result in a screaming kernel, even with KASAN_SW_TAGS.
> >
> > So I can see two possibilities here:
> >
> > - either gcc is incompatible with KASAN_SW_TAGS and the generic
> >   version is the only one that works
> >
> > - or we have a compiler bug on our hands.
> >
> > Frankly, I can't believe the later, as the code is so daft that I
> > can't imagine gcc getting it *that* wrong.
> >
> > Who knows enough about KASAN to dig into this?

This looks related to Samuel's "arm64: Fix KASAN random tag seed
initialization" patch that landed in August.

I am a bit surprised the bug is reported before the
"KernelAddressSanitizer initialized" banner is printed - I thought we
shouldn't be reporting anything until the tool is fully initialized.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUbWvN%3DFiXjU_QZKm_qDhxU8dZQ4fgELXsRsPCj4YHp9A%40mail.gm=
ail.com.
