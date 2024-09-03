Return-Path: <kasan-dev+bncBDE45GUIXYNRBV7H3S3AMGQEUDCY2WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 01E4896A397
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2024 18:05:46 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id af79cd13be357-7a8084eb116sf719059085a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2024 09:05:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725379544; cv=pass;
        d=google.com; s=arc-20240605;
        b=g37yVpffp7G5J8g9tt+WSD2Gqmb7KrqXPDN/kR0ZX2YmxQuVbP6KNPl/8YKqmfnHe+
         xY1n5DFqSSFKn892gm4kGDB9K0oLsNbIxi8aHTghNXBQ/MjxbvMwZHVm4DbVTjEkLCIt
         3NS9qu/ZAfyAXqNGMk3/RSsgMNAxJ1R0MhVk39Jc57j9K7F/axRa+BJn73LdYIBAX1k0
         tOqlULBx7ja17bSUFgc87LxfY+SBzRPMIHajq96nIm3HaJ0jHLb1JjvI60Lmxhjqs4/s
         v2VirEdOvKI0WO96wDWNDXVaDzfvw5RziEuNeTvprZz63uc0kpJi6JKm7D3KmfBie7TT
         OuLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:user-agent:references:in-reply-to:subject:cc:to:from
         :message-id:date:dkim-signature;
        bh=cEpTQgI9ewR8K7sz7gFfI7tgnv8IvcePziGJfKCZzOM=;
        fh=xk1BKqUBkvKvUJtUd5ZkC1iXVJtnNH9klJGFmln/Ofg=;
        b=eHLkn0yaj4mZZB7vILidtfQu7mnD4K37jKB7s1f/O+0JhkSRxvA5Vp0nAqSXD5MwiX
         pBZO3owjJrfUUiYYPYN251EU5VySlZn6cbrtZ4uGVDxbnW4FLEQbpmYh3BuhVv3R9NpP
         nrkTSTNU1IZS7VUfkZuuavNDIQJEAng4bkFTQ2ST9QMq+H4ftGWBrTlmsjXXMu/y418u
         EjG+VWMn3CNNM0kQZTQOf4HSfmNEBZGOeM8hlVN9jDOrqzt9I7aZrczyL63km+xwWQma
         NWT5bYRN8eYExUrXS/YAUlmgfMO0tVD2pplVVEYWwXX9onihZsb1YqS0I1UswdgvKFVY
         QUCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=avChr2Ms;
       spf=pass (google.com: domain of maz@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=maz@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725379544; x=1725984344; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:subject:cc:to:from:message-id:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=cEpTQgI9ewR8K7sz7gFfI7tgnv8IvcePziGJfKCZzOM=;
        b=Rxrafgo2bOOcd+KQHM891wKXcQpUCkKbwNRgNGhaGNqm8zaC4PhT3zQhSA2CSTgg+Q
         nIadtwHDCAioEyb2BMEXw3NBexFIsuzodqp+rdsJ73tS4RE1vWmvExcUrjaXmuHhB2V/
         tQozN2I5Ce60XjlMBiQfdbh0UIKaD6aa3WRf8dewJHDqjSDgxrklYrOTJNUFPdsU9ebb
         QAZz+KIF9sLKyP3PM6HTcVrrTNuc+88LXY60HtLdXypLKYXYwhc2niCJ15k/rP5D9yY+
         IwK86QZWWczrgNNXjWdkE8VVX2pr7aDHTolNeMvi3d0B3vKYhUwr1Ni4LzGW+NzjNO+b
         OBDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725379544; x=1725984344;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:subject:cc:to:from:message-id:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=cEpTQgI9ewR8K7sz7gFfI7tgnv8IvcePziGJfKCZzOM=;
        b=pbKcMk+GnC10xb0UvTVehC8r04nLz5mZEA3eewiEnxiYXKWGj32FoLJPDwcLZ1ZE9M
         g+ibYe+IgW/eaHMxLYESefOviUHoVza82FPLxhbTbLCnvj1g6NDaelsZPwh8ouLJqcDi
         3wh7Fd5d6xbvArKyK5SfXHT/j1RI/2V2Ruxt94vqBA7THC7m8NSV99D9h+FLNEIPhXiz
         x5JjhIA8V36oQyFjmoY5cy/AtUgXm+Vj5flLx2+4Kce3zE567ZaxtS3L1wdWEgW34W8Z
         /+vjneBX7f690n7iIq6f7YmCxMPmT8Q0w1wiCM/jdEj9/8GQH+MUShUL6qKD7tktsm5Q
         dq6Q==
X-Forwarded-Encrypted: i=2; AJvYcCViFuPBLZnP6ZNL72DHVlT/v7fVYwWc23T0e9+AQRrM+6RKZbR0aStWAN3S4uwj+zbUGzA3uQ==@lfdr.de
X-Gm-Message-State: AOJu0Yysb/ZGk7aDafhpxoSbSfBSM1GiwlWfmd8FmBYdiBE8fJhyZUOT
	apzSQJ+HWJS/lMQY0x0yYmHZq9HAXT31068/PIRJR0KH/toKz0wD
X-Google-Smtp-Source: AGHT+IEDXCi8YsFhtdZp1nX6svamcSfg3SZDJH6NDCmspeQasEaMFe6emgY4uJlRl4jZXkA23b7yXg==
X-Received: by 2002:a05:6214:4408:b0:6c3:6d91:c363 with SMTP id 6a1803df08f44-6c36d91c466mr56239076d6.27.1725379544108;
        Tue, 03 Sep 2024 09:05:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4dcb:0:b0:6c3:5757:f779 with SMTP id 6a1803df08f44-6c35757ff14ls35987546d6.0.-pod-prod-09-us;
 Tue, 03 Sep 2024 09:05:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXPBloBuJabFB+4A76sKvVe74z9WoaHePOaTj7c9O8ZidNmqN5zqvXxHkGxS40UVAygo0lIIvWJtBU=@googlegroups.com
X-Received: by 2002:a05:6102:c46:b0:493:b588:9462 with SMTP id ada2fe7eead31-49a778e0560mr11958826137.14.1725379543080;
        Tue, 03 Sep 2024 09:05:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725379542; cv=none;
        d=google.com; s=arc-20160816;
        b=tc2EdnPOfsFFOTu3kSHoV4Ttfj5bnnuyCsSTBKFjAOj+2N7A/g8Le680Uzt3gDwNJQ
         xJBqT8YER89w6dDBqY5UmkI0ozMcJXVdvVjpJxzU1XhxkNr1PLJas2d41aArEFXmGUML
         eM7xXwfiN7eYERvBZaV/iVAQwCNbNhhn+CNNHlkMPp1GRi9AoQlWjOdYaKKTJkMOGyWB
         9gah+vJY717cHG0OpdJTnuso/nybYSYonRbu66kASQvRuRJCe/kplSPddh2uejv57I/j
         9h3EG4a9zQaWz5OAcCKNSkssCegF7xxlbHCPIgJHkkNOAaWA0xRey5pjR5nOxmDlvp/t
         TH1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:subject:cc:to:from:message-id:date:dkim-signature;
        bh=yihzTrlKqUmEH9UVfnUiCUnd1hgJ1/s0nLlswnTd0Ds=;
        fh=G863ooW5RJUKuJD6ZkipPTL5h/PaL13CSvYDwlzs1gE=;
        b=gPObeaK/NeceZ8whtuxJxDtyTeXQZ3KUbwpBzsIeWuz+eO9VX1XYMkw5rLWB32P98D
         PLyP1uhBm7Y7De2SMBGxW0EkAD4r9HsGiNHX0j2g1QZ/kTD7W98Sn++X2npnodpHuVyd
         e7mLtKOvvbyvepfeJuEgOhIoyY5XBmt/jcaFqpQuckkWC3aOrCChjraTJ4gf207iagEJ
         QcLcEIspHcKIo0jHhria4OBnU6FkS1crb80z9sXEv3XO1L96hdG8R/ze6Ov6eR7hYaPn
         dSYdJSW0YVLnmEwa6MWod0yZJ+sGH5X/zBFYe1VzDUjGNpuzs3yP8PCmuY98j7kDw35I
         Atuw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=avChr2Ms;
       spf=pass (google.com: domain of maz@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=maz@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-49a5f499c3csi661253137.2.2024.09.03.09.05.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Sep 2024 09:05:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of maz@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id D7FEE5C5A13;
	Tue,  3 Sep 2024 16:05:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C8605C4CEC4;
	Tue,  3 Sep 2024 16:05:41 +0000 (UTC)
Received: from sofa.misterjones.org ([185.219.108.64] helo=goblin-girl.misterjones.org)
	by disco-boy.misterjones.org with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.95)
	(envelope-from <maz@kernel.org>)
	id 1slW2F-009IVG-T3;
	Tue, 03 Sep 2024 17:05:39 +0100
Date: Tue, 03 Sep 2024 17:05:38 +0100
Message-ID: <86seugvi25.wl-maz@kernel.org>
From: "'Marc Zyngier' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: samuel.holland@sifive.com,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Will Deacon <will@kernel.org>,
	syzbot <syzbot+908886656a02769af987@syzkaller.appspotmail.com>,
	catalin.marinas@arm.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	syzkaller-bugs@googlegroups.com
Subject: Re: [syzbot] [arm?] upstream test error: KASAN: invalid-access Write in setup_arch
In-Reply-To: <CAG_fn=UbWvN=FiXjU_QZKm_qDhxU8dZQ4fgELXsRsPCj4YHp9A@mail.gmail.com>
References: <000000000000f362e80620e27859@google.com>
	<20240830095254.GA7769@willie-the-truck>
	<86wmjwvatn.wl-maz@kernel.org>
	<CANp29Y6EJXFTOy6Pd466r+RwzaGHe7JQMTaqMPSO2s7ubm-PKw@mail.gmail.com>
	<CAG_fn=UbWvN=FiXjU_QZKm_qDhxU8dZQ4fgELXsRsPCj4YHp9A@mail.gmail.com>
User-Agent: Wanderlust/2.15.9 (Almost Unreal) SEMI-EPG/1.14.7 (Harue)
 FLIM-LB/1.14.9 (=?UTF-8?B?R29qxY0=?=) APEL-LB/10.8 EasyPG/1.0.0 Emacs/29.4
 (aarch64-unknown-linux-gnu) MULE/6.0 (HANACHIRUSATO)
MIME-Version: 1.0 (generated by SEMI-EPG 1.14.7 - "Harue")
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-SA-Exim-Connect-IP: 185.219.108.64
X-SA-Exim-Rcpt-To: glider@google.com, samuel.holland@sifive.com, andreyknvl@gmail.com, nogikh@google.com, kasan-dev@googlegroups.com, will@kernel.org, syzbot+908886656a02769af987@syzkaller.appspotmail.com, catalin.marinas@arm.com, linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, syzkaller-bugs@googlegroups.com
X-SA-Exim-Mail-From: maz@kernel.org
X-SA-Exim-Scanned: No (on disco-boy.misterjones.org); SAEximRunCond expanded to false
X-Original-Sender: maz@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=avChr2Ms;       spf=pass
 (google.com: domain of maz@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=maz@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Marc Zyngier <maz@kernel.org>
Reply-To: Marc Zyngier <maz@kernel.org>
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

On Tue, 03 Sep 2024 16:39:28 +0100,
Alexander Potapenko <glider@google.com> wrote:
>=20
> On Mon, Sep 2, 2024 at 12:03=E2=80=AFPM 'Aleksandr Nogikh' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > +kasan-dev
> >
> > On Sat, Aug 31, 2024 at 7:53=E2=80=AFPM 'Marc Zyngier' via syzkaller-bu=
gs
> > <syzkaller-bugs@googlegroups.com> wrote:
> > >
> > > On Fri, 30 Aug 2024 10:52:54 +0100,
> > > Will Deacon <will@kernel.org> wrote:
> > > >
> > > > On Fri, Aug 30, 2024 at 01:35:24AM -0700, syzbot wrote:
> > > > > Hello,
> > > > >
> > > > > syzbot found the following issue on:
> > > > >
> > > > > HEAD commit:    33faa93bc856 Merge branch kvmarm-master/next into=
 kvmarm-m..
> > > > > git tree:       git://git.kernel.org/pub/scm/linux/kernel/git/kvm=
arm/kvmarm.git fuzzme
> > > >
> > > > +Marc, as this is his branch.
> > > >
> > > > > console output: https://syzkaller.appspot.com/x/log.txt?x=3D13984=
20b980000
> > > > > kernel config:  https://syzkaller.appspot.com/x/.config?x=3D2b7b3=
1c9aa1397ca
> > > > > dashboard link: https://syzkaller.appspot.com/bug?extid=3D9088866=
56a02769af987
> > > > > compiler:       gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binuti=
ls for Debian) 2.40
> > > > > userspace arch: arm64
> > >
> > > As it turns out, this isn't specific to this branch. I can reproduce
> > > it with this config on a vanilla 6.10 as a KVM guest. Even worse,
> > > compiling with clang results in an unbootable kernel (without any
> > > output at all).
> > >
> > > Mind you, the binary is absolutely massive (130MB with gcc, 156MB wit=
h
> > > clang), and I wouldn't be surprised if we were hitting some kind of
> > > odd limit.
> > >
> > > > >
> > > > > Downloadable assets:
> > > > > disk image (non-bootable): https://storage.googleapis.com/syzbot-=
assets/384ffdcca292/non_bootable_disk-33faa93b.raw.xz
> > > > > vmlinux: https://storage.googleapis.com/syzbot-assets/9093742fcee=
9/vmlinux-33faa93b.xz
> > > > > kernel image: https://storage.googleapis.com/syzbot-assets/b1f599=
907931/Image-33faa93b.gz.xz
> > > > >
> > > > > IMPORTANT: if you fix the issue, please add the following tag to =
the commit:
> > > > > Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.co=
m
> > > > >
> > > > > Booting Linux on physical CPU 0x0000000000 [0x000f0510]
> > > > > Linux version 6.11.0-rc5-syzkaller-g33faa93bc856 (syzkaller@syzka=
ller) (gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40=
) #0 SMP PREEMPT now
> > > > > random: crng init done
> > > > > Machine model: linux,dummy-virt
> > > > > efi: UEFI not found.
> > > > > NUMA: No NUMA configuration found
> > > > > NUMA: Faking a node at [mem 0x0000000040000000-0x00000000bfffffff=
]
> > > > > NUMA: NODE_DATA [mem 0xbfc1d340-0xbfc20fff]
> > > > > Zone ranges:
> > > > >   DMA      [mem 0x0000000040000000-0x00000000bfffffff]
> > > > >   DMA32    empty
> > > > >   Normal   empty
> > > > >   Device   empty
> > > > > Movable zone start for each node
> > > > > Early memory node ranges
> > > > >   node   0: [mem 0x0000000040000000-0x00000000bfffffff]
> > > > > Initmem setup node 0 [mem 0x0000000040000000-0x00000000bfffffff]
> > > > > cma: Reserved 32 MiB at 0x00000000bba00000 on node -1
> > > > > psci: probing for conduit method from DT.
> > > > > psci: PSCIv1.1 detected in firmware.
> > > > > psci: Using standard PSCI v0.2 function IDs
> > > > > psci: Trusted OS migration not required
> > > > > psci: SMC Calling Convention v1.0
> > > > > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > > > BUG: KASAN: invalid-access in smp_build_mpidr_hash arch/arm64/ker=
nel/setup.c:133 [inline]
> > > > > BUG: KASAN: invalid-access in setup_arch+0x984/0xd60 arch/arm64/k=
ernel/setup.c:356
> > > > > Write of size 4 at addr 03ff800086867e00 by task swapper/0
> > > > > Pointer tag: [03], memory tag: [fe]
> > > > >
> > > > > CPU: 0 UID: 0 PID: 0 Comm: swapper Not tainted 6.11.0-rc5-syzkall=
er-g33faa93bc856 #0
> > > > > Hardware name: linux,dummy-virt (DT)
> > > > > Call trace:
> > > > >  dump_backtrace+0x204/0x3b8 arch/arm64/kernel/stacktrace.c:317
> > > > >  show_stack+0x2c/0x3c arch/arm64/kernel/stacktrace.c:324
> > > > >  __dump_stack lib/dump_stack.c:93 [inline]
> > > > >  dump_stack_lvl+0x260/0x3b4 lib/dump_stack.c:119
> > > > >  print_address_description mm/kasan/report.c:377 [inline]
> > > > >  print_report+0x118/0x5ac mm/kasan/report.c:488
> > > > >  kasan_report+0xc8/0x108 mm/kasan/report.c:601
> > > > >  kasan_check_range+0x94/0xb8 mm/kasan/sw_tags.c:84
> > > > >  __hwasan_store4_noabort+0x20/0x2c mm/kasan/sw_tags.c:149
> > > > >  smp_build_mpidr_hash arch/arm64/kernel/setup.c:133 [inline]
> > > > >  setup_arch+0x984/0xd60 arch/arm64/kernel/setup.c:356
> > > > >  start_kernel+0xe0/0xff0 init/main.c:926
> > > > >  __primary_switched+0x84/0x8c arch/arm64/kernel/head.S:243
> > > > >
> > > > > The buggy address belongs to stack of task swapper/0
> > > > >
> > > > > Memory state around the buggy address:
> > > > >  ffff800086867c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0=
0
> > > > >  ffff800086867d00: 00 fe fe 00 00 00 fe fe fe fe fe fe fe fe fe f=
e
> > > > > >ffff800086867e00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe f=
e
> > > > >                    ^
> > > > >  ffff800086867f00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe f=
e
> > > > >  ffff800086868000: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe f=
e
> > > > > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > >
> > > > I can't spot the issue here. We have a couple of fixed-length
> > > > (4 element) arrays on the stack and they're indexed by a simple loo=
p
> > > > counter that runs from 0-3.
> > >
> > > Having trimmed the config to the extreme, I can only trigger the
> > > warning with CONFIG_KASAN_SW_TAGS (CONFIG_KASAN_GENERIC does not
> > > scream). Same thing if I use gcc 14.2.0.
> > >
> > > However, compiling with clang 14 (Debian clang version 14.0.6) does
> > > *not* result in a screaming kernel, even with KASAN_SW_TAGS.
> > >
> > > So I can see two possibilities here:
> > >
> > > - either gcc is incompatible with KASAN_SW_TAGS and the generic
> > >   version is the only one that works
> > >
> > > - or we have a compiler bug on our hands.
> > >
> > > Frankly, I can't believe the later, as the code is so daft that I
> > > can't imagine gcc getting it *that* wrong.
> > >
> > > Who knows enough about KASAN to dig into this?
>=20
> This looks related to Samuel's "arm64: Fix KASAN random tag seed
> initialization" patch that landed in August.

f75c235565f9 arm64: Fix KASAN random tag seed initialization

$ git describe --contains f75c235565f9 --match=3Dv\*
v6.11-rc4~15^2

So while this is in -rc4, -rc6 still has the same issue (with GCC --
clang is OK).

> I am a bit surprised the bug is reported before the
> "KernelAddressSanitizer initialized" banner is printed - I thought we
> shouldn't be reporting anything until the tool is fully initialized.

Specially if this can report false positives...

Thanks,

	M.

--=20
Without deviation from the norm, progress is not possible.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/86seugvi25.wl-maz%40kernel.org.
