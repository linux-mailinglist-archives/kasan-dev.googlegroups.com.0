Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBK6Y3GIAMGQEC6QDQRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id E186E4C19BF
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Feb 2022 18:17:31 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id r8-20020a7bc088000000b0037bbf779d26sf2010942wmh.7
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Feb 2022 09:17:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645636651; cv=pass;
        d=google.com; s=arc-20160816;
        b=fEKWZuT1WT2Q2TB/DsSudJIZZwyTQoLMpWm7YrJJHen+uZDOyyEdBhrKK0mB17lsFs
         drQxOqouI8Lht4UbQ8HY75Q8DgPrDCSMAd8HDpcMpdjajk7jmbzGxzfGNvlOjMa8gf1E
         hUU2/Q0JxWUS2n9D2/DKH11must7/BGJxh/psoP+m6nwYM3yNlClNH1Esk5ybirLfRH4
         adtcrF6mFIUA7vOzYRYZIzePVcIKXdsCm5+KDfpsgBgpKp4Ua6sT1JqoFofon1k6gXab
         0i2OG73Xa7B8IF8hzItftedNyKJhz3jNkuOYM3xFFqgaX2WHfxTd5Bab/SpeWrYFtieM
         c+TA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=TVw+5NBpE26bo1Zhscbv5G9uB2IN5ThLVo6P/dvkscQ=;
        b=P1NEVDsffjOhAH1QBu40m/cAFTWgZagZL1S1AFpGOdV29+HSp9z3UgjFGwe/9qJHxc
         Q8efXfpRNKhuV1L9wyKTlVgvXtZ53eKXxXchyf8y9klbfnIh8nDPsQ7NOXCzSZwxtthH
         smgWAqiqoxXL9PArc+WKmp2r8fL42smAYFODdscbEuZLfVbbiVPbLcbNU+ryqDBwEGpd
         TusLIpCkIMopAzlPVggEvPT8tl/LqFLUWOiRfyYYLUX2tKOl1doNE+FPw/qmH/zrCVdZ
         EPZZomxWjov878zXCkq/nidN6PzxM/7/hRELIcbcddvqxn7QvTdfTxw21GQUhoyGruBq
         /LFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=JQYhvWfj;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TVw+5NBpE26bo1Zhscbv5G9uB2IN5ThLVo6P/dvkscQ=;
        b=Vq2RXHHRCThEqZCrq+K3gEV+Oyqhzm9n5XWOsLrtsMkYFOp1xlbtD/JCEj2YyPJiow
         pbc4oaITiZXqIR7Jm7YJe0ySb5UG/z4L6BHrwJDRX5kI+Hkx6H+6XOrPM/aX3Nwii6KU
         +FCYAHD7UP83QUkHC0KwTALPPupB71QsA4VbqEY2R+HUAf8qpJxCD0SJAKrx9OtSlknn
         b4JUm39hUwrJI0zjIXehD4XQFVtSPMYpblsoBaRz924BrmtshKcw51l0NCZv1WuCo4dX
         e/opH+7kzJG5c03Pa/0HeRaulOA8+nNnpenm35L7G4duIGqkbPxsccyzyeVubFV8Jvz6
         WzJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TVw+5NBpE26bo1Zhscbv5G9uB2IN5ThLVo6P/dvkscQ=;
        b=nrNAKagUzB0PqGd4cvbp6cNGO+8HrGKUZ9sMzUbyNjVCRyE4dOncudrGHZ6wUD/XTT
         IaRGZD9xw/PWpbdecPOpgUgqfofWcVZC1sP9Cbuhm9R1nSu1WJK8FT5+T+Z9PaxtNPnd
         OlhxPFYfOugBnm0P6wtH8YlNcg797c53E/2hhNQDEqdl/QTegZy6hSB3o3gqbo3fYrSu
         /vRiIgrTpT8Sb9WawmcDXql9mNo8XDkGsJ+/AfVWD53UYykxlE1e/0CxaZbH0kd7zpMv
         kyuz/6nAM7I3C6tSNEpKS1JpV7XYLYrKoj24rFKRXGhDtMYre1DrGcZkUw+o3EFWwqdy
         LMqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530zcW5GK1g3CEIZ/7QEWv2gNrOObJbFYgHOeiKofnAgH3v8AXEV
	9NRCxjOzsgUoT40uvJEAiCk=
X-Google-Smtp-Source: ABdhPJwmCVPHG7UwnK85in+iRMaDHqia8Gkb71Xk5B84lDLH8tgHzkChaoKU6I1kyEDrLgAD3XQGYg==
X-Received: by 2002:a5d:6885:0:b0:1ed:c0bc:c205 with SMTP id h5-20020a5d6885000000b001edc0bcc205mr440617wru.683.1645636651484;
        Wed, 23 Feb 2022 09:17:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d2a:b0:380:dd99:d301 with SMTP id
 l42-20020a05600c1d2a00b00380dd99d301ls2631267wms.2.canary-gmail; Wed, 23 Feb
 2022 09:17:30 -0800 (PST)
X-Received: by 2002:a05:600c:25a:b0:380:55e:fa39 with SMTP id 26-20020a05600c025a00b00380055efa39mr555666wmj.40.1645636650587;
        Wed, 23 Feb 2022 09:17:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645636650; cv=none;
        d=google.com; s=arc-20160816;
        b=fCakIodIQUhK7JPpNdcbFlQEkTUX0YETE3bjNdf4k8Ydzi0tgUrQ3zK7MojIkp98jL
         w6gIyyJS7zpp/hCZsq7hxqaUY5kzX1RDPBQu7U9zAf1e3sgoWl+67/gr+LDWkWGPkW0e
         F4pre9juxD+01hA8+wQhj4OIgRxscxw+X95YlGjiWySX7RLFu/lI/DB1TQ1YOnroVG1m
         5zcOEjTFBd6J0A8ffSL7gFCX6Je+gULyVDKR6vrNU7+jKJms7luBYLre+wmL/sN4gtAW
         7S6ZCiFi097k7cRofe/IkmxZ+7sAMc3s4189p+mtvQKLk6hYyjW+yeKjrq0tVIhcGNUr
         YorQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/ozkhea4bGdkwQyqdllwEcc/DZs+W0S+IsF9ZSOsgS8=;
        b=TI6yfRCraXYN6o2ymbHCaUeZH4Nf7+cP2cIT38DH+0ewNLZX6DsFZxA4YaPdqeCACI
         LB6zlME/mqrty/1at753aF9WSDwaI/z8zgrOLb6BpqssxiUoXF5ub5GZfE69gfebv2Pa
         eq+TSQBaXjftKPr+S+Zq2mWJ2Lq2lSzPXllcqeKGs9QeD8WhFFFP3Ta4dwqObfa4qiap
         8Tfe49Pzp9aMTZVeL4jZ1qQmMYF+NUA1OtFiPwHVyeFShdSfMx834H9f5ARbSkH6P77W
         fon759IuOn56zoocF/tqV1BgHb6FADEud2nhFR4qBx/hpkYDD51vkqCJIKDyZ8puommo
         yRkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=JQYhvWfj;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id p22-20020a05600c359600b0037bb7df18e4si167758wmq.1.2022.02.23.09.17.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Feb 2022 09:17:30 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-ed1-f69.google.com (mail-ed1-f69.google.com [209.85.208.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 121243F1DD
	for <kasan-dev@googlegroups.com>; Wed, 23 Feb 2022 17:17:30 +0000 (UTC)
Received: by mail-ed1-f69.google.com with SMTP id b13-20020a056402278d00b0041311e02a9bso4720935ede.13
        for <kasan-dev@googlegroups.com>; Wed, 23 Feb 2022 09:17:30 -0800 (PST)
X-Received: by 2002:a17:906:71d5:b0:6a7:fd56:e9ad with SMTP id i21-20020a17090671d500b006a7fd56e9admr538252ejk.178.1645636647500;
        Wed, 23 Feb 2022 09:17:27 -0800 (PST)
X-Received: by 2002:a17:906:71d5:b0:6a7:fd56:e9ad with SMTP id
 i21-20020a17090671d500b006a7fd56e9admr538234ejk.178.1645636647224; Wed, 23
 Feb 2022 09:17:27 -0800 (PST)
MIME-Version: 1.0
References: <20220221161232.2168364-1-alexandre.ghiti@canonical.com>
 <20220221161232.2168364-5-alexandre.ghiti@canonical.com> <CANp29Y7M=wSLBE8m0-CHKtYPkqgcxNiUPEyRNv-VHeR5O2BTYQ@mail.gmail.com>
 <CA+zEjCt02Cx1Q1yDGN9V6Wvgx0+jvcqft6U56M3wsidkW5sMjg@mail.gmail.com>
In-Reply-To: <CA+zEjCt02Cx1Q1yDGN9V6Wvgx0+jvcqft6U56M3wsidkW5sMjg@mail.gmail.com>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Wed, 23 Feb 2022 18:17:16 +0100
Message-ID: <CA+zEjCsDPqg1YwS_z4pCnP4GvwYd6Dhr6xwz51G4B8qvsUHqKQ@mail.gmail.com>
Subject: Re: [PATCH -fixes v2 4/4] riscv: Fix config KASAN && DEBUG_VIRTUAL
To: Aleksandr Nogikh <nogikh@google.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, linux-riscv@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=JQYhvWfj;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
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

On Wed, Feb 23, 2022 at 2:10 PM Alexandre Ghiti
<alexandre.ghiti@canonical.com> wrote:
>
> Hi Aleksandr,
>
> On Tue, Feb 22, 2022 at 11:28 AM Aleksandr Nogikh <nogikh@google.com> wrote:
> >
> > Hi Alexandre,
> >
> > Thanks for the series!
> >
> > However, I still haven't managed to boot the kernel. What I did:
> > 1) Checked out the riscv/fixes branch (this is the one we're using on
> > syzbot). The latest commit was
> > 6df2a016c0c8a3d0933ef33dd192ea6606b115e3.
> > 2) Applied all 4 patches.
> > 3) Used the config from the cover letter:
> > https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
> > 4) Built with `make -j32 ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-`
> > 5) Ran with `qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot
> > -device virtio-rng-pci -machine virt -device
> > virtio-net-pci,netdev=net0 -netdev
> > user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:12529-:22 -device
> > virtio-blk-device,drive=hd0 -drive
> > file=~/kernel-image/riscv64,if=none,format=raw,id=hd0 -snapshot
> > -kernel ~/linux-riscv/arch/riscv/boot/Image -append "root=/dev/vda
> > console=ttyS0 earlyprintk=serial"` (this is similar to how syzkaller
> > runs qemu).
> >
> > Can you please hint at what I'm doing differently?
>
> A short summary of what I found to keep you updated:
>
> I compared your command line and mine, the differences are that I use
> "smp=4" and I add "earlycon" to the kernel command line. When added to
> your command line, that allows it to boot. I understand why it helps
> but I can't explain what's wrong...Anyway, I fixed a warning that I
> had missed and that allows me to remove the "smp=4" and "earlycon".
>
> But this is not over yet...Your command line still does not allow to
> reach userspace, it fails with the following stacktrace:
>
> [   11.537817][    T1] Unable to handle kernel paging request at
> virtual address fffff5eeffffc800
> [   11.539450][    T1] Oops [#1]
> [   11.539909][    T1] Modules linked in:
> [   11.540451][    T1] CPU: 0 PID: 1 Comm: swapper/0 Not tainted
> 5.17.0-rc1-00007-ga68b89289e26-dirty #28
> [   11.541364][    T1] Hardware name: riscv-virtio,qemu (DT)
> [   11.542032][    T1] epc : kasan_check_range+0x96/0x13e
> [   11.542654][    T1]  ra : memset+0x1e/0x4c
> [   11.543388][    T1] epc : ffffffff8046c312 ra : ffffffff8046ca16 sp
> : ffffaf8007337b70
> [   11.544037][    T1]  gp : ffffffff85866c80 tp : ffffaf80073d8000 t0
> : 0000000000046000
> [   11.544637][    T1]  t1 : fffff5eeffffc9ff t2 : 0000000000000000 s0
> : ffffaf8007337ba0
> [   11.545409][    T1]  s1 : 0000000000001000 a0 : fffff5eeffffca00 a1
> : 0000000000001000
> [   11.546072][    T1]  a2 : 0000000000000001 a3 : ffffffff8039ef24 a4
> : ffffaf7ffffe4000
> [   11.546707][    T1]  a5 : fffff5eeffffc800 a6 : 0000004000000000 a7
> : ffffaf7ffffe4fff
> [   11.547541][    T1]  s2 : ffffaf7ffffe4000 s3 : 0000000000000000 s4
> : ffffffff8467faa8
> [   11.548277][    T1]  s5 : 0000000000000000 s6 : ffffffff85869840 s7
> : 0000000000000000
> [   11.548950][    T1]  s8 : 0000000000001000 s9 : ffffaf805a54a048
> s10: ffffffff8588d420
> [   11.549705][    T1]  s11: ffffaf7ffffe4000 t3 : 0000000000000000 t4
> : 0000000000000040
> [   11.550465][    T1]  t5 : fffff5eeffffca00 t6 : 0000000000000002
> [   11.551131][    T1] status: 0000000000000120 badaddr:
> fffff5eeffffc800 cause: 000000000000000d
> [   11.551961][    T1] [<ffffffff8039ef24>] pcpu_alloc+0x84a/0x125c
> [   11.552928][    T1] [<ffffffff8039f994>] __alloc_percpu+0x28/0x34
> [   11.553555][    T1] [<ffffffff83286954>] ip_rt_init+0x15a/0x35c
> [   11.554128][    T1] [<ffffffff83286d24>] ip_init+0x18/0x30
> [   11.554642][    T1] [<ffffffff8328844a>] inet_init+0x2a6/0x550
> [   11.555428][    T1] [<ffffffff80003220>] do_one_initcall+0x132/0x7e4
> [   11.556049][    T1] [<ffffffff83201f7a>] kernel_init_freeable+0x510/0x5b4
> [   11.556771][    T1] [<ffffffff831424e4>] kernel_init+0x28/0x21c
> [   11.557344][    T1] [<ffffffff800056a0>] ret_from_exception+0x0/0x14
> [   11.585469][    T1] ---[ end trace 0000000000000000 ]---
>
> 0xfffff5eeffffc800 is a KASAN address that points to the very end of
> vmalloc address range, which is weird since KASAN_VMALLOC is not
> enabled.
> Moreover my command line does not trigger the above bug, and I'm
> trying to understand why:

When I read this email I saw that I did not use the same qemu version:
I have a locally built version that disables sv48, which is the one
that works so the problem came from the sv48 support.

In a nutshell, the issue comes from the fact that kasan inner regions
are not aligned on PGDIR_SIZE when sv48 (which is 4-level page table)
is on, and then when populating the kasan linear mapping region, that
clears the kasan vmalloc region which is in the same PGD: the fix is
to copy its content before initializing the linear mapping entries.
This issue only happens when KASAN_VMALLOC is disabled. I had fixed
this already for kasan_shallow_populate_pud, but missed
kasan_populate_pud.

Tomorrow I'll push the v3. It still does not fix the issue I describe
in the cover letter though, so still more work to do. At least, I was
able to reach userspace with your *exact* qemu command :)

Alex


>
> /home/alex/work/qemu/build/riscv64-softmmu/qemu-system-riscv64 -M virt
> -bios /home/alex/work/opensbi/build/platform/generic/firmware/fw_dynamic.bin
> -kernel /home/alex/work/kernel-build/riscv_rv64_kernel/arch/riscv/boot/Image
> -netdev user,id=net0 -device virtio-net-device,netdev=net0 -drive
> file=/home/alex/work/kernel-build/rootfs.ext2,format=raw,id=hd0
> -device virtio-blk-device,drive=hd0 -nographic -smp 4 -m 16G -s
> -append "rootwait earlycon root=/dev/vda ro earlyprintk=serial"
>
> I'm looking into all of this and will get back with a v3 soon :)
>
> Thanks,
>
> Alex
>
>
>
>
>
>
> >
> > A simple config with KASAN, KASAN_OUTLINE and DEBUG_VIRTUAL now indeed
> > leads to a booting kernel, which was not the case before.
> > make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> > ./scripts/config -e KASAN -e KASAN_OUTLINE -e DEBUG_VIRTUAL
> > make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> >
> > --
> > Best Regards,
> > Aleksandr
> >
> > On Mon, Feb 21, 2022 at 5:17 PM Alexandre Ghiti
> > <alexandre.ghiti@canonical.com> wrote:
> > >
> > > __virt_to_phys function is called very early in the boot process (ie
> > > kasan_early_init) so it should not be instrumented by KASAN otherwise it
> > > bugs.
> > >
> > > Fix this by declaring phys_addr.c as non-kasan instrumentable.
> > >
> > > Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > > ---
> > >  arch/riscv/mm/Makefile | 3 +++
> > >  1 file changed, 3 insertions(+)
> > >
> > > diff --git a/arch/riscv/mm/Makefile b/arch/riscv/mm/Makefile
> > > index 7ebaef10ea1b..ac7a25298a04 100644
> > > --- a/arch/riscv/mm/Makefile
> > > +++ b/arch/riscv/mm/Makefile
> > > @@ -24,6 +24,9 @@ obj-$(CONFIG_KASAN)   += kasan_init.o
> > >  ifdef CONFIG_KASAN
> > >  KASAN_SANITIZE_kasan_init.o := n
> > >  KASAN_SANITIZE_init.o := n
> > > +ifdef CONFIG_DEBUG_VIRTUAL
> > > +KASAN_SANITIZE_physaddr.o := n
> > > +endif
> > >  endif
> > >
> > >  obj-$(CONFIG_DEBUG_VIRTUAL) += physaddr.o
> > > --
> > > 2.32.0
> > >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCsDPqg1YwS_z4pCnP4GvwYd6Dhr6xwz51G4B8qvsUHqKQ%40mail.gmail.com.
