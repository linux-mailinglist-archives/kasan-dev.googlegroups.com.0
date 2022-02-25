Return-Path: <kasan-dev+bncBCRKNY4WZECBBOVH4GIAMGQE5AHRYCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 77CD44C3CCA
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 04:57:48 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id z4-20020a4ad1a4000000b0031beb2043f7sf2017344oor.20
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Feb 2022 19:57:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645761467; cv=pass;
        d=google.com; s=arc-20160816;
        b=wusY/0ErH8EFtMDYBklCWo9lB5oE74YgkyVaZZLGNnSDbtqaWZ1IBtRgdMNBa2Q67C
         jlg22xwsprB8xR3FnQK924yffotDizpbmu7STTsnyzO+EKDPv0xu50qB7jVG15X224dK
         BNIEiYjcaVqPhfcLPzVDzWTYjFIiFQPFYm3+5lNg0GOIsoYVB3B3MgurSsfvDGBjbLsX
         7NX2OzYmwO3qfD52BQiGAM2/i5cZzAqhNnq7r5jP0OvxeL7yvjFEi8u6SAYyc7+N7VVu
         HJGbk+qmsrujBoQ+wYI+b1WZAgomTBmJJ93YNcHw7UwjO9d2DggCBl8h2FzaOQqD0w7o
         u/GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=TGrR0ibd0XuwJYmylqYBT/o5eXsckSc+48zuUA3vhCI=;
        b=UKfGZAL15sWRCNRQLfxM/U3ms+bevvyb9gANLoW0B22PhsJWzrxzEjSdgr/vl2IC3D
         kK1ZYodQYF/AOMYR/1HKqFikhyVCB6DbdiSQW+leZWyXVeer0lgXlLZgriw2oxVzpxrM
         b2lmKpEsa7xfMThDMkxg0w4gaUkPAvFH4FooY5XG687zQqoUjNrUWo7QhrHWUGww5SD1
         Zl1eTcNhbL2YDmkj11pGtJqWWxcMdwo5e+4Ht2GkY8vJlSAOGwZPZ4o/UKNCyIQW06en
         IH4Cvd3DQASvZJsvl9PBmiC+J61Rm2oyIRgnaaJKgKAzRPfU3eJWsm5Lpsg5xpztNKyu
         eybQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=IyvZ7Y0O;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TGrR0ibd0XuwJYmylqYBT/o5eXsckSc+48zuUA3vhCI=;
        b=K97FChuVR7WPIeHKQnCOuMNbOlTrHGHt389V53K7MgMICId2Ptkwz1O56Aq6XLyJ/V
         5bE1q061WJPOEB84XS69m2dXPZ0UG6lvQQklKQyTMQWBX1xVrNMsQcfHgEI6CxTa16kO
         qacvGVKAts3TKXZpjWtCgwKL7Kwv2Sj0XIDgRBY50TjSrDD7D8YmeHsnthYDdCjJtRqm
         2rHvyMtESuGGgR/By4CpEK0Mic83TXC2kZprqstybqn4Rlbj946r4YkUYgoNOY7MymlY
         wgB4FAfQVbs7EZ+RD0g/o2ItEh0KbfaG5Tq/VXd0U/HZvbnw433K3c/ywKDSZMH77ssh
         z4fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TGrR0ibd0XuwJYmylqYBT/o5eXsckSc+48zuUA3vhCI=;
        b=tm3nHbCseruOk36ioXnz3x2XbswqWFqSunn8Mph19+5wVSfYVD2WRJ2Cxc3PgLLZtR
         Mj8zPbahd9L/N+K5WhPrF3/ItstnWLqcvJIfAvQGwN6la+vh8Y7it9vPEWjpXOVEOLcb
         cyEK2llmQq+nNx6KlR5Nb8SEq/0PMIxvUB9y4a3LTc/oWHq7nJbvsHvEQ12yw9x09Ls1
         ee+8BzjpyJFWcv3UCdrt6hvm1GQnIhx5yLYxJpvVrrfXPdLnXRC9KjsCdfn3G/pw3p8J
         VAi1OLaBY0YmesatB13XzfBt599ZpwtxwHT/BqvtYhmv3AWxXTCPcLRfQDCP70metyq3
         d2yg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Y5Dl5LqDy+F3K3QqutUjHGgeNChwVcMSzWItC0vVorbF+Qtbw
	kO6gfDds3pB6Eh4O7IUR234=
X-Google-Smtp-Source: ABdhPJwwqpuQR0i3PqfBguh/+Per1P3N9kMdaTipzLs30JLEWRRHPwq5z+kI6GQdOCuVbI7T8sC/vA==
X-Received: by 2002:a05:6808:144c:b0:2d5:283c:5b52 with SMTP id x12-20020a056808144c00b002d5283c5b52mr613563oiv.257.1645761466981;
        Thu, 24 Feb 2022 19:57:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d68e:b0:b4:358a:6de7 with SMTP id
 z14-20020a056870d68e00b000b4358a6de7ls1549539oap.2.gmail; Thu, 24 Feb 2022
 19:57:46 -0800 (PST)
X-Received: by 2002:a05:6870:3112:b0:ce:c0c9:62b with SMTP id v18-20020a056870311200b000cec0c9062bmr582082oaa.125.1645761466583;
        Thu, 24 Feb 2022 19:57:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645761466; cv=none;
        d=google.com; s=arc-20160816;
        b=kXw2lVZCaiUsCrbHRYFilLB5APqXv+3CiMn65vqS/B+aPFbvtFn+Lnqe9vD1WpIGMc
         9uKWFbRUAyyVU6DwUhM8NAYCue3jtKtegCs9BphI1ixGxRxfZJUFkro9Nn9xZOLQHI8l
         Ui85FgZJ7WJWYN+Pa+Hkm1Y0yAApOQbrHMOeT69re7gqpnApB/IpekWmhke4o8LVzDkj
         d5xkmVc6zyPcP87rvpaKYLKVUSHmAzIU5xZy/RdvHhhonB5CfTNz4tmnkccMRzyeBhnM
         4D1GHA2Feb2V/N3KSz5uL7hoJs3OWYp/YWq0mAjN7h9ZKlHjKjdJXL4fEeVEKCreRrAn
         +84A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=iDFAzQ7oWupo/um69ebEfgZLXtbKoa51CUofPSlUDVo=;
        b=cC9zzWMBlEGl7/JmGLoWtDmmhNEpbn5f27BEJ5G+Ebp2leJAzn5G8MaW+l2bMkju2E
         5gFnpg5WMrZRTujnhhUft7A2nWSuIxThohudRPg+OWcTxj37RlMyL+TIBVhVtYG6meBg
         vHupMvQSiAdfnrliO7Wb4iR+lMEcJgU4RsWHLOqu5iUEGw+poLR32KSGppT74vgstSIX
         KiI/dZW24ZmU+EjJch5ChC1iMEZhQBygp3QfXoBqnQezaliV7tLpZGQsNsTwJRwiCG1J
         ggIvB2rZHt8oM4wEHpk2/nDxNxHc2c6/PplVB7BWeCcGlgU+7IZtl+xwtm7VbozrnMew
         DpMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=IyvZ7Y0O;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id w26-20020a056830079a00b005ad081e3cbdsi165352ots.4.2022.02.24.19.57.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Feb 2022 19:57:46 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id z4so3507472pgh.12
        for <kasan-dev@googlegroups.com>; Thu, 24 Feb 2022 19:57:46 -0800 (PST)
X-Received: by 2002:a05:6a00:244f:b0:4cc:a2ba:4cd8 with SMTP id d15-20020a056a00244f00b004cca2ba4cd8mr5890382pfj.74.1645761465519;
        Thu, 24 Feb 2022 19:57:45 -0800 (PST)
Received: from localhost ([12.3.194.138])
        by smtp.gmail.com with ESMTPSA id lx7-20020a17090b4b0700b001b7d5b6d10asm745325pjb.48.2022.02.24.19.57.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 24 Feb 2022 19:57:45 -0800 (PST)
Date: Thu, 24 Feb 2022 19:57:45 -0800 (PST)
Subject: Re: [PATCH -fixes v2 4/4] riscv: Fix config KASAN && DEBUG_VIRTUAL
In-Reply-To: <CA+zEjCsDPqg1YwS_z4pCnP4GvwYd6Dhr6xwz51G4B8qvsUHqKQ@mail.gmail.com>
CC: nogikh@google.com, Paul Walmsley <paul.walmsley@sifive.com>,
  aou@eecs.berkeley.edu, ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
  dvyukov@google.com, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alexandre.ghiti@canonical.com
Message-ID: <mhng-ed033018-ce9a-4b4c-b154-bd761639131d@palmer-ri-x1c9>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b=IyvZ7Y0O;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Wed, 23 Feb 2022 09:17:16 PST (-0800), alexandre.ghiti@canonical.com wrote:
> On Wed, Feb 23, 2022 at 2:10 PM Alexandre Ghiti
> <alexandre.ghiti@canonical.com> wrote:
>>
>> Hi Aleksandr,
>>
>> On Tue, Feb 22, 2022 at 11:28 AM Aleksandr Nogikh <nogikh@google.com> wrote:
>> >
>> > Hi Alexandre,
>> >
>> > Thanks for the series!
>> >
>> > However, I still haven't managed to boot the kernel. What I did:
>> > 1) Checked out the riscv/fixes branch (this is the one we're using on
>> > syzbot). The latest commit was
>> > 6df2a016c0c8a3d0933ef33dd192ea6606b115e3.
>> > 2) Applied all 4 patches.
>> > 3) Used the config from the cover letter:
>> > https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
>> > 4) Built with `make -j32 ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-`
>> > 5) Ran with `qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot
>> > -device virtio-rng-pci -machine virt -device
>> > virtio-net-pci,netdev=net0 -netdev
>> > user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:12529-:22 -device
>> > virtio-blk-device,drive=hd0 -drive
>> > file=~/kernel-image/riscv64,if=none,format=raw,id=hd0 -snapshot
>> > -kernel ~/linux-riscv/arch/riscv/boot/Image -append "root=/dev/vda
>> > console=ttyS0 earlyprintk=serial"` (this is similar to how syzkaller
>> > runs qemu).
>> >
>> > Can you please hint at what I'm doing differently?
>>
>> A short summary of what I found to keep you updated:
>>
>> I compared your command line and mine, the differences are that I use
>> "smp=4" and I add "earlycon" to the kernel command line. When added to
>> your command line, that allows it to boot. I understand why it helps
>> but I can't explain what's wrong...Anyway, I fixed a warning that I
>> had missed and that allows me to remove the "smp=4" and "earlycon".
>>
>> But this is not over yet...Your command line still does not allow to
>> reach userspace, it fails with the following stacktrace:
>>
>> [   11.537817][    T1] Unable to handle kernel paging request at
>> virtual address fffff5eeffffc800
>> [   11.539450][    T1] Oops [#1]
>> [   11.539909][    T1] Modules linked in:
>> [   11.540451][    T1] CPU: 0 PID: 1 Comm: swapper/0 Not tainted
>> 5.17.0-rc1-00007-ga68b89289e26-dirty #28
>> [   11.541364][    T1] Hardware name: riscv-virtio,qemu (DT)
>> [   11.542032][    T1] epc : kasan_check_range+0x96/0x13e
>> [   11.542654][    T1]  ra : memset+0x1e/0x4c
>> [   11.543388][    T1] epc : ffffffff8046c312 ra : ffffffff8046ca16 sp
>> : ffffaf8007337b70
>> [   11.544037][    T1]  gp : ffffffff85866c80 tp : ffffaf80073d8000 t0
>> : 0000000000046000
>> [   11.544637][    T1]  t1 : fffff5eeffffc9ff t2 : 0000000000000000 s0
>> : ffffaf8007337ba0
>> [   11.545409][    T1]  s1 : 0000000000001000 a0 : fffff5eeffffca00 a1
>> : 0000000000001000
>> [   11.546072][    T1]  a2 : 0000000000000001 a3 : ffffffff8039ef24 a4
>> : ffffaf7ffffe4000
>> [   11.546707][    T1]  a5 : fffff5eeffffc800 a6 : 0000004000000000 a7
>> : ffffaf7ffffe4fff
>> [   11.547541][    T1]  s2 : ffffaf7ffffe4000 s3 : 0000000000000000 s4
>> : ffffffff8467faa8
>> [   11.548277][    T1]  s5 : 0000000000000000 s6 : ffffffff85869840 s7
>> : 0000000000000000
>> [   11.548950][    T1]  s8 : 0000000000001000 s9 : ffffaf805a54a048
>> s10: ffffffff8588d420
>> [   11.549705][    T1]  s11: ffffaf7ffffe4000 t3 : 0000000000000000 t4
>> : 0000000000000040
>> [   11.550465][    T1]  t5 : fffff5eeffffca00 t6 : 0000000000000002
>> [   11.551131][    T1] status: 0000000000000120 badaddr:
>> fffff5eeffffc800 cause: 000000000000000d
>> [   11.551961][    T1] [<ffffffff8039ef24>] pcpu_alloc+0x84a/0x125c
>> [   11.552928][    T1] [<ffffffff8039f994>] __alloc_percpu+0x28/0x34
>> [   11.553555][    T1] [<ffffffff83286954>] ip_rt_init+0x15a/0x35c
>> [   11.554128][    T1] [<ffffffff83286d24>] ip_init+0x18/0x30
>> [   11.554642][    T1] [<ffffffff8328844a>] inet_init+0x2a6/0x550
>> [   11.555428][    T1] [<ffffffff80003220>] do_one_initcall+0x132/0x7e4
>> [   11.556049][    T1] [<ffffffff83201f7a>] kernel_init_freeable+0x510/0x5b4
>> [   11.556771][    T1] [<ffffffff831424e4>] kernel_init+0x28/0x21c
>> [   11.557344][    T1] [<ffffffff800056a0>] ret_from_exception+0x0/0x14
>> [   11.585469][    T1] ---[ end trace 0000000000000000 ]---
>>
>> 0xfffff5eeffffc800 is a KASAN address that points to the very end of
>> vmalloc address range, which is weird since KASAN_VMALLOC is not
>> enabled.
>> Moreover my command line does not trigger the above bug, and I'm
>> trying to understand why:
>
> When I read this email I saw that I did not use the same qemu version:
> I have a locally built version that disables sv48, which is the one
> that works so the problem came from the sv48 support.
>
> In a nutshell, the issue comes from the fact that kasan inner regions
> are not aligned on PGDIR_SIZE when sv48 (which is 4-level page table)
> is on, and then when populating the kasan linear mapping region, that
> clears the kasan vmalloc region which is in the same PGD: the fix is
> to copy its content before initializing the linear mapping entries.
> This issue only happens when KASAN_VMALLOC is disabled. I had fixed
> this already for kasan_shallow_populate_pud, but missed
> kasan_populate_pud.
>
> Tomorrow I'll push the v3. It still does not fix the issue I describe
> in the cover letter though, so still more work to do. At least, I was
> able to reach userspace with your *exact* qemu command :)

I can't find a v3.

>
> Alex
>
>
>>
>> /home/alex/work/qemu/build/riscv64-softmmu/qemu-system-riscv64 -M virt
>> -bios /home/alex/work/opensbi/build/platform/generic/firmware/fw_dynamic.bin
>> -kernel /home/alex/work/kernel-build/riscv_rv64_kernel/arch/riscv/boot/Image
>> -netdev user,id=net0 -device virtio-net-device,netdev=net0 -drive
>> file=/home/alex/work/kernel-build/rootfs.ext2,format=raw,id=hd0
>> -device virtio-blk-device,drive=hd0 -nographic -smp 4 -m 16G -s
>> -append "rootwait earlycon root=/dev/vda ro earlyprintk=serial"
>>
>> I'm looking into all of this and will get back with a v3 soon :)
>>
>> Thanks,
>>
>> Alex
>>
>>
>>
>>
>>
>>
>> >
>> > A simple config with KASAN, KASAN_OUTLINE and DEBUG_VIRTUAL now indeed
>> > leads to a booting kernel, which was not the case before.
>> > make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
>> > ./scripts/config -e KASAN -e KASAN_OUTLINE -e DEBUG_VIRTUAL
>> > make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
>> >
>> > --
>> > Best Regards,
>> > Aleksandr
>> >
>> > On Mon, Feb 21, 2022 at 5:17 PM Alexandre Ghiti
>> > <alexandre.ghiti@canonical.com> wrote:
>> > >
>> > > __virt_to_phys function is called very early in the boot process (ie
>> > > kasan_early_init) so it should not be instrumented by KASAN otherwise it
>> > > bugs.
>> > >
>> > > Fix this by declaring phys_addr.c as non-kasan instrumentable.
>> > >
>> > > Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
>> > > ---
>> > >  arch/riscv/mm/Makefile | 3 +++
>> > >  1 file changed, 3 insertions(+)
>> > >
>> > > diff --git a/arch/riscv/mm/Makefile b/arch/riscv/mm/Makefile
>> > > index 7ebaef10ea1b..ac7a25298a04 100644
>> > > --- a/arch/riscv/mm/Makefile
>> > > +++ b/arch/riscv/mm/Makefile
>> > > @@ -24,6 +24,9 @@ obj-$(CONFIG_KASAN)   += kasan_init.o
>> > >  ifdef CONFIG_KASAN
>> > >  KASAN_SANITIZE_kasan_init.o := n
>> > >  KASAN_SANITIZE_init.o := n
>> > > +ifdef CONFIG_DEBUG_VIRTUAL
>> > > +KASAN_SANITIZE_physaddr.o := n
>> > > +endif
>> > >  endif
>> > >
>> > >  obj-$(CONFIG_DEBUG_VIRTUAL) += physaddr.o
>> > > --
>> > > 2.32.0
>> > >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-ed033018-ce9a-4b4c-b154-bd761639131d%40palmer-ri-x1c9.
