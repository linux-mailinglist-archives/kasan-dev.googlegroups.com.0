Return-Path: <kasan-dev+bncBDQ7NGWH7YJRB5XE3CIAMGQEICGOZAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id E183B4C139D
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Feb 2022 14:11:18 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id bf20-20020a2eaa14000000b0024634b36cdasf5358223ljb.0
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Feb 2022 05:11:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645621878; cv=pass;
        d=google.com; s=arc-20160816;
        b=TR4JDgwI/8R4ArIiMfYPr4n6npF0T1N8oLcrdt3NfqDMwWGI/FgltH5i4EquZfEETJ
         MPIBzZuf6esx/5m8w0IwCTkLgRKoUZw2FmVlDIfKEKNPdOrIB1KM/hdPTmAn8iYK4GSy
         2D51V8/CByHOsi+6vV0dXjZVr8DskDiTTxtgvpgJzOB+X9q90bUjuJIv2FsahLDAuhDh
         1VX21PCncPNUPhjg6a1AGOy9YbGjqD0L2IEjJfCMmnqJpEYjoZghYn9DUqaFnf4XBZX7
         Ly5K8UVbZpW19/kvld2cm/DmlBT16W4ZzPr07uZYuToKLZqvrASgsDM7jpfkOaqFcljU
         W2RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=HMzPze0QUjvsAJ9RiRJb4vM4UJESq6EN7o9OUkuGu+k=;
        b=sbfcalNnhtXU9Yld5bbJPvrAY9v7VqEr5h+mfivzpYVKDnQXQOs0cMZ+285yct1/Nm
         Alb+dxrA9Ao2XOBm1BF5NNSszSiF5NNq1vFq+uH2lLYvZszhiDdFP5SK3k341gVgbg8U
         bZiIQTf8KjhS5oiiwinLq3pFKQBXDIx/AGaghdDVWezvnpOHzBmGy4mE2UNDJrADr5Ps
         RmO0pz20Rr2njB6tCFM9WR40rFJytNgt9acgwkXOsrIL70Fz303b2sBT2Vw3W+Jjo7jx
         cCFTYGFMGkYWRDFmtwzeZevJCEfT49pO0vdfOrDG/KJWkgcTtkTGnIYOgHuzgm8QbUPf
         ItJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b="mEK4/qgV";
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HMzPze0QUjvsAJ9RiRJb4vM4UJESq6EN7o9OUkuGu+k=;
        b=WS5YKquR0ParHvHLbzhCQHNbYcvUmDrcEar2btZRDztC7SVrSfT4FWH1CtvvJGvYRA
         NkSXqDyB4E4p5nOx8JdW2VjItQq17MbUfIYT+4jiFYNJFD3H45FgnYtaK2+S60u/0mvk
         XhUqQqSNR/EIj/3S/4ROiBTbHA9LEoMkox+FjkhQGf4n0mvcmaQJn63wz6HtDtZmrdXt
         4w47X/xHtZ1Eq1z1D9qXiWoms3QAlpRSgEgbT8KzefEnLzHFEuATIJAbu4AcdSNHk9+M
         uk++6H0+t5ET+GpCiBV7999fEBJPEzfc9DJUeFZBGbcR4vu9AK1QD092dXQ2EDDnu/lF
         /sSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HMzPze0QUjvsAJ9RiRJb4vM4UJESq6EN7o9OUkuGu+k=;
        b=z1LejtV7gfK+DJCCvikS4JSEJe5ta2DAU7lD1ZOhZyM5IVw/+dQ9cuwCK0wIAdeZxl
         OXUQhBa5eyr9NYkbKeiQ+wuPI7an7cji0uHsXKEs+c0WYfLeTkKMbK6KkuAcpaOa3sz7
         PVF0D+1+dSgv2cRsNqOINAjullFrG1IxE57dVr8ZQQO9BmD7mlh0k5jNtO1KCekGIhyd
         s/flLNz91Ciy7chjrrOMhoof3lFmKcvYuVvrA4tCODCYwmpWfkQOFN2pCpSL3+3AyGIB
         0VsQsX5eUpshj9XAfewB26vJW46dtf9090DdacZ5u/+FlVCL79h2g1rrI8/SSKhmj01X
         Z5NA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531eDvtappVqHP+UazDWJq3HKzsEftTfhW33ZF5C8h6NKSR7r3pI
	D1isfpUONZQPjzYK2OBFLuE=
X-Google-Smtp-Source: ABdhPJxGi0eF1v7J75Y40E8iGMoA3NCykaDVSsfYkAsJ3zB0IQlLj68c7qhgG3wA/ypxXDYliy1XZA==
X-Received: by 2002:a2e:8898:0:b0:246:4793:f63a with SMTP id k24-20020a2e8898000000b002464793f63amr7084495lji.424.1645621878245;
        Wed, 23 Feb 2022 05:11:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2394:b0:443:f5b2:4a94 with SMTP id
 c20-20020a056512239400b00443f5b24a94ls104373lfv.2.gmail; Wed, 23 Feb 2022
 05:11:17 -0800 (PST)
X-Received: by 2002:a05:6512:3d94:b0:43e:af37:af96 with SMTP id k20-20020a0565123d9400b0043eaf37af96mr20228430lfv.469.1645621877245;
        Wed, 23 Feb 2022 05:11:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645621877; cv=none;
        d=google.com; s=arc-20160816;
        b=aUS+bfw/nqQ1iuGM8C9wRL1cOCOGq2XiZxXfr2Wl0tkAu03zD0OCcvj1WUE4/B/MM+
         sykEKhwtqSlsTkrP55O+pJoEq9/5szZ/NeYYECb+ysn5xOHHBW+mRiAKrhZhKLtpvYQh
         TJpfQl33BiEOuOGLFZBPIr90x+ZiJnNJ7oQRVwssVH5ndbltqC8zRPcLAQAspYmSWKZi
         WYkn8S8xVrMoeq8n4ua+mhxQ/q1vdSognBpipeVo3aagLeTnQd91TFpL0cDdmr5ydT6+
         2gP/tHlwYA1xKoqOPBVbSSbvs/sr10EuVGERj0gWv6Jm2tgMyx6oVgBWqHJiYAn3Gw9B
         8QRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UXKLKyZvqZuicoDX6WsicwD+NuWstrOluCAJwIKeGTs=;
        b=oZK2+Uo3xr5t4gAzej/Syqj+YZiJvcO+EW+B0ITUSK8QuPFzPix3cOHluQ7GBtIGuB
         A89pam5YcT8Y090nxBdGm8FKeakIcVf1frB3vCVS3yNReVWzy/oKyEylQM0KKq61rzj8
         RKB4zIKVHd8OpH69kn2UUArqr0AJsaCmAKGieyAvSXOGTgfDYaBW3URK7U820PPydQVk
         7SYZwgW5kTPZNHrH4pg8q0fpDKEWrfJ+uGV90AycGJB/4OJP4ONbjCqUizKW0Eqt3LHQ
         SGxOAPX3xBPz8QBDdF3GgRFyO3PQonWlgnh9d2uBWlqe8GDrTbivzH/ep4vINFg8uhqb
         diRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b="mEK4/qgV";
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id w11si667611lfr.12.2022.02.23.05.11.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Feb 2022 05:11:17 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-ed1-f72.google.com (mail-ed1-f72.google.com [209.85.208.72])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id B37663FCA4
	for <kasan-dev@googlegroups.com>; Wed, 23 Feb 2022 13:11:07 +0000 (UTC)
Received: by mail-ed1-f72.google.com with SMTP id l3-20020a50cbc3000000b0041083c11173so13577199edi.4
        for <kasan-dev@googlegroups.com>; Wed, 23 Feb 2022 05:11:07 -0800 (PST)
X-Received: by 2002:a17:906:d9db:b0:6ce:8bfb:53c9 with SMTP id qk27-20020a170906d9db00b006ce8bfb53c9mr22490679ejb.10.1645621865034;
        Wed, 23 Feb 2022 05:11:05 -0800 (PST)
X-Received: by 2002:a17:906:d9db:b0:6ce:8bfb:53c9 with SMTP id
 qk27-20020a170906d9db00b006ce8bfb53c9mr22490660ejb.10.1645621864802; Wed, 23
 Feb 2022 05:11:04 -0800 (PST)
MIME-Version: 1.0
References: <20220221161232.2168364-1-alexandre.ghiti@canonical.com>
 <20220221161232.2168364-5-alexandre.ghiti@canonical.com> <CANp29Y7M=wSLBE8m0-CHKtYPkqgcxNiUPEyRNv-VHeR5O2BTYQ@mail.gmail.com>
In-Reply-To: <CANp29Y7M=wSLBE8m0-CHKtYPkqgcxNiUPEyRNv-VHeR5O2BTYQ@mail.gmail.com>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Wed, 23 Feb 2022 14:10:53 +0100
Message-ID: <CA+zEjCt02Cx1Q1yDGN9V6Wvgx0+jvcqft6U56M3wsidkW5sMjg@mail.gmail.com>
Subject: Re: [PATCH -fixes v2 4/4] riscv: Fix config KASAN && DEBUG_VIRTUAL
To: Aleksandr Nogikh <nogikh@google.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Nick Hu <nickhu@andestech.com>, 
	linux-riscv@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b="mEK4/qgV";       spf=pass
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

Hi Aleksandr,

On Tue, Feb 22, 2022 at 11:28 AM Aleksandr Nogikh <nogikh@google.com> wrote:
>
> Hi Alexandre,
>
> Thanks for the series!
>
> However, I still haven't managed to boot the kernel. What I did:
> 1) Checked out the riscv/fixes branch (this is the one we're using on
> syzbot). The latest commit was
> 6df2a016c0c8a3d0933ef33dd192ea6606b115e3.
> 2) Applied all 4 patches.
> 3) Used the config from the cover letter:
> https://gist.github.com/a-nogikh/279c85c2d24f47efcc3e865c08844138
> 4) Built with `make -j32 ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-`
> 5) Ran with `qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot
> -device virtio-rng-pci -machine virt -device
> virtio-net-pci,netdev=net0 -netdev
> user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:12529-:22 -device
> virtio-blk-device,drive=hd0 -drive
> file=~/kernel-image/riscv64,if=none,format=raw,id=hd0 -snapshot
> -kernel ~/linux-riscv/arch/riscv/boot/Image -append "root=/dev/vda
> console=ttyS0 earlyprintk=serial"` (this is similar to how syzkaller
> runs qemu).
>
> Can you please hint at what I'm doing differently?

A short summary of what I found to keep you updated:

I compared your command line and mine, the differences are that I use
"smp=4" and I add "earlycon" to the kernel command line. When added to
your command line, that allows it to boot. I understand why it helps
but I can't explain what's wrong...Anyway, I fixed a warning that I
had missed and that allows me to remove the "smp=4" and "earlycon".

But this is not over yet...Your command line still does not allow to
reach userspace, it fails with the following stacktrace:

[   11.537817][    T1] Unable to handle kernel paging request at
virtual address fffff5eeffffc800
[   11.539450][    T1] Oops [#1]
[   11.539909][    T1] Modules linked in:
[   11.540451][    T1] CPU: 0 PID: 1 Comm: swapper/0 Not tainted
5.17.0-rc1-00007-ga68b89289e26-dirty #28
[   11.541364][    T1] Hardware name: riscv-virtio,qemu (DT)
[   11.542032][    T1] epc : kasan_check_range+0x96/0x13e
[   11.542654][    T1]  ra : memset+0x1e/0x4c
[   11.543388][    T1] epc : ffffffff8046c312 ra : ffffffff8046ca16 sp
: ffffaf8007337b70
[   11.544037][    T1]  gp : ffffffff85866c80 tp : ffffaf80073d8000 t0
: 0000000000046000
[   11.544637][    T1]  t1 : fffff5eeffffc9ff t2 : 0000000000000000 s0
: ffffaf8007337ba0
[   11.545409][    T1]  s1 : 0000000000001000 a0 : fffff5eeffffca00 a1
: 0000000000001000
[   11.546072][    T1]  a2 : 0000000000000001 a3 : ffffffff8039ef24 a4
: ffffaf7ffffe4000
[   11.546707][    T1]  a5 : fffff5eeffffc800 a6 : 0000004000000000 a7
: ffffaf7ffffe4fff
[   11.547541][    T1]  s2 : ffffaf7ffffe4000 s3 : 0000000000000000 s4
: ffffffff8467faa8
[   11.548277][    T1]  s5 : 0000000000000000 s6 : ffffffff85869840 s7
: 0000000000000000
[   11.548950][    T1]  s8 : 0000000000001000 s9 : ffffaf805a54a048
s10: ffffffff8588d420
[   11.549705][    T1]  s11: ffffaf7ffffe4000 t3 : 0000000000000000 t4
: 0000000000000040
[   11.550465][    T1]  t5 : fffff5eeffffca00 t6 : 0000000000000002
[   11.551131][    T1] status: 0000000000000120 badaddr:
fffff5eeffffc800 cause: 000000000000000d
[   11.551961][    T1] [<ffffffff8039ef24>] pcpu_alloc+0x84a/0x125c
[   11.552928][    T1] [<ffffffff8039f994>] __alloc_percpu+0x28/0x34
[   11.553555][    T1] [<ffffffff83286954>] ip_rt_init+0x15a/0x35c
[   11.554128][    T1] [<ffffffff83286d24>] ip_init+0x18/0x30
[   11.554642][    T1] [<ffffffff8328844a>] inet_init+0x2a6/0x550
[   11.555428][    T1] [<ffffffff80003220>] do_one_initcall+0x132/0x7e4
[   11.556049][    T1] [<ffffffff83201f7a>] kernel_init_freeable+0x510/0x5b4
[   11.556771][    T1] [<ffffffff831424e4>] kernel_init+0x28/0x21c
[   11.557344][    T1] [<ffffffff800056a0>] ret_from_exception+0x0/0x14
[   11.585469][    T1] ---[ end trace 0000000000000000 ]---

0xfffff5eeffffc800 is a KASAN address that points to the very end of
vmalloc address range, which is weird since KASAN_VMALLOC is not
enabled.
Moreover my command line does not trigger the above bug, and I'm
trying to understand why:

/home/alex/work/qemu/build/riscv64-softmmu/qemu-system-riscv64 -M virt
-bios /home/alex/work/opensbi/build/platform/generic/firmware/fw_dynamic.bin
-kernel /home/alex/work/kernel-build/riscv_rv64_kernel/arch/riscv/boot/Image
-netdev user,id=net0 -device virtio-net-device,netdev=net0 -drive
file=/home/alex/work/kernel-build/rootfs.ext2,format=raw,id=hd0
-device virtio-blk-device,drive=hd0 -nographic -smp 4 -m 16G -s
-append "rootwait earlycon root=/dev/vda ro earlyprintk=serial"

I'm looking into all of this and will get back with a v3 soon :)

Thanks,

Alex






>
> A simple config with KASAN, KASAN_OUTLINE and DEBUG_VIRTUAL now indeed
> leads to a booting kernel, which was not the case before.
> make defconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
> ./scripts/config -e KASAN -e KASAN_OUTLINE -e DEBUG_VIRTUAL
> make olddefconfig ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
>
> --
> Best Regards,
> Aleksandr
>
> On Mon, Feb 21, 2022 at 5:17 PM Alexandre Ghiti
> <alexandre.ghiti@canonical.com> wrote:
> >
> > __virt_to_phys function is called very early in the boot process (ie
> > kasan_early_init) so it should not be instrumented by KASAN otherwise it
> > bugs.
> >
> > Fix this by declaring phys_addr.c as non-kasan instrumentable.
> >
> > Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > ---
> >  arch/riscv/mm/Makefile | 3 +++
> >  1 file changed, 3 insertions(+)
> >
> > diff --git a/arch/riscv/mm/Makefile b/arch/riscv/mm/Makefile
> > index 7ebaef10ea1b..ac7a25298a04 100644
> > --- a/arch/riscv/mm/Makefile
> > +++ b/arch/riscv/mm/Makefile
> > @@ -24,6 +24,9 @@ obj-$(CONFIG_KASAN)   += kasan_init.o
> >  ifdef CONFIG_KASAN
> >  KASAN_SANITIZE_kasan_init.o := n
> >  KASAN_SANITIZE_init.o := n
> > +ifdef CONFIG_DEBUG_VIRTUAL
> > +KASAN_SANITIZE_physaddr.o := n
> > +endif
> >  endif
> >
> >  obj-$(CONFIG_DEBUG_VIRTUAL) += physaddr.o
> > --
> > 2.32.0
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCt02Cx1Q1yDGN9V6Wvgx0%2Bjvcqft6U56M3wsidkW5sMjg%40mail.gmail.com.
