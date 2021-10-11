Return-Path: <kasan-dev+bncBCMIZB7QWENRBIGLR6FQMGQENRWQNZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id E0CBE42878C
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 09:20:01 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id w1-20020a4a2741000000b002b6eb5b596csf1747289oow.9
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 00:20:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633936800; cv=pass;
        d=google.com; s=arc-20160816;
        b=dApNaEQnGIVF3lUVKoyeklfifyn04bM2QyBG+4cJPQyGgZHq4Rym68xGObU1ExkcgC
         tkNGIMdqAvGiFKxrK/4Dq7xNRRqD2DL6Bfk3Yp9YAZMCgwtRM6LbG5Et0bO5BZhi0wG+
         N2Lzq5dRZwrH09s7Z7O22TPgHQlEG7LQbrkfYZrNweV1V4O497mqnGccQIClZ5A2/bUZ
         5cUtpIIOY0zQjJr2VMFOJzrfFYsqlKt4GkHS92uTZxxN4AMTwvieIiRP4feQ1NFGcfE9
         D/iHK8PMHfgkqwVvfq7vrTJif3ioQZghBhON8cw+UhejPeHyHhx8qxPPjg19ay+qCKuU
         XJgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=k4Ac3NIGKMyIO4i2Z1mM6l3BBGgz275p1CxZveFnsxg=;
        b=niMDfRANATMCD0FkI2cw/3uNq4iSXbjdrj1iC3vwrLveRCcAO1xqKrRmA9HX5nLxXk
         x2v8SS3WhAebod1sz2aZO++qxO5ZqjNDrEvRes53jGhk1ci94G+Rb9yP5E2fOrbChkQR
         Zqm9vGrLH7yYQiTH9h+144fQcYEz2NlIjJHP6DuMIfotpaecgRHQF8yesD1ISeWrqMtg
         moqh7v7FZEIksRIyC7EkHrNi/EOjzxFqE79x7j7kmUFo16HFEE+cov0VYboxDjjOsFf6
         b7zgpzLq287yDIlOqNzHy9KPDC0hSMSRBp34DFf96ldtGIPxeg0z8NCtJx8hPsAhthSn
         Exbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Qqgyce7V;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=k4Ac3NIGKMyIO4i2Z1mM6l3BBGgz275p1CxZveFnsxg=;
        b=XEuGSRHON86Z6KckWt84O0LJQ7YPfnM3Tw+xNqtAiho0TfN9EokRa5QOyZCO4BlqE9
         RqH1dJQ6m8NCWcQJc6UpFP3KPSFzhtpFDV4NNBUYjhaIvQxaRrwTiNzTNyt/QbMd6OeQ
         fMa7kl0fmovNLigdO3dmzcKiO0c2W0rGn6Rd9B2a9P/RL6Xtsglb3wWBhpQ2asF5X0dH
         lwr+k+Dg6pYjQt5U85BIfPhDUk53DxBF4Nbl5iuOffWS4A0YOUx3n5m6FDyG+EoFALFN
         BsTQdVia8dKBKIPK7k0B9ILlb2pjpaMSxOzKg8FzFZ5yXbMlCTuRUAdaMaKRWxnTJ7YL
         S56Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=k4Ac3NIGKMyIO4i2Z1mM6l3BBGgz275p1CxZveFnsxg=;
        b=CElr0cr5PRc7ogz51BHyskMxq0hyfg4DGChSrA/Cm4+M41lQpXa6qoVWb9ZA74yDpr
         f3anEfXXBWudXPES6OwKgRWS1odecf/xRI2ZWdnyF0QVIlaNcBRdUvh9IGBZLBs08Wnf
         7yHcaLIu7xIf1wr/Ncd8lbLiqF5U/hqnZrSfYYMnAAMBUlQGixez15cpftYIIarT5Cvz
         ATrwQKN5DY/3SRJ3guvuTqvyRR+zeX/mqluQIFu2OwhZVDYvrjiO7TrHf/Aq5UlQDr1r
         zOeMLld5V80Cc1GhacFHzBD30L0tLvU9ZCjP/9C0Yhm0HTtmVtzL4dZ2LJnFFcV9RTtF
         gA8g==
X-Gm-Message-State: AOAM53090EPddHtwbgq2hDLHgGRMn9+PdbkMa4hbKL6z21r7uV6k5L49
	h6CTZr0lID50724THCfvpeA=
X-Google-Smtp-Source: ABdhPJzCYEh0rPQD32SVutdYulkL70oWs+wkBa2baaIc5HH+KpsRW/HVUfG6yhz9yVCPhXCYVc/8NA==
X-Received: by 2002:a54:418a:: with SMTP id 10mr17103543oiy.13.1633936800624;
        Mon, 11 Oct 2021 00:20:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:48:: with SMTP id v8ls2544061oic.11.gmail; Mon, 11
 Oct 2021 00:20:00 -0700 (PDT)
X-Received: by 2002:aca:5c09:: with SMTP id q9mr4708334oib.85.1633936800224;
        Mon, 11 Oct 2021 00:20:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633936800; cv=none;
        d=google.com; s=arc-20160816;
        b=kSDsXjVLwICFFrBd+euTmV+iKbuldgblklXJvFQt3CvgxTtQNrVqwnJFg1481xHvzo
         aVcVm/6ck8msXs7FsOoaWTGOZwTpzlTlNuYTOwRx3oPhQlxlCIKp2XBU9zlJXvmibMbn
         /O/x4xsu9vQS2lR/MYlSmtlaiYEqpfGJeuMCIh71jodLVk/xZsoL4ihXdo/phys2EBgY
         VmtE4Zl47oFeu7h6L03nHHYJ2BgARzjp1+ANYDfRxC0Voo2VNcDwomo+vbCctciR//2+
         DFAHCo29pGUPQjZZWKLlJpnhYh1s/ueQ26BXlI69MuwiJiI9fA6KvWD96C6m8aQ3Rl+x
         6VpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hvLHxd7M6lrg6ngmQ548ehLrcVjs8MUn2wc/QvypJI4=;
        b=aQRwXMKiWQkoHiy35ZNzLe+4ORP29+EqSISyG2VZO2nDwAS5Z5i7/mdPLNpt/N//Uq
         jfUHj4yNDijKbX1vdmp1rfN8OWj04lIzBTVV5+04HjPMJb8c60CVNANex6Otj3SHRMOE
         I7VyMfv63BfXc4rQXalt/4GylpZ4nC+o5BmUA0peHc5AKOSiCpxx4kbq/IBkYE/0Hpv5
         LFAsnvRxOauIulbH5gDHJ1+PoFGjoUaVFluccgD9DmTsVk4GnJlUyyPChdF1SPNHjuTy
         pMgL1OEw8/MASWTYdO/E742BBeC6bwMVhnaM7UDeb1pzoFNWmw+HAyHkgVbAN2qUoWmH
         wleQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Qqgyce7V;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x232.google.com (mail-oi1-x232.google.com. [2607:f8b0:4864:20::232])
        by gmr-mx.google.com with ESMTPS id bc13si632033oob.2.2021.10.11.00.20.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Oct 2021 00:20:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::232 as permitted sender) client-ip=2607:f8b0:4864:20::232;
Received: by mail-oi1-x232.google.com with SMTP id n64so23519707oih.2
        for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 00:20:00 -0700 (PDT)
X-Received: by 2002:aca:5dc5:: with SMTP id r188mr2376347oib.160.1633936799664;
 Mon, 11 Oct 2021 00:19:59 -0700 (PDT)
MIME-Version: 1.0
References: <YWLwUUNuRrO7AxtM@arighi-desktop> <CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com>
 <YWPaZSX4WyOwilW+@arighi-desktop> <CANpmjNMFFFa=6toZJXqo_9hzv05zoD0aXA4D_K93rfw58cEw3w@mail.gmail.com>
 <YWPjZv7ClDOE66iI@arighi-desktop>
In-Reply-To: <YWPjZv7ClDOE66iI@arighi-desktop>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Oct 2021 09:19:48 +0200
Message-ID: <CACT4Y+b4Xmev7uLhASpHnELcteadhaXCBkkD5hO2YNP5M2451g@mail.gmail.com>
Subject: Re: BUG: soft lockup in __kmalloc_node() with KFENCE enabled
To: Andrea Righi <andrea.righi@canonical.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Qqgyce7V;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::232
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 11 Oct 2021 at 09:10, Andrea Righi <andrea.righi@canonical.com> wro=
te:
>
> On Mon, Oct 11, 2021 at 08:48:29AM +0200, Marco Elver wrote:
> > On Mon, 11 Oct 2021 at 08:32, Andrea Righi <andrea.righi@canonical.com>=
 wrote:
> > > On Mon, Oct 11, 2021 at 08:00:00AM +0200, Marco Elver wrote:
> > > > On Sun, 10 Oct 2021 at 15:53, Andrea Righi <andrea.righi@canonical.=
com> wrote:
> > > > > I can systematically reproduce the following soft lockup w/ the l=
atest
> > > > > 5.15-rc4 kernel (and all the 5.14, 5.13 and 5.12 kernels that I'v=
e
> > > > > tested so far).
> > > > >
> > > > > I've found this issue by running systemd autopkgtest (I'm using t=
he
> > > > > latest systemd in Ubuntu - 248.3-1ubuntu7 - but it should happen =
with
> > > > > any recent version of systemd).
> > > > >
> > > > > I'm running this test inside a local KVM instance and apparently =
systemd
> > > > > is starting up its own KVM instances to run its tests, so the con=
text is
> > > > > a nested KVM scenario (even if I don't think the nested KVM part =
really
> > > > > matters).
> > > > >
> > > > > Here's the oops:
> > > > >
> > > > > [   36.466565] watchdog: BUG: soft lockup - CPU#0 stuck for 26s! =
[udevadm:333]
> > > > > [   36.466565] Modules linked in: btrfs blake2b_generic zstd_comp=
ress raid10 raid456 async_raid6_recov async_memcpy async_pq async_xor async=
_tx xor raid6_pq libcrc32c raid1 raid0 multipath linear psmouse floppy
> > > > > [   36.466565] CPU: 0 PID: 333 Comm: udevadm Not tainted 5.15-rc4
> > > > > [   36.466565] Hardware name: QEMU Standard PC (i440FX + PIIX, 19=
96), BIOS 1.14.0-2 04/01/2014
> > > > [...]
> > > > >
> > > > > If I disable CONFIG_KFENCE the soft lockup doesn't happen and sys=
temd
> > > > > autotest completes just fine.
> > > > >
> > > > > We've decided to disable KFENCE in the latest Ubuntu Impish kerne=
l
> > > > > (5.13) for now, because of this issue, but I'm still investigatin=
g
> > > > > trying to better understand the problem.
> > > > >
> > > > > Any hint / suggestion?
> > > >
> > > > Can you confirm this is not a QEMU TCG instance? There's been a kno=
wn
> > > > issue with it: https://bugs.launchpad.net/qemu/+bug/1920934
> > >
> > > It looks like systemd is running qemu-system-x86 without any "accel"
> > > options, so IIUC the instance shouldn't use TCG. Is this a correct
> > > assumption or is there a better way to check?
> >
> > AFAIK, the default is TCG if nothing else is requested. What was the
> > command line?
>
> This is the full command line of what systemd is running:
>
>   /bin/qemu-system-x86_64 -smp 4 -net none -m 512M -nographic -vga none -=
kernel /boot/vmlinuz-5.15-rc4 -drive format=3Draw,cache=3Dunsafe,file=3D/va=
r/tmp/systemd-test.sI1nrh/badid.img -initrd /boot/initrd.img-5.15-rc4 -appe=
nd  root=3D/dev/sda1 rw raid=3Dnoautodetect rd.luks=3D0 loglevel=3D2 init=
=3D/lib/systemd/systemd console=3DttyS0 selinux=3D0  SYSTEMD_UNIT_PATH=3D/u=
sr/lib/systemd/tests/testdata/testsuite-14.units:/usr/lib/systemd/tests/tes=
tdata/units: systemd.unit=3Dtestsuite.target systemd.wants=3Dtestsuite-14.s=
ervice systemd.wants=3Dend.service
>
> And this is running inside a KVM instance (so a nested KVM scenario).

Hi Andrea,

I think you need to pass -enable-kvm to make it "nested KVM scenario",
otherwise it's TCG emulation.

You seem to use the default 20s stall timeout. FWIW syzbot uses 160
secs timeout for TCG emulation to avoid false positive warnings:
https://github.com/google/syzkaller/blob/838e7e2cd9228583ca33c49a39aea4d863=
d3e36d/dashboard/config/linux/upstream-arm64-kasan.config#L509
There are a number of other timeouts raised as well, some as high as
420 seconds.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2Bb4Xmev7uLhASpHnELcteadhaXCBkkD5hO2YNP5M2451g%40mail.gmai=
l.com.
