Return-Path: <kasan-dev+bncBDOPF7OU44DRBFUFSCFQMGQEYX7AU2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 7ACA8428998
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 11:23:35 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id u17-20020a05651206d100b003fd714d9a38sf6761841lff.8
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 02:23:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633944215; cv=pass;
        d=google.com; s=arc-20160816;
        b=t+pbme3FD98QgJq9YMPDHIqtiSBmqk7Dyas2I62zYj9U9bg4lUgIe1pbpoEr8I0dZ8
         lmuW3tHZ4S+QmHgEuLkp99NwEDVumHClvlI2I/iw4+EuR53ybw2MzBC6yT+0AlXcRhRQ
         zrCTYn2FNNA6sBUdDWao9+OOBxnaApXLfpYAc6Qczivj8KUlEDogxuFtpZUEsVU9HaZc
         s+WjOimVgkmtCQSlnh5Q9qZn24U7v2nM3cnww2eu0xzk2cPy7f2YIC1F+x4OifbuIeOK
         y6WY/29vqLsjq331L+fTwY8hETiikoLqjyf2Anj1XBjvN4G8E2YKkeiXdQraZ3h3bdo1
         YPaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=S9eWqomUjeHe8xOzCdS7tpYDuus5ZFIskJlHI66mSdY=;
        b=JQF4u6sYGBDHNMpOQSL8y4d/B6I7R1LCA/zzg+bXqXjop3dUfLjrqLIWpvGY440ZcK
         AsjOWOxf8SlPwgzLWF7By+gnKeA0efk+1lTKfkMP9GtkCCLqjE5y9Zz+ei2+AH/CTkyP
         1/hfAe0pReNYbjLEFDqZy+Hur1QGMw0uldDrS67JvrefJYDywf7ZMdGhOTwUNzAALooS
         ozKnawsKIknGFYTsrVEF3IubHQkolUC+yqaalYkeH2iVuZVGOYBq4LwtQtGAQ+xb94EV
         Pf6Oa2oow80mbpl8NoQ+mS/wfWYzISKGmUUO6IGGD4p4s/c9evOu5c/DVELeUHZ4vISx
         MdRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=f2Bgj7ok;
       spf=pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:content-transfer-encoding
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S9eWqomUjeHe8xOzCdS7tpYDuus5ZFIskJlHI66mSdY=;
        b=Cfn5je9Sj2AglvfQDjG3wB7F8GmKv38/qGZCoRnh6w6joOXslUA5KkGaHULZt3rr+l
         gw/30x9zfY7ztrNVCL0XOtDu178pnZLaV7ASdLYGOW6nbKO15mLqw1ElrsQYK1LNRgPr
         02UXmMhCBQIWnfsX8aRoc3a6jcoIQ0lH0Ktzkqd2M09wR1VRdCMaKHHcAGN2w6pfxhhm
         gMTMjHnhz6ZlK4m3W1/zovUmbrndxGL72km4Vmr92bN+KFSHQb8XS/XXg8+21z6QO9cs
         VQShcpG2/ceiuKPLlxONLwkxcEygLOVnS3ZPcWC5Aci4V9YkIsHm+8eLOxXtkCeXOa39
         tpjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S9eWqomUjeHe8xOzCdS7tpYDuus5ZFIskJlHI66mSdY=;
        b=gpcdfFi0SVpbAMspIIGcCnRmFguZiLM3Juo+I/A6vYGUooUgqcxRw2smEwnLqYorcW
         DsgsqGslq224PSc9DdgI8Jtbv5gjAdKj6xogJAru7DbPicmYqyqESU5iw4+QA7xFD0z3
         c2ct8wV5KgTg/RHFlWARhJGQ/8bi0yJ6Jx2fB9MRYIl+st6WMFALcWJHboL6fE9f0YZZ
         gNJ+J+pxn6OApmJI0W6s9DvGUraIaDfUkQR/S/U9t7NQ8abJ9FEIv4DGdCyr74Q0aAQc
         KgD5Jl7elUXaoxH0QIYGupEe6w700VN8uG3DMnCxd6cOdqxOrNcx2X7KyiSIVFUduHW2
         mx9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5315kTQrUexnNHwpkmQdcQpgOENEoaPShO993vS63Q8hIrDS2xkm
	2aM3kiGLoKohlOlqF9XI0e0=
X-Google-Smtp-Source: ABdhPJyiydcBGmV0CJVPiYrI2ndcsdslJo2j3K4reCrZi0FsKzaYLDZVLxbxHFAIVKMdGWi8Ng+mNQ==
X-Received: by 2002:a05:651c:98f:: with SMTP id b15mr14177244ljq.72.1633944215080;
        Mon, 11 Oct 2021 02:23:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7f06:: with SMTP id a6ls1601873ljd.9.gmail; Mon, 11 Oct
 2021 02:23:34 -0700 (PDT)
X-Received: by 2002:a2e:4b19:: with SMTP id y25mr21761108lja.501.1633944214061;
        Mon, 11 Oct 2021 02:23:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633944214; cv=none;
        d=google.com; s=arc-20160816;
        b=ri8VZtSMBtbROGZDIcb8rR6fxSeMFBa7o/Hgud8n2v12kpuzWBVjDxeJtP/NbYRMNU
         qJV0IxRbEly0bq7uroe8Cvq6DkcOFbQIeyxhTvfFV7KWt/rUVEcrWGwkhJ+zInhC6Lw6
         SXKz8WkpBhuaA/H3Jk2GO+hDHlrV1Mc1chHJc+HnTmxhWpeWPewPKjvZZ2F7K7g3obkG
         c2Zn4r2slwLqD8+vXmdcmqdUvQvwWXif2ArVTENFzqSviw0NlVjrsauKUyHC1c1K8Kj+
         wKCpKuYigoyGdReFv8CNRlrfwQVhL0aFJr75u6eztFtoG/vfznrgPb9wS+6ZrCErA3rP
         VzEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XGF6U6ImX48DlfSujlkFaxlWBKpZditGsN8NI04ojEA=;
        b=GNI9EHG6kPZUONXvmqEhEfSR4h4HPkshUkJ4+H5fmPooHgYU/AgBw7wYSzAzVc7Nep
         4JOOMuJR/dEbxoCBEhHacwfK5Sj8mbBBsoFFwv/mjcO7NrsSF0lNtm4oPaxozPZMexjt
         YewRuPZNCAkCLm6ddIeHV70hzRSdxqU+Km5DlIHggbgsngbKwmrUfsuOMuJ2YqRL3JqV
         FSOeuf4TjfcDdP60EktIlTmwg9+GBWogMKuxLAEhUtjJFyuc4wZNNyBvG3i3h2CCps3C
         aZItpr88oaX6NPOPZBuuXwnoNtBNpNTtMue9AIc6DR4/sZb0woEKrblrR45et/U8uySh
         sCbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=f2Bgj7ok;
       spf=pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id z12si482397lfd.13.2021.10.11.02.23.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Oct 2021 02:23:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-ed1-f72.google.com (mail-ed1-f72.google.com [209.85.208.72])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 30FC940016
	for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 09:23:33 +0000 (UTC)
Received: by mail-ed1-f72.google.com with SMTP id e14-20020a056402088e00b003db6ebb9526so5733923edy.22
        for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 02:23:33 -0700 (PDT)
X-Received: by 2002:a17:906:d937:: with SMTP id rn23mr24575970ejb.101.1633944212772;
        Mon, 11 Oct 2021 02:23:32 -0700 (PDT)
X-Received: by 2002:a17:906:d937:: with SMTP id rn23mr24575945ejb.101.1633944212505;
        Mon, 11 Oct 2021 02:23:32 -0700 (PDT)
Received: from localhost ([2001:67c:1560:8007::aac:c1b6])
        by smtp.gmail.com with ESMTPSA id g17sm3861642edv.72.2021.10.11.02.23.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Oct 2021 02:23:31 -0700 (PDT)
Date: Mon, 11 Oct 2021 11:23:30 +0200
From: Andrea Righi <andrea.righi@canonical.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: BUG: soft lockup in __kmalloc_node() with KFENCE enabled
Message-ID: <YWQCknwPcGlOBfUi@arighi-desktop>
References: <YWLwUUNuRrO7AxtM@arighi-desktop>
 <CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com>
 <YWPaZSX4WyOwilW+@arighi-desktop>
 <CANpmjNMFFFa=6toZJXqo_9hzv05zoD0aXA4D_K93rfw58cEw3w@mail.gmail.com>
 <YWPjZv7ClDOE66iI@arighi-desktop>
 <CACT4Y+b4Xmev7uLhASpHnELcteadhaXCBkkD5hO2YNP5M2451g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+b4Xmev7uLhASpHnELcteadhaXCBkkD5hO2YNP5M2451g@mail.gmail.com>
X-Original-Sender: andrea.righi@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=f2Bgj7ok;       spf=pass
 (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122
 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Content-Transfer-Encoding: quoted-printable
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

On Mon, Oct 11, 2021 at 09:19:48AM +0200, Dmitry Vyukov wrote:
> On Mon, 11 Oct 2021 at 09:10, Andrea Righi <andrea.righi@canonical.com> w=
rote:
> >
> > On Mon, Oct 11, 2021 at 08:48:29AM +0200, Marco Elver wrote:
> > > On Mon, 11 Oct 2021 at 08:32, Andrea Righi <andrea.righi@canonical.co=
m> wrote:
> > > > On Mon, Oct 11, 2021 at 08:00:00AM +0200, Marco Elver wrote:
> > > > > On Sun, 10 Oct 2021 at 15:53, Andrea Righi <andrea.righi@canonica=
l.com> wrote:
> > > > > > I can systematically reproduce the following soft lockup w/ the=
 latest
> > > > > > 5.15-rc4 kernel (and all the 5.14, 5.13 and 5.12 kernels that I=
've
> > > > > > tested so far).
> > > > > >
> > > > > > I've found this issue by running systemd autopkgtest (I'm using=
 the
> > > > > > latest systemd in Ubuntu - 248.3-1ubuntu7 - but it should happe=
n with
> > > > > > any recent version of systemd).
> > > > > >
> > > > > > I'm running this test inside a local KVM instance and apparentl=
y systemd
> > > > > > is starting up its own KVM instances to run its tests, so the c=
ontext is
> > > > > > a nested KVM scenario (even if I don't think the nested KVM par=
t really
> > > > > > matters).
> > > > > >
> > > > > > Here's the oops:
> > > > > >
> > > > > > [   36.466565] watchdog: BUG: soft lockup - CPU#0 stuck for 26s=
! [udevadm:333]
> > > > > > [   36.466565] Modules linked in: btrfs blake2b_generic zstd_co=
mpress raid10 raid456 async_raid6_recov async_memcpy async_pq async_xor asy=
nc_tx xor raid6_pq libcrc32c raid1 raid0 multipath linear psmouse floppy
> > > > > > [   36.466565] CPU: 0 PID: 333 Comm: udevadm Not tainted 5.15-r=
c4
> > > > > > [   36.466565] Hardware name: QEMU Standard PC (i440FX + PIIX, =
1996), BIOS 1.14.0-2 04/01/2014
> > > > > [...]
> > > > > >
> > > > > > If I disable CONFIG_KFENCE the soft lockup doesn't happen and s=
ystemd
> > > > > > autotest completes just fine.
> > > > > >
> > > > > > We've decided to disable KFENCE in the latest Ubuntu Impish ker=
nel
> > > > > > (5.13) for now, because of this issue, but I'm still investigat=
ing
> > > > > > trying to better understand the problem.
> > > > > >
> > > > > > Any hint / suggestion?
> > > > >
> > > > > Can you confirm this is not a QEMU TCG instance? There's been a k=
nown
> > > > > issue with it: https://bugs.launchpad.net/qemu/+bug/1920934
> > > >
> > > > It looks like systemd is running qemu-system-x86 without any "accel=
"
> > > > options, so IIUC the instance shouldn't use TCG. Is this a correct
> > > > assumption or is there a better way to check?
> > >
> > > AFAIK, the default is TCG if nothing else is requested. What was the
> > > command line?
> >
> > This is the full command line of what systemd is running:
> >
> >   /bin/qemu-system-x86_64 -smp 4 -net none -m 512M -nographic -vga none=
 -kernel /boot/vmlinuz-5.15-rc4 -drive format=3Draw,cache=3Dunsafe,file=3D/=
var/tmp/systemd-test.sI1nrh/badid.img -initrd /boot/initrd.img-5.15-rc4 -ap=
pend  root=3D/dev/sda1 rw raid=3Dnoautodetect rd.luks=3D0 loglevel=3D2 init=
=3D/lib/systemd/systemd console=3DttyS0 selinux=3D0  SYSTEMD_UNIT_PATH=3D/u=
sr/lib/systemd/tests/testdata/testsuite-14.units:/usr/lib/systemd/tests/tes=
tdata/units: systemd.unit=3Dtestsuite.target systemd.wants=3Dtestsuite-14.s=
ervice systemd.wants=3Dend.service
> >
> > And this is running inside a KVM instance (so a nested KVM scenario).
>=20
> Hi Andrea,
>=20
> I think you need to pass -enable-kvm to make it "nested KVM scenario",
> otherwise it's TCG emulation.

So, IIUC I shouldn't hit the QEMU TCG issue mentioned by Marco, right?

>=20
> You seem to use the default 20s stall timeout. FWIW syzbot uses 160
> secs timeout for TCG emulation to avoid false positive warnings:
> https://github.com/google/syzkaller/blob/838e7e2cd9228583ca33c49a39aea4d8=
63d3e36d/dashboard/config/linux/upstream-arm64-kasan.config#L509
> There are a number of other timeouts raised as well, some as high as
> 420 seconds.

I see, I'll try with these settings and see if I can still hit the soft
lockup messages.

Thanks,
-Andrea

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YWQCknwPcGlOBfUi%40arighi-desktop.
