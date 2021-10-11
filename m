Return-Path: <kasan-dev+bncBDOPF7OU44DRB4GGR6FQMGQEXCLQJYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id ED1C5428774
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 09:10:40 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id x7-20020a056512130700b003fd1a7424a8sf11949735lfu.5
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 00:10:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633936240; cv=pass;
        d=google.com; s=arc-20160816;
        b=xl0kNBO6hqEVi7pP5l02dLm/UYrbf3LJx5LzPDRyTJbHItFCAEj9w7T169cm8JPQP9
         KFJJeyDeCEjtyOmygX9udbkaODipxJ4AgAwPnrMqrJcUq5uA4N2fR41xH8D1nyYF3GCO
         j1i49nvsiXPiwiZxW6BORrzQCsOBMIXIfKT6XvKh1avPMEuNB4Lu/XXM74wrkYDueG2v
         ZhLw9mlUuFjTkRaVcBTRk2+ed/VOfXeN7/v9NxQH2MT4rIMQ45sjkKduLI6OEmYgZD1H
         XTgWXICZC/lCd3kKbo/wBM20rdMa09LWiWPOxKC3h2jLW1XdoaeLKjQGYOqhKeY705vN
         iTpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=mPYgbOrtv76ohY6XAREMFqnqrfOKJT1UpbfeWL987LM=;
        b=XwhLshEsOgEkpsKpV/dzaNSjMCSUPIQYJRHkr7e8cXXBmuZSkxz9LQtdZfRNCUdElW
         XRle0spgCgFErBQ01apt1c7cxw0lbsi6ubr61NEyspBBDuAQCnBeBQ2XrOSnym/04BIf
         X4jALXDWTn8Tf3qsi9PqDLS/TV8oozwGdJPCK3EFXdBOm2ieoH9nczxkxMtubc5Xi8T1
         NaHFEADsP28LLbsqiz5xiAtWkOie2JGUTFs23jLN/qp+9+E/kNo67iVaYO4urT20c5GK
         IOEIst/yCEEoI6UV6P6soXFpZhNM001/xESLBhTWdZCZbc2BYgt0P5GZ74SMOcnJttB1
         OItg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=NRS08aMG;
       spf=pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:content-transfer-encoding
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mPYgbOrtv76ohY6XAREMFqnqrfOKJT1UpbfeWL987LM=;
        b=ZwqUY/XzJpMdRCM+FZZObZwwgmWb9t2KtDW0QselM9x2mtk9MA/n2XvwvexobkB27c
         tlFFvnN0EwkgU0IOr2AwnVLmOfudbveu8FhjfaMgkQUy6/DOzkbAtuESI3DS7ub2rxn5
         jGTxDxfdT/mk0T96oKiMd+ztqm6zJXadcfBChWeZREoADdw6GzLEB08QVaeiBu0x6Ru2
         fQyLikgDG/DBclHmszML8bDpWKLUky70WYwKH0Ryrz5waO+/8Dg8KRD4zWA+j9LufaoK
         VzRYpI1SDSY6eM1rIg2W+GuA3q6886rbGgSGMaRoSSABPXjTZDyXNDgW/2owaecf+cWi
         lDKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mPYgbOrtv76ohY6XAREMFqnqrfOKJT1UpbfeWL987LM=;
        b=F/luqCvPCFBw/OfEK01mDeyouAM2B1piA036fvnud8jt0/E3Q+loXwQiihZxYZ+Q49
         r9iYhNZCkjef2rGZBD4ZCog7bPXzW4zJQybhaDA8+dbS69EeHBPds+ytxronFgy1bIvA
         XZL0+L49tA1rcO0vPF8muj2LyyNKVOU4yxcuRpn0SiL48+wrSr3WqIksC2uh0HVTRP4D
         8CRPJNcqD2VTL8/qh7QiUDukD5K7VbDXVYmphNKB+kX1nVjozBOT4ZK3eARJABKnGeZD
         jG6Y+sECz7HOzhfl+SGiTB2MPefvY24aYoIq+QmAutCnQl8f1g0dH6jVGl9f3ZiGDOHC
         vNcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530dS6sbwMVwbAIlSmoI1RyYkvYFKYMaxLTzoN37Ted/HI8xWdEx
	1bHHqiVVIcNUJLtXtXJI1dk=
X-Google-Smtp-Source: ABdhPJzXOOO1wvhidp3NFO+veEtcP5SUXIwCTMXz+d1gyQifSLyRx7I5jXIBwtbFB/Lql5BqO9azLw==
X-Received: by 2002:a05:6512:3403:: with SMTP id i3mr24350885lfr.533.1633936240497;
        Mon, 11 Oct 2021 00:10:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f14:: with SMTP id y20ls1745350lfa.1.gmail; Mon,
 11 Oct 2021 00:10:39 -0700 (PDT)
X-Received: by 2002:a05:6512:3054:: with SMTP id b20mr26712416lfb.660.1633936239469;
        Mon, 11 Oct 2021 00:10:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633936239; cv=none;
        d=google.com; s=arc-20160816;
        b=XBvxQAIsH3fBhPUb3x9WA9ySRfeLYMcw1R1zKT9biJ+qBwOqJ24LTWDrcNBTPhd8SZ
         5lpbFivr4CI/wNVr6cHD8gW6grZFcle+Ad04Gxwe5dicj6YmL8AzdERWAX9WGQ3SpjHR
         6Ki0cVG/mWsJBATXjQLkl3JhfbPaelSxQQaIeNdCJfXtwCCf5qhtmiMtGMqxuhZWmW7Q
         MQwMa80WQk/X+a3QOcSIi+KMVaJohEB9p79SiBk57bzk1oSOlYKHbehKuOPLREsz7dRP
         tnI1ujUuTFSDNZ9bNObHB2ejsH6ruEdw3nEiyfr3B8QRgVIVM1Be2+qb7OZVRpLGkrKk
         MBGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=h1SUzCf91Jwpb9fhrX0NRvLQL7EyCkzdP0gPLLjD4b8=;
        b=Y5Db6Vb6ajtENw+WVU0SEb3nlK4nyiuE6yWEF4fDo+NUOCJMBmyrmhkaWy8jeWSnS8
         zNpq15RNfcPnv0g3qWS8UfzsLkDET4ES9E35atBQNSZTyJl+lp2b8DM9LSEohUIBxuYI
         g+mn1bnkn/ZAVb03gYsMo2xNG/0IiiBtlLAziFPZUnEBTE50n5ng164maBOOi9cBePi6
         Uu/1ucaGowFfBwDJp6KOoWNA7G3JX3ftJN3BzM2Ls0DNw02gstFDsAbqytCCcwwEA29W
         HJqApwx0VBWl2lZ0zlGJGX/84kKaGDTZ86yYqKApKkJhTsbx71V/MgMyxrXGiTUjmH1+
         BsGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=NRS08aMG;
       spf=pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id g28si389313lfv.3.2021.10.11.00.10.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Oct 2021 00:10:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-ed1-f70.google.com (mail-ed1-f70.google.com [209.85.208.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 8C4FF4000F
	for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 07:10:33 +0000 (UTC)
Received: by mail-ed1-f70.google.com with SMTP id p13-20020a056402044d00b003db3256e4f2so15081141edw.3
        for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 00:10:33 -0700 (PDT)
X-Received: by 2002:a17:906:c009:: with SMTP id e9mr23871353ejz.509.1633936232561;
        Mon, 11 Oct 2021 00:10:32 -0700 (PDT)
X-Received: by 2002:a17:906:c009:: with SMTP id e9mr23871340ejz.509.1633936232329;
        Mon, 11 Oct 2021 00:10:32 -0700 (PDT)
Received: from localhost ([2001:67c:1560:8007::aac:c1b6])
        by smtp.gmail.com with ESMTPSA id y19sm2560185edd.39.2021.10.11.00.10.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Oct 2021 00:10:31 -0700 (PDT)
Date: Mon, 11 Oct 2021 09:10:30 +0200
From: Andrea Righi <andrea.righi@canonical.com>
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: BUG: soft lockup in __kmalloc_node() with KFENCE enabled
Message-ID: <YWPjZv7ClDOE66iI@arighi-desktop>
References: <YWLwUUNuRrO7AxtM@arighi-desktop>
 <CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com>
 <YWPaZSX4WyOwilW+@arighi-desktop>
 <CANpmjNMFFFa=6toZJXqo_9hzv05zoD0aXA4D_K93rfw58cEw3w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMFFFa=6toZJXqo_9hzv05zoD0aXA4D_K93rfw58cEw3w@mail.gmail.com>
X-Original-Sender: andrea.righi@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=NRS08aMG;       spf=pass
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

On Mon, Oct 11, 2021 at 08:48:29AM +0200, Marco Elver wrote:
> On Mon, 11 Oct 2021 at 08:32, Andrea Righi <andrea.righi@canonical.com> w=
rote:
> > On Mon, Oct 11, 2021 at 08:00:00AM +0200, Marco Elver wrote:
> > > On Sun, 10 Oct 2021 at 15:53, Andrea Righi <andrea.righi@canonical.co=
m> wrote:
> > > > I can systematically reproduce the following soft lockup w/ the lat=
est
> > > > 5.15-rc4 kernel (and all the 5.14, 5.13 and 5.12 kernels that I've
> > > > tested so far).
> > > >
> > > > I've found this issue by running systemd autopkgtest (I'm using the
> > > > latest systemd in Ubuntu - 248.3-1ubuntu7 - but it should happen wi=
th
> > > > any recent version of systemd).
> > > >
> > > > I'm running this test inside a local KVM instance and apparently sy=
stemd
> > > > is starting up its own KVM instances to run its tests, so the conte=
xt is
> > > > a nested KVM scenario (even if I don't think the nested KVM part re=
ally
> > > > matters).
> > > >
> > > > Here's the oops:
> > > >
> > > > [   36.466565] watchdog: BUG: soft lockup - CPU#0 stuck for 26s! [u=
devadm:333]
> > > > [   36.466565] Modules linked in: btrfs blake2b_generic zstd_compre=
ss raid10 raid456 async_raid6_recov async_memcpy async_pq async_xor async_t=
x xor raid6_pq libcrc32c raid1 raid0 multipath linear psmouse floppy
> > > > [   36.466565] CPU: 0 PID: 333 Comm: udevadm Not tainted 5.15-rc4
> > > > [   36.466565] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996=
), BIOS 1.14.0-2 04/01/2014
> > > [...]
> > > >
> > > > If I disable CONFIG_KFENCE the soft lockup doesn't happen and syste=
md
> > > > autotest completes just fine.
> > > >
> > > > We've decided to disable KFENCE in the latest Ubuntu Impish kernel
> > > > (5.13) for now, because of this issue, but I'm still investigating
> > > > trying to better understand the problem.
> > > >
> > > > Any hint / suggestion?
> > >
> > > Can you confirm this is not a QEMU TCG instance? There's been a known
> > > issue with it: https://bugs.launchpad.net/qemu/+bug/1920934
> >
> > It looks like systemd is running qemu-system-x86 without any "accel"
> > options, so IIUC the instance shouldn't use TCG. Is this a correct
> > assumption or is there a better way to check?
>=20
> AFAIK, the default is TCG if nothing else is requested. What was the
> command line?

This is the full command line of what systemd is running:

  /bin/qemu-system-x86_64 -smp 4 -net none -m 512M -nographic -vga none -ke=
rnel /boot/vmlinuz-5.15-rc4 -drive format=3Draw,cache=3Dunsafe,file=3D/var/=
tmp/systemd-test.sI1nrh/badid.img -initrd /boot/initrd.img-5.15-rc4 -append=
  root=3D/dev/sda1 rw raid=3Dnoautodetect rd.luks=3D0 loglevel=3D2 init=3D/=
lib/systemd/systemd console=3DttyS0 selinux=3D0  SYSTEMD_UNIT_PATH=3D/usr/l=
ib/systemd/tests/testdata/testsuite-14.units:/usr/lib/systemd/tests/testdat=
a/units: systemd.unit=3Dtestsuite.target systemd.wants=3Dtestsuite-14.servi=
ce systemd.wants=3Dend.service

And this is running inside a KVM instance (so a nested KVM scenario).

-Andrea

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YWPjZv7ClDOE66iI%40arighi-desktop.
