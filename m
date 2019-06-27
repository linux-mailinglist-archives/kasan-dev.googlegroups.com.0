Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7UV2LUAKGQE664HYGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 1423B57F30
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 11:23:12 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id q11sf1103984pll.22
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 02:23:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561627390; cv=pass;
        d=google.com; s=arc-20160816;
        b=JIyL4ob2R2UZaI+r2d19ZYfi2gLgOeVgLPjfD0EBCkj53HVwud45Cqj+Q7LvxD+twb
         QYCo3JUSC2/x/+AvgWg7+l/U2ZesVjP9GAuCUWOovanv7NL3qF5p2mb6P6qgvtBBdVCk
         RYdlKWOxZ/k+QqRz6EW4FDHMjyQv+toGHQpJpKeKZ9VdzPeNaa+RHWQ0EspxD0IrtFcL
         n6v+pqcBDja87CxfZ01dr4oSmARzqBx8kUxexcA/tb17WDLKXVlGSD3jk/PvMwkaGtzw
         W4Qgr6FEfnQ46BJmtnhRFSgSzjSx4Iaaya5GIkBuqFOJVDYrV4R/GLZGaynUEmTz5FOa
         qxdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Fo9zeqVM19pMF1pNKD/DcPLIsLFcnoUdZEivzCfYDKA=;
        b=B84ML2MGL5n7fQlZOmpk+hPy0sJjx4RpGXwuqF0VeHoAYW43nINeKVybkEdmKx1GUA
         Bpew8eWTDyo2E4DLgXZiKoWel1xlCbsvaKS0zHJYVUt2Z+ZgJzs2wVKoiNKM8j7InBGP
         bNZxni3iSDNCx++X8uRxFzEDcMOtR9wH5czkZMt0wqhMwFXIy+fG3ikGvkOhDrBd41Zn
         tYQ8eGisv369DItv+ihbzIOExARxLVf9uCnoui8zaTXUkFLSjYVmLrxF/Y0F5Rpovcjq
         ybsKLVGr+E7EVM9pmSRVQqmZ0V8bu3xw3g+cWKSDFKqVt4tzgL1BSsxbYKVJk+V8VpSq
         oGVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wqdd9jvq;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::941 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Fo9zeqVM19pMF1pNKD/DcPLIsLFcnoUdZEivzCfYDKA=;
        b=kKRvEHuQbyoo/rfjjJQyTNqzfq8qXqsHPtjWQNF+3p8roLe3zmagRuLV71ikGG9XjC
         lvNmTZYi3vkZNQMR2Gx86OTKQf+09Wyl+s8Xr9hGbR0/iBEYU2jX52SOsW0TnNgXLlMs
         zArnLepL8ZGBmJjr1ZczC0dq6rwiUxiuR9cn4cAovaOP0knTsvC4rnMnVpdHi9SnNqx/
         rcN9+hY8CR9iPqfjQcMqvCl+zK/omIG7/PISIxT4OfMTJVe7aFpGvZSo/JI3Zp5jdNLK
         Q29hEO+RwpaLEEgLpn5M0tCuVuHhcz+dqsIYecWUrpYd49jHhtK38uMP52Fh2m9+GMC5
         utwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Fo9zeqVM19pMF1pNKD/DcPLIsLFcnoUdZEivzCfYDKA=;
        b=AXnOuQZLs3F9Ys958b6hH1HTIciZibUsbyz9sLTpBlvTaTU6rhgdORHNMja0TaqhyQ
         snAcQMayEBDI82homQQVPK3RNHydHZ4AhT0YZpWrcrtL3MY5iGc9CRjRHeL//xRXXYbH
         EGCdOKQHuSunDRRU5F1gBkI6B/MmJ9JzkET0nrJKfEiKZhSjOb2K9HEU9spCCqTUAgIi
         MW3VgHjrdwWKfihBP9nPc83IlMg2feEsujL501wbuGUMwUzgYM8NCXLZ+7lXy6rEHI8E
         tpLP8c5LzZEd/6hSw2gXmgMrLrPu4CtpmX8gtFlOwOJvFLsTJTtvk4wgijCZVk4ZxfHk
         I5+A==
X-Gm-Message-State: APjAAAVvpc8Rs+WzWxj+u5BFe+c2fZ4Y4R7ZEeBT4ZaRHG4yvcyYK4NY
	U7+nhKK34xA0Ju8at+42WYA=
X-Google-Smtp-Source: APXvYqznjp+VTJwQLRx4ig5V0IL4uIFyd0qPSbPuY18MZCbRG8B14rYdI2C5ANj+GLu05JssNQIIxg==
X-Received: by 2002:a63:fb17:: with SMTP id o23mr2799729pgh.362.1561627390500;
        Thu, 27 Jun 2019 02:23:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8d93:: with SMTP id v19ls1505453plo.6.gmail; Thu, 27
 Jun 2019 02:23:10 -0700 (PDT)
X-Received: by 2002:a17:90a:3787:: with SMTP id v7mr4833573pjb.33.1561627390128;
        Thu, 27 Jun 2019 02:23:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561627390; cv=none;
        d=google.com; s=arc-20160816;
        b=rJ4EEVUu/gKI7/RpGYgVrdC4F6b9xc1OJo3gx085wYT9ZhwmIi6OZ6lgS9tlePcGEB
         bz95J3G9k2G8HHkZG7du48z1mowrdTTH/gTchlnkxb41g6RI51LfbyHuIZN3fNre/kew
         ZGyTwrsWJPNyo7eC3Wcb5ZEc0ffk1yQ0h3iAThgeXaFCx3HhzdxuUSgChGJRbRfpTOmM
         A1xfBFwD6fnRwEO6SEp1msJq9kyRCFKXz2o5Rroy7pE4Zhaz0Uex/oE7V9PvdsgUY4TF
         oMR6OepDziCzbeW/MkGa8rgFmoTV1Ec8zJWIOPvSHr1dia4dgT29nH3Y/M5ILDoH4Fxt
         BR/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OdxraAtzWBxXNIcohdO63gAHkiIx+Bi5imYya9cGm/w=;
        b=WpukCrQrqHL1Nnmt1O9Bya8NbE3Ghv8YRYYtoSee+0HC1YZ0PLfNoBfi0ZihUE4jOQ
         kru9CA5zxoN7TGZoKSnbT7nXTP8yVBrBxSny5iK/YtLNxHlHDZHy5xdFGRphFhcOQIWa
         62nH7hxL6thFsksWI0UWe0Ij1ezOC7JiI4p1Fw1DLm5q1IT5VKFscwXbvCNcsqqnEyNM
         TDLrHop8StV0TBu8wfopfl4VsTzAT/pR12Ul5i+nlFr4KP9gW2VEaSATfqAk3P+64xfQ
         CVWTkZPl0frB9BG8c1NDTNxf7rIUcUcQfv9EbbfzjTtvHlWqjz0G11VIatDAqkDBoF29
         m5wQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wqdd9jvq;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::941 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x941.google.com (mail-ua1-x941.google.com. [2607:f8b0:4864:20::941])
        by gmr-mx.google.com with ESMTPS id y13si70416pfl.3.2019.06.27.02.23.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Jun 2019 02:23:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::941 as permitted sender) client-ip=2607:f8b0:4864:20::941;
Received: by mail-ua1-x941.google.com with SMTP id v20so584187uao.3
        for <kasan-dev@googlegroups.com>; Thu, 27 Jun 2019 02:23:10 -0700 (PDT)
X-Received: by 2002:ab0:751a:: with SMTP id m26mr1544241uap.11.1561627388833;
 Thu, 27 Jun 2019 02:23:08 -0700 (PDT)
MIME-Version: 1.0
References: <CADvbK_fCWry5LRV-6yzkgLQXFj0_Qxi46gRrrO-ikOh8SbxQuA@mail.gmail.com>
 <CAG_fn=UoK7qE-x7NHN17GXGNctKoEKZe9rZ7QqP1otnSCfcJDw@mail.gmail.com>
 <CADvbK_fTGwW=HHhXFgatN7QzhNHoFTjmNH7orEdb3N1Gt+1fgg@mail.gmail.com> <CAG_fn=U-OBaRhPN7ab9dFcpchC1AftBN+wJMF+13FOBZORieUg@mail.gmail.com>
In-Reply-To: <CAG_fn=U-OBaRhPN7ab9dFcpchC1AftBN+wJMF+13FOBZORieUg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Jun 2019 11:22:57 +0200
Message-ID: <CAG_fn=W7Z31JjMio++4pWa67BNfZRzwtjnRC-_DQXQch1X=F5w@mail.gmail.com>
Subject: Re: how to start kmsan kernel with qemu
To: Xin Long <lucien.xin@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Dmitriy Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Wqdd9jvq;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::941 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

Actually, your config says:
  "Compiler: clang version 8.0.0 (trunk 343298)"
I think you'll need at least Clang r362410 (mine is r362913)

On Thu, Jun 27, 2019 at 11:20 AM Alexander Potapenko <glider@google.com> wr=
ote:
>
> Hi Xin,
>
> Sorry for the late reply.
> I've built the ToT KMSAN tree using your config and my almost-ToT
> Clang and couldn't reproduce the problem.
> I believe something is wrong with your Clang version, as
> CONFIG_CLANG_VERSION should really be 90000.
> You can run `make V=3D1` to see which Clang version is being invoked -
> make sure it's a fresh one.
>
> HTH,
> Alex
>
> On Fri, Jun 21, 2019 at 10:09 PM Xin Long <lucien.xin@gmail.com> wrote:
> >
> > as attached,
> >
> > It actually came from https://syzkaller.appspot.com/x/.config?x=3D60246=
8164ccdc30a
> > after I built, clang version changed to:
> >
> > CONFIG_CLANG_VERSION=3D80000
> >
> > On Sat, Jun 22, 2019 at 2:06 AM Alexander Potapenko <glider@google.com>=
 wrote:
> > >
> > > Hi Xin,
> > >
> > > Could you please share the config you're using to build the kernel?
> > > I'll take a closer look on Monday when I am back to the office.
> > >
> > > On Fri, 21 Jun 2019, 18:15 Xin Long, <lucien.xin@gmail.com> wrote:
> > >>
> > >> this is my command:
> > >>
> > >> /usr/libexec/qemu-kvm -smp 2 -m 4G -enable-kvm -cpu host \
> > >>     -net nic -net user,hostfwd=3Dtcp::10022-:22 \
> > >>     -kernel /home/kmsan/arch/x86/boot/bzImage -nographic \
> > >>     -device virtio-scsi-pci,id=3Dscsi \
> > >>     -device scsi-hd,bus=3Dscsi.0,drive=3Dd0 \
> > >>     -drive file=3D/root/test/wheezy.img,format=3Draw,if=3Dnone,id=3D=
d0 \
> > >>     -append "root=3D/dev/sda console=3DttyS0 earlyprintk=3Dserial ro=
data=3Dn \
> > >>       oops=3Dpanic panic_on_warn=3D1 panic=3D86400 kvm-intel.nested=
=3D1 \
> > >>       security=3Dapparmor ima_policy=3Dtcb workqueue.watchdog_thresh=
=3D140 \
> > >>       nf-conntrack-ftp.ports=3D20000 nf-conntrack-tftp.ports=3D20000=
 \
> > >>       nf-conntrack-sip.ports=3D20000 nf-conntrack-irc.ports=3D20000 =
\
> > >>       nf-conntrack-sane.ports=3D20000 vivid.n_devs=3D16 \
> > >>       vivid.multiplanar=3D1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2 \
> > >>       spec_store_bypass_disable=3Dprctl nopcid"
> > >>
> > >> the commit is on:
> > >> commit f75e4cfea97f67b7530b8b991b3005f991f04778 (HEAD)
> > >> Author: Alexander Potapenko <glider@google.com>
> > >> Date:   Wed May 22 12:30:13 2019 +0200
> > >>
> > >>     kmsan: use kmsan_handle_urb() in urb.c
> > >>
> > >> and when starting, it shows:
> > >> [    0.561925][    T0] Kernel command line: root=3D/dev/sda
> > >> console=3DttyS0 earlyprintk=3Dserial rodata=3Dn       oops=3Dpanic
> > >> panic_on_warn=3D1 panic=3D86400 kvm-intel.nested=3D1       security=
=3Dad
> > >> [    0.707792][    T0] Memory: 3087328K/4193776K available (219164K
> > >> kernel code, 7059K rwdata, 11712K rodata, 5064K init, 11904K bss,
> > >> 1106448K reserved, 0K cma-reserved)
> > >> [    0.710935][    T0] SLUB: HWalign=3D64, Order=3D0-3, MinObjects=
=3D0,
> > >> CPUs=3D2, Nodes=3D1
> > >> [    0.711953][    T0] Starting KernelMemorySanitizer
> > >> [    0.712563][    T0]
> > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > >> [    0.713657][    T0] BUG: KMSAN: uninit-value in mutex_lock+0xd1/0=
xe0
> > >> [    0.714570][    T0] CPU: 0 PID: 0 Comm: swapper Not tainted 5.1.0=
 #5
> > >> [    0.715417][    T0] Hardware name: Red Hat KVM, BIOS
> > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> > >> [    0.716659][    T0] Call Trace:
> > >> [    0.717127][    T0]  dump_stack+0x134/0x190
> > >> [    0.717727][    T0]  kmsan_report+0x131/0x2a0
> > >> [    0.718347][    T0]  __msan_warning+0x7a/0xf0
> > >> [    0.718952][    T0]  mutex_lock+0xd1/0xe0
> > >> [    0.719478][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0xd20
> > >> [    0.720260][    T0]  ? vprintk_func+0x6b5/0x8a0
> > >> [    0.720926][    T0]  ? rb_get_reader_page+0x1140/0x1140
> > >> [    0.721632][    T0]  __cpuhp_setup_state+0x181/0x2e0
> > >> [    0.722374][    T0]  ? rb_get_reader_page+0x1140/0x1140
> > >> [    0.723115][    T0]  tracer_alloc_buffers+0x16b/0xb96
> > >> [    0.723846][    T0]  early_trace_init+0x193/0x28f
> > >> [    0.724501][    T0]  start_kernel+0x497/0xb38
> > >> [    0.725134][    T0]  x86_64_start_reservations+0x19/0x2f
> > >> [    0.725871][    T0]  x86_64_start_kernel+0x84/0x87
> > >> [    0.726538][    T0]  secondary_startup_64+0xa4/0xb0
> > >> [    0.727173][    T0]
> > >> [    0.727454][    T0] Local variable description:
> > >> ----success.i.i.i.i@mutex_lock
> > >> [    0.728379][    T0] Variable was created at:
> > >> [    0.728977][    T0]  mutex_lock+0x48/0xe0
> > >> [    0.729536][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0xd20
> > >> [    0.730323][    T0]
> > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > >> [    0.731364][    T0] Disabling lock debugging due to kernel taint
> > >> [    0.732169][    T0] Kernel panic - not syncing: panic_on_warn set=
 ...
> > >> [    0.733047][    T0] CPU: 0 PID: 0 Comm: swapper Tainted: G    B
> > >>         5.1.0 #5
> > >> [    0.734080][    T0] Hardware name: Red Hat KVM, BIOS
> > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> > >> [    0.735319][    T0] Call Trace:
> > >> [    0.735735][    T0]  dump_stack+0x134/0x190
> > >> [    0.736308][    T0]  panic+0x3ec/0xb3b
> > >> [    0.736826][    T0]  kmsan_report+0x29a/0x2a0
> > >> [    0.737417][    T0]  __msan_warning+0x7a/0xf0
> > >> [    0.737973][    T0]  mutex_lock+0xd1/0xe0
> > >> [    0.738527][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0xd20
> > >> [    0.739342][    T0]  ? vprintk_func+0x6b5/0x8a0
> > >> [    0.739972][    T0]  ? rb_get_reader_page+0x1140/0x1140
> > >> [    0.740695][    T0]  __cpuhp_setup_state+0x181/0x2e0
> > >> [    0.741412][    T0]  ? rb_get_reader_page+0x1140/0x1140
> > >> [    0.742160][    T0]  tracer_alloc_buffers+0x16b/0xb96
> > >> [    0.742866][    T0]  early_trace_init+0x193/0x28f
> > >> [    0.743512][    T0]  start_kernel+0x497/0xb38
> > >> [    0.744128][    T0]  x86_64_start_reservations+0x19/0x2f
> > >> [    0.744863][    T0]  x86_64_start_kernel+0x84/0x87
> > >> [    0.745534][    T0]  secondary_startup_64+0xa4/0xb0
> > >> [    0.746290][    T0] Rebooting in 86400 seconds..
> > >>
> > >> when I set "panic_on_warn=3D0", it foods the console with:
> > >> ...
> > >> [   25.206759][    C0] Variable was created at:
> > >> [   25.207302][    C0]  vprintk_emit+0xf4/0x800
> > >> [   25.207844][    C0]  vprintk_deferred+0x90/0xed
> > >> [   25.208404][    C0]
> > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > >> [   25.209763][    C0]  x86_64_start_reservations+0x19/0x2f
> > >> [   25.209769][    C0]
> > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > >> [   25.211408][    C0] BUG: KMSAN: uninit-value in vprintk_emit+0x44=
3/0x800
> > >> [   25.212237][    C0] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G    B
> > >>           5.1.0 #5
> > >> [   25.213206][    C0] Hardware name: Red Hat KVM, BIOS
> > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> > >> [   25.214326][    C0] Call Trace:
> > >> [   25.214725][    C0]  <IRQ>
> > >> [   25.215080][    C0]  dump_stack+0x134/0x190
> > >> [   25.215624][    C0]  kmsan_report+0x131/0x2a0
> > >> [   25.216204][    C0]  __msan_warning+0x7a/0xf0
> > >> [   25.216771][    C0]  vprintk_emit+0x443/0x800
> > >> [   25.217334][    C0]  ? __msan_metadata_ptr_for_store_1+0x13/0x20
> > >> [   25.218127][    C0]  vprintk_deferred+0x90/0xed
> > >> [   25.218714][    C0]  printk_deferred+0x186/0x1d3
> > >> [   25.219353][    C0]  __printk_safe_flush+0x72e/0xc00
> > >> [   25.220006][    C0]  ? printk_safe_flush+0x1e0/0x1e0
> > >> [   25.220635][    C0]  irq_work_run+0x1ad/0x5c0
> > >> [   25.221210][    C0]  ? flat_init_apic_ldr+0x170/0x170
> > >> [   25.221851][    C0]  smp_irq_work_interrupt+0x237/0x3e0
> > >> [   25.222520][    C0]  irq_work_interrupt+0x2e/0x40
> > >> [   25.223110][    C0]  </IRQ>
> > >> [   25.223475][    C0] RIP: 0010:kmem_cache_init_late+0x0/0xb
> > >> [   25.224164][    C0] Code: d4 e8 5d dd 2e f2 e9 74 fe ff ff 48 89 =
d3
> > >> 8b 7d d4 e8 cd d7 2e f2 89 c0 48 89 c1 48 c1 e1 20 48 09 c1 48 89 0b
> > >> e9 81 fe ff ff <55> 48 89 e5 e8 20 de 2e1
> > >> [   25.226526][    C0] RSP: 0000:ffffffff8f40feb8 EFLAGS: 00000246
> > >> ORIG_RAX: ffffffffffffff09
> > >> [   25.227548][    C0] RAX: ffff88813f995785 RBX: 0000000000000000
> > >> RCX: 0000000000000000
> > >> [   25.228511][    C0] RDX: ffff88813f2b0784 RSI: 0000160000000000
> > >> RDI: 0000000000000785
> > >> [   25.229473][    C0] RBP: ffffffff8f40ff20 R08: 000000000fac3785
> > >> R09: 0000778000000001
> > >> [   25.230440][    C0] R10: ffffd0ffffffffff R11: 0000100000000000
> > >> R12: 0000000000000000
> > >> [   25.231403][    C0] R13: 0000000000000000 R14: ffffffff8fb8cfd0
> > >> R15: 0000000000000000
> > >> [   25.232407][    C0]  ? start_kernel+0x5d8/0xb38
> > >> [   25.233003][    C0]  x86_64_start_reservations+0x19/0x2f
> > >> [   25.233670][    C0]  x86_64_start_kernel+0x84/0x87
> > >> [   25.234314][    C0]  secondary_startup_64+0xa4/0xb0
> > >> [   25.234949][    C0]
> > >> [   25.235231][    C0] Local variable description: ----flags.i.i.i@v=
printk_emit
> > >> [   25.236101][    C0] Variable was created at:
> > >> [   25.236643][    C0]  vprintk_emit+0xf4/0x800
> > >> [   25.237188][    C0]  vprintk_deferred+0x90/0xed
> > >> [   25.237752][    C0]
> > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > >> [   25.239117][    C0]  x86_64_start_kernel+0x84/0x87
> > >> [   25.239123][    C0]
> > >> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > >> [   25.240704][    C0] BUG: KMSAN: uninit-value in vprintk_emit+0x44=
3/0x800
> > >> [   25.241540][    C0] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G    B
> > >>           5.1.0 #5
> > >> [   25.242512][    C0] Hardware name: Red Hat KVM, BIOS
> > >> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> > >> [   25.243635][    C0] Call Trace:
> > >> [   25.244038][    C0]  <IRQ>
> > >> [   25.244390][    C0]  dump_stack+0x134/0x190
> > >> [   25.244940][    C0]  kmsan_report+0x131/0x2a0
> > >> [   25.245515][    C0]  __msan_warning+0x7a/0xf0
> > >> [   25.246082][    C0]  vprintk_emit+0x443/0x800
> > >> [   25.246638][    C0]  ? __msan_metadata_ptr_for_store_1+0x13/0x20
> > >> [   25.247430][    C0]  vprintk_deferred+0x90/0xed
> > >> [   25.248018][    C0]  printk_deferred+0x186/0x1d3
> > >> [   25.248650][    C0]  __printk_safe_flush+0x72e/0xc00
> > >> [   25.249320][    C0]  ? printk_safe_flush+0x1e0/0x1e0
> > >> [   25.249949][    C0]  irq_work_run+0x1ad/0x5c0
> > >> [   25.250524][    C0]  ? flat_init_apic_ldr+0x170/0x170
> > >> [   25.251167][    C0]  smp_irq_work_interrupt+0x237/0x3e0
> > >> [   25.251837][    C0]  irq_work_interrupt+0x2e/0x40
> > >> [   25.252424][    C0]  </IRQ>
> > >> ....
> > >>
> > >>
> > >> I couldn't even log in.
> > >>
> > >> how should I use qemu with wheezy.img to start a kmsan kernel?
> > >>
> > >> Thanks.
>
>
>
> --
> Alexander Potapenko
> Software Engineer
>
> Google Germany GmbH
> Erika-Mann-Stra=C3=9Fe, 33
> 80636 M=C3=BCnchen
>
> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
> Registergericht und -nummer: Hamburg, HRB 86891
> Sitz der Gesellschaft: Hamburg



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DW7Z31JjMio%2B%2B4pWa67BNfZRzwtjnRC-_DQXQch1X%3DF5w%40mai=
l.gmail.com.
For more options, visit https://groups.google.com/d/optout.
