Return-Path: <kasan-dev+bncBCH2XPOBSAERBZ5IVX6QKGQE4YKGT4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id D45422AE6C0
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 04:03:04 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id a6sf622646ybi.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 19:03:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605063783; cv=pass;
        d=google.com; s=arc-20160816;
        b=G3hrJGDFoYYpxgZOV5MfACOseLvTqJVgQpg7vGkf8eB2aG4nR4xhxnHx2Qre5mgeGP
         MhDJfBylQZR0PMs6xfkt/ACPBUdEReVqXK9uchbcHwyM+zPmog9XPl46TF/EWFtY5lUk
         Sq9DsVarInsjutc2UfCnO1r1O8T+DzVNwXpP7/ufof4vW1FxSo+J+w3ujtAcneAxxp62
         1bDX/JEiSusW2KJi3CToIFYwcXNVzgfCeS++bw7kZ+HhPumsbaZtsjYMvAOMw9ED1c0V
         EF6nyMgHX+lfqbjikNDVdz4iyVbBXfGbY4vS4Bec1CiiN+NWZDaCo2yuOwvdnrdvq1ED
         C7wA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=xj22d9BUs8we3DXrtOfxrb456a4w4slG6yMjAGZlCCU=;
        b=YCufG93uNmtXr4ZUPUBlyzK6NtKx8Oco0ArWl/hC06LdttHfq2QUIlQjn2eYl1zI7F
         TF4YycQp89zObc/BmI1wEa6wlGOSZ1weJI0Q+SrQY8eI8fYKcCPjalpo146YrPB/V29h
         4XjDKZ0a8mDCbErB5o3TNaNFRsi69Xt8OrZCfeJWJ7lvVHxqG/AgXXLrEZOt3KNIocvm
         LM/5VUulSUjN3LmrJXpnbi9J3Xwux+u1eAJJCJzGUJCgWFRXaCoEX1zQxBpQ74NEDTWm
         M8DY6Z5wLwD9ahRg7MAKfs69gAJ07iRoiNGiMXc/qBG5qDY34GL16CgG+jrBIvsu/q6I
         EMHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Ynr3M+qI;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xj22d9BUs8we3DXrtOfxrb456a4w4slG6yMjAGZlCCU=;
        b=HTrzXCZCW0F5MYSPQXGu15dLWEaEDB8tSrknhW4i8tzpShujzQJBlz6WyYuNSaX5Pf
         A22IZYgNDHcZIpe9HLaEoHuBHtbNwToOwZrHTPgoCc2dQA+RiuoYmZEkigDdqy2lpADN
         8MXhovhY71o672cqZagTMJp67cyH9R/SZUGyhUiKCq0vZyTvQ1wgCoMNqAknzpYhxDDg
         k1u6aNt1bf1vCgYptStC+a2V0R0/Of9ssH4+pUjeMlf6KBSuBcCD3Bdzrplow5WoVYhu
         HfwAk9Q+CAH507Xv/NgkvtenXG6h5YPBsBprnz3/OJ0hLt9RMDvc9SHxqtoMw3hX4+mw
         1iTg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xj22d9BUs8we3DXrtOfxrb456a4w4slG6yMjAGZlCCU=;
        b=T+k+pA0AKgouIYmxq1pC+zI31wAHv7jnaCUZr4Dwa03m+jr8AyhpzRwAT2m/Ked0wa
         nu/wO9KOyWIWRa9urXVDNlPnk7mepuqwU/cubVLKYT9B6b8wZgULpV045Di/BK0iV38g
         ysZmkchNsThrchJq2yzk+IPM2LFSmK5wxag9WWSx08Uacmz2QrczkUnoWHoL4eqgwqsm
         4ricxG7NbcGdjht0oCSfYf+fZOkmXnt6atcH5F/gmdLewcmvYKdILNX0Y+rRCOKhBE+1
         DItTvMba5GiYIt+PQCUP5xbqrH9QWTV4UDzGmb9NQ1Ve5JJ1jJvat2d3Rq+ax5fYlVEY
         w/TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xj22d9BUs8we3DXrtOfxrb456a4w4slG6yMjAGZlCCU=;
        b=k73u6gKzU9tsyCKAckVtvg2JNn7Phx9wZdTchAvmeLEBSSbnSPHaTcOh4YlZUjSFOV
         lY0PkX4v2854qbEOo99WP/J3ajfRejmKvBezMzrcEg7uvxDSKE3kESobeRy2Pwiy2YA3
         S+Y4sVa8jrarxH5hdoQCO3ivkuvdd73f2guZs8bpcM+MDoU+GDuHyaFrg5541+Ah9maI
         nT7HGkdtPBnfgdZgZPNlyv85EAhzbdJG5SRkB9nKt1/ET7X/sLNPHZww1sP6r0phvarr
         H9fy2Fe9G0QkZqFSB4aTsGJi9ViBkRjynp9JNkcwzbJLryVgE0Gt9vTr2hTtFWEP5lVt
         OTqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530DmIrjwQPHSd2Q4WKTB2lNl9aSsBu0f5u5AhvdRo6qXFAipEKP
	aDrkxcY+jbmy1XQZ3+JAUaU=
X-Google-Smtp-Source: ABdhPJw1EUKvg9BU7/86q4O15qZ5/NqOyWHKuF4XbHJVV5WubLurb03/FVjCSzWIW+xNPXVy3IFo0Q==
X-Received: by 2002:a25:338b:: with SMTP id z133mr33343935ybz.33.1605063783720;
        Tue, 10 Nov 2020 19:03:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:4e3:: with SMTP id w3ls7196784ybs.2.gmail; Tue, 10
 Nov 2020 19:03:02 -0800 (PST)
X-Received: by 2002:a25:a221:: with SMTP id b30mr31019435ybi.130.1605063782857;
        Tue, 10 Nov 2020 19:03:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605063782; cv=none;
        d=google.com; s=arc-20160816;
        b=Cs/qvSgPOsqTq+ZoKVjcnW4Z4IaxpfVCPy07J5/qOafATiONh0Fw2Ll10fNogBk1Ut
         rh4sfKnwhWD8sQJ+mUMyGKUjP2whirGR0fDmN3JW1FCuUYYyuTrYy02xL7Esel9UW0TF
         ujv3yEvSKs/o2sfmD2/QnDNS1AwQetbPpIxRPEhTibvbfujjEJ9ulhFB54HWJDvseMW/
         /a++kvIhJIehQB14gNz9UzOEEwo3u5cVbjvLUxJ+T78R6rcZDmBCWBeEkfMeRZvFKW02
         RRT/nQpzeswGCmwirNntBtqrOWidIYLNFYB6cKNmwRctMSztBtpfpQFrh8SKr9HnMiMQ
         S4TQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=qs8eBcUwotSZEB1k2UTSJFRmFlXEHtZiXE6n92P1lvQ=;
        b=ZGRcnexOcmRx5NxfWdPNqm0lnCdcEh4IJyeR+Gpk16zeV1pkGZhhtAMvwCJCyt7qQA
         t1JGjNTx7GXVWwkSMHovyJK3X4E8zuBOPt3ebgeSoe5tMt174l8xq/mEBB7aDTUAfARG
         dCIpePOcvwjqs5FhBXMlQk/5h61uZkP4aOTuM4cuOpb17tmIaKAZmzSvQwhj7XWBUoIW
         wUAIm7njuFwkFdgPLvLIrEFPfMlQ/XVVa0r3amv9aY0l45nWfubQg5ewU97I/Kz1jmjs
         Ny0dpbZApzP3+Z+J3USEXd3jDrp68YDbnIS7AfDxJhHEtANHNp/9YikXC480YF9fwBho
         rRBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Ynr3M+qI;
       spf=pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id l5si34887ybb.1.2020.11.10.19.03.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 19:03:02 -0800 (PST)
Received-SPF: pass (google.com: domain of mudongliangabcd@gmail.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id o71so258730ybc.2
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 19:03:02 -0800 (PST)
X-Received: by 2002:a25:a065:: with SMTP id x92mr31137795ybh.94.1605063782524;
 Tue, 10 Nov 2020 19:03:02 -0800 (PST)
MIME-Version: 1.0
References: <34d79b2a-1342-4d5e-8ebc-8c4fd5945f2cn@googlegroups.com>
 <CACT4Y+a=MGJSkzWOvCSyK1p5JaHkU7RWABOJj=SMrD+DJacieg@mail.gmail.com> <CAG_fn=XpZOpKoKYO5xVuAFGPGLfrEpOWaR0VtQfmXRexNFsfNQ@mail.gmail.com>
In-Reply-To: <CAG_fn=XpZOpKoKYO5xVuAFGPGLfrEpOWaR0VtQfmXRexNFsfNQ@mail.gmail.com>
From: =?UTF-8?B?5oWV5Yas5Lqu?= <mudongliangabcd@gmail.com>
Date: Wed, 11 Nov 2020 11:02:36 +0800
Message-ID: <CAD-N9QV_YL9dyj-RfHOFOtXrYESqocWddt30-wB5vOE+nmy2sw@mail.gmail.com>
Subject: Re: Continuous KMSAN reports during booting hinders PoC testing
To: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mudongliangabcd@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Ynr3M+qI;       spf=pass
 (google.com: domain of mudongliangabcd@gmail.com designates
 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=mudongliangabcd@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Nov 10, 2020 at 11:16 PM Alexander Potapenko <glider@google.com> wr=
ote:
>
> Hi Dongliang,
>
> Am I understanding right that you were running KMSAN locally?
> Which version were you using for your tests? Note that there've been a
> couple of rebases lately, so things might have changed.
>

Yes, I am running KMSAN and trying to reproduce a KMSAN reporting bug local=
ly.

KMSAN: https://github.com/google/kmsan/commits/f75e4cfea97f67b7530b8b991b30=
05f991f04778
.config: https://syzkaller.appspot.com/text?tag=3DKernelConfig&x=3D60246816=
4ccdc30a
syzkaller: https://github.com/google/syzkaller/commits/63bf051fc1ccc110060b=
e8490f4f5492b0a78766

Let me try the latest kmsan with the same .config and see whether it
works. If so, please let me know which commits fix the mentioned
issues.

> These reports are happening while unwinding the stacks, which KMSAN
> does every now and then.
> I am pretty sure however, that I taught the tool to ignore such
> reports (they make no sense, as stack walking always involves touching
> uninitialized data on the stack).
> So I'd be glad to hear more about the reproduction steps for this
> issue (KMSAN version, kernel config, Clang version, QEMU boot
> parameters)

clang version 12.0.0 (https://github.com/llvm/llvm-project/
c9f69ee7f94cfefc373c3c6cae08e51b11e6d3c2)
Target: x86_64-unknown-linux-gnu
Thread model: posix

I followed the README of kmsan
repo(https://github.com/google/kmsan/blob/master/README.md#how-to-build)
to download clang and build kernel image. And the startvm script is as
follows:

qemu-system-x86_64 \
  -kernel $KERNEL/arch/x86/boot/bzImage \
  -append "console=3DttyS0 root=3D/dev/sda debug earlyprintk=3Dserial slub_=
debug=3DQUZ"\
  -hda $IMAGE/${IMG_NAME}.img \
  -net user,hostfwd=3Dtcp::10021-:22 -net nic \
  -enable-kvm \
  -nographic \
  -m 2G \
  -smp 2 \
  -pidfile vm.pid

> I tried building KMSAN with the latest config for the crash you've
> mentioned, and it booted cleanly.

This is good news. Maybe I can cherry-pick some commits to fix this problem=
.




>
> Alex
>
> On Tue, Nov 10, 2020 at 3:30 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Tue, Nov 10, 2020 at 11:59 AM mudongl...@gmail.com
> > <mudongliangabcd@gmail.com> wrote:
> > >
> > > Hi all,
> > >
> > > when I tried to reproduce the crash(https://syzkaller.appspot.com/bug=
?id=3D3fc6579f907ab3449adb030e8dc65fafdb8e09e4), I found an annoying thing =
during booting of KMSAN-instrumented kernel image - KMSAN keeps reporting s=
everal uninit-value issues. The issues are in the following:
> > >
> > > BUG: KMSAN: uninit-value in unwind_next_frame+0x519/0xf50
> > > BUG: KMSAN: uninit-value in update_stack_state+0xac7/0xae0
> > > BUG: KMSAN: uninit-value in __kernel_text_address+0x1b0/0x330
> > > BUG: KMSAN: uninit-value in arch_stack_walk+0x374/0x3e0
> > > ...
> > >
> > > Even after 20 minutes running, the messages are still printing and QE=
MU is not ready. I wonder if these messages are false positives or not. And=
 how could I successfully enter the VM and test the provided PoC?
> > >
> > > Best regards,
> > > Dongliang Mu
> >
> > +kasan-dev
> > does not seem to be related to syzkaller (to bcc)
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
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAD-N9QV_YL9dyj-RfHOFOtXrYESqocWddt30-wB5vOE%2Bnmy2sw%40mail.gmai=
l.com.
