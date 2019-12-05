Return-Path: <kasan-dev+bncBCMIZB7QWENRB5FRUPXQKGQEEMG6DMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 404E9113F2C
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 11:16:21 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id j1sf1808559qkk.17
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 02:16:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575540980; cv=pass;
        d=google.com; s=arc-20160816;
        b=lvGp07G0VFwvxLmbXO9vwj78xpAe/fzhpBwcjAYBXptTLD9Id15vXwLAFw3t1GzQCL
         JB8w25Sm94Avaskw0Zm5o/fOD0PuEMKl8uUSVQwiHFJB4xvrqCFYE9dV8qNzwAB8qSWD
         3d61hzXdugvmUxMBKtmSgujmqQU1rfV9buixjxq3YZdVdw2J36YwgJhW8gimwCLnRpwG
         VXki5EGN5P5bC21T6Ge0Xh7hTvqbr/vw/s4+KlsXSDfk4j2Y2kzjOwBCTM7zeHsx++cU
         avFR6P8h5vlKPHjcnxYM8FvaLegpGeP/bWTOQU6ER+oJxDvSGLkd5UsklAM5YazaVTgZ
         kULw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=X5I9UMLY3C3S9rv8xftVkEgw/xSFtaR2x0G9G4LpHD8=;
        b=aAHzFU47sL5ZmHrSnLgbn1iwHAqkqmsVVGkDIi6LQ0/FAT1hwtNh85XuHlaJiCkTzq
         xJaJWA7TqKc16x9srfQXgbyLK8OLg/EcEt2dn3MYJlOtqfEDfRGEZLVpXDQknvHOJT+6
         esVowjb4ZaeLrAnhLb5SQVLmzf3zPBZtvD85r5pNQ+U5BjE1vw3mYbP97zpzSI1L/oPW
         Q/j0NDp3BmzeDLs7GbB3iYYfVypTSvo4PVG6kVC4Z6aO7fOga+5LyF/MK39aGCl+jrf6
         Zbo+WPsVC2/6nheoxzSDvVmocWruYIuXO/a+4P54+C/nv/A2DNCZTn4MxFgtM6Mz/Oyp
         ZAgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lCZ22bHz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X5I9UMLY3C3S9rv8xftVkEgw/xSFtaR2x0G9G4LpHD8=;
        b=HbdHtA7TWO8pbMpBjr3yRhfHbPWDFujkxEdQhzQ4GwdwdKnRagVDrtC/g0MXVg2uNa
         crqfmrSI/7g0EGNXHSRtxYXdPWMpcxwtrVlvYWxnuLtXjURHDMDxeMzU1iGIewWA9Thm
         na1ygpgZf6nyUFBoKFthUYseqyiSFKCYS0VVdxI7rLaxCwv9BmguFhrIIVFs1IiKtJw4
         1HnFneFeGtXIqbnqDnljiNB/a6fh/7K3dcDKPJh324vMBj0mmu2dlxGLtuO7vi5Sxhjk
         nF4rxM0nAHBq/xg3lrG2n9IDA4qIyFojKdxX0szjwNkqAUhrK1H0uSw/XCZPr4hpssce
         GHFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X5I9UMLY3C3S9rv8xftVkEgw/xSFtaR2x0G9G4LpHD8=;
        b=pKUQ+cB+hlpcb/wRVAlGGnaxHByCgblfZmOQqD5flANUZC1xVBd0oAJnrjfVPIkZ3Q
         1zYDtrTTOpOSowrtgHRBd5KWps+/7ZEFe+eQyiwHx/Xs6+xDp8WPxbF45qZznKAlbyPg
         qbjNIqGVfHNaY2kdTW13VI2A6ppvM0s6QPVeP4RvsU3kYGUf1Fc0RXXggG4x/CXGo938
         Y9C56I0f3ApKU6g+z1/ysXc7g9aE/0cfQnuq0DHjzhqrt1mNmLtTlCAzgn4kja+7WMJ0
         8ErYXFD1Y+4ekOJky26wEHzPidLdLt5W6n5NgILYJLaRdlX/T5SXEeB7lDfFhCuQaCra
         QRWw==
X-Gm-Message-State: APjAAAXjOraxX0f/tQmDetX3YxvYuD7tWTMDs9+ZsxTIfwusDU2+vVS3
	i/my6kpAv+nFALFw1LURetY=
X-Google-Smtp-Source: APXvYqwRYNVui42UrTXX5BgeHDH0XkEd2ZakHR1MMPO+NSivAghNSDOeG+FYa+ojFd3o9yezd7OxDA==
X-Received: by 2002:ae9:e901:: with SMTP id x1mr7043234qkf.117.1575540980160;
        Thu, 05 Dec 2019 02:16:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:49b1:: with SMTP id u17ls445694qvx.14.gmail; Thu, 05 Dec
 2019 02:16:19 -0800 (PST)
X-Received: by 2002:a05:6214:1150:: with SMTP id b16mr6770325qvt.71.1575540979676;
        Thu, 05 Dec 2019 02:16:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575540979; cv=none;
        d=google.com; s=arc-20160816;
        b=ldH0kY8g3eXfuqul1Qb+Sb5PYWc1XN8tkF9/f4ZcLKxR4emZJibGiSxjcTudDWtRqc
         Z9/TnxEvzVYVGaMgl5Ci69h14T44zkaLJkk6zqgfb32NfAL+l3BxipzbFBNfcXZNhmWS
         6AkdZfXJMn+Dc/0ERs9eDya3ABcRusXP85Qv0CfA79fwE9hvEq6q33G9AEwrDYRNNYDQ
         2D6CGtrQDTCVSf+TlrcZjzzFdD7erBJfJ1cTDCumVo1XyIXTkYpu5vYHxW/Zmfl+pI3P
         tOZlTkFzGb9MGbkN8XIyDbj3Ts8sEV6aDF0K6j+lqYuqVxyFtBYuv6HFs70cTo+73JBK
         jmqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5K3iSfguK9BgLZmuNv+P78rfwEAvYBwmmPVubK0s/pU=;
        b=taUuHXb7CK+Nb7NCO/todIC0sJhcqTswjub6E/rxZIZb7Y9iXeVyAb4qX5VOsBVHti
         ShB6hvEguXO1IZ5Mf7MCQLnFcpmJAyfuDGXf+CvXoP5o997Ey/07TgKHLQwTEjtRqCnu
         FkIH3Kgeje5zzorJ0WQyQ2sI4/h4hKV4LiO2B/ad8Ch5PkMoqZqMTVzc/E1CYVwxahMd
         I1VATusoP+pIu92aDjMsULQQiVJIeo2a5vj758FN8VR1jRwO/0NW+upyLw9I03VmHpag
         FKRKPjc9yv+3Tb3IP2IroBGmfAp5SvNN2yLhJ03fAmpimcmCYPdPqTJ7cggSKa7yeY6Q
         8Qzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lCZ22bHz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id g23si541024qki.4.2019.12.05.02.16.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Dec 2019 02:16:19 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id g1so3018223qtj.6
        for <kasan-dev@googlegroups.com>; Thu, 05 Dec 2019 02:16:19 -0800 (PST)
X-Received: by 2002:ac8:2489:: with SMTP id s9mr6779647qts.257.1575540979068;
 Thu, 05 Dec 2019 02:16:19 -0800 (PST)
MIME-Version: 1.0
References: <0000000000003e640e0598e7abc3@google.com> <41c082f5-5d22-d398-3bdd-3f4bf69d7ea3@redhat.com>
In-Reply-To: <41c082f5-5d22-d398-3bdd-3f4bf69d7ea3@redhat.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Dec 2019 11:16:08 +0100
Message-ID: <CACT4Y+bCHOCLYF+TW062n8+tqfK9vizaRvyjUXNPdneciq0Ahg@mail.gmail.com>
Subject: Re: KASAN: slab-out-of-bounds Read in fbcon_get_font
To: Paolo Bonzini <pbonzini@redhat.com>
Cc: syzbot <syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>, Daniel Thompson <daniel.thompson@linaro.org>, 
	Daniel Vetter <daniel.vetter@ffwll.ch>, DRI <dri-devel@lists.freedesktop.org>, 
	ghalat@redhat.com, Gleb Natapov <gleb@kernel.org>, gwshan@linux.vnet.ibm.com, 
	"H. Peter Anvin" <hpa@zytor.com>, James Morris <jmorris@namei.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, KVM list <kvm@vger.kernel.org>, 
	Linux Fbdev development list <linux-fbdev@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-security-module <linux-security-module@vger.kernel.org>, 
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	Russell Currey <ruscur@russell.cc>, Sam Ravnborg <sam@ravnborg.org>, 
	"Serge E. Hallyn" <serge@hallyn.com>, stewart@linux.vnet.ibm.com, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lCZ22bHz;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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

On Thu, Dec 5, 2019 at 11:13 AM Paolo Bonzini <pbonzini@redhat.com> wrote:
>
> On 04/12/19 22:41, syzbot wrote:
> > syzbot has bisected this bug to:
> >
> > commit 2de50e9674fc4ca3c6174b04477f69eb26b4ee31
> > Author: Russell Currey <ruscur@russell.cc>
> > Date:   Mon Feb 8 04:08:20 2016 +0000
> >
> >     powerpc/powernv: Remove support for p5ioc2
> >
> > bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=127a042ae00000
> > start commit:   76bb8b05 Merge tag 'kbuild-v5.5' of
> > git://git.kernel.org/p..
> > git tree:       upstream
> > final crash:    https://syzkaller.appspot.com/x/report.txt?x=117a042ae00000
> > console output: https://syzkaller.appspot.com/x/log.txt?x=167a042ae00000
> > kernel config:  https://syzkaller.appspot.com/x/.config?x=dd226651cb0f364b
> > dashboard link:
> > https://syzkaller.appspot.com/bug?extid=4455ca3b3291de891abc
> > syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=11181edae00000
> > C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=105cbb7ae00000
> >
> > Reported-by: syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com
> > Fixes: 2de50e9674fc ("powerpc/powernv: Remove support for p5ioc2")
> >
> > For information about bisection process see:
> > https://goo.gl/tpsmEJ#bisection
> >
>
> Why is everybody being CC'd, even if the bug has nothing to do with the
> person's subsystem?

The To list should be intersection of 2 groups of emails: result of
get_maintainers.pl on the file identified as culprit in the crash
message + emails extracted from the bisected to commit.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbCHOCLYF%2BTW062n8%2BtqfK9vizaRvyjUXNPdneciq0Ahg%40mail.gmail.com.
