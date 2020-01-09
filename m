Return-Path: <kasan-dev+bncBCMIZB7QWENRBV4F3TYAKGQEYYJSLHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id AE92013572C
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 11:39:20 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id n130sf3073607oib.5
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 02:39:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578566359; cv=pass;
        d=google.com; s=arc-20160816;
        b=xbTmnAWq2SHdryFlozuIvxb5hr8NLXP9vlCaYuwLsixkZIG5IgL+JSmJwPbbXqyO+3
         p252xKRl9/XBXZfFXdbogRp2PvAccWMsUV2DL1eakWtvqrIZIZkz5pHf9v6Q7XY4DeGW
         cp2gulMk6cVbcIoXxqhRliaMxF2U6mWh+ttpOA2Gx8NXxU+BRBWoNJVFuSjW9sLMQ2nD
         Q0p19Gm8wcptxgWnpC8J3tIZAgmoo/L0xBpbTl+u3B5w6RfZ5gGu9wvTLyr2PIdMU1QF
         iPzW5GecVGBf+cnCMMIbj+HavDfi/CU7B3QihpkKmpzB9WJpEIgZ/s2a5TbTEWZQ+dt+
         eazA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xPAWahBF4AY6PQAxxAy5h8nT6iAhYoCTgXDOO2aZIPU=;
        b=ipwHRn6ur52ul6/toDr0vuJKnhGTgTcjJRSob7Og8Q+KQX6NLP1uzNsTxZYdSlKmbN
         RgdJqzQoKOGtzTgr7o8rX/B+UUSJfwB3FXKskq/hCMEPGv6+7pjvqRtRKrRdPuZ2lrnW
         SKwd3EuUqH5J0YKkU4+Y0VZprWnHAAqqBJq8xxjTe96l5zcebP5BGlT3b+NTQqfg+LAc
         NNkaBHbLcb1Vufnnpgj/SlBKZSZhBrDwLz7KMwXjPLuUeOD7bV3gklklDsO9JT3wlnTN
         Vyg8bHccnl27ZnVhOW6NifXQKXnbZQgFWR1G0hjdvUiayOvXnq8Wc00j6gjpjfTrUIor
         q75w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q1QWcwrC;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xPAWahBF4AY6PQAxxAy5h8nT6iAhYoCTgXDOO2aZIPU=;
        b=RwRQUKq3OUgOk0CJPaaox6gNC3k8dh118NsLcxxlZekSck/vYBizcvBiF+0xVAXz9/
         KuzvW+hRT9/uXLqNcrkInlImaFDCiqmJN1GqHwCpN05vWGwc4Zd9c/uc5sfV4Mfhr7ki
         SeQEr7mpLRSQ53vfTrmHuZrFavsh0e0s8gIg7FB3FsI+w34qL8Pc8rVBQrfobAXjhAyY
         xDOHJVLtg1576ZDo33m5ZOr6DUEV3i7EYcFzwNP/2LAGEb8qr8LTe31m69iKtkxCh9s8
         giNTmndRWhca9t1qv8dj87KpMWB31kOatRR2VJWokbb9UJvmN7UC+W4WcXwYLOTsudrt
         B/hA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xPAWahBF4AY6PQAxxAy5h8nT6iAhYoCTgXDOO2aZIPU=;
        b=bAo8eUWZAuL/tGvohkiFPSAPGxOqy+/mMxsqpi4gDVN3rLQcY4C/mpyYXwrEAHYiJc
         Y2fp1B+AVtNLOVT+40frHdGXh+bOGOhEUKDhlsWMOUSEx1rVfIsDI21n6nGXthnpQBO9
         T1qFGP45Aj1Ps6v/szLGMGeV08X2D2+wneiaw/jfIciEht+bVcBAjC8AKi/S6AFd5H4L
         X6KYTGCUia4qSWDwS1PofNfgxrqGM7p1VgJ+UJIAjujdsOTdoTVgn9VDpzzoHjNpBETM
         eHT2AoFLnhko6Rfsgk/MiTnCkclXkrc8keFI+l0uRW9GaBMOxLcMcOqyxLVbJKhWATPR
         fqAg==
X-Gm-Message-State: APjAAAXPg9peFWfDu0AiZqLGEQfEd2pc9PmhR4ihIb00/09B6qitHcjn
	rKsZbZg4xSW5Uxck0PEfoq0=
X-Google-Smtp-Source: APXvYqyxfS9FfArE7ZcS/W4V6NB8uXNynSHTVMewmtGRTF0oGZKMBPXi1Q7cZiU7/Vyc+vZAbUyZxg==
X-Received: by 2002:aca:a849:: with SMTP id r70mr2680762oie.28.1578566359357;
        Thu, 09 Jan 2020 02:39:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:714f:: with SMTP id y15ls315471otj.14.gmail; Thu, 09 Jan
 2020 02:39:19 -0800 (PST)
X-Received: by 2002:a9d:3e16:: with SMTP id a22mr8320758otd.259.1578566358966;
        Thu, 09 Jan 2020 02:39:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578566358; cv=none;
        d=google.com; s=arc-20160816;
        b=FKOaiGundj6d7e1/9UnE+E17e9r6VvMjfdZZmrxKm5lnbBA6PA3MieO4kC11dwRbB3
         EkW+a7C0mg0G3GBfFUlK14XA8ora0A3flJj2MbYk/Xjf9zXoZUTy0bsmtV0FEOm2+F/b
         uhuLIc4lQNMylE4b+vVwVKwQjbuJIr5O+Z0HH+8gOcvXLEgejlDXULGt/Nmxu9JctXCW
         mjZmsKCNVPfwUBH0yz11dN348wEdktGw2wJ6pGFmymgG9b6qp24+QJlVyRYFwdOhQQYu
         ZYDKr2GUbgFXVkkkzkIexy6gWFVKeAANzEzrk0Vb+TNugii+P9CblaJJrele+FenFVz7
         ZolQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9xn1JyxwI+0XYf3lA9v7eIZLbewUvsaljCIr7fZGL9k=;
        b=wp3bbD55t1WMQYfP/VCLpalbNrsshEyGVwZYx4IdiIvRtnNDrIz0tXh+hF/0cPE0xn
         62L4RjyAV+VvdPruFJythP7eBtoS9FHT9txpf2PNk02I+XCtqpp3L3bEEv/Yi6dSUqIb
         IPaZEG/4ZIEUmcJumvCxlUOhaNg+jveC/Tn6OqqiJDtpmRclAk6VuJWsrwAhjzVUJUHr
         m86hIHZeKnaeE0xzAtj5j3TC7N2NI986ZMj7WExl2nWXvfq8QJX7BFTspmq6VG7xZVbF
         bOyie0hbUtdvIijpSNV89MtasnQHkbXaw2N6A0754YyY36qeID1PJiTUoSVQWoGf/rwh
         KS8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q1QWcwrC;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id q188si307473oic.5.2020.01.09.02.39.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jan 2020 02:39:18 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id d71so5538468qkc.0
        for <kasan-dev@googlegroups.com>; Thu, 09 Jan 2020 02:39:18 -0800 (PST)
X-Received: by 2002:a37:e312:: with SMTP id y18mr8998740qki.250.1578566357984;
 Thu, 09 Jan 2020 02:39:17 -0800 (PST)
MIME-Version: 1.0
References: <00000000000036decf0598c8762e@google.com> <CACT4Y+YVMUxeLcFMray9n0+cXbVibj5X347LZr8YgvjN5nC8pw@mail.gmail.com>
 <CACT4Y+asdED7tYv462Ui2OhQVKXVUnC+=fumXR3qM1A4d6AvOQ@mail.gmail.com>
 <f7758e0a-a157-56a2-287e-3d4452d72e00@schaufler-ca.com> <87a787ekd0.fsf@dja-thinkpad.axtens.net>
 <87h81zax74.fsf@dja-thinkpad.axtens.net> <CACT4Y+b+Vx1FeCmhMAYq-g3ObHdMPOsWxouyXXUr7S5OjNiVGQ@mail.gmail.com>
 <0b60c93e-a967-ecac-07e7-67aea1a0208e@I-love.SAKURA.ne.jp>
 <6d009462-74d9-96e9-ab3f-396842a58011@schaufler-ca.com> <CACT4Y+bURugCpLm5TG37-7voFEeEoXo_Gb=3sy75_RELZotXHw@mail.gmail.com>
 <CACT4Y+avizeUd=nY2w1B_LbEC1cP5prBfpnANYaxhgS_fcL6ag@mail.gmail.com>
 <CACT4Y+Z3GCncV3G1=36NmDRX_XOZsdoRJ3UshZoornbSRSN28w@mail.gmail.com> <CACT4Y+ZyVi=ow+VXA9PaWEVE8qKj8_AKzeFsNdsmiSR9iL3FOw@mail.gmail.com>
In-Reply-To: <CACT4Y+ZyVi=ow+VXA9PaWEVE8qKj8_AKzeFsNdsmiSR9iL3FOw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jan 2020 11:39:06 +0100
Message-ID: <CACT4Y+axj5M4p=mZkFb1MyBw0MK1c6nWb-fKQcYSnYB8n1Cb8Q@mail.gmail.com>
Subject: Re: INFO: rcu detected stall in sys_kill
To: Casey Schaufler <casey@schaufler-ca.com>, Daniel Axtens <dja@axtens.net>, 
	Alexander Potapenko <glider@google.com>, clang-built-linux <clang-built-linux@googlegroups.com>
Cc: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	syzbot <syzbot+de8d933e7d153aa0c1bb@syzkaller.appspotmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=q1QWcwrC;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Thu, Jan 9, 2020 at 11:05 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > > On 1/8/2020 2:25 AM, Tetsuo Handa wrote:
> > > > > > On 2020/01/08 15:20, Dmitry Vyukov wrote:
> > > > > >> I temporarily re-enabled smack instance and it produced another 50
> > > > > >> stalls all over the kernel, and now keeps spewing a dozen every hour.
> > > > >
> > > > > Do I have to be using clang to test this? I'm setting up to work on this,
> > > > > and don't want to waste time using my current tool chain if the problem
> > > > > is clang specific.
> > > >
> > > > Humm, interesting. Initially I was going to say that most likely it's
> > > > not clang-related. Bug smack instance is actually the only one that
> > > > uses clang as well (except for KMSAN of course). So maybe it's indeed
> > > > clang-related rather than smack-related. Let me try to build a kernel
> > > > with clang.
> > >
> > > +clang-built-linux, glider
> > >
> > > [clang-built linux is severe broken since early Dec]
> > >
> > > Building kernel with clang I can immediately reproduce this locally:
> > >
> > > $ syz-manager
> > > 2020/01/09 09:27:15 loading corpus...
> > > 2020/01/09 09:27:17 serving http on http://0.0.0.0:50001
> > > 2020/01/09 09:27:17 serving rpc on tcp://[::]:45851
> > > 2020/01/09 09:27:17 booting test machines...
> > > 2020/01/09 09:27:17 wait for the connection from test machine...
> > > 2020/01/09 09:29:23 machine check:
> > > 2020/01/09 09:29:23 syscalls                : 2961/3195
> > > 2020/01/09 09:29:23 code coverage           : enabled
> > > 2020/01/09 09:29:23 comparison tracing      : enabled
> > > 2020/01/09 09:29:23 extra coverage          : enabled
> > > 2020/01/09 09:29:23 setuid sandbox          : enabled
> > > 2020/01/09 09:29:23 namespace sandbox       : enabled
> > > 2020/01/09 09:29:23 Android sandbox         : /sys/fs/selinux/policy
> > > does not exist
> > > 2020/01/09 09:29:23 fault injection         : enabled
> > > 2020/01/09 09:29:23 leak checking           : CONFIG_DEBUG_KMEMLEAK is
> > > not enabled
> > > 2020/01/09 09:29:23 net packet injection    : enabled
> > > 2020/01/09 09:29:23 net device setup        : enabled
> > > 2020/01/09 09:29:23 concurrency sanitizer   : /sys/kernel/debug/kcsan
> > > does not exist
> > > 2020/01/09 09:29:23 devlink PCI setup       : PCI device 0000:00:10.0
> > > is not available
> > > 2020/01/09 09:29:27 corpus                  : 50226 (0 deleted)
> > > 2020/01/09 09:29:27 VMs 20, executed 0, cover 0, crashes 0, repro 0
> > > 2020/01/09 09:29:37 VMs 20, executed 45, cover 0, crashes 0, repro 0
> > > 2020/01/09 09:29:47 VMs 20, executed 74, cover 0, crashes 0, repro 0
> > > 2020/01/09 09:29:57 VMs 20, executed 80, cover 0, crashes 0, repro 0
> > > 2020/01/09 09:30:07 VMs 20, executed 80, cover 0, crashes 0, repro 0
> > > 2020/01/09 09:30:17 VMs 20, executed 80, cover 0, crashes 0, repro 0
> > > 2020/01/09 09:30:27 VMs 20, executed 80, cover 0, crashes 0, repro 0
> > > 2020/01/09 09:30:37 VMs 20, executed 80, cover 0, crashes 0, repro 0
> > > 2020/01/09 09:30:47 VMs 20, executed 80, cover 0, crashes 0, repro 0
> > > 2020/01/09 09:30:57 VMs 20, executed 80, cover 0, crashes 0, repro 0
> > > 2020/01/09 09:31:07 VMs 20, executed 80, cover 0, crashes 0, repro 0
> > > 2020/01/09 09:31:17 VMs 20, executed 80, cover 0, crashes 0, repro 0
> > > 2020/01/09 09:31:26 vm-10: crash: INFO: rcu detected stall in do_idle
> > > 2020/01/09 09:31:27 VMs 13, executed 80, cover 0, crashes 0, repro 0
> > > 2020/01/09 09:31:28 vm-1: crash: INFO: rcu detected stall in sys_futex
> > > 2020/01/09 09:31:29 vm-4: crash: INFO: rcu detected stall in sys_futex
> > > 2020/01/09 09:31:31 vm-0: crash: INFO: rcu detected stall in sys_getsockopt
> > > 2020/01/09 09:31:33 vm-18: crash: INFO: rcu detected stall in sys_clone3
> > > 2020/01/09 09:31:35 vm-3: crash: INFO: rcu detected stall in sys_futex
> > > 2020/01/09 09:31:36 vm-8: crash: INFO: rcu detected stall in do_idle
> > > 2020/01/09 09:31:37 VMs 7, executed 80, cover 0, crashes 6, repro 0
> > > 2020/01/09 09:31:38 vm-19: crash: INFO: rcu detected stall in schedule_tail
> > > 2020/01/09 09:31:40 vm-6: crash: INFO: rcu detected stall in schedule_tail
> > > 2020/01/09 09:31:42 vm-2: crash: INFO: rcu detected stall in schedule_tail
> > > 2020/01/09 09:31:44 vm-12: crash: INFO: rcu detected stall in sys_futex
> > > 2020/01/09 09:31:46 vm-15: crash: INFO: rcu detected stall in sys_nanosleep
> > > 2020/01/09 09:31:47 VMs 1, executed 80, cover 0, crashes 11, repro 0
> > > 2020/01/09 09:31:48 vm-16: crash: INFO: rcu detected stall in sys_futex
> > > 2020/01/09 09:31:50 vm-9: crash: INFO: rcu detected stall in schedule
> > > 2020/01/09 09:31:52 vm-13: crash: INFO: rcu detected stall in schedule_tail
> > > 2020/01/09 09:31:54 vm-11: crash: INFO: rcu detected stall in schedule_tail
> > > 2020/01/09 09:31:56 vm-17: crash: INFO: rcu detected stall in sys_futex
> > > 2020/01/09 09:31:57 VMs 0, executed 80, cover 0, crashes 16, repro 0
> > > 2020/01/09 09:31:58 vm-7: crash: INFO: rcu detected stall in sys_futex
> > > 2020/01/09 09:32:00 vm-5: crash: INFO: rcu detected stall in dput
> > > 2020/01/09 09:32:02 vm-14: crash: INFO: rcu detected stall in sys_nanosleep
> > >
> > >
> > > Then I switched LSM to selinux and I _still_ can reproduce this. So,
> > > Casey, you may relax, this is not smack-specific :)
> > >
> > > Then I disabled CONFIG_KASAN_VMALLOC and CONFIG_VMAP_STACK and it
> > > started working normally.
> > >
> > > So this is somehow related to both clang and KASAN/VMAP_STACK.
> > >
> > > The clang I used is:
> > > https://storage.googleapis.com/syzkaller/clang-kmsan-362913.tar.gz
> > > (the one we use on syzbot).
> >
> >
> > Clustering hangs, they all happen within very limited section of the code:
> >
> >       1  free_thread_stack+0x124/0x590 kernel/fork.c:284
> >       5  free_thread_stack+0x12e/0x590 kernel/fork.c:280
> >      39  free_thread_stack+0x12e/0x590 kernel/fork.c:284
> >       6  free_thread_stack+0x133/0x590 kernel/fork.c:280
> >       5  free_thread_stack+0x13d/0x590 kernel/fork.c:280
> >       2  free_thread_stack+0x141/0x590 kernel/fork.c:280
> >       6  free_thread_stack+0x14c/0x590 kernel/fork.c:280
> >       9  free_thread_stack+0x151/0x590 kernel/fork.c:280
> >       3  free_thread_stack+0x15b/0x590 kernel/fork.c:280
> >      67  free_thread_stack+0x168/0x590 kernel/fork.c:280
> >       6  free_thread_stack+0x16d/0x590 kernel/fork.c:284
> >       2  free_thread_stack+0x177/0x590 kernel/fork.c:284
> >       1  free_thread_stack+0x182/0x590 kernel/fork.c:284
> >       1  free_thread_stack+0x186/0x590 kernel/fork.c:284
> >      16  free_thread_stack+0x18b/0x590 kernel/fork.c:284
> >       4  free_thread_stack+0x195/0x590 kernel/fork.c:284
> >
> > Here is disass of the function:
> > https://gist.githubusercontent.com/dvyukov/a283d1aaf2ef7874001d56525279ccbd/raw/ac2478bff6472bc473f57f91a75f827cd72bb6bf/gistfile1.txt
> >
> > But if I am not mistaken, the function only ever jumps down. So how
> > can it loop?...
>
>
> This is a miscompilation related to static branches.
>
> objdump shows:
>
> ffffffff814878f8: 0f 1f 44 00 00        nopl   0x0(%rax,%rax,1)
>  ./arch/x86/include/asm/jump_label.h:25
> asm_volatile_goto("1:"
>
> However, the actual instruction in memory at the time is:
>
>    0xffffffff814878f8 <+408>: jmpq   0xffffffff8148787f <free_thread_stack+287>
>
> Which jumps to a wrong location in free_thread_stack and makes it loop.
>
> The static branch is this:
>
> static inline bool memcg_kmem_enabled(void)
> {
>   return static_branch_unlikely(&memcg_kmem_enabled_key);
> }
>
> static inline void memcg_kmem_uncharge(struct page *page, int order)
> {
>   if (memcg_kmem_enabled())
>     __memcg_kmem_uncharge(page, order);
> }
>
> I suspect it may have something to do with loop unrolling. It may jump
> to the right location, but in the wrong unrolled iteration.


Kernel built with clang version 10.0.0
(https://github.com/llvm/llvm-project.git
c2443155a0fb245c8f17f2c1c72b6ea391e86e81) works fine.

Alex, please update clang on syzbot machines.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Baxj5M4p%3DmZkFb1MyBw0MK1c6nWb-fKQcYSnYB8n1Cb8Q%40mail.gmail.com.
