Return-Path: <kasan-dev+bncBCMIZB7QWENRBUOS3PYAKGQEZXJEDNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id EAB611354BA
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 09:50:26 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id l13sf3328884otn.18
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 00:50:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578559825; cv=pass;
        d=google.com; s=arc-20160816;
        b=s/zYhp3zVGNSKd7GMii5zO31x5LrePesVKngNTIrE3jgFa+oWVjqum6t0HzZw9T3tu
         bZfdfBaWZurXqajIy6V9LPyLJ1JLMYn+yrQehMvxb59JG53UVGqYPlWsg5qY4ZyPIwho
         WXvVEh3+/mMHcqZzD5W+yVcWvW0bJMtiBe3qcm1CfkUPEyzRIs/lMPN/uiBKEvuM7lia
         4BySq5NmR8krh8eCIou8q6zItlfrPbt3uxgJXhEdE81DjgXBciPlQQg+39GNarNdatih
         DXUfIJOA3XkIDH/HpXlN+pJ8x2KZzVnqVbr8p46SplEk5AU7h0oViQeVQgIu038nlgoa
         hxSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ueRKrgPDGDc00b+NmmrTVxJzEyhLDUgN4N611SXt2fk=;
        b=JBB3EuTNNxUk1cVzcLKeHEhc3OBAv4WnzysOV4RnkjiDjG/l5xqi9Kvq3n78/KYIPs
         gsfR0YRnFRGJxCosPiBUN+qU8ARYpPJv8lapcAWZlHItLnJ1yAbS7voGrQrXGQR4lAjg
         ByOKoD7dxhLipTVasGE8yQgxIhBwkC8g4r9qB28OEtlj2SZHecBenUv4ft1MIJMXZkGY
         b8cQYd85v+XoBpY/MGZpLMvWgbYGtnwPGRfi5UysPVR1f88y55BgQgb3QU/HIEKDY/Kh
         gGcKzFw9jnsxk8bqRGWoQ73TJ9CrbCSyukwUT+OyDuwRS+f4/7URm0NBlWnOo581+FmM
         SF0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sgrs6iYb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ueRKrgPDGDc00b+NmmrTVxJzEyhLDUgN4N611SXt2fk=;
        b=dSfrgIO58wl2qZdh8AnysuXLITCSpsMBT0RJRJ4bUVDqcS9BpRI38awfrD1sR4RYPJ
         NMCWdMghFPSXnCkvtpAFsl8w48ygcf6Bw5SWYEinKeCzP1JedOrjGbpa4oxCPkiF1Hlu
         E/egmdEpHkBGXl31Id2TAuzgjpAIZCa2IR2kPEFqLCqI+GMvQffQJtivw8SpFdxftBxt
         ParMAm6vTeV5zhf2LKd5wIqLFT5agxSCNc8NJlKudcuLvXwBc3qEgq0Z4zbewPTwrSlY
         UmuFiSyVu6Pg+s3YaMUErpkV/1K59iXxoApn1nZfX5cyaVJ483BzC73/uG9YkFn8w9o3
         9m6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ueRKrgPDGDc00b+NmmrTVxJzEyhLDUgN4N611SXt2fk=;
        b=WMyps/l8RJsFo8JG3wdfcmfzQ6WJn4qOyb303Rr3K48z9Q0bW11r47sp+4HEbXHE+v
         WZNvPNA87QWwqOzgm1UW/QAMcPjyiyUsopWD24R+pJKFTwDOGqJCLF6OkXgk+bGSVPA8
         5twWcisuGhpNE2D8GHxHcHylPq76+sBvOWlTLH+VY2TDuRFt9fNaiUcg6FIWVIBYUS+l
         MAlhaqx0yiwM0jmUuBwGJLNhpW6Xgd/YB01jiWKiElAt6O+FwHGWei5KwuQoPHM1KYiI
         uWpJ2zip8zYuwG2+MZL7Y+3/OmkmLrFNumi6aRGX+cZiMB2YO3QllZ8v2rQCepT0c6OD
         kfOw==
X-Gm-Message-State: APjAAAVM5jFgP8vRn0LNMXZnjPSG9qoSLxYo4URSgsr65Wl+LC0Qae4/
	pCUJaKdgNfAy4J8fnhK8PSc=
X-Google-Smtp-Source: APXvYqxhxV/0HJwmIWG9/WsOVlki8kPN4ktett73Wi09BtnfFGTpfRxynyWoZZNFqanjw9BmPRTWaQ==
X-Received: by 2002:aca:2207:: with SMTP id b7mr2348323oic.109.1578559825727;
        Thu, 09 Jan 2020 00:50:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:895:: with SMTP id 143ls285416oii.1.gmail; Thu, 09 Jan
 2020 00:50:25 -0800 (PST)
X-Received: by 2002:aca:ba88:: with SMTP id k130mr2408935oif.167.1578559825377;
        Thu, 09 Jan 2020 00:50:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578559825; cv=none;
        d=google.com; s=arc-20160816;
        b=tWoNNZtyomv2i1PYxuOQsjQ6fahca52CUhj/Hvg+i3AACT56y7GR2YjgAuYXnsX3vx
         RnLl2ReP2qElrhCFkJyBBrbbncjyJdhW6zxH3yCN6RlZZL2ZcXCvTJn+2V5rE9igJ036
         qwzF2F0ddQbZQpFEicjIyNpAfXLEZKpfDRNGsI34vZgrLPnYhwUoqAjpj0GnyBMOao85
         GvbEVidE0AB7PDGlIArTu41Itfj3zHsDOidBl66n6DX4G/DOMMvh7yG+Z0JjdCmWYbjO
         ajc4krSNTLRq8EOBKSUp4ZY3YSKx0vAzKsHk63X7HtVDF07TqteLXn/qmUddyRRuq8pv
         iGFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wloqhRoEICQ+k5+VnPqK5Heg13aiPvech9Fyx9hUKYs=;
        b=eZtpopXQxen3W1eyUM0H4PwQg8rox3Bf1+BXntGfcceN6FDSd4SWvpMfQ249EA7pem
         xex2xMmI9Rber3spn8vbjq5MhvPYSp2KKYNbdR+zk4pdIiwWnmTUgk1LEzqXMuuONJv7
         NnSO8SXrj/GeW5dLEMc5pN/xCV+sZ+O5u5fFV1rNggOLqhW9Wa4bvuMuTBlg4ygrOjvD
         8yt3me+yXz7JUiyPhokH6WQ283R53Z0UQV6uhx1r8CVBdlcaW9wLaKtpQyGFi2NveRnW
         x+jVmFolA1IXDDTE0ApWQrWt+TivhS26UcRfDpAdzEUgJfVn27KALttwq22yK9J4sQYX
         a6XQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sgrs6iYb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id w63si252528oif.2.2020.01.09.00.50.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jan 2020 00:50:25 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id u1so2612114qvk.13
        for <kasan-dev@googlegroups.com>; Thu, 09 Jan 2020 00:50:25 -0800 (PST)
X-Received: by 2002:ad4:4810:: with SMTP id g16mr7563219qvy.22.1578559824505;
 Thu, 09 Jan 2020 00:50:24 -0800 (PST)
MIME-Version: 1.0
References: <00000000000036decf0598c8762e@google.com> <CACT4Y+YVMUxeLcFMray9n0+cXbVibj5X347LZr8YgvjN5nC8pw@mail.gmail.com>
 <CACT4Y+asdED7tYv462Ui2OhQVKXVUnC+=fumXR3qM1A4d6AvOQ@mail.gmail.com>
 <f7758e0a-a157-56a2-287e-3d4452d72e00@schaufler-ca.com> <87a787ekd0.fsf@dja-thinkpad.axtens.net>
 <87h81zax74.fsf@dja-thinkpad.axtens.net> <CACT4Y+b+Vx1FeCmhMAYq-g3ObHdMPOsWxouyXXUr7S5OjNiVGQ@mail.gmail.com>
 <0b60c93e-a967-ecac-07e7-67aea1a0208e@I-love.SAKURA.ne.jp>
 <6d009462-74d9-96e9-ab3f-396842a58011@schaufler-ca.com> <CACT4Y+bURugCpLm5TG37-7voFEeEoXo_Gb=3sy75_RELZotXHw@mail.gmail.com>
In-Reply-To: <CACT4Y+bURugCpLm5TG37-7voFEeEoXo_Gb=3sy75_RELZotXHw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jan 2020 09:50:12 +0100
Message-ID: <CACT4Y+avizeUd=nY2w1B_LbEC1cP5prBfpnANYaxhgS_fcL6ag@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=sgrs6iYb;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44
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

On Thu, Jan 9, 2020 at 9:19 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Wed, Jan 8, 2020 at 6:19 PM Casey Schaufler <casey@schaufler-ca.com> wrote:
> >
> > On 1/8/2020 2:25 AM, Tetsuo Handa wrote:
> > > On 2020/01/08 15:20, Dmitry Vyukov wrote:
> > >> I temporarily re-enabled smack instance and it produced another 50
> > >> stalls all over the kernel, and now keeps spewing a dozen every hour.
> >
> > Do I have to be using clang to test this? I'm setting up to work on this,
> > and don't want to waste time using my current tool chain if the problem
> > is clang specific.
>
> Humm, interesting. Initially I was going to say that most likely it's
> not clang-related. Bug smack instance is actually the only one that
> uses clang as well (except for KMSAN of course). So maybe it's indeed
> clang-related rather than smack-related. Let me try to build a kernel
> with clang.

+clang-built-linux, glider

[clang-built linux is severe broken since early Dec]

Building kernel with clang I can immediately reproduce this locally:

$ syz-manager
2020/01/09 09:27:15 loading corpus...
2020/01/09 09:27:17 serving http on http://0.0.0.0:50001
2020/01/09 09:27:17 serving rpc on tcp://[::]:45851
2020/01/09 09:27:17 booting test machines...
2020/01/09 09:27:17 wait for the connection from test machine...
2020/01/09 09:29:23 machine check:
2020/01/09 09:29:23 syscalls                : 2961/3195
2020/01/09 09:29:23 code coverage           : enabled
2020/01/09 09:29:23 comparison tracing      : enabled
2020/01/09 09:29:23 extra coverage          : enabled
2020/01/09 09:29:23 setuid sandbox          : enabled
2020/01/09 09:29:23 namespace sandbox       : enabled
2020/01/09 09:29:23 Android sandbox         : /sys/fs/selinux/policy
does not exist
2020/01/09 09:29:23 fault injection         : enabled
2020/01/09 09:29:23 leak checking           : CONFIG_DEBUG_KMEMLEAK is
not enabled
2020/01/09 09:29:23 net packet injection    : enabled
2020/01/09 09:29:23 net device setup        : enabled
2020/01/09 09:29:23 concurrency sanitizer   : /sys/kernel/debug/kcsan
does not exist
2020/01/09 09:29:23 devlink PCI setup       : PCI device 0000:00:10.0
is not available
2020/01/09 09:29:27 corpus                  : 50226 (0 deleted)
2020/01/09 09:29:27 VMs 20, executed 0, cover 0, crashes 0, repro 0
2020/01/09 09:29:37 VMs 20, executed 45, cover 0, crashes 0, repro 0
2020/01/09 09:29:47 VMs 20, executed 74, cover 0, crashes 0, repro 0
2020/01/09 09:29:57 VMs 20, executed 80, cover 0, crashes 0, repro 0
2020/01/09 09:30:07 VMs 20, executed 80, cover 0, crashes 0, repro 0
2020/01/09 09:30:17 VMs 20, executed 80, cover 0, crashes 0, repro 0
2020/01/09 09:30:27 VMs 20, executed 80, cover 0, crashes 0, repro 0
2020/01/09 09:30:37 VMs 20, executed 80, cover 0, crashes 0, repro 0
2020/01/09 09:30:47 VMs 20, executed 80, cover 0, crashes 0, repro 0
2020/01/09 09:30:57 VMs 20, executed 80, cover 0, crashes 0, repro 0
2020/01/09 09:31:07 VMs 20, executed 80, cover 0, crashes 0, repro 0
2020/01/09 09:31:17 VMs 20, executed 80, cover 0, crashes 0, repro 0
2020/01/09 09:31:26 vm-10: crash: INFO: rcu detected stall in do_idle
2020/01/09 09:31:27 VMs 13, executed 80, cover 0, crashes 0, repro 0
2020/01/09 09:31:28 vm-1: crash: INFO: rcu detected stall in sys_futex
2020/01/09 09:31:29 vm-4: crash: INFO: rcu detected stall in sys_futex
2020/01/09 09:31:31 vm-0: crash: INFO: rcu detected stall in sys_getsockopt
2020/01/09 09:31:33 vm-18: crash: INFO: rcu detected stall in sys_clone3
2020/01/09 09:31:35 vm-3: crash: INFO: rcu detected stall in sys_futex
2020/01/09 09:31:36 vm-8: crash: INFO: rcu detected stall in do_idle
2020/01/09 09:31:37 VMs 7, executed 80, cover 0, crashes 6, repro 0
2020/01/09 09:31:38 vm-19: crash: INFO: rcu detected stall in schedule_tail
2020/01/09 09:31:40 vm-6: crash: INFO: rcu detected stall in schedule_tail
2020/01/09 09:31:42 vm-2: crash: INFO: rcu detected stall in schedule_tail
2020/01/09 09:31:44 vm-12: crash: INFO: rcu detected stall in sys_futex
2020/01/09 09:31:46 vm-15: crash: INFO: rcu detected stall in sys_nanosleep
2020/01/09 09:31:47 VMs 1, executed 80, cover 0, crashes 11, repro 0
2020/01/09 09:31:48 vm-16: crash: INFO: rcu detected stall in sys_futex
2020/01/09 09:31:50 vm-9: crash: INFO: rcu detected stall in schedule
2020/01/09 09:31:52 vm-13: crash: INFO: rcu detected stall in schedule_tail
2020/01/09 09:31:54 vm-11: crash: INFO: rcu detected stall in schedule_tail
2020/01/09 09:31:56 vm-17: crash: INFO: rcu detected stall in sys_futex
2020/01/09 09:31:57 VMs 0, executed 80, cover 0, crashes 16, repro 0
2020/01/09 09:31:58 vm-7: crash: INFO: rcu detected stall in sys_futex
2020/01/09 09:32:00 vm-5: crash: INFO: rcu detected stall in dput
2020/01/09 09:32:02 vm-14: crash: INFO: rcu detected stall in sys_nanosleep


Then I switched LSM to selinux and I _still_ can reproduce this. So,
Casey, you may relax, this is not smack-specific :)

Then I disabled CONFIG_KASAN_VMALLOC and CONFIG_VMAP_STACK and it
started working normally.

So this is somehow related to both clang and KASAN/VMAP_STACK.

The clang I used is:
https://storage.googleapis.com/syzkaller/clang-kmsan-362913.tar.gz
(the one we use on syzbot).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BavizeUd%3DnY2w1B_LbEC1cP5prBfpnANYaxhgS_fcL6ag%40mail.gmail.com.
