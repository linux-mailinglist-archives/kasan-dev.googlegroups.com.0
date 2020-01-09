Return-Path: <kasan-dev+bncBCMIZB7QWENRBAHF3PYAKGQETTBTLGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id 78CCA1355CA
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 10:29:37 +0100 (CET)
Received: by mail-vs1-xe38.google.com with SMTP id o185sf978416vsc.5
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 01:29:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578562176; cv=pass;
        d=google.com; s=arc-20160816;
        b=Pw5K4N6J0GbCooKqIfpiAhJ9YSII7XtzPlwyEZ3rWTRai302gQGmELqodMK6Ixc8nx
         6mu0C+D7txAInjBn3ao+ARuDfh/W4HbRIcQLgYb3htBTw6Nyhn/jhTO48nWkZ5EVgL0M
         7C8hkHnP81qlZeD5qAzZqVbaQGY30ioyY31z2QtrKy15l1IMK61649XWN1ibrwkhynIJ
         nP62rjQf5lmQB/pXKacINSm5N5CTbqhwcHdrG4zqtkRUc2vPLg+buDoHZRNDXgST23/V
         Qw892+B9Z2GwJGdIXwh92NWESASt1dtM6v7ZjA8sqhvBpQHFmOfXdqALq3eQDpV54SYt
         JV0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oAm3jLQX2/pjhmb5gHzDS97E3wNyK+CAKeGKoNo3x+Y=;
        b=lGAzWxVxq3l6svRm2aU+vAMb0XWdGciWhN4qQXwM+5t4TST6NyJGzpxS4DNUeztvx2
         rllfxMwHPS7IjIm3ZXAUpBDnLof3K9iR0ZHQE9VevNnuuGb/6eHSfzjIi3i7tDTj52Q/
         QAq2HDnQAhtqdkqcN21jeZCGzZZdar3PzVye5b9KAZ0PukyjG9sWXuQS6OUYH+lL5QPx
         uFugT0j3lwVxioMWGhfBtjqSl88e4OgTyyWnH1oxa6jRpaWJE/xamn5Daa9SRX9B6/CA
         T36zyDEM5QVgDnayXih9MOSERRlRSHllliUx+w2H7+z0oq0IVD9ZXTs4DWVmalV26RxX
         itog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CF29A5OZ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oAm3jLQX2/pjhmb5gHzDS97E3wNyK+CAKeGKoNo3x+Y=;
        b=k6L+IssGRBxQxeVF7TC/+BGfRR2w0URankknokZwA4HmUIeKIpOM52+N3q1rPOyX6A
         orAb+3MAfcjkMppPeSQnDh+XD4KoWRSagYTWxg0Tc8nchKnP6iXSEnt27PThmwbiaVkd
         zn/UUeHdPeh+uuFxig3jHFj71HWtIZz2k+bcEEfJmBmg+UGUdVrwarlneGANcEkE4fJ7
         32RqgO0mnNcXYPH8bZquLkhV4eqMRMRxxrVSJ0cCnP368kPn0NFGwMnvK52P40tdQPlz
         xd4LmHpuuHavn8olOicOb8x5pxrSgl9ZiIPR96t3PVsfISXwNqHmpKaS+CG6U0Gt9OA3
         xTgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oAm3jLQX2/pjhmb5gHzDS97E3wNyK+CAKeGKoNo3x+Y=;
        b=D0UjkWK4TqaQXCwkmbz0xcKgZVQW0Mvogt0hDumCfTf/PFjTZ+4kxx2c/6G4+Td/3s
         U3XW8Da6CFgBDbDrHXIp+AxO6JigyNsNkXfAGFwyJz9o5sr0o9XfoN2STDQ+33+ZrwQD
         X0ex98FQwxeunFTbhTE6tRDFyzt5xzHzYRS776inYxo6ab0oLZXMjMO84Lcv66p70egB
         ie2THDwTUIneS2GAVvCs+cwVaGdqwZ3fLDQpVjxcoVEsJCIVjVYEsYLKjHV6UuqRm1C5
         s9WuvMW8hJX4wL/4F2+UN4a45o+sL5REqZ0a9cg5VY5Wik3UbpWmtQeNgpkeOe3ZqWvg
         7VJQ==
X-Gm-Message-State: APjAAAV2sd531z02WO/SXLh139CyfH6lp/7tTDZ2Jki7nZJJg1RpInxG
	YnklYnSJ3oXeN6c9KE1alTM=
X-Google-Smtp-Source: APXvYqwUrAxKfeqrSsH60VeLVqmpuoNUsawLUxBGQQ29vZbIiEeNagaNtamXWxvVEExkBprEL4odCg==
X-Received: by 2002:a05:6102:300c:: with SMTP id s12mr5403044vsa.188.1578562176483;
        Thu, 09 Jan 2020 01:29:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:b304:: with SMTP id a4ls135628vsm.13.gmail; Thu, 09 Jan
 2020 01:29:36 -0800 (PST)
X-Received: by 2002:a67:f683:: with SMTP id n3mr5340397vso.117.1578562176033;
        Thu, 09 Jan 2020 01:29:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578562176; cv=none;
        d=google.com; s=arc-20160816;
        b=BwLdSWT4xgU/fPYsV1Ptma11vga4j/VvEFSkucabYMNjJfzZo/hqZYf9kvknoMjWAf
         HhlYZRY1Oq6wF8sb9KU4wHZH8/JrGlTAQQRsfA+QPHXK8PBoaxt9Qe3YJVvzuPKZWAN2
         pL10r5rYpiHJTvrdXA3rC5oxdzQXFGlu/3o4iXuSONMNRZj0l9auouzOmKliiUztszw6
         p4ldC0EGlpDKLOy7WAtfTaE86YlhSRe84x9lh8lWG2rJq2dA1VfqWpP2IXX8F8p2NJeU
         bVwp/1t04WqqETvrDvlJUy1iXTJf4ovSaNzF2NStTuRD19+/iewBrYQh1NLxbSBvbcl0
         DvxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=htGEPzh2cvAg6/SqoSQkw2b0L7SR3bZlTMACQb3VVDc=;
        b=HoC1sABVgAfbEZWjTxKYWn2HHttPwDVpJrLnbXDXBLyY6JEKbA2Eknog84w9dAHzaq
         8qjmjwGE8uj7/VChLNxFpZLCy1gN8SdthvQuJDcVHs9wWVsdMZwFUbgEd/zkCLv8Y6HR
         iG7YEdtxfD9imNGTldeSnb45y/inLxOxNd9VvI1uUeeYW/KTQq7i9szyeTP459FtusQG
         C49IELLZWgfWtKQ+bFCV6BFsoJM5H2QZEZ6FXfkXmNc+8EBhZqduypg9X08RTuHoUYKr
         aJnTYhivpD6ZpLWIhtuy8byhHZz+Xi8RHY4e+LIRMDQJPVL3+NRLPA1F8hPuu3Q+BUHc
         C5OA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CF29A5OZ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id 75si182481vkx.3.2020.01.09.01.29.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jan 2020 01:29:36 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id f16so2672447qvi.4
        for <kasan-dev@googlegroups.com>; Thu, 09 Jan 2020 01:29:36 -0800 (PST)
X-Received: by 2002:ad4:5a53:: with SMTP id ej19mr8036254qvb.34.1578562175261;
 Thu, 09 Jan 2020 01:29:35 -0800 (PST)
MIME-Version: 1.0
References: <00000000000036decf0598c8762e@google.com> <CACT4Y+YVMUxeLcFMray9n0+cXbVibj5X347LZr8YgvjN5nC8pw@mail.gmail.com>
 <CACT4Y+asdED7tYv462Ui2OhQVKXVUnC+=fumXR3qM1A4d6AvOQ@mail.gmail.com>
 <f7758e0a-a157-56a2-287e-3d4452d72e00@schaufler-ca.com> <87a787ekd0.fsf@dja-thinkpad.axtens.net>
 <87h81zax74.fsf@dja-thinkpad.axtens.net> <CACT4Y+b+Vx1FeCmhMAYq-g3ObHdMPOsWxouyXXUr7S5OjNiVGQ@mail.gmail.com>
 <0b60c93e-a967-ecac-07e7-67aea1a0208e@I-love.SAKURA.ne.jp>
 <6d009462-74d9-96e9-ab3f-396842a58011@schaufler-ca.com> <CACT4Y+bURugCpLm5TG37-7voFEeEoXo_Gb=3sy75_RELZotXHw@mail.gmail.com>
 <CACT4Y+avizeUd=nY2w1B_LbEC1cP5prBfpnANYaxhgS_fcL6ag@mail.gmail.com>
In-Reply-To: <CACT4Y+avizeUd=nY2w1B_LbEC1cP5prBfpnANYaxhgS_fcL6ag@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jan 2020 10:29:23 +0100
Message-ID: <CACT4Y+Z3GCncV3G1=36NmDRX_XOZsdoRJ3UshZoornbSRSN28w@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=CF29A5OZ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Thu, Jan 9, 2020 at 9:50 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Jan 9, 2020 at 9:19 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Wed, Jan 8, 2020 at 6:19 PM Casey Schaufler <casey@schaufler-ca.com> wrote:
> > >
> > > On 1/8/2020 2:25 AM, Tetsuo Handa wrote:
> > > > On 2020/01/08 15:20, Dmitry Vyukov wrote:
> > > >> I temporarily re-enabled smack instance and it produced another 50
> > > >> stalls all over the kernel, and now keeps spewing a dozen every hour.
> > >
> > > Do I have to be using clang to test this? I'm setting up to work on this,
> > > and don't want to waste time using my current tool chain if the problem
> > > is clang specific.
> >
> > Humm, interesting. Initially I was going to say that most likely it's
> > not clang-related. Bug smack instance is actually the only one that
> > uses clang as well (except for KMSAN of course). So maybe it's indeed
> > clang-related rather than smack-related. Let me try to build a kernel
> > with clang.
>
> +clang-built-linux, glider
>
> [clang-built linux is severe broken since early Dec]
>
> Building kernel with clang I can immediately reproduce this locally:
>
> $ syz-manager
> 2020/01/09 09:27:15 loading corpus...
> 2020/01/09 09:27:17 serving http on http://0.0.0.0:50001
> 2020/01/09 09:27:17 serving rpc on tcp://[::]:45851
> 2020/01/09 09:27:17 booting test machines...
> 2020/01/09 09:27:17 wait for the connection from test machine...
> 2020/01/09 09:29:23 machine check:
> 2020/01/09 09:29:23 syscalls                : 2961/3195
> 2020/01/09 09:29:23 code coverage           : enabled
> 2020/01/09 09:29:23 comparison tracing      : enabled
> 2020/01/09 09:29:23 extra coverage          : enabled
> 2020/01/09 09:29:23 setuid sandbox          : enabled
> 2020/01/09 09:29:23 namespace sandbox       : enabled
> 2020/01/09 09:29:23 Android sandbox         : /sys/fs/selinux/policy
> does not exist
> 2020/01/09 09:29:23 fault injection         : enabled
> 2020/01/09 09:29:23 leak checking           : CONFIG_DEBUG_KMEMLEAK is
> not enabled
> 2020/01/09 09:29:23 net packet injection    : enabled
> 2020/01/09 09:29:23 net device setup        : enabled
> 2020/01/09 09:29:23 concurrency sanitizer   : /sys/kernel/debug/kcsan
> does not exist
> 2020/01/09 09:29:23 devlink PCI setup       : PCI device 0000:00:10.0
> is not available
> 2020/01/09 09:29:27 corpus                  : 50226 (0 deleted)
> 2020/01/09 09:29:27 VMs 20, executed 0, cover 0, crashes 0, repro 0
> 2020/01/09 09:29:37 VMs 20, executed 45, cover 0, crashes 0, repro 0
> 2020/01/09 09:29:47 VMs 20, executed 74, cover 0, crashes 0, repro 0
> 2020/01/09 09:29:57 VMs 20, executed 80, cover 0, crashes 0, repro 0
> 2020/01/09 09:30:07 VMs 20, executed 80, cover 0, crashes 0, repro 0
> 2020/01/09 09:30:17 VMs 20, executed 80, cover 0, crashes 0, repro 0
> 2020/01/09 09:30:27 VMs 20, executed 80, cover 0, crashes 0, repro 0
> 2020/01/09 09:30:37 VMs 20, executed 80, cover 0, crashes 0, repro 0
> 2020/01/09 09:30:47 VMs 20, executed 80, cover 0, crashes 0, repro 0
> 2020/01/09 09:30:57 VMs 20, executed 80, cover 0, crashes 0, repro 0
> 2020/01/09 09:31:07 VMs 20, executed 80, cover 0, crashes 0, repro 0
> 2020/01/09 09:31:17 VMs 20, executed 80, cover 0, crashes 0, repro 0
> 2020/01/09 09:31:26 vm-10: crash: INFO: rcu detected stall in do_idle
> 2020/01/09 09:31:27 VMs 13, executed 80, cover 0, crashes 0, repro 0
> 2020/01/09 09:31:28 vm-1: crash: INFO: rcu detected stall in sys_futex
> 2020/01/09 09:31:29 vm-4: crash: INFO: rcu detected stall in sys_futex
> 2020/01/09 09:31:31 vm-0: crash: INFO: rcu detected stall in sys_getsockopt
> 2020/01/09 09:31:33 vm-18: crash: INFO: rcu detected stall in sys_clone3
> 2020/01/09 09:31:35 vm-3: crash: INFO: rcu detected stall in sys_futex
> 2020/01/09 09:31:36 vm-8: crash: INFO: rcu detected stall in do_idle
> 2020/01/09 09:31:37 VMs 7, executed 80, cover 0, crashes 6, repro 0
> 2020/01/09 09:31:38 vm-19: crash: INFO: rcu detected stall in schedule_tail
> 2020/01/09 09:31:40 vm-6: crash: INFO: rcu detected stall in schedule_tail
> 2020/01/09 09:31:42 vm-2: crash: INFO: rcu detected stall in schedule_tail
> 2020/01/09 09:31:44 vm-12: crash: INFO: rcu detected stall in sys_futex
> 2020/01/09 09:31:46 vm-15: crash: INFO: rcu detected stall in sys_nanosleep
> 2020/01/09 09:31:47 VMs 1, executed 80, cover 0, crashes 11, repro 0
> 2020/01/09 09:31:48 vm-16: crash: INFO: rcu detected stall in sys_futex
> 2020/01/09 09:31:50 vm-9: crash: INFO: rcu detected stall in schedule
> 2020/01/09 09:31:52 vm-13: crash: INFO: rcu detected stall in schedule_tail
> 2020/01/09 09:31:54 vm-11: crash: INFO: rcu detected stall in schedule_tail
> 2020/01/09 09:31:56 vm-17: crash: INFO: rcu detected stall in sys_futex
> 2020/01/09 09:31:57 VMs 0, executed 80, cover 0, crashes 16, repro 0
> 2020/01/09 09:31:58 vm-7: crash: INFO: rcu detected stall in sys_futex
> 2020/01/09 09:32:00 vm-5: crash: INFO: rcu detected stall in dput
> 2020/01/09 09:32:02 vm-14: crash: INFO: rcu detected stall in sys_nanosleep
>
>
> Then I switched LSM to selinux and I _still_ can reproduce this. So,
> Casey, you may relax, this is not smack-specific :)
>
> Then I disabled CONFIG_KASAN_VMALLOC and CONFIG_VMAP_STACK and it
> started working normally.
>
> So this is somehow related to both clang and KASAN/VMAP_STACK.
>
> The clang I used is:
> https://storage.googleapis.com/syzkaller/clang-kmsan-362913.tar.gz
> (the one we use on syzbot).


Clustering hangs, they all happen within very limited section of the code:

      1  free_thread_stack+0x124/0x590 kernel/fork.c:284
      5  free_thread_stack+0x12e/0x590 kernel/fork.c:280
     39  free_thread_stack+0x12e/0x590 kernel/fork.c:284
      6  free_thread_stack+0x133/0x590 kernel/fork.c:280
      5  free_thread_stack+0x13d/0x590 kernel/fork.c:280
      2  free_thread_stack+0x141/0x590 kernel/fork.c:280
      6  free_thread_stack+0x14c/0x590 kernel/fork.c:280
      9  free_thread_stack+0x151/0x590 kernel/fork.c:280
      3  free_thread_stack+0x15b/0x590 kernel/fork.c:280
     67  free_thread_stack+0x168/0x590 kernel/fork.c:280
      6  free_thread_stack+0x16d/0x590 kernel/fork.c:284
      2  free_thread_stack+0x177/0x590 kernel/fork.c:284
      1  free_thread_stack+0x182/0x590 kernel/fork.c:284
      1  free_thread_stack+0x186/0x590 kernel/fork.c:284
     16  free_thread_stack+0x18b/0x590 kernel/fork.c:284
      4  free_thread_stack+0x195/0x590 kernel/fork.c:284

Here is disass of the function:
https://gist.githubusercontent.com/dvyukov/a283d1aaf2ef7874001d56525279ccbd/raw/ac2478bff6472bc473f57f91a75f827cd72bb6bf/gistfile1.txt

But if I am not mistaken, the function only ever jumps down. So how
can it loop?...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ3GCncV3G1%3D36NmDRX_XOZsdoRJ3UshZoornbSRSN28w%40mail.gmail.com.
