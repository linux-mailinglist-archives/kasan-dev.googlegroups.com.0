Return-Path: <kasan-dev+bncBCMIZB7QWENRBBUYWXXAKGQELM7GOKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 631EEFC676
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 13:43:51 +0100 (CET)
Received: by mail-ua1-x93a.google.com with SMTP id b19sf1384435uak.5
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 04:43:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573735430; cv=pass;
        d=google.com; s=arc-20160816;
        b=bdnEdjytkUNPuf2aP9845BChZ2WKNrwjcFnzp/XpI4jmVANjkFqtAfWJ3ewQwN3LbW
         caL+RExniQ87BT8WXMMa5wffncERl3gT3cZ+SQbndRJpEs5CWTsr0tgSIbHPmaAnDJCg
         dQ60miXVdgGug7u80WLrIf3av8iN8s3pMEfK2CrZzPhWBASNZLNrGBNHW6aB6Z9v53u0
         1wwtjpgdUHFM9S7AHZfJFjiUknsnSNxn7QNJ9wT6oaw/Xto6YUKU4urfoUAnBdmUwpXj
         Z2o0/Y+H/j5AvXOCjZSvj093M73/9R3zEOwKU5T4fpOW34eM3AR2ZG7V/f/fHxV/T5dR
         jXcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=76ndaG2CkRfQGjCM3B6YMfCmpfFdr35lPFw8bF5/cbI=;
        b=dyriC2O+t0zfpyw2XTi/h8/2BcGepPFRJym4SXxVUwbWvwW2jUP2Z3ruout1y/DC3K
         GNM9acclQmsXjMEx3S2g2YrcyHme33eehWQuz74zjliIYglmijstVTiToR21IUKr6KAo
         GKXSVCdi/iSu1+Hn1eH+hBodydg4oFDs2ISXmGXjUtDM/JdAkwssMMJ6EnwtcoiFS8UK
         Bz06Fm+R1/o0v+FqGJftwvt6R2dyfw984z2XCF09akYGKlLogc9n9ovQb2PTfnUkyXbx
         4yO6wxqhF5sBpIqhMjtcSOzl2OPs/UyipeLC+igejzUhB20T0uw2a85U8rPZEz7RO6dS
         dvSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k0Kq6vhG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=76ndaG2CkRfQGjCM3B6YMfCmpfFdr35lPFw8bF5/cbI=;
        b=JRcEvJcB+PexC5HC/5cGF7HYNSCAtjczR4yUKKbbkMHpZcloNiDYXvW13ahd8PoCpv
         QfRL+k89aOuafCekjGy3VktyaATzzGJOe3xFobYxxHHhuIjJMIbPbDuyxrknNyy7RcYJ
         9HZZ4wdSf2hJY/htpvDu704+Uvn+/sxb5xnkGl5tWDZPW2Y+e90bvwvdEstB39IORMVz
         w8OQxX7b73Av6ctY8+38rOkbCzWI4JGMWicAWEmnWLK+eBEjyqClVGMn+urGtC2xkXkx
         3eI/dVfaE4dbDOOU8Y3DDG4HmNIiwK9iNDzmcVFEg3Nns4Ekp5QX27lXvvsh1y/WMvWK
         xw+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=76ndaG2CkRfQGjCM3B6YMfCmpfFdr35lPFw8bF5/cbI=;
        b=QoSRWOdM3lS/Neo2VjJ6ehzUBxbA+rd1A6d9Pjrn1HTCdYYG328P9SABIg7ghkhB5i
         koKHGDm9/zpLf4s4pT0Eo5C8HR3zH+KxU8VV0iUgOPhUxJMa/31cUce7jUNGrU4z5mb+
         nbk4oFwBB7FWbB6S2f7ZNAOtzctTZ00yj7gCCS0D76QriBWepf4wr1l2EJqqQ0jIoByT
         +RwBNICuww8LbvcGJs92TgPv7LHi9MqOYRH93TYiS2+WEimuUnZYNQKRuuRtwCB4Ap1w
         sYAAp8Ns0rL/gD17CYzW+ptTBdZfuqyfmG3jubBPA9zyQJoY2LZ1pObesdOaaNSbEFgz
         +mEA==
X-Gm-Message-State: APjAAAW9FQB0oeb0O0M0KlIppXCUWDPAkuz6YUykdmA0yLDOjYQ0o3O7
	5Ug2BPjq/Vd6b65J1nmMY6w=
X-Google-Smtp-Source: APXvYqyD54LzXIhJOs5I3xnoHLlFHgMsjq9+ehmocJ2bi6Zn/eeO9snUCzcVVee1qNBjLAvZupBqmQ==
X-Received: by 2002:a1f:8dc5:: with SMTP id p188mr4926321vkd.13.1573735430123;
        Thu, 14 Nov 2019 04:43:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7cc8:: with SMTP id x191ls223699vsc.15.gmail; Thu, 14
 Nov 2019 04:43:49 -0800 (PST)
X-Received: by 2002:a05:6102:a0e:: with SMTP id t14mr5451625vsa.68.1573735429798;
        Thu, 14 Nov 2019 04:43:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573735429; cv=none;
        d=google.com; s=arc-20160816;
        b=UbfXewKdqB3CkIGPC/iQ7l4+CP9uUNWwPgackJHf/bYrrFH9fE6WT5JID5wrObYRLL
         M5hmJMCAvNGWVv5CqDu4JBJaBw60LKOfizP8ZI7qBOMDQHLfs3K02Z277r0tOpzwws0T
         PjJbpkkwwpq7bIEMSBBLeQiZ/XuDf0zbk/mdLIP7FrqHL5WYL/yLQqVy6pAmetluDZB8
         DCOG0+Fadn7WTEhNbedEiZJAHxNP4HX56N53TYnELGeydk3klP8lbZpEafvTOxd6A7XU
         ikAEC2QqBgaEGoGTSCup20uqvDWbP7OXUCZUlqygY71MocN4kvr5VzWBWZrqt4FYP8aD
         fu5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Xu8unMoQOZazVAKAkb/in0L2d5yNwJaxTomjvfcBeLE=;
        b=rUoeUDRlLBBETEtidRV6haOPu32chhed2f8IWX4ShU4Hw9zl0x6vxhw8BDeZeSBkGU
         1WgMvklZSt0GhytWlnmP/b6zyoFdcP2CPhO74Us3ku7qxyawtA2gJcGdUiBUERZXcIun
         iZwmHdIv8k6nrdE8j/QWcMckC3L9Cm0a5RjG3+pQQiLzp7VejDg9EmxyoL9QuC9M+zBs
         IjoS65nazZwWJYCAm3psRh/apB9tIBJEEDoxVzQTIy9VFBf4AdmKL0c+0kpu7EcHU2a5
         QNVBUEspDiJZQjvWSuaocbrt1CIATgPodUf56AvyLjeAgr9Xt0jQaRr6/ZXs8yO1jRbD
         D6EQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k0Kq6vhG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id e11si409983uaf.0.2019.11.14.04.43.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 04:43:49 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id q19so2246393qvs.5
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 04:43:49 -0800 (PST)
X-Received: by 2002:a0c:b446:: with SMTP id e6mr7843083qvf.159.1573735428994;
 Thu, 14 Nov 2019 04:43:48 -0800 (PST)
MIME-Version: 1.0
References: <0000000000007ce85705974c50e5@google.com> <alpine.DEB.2.21.1911141210410.2507@nanos.tec.linutronix.de>
 <CACT4Y+aBLAWOQn4Mosd2Ymvmpbg9E2Lk7PhuziiL8fzM7LT-6g@mail.gmail.com>
In-Reply-To: <CACT4Y+aBLAWOQn4Mosd2Ymvmpbg9E2Lk7PhuziiL8fzM7LT-6g@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Nov 2019 13:43:37 +0100
Message-ID: <CACT4Y+ap9wFaOq-3WhO3-QnW7dCFWArvozQHKxBcmzR3wppvFQ@mail.gmail.com>
Subject: Re: linux-next boot error: general protection fault in __x64_sys_settimeofday
To: Thomas Gleixner <tglx@linutronix.de>, Arnd Bergmann <arnd@arndb.de>
Cc: syzbot <syzbot+dccce9b26ba09ca49966@syzkaller.appspotmail.com>, 
	John Stultz <john.stultz@linaro.org>, LKML <linux-kernel@vger.kernel.org>, sboyd@kernel.org, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Jann Horn <jannh@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=k0Kq6vhG;       spf=pass
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

On Thu, Nov 14, 2019 at 1:42 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Nov 14, 2019 at 1:35 PM Thomas Gleixner <tglx@linutronix.de> wrote:
> >
> > On Thu, 14 Nov 2019, syzbot wrote:
> >
> > From the full console output:
> >
> > kasan: CONFIG_KASAN_INLINE enabled
> > kasan: GPF could be caused by NULL-ptr deref or user memory access
> > general protection fault: 0000 [#1] PREEMPT SMP KASAN
> > RIP: 0010:__x64_sys_settimeofday+0x170/0x320
> >
> > Code: 85 50 ff ff ff 85 c0 0f 85 50 01 00 00 e8 b8 cd 10 00 48 8b 85 48 ff ff ff 48 c1 e8 03 48 89 c2 48 b8 00 00 00 00 00 fc ff df <80> 3c 02 00 0f 85 8a 01 00 00 49 8b 74 24 08 bf 40 42 0f 00 48 89
> >
> >       80 3c 02 00             cmpb   $0x0,(%rdx,%rax,1)
> >
> > RSP: 0018:ffff888093d0fe58 EFLAGS: 00010206
> > RAX: dffffc0000000000 RBX: 1ffff110127a1fcd RCX: ffffffff8162e915
> > RDX: 00000fff820fb94b RSI: ffffffff8162e928 RDI: 0000000000000005
> >
> > i.e.
> >
> >      *(0x00000fff820fb94b + 0xdffffc0000000000 * 1) == 0
> >
> >      *(0xe0000bff820fb94b) == 0
> >
> > So base == 0x00000fff820fb94b and index == 0xdffffc0000000000 and scale =
> > 1. As scale is 1, base and index might be swapped, but that still does not
> > make any sense.
> >
> > 0xdffffc0000000000 is explicitely loaded into RAX according to the
> > disassembly, but I can't find the corresponding source as this is in the
> > middle of the function prologue and looks KASAN related.
> >
> > RBP: ffff888093d0ff10 R08: ffff8880a8904380 R09: ffff8880a8904c18
> > R10: fffffbfff1390d30 R11: ffffffff89c86987 R12: 00007ffc107dca50
> > R13: ffff888093d0fee8 R14: 00007ffc107dca10 R15: 0000000000087a85
> > FS:  00007f614c01b700(0000) GS:ffff8880ae800000(0000) knlGS:0000000000000000
> > CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> > CR2: 00007f4440cdf000 CR3: 00000000a5236000 CR4: 00000000001406f0
> > DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> > DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> > Call Trace:
> >  ? do_sys_settimeofday64+0x250/0x250
> >  ? trace_hardirqs_on_thunk+0x1a/0x1c
> >  ? do_syscall_64+0x26/0x760
> >  ? entry_SYSCALL_64_after_hwframe+0x49/0xbe
> >  ? do_syscall_64+0x26/0x760
> >  ? lockdep_hardirqs_on+0x421/0x5e0
> >  ? trace_hardirqs_on+0x67/0x240
> >  do_syscall_64+0xfa/0x760
> >  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> >
> > The below is the user code which triggered that:
> >
> > RIP: 0033:0x7f614bb16047
> >
> > Code: ff ff 73 05 48 83 c4 08 c3 48 8b 0d eb 7d 2e 00 31 d2 48 29 c2 64 89 11 48 83 c8 ff eb e6 90 90 90 90 90 b8 a4 00 00 00 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d c1 7d 2e 00 31 d2 48 29 c2 64
> >
> >   23:   b8 a4 00 00 00          mov    $0xa4,%eax
> >   28:   0f 05                   syscall
> >   2a:*  48 3d 01 f0 ff ff       cmp    $0xfffffffffffff001,%rax
> >   30:   73 01                   jae    0x33
> >   32:   c3                      retq
> >
> > RSP: 002b:00007ffc107dc978 EFLAGS: 00000206 ORIG_RAX: 00000000000000a4
> > RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007f614bb16047
> > RDX: 000000005dcd1ee0 RSI: 00007ffc107dca10 RDI: 00007ffc107dca50
> > RBP: 0000000000000000 R08: 00007ffc107e6080 R09: 0000000000000eca
> > R10: 0000000000000000 R11: 0000000000000206 R12: 0000000000000000
> > R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
> >
> > So RAX is obviously the syscall number and the arguments are in RDI (tv()
> > and RSI (tz), which both look like legit user space addresses.
> >
> > As this is deep in the function prologue compiler/KASAN people might want
> > to have a look at that.
>
> Looks like a plain user memory access:
>
> SYSCALL_DEFINE2(settimeofday, struct __kernel_old_timeval __user *, tv,
> struct timezone __user *, tz)
> {
> ....
> if (tv->tv_usec > USEC_PER_SEC)  // <==== HERE
> return -EINVAL;
>
> Urgently need +Jann's patch to better explain these things!

+Arnd, this does not look right:

commit adde74306a4b05c04dc51f31a08240faf6e97aa9
Author: Arnd Bergmann <arnd@arndb.de>
Date:   Wed Aug 15 20:04:11 2018 +0200

    y2038: time: avoid timespec usage in settimeofday()
...

-               if (!timeval_valid(&user_tv))
+               if (tv->tv_usec > USEC_PER_SEC)
                        return -EINVAL;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bap9wFaOq-3WhO3-QnW7dCFWArvozQHKxBcmzR3wppvFQ%40mail.gmail.com.
