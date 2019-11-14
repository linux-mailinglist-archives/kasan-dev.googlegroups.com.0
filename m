Return-Path: <kasan-dev+bncBDAMN6NI5EERBHEUWXXAKGQEMFS3ZTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id C2B3EFC666
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 13:35:40 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id h191sf3851910wme.5
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 04:35:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573734940; cv=pass;
        d=google.com; s=arc-20160816;
        b=B3wKfMQrPeAcmqYaegZaRrBL9UDD+5+PPac2kYMAzKZ1IXzLok0rLZqMOadKlRDreh
         MMfcX6zHnXvcEmJiYI767lMn/2eRauRrDVDAgJyZU4b8A1LIwn0lYYxds98kf17OAjw1
         6AlY/SlW9KDXcurk6EUaTij+Ajl0PZFyYYO9pWCQVuantjtC+JPtByn55TXmF+12/Hv6
         kFlaPEGfsYlHq8KjfW2lu7Vyf8cWBIWiM97pvy72FHFICU46vxgn6Zh0eF2q8MEFxBuO
         Jol7BMVDPKfG9YVgFKCdwQWGlqrDaeTL/FcCRf7R+5w/N1Mi8J6cc9X7dyBaHBnNVRDy
         lvLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=a1yn95gvL2Ose35huZWDoHOekbnAhfW0/OBNS1xI+Ck=;
        b=pHhjHFl+wjcpv7ElBMdOcDsAouy/MReGPwi6dKu16z0qmb2HkJa8pDse7HafIWVo9y
         GkXMJPeK0LT+QOyHCGTC3x6hFtoxKwEH8ioEb0yo554IgVeKdx2BTez+Uwa32JJ3B98N
         gRpgw4sr/t8zAXv3PNJbLb7TIYl7eWS+km2BU5Udabr50xyYfeSr0XYj2Gi+ZH6BYTXn
         QxeFvExqLOgnF+dO+WdHvbH4YutBc5fqzt/TM1vPCcDdeqPf1QDkYG4p6/hdGU3Ux0kx
         NeyJa7OparjyoizRu27i0YxGVQ6L08zWQDdmfTlQEr0htCrJPPaOxPVpLPyRbhMcsFRA
         eTzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=a1yn95gvL2Ose35huZWDoHOekbnAhfW0/OBNS1xI+Ck=;
        b=LAMEHDAUD97TD3levj020smZs4P1wYRsh29e2lM6+6rOMkFpI7ZYAPooSXkOLWHnTj
         OMUABEfRSUdpiNOIKve54gBmtmMAGBYyk/H0284JjqxlQVQrSqGHBAQ3Eyd+oyvMRoDC
         1JaVM8S7cXKVOWNcnIjbg6tQ9B4QN5/6cYxoo1dAYIG2QwNuJUdwV3G7Lmmh3SbIF9m/
         Hl2dc9dq68snEiROBkQZK7ozL44W9hqP7lZ3JCw7v/f56GdP8f3X57QVo0DQH20sKQ9o
         E1o6Az4K3W7b9YmlcG6swx/0Yzyni5ak1LYt9g1wxcYhz3Z52ZY+3fDOtlgHXrbt/hDj
         yI2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a1yn95gvL2Ose35huZWDoHOekbnAhfW0/OBNS1xI+Ck=;
        b=RLI2avCb5v7E0vMSrGEcQXBUYMj3ok2APnkG/B9Lr+1QpuBbjkFcHPmAWDAmv5DIEJ
         ju8uOp/E2BdDDcoZ54cekkCZiY7qdNSjYiYGVkOEoiZPyFJ7QKfLjLlON8eu6oP5IOfO
         wR5Lv6wj6aY6hLMQWIQGDSs7NJ8KE8rvq4L5G2y4K3NzTV6CxluaxrMaWwdjLBZQj9Z0
         UHDcB/RHT09hHlchrNPUkBBC3ylWacWK8TGq5PH5TL4SBcp9oGPt+lNpTtMZyuC6LOPZ
         Vb68mpjo1nhxEMlxhI6S1QwV0C20aC4bFU1ODYKe8St+n1ufhVXuNj07QMIIlkxZ+cgu
         6wiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXD9BK3rCOAKRD24I5xeaC03iibCIkRHuIH2gsah1TdROcHMA05
	T75FjqA2nz017qmLftkTfTo=
X-Google-Smtp-Source: APXvYqyKuv92WhOyKmnDpsa34lzm1xTDM0dJQUUcNqZIEcF9c+KimLt/z1GlTTQhK2fCQLoCvrYtog==
X-Received: by 2002:a7b:c3d6:: with SMTP id t22mr7957200wmj.13.1573734940425;
        Thu, 14 Nov 2019 04:35:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7406:: with SMTP id p6ls8966988wmc.2.gmail; Thu, 14 Nov
 2019 04:35:39 -0800 (PST)
X-Received: by 2002:a1c:998f:: with SMTP id b137mr8031271wme.104.1573734939928;
        Thu, 14 Nov 2019 04:35:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573734939; cv=none;
        d=google.com; s=arc-20160816;
        b=DMukEhKrzmjsdcs+aU3i3L1HfT5yuEji8hw/E0bcikP3xbs5T9p+F/q1IeJkMcAjoW
         Z7VDN/ANSGjUcQtwzUVJZ561VJutfApMim9unKqbjq5wq2EPL71Suf/z7Ngv/iO4/cvj
         97lL/pPSxRo/cDUIXNAbQV5Xtwst2GCwRzELZ53q/zrqia3xYZdmYyhJ+11XmDtfqy9l
         mY5AEEBq70mdZGybQK9hcfwSJwT0dwFSlaRLegOILnTAow9c9DIjCW7lTKLfQJBaj6fa
         pLUstzOBq2f3ix46dBaTutHSBDEWOn9m1WMRLAhq0qpKxJ65481s4BNrWP5rr5ASw6yu
         qBWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date;
        bh=mJNXdpsEso0z9AxnOIzm3WW8BN59O0bAxXEMLS/old4=;
        b=qqs77WLpd4tbXOzxX93JMBB67+QnE4lFIYnNOmL0ONcE4ySCAFSOzx0BR78b0vssvA
         7tYOZ97GLN/Wy8sG/A+VWr2gIwkW7HSahiiXAuNSqlMlogaS1/Gk3uL9ePPiuACPyAuX
         q0y4s+hjFAOyJJ4LyO0nSrb/Lf4W6z3Gw5oT++++L2DerfbTTmoeZYpMUJEiHKfHbTmp
         0HOLSo+HiWajpYmcXz8ZSUCm2WaZehozW+AFuhyXH5/nb9vOU1uNdFDmz7TRz5sUomh/
         M09+BIxKNJILdrumTkWVzKC+PtKxWavcHYbVSPIoC6wT1kjIj9B9cMsu2iI1L3zNu9VB
         KW+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de
Received: from Galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id w6si619914wmk.3.2019.11.14.04.35.39
        (version=TLS1_2 cipher=AES128-SHA bits=128/128);
        Thu, 14 Nov 2019 04:35:39 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Received: from [5.158.153.52] (helo=nanos.tec.linutronix.de)
	by Galois.linutronix.de with esmtpsa (TLS1.2:DHE_RSA_AES_256_CBC_SHA256:256)
	(Exim 4.80)
	(envelope-from <tglx@linutronix.de>)
	id 1iVELY-0001tY-2R; Thu, 14 Nov 2019 13:35:36 +0100
Date: Thu, 14 Nov 2019 13:35:35 +0100 (CET)
From: Thomas Gleixner <tglx@linutronix.de>
To: syzbot <syzbot+dccce9b26ba09ca49966@syzkaller.appspotmail.com>
cc: John Stultz <john.stultz@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
    sboyd@kernel.org, syzkaller-bugs@googlegroups.com, x86@kernel.org, 
    kasan-dev@googlegroups.com
Subject: Re: linux-next boot error: general protection fault in
 __x64_sys_settimeofday
In-Reply-To: <0000000000007ce85705974c50e5@google.com>
Message-ID: <alpine.DEB.2.21.1911141210410.2507@nanos.tec.linutronix.de>
References: <0000000000007ce85705974c50e5@google.com>
User-Agent: Alpine 2.21 (DEB 202 2017-01-01)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of tglx@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de
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

On Thu, 14 Nov 2019, syzbot wrote:

From the full console output:

kasan: CONFIG_KASAN_INLINE enabled
kasan: GPF could be caused by NULL-ptr deref or user memory access
general protection fault: 0000 [#1] PREEMPT SMP KASAN
RIP: 0010:__x64_sys_settimeofday+0x170/0x320 

Code: 85 50 ff ff ff 85 c0 0f 85 50 01 00 00 e8 b8 cd 10 00 48 8b 85 48 ff ff ff 48 c1 e8 03 48 89 c2 48 b8 00 00 00 00 00 fc ff df <80> 3c 02 00 0f 85 8a 01 00 00 49 8b 74 24 08 bf 40 42 0f 00 48 89

      80 3c 02 00             cmpb   $0x0,(%rdx,%rax,1)

RSP: 0018:ffff888093d0fe58 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: 1ffff110127a1fcd RCX: ffffffff8162e915
RDX: 00000fff820fb94b RSI: ffffffff8162e928 RDI: 0000000000000005

i.e.
	
     *(0x00000fff820fb94b + 0xdffffc0000000000 * 1) == 0

     *(0xe0000bff820fb94b) == 0

So base == 0x00000fff820fb94b and index == 0xdffffc0000000000 and scale =
1. As scale is 1, base and index might be swapped, but that still does not
make any sense.

0xdffffc0000000000 is explicitely loaded into RAX according to the
disassembly, but I can't find the corresponding source as this is in the
middle of the function prologue and looks KASAN related.

RBP: ffff888093d0ff10 R08: ffff8880a8904380 R09: ffff8880a8904c18
R10: fffffbfff1390d30 R11: ffffffff89c86987 R12: 00007ffc107dca50
R13: ffff888093d0fee8 R14: 00007ffc107dca10 R15: 0000000000087a85
FS:  00007f614c01b700(0000) GS:ffff8880ae800000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00007f4440cdf000 CR3: 00000000a5236000 CR4: 00000000001406f0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
Call Trace:
 ? do_sys_settimeofday64+0x250/0x250
 ? trace_hardirqs_on_thunk+0x1a/0x1c
 ? do_syscall_64+0x26/0x760
 ? entry_SYSCALL_64_after_hwframe+0x49/0xbe
 ? do_syscall_64+0x26/0x760
 ? lockdep_hardirqs_on+0x421/0x5e0
 ? trace_hardirqs_on+0x67/0x240
 do_syscall_64+0xfa/0x760
 entry_SYSCALL_64_after_hwframe+0x49/0xbe

The below is the user code which triggered that:

RIP: 0033:0x7f614bb16047

Code: ff ff 73 05 48 83 c4 08 c3 48 8b 0d eb 7d 2e 00 31 d2 48 29 c2 64 89 11 48 83 c8 ff eb e6 90 90 90 90 90 b8 a4 00 00 00 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d c1 7d 2e 00 31 d2 48 29 c2 64

  23:   b8 a4 00 00 00          mov    $0xa4,%eax
  28:   0f 05                   syscall
  2a:*  48 3d 01 f0 ff ff       cmp    $0xfffffffffffff001,%rax
  30:   73 01                   jae    0x33
  32:   c3                      retq

RSP: 002b:00007ffc107dc978 EFLAGS: 00000206 ORIG_RAX: 00000000000000a4
RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007f614bb16047
RDX: 000000005dcd1ee0 RSI: 00007ffc107dca10 RDI: 00007ffc107dca50
RBP: 0000000000000000 R08: 00007ffc107e6080 R09: 0000000000000eca
R10: 0000000000000000 R11: 0000000000000206 R12: 0000000000000000
R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000

So RAX is obviously the syscall number and the arguments are in RDI (tv()
and RSI (tz), which both look like legit user space addresses.

As this is deep in the function prologue compiler/KASAN people might want
to have a look at that.

Thanks,

	tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.DEB.2.21.1911141210410.2507%40nanos.tec.linutronix.de.
