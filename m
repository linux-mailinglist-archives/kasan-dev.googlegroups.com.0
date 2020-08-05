Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2UHVP4QKGQECJ6XX2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 09CA323CB86
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Aug 2020 16:36:28 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id t2sf18507070plq.10
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Aug 2020 07:36:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596638186; cv=pass;
        d=google.com; s=arc-20160816;
        b=o7oBAIdOzfp3wZIXdRuLFkSGKKpO8U2B0zRs5hfJq5CweDqxcow0IJrYohp47pCeLV
         SN+R9Z0AbTt0eUnDJEq5jgfnMQ0flv59zzr4fkO6du06YJchdkSGpJRb2YXPhtK0uBif
         x4WxUY7XLT6a155oGFA0p6HamuU8nxNRhef3J9EBkSz1unhe1mg9ESRBeCAHONKsXLbJ
         3+U0sjQgF0onMjwQZ3W5XEn6Y/8qCUeSupFmObrEyj5PRKGR4tVYZaD9KdSrXJU3TVyA
         VrroBE6T5TFwAEOaM06NGr6hWtRdI80+lg0PvwvulP/u2ACOT3qOYeR3jnCFk9kvFDo8
         XInA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+uczM4O6ECVIpoB3K4GkIZ4ofu76zGvCb3Og09jLcXE=;
        b=E+ftwEA8xSldN/N0jHJUHHh6D3Q3BJ4/yFWNEdlf2dNQWLBmlrGS9Cj2GmWQmmAXBW
         wdtDUd9CeLygU6Lg/azK/bHos+7+p2MSU5g44XOXUG4x9w4Z7A0Y4bsV3nhrDUkSJjor
         ZAEsu2Cb8kRplWcfL03nnkYD13j1Z0tavmUuz3qmrGE+64BULAIwdoLv7MAOJhFG3tm6
         hp+LL1G7DCZbGqQq8PDY5AW5sDqrm6KgCwpWOUghHnEq67MDO2Lucs5XPk7jEH5qKrTL
         uPFCIpW+TfQCAEfPUAa9VrMlXiM1L131M73N6BwYpGlgvHueZ/bNr9hctXSF2n225kVo
         /svw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j1JMhs8V;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+uczM4O6ECVIpoB3K4GkIZ4ofu76zGvCb3Og09jLcXE=;
        b=ZZOO9mHd+PPrO2MzwLGRRqj98NQdzGv71eyvkDgYhtituzjP82H3RK7FnhOxE+wJGl
         s87Hq28wYSO9Q85O7pME/QbD8enyEk4PGiyrDydGGh8JjfWFsAq77frAny0giuPIATES
         Gcgb95Lor/eR5wSY/t6Mp24hVxe05nqxvbUh1CYZ59q39fC+l4YwonM6uELO+eBM44GJ
         gL5lNT5L/tBRiysmHRx8M/oOdMMoGdZ0pEI+Ra2ApUJNTzr2PC1710lVBpnHE+aQJBMk
         l0HrG9yhq/NtR4YcXtCwWSskYK3AafnEaZpJqerOKG8I26LlOQq7V6vXfCyMXiOtu48B
         Z10Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+uczM4O6ECVIpoB3K4GkIZ4ofu76zGvCb3Og09jLcXE=;
        b=LrfbNVq5By7y8pbqUN++CXQY86m0xlsiQ1tnV8nZdxcFzph+VchKg9H5+PiPIwbk5U
         njYODxvoIC/35PG/v6jjEHv1uLKN81oC2dJoj/L53mykIdGQ8PQqGm9qSA3Ntcx5xpM4
         jh274x25/C58KjThWqpSJ7ed5r0SMfWQsNzkCkJuqiZrX8axZAegZbNVn1UXpqHCgHP1
         0vXeRq3ZeezdxtiK0YIc26m5TknNfGJIiQoMJHrj2nZ++cnMr4U8Ds75lrpm+b7XnDD/
         8ttNE0FZ2SH0S5gsS9H+jnZCcLHdAI3cWtv4Fbj00OoUJkNeKjJ8Vyv0sk5M30s/N5qO
         H3IA==
X-Gm-Message-State: AOAM532kgUkpkk4gvCs3fhgKQE6t4QVziqBlneNznm1VWGLTuz3chkQi
	Vc9qJEhbAN0xUQ/45xMa8aE=
X-Google-Smtp-Source: ABdhPJy/Tcm956gY8FWGx4lFQpz8VE3Os/YQMKx3cvqfF0Od59dH0rqqWL3VJhv6aH1b9ZEZIxqHEw==
X-Received: by 2002:aa7:9519:: with SMTP id b25mr3620907pfp.292.1596638186723;
        Wed, 05 Aug 2020 07:36:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b602:: with SMTP id b2ls1147404pls.11.gmail; Wed, 05
 Aug 2020 07:36:26 -0700 (PDT)
X-Received: by 2002:a17:90a:3509:: with SMTP id q9mr3859034pjb.190.1596638186287;
        Wed, 05 Aug 2020 07:36:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596638186; cv=none;
        d=google.com; s=arc-20160816;
        b=ob+boEBsXilxK7Qjc2FBrUsovez0TxQTCH98zazToY+VKkYA8jTPAnWWqF89pMy75C
         lsIhZqgOCi8Q7r+COMjKNuUHsU1U+tjFMGV89oBASH/PP7wdvb5cnbirGva49JOsIhv9
         XdENrY0DO2xtkygXC6YADvXTerqTG1EWqlyELBfMdXV9pV5j4omAEdMvNhdGJqOrSuPz
         eXojDKIxi6YUEyDpp7s4FFWnrvgCn6ePuqSEnZOYO+FEZIpmI+sfZKJiWuxMlZ10s6xM
         ntDcwKlB2mQ/fi836B5lL9R/Eqhk9+SkLLgbU6jWbgCoxmX5zjBpRSUsu4TWEqLLVixQ
         7jpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nPbiD7579GQktE8TnDJJA8yObifQYqFq9LVQt+NlZPM=;
        b=K+L5RZVB8IihiZPWLd25RXm8EWTy97aTc18ofST/vblo4BjiLJHcxlEMt7m888vxVP
         QvjsH9ef1YvyNThxqJMQnV4OU2CWczOQHsG32C6HUilclKWN93mARbkIuz9owzlW3U+t
         MWCwHcmj1p3z1eU6IqUQjhX/eb68gSAko57eRpcuiWY8c4tLUtcU8A+3hLpdyj0xBEVf
         SsqWTgOVlASSl/3/kaNOyh7qW7qsKKVndYeCKDGsApG6NjG5+YW7+wiTFdTZi1WAET22
         DNPH7dfd0TRICcjtIpBe+/0DC4ysUcW/CkWO9PaqspewRuwjTy9z0K9z+jmKJgUXdrR+
         D4CA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=j1JMhs8V;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc41.google.com (mail-oo1-xc41.google.com. [2607:f8b0:4864:20::c41])
        by gmr-mx.google.com with ESMTPS id h41si337058pje.0.2020.08.05.07.36.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Aug 2020 07:36:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) client-ip=2607:f8b0:4864:20::c41;
Received: by mail-oo1-xc41.google.com with SMTP id k63so5972831oob.1
        for <kasan-dev@googlegroups.com>; Wed, 05 Aug 2020 07:36:26 -0700 (PDT)
X-Received: by 2002:a4a:a648:: with SMTP id j8mr3132445oom.36.1596638185370;
 Wed, 05 Aug 2020 07:36:25 -0700 (PDT)
MIME-Version: 1.0
References: <0000000000007d3b2d05ac1c303e@google.com> <20200805132629.GA87338@elver.google.com>
 <20200805134232.GR2674@hirez.programming.kicks-ass.net> <20200805135940.GA156343@elver.google.com>
 <20200805141237.GS2674@hirez.programming.kicks-ass.net> <20200805141709.GD35926@hirez.programming.kicks-ass.net>
In-Reply-To: <20200805141709.GD35926@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 Aug 2020 16:36:12 +0200
Message-ID: <CANpmjNN6FWZ+MsAn3Pj+WEez97diHzqF8hjONtHG15C2gSpSgw@mail.gmail.com>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*() helpers
To: Peter Zijlstra <peterz@infradead.org>
Cc: Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, fenghua.yu@intel.com, 
	"H. Peter Anvin" <hpa@zytor.com>, LKML <linux-kernel@vger.kernel.org>, 
	Ingo Molnar <mingo@redhat.com>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	Thomas Gleixner <tglx@linutronix.de>, "Luck, Tony" <tony.luck@intel.com>, 
	"the arch/x86 maintainers" <x86@kernel.org>, yu-cheng.yu@intel.com, jgross@suse.com, sdeep@vmware.com, 
	virtualization@lists.linux-foundation.org, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=j1JMhs8V;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 5 Aug 2020 at 16:17, <peterz@infradead.org> wrote:
>
> On Wed, Aug 05, 2020 at 04:12:37PM +0200, peterz@infradead.org wrote:
> > On Wed, Aug 05, 2020 at 03:59:40PM +0200, Marco Elver wrote:
> > > On Wed, Aug 05, 2020 at 03:42PM +0200, peterz@infradead.org wrote:
> >
> > > > Shouldn't we __always_inline those? They're going to be really small.
> > >
> > > I can send a v2, and you can choose. For reference, though:
> > >
> > >     ffffffff86271ee0 <arch_local_save_flags>:
> > >     ffffffff86271ee0:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > >     ffffffff86271ee5:       48 83 3d 43 87 e4 01    cmpq   $0x0,0x1e48743(%rip)        # ffffffff880ba630 <pv_ops+0x120>
> > >     ffffffff86271eec:       00
> > >     ffffffff86271eed:       74 0d                   je     ffffffff86271efc <arch_local_save_flags+0x1c>
> > >     ffffffff86271eef:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > >     ffffffff86271ef4:       ff 14 25 30 a6 0b 88    callq  *0xffffffff880ba630
> > >     ffffffff86271efb:       c3                      retq
> > >     ffffffff86271efc:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > >     ffffffff86271f01:       0f 0b                   ud2
> >
> > >     ffffffff86271a90 <arch_local_irq_restore>:
> > >     ffffffff86271a90:       53                      push   %rbx
> > >     ffffffff86271a91:       48 89 fb                mov    %rdi,%rbx
> > >     ffffffff86271a94:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > >     ffffffff86271a99:       48 83 3d 97 8b e4 01    cmpq   $0x0,0x1e48b97(%rip)        # ffffffff880ba638 <pv_ops+0x128>
> > >     ffffffff86271aa0:       00
> > >     ffffffff86271aa1:       74 11                   je     ffffffff86271ab4 <arch_local_irq_restore+0x24>
> > >     ffffffff86271aa3:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > >     ffffffff86271aa8:       48 89 df                mov    %rbx,%rdi
> > >     ffffffff86271aab:       ff 14 25 38 a6 0b 88    callq  *0xffffffff880ba638
> > >     ffffffff86271ab2:       5b                      pop    %rbx
> > >     ffffffff86271ab3:       c3                      retq
> > >     ffffffff86271ab4:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > >     ffffffff86271ab9:       0f 0b                   ud2
> >
> >
> > Blergh, that's abysmall. In part I suspect because you have
> > CONFIG_PARAVIRT_DEBUG, let me try and untangle that PV macro maze.
>
> Yeah, look here:
>
> 0000 0000000000462149 <arch_local_save_flags>:
> 0000   462149:  ff 14 25 00 00 00 00    callq  *0x0
> 0003                    46214c: R_X86_64_32S    pv_ops+0x120
> 0007   462150:  c3                      retq
>
>
> That's exactly what I was expecting.

Ah, for some reason the __always_inline version does *not* work with
KCSAN -- I'm getting various warnings, including the same lockdep
warning. I think there is some weirdness when this stuff gets inlined
into instrumented functions. At least with KCSAN, when any accesses
here are instrumented, and then KCSAN disable/enables interrupts,
things break. So, these functions should never be instrumented,
noinstr or not. Marking them 'inline noinstr' seems like the safest
option. Without CONFIG_PARAVIRT_DEBUG, any compiler should hopefully
inline them?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN6FWZ%2BMsAn3Pj%2BWEez97diHzqF8hjONtHG15C2gSpSgw%40mail.gmail.com.
