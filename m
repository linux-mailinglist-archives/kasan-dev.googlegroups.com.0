Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ6ZVP4QKGQEW7IVA5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id CC0D123CD70
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Aug 2020 19:31:20 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id k11sf30047207ybp.1
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Aug 2020 10:31:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596648679; cv=pass;
        d=google.com; s=arc-20160816;
        b=RJKzRa7cGCurtjAcl77vCNmb+pJNxZAs8MCXvXtkTM9wSHPpVPl+mYVPG78GIFEVrT
         7E/rIdsdk7TDbDgAgz6zBg9N/AI1zPKSAvYdZwhyEnN2fMvCqMsRbkUME+jRTDaELl4y
         F7zGc+bqKE7LTfR/TCHhqOcQvt8+dgje/xNK2eLDqJH/hR90SUEpCKUpnBnW3U37PQTk
         fhxYbeVhl+BsElqy0U2EFIA0K+KSpczsUSkPgzxA5pHwbwBkF50cqp7hy5sfPyA/FPEm
         gBn7RLjqsm7o4+6hZ9tjtViKIctB6nCDqasqyzoc5gkq0a9QUG2UGS2g5j2VJPtKzQRU
         mFNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GsSsLAyeD9tjMQCC2mW3nmchYS49adV6z0FtlZUV9hk=;
        b=dik4DTkMAzahpasoE35jZTCS2krumYKOQGFGrVpJIN+0mBAqgoRV6iOGbQS2bWyMVh
         1qDhR9f3Li1uwGq/PvWLQ0MJCoqS46EvNXFgJKWw4sK7ZY2kRQoNvf4lYZcLj5kU6uiR
         p1ADL+Hwmr4iVBkJVRes5h3ONPZPUliZpC4m4wsA7D8DINo4Jo+nnl/F8zuYkz6KjBXV
         hHx0iNpufrw0fZJOChpv++GMOYTuy6oJAsRKd4IBMy0H1OAzE/Isyf0kvo9QbgRVrCRl
         7AQGs7BdgLfUiMkj5z7A0TgD38M+0vP/XfW8YJxQTB+sDAhDsqtdadwysiU4y3GEXOet
         nQ3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ghcoPHMA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GsSsLAyeD9tjMQCC2mW3nmchYS49adV6z0FtlZUV9hk=;
        b=gfiKfNYUTg07/tAhnI9N5goJb6N2/7S/fOWl4vUCBcIXji5Mt6MWm1TJAxcHC82iu0
         HgV7G021R2G0xHg/RUVhoMMFuD/xwfZ13Kboyd+rnElDdObesOmkKzaxXSLgLdblWQ6u
         d5t4TLt2gyHS7h7GBXs+PKTpbkWp9K6uS8TFfeH9q5rP6QpI+WZG4t3VvMUFcG0jpnq1
         4ZoHcdC518hSuiId22LIjbmlRexkNAp+1f4tdshrmVIeUUbto38qr69cxmEyxH3a5f1a
         hPpr403E3SjIdQe16WEDwMJ8SJk29SDpad8UQ0Wa4R2VCkTAAB2z5JYhCQXto2TNhCHb
         od5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GsSsLAyeD9tjMQCC2mW3nmchYS49adV6z0FtlZUV9hk=;
        b=eMzKKHndp7oeLXTHO7/fSW4wbpAJSCs05VKYheoqYdNBlyPOUGUgWSD1wqSqr5mKDn
         8Co3mq2/kKllBwPOmJareqwYxxD8OOPknUOwmokZHMG6qYJXGwgCwuSWHK+A30Ar8bgA
         hNeyr/BqJsBc54faklSBnS90vthZeL9EKZqj1c89llnpW8YifGA23jjt65872X7gAtlu
         Zr8EoXwDfl+w9fAegl8UzVyqH1ZcubrNUvGWsRV7zgvZjCziBEaRAVaOQ11sa0+os4DN
         f7WWMpK1UlmQfM8uRI9AwD/JgE5zyC8tKwaXUKNoKcnyp1Ctd5vQB2+WBxEfg6cuuPVH
         KoBw==
X-Gm-Message-State: AOAM53023I19DjOceYrOi2UT/89XZ6l7zO3SnSL+9lX4visH5Zg2C973
	65R7hIZAyFIkxhH6ijcW0/E=
X-Google-Smtp-Source: ABdhPJzDBu1L/HL/hLrMW1lTYQ3z6ByIaBm+PATIgPDSEsi/2edffHWGHCPRkFYSgc82myRTnDkBng==
X-Received: by 2002:a25:8411:: with SMTP id u17mr5085456ybk.95.1596648679655;
        Wed, 05 Aug 2020 10:31:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:dad5:: with SMTP id n204ls1184683ybf.8.gmail; Wed, 05
 Aug 2020 10:31:19 -0700 (PDT)
X-Received: by 2002:a25:5f0c:: with SMTP id t12mr6550861ybb.54.1596648679284;
        Wed, 05 Aug 2020 10:31:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596648679; cv=none;
        d=google.com; s=arc-20160816;
        b=Rxypf6br1KIzmIQstHK4lw15GSqpRy9SAQMvO1Omiz2o7o/zR3tKsQ3TLT6EpTiEPU
         PAZOxNejho4o7AF/blBvCFS/0TQfCIiU3pI4OYDQSQmcgTjC3LXoERX6TLJR8589AgHW
         uqJTXtPSl1RTKXA8nvIJF8+tXb9hdzzSXH/uHmoDREEaXcSG1YRwgTeaQNrLSMlHOyRo
         urer4aQt23daYc1BmhFbFVGqSQb/iKDbQ+V2LP+AsI5OupVx3m+MFGTAI/ReMPvfg5yf
         KLwq213JVshZRzDFOT03+4wiyymhXJ0lU0aCRei7Ppozc3hC69cIlbFlqj+0XJjXfb28
         cTew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=S/ISdwGRB2GCE/7Xam1/dQaAy+/JGNh8/9LD5lfT6Q8=;
        b=JzFDKNp1INdi2RVW2v0xQnaridxoUaBm1y4igr6krW6P0hWxsFEwFyYwEtflCgKkZ0
         bWzC6m0lFSL9UQ/yneW1jujktlyzPuBouxE37S59IrMzeI/e0qBzd5CmiXD2L1heghNJ
         Iu+EepQszP1sVzdAq99jj3eRYl4w+8DhQ3tAVxpNY70sGnqKDTlVUbIhsyt15edp0AqV
         AIpyBqfQC4zt31C+mjGdy0na1MrepqmB2nODaQvZAauNgLyaXekvzvCnkpxsEJu7Q9jG
         1y0Z13GYSbikMMoO2DekVPeXL2C2u6+fid3XLvdS9hTZXVj4lKmpB/oK3yWyQ95N4KTz
         3thQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ghcoPHMA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id k129si186729ybk.1.2020.08.05.10.31.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Aug 2020 10:31:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id z22so9721448oid.1
        for <kasan-dev@googlegroups.com>; Wed, 05 Aug 2020 10:31:19 -0700 (PDT)
X-Received: by 2002:aca:d4d5:: with SMTP id l204mr3765321oig.70.1596648678688;
 Wed, 05 Aug 2020 10:31:18 -0700 (PDT)
MIME-Version: 1.0
References: <0000000000007d3b2d05ac1c303e@google.com> <20200805132629.GA87338@elver.google.com>
 <20200805134232.GR2674@hirez.programming.kicks-ass.net> <20200805135940.GA156343@elver.google.com>
 <20200805141237.GS2674@hirez.programming.kicks-ass.net> <20200805141709.GD35926@hirez.programming.kicks-ass.net>
 <CANpmjNN6FWZ+MsAn3Pj+WEez97diHzqF8hjONtHG15C2gSpSgw@mail.gmail.com>
In-Reply-To: <CANpmjNN6FWZ+MsAn3Pj+WEez97diHzqF8hjONtHG15C2gSpSgw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 Aug 2020 19:31:07 +0200
Message-ID: <CANpmjNNy3XKQqgrjGPPKKvXhAoF=mae7dk8hmoS4k4oNnnB=KA@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=ghcoPHMA;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Wed, 5 Aug 2020 at 16:36, Marco Elver <elver@google.com> wrote:
>
> On Wed, 5 Aug 2020 at 16:17, <peterz@infradead.org> wrote:
> >
> > On Wed, Aug 05, 2020 at 04:12:37PM +0200, peterz@infradead.org wrote:
> > > On Wed, Aug 05, 2020 at 03:59:40PM +0200, Marco Elver wrote:
> > > > On Wed, Aug 05, 2020 at 03:42PM +0200, peterz@infradead.org wrote:
> > >
> > > > > Shouldn't we __always_inline those? They're going to be really small.
> > > >
> > > > I can send a v2, and you can choose. For reference, though:
> > > >
> > > >     ffffffff86271ee0 <arch_local_save_flags>:
> > > >     ffffffff86271ee0:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > > >     ffffffff86271ee5:       48 83 3d 43 87 e4 01    cmpq   $0x0,0x1e48743(%rip)        # ffffffff880ba630 <pv_ops+0x120>
> > > >     ffffffff86271eec:       00
> > > >     ffffffff86271eed:       74 0d                   je     ffffffff86271efc <arch_local_save_flags+0x1c>
> > > >     ffffffff86271eef:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > > >     ffffffff86271ef4:       ff 14 25 30 a6 0b 88    callq  *0xffffffff880ba630
> > > >     ffffffff86271efb:       c3                      retq
> > > >     ffffffff86271efc:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > > >     ffffffff86271f01:       0f 0b                   ud2
> > >
> > > >     ffffffff86271a90 <arch_local_irq_restore>:
> > > >     ffffffff86271a90:       53                      push   %rbx
> > > >     ffffffff86271a91:       48 89 fb                mov    %rdi,%rbx
> > > >     ffffffff86271a94:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > > >     ffffffff86271a99:       48 83 3d 97 8b e4 01    cmpq   $0x0,0x1e48b97(%rip)        # ffffffff880ba638 <pv_ops+0x128>
> > > >     ffffffff86271aa0:       00
> > > >     ffffffff86271aa1:       74 11                   je     ffffffff86271ab4 <arch_local_irq_restore+0x24>
> > > >     ffffffff86271aa3:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > > >     ffffffff86271aa8:       48 89 df                mov    %rbx,%rdi
> > > >     ffffffff86271aab:       ff 14 25 38 a6 0b 88    callq  *0xffffffff880ba638
> > > >     ffffffff86271ab2:       5b                      pop    %rbx
> > > >     ffffffff86271ab3:       c3                      retq
> > > >     ffffffff86271ab4:       0f 1f 44 00 00          nopl   0x0(%rax,%rax,1)
> > > >     ffffffff86271ab9:       0f 0b                   ud2
> > >
> > >
> > > Blergh, that's abysmall. In part I suspect because you have
> > > CONFIG_PARAVIRT_DEBUG, let me try and untangle that PV macro maze.
> >
> > Yeah, look here:
> >
> > 0000 0000000000462149 <arch_local_save_flags>:
> > 0000   462149:  ff 14 25 00 00 00 00    callq  *0x0
> > 0003                    46214c: R_X86_64_32S    pv_ops+0x120
> > 0007   462150:  c3                      retq
> >
> >
> > That's exactly what I was expecting.
>
> Ah, for some reason the __always_inline version does *not* work with
> KCSAN -- I'm getting various warnings, including the same lockdep
> warning. I think there is some weirdness when this stuff gets inlined
> into instrumented functions. At least with KCSAN, when any accesses
> here are instrumented, and then KCSAN disable/enables interrupts,
> things break. So, these functions should never be instrumented,
> noinstr or not. Marking them 'inline noinstr' seems like the safest
> option. Without CONFIG_PARAVIRT_DEBUG, any compiler should hopefully
> inline them?

Oh well, it seems that KCSAN on syzbot still crashes even with this
"fix". It's harder to reproduce though, and I don't have a clear
reproducer other than "fuzz the kernel" right now. I think the new IRQ
state tracking code is still not compatible with KCSAN, even though we
thought it would be. Most likely there are still ways to get recursion
lockdep->KCSAN. An alternative would be to deal with the recursion
like we did before, instead of trying to squash all of it. I'll try to
investigate -- Peter, if you have ideas, help is appreciated.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNy3XKQqgrjGPPKKvXhAoF%3Dmae7dk8hmoS4k4oNnnB%3DKA%40mail.gmail.com.
