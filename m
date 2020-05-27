Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMXDXH3AKGQEKUQ766I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id E01CD1E44C7
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 15:57:07 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id 184sf17076052iow.10
        for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 06:57:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590587826; cv=pass;
        d=google.com; s=arc-20160816;
        b=oftd/AjarRf+TkqV6I2O/ynh59euoNrw1VVxApHQzmYkQiVkrzh1PPaM82MOSsmB1Z
         f4hsf9a8RGeJ31BVSCJmLx4Nn4aX+OD8zj8tLW3slWeXAbovW0giEKSKxZek5ByFDVb1
         H/rw8NX0rzLLNEfIueA3vB5kNC+mcQhlT/ZEx4/M9ha5rMIQBftIpTPipeIeZrWWgqoR
         x8FOxZDnbOfGo3RYaXWmr9oSa70ZyXNVSKYvd+ngptKMLHp4kOS99vd1f7DGfGCyH23A
         uV1cc/gNEwZui+syhsKUNFy96xvab8PofGxZX4MEr7F9T1qoJ4gisRc+fG04dmwtkrul
         e6kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=b4j5SCNOgWAORRI1c+/9+X5u7zKZmgCJsb78568QceA=;
        b=y8pi4L1UjHyPu1fsrJ3PYcXKVtTxacd2gzDd02XMYA7V7N1e5EagHmTedMgEeeQkLi
         odhvfWeIYY13wcm1XTR6XnXRkqeGGP+KAXq7yJVDqtmT57EQFGa2jsORewDq0IHlX5nJ
         +SA7QyF9ddkVB8CF2oiGGiZ/DO2b3DmrMxLIsTqJ6wWuJMldc88EGHG+Yw/dpAd2r9WP
         f6uWfeK5En8wVywuBwdZF2BPBJeZWNcszEtg+PlGIMvdcgYYvn6SQIfwCAvlcYdBYks6
         HRbVIbCvImd7f86aaGeayYLFyaQja6iwaGfdchue+phdPSK7UXVQzRucp5O5hBXVUP5n
         X1pw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Hcywj/S6";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b4j5SCNOgWAORRI1c+/9+X5u7zKZmgCJsb78568QceA=;
        b=HlP0LyNozhaOjXR7vp8m8LrVoXNi/HOpgZhOW1dEkkfCVG2U8OY2mxRrWFayy1AAZG
         QiS7L6+2qs5eVS3RvxFKPRb8S1fBN0+aCSVyFK8GgSRm2Hh9OWckSG4x8MddRmENpaQA
         6YRepXRWscR/855d2uhAHwo+XLU9iYfmZ8CYDrH5+CX8ya9RLXwUcINlllfZ4cDzN7pA
         sBsxtjpw9lndwq3Ivefnbk1td+r8Iy5aLg+52Br31dA/7o12Ki0LvFh+IHwmMoDHFVbi
         ut6YFxWwfQEaTU4gJQ7yV9QkrnKlgLTbdIwA4S6Yv+RzT3r4qEv0JA7nyhu3cBvXe39u
         WDXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b4j5SCNOgWAORRI1c+/9+X5u7zKZmgCJsb78568QceA=;
        b=KTP2BKZgx2xVoLRC3GsXHjb1AsIHbI68jZqQ7Stt5iaInZb/vSE/dtbdnu/OtDundU
         H3Tyjaxcu4uNRhz+LniIq8s0qndTGdfxL7yc6/+tp8b4yYK6F5v7erkwie1UnGLyU3FE
         zfQ1Fr3g6eUC/fmBbwA0baMx3ict8m2rrbVH7jZXxzNe+gfNOjtnB+8mkBnDCEOB1ZDE
         pqbSQlRANSLjOmGnCK6n3iubfsVyypYc0hwGeAclzXP9ZQyTlHvFJvuQhIFyJxdHaZ20
         GpdcatCwY55l2fq9LAjLKK/6JQ1zLT6dppAivTsMKoLRpaspvCnLkKl1q+UF6kqzMVBY
         hpPg==
X-Gm-Message-State: AOAM532/GAp0D/MKDseg9VFQYCquq9aBq4iB279gfvkC9PkYue/9oG5c
	9XAyhVYfJ4/++7hQiRAjnj0=
X-Google-Smtp-Source: ABdhPJwPuut+ghSP/yTrlu0SN7dQiEELvidRqQtLWEJ9N6pXc/PNMDYh2CDDjDNPyohemiwrd8faGg==
X-Received: by 2002:a6b:7841:: with SMTP id h1mr21274541iop.101.1590587826535;
        Wed, 27 May 2020 06:57:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:9716:: with SMTP id x22ls231539jai.3.gmail; Wed, 27 May
 2020 06:57:06 -0700 (PDT)
X-Received: by 2002:a02:a99a:: with SMTP id q26mr5473560jam.61.1590587826069;
        Wed, 27 May 2020 06:57:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590587826; cv=none;
        d=google.com; s=arc-20160816;
        b=TUx3aTHXhSj/IcKMkl+UE1HvynBjKkYLIahbn2ZXnIkfhtb5Fnm9K09fttRgdtUMn3
         4gDIbqCslJo4dIIEMudomLE5kR5qDlIUZg+0+C7vhJrQNtKFYWQC5+ZJ801J5NqhTAWq
         lBbki0rdbMXX/D3ndNz5wmbrvx0gxEdkxnhutaRC33GASoNoCTyPN1AYMIvQUieX+fq6
         795VwOrA5sbzX8OGslZ2Q7Jvu8ezq4Xs5hf12G/bQTYod3MuckGrBSrDgtjM0na8Mrp3
         8rC+TJuou+IfFAPmxOVq/0I2PBi+38XVGLbhC3PEW4IOXzEBCT9JrTHJMsk7600djHn/
         HuzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IdFFnED2awUw3pJ4+j8OXoHJjtxYorX0jVxetfYLfoE=;
        b=O1FHNXbELkd/fExcXy1xES5UmzDScTK3CqFTwzS/vIxMGIRM7w3IFWxs6l9PD5gNUQ
         dntMBwkx2C+Reh7L440Ahj3/6ts9Fbr8ZjU6pvqlVEZwYu4oh93I25Rj0kSejYZgHOs3
         IwQRHKLZFYmGTflAs6ZgG1AK7xK6lv58NEk7BcO/j5McMWemmw82viT84pFhPM+OXrR7
         tqARjMbEXWphRgf28oA7A//oKofj0aCIcgj5nyz1Z7Svcmpwx2PTC1ga5atUdNuYVIET
         zHxAr0ZUqJZiV7jjfv17uxvmW1+r61A+kQVGzfGXSHEOHlq17WovLh079aJcrSRHPCy9
         9SEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Hcywj/S6";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id d3si168746ilg.0.2020.05.27.06.57.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 May 2020 06:57:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id i22so21756650oik.10
        for <kasan-dev@googlegroups.com>; Wed, 27 May 2020 06:57:06 -0700 (PDT)
X-Received: by 2002:aca:6747:: with SMTP id b7mr2844571oiy.121.1590587825434;
 Wed, 27 May 2020 06:57:05 -0700 (PDT)
MIME-Version: 1.0
References: <20200527103236.148700-1-elver@google.com> <CAK8P3a1MFgRxm6=+9WZKNzN+Nc5fhrDso6orSNQaaa-0yqygYA@mail.gmail.com>
 <CA+icZUWtzu0ONUSy0E27Mq1BrdO79qNaY3Si-PDhHZyF8M4S5g@mail.gmail.com>
 <CAK8P3a04=mVQgSrvDhpVxQj50JEFDn_xMhYrvjmUnLYTWH3QXQ@mail.gmail.com>
 <CA+icZUXVSTxDYJwXLyAwZd91cjMPcPRpeAR72JKqkqa-wRNnWg@mail.gmail.com>
 <CAK8P3a3i0kPf8dRg7Ko-33hsb+LkP=P05uz2tGvg5B43O-hFvg@mail.gmail.com>
 <CA+icZUWr5xDz5ujBfsXjnDdiBuopaGE6xO5LJQP9_y=YoROb+Q@mail.gmail.com>
 <CANpmjNOtKQAB_3t1G5Da-J1k-9Dk6eQKP+xNozRbmHJXZqXGFw@mail.gmail.com> <CA+icZUWzPMOj+qsDz-5Z3tD-hX5gcowjBkwYyiy8SL36Jg+2Nw@mail.gmail.com>
In-Reply-To: <CA+icZUWzPMOj+qsDz-5Z3tD-hX5gcowjBkwYyiy8SL36Jg+2Nw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 May 2020 15:56:53 +0200
Message-ID: <CANpmjNOPcFSr2n_ro8TqhOBXOBfUY0vZtj_VT7hh3HOhJN4BqQ@mail.gmail.com>
Subject: Re: [PATCH -tip] compiler_types.h: Optimize __unqual_scalar_typeof
 compilation time
To: sedat.dilek@gmail.com
Cc: Arnd Bergmann <arnd@arndb.de>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Hcywj/S6";       spf=pass
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

On Wed, 27 May 2020 at 15:37, Sedat Dilek <sedat.dilek@gmail.com> wrote:
>
> On Wed, May 27, 2020 at 3:30 PM Marco Elver <elver@google.com> wrote:
> >
> > On Wed, 27 May 2020 at 15:11, Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > >
> > > On Wed, May 27, 2020 at 2:50 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > >
> > > > On Wed, May 27, 2020 at 2:35 PM Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > > > > On Wed, May 27, 2020 at 2:31 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > > > > On Wed, May 27, 2020 at 1:36 PM Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > > > > > > On Wed, May 27, 2020 at 1:27 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > > > > > > On Wed, May 27, 2020 at 12:33 PM Marco Elver <elver@google.com> wrote:
> > > > > > > >
> > > > > > > > This gives us back 80% of the performance drop on clang, and 50%
> > > > > > > > of the drop I saw with gcc, compared to current mainline.
> > > > > > > >
> > > > > > > > Tested-by: Arnd Bergmann <arnd@arndb.de>
> > > > > > > >
> > > > > > >
> > > > > > > Hi Arnd,
> > > > > > >
> > > > > > > with "mainline" you mean Linux-next aka Linux v5.8 - not v5.7?
> > > > > >
> > > > > > I meant v5.7.
> > > > > >
> > > > > > > I have not seen __unqual_scalar_typeof(x) in compiler_types.h in Linux v5.7.
> > > > > > >
> > > > > > > Is there a speedup benefit also for Linux v5.7?
> > > > > > > Which patches do I need?
> > > > > >
> > > > > > v5.7-rc is the baseline and is the fastest I currently see. On certain files,
> > > > > > I saw an intermittent 10x slowdown that was already fixed earlier, now
> > > > > > linux-next
> > > > > > is more like 2x slowdown for me and 1.2x with this patch on top, so we're
> > > > > > almost back to the speed of linux-5.7.
> > > > > >
> > > > >
> > > > > Which clang version did you use - and have you set KCSAN kconfigs -
> > > > > AFAICS this needs clang-11?
> > > >
> > > > I'm currently using clang-11, but I see the same problem with older
> > > > versions, and both with and without KCSAN enabled. I think the issue
> > > > is mostly the deep nesting of macros that leads to code bloat.
> > > >
> > >
> > > Thanks.
> > >
> > > With clang-10:
> > >
> > > $ scripts/diffconfig /boot/config-5.7.0-rc7-2-amd64-clang .config
> > >  BUILD_SALT "5.7.0-rc7-2-amd64-clang" -> "5.7.0-rc7-3-amd64-clang"
> > > +HAVE_ARCH_KCSAN y
> >
> > Clang 10 doesn't support KCSAN (HAVE_KCSAN_COMPILER unset).
> >
> > > With clang-11:
> > >
> > > $ scripts/diffconfig /boot/config-5.7.0-rc7-2-amd64-clang .config
> > >  BUILD_SALT "5.7.0-rc7-2-amd64-clang" -> "5.7.0-rc7-3-amd64-clang"
> > >  CLANG_VERSION 100001 -> 110000
> > > +CC_HAS_ASM_INLINE y
> > > +HAVE_ARCH_KCSAN y
> > > +HAVE_KCSAN_COMPILER y
> > > +KCSAN n
> > >
> > > Which KCSAN kconfigs did you enable?
> >
> > To clarify: as said in [1], KCSAN (or any other instrumentation) is no
> > longer relevant to the issue here, and the compile-time regression is
> > observable with most configs. The problem is due to pre-processing and
> > parsing, which came about due to new READ_ONCE() and the
> > __unqual_scalar_typeof() macro (which this patch optimizes).
> >
> > KCSAN and new ONCEs got tangled up because we first attempted to
> > annotate {READ,WRITE}_ONCE() with data_race(), but that turned out to
> > have all kinds of other issues (explanation in [2]). So we decided to
> > drop all the KCSAN-specific bits from ONCE, and require KCSAN to be
> > Clang 11. Those fixes were applied to the first version of new
> > {READ,WRITE}_ONCE() in -tip, which actually restored the new ONCEs to
> > the pre-KCSAN version (now that KCSAN can deal with them without
> > annotations).
> >
> > Hope this makes more sense now.
> >
> > [1] https://lore.kernel.org/lkml/CANpmjNOUdr2UG3F45=JaDa0zLwJ5ukPc1MMKujQtmYSmQnjcXg@mail.gmail.com/
> > [2] https://lore.kernel.org/lkml/20200521142047.169334-1-elver@google.com/
> >
>
> Thanks, Marco.
>
> I pulled tip.git#locking/kcsan on top of Linux v5.7-rc7 and applied this patch.
> Just wanted to try KCSAN for the first time and it will also be my
> first building with clang-11.
> That's why I asked.

In general, CONFIG_KCSAN=y and the defaults for the other KCSAN
options should be good. Depending on the size of your system, you
could also tweak KCSAN runtime performance:
https://lwn.net/Articles/816850/#Interacting%20with%20KCSAN%20at%20Runtime
-- the defaults should be good for most systems though.
Hope this helps. Any more questions, do let me know.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOPcFSr2n_ro8TqhOBXOBfUY0vZtj_VT7hh3HOhJN4BqQ%40mail.gmail.com.
