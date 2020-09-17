Return-Path: <kasan-dev+bncBD6K324WS4FBBEMURX5QKGQESEWDLQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id DF2E626DA5B
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 13:35:45 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id w7sf778790wrp.2
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 04:35:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600342545; cv=pass;
        d=google.com; s=arc-20160816;
        b=DTwU6Y4AxfBUkd+5l2GeYUiBKcCbeFkrPWydAGSgUghC2qeCCYCRlY1uQnMNE9AMuk
         +nUXRTZbfDPd0TwhXMb2rofSYY9JEX5jhWAvunGfTZZy0Q5uM+acHp0X752DuSRwIxf7
         tPph7HBU5OqgpV0suvD1FCuxQJXS0fcPuBfWeC9PjnyG1CeHbDT+tU/x2D4V2bJJ8Mii
         ousV/zE+OtbgtSmpFZ+l2DLnL4QIK/CJp99YovjxbUqMSEcIqZ5FJjDi9A45PbgF+lmi
         oIzrQDiTDHgtJDrOFSBxDSnlZ3ehuo7lRdsdqkyJKNUEutniDLQP4ieCHpi9Cuy1QtWe
         yDeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=YBgpT1Mj2rhjF9VISiGuBjyijYvYpbEGLx2xRBAe+1s=;
        b=S/K6W7w0U5qPn0ccE0JIX4zE9IqS2gonIXls+8Otub/2U4ELoSQv6FAczN+8t2ax8/
         uPxGMGn0clQyXWsxD2elO9Uo0HopLN6yCktyDDu4ZxzEeukWHew5fCbJr6mtSttpWsFH
         KUAcXAdxpkMavUS/NfZbmNbrhifFWKlc517fchvenv1jDk1grIeZlHIAdO9yOucLtlO8
         tAr4t1lFdABsH76HT2oV6a8uJzR9NQPCPmhAdlt50Yvm6PeZNvBhw2tNahKZDWLRgpvN
         JBY8uvrgXfj64IknSaZ++WXzF8oIXvAB9xNrxx2b2z26awNoeAHeps1jSO6ei/YB42I0
         IjbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MZtwfo2W;
       spf=pass (google.com: domain of georgepope@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=georgepope@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=YBgpT1Mj2rhjF9VISiGuBjyijYvYpbEGLx2xRBAe+1s=;
        b=Bt/DfqVRZilL8J9e1VDNW7+GVlL2JcljFaIoDuNKF+x5nmZ/R47CVvMJEx6MjyI/OG
         FsNLMQux8A8aFtdWAngh01cmFjg1vljiSp0qVMIEbkEi18YLotbyn7sIyV7VeBj6O09Q
         7MgP0CtLlfHG9xQYZlEE6tRi4ljxDKeDgwQnJ+lMcn8+a/zDMy6LohD8tDcvxFgTgoII
         9NWccV0JeGW341soJPy5A3/KfvlJrJexmOAwqIRVL0L8WAMMX9VTzJj5MS3CoRTMpZqC
         /O54BKDMvhpKjGyV/fzGGQyAxOhwO+rx3ubKjiUg8AkdLvbgDvlcqrSv40l8Pa16V3nJ
         gvDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YBgpT1Mj2rhjF9VISiGuBjyijYvYpbEGLx2xRBAe+1s=;
        b=CuRhz6CLpHDr+YHQ6kzkqpzLEfI4TfWRRHFSnKuJJFzKhNargbN0OWYnJvEuFewJs9
         oWxj2TOZPozODeoDgVhZCOvQ/PDcorKpqH08ELdIIAD8sQzVhz4nNQ4zfipiv4Ppcj7A
         CdGqNvdgzAIEoNdmpGlxIeBTAIDNDKvCZGiIFAqH7r8+FgwbPHq6W7PpYgQEs7EI5z+p
         1bJeOkwnb0ZaSHFHNmH3O9tdg0hjAD7rOvuROTNqJYMuX61ZzcUoXkzPlgqJqsmOi2+B
         wRczeHSc+/jKlzraXhixGRvH0WUwP1bdfMZBwJYF6lNBXGXZUdGucnFHsy15LxFxcxio
         jIng==
X-Gm-Message-State: AOAM5333L2mWw61CkDkQCSyhN1rnVPMZpHDK6WL1R8+8fBVIEMhdrFqR
	RfZZWEcvky9bGEfqEJfykSc=
X-Google-Smtp-Source: ABdhPJzyBSzVD1zIQYNuKNwGpzKBEuuz+xXVm/k41WfK3SaM1j1eHwjo8ov8abhGF30ctVYyibxeYQ==
X-Received: by 2002:adf:db48:: with SMTP id f8mr32800809wrj.144.1600342545571;
        Thu, 17 Sep 2020 04:35:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:8:: with SMTP id h8ls2163962wrx.3.gmail; Thu, 17
 Sep 2020 04:35:44 -0700 (PDT)
X-Received: by 2002:adf:e80b:: with SMTP id o11mr29775031wrm.118.1600342544718;
        Thu, 17 Sep 2020 04:35:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600342544; cv=none;
        d=google.com; s=arc-20160816;
        b=w810kNHAW+Q4bmBSVFZXm4oNOrOGbSyPOUaUxjkzn06KZLVDGNZgmkZVyvalcZYxJb
         rHDfckM5QHXg23FuPEe0JYpuTo8BMP6LKiULk+bvpZ79GYXeOcdQe+ixKuE6fzCvoavS
         zY+vF5O8jhrb63aAO2/5ur/H1R0A6DEwbinxjm/8vpi2dy32Tl0L68VrLuy1qVAvNq2o
         V1CRyVl4J7Xpm33B1HNFZaz+qZz37uCHzSpVgITnU+kCXUL5c0Fcamlx9LzGT4a+bS9m
         t0YzrSdIt47T2DGuq6PtL5wt0PqBG8CVvJBl5aeb55bVFatgvpbo15FhTt8lRd05Gc2A
         /2/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=EtH4/cbuQgykQYd+jjjiuY8limbLr894Hm1Wfr5TKQE=;
        b=S3u6K7s6T4Q0zRTOUkVkrIDIGpgeG/q9AwZU70NOELglHbJpr/PXIxQGbZrsQIvGF0
         lIeAqOCmKbvV1COGLFVmjyLd9pQZ2y5rfXyN4OWRi9WbCwKd6WhIWEV21aISa3V/LE1o
         Mybmcv9IfPqfjim8lUBDefwJ5VDsaOj2lnyfclycb45SAPUusqPFIFcth1CHY7PLNUiH
         OIPVoGoHlDQrOxgrSdc4htJ02XplO5HPitUdr3JfuS3pAbUHGZnPXKNLG3zEw4tGHaCu
         gIRBq9CoiFDP3WSgumE+wVUZRvUwUkQVmPvMnB/Iu0s60MAaaB2SlCXIJahCAR4hTgmj
         Og1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MZtwfo2W;
       spf=pass (google.com: domain of georgepope@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=georgepope@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id s79si33354wme.2.2020.09.17.04.35.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Sep 2020 04:35:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of georgepope@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id o5so1663474wrn.13
        for <kasan-dev@googlegroups.com>; Thu, 17 Sep 2020 04:35:44 -0700 (PDT)
X-Received: by 2002:adf:df87:: with SMTP id z7mr32658549wrl.239.1600342544219;
        Thu, 17 Sep 2020 04:35:44 -0700 (PDT)
Received: from google.com (49.222.77.34.bc.googleusercontent.com. [34.77.222.49])
        by smtp.gmail.com with ESMTPSA id f14sm10591991wme.22.2020.09.17.04.35.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Sep 2020 04:35:42 -0700 (PDT)
Date: Thu, 17 Sep 2020 11:35:40 +0000
From: "'George Popescu' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>, maz@kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	kvmarm@lists.cs.columbia.edu, LKML <linux-kernel@vger.kernel.org>,
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	james.morse@arm.com, julien.thierry.kdev@gmail.com,
	suzuki.poulose@arm.com,
	Nathan Chancellor <natechancellor@gmail.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	David Brazdil <dbrazdil@google.com>, broonie@kernel.org,
	Fangrui Song <maskray@google.com>, Andrew Scull <ascull@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Thomas Gleixner <tglx@linutronix.de>, Arnd Bergmann <arnd@arndb.de>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: [PATCH 06/14] Fix CFLAGS for UBSAN_BOUNDS on Clang
Message-ID: <20200917113540.GA1742660@google.com>
References: <202009141509.CDDC8C8@keescook>
 <20200915102458.GA1650630@google.com>
 <CANpmjNOTcS_vvZ1swh1iHYaRbTvGKnPAe4Q2DpR1MGhk_oZDeA@mail.gmail.com>
 <20200915120105.GA2294884@google.com>
 <CANpmjNPpq7LfTHYesz2wTVw6Pqv0FQ2gc-vmSB6Mdov+XWPZiw@mail.gmail.com>
 <20200916074027.GA2946587@google.com>
 <CANpmjNMT9-a8qKZSvGWBPAb9x9y1DkrZMSvHGq++_TcEv=7AuA@mail.gmail.com>
 <20200916121401.GA3362356@google.com>
 <20200916134029.GA1146904@elver.google.com>
 <CANpmjNOfgeR0zpL-4AtOt0FL56BFZ_sud-mR3CrYB7OCMg0PaA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOfgeR0zpL-4AtOt0FL56BFZ_sud-mR3CrYB7OCMg0PaA@mail.gmail.com>
X-Original-Sender: georgepope@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MZtwfo2W;       spf=pass
 (google.com: domain of georgepope@google.com designates 2a00:1450:4864:20::441
 as permitted sender) smtp.mailfrom=georgepope@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: George Popescu <georgepope@google.com>
Reply-To: George Popescu <georgepope@google.com>
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

On Thu, Sep 17, 2020 at 08:37:07AM +0200, Marco Elver wrote:
> On Wed, 16 Sep 2020 at 15:40, Marco Elver <elver@google.com> wrote:
> > On Wed, Sep 16, 2020 at 12:14PM +0000, George Popescu wrote:
> > > On Wed, Sep 16, 2020 at 10:32:40AM +0200, Marco Elver wrote:
> > > > On Wed, 16 Sep 2020 at 09:40, George Popescu <georgepope@google.com> wrote:
> > > > > On Tue, Sep 15, 2020 at 07:32:28PM +0200, Marco Elver wrote:
> > > > > > On Tue, 15 Sep 2020 at 14:01, George Popescu <georgepope@google.com> wrote:
> > > > > > > On Tue, Sep 15, 2020 at 01:18:11PM +0200, Marco Elver wrote:
> > > > > > > > On Tue, 15 Sep 2020 at 12:25, George Popescu <georgepope@google.com> wrote:
> > > > > > > > > On Mon, Sep 14, 2020 at 03:13:14PM -0700, Kees Cook wrote:
> > > > > > > > > > On Mon, Sep 14, 2020 at 05:27:42PM +0000, George-Aurelian Popescu wrote:
> > > > > > > > > > > From: George Popescu <georgepope@google.com>
> > > > > > > > > > >
> > > > > > > > > > > When the kernel is compiled with Clang, UBSAN_BOUNDS inserts a brk after
> > > > > > > > > > > the handler call, preventing it from printing any information processed
> > > > > > > > > > > inside the buffer.
> > > > > > > > > > > For Clang -fsanitize=bounds expands to -fsanitize=array-bounds and
> > > > > > > > > > > -fsanitize=local-bounds, and the latter adds a brk after the handler
> > > > > > > > > > > call
> > > > > > > > > >
> > > > > > > > > This would mean losing the local-bounds coverage. I tried to  test it without
> > > > > > > > > local-bounds and with a locally defined array on the stack and it works fine
> > > > > > > > > (the handler is called and the error reported). For me it feels like
> > > > > > > > > --array-bounds and --local-bounds are triggered for the same type of
> > > > > > > > > undefined_behaviours but they are handling them different.
> > > > > > > >
> > > > > > > > Does -fno-sanitize-trap=bounds help?
> > [...]
> > > > Your full config would be good, because it includes compiler version etc.
> > > My full config is:
> >
> > Thanks. Yes, I can reproduce, and the longer I keep digging I start
> > wondering why we have local-bounds at all.
> >
> > It appears that local-bounds finds a tiny subset of the issues that
> > KASAN finds:
> >
> >         http://lists.llvm.org/pipermail/cfe-commits/Week-of-Mon-20131021/091536.html
> >         http://llvm.org/viewvc/llvm-project?view=revision&revision=193205
> >
> > fsanitize=undefined also does not include local-bounds:
> >
> >         https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html#available-checks
> >
> > And the reason is that we do want to enable KASAN and UBSAN together;
> > but local-bounds is useless overhead if we already have KASAN.
> >
> > I'm inclined to say that what you propose is reasonable (but the commit
> > message needs to be more detailed explaining the relationship with
> > KASAN) -- but I have no idea if this is going to break somebody's
> > usecase (e.g. find some OOB bugs, but without KASAN -- but then why not
> > use KASAN?!)
> 
> So, it seems that local-bounds can still catch some rare OOB accesses,
> where KASAN fails to catch it because the access might skip over the
> redzone.
> 
> The other more interesting bit of history is that
> -fsanitize=local-bounds used to be -fbounds-checking, and meant for
> production use as a hardening feature:
> http://lists.llvm.org/pipermail/llvm-dev/2012-May/049972.html
> 
> And local-bounds just does not behave like any other sanitizer as a
> result, it just traps. The fact that it's enabled via
> -fsanitize=local-bounds (or just bounds) but hasn't much changed in
> behaviour is a little unfortunate.

> I suppose there are 3 options:
> 
> 1. George implements trap handling somehow. Is this feasible? If not,
> why not? Maybe that should also have been explained in the commit
> message.
> 
> 2. Only enable -fsanitize=local-bounds if UBSAN_TRAP was selected, at
> least for as long as Clang traps for local-bounds. I think this makes
> sense either way, because if we do not expect UBSAN to trap, it really
> should not trap!
> 
> 3. Change the compiler. As always, this will take a while to implement
> and then to reach whoever should have that updated compiler.
> 
> Preferences?
Considering of what you said above, I find option 2 the most elegant.
The first one doesn't sound doable for the moment, also the third.
I will edit this patch considering your comments and resend it to the
list.
Thank you for your support.

Thanks,
George


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917113540.GA1742660%40google.com.
