Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO7YXL3AKGQEU7HXXXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E2B7D1E4DFB
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 21:15:08 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id g9sf5946197ybc.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 12:15:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590606908; cv=pass;
        d=google.com; s=arc-20160816;
        b=w3kM1XqLR0fvCHRyTBJ31kQVH4Ug7AqelBPqBj4K2+9o2DCRl3EQUu8LTkhvJvh+BL
         wI9DP0gWgRLa/XDVGrcTbdVh5vEROcF1MbW5IUvnFhR/4MkOfw+zivh9JtT3Ip91y93g
         k9Qk3+xn3hRxCImU1MQNYjInZwRr2fegfGOKWOBkPu5LGL9DItHmj4XPKH32c6Lb+7eu
         /kASrhVMC4IsNQjEAYI4j3eRqDgGVDhUjR8gxA7KkJcVJGqL7B+lsy16qc7zdjAMXap5
         +NW4D0MijMkQtQbo0XGm2acT0NJ2WwjONV42DcxuOmJzA6Ce+j5ztgzIiT6MVEErra3t
         rgew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5UrcCs3bc5fqYbWNcHIrVWzkLFrXc2N6EaHbAmugW6Y=;
        b=T/+qnYpmoxvuePlVQ7ameugFVHRJoXRwdSehPoubuvf9pUeKQ1ju5SR95Q9Xy6B5em
         KFXIp1UYjszGGUbByR49Jpj3wZibmCEkYRTryE9nHEGwNgq7e8ORGQP8u9f3gyIfuYGR
         56jgK0156JbojXKmjTVkJ6rOyLYxc5Me5GsRVIOXXZFa/PJ2VLEOxJeuuOO7SJmnHcWm
         ZAAJDEg60ayaLr0x5+gcO893rNPaQFgTr67Rymq903VPhl39UQAJmbADYM/Jfb42rxx5
         nzrLa0PmQHaAOtW8ouUa98F1T7egbE5uvrqOCVKIKGCLQVgOxwNYQ7YSEPDeKvAQAvMx
         70jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P8uATb2Z;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5UrcCs3bc5fqYbWNcHIrVWzkLFrXc2N6EaHbAmugW6Y=;
        b=LsAhlo6xoysQ+m2ZijPtapYgVKG9Mez4QvXkT3XAnznqfwpueMmSUZ3CzisHu6myux
         W9HUXx2jxaTfBdk8e6gD1HJj+B3GaGtvzFET/MyQE8a2uRQ2Zlz52bSO+S8Y5C046TSo
         fpSop8M7kFipzWf/MzF/AA4Cm2AdgOSYfxJ9aDyYLEGwj+iicplBKgidM024w47bmU//
         4l6XzySS82LT4+traVxQdGecPKrT8XRz6s9OlMO/nyN1vE9fqymY953izo6qxjYe4Mxt
         dU4dDhQWIKe/LPrOqUHjNlhwkcPHVLO0dtZxTPyg/Nc8EbGiGAfypxSzsIr7aeNP3/nD
         AqEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5UrcCs3bc5fqYbWNcHIrVWzkLFrXc2N6EaHbAmugW6Y=;
        b=QLH0Hulvji/wt4SBxpjE3+dea8ZtqPxxB4lAT9NlAkaGbWaB1lJhFTrFQ3E32NoYLu
         oO1seKA0u+m4YxDBlS4CeGWPDG03euhVc4brkXoXlSP+vd6soZc/apLIvhv2sCvHzWdc
         zeDbqwWgJSny7i4rc+fRKit4yLm4n4vCKzNt/+HlalD0eqaiCJquOZAzwt/SYZkgAeTP
         pI/oW/LDXApce+uqxX8KVvzyRExC2rfwnLKTSoyzGV3HHEaL3K5wEwZk7fVbvCCg2735
         8pACcxq9uA9305dn1+0g68m7U0juLLCbOw3bnJjBmSsJs75WMNpKxvdbHvfx5/Jm0Ecw
         IKIQ==
X-Gm-Message-State: AOAM533aZx7ps25k9Pky6h/SR9d6/CE8eH6KFrsfyiUTtIVLOEGYvoyG
	/9QmG1ajWvagqy6rGQwGCGM=
X-Google-Smtp-Source: ABdhPJyhQKWE9EUdujKLPA3yRmNbVVBdWi6uxyZJIhwb8vLAIJETglsfh0PEILNEhhRkHpTAJ8xMTA==
X-Received: by 2002:a25:3783:: with SMTP id e125mr11034268yba.168.1590606907903;
        Wed, 27 May 2020 12:15:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:824a:: with SMTP id d10ls5910071ybn.10.gmail; Wed, 27
 May 2020 12:15:07 -0700 (PDT)
X-Received: by 2002:a25:d058:: with SMTP id h85mr13069795ybg.93.1590606907452;
        Wed, 27 May 2020 12:15:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590606907; cv=none;
        d=google.com; s=arc-20160816;
        b=bBJOmpMbgjJgpqXrTGNFOH1qlLw6E1BZmbKbvfGtSeO+GTjg24ODo7pAxQMBibjGak
         YAzAB820iu783kqVvG6KLQK4A+G0cHIgbjSAlziZQQRYRnsW6eJb/xtocL+A+fxxrv4T
         HlGSVWboXfj6VlIyjrLVPYoq78US7SjFS1jlW0CGddIHvBmm4Ph7pCxDemOIiPi4WE0d
         +PdPZC4CWWVYJXoC2kxBiDLhtKuOBvp4m6GI04AqPJAjh0x8WlqzEnz1hSOVm9/vJQi6
         qAQqJ+4mF0UwaDQTIJOHihsINPHfqNDoqRsyj3ZzwHXqfnFab+D+vYqdto+CCjnsUmD+
         pYSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CPpomYNzZ7JQdxP/DL0TvucyrSh7m4+4U1ykvIyyU6Y=;
        b=NawFcBh4UMoHRr9Qbokz4K7/xBwZyCmmgICHu35ikZaKn3elOi1GSixCMCqXGQNhkO
         /o1c1z8df8GYKFS5VXVFsVWoVfPQ+HBW/a3pd6JPZTfiJYFrLW8cMLdpLsnSlWpfEZ1T
         ZTJC+IrHEsGoNGpmebZt+IqXzUligYBJLKlZWrCu9gZ3LdPL77MqgoX9IoZz3X5PgKqw
         OgsfkFdgFWPtmcsqnNDwSLdQyeWOif0q9GSP/W85jsKMR5PgpQHJddak3Mod8LnlKPMS
         1VN9HeKB8vms4wvfenh5FLI9I4VxvFzDpZNWsVxpDg5fdhIAAoBT2s4UJVK3qyaDJMll
         4rng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P8uATb2Z;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id a83si293734yba.1.2020.05.27.12.15.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 May 2020 12:15:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id d191so22696820oib.12
        for <kasan-dev@googlegroups.com>; Wed, 27 May 2020 12:15:07 -0700 (PDT)
X-Received: by 2002:aca:ebc5:: with SMTP id j188mr3919306oih.70.1590606906697;
 Wed, 27 May 2020 12:15:06 -0700 (PDT)
MIME-Version: 1.0
References: <20200527103236.148700-1-elver@google.com> <CAK8P3a1MFgRxm6=+9WZKNzN+Nc5fhrDso6orSNQaaa-0yqygYA@mail.gmail.com>
 <CA+icZUWtzu0ONUSy0E27Mq1BrdO79qNaY3Si-PDhHZyF8M4S5g@mail.gmail.com>
 <CAK8P3a04=mVQgSrvDhpVxQj50JEFDn_xMhYrvjmUnLYTWH3QXQ@mail.gmail.com>
 <CA+icZUXVSTxDYJwXLyAwZd91cjMPcPRpeAR72JKqkqa-wRNnWg@mail.gmail.com>
 <CAK8P3a3i0kPf8dRg7Ko-33hsb+LkP=P05uz2tGvg5B43O-hFvg@mail.gmail.com>
 <CA+icZUWr5xDz5ujBfsXjnDdiBuopaGE6xO5LJQP9_y=YoROb+Q@mail.gmail.com>
 <CANpmjNOtKQAB_3t1G5Da-J1k-9Dk6eQKP+xNozRbmHJXZqXGFw@mail.gmail.com>
 <CA+icZUWzPMOj+qsDz-5Z3tD-hX5gcowjBkwYyiy8SL36Jg+2Nw@mail.gmail.com>
 <CANpmjNOPcFSr2n_ro8TqhOBXOBfUY0vZtj_VT7hh3HOhJN4BqQ@mail.gmail.com> <CA+icZUVK=5agY_FPdPeRbZyn3EoUgnmPToR3iGWuCzY+KHtoAA@mail.gmail.com>
In-Reply-To: <CA+icZUVK=5agY_FPdPeRbZyn3EoUgnmPToR3iGWuCzY+KHtoAA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 27 May 2020 21:14:54 +0200
Message-ID: <CANpmjNOA2Oa=AJkKYadbvEVOaqzgD840aC5wfGGrFvDqUmjhpg@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=P8uATb2Z;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Wed, 27 May 2020 at 21:11, Sedat Dilek <sedat.dilek@gmail.com> wrote:
>
> On Wed, May 27, 2020 at 3:57 PM Marco Elver <elver@google.com> wrote:
> >
> > On Wed, 27 May 2020 at 15:37, Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > >
> > > On Wed, May 27, 2020 at 3:30 PM Marco Elver <elver@google.com> wrote:
> > > >
> > > > On Wed, 27 May 2020 at 15:11, Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > > > >
> > > > > On Wed, May 27, 2020 at 2:50 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > > > >
> > > > > > On Wed, May 27, 2020 at 2:35 PM Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > > > > > > On Wed, May 27, 2020 at 2:31 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > > > > > > On Wed, May 27, 2020 at 1:36 PM Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > > > > > > > > On Wed, May 27, 2020 at 1:27 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > > > > > > > > On Wed, May 27, 2020 at 12:33 PM Marco Elver <elver@google.com> wrote:
> > > > > > > > > >
> > > > > > > > > > This gives us back 80% of the performance drop on clang, and 50%
> > > > > > > > > > of the drop I saw with gcc, compared to current mainline.
> > > > > > > > > >
> > > > > > > > > > Tested-by: Arnd Bergmann <arnd@arndb.de>
> > > > > > > > > >
> > > > > > > > >
> > > > > > > > > Hi Arnd,
> > > > > > > > >
> > > > > > > > > with "mainline" you mean Linux-next aka Linux v5.8 - not v5.7?
> > > > > > > >
> > > > > > > > I meant v5.7.
> > > > > > > >
> > > > > > > > > I have not seen __unqual_scalar_typeof(x) in compiler_types.h in Linux v5.7.
> > > > > > > > >
> > > > > > > > > Is there a speedup benefit also for Linux v5.7?
> > > > > > > > > Which patches do I need?
> > > > > > > >
> > > > > > > > v5.7-rc is the baseline and is the fastest I currently see. On certain files,
> > > > > > > > I saw an intermittent 10x slowdown that was already fixed earlier, now
> > > > > > > > linux-next
> > > > > > > > is more like 2x slowdown for me and 1.2x with this patch on top, so we're
> > > > > > > > almost back to the speed of linux-5.7.
> > > > > > > >
> > > > > > >
> > > > > > > Which clang version did you use - and have you set KCSAN kconfigs -
> > > > > > > AFAICS this needs clang-11?
> > > > > >
> > > > > > I'm currently using clang-11, but I see the same problem with older
> > > > > > versions, and both with and without KCSAN enabled. I think the issue
> > > > > > is mostly the deep nesting of macros that leads to code bloat.
> > > > > >
> > > > >
> > > > > Thanks.
> > > > >
> > > > > With clang-10:
> > > > >
> > > > > $ scripts/diffconfig /boot/config-5.7.0-rc7-2-amd64-clang .config
> > > > >  BUILD_SALT "5.7.0-rc7-2-amd64-clang" -> "5.7.0-rc7-3-amd64-clang"
> > > > > +HAVE_ARCH_KCSAN y
> > > >
> > > > Clang 10 doesn't support KCSAN (HAVE_KCSAN_COMPILER unset).
> > > >
> > > > > With clang-11:
> > > > >
> > > > > $ scripts/diffconfig /boot/config-5.7.0-rc7-2-amd64-clang .config
> > > > >  BUILD_SALT "5.7.0-rc7-2-amd64-clang" -> "5.7.0-rc7-3-amd64-clang"
> > > > >  CLANG_VERSION 100001 -> 110000
> > > > > +CC_HAS_ASM_INLINE y
> > > > > +HAVE_ARCH_KCSAN y
> > > > > +HAVE_KCSAN_COMPILER y
> > > > > +KCSAN n
> > > > >
> > > > > Which KCSAN kconfigs did you enable?
> > > >
> > > > To clarify: as said in [1], KCSAN (or any other instrumentation) is no
> > > > longer relevant to the issue here, and the compile-time regression is
> > > > observable with most configs. The problem is due to pre-processing and
> > > > parsing, which came about due to new READ_ONCE() and the
> > > > __unqual_scalar_typeof() macro (which this patch optimizes).
> > > >
> > > > KCSAN and new ONCEs got tangled up because we first attempted to
> > > > annotate {READ,WRITE}_ONCE() with data_race(), but that turned out to
> > > > have all kinds of other issues (explanation in [2]). So we decided to
> > > > drop all the KCSAN-specific bits from ONCE, and require KCSAN to be
> > > > Clang 11. Those fixes were applied to the first version of new
> > > > {READ,WRITE}_ONCE() in -tip, which actually restored the new ONCEs to
> > > > the pre-KCSAN version (now that KCSAN can deal with them without
> > > > annotations).
> > > >
> > > > Hope this makes more sense now.
> > > >
> > > > [1] https://lore.kernel.org/lkml/CANpmjNOUdr2UG3F45=JaDa0zLwJ5ukPc1MMKujQtmYSmQnjcXg@mail.gmail.com/
> > > > [2] https://lore.kernel.org/lkml/20200521142047.169334-1-elver@google.com/
> > > >
> > >
> > > Thanks, Marco.
> > >
> > > I pulled tip.git#locking/kcsan on top of Linux v5.7-rc7 and applied this patch.
> > > Just wanted to try KCSAN for the first time and it will also be my
> > > first building with clang-11.
> > > That's why I asked.
> >
> > In general, CONFIG_KCSAN=y and the defaults for the other KCSAN
> > options should be good. Depending on the size of your system, you
> > could also tweak KCSAN runtime performance:
> > https://lwn.net/Articles/816850/#Interacting%20with%20KCSAN%20at%20Runtime
> > -- the defaults should be good for most systems though.
> > Hope this helps. Any more questions, do let me know.
> >
>
> Which "projects" and packages do I need?
>
> I have installed:
>
> # LC_ALL=C apt-get install llvm-11 clang-11 lld-11
> --no-install-recommends -t llvm-toolchain -y
>
> # dpkg -l | grep
> 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261 | awk
> '/^ii/ {print $1 " " $2 " " $3}' | column -t
> ii  clang-11
> 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> ii  libclang-common-11-dev
> 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> ii  libclang-cpp11
> 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> ii  libclang1-11
> 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> ii  libllvm11:amd64
> 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> ii  lld-11
> 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> ii  llvm-11
> 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> ii  llvm-11-runtime
> 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
>
> Is that enough?

Just clang-11 (and its transitive dependencies) is enough. Unsure what
your installed binary is, likely "clang-11", so if you can do "make
CC=clang-11 defconfig" (and check for CONFIG_HAVE_KCSAN_COMPILER)
you're good to go.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOA2Oa%3DAJkKYadbvEVOaqzgD840aC5wfGGrFvDqUmjhpg%40mail.gmail.com.
