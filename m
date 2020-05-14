Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDFS632QKGQE3O6TPGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id D8D171D3CA0
	for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 21:16:29 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id k11sf16116otc.8
        for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 12:16:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589483789; cv=pass;
        d=google.com; s=arc-20160816;
        b=RnmZolhyrfpzgwWjbbBXWKq7kE4iZkd091TKWcTjdFv5REW8UDWDPuw+n4CulFsfB9
         YtTtBh8GenkX1DZ+GAcLMCUA3L022+01aBGu2Ywls7IS1r7C3V2Yf4LsAkhTUWGQYodo
         lCBszYlzzjGItWF0mzcrpRSWYBMb8pusiGZIVb6OictLBOLKjYeM3tZC6EGZ5eG83U1U
         YgdhA5L3Jd60h9I8+Zd6S0YqLg1YbVd2jwRs8Pc3EetEydBeE7UaR03LpY/DtGc0pGE1
         gpOhYnGPAq5l3XwU8P2oZnoV9/fW3+U5rElGkY/AuXuyplkRRZ0udS4K4SGFsE0IGkq6
         kDDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UFPivZhDz25EXWx+GzAZ2ud3S22kF5BpRzCaMD7jiW8=;
        b=v4hW4GfuiazmcELSJ5W2Cw8Aq+6/IEDIgBeZ4863Ol6PaUnHXbNJ2MKIT0LLPiH2y9
         N6llxrTGcE5t2oWOtbGiClbxKSA41j3t//YzWpfkBPbE9xCF4J8K2mbVv83skN1m5iCd
         Y4zX68oCB2pOika3pY5RDXw8hhdj4MD8hdcflsLDYTlB3QyCBB+1wBTkXv3q2oM+L/Qz
         +9YdrK/VXtLk4XA7cWVCMpvjoSLl6YkwTbkgpLdpQudhrZ05xxU99W/f+udNApXt7cTr
         tGfdJ1Ib112bJooUDSD2KZL+Yro4B9CSXDjBTKprpmaZ5VEm7Y8Nn1k22iVUIIaGAqd8
         gSFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="VPs/Qast";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UFPivZhDz25EXWx+GzAZ2ud3S22kF5BpRzCaMD7jiW8=;
        b=pC+H8KVevm6kcB7y58zEuUCBFHezLfrKVovf3YENLXmFYxhiAec9z/yBosW3Joy/Af
         2Nbpz3mKLWIzfhLLn1WnDF4EU6vF0jIPeJRW7sS0o3joB3N3zZZDvOXvmhDgiLSX5E4S
         hbO+/bUEwFQrQhnXtPdzIQfdylzJLZlM+mAhTrYZwO7Qj5nUwSpwlR9EOAuQsNylpIms
         LtmeQmZZIaJ0GVUi5o1A43Ev9WtqORu/auHOBAJ62niEvzFBYUlhbVvTD7E/QoYgMPEw
         qR7MOjXk2ppBzwlcFeVUf03T4y2yWnpdvNdBR85aevHiS6FcMCfgJy+iaM/RxxMfvrrE
         4T7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UFPivZhDz25EXWx+GzAZ2ud3S22kF5BpRzCaMD7jiW8=;
        b=hjyl0KsnnOdBuJaqgj1zN8+hyrqutH78PzT2+MsfFuEabK+9Uyy0kLd0syAixdwftp
         OPvInDEfn08SGwiuCKARj1wyW8tEE1uLAeiKRNpGz5l/RjoWpsTpwdUu0bG1G1RSBTKu
         lh8ZBnX4KYlMS+rE2hNG16EJHJPBF7I5mSBIgQLaYTqTfyKW8818uzrGivFYmMNYEz9Y
         WO3WJ0JNwk9ccjeBFhPnuWDvfOMF5B0PYJlEiVGxo/b26KBLv539L7NftUGe5Nq9xeyD
         OuP8zH7EjqFCnD93/MT/n4y018hMP2Wl2BtKqqAJM1tuLkFhNWuZABYN9jKKkQyzMfR3
         JUHg==
X-Gm-Message-State: AOAM531+78dPjb4xFNcGlURVemnvXbuYUngVj+yhK6VJ8SH33HD879/P
	AKYDwULvW57pRP2wKYe8U1E=
X-Google-Smtp-Source: ABdhPJy1mMNR7cVmoUP2w8jWycuwWFgHKFSB9D5/dDCTCgYCBsixDzcgXBQiLMn6ZTWUla5EzyA7aw==
X-Received: by 2002:a9d:d0a:: with SMTP id 10mr4604551oti.189.1589483788776;
        Thu, 14 May 2020 12:16:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:86a:: with SMTP id 97ls771305oty.9.gmail; Thu, 14 May
 2020 12:16:28 -0700 (PDT)
X-Received: by 2002:a05:6830:18c7:: with SMTP id v7mr5121771ote.48.1589483788333;
        Thu, 14 May 2020 12:16:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589483788; cv=none;
        d=google.com; s=arc-20160816;
        b=elMR1Snv62uVCJsWUun2n0Q1kB9QzgJW8MnoC4tLa3XFQzyKr0ECkqnkNqnGF4yoXz
         uR2YmVGw5wvKe2vY4Qpmk8+4PVLgNvT+Ju036M6rnVFfIYJcbSuQYnAVrYA7UzKBdPf8
         KpMuJ3B51cpTkL4J30QA31jKNqaF1EJDTlqqOh7/DS6ZME4Hx4Eef+ohiBs6xRUjoGTo
         K6EYBaTi8YOOLIFMdFHW+RRIshBREuMfpW97AiafvoHPDWgWsj9HOW8yCZgaCU8VUi8y
         M4C0ZOk9xWONT2MukFtgQrXtKQuzHdUscLQTI/epgkua8SBQexfFbSme7bxHNDs6TKHn
         99eQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Py18wA5N29X3tShwOlaJKFh5xwNW9HxDBsL7uWnBtiQ=;
        b=TJeKDwb0ERta8wZDMknJfEzW1qYkwiz9pk1Ylpga+4mLBKM6HbLeudtiLUzAnqXzIU
         Ijq1z+5ykfLS1dNeNWK+uBGZvxL6zEM8G22Z28oWP392ce4nRTXxLFJbJuit38Hl7t0K
         beUOhD39si2jEuzkMwTKRM/I/NLNuh1mGtOQcBhNHEMlDQXRdM7UeMuV98J9TOxeEIie
         JI/BxbcJc36zgqAk2JfmE3oL4Umh/5sjTcHHANof5cohYboIhwkhsLj+iecLben4VbTB
         Gw9I9m9FpcumxQ29Z2K7ITyAzJMWMEDcRnk8vT41ow5Uf6E1kzuw3jvlghnkdnzxwE+D
         Pk0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="VPs/Qast";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id f197si330134oob.1.2020.05.14.12.16.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 May 2020 12:16:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id o7so41865oif.2
        for <kasan-dev@googlegroups.com>; Thu, 14 May 2020 12:16:28 -0700 (PDT)
X-Received: by 2002:aca:3254:: with SMTP id y81mr11707277oiy.172.1589483787767;
 Thu, 14 May 2020 12:16:27 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNNLY9EcSXhBbdjMR2pLJfrgQoffuzs27Xrgx3nOuAUxMQ@mail.gmail.com>
 <CAKwvOdnQaeQ2bLqyXs-H3MZTPBd+yteVG4NiY0Wd05WceAad9g@mail.gmail.com>
 <CANpmjNPLgFdFpHzj5Hb_1CfFzPMmqy3z1O98N=wsr8kQ1VS9_Q@mail.gmail.com> <CAKwvOd=0Ducgnkf8tzNGH10_UJSk56Ff_oSyGMddBCyG3Xt5Gg@mail.gmail.com>
In-Reply-To: <CAKwvOd=0Ducgnkf8tzNGH10_UJSk56Ff_oSyGMddBCyG3Xt5Gg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 May 2020 21:16:16 +0200
Message-ID: <CANpmjNNZ=50HgbSxoyha0+0-ucO_FLSyB7VfBT7WnmOdpF7uvw@mail.gmail.com>
Subject: Re: ORC unwinder with Clang
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: clang-built-linux <clang-built-linux@googlegroups.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="VPs/Qast";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Thu, 14 May 2020 at 20:35, 'Nick Desaulniers' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Thu, May 14, 2020 at 11:04 AM Marco Elver <elver@google.com> wrote:
> >
> > On Thu, 14 May 2020 at 19:48, 'Nick Desaulniers' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > >
> > > + Josh, Peter
> > >
> > > On Thu, May 14, 2020 at 10:41 AM Marco Elver <elver@google.com> wrote:
> > > >
> > > > Hi,
> > > >
> > > > Is CONFIG_UNWINDER_ORC=y fully supported with Clang?
> > >
> > > We're down to 4 objtool warnings in an allyesconfig build.  3 I
> > > understand pretty well, and patches exist for them, but I haven't
> > > looked into the 4th yet.  Otherwise it works (to the best of anyone's
> > > knowledge).  Though kbuild test robot has dug up 4 new reports from
> > > randconfigs that I need to look into.
> > >
> > > Here's our list of open issues with the objtool label:
> > > https://github.com/ClangBuiltLinux/linux/issues?q=is%3Aopen+is%3Aissue+label%3A%22%5BTOOL%5D+objtool%22
> > >
> > > I remember Josh mentioning
> > > https://github.com/ClangBuiltLinux/linux/issues/612 which I haven't
> > > had time to look into.
> > >
> > > >
> > > > I'm seeing frames dropped in stack-traces with
> > > > stack_trace_{dump,print}. Before I dig further, the way I noticed this
> > > > is when running the KCSAN test (in linux-next):
> > > >
> > > > CONFIG_KCSAN=y
> > > > CONFIG_KCSAN_TEST=y
>
> (KCSAN_TEST depends on CONFIG_KUNIT=y, needed to enable that, too on
> top of defconfig).

Sorry, yes that one was missing.

> > > >
> > > > The test-cases "test_assert_exclusive_access_writer" for example fail
> > > > because the frame of the function that did the actual access is not in
> > > > the stack-trace.
> > > >
> > > > When I use __attribute__((disable_tail_calls)) on the functions that
> > > > do not show up in the stack traces, the problem goes away. Obviously
> > > > we don't want to generally disable tail-calls, but it highlights an
> > > > issue with the ORC unwinder and Clang.
> > > >
> > > > Is this a known issue? Any way to fix this?
> > >
> > > First I've heard of it.  Which functions, and what's the minimal set
> > > of configs to enable on top of defconfig to reproduce?
> >
> > In linux-next:
> >
> > CONFIG_KCSAN=y
> > CONFIG_KCSAN_TEST=y
> >
> > And wait for the "test_assert_exclusive*" test-cases, which will fail.
>
> For me, all of the tests fail with:
> test_basic-02: too few online CPUs (1 < 2) for test
> but I guess that's because my QEMU virtual machine only has 1 cpu?
> Ah, if I add `-smp $(nproc)` to my invocation I can get past that.
>
> I see:
> test_basic_*
> test_concurrent_races*
> test_novalue_change_exception*
> test_kernel_write_nochange_rcu*
> test_unknown_origin*
> test_write_write_assume_atomic*
> test_write_write_struct*
> test_write_write_struct_part*
> test_read_atomic_write_atomic*
> test_read_plain_atomic_write*

Strange. That's definitely missing something. Maybe we get to where we
want to be by modifying the test as follows:

  sed -i '/CASE(test_[^a].*),/d' kernel/kcsan/kcsan-test.c

And I double-checked, the code is definitely in linux-next.

> Tests take about 3 minutes to run for me, but I didn't see any
> test_assert_exclusive*.  Should I look again, or am I missing a
> config, or perhaps a patch?  This is my first time running KUnit, too.
> Is there a way to specify just the single unit test you'd like to run,
> a la gunit, or do you have to run the full suite?

You can make the tests run quicker with:

CONFIG_KCSAN_REPORT_ONCE_IN_MS=100

> > The stack traces of the races shown should all start with a
> > "test_kernel_*" function, but do not. Then:
> >
> >   sed -i "s/noinline/noinline __attribute__((disable_tail_calls))/"
> > kernel/kcsan/kcsan-test.c
> >
> > which adds the disable_tail_calls attribute to all "test_kernel_*"
> > functions, and the tests pass.
>
> That's a good lead to start with.  Do the tests pass with
> UNWINDER_FRAME_POINTER rather than UNWINDER_ORC?  Rather than
> blanketing the kernel with disable_tail_calls, the next steps I
> recommend is to narrow down which function caller and callee
> specifically trip up this test.  Maybe from there, we can take a look
> at the unwind info from objtool that ORC consumes?

Indeed, UNWINDER_FRAME_POINTER works as expected.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNZ%3D50HgbSxoyha0%2B0-ucO_FLSyB7VfBT7WnmOdpF7uvw%40mail.gmail.com.
