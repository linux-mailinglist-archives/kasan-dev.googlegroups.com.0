Return-Path: <kasan-dev+bncBDPJLN7A4MFRB7O32KGAMGQEWYJML6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E7EC4541BD
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 08:23:43 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id bp10-20020a056512158a00b0040376f60e35sf901910lfb.8
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 23:23:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637133822; cv=pass;
        d=google.com; s=arc-20160816;
        b=pHYZJyAV8t+YqO33p9fX2emmDvTs6j5ojhZsa6sk1baYOvo1+xxnVxl9xiV7NKisK1
         CqzKDfd6p/W3HtzcEtQrbIHMeccMombHE6/rFIz4+l1whglsD/3cJbABwuZcTxRh3xXI
         3K8MJ24jCx0mHbpbu0HQGVbYiNBcEqi07KVWkkaxtW5B4+Zgn0b6uAjSTepNxWKERWB6
         risjTtkP7Ah+uazSY2UR1ZyOiZDL61KHPn64z6CGx0QL1QxGUNy+SWoTCLZ4qDh4Bek8
         oS0Q0UsK8gk8TC75AGQ7K2XF0pTwTnthDvAWFdnA6CpE7xh/ls0FqAJfoL9cnD2Zoo+s
         fVCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=bJSSr/NCPKRBoWmf9HhbTgjxWBrXC9Wmi09zoce4KNc=;
        b=j+4uKfMcCzLuVisKEbDLur4PVoCAk3cI4qAwWzDJZCLE8R9t1uWO0mhHg4jweTtZzO
         gSQzGS3ePWn0hgK20d5m71oDdso4HbpZRbl6+iaI1KtG1DInQEhrcjAsOZ/i1NiHnjcx
         FgsYv/NOCCXMIdqHoZ4k0jX/6064coMOJv5MZZJNlrC76GKHzRG4/DJfBj04sxnFvrAK
         V/X8K4ClARBJZ63zl63EezPq+IxlCqJDPZzcImW+rnCWdKEKxTswLA7bhEEDm+FoGtkG
         ymmv2NgUyVNVqA5E75eVcF48Xxh9tl8zMVJfR37QcU5Xax9a6Yr1mGJnR4FKD04MKr5r
         n7AQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=hh3mp0vG;
       spf=pass (google.com: domain of kaiwan.billimoria@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=kaiwan.billimoria@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bJSSr/NCPKRBoWmf9HhbTgjxWBrXC9Wmi09zoce4KNc=;
        b=BjSvAP0aVAS8ClyUCNwUVNGNjn3Ns7hL3Az+VhyDy8OHohEi9x8K5VL5Tdeh6JHS+G
         J+KZv7l23wodKYkPC+2d2J/zlpr29C0b+sA7qoilcASy3MbLXtobT8A9mW9GRfmg4CWo
         OIAzaj/g62DDetStTa7Bn/0B1TTCaofevNUEZPUEjIUyaoHp+01MHhitmcghtvue9x/N
         +i7C+rxl8jgXMnDiNk6xU+xpCdQpHw14UG/Ft27KemUbqd80YHDsJBESw9RKQpliTuQs
         2CFy5NWpl9dH1+paZ4RKjvjiTVJYLEl/c3Frjd7c4/cJqEuPd/PbgTiGv9m3F45w8GhR
         yXpw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bJSSr/NCPKRBoWmf9HhbTgjxWBrXC9Wmi09zoce4KNc=;
        b=JKVqXqAbKJbXy1OYLsvRfueWdKG8DaTS7bC4gfZWXc1V4JG3sejEHBuXvXbwLGbMET
         OGAv7yKI8YuIJ3nYRoyyQ0ZxblVleuGLtD3XqzNdj0x5sQQWJKWXivZBAe/YwMLK3mw7
         YHpHfq9ehhugN8FutazoI8WIujc5OuIpmKyig/n45C07i4HOkgTyJ2BTVpZ/9uDiPBuP
         Z9h59GZY7zRmk5U7QidZzN912dp+PmTRFfrMxKlHAzkquzStcHU84WFBBp5Nsqw8Tlm2
         rO72d0DEeO9/Q4eWH2gWKzgQQAR1zwocn7h3eRpFnJwEgxGEeClL/lAyEkLJ8pr5gJP1
         /ZJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bJSSr/NCPKRBoWmf9HhbTgjxWBrXC9Wmi09zoce4KNc=;
        b=aSNqh5LrurpjpbfP2jGlsSFZHXmvDd/EKc1xgq4NhcxAKJd9WjboXTX1k7s8mcUV/E
         uITuOqfPl/2k0L9hqFH7LcnnzjdMg7N1yeJY5s+6Q/3V2qOz1OwxJ9diPsX2JxsuMLwT
         B1TizdT63nyu1EnXVzxx8nTHIYOLuzwt3h1Jr2KRDetiS6mpDMo5NwyPm6vpO7pdod7L
         /FzfRX58MiHnumVy4kYD0RXOE7VB6HZLO6+6+s3EWo/BxO2l9zI+H70J0ScG+OGu3Uvu
         /OcLukCdfssJgYbDObAUEA+T+bAfELgxsQv/Xhl2RrOAU7AULR3Q/TvAuB1+g9xi6bOY
         a8mg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530fHVxXByVeonmZRerEt3+DzOP1S87kKCwmE8SHxIyGQanelC75
	zgLCHiVarhGD7bl2r08rKHE=
X-Google-Smtp-Source: ABdhPJxwPHtmpFxyfSN2LTXZKtqePFNI4miny0jvxuNt05JahFlfJEJRi6dSVzWCQxixPPyC+tjmQQ==
X-Received: by 2002:a05:6512:2506:: with SMTP id be6mr13092440lfb.597.1637133822131;
        Tue, 16 Nov 2021 23:23:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3499:: with SMTP id v25ls2069995lfr.0.gmail; Tue,
 16 Nov 2021 23:23:41 -0800 (PST)
X-Received: by 2002:ac2:5049:: with SMTP id a9mr13552440lfm.666.1637133820936;
        Tue, 16 Nov 2021 23:23:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637133820; cv=none;
        d=google.com; s=arc-20160816;
        b=cg8eT1RZ1hSWxko5We/Cvlg3Vs3AJ8rIE0VtBt/BZQLXCASt3fb7y9YaKfmLuIXquL
         X34b2R/OFSN1YDAQ+9nOuNwtqCkj0aMtoVEfY2gcxGUfunXO17EfRyB2TJGj6dfFtHXp
         UB4ZzUr6aYUlsRkJuzXTWWabA7h6yyhCMT3LhdHij7X1+EHYJ/bZJSiIb98U1ozL0xfE
         XxRZt12kAK6ZH8xT568056pQ8QGuRqss3Q2Iz2I+8KKI1L+uHJEc5mp186YcVZiYtjlt
         ifeU8hMYZkopBj3DF5WB/mVFlC/gj8mjjQHTA7ebTaVQyGEZSaC9T48Quf4iXKkizCYK
         Ggkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C3o9lRSQJ+Nlyf9jhX8dKRHejLU4EBnMJU7XJ+a74n8=;
        b=w9TzR46oC3vBV9kZfjQfyEy7J4ueLbcnhouBCRH0hN9A3bTyodhCcR+/URKuXfx0cR
         da9Vhs+3Ofd+EinJjWBmNkUvVkGZwwyK0EiUjFKypwSyTlqcYJTgCO87tRb8cXwnlkDc
         HjrQDx+dpvW3OrpaWpIbgAx/mHs89+oaVgB6Ms/PCd+2MuQYt0OgAxxgZnDv+E+n0VTr
         RN4AygOQnNCx1KwIx7j13mjGbYlXPNllPBq2W8Z+0Xjni/yPD7qcQk1y6MgNQ7ROcW02
         GY6ICQRrLB9HQ1wYmzsxRZxHocv1CW+xvzdODFAYuR4R8ahKUd+5ahxQMZBtLk7Uk1/Y
         HLAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=hh3mp0vG;
       spf=pass (google.com: domain of kaiwan.billimoria@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=kaiwan.billimoria@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id b11si1056482lfv.12.2021.11.16.23.23.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 23:23:40 -0800 (PST)
Received-SPF: pass (google.com: domain of kaiwan.billimoria@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id g14so6711572edz.2
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 23:23:40 -0800 (PST)
X-Received: by 2002:a50:be87:: with SMTP id b7mr18749872edk.199.1637133820612;
 Tue, 16 Nov 2021 23:23:40 -0800 (PST)
MIME-Version: 1.0
References: <a2ced905703ede4465f3945eb3ae4e615c02faf8.camel@gmail.com>
 <CANpmjNNSRVMO+PJWvpP=w+V6CR51Yd-r2ku_fVEvymae0g7JaQ@mail.gmail.com>
 <c2693ecb223eb634f4fa94101c4cb98999ef0032.camel@gmail.com> <YZPeRGpOTSgXjaE6@elver.google.com>
In-Reply-To: <YZPeRGpOTSgXjaE6@elver.google.com>
From: Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
Date: Wed, 17 Nov 2021 12:53:29 +0530
Message-ID: <CAPDLWs88WLTPVnh1TtY3tOU6XLPucf8zKMhzCfxRv2HbCnKndA@mail.gmail.com>
Subject: Re: KASAN isn't catching rd/wr underflow bugs on static global memory?
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, Chi-Thanh Hoang <chithanh.hoang@gmail.com>
Content-Type: multipart/alternative; boundary="000000000000d3d41e05d0f6eb74"
X-Original-Sender: kaiwan.billimoria@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=hh3mp0vG;       spf=pass
 (google.com: domain of kaiwan.billimoria@gmail.com designates
 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=kaiwan.billimoria@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--000000000000d3d41e05d0f6eb74
Content-Type: text/plain; charset="UTF-8"

On Tue, 16 Nov 2021, 22:07 Marco Elver, <elver@google.com> wrote:

> On Tue, Nov 16, 2021 at 07:46PM +0530, Kaiwan N Billimoria wrote:
> > On Tue, 2021-11-16 at 12:52 +0100, Marco Elver wrote:
> > >
> > > KASAN globals support used to be limited in Clang. This was fixed in
> > > Clang 11. I'm not sure about GCC.
> > ...
> > > > Which compiler versions are you using? This is probably the most
> > > important piece to the puzzle.
> > >
> > Right! This is the primary issue i think, thanks!
> > am currently using gcc 9.3.0.
> >
> > So, my Ubuntu system had clang-10; I installed clang-11 on top of it...
> > (this causes some issues?). Updated the Makefile to use clang-11, and it
> did build.
>
> Only the test or the whole kernel? You need to build the whole kernel
> and your module with the same compiler, otherwise all bets are off wrt
> things like KASAN.
>
Ah, will do so and let you know, thanks!



> > But when running these tests, *only* UBSAN was triggered, KASAN unseen.
> > So: I then rebuilt the 5.10.60 kernel removing UBSAN config and retried
> (same module rebuilt w/ clang 11).
> > This time UBSAN didn't pop up but nor did KASAN ! (For the same rd/wr
> underflow testcases)...
> > My script + dmesg:
> > ...
> > (Type in the testcase number to run):
> > 4.4
> > Running testcase "4.4" via test module now...
> > [  371.368096] testcase to run: 4.4
> > $
> >
> > This implies it escaped unnoticed..
> >
> > To show the difference, here's my testcase #4.1- Read  (right) overflow
> on global memory - output:
> >
> > Running testcase "4.1" via test module now...
> > [ 1372.401484] testcase to run: 4.1
> > [ 1372.401515]
> ==================================================================
> > [ 1372.402284] BUG: KASAN: global-out-of-bounds in
> static_mem_oob_right+0xaf/0x160 [test_kmembugs]
> > [ 1372.402851] Read of size 1 at addr ffffffffc088dfcc by task
> run_tests/1656
> >
> > [ 1372.403428] CPU: 2 PID: 1656 Comm: run_tests Tainted: G    B      O
>     5.10.60-dbg02 #14
> > [ 1372.403442] Hardware name: innotek GmbH VirtualBox/VirtualBox, BIOS
> VirtualBox 12/01/2006
> > [ 1372.403454] Call Trace:
> > [ 1372.403486]  dump_stack+0xbd/0xfa
> >
> > [... lots more, as expected ...]
> >
> > So, am puzzled... why isn't KASAN catching the underflow...
>
> Please take a look at the paragraph at:
>
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/lib/test_kasan.c#n706
>
> I think your test is giving the compiler opportunities to miscompile
> your code, because, well it has undefined behaviour (negative index)
> that it very clearly can see. I think you need to put more effort into
> hiding the UB from the optimizer like we do in test_kasan.c.
>
> If you want to know in detail what's happening I recommend you
> disassemble your compiled code and check if the negative dereferences
> are still there.
>
Will recheck...

Thanks, Kaiwan.

>
> > A couple of caveats:
> > 1) I had to manually setup a soft link to llvm-objdump (it was installed
> as llvm-objdump-11)
> > 2) the module build initially failed with
> > /bin/sh: 1: ld.lld: not found
> > So I installed the 'lld' package; then the build worked..
> >
> > Any thoughts?
>
> Is this "make LLVM=1". Yeah, if there's a version suffix it's known to
> be problematic.
>
> You can just build the kernel with "make CC=clang" and it'll use
> binutils ld, which works as well.
>
> > > FWIW, the kernel has its own KASAN test suite in lib/test_kasan.c.
> > > There are a few things to not make the compiler optimize away
> > > explicitly buggy code, so I'd also suggest you embed your test in
> > > test_kasan and see if it changes anything (unlikely but worth a shot).
> > I have studied it, and essentially copied it's techniques where
> required... Interestingly, the kernel's test_kasan module does _not_ have a
> test case for this: underflow on global memory! :-)
>
> I just added such a test (below) and it passes just fine with clang 11
> (I'll probably send it as a real patch later). Notice that the address
> itself ("array") is a volatile, so that the compiler cannot make any
> assumptions about it.
>
> Thanks,
> -- Marco
>
> ------ >8 ------
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 67ed689a0b1b..e56c9eb3f16e 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -700,7 +700,7 @@ static void kmem_cache_bulk(struct kunit *test)
>
>  static char global_array[10];
>
> -static void kasan_global_oob(struct kunit *test)
> +static void kasan_global_oob_right(struct kunit *test)
>  {
>         /*
>          * Deliberate out-of-bounds access. To prevent
> CONFIG_UBSAN_LOCAL_BOUNDS
> @@ -723,6 +723,15 @@ static void kasan_global_oob(struct kunit *test)
>         KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>  }
>
> +static void kasan_global_oob_left(struct kunit *test)
> +{
> +       char *volatile array = global_array;
> +       char *p = array - 3;
> +
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
> +       KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
> +}
> +
>  /* Check that ksize() makes the whole object accessible. */
>  static void ksize_unpoisons_memory(struct kunit *test)
>  {
> @@ -1160,7 +1169,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>         KUNIT_CASE(kmem_cache_oob),
>         KUNIT_CASE(kmem_cache_accounted),
>         KUNIT_CASE(kmem_cache_bulk),
> -       KUNIT_CASE(kasan_global_oob),
> +       KUNIT_CASE(kasan_global_oob_right),
> +       KUNIT_CASE(kasan_global_oob_left),
>         KUNIT_CASE(kasan_stack_oob),
>         KUNIT_CASE(kasan_alloca_oob_left),
>         KUNIT_CASE(kasan_alloca_oob_right),
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAPDLWs88WLTPVnh1TtY3tOU6XLPucf8zKMhzCfxRv2HbCnKndA%40mail.gmail.com.

--000000000000d3d41e05d0f6eb74
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"auto"><div><br><br><div class=3D"gmail_quote"><div dir=3D"ltr" =
class=3D"gmail_attr">On Tue, 16 Nov 2021, 22:07 Marco Elver, &lt;<a href=3D=
"mailto:elver@google.com">elver@google.com</a>&gt; wrote:<br></div><blockqu=
ote class=3D"gmail_quote" style=3D"margin:0 0 0 .8ex;border-left:1px #ccc s=
olid;padding-left:1ex">On Tue, Nov 16, 2021 at 07:46PM +0530, Kaiwan N Bill=
imoria wrote:<br>
&gt; On Tue, 2021-11-16 at 12:52 +0100, Marco Elver wrote:<br>
&gt; &gt; <br>
&gt; &gt; KASAN globals support used to be limited in Clang. This was fixed=
 in<br>
&gt; &gt; Clang 11. I&#39;m not sure about GCC.<br>
&gt; ...<br>
&gt; &gt; &gt; Which compiler versions are you using? This is probably the =
most<br>
&gt; &gt; important piece to the puzzle.<br>
&gt; &gt; <br>
&gt; Right! This is the primary issue i think, thanks!<br>
&gt; am currently using gcc 9.3.0.<br>
&gt; <br>
&gt; So, my Ubuntu system had clang-10; I installed clang-11 on top of it..=
.<br>
&gt; (this causes some issues?). Updated the Makefile to use clang-11, and =
it did build.<br>
<br>
Only the test or the whole kernel? You need to build the whole kernel<br>
and your module with the same compiler, otherwise all bets are off wrt<br>
things like KASAN.<br></blockquote></div></div><div dir=3D"auto">Ah, will d=
o so and let you know, thanks!=C2=A0</div><div dir=3D"auto"><br></div><div =
dir=3D"auto"><br></div><div dir=3D"auto"><div class=3D"gmail_quote"><blockq=
uote class=3D"gmail_quote" style=3D"margin:0 0 0 .8ex;border-left:1px #ccc =
solid;padding-left:1ex">
<br>
&gt; But when running these tests, *only* UBSAN was triggered, KASAN unseen=
.<br>
&gt; So: I then rebuilt the 5.10.60 kernel removing UBSAN config and retrie=
d (same module rebuilt w/ clang 11).<br>
&gt; This time UBSAN didn&#39;t pop up but nor did KASAN ! (For the same rd=
/wr underflow testcases)...<br>
&gt; My script + dmesg:<br>
&gt; ...<br>
&gt; (Type in the testcase number to run): <br>
&gt; 4.4<br>
&gt; Running testcase &quot;4.4&quot; via test module now...<br>
&gt; [=C2=A0 371.368096] testcase to run: 4.4<br>
&gt; $ <br>
&gt; <br>
&gt; This implies it escaped unnoticed..<br>
&gt; <br>
&gt; To show the difference, here&#39;s my testcase #4.1- Read=C2=A0 (right=
) overflow on global memory - output:<br>
&gt; <br>
&gt; Running testcase &quot;4.1&quot; via test module now...<br>
&gt; [ 1372.401484] testcase to run: 4.1<br>
&gt; [ 1372.401515] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
&gt; [ 1372.402284] BUG: KASAN: global-out-of-bounds in static_mem_oob_righ=
t+0xaf/0x160 [test_kmembugs]<br>
&gt; [ 1372.402851] Read of size 1 at addr ffffffffc088dfcc by task run_tes=
ts/1656<br>
&gt; <br>
&gt; [ 1372.403428] CPU: 2 PID: 1656 Comm: run_tests Tainted: G=C2=A0 =C2=
=A0 B=C2=A0 =C2=A0 =C2=A0 O=C2=A0 =C2=A0 =C2=A0 5.10.60-dbg02 #14<br>
&gt; [ 1372.403442] Hardware name: innotek GmbH VirtualBox/VirtualBox, BIOS=
 VirtualBox 12/01/2006<br>
&gt; [ 1372.403454] Call Trace:<br>
&gt; [ 1372.403486]=C2=A0 dump_stack+0xbd/0xfa<br>
&gt; <br>
&gt; [... lots more, as expected ...]<br>
&gt; <br>
&gt; So, am puzzled... why isn&#39;t KASAN catching the underflow...<br>
<br>
Please take a look at the paragraph at:<br>
<a href=3D"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.g=
it/tree/lib/test_kasan.c#n706" rel=3D"noreferrer noreferrer" target=3D"_bla=
nk">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree=
/lib/test_kasan.c#n706</a><br>
<br>
I think your test is giving the compiler opportunities to miscompile<br>
your code, because, well it has undefined behaviour (negative index)<br>
that it very clearly can see. I think you need to put more effort into<br>
hiding the UB from the optimizer like we do in test_kasan.c.<br>
<br>
If you want to know in detail what&#39;s happening I recommend you<br>
disassemble your compiled code and check if the negative dereferences<br>
are still there.<br></blockquote></div></div><div dir=3D"auto">Will recheck=
...=C2=A0</div><div dir=3D"auto"><br></div><div dir=3D"auto">Thanks, Kaiwan=
.=C2=A0</div><div dir=3D"auto"><div class=3D"gmail_quote"><blockquote class=
=3D"gmail_quote" style=3D"margin:0 0 0 .8ex;border-left:1px #ccc solid;padd=
ing-left:1ex">
<br>
&gt; A couple of caveats:<br>
&gt; 1) I had to manually setup a soft link to llvm-objdump (it was install=
ed as llvm-objdump-11)<br>
&gt; 2) the module build initially failed with<br>
&gt; /bin/sh: 1: ld.lld: not found<br>
&gt; So I installed the &#39;lld&#39; package; then the build worked..<br>
&gt; <br>
&gt; Any thoughts?<br>
<br>
Is this &quot;make LLVM=3D1&quot;. Yeah, if there&#39;s a version suffix it=
&#39;s known to<br>
be problematic.<br>
<br>
You can just build the kernel with &quot;make CC=3Dclang&quot; and it&#39;l=
l use<br>
binutils ld, which works as well.<br>
<br>
&gt; &gt; FWIW, the kernel has its own KASAN test suite in lib/test_kasan.c=
.<br>
&gt; &gt; There are a few things to not make the compiler optimize away<br>
&gt; &gt; explicitly buggy code, so I&#39;d also suggest you embed your tes=
t in<br>
&gt; &gt; test_kasan and see if it changes anything (unlikely but worth a s=
hot).<br>
&gt; I have studied it, and essentially copied it&#39;s techniques where re=
quired... Interestingly, the kernel&#39;s test_kasan module does _not_ have=
 a test case for this: underflow on global memory! :-)<br>
<br>
I just added such a test (below) and it passes just fine with clang 11<br>
(I&#39;ll probably send it as a real patch later). Notice that the address<=
br>
itself (&quot;array&quot;) is a volatile, so that the compiler cannot make =
any<br>
assumptions about it.<br>
<br>
Thanks,<br>
-- Marco<br>
<br>
------ &gt;8 ------<br>
<br>
diff --git a/lib/test_kasan.c b/lib/test_kasan.c<br>
index 67ed689a0b1b..e56c9eb3f16e 100644<br>
--- a/lib/test_kasan.c<br>
+++ b/lib/test_kasan.c<br>
@@ -700,7 +700,7 @@ static void kmem_cache_bulk(struct kunit *test)<br>
<br>
=C2=A0static char global_array[10];<br>
<br>
-static void kasan_global_oob(struct kunit *test)<br>
+static void kasan_global_oob_right(struct kunit *test)<br>
=C2=A0{<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 /*<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0* Deliberate out-of-bounds access. To pre=
vent CONFIG_UBSAN_LOCAL_BOUNDS<br>
@@ -723,6 +723,15 @@ static void kasan_global_oob(struct kunit *test)<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *=
)p);<br>
=C2=A0}<br>
<br>
+static void kasan_global_oob_left(struct kunit *test)<br>
+{<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0char *volatile array =3D global_array;<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0char *p =3D array - 3;<br>
+<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_G=
ENERIC);<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *=
)p);<br>
+}<br>
+<br>
=C2=A0/* Check that ksize() makes the whole object accessible. */<br>
=C2=A0static void ksize_unpoisons_memory(struct kunit *test)<br>
=C2=A0{<br>
@@ -1160,7 +1169,8 @@ static struct kunit_case kasan_kunit_test_cases[] =3D=
 {<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 KUNIT_CASE(kmem_cache_oob),<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 KUNIT_CASE(kmem_cache_accounted),<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 KUNIT_CASE(kmem_cache_bulk),<br>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0KUNIT_CASE(kasan_global_oob),<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0KUNIT_CASE(kasan_global_oob_right),<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0KUNIT_CASE(kasan_global_oob_left),<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 KUNIT_CASE(kasan_stack_oob),<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 KUNIT_CASE(kasan_alloca_oob_left),<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 KUNIT_CASE(kasan_alloca_oob_right),<br>
</blockquote></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAPDLWs88WLTPVnh1TtY3tOU6XLPucf8zKMhzCfxRv2HbCnKndA%40=
mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.googl=
e.com/d/msgid/kasan-dev/CAPDLWs88WLTPVnh1TtY3tOU6XLPucf8zKMhzCfxRv2HbCnKndA=
%40mail.gmail.com</a>.<br />

--000000000000d3d41e05d0f6eb74--
