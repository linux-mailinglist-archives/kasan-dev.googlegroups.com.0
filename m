Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSU42SGAMGQE3GAHNLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F3DF45484B
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 15:14:35 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id v13-20020a05620a440d00b00468380f4407sf1919653qkp.17
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 06:14:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637158474; cv=pass;
        d=google.com; s=arc-20160816;
        b=hw79CHx1EqjcnkLzMRBTf4FQRsSYL1iqJ3ntruort3JhKLCAOmIBolQCb/k6fyzmrz
         AfNz8AYi7Ijra0Ys3zlJqb/Owgiuu04ld681KCJGmPYmj5Q3yDP+vfeB7IR5geBaCtuG
         hRbFI/gNcD6dRiNAIdJSDnqci5KcVDAFdIP7n9CQHzk0NMdJNpy8Irfxeipl0Zwd2zKU
         1ALeSloBppHjbs4QnQPcePGcRSD79zN2gUmfrVoWP41yjUvirS22nT1SUsZiwF2/DW2l
         xYK0UKRMvRHuXhk6mZ1aaJrzB0XF1hXbDHwDOgKccMTVlo2xO2toqpAvXs1tmElQvAVw
         5wYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XjhNKnQlU4nShBtpJ1fF7yXChiDaD3b8svlq7LfW3lY=;
        b=GGy2KkU7ayWgJArHiGAASTXPp8dIw0YHVCBUy0mVIdgt+oirQVhX729TSL9yKHWgGS
         b47ogeNwd/dU3db84C+WqftUtt4CL9tBKLHV3NPFrEySkfKLLgOvcg4zZwf/3Wa5ehNC
         zjEz8ONMiy0IlC4BVYFa4r3znfLWbzHro/GNngtgliiuYoE52a6Dl6xWIOBQxALU3qJ3
         f9SQi4XTilCRUxp5O+kMsP5IP67jGX85nMimHfzeR5Wm2xax/sYBx23v9jen2qJek/SF
         l1odwAf1Uf0WLNenmjyL09dJjNNH49N2iNqjYvNyolYsKXYbMeZ9YdCOy5v6E/yWvzkT
         o2Dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oxgTuF0P;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=XjhNKnQlU4nShBtpJ1fF7yXChiDaD3b8svlq7LfW3lY=;
        b=OIeQm4XBZU8tEkZ0UsR8nTTeQGiMoZJAIetrxye7ZX9NRsBcrgfJ+o2vNTl//vGqUL
         beBqlwRtqbfAJJiDxHaOmYqmv5xseYxxlm1sHAYqWqaq1Wr6aqO8elYxiOqT0Vw6h8EO
         i0t0Yr7rj/zyqp2+XAylbhtvIz8JgeAvOwAaKxPavAFK1+bhL/8no1cgqAB6w/IEZwuj
         3QLbfnWvYW9iNp63bVWhA6Z71naoeSrdb1RsAvJ5DyFNMLW3jzIrmv5ezrCFoWoLCrdn
         aXfr0r+fC21A7rpwR1Tj3VLpyDt7VPNZZ0/M8+/2YHxguWjWCKsfSNDUPOYTH4Q2R04i
         l/Qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XjhNKnQlU4nShBtpJ1fF7yXChiDaD3b8svlq7LfW3lY=;
        b=Vt2s+vWWG4lk/5WkobUrj9/FphWC4zNL1x/oDo2OVW4UX4D9i1050A7HdnToC6ZSiq
         BR45uDfRiEclxIueu2eVe0FZz0D4g/ZL8kwKCx7XPqLwBvEIoTGHVm3xwomuG5FDQ8V0
         qzxxIFy6DP8pEqVdYbTccZdX6OAfgVxoJ3G96/bsQPGshgRNX4U8tKcU8A4N0Bbe2GKC
         el5XCiZTGuHUTIBy8h1D6Mf9xX7jPzzDQKAaDRfC78flI52OC1nychZrTH6xAT6r8IeO
         YyGtjNudhgu2Veb99kZhoWAtgh7DiwWtYpLB9Umy83sIy/uhl1hNRl7bE4i5b+TUy/QL
         JP8A==
X-Gm-Message-State: AOAM531LF5osMpcoLsboExWqYdARWlf3jdchXXWFPgVyz3h3/LfF/FRd
	Hhw6MuPrpPk8BuZtDKCpKVs=
X-Google-Smtp-Source: ABdhPJyUpuuopCdkGErdynEA4tcpWtOdqrWuRZiSaYA+01a+naZrIJJKc8M78xTWsfxARtebAtMc9Q==
X-Received: by 2002:a05:6214:29eb:: with SMTP id jv11mr55337728qvb.13.1637158474444;
        Wed, 17 Nov 2021 06:14:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1a10:: with SMTP id fh16ls7074421qvb.0.gmail; Wed,
 17 Nov 2021 06:14:34 -0800 (PST)
X-Received: by 2002:a05:6214:174d:: with SMTP id dc13mr54769500qvb.7.1637158474011;
        Wed, 17 Nov 2021 06:14:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637158474; cv=none;
        d=google.com; s=arc-20160816;
        b=sj9WxAd4hbinm9P5nkrAeEhSTeKRmb82IP4w3Be4fhe72FaqC3JltDDd+eB9LD7YsV
         7N6m+rBVjK4CzKbtsl6IV6G8ZP0/iBUcTImKJj82r4CBINiw1c3mvlfY/t2MllDkkoTA
         xo21iuKTvj5TCIIJUKB6ulK/7m3u0arT1bW7Jv/xxuApGPnhcozT9JSAGgR8wOY6T3eP
         oFkCdwE8+nxTMOJNntgHD1yYgM8SJRgZeCHhJQuwbYs1D4cOrelpXgA3FJ774ToHMxyH
         xQZQO6yT2x6qANb3f6wTpWd6oo9WiOD/SIrnKrt9Rm9/Tlp+S/sw0fpvpI5h9QuEVPRp
         G59g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NVuMeBateBvTO1mSrzSln/z5CnTQs7SK2INfshKUiNw=;
        b=Iogx1angHQInMdsJkybBUSYX5PHezwRKH0eyijyTakEqsE8xHNdfBuYYmEx6ibDcQr
         ARZK6SXO9GRziVQytJqv52gbGeaCNBvMz2HuHYidUNy/XHslA6IceA/FJRf7f95By2B3
         6nBPPTVHuzLhjRaQZKSgjgALVCtjpaNoYv7tdiIbsBblZtuwyhfXT6+ux0T9Vbx+6YiD
         cpzHYyWtpWaawN8/tqhV/LR28g4oLj+Cjr1hnOd7KviKbL/qivon9oiVV0scMo+Zdwcq
         KFh7mZo/olWtb90mWwM7N6uW+3ngE5FlKfhCFBYgMquAdnujgbJroyzRUa39oBBm9tBr
         8LEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oxgTuF0P;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x329.google.com (mail-ot1-x329.google.com. [2607:f8b0:4864:20::329])
        by gmr-mx.google.com with ESMTPS id m14si3126qkn.1.2021.11.17.06.14.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Nov 2021 06:14:34 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) client-ip=2607:f8b0:4864:20::329;
Received: by mail-ot1-x329.google.com with SMTP id x43-20020a056830246b00b00570d09d34ebso4980572otr.2
        for <kasan-dev@googlegroups.com>; Wed, 17 Nov 2021 06:14:33 -0800 (PST)
X-Received: by 2002:a9d:77d1:: with SMTP id w17mr13642166otl.329.1637158473388;
 Wed, 17 Nov 2021 06:14:33 -0800 (PST)
MIME-Version: 1.0
References: <a2ced905703ede4465f3945eb3ae4e615c02faf8.camel@gmail.com>
 <CANpmjNNSRVMO+PJWvpP=w+V6CR51Yd-r2ku_fVEvymae0g7JaQ@mail.gmail.com>
 <c2693ecb223eb634f4fa94101c4cb98999ef0032.camel@gmail.com>
 <YZPeRGpOTSgXjaE6@elver.google.com> <CAPDLWs88WLTPVnh1TtY3tOU6XLPucf8zKMhzCfxRv2HbCnKndA@mail.gmail.com>
 <CA+LMZ3r9ioqSN31w5v_Bkgs7UyPux=0MO8g0dQC16AxEiorBcg@mail.gmail.com>
In-Reply-To: <CA+LMZ3r9ioqSN31w5v_Bkgs7UyPux=0MO8g0dQC16AxEiorBcg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 17 Nov 2021 15:14:21 +0100
Message-ID: <CANpmjNMzv2b1srETOp1STjVWYZx-1XpdMm5yY485vSmd=wjJiw@mail.gmail.com>
Subject: Re: KASAN isn't catching rd/wr underflow bugs on static global memory?
To: Chi-Thanh Hoang <chithanh.hoang@gmail.com>
Cc: Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=oxgTuF0P;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as
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

On Wed, 17 Nov 2021 at 15:11, Chi-Thanh Hoang <chithanh.hoang@gmail.com> wr=
ote:
>
> I managed to figure out why the global OOB-left is not being detected and=
 work around the issue 8-)
> I am still using gcc 9.3.0.

Yeah, gcc is doing worse here. I just filed:
https://bugzilla.kernel.org/show_bug.cgi?id=3D215051

Clang 11+ doesn't have this issue.

Please, if you can, post your findings to the bugzilla bug above. Then
we can perhaps take it to gcc devs and ask them to do the same as
clang or fix it some other way.

Thanks,
-- Marco

> I notice KASAN detects fine when OOB happen in overflow, KASAN shown the =
status of shadow memory around the OOB, I see there is no redzone for the g=
lobal before the allocated memory, there is redzone after, if the global is=
 the first declared object in the .bss example, there is no redzone in fron=
t of it so shadow memory are zero, that is why KASAN did not detect.
> I then do the following, I declare 3 globals array in .bss, and test the =
OOB underflow on the second array and KASAN does detect as doing -1 will fa=
ll into the redzone of the first object.
> I agree this is kind of a corner case, but to fix this I guess we need to=
 provide redzone in front of the first global either in .bss or .data, and =
if possible to configure the size of such redzone.
>
> at ffffffffa07a6580 is start of .bss, in the log below there is 3 arrays =
of 10 bytes (00 02 from shadow mem), the fault detected as shown on the 2nd=
 array when I do a -1 reference.
> [25768.140717] Memory state around the buggy address:
> [25768.140721]  ffffffffa07a6480: 00 00 00 00 00 00 00 00 00 00 00 00 00 =
00 00 00
> [25768.140725]  ffffffffa07a6500: 00 00 00 00 00 00 00 00 00 00 00 00 00 =
00 00 00  <<<<< Here are zero value in shadow mem so access is good
> [25768.140730] >ffffffffa07a6580: 00 02 f9 f9 f9 f9 f9 f9 00 02 f9 f9 f9 =
f9 f9 f9
> [25768.140733]                                         ^
> [25768.140737]  ffffffffa07a6600: 00 02 f9 f9 f9 f9 f9 f9 01 f9 f9 f9 f9 =
f9 f9 f9
> [25768.140741]  ffffffffa07a6680: 00 f9 f9 f9 f9 f9 f9 f9 00 00 00 00 00 =
00 00 00
>
>
> On Wed, 17 Nov 2021 at 02:23, Kaiwan N Billimoria <kaiwan.billimoria@gmai=
l.com> wrote:
>>
>>
>>
>> On Tue, 16 Nov 2021, 22:07 Marco Elver, <elver@google.com> wrote:
>>>
>>> On Tue, Nov 16, 2021 at 07:46PM +0530, Kaiwan N Billimoria wrote:
>>> > On Tue, 2021-11-16 at 12:52 +0100, Marco Elver wrote:
>>> > >
>>> > > KASAN globals support used to be limited in Clang. This was fixed i=
n
>>> > > Clang 11. I'm not sure about GCC.
>>> > ...
>>> > > > Which compiler versions are you using? This is probably the most
>>> > > important piece to the puzzle.
>>> > >
>>> > Right! This is the primary issue i think, thanks!
>>> > am currently using gcc 9.3.0.
>>> >
>>> > So, my Ubuntu system had clang-10; I installed clang-11 on top of it.=
..
>>> > (this causes some issues?). Updated the Makefile to use clang-11, and=
 it did build.
>>>
>>> Only the test or the whole kernel? You need to build the whole kernel
>>> and your module with the same compiler, otherwise all bets are off wrt
>>> things like KASAN.
>>
>> Ah, will do so and let you know, thanks!
>>
>>
>>>
>>> > But when running these tests, *only* UBSAN was triggered, KASAN unsee=
n.
>>> > So: I then rebuilt the 5.10.60 kernel removing UBSAN config and retri=
ed (same module rebuilt w/ clang 11).
>>> > This time UBSAN didn't pop up but nor did KASAN ! (For the same rd/wr=
 underflow testcases)...
>>> > My script + dmesg:
>>> > ...
>>> > (Type in the testcase number to run):
>>> > 4.4
>>> > Running testcase "4.4" via test module now...
>>> > [  371.368096] testcase to run: 4.4
>>> > $
>>> >
>>> > This implies it escaped unnoticed..
>>> >
>>> > To show the difference, here's my testcase #4.1- Read  (right) overfl=
ow on global memory - output:
>>> >
>>> > Running testcase "4.1" via test module now...
>>> > [ 1372.401484] testcase to run: 4.1
>>> > [ 1372.401515] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>> > [ 1372.402284] BUG: KASAN: global-out-of-bounds in static_mem_oob_rig=
ht+0xaf/0x160 [test_kmembugs]
>>> > [ 1372.402851] Read of size 1 at addr ffffffffc088dfcc by task run_te=
sts/1656
>>> >
>>> > [ 1372.403428] CPU: 2 PID: 1656 Comm: run_tests Tainted: G    B      =
O      5.10.60-dbg02 #14
>>> > [ 1372.403442] Hardware name: innotek GmbH VirtualBox/VirtualBox, BIO=
S VirtualBox 12/01/2006
>>> > [ 1372.403454] Call Trace:
>>> > [ 1372.403486]  dump_stack+0xbd/0xfa
>>> >
>>> > [... lots more, as expected ...]
>>> >
>>> > So, am puzzled... why isn't KASAN catching the underflow...
>>>
>>> Please take a look at the paragraph at:
>>> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree=
/lib/test_kasan.c#n706
>>>
>>> I think your test is giving the compiler opportunities to miscompile
>>> your code, because, well it has undefined behaviour (negative index)
>>> that it very clearly can see. I think you need to put more effort into
>>> hiding the UB from the optimizer like we do in test_kasan.c.
>>>
>>> If you want to know in detail what's happening I recommend you
>>> disassemble your compiled code and check if the negative dereferences
>>> are still there.
>>
>> Will recheck...
>>
>> Thanks, Kaiwan.
>>>
>>>
>>> > A couple of caveats:
>>> > 1) I had to manually setup a soft link to llvm-objdump (it was instal=
led as llvm-objdump-11)
>>> > 2) the module build initially failed with
>>> > /bin/sh: 1: ld.lld: not found
>>> > So I installed the 'lld' package; then the build worked..
>>> >
>>> > Any thoughts?
>>>
>>> Is this "make LLVM=3D1". Yeah, if there's a version suffix it's known t=
o
>>> be problematic.
>>>
>>> You can just build the kernel with "make CC=3Dclang" and it'll use
>>> binutils ld, which works as well.
>>>
>>> > > FWIW, the kernel has its own KASAN test suite in lib/test_kasan.c.
>>> > > There are a few things to not make the compiler optimize away
>>> > > explicitly buggy code, so I'd also suggest you embed your test in
>>> > > test_kasan and see if it changes anything (unlikely but worth a sho=
t).
>>> > I have studied it, and essentially copied it's techniques where requi=
red... Interestingly, the kernel's test_kasan module does _not_ have a test=
 case for this: underflow on global memory! :-)
>>>
>>> I just added such a test (below) and it passes just fine with clang 11
>>> (I'll probably send it as a real patch later). Notice that the address
>>> itself ("array") is a volatile, so that the compiler cannot make any
>>> assumptions about it.
>>>
>>> Thanks,
>>> -- Marco
>>>
>>> ------ >8 ------
>>>
>>> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
>>> index 67ed689a0b1b..e56c9eb3f16e 100644
>>> --- a/lib/test_kasan.c
>>> +++ b/lib/test_kasan.c
>>> @@ -700,7 +700,7 @@ static void kmem_cache_bulk(struct kunit *test)
>>>
>>>  static char global_array[10];
>>>
>>> -static void kasan_global_oob(struct kunit *test)
>>> +static void kasan_global_oob_right(struct kunit *test)
>>>  {
>>>         /*
>>>          * Deliberate out-of-bounds access. To prevent CONFIG_UBSAN_LOC=
AL_BOUNDS
>>> @@ -723,6 +723,15 @@ static void kasan_global_oob(struct kunit *test)
>>>         KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>>>  }
>>>
>>> +static void kasan_global_oob_left(struct kunit *test)
>>> +{
>>> +       char *volatile array =3D global_array;
>>> +       char *p =3D array - 3;
>>> +
>>> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
>>> +       KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>>> +}
>>> +
>>>  /* Check that ksize() makes the whole object accessible. */
>>>  static void ksize_unpoisons_memory(struct kunit *test)
>>>  {
>>> @@ -1160,7 +1169,8 @@ static struct kunit_case kasan_kunit_test_cases[]=
 =3D {
>>>         KUNIT_CASE(kmem_cache_oob),
>>>         KUNIT_CASE(kmem_cache_accounted),
>>>         KUNIT_CASE(kmem_cache_bulk),
>>> -       KUNIT_CASE(kasan_global_oob),
>>> +       KUNIT_CASE(kasan_global_oob_right),
>>> +       KUNIT_CASE(kasan_global_oob_left),
>>>         KUNIT_CASE(kasan_stack_oob),
>>>         KUNIT_CASE(kasan_alloca_oob_left),
>>>         KUNIT_CASE(kasan_alloca_oob_right),

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMzv2b1srETOp1STjVWYZx-1XpdMm5yY485vSmd%3DwjJiw%40mail.gmai=
l.com.
