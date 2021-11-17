Return-Path: <kasan-dev+bncBCEZPNXX34KRBJE32SGAMGQEB6XC7VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 40AA1454841
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 15:11:50 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id a26-20020a63bd1a000000b002fab31bc2d9sf254435pgf.7
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 06:11:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637158308; cv=pass;
        d=google.com; s=arc-20160816;
        b=eCjn4P1QtxaW23QcR2Y99E6PtOZgO99QbKiURTVELgoeBHbpr6aG2p9mHxlbD4CWlY
         Zg805UuhgcCtgToQzAf2ScsPBYEVuHiycbQJA8n7lxoX6pVSVVZYKbjAF5KVpgDjY5bl
         VuucHxTl9yuPBs22X4XqVO7iwIekHInG4vuy25+at3gKDtpcyx25qFvYjLUjl835RqCw
         buekl0PWYZnaxuKqvv0Kx4JjU+CgjDz9hy2PjpZdP4WX4Vm3EPOEe06I6FZaGh/9XYyR
         owPJ/HF6NBwJYIGUMVCk1ngg9N1fhlgXu6cjKoJN/HrNz6Iw2BVGilPhmcRRf5BocKCw
         RsbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=kH0lNMHUHhuhSt7QWr7RNn7lKWqQf5eMMscmllULTUQ=;
        b=gb6NTPyF7l5D6gynjjLc1PdT2VXqV3UhHeC2kEhi9i3ZsMR/Fjv/6f/sYxI8gzIxEX
         3i/XTKcQjcpldiib7/IiLcj8If7PbLOT8U6H6OqsspidbDdXFCFXfhOyhDmHuoL/IHdq
         d2JP5r93H7QSyIrDU+bPD923loGJAGgNX2JVJCWHSqYY39c5Tymxip+1nhbGjrY1SiHV
         IK7WY1LTD07ND0rMVLnFcEATe/mTUHUaIU5J0Ko63P4eELj/ZxYe+PRQEazKev06kReV
         4WKHDrhCqpajgFMFTa50IkvpFEGqhSj1rUQDsOcuVqLDimSOf+uV1HGyFRJ9gqvm6fr7
         JpUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="J2f69/Jv";
       spf=pass (google.com: domain of chithanh.hoang@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=chithanh.hoang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kH0lNMHUHhuhSt7QWr7RNn7lKWqQf5eMMscmllULTUQ=;
        b=V5Ox3gVZCVeBGrWupprkKbpqmYBFQzBU5Mo6C2Zq4li9+lyV2q72TjmQwhu5Ub9rnp
         hjxgRjpkxkdZZkhyyi4Yh2oYawBLPI2Bdt86sZfD0F6XE0CMTDzoHFAaOj5dchYqlzgS
         UtP7rru6b06qkn6+dqLCxEAgTl0UZ8I8IwPY5a+Fd7y+TZXb73/kcvwUzPjpiipy9jtM
         r64mTonFxIAkXUsXseDX/8kfAU7iGr5L8szS5jvMEHddrVsS47m8XizK7LkdQFQb+g7X
         u5JTziAuH8JQWjBn7xm7kqoLbp5vMeNYPQ1ybkP0emcNUXZMZx1dvOf8ORuy2Crkj/5d
         eITw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kH0lNMHUHhuhSt7QWr7RNn7lKWqQf5eMMscmllULTUQ=;
        b=m9/9n80iy5pGuhqdx4v7GfZJLL8vqJBGmLWyrSRavPJoW+bezHYKDMaUzy7iNfaDdV
         u+CP1gW+u/OlSFdCUgl6ScJWYCxJLxd5mDJWzqTWThnE9+37Do3bvtuYurZCfO66dwZH
         YCAsMCdHtp7zvLufXSiJItJmRBt/nI+96GoohXKzmzpoEWpqS0micIbGRj8YnDSxXglK
         RedpdHZ+mLi6zrA8puSkc72PPpkOios+8cIhNZJN0wFhg22Wn1TYwXeUEg4bI7oprdBN
         31QAdEAK2Bi39pZ3Rvj6qrr042P5wY/oIKN0cMwb3UvKEsw2HjD96P7hNuz4xW8/J9oH
         9xNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kH0lNMHUHhuhSt7QWr7RNn7lKWqQf5eMMscmllULTUQ=;
        b=LI4Xkpr8LTMr/7XG+zSryvd6CzLqcMI98gWJYC373n/lcStngOwQJkLzt9yD4/0m3d
         WiK3KTBbDEsbPtlqZ8EIdL07nGVU6lEahET5jPaz79VpWRXhgn+IrMCxFfntBoGuEjeS
         sm98CIeuPxRc1t0W0AVIIqs3cBy82Shd98b3iH0uFt0GQStHO7La4v28Q05JX+sEHwkF
         39FZxQA/+ma9z2RZNQTsWjY5L3LF2FgJkgswqoWHRM0lW6dv+N+VZg+8kHssouqGWh/y
         zXH2jAzqISoVZGCCyDO6BbFpLVjg5byOK2Dj1yzOEtsSEU7+PnsWxPg37/irWaISQpe/
         iKww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531X/PxyiHmivt9AiV19pn5i/b0rLn3ZrQMZYW3+BuZDNOvD0Mq2
	nTQlzPsc62UHGuW1qrQki1Q=
X-Google-Smtp-Source: ABdhPJxDEhJguI2aREZkNcU3sxBeQL23kjeL3ifAzV9Wd37HJOXDtMU/bQ5ja+G2RbXYsh4bUhfqSg==
X-Received: by 2002:a65:614d:: with SMTP id o13mr5338605pgv.10.1637158308536;
        Wed, 17 Nov 2021 06:11:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e749:: with SMTP id p9ls13477307plf.6.gmail; Wed, 17
 Nov 2021 06:11:47 -0800 (PST)
X-Received: by 2002:a17:902:e806:b0:141:fd0a:2201 with SMTP id u6-20020a170902e80600b00141fd0a2201mr54566354plg.48.1637158307800;
        Wed, 17 Nov 2021 06:11:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637158307; cv=none;
        d=google.com; s=arc-20160816;
        b=vglMD37qSD7s/yz/mD/X00c/aPJsQSgn94Of6FRPxehFbB0wjrvGPzH+zv6cfzoOFl
         gw5agnGqbmtQy+Vjc/6ZTMiphJIYWPGgJuHXTfI0DdeqlLjiaN4GCCdOGDIPOLkGq2g7
         1+ea3Pjbq/U6L6sgjM/vB3sP4gH1vkstcSReLb6EU5ILd5esYjwrG2JPsFIF01uuZTsA
         jd4J0O35XkzivGnzWmUFjefa5IDjgVrUua1lNFN8201f/z6hd0OuE8U7I4ARmranUUWn
         IY1ffSWAWL2aqylwyPL7h6s6Ub37Ek5159gJ11TwNWKLXq7nMa4FOvUiSntiPl0bChzm
         KJSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NKTyXR8IWB8HjnValGPCIyVMUCVjM5L9IGI6xlNQyLQ=;
        b=TnzRXjS2OsUvlS2gseWSy+teQI0SCFp0IxzoMrQEhKa8FW5AmosXha1hulB5Af2557
         h2Rqq0eudyE52iLufaH1Z05A/lUcUrEL8/qiz26eKmeGAkQbWJ/ahHMY9V3ewsrvQA30
         XC41JLdikQTYS5Ie5mN9lJl8pK0LTVAkfhHmBFrt3JUDM3MjWphipZanSk/Ve83oRZ69
         YOuS/CtZTPn03rUdX3ZkMWTcMsWinNSOzXYYoKDtg4dkJwmNyRy9xE34Z0R93punH1qi
         N9VP8AyYYqOn3w35xOFvJDnxmHpWkJ9bRP3X3rCDp+JGN4WoRuzIeI5adNJVy2IS5X6x
         SlXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="J2f69/Jv";
       spf=pass (google.com: domain of chithanh.hoang@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=chithanh.hoang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id x31si1700514pfh.5.2021.11.17.06.11.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Nov 2021 06:11:47 -0800 (PST)
Received-SPF: pass (google.com: domain of chithanh.hoang@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id q17so2251833plr.11
        for <kasan-dev@googlegroups.com>; Wed, 17 Nov 2021 06:11:47 -0800 (PST)
X-Received: by 2002:a17:903:41c1:b0:141:f28f:729e with SMTP id
 u1-20020a17090341c100b00141f28f729emr55228867ple.34.1637158302668; Wed, 17
 Nov 2021 06:11:42 -0800 (PST)
MIME-Version: 1.0
References: <a2ced905703ede4465f3945eb3ae4e615c02faf8.camel@gmail.com>
 <CANpmjNNSRVMO+PJWvpP=w+V6CR51Yd-r2ku_fVEvymae0g7JaQ@mail.gmail.com>
 <c2693ecb223eb634f4fa94101c4cb98999ef0032.camel@gmail.com>
 <YZPeRGpOTSgXjaE6@elver.google.com> <CAPDLWs88WLTPVnh1TtY3tOU6XLPucf8zKMhzCfxRv2HbCnKndA@mail.gmail.com>
In-Reply-To: <CAPDLWs88WLTPVnh1TtY3tOU6XLPucf8zKMhzCfxRv2HbCnKndA@mail.gmail.com>
From: Chi-Thanh Hoang <chithanh.hoang@gmail.com>
Date: Wed, 17 Nov 2021 09:11:32 -0500
Message-ID: <CA+LMZ3r9ioqSN31w5v_Bkgs7UyPux=0MO8g0dQC16AxEiorBcg@mail.gmail.com>
Subject: Re: KASAN isn't catching rd/wr underflow bugs on static global memory?
To: Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com
Content-Type: multipart/alternative; boundary="000000000000125c0c05d0fc9fa2"
X-Original-Sender: chithanh.hoang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="J2f69/Jv";       spf=pass
 (google.com: domain of chithanh.hoang@gmail.com designates
 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=chithanh.hoang@gmail.com;
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

--000000000000125c0c05d0fc9fa2
Content-Type: text/plain; charset="UTF-8"

I managed to figure out why the global OOB-left is not being detected and
work around the issue 8-)
I am still using gcc 9.3.0.
I notice KASAN detects fine when OOB happen in overflow, KASAN shown the
status of shadow memory around the OOB, I see there is no redzone for the
global before the allocated memory, there is redzone after, if the global
is the first declared object in the .bss example, there is no redzone in
front of it so shadow memory are zero, that is why KASAN did not detect.
I then do the following, I declare 3 globals array in .bss, and test the
OOB underflow on the second array and KASAN does detect as doing -1 will
fall into the redzone of the first object.
I agree this is kind of a corner case, but to fix this I guess we need to
provide redzone in front of the first global either in .bss or .data, and
if possible to configure the size of such redzone.

at ffffffffa07a6580 is start of .bss, in the log below there is 3 arrays of
10 bytes (00 02 from shadow mem), the fault detected as shown on the 2nd
array when I do a -1 reference.
[25768.140717] Memory state around the buggy address:
[25768.140721]  ffffffffa07a6480: 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00
[25768.140725]  ffffffffa07a6500: 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00  <<<<< Here are zero value in shadow mem so access is good
[25768.140730] >ffffffffa07a6580: *00 02* f9 f9 f9 f9 f9 *f9* *00 02* f9 f9
f9 f9 f9 f9
[25768.140733]                                         ^
[25768.140737]  ffffffffa07a6600: *00 02* f9 f9 f9 f9 f9 f9 01 f9 f9 f9 f9
f9 f9 f9
[25768.140741]  ffffffffa07a6680: 00 f9 f9 f9 f9 f9 f9 f9 00 00 00 00 00 00
00 00


On Wed, 17 Nov 2021 at 02:23, Kaiwan N Billimoria <
kaiwan.billimoria@gmail.com> wrote:

>
>
> On Tue, 16 Nov 2021, 22:07 Marco Elver, <elver@google.com> wrote:
>
>> On Tue, Nov 16, 2021 at 07:46PM +0530, Kaiwan N Billimoria wrote:
>> > On Tue, 2021-11-16 at 12:52 +0100, Marco Elver wrote:
>> > >
>> > > KASAN globals support used to be limited in Clang. This was fixed in
>> > > Clang 11. I'm not sure about GCC.
>> > ...
>> > > > Which compiler versions are you using? This is probably the most
>> > > important piece to the puzzle.
>> > >
>> > Right! This is the primary issue i think, thanks!
>> > am currently using gcc 9.3.0.
>> >
>> > So, my Ubuntu system had clang-10; I installed clang-11 on top of it...
>> > (this causes some issues?). Updated the Makefile to use clang-11, and
>> it did build.
>>
>> Only the test or the whole kernel? You need to build the whole kernel
>> and your module with the same compiler, otherwise all bets are off wrt
>> things like KASAN.
>>
> Ah, will do so and let you know, thanks!
>
>
>
>> > But when running these tests, *only* UBSAN was triggered, KASAN unseen.
>> > So: I then rebuilt the 5.10.60 kernel removing UBSAN config and retried
>> (same module rebuilt w/ clang 11).
>> > This time UBSAN didn't pop up but nor did KASAN ! (For the same rd/wr
>> underflow testcases)...
>> > My script + dmesg:
>> > ...
>> > (Type in the testcase number to run):
>> > 4.4
>> > Running testcase "4.4" via test module now...
>> > [  371.368096] testcase to run: 4.4
>> > $
>> >
>> > This implies it escaped unnoticed..
>> >
>> > To show the difference, here's my testcase #4.1- Read  (right) overflow
>> on global memory - output:
>> >
>> > Running testcase "4.1" via test module now...
>> > [ 1372.401484] testcase to run: 4.1
>> > [ 1372.401515]
>> ==================================================================
>> > [ 1372.402284] BUG: KASAN: global-out-of-bounds in
>> static_mem_oob_right+0xaf/0x160 [test_kmembugs]
>> > [ 1372.402851] Read of size 1 at addr ffffffffc088dfcc by task
>> run_tests/1656
>> >
>> > [ 1372.403428] CPU: 2 PID: 1656 Comm: run_tests Tainted: G    B      O
>>     5.10.60-dbg02 #14
>> > [ 1372.403442] Hardware name: innotek GmbH VirtualBox/VirtualBox, BIOS
>> VirtualBox 12/01/2006
>> > [ 1372.403454] Call Trace:
>> > [ 1372.403486]  dump_stack+0xbd/0xfa
>> >
>> > [... lots more, as expected ...]
>> >
>> > So, am puzzled... why isn't KASAN catching the underflow...
>>
>> Please take a look at the paragraph at:
>>
>> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/lib/test_kasan.c#n706
>>
>> I think your test is giving the compiler opportunities to miscompile
>> your code, because, well it has undefined behaviour (negative index)
>> that it very clearly can see. I think you need to put more effort into
>> hiding the UB from the optimizer like we do in test_kasan.c.
>>
>> If you want to know in detail what's happening I recommend you
>> disassemble your compiled code and check if the negative dereferences
>> are still there.
>>
> Will recheck...
>
> Thanks, Kaiwan.
>
>>
>> > A couple of caveats:
>> > 1) I had to manually setup a soft link to llvm-objdump (it was
>> installed as llvm-objdump-11)
>> > 2) the module build initially failed with
>> > /bin/sh: 1: ld.lld: not found
>> > So I installed the 'lld' package; then the build worked..
>> >
>> > Any thoughts?
>>
>> Is this "make LLVM=1". Yeah, if there's a version suffix it's known to
>> be problematic.
>>
>> You can just build the kernel with "make CC=clang" and it'll use
>> binutils ld, which works as well.
>>
>> > > FWIW, the kernel has its own KASAN test suite in lib/test_kasan.c.
>> > > There are a few things to not make the compiler optimize away
>> > > explicitly buggy code, so I'd also suggest you embed your test in
>> > > test_kasan and see if it changes anything (unlikely but worth a shot).
>> > I have studied it, and essentially copied it's techniques where
>> required... Interestingly, the kernel's test_kasan module does _not_ have a
>> test case for this: underflow on global memory! :-)
>>
>> I just added such a test (below) and it passes just fine with clang 11
>> (I'll probably send it as a real patch later). Notice that the address
>> itself ("array") is a volatile, so that the compiler cannot make any
>> assumptions about it.
>>
>> Thanks,
>> -- Marco
>>
>> ------ >8 ------
>>
>> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
>> index 67ed689a0b1b..e56c9eb3f16e 100644
>> --- a/lib/test_kasan.c
>> +++ b/lib/test_kasan.c
>> @@ -700,7 +700,7 @@ static void kmem_cache_bulk(struct kunit *test)
>>
>>  static char global_array[10];
>>
>> -static void kasan_global_oob(struct kunit *test)
>> +static void kasan_global_oob_right(struct kunit *test)
>>  {
>>         /*
>>          * Deliberate out-of-bounds access. To prevent
>> CONFIG_UBSAN_LOCAL_BOUNDS
>> @@ -723,6 +723,15 @@ static void kasan_global_oob(struct kunit *test)
>>         KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>>  }
>>
>> +static void kasan_global_oob_left(struct kunit *test)
>> +{
>> +       char *volatile array = global_array;
>> +       char *p = array - 3;
>> +
>> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
>> +       KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>> +}
>> +
>>  /* Check that ksize() makes the whole object accessible. */
>>  static void ksize_unpoisons_memory(struct kunit *test)
>>  {
>> @@ -1160,7 +1169,8 @@ static struct kunit_case kasan_kunit_test_cases[] =
>> {
>>         KUNIT_CASE(kmem_cache_oob),
>>         KUNIT_CASE(kmem_cache_accounted),
>>         KUNIT_CASE(kmem_cache_bulk),
>> -       KUNIT_CASE(kasan_global_oob),
>> +       KUNIT_CASE(kasan_global_oob_right),
>> +       KUNIT_CASE(kasan_global_oob_left),
>>         KUNIT_CASE(kasan_stack_oob),
>>         KUNIT_CASE(kasan_alloca_oob_left),
>>         KUNIT_CASE(kasan_alloca_oob_right),
>>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BLMZ3r9ioqSN31w5v_Bkgs7UyPux%3D0MO8g0dQC16AxEiorBcg%40mail.gmail.com.

--000000000000125c0c05d0fc9fa2
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">I managed to figure out why the global OOB-left is not bei=
ng detected and work around the issue 8-)<div>I am still using gcc 9.3.0.</=
div><div>I notice KASAN detects fine when OOB happen in overflow, KASAN sho=
wn the status of shadow memory around the OOB, I see there is no redzone fo=
r the global before the allocated memory, there is redzone after, if the gl=
obal is the first declared object in the .bss example, there is no redzone =
in front of it so shadow memory are zero, that is why KASAN did not detect.=
</div><div>I then do the following, I declare 3 globals array in .bss, and =
test the OOB underflow on the second array and KASAN does detect as doing -=
1 will fall into the redzone of the first object.</div><div>I agree this is=
 kind of a corner case, but to fix this I guess we need to provide redzone =
in front of the first global either in .bss or .data, and if possible to co=
nfigure the size of such redzone.</div><div><font face=3D"monospace"><br></=
font></div><div><font face=3D"monospace">at=C2=A0</font><span style=3D"font=
-family:monospace">ffffffffa07a6580 is start of .bss, in the log below ther=
e is 3 arrays of 10 bytes (00 02 from shadow mem), the fault detected as sh=
own on the 2nd array when I do a -1 reference.</span></div><div><font face=
=3D"monospace">[25768.140717] Memory state around the buggy address:<br>[25=
768.140721] =C2=A0ffffffffa07a6480: 00 00 00 00 00 00 00 00 00 00 00 00 00 =
00 00 00<br>[25768.140725] =C2=A0ffffffffa07a6500: 00 00 00 00 00 00 00 00 =
00 00 00 00 00 00 00 00=C2=A0 &lt;&lt;&lt;&lt;&lt; Here are zero value in s=
hadow mem so access is good<br>[25768.140730] &gt;ffffffffa07a6580: <b>00 0=
2</b> f9 f9 f9 f9 f9 <i>f9</i> <b>00 02</b> f9 f9 f9 f9 f9 f9<br>[25768.140=
733] =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 ^<br>=
[25768.140737] =C2=A0ffffffffa07a6600: <b>00 02</b> f9 f9 f9 f9 f9 f9 01 f9=
 f9 f9 f9 f9 f9 f9<br>[25768.140741] =C2=A0ffffffffa07a6680: 00 f9 f9 f9 f9=
 f9 f9 f9 00 00 00 00 00 00 00 00</font><br></div><div><br></div></div><br>=
<div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">On Wed, 17=
 Nov 2021 at 02:23, Kaiwan N Billimoria &lt;<a href=3D"mailto:kaiwan.billim=
oria@gmail.com">kaiwan.billimoria@gmail.com</a>&gt; wrote:<br></div><blockq=
uote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1p=
x solid rgb(204,204,204);padding-left:1ex"><div dir=3D"auto"><div><br><br><=
div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">On Tue, 16 =
Nov 2021, 22:07 Marco Elver, &lt;<a href=3D"mailto:elver@google.com" target=
=3D"_blank">elver@google.com</a>&gt; wrote:<br></div><blockquote class=3D"g=
mail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204=
,204,204);padding-left:1ex">On Tue, Nov 16, 2021 at 07:46PM +0530, Kaiwan N=
 Billimoria wrote:<br>
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
uote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1p=
x solid rgb(204,204,204);padding-left:1ex">
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
=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rg=
b(204,204,204);padding-left:1ex">
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
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BLMZ3r9ioqSN31w5v_Bkgs7UyPux%3D0MO8g0dQC16AxEiorBc=
g%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CA%2BLMZ3r9ioqSN31w5v_Bkgs7UyPux%3D0MO8g0dQC16A=
xEiorBcg%40mail.gmail.com</a>.<br />

--000000000000125c0c05d0fc9fa2--
