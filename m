Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTN4Z6GAMGQEO3NFMKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 01A2E4537C3
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 17:37:34 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id y40-20020a0565123f2800b003fded085638sf8391898lfa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 08:37:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637080653; cv=pass;
        d=google.com; s=arc-20160816;
        b=F/nqle3und4NRQ6uvGGRtUld5ikRyHz0nK/96vmh9nzebK3+XjnBxvrQA9wKYo8A/9
         JWQYND3eoX1ljMVLGAjF+9gOKmW0Dir26B4NFLztPOB4vTHLgahFS++g3fvEi0ND30Wi
         1YUKJApSLVXDyP30Af1r2S05q35+ojqak5vGmH4KnbaAUUJ43RpljAlUBLCHL3Zpie0C
         jy6J8OHjw0/TUktt2smexSLA3XlumDBJigNTMDWYW2/+8p1a2j6yWU3svfRmpcv7Mb6w
         E0VN81yUh7JhsOf4nP/z6G4o7hH+eN2dzX9GPtTCmIHbZk8VYY5Vo9/PpLauTheUh/l7
         4YLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=1ti8WivOPuTsmNAok0lO31ocIlaqw9Tzij1zNp8qfbI=;
        b=FTBHlLcZqz3PzUeWJzjOByE6KLFrlNqN778cIhYDSLUFVPJ9YEq/IjRhwwpyDPtOZP
         4szhyBJMQCMOjUKOJ4rVCekf8vDorT6ad5fsassY7JYf4sl5soEFV0sjYXhvAYtrOyQY
         Eau5JoXbsrgRp/Fc2RN9JckV56s/q+9xhXQlel5uVQtbmZABL9RPQYbrxv/ZGYv3ru1J
         5aMjc4fgn/eSH3IH2vrbmP0vRxmTFfL1DCWP9kCpbN0O+RoGiV5jE3RXGW4OoufGvhFe
         RnLkdf+u0irpqmZu0Wl69k3aeRimQYgrNWhS3EnBxixOgLRlgHRySWo7piVyMreyigZp
         GnBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tf1H6JKf;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=1ti8WivOPuTsmNAok0lO31ocIlaqw9Tzij1zNp8qfbI=;
        b=Iyinu6rYsTv5zr0TavhD73NWkOKf91/VyBpTPiSMUlf26/UB2CL/JwYXNJL1IoWZ38
         sosLrXh0TfcZo1zGjph7ALkWznLQKMMuHypEYwf72a9HWjBkgKKpuyF6tWK1v5WkLr/1
         bgkIcvh1O9I+Gg2DUazTUr4y+Vble8OyG/Wg6XtOxw7x6Z9KcqycWZ7jUoR0ROAdp+Qz
         YzN6WXePq6kDj4SnkwUWVlvoM46U/9YRwgQJlaG0RQLNfyga6YftIBH2JXQGwkEQ0GOX
         Nb+dyt2oDD0q5KD0HqCI1SwVjAvUwMqPSvtYqtF/OS72j4+Jq2XeMWEq0QE2aeqFNTPw
         rneg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1ti8WivOPuTsmNAok0lO31ocIlaqw9Tzij1zNp8qfbI=;
        b=VdrnxSdvYQ73U/4pL2JqAvG4XfEjBatNtUWGh+GCrGJyYpL1TqJ29JKrU20apsn63B
         qmFAevCf/uTnCh4yyfQwz/yBhSy3IVyZYV2IgYbeBeZs9WFToKo+1+t3sMuehzjyTE6J
         /hPyZuxykVhmBDExPcuLgIXjGRADVkkiR+wZdjBsh39xAdpMBaXByLJOYwbtzzog8FjV
         8lvkNwlJLF+zY1ivgYjpN30O6AHgyuXRbi0OkLxWiC2QndB1MSy5Kt3Hbe8tVmwPCEaf
         tezHPWCWUGnCC8iUzDPbne4yHzZxDtJ/3WOHUxi5dCMUH9lUBv9xLnr61WBDWT4kyHEm
         GOGg==
X-Gm-Message-State: AOAM533UZY9Ld8AsQR4iwT6BlRMveEW+h3P8sH641VBAIkqp/5Q64adI
	Murf/WrPPkOwEPdHygwZgs4=
X-Google-Smtp-Source: ABdhPJzFCT+Xl3RvLd97qIPnu+txZMAX5i0SdCOBb2i5Dl5KSM11Rg9P1diHIHkN8aIlTAk+eaXqmg==
X-Received: by 2002:a2e:b88e:: with SMTP id r14mr442769ljp.365.1637080653560;
        Tue, 16 Nov 2021 08:37:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8611:: with SMTP id a17ls358227lji.1.gmail; Tue, 16 Nov
 2021 08:37:32 -0800 (PST)
X-Received: by 2002:a05:651c:1548:: with SMTP id y8mr501594ljp.458.1637080652481;
        Tue, 16 Nov 2021 08:37:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637080652; cv=none;
        d=google.com; s=arc-20160816;
        b=TfrSzQLrl6VXGj+DAcRVKqJS2zXklITvP8LIDpUOHa3rwAIDxzRgUYIqArr56DdH9G
         WUSQQyqP4Qt1B/9DtSPPIgRoNb1Oqfu95Khkfu4QrP4DyyH5vrOtDVVC1rotpZyw8hIV
         rXHYRH3Lc7ul9tfjRvGgyMYxRmUpDWdEN/b3w8krKwFWXWyunTV+W0iDzylrRxjEdoHF
         30Hme3z1vKvt4/0Wi88B2gOdRgXhrYYTk4fZOhztEBnIfH5TY1FQX3iscJOfb0Icw1d1
         55cr282hwa7aYcFsbIyYaMUbeTW/NEJF8UeLVjG6T40qHpk3vc6tmjs6ZD/pSEBM8Dka
         5H5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=e67vX3WEbPLEdrDSDU1oq4usnXf+xAkRvSIMthcAISo=;
        b=D3hBA2gsAgCnGwX/nLclqRkAQG0V3Qu1Rmk2PZh6exg/gBXHf2MoCYpfSKP5X9luwM
         6SYtQsmr48XEVXtZotLjF3S5eKst05pyl8p27xzPXeLcJ7/NHoCmcDJ7O5mPQDlfC/1g
         doKg1OQgjxkkBDP/5Jb14zuUAjCpWvEG9+SUtRPNoNXUDzVTJeeM/otw9XrrI2MqNSF2
         bdeHTMc078wpduGywl07Q37Ku4a7d7QBHE8m9aG3jEcE/Okmf/OQ5Jjvinmny4h3nzaw
         R37OBnJWrguk7zTngxXr8F+NyqTS+st9oVg9kdC+R7QHrBv4qtKdJrmy9haLL3jxml9w
         hISQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tf1H6JKf;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id t12si1605137ljh.0.2021.11.16.08.37.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 08:37:32 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id p18so8201952wmq.5
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 08:37:32 -0800 (PST)
X-Received: by 2002:a1c:23cb:: with SMTP id j194mr71731195wmj.13.1637080651610;
        Tue, 16 Nov 2021 08:37:31 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:ee27:74df:199e:beab])
        by smtp.gmail.com with ESMTPSA id n32sm3894156wms.1.2021.11.16.08.37.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Nov 2021 08:37:30 -0800 (PST)
Date: Tue, 16 Nov 2021 17:37:24 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
Cc: kasan-dev@googlegroups.com, Chi-Thanh Hoang <chithanh.hoang@gmail.com>
Subject: Re: KASAN isn't catching rd/wr underflow bugs on static global
 memory?
Message-ID: <YZPeRGpOTSgXjaE6@elver.google.com>
References: <a2ced905703ede4465f3945eb3ae4e615c02faf8.camel@gmail.com>
 <CANpmjNNSRVMO+PJWvpP=w+V6CR51Yd-r2ku_fVEvymae0g7JaQ@mail.gmail.com>
 <c2693ecb223eb634f4fa94101c4cb98999ef0032.camel@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c2693ecb223eb634f4fa94101c4cb98999ef0032.camel@gmail.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=tf1H6JKf;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as
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

On Tue, Nov 16, 2021 at 07:46PM +0530, Kaiwan N Billimoria wrote:
> On Tue, 2021-11-16 at 12:52 +0100, Marco Elver wrote:
> > 
> > KASAN globals support used to be limited in Clang. This was fixed in
> > Clang 11. I'm not sure about GCC.
> ...
> > > Which compiler versions are you using? This is probably the most
> > important piece to the puzzle.
> > 
> Right! This is the primary issue i think, thanks!
> am currently using gcc 9.3.0.
> 
> So, my Ubuntu system had clang-10; I installed clang-11 on top of it...
> (this causes some issues?). Updated the Makefile to use clang-11, and it did build.

Only the test or the whole kernel? You need to build the whole kernel
and your module with the same compiler, otherwise all bets are off wrt
things like KASAN.

> But when running these tests, *only* UBSAN was triggered, KASAN unseen.
> So: I then rebuilt the 5.10.60 kernel removing UBSAN config and retried (same module rebuilt w/ clang 11).
> This time UBSAN didn't pop up but nor did KASAN ! (For the same rd/wr underflow testcases)...
> My script + dmesg:
> ...
> (Type in the testcase number to run): 
> 4.4
> Running testcase "4.4" via test module now...
> [  371.368096] testcase to run: 4.4
> $ 
> 
> This implies it escaped unnoticed..
> 
> To show the difference, here's my testcase #4.1- Read  (right) overflow on global memory - output:
> 
> Running testcase "4.1" via test module now...
> [ 1372.401484] testcase to run: 4.1
> [ 1372.401515] ==================================================================
> [ 1372.402284] BUG: KASAN: global-out-of-bounds in static_mem_oob_right+0xaf/0x160 [test_kmembugs]
> [ 1372.402851] Read of size 1 at addr ffffffffc088dfcc by task run_tests/1656
> 
> [ 1372.403428] CPU: 2 PID: 1656 Comm: run_tests Tainted: G    B      O      5.10.60-dbg02 #14
> [ 1372.403442] Hardware name: innotek GmbH VirtualBox/VirtualBox, BIOS VirtualBox 12/01/2006
> [ 1372.403454] Call Trace:
> [ 1372.403486]  dump_stack+0xbd/0xfa
> 
> [... lots more, as expected ...]
> 
> So, am puzzled... why isn't KASAN catching the underflow...

Please take a look at the paragraph at:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/lib/test_kasan.c#n706

I think your test is giving the compiler opportunities to miscompile
your code, because, well it has undefined behaviour (negative index)
that it very clearly can see. I think you need to put more effort into
hiding the UB from the optimizer like we do in test_kasan.c.

If you want to know in detail what's happening I recommend you
disassemble your compiled code and check if the negative dereferences
are still there.

> A couple of caveats:
> 1) I had to manually setup a soft link to llvm-objdump (it was installed as llvm-objdump-11)
> 2) the module build initially failed with
> /bin/sh: 1: ld.lld: not found
> So I installed the 'lld' package; then the build worked..
> 
> Any thoughts?

Is this "make LLVM=1". Yeah, if there's a version suffix it's known to
be problematic.

You can just build the kernel with "make CC=clang" and it'll use
binutils ld, which works as well.

> > FWIW, the kernel has its own KASAN test suite in lib/test_kasan.c.
> > There are a few things to not make the compiler optimize away
> > explicitly buggy code, so I'd also suggest you embed your test in
> > test_kasan and see if it changes anything (unlikely but worth a shot).
> I have studied it, and essentially copied it's techniques where required... Interestingly, the kernel's test_kasan module does _not_ have a test case for this: underflow on global memory! :-)

I just added such a test (below) and it passes just fine with clang 11
(I'll probably send it as a real patch later). Notice that the address
itself ("array") is a volatile, so that the compiler cannot make any
assumptions about it.

Thanks,
-- Marco

------ >8 ------

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 67ed689a0b1b..e56c9eb3f16e 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -700,7 +700,7 @@ static void kmem_cache_bulk(struct kunit *test)
 
 static char global_array[10];
 
-static void kasan_global_oob(struct kunit *test)
+static void kasan_global_oob_right(struct kunit *test)
 {
 	/*
 	 * Deliberate out-of-bounds access. To prevent CONFIG_UBSAN_LOCAL_BOUNDS
@@ -723,6 +723,15 @@ static void kasan_global_oob(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
+static void kasan_global_oob_left(struct kunit *test)
+{
+	char *volatile array = global_array;
+	char *p = array - 3;
+
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
+	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
+}
+
 /* Check that ksize() makes the whole object accessible. */
 static void ksize_unpoisons_memory(struct kunit *test)
 {
@@ -1160,7 +1169,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmem_cache_oob),
 	KUNIT_CASE(kmem_cache_accounted),
 	KUNIT_CASE(kmem_cache_bulk),
-	KUNIT_CASE(kasan_global_oob),
+	KUNIT_CASE(kasan_global_oob_right),
+	KUNIT_CASE(kasan_global_oob_left),
 	KUNIT_CASE(kasan_stack_oob),
 	KUNIT_CASE(kasan_alloca_oob_left),
 	KUNIT_CASE(kasan_alloca_oob_right),

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YZPeRGpOTSgXjaE6%40elver.google.com.
