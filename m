Return-Path: <kasan-dev+bncBDPJLN7A4MFRBXX2Z2GAMGQENMUYONI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 771934533EB
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 15:17:04 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id d14-20020a056e02214e00b0026cd53452f7sf12757468ilv.22
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 06:17:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637072223; cv=pass;
        d=google.com; s=arc-20160816;
        b=fArYE9wS5fOYYQzjE0ocvNWxf7wEPBoIipaum/QrusTqZA7sWsh1vAdePTchPBgpcN
         HoAL/pyGwh2lvNE/ztpmzyy/vuHbb12kJTQhGbJjfmPocpIiFPNqCQnDLaE7sUPJTv1B
         OSgFZKK4MppE04Z5xZJqwFgejMYEZ3p8DKBcW/xzz3QoMHsJ2nqIX1DIW68gbMPrCBHa
         stdd/I+Sl7hUGwY9zgfn2Hd95uCWifXtfX7SW2BsavrNwu+zu/6dGtI1ikt4s8lbEUWO
         meJ1QW2jYScEniFLS5dLoqvDwx6Zz2YriXUyxqXwWDuh7d+xVLiH9e8TIYIJHeSOoEfp
         RReg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature:dkim-signature;
        bh=qrgK+RTOoLuKZAil+um9Xwz27wI56AADV9CbiIcehCY=;
        b=nnObK+1kAH3i62qGiscnj4eIBBVuIiHfdzue7PZCFO6rTICjmWagskJvbe3LHvFyNS
         lATJvspBu7N/XH/s+Q73oRunDtcVJDKVeYlPJj7PRpqvBPVaET66vl23kI3OoxXygwzQ
         pXh9Qq7+W96W6mwg4qKiWJrreQYFLryBbls8pkCwgp5p2pGOwNbgtupkpZhU/6NNHci4
         OM4RxkWhJ7kUrXJQdhc0rsmj8uiJLyBLLToPJ6jsk29sAzp7uiJwcVsqBOMZlLzvw7i6
         bScV5RUTtL8vYdaTEzO0LsgD1LH4NnwnJPLrAdANgNh76IdbsDivzr6CIZFLj8YvhqWw
         w4kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=fn+5JrZJ;
       spf=pass (google.com: domain of kaiwan.billimoria@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=kaiwan.billimoria@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qrgK+RTOoLuKZAil+um9Xwz27wI56AADV9CbiIcehCY=;
        b=E0rlnlVOUmrybh3REY8728EhDVyZxRRoW0IEV3QYYUVyFrmaon9IU5lMr1cPK5h5Im
         NlA5oHMgz/cb25uljXBEmsZ4T/Y5ydaLhTvnXf+R+6bXb/jSYJH2LGj/XWMP3H6IJPbJ
         I2q/V5KGniWB9KzxiHoSmQQuWSeyImXQKuv2z1UOtzU9JBs3XPaNnap7q4dXxzG+r5tr
         Dwd4NiLVC7IxW9m5vX6fTPAP1Ghr7+QiGTo0iQlwnyQlG++JmdDF1NNhi+Z36ZqQ2KzP
         MRJUgkT38xm+Ul0FT8jjpYZCLLil2rLNDrJUTGlvdNXmmhGfHxCOsQDqBJuoBdi21Guo
         bP3A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qrgK+RTOoLuKZAil+um9Xwz27wI56AADV9CbiIcehCY=;
        b=HzB5QDnwpn5L1ojyio4Yugx50+NUXIKSDjRxrJ8h8eXfRxbxQGx3kMF9obNGHdWD7Q
         p5DuGETF+Lm8fwxCUZvBJk8qDKUw6j3NfNqo4iBXKqerxcMuktrNLEpQoutGyXwJNsrq
         ramKfzLyfSvV7UHU3/LlmqDfxblWGhCF5XJDAAorrlLMLFaOS4l+xDHm/U85iCF6zz0W
         2UTSC2ewDoGr2Q+x4GHF0QZuecwx/Q+kMqrCT33s7UTGctQPx7uFaqwDExN+mfJlke3e
         3rDqw/r/q2oVSvoeAxbg0i78xqFI0t1dqLvIkhzMdUqqT2M1DNosmeJyEfj4scoRMRpS
         /akw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qrgK+RTOoLuKZAil+um9Xwz27wI56AADV9CbiIcehCY=;
        b=bHPn8s1W5a/SyW6QQ+lanowII7rgFgy+gHdbnifKisvHe5q1eMYijHoAa1kTuqWKa7
         Pgob0Dm0R5wnWENPEN3nL5Sx4r1l77NBs+XyGS9ZrckTxHvcUYBj+kPJFhu0xvpUEPw3
         ll3QiuGm2d41Eiccfht/n3Tr7kOsNboazHg8rK7kG/D7+uoC7c3u/z1p660RUxlz/r1K
         x1bgmnW5DH9+QsKitLvz99AYWvLjH4rwhlCXehtkUhFCXbVeJXp9P2KZLT8ea8JVMAUo
         Hrm3PhSitw2JO5RIdKdI0bQciFgEYbxmRYWmLphSnBdN5tJ2fLAa5WdnzLaeoBxx3MHg
         KgQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Y/zgROyg/4LjQYo5NQOzC50t1CNmKs2CcYcdICRTxVawlYNiA
	3gewJn+HrFktsC2VUTwZMhs=
X-Google-Smtp-Source: ABdhPJw+g9BTC9C7Cw8C+BOQrUUylGBRjUqXeB7enNAiCvfHOL4Xd8GJUPPPeqXJ99ZdkI75z5GsNg==
X-Received: by 2002:a05:6638:dd5:: with SMTP id m21mr5765214jaj.44.1637072223047;
        Tue, 16 Nov 2021 06:17:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:cf81:: with SMTP id w1ls1667421jar.9.gmail; Tue, 16 Nov
 2021 06:17:02 -0800 (PST)
X-Received: by 2002:a02:a11d:: with SMTP id f29mr5867436jag.78.1637072221855;
        Tue, 16 Nov 2021 06:17:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637072221; cv=none;
        d=google.com; s=arc-20160816;
        b=K5coqFwFpR7aWQJ8Or5Yepdx9z3CddjLDQM+CZpEY7sjMhRugP2yDKp8M7Sw3ut0lg
         eAXFlIaRBlucTiLngVj0W5fKR2IaDx32HvH54qPw2n9WH49xsBdQI35Wyj0vi3LfX6VY
         HL+0vYhL4uxlWqRS3t5j4qd6J951Rp/wSDrLFIvdaL8Faa4NekJjxQOhnsqmst/P+V42
         PHf0Uk/QaNWzF0pnIZKX3QYWl267bt76l8Aeu3SftqmaJcXt+Qa+xNc/QcR8vkS1aeq+
         LMAR6uHSAiJHgyRlig6aYs/4AIHcrh7sJM6o8+mKPDSumU1QPbvNkQp/Wj6/utopOGJ3
         /Qpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=pMIsc3ZUJURYAPxXNgmbrdmsnAq9AnG3w6LrCE8fzlw=;
        b=TLn7LArYDbw8ueoDqDLKFqkDHMYHgywSTMJEKvC6MLGenA3WM2VJ0sT7Q5vZSSVcWl
         kshJhkR0SJM3Alp2XmzWqHfY7ORI2Q7d+dpaAaogX1EeXN5WmagZcqqFPkzwngmV55XM
         YOcsS/t81CgLL3pXqwoJnvDKG/SaIwrc7Q1VExjky7EePKEDWq9bLH+E/OReJbwsd24T
         wqBSlMuW5GS2ifMP5zLoSBEfzNrVcS1ThQNvy6bXZDfrutT4PhFt9/Rs763NW66T6Jhx
         g1chebXbt/eaDnyXbunB+zWUkvIsQJQjPecyqfKflqo8F3XqOIUQhgExVqWE5f6Ah60h
         pEug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=fn+5JrZJ;
       spf=pass (google.com: domain of kaiwan.billimoria@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=kaiwan.billimoria@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id o6si1127225ill.3.2021.11.16.06.17.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 06:17:01 -0800 (PST)
Received-SPF: pass (google.com: domain of kaiwan.billimoria@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id y8so12057317plg.1
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 06:17:01 -0800 (PST)
X-Received: by 2002:a17:902:d491:b0:142:1c30:dc17 with SMTP id c17-20020a170902d49100b001421c30dc17mr45355426plg.14.1637072221410;
        Tue, 16 Nov 2021 06:17:01 -0800 (PST)
Received: from k7550 ([103.214.62.4])
        by smtp.gmail.com with ESMTPSA id b23sm6022944pgg.73.2021.11.16.06.16.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Nov 2021 06:17:00 -0800 (PST)
Message-ID: <c2693ecb223eb634f4fa94101c4cb98999ef0032.camel@gmail.com>
Subject: Re: KASAN isn't catching rd/wr underflow bugs on static global
 memory?
From: Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, Chi-Thanh Hoang <chithanh.hoang@gmail.com>
Date: Tue, 16 Nov 2021 19:46:56 +0530
In-Reply-To: <CANpmjNNSRVMO+PJWvpP=w+V6CR51Yd-r2ku_fVEvymae0g7JaQ@mail.gmail.com>
References: <a2ced905703ede4465f3945eb3ae4e615c02faf8.camel@gmail.com>
	 <CANpmjNNSRVMO+PJWvpP=w+V6CR51Yd-r2ku_fVEvymae0g7JaQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.36.5-0ubuntu1
MIME-Version: 1.0
X-Original-Sender: kaiwan.billimoria@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=fn+5JrZJ;       spf=pass
 (google.com: domain of kaiwan.billimoria@gmail.com designates
 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=kaiwan.billimoria@gmail.com;
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

On Tue, 2021-11-16 at 12:52 +0100, Marco Elver wrote:
> 
> KASAN globals support used to be limited in Clang. This was fixed in
> Clang 11. I'm not sure about GCC.
...
> > Which compiler versions are you using? This is probably the most
> important piece to the puzzle.
> 
Right! This is the primary issue i think, thanks!
am currently using gcc 9.3.0.

So, my Ubuntu system had clang-10; I installed clang-11 on top of it...
(this causes some issues?). Updated the Makefile to use clang-11, and it did build.

But when running these tests, *only* UBSAN was triggered, KASAN unseen.
So: I then rebuilt the 5.10.60 kernel removing UBSAN config and retried (same module rebuilt w/ clang 11).
This time UBSAN didn't pop up but nor did KASAN ! (For the same rd/wr underflow testcases)...
My script + dmesg:
...
(Type in the testcase number to run): 
4.4
Running testcase "4.4" via test module now...
[  371.368096] testcase to run: 4.4
$ 

This implies it escaped unnoticed..

To show the difference, here's my testcase #4.1- Read  (right) overflow on global memory - output:

Running testcase "4.1" via test module now...
[ 1372.401484] testcase to run: 4.1
[ 1372.401515] ==================================================================
[ 1372.402284] BUG: KASAN: global-out-of-bounds in static_mem_oob_right+0xaf/0x160 [test_kmembugs]
[ 1372.402851] Read of size 1 at addr ffffffffc088dfcc by task run_tests/1656

[ 1372.403428] CPU: 2 PID: 1656 Comm: run_tests Tainted: G    B      O      5.10.60-dbg02 #14
[ 1372.403442] Hardware name: innotek GmbH VirtualBox/VirtualBox, BIOS VirtualBox 12/01/2006
[ 1372.403454] Call Trace:
[ 1372.403486]  dump_stack+0xbd/0xfa

[... lots more, as expected ...]

So, am puzzled... why isn't KASAN catching the underflow...

A couple of caveats:
1) I had to manually setup a soft link to llvm-objdump (it was installed as llvm-objdump-11)
2) the module build initially failed with
/bin/sh: 1: ld.lld: not found
So I installed the 'lld' package; then the build worked..

Any thoughts?
...

> 
> FWIW, the kernel has its own KASAN test suite in lib/test_kasan.c.
> There are a few things to not make the compiler optimize away
> explicitly buggy code, so I'd also suggest you embed your test in
> test_kasan and see if it changes anything (unlikely but worth a shot).
I have studied it, and essentially copied it's techniques where required... Interestingly, the kernel's test_kasan module does _not_ have a test case for this: underflow on global memory! :-)

Thanks,
Kaiwan.

> 
> If you are using GCC, can you try again with Clang 11 or 12?
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c2693ecb223eb634f4fa94101c4cb98999ef0032.camel%40gmail.com.
