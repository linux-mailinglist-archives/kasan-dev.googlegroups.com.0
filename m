Return-Path: <kasan-dev+bncBCEZPNXX34KRBEED26GAMGQEHNPOHYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 222664552FF
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 03:59:30 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id a16-20020a17090aa51000b001a78699accesf4160424pjq.8
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 18:59:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637204368; cv=pass;
        d=google.com; s=arc-20160816;
        b=V+AgvoesE5DV9B7fn+/7a+F36XvGP8skNvXW4Y0RAlFpxjEOc/7Z+/mhwAftfFMbzX
         0JXnooKLj1G4FgIpNUId8oqXUAJAxs3pv5dMVB2GYCV35DXc7sNY5vuBa1jY+SKU5jcq
         MbGqq+jyJcB+GLCuJyMGcJLzJFhuhjfuaDxVvIY4VxWuPi4VJds+6ScQhIQKK4MuY1j4
         r1bwMPISeIdLSUe4F9DIah3A4aUQtyU6U2dJ9CT7Lo6UjMFarvVRgGtpI1EgIXfwQt+8
         jPYVnLz0dgTUBGuOB/A2skDfyhR1DeMlh5wwavnB/5FCYc9658NS2PwNgiA3SZogakGS
         meUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=7gR6CYGHg+rURD842xYPpYx29L4bTDLUFaTiQvJ2LY0=;
        b=S1TZfcCuBQYqy7EyHVqi9/SzTraQ9JOFWWiwDX5sV1raHiFZHmauJPwbqjZE1LN3Y8
         EsD/J68hp8hNP48aPOzvfAC3cVapNde3004QTkO2f2GSbwWG99g1KQJEjxZP98jNda6l
         /6GJ6aYijdo9rj3eOeL0t1GytUsANIQV95Nkr6uNHNQxgOBtWhfgqMag0hXYON4n7Cuf
         q/x/WapryFGfmd9XL/aCCPZbshQ3TKB7GDjG7WksGrdjW112lB+YHsEPaY04WRVDpQtE
         2M8tJBQg8PJRBygf8o22EQ3ddujiTnz4xZIqr1MEtssFCRJuBSi3l45zD7FixEDhYqql
         VrwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=l1VbhvJq;
       spf=pass (google.com: domain of chithanh.hoang@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=chithanh.hoang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7gR6CYGHg+rURD842xYPpYx29L4bTDLUFaTiQvJ2LY0=;
        b=iqlfo8oxKBOkw16sFqZDrWSdrsgdxm8dU6C3gLs1VejUw0S6HFbKMPwlmViumPKOre
         KbXmsa0Ls07UbuEiXO62MK3CDhqTbGDRYE3pLzyuVWT3wvQDiKeQvmlb8ZVP6F8bJAeD
         uirwRyM2VjLUg52B0TY9AoMDLojVt1y3wBSSippQ0aSHGcP6vV1ii97DjxYv/JzFn+/3
         qJt14D/TwzrpwLht5f0h7Ew7/8jrrpdIQo7qO13OqB5GsBCjEtesl7Q3e9pxTLOguxGq
         RlKM42Sk77DVXWMOk88JHjT8HWGoBFW6wZfBTuj6zFb3+hYmk8j/o/5427FaMPzEWn+x
         9JRA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7gR6CYGHg+rURD842xYPpYx29L4bTDLUFaTiQvJ2LY0=;
        b=H/bunD9puKCh7e+h6cBJnITeZnhfpcULviAyO7X+ZOhMAjNVJ8Ld4bobaNMr0OCdn7
         CRv2cuTe4tgYh8Yz9xXfigJkDAkXvMbqi4tmW/9zpnaQfuP+z6vp99rwGtkW3enL6b3y
         1apEazd6PYUSJI+XYgXRR157kojulJmGEeouB1ejgNGgFzlYOhU2wvHi6Bm+MlTaz3RK
         s6TNlj17O0ARn/zdNVcYXmw4GTEYV8LDND9L3WUGtiA3yewtmstP6sl+Rms3E4nH3c17
         RWLeaZ4Fdkv5w8aZMV+kdq4EhPegodWB3/nL59BdnCvnClv68LE2dr2cgUn4i0r4/BKm
         kNaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7gR6CYGHg+rURD842xYPpYx29L4bTDLUFaTiQvJ2LY0=;
        b=fsuW61UqPTwmSzzvZqU+q5uf/5SrMseHhlmH42tmxcO4urRdgr6qPYvl0pu2aczF16
         WgSEsRwVQtNeDF4aOFzOyq5QjJUevzxwbQFTLXuaG+PfYb+tF/bo5hZAKLPdGtB5760I
         RhFLeZTRIrY+BjB0bFwjrJ4TSkRm8vk856YOOEKsyS6xz7HU9hK9sg4SG76Hh5xhPmzo
         5af4eoapZBYGlS8oPKLksEJKAARPTCZh8lCjJG/s1IhxFbcLwyNuvlOmlXAdFwAwspwx
         wV/l/uYBbAZJWmjTCVI58FPIdjMO7UUEC5RyZ720bv5iKVkD4yNnNBLd5WiBc9xgjsMK
         yW0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532zaHJ1/BkFpujE3JaWl5UedC0eMGas5xMSP0w8nsQVaKT+y2HT
	SebsSKdVPg17S1sLBr6SQmw=
X-Google-Smtp-Source: ABdhPJxr2InBjnmElqcP1heZ8NlwUsvJzaN9/M0LnCe2t06nhRBKaEBleGG3SuqyUgGX4KD1Y8+MGg==
X-Received: by 2002:a05:6a00:140c:b0:44b:e251:fe13 with SMTP id l12-20020a056a00140c00b0044be251fe13mr11879945pfu.10.1637204368373;
        Wed, 17 Nov 2021 18:59:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1c05:: with SMTP id c5ls461502pgc.6.gmail; Wed, 17 Nov
 2021 18:59:27 -0800 (PST)
X-Received: by 2002:a63:91c7:: with SMTP id l190mr8031541pge.447.1637204367708;
        Wed, 17 Nov 2021 18:59:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637204367; cv=none;
        d=google.com; s=arc-20160816;
        b=PofY7D2URaudja5iZkad+vkyEY8thkB858RCA4p8flmCqvjTBCIe3K9UkO98M0Z55r
         z+DircwIRDwijpUfJKyfihyQfIot/JMBrlESImNK/DmPUfx7djDaauwlnpJJ7ucn7OaA
         39SPze25amXG/GwPn3v9dz2timSfwN9uKJBY9wH8nKWA/O8OVarT/GHnNVVzgYvZ99TH
         g96stQ3nCAQxSDA/dpb5TjVY8XlVmxueEKnxfuWmzfn9L5yHjC+QXvvBh+hBvIBdznd+
         ul5RwgELUUelvv+N8c1DrY3NeQwX83G52C71+Aipy8IDwfuD8q5sh7QdXYZI19I3lAZR
         +qaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=c1n2VocZrwNIf3Tn3vbYwvjWty5HMUJpwwN5pId01ug=;
        b=mveK/Fu14gtUvXcygVpr+PI4V0HadKQIvYTfCQd2CCFq1o6Xq4Lsw1cMeZaOv9aLR4
         1BoF6qhQQP9+oRqXu1/z8helRZYWphnnxjbfr5tfGkPyKOadckDy5ke8pCP0WYsHoV7+
         qmj4KmK5mmGG4evTosanTDu9fETzGCxevYvuTUOWzlYpO+Gb7UN4kpPgCZbGbhd62MVg
         MNl4P23JacXPijwFKjzfF3D5WtGOei8MsFyMqnYyrPWD6sJtsskKzMtcwDhjurpF2RRa
         mv8aXSD/Lhlp94mJTRpi5cdb63nq6ih8ussQ2yJLi48pXH2dh+fe954wb+rO50LYy6X2
         /3xA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=l1VbhvJq;
       spf=pass (google.com: domain of chithanh.hoang@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=chithanh.hoang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id mq9si914672pjb.3.2021.11.17.18.59.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Nov 2021 18:59:27 -0800 (PST)
Received-SPF: pass (google.com: domain of chithanh.hoang@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id k4so3951473plx.8
        for <kasan-dev@googlegroups.com>; Wed, 17 Nov 2021 18:59:27 -0800 (PST)
X-Received: by 2002:a17:90a:be10:: with SMTP id a16mr6055005pjs.133.1637204367371;
 Wed, 17 Nov 2021 18:59:27 -0800 (PST)
MIME-Version: 1.0
References: <a2ced905703ede4465f3945eb3ae4e615c02faf8.camel@gmail.com>
 <CANpmjNNSRVMO+PJWvpP=w+V6CR51Yd-r2ku_fVEvymae0g7JaQ@mail.gmail.com>
 <c2693ecb223eb634f4fa94101c4cb98999ef0032.camel@gmail.com>
 <YZPeRGpOTSgXjaE6@elver.google.com> <CAPDLWs88WLTPVnh1TtY3tOU6XLPucf8zKMhzCfxRv2HbCnKndA@mail.gmail.com>
 <CA+LMZ3r9ioqSN31w5v_Bkgs7UyPux=0MO8g0dQC16AxEiorBcg@mail.gmail.com> <CANpmjNMzv2b1srETOp1STjVWYZx-1XpdMm5yY485vSmd=wjJiw@mail.gmail.com>
In-Reply-To: <CANpmjNMzv2b1srETOp1STjVWYZx-1XpdMm5yY485vSmd=wjJiw@mail.gmail.com>
From: Chi-Thanh Hoang <chithanh.hoang@gmail.com>
Date: Wed, 17 Nov 2021 21:59:16 -0500
Message-ID: <CA+LMZ3qhJ1dnS3O9vKRA1DCF93Lpi-xq9PmStwhWC+ykRSGr_g@mail.gmail.com>
Subject: Re: KASAN isn't catching rd/wr underflow bugs on static global memory?
To: Marco Elver <elver@google.com>
Cc: Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>, kasan-dev@googlegroups.com
Content-Type: multipart/alternative; boundary="000000000000bdefd705d107584f"
X-Original-Sender: chithanh.hoang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=l1VbhvJq;       spf=pass
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

--000000000000bdefd705d107584f
Content-Type: text/plain; charset="UTF-8"

Thanks Marco for creating the bugzilla.
I will post my findings.
I found the Clang compiler quite smart when comparing code generated vs
gcc, i.e. clang would not bother generating code that are OOB when indexing
[ ].

On Wed, 17 Nov 2021 at 09:14, Marco Elver <elver@google.com> wrote:

> On Wed, 17 Nov 2021 at 15:11, Chi-Thanh Hoang <chithanh.hoang@gmail.com>
> wrote:
> >
> > I managed to figure out why the global OOB-left is not being detected
> and work around the issue 8-)
> > I am still using gcc 9.3.0.
>
> Yeah, gcc is doing worse here. I just filed:
> https://bugzilla.kernel.org/show_bug.cgi?id=215051
>
> Clang 11+ doesn't have this issue.
>
> Please, if you can, post your findings to the bugzilla bug above. Then
> we can perhaps take it to gcc devs and ask them to do the same as
> clang or fix it some other way.
>
> Thanks,
> -- Marco
>
> > I notice KASAN detects fine when OOB happen in overflow, KASAN shown the
> status of shadow memory around the OOB, I see there is no redzone for the
> global before the allocated memory, there is redzone after, if the global
> is the first declared object in the .bss example, there is no redzone in
> front of it so shadow memory are zero, that is why KASAN did not detect.
> > I then do the following, I declare 3 globals array in .bss, and test the
> OOB underflow on the second array and KASAN does detect as doing -1 will
> fall into the redzone of the first object.
> > I agree this is kind of a corner case, but to fix this I guess we need
> to provide redzone in front of the first global either in .bss or .data,
> and if possible to configure the size of such redzone.
> >
> > at ffffffffa07a6580 is start of .bss, in the log below there is 3 arrays
> of 10 bytes (00 02 from shadow mem), the fault detected as shown on the 2nd
> array when I do a -1 reference.
> > [25768.140717] Memory state around the buggy address:
> > [25768.140721]  ffffffffa07a6480: 00 00 00 00 00 00 00 00 00 00 00 00 00
> 00 00 00
> > [25768.140725]  ffffffffa07a6500: 00 00 00 00 00 00 00 00 00 00 00 00 00
> 00 00 00  <<<<< Here are zero value in shadow mem so access is good
> > [25768.140730] >ffffffffa07a6580: 00 02 f9 f9 f9 f9 f9 f9 00 02 f9 f9 f9
> f9 f9 f9
> > [25768.140733]                                         ^
> > [25768.140737]  ffffffffa07a6600: 00 02 f9 f9 f9 f9 f9 f9 01 f9 f9 f9 f9
> f9 f9 f9
> > [25768.140741]  ffffffffa07a6680: 00 f9 f9 f9 f9 f9 f9 f9 00 00 00 00 00
> 00 00 00
> >
> >
> > On Wed, 17 Nov 2021 at 02:23, Kaiwan N Billimoria <
> kaiwan.billimoria@gmail.com> wrote:
> >>
> >>
> >>
> >> On Tue, 16 Nov 2021, 22:07 Marco Elver, <elver@google.com> wrote:
> >>>
> >>> On Tue, Nov 16, 2021 at 07:46PM +0530, Kaiwan N Billimoria wrote:
> >>> > On Tue, 2021-11-16 at 12:52 +0100, Marco Elver wrote:
> >>> > >
> >>> > > KASAN globals support used to be limited in Clang. This was fixed
> in
> >>> > > Clang 11. I'm not sure about GCC.
> >>> > ...
> >>> > > > Which compiler versions are you using? This is probably the most
> >>> > > important piece to the puzzle.
> >>> > >
> >>> > Right! This is the primary issue i think, thanks!
> >>> > am currently using gcc 9.3.0.
> >>> >
> >>> > So, my Ubuntu system had clang-10; I installed clang-11 on top of
> it...
> >>> > (this causes some issues?). Updated the Makefile to use clang-11,
> and it did build.
> >>>
> >>> Only the test or the whole kernel? You need to build the whole kernel
> >>> and your module with the same compiler, otherwise all bets are off wrt
> >>> things like KASAN.
> >>
> >> Ah, will do so and let you know, thanks!
> >>
> >>
> >>>
> >>> > But when running these tests, *only* UBSAN was triggered, KASAN
> unseen.
> >>> > So: I then rebuilt the 5.10.60 kernel removing UBSAN config and
> retried (same module rebuilt w/ clang 11).
> >>> > This time UBSAN didn't pop up but nor did KASAN ! (For the same
> rd/wr underflow testcases)...
> >>> > My script + dmesg:
> >>> > ...
> >>> > (Type in the testcase number to run):
> >>> > 4.4
> >>> > Running testcase "4.4" via test module now...
> >>> > [  371.368096] testcase to run: 4.4
> >>> > $
> >>> >
> >>> > This implies it escaped unnoticed..
> >>> >
> >>> > To show the difference, here's my testcase #4.1- Read  (right)
> overflow on global memory - output:
> >>> >
> >>> > Running testcase "4.1" via test module now...
> >>> > [ 1372.401484] testcase to run: 4.1
> >>> > [ 1372.401515]
> ==================================================================
> >>> > [ 1372.402284] BUG: KASAN: global-out-of-bounds in
> static_mem_oob_right+0xaf/0x160 [test_kmembugs]
> >>> > [ 1372.402851] Read of size 1 at addr ffffffffc088dfcc by task
> run_tests/1656
> >>> >
> >>> > [ 1372.403428] CPU: 2 PID: 1656 Comm: run_tests Tainted: G    B
> O      5.10.60-dbg02 #14
> >>> > [ 1372.403442] Hardware name: innotek GmbH VirtualBox/VirtualBox,
> BIOS VirtualBox 12/01/2006
> >>> > [ 1372.403454] Call Trace:
> >>> > [ 1372.403486]  dump_stack+0xbd/0xfa
> >>> >
> >>> > [... lots more, as expected ...]
> >>> >
> >>> > So, am puzzled... why isn't KASAN catching the underflow...
> >>>
> >>> Please take a look at the paragraph at:
> >>>
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/lib/test_kasan.c#n706
> >>>
> >>> I think your test is giving the compiler opportunities to miscompile
> >>> your code, because, well it has undefined behaviour (negative index)
> >>> that it very clearly can see. I think you need to put more effort into
> >>> hiding the UB from the optimizer like we do in test_kasan.c.
> >>>
> >>> If you want to know in detail what's happening I recommend you
> >>> disassemble your compiled code and check if the negative dereferences
> >>> are still there.
> >>
> >> Will recheck...
> >>
> >> Thanks, Kaiwan.
> >>>
> >>>
> >>> > A couple of caveats:
> >>> > 1) I had to manually setup a soft link to llvm-objdump (it was
> installed as llvm-objdump-11)
> >>> > 2) the module build initially failed with
> >>> > /bin/sh: 1: ld.lld: not found
> >>> > So I installed the 'lld' package; then the build worked..
> >>> >
> >>> > Any thoughts?
> >>>
> >>> Is this "make LLVM=1". Yeah, if there's a version suffix it's known to
> >>> be problematic.
> >>>
> >>> You can just build the kernel with "make CC=clang" and it'll use
> >>> binutils ld, which works as well.
> >>>
> >>> > > FWIW, the kernel has its own KASAN test suite in lib/test_kasan.c.
> >>> > > There are a few things to not make the compiler optimize away
> >>> > > explicitly buggy code, so I'd also suggest you embed your test in
> >>> > > test_kasan and see if it changes anything (unlikely but worth a
> shot).
> >>> > I have studied it, and essentially copied it's techniques where
> required... Interestingly, the kernel's test_kasan module does _not_ have a
> test case for this: underflow on global memory! :-)
> >>>
> >>> I just added such a test (below) and it passes just fine with clang 11
> >>> (I'll probably send it as a real patch later). Notice that the address
> >>> itself ("array") is a volatile, so that the compiler cannot make any
> >>> assumptions about it.
> >>>
> >>> Thanks,
> >>> -- Marco
> >>>
> >>> ------ >8 ------
> >>>
> >>> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> >>> index 67ed689a0b1b..e56c9eb3f16e 100644
> >>> --- a/lib/test_kasan.c
> >>> +++ b/lib/test_kasan.c
> >>> @@ -700,7 +700,7 @@ static void kmem_cache_bulk(struct kunit *test)
> >>>
> >>>  static char global_array[10];
> >>>
> >>> -static void kasan_global_oob(struct kunit *test)
> >>> +static void kasan_global_oob_right(struct kunit *test)
> >>>  {
> >>>         /*
> >>>          * Deliberate out-of-bounds access. To prevent
> CONFIG_UBSAN_LOCAL_BOUNDS
> >>> @@ -723,6 +723,15 @@ static void kasan_global_oob(struct kunit *test)
> >>>         KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
> >>>  }
> >>>
> >>> +static void kasan_global_oob_left(struct kunit *test)
> >>> +{
> >>> +       char *volatile array = global_array;
> >>> +       char *p = array - 3;
> >>> +
> >>> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
> >>> +       KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
> >>> +}
> >>> +
> >>>  /* Check that ksize() makes the whole object accessible. */
> >>>  static void ksize_unpoisons_memory(struct kunit *test)
> >>>  {
> >>> @@ -1160,7 +1169,8 @@ static struct kunit_case
> kasan_kunit_test_cases[] = {
> >>>         KUNIT_CASE(kmem_cache_oob),
> >>>         KUNIT_CASE(kmem_cache_accounted),
> >>>         KUNIT_CASE(kmem_cache_bulk),
> >>> -       KUNIT_CASE(kasan_global_oob),
> >>> +       KUNIT_CASE(kasan_global_oob_right),
> >>> +       KUNIT_CASE(kasan_global_oob_left),
> >>>         KUNIT_CASE(kasan_stack_oob),
> >>>         KUNIT_CASE(kasan_alloca_oob_left),
> >>>         KUNIT_CASE(kasan_alloca_oob_right),
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BLMZ3qhJ1dnS3O9vKRA1DCF93Lpi-xq9PmStwhWC%2BykRSGr_g%40mail.gmail.com.

--000000000000bdefd705d107584f
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div>Thanks Marco for creating the bugzilla.</div><div>I w=
ill post my findings.</div><div>I found the Clang compiler quite smart when=
 comparing code generated vs gcc, i.e. clang would not bother generating co=
de that are OOB when indexing [ ].</div><br><div class=3D"gmail_quote"><div=
 dir=3D"ltr" class=3D"gmail_attr">On Wed, 17 Nov 2021 at 09:14, Marco Elver=
 &lt;<a href=3D"mailto:elver@google.com">elver@google.com</a>&gt; wrote:<br=
></div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;=
border-left:1px solid rgb(204,204,204);padding-left:1ex">On Wed, 17 Nov 202=
1 at 15:11, Chi-Thanh Hoang &lt;<a href=3D"mailto:chithanh.hoang@gmail.com"=
 target=3D"_blank">chithanh.hoang@gmail.com</a>&gt; wrote:<br>
&gt;<br>
&gt; I managed to figure out why the global OOB-left is not being detected =
and work around the issue 8-)<br>
&gt; I am still using gcc 9.3.0.<br>
<br>
Yeah, gcc is doing worse here. I just filed:<br>
<a href=3D"https://bugzilla.kernel.org/show_bug.cgi?id=3D215051" rel=3D"nor=
eferrer" target=3D"_blank">https://bugzilla.kernel.org/show_bug.cgi?id=3D21=
5051</a><br>
<br>
Clang 11+ doesn&#39;t have this issue.<br>
<br>
Please, if you can, post your findings to the bugzilla bug above. Then<br>
we can perhaps take it to gcc devs and ask them to do the same as<br>
clang or fix it some other way.<br>
<br>
Thanks,<br>
-- Marco<br>
<br>
&gt; I notice KASAN detects fine when OOB happen in overflow, KASAN shown t=
he status of shadow memory around the OOB, I see there is no redzone for th=
e global before the allocated memory, there is redzone after, if the global=
 is the first declared object in the .bss example, there is no redzone in f=
ront of it so shadow memory are zero, that is why KASAN did not detect.<br>
&gt; I then do the following, I declare 3 globals array in .bss, and test t=
he OOB underflow on the second array and KASAN does detect as doing -1 will=
 fall into the redzone of the first object.<br>
&gt; I agree this is kind of a corner case, but to fix this I guess we need=
 to provide redzone in front of the first global either in .bss or .data, a=
nd if possible to configure the size of such redzone.<br>
&gt;<br>
&gt; at ffffffffa07a6580 is start of .bss, in the log below there is 3 arra=
ys of 10 bytes (00 02 from shadow mem), the fault detected as shown on the =
2nd array when I do a -1 reference.<br>
&gt; [25768.140717] Memory state around the buggy address:<br>
&gt; [25768.140721]=C2=A0 ffffffffa07a6480: 00 00 00 00 00 00 00 00 00 00 0=
0 00 00 00 00 00<br>
&gt; [25768.140725]=C2=A0 ffffffffa07a6500: 00 00 00 00 00 00 00 00 00 00 0=
0 00 00 00 00 00=C2=A0 &lt;&lt;&lt;&lt;&lt; Here are zero value in shadow m=
em so access is good<br>
&gt; [25768.140730] &gt;ffffffffa07a6580: 00 02 f9 f9 f9 f9 f9 f9 00 02 f9 =
f9 f9 f9 f9 f9<br>
&gt; [25768.140733]=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0^<br>
&gt; [25768.140737]=C2=A0 ffffffffa07a6600: 00 02 f9 f9 f9 f9 f9 f9 01 f9 f=
9 f9 f9 f9 f9 f9<br>
&gt; [25768.140741]=C2=A0 ffffffffa07a6680: 00 f9 f9 f9 f9 f9 f9 f9 00 00 0=
0 00 00 00 00 00<br>
&gt;<br>
&gt;<br>
&gt; On Wed, 17 Nov 2021 at 02:23, Kaiwan N Billimoria &lt;<a href=3D"mailt=
o:kaiwan.billimoria@gmail.com" target=3D"_blank">kaiwan.billimoria@gmail.co=
m</a>&gt; wrote:<br>
&gt;&gt;<br>
&gt;&gt;<br>
&gt;&gt;<br>
&gt;&gt; On Tue, 16 Nov 2021, 22:07 Marco Elver, &lt;<a href=3D"mailto:elve=
r@google.com" target=3D"_blank">elver@google.com</a>&gt; wrote:<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; On Tue, Nov 16, 2021 at 07:46PM +0530, Kaiwan N Billimoria wro=
te:<br>
&gt;&gt;&gt; &gt; On Tue, 2021-11-16 at 12:52 +0100, Marco Elver wrote:<br>
&gt;&gt;&gt; &gt; &gt;<br>
&gt;&gt;&gt; &gt; &gt; KASAN globals support used to be limited in Clang. T=
his was fixed in<br>
&gt;&gt;&gt; &gt; &gt; Clang 11. I&#39;m not sure about GCC.<br>
&gt;&gt;&gt; &gt; ...<br>
&gt;&gt;&gt; &gt; &gt; &gt; Which compiler versions are you using? This is =
probably the most<br>
&gt;&gt;&gt; &gt; &gt; important piece to the puzzle.<br>
&gt;&gt;&gt; &gt; &gt;<br>
&gt;&gt;&gt; &gt; Right! This is the primary issue i think, thanks!<br>
&gt;&gt;&gt; &gt; am currently using gcc 9.3.0.<br>
&gt;&gt;&gt; &gt;<br>
&gt;&gt;&gt; &gt; So, my Ubuntu system had clang-10; I installed clang-11 o=
n top of it...<br>
&gt;&gt;&gt; &gt; (this causes some issues?). Updated the Makefile to use c=
lang-11, and it did build.<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; Only the test or the whole kernel? You need to build the whole=
 kernel<br>
&gt;&gt;&gt; and your module with the same compiler, otherwise all bets are=
 off wrt<br>
&gt;&gt;&gt; things like KASAN.<br>
&gt;&gt;<br>
&gt;&gt; Ah, will do so and let you know, thanks!<br>
&gt;&gt;<br>
&gt;&gt;<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; &gt; But when running these tests, *only* UBSAN was triggered,=
 KASAN unseen.<br>
&gt;&gt;&gt; &gt; So: I then rebuilt the 5.10.60 kernel removing UBSAN conf=
ig and retried (same module rebuilt w/ clang 11).<br>
&gt;&gt;&gt; &gt; This time UBSAN didn&#39;t pop up but nor did KASAN ! (Fo=
r the same rd/wr underflow testcases)...<br>
&gt;&gt;&gt; &gt; My script + dmesg:<br>
&gt;&gt;&gt; &gt; ...<br>
&gt;&gt;&gt; &gt; (Type in the testcase number to run):<br>
&gt;&gt;&gt; &gt; 4.4<br>
&gt;&gt;&gt; &gt; Running testcase &quot;4.4&quot; via test module now...<b=
r>
&gt;&gt;&gt; &gt; [=C2=A0 371.368096] testcase to run: 4.4<br>
&gt;&gt;&gt; &gt; $<br>
&gt;&gt;&gt; &gt;<br>
&gt;&gt;&gt; &gt; This implies it escaped unnoticed..<br>
&gt;&gt;&gt; &gt;<br>
&gt;&gt;&gt; &gt; To show the difference, here&#39;s my testcase #4.1- Read=
=C2=A0 (right) overflow on global memory - output:<br>
&gt;&gt;&gt; &gt;<br>
&gt;&gt;&gt; &gt; Running testcase &quot;4.1&quot; via test module now...<b=
r>
&gt;&gt;&gt; &gt; [ 1372.401484] testcase to run: 4.1<br>
&gt;&gt;&gt; &gt; [ 1372.401515] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D<br>
&gt;&gt;&gt; &gt; [ 1372.402284] BUG: KASAN: global-out-of-bounds in static=
_mem_oob_right+0xaf/0x160 [test_kmembugs]<br>
&gt;&gt;&gt; &gt; [ 1372.402851] Read of size 1 at addr ffffffffc088dfcc by=
 task run_tests/1656<br>
&gt;&gt;&gt; &gt;<br>
&gt;&gt;&gt; &gt; [ 1372.403428] CPU: 2 PID: 1656 Comm: run_tests Tainted: =
G=C2=A0 =C2=A0 B=C2=A0 =C2=A0 =C2=A0 O=C2=A0 =C2=A0 =C2=A0 5.10.60-dbg02 #1=
4<br>
&gt;&gt;&gt; &gt; [ 1372.403442] Hardware name: innotek GmbH VirtualBox/Vir=
tualBox, BIOS VirtualBox 12/01/2006<br>
&gt;&gt;&gt; &gt; [ 1372.403454] Call Trace:<br>
&gt;&gt;&gt; &gt; [ 1372.403486]=C2=A0 dump_stack+0xbd/0xfa<br>
&gt;&gt;&gt; &gt;<br>
&gt;&gt;&gt; &gt; [... lots more, as expected ...]<br>
&gt;&gt;&gt; &gt;<br>
&gt;&gt;&gt; &gt; So, am puzzled... why isn&#39;t KASAN catching the underf=
low...<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; Please take a look at the paragraph at:<br>
&gt;&gt;&gt; <a href=3D"https://git.kernel.org/pub/scm/linux/kernel/git/tor=
valds/linux.git/tree/lib/test_kasan.c#n706" rel=3D"noreferrer" target=3D"_b=
lank">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tr=
ee/lib/test_kasan.c#n706</a><br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; I think your test is giving the compiler opportunities to misc=
ompile<br>
&gt;&gt;&gt; your code, because, well it has undefined behaviour (negative =
index)<br>
&gt;&gt;&gt; that it very clearly can see. I think you need to put more eff=
ort into<br>
&gt;&gt;&gt; hiding the UB from the optimizer like we do in test_kasan.c.<b=
r>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; If you want to know in detail what&#39;s happening I recommend=
 you<br>
&gt;&gt;&gt; disassemble your compiled code and check if the negative deref=
erences<br>
&gt;&gt;&gt; are still there.<br>
&gt;&gt;<br>
&gt;&gt; Will recheck...<br>
&gt;&gt;<br>
&gt;&gt; Thanks, Kaiwan.<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; &gt; A couple of caveats:<br>
&gt;&gt;&gt; &gt; 1) I had to manually setup a soft link to llvm-objdump (i=
t was installed as llvm-objdump-11)<br>
&gt;&gt;&gt; &gt; 2) the module build initially failed with<br>
&gt;&gt;&gt; &gt; /bin/sh: 1: ld.lld: not found<br>
&gt;&gt;&gt; &gt; So I installed the &#39;lld&#39; package; then the build =
worked..<br>
&gt;&gt;&gt; &gt;<br>
&gt;&gt;&gt; &gt; Any thoughts?<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; Is this &quot;make LLVM=3D1&quot;. Yeah, if there&#39;s a vers=
ion suffix it&#39;s known to<br>
&gt;&gt;&gt; be problematic.<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; You can just build the kernel with &quot;make CC=3Dclang&quot;=
 and it&#39;ll use<br>
&gt;&gt;&gt; binutils ld, which works as well.<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; &gt; &gt; FWIW, the kernel has its own KASAN test suite in lib=
/test_kasan.c.<br>
&gt;&gt;&gt; &gt; &gt; There are a few things to not make the compiler opti=
mize away<br>
&gt;&gt;&gt; &gt; &gt; explicitly buggy code, so I&#39;d also suggest you e=
mbed your test in<br>
&gt;&gt;&gt; &gt; &gt; test_kasan and see if it changes anything (unlikely =
but worth a shot).<br>
&gt;&gt;&gt; &gt; I have studied it, and essentially copied it&#39;s techni=
ques where required... Interestingly, the kernel&#39;s test_kasan module do=
es _not_ have a test case for this: underflow on global memory! :-)<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; I just added such a test (below) and it passes just fine with =
clang 11<br>
&gt;&gt;&gt; (I&#39;ll probably send it as a real patch later). Notice that=
 the address<br>
&gt;&gt;&gt; itself (&quot;array&quot;) is a volatile, so that the compiler=
 cannot make any<br>
&gt;&gt;&gt; assumptions about it.<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; Thanks,<br>
&gt;&gt;&gt; -- Marco<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; ------ &gt;8 ------<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; diff --git a/lib/test_kasan.c b/lib/test_kasan.c<br>
&gt;&gt;&gt; index 67ed689a0b1b..e56c9eb3f16e 100644<br>
&gt;&gt;&gt; --- a/lib/test_kasan.c<br>
&gt;&gt;&gt; +++ b/lib/test_kasan.c<br>
&gt;&gt;&gt; @@ -700,7 +700,7 @@ static void kmem_cache_bulk(struct kunit *=
test)<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt;=C2=A0 static char global_array[10];<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; -static void kasan_global_oob(struct kunit *test)<br>
&gt;&gt;&gt; +static void kasan_global_oob_right(struct kunit *test)<br>
&gt;&gt;&gt;=C2=A0 {<br>
&gt;&gt;&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0/*<br>
&gt;&gt;&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 * Deliberate out-of-bounds a=
ccess. To prevent CONFIG_UBSAN_LOCAL_BOUNDS<br>
&gt;&gt;&gt; @@ -723,6 +723,15 @@ static void kasan_global_oob(struct kunit=
 *test)<br>
&gt;&gt;&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0KUNIT_EXPECT_KASAN_FAIL(test,=
 *(volatile char *)p);<br>
&gt;&gt;&gt;=C2=A0 }<br>
&gt;&gt;&gt;<br>
&gt;&gt;&gt; +static void kasan_global_oob_left(struct kunit *test)<br>
&gt;&gt;&gt; +{<br>
&gt;&gt;&gt; +=C2=A0 =C2=A0 =C2=A0 =C2=A0char *volatile array =3D global_ar=
ray;<br>
&gt;&gt;&gt; +=C2=A0 =C2=A0 =C2=A0 =C2=A0char *p =3D array - 3;<br>
&gt;&gt;&gt; +<br>
&gt;&gt;&gt; +=C2=A0 =C2=A0 =C2=A0 =C2=A0KASAN_TEST_NEEDS_CONFIG_ON(test, C=
ONFIG_KASAN_GENERIC);<br>
&gt;&gt;&gt; +=C2=A0 =C2=A0 =C2=A0 =C2=A0KUNIT_EXPECT_KASAN_FAIL(test, *(vo=
latile char *)p);<br>
&gt;&gt;&gt; +}<br>
&gt;&gt;&gt; +<br>
&gt;&gt;&gt;=C2=A0 /* Check that ksize() makes the whole object accessible.=
 */<br>
&gt;&gt;&gt;=C2=A0 static void ksize_unpoisons_memory(struct kunit *test)<b=
r>
&gt;&gt;&gt;=C2=A0 {<br>
&gt;&gt;&gt; @@ -1160,7 +1169,8 @@ static struct kunit_case kasan_kunit_tes=
t_cases[] =3D {<br>
&gt;&gt;&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0KUNIT_CASE(kmem_cache_oob),<b=
r>
&gt;&gt;&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0KUNIT_CASE(kmem_cache_account=
ed),<br>
&gt;&gt;&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0KUNIT_CASE(kmem_cache_bulk),<=
br>
&gt;&gt;&gt; -=C2=A0 =C2=A0 =C2=A0 =C2=A0KUNIT_CASE(kasan_global_oob),<br>
&gt;&gt;&gt; +=C2=A0 =C2=A0 =C2=A0 =C2=A0KUNIT_CASE(kasan_global_oob_right)=
,<br>
&gt;&gt;&gt; +=C2=A0 =C2=A0 =C2=A0 =C2=A0KUNIT_CASE(kasan_global_oob_left),=
<br>
&gt;&gt;&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0KUNIT_CASE(kasan_stack_oob),<=
br>
&gt;&gt;&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0KUNIT_CASE(kasan_alloca_oob_l=
eft),<br>
&gt;&gt;&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0KUNIT_CASE(kasan_alloca_oob_r=
ight),<br>
</blockquote></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BLMZ3qhJ1dnS3O9vKRA1DCF93Lpi-xq9PmStwhWC%2BykRSGr_=
g%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CA%2BLMZ3qhJ1dnS3O9vKRA1DCF93Lpi-xq9PmStwhWC%2B=
ykRSGr_g%40mail.gmail.com</a>.<br />

--000000000000bdefd705d107584f--
