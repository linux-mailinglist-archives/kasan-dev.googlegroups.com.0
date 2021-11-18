Return-Path: <kasan-dev+bncBDPJLN7A4MFRBKOW26GAMGQECIGQQKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id BE703455480
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 06:56:57 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id f3-20020a5d50c3000000b00183ce1379fesf830687wrt.5
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 21:56:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637215017; cv=pass;
        d=google.com; s=arc-20160816;
        b=vafJ7xvLnmwircHzxGUBgov0DtbDCeWjEGcrHPJdmqB2u80ACYPPcb4u5KfgERThW2
         BIKb91ZQT1Lm1cEAFmnWMJ/EvhLMw4XDxfgxMunFZCYNTLPpmAxG6t0HZw/pm/n7o2E+
         /rMOKvbn434OAEwVuINLrysNPmcwEnB1uWnoRyqS7SbPlShLu0EEIKMVmPt9v8/zpk71
         lJ2F+WoES2Zqoe459rfgu+BAkFcMO1e/2kpTy+ugsI5kQGCF7plxYts5xZAOpev6fOAm
         VPOLkTsmX5Tc1oF7QeIShNk9bdl2aIGzNMDeLQKoa1uODofpMmpR2CKqpmkY4uMXEeNO
         XtIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=kQa1SiPwzccjQQkuPBd78PC788kgju84S93u6YIkSYY=;
        b=y4ZuCJUhv2Vci7NwGPnbUWatsz0q2ZTAN0rSWrtYSQjZ1nKFS0ueSa/DxVBCE6jJCl
         ZkAIoqzdqFDtMEIz3AYjYq8Doam35b9/a6jy2Zz1y4hErMvvkNyV+JfOnsLxG8pBhG4J
         uIGcQga7/NpMRy5+eOQPges2bKp5xSrpsWHg4R6MXU3Ji41XyTayoPdFOOkX3fd6u1Xh
         NSR5KAeuTPfD3RpP+owhADoXurx/mDGFZjsM8p65S0FZl90FWvgdS89FwbwZOG3sctJK
         UMR/3JtqWAMxReymJ2eXFq24sONEt4fWuEytSQpUgXZnkyXHDmW3l9U98Dw77jDZ27Cd
         qEBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=XHoShk6w;
       spf=pass (google.com: domain of kaiwan.billimoria@gmail.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=kaiwan.billimoria@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kQa1SiPwzccjQQkuPBd78PC788kgju84S93u6YIkSYY=;
        b=ON/f2WBu/rR6jHJ0b/3Y7Ws/AEU2azBU4Z1Ct5/Oh+u3s2w2JaRFezG7LQ6nX26vU8
         o+Ns/dw0m4Iek0X40d05e0eVAfP/bO+83u3Zi75wbTLjSOWTgGDV4DlkfBoyj8HkaPnd
         YLdJyFxutnBfM/0l40/38TMS2UP+B2Qp1Aw2jUeLAIIYcybcaa+08oyGkjTNUcmubNwH
         zYu85+pYxeVtF5Is0y0JD3pCKJwmH+G/x1NXrEQKLBGSWWlog5dQo2TDkjN58saLOqGD
         tEQYaolPLx5PiONiWZEo9Z8Nch4CHSleBDGZgOnAeDETAirQjOnKNsMZiSzomV74LjoX
         RQfQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kQa1SiPwzccjQQkuPBd78PC788kgju84S93u6YIkSYY=;
        b=IX0sdB+ZcegRG8HenLI7dEpRl7zvS7Zt19PBfYj1jtb7+gODxhwL4hz4HunjdivhS5
         FASlDe9gqd6OTcuaU8Y8i9obo2hkZyaNT+P21ZqgIwPCP6cWe4sr2uV25vNjuY5qMnGn
         u+pHQROdWnBy4QSQkwQs238fuG+AfHInUVV4l2v2SDdZ5GF5lqoAM39OzkDMnv8eJKe0
         Mi2c8W2xrSiFvwMwMo2EeFb/Xp++v8U5+8asOVm+fqR58CnweAfBYJ4rwUGitpAIfNiB
         4Eqtt3/4votibSNOyfMg/aBTfTECkcfnTXnSDEdGHQ/yHVDypHzOJNF8/VWPOrOvKAxq
         HQjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kQa1SiPwzccjQQkuPBd78PC788kgju84S93u6YIkSYY=;
        b=bfEGP0iKuSHShxR35I4bkSijsCQ5GOayOmL3IUowttb5YqXIvDyoS8hEyKBVDRe4tA
         Qgxe/6YcHyYPbSFYIMFbSjC/xqj6JJqr/nn8j/etUrZKPwfAkbl7dk4v/X1CpyWrv2jE
         JUnhex9PxCgZ9c7Rk5wKZnObAbL7TpivfK6xlE1zNkTlZ09ucYC4yzwMECbimH6LI/oS
         HL1qem1U2LscVlH/8BMI1gE2JIhRLsPu7d1ectM6pJEDO5di7H/Y9zvTcUmObCbETfpz
         2OL/Pfpq67eNN/SVKVIP24HhFLlNITfyQeEdZtjsz6we3KWETM3eAR7BbuTpocsswRSA
         M/wQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531g0VlWOEkcM0hNk+7zd5XjOULS7SbmhQEQvZzpezCIFaj7XTl+
	8y5Vq4S+af47ya+9w8jL9V4=
X-Google-Smtp-Source: ABdhPJywWlaDe5Q3x76htCARnvdk54eP8xurtB6214aH9DhPG0zGWeRQ43R8/bhCjg40L1tY5MYivQ==
X-Received: by 2002:adf:fed0:: with SMTP id q16mr28434854wrs.276.1637215017488;
        Wed, 17 Nov 2021 21:56:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1943:: with SMTP id 64ls985886wmz.0.gmail; Wed, 17 Nov
 2021 21:56:56 -0800 (PST)
X-Received: by 2002:a05:600c:4154:: with SMTP id h20mr6625143wmm.189.1637215016530;
        Wed, 17 Nov 2021 21:56:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637215016; cv=none;
        d=google.com; s=arc-20160816;
        b=sG2jgw87dapbAqPTGDUjTLpGYAH8khr7U8czBJBvYDSw5mFR/5eiT0LtvnOI2HYzeD
         GnWnTtgfjfpkD5+cnFa9VxTFWLwNRsGS2+YczgDJF+RUOvYHkFo5oH4JQfM0x0/E4pzZ
         nkH0b/U+FIMk8RYGeTz3Q+PYzm0ka3la5U67wQfPZ1xB752+YNZUW3x1avckcLpIWe4p
         4/ok4AKhY/eosGPfgbXz1XDhZsi9EJnWO0OXTaQQxyb5hEc0QADkT4lKY65UCDznHVTX
         iWxqb8wgP+dyCoXvRn3mXa0idb01mi8oEOReQiPDrM+ium8U8x7HqXCZXBK1/Pcnhuwv
         Ro0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=EmmKSp7r5F+IZJolfx4HBqyAqNMoBEiTx2bxAMHoQd0=;
        b=HiNdcx2KqWFzojw3HuqNa6Iv3EeUrt6pf7eN6aXx7h4IbFHg3zVi8r5SL6puA+qotN
         wbW+N6LbVMePfM4r+eG+51C5Ljvg+YvZVJ3ZgXRtTYv1qLBVsfiPJh7gd4phnJDBB7qG
         paerw1jyG+8W1Z1XhZFxOGvvGuhbW0gcml3Yk9+vc6qbbkkvjSiYHmm/31b6XK+eYeD+
         NEDvHsTd4NG/88FDJcz93w4LEjWetGUGCfXegLpVBSRZyKTy/tiW98Gb6wXbCTmuWJ+h
         zreDMUDSfPYqt5YKVqVrUrs/51cZBjVyv9m5Vvx9suB/987SqsXxhzjCde7uadao9f9Q
         25LA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=XHoShk6w;
       spf=pass (google.com: domain of kaiwan.billimoria@gmail.com designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=kaiwan.billimoria@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x529.google.com (mail-ed1-x529.google.com. [2a00:1450:4864:20::529])
        by gmr-mx.google.com with ESMTPS id i17si76739wrb.1.2021.11.17.21.56.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Nov 2021 21:56:56 -0800 (PST)
Received-SPF: pass (google.com: domain of kaiwan.billimoria@gmail.com designates 2a00:1450:4864:20::529 as permitted sender) client-ip=2a00:1450:4864:20::529;
Received: by mail-ed1-x529.google.com with SMTP id g14so21935673edz.2
        for <kasan-dev@googlegroups.com>; Wed, 17 Nov 2021 21:56:56 -0800 (PST)
X-Received: by 2002:a17:906:7009:: with SMTP id n9mr29883994ejj.431.1637215016007;
 Wed, 17 Nov 2021 21:56:56 -0800 (PST)
MIME-Version: 1.0
References: <a2ced905703ede4465f3945eb3ae4e615c02faf8.camel@gmail.com>
 <CANpmjNNSRVMO+PJWvpP=w+V6CR51Yd-r2ku_fVEvymae0g7JaQ@mail.gmail.com>
 <c2693ecb223eb634f4fa94101c4cb98999ef0032.camel@gmail.com>
 <YZPeRGpOTSgXjaE6@elver.google.com> <CAPDLWs88WLTPVnh1TtY3tOU6XLPucf8zKMhzCfxRv2HbCnKndA@mail.gmail.com>
 <CA+LMZ3r9ioqSN31w5v_Bkgs7UyPux=0MO8g0dQC16AxEiorBcg@mail.gmail.com>
 <CANpmjNMzv2b1srETOp1STjVWYZx-1XpdMm5yY485vSmd=wjJiw@mail.gmail.com> <CA+LMZ3qhJ1dnS3O9vKRA1DCF93Lpi-xq9PmStwhWC+ykRSGr_g@mail.gmail.com>
In-Reply-To: <CA+LMZ3qhJ1dnS3O9vKRA1DCF93Lpi-xq9PmStwhWC+ykRSGr_g@mail.gmail.com>
From: Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
Date: Thu, 18 Nov 2021 11:26:39 +0530
Message-ID: <CAPDLWs9TR4gNHg+n2j2958yff+F6Ex0gVZxD8qtcPrgcYghfWA@mail.gmail.com>
Subject: Re: KASAN isn't catching rd/wr underflow bugs on static global memory?
To: Chi-Thanh Hoang <chithanh.hoang@gmail.com>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: kaiwan.billimoria@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=XHoShk6w;       spf=pass
 (google.com: domain of kaiwan.billimoria@gmail.com designates
 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=kaiwan.billimoria@gmail.com;
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

On Thu, Nov 18, 2021 at 8:29 AM Chi-Thanh Hoang
<chithanh.hoang@gmail.com> wrote:
>
> Thanks Marco for creating the bugzilla.
> I will post my findings.

Super. Thanks Chi-Thanh, Marco, very helpful insights.
Also, Marco, am glad to see your latest patch to the test_kasan module
covering the left OOB on global data..

> I found the Clang compiler quite smart when comparing code generated vs g=
cc, i.e. clang would not bother generating code that are OOB when indexing =
[ ].

Really good to know!
I think I am facing this "issue" - my supposedly buggy code isn't
causing bugs (when built with clang) :-)
Specifically, the OOB accesses upon global memory..
>>
>>
>> Please, if you can, post your findings to the bugzilla bug above. Then
>> we can perhaps take it to gcc devs and ask them to do the same as
>> clang or fix it some other way.

That would be great...

>>
>> Thanks,
>> -- Marco
>>
>> > I notice KASAN detects fine when OOB happen in overflow, KASAN shown t=
he status of shadow memory around the OOB, I see there is no redzone for th=
e global before the allocated memory, there is redzone after, if the global=
 is the first declared object in the .bss example, there is no redzone in f=
ront of it so shadow memory are zero, that is why KASAN did not detect.
>> > I then do the following, I declare 3 globals array in .bss, and test t=
he OOB underflow on the second array and KASAN does detect as doing -1 will=
 fall into the redzone of the first object.
>> > I agree this is kind of a corner case, but to fix this I guess we need=
 to provide redzone in front of the first global either in .bss or .data, a=
nd if possible to configure the size of such redzone.
>> >
>> > at ffffffffa07a6580 is start of .bss, in the log below there is 3 arra=
ys of 10 bytes (00 02 from shadow mem), the fault detected as shown on the =
2nd array when I do a -1 reference.
>> > [25768.140717] Memory state around the buggy address:
>> > [25768.140721]  ffffffffa07a6480: 00 00 00 00 00 00 00 00 00 00 00 00 =
00 00 00 00
>> > [25768.140725]  ffffffffa07a6500: 00 00 00 00 00 00 00 00 00 00 00 00 =
00 00 00 00  <<<<< Here are zero value in shadow mem so access is good
>> > [25768.140730] >ffffffffa07a6580: 00 02 f9 f9 f9 f9 f9 f9 00 02 f9 f9 =
f9 f9 f9 f9
>> > [25768.140733]                                         ^
>> > [25768.140737]  ffffffffa07a6600: 00 02 f9 f9 f9 f9 f9 f9 01 f9 f9 f9 =
f9 f9 f9 f9
>> > [25768.140741]  ffffffffa07a6680: 00 f9 f9 f9 f9 f9 f9 f9 00 00 00 00 =
00 00 00 00
>> >

Really interesting! Am trying to replicate along similar lines but it
doesn't trigger !

static char global_arr1[100];
static int global_arr2[10];
static char global_arr3[10];
...
int global_mem_oob_left(int mode)
{
    volatile char w;
    char *volatile array =3D global_arr3;
    char *p =3D array - 3; // invalid, not within bounds

    w =3D *(volatile char *)p;
    ...
}

I also find that the global arrays seem to be laid out "in reverse",
i.e., if i print their kernel va's:
test_kmembugs:global_mem_oob_left(): global_arr1=3Dffffffffc07db8e0
global_arr2=3Dffffffffc07db900 global_arr3=3Dffffffffc07db8c0

And the last one, global_arr3, coincides with the BSS start:

$ sudo cat /sys/module/test_kmembugs/sections/.bss
0xffffffffc07db8c0

Can we infer anything here?

Thanks Marco, Chi-Thanh,

Regards,
Kaiwan.

>> >
>> > On Wed, 17 Nov 2021 at 02:23, Kaiwan N Billimoria <kaiwan.billimoria@g=
mail.com> wrote:
>> >>
>> >>
>> >>
>> >> On Tue, 16 Nov 2021, 22:07 Marco Elver, <elver@google.com> wrote:
>> >>>
>> >>> On Tue, Nov 16, 2021 at 07:46PM +0530, Kaiwan N Billimoria wrote:
>> >>> > On Tue, 2021-11-16 at 12:52 +0100, Marco Elver wrote:
>> >>> > >
>> >>> > > KASAN globals support used to be limited in Clang. This was fixe=
d in
>> >>> > > Clang 11. I'm not sure about GCC.
>> >>> > ...
>> >>> > > > Which compiler versions are you using? This is probably the mo=
st
>> >>> > > important piece to the puzzle.
>> >>> > >
>> >>> > Right! This is the primary issue i think, thanks!
>> >>> > am currently using gcc 9.3.0.
>> >>> >
>> >>> > So, my Ubuntu system had clang-10; I installed clang-11 on top of =
it...
>> >>> > (this causes some issues?). Updated the Makefile to use clang-11, =
and it did build.
>> >>>
>> >>> Only the test or the whole kernel? You need to build the whole kerne=
l
>> >>> and your module with the same compiler, otherwise all bets are off w=
rt
>> >>> things like KASAN.
>> >>
>> >> Ah, will do so and let you know, thanks!
>> >>
>> >>
>> >>>
>> >>> > But when running these tests, *only* UBSAN was triggered, KASAN un=
seen.
>> >>> > So: I then rebuilt the 5.10.60 kernel removing UBSAN config and re=
tried (same module rebuilt w/ clang 11).
>> >>> > This time UBSAN didn't pop up but nor did KASAN ! (For the same rd=
/wr underflow testcases)...
>> >>> > My script + dmesg:
>> >>> > ...
>> >>> > (Type in the testcase number to run):
>> >>> > 4.4
>> >>> > Running testcase "4.4" via test module now...
>> >>> > [  371.368096] testcase to run: 4.4
>> >>> > $
>> >>> >
>> >>> > This implies it escaped unnoticed..
>> >>> >
>> >>> > To show the difference, here's my testcase #4.1- Read  (right) ove=
rflow on global memory - output:
>> >>> >
>> >>> > Running testcase "4.1" via test module now...
>> >>> > [ 1372.401484] testcase to run: 4.1
>> >>> > [ 1372.401515] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>> >>> > [ 1372.402284] BUG: KASAN: global-out-of-bounds in static_mem_oob_=
right+0xaf/0x160 [test_kmembugs]
>> >>> > [ 1372.402851] Read of size 1 at addr ffffffffc088dfcc by task run=
_tests/1656
>> >>> >
>> >>> > [ 1372.403428] CPU: 2 PID: 1656 Comm: run_tests Tainted: G    B   =
   O      5.10.60-dbg02 #14
>> >>> > [ 1372.403442] Hardware name: innotek GmbH VirtualBox/VirtualBox, =
BIOS VirtualBox 12/01/2006
>> >>> > [ 1372.403454] Call Trace:
>> >>> > [ 1372.403486]  dump_stack+0xbd/0xfa
>> >>> >
>> >>> > [... lots more, as expected ...]
>> >>> >
>> >>> > So, am puzzled... why isn't KASAN catching the underflow...
>> >>>
>> >>> Please take a look at the paragraph at:
>> >>> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/t=
ree/lib/test_kasan.c#n706
>> >>>
>> >>> I think your test is giving the compiler opportunities to miscompile
>> >>> your code, because, well it has undefined behaviour (negative index)
>> >>> that it very clearly can see. I think you need to put more effort in=
to
>> >>> hiding the UB from the optimizer like we do in test_kasan.c.
>> >>>
>> >>> If you want to know in detail what's happening I recommend you
>> >>> disassemble your compiled code and check if the negative dereference=
s
>> >>> are still there.
>> >>
>> >> Will recheck...
>> >>
>> >> Thanks, Kaiwan.
>> >>>
>> >>>
>> >>> > A couple of caveats:
>> >>> > 1) I had to manually setup a soft link to llvm-objdump (it was ins=
talled as llvm-objdump-11)
>> >>> > 2) the module build initially failed with
>> >>> > /bin/sh: 1: ld.lld: not found
>> >>> > So I installed the 'lld' package; then the build worked..
>> >>> >
>> >>> > Any thoughts?
>> >>>
>> >>> Is this "make LLVM=3D1". Yeah, if there's a version suffix it's know=
n to
>> >>> be problematic.
>> >>>
>> >>> You can just build the kernel with "make CC=3Dclang" and it'll use
>> >>> binutils ld, which works as well.
>> >>>
>> >>> > > FWIW, the kernel has its own KASAN test suite in lib/test_kasan.=
c.
>> >>> > > There are a few things to not make the compiler optimize away
>> >>> > > explicitly buggy code, so I'd also suggest you embed your test i=
n
>> >>> > > test_kasan and see if it changes anything (unlikely but worth a =
shot).
>> >>> > I have studied it, and essentially copied it's techniques where re=
quired... Interestingly, the kernel's test_kasan module does _not_ have a t=
est case for this: underflow on global memory! :-)
>> >>>
>> >>> I just added such a test (below) and it passes just fine with clang =
11
>> >>> (I'll probably send it as a real patch later). Notice that the addre=
ss
>> >>> itself ("array") is a volatile, so that the compiler cannot make any
>> >>> assumptions about it.
>> >>>
>> >>> Thanks,
>> >>> -- Marco
>> >>>
>> >>> ------ >8 ------
>> >>>
>> >>> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
>> >>> index 67ed689a0b1b..e56c9eb3f16e 100644
>> >>> --- a/lib/test_kasan.c
>> >>> +++ b/lib/test_kasan.c
>> >>> @@ -700,7 +700,7 @@ static void kmem_cache_bulk(struct kunit *test)
>> >>>
>> >>>  static char global_array[10];
>> >>>
>> >>> -static void kasan_global_oob(struct kunit *test)
>> >>> +static void kasan_global_oob_right(struct kunit *test)
>> >>>  {
>> >>>         /*
>> >>>          * Deliberate out-of-bounds access. To prevent CONFIG_UBSAN_=
LOCAL_BOUNDS
>> >>> @@ -723,6 +723,15 @@ static void kasan_global_oob(struct kunit *test=
)
>> >>>         KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>> >>>  }
>> >>>
>> >>> +static void kasan_global_oob_left(struct kunit *test)
>> >>> +{
>> >>> +       char *volatile array =3D global_array;
>> >>> +       char *p =3D array - 3;
>> >>> +
>> >>> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
>> >>> +       KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>> >>> +}
>> >>> +
>> >>>  /* Check that ksize() makes the whole object accessible. */
>> >>>  static void ksize_unpoisons_memory(struct kunit *test)
>> >>>  {
>> >>> @@ -1160,7 +1169,8 @@ static struct kunit_case kasan_kunit_test_case=
s[] =3D {
>> >>>         KUNIT_CASE(kmem_cache_oob),
>> >>>         KUNIT_CASE(kmem_cache_accounted),
>> >>>         KUNIT_CASE(kmem_cache_bulk),
>> >>> -       KUNIT_CASE(kasan_global_oob),
>> >>> +       KUNIT_CASE(kasan_global_oob_right),
>> >>> +       KUNIT_CASE(kasan_global_oob_left),
>> >>>         KUNIT_CASE(kasan_stack_oob),
>> >>>         KUNIT_CASE(kasan_alloca_oob_left),
>> >>>         KUNIT_CASE(kasan_alloca_oob_right),

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAPDLWs9TR4gNHg%2Bn2j2958yff%2BF6Ex0gVZxD8qtcPrgcYghfWA%40mail.gm=
ail.com.
