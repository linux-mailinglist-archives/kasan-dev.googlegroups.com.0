Return-Path: <kasan-dev+bncBCMIZB7QWENRBS6ESOAQMGQELK6EZ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D2653185DB
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 08:52:45 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id a12sf4907452ioe.5
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Feb 2021 23:52:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613029964; cv=pass;
        d=google.com; s=arc-20160816;
        b=yJT1EBt9O0/wL+cUdmKLsqdJQp3HUvyW4f6WRvKDOFYa+swUoZc6BzlTmd4yhwmqFT
         U1H+n8w/9ODSPsilq0Ou5xptOq1+ADXMYbl2TGd+pfyCQ3Z9oZVHeLFsTNC+EyKwGGkA
         gaKnkWM+pT7cYgTaKZB9STmO7vDgdh3xBJ4fvabG0XgUd+gdSv/2IzHmfRWDpZB6uqny
         sHK7SX7i84rPTRMS4Y2plZZLa+H/5GCADMiVCryXKzB/avXXTa/gqzY62QKQTMt/bxFp
         pd3Ti2J0G58K5xxCAJas+zGAWpcDpd/kb8qqb/7H89IRlGeJZ82ngWOHzdty6OcV/j09
         N4Hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/HJsRV9G2Rmgc/ou/70YgDkUjNAlVA5q99TqVgwhjB0=;
        b=yQhW3PhM9VFSfQYmB5Xu/EoteNsSmY4FpUGx5aoFFFgPfqkAIYTIuKgxImbdvx9eZq
         RUAoaScwd35pnym6fheAOyywJilZtrjVckM6NC/YfrNnuc6nbuJfAH0nX9AFYicTP0qK
         G1mMrL9dY5oID3V2bbgXTZCbLTORLVJrbMc1xZVTc4p585ivMo/TvJ/Z4hpsuTAJv/d5
         oarHCoPz2Tv60C/AEWRoEvyThVA07tFlrjv9kQ2VKSGP/EM6PYOwwMifS0sIc7dUNK7p
         k12zQWfCuw1mybcp75NhBHE79Hx5ulcaU+rznl3KpTDqCJHWYNPLo4PAWQYvnDJqdcod
         vP7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ekZlAbes;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=/HJsRV9G2Rmgc/ou/70YgDkUjNAlVA5q99TqVgwhjB0=;
        b=R4RP9doBhyB80rxHXghh3Z3/Kg9F4zcO4K/jAC8IeGgkYw+5WzgoAB4lBXCPftqCZa
         Dm/1L6MW/HSXOL/NoYib+2hcttOeS23NQ9xJ9yzCCxFflKgejdm3o9FPt53ZA2Xc3dM7
         em/9vYX+kvfsOk6hW31NjyNRKepg2aN5419+vL+16LcYJpQwZS51tEaD6pO2z1wnuqtx
         YE/KOqcSkRLILi4McI9KQuyGSrEeLMNrDJPLEljlpidET2CV2yNNzM12UjvVUuldRMcw
         OvIqPvhWu4mwPDoE4hpXytvyYMHLXShmfwu5JduC4bI60r8bgPDDBj+y23Ho7ZBluW7Q
         338Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/HJsRV9G2Rmgc/ou/70YgDkUjNAlVA5q99TqVgwhjB0=;
        b=bU8d8I8/RrGLMPSMfY7UWJeoPGWlbFIami9O7cC1Ziep/Nr2pJucG4xX6dSyhJj3sp
         mPUW82tBqqXyDlvwy8j5kF2LniEgO/J2bkt2SI7yl7bEkj4GCjUXXY9IOa7g0I5xUhan
         Yb4y/O+5KTsEmx49r99j0iwqsTFfm3KwyqYQi3F156zAF8+rZ17D4jSB1vle7l3JXrii
         OOWs1sRvUhHltmXWNoYKy1nN0u3MnZ2dVLlXWD56ArLDGE/lt2I9ikUtAKiVYKjpy5aS
         fCH+UtGD0rsNXk5de6Cnaxd25mnKoFEHQUU+MxDljHzChYrkUNyBitvqdiegCj94iYM1
         8odQ==
X-Gm-Message-State: AOAM532yC8qv9DDAGcRuJHl45vIy1RJeGO3sc9Dp4JoOpomKUSPeDpOs
	zkBKGdIHuT3gibYIpp3XxXo=
X-Google-Smtp-Source: ABdhPJx3zEbu0A2Mu4Fhh+Ldr+smpR62/7eVBwsQAoffCeDPDS0tLf+SFtWW5bTMoWLxRpElG/5ykQ==
X-Received: by 2002:a92:870d:: with SMTP id m13mr4652194ild.104.1613029964011;
        Wed, 10 Feb 2021 23:52:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:ac19:: with SMTP id a25ls699347jao.8.gmail; Wed, 10 Feb
 2021 23:52:43 -0800 (PST)
X-Received: by 2002:a05:6638:96c:: with SMTP id o12mr7422871jaj.24.1613029963595;
        Wed, 10 Feb 2021 23:52:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613029963; cv=none;
        d=google.com; s=arc-20160816;
        b=U76P5iaYq4oJo3QMDUBj43v3GvnXlZvHKWtwiJ48Ig2yPmZXpduar4UbErLsXgHdOa
         XG4wz0RHU+LS/k12lX6aOCs1vHyfAtoYKfj4R0yX0FI3k8d7VuaO64yKhpllZTQOINH8
         i/drAywW2vs7H7Q1XHw6uJzjPLnAGNBOqFtedxzmQbl2wCyxiIre8kR/k7tFivqhSIUj
         mGITWq8CEozoAFmTGVoKEzVVvLflA2hDz+lwJ3Bb8RzKoLqUPxZ6Ckq4X41qUkjY2OC/
         njFPxdB1ZgLkx0I7xoV4hzdMVW9LausfAQ0b7w+8YuEREc4E1tXxjip5gPFQaZG+MPvX
         b7aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VR5dSSzrvcgi60K+WwYFiQxiaKGU+3rRYVA08rYgY58=;
        b=mARAw2k/6VW2OJWPXnVYXhbULOQl1bmtUFLtmyUqgGt/YRHGDOfyUQmjnajvYhK2NC
         tukw6UZ4e2kba0a8O2yTwBuOYKKFwRc2PItJSJmz8bxvxfhbTEVwTn8bJEaTejkF9odF
         jFrtvD10ZJlGPy4ehYG2hqg2EiNo3O1FkfStoFN6TzgCURpmO8lie3OfInU/eCFlsKUE
         1cJ3/6c5nHKE0lZcrabUghBuz/w1gMpQSUsElI1UTc8+5NYb/L0n/bm5c4QMJG26r3td
         7XzfQXTCFZJAR8/UuQ+d+hmhPxX6cGhpdQIWlscIH5tkxcdWAzGLQh//Q2dTBzjzrQVP
         6jVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ekZlAbes;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id m132si215177ioa.3.2021.02.10.23.52.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Feb 2021 23:52:43 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id e15so3537476qte.9
        for <kasan-dev@googlegroups.com>; Wed, 10 Feb 2021 23:52:43 -0800 (PST)
X-Received: by 2002:ac8:7512:: with SMTP id u18mr6317593qtq.290.1613029962958;
 Wed, 10 Feb 2021 23:52:42 -0800 (PST)
MIME-Version: 1.0
References: <CACV+nar9Apf15oXvwqsyd5OEX3PQ6OTxbhgG+0JRP0+iUvh_KQ@mail.gmail.com>
 <CACT4Y+Yo-HtoNrA8PL3qWYoUitt-WHgZmJ7wqh9zn01t53JL9g@mail.gmail.com> <CACV+naqJOptZa2e1+a9pNYP7Wh5yLwKtDSgzEz7yQaTB4uzLYQ@mail.gmail.com>
In-Reply-To: <CACV+naqJOptZa2e1+a9pNYP7Wh5yLwKtDSgzEz7yQaTB4uzLYQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Feb 2021 08:52:31 +0100
Message-ID: <CACT4Y+Z51+01x_b+LTfeE2zP-w9Yt9eFOA6mdh7cVpc4BcZZLQ@mail.gmail.com>
Subject: Re: reproduce data race
To: Jin Huang <andy.jinhuang@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ekZlAbes;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82a
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Feb 10, 2021 at 7:23 PM Jin Huang <andy.jinhuang@gmail.com> wrote:
>
> Oh, I see. Thank you for your explanation.
>
> Now I want to reproduce the data race myself based on the syzkaller log i=
nformation.
> Since I can not get the reproduce source code from syzkaller tools, like =
syz-repro, syz-execprog, I want to write the C program to reproduce the dat=
a race myself.
>
> The crash log file generated by syzkaller already shows the syscalls trig=
gering the data race, but all the input parameters are numbers, like fd, an=
d other parameters, hard for me to recognize. Do you have any suggestions i=
f I want to get the inputs. In the end, I can just write the program like y=
ours, https://groups.google.com/g/syzkaller/c/fHZ42YrQM-Y/m/Z4Xf-BbUDgAJ?pl=
i=3D1
>
> Maybe I am still not so clear about how to use syz-execprog. As described=
 here, https://github.com/google/syzkaller/blob/master/docs/reproducing_cra=
shes.md, I can run syz-execprog with the crash-log, and it will run to prod=
uce the data race but seems it will not stop, always resuming the programs =
and stuff. As I understand, it should produce some output file so that I ca=
n further use syz-prog2c to get the C source reproduce program, right?

Yes, syz-execprog is intended for just running the program or a set of
programs, it does not do anything else.
Yes, syz-prog2c converts syzkaller programs in the log to
corresponding C programs.
If you see what program in the crash log caused the race, you need to
save it to a separate file and then invoke syz-prog2c on that file. It
will give you a C program.


> On Wed, Feb 10, 2021 at 3:23 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>>
>> On Wed, Feb 10, 2021 at 6:20 AM Jin Huang <andy.jinhuang@gmail.com> wrot=
e:
>> >
>> > Hi, my name is Jin Huang, a graduate student at TAMU.
>> >
>> > After running syzkaller to fuzz the Linux Kernel through some syscalls=
 I set up, I got some KCSAN data race report, and I tried to reproduce the =
data race myself.
>> >
>> > First I tried ./syz-repro -config my.cfg crashlog
>> > It was running for about half a hour, and reported some KCSAN data rac=
e, and stopped. And these data race are also different from the one I got r=
unning syzkaller.
>> >
>> > Then I tried tools/syz-execprog on the crashlog on vm.
>> > And it is still running, and report some data race as well.
>> >
>> > I think there should be some way for me to get the corresponding input=
 for the syscalls fuzzing I set up, so that I can reproduce the data race r=
eported, or as the document suggests, I could just get the source code thro=
ugh the syzkaller tools to reproduce the data race?
>>
>> +syzkaller mailing list
>>
>> Hi Jin,
>>
>> syz-mananger extract reproducers for bugs automatically. You don't
>> need to do anything at all.
>> But note it does not always work and, yes, it may extract a reproducer
>> for a different bug. That's due to non-determinism everywhere,
>> concurrency, accumulated state, too many bugs in the kernel and for
>> KCSAN additionally
>> samping nature.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BZ51%2B01x_b%2BLTfeE2zP-w9Yt9eFOA6mdh7cVpc4BcZZLQ%40mail.=
gmail.com.
