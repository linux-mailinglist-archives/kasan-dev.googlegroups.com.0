Return-Path: <kasan-dev+bncBDKYJ4OFZQIRBPW5SOAQMGQEOLN4NVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 93821318669
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 09:45:50 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id i4sf5330166wmb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 00:45:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613033150; cv=pass;
        d=google.com; s=arc-20160816;
        b=g3H1y1IOiNOtt7SSUI3UEqfWJzA1ZdTevO5tXk3nZj93B4qlaUKCFHpRxSBmMGBijf
         fHGSpWw4uajcAYP73ysN+4SZsKY70FCjkTNvIwbnL8Y0exudFz2sB2VLtOy7yXJR6xrx
         ClWTh/EUqzS1TDxluRCm+/a/+G+ALkyZAO8on+gChbRt8cEY0XpsAdgrCSygVu8AQNRR
         3LsGOSVAbeWAuEMspbQNSR/tNgypAPo4xdPbU4dnbxlQ5wJdAiuQJB2BrNtxNGs4h35+
         Aa9IK5uT/DY0QWZz3fXlPZ7IFMSwORZhlaXdJstMDlapTj6zrwKYPtT/TNn2SjxweeCo
         T8Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=6XtS0K6DzzHEQZNwxHK22xrt18U3sI28W/OkHkyeBnI=;
        b=vcsnX/extV4C5Jad7bLwrZn1+mbQ6lJvs3VTRNsgXvJLe9fkFOGhuhhVa7vhdBT0mN
         IIf6vx5QSr5DvGG7GHT2y85SiiIzymaT0SIz1KRCmu13y79q1fAmW8rLm1PCiFfgrERH
         Rq48nnP7SJ9G6Ylo2prUHUt/OvukUZcHlJgWZhbe85p7eXCwiuIVE+MnIoJVOALDEV88
         I4nBvHavPTcmTk6zf4qAx8icebErz1MaYDhVugDKqyvRAd4hD1ugHRAH8p4w84OFjB2l
         fYD4u07VOgRLInSeri/WozooLPh+htxs5h6rib+ao+jNdswZiU0neN/thKHRfAec2mk2
         LFVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=sxmqsYhT;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6XtS0K6DzzHEQZNwxHK22xrt18U3sI28W/OkHkyeBnI=;
        b=EP9ZarkKNt6Bg3jZo9o2oNHvbsdkrspxrHxt9t9qGgrJA1pOfNzGBmljypdz5LjDGW
         kAaZU0Vcyb2DRMu3jNeYhXP+0C7KApdq1kiAMcwhQ8dIgtnhgyDbic1jk2suUGVmPhKT
         oZx1w2LZymrHfDGcUEeisv6QNz1VGSJ0RM9BCsvqjrL/dqIG9yAXEmmJu9vFy5Nfde8D
         QJLzJmz6Ra1l1McvwbclAjzAbif79+UOl0ImdPWgQYaPbaJdQpoqiYjn65poCrOzLlw3
         r47zRnKBwlvGrKmaFLtI+vlMhJsttLbMczal/eeS4ZPNBw90FpxBR67VEF8rRX5VAFf+
         ABWA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6XtS0K6DzzHEQZNwxHK22xrt18U3sI28W/OkHkyeBnI=;
        b=T0ESyinQ3rzpnOTzcWk6yhw/QXe/pUaT8PNFIub57sqO8iZ6+FASj/3ZWmBAZXHiiK
         JhW30fUKMBqjqy7wEVjw3DPOWrNqNBrju7pcxqZ3AAmeuNv0NnUpxXE8eWH/sM5EosEA
         qpdCI046z1BeAj1NaKfFOWHJtrcBFV6sa9yuK9TqelyyX9hC/kMz2Gi5D7HgI/vFTkcm
         Eai66BERhSQvAN/560pTnD4BTvS/JDZOcvD5vfJAtWaL76naL5CaKtpmswaNr0LxkDJl
         o994vLHus0jeBydrv37nxv5BqZy29akpGiWA7BzcWcCEAlU4aQjrsC8Xo3lMtkc3ohhB
         D91Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6XtS0K6DzzHEQZNwxHK22xrt18U3sI28W/OkHkyeBnI=;
        b=t9A3awvnASts4gUo1fMkzinZGKgpMSqTMNgsf6+PeeztgXSpsnEVVeyzSyXJ4qg+7a
         htENQomtk/OvfbydSBzNcrQmUgsVemTqPAFzMIxpBS9WYrKhJ8I6LhDQtkHtIAQyRGI4
         k1TWrWLP6C8NC5+/KJaCOQv7X4PuxKNBCCa/wN94z6ELkDYpq4cPPViGlwdscV/4v8uS
         bVTN5B7iJKfTodV8BCwQJGyOQitDLPq1gGIkDafrFHuW3I8wzZ52PzpStJ+fJNCAcOao
         wDYU5V+ApXGMpC+wH/ZcD6ZEAhyrX1pkiTgDBwQQvCRjQ6vVQWi7O5FrmV1FJPONaRIi
         gpbQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5305kADvLhvIIXsLVIhM8y/wg/24IcjApBHc+Lv0vCWEsrKVvu6K
	idfcHPdCFsGcqow2K+SSsAA=
X-Google-Smtp-Source: ABdhPJzsF0krHF4leC1JkyigkSDzXziHuaBGeVjtuEBInuAC4o35dc2OY/M0HAPig/gK3FMDXUTNKw==
X-Received: by 2002:a05:600c:4788:: with SMTP id k8mr3899060wmo.138.1613033150337;
        Thu, 11 Feb 2021 00:45:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c1ce:: with SMTP id a14ls1208243wmj.3.gmail; Thu, 11 Feb
 2021 00:45:49 -0800 (PST)
X-Received: by 2002:a1c:2e83:: with SMTP id u125mr3711007wmu.13.1613033149398;
        Thu, 11 Feb 2021 00:45:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613033149; cv=none;
        d=google.com; s=arc-20160816;
        b=VVQLHnDgN2gNTH3uh0kpnOkGFK7eYkxn6GulLniXZgFa6AjK3B5FHNNW3+WDGipW4g
         B3zQim712jOBmRNWjlWknxz8U7C5bELhZ/yX7vtQBK3jpGWJUVExQIty7WML2F+RCsng
         bQhHacZCePxWMBdsFrRdgyqtPmXcCuVzFWywxPGpHn7gyPgrd2qUFflc0sbO+4STMXYV
         xBi03ODek+DFyhxSiHrrjAWI4PXkc7MrLlrS34Qpt2R/WGHTT4cbKjy1S9FEaQpoqwIb
         AmCtsxUC4hiEIDvF+3NCSYJMSYegUD26rU7Us61cymfnT5at7wRKmGMp/fWG6zhHN+sX
         dSCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=D/0NX/Sh+2DWrIkEPxVzPMUT+nVskniZWXHH5VZbWXk=;
        b=csaRB/r++U1oB1yFc3yf3nzBXZByI7i5NT+Hb6ssj2V4K8PaYR9CARbEYLUSTGpXss
         6kyloD8mqzr+q6sxAcKJN6MHempkiG3BS/qdiWf92pIwaVgS1evHdG9vI6mhgpEnn7Ly
         WDAAZQDFpq0jFsAd9SKxlZGQa2cdQW+N0hRTlmtC3E7YrakH0a76RrCGAYai/JQ0Dqmz
         N7NXsm61ma962Hde3iMM6090co9CFlJ+0ds6HFyFKR+HmcKxm7jlzSFn4zfmkX/E5/0/
         PjX3LorJnqn81TMRn6yJu+FOQMc578FKrPVuTw2PuDTsWjworHnDlPUJqyJ9ZChwCd7w
         Vn2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=sxmqsYhT;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x629.google.com (mail-ej1-x629.google.com. [2a00:1450:4864:20::629])
        by gmr-mx.google.com with ESMTPS id u1si228541wmj.0.2021.02.11.00.45.49
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Feb 2021 00:45:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) client-ip=2a00:1450:4864:20::629;
Received: by mail-ej1-x629.google.com with SMTP id l25so8776216eja.9;
        Thu, 11 Feb 2021 00:45:49 -0800 (PST)
X-Received: by 2002:a17:907:9483:: with SMTP id dm3mr7344273ejc.120.1613033149148;
 Thu, 11 Feb 2021 00:45:49 -0800 (PST)
MIME-Version: 1.0
References: <CACV+nar9Apf15oXvwqsyd5OEX3PQ6OTxbhgG+0JRP0+iUvh_KQ@mail.gmail.com>
 <CACT4Y+Yo-HtoNrA8PL3qWYoUitt-WHgZmJ7wqh9zn01t53JL9g@mail.gmail.com>
 <CACV+naqJOptZa2e1+a9pNYP7Wh5yLwKtDSgzEz7yQaTB4uzLYQ@mail.gmail.com> <CACT4Y+Z51+01x_b+LTfeE2zP-w9Yt9eFOA6mdh7cVpc4BcZZLQ@mail.gmail.com>
In-Reply-To: <CACT4Y+Z51+01x_b+LTfeE2zP-w9Yt9eFOA6mdh7cVpc4BcZZLQ@mail.gmail.com>
From: Jin Huang <andy.jinhuang@gmail.com>
Date: Thu, 11 Feb 2021 03:45:37 -0500
Message-ID: <CACV+naoUEFVxgx10kbSFfnnOboHe18hibeRqfZ2jLMHmP842QQ@mail.gmail.com>
Subject: Re: reproduce data race
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: multipart/alternative; boundary="000000000000ddb53105bb0b8bc4"
X-Original-Sender: andy.jinhuang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=sxmqsYhT;       spf=pass
 (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::629
 as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--000000000000ddb53105bb0b8bc4
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

=E2=80=9CIf you see what program in the crash log caused the race, you need=
 to save
it to a separate file and then invoke syz-prog2c on that file. It will give
you a C program.=E2=80=9D

For example, a segment of the log file is:
08:55:49 executing program 6:
r0 =3D epoll_create(0x800)
syz_io_uring_setup(0x472e, &(0x7f0000000100), &(0x7f0000ffe000/0x1000)=3Dni=
l,
&(0x7f0000ffc000/0x1000)=3Dnil, &(0x7f0000000180), &(0x7f00000001c0))
epoll_wait(r0, &(0x7f0000000000)=3D[{}], 0x1, 0x0)

08:55:49 executing program 4:
r0 =3D epoll_create1(0x0)
r1 =3D epoll_create1(0x0)
r2 =3D syz_io_uring_setup(0x472e, &(0x7f0000000100),
&(0x7f0000ffe000/0x1000)=3Dnil, &(0x7f0000ffc000/0x1000)=3Dnil,
&(0x7f0000000180), &(0x7f00000001c0))
epoll_ctl$EPOLL_CTL_ADD(r1, 0x1, r2, 0x0)
epoll_ctl$EPOLL_CTL_ADD(r0, 0x1, r1, &(0x7f0000000080)=3D{0x6})

[  932.291530]
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[  932.292332] BUG: KCSAN: data-race in start_this_handle /
start_this_handle


Do you mean I can just copy this part:

r0 =3D epoll_create1(0x0)
r1 =3D epoll_create1(0x0)
r2 =3D syz_io_uring_setup(0x472e, &(0x7f0000000100),
&(0x7f0000ffe000/0x1000)=3Dnil, &(0x7f0000ffc000/0x1000)=3Dnil,
&(0x7f0000000180), &(0x7f00000001c0))
epoll_ctl$EPOLL_CTL_ADD(r1, 0x1, r2, 0x0)
epoll_ctl$EPOLL_CTL_ADD(r0, 0x1, r1, &(0x7f0000000080)=3D{0x6})

into a separate file, example, and the syz-proc2c running on it will
generate a corresponding C program?

But then I try syz-proc2c -prog example, it does not work, with this
information:
panic: bad slowdown 0

goroutine 1 [running]:
github.com/google/syzkaller/sys/targets.(*Target).Timeouts(0xc000332e00,
0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
        /home/jin/syzkaller_space/gopath/src/
github.com/google/syzkaller/sys/targets/targets.go:682 +0x239
github.com/google/syzkaller/pkg/csource.Write(0xc000e8eb00, 0x0, 0x1, 0x1,
0x0, 0x0, 0x0, 0x0, 0xffffffffffffffff, 0x0, ...)
        /home/jin/syzkaller_space/gopath/src/
github.com/google/syzkaller/pkg/csource/csource.go:97 +0xae0
main.main()
        /home/jin/syzkaller_space/gopath/src/
github.com/google/syzkaller/tools/syz-prog2c/prog2c.go:101 +0x816

Do I miss something?

Thank You
Best
Jin Huang


On Thu, Feb 11, 2021 at 2:52 AM Dmitry Vyukov <dvyukov@google.com> wrote:

> On Wed, Feb 10, 2021 at 7:23 PM Jin Huang <andy.jinhuang@gmail.com> wrote=
:
> >
> > Oh, I see. Thank you for your explanation.
> >
> > Now I want to reproduce the data race myself based on the syzkaller log
> information.
> > Since I can not get the reproduce source code from syzkaller tools, lik=
e
> syz-repro, syz-execprog, I want to write the C program to reproduce the
> data race myself.
> >
> > The crash log file generated by syzkaller already shows the syscalls
> triggering the data race, but all the input parameters are numbers, like
> fd, and other parameters, hard for me to recognize. Do you have any
> suggestions if I want to get the inputs. In the end, I can just write the
> program like yours,
> https://groups.google.com/g/syzkaller/c/fHZ42YrQM-Y/m/Z4Xf-BbUDgAJ?pli=3D=
1
> >
> > Maybe I am still not so clear about how to use syz-execprog. As
> described here,
> https://github.com/google/syzkaller/blob/master/docs/reproducing_crashes.=
md,
> I can run syz-execprog with the crash-log, and it will run to produce the
> data race but seems it will not stop, always resuming the programs and
> stuff. As I understand, it should produce some output file so that I can
> further use syz-prog2c to get the C source reproduce program, right?
>
> Yes, syz-execprog is intended for just running the program or a set of
> programs, it does not do anything else.
> Yes, syz-prog2c converts syzkaller programs in the log to
> corresponding C programs.
> If you see what program in the crash log caused the race, you need to
> save it to a separate file and then invoke syz-prog2c on that file. It
> will give you a C program.
>
>
> > On Wed, Feb 10, 2021 at 3:23 AM Dmitry Vyukov <dvyukov@google.com>
> wrote:
> >>
> >> On Wed, Feb 10, 2021 at 6:20 AM Jin Huang <andy.jinhuang@gmail.com>
> wrote:
> >> >
> >> > Hi, my name is Jin Huang, a graduate student at TAMU.
> >> >
> >> > After running syzkaller to fuzz the Linux Kernel through some
> syscalls I set up, I got some KCSAN data race report, and I tried to
> reproduce the data race myself.
> >> >
> >> > First I tried ./syz-repro -config my.cfg crashlog
> >> > It was running for about half a hour, and reported some KCSAN data
> race, and stopped. And these data race are also different from the one I
> got running syzkaller.
> >> >
> >> > Then I tried tools/syz-execprog on the crashlog on vm.
> >> > And it is still running, and report some data race as well.
> >> >
> >> > I think there should be some way for me to get the corresponding
> input for the syscalls fuzzing I set up, so that I can reproduce the data
> race reported, or as the document suggests, I could just get the source
> code through the syzkaller tools to reproduce the data race?
> >>
> >> +syzkaller mailing list
> >>
> >> Hi Jin,
> >>
> >> syz-mananger extract reproducers for bugs automatically. You don't
> >> need to do anything at all.
> >> But note it does not always work and, yes, it may extract a reproducer
> >> for a different bug. That's due to non-determinism everywhere,
> >> concurrency, accumulated state, too many bugs in the kernel and for
> >> KCSAN additionally
> >> samping nature.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACV%2BnaoUEFVxgx10kbSFfnnOboHe18hibeRqfZ2jLMHmP842QQ%40mail.gmai=
l.com.

--000000000000ddb53105bb0b8bc4
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div>=E2=80=9CIf you see what program in the crash log cau=
sed the race, you need to save it to a separate file and then invoke syz-pr=
og2c on that file. It will give you a C program.=E2=80=9D</div><div><br></d=
iv><div>For=C2=A0example, a segment of the log file is:</div><div>08:55:49 =
executing program 6:<br>r0 =3D epoll_create(0x800)<br>syz_io_uring_setup(0x=
472e, &amp;(0x7f0000000100), &amp;(0x7f0000ffe000/0x1000)=3Dnil, &amp;(0x7f=
0000ffc000/0x1000)=3Dnil, &amp;(0x7f0000000180), &amp;(0x7f00000001c0))<br>=
epoll_wait(r0, &amp;(0x7f0000000000)=3D[{}], 0x1, 0x0)<br><br>08:55:49 exec=
uting program 4:<br>r0 =3D epoll_create1(0x0)<br>r1 =3D epoll_create1(0x0)<=
br>r2 =3D syz_io_uring_setup(0x472e, &amp;(0x7f0000000100), &amp;(0x7f0000f=
fe000/0x1000)=3Dnil, &amp;(0x7f0000ffc000/0x1000)=3Dnil, &amp;(0x7f00000001=
80), &amp;(0x7f00000001c0))<br>epoll_ctl$EPOLL_CTL_ADD(r1, 0x1, r2, 0x0)<br=
>epoll_ctl$EPOLL_CTL_ADD(r0, 0x1, r1, &amp;(0x7f0000000080)=3D{0x6})<br><br=
>[ =C2=A0932.291530] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>[ =
=C2=A0932.292332] BUG: KCSAN: data-race in start_this_handle / start_this_h=
andle<br></div><div><br></div><div><br></div><div>Do you mean I can just co=
py this part:</div><div><br></div><div>r0 =3D epoll_create1(0x0)</div>r1 =
=3D epoll_create1(0x0)<br>r2 =3D syz_io_uring_setup(0x472e, &amp;(0x7f00000=
00100), &amp;(0x7f0000ffe000/0x1000)=3Dnil, &amp;(0x7f0000ffc000/0x1000)=3D=
nil, &amp;(0x7f0000000180), &amp;(0x7f00000001c0))<br>epoll_ctl$EPOLL_CTL_A=
DD(r1, 0x1, r2, 0x0)<br>epoll_ctl$EPOLL_CTL_ADD(r0, 0x1, r1, &amp;(0x7f0000=
000080)=3D{0x6})<div><br></div><div>into a separate file, example, and the =
syz-proc2c running on it will generate a corresponding C program?</div><div=
><br></div><div>But then I try syz-proc2c -prog example, it does not work, =
with this information:</div><div>panic: bad slowdown 0<br><br>goroutine 1 [=
running]:<br><a href=3D"http://github.com/google/syzkaller/sys/targets.(*Ta=
rget).Timeouts(0xc000332e00" target=3D"_blank">github.com/google/syzkaller/=
sys/targets.(*Target).Timeouts(0xc000332e00</a>, 0x0, 0x0, 0x0, 0x0, 0x0, 0=
x0, 0x0, 0x0)<br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 /home/jin/syzkaller_space/gopa=
th/src/<a href=3D"http://github.com/google/syzkaller/sys/targets/targets.go=
:682" target=3D"_blank">github.com/google/syzkaller/sys/targets/targets.go:=
682</a>=C2=A0+0x239<br><a href=3D"http://github.com/google/syzkaller/pkg/cs=
ource.Write(0xc000e8eb00" target=3D"_blank">github.com/google/syzkaller/pkg=
/csource.Write(0xc000e8eb00</a>, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0xfffff=
fffffffffff, 0x0, ...)<br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 /home/jin/syzkaller_s=
pace/gopath/src/<a href=3D"http://github.com/google/syzkaller/pkg/csource/c=
source.go:97" target=3D"_blank">github.com/google/syzkaller/pkg/csource/cso=
urce.go:97</a>=C2=A0+0xae0<br>main.main()<br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 /h=
ome/jin/syzkaller_space/gopath/src/<a href=3D"http://github.com/google/syzk=
aller/tools/syz-prog2c/prog2c.go:101" target=3D"_blank">github.com/google/s=
yzkaller/tools/syz-prog2c/prog2c.go:101</a>=C2=A0+0x816<br></div><div><br><=
/div><div>Do I miss something?</div><div><div dir=3D"ltr" class=3D"gmail_si=
gnature" data-smartmail=3D"gmail_signature"><div dir=3D"ltr"><div><br></div=
><div>Thank You</div>Best<div>Jin Huang</div></div></div></div><br></div><b=
r><div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmail_attr">On Thu, =
Feb 11, 2021 at 2:52 AM Dmitry Vyukov &lt;<a href=3D"mailto:dvyukov@google.=
com">dvyukov@google.com</a>&gt; wrote:<br></div><blockquote class=3D"gmail_=
quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,=
204);padding-left:1ex">On Wed, Feb 10, 2021 at 7:23 PM Jin Huang &lt;<a hre=
f=3D"mailto:andy.jinhuang@gmail.com" target=3D"_blank">andy.jinhuang@gmail.=
com</a>&gt; wrote:<br>
&gt;<br>
&gt; Oh, I see. Thank you for your explanation.<br>
&gt;<br>
&gt; Now I want to reproduce the data race myself based on the syzkaller lo=
g information.<br>
&gt; Since I can not get the reproduce source code from syzkaller tools, li=
ke syz-repro, syz-execprog, I want to write the C program to reproduce the =
data race myself.<br>
&gt;<br>
&gt; The crash log file generated by syzkaller already shows the syscalls t=
riggering the data race, but all the input parameters are numbers, like fd,=
 and other parameters, hard for me to recognize. Do you have any suggestion=
s if I want to get the inputs. In the end, I can just write the program lik=
e yours, <a href=3D"https://groups.google.com/g/syzkaller/c/fHZ42YrQM-Y/m/Z=
4Xf-BbUDgAJ?pli=3D1" rel=3D"noreferrer" target=3D"_blank">https://groups.go=
ogle.com/g/syzkaller/c/fHZ42YrQM-Y/m/Z4Xf-BbUDgAJ?pli=3D1</a><br>
&gt;<br>
&gt; Maybe I am still not so clear about how to use syz-execprog. As descri=
bed here, <a href=3D"https://github.com/google/syzkaller/blob/master/docs/r=
eproducing_crashes.md" rel=3D"noreferrer" target=3D"_blank">https://github.=
com/google/syzkaller/blob/master/docs/reproducing_crashes.md</a>, I can run=
 syz-execprog with the crash-log, and it will run to produce the data race =
but seems it will not stop, always resuming the programs and stuff. As I un=
derstand, it should produce some output file so that I can further use syz-=
prog2c to get the C source reproduce program, right?<br>
<br>
Yes, syz-execprog is intended for just running the program or a set of<br>
programs, it does not do anything else.<br>
Yes, syz-prog2c converts syzkaller programs in the log to<br>
corresponding C programs.<br>
If you see what program in the crash log caused the race, you need to<br>
save it to a separate file and then invoke syz-prog2c on that file. It<br>
will give you a C program.<br>
<br>
<br>
&gt; On Wed, Feb 10, 2021 at 3:23 AM Dmitry Vyukov &lt;<a href=3D"mailto:dv=
yukov@google.com" target=3D"_blank">dvyukov@google.com</a>&gt; wrote:<br>
&gt;&gt;<br>
&gt;&gt; On Wed, Feb 10, 2021 at 6:20 AM Jin Huang &lt;<a href=3D"mailto:an=
dy.jinhuang@gmail.com" target=3D"_blank">andy.jinhuang@gmail.com</a>&gt; wr=
ote:<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Hi, my name is Jin Huang, a graduate student at TAMU.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; After running syzkaller to fuzz the Linux Kernel through some=
 syscalls I set up, I got some KCSAN data race report, and I tried to repro=
duce the data race myself.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; First I tried ./syz-repro -config my.cfg crashlog<br>
&gt;&gt; &gt; It was running for about half a hour, and reported some KCSAN=
 data race, and stopped. And these data race are also different from the on=
e I got running syzkaller.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Then I tried tools/syz-execprog on the crashlog on vm.<br>
&gt;&gt; &gt; And it is still running, and report some data race as well.<b=
r>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; I think there should be some way for me to get the correspond=
ing input for the syscalls fuzzing I set up, so that I can reproduce the da=
ta race reported, or as the document suggests, I could just get the source =
code through the syzkaller tools to reproduce the data race?<br>
&gt;&gt;<br>
&gt;&gt; +syzkaller mailing list<br>
&gt;&gt;<br>
&gt;&gt; Hi Jin,<br>
&gt;&gt;<br>
&gt;&gt; syz-mananger extract reproducers for bugs automatically. You don&#=
39;t<br>
&gt;&gt; need to do anything at all.<br>
&gt;&gt; But note it does not always work and, yes, it may extract a reprod=
ucer<br>
&gt;&gt; for a different bug. That&#39;s due to non-determinism everywhere,=
<br>
&gt;&gt; concurrency, accumulated state, too many bugs in the kernel and fo=
r<br>
&gt;&gt; KCSAN additionally<br>
&gt;&gt; samping nature.<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CACV%2BnaoUEFVxgx10kbSFfnnOboHe18hibeRqfZ2jLMHmP842QQ%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CACV%2BnaoUEFVxgx10kbSFfnnOboHe18hibeRqfZ2jLMHmP8=
42QQ%40mail.gmail.com</a>.<br />

--000000000000ddb53105bb0b8bc4--
