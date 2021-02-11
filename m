Return-Path: <kasan-dev+bncBDKYJ4OFZQIRBQX3SOAQMGQEMBWFWXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8451A31875F
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 10:49:55 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id b14sf3279408ljf.22
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 01:49:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613036995; cv=pass;
        d=google.com; s=arc-20160816;
        b=pTXAJvyW4ZLXrcN/nMBKxqRaLEOpv86reE4hPOdrSTRjLPO0B4MHyo3SjUjPVwvFp/
         3jR0J0SofssoiiHkNCVgMoKjUTVyQYm1yAjqlliZsuknfM0AM1Vg63PBznvE7U6/ZYoG
         og4UyRgM06XBPYNqFAe7plvzd3Br63IgjYUmx5zNFPHGInsj0lxJhCAbPscxpEWK9dP1
         CQEf4k6+eI+w+XQPWs47147kNyCSMptEA+RbCHssJnjGapQQt9406jk70zVTViPo7inD
         3fQN1gt7psJRBTc0WmP9cxWJxzdskkYHrXddaKQ0Pa+jmDSj+mmtNiWVhi4dw+NuBR5+
         VSLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=ZG0ivptV5K1EUb72O2Fx6nRZlbss1MtnCRjdYe7MpCI=;
        b=uYHFbJCvBcNd4+cZXdHTAjcAix1naf/fUkcAyVu4pQQSjjQL1IrgPZpSORiKyiIyop
         KOibJeEYU2/87ngcCAQ2ocUUIve1eCGb/o3nishY/L0L62hiEJh4ASvZOpFIi6mPFpxW
         LAA8vzfSnhbnTxHhtQ9Or08Hq6j6lTI9YZh//c1YHYe/94Sn8JLLMs3xAYHRa0dOPt3V
         wDbb8/L/2Mk48amSr7wU0yTtlKIpoM/xX7orhH3kPmYErQh7rQNE8OKeI0hvh5BO/d0t
         YOju+y3SrjLAo7eyx5lHHasU9qE4WLaEzQqGBZfKH44fGFnBon3iwXrTTmLUE4mdTrsM
         opmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=rfqwrpRS;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZG0ivptV5K1EUb72O2Fx6nRZlbss1MtnCRjdYe7MpCI=;
        b=YTSgk0jp3kdM8pZl0Z8tWbOF4MuQWM69ZFxnHHlIV1tWzjUKROFr66qYx/GhT40s+Q
         mfdbFt3rF0cyHPfyBjAHzPfS3jTYbo3Lb9/UeK0jb6PxM98Sb+Ln0E+RpNdibDkHorjJ
         oox0Z2frz5t3JXQP/nFwp7h1OulORd5kp/dmcU7lNgwGKpnxyQDo+I8k5JomYt2+71Hl
         6PLuKxsM+aBQ2oaij7eLnK9OwPW/LAWVh7TqdFv3H8ifECLhnyuI50FdBbmE0OgSPieE
         F68/RKkdlq3cFWwLNtp4jkjm6IC9UewBjlJ7thX2YPDjHY5YP33RS1n6vn/nOLhTTYnJ
         m7zQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZG0ivptV5K1EUb72O2Fx6nRZlbss1MtnCRjdYe7MpCI=;
        b=jmjW2A7eJT/UrHQDBroQQ6NMKeZesGbymLxE80L8nbTuzeYrrQ2RuvNd47SeBjhlYS
         fdIpKbFlSCaESRfPhJK1KBodVbZqqWzhD+iVBFiuayDZPE36M2kz57vuVFXAQsGJiAj8
         WO518Pipo48w4/hozeONQDGAiDFBcnJ4ckYrRwHecUrAEli00a+MXnvmOVkwguIexfPV
         7wSkRAvcfHhyCgLGlZaxPy3QrKyJfxQai0vSm/5/mAVmZ8qzN6YFefbCDHOqDtFQxCS5
         5EiCy6HaAhoWk7vFhbvjGPnVMzYG90w719eHd27UGuBWevcBVjD4f/cVqxUZyN3SUs4H
         zPrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZG0ivptV5K1EUb72O2Fx6nRZlbss1MtnCRjdYe7MpCI=;
        b=S50fdRZ1/o9bYsLFeZOH6wf2iooI+EnQ9oLUROERc9IefRBDItYRZgAyH+rV4zGq9H
         CrB69ooqcbt3s17OqtyX1Bx5hX+QvsKfXe6b90c1ArUZZPbMsVy96W0vvDnh5/AUAMPM
         3VmgdG+6vG5zqGVn6Esk5Oyteg1ys9K+IAtMz3+qKTvvGzQ883vBY/aHVq48Pzi5TEYx
         7F83T6jjZHdgqPuHS3yFr8km7w2dPnOagQe+FMwvE0otHFUcOZcXhQhxjHP/6uY5J+2E
         5JPxQKuGdUCU5VKgrIqCEr8ZXsI4JvHTI7A+1oKxWkz6OBlSSddOGCKVzIS3KfW0sI24
         dy2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532xIBMVfpIKWV4GgHkr4Lmu/PcrFTCKGteJYXvs95osNacTZMJX
	4Y4fdjf4ihgwcfEa140WQ8s=
X-Google-Smtp-Source: ABdhPJzVWuyIjfUL7SQEgCS0Y14QyMMM1ZrWjJgQO1u/lfnHg9aqJrc08g/eoWGHeUYR00INqelmhg==
X-Received: by 2002:a05:6512:110b:: with SMTP id l11mr4095170lfg.468.1613036995064;
        Thu, 11 Feb 2021 01:49:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:6e14:: with SMTP id j20ls284750ljc.6.gmail; Thu, 11 Feb
 2021 01:49:54 -0800 (PST)
X-Received: by 2002:a05:651c:555:: with SMTP id q21mr4593741ljp.471.1613036993948;
        Thu, 11 Feb 2021 01:49:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613036993; cv=none;
        d=google.com; s=arc-20160816;
        b=khiQuZFm23UipZHRbk+McNeBe1SAAfYZJCkRqUUcQzsZQ8QBgBzdXkyxtLiuDuvsjH
         qg1dekb9XtR5AMdR2SNrG4a5rqQTPBCnqNpVU6HvVm6zYN3N3HbLbNdk03rCBF6xXaXA
         A4bK3mIYCIevlQLrRkyedU4u+OhjiTECvASsG8D0vjwN8bWu89lwvOina/KoyEsQcrz2
         6MXBlK5DCQU1VtNSdpv4SsoMJL2FaCEdu1UIHDgoAq10xK5lf0JmYFt65CQqd1wSzA6x
         PszbO082WMBMwFRBXwOrmwnNfp/idCXjg2+PoraP6HcJzdNQcUeznIAbCbMtaj1oIdZc
         WCww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qxXRSwtsDZXQIFQ0LYxdWsIF7iE0qKMv51jazZLI23g=;
        b=kn8ivialk4f6k3b3Yb9hiZkeseRCu6kqhSitKm1ulgjiwdqVSyzezV2k0h2X8IhumL
         H2F5pVOoycz8DF9LclX7ykjzab4kAuBn0fh1y3LShTx8eKtMTjM/l8bdw6BJ6JTB7hxO
         1c4nPpM4LWm6hpU1zNQJDbaLKOikfFbZIWqbx2M/9K9lP1Q/tpVA9oABannGMtMsDKC2
         OoqtO6h0+JRo8jYt9eEMTdAcdR//+GqzlBYouamOATUmuFJM+GGU9U6pXTAiKXfNANyB
         U4YUSLjZ+IdnppQPLzMUnO3gcblzcfRSVhc5MX1GP0AGPwXfDbM7V5ot+hnQcoZoMA/b
         UL+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=rfqwrpRS;
       spf=pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=andy.jinhuang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52f.google.com (mail-ed1-x52f.google.com. [2a00:1450:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id s5si263416ljg.7.2021.02.11.01.49.53
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Feb 2021 01:49:53 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) client-ip=2a00:1450:4864:20::52f;
Received: by mail-ed1-x52f.google.com with SMTP id y8so6271976ede.6;
        Thu, 11 Feb 2021 01:49:53 -0800 (PST)
X-Received: by 2002:a05:6402:6cc:: with SMTP id n12mr7689000edy.69.1613036993549;
 Thu, 11 Feb 2021 01:49:53 -0800 (PST)
MIME-Version: 1.0
References: <CACV+nar9Apf15oXvwqsyd5OEX3PQ6OTxbhgG+0JRP0+iUvh_KQ@mail.gmail.com>
 <CACT4Y+Yo-HtoNrA8PL3qWYoUitt-WHgZmJ7wqh9zn01t53JL9g@mail.gmail.com>
 <CACV+naqJOptZa2e1+a9pNYP7Wh5yLwKtDSgzEz7yQaTB4uzLYQ@mail.gmail.com>
 <CACT4Y+Z51+01x_b+LTfeE2zP-w9Yt9eFOA6mdh7cVpc4BcZZLQ@mail.gmail.com>
 <CACV+naoDZiei0UR5psO05UhJXiYtgLzfBamoYNfKmOPNaBFr_g@mail.gmail.com>
 <CACT4Y+aCJOL3bQEcBNVqXWTWD5xZyB_E53_OGYB33gG+G8PLFQ@mail.gmail.com> <CACV+napVK9r2a61a8=bPcgAzeK+xdbg6fskBX+Aan2_b4+G5EQ@mail.gmail.com>
In-Reply-To: <CACV+napVK9r2a61a8=bPcgAzeK+xdbg6fskBX+Aan2_b4+G5EQ@mail.gmail.com>
From: Jin Huang <andy.jinhuang@gmail.com>
Date: Thu, 11 Feb 2021 04:49:42 -0500
Message-ID: <CACV+naq++A0btYaV8POmP8+_3BytCaGnOGDG6KmXYCfv463q1g@mail.gmail.com>
Subject: Re: reproduce data race
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: multipart/alternative; boundary="00000000000002972305bb0c71e8"
X-Original-Sender: andy.jinhuang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=rfqwrpRS;       spf=pass
 (google.com: domain of andy.jinhuang@gmail.com designates 2a00:1450:4864:20::52f
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

--00000000000002972305bb0c71e8
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi, Dmitry
Still a question , for example the log I select is:
08:55:49 executing program 1:
r0 =3D epoll_create(0x800)
syz_io_uring_setup(0x472e, &(0x7f0000000100), &(0x7f0000ffe000/0x1000)=3Dni=
l,
&(0x7f0000ffc000/0x1000)=3Dnil, &(0x7f0000000180), &(0x7f00000001c0))
epoll_wait(r0, &(0x7f0000000000)=3D[{}], 0x1, 0x0)

08:55:49 executing program 2:
r0 =3D syz_io_uring_setup(0x61a1, &(0x7f0000000000)=3D{0x0, 0x4ff, 0x1, 0x0=
,
0x32a}, &(0x7f0000ffc000/0x2000)=3Dnil, &(0x7f0000ffc000/0x2000)=3Dnil,
&(0x7f0000000080), &(0x7f00000000c0))
syz_io_uring_setup(0x3243, &(0x7f0000000100)=3D{0x0, 0xd02d, 0x20, 0x3,
0x16e, 0x0, r0}, &(0x7f0000ffc000/0x3000)=3Dnil,
&(0x7f0000ffc000/0x4000)=3Dnil, &(0x7f0000000180), &(0x7f00000001c0))
clone(0x22102000, 0x0, 0x0, 0x0, 0x0)
syz_io_uring_setup(0x2fa8, &(0x7f0000000200)=3D{0x0, 0xd1a6, 0x0, 0x1, 0xf6=
,
0x0, r0}, &(0x7f0000ffc000/0x2000)=3Dnil, &(0x7f0000ffc000/0x1000)=3Dnil,
&(0x7f0000000280), &(0x7f00000002c0))

Could I generate the C program to run program1 and program2 on different
threads? Or I need to generate for program1 and program2 separately and
merge the program source code myself?
Since I see the -threaded option for syz-prog2c, but not sure the effect.


Thank You
Best
Jin Huang


On Thu, Feb 11, 2021 at 4:11 AM Jin Huang <andy.jinhuang@gmail.com> wrote:

> Amazing!
> It works!
>
> Thank You
> Best
> Jin Huang
>
>
> On Thu, Feb 11, 2021 at 3:48 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
>> On Thu, Feb 11, 2021 at 9:45 AM Jin Huang <andy.jinhuang@gmail.com>
>> wrote:
>> >
>> > =E2=80=9CIf you see what program in the crash log caused the race, you=
 need to
>> save it to a separate file and then invoke syz-prog2c on that file. It w=
ill
>> give you a C program.=E2=80=9D
>> >
>> > For example, a segment of the log file is:
>> > 08:55:49 executing program 6:
>> > r0 =3D epoll_create(0x800)
>> > syz_io_uring_setup(0x472e, &(0x7f0000000100),
>> &(0x7f0000ffe000/0x1000)=3Dnil, &(0x7f0000ffc000/0x1000)=3Dnil,
>> &(0x7f0000000180), &(0x7f00000001c0))
>> > epoll_wait(r0, &(0x7f0000000000)=3D[{}], 0x1, 0x0)
>> >
>> > 08:55:49 executing program 4:
>> > r0 =3D epoll_create1(0x0)
>> > r1 =3D epoll_create1(0x0)
>> > r2 =3D syz_io_uring_setup(0x472e, &(0x7f0000000100),
>> &(0x7f0000ffe000/0x1000)=3Dnil, &(0x7f0000ffc000/0x1000)=3Dnil,
>> &(0x7f0000000180), &(0x7f00000001c0))
>> > epoll_ctl$EPOLL_CTL_ADD(r1, 0x1, r2, 0x0)
>> > epoll_ctl$EPOLL_CTL_ADD(r0, 0x1, r1, &(0x7f0000000080)=3D{0x6})
>> >
>> > [  932.291530]
>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>> > [  932.292332] BUG: KCSAN: data-race in start_this_handle /
>> start_this_handle
>> >
>> >
>> > Do you mean I can just copy this part:
>> >
>> > r0 =3D epoll_create1(0x0)
>> > r1 =3D epoll_create1(0x0)
>> > r2 =3D syz_io_uring_setup(0x472e, &(0x7f0000000100),
>> &(0x7f0000ffe000/0x1000)=3Dnil, &(0x7f0000ffc000/0x1000)=3Dnil,
>> &(0x7f0000000180), &(0x7f00000001c0))
>> > epoll_ctl$EPOLL_CTL_ADD(r1, 0x1, r2, 0x0)
>> > epoll_ctl$EPOLL_CTL_ADD(r0, 0x1, r1, &(0x7f0000000080)=3D{0x6})
>> >
>> > into a separate file, example, and the syz-proc2c running on it will
>> generate a corresponding C program?
>>
>> Yes.
>>
>> Please sync to HEAD to pick up this commit:
>>
>> https://github.com/google/syzkaller/commit/50068b628237c3793bf1df02bd207=
b713ff17b8b
>> It should fix the crash.
>>
>>
>> > But then I try syz-proc2c -prog example, it does not work, with this
>> information:
>> > panic: bad slowdown 0
>> >
>> > goroutine 1 [running]:
>> > github.com/google/syzkaller/sys/targets.(*Target).Timeouts(0xc000332e0=
0,
>> 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
>> >         /home/jin/syzkaller_space/gopath/src/
>> github.com/google/syzkaller/sys/targets/targets.go:682 +0x239
>> > github.com/google/syzkaller/pkg/csource.Write(0xc000e8eb00, 0x0, 0x1,
>> 0x1, 0x0, 0x0, 0x0, 0x0, 0xffffffffffffffff, 0x0, ...)
>> >         /home/jin/syzkaller_space/gopath/src/
>> github.com/google/syzkaller/pkg/csource/csource.go:97 +0xae0
>> > main.main()
>> >         /home/jin/syzkaller_space/gopath/src/
>> github.com/google/syzkaller/tools/syz-prog2c/prog2c.go:101 +0x816
>> >
>> > Do I miss something?
>> >
>> >
>> >
>> >
>> > Thank You
>> > Best
>> > Jin Huang
>> >
>> >
>> > On Thu, Feb 11, 2021 at 2:52 AM Dmitry Vyukov <dvyukov@google.com>
>> wrote:
>> >>
>> >> On Wed, Feb 10, 2021 at 7:23 PM Jin Huang <andy.jinhuang@gmail.com>
>> wrote:
>> >> >
>> >> > Oh, I see. Thank you for your explanation.
>> >> >
>> >> > Now I want to reproduce the data race myself based on the syzkaller
>> log information.
>> >> > Since I can not get the reproduce source code from syzkaller tools,
>> like syz-repro, syz-execprog, I want to write the C program to reproduce
>> the data race myself.
>> >> >
>> >> > The crash log file generated by syzkaller already shows the syscall=
s
>> triggering the data race, but all the input parameters are numbers, like
>> fd, and other parameters, hard for me to recognize. Do you have any
>> suggestions if I want to get the inputs. In the end, I can just write th=
e
>> program like yours,
>> https://groups.google.com/g/syzkaller/c/fHZ42YrQM-Y/m/Z4Xf-BbUDgAJ?pli=
=3D1
>> >> >
>> >> > Maybe I am still not so clear about how to use syz-execprog. As
>> described here,
>> https://github.com/google/syzkaller/blob/master/docs/reproducing_crashes=
.md,
>> I can run syz-execprog with the crash-log, and it will run to produce th=
e
>> data race but seems it will not stop, always resuming the programs and
>> stuff. As I understand, it should produce some output file so that I can
>> further use syz-prog2c to get the C source reproduce program, right?
>> >>
>> >> Yes, syz-execprog is intended for just running the program or a set o=
f
>> >> programs, it does not do anything else.
>> >> Yes, syz-prog2c converts syzkaller programs in the log to
>> >> corresponding C programs.
>> >> If you see what program in the crash log caused the race, you need to
>> >> save it to a separate file and then invoke syz-prog2c on that file. I=
t
>> >> will give you a C program.
>> >>
>> >>
>> >> > On Wed, Feb 10, 2021 at 3:23 AM Dmitry Vyukov <dvyukov@google.com>
>> wrote:
>> >> >>
>> >> >> On Wed, Feb 10, 2021 at 6:20 AM Jin Huang <andy.jinhuang@gmail.com=
>
>> wrote:
>> >> >> >
>> >> >> > Hi, my name is Jin Huang, a graduate student at TAMU.
>> >> >> >
>> >> >> > After running syzkaller to fuzz the Linux Kernel through some
>> syscalls I set up, I got some KCSAN data race report, and I tried to
>> reproduce the data race myself.
>> >> >> >
>> >> >> > First I tried ./syz-repro -config my.cfg crashlog
>> >> >> > It was running for about half a hour, and reported some KCSAN
>> data race, and stopped. And these data race are also different from the =
one
>> I got running syzkaller.
>> >> >> >
>> >> >> > Then I tried tools/syz-execprog on the crashlog on vm.
>> >> >> > And it is still running, and report some data race as well.
>> >> >> >
>> >> >> > I think there should be some way for me to get the corresponding
>> input for the syscalls fuzzing I set up, so that I can reproduce the dat=
a
>> race reported, or as the document suggests, I could just get the source
>> code through the syzkaller tools to reproduce the data race?
>> >> >>
>> >> >> +syzkaller mailing list
>> >> >>
>> >> >> Hi Jin,
>> >> >>
>> >> >> syz-mananger extract reproducers for bugs automatically. You don't
>> >> >> need to do anything at all.
>> >> >> But note it does not always work and, yes, it may extract a
>> reproducer
>> >> >> for a different bug. That's due to non-determinism everywhere,
>> >> >> concurrency, accumulated state, too many bugs in the kernel and fo=
r
>> >> >> KCSAN additionally
>> >> >> samping nature.
>>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACV%2Bnaq%2B%2BA0btYaV8POmP8%2B_3BytCaGnOGDG6KmXYCfv463q1g%40mai=
l.gmail.com.

--00000000000002972305bb0c71e8
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hi, Dmitry<div>Still a question , for example the log I se=
lect is:</div><div>08:55:49 executing program 1:<br>r0 =3D epoll_create(0x8=
00)<br>syz_io_uring_setup(0x472e, &amp;(0x7f0000000100), &amp;(0x7f0000ffe0=
00/0x1000)=3Dnil, &amp;(0x7f0000ffc000/0x1000)=3Dnil, &amp;(0x7f0000000180)=
, &amp;(0x7f00000001c0))<br>epoll_wait(r0, &amp;(0x7f0000000000)=3D[{}], 0x=
1, 0x0)<br><br>08:55:49 executing program 2:<br>r0 =3D syz_io_uring_setup(0=
x61a1, &amp;(0x7f0000000000)=3D{0x0, 0x4ff, 0x1, 0x0, 0x32a}, &amp;(0x7f000=
0ffc000/0x2000)=3Dnil, &amp;(0x7f0000ffc000/0x2000)=3Dnil, &amp;(0x7f000000=
0080), &amp;(0x7f00000000c0))<br>syz_io_uring_setup(0x3243, &amp;(0x7f00000=
00100)=3D{0x0, 0xd02d, 0x20, 0x3, 0x16e, 0x0, r0}, &amp;(0x7f0000ffc000/0x3=
000)=3Dnil, &amp;(0x7f0000ffc000/0x4000)=3Dnil, &amp;(0x7f0000000180), &amp=
;(0x7f00000001c0))<br>clone(0x22102000, 0x0, 0x0, 0x0, 0x0)<br>syz_io_uring=
_setup(0x2fa8, &amp;(0x7f0000000200)=3D{0x0, 0xd1a6, 0x0, 0x1, 0xf6, 0x0, r=
0}, &amp;(0x7f0000ffc000/0x2000)=3Dnil, &amp;(0x7f0000ffc000/0x1000)=3Dnil,=
 &amp;(0x7f0000000280), &amp;(0x7f00000002c0))<br></div><div><br></div><div=
>Could I generate the C program to run program1 and program2 on different t=
hreads? Or I need to generate for program1 and program2 separately and merg=
e the program source code myself?</div><div>Since I see the -threaded optio=
n for syz-prog2c, but not sure the effect.</div><div></div><div><br clear=
=3D"all"><div><div dir=3D"ltr" class=3D"gmail_signature" data-smartmail=3D"=
gmail_signature"><div dir=3D"ltr"><div><br></div><div>Thank You</div>Best<d=
iv>Jin Huang</div></div></div></div><br></div></div><br><div class=3D"gmail=
_quote"><div dir=3D"ltr" class=3D"gmail_attr">On Thu, Feb 11, 2021 at 4:11 =
AM Jin Huang &lt;<a href=3D"mailto:andy.jinhuang@gmail.com">andy.jinhuang@g=
mail.com</a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote" style=3D=
"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-le=
ft:1ex"><div dir=3D"ltr">Amazing!<div>It works!<br clear=3D"all"><div><div =
dir=3D"ltr"><div dir=3D"ltr"><div><br></div><div>Thank You</div>Best<div>Ji=
n Huang</div></div></div></div><br></div></div><br><div class=3D"gmail_quot=
e"><div dir=3D"ltr" class=3D"gmail_attr">On Thu, Feb 11, 2021 at 3:48 AM Dm=
itry Vyukov &lt;<a href=3D"mailto:dvyukov@google.com" target=3D"_blank">dvy=
ukov@google.com</a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote" s=
tyle=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);pad=
ding-left:1ex">On Thu, Feb 11, 2021 at 9:45 AM Jin Huang &lt;<a href=3D"mai=
lto:andy.jinhuang@gmail.com" target=3D"_blank">andy.jinhuang@gmail.com</a>&=
gt; wrote:<br>
&gt;<br>
&gt; =E2=80=9CIf you see what program in the crash log caused the race, you=
 need to save it to a separate file and then invoke syz-prog2c on that file=
. It will give you a C program.=E2=80=9D<br>
&gt;<br>
&gt; For example, a segment of the log file is:<br>
&gt; 08:55:49 executing program 6:<br>
&gt; r0 =3D epoll_create(0x800)<br>
&gt; syz_io_uring_setup(0x472e, &amp;(0x7f0000000100), &amp;(0x7f0000ffe000=
/0x1000)=3Dnil, &amp;(0x7f0000ffc000/0x1000)=3Dnil, &amp;(0x7f0000000180), =
&amp;(0x7f00000001c0))<br>
&gt; epoll_wait(r0, &amp;(0x7f0000000000)=3D[{}], 0x1, 0x0)<br>
&gt;<br>
&gt; 08:55:49 executing program 4:<br>
&gt; r0 =3D epoll_create1(0x0)<br>
&gt; r1 =3D epoll_create1(0x0)<br>
&gt; r2 =3D syz_io_uring_setup(0x472e, &amp;(0x7f0000000100), &amp;(0x7f000=
0ffe000/0x1000)=3Dnil, &amp;(0x7f0000ffc000/0x1000)=3Dnil, &amp;(0x7f000000=
0180), &amp;(0x7f00000001c0))<br>
&gt; epoll_ctl$EPOLL_CTL_ADD(r1, 0x1, r2, 0x0)<br>
&gt; epoll_ctl$EPOLL_CTL_ADD(r0, 0x1, r1, &amp;(0x7f0000000080)=3D{0x6})<br=
>
&gt;<br>
&gt; [=C2=A0 932.291530] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
<br>
&gt; [=C2=A0 932.292332] BUG: KCSAN: data-race in start_this_handle / start=
_this_handle<br>
&gt;<br>
&gt;<br>
&gt; Do you mean I can just copy this part:<br>
&gt;<br>
&gt; r0 =3D epoll_create1(0x0)<br>
&gt; r1 =3D epoll_create1(0x0)<br>
&gt; r2 =3D syz_io_uring_setup(0x472e, &amp;(0x7f0000000100), &amp;(0x7f000=
0ffe000/0x1000)=3Dnil, &amp;(0x7f0000ffc000/0x1000)=3Dnil, &amp;(0x7f000000=
0180), &amp;(0x7f00000001c0))<br>
&gt; epoll_ctl$EPOLL_CTL_ADD(r1, 0x1, r2, 0x0)<br>
&gt; epoll_ctl$EPOLL_CTL_ADD(r0, 0x1, r1, &amp;(0x7f0000000080)=3D{0x6})<br=
>
&gt;<br>
&gt; into a separate file, example, and the syz-proc2c running on it will g=
enerate a corresponding C program?<br>
<br>
Yes.<br>
<br>
Please sync to HEAD to pick up this commit:<br>
<a href=3D"https://github.com/google/syzkaller/commit/50068b628237c3793bf1d=
f02bd207b713ff17b8b" rel=3D"noreferrer" target=3D"_blank">https://github.co=
m/google/syzkaller/commit/50068b628237c3793bf1df02bd207b713ff17b8b</a><br>
It should fix the crash.<br>
<br>
<br>
&gt; But then I try syz-proc2c -prog example, it does not work, with this i=
nformation:<br>
&gt; panic: bad slowdown 0<br>
&gt;<br>
&gt; goroutine 1 [running]:<br>
&gt; <a href=3D"http://github.com/google/syzkaller/sys/targets.(*Target).Ti=
meouts(0xc000332e00" rel=3D"noreferrer" target=3D"_blank">github.com/google=
/syzkaller/sys/targets.(*Target).Timeouts(0xc000332e00</a>, 0x0, 0x0, 0x0, =
0x0, 0x0, 0x0, 0x0, 0x0)<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0/home/jin/syzkaller_space/gopath/src/=
<a href=3D"http://github.com/google/syzkaller/sys/targets/targets.go:682" r=
el=3D"noreferrer" target=3D"_blank">github.com/google/syzkaller/sys/targets=
/targets.go:682</a> +0x239<br>
&gt; <a href=3D"http://github.com/google/syzkaller/pkg/csource.Write(0xc000=
e8eb00" rel=3D"noreferrer" target=3D"_blank">github.com/google/syzkaller/pk=
g/csource.Write(0xc000e8eb00</a>, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0xffff=
ffffffffffff, 0x0, ...)<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0/home/jin/syzkaller_space/gopath/src/=
<a href=3D"http://github.com/google/syzkaller/pkg/csource/csource.go:97" re=
l=3D"noreferrer" target=3D"_blank">github.com/google/syzkaller/pkg/csource/=
csource.go:97</a> +0xae0<br>
&gt; main.main()<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0/home/jin/syzkaller_space/gopath/src/=
<a href=3D"http://github.com/google/syzkaller/tools/syz-prog2c/prog2c.go:10=
1" rel=3D"noreferrer" target=3D"_blank">github.com/google/syzkaller/tools/s=
yz-prog2c/prog2c.go:101</a> +0x816<br>
&gt;<br>
&gt; Do I miss something?<br>
&gt;<br>
&gt;<br>
&gt;<br>
&gt;<br>
&gt; Thank You<br>
&gt; Best<br>
&gt; Jin Huang<br>
&gt;<br>
&gt;<br>
&gt; On Thu, Feb 11, 2021 at 2:52 AM Dmitry Vyukov &lt;<a href=3D"mailto:dv=
yukov@google.com" target=3D"_blank">dvyukov@google.com</a>&gt; wrote:<br>
&gt;&gt;<br>
&gt;&gt; On Wed, Feb 10, 2021 at 7:23 PM Jin Huang &lt;<a href=3D"mailto:an=
dy.jinhuang@gmail.com" target=3D"_blank">andy.jinhuang@gmail.com</a>&gt; wr=
ote:<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Oh, I see. Thank you for your explanation.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Now I want to reproduce the data race myself based on the syz=
kaller log information.<br>
&gt;&gt; &gt; Since I can not get the reproduce source code from syzkaller =
tools, like syz-repro, syz-execprog, I want to write the C program to repro=
duce the data race myself.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; The crash log file generated by syzkaller already shows the s=
yscalls triggering the data race, but all the input parameters are numbers,=
 like fd, and other parameters, hard for me to recognize. Do you have any s=
uggestions if I want to get the inputs. In the end, I can just write the pr=
ogram like yours, <a href=3D"https://groups.google.com/g/syzkaller/c/fHZ42Y=
rQM-Y/m/Z4Xf-BbUDgAJ?pli=3D1" rel=3D"noreferrer" target=3D"_blank">https://=
groups.google.com/g/syzkaller/c/fHZ42YrQM-Y/m/Z4Xf-BbUDgAJ?pli=3D1</a><br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Maybe I am still not so clear about how to use syz-execprog. =
As described here, <a href=3D"https://github.com/google/syzkaller/blob/mast=
er/docs/reproducing_crashes.md" rel=3D"noreferrer" target=3D"_blank">https:=
//github.com/google/syzkaller/blob/master/docs/reproducing_crashes.md</a>, =
I can run syz-execprog with the crash-log, and it will run to produce the d=
ata race but seems it will not stop, always resuming the programs and stuff=
. As I understand, it should produce some output file so that I can further=
 use syz-prog2c to get the C source reproduce program, right?<br>
&gt;&gt;<br>
&gt;&gt; Yes, syz-execprog is intended for just running the program or a se=
t of<br>
&gt;&gt; programs, it does not do anything else.<br>
&gt;&gt; Yes, syz-prog2c converts syzkaller programs in the log to<br>
&gt;&gt; corresponding C programs.<br>
&gt;&gt; If you see what program in the crash log caused the race, you need=
 to<br>
&gt;&gt; save it to a separate file and then invoke syz-prog2c on that file=
. It<br>
&gt;&gt; will give you a C program.<br>
&gt;&gt;<br>
&gt;&gt;<br>
&gt;&gt; &gt; On Wed, Feb 10, 2021 at 3:23 AM Dmitry Vyukov &lt;<a href=3D"=
mailto:dvyukov@google.com" target=3D"_blank">dvyukov@google.com</a>&gt; wro=
te:<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; On Wed, Feb 10, 2021 at 6:20 AM Jin Huang &lt;<a href=3D"=
mailto:andy.jinhuang@gmail.com" target=3D"_blank">andy.jinhuang@gmail.com</=
a>&gt; wrote:<br>
&gt;&gt; &gt;&gt; &gt;<br>
&gt;&gt; &gt;&gt; &gt; Hi, my name is Jin Huang, a graduate student at TAMU=
.<br>
&gt;&gt; &gt;&gt; &gt;<br>
&gt;&gt; &gt;&gt; &gt; After running syzkaller to fuzz the Linux Kernel thr=
ough some syscalls I set up, I got some KCSAN data race report, and I tried=
 to reproduce the data race myself.<br>
&gt;&gt; &gt;&gt; &gt;<br>
&gt;&gt; &gt;&gt; &gt; First I tried ./syz-repro -config my.cfg crashlog<br=
>
&gt;&gt; &gt;&gt; &gt; It was running for about half a hour, and reported s=
ome KCSAN data race, and stopped. And these data race are also different fr=
om the one I got running syzkaller.<br>
&gt;&gt; &gt;&gt; &gt;<br>
&gt;&gt; &gt;&gt; &gt; Then I tried tools/syz-execprog on the crashlog on v=
m.<br>
&gt;&gt; &gt;&gt; &gt; And it is still running, and report some data race a=
s well.<br>
&gt;&gt; &gt;&gt; &gt;<br>
&gt;&gt; &gt;&gt; &gt; I think there should be some way for me to get the c=
orresponding input for the syscalls fuzzing I set up, so that I can reprodu=
ce the data race reported, or as the document suggests, I could just get th=
e source code through the syzkaller tools to reproduce the data race?<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; +syzkaller mailing list<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; Hi Jin,<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; syz-mananger extract reproducers for bugs automatically. =
You don&#39;t<br>
&gt;&gt; &gt;&gt; need to do anything at all.<br>
&gt;&gt; &gt;&gt; But note it does not always work and, yes, it may extract=
 a reproducer<br>
&gt;&gt; &gt;&gt; for a different bug. That&#39;s due to non-determinism ev=
erywhere,<br>
&gt;&gt; &gt;&gt; concurrency, accumulated state, too many bugs in the kern=
el and for<br>
&gt;&gt; &gt;&gt; KCSAN additionally<br>
&gt;&gt; &gt;&gt; samping nature.<br>
</blockquote></div>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CACV%2Bnaq%2B%2BA0btYaV8POmP8%2B_3BytCaGnOGDG6KmXYCfv4=
63q1g%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://grou=
ps.google.com/d/msgid/kasan-dev/CACV%2Bnaq%2B%2BA0btYaV8POmP8%2B_3BytCaGnOG=
DG6KmXYCfv463q1g%40mail.gmail.com</a>.<br />

--00000000000002972305bb0c71e8--
