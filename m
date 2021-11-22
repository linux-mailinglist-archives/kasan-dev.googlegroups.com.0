Return-Path: <kasan-dev+bncBCLMXXWM5YBBB7M25SGAMGQEIJU4E6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B046458854
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Nov 2021 04:24:47 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id gf10-20020a056214250a00b003c08951ea03sf15318446qvb.17
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Nov 2021 19:24:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637551486; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ogy4VP5P8Zsug+qS5BlrGqlFAZxhSziOVIOQSbWWkcrkcmw+XArIEXf+zHUj+IDcD1
         /FTp+1mgCVfydV18EqEnygODC2aaN3jZ1c6766hKLBSfi8uRJ2v9Dz+3KqGlViAW/tcK
         J2D02BpzztmiyWbih44uJpmrxXmCZln87Ui+Ahy7Q6aKbNOnzvrYfaijHpP9IihH4fQK
         lmTvy5myX/uK0lUC5KARQ6xHbWLM2TDsBUmRASEmJoxLl6chGG+lgDJgt0XU1WuM3Guw
         9dwiuGbHuQ65c/unXdkiSsWev1jMBDpBpKLp0Y8IRobJMwLuIn973s5ysD/R+DXduaaq
         1NxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=bdzF9rpIGfUE0pczlBO3CaWOJQfXeGTTT90KHZ1Z0LI=;
        b=KAQjDQGNdwzfBwB6RykbNhQUilZ4uOWmjRvnW+xmX5d3/0ASz3n7/1AE+3XGJjXJux
         Qosb4QQaaic+6KuJ5tEXWcQl1n9v5ZRNyjfBdQEpEgikLowduSBYnQguU3UPEUOC+ADK
         nQTAYyuc81QV4nd/M9S+ck6iIEAT6aw0lgyP82G4X7mdtgsAkxa8t1f72oTfSh0LeyX7
         VlAcpb91rl1bSKjCdNcuuvycQNG7xghvRlVmlTIabKgrMBk8o09XUb3D1KlTEShnAsDO
         ocwR0NlUYEAObsENoK664cjYxM3adetLo9MlG4EMSuRwEyuAgmlFdiArSY8CBVTotd6f
         GvrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=F8VYmiEM;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 199.106.114.38 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bdzF9rpIGfUE0pczlBO3CaWOJQfXeGTTT90KHZ1Z0LI=;
        b=HDp0sx0MRb1z+Dl4juh6iE0aa7Mdmk84Fa7UMluYzMqpKbu3i2cZmPDIOfWBnVhiB/
         +yIu02yCfKMgI4q1NufZ61R9tqTm3Xjw8/kO5F2HvyxDZZsg8W4YgWIDcyWIqPGgX1nW
         6K7oFEb4xXOP5GBKD9Wkh97eU3N5gMZmVEcz2Hmzr8dFaHebHUb/3kD/9X3C77trMI55
         Iucw3+VYBT3KbbpEaKBk+3ftw4ljThjM9XFZdZS3i+UbzH5LnOPwZ0DeOrBeI43SY1g9
         IFrXAtsGrr7Knxe98ihcMFO+i65rtXcNoJcgWvuYX/hYO2tx+Cs3cuaoZT6+kUtYHdFO
         WRvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bdzF9rpIGfUE0pczlBO3CaWOJQfXeGTTT90KHZ1Z0LI=;
        b=bXD371t/0chVcahRl3vEqhdUZGNl3aU71uTLu0k7PFDckHq8Fe+jdJ9TLC0ugo5Yzv
         Ff0XL6/hthi7rtHhO0T/kIRHghkmqIp7gYiNgBT+vJOiRGRJelaMZsVgxu7HYKigw0ud
         2/djfTHxGsnItAMnM9lCYVhW2TyS8fYlUsA6Z8xReam1cUASg38LyO/IfnWiwe9IbLx2
         wtpNLB08PnxK2nzJUdJqR6e/L4k+1MFitQAl/OqVigDEjlFseCDe5Sg5vdrbpBXqOhFj
         n4x1MSN1wDCCLGlF0K0XoCbGLTmDLCKir/VzwY4SZHs1zHxGRdgQD4CXb9PiFAkOuv/a
         WDOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/+HkwfDIVxjwRP83MUWBp0zMkBuw+2O1olIL61nGMG/L/h1GD
	Esgf8ocgIbiSariwxrLatP4=
X-Google-Smtp-Source: ABdhPJwnBQUve3REQvJmk4vUXiINJ0ypdPgFfJUW01XW0jAVJzQxvKfsyuwSeVn3zmBbuSWRD7sHFA==
X-Received: by 2002:a37:4250:: with SMTP id p77mr45516720qka.430.1637551486049;
        Sun, 21 Nov 2021 19:24:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5c85:: with SMTP id r5ls3173538qta.5.gmail; Sun, 21 Nov
 2021 19:24:45 -0800 (PST)
X-Received: by 2002:ac8:5c50:: with SMTP id j16mr28296306qtj.255.1637551485614;
        Sun, 21 Nov 2021 19:24:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637551485; cv=none;
        d=google.com; s=arc-20160816;
        b=F4sKSCn//v+wJ0ZKcS36feTIWxmZhBzScYBlUrzLw9kAlgMtPVxRRfaydD4yTO+05V
         ttc/36MIW/oMDM+dz9+xduBEKjop4N9pKWw6Dyi5BiGoZSfPHntbgwnPkHBV2vexDu8t
         luGPA1ebKKUsV91ZIP43mrsVPgnEhEr+tSZG6fxVskZ7vY0gSipZcm9r9QWtWZJM6y8m
         DORKENMNb8Z/+cN/bwXpJ6DIvKllqxbJEilZjqjCwTS+Njg2IsWT7dOnzu6GER3XaUrQ
         vpYk/rR9g43ZDQvy2uiW8pn2eGM/AiuIx1nxJoXOR1kDrP9O/9oA2/2roC5mHiIaIZK7
         OC7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=FQp/VvzFx5b8aaMRmEVH5xC0xjLOHpfmKQXKXwEj9B8=;
        b=SjDblp9KuZNdrc623u4bQCIZIFhMjwlIanZ0JHoYr5Zu6PsPE/elW9zQKUiUUYoEc5
         blYbJRJ1PDDrV8IaFTgwByb9ftP8+xyD+ufSM5H4ioBIRVmcn0cNZhsUiu1qPN1WAFmd
         HkXGlZtU4uA6L4vhD20y51iKCrv+HIGvqMt+E7zvXyMQMiHJYFRLIa9XnOopL+EjBEGm
         NogH3V8l9QM2vmYS9a9zzgDTu8yCcjoc7TYJUHv21j4Gr+x/mbQpXsyOH1P6qRrzDjtX
         cy6oKljEL9MbBrGv0QlzeiPveln1mzK9WtKwrirrAOdP+2/MnhdAx2WshN0InkDcoj/L
         O9gQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=F8VYmiEM;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 199.106.114.38 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from alexa-out-sd-01.qualcomm.com (alexa-out-sd-01.qualcomm.com. [199.106.114.38])
        by gmr-mx.google.com with ESMTPS id bs32si1128438qkb.7.2021.11.21.19.24.45
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 21 Nov 2021 19:24:45 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 199.106.114.38 as permitted sender) client-ip=199.106.114.38;
Received: from unknown (HELO ironmsg-SD-alpha.qualcomm.com) ([10.53.140.30])
  by alexa-out-sd-01.qualcomm.com with ESMTP; 21 Nov 2021 19:24:44 -0800
X-QCInternal: smtphost
Received: from nasanex01c.na.qualcomm.com ([10.47.97.222])
  by ironmsg-SD-alpha.qualcomm.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Nov 2021 19:24:44 -0800
Received: from nalasex01a.na.qualcomm.com (10.47.209.196) by
 nasanex01c.na.qualcomm.com (10.47.97.222) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.922.19; Sun, 21 Nov 2021 19:24:43 -0800
Received: from nalasex01a.na.qualcomm.com ([fe80::ccf6:7e20:8c96:abe3]) by
 nalasex01a.na.qualcomm.com ([fe80::ccf6:7e20:8c96:abe3%4]) with mapi id
 15.02.0922.019; Sun, 21 Nov 2021 19:24:43 -0800
From: "JianGen Jiao (QUIC)" <quic_jiangenj@quicinc.com>
To: Kaipeng Zeng <kaipeng94@gmail.com>, Dmitry Vyukov <dvyukov@google.com>
CC: "JianGen Jiao (QUIC)" <quic_jiangenj@quicinc.com>, syzkaller
	<syzkaller@googlegroups.com>, "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, LKML
	<linux-kernel@vger.kernel.org>, Alexander Lochmann
	<info@alexander-lochmann.de>, "Likai Ding (QUIC)" <quic_likaid@quicinc.com>,
	Hangbin Liu <liuhangbin@gmail.com>
Subject: RE: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
Thread-Topic: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
Thread-Index: AQHX23vBqfkgnFSKsE2m4CqXnKYayqwJ2FMAgADexICAAHs6AIAADBkAgAAaKICAAANPgIAED+WAgAAEUrA=
Date: Mon, 22 Nov 2021 03:24:43 +0000
Message-ID: <062ffa8658124e089f17d73c2f523afb@quicinc.com>
References: <1637130234-57238-1-git-send-email-quic_jiangenj@quicinc.com>
 <CACT4Y+YwNawV9H7uFMVSCA5WB-Dkyu9TX+rMM3FR6gNGkKFPqw@mail.gmail.com>
 <DM8PR02MB8247720860A08914CAA41D42F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
 <CACT4Y+a07DxQdYFY6uc5Y4GhTUbcnETij6gg3y+JRDvtwSmK5g@mail.gmail.com>
 <DM8PR02MB8247A19843220E03B34BA440F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
 <CACT4Y+Y36wgP_xjYVQApNLdMOFTr2-KCHc=AipcZyZiAhwf1Nw@mail.gmail.com>
 <CACT4Y+YF4Ngm6em_Sn2p+N0x1L+O8A=BEVTNhd00LmSZ+aH1iQ@mail.gmail.com>
 <CAHk8ZdsPDDshy2EVtdGs=rjVOEWDctcNo2H+B5=d4GRcpQunog@mail.gmail.com>
In-Reply-To: <CAHk8ZdsPDDshy2EVtdGs=rjVOEWDctcNo2H+B5=d4GRcpQunog@mail.gmail.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [10.253.34.55]
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcdkim header.b=F8VYmiEM;       spf=pass
 (google.com: domain of quic_jiangenj@quicinc.com designates 199.106.114.38 as
 permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
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

Hi Kaipeng,
> BTW, our coverage filter is for Linux/amd64 only. Seems the author needs =
a coverage filter on arm.

Let you know that cov filer for arm[64] is available too in syzkaller back =
months.

-----Original Message-----
From: Kaipeng Zeng <kaipeng94@gmail.com>=20
Sent: Monday, November 22, 2021 11:09 AM
To: Dmitry Vyukov <dvyukov@google.com>
Cc: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>; syzkaller <syzkaller@g=
ooglegroups.com>; andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML <l=
inux-kernel@vger.kernel.org>; Alexander Lochmann <info@alexander-lochmann.d=
e>; Likai Ding (QUIC) <quic_likaid@quicinc.com>; Hangbin Liu <liuhangbin@gm=
ail.com>
Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range

WARNING: This email originated from outside of Qualcomm. Please be wary of =
any links or attachments, and do not enable macros.

Hi Dmitry,

On Fri, Nov 19, 2021 at 9:07 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Fri, 19 Nov 2021 at 13:55, Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > +Kaipeng, Hangbin who contributed the coverage filter to syzkaller.
> > This is a discussion about adding a similar filter to the kernel.=20
> > You can see whole discussion here:
> > https://groups.google.com/g/kasan-dev/c/TQmYUdUC08Y
>
> Joey, what do you think in general about passing a filter bitmap to the k=
ernel?
>
> Since the bitmap is large, it can make sense to reuse it across=20
> different KCOV instances.
> I am thinking about something along the following lines:
>
> kcov_fd =3D open("/debugfs/kcov");
> filter_fd =3D ioctl(kcov_fd, KCOV_CREATE_FILTER, &{... some args=20
> specifying start/end ...}); filter =3D mmap(..., filter_fd); ... write=20
> to the filter ...
>
> ...
> kcov_fd2 =3D open("/debugfs/kcov");
> ioctl(kcov_fd2, KCOV_ATTACH_FILTER, filter_fd); ioctl(kcov_fd2,=20
> KCOV_ENABLE);
>
>
> This would allow us to create 2 filters:
> 1. One the interesting subsystems
> 2. Second only for yet uncovered PCs in the interesting subsystems=20
> (updated as we discover more coverage)
>
> During fuzzing we attach the second filter to KCOV.
> But when we want to obtain full program coverage, we attach the first one=
.
>
> The filters (bitmaps) are reused across all threads in all executor=20
> processes (so that we have only 2 filters globally per VM).
>

I think implementing such a filter in kernel would be harmful to syzkaller =
fuzzing:
1. Both two bitmaps would impede syzkaller from getting backward and forwar=
d edge between interesting and uninteresting code.
Currently, syzkaller uses edge but not coverage to decide if the prog shoul=
d be collected to the corpus. And the second bitmap actually destroys the C=
FG in the interesting subsystem.
It's impossible that syzkaller restores such information by analyzing the f=
iltered coverage. While syzkaller coverage filter doesn't have this problem=
.
2. The First bitmap would impede syzkaller from getting full coverage of th=
e whole kernel. So that it would be hard to analyze how the kernel path get=
s into the interesting subsystem.
It's OK if the syscall description is completed. But, we always need to do =
such analysis if we try to improve syscall descriptions.
3. Coverage of prog would be imcompleted.

It seems the only reason to introduce in-kernel coverage filter is to defen=
se KCOV area overflow. Do nothing in improving the fuzzing loop.
It is reasonable that a fuzzer should collect full information as feedback,=
 then analyze and decide how to use that information and which to drop.
In the other hand, kernel should try its best to send more information to f=
uzzer. Only if the memory is not enough to store such information.
Doing such in-kernel filtering would be reasonable.

An alternative choice is doing edge analyzing in kernel also, but KCOV woul=
d be more and more restricted and limited.

So, I think the pc_range is enough for defense KCOV area overflow. And keep=
 it from the syzkaller fuzzing loop. But not implement such bitmap into ker=
nel.
Coverage filter in syzkaller would be more flexible. A user could effective=
ly fuzz their objective subsystems and easier to customize fuzzing loop.

BTW, our coverage filter is for Linux/amd64 only. Seems the author needs a =
coverage filter on arm.


> KCOV_CREATE_FILTER could also accept how many bytes each bit=20
> represents (that scaling factor, as hardcoding 4, 8, 16 may be bad for=20
> a stable kernel interface).
>
> But I am still not sure how to support both the main kernel and=20
> modules. We could allow setting up multiple filters for different PC=20
> ranges. Or may be just 2 (one for kernel and one for modules range).
> Or maybe 1 bitmap can cover both kernel and modules?
>
> Thoughts?
>
>
> > On Fri, 19 Nov 2021 at 12:21, JianGen Jiao (QUIC)=20
> > <quic_jiangenj@quicinc.com> wrote:
> > >
> > > Yes, on x86_64, module address space is after kernel. But like below =
on arm64, it's different.
> > >
> > > # grep stext /proc/kallsyms
> > > ffffffc010010000 T _stext
> > > # cat /proc/modules |sort -k 6 | tail -2
> > > Some_module_1 552960 0 - Live 0xffffffc00ca05000 (O)
> > > Some_module_1 360448 0 - Live 0xffffffc00cb8f000 (O) # cat=20
> > > /proc/modules |sort -k 6 | head -2
> > > Some_module_3 16384 1 - Live 0xffffffc009430000
> > >
> > > -----Original Message-----
> > > From: Dmitry Vyukov <dvyukov@google.com>
> > > Sent: Friday, November 19, 2021 6:38 PM
> > > To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> > > Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML=20
> > > <linux-kernel@vger.kernel.org>; Alexander Lochmann=20
> > > <info@alexander-lochmann.de>; Likai Ding (QUIC)=20
> > > <quic_likaid@quicinc.com>
> > > Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
> > >
> > > WARNING: This email originated from outside of Qualcomm. Please be wa=
ry of any links or attachments, and do not enable macros.
> > >
> > > On Fri, 19 Nov 2021 at 04:17, JianGen Jiao (QUIC) <quic_jiangenj@quic=
inc.com> wrote:
> > > >
> > > > Hi Dmitry,
> > > > I'm using the start, end pc from cover filter, which currently is t=
he fast way compared to the big bitmap passing from syzkaller solution, as =
I only set the cover filter to dirs/files I care about.
> > >
> > > I see.
> > > But if we are unlucky and our functions of interest are at the very l=
ow and high addresses, start/end will cover almost all kernel code...
> > >
> > > > I checked
> > > > https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCAA
> > > > AJ, The bitmap seems not the same as syzkaller one, which one=20
> > > > will be used finally?
> > >
> > > I don't know yet. We need to decide.
> > > In syzkaller we are more flexible and can change code faster, while k=
ernel interfaces are stable and need to be kept forever. So I think we need=
 to concentrate more on the good kernel interface and then support it in sy=
zkaller.
> > >
> > > > ``` Alexander's one
> > > > + pos =3D (ip - canonicalize_ip((unsigned long)&_stext)) / 4; idx=
=20
> > > > + =3D pos % BITS_PER_LONG; pos /=3D BITS_PER_LONG; if (likely(pos <
> > > > + t->kcov_size)) WRITE_ONCE(area[pos], READ_ONCE(area[pos]) | 1L=20
> > > > + t-><<
> > > > + idx);
> > > > ```
> > > > Pc offset is divided by 4 and start is _stext. But for some arch, p=
c is less than _stext.
> > >
> > > You mean that modules can have PC < _stext?
> > >
> > > > ``` https://github.com/google/syzkaller/blob/master/syz-manager/cov=
filter.go#L139-L154
> > > >         data :=3D make([]byte, 8+((size>>4)/8+1))
> > > >         order :=3D binary.ByteOrder(binary.BigEndian)
> > > >         if target.LittleEndian {
> > > >                 order =3D binary.LittleEndian
> > > >         }
> > > >         order.PutUint32(data, start)
> > > >         order.PutUint32(data[4:], size)
> > > >
> > > >         bitmap :=3D data[8:]
> > > >         for pc :=3D range pcs {
> > > >                 // The lowest 4-bit is dropped.
> > > >                 pc =3D uint32(backend.NextInstructionPC(target, uin=
t64(pc)))
> > > >                 pc =3D (pc - start) >> 4
> > > >                 bitmap[pc/8] |=3D (1 << (pc % 8))
> > > >         }
> > > >         return data
> > > > ```
> > > > Pc offset is divided by 16 and start is cover filter start pc.
> > > >
> > > > I think divided by 8 is more reasonable? Because there is at least =
one instruction before each __sanitizer_cov_trace_pc call.
> > > > 0000000000000160 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
> > > > 0000000000000168 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
> > > >
> > > > I think we still need my patch because we still need a way to keep =
the trace_pc call and post-filter in syzkaller doesn't solve trace_pc dropp=
ing, right?
> > >
> > > Yes, the in-kernel filter solves the problem of trace capacity/overfl=
ows.
> > >
> > >
> > > > But for sure I can use the bitmap from syzkaller.
> > > >
> > > > THX
> > > > Joey
> > > > -----Original Message-----
> > > > From: Dmitry Vyukov <dvyukov@google.com>
> > > > Sent: Thursday, November 18, 2021 10:00 PM
> > > > To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> > > > Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML=20
> > > > <linux-kernel@vger.kernel.org>; Alexander Lochmann=20
> > > > <info@alexander-lochmann.de>
> > > > Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
> > > >
> > > > WARNING: This email originated from outside of Qualcomm. Please be =
wary of any links or attachments, and do not enable macros.
> > > >
> > > > ,On Wed, 17 Nov 2021 at 07:24, Joey Jiao <quic_jiangenj@quicinc.com=
> wrote:
> > > > >
> > > > > Sometimes we only interested in the pcs within some range,=20
> > > > > while there are cases these pcs are dropped by kernel due to=20
> > > > > `pos >=3D
> > > > > t->kcov_size`, and by increasing the map area size doesn't help.
> > > > >
> > > > > To avoid disabling KCOV for these not intereseted pcs during=20
> > > > > build time, adding this new KCOV_PC_RANGE cmd.
> > > >
> > > > Hi Joey,
> > > >
> > > > How do you use this? I am concerned that a single range of PCs is t=
oo restrictive. I can only see how this can work for single module (continu=
ous in memory) or a single function. But for anything else (something in th=
e main kernel, or several modules), it won't work as PCs are not continuous=
.
> > > >
> > > > Maybe we should use a compressed bitmap of interesting PCs? It allo=
ws to support all cases and we already have it in syz-executor, then syz-ex=
ecutor could simply pass the bitmap to the kernel rather than post-filter.
> > > > It's also overlaps with the KCOV_MODE_UNIQUE mode that +Alexander p=
roposed here:
> > > > https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCAA
> > > > AJ It would be reasonable if kernel uses the same bitmap format=20
> > > > for these
> > > > 2 features.
> > > >
> > > >
> > > >
> > > > > An example usage is to use together syzkaller's cov filter.
> > > > >
> > > > > Change-Id: I954f6efe1bca604f5ce31f8f2b6f689e34a2981d
> > > > > Signed-off-by: Joey Jiao <quic_jiangenj@quicinc.com>
> > > > > ---
> > > > >  Documentation/dev-tools/kcov.rst | 10 ++++++++++
> > > > >  include/uapi/linux/kcov.h        |  7 +++++++
> > > > >  kernel/kcov.c                    | 18 ++++++++++++++++++
> > > > >  3 files changed, 35 insertions(+)
> > > > >
> > > > > diff --git a/Documentation/dev-tools/kcov.rst
> > > > > b/Documentation/dev-tools/kcov.rst
> > > > > index d83c9ab..fbcd422 100644
> > > > > --- a/Documentation/dev-tools/kcov.rst
> > > > > +++ b/Documentation/dev-tools/kcov.rst
> > > > > @@ -52,9 +52,15 @@ program using kcov:
> > > > >      #include <fcntl.h>
> > > > >      #include <linux/types.h>
> > > > >
> > > > > +    struct kcov_pc_range {
> > > > > +      uint32 start;
> > > > > +      uint32 end;
> > > > > +    };
> > > > > +
> > > > >      #define KCOV_INIT_TRACE                    _IOR('c', 1, unsi=
gned long)
> > > > >      #define KCOV_ENABLE                        _IO('c', 100)
> > > > >      #define KCOV_DISABLE                       _IO('c', 101)
> > > > > +    #define KCOV_TRACE_RANGE                   _IOW('c', 103, st=
ruct kcov_pc_range)
> > > > >      #define COVER_SIZE                 (64<<10)
> > > > >
> > > > >      #define KCOV_TRACE_PC  0
> > > > > @@ -64,6 +70,8 @@ program using kcov:
> > > > >      {
> > > > >         int fd;
> > > > >         unsigned long *cover, n, i;
> > > > > +        /* Change start and/or end to your interested pc range. =
*/
> > > > > +        struct kcov_pc_range pc_range =3D {.start =3D 0, .end =
=3D=20
> > > > > + (uint32)(~((uint32)0))};
> > > > >
> > > > >         /* A single fd descriptor allows coverage collection on a=
 single
> > > > >          * thread.
> > > > > @@ -79,6 +87,8 @@ program using kcov:
> > > > >                                      PROT_READ | PROT_WRITE, MAP_=
SHARED, fd, 0);
> > > > >         if ((void*)cover =3D=3D MAP_FAILED)
> > > > >                 perror("mmap"), exit(1);
> > > > > +        if (ioctl(fd, KCOV_PC_RANGE, pc_range))
> > > > > +               dprintf(2, "ignore KCOV_PC_RANGE error.\n");
> > > > >         /* Enable coverage collection on the current thread. */
> > > > >         if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC))
> > > > >                 perror("ioctl"), exit(1); diff --git=20
> > > > > a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h index=20
> > > > > 1d0350e..353ff0a 100644
> > > > > --- a/include/uapi/linux/kcov.h
> > > > > +++ b/include/uapi/linux/kcov.h
> > > > > @@ -16,12 +16,19 @@ struct kcov_remote_arg {
> > > > >         __aligned_u64   handles[0];
> > > > >  };
> > > > >
> > > > > +#define PC_RANGE_MASK ((__u32)(~((u32) 0))) struct kcov_pc_range=
 {
> > > > > +       __u32           start;          /* start pc & 0xFFFFFFFF =
*/
> > > > > +       __u32           end;            /* end pc & 0xFFFFFFFF */
> > > > > +};
> > > > > +
> > > > >  #define KCOV_REMOTE_MAX_HANDLES                0x100
> > > > >
> > > > >  #define KCOV_INIT_TRACE                        _IOR('c', 1, unsi=
gned long)
> > > > >  #define KCOV_ENABLE                    _IO('c', 100)
> > > > >  #define KCOV_DISABLE                   _IO('c', 101)
> > > > >  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, struct kco=
v_remote_arg)
> > > > > +#define KCOV_PC_RANGE                  _IOW('c', 103, struct kco=
v_pc_range)
> > > > >
> > > > >  enum {
> > > > >         /*
> > > > > diff --git a/kernel/kcov.c b/kernel/kcov.c index=20
> > > > > 36ca640..59550450
> > > > > 100644
> > > > > --- a/kernel/kcov.c
> > > > > +++ b/kernel/kcov.c
> > > > > @@ -36,6 +36,7 @@
> > > > >   *  - initial state after open()
> > > > >   *  - then there must be a single ioctl(KCOV_INIT_TRACE) call
> > > > >   *  - then, mmap() call (several calls are allowed but not=20
> > > > > useful)
> > > > > + *  - then, optional to set trace pc range
> > > > >   *  - then, ioctl(KCOV_ENABLE, arg), where arg is
> > > > >   *     KCOV_TRACE_PC - to trace only the PCs
> > > > >   *     or
> > > > > @@ -69,6 +70,8 @@ struct kcov {
> > > > >          * kcov_remote_stop(), see the comment there.
> > > > >          */
> > > > >         int                     sequence;
> > > > > +       /* u32 Trace PC range from start to end. */
> > > > > +       struct kcov_pc_range    pc_range;
> > > > >  };
> > > > >
> > > > >  struct kcov_remote_area {
> > > > > @@ -192,6 +195,7 @@ static notrace unsigned long=20
> > > > > canonicalize_ip(unsigned long ip)  void notrace
> > > > > __sanitizer_cov_trace_pc(void)  {
> > > > >         struct task_struct *t;
> > > > > +       struct kcov_pc_range pc_range;
> > > > >         unsigned long *area;
> > > > >         unsigned long ip =3D canonicalize_ip(_RET_IP_);
> > > > >         unsigned long pos;
> > > > > @@ -199,6 +203,11 @@ void notrace __sanitizer_cov_trace_pc(void)
> > > > >         t =3D current;
> > > > >         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> > > > >                 return;
> > > > > +       pc_range =3D t->kcov->pc_range;
> > > > > +       if (pc_range.start < pc_range.end &&
> > > > > +               ((ip & PC_RANGE_MASK) < pc_range.start ||
> > > > > +               (ip & PC_RANGE_MASK) > pc_range.end))
> > > > > +               return;
> > > > >
> > > > >         area =3D t->kcov_area;
> > > > >         /* The first 64-bit word is the number of subsequent=20
> > > > > PCs. */ @@ -568,6 +577,7 @@ static int kcov_ioctl_locked(struct k=
cov *kcov, unsigned int cmd,
> > > > >         int mode, i;
> > > > >         struct kcov_remote_arg *remote_arg;
> > > > >         struct kcov_remote *remote;
> > > > > +       struct kcov_pc_range *pc_range;
> > > > >         unsigned long flags;
> > > > >
> > > > >         switch (cmd) {
> > > > > @@ -589,6 +599,14 @@ static int kcov_ioctl_locked(struct kcov *kc=
ov, unsigned int cmd,
> > > > >                 kcov->size =3D size;
> > > > >                 kcov->mode =3D KCOV_MODE_INIT;
> > > > >                 return 0;
> > > > > +       case KCOV_PC_RANGE:
> > > > > +               /* Limit trace pc range. */
> > > > > +               pc_range =3D (struct kcov_pc_range *)arg;
> > > > > +               if (copy_from_user(&kcov->pc_range, pc_range, siz=
eof(kcov->pc_range)))
> > > > > +                       return -EINVAL;
> > > > > +               if (kcov->pc_range.start >=3D kcov->pc_range.end)
> > > > > +                       return -EINVAL;
> > > > > +               return 0;
> > > > >         case KCOV_ENABLE:
> > > > >                 /*
> > > > >                  * Enable coverage for the current task.
> > > > > --
> > > > > 2.7.4

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/062ffa8658124e089f17d73c2f523afb%40quicinc.com.
