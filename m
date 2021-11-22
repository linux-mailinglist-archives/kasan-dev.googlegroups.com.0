Return-Path: <kasan-dev+bncBCLMXXWM5YBBBENE5SGAMGQEGZPPJLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 91C16458870
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Nov 2021 04:44:18 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id q36-20020a4a88e7000000b002c2848c4755sf10013168ooh.10
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Nov 2021 19:44:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637552657; cv=pass;
        d=google.com; s=arc-20160816;
        b=wEMP7GrK48urwlBP42ApTBMelMv1Aa6IySmGBRPiF0BYWhwCXc7OHf4EgtTz/gZ+s8
         0Fu7us7KVRRGJX7Yyo+wgXsrXwLIeMMGtufzaLH7T2AVQUzcZRacV7jh082MfVy37lxx
         lsruAWKMABbEpYRAF5ZkIjD5OkkYoXT4xd3hq/Q8GNvcdfWX7PwF8vi7z33O+cyNQ4w7
         ZAmU337sEEjXcRrwJnfEptMsPB1C/nnhFsGvgWBAFzMZ039KRS6l/szd9lBU+n2TESfy
         KoDl70AVMtd3vzZPVwKz90JyvyGe9GaUBJVYr5VDghhgw63oDGhR8pj4wzErSwpoaZLZ
         9oow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:dkim-signature;
        bh=MVvknMqYUmBybcT1xHeG0NKyxjk7Hz3SoeVTRgw9KiE=;
        b=Emp7lltvB15Ibi6LI6n30Ooj0HHZAaKp9JvutyqjP0xqM5Ww6FiqwticF6F8gA+40j
         3bYqjytI9dVFJPaIPuvCBtiAi2bYWnyN1E9UcmXPGHV8VFOSpkiPUBhNVdSdMYE1XdUj
         zONScVenlUseFCEgW70/xV/uMBf4kBnu1+ZNIl+8X6cqlU24kT0zmLPQZWN5JMIDdnyR
         2QwPrbdXZpSsVHfYIDqsbIFQ/82MokswEMtaFAr9CzxSFBhhCQWQ9FqUn8lJOTmdccCt
         38S8wJANiXAWpfF2YQUTLkUEOPlC9fmI1uN40cXr0nAamNuwBKaYiE99q81+g6+Pt9Yj
         31/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=KvzhLvJF;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 129.46.98.28 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MVvknMqYUmBybcT1xHeG0NKyxjk7Hz3SoeVTRgw9KiE=;
        b=YXff2xzA+H4dR3/P28SJ0mMEyz3Dq2vjoWWtG5EqRhraa6dePOYff6ssSh9N3DKh5r
         onqxBSSKlrc9Wv9FyknLwC1Ww5KQY2ma9fOho1r/YToxjQfCfpVn7jkWqsFzuI4nCtwe
         HNn9XHReKMf1VEjR3d7W1hAYY+IH7kg9g+TFFztV8e+VMv0VzSoJrbRZ0MaQe/Qn+ugg
         Ve9eqeknA/8HIrXxj/FvEe3qs931biJ70lwFD1s9ia3gH1pH/egg5JLwUv9SPSiTBmrZ
         19x+YX110k+o8i7HCxdkMXD7N+LHuKAPgLt6KHw5UrZ6wrHp/y8OvZonSY82jPGdX4HB
         Rn2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MVvknMqYUmBybcT1xHeG0NKyxjk7Hz3SoeVTRgw9KiE=;
        b=7pAebcxCrzmuswDBSa9arrWbzpeh0HeK4jNGO3G2vmZqbwNzy99JPSw/S+iK1uO4be
         Uym8tsEgToHAVnNT2oQJgZuxAS3fI2TXOoDu0iVkRREQu10FZh9vbfwSgF4u8rthihzf
         ZmohXJAs6qxYIZmlmtYF7U38WrQhs/ETYRCw0yJX7AEdFoDSeZFnM1g+5xZs9xGc8qGa
         G1dsPD4mmD9hzIHxXsWdQgiSuJa2uKR1y0k+fQmyuhpyypvoOkGT+IeUf2l7be6QvE3o
         zlXMtH0wH1XXrGNKcIpgOeuUCITiY8/xgO9IKB11dRbpKCFt1OE1vSSapbcNQtLGKDRw
         MB4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532w+A6+AyI1mW23tZ3yYRBZsoO5SQmmQh2xr8SYp/o29iS7c30r
	/HgzuV6t3+R5CZL5XWE4TmU=
X-Google-Smtp-Source: ABdhPJwoHEOFgOb2Rch+4pCw0tlhtlzTpVkIfHxy+LFdfa1ruASIgyLqwkBsTI0/O6v8SGF2YWSFEw==
X-Received: by 2002:a05:6830:1da:: with SMTP id r26mr21724814ota.73.1637552657095;
        Sun, 21 Nov 2021 19:44:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4f01:: with SMTP id c1ls377434oob.11.gmail; Sun, 21 Nov
 2021 19:44:16 -0800 (PST)
X-Received: by 2002:a4a:d00a:: with SMTP id h10mr28762914oor.60.1637552656718;
        Sun, 21 Nov 2021 19:44:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637552656; cv=none;
        d=google.com; s=arc-20160816;
        b=Eu6rnj+a2zdjo/ftwJkVzeNI8X2vTVv4pWC2GPjJwmqQ+ylLm00FQa+GeUUToZBjuZ
         PKI1OEycYi9IZi9avhlqnhMJFgYZEUqBGcZGZTxTBY+sqHD3VQoqKPSnEexu9Ca/iSvI
         y3LdFII3xRhlr7Ob2UrFfvwZ/QbGKN5peyBzBLjTHHt9mjTlM8+wi3BsEcXROC2Xld8T
         YBDLvJrHmVupZAs634mOOQdCcV8O+94CjXEuHY2MJtl7XFm/+iICX2rnm6MVQChqDWbO
         sPN2+oZ6L15cQ+1Ned9YPIIL+jW7h6r7uO4j5mQBduzn1wHx9eXguZdAlCS5DptPhHoy
         o6Zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=tqr+dB/M0DQfs6hMLcmHTDCIbNgDhTnFAlimS74kXd0=;
        b=dd5bwXYfnmAeeslSAtxWY6R4AeDqZq968PC3mLJfD58A1Jpzmdjmrnd75EIScgCfwY
         fJ+EnCkcwoyt6W3UF9nKKX5DfohupqHs8pT9DWJIHBGYEvMoHdo6yZLV38LnOP20tPGG
         NQOrfMXL/Pn8UccP63FHwYdylm7xHgvtBG9dkJQI4LnV0Caumt4xIzB+EvMNCM2bBJ//
         B0yq2lUUmM0zhAjmYZKsV8T1md1FBJtkurvE1YuGkihJ8MFwXykTX8d0gMP14E07xlrI
         krgLSdMdakR+yBe9+pQzIkjRqpKosYREYr5rIJcOBWNqxz8cTR4XLrvo+mlm5IoGK0eE
         8sfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=KvzhLvJF;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 129.46.98.28 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from alexa-out.qualcomm.com (alexa-out.qualcomm.com. [129.46.98.28])
        by gmr-mx.google.com with ESMTPS id u27si701249ots.2.2021.11.21.19.44.16
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 21 Nov 2021 19:44:16 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 129.46.98.28 as permitted sender) client-ip=129.46.98.28;
Received: from ironmsg08-lv.qualcomm.com ([10.47.202.152])
  by alexa-out.qualcomm.com with ESMTP; 21 Nov 2021 19:44:15 -0800
X-QCInternal: smtphost
Received: from nasanex01c.na.qualcomm.com ([10.47.97.222])
  by ironmsg08-lv.qualcomm.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Nov 2021 19:44:15 -0800
Received: from nalasex01b.na.qualcomm.com (10.47.209.197) by
 nasanex01c.na.qualcomm.com (10.47.97.222) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.922.19; Sun, 21 Nov 2021 19:44:14 -0800
Received: from nalasex01a.na.qualcomm.com (10.47.209.196) by
 nalasex01b.na.qualcomm.com (10.47.209.197) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.922.19; Sun, 21 Nov 2021 19:44:14 -0800
Received: from nalasex01a.na.qualcomm.com ([fe80::ccf6:7e20:8c96:abe3]) by
 nalasex01a.na.qualcomm.com ([fe80::ccf6:7e20:8c96:abe3%4]) with mapi id
 15.02.0922.019; Sun, 21 Nov 2021 19:44:14 -0800
From: "JianGen Jiao (QUIC)" <quic_jiangenj@quicinc.com>
To: Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
	<andreyknvl@gmail.com>
CC: syzkaller <syzkaller@googlegroups.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, "Alexander
 Lochmann" <info@alexander-lochmann.de>, "Likai Ding (QUIC)"
	<quic_likaid@quicinc.com>, Kaipeng Zeng <kaipeng94@gmail.com>, Hangbin Liu
	<liuhangbin@gmail.com>
Subject: RE: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
Thread-Topic: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
Thread-Index: AQHX23vBqfkgnFSKsE2m4CqXnKYayqwJ2FMAgADexICAAHs6AIAADBkAgAAaKICAAANPgIAAEWQAgAABLQCAA3/PEA==
Date: Mon, 22 Nov 2021 03:44:14 +0000
Message-ID: <16605acf697e47299e3ba3bddf04441e@quicinc.com>
References: <1637130234-57238-1-git-send-email-quic_jiangenj@quicinc.com>
 <CACT4Y+YwNawV9H7uFMVSCA5WB-Dkyu9TX+rMM3FR6gNGkKFPqw@mail.gmail.com>
 <DM8PR02MB8247720860A08914CAA41D42F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
 <CACT4Y+a07DxQdYFY6uc5Y4GhTUbcnETij6gg3y+JRDvtwSmK5g@mail.gmail.com>
 <DM8PR02MB8247A19843220E03B34BA440F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
 <CACT4Y+Y36wgP_xjYVQApNLdMOFTr2-KCHc=AipcZyZiAhwf1Nw@mail.gmail.com>
 <CACT4Y+YF4Ngm6em_Sn2p+N0x1L+O8A=BEVTNhd00LmSZ+aH1iQ@mail.gmail.com>
 <CA+fCnZct-Fy6JEUoHgk0h=2aFeBAWz2Ax_kOCee3-i_6zU-wfQ@mail.gmail.com>
 <CACT4Y+bYvCKikJK_HwwPHWW057E-s1cDzQNm7KTNz_hXTUOWzQ@mail.gmail.com>
In-Reply-To: <CACT4Y+bYvCKikJK_HwwPHWW057E-s1cDzQNm7KTNz_hXTUOWzQ@mail.gmail.com>
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
 header.i=@quicinc.com header.s=qcdkim header.b=KvzhLvJF;       spf=pass
 (google.com: domain of quic_jiangenj@quicinc.com designates 129.46.98.28 as
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

https://stackoverflow.com/questions/43003805/can-ebpf-modify-the-return-val=
ue-or-parameters-of-a-syscall
eBPF seems read-only, I think it won't overcome the area overflow if cannot=
 modify the area inside kernel?

-----Original Message-----
From: Dmitry Vyukov <dvyukov@google.com>=20
Sent: Friday, November 19, 2021 10:14 PM
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>; syzkaller <syzkaller@g=
ooglegroups.com>; kasan-dev@googlegroups.com; LKML <linux-kernel@vger.kerne=
l.org>; Alexander Lochmann <info@alexander-lochmann.de>; Likai Ding (QUIC) =
<quic_likaid@quicinc.com>; Kaipeng Zeng <kaipeng94@gmail.com>; Hangbin Liu =
<liuhangbin@gmail.com>
Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range

 On Fri, 19 Nov 2021 at 15:09, Andrey Konovalov <andreyknvl@gmail.com> wrot=
e:
> > > +Kaipeng, Hangbin who contributed the coverage filter to syzkaller.
> > > This is a discussion about adding a similar filter to the kernel.=20
> > > You can see whole discussion here:
> > > https://groups.google.com/g/kasan-dev/c/TQmYUdUC08Y
> >
> > Joey, what do you think in general about passing a filter bitmap to the=
 kernel?
> >
> > Since the bitmap is large, it can make sense to reuse it across=20
> > different KCOV instances.
> > I am thinking about something along the following lines:
> >
> > kcov_fd =3D open("/debugfs/kcov");
> > filter_fd =3D ioctl(kcov_fd, KCOV_CREATE_FILTER, &{... some args=20
> > specifying start/end ...}); filter =3D mmap(..., filter_fd); ... write=
=20
> > to the filter ...
> >
> > ...
> > kcov_fd2 =3D open("/debugfs/kcov");
> > ioctl(kcov_fd2, KCOV_ATTACH_FILTER, filter_fd); ioctl(kcov_fd2,=20
> > KCOV_ENABLE);
> >
> >
> > This would allow us to create 2 filters:
> > 1. One the interesting subsystems
> > 2. Second only for yet uncovered PCs in the interesting subsystems=20
> > (updated as we discover more coverage)
> >
> > During fuzzing we attach the second filter to KCOV.
> > But when we want to obtain full program coverage, we attach the first o=
ne.
> >
> > The filters (bitmaps) are reused across all threads in all executor=20
> > processes (so that we have only 2 filters globally per VM).
> >
> > KCOV_CREATE_FILTER could also accept how many bytes each bit=20
> > represents (that scaling factor, as hardcoding 4, 8, 16 may be bad=20
> > for a stable kernel interface).
> >
> > But I am still not sure how to support both the main kernel and=20
> > modules. We could allow setting up multiple filters for different PC=20
> > ranges. Or may be just 2 (one for kernel and one for modules range).
> > Or maybe 1 bitmap can cover both kernel and modules?
> >
> > Thoughts?
>
> Throwing in a thought without a concrete design suggestion: how about=20
> en eBPF-based filter? The flexibility would allow covering as many PC=20
> ranges as one wants. And, perhaps, do other things.

This is definitely interesting and flexible. eBPF have different types of m=
aps nowadays and these can be accessed from user-space as well.
Alternatively could we attach just an eBPF map as a filter?
But we would need to measure overhead, this will be executed for every basi=
c block of code.



> > > On Fri, 19 Nov 2021 at 12:21, JianGen Jiao (QUIC)=20
> > > <quic_jiangenj@quicinc.com> wrote:
> > > >
> > > > Yes, on x86_64, module address space is after kernel. But like belo=
w on arm64, it's different.
> > > >
> > > > # grep stext /proc/kallsyms
> > > > ffffffc010010000 T _stext
> > > > # cat /proc/modules |sort -k 6 | tail -2
> > > > Some_module_1 552960 0 - Live 0xffffffc00ca05000 (O)
> > > > Some_module_1 360448 0 - Live 0xffffffc00cb8f000 (O) # cat=20
> > > > /proc/modules |sort -k 6 | head -2
> > > > Some_module_3 16384 1 - Live 0xffffffc009430000
> > > >
> > > > -----Original Message-----
> > > > From: Dmitry Vyukov <dvyukov@google.com>
> > > > Sent: Friday, November 19, 2021 6:38 PM
> > > > To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> > > > Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML=20
> > > > <linux-kernel@vger.kernel.org>; Alexander Lochmann=20
> > > > <info@alexander-lochmann.de>; Likai Ding (QUIC)=20
> > > > <quic_likaid@quicinc.com>
> > > > Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
> > > >
> > > > WARNING: This email originated from outside of Qualcomm. Please be =
wary of any links or attachments, and do not enable macros.
> > > >
> > > > On Fri, 19 Nov 2021 at 04:17, JianGen Jiao (QUIC) <quic_jiangenj@qu=
icinc.com> wrote:
> > > > >
> > > > > Hi Dmitry,
> > > > > I'm using the start, end pc from cover filter, which currently is=
 the fast way compared to the big bitmap passing from syzkaller solution, a=
s I only set the cover filter to dirs/files I care about.
> > > >
> > > > I see.
> > > > But if we are unlucky and our functions of interest are at the very=
 low and high addresses, start/end will cover almost all kernel code...
> > > >
> > > > > I checked
> > > > > https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzC
> > > > > AAAJ, The bitmap seems not the same as syzkaller one, which=20
> > > > > one will be used finally?
> > > >
> > > > I don't know yet. We need to decide.
> > > > In syzkaller we are more flexible and can change code faster, while=
 kernel interfaces are stable and need to be kept forever. So I think we ne=
ed to concentrate more on the good kernel interface and then support it in =
syzkaller.
> > > >
> > > > > ``` Alexander's one
> > > > > + pos =3D (ip - canonicalize_ip((unsigned long)&_stext)) / 4;=20
> > > > > + idx =3D pos % BITS_PER_LONG; pos /=3D BITS_PER_LONG; if=20
> > > > > + (likely(pos <
> > > > > + t->kcov_size)) WRITE_ONCE(area[pos], READ_ONCE(area[pos]) |=20
> > > > > + t->1L <<
> > > > > + idx);
> > > > > ```
> > > > > Pc offset is divided by 4 and start is _stext. But for some arch,=
 pc is less than _stext.
> > > >
> > > > You mean that modules can have PC < _stext?
> > > >
> > > > > ``` https://github.com/google/syzkaller/blob/master/syz-manager/c=
ovfilter.go#L139-L154
> > > > >         data :=3D make([]byte, 8+((size>>4)/8+1))
> > > > >         order :=3D binary.ByteOrder(binary.BigEndian)
> > > > >         if target.LittleEndian {
> > > > >                 order =3D binary.LittleEndian
> > > > >         }
> > > > >         order.PutUint32(data, start)
> > > > >         order.PutUint32(data[4:], size)
> > > > >
> > > > >         bitmap :=3D data[8:]
> > > > >         for pc :=3D range pcs {
> > > > >                 // The lowest 4-bit is dropped.
> > > > >                 pc =3D uint32(backend.NextInstructionPC(target, u=
int64(pc)))
> > > > >                 pc =3D (pc - start) >> 4
> > > > >                 bitmap[pc/8] |=3D (1 << (pc % 8))
> > > > >         }
> > > > >         return data
> > > > > ```
> > > > > Pc offset is divided by 16 and start is cover filter start pc.
> > > > >
> > > > > I think divided by 8 is more reasonable? Because there is at leas=
t one instruction before each __sanitizer_cov_trace_pc call.
> > > > > 0000000000000160 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
> > > > > 0000000000000168 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
> > > > >
> > > > > I think we still need my patch because we still need a way to kee=
p the trace_pc call and post-filter in syzkaller doesn't solve trace_pc dro=
pping, right?
> > > >
> > > > Yes, the in-kernel filter solves the problem of trace capacity/over=
flows.
> > > >
> > > >
> > > > > But for sure I can use the bitmap from syzkaller.
> > > > >
> > > > > THX
> > > > > Joey
> > > > > -----Original Message-----
> > > > > From: Dmitry Vyukov <dvyukov@google.com>
> > > > > Sent: Thursday, November 18, 2021 10:00 PM
> > > > > To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> > > > > Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML=20
> > > > > <linux-kernel@vger.kernel.org>; Alexander Lochmann=20
> > > > > <info@alexander-lochmann.de>
> > > > > Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
> > > > >
> > > > > WARNING: This email originated from outside of Qualcomm. Please b=
e wary of any links or attachments, and do not enable macros.
> > > > >
> > > > > ,On Wed, 17 Nov 2021 at 07:24, Joey Jiao <quic_jiangenj@quicinc.c=
om> wrote:
> > > > > >
> > > > > > Sometimes we only interested in the pcs within some range,=20
> > > > > > while there are cases these pcs are dropped by kernel due to=20
> > > > > > `pos >=3D
> > > > > > t->kcov_size`, and by increasing the map area size doesn't help=
.
> > > > > >
> > > > > > To avoid disabling KCOV for these not intereseted pcs during=20
> > > > > > build time, adding this new KCOV_PC_RANGE cmd.
> > > > >
> > > > > Hi Joey,
> > > > >
> > > > > How do you use this? I am concerned that a single range of PCs is=
 too restrictive. I can only see how this can work for single module (conti=
nuous in memory) or a single function. But for anything else (something in =
the main kernel, or several modules), it won't work as PCs are not continuo=
us.
> > > > >
> > > > > Maybe we should use a compressed bitmap of interesting PCs? It al=
lows to support all cases and we already have it in syz-executor, then syz-=
executor could simply pass the bitmap to the kernel rather than post-filter=
.
> > > > > It's also overlaps with the KCOV_MODE_UNIQUE mode that +Alexander=
 proposed here:
> > > > > https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzC
> > > > > AAAJ It would be reasonable if kernel uses the same bitmap=20
> > > > > format for these
> > > > > 2 features.
> > > > >
> > > > >
> > > > >
> > > > > > An example usage is to use together syzkaller's cov filter.
> > > > > >
> > > > > > Change-Id: I954f6efe1bca604f5ce31f8f2b6f689e34a2981d
> > > > > > Signed-off-by: Joey Jiao <quic_jiangenj@quicinc.com>
> > > > > > ---
> > > > > >  Documentation/dev-tools/kcov.rst | 10 ++++++++++
> > > > > >  include/uapi/linux/kcov.h        |  7 +++++++
> > > > > >  kernel/kcov.c                    | 18 ++++++++++++++++++
> > > > > >  3 files changed, 35 insertions(+)
> > > > > >
> > > > > > diff --git a/Documentation/dev-tools/kcov.rst
> > > > > > b/Documentation/dev-tools/kcov.rst
> > > > > > index d83c9ab..fbcd422 100644
> > > > > > --- a/Documentation/dev-tools/kcov.rst
> > > > > > +++ b/Documentation/dev-tools/kcov.rst
> > > > > > @@ -52,9 +52,15 @@ program using kcov:
> > > > > >      #include <fcntl.h>
> > > > > >      #include <linux/types.h>
> > > > > >
> > > > > > +    struct kcov_pc_range {
> > > > > > +      uint32 start;
> > > > > > +      uint32 end;
> > > > > > +    };
> > > > > > +
> > > > > >      #define KCOV_INIT_TRACE                    _IOR('c', 1, un=
signed long)
> > > > > >      #define KCOV_ENABLE                        _IO('c', 100)
> > > > > >      #define KCOV_DISABLE                       _IO('c', 101)
> > > > > > +    #define KCOV_TRACE_RANGE                   _IOW('c', 103, =
struct kcov_pc_range)
> > > > > >      #define COVER_SIZE                 (64<<10)
> > > > > >
> > > > > >      #define KCOV_TRACE_PC  0 @@ -64,6 +70,8 @@ program=20
> > > > > > using kcov:
> > > > > >      {
> > > > > >         int fd;
> > > > > >         unsigned long *cover, n, i;
> > > > > > +        /* Change start and/or end to your interested pc range=
. */
> > > > > > +        struct kcov_pc_range pc_range =3D {.start =3D 0, .end =
=3D=20
> > > > > > + (uint32)(~((uint32)0))};
> > > > > >
> > > > > >         /* A single fd descriptor allows coverage collection on=
 a single
> > > > > >          * thread.
> > > > > > @@ -79,6 +87,8 @@ program using kcov:
> > > > > >                                      PROT_READ | PROT_WRITE, MA=
P_SHARED, fd, 0);
> > > > > >         if ((void*)cover =3D=3D MAP_FAILED)
> > > > > >                 perror("mmap"), exit(1);
> > > > > > +        if (ioctl(fd, KCOV_PC_RANGE, pc_range))
> > > > > > +               dprintf(2, "ignore KCOV_PC_RANGE error.\n");
> > > > > >         /* Enable coverage collection on the current thread. */
> > > > > >         if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC))
> > > > > >                 perror("ioctl"), exit(1); diff --git=20
> > > > > > a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h=20
> > > > > > index 1d0350e..353ff0a 100644
> > > > > > --- a/include/uapi/linux/kcov.h
> > > > > > +++ b/include/uapi/linux/kcov.h
> > > > > > @@ -16,12 +16,19 @@ struct kcov_remote_arg {
> > > > > >         __aligned_u64   handles[0];
> > > > > >  };
> > > > > >
> > > > > > +#define PC_RANGE_MASK ((__u32)(~((u32) 0))) struct kcov_pc_ran=
ge {
> > > > > > +       __u32           start;          /* start pc & 0xFFFFFFF=
F */
> > > > > > +       __u32           end;            /* end pc & 0xFFFFFFFF =
*/
> > > > > > +};
> > > > > > +
> > > > > >  #define KCOV_REMOTE_MAX_HANDLES                0x100
> > > > > >
> > > > > >  #define KCOV_INIT_TRACE                        _IOR('c', 1, un=
signed long)
> > > > > >  #define KCOV_ENABLE                    _IO('c', 100)
> > > > > >  #define KCOV_DISABLE                   _IO('c', 101)
> > > > > >  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, struct k=
cov_remote_arg)
> > > > > > +#define KCOV_PC_RANGE                  _IOW('c', 103, struct k=
cov_pc_range)
> > > > > >
> > > > > >  enum {
> > > > > >         /*
> > > > > > diff --git a/kernel/kcov.c b/kernel/kcov.c index=20
> > > > > > 36ca640..59550450
> > > > > > 100644
> > > > > > --- a/kernel/kcov.c
> > > > > > +++ b/kernel/kcov.c
> > > > > > @@ -36,6 +36,7 @@
> > > > > >   *  - initial state after open()
> > > > > >   *  - then there must be a single ioctl(KCOV_INIT_TRACE) call
> > > > > >   *  - then, mmap() call (several calls are allowed but not=20
> > > > > > useful)
> > > > > > + *  - then, optional to set trace pc range
> > > > > >   *  - then, ioctl(KCOV_ENABLE, arg), where arg is
> > > > > >   *     KCOV_TRACE_PC - to trace only the PCs
> > > > > >   *     or
> > > > > > @@ -69,6 +70,8 @@ struct kcov {
> > > > > >          * kcov_remote_stop(), see the comment there.
> > > > > >          */
> > > > > >         int                     sequence;
> > > > > > +       /* u32 Trace PC range from start to end. */
> > > > > > +       struct kcov_pc_range    pc_range;
> > > > > >  };
> > > > > >
> > > > > >  struct kcov_remote_area {
> > > > > > @@ -192,6 +195,7 @@ static notrace unsigned long=20
> > > > > > canonicalize_ip(unsigned long ip)  void notrace
> > > > > > __sanitizer_cov_trace_pc(void)  {
> > > > > >         struct task_struct *t;
> > > > > > +       struct kcov_pc_range pc_range;
> > > > > >         unsigned long *area;
> > > > > >         unsigned long ip =3D canonicalize_ip(_RET_IP_);
> > > > > >         unsigned long pos;
> > > > > > @@ -199,6 +203,11 @@ void notrace __sanitizer_cov_trace_pc(void=
)
> > > > > >         t =3D current;
> > > > > >         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> > > > > >                 return;
> > > > > > +       pc_range =3D t->kcov->pc_range;
> > > > > > +       if (pc_range.start < pc_range.end &&
> > > > > > +               ((ip & PC_RANGE_MASK) < pc_range.start ||
> > > > > > +               (ip & PC_RANGE_MASK) > pc_range.end))
> > > > > > +               return;
> > > > > >
> > > > > >         area =3D t->kcov_area;
> > > > > >         /* The first 64-bit word is the number of subsequent=20
> > > > > > PCs. */ @@ -568,6 +577,7 @@ static int kcov_ioctl_locked(struct=
 kcov *kcov, unsigned int cmd,
> > > > > >         int mode, i;
> > > > > >         struct kcov_remote_arg *remote_arg;
> > > > > >         struct kcov_remote *remote;
> > > > > > +       struct kcov_pc_range *pc_range;
> > > > > >         unsigned long flags;
> > > > > >
> > > > > >         switch (cmd) {
> > > > > > @@ -589,6 +599,14 @@ static int kcov_ioctl_locked(struct kcov *=
kcov, unsigned int cmd,
> > > > > >                 kcov->size =3D size;
> > > > > >                 kcov->mode =3D KCOV_MODE_INIT;
> > > > > >                 return 0;
> > > > > > +       case KCOV_PC_RANGE:
> > > > > > +               /* Limit trace pc range. */
> > > > > > +               pc_range =3D (struct kcov_pc_range *)arg;
> > > > > > +               if (copy_from_user(&kcov->pc_range, pc_range, s=
izeof(kcov->pc_range)))
> > > > > > +                       return -EINVAL;
> > > > > > +               if (kcov->pc_range.start >=3D kcov->pc_range.en=
d)
> > > > > > +                       return -EINVAL;
> > > > > > +               return 0;
> > > > > >         case KCOV_ENABLE:
> > > > > >                 /*
> > > > > >                  * Enable coverage for the current task.
> > > > > > --
> > > > > > 2.7.4

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/16605acf697e47299e3ba3bddf04441e%40quicinc.com.
