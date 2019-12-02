Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPVXSPXQKGQECRJESSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id C034D10E7C4
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Dec 2019 10:39:11 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id n89sf2762346pji.6
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Dec 2019 01:39:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575279550; cv=pass;
        d=google.com; s=arc-20160816;
        b=OsOYiucqriTg5VZFSyPXwf3RM6Ry9lP5Dk3zG7ZchCxUohoZ1A+5PRd8bKx6efDVvl
         nafvTSBR88lHOEfL9GywnFfhF6hNsUv1+2+HRglrg3S+YS0foOXu9vF1/IpdfeKRTXlo
         M+ZtutzdktFTpi/zSWTZOvLUCKkkIiphhJdZR/HoIRocy83HOwAr56iR8jasDEyKIUEW
         6ljSnRMAg/7me7SghjB4aU4tKabMAw44NEfM2NGT9In4Kb7bcXpRzBG4HwuEHDF9D3PP
         GCMGnhU5JaftLzpi21oPCrEBeilE+3ayLpwGFZOkeXLCn1xbHlRxHJPjo5ePHiz6vsy+
         YuWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=u3+6ftB4g9udl+FeICp3A2Kl1ERJboqk0Zybt9jCq64=;
        b=aFn8pDwWk92bv17sl3tdIYgG+sUydHmM9vAMw7sRuiRhtMOUwh0cT3SCc4Inx9oChE
         3RNLEe0FE7yIZB4eyQyEc3vvFEX8R2H1lLMUpqEBbq1FNTTdfxZUK9Vwrt2XKHZSB8CF
         68KemTvhva25r16UumLx4W4qLChr0lFAUC3wHiAYCqz8zt3TVlZj5115WbXP5b0w/IA6
         HhVHJTin6pWUFKJ+1I+mTl+D37+Qqf3LReGOIfVwRPiu0kBWMeHSgU2iZnEhb8iEeZ5Y
         zTp9QHBVosiHN0wDRK1+sEBOL3s8pVIe3VMHF/n4StfOZTsUTx5yY3YcBTWaJDll33Go
         Biow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=n0RV9WdT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=u3+6ftB4g9udl+FeICp3A2Kl1ERJboqk0Zybt9jCq64=;
        b=SfcyZysAhTPC9cZHf/3nvC5r1mq8xgsYAoMmXQW0KSqQjFoNSa4nUtIUdgvVKBPpJl
         2I9g5smZ6Ajv0ZLH/roVpYYK26SUVMoW2GkTyXHdaOek8uCnGJ1QR0AywchplRpfy0wh
         0QpQkkQNV0eyoWJp0hP1tUQj27Uc7tpaD6wxtWE7r+ULTS+f+SfRxsdIDOT0bYvtROF1
         GMOiSRUdC80xQxVLJzSHLGfymoJbsb5KTq/yToimvLU+I+16cA4TAPj2gj2Ud6ouw+iE
         kXW6/KYMU0neJHGKL34EO0r31l2hvdC8gR0lt/uXCecSWfeX2viz18ZvHC65w2QEOUJy
         gytg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=u3+6ftB4g9udl+FeICp3A2Kl1ERJboqk0Zybt9jCq64=;
        b=T/ggATm8PGf/4NhN078m8MfL7XKEVZQSBt7s3R4JHtfv2q3luGPHLX3h8kwyqIoemY
         P2rCiw6UrZeEp5x6Xi5RNZi7+uYYfBTcQZl8hnPBmDotNEl4cwNaGGPPOV+JXWaqdhZ5
         vO6DSEBwO7FLsID/mUVrVf/UdFBam33OCKF10XWJjn4toO1pFt3MHWOFO6hWYYbyGvmU
         M8o8ErZBegisp7gza6hmluHXTaLxEB1FeEXeD/6z6tPui6hpYP5+UQRLSfAtsXdBSxRA
         971esAOi40Uv9J5C0nMroBeMXaaUfkkoTJXaBXf2Ie1819oUB57sOJXSJTMNr9nYbt+/
         CV/Q==
X-Gm-Message-State: APjAAAUQAC6a4+jbsTSD1KmZXobhF9SFgK9f1dfUNqLlQos0jlpatnhk
	9JuaWYpz3/unrWENcCu6iUs=
X-Google-Smtp-Source: APXvYqzb8qI0inLsyfdRrwtlD4pt2OAxpEM4OxxoJje6NbET+caALsN5asqTAoYZgKwPXbHOaLpYmQ==
X-Received: by 2002:a17:902:a98b:: with SMTP id bh11mr26795140plb.281.1575279550286;
        Mon, 02 Dec 2019 01:39:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ac0a:: with SMTP id v10ls1692398pfe.4.gmail; Mon, 02 Dec
 2019 01:39:09 -0800 (PST)
X-Received: by 2002:a63:1b53:: with SMTP id b19mr22237460pgm.5.1575279549739;
        Mon, 02 Dec 2019 01:39:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575279549; cv=none;
        d=google.com; s=arc-20160816;
        b=CInrp58uJsMuQcMVcEocULS7Y0PDDqWfxllNCnQ4Pv1+Gc0Nm1vycsvd2dFp0Tj4o7
         a2ch4jsdNOzG9xoPVzfs0Z6AfwAH74bYNmzKQD61ed5lY8eyedReKC4/DI//LBRYdAGu
         8xtLA5xrlg7sAiHB2o7zqF40XoZbVTdfRVVzW1U/PNhO8yFTm/PetiB34pxYnMXsalqD
         mCN9TehOUChVAlLBZTMdCVKgqGIM+I5jAE0EFx8bSAo6lnm6T1kEiWLzrryX+cKbU+ND
         lV//G0x4w9rLJ+D6GdVZ3AscUy4j2Ch+OJqPE/A/vsRRpP+hK7DsnZ3GbGkkxYG0nbrV
         fXEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=mXfbyf/upZZBnp2Na+IfEomlLG1jmss1TGoDx2NxQIQ=;
        b=ENL1z7kcw1AeDQ1Vde0XGf+EgV4jOTg7zRuPfWqJxJPSZ8T8ApAMfuiq/Z8oFLhl5F
         ogXTzuGttedts/rxeTfJamuE6zfIKFusY4aJAzxNeoR56QarpxmZnQh4hlhALqQPsdno
         ioARot1QWqPVnFrheQyvA+qRSC3l4mkEHl9XMFgMz3kkCVdVlwEOnzT6bNjL0pDwGDFW
         rgArJIm/v0GsypzyH15vlhqr+e41I8Kqfs7QmQ7Gq2vnnczEB09t2CL/MbUnVmhw7wS4
         EHnC6FFlWrIdRtrU47aUl7J2o3FyNrCtWMr0zcrZGjF0y7UkcNlx/5vNSKTisoQ2U0gJ
         Q8IQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=n0RV9WdT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id j19si1461507pff.4.2019.12.02.01.39.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Dec 2019 01:39:09 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id 6so6604242oix.7
        for <kasan-dev@googlegroups.com>; Mon, 02 Dec 2019 01:39:09 -0800 (PST)
X-Received: by 2002:aca:d4c1:: with SMTP id l184mr23250358oig.172.1575279548664;
 Mon, 02 Dec 2019 01:39:08 -0800 (PST)
MIME-Version: 1.0
References: <000001d5824d$c8b2a060$5a17e120$@codeaurora.org>
 <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com>
 <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
 <20191014101938.GB41626@lakrids.cambridge.arm.com> <0101016ec501966f-4b89bcda-49ba-45d3-b226-62538b901b04-000000@us-west-2.amazonses.com>
In-Reply-To: <0101016ec501966f-4b89bcda-49ba-45d3-b226-62538b901b04-000000@us-west-2.amazonses.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 2 Dec 2019 10:38:57 +0100
Message-ID: <CANpmjNPCwB+5oTVZBXojvSGL=8ybomBKFD4HtwFvGmLyuQOVaQ@mail.gmail.com>
Subject: Re: KCSAN Support on ARM64 Kernel
To: sgrover@codeaurora.org
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	"Paul E. McKenney" <paulmck@linux.ibm.com>, Will Deacon <willdeacon@google.com>, 
	Andrea Parri <parri.andrea@gmail.com>, Alan Stern <stern@rowland.harvard.edu>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=n0RV9WdT;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

We're in the process of upstreaming KCSAN, which will simplify a lot
of things including Arm64 support. So far KCSAN is not yet in
mainline, but I assume when that happens (if things go well, very
soon) it should be trivial to add Arm64 support based on Mark's
prototype.

Thanks,
-- Marco

On Mon, 2 Dec 2019 at 06:07, <sgrover@codeaurora.org> wrote:
>
> Hi All,
>
> Is there any update in Arm64 support of KCSAN.
>
> Regards,
> Sachin Grover
>
> -----Original Message-----
> From: Mark Rutland <mark.rutland@arm.com>
> Sent: Monday, 14 October, 2019 3:50 PM
> To: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>; sgrover@codeaurora.org; kasan-dev=
 <kasan-dev@googlegroups.com>; LKML <linux-kernel@vger.kernel.org>; Paul E.=
 McKenney <paulmck@linux.ibm.com>; Will Deacon <willdeacon@google.com>; And=
rea Parri <parri.andrea@gmail.com>; Alan Stern <stern@rowland.harvard.edu>
> Subject: Re: KCSAN Support on ARM64 Kernel
>
> On Mon, Oct 14, 2019 at 11:09:40AM +0200, Marco Elver wrote:
> > On Mon, 14 Oct 2019 at 10:40, Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > On Mon, Oct 14, 2019 at 7:11 AM <sgrover@codeaurora.org> wrote:
> > > >
> > > > Hi Dmitry,
> > > >
> > > > I am from Qualcomm Linux Security Team, just going through KCSAN
> > > > and found that there was a thread for arm64 support
> > > > (https://lkml.org/lkml/2019/9/20/804).
> > > >
> > > > Can you please tell me if KCSAN is supported on ARM64 now? Can I
> > > > just rebase the KCSAN branch on top of our let=E2=80=99s say androi=
d
> > > > mainline kernel, enable the config and run syzkaller on that for
> > > > finding race conditions?
> > > >
> > > > It would be very helpful if you reply, we want to setup this for
> > > > finding issues on our proprietary modules that are not part of
> > > > kernel mainline.
> > > >
> > > > Regards,
> > > >
> > > > Sachin Grover
> > >
> > > +more people re KCSAN on ARM64
> >
> > KCSAN does not yet have ARM64 support. Once it's upstream, I would
> > expect that Mark's patches (from repo linked in LKML thread) will just
> > cleanly apply to enable ARM64 support.
>
> Once the core kcsan bits are ready, I'll rebase the arm64 patch atop.
> I'm expecting some things to change as part of review, so it'd be great t=
o see that posted ASAP.
>
> For arm64 I'm not expecting major changes (other than those necessary to =
handle the arm64 atomic rework that went in to v5.4-rc1)
>
> FWIW, I was able to run Syzkaller atop of my arm64/kcsan branch, but it's=
 very noisy as it has none of the core fixes.
>
> Thanks,
> Mark.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPCwB%2B5oTVZBXojvSGL%3D8ybomBKFD4HtwFvGmLyuQOVaQ%40mail.gm=
ail.com.
