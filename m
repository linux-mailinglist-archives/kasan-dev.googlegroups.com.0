Return-Path: <kasan-dev+bncBDGYRP4K5MGBBYXR66GAMGQEHVPCXAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id CE73F45B696
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 09:33:40 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id z4-20020a656104000000b00321790921fbsf450392pgu.4
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 00:33:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637742819; cv=pass;
        d=google.com; s=arc-20160816;
        b=zqNPGmk9yKV5fDGkrIGUiBcpR5PgIUaG8SeUUaIqQyg8L9B8KgSP6D3Q56Ve/seMGL
         d86MIxisIrY/3dNEtH2uzo2xy+T833nNbwN9I4lYcGOBpytTswQ7NwKc0324LywKK7u3
         Gx7GUAGFM9Ty9QQBwoeLFMRLWVFwOUGXHgjjl2eQe1gL1Pdvni2YejV6knemMENUGvUA
         e9bc5wwqvcZr1L2a18/XeCOs1vlnx5IBltD1pL0H7qgKs03so/tSQGYKyP+GDvbCCOMW
         5/DR5Pgtvf/7/D+ysyAxKMJAl39sdHUYuhxUOw5nw5NgvXuq+zL7XESiG8ORYt9mQCnv
         /gGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=xyZPv28Owzq+WtBjqaq1L95XboujsOsHsMIWz0LF3Hk=;
        b=JzjbQ7Ovfi4nb5FbpEGM5cbKNatg2FFZEgjDenJdEAGbbRA1VxahFtruzaSpo4aKs9
         F1CyZdJt6Co6fgtJaii6XxDK9hCxSrR5A/znL2MHteiqcNtBBfej98+B3gGhU7Czza1T
         atjsnL2Qfbt2ka4QGmQ61e/mpbIaVLDIBsd84rURmLSssj7rFs2O1tqG8oPcFLhhpkcm
         49ddIx90AtiDU5NcCiVQ//sgFCvIwFcn8xZBIZmwyg+gqGjrDmUATTqbI0x/TUfH+POV
         4sb1g+BRdaDiaAtIj6Y44idKhKGUCeAP69V+iW4JvUZDFOE+ogF3OoEPnFCk+LCMexP3
         clIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=LJBo8MkM;
       spf=pass (google.com: domain of kaipeng94@gmail.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=kaipeng94@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xyZPv28Owzq+WtBjqaq1L95XboujsOsHsMIWz0LF3Hk=;
        b=GJNyfQtcG6oAGUfTBGvB4aL6FGXXNy104VYCSGJ3TavTflSbVAj+H7wSSR/i+N5BXU
         IgKFZS5OafiexCBYl/tekEpruD/CFYAaJLzM5/aXsdklsytF9/5J3BAjwL1MjleHcmTj
         p8d5pxPPWZpEG8CFLNMEMkHnpNHrYD3XRS8vs9Z3WSU1Ig5wNMVALlzjEAoGf0DyhIHX
         rMgQo8pnXW3XLoImxSppaQ0OtuanV+zeNxCep61jq353//b1rQLVcBUHVsEOs+Um/kSI
         vpIbKoYKdDfzE2ZgjGEWhkWpkWDa4X7dh113OZNCxGFOnE1PHJmTz+PWx5Qer4CR7xQZ
         3XVQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xyZPv28Owzq+WtBjqaq1L95XboujsOsHsMIWz0LF3Hk=;
        b=Oj2L14ARSrOD3zYzHDTmOYa/Diu0v/tZLtdqF3680TR9ABf6QwzAHa+R1cfMspnqvA
         2ulI81I2+Nry8BuzILVlRVEIImjgXp6Fys2tfQiRZrsbbVuH3Tpmx5xT+3++pw8Z4K9U
         2u9cgnqvmU+RsqMtypefm3rg87+EoczljgSBN4T30d9Tm3rwvde1kdYIqk8Ww6o6hEde
         O+CHeeFaT+4nElgPz3fGVXlbyZi7nwOaPzYvdUHVXQUlFPdlaQc9MKh9i85VFHxUH35C
         nW6S0YCGPa5d6QTQAMUeNnbBzDOuJwp9nRsZsugMVwwV486k1uyrBn6/1R6MdHs9s5sk
         jqKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xyZPv28Owzq+WtBjqaq1L95XboujsOsHsMIWz0LF3Hk=;
        b=5Yi0qr2AaIzVZwJtIEx68s40YTwJJOwLAXiSfyf/pEMiIcMIULJMkml4Zx7O6bQHVY
         6klOiR9gzbNAt1QPVAV2Aij/BtwETt5knjiEhox9GF4qQEZ6tye2KHrETQ0NKpM8WfMG
         qQvcX1RZVhkX5QHWLgSxcEwPKrquXieXQ2Tj75M15Yb5Z+tIkV7vfwGNdaqHat4gmiSy
         nrQtKr5GJLRMs8B8Qd7WUTxXimult7+Dhoc1gsh/8MhFEg/yBpa2WHZ38F4B6OdAufvx
         tbawmzVWEygKI2TttOQcYXhs6KyWYKy4i3W1iEVrekDHSYoL9g6v5idKAM9w7aKX3cx4
         PZKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PG+EzvcLk1pChyuzpOL7RKKVlC4Ld1e9f6AZL1iKr+NSQIeuX
	t8oMvjXTtZEjJZMddec/Df0=
X-Google-Smtp-Source: ABdhPJwzBhlcIj37pjilrVX+/F6ta7nmrfTeUoXVBYAZ6y9jp0GClTbQ4PpQ3NFzrQhVfiBfy4ehHA==
X-Received: by 2002:a17:902:c407:b0:142:28fe:668e with SMTP id k7-20020a170902c40700b0014228fe668emr15913464plk.31.1637742818905;
        Wed, 24 Nov 2021 00:33:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1bcf:: with SMTP id oa15ls1927159pjb.0.canary-gmail;
 Wed, 24 Nov 2021 00:33:38 -0800 (PST)
X-Received: by 2002:a17:90b:3511:: with SMTP id ls17mr6166600pjb.81.1637742818317;
        Wed, 24 Nov 2021 00:33:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637742818; cv=none;
        d=google.com; s=arc-20160816;
        b=H1IFzSdlK5IxhWtoWxxj1WOTNSZWtwGya8tFILcwZOuEVt2jxsynLAasyireDi3hwE
         zjcowZ5RcwOQf2sTZI3ZSkld9S6BTRXwuksJ5VeyzYXOdyBqyYtaYC0FVIo604deIf1p
         o9Medbxf0dsIHQdk/Fr3X4RTo0FCETf6icI9CBBbs4v05YmQu9o5xndWaVeVUVFCPrSv
         hMDRRPTkgfjGwRGt7vYsQxPyn5zjg+mOMwrKmxkCqt9vvSCexQainGG+xrzC7JaTukE8
         UC0TlmO2Durbila3dIScqzFTqPIMhgv/vTDIdy+s0ncDvSXYMCs6NwBaAe1rmc6R/ZwK
         DSbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tP10DOG463xXLNI62otDmU6DPleLlPyFGqakw7Ax0FU=;
        b=fx8Kt7isyNseS0svnRxHv+dvaafzZoJe0QPrjP/3W1Dpxosa0omq1Ria/mQ5EdfFCI
         YFaiWkWGw+kGZ+ChsC9V8n2w2BZWltrqsXsH1htPzv76rbk0I6K+p4O21jJp3K0T5rhw
         XP7KwCbQ0tN/rI4w2Mg2GCcwXR+aIrRKYE/ViZOgfsO5P2I8KeaTuvHT7eQEr1lp8hic
         AZqz6mOYOszNWFaxgdj9SxzjfGRP9kUmXEQ7xfT30Rg2oDvwj7AikRR/d2cJ0Sz7MxGj
         wOn/kfEpsazy6zSBi9+4lSNEY8HhQRLNYgnEgBq9G/ylWDnui5zN8yr73IgaU/Jnhyus
         x6PA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=LJBo8MkM;
       spf=pass (google.com: domain of kaipeng94@gmail.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=kaipeng94@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oi1-x231.google.com (mail-oi1-x231.google.com. [2607:f8b0:4864:20::231])
        by gmr-mx.google.com with ESMTPS id p10si132851pfh.2.2021.11.24.00.33.38
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Nov 2021 00:33:38 -0800 (PST)
Received-SPF: pass (google.com: domain of kaipeng94@gmail.com designates 2607:f8b0:4864:20::231 as permitted sender) client-ip=2607:f8b0:4864:20::231;
Received: by mail-oi1-x231.google.com with SMTP id u74so3855048oie.8;
        Wed, 24 Nov 2021 00:33:38 -0800 (PST)
X-Received: by 2002:aca:2b09:: with SMTP id i9mr4067402oik.14.1637742817622;
 Wed, 24 Nov 2021 00:33:37 -0800 (PST)
MIME-Version: 1.0
References: <1637130234-57238-1-git-send-email-quic_jiangenj@quicinc.com>
 <CACT4Y+YwNawV9H7uFMVSCA5WB-Dkyu9TX+rMM3FR6gNGkKFPqw@mail.gmail.com>
 <DM8PR02MB8247720860A08914CAA41D42F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
 <CACT4Y+a07DxQdYFY6uc5Y4GhTUbcnETij6gg3y+JRDvtwSmK5g@mail.gmail.com>
 <DM8PR02MB8247A19843220E03B34BA440F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
 <CACT4Y+Y36wgP_xjYVQApNLdMOFTr2-KCHc=AipcZyZiAhwf1Nw@mail.gmail.com>
 <CACT4Y+YF4Ngm6em_Sn2p+N0x1L+O8A=BEVTNhd00LmSZ+aH1iQ@mail.gmail.com>
 <CAHk8ZdsPDDshy2EVtdGs=rjVOEWDctcNo2H+B5=d4GRcpQunog@mail.gmail.com>
 <062ffa8658124e089f17d73c2f523afb@quicinc.com> <DM8PR02MB82473E366FA560E2FF214EF8F8609@DM8PR02MB8247.namprd02.prod.outlook.com>
 <CACT4Y+baE0Wn9fCbLF1O_3XVRwiBVpbmTV5KDNdTQb9RSy_FCg@mail.gmail.com>
In-Reply-To: <CACT4Y+baE0Wn9fCbLF1O_3XVRwiBVpbmTV5KDNdTQb9RSy_FCg@mail.gmail.com>
From: Kaipeng Zeng <kaipeng94@gmail.com>
Date: Wed, 24 Nov 2021 16:33:25 +0800
Message-ID: <CAHk8ZdvhcFQPkovXL_-t2NMyGb4H9poC7ysfo8DsjeGioqjPyQ@mail.gmail.com>
Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
To: Dmitry Vyukov <dvyukov@google.com>
Cc: "JianGen Jiao (QUIC)" <quic_jiangenj@quicinc.com>, syzkaller <syzkaller@googlegroups.com>, 
	"andreyknvl@gmail.com" <andreyknvl@gmail.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Alexander Lochmann <info@alexander-lochmann.de>, "Likai Ding (QUIC)" <quic_likaid@quicinc.com>, 
	Hangbin Liu <liuhangbin@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Kaipeng94@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=LJBo8MkM;       spf=pass
 (google.com: domain of kaipeng94@gmail.com designates 2607:f8b0:4864:20::231
 as permitted sender) smtp.mailfrom=kaipeng94@gmail.com;       dmarc=pass
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

On Tue, Nov 23, 2021 at 2:31 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> I am not sure... hard question. I actually see the main downside of
> installing bitmap in the kernel implementation complexity and
> additional code (checking range is definitely simpler).
>
> Let me comment on Kaipeng's points:
> 1. Re edge coverage. There is an idea to remove it from syzkaller:
> https://groups.google.com/g/syzkaller/c/8AUanXPoWiw/m/gAzSjv8yAwAJ
> For clang we already have edge coverage (so with syz-executor
> additional hashing of PC pairs we are actually getting double-edges);
> nobody proved that edges are actually useful for kernel. Removing
> edges would make module support easier and will just remove a bunch of
> code and maybe make fuzzing faster. But we will need to benchmark.
>

1. It seems that only switch to Clang edge instrument can't completely
replace syzkaller edge calculate because it's based on
intra-procedural analysis, the inter-procedural edge would be lost.
Maybe add -fsanitize-coverage=3Dtrace-pc,indirect-calls or callgraph
analysis can restore these information.

2. Currently syzkaller uses the length of edges to determine which
testcases are valuable to mutate. Using Clang edge may meet a problem
here. Clang put some fake block which is just an edge and do nothing
actually. But syzkaller would assign the same prior to it as other
real blocks. And it seems that these fake blocks are not conspicuous
and can't be picked out unless we do more static analysis.

Also, all of these are based on "fuzzer can benefit from control flow
and call graph information". Maybe support using syzkaller on such
memory-limited devices are more necessary. I have less experience with
this. If so, just forget what I mentioned above:).

> 2/3. It should be possible to attach different filters and in
> particular we could not install a filter at all when collecting full
> coverage.
>
> An interesting benefit of a bitmap filter is that we can update with
> max coverage during fuzzing, so that the kernel will log only new
> uncovered PCs. Then the trace will be very small and we will never
> miss new coverage due to buffer overflow.
>
> Re BPF, it can be used only to decide if we log a PC or not. Namely:
> if (execute_bpf_filter(kcov->bpf_prog, pc))
>    kcov->trace[pos] =3D pc;
>
> Or, if we install just a map:
> if (bpf_map_contains(kcov->bpf_map, pc))
>    kcov->trace[pos] =3D pc;
>
> Not sure if it needs to be a positive or a negative test (!bpf_map_contai=
ns).
>
>
> On Tue, 23 Nov 2021 at 04:18, JianGen Jiao (QUIC)
> <quic_jiangenj@quicinc.com> wrote:
> >
> > Hi Dmitry,
> > Based on these info, any further comment and next action?
> >
> > # Summary
> > * shouldn't filter inside kernel which will loose edge info (Kaipeng).
> > * filter start, end should be enough (Kaipeng).
> > * put edge info into kernel? (Kaipeng) __sanitizer_cov_trace_pc_guard m=
ight be an option? But it will loose PC info for /cover page (perhaps needs=
 gcov), also not feasible to filter out pc guard value. (Joey)
> > * eBPF is for read-only purpose, not suitable to overcome kcov->area ov=
erflow (Joey).
> > * PC RANGE (start, end) can be used together with current cover filter =
(start, start+size) in syzkaller to fuzzing file or module interested (Joey=
).
> > * KCOV uniq PC is for another purpose (dropping edge info) even it also=
 overcomes kcov->area overflow (Joey).
> >
> > THX
> > Joey
> >
> > -----Original Message-----
> > From: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> > Sent: Monday, November 22, 2021 11:25 AM
> > To: Kaipeng Zeng <kaipeng94@gmail.com>; Dmitry Vyukov <dvyukov@google.c=
om>
> > Cc: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>; syzkaller <syzkall=
er@googlegroups.com>; andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKM=
L <linux-kernel@vger.kernel.org>; Alexander Lochmann <info@alexander-lochma=
nn.de>; Likai Ding (QUIC) <quic_likaid@quicinc.com>; Hangbin Liu <liuhangbi=
n@gmail.com>
> > Subject: RE: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
> >
> > Hi Kaipeng,
> > > BTW, our coverage filter is for Linux/amd64 only. Seems the author ne=
eds a coverage filter on arm.
> >
> > Let you know that cov filer for arm[64] is available too in syzkaller b=
ack months.
> >
> > -----Original Message-----
> > From: Kaipeng Zeng <kaipeng94@gmail.com>
> > Sent: Monday, November 22, 2021 11:09 AM
> > To: Dmitry Vyukov <dvyukov@google.com>
> > Cc: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>; syzkaller <syzkall=
er@googlegroups.com>; andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKM=
L <linux-kernel@vger.kernel.org>; Alexander Lochmann <info@alexander-lochma=
nn.de>; Likai Ding (QUIC) <quic_likaid@quicinc.com>; Hangbin Liu <liuhangbi=
n@gmail.com>
> > Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
> >
> > WARNING: This email originated from outside of Qualcomm. Please be wary=
 of any links or attachments, and do not enable macros.
> >
> > Hi Dmitry,
> >
> > On Fri, Nov 19, 2021 at 9:07 PM Dmitry Vyukov <dvyukov@google.com> wrot=
e:
> > >
> > > On Fri, 19 Nov 2021 at 13:55, Dmitry Vyukov <dvyukov@google.com> wrot=
e:
> > > >
> > > > +Kaipeng, Hangbin who contributed the coverage filter to syzkaller.
> > > > This is a discussion about adding a similar filter to the kernel.
> > > > You can see whole discussion here:
> > > > https://groups.google.com/g/kasan-dev/c/TQmYUdUC08Y
> > >
> > > Joey, what do you think in general about passing a filter bitmap to t=
he kernel?
> > >
> > > Since the bitmap is large, it can make sense to reuse it across
> > > different KCOV instances.
> > > I am thinking about something along the following lines:
> > >
> > > kcov_fd =3D open("/debugfs/kcov");
> > > filter_fd =3D ioctl(kcov_fd, KCOV_CREATE_FILTER, &{... some args
> > > specifying start/end ...}); filter =3D mmap(..., filter_fd); ... writ=
e
> > > to the filter ...
> > >
> > > ...
> > > kcov_fd2 =3D open("/debugfs/kcov");
> > > ioctl(kcov_fd2, KCOV_ATTACH_FILTER, filter_fd); ioctl(kcov_fd2,
> > > KCOV_ENABLE);
> > >
> > >
> > > This would allow us to create 2 filters:
> > > 1. One the interesting subsystems
> > > 2. Second only for yet uncovered PCs in the interesting subsystems
> > > (updated as we discover more coverage)
> > >
> > > During fuzzing we attach the second filter to KCOV.
> > > But when we want to obtain full program coverage, we attach the first=
 one.
> > >
> > > The filters (bitmaps) are reused across all threads in all executor
> > > processes (so that we have only 2 filters globally per VM).
> > >
> >
> > I think implementing such a filter in kernel would be harmful to syzkal=
ler fuzzing:
> > 1. Both two bitmaps would impede syzkaller from getting backward and fo=
rward edge between interesting and uninteresting code.
> > Currently, syzkaller uses edge but not coverage to decide if the prog s=
hould be collected to the corpus. And the second bitmap actually destroys t=
he CFG in the interesting subsystem.
> > It's impossible that syzkaller restores such information by analyzing t=
he filtered coverage. While syzkaller coverage filter doesn't have this pro=
blem.
> > 2. The First bitmap would impede syzkaller from getting full coverage o=
f the whole kernel. So that it would be hard to analyze how the kernel path=
 gets into the interesting subsystem.
> > It's OK if the syscall description is completed. But, we always need to=
 do such analysis if we try to improve syscall descriptions.
> > 3. Coverage of prog would be imcompleted.
> >
> > It seems the only reason to introduce in-kernel coverage filter is to d=
efense KCOV area overflow. Do nothing in improving the fuzzing loop.
> > It is reasonable that a fuzzer should collect full information as feedb=
ack, then analyze and decide how to use that information and which to drop.
> > In the other hand, kernel should try its best to send more information =
to fuzzer. Only if the memory is not enough to store such information.
> > Doing such in-kernel filtering would be reasonable.
> >
> > An alternative choice is doing edge analyzing in kernel also, but KCOV =
would be more and more restricted and limited.
> >
> > So, I think the pc_range is enough for defense KCOV area overflow. And =
keep it from the syzkaller fuzzing loop. But not implement such bitmap into=
 kernel.
> > Coverage filter in syzkaller would be more flexible. A user could effec=
tively fuzz their objective subsystems and easier to customize fuzzing loop=
.
> >
> > BTW, our coverage filter is for Linux/amd64 only. Seems the author need=
s a coverage filter on arm.
> >
> >
> > > KCOV_CREATE_FILTER could also accept how many bytes each bit
> > > represents (that scaling factor, as hardcoding 4, 8, 16 may be bad fo=
r
> > > a stable kernel interface).
> > >
> > > But I am still not sure how to support both the main kernel and
> > > modules. We could allow setting up multiple filters for different PC
> > > ranges. Or may be just 2 (one for kernel and one for modules range).
> > > Or maybe 1 bitmap can cover both kernel and modules?
> > >
> > > Thoughts?
> > >
> > >
> > > > On Fri, 19 Nov 2021 at 12:21, JianGen Jiao (QUIC)
> > > > <quic_jiangenj@quicinc.com> wrote:
> > > > >
> > > > > Yes, on x86_64, module address space is after kernel. But like be=
low on arm64, it's different.
> > > > >
> > > > > # grep stext /proc/kallsyms
> > > > > ffffffc010010000 T _stext
> > > > > # cat /proc/modules |sort -k 6 | tail -2
> > > > > Some_module_1 552960 0 - Live 0xffffffc00ca05000 (O)
> > > > > Some_module_1 360448 0 - Live 0xffffffc00cb8f000 (O) # cat
> > > > > /proc/modules |sort -k 6 | head -2
> > > > > Some_module_3 16384 1 - Live 0xffffffc009430000
> > > > >
> > > > > -----Original Message-----
> > > > > From: Dmitry Vyukov <dvyukov@google.com>
> > > > > Sent: Friday, November 19, 2021 6:38 PM
> > > > > To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> > > > > Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML
> > > > > <linux-kernel@vger.kernel.org>; Alexander Lochmann
> > > > > <info@alexander-lochmann.de>; Likai Ding (QUIC)
> > > > > <quic_likaid@quicinc.com>
> > > > > Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
> > > > >
> > > > > WARNING: This email originated from outside of Qualcomm. Please b=
e wary of any links or attachments, and do not enable macros.
> > > > >
> > > > > On Fri, 19 Nov 2021 at 04:17, JianGen Jiao (QUIC) <quic_jiangenj@=
quicinc.com> wrote:
> > > > > >
> > > > > > Hi Dmitry,
> > > > > > I'm using the start, end pc from cover filter, which currently =
is the fast way compared to the big bitmap passing from syzkaller solution,=
 as I only set the cover filter to dirs/files I care about.
> > > > >
> > > > > I see.
> > > > > But if we are unlucky and our functions of interest are at the ve=
ry low and high addresses, start/end will cover almost all kernel code...
> > > > >
> > > > > > I checked
> > > > > > https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCA=
A
> > > > > > AJ, The bitmap seems not the same as syzkaller one, which one
> > > > > > will be used finally?
> > > > >
> > > > > I don't know yet. We need to decide.
> > > > > In syzkaller we are more flexible and can change code faster, whi=
le kernel interfaces are stable and need to be kept forever. So I think we =
need to concentrate more on the good kernel interface and then support it i=
n syzkaller.
> > > > >
> > > > > > ``` Alexander's one
> > > > > > + pos =3D (ip - canonicalize_ip((unsigned long)&_stext)) / 4; i=
dx
> > > > > > + =3D pos % BITS_PER_LONG; pos /=3D BITS_PER_LONG; if (likely(p=
os <
> > > > > > + t->kcov_size)) WRITE_ONCE(area[pos], READ_ONCE(area[pos]) | 1=
L
> > > > > > + t-><<
> > > > > > + idx);
> > > > > > ```
> > > > > > Pc offset is divided by 4 and start is _stext. But for some arc=
h, pc is less than _stext.
> > > > >
> > > > > You mean that modules can have PC < _stext?
> > > > >
> > > > > > ``` https://github.com/google/syzkaller/blob/master/syz-manager=
/covfilter.go#L139-L154
> > > > > >         data :=3D make([]byte, 8+((size>>4)/8+1))
> > > > > >         order :=3D binary.ByteOrder(binary.BigEndian)
> > > > > >         if target.LittleEndian {
> > > > > >                 order =3D binary.LittleEndian
> > > > > >         }
> > > > > >         order.PutUint32(data, start)
> > > > > >         order.PutUint32(data[4:], size)
> > > > > >
> > > > > >         bitmap :=3D data[8:]
> > > > > >         for pc :=3D range pcs {
> > > > > >                 // The lowest 4-bit is dropped.
> > > > > >                 pc =3D uint32(backend.NextInstructionPC(target,=
 uint64(pc)))
> > > > > >                 pc =3D (pc - start) >> 4
> > > > > >                 bitmap[pc/8] |=3D (1 << (pc % 8))
> > > > > >         }
> > > > > >         return data
> > > > > > ```
> > > > > > Pc offset is divided by 16 and start is cover filter start pc.
> > > > > >
> > > > > > I think divided by 8 is more reasonable? Because there is at le=
ast one instruction before each __sanitizer_cov_trace_pc call.
> > > > > > 0000000000000160 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
> > > > > > 0000000000000168 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
> > > > > >
> > > > > > I think we still need my patch because we still need a way to k=
eep the trace_pc call and post-filter in syzkaller doesn't solve trace_pc d=
ropping, right?
> > > > >
> > > > > Yes, the in-kernel filter solves the problem of trace capacity/ov=
erflows.
> > > > >
> > > > >
> > > > > > But for sure I can use the bitmap from syzkaller.
> > > > > >
> > > > > > THX
> > > > > > Joey
> > > > > > -----Original Message-----
> > > > > > From: Dmitry Vyukov <dvyukov@google.com>
> > > > > > Sent: Thursday, November 18, 2021 10:00 PM
> > > > > > To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> > > > > > Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML
> > > > > > <linux-kernel@vger.kernel.org>; Alexander Lochmann
> > > > > > <info@alexander-lochmann.de>
> > > > > > Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
> > > > > >
> > > > > > WARNING: This email originated from outside of Qualcomm. Please=
 be wary of any links or attachments, and do not enable macros.
> > > > > >
> > > > > > ,On Wed, 17 Nov 2021 at 07:24, Joey Jiao <quic_jiangenj@quicinc=
.com> wrote:
> > > > > > >
> > > > > > > Sometimes we only interested in the pcs within some range,
> > > > > > > while there are cases these pcs are dropped by kernel due to
> > > > > > > `pos >=3D
> > > > > > > t->kcov_size`, and by increasing the map area size doesn't he=
lp.
> > > > > > >
> > > > > > > To avoid disabling KCOV for these not intereseted pcs during
> > > > > > > build time, adding this new KCOV_PC_RANGE cmd.
> > > > > >
> > > > > > Hi Joey,
> > > > > >
> > > > > > How do you use this? I am concerned that a single range of PCs =
is too restrictive. I can only see how this can work for single module (con=
tinuous in memory) or a single function. But for anything else (something i=
n the main kernel, or several modules), it won't work as PCs are not contin=
uous.
> > > > > >
> > > > > > Maybe we should use a compressed bitmap of interesting PCs? It =
allows to support all cases and we already have it in syz-executor, then sy=
z-executor could simply pass the bitmap to the kernel rather than post-filt=
er.
> > > > > > It's also overlaps with the KCOV_MODE_UNIQUE mode that +Alexand=
er proposed here:
> > > > > > https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCA=
A
> > > > > > AJ It would be reasonable if kernel uses the same bitmap format
> > > > > > for these
> > > > > > 2 features.
> > > > > >
> > > > > >
> > > > > >
> > > > > > > An example usage is to use together syzkaller's cov filter.
> > > > > > >
> > > > > > > Change-Id: I954f6efe1bca604f5ce31f8f2b6f689e34a2981d
> > > > > > > Signed-off-by: Joey Jiao <quic_jiangenj@quicinc.com>
> > > > > > > ---
> > > > > > >  Documentation/dev-tools/kcov.rst | 10 ++++++++++
> > > > > > >  include/uapi/linux/kcov.h        |  7 +++++++
> > > > > > >  kernel/kcov.c                    | 18 ++++++++++++++++++
> > > > > > >  3 files changed, 35 insertions(+)
> > > > > > >
> > > > > > > diff --git a/Documentation/dev-tools/kcov.rst
> > > > > > > b/Documentation/dev-tools/kcov.rst
> > > > > > > index d83c9ab..fbcd422 100644
> > > > > > > --- a/Documentation/dev-tools/kcov.rst
> > > > > > > +++ b/Documentation/dev-tools/kcov.rst
> > > > > > > @@ -52,9 +52,15 @@ program using kcov:
> > > > > > >      #include <fcntl.h>
> > > > > > >      #include <linux/types.h>
> > > > > > >
> > > > > > > +    struct kcov_pc_range {
> > > > > > > +      uint32 start;
> > > > > > > +      uint32 end;
> > > > > > > +    };
> > > > > > > +
> > > > > > >      #define KCOV_INIT_TRACE                    _IOR('c', 1, =
unsigned long)
> > > > > > >      #define KCOV_ENABLE                        _IO('c', 100)
> > > > > > >      #define KCOV_DISABLE                       _IO('c', 101)
> > > > > > > +    #define KCOV_TRACE_RANGE                   _IOW('c', 103=
, struct kcov_pc_range)
> > > > > > >      #define COVER_SIZE                 (64<<10)
> > > > > > >
> > > > > > >      #define KCOV_TRACE_PC  0
> > > > > > > @@ -64,6 +70,8 @@ program using kcov:
> > > > > > >      {
> > > > > > >         int fd;
> > > > > > >         unsigned long *cover, n, i;
> > > > > > > +        /* Change start and/or end to your interested pc ran=
ge. */
> > > > > > > +        struct kcov_pc_range pc_range =3D {.start =3D 0, .en=
d =3D
> > > > > > > + (uint32)(~((uint32)0))};
> > > > > > >
> > > > > > >         /* A single fd descriptor allows coverage collection =
on a single
> > > > > > >          * thread.
> > > > > > > @@ -79,6 +87,8 @@ program using kcov:
> > > > > > >                                      PROT_READ | PROT_WRITE, =
MAP_SHARED, fd, 0);
> > > > > > >         if ((void*)cover =3D=3D MAP_FAILED)
> > > > > > >                 perror("mmap"), exit(1);
> > > > > > > +        if (ioctl(fd, KCOV_PC_RANGE, pc_range))
> > > > > > > +               dprintf(2, "ignore KCOV_PC_RANGE error.\n");
> > > > > > >         /* Enable coverage collection on the current thread. =
*/
> > > > > > >         if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC))
> > > > > > >                 perror("ioctl"), exit(1); diff --git
> > > > > > > a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h index
> > > > > > > 1d0350e..353ff0a 100644
> > > > > > > --- a/include/uapi/linux/kcov.h
> > > > > > > +++ b/include/uapi/linux/kcov.h
> > > > > > > @@ -16,12 +16,19 @@ struct kcov_remote_arg {
> > > > > > >         __aligned_u64   handles[0];
> > > > > > >  };
> > > > > > >
> > > > > > > +#define PC_RANGE_MASK ((__u32)(~((u32) 0))) struct kcov_pc_r=
ange {
> > > > > > > +       __u32           start;          /* start pc & 0xFFFFF=
FFF */
> > > > > > > +       __u32           end;            /* end pc & 0xFFFFFFF=
F */
> > > > > > > +};
> > > > > > > +
> > > > > > >  #define KCOV_REMOTE_MAX_HANDLES                0x100
> > > > > > >
> > > > > > >  #define KCOV_INIT_TRACE                        _IOR('c', 1, =
unsigned long)
> > > > > > >  #define KCOV_ENABLE                    _IO('c', 100)
> > > > > > >  #define KCOV_DISABLE                   _IO('c', 101)
> > > > > > >  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, struct=
 kcov_remote_arg)
> > > > > > > +#define KCOV_PC_RANGE                  _IOW('c', 103, struct=
 kcov_pc_range)
> > > > > > >
> > > > > > >  enum {
> > > > > > >         /*
> > > > > > > diff --git a/kernel/kcov.c b/kernel/kcov.c index
> > > > > > > 36ca640..59550450
> > > > > > > 100644
> > > > > > > --- a/kernel/kcov.c
> > > > > > > +++ b/kernel/kcov.c
> > > > > > > @@ -36,6 +36,7 @@
> > > > > > >   *  - initial state after open()
> > > > > > >   *  - then there must be a single ioctl(KCOV_INIT_TRACE) cal=
l
> > > > > > >   *  - then, mmap() call (several calls are allowed but not
> > > > > > > useful)
> > > > > > > + *  - then, optional to set trace pc range
> > > > > > >   *  - then, ioctl(KCOV_ENABLE, arg), where arg is
> > > > > > >   *     KCOV_TRACE_PC - to trace only the PCs
> > > > > > >   *     or
> > > > > > > @@ -69,6 +70,8 @@ struct kcov {
> > > > > > >          * kcov_remote_stop(), see the comment there.
> > > > > > >          */
> > > > > > >         int                     sequence;
> > > > > > > +       /* u32 Trace PC range from start to end. */
> > > > > > > +       struct kcov_pc_range    pc_range;
> > > > > > >  };
> > > > > > >
> > > > > > >  struct kcov_remote_area {
> > > > > > > @@ -192,6 +195,7 @@ static notrace unsigned long
> > > > > > > canonicalize_ip(unsigned long ip)  void notrace
> > > > > > > __sanitizer_cov_trace_pc(void)  {
> > > > > > >         struct task_struct *t;
> > > > > > > +       struct kcov_pc_range pc_range;
> > > > > > >         unsigned long *area;
> > > > > > >         unsigned long ip =3D canonicalize_ip(_RET_IP_);
> > > > > > >         unsigned long pos;
> > > > > > > @@ -199,6 +203,11 @@ void notrace __sanitizer_cov_trace_pc(vo=
id)
> > > > > > >         t =3D current;
> > > > > > >         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> > > > > > >                 return;
> > > > > > > +       pc_range =3D t->kcov->pc_range;
> > > > > > > +       if (pc_range.start < pc_range.end &&
> > > > > > > +               ((ip & PC_RANGE_MASK) < pc_range.start ||
> > > > > > > +               (ip & PC_RANGE_MASK) > pc_range.end))
> > > > > > > +               return;
> > > > > > >
> > > > > > >         area =3D t->kcov_area;
> > > > > > >         /* The first 64-bit word is the number of subsequent
> > > > > > > PCs. */ @@ -568,6 +577,7 @@ static int kcov_ioctl_locked(stru=
ct kcov *kcov, unsigned int cmd,
> > > > > > >         int mode, i;
> > > > > > >         struct kcov_remote_arg *remote_arg;
> > > > > > >         struct kcov_remote *remote;
> > > > > > > +       struct kcov_pc_range *pc_range;
> > > > > > >         unsigned long flags;
> > > > > > >
> > > > > > >         switch (cmd) {
> > > > > > > @@ -589,6 +599,14 @@ static int kcov_ioctl_locked(struct kcov=
 *kcov, unsigned int cmd,
> > > > > > >                 kcov->size =3D size;
> > > > > > >                 kcov->mode =3D KCOV_MODE_INIT;
> > > > > > >                 return 0;
> > > > > > > +       case KCOV_PC_RANGE:
> > > > > > > +               /* Limit trace pc range. */
> > > > > > > +               pc_range =3D (struct kcov_pc_range *)arg;
> > > > > > > +               if (copy_from_user(&kcov->pc_range, pc_range,=
 sizeof(kcov->pc_range)))
> > > > > > > +                       return -EINVAL;
> > > > > > > +               if (kcov->pc_range.start >=3D kcov->pc_range.=
end)
> > > > > > > +                       return -EINVAL;
> > > > > > > +               return 0;
> > > > > > >         case KCOV_ENABLE:
> > > > > > >                 /*
> > > > > > >                  * Enable coverage for the current task.
> > > > > > > --
> > > > > > > 2.7.4

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHk8ZdvhcFQPkovXL_-t2NMyGb4H9poC7ysfo8DsjeGioqjPyQ%40mail.gmail.=
com.
