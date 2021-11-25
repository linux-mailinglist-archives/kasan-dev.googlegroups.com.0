Return-Path: <kasan-dev+bncBCMIZB7QWENRBC7W7SGAMGQE3CXSP2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id EC58E45D56B
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Nov 2021 08:28:12 +0100 (CET)
Received: by mail-ot1-x337.google.com with SMTP id n13-20020a9d6f0d000000b00579e30aaa02sf2441112otq.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 23:28:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637825291; cv=pass;
        d=google.com; s=arc-20160816;
        b=wnpMcwJCEHkrUGu+w9eQRVIJ3xBx2mlIqp8ZLM324KBRXe9MwORdQEYIRn6tBn0tGI
         zr5x47T3OVKO5wdPs27bhj1ZMHqIkTwj2F07biywYlAx311iEfm58xwLXZsmGEz8Pp+t
         59i8g4R8L8H4AL5Q8i+X4qT80WxA+8MFAI2Q3V5CTz+/UhyQVJIbCN3WmzdU4VFBFuSv
         BEjDSZN1GIa+I728V3lDVczRifr2D+dR1uWQj5jJacv5A7BiJeujdtItDh2ve7ECivhN
         SUKX5n5aHW2rtj9fuB/US9cbJUNfdv6gPb6GN/8mEOK5Ir6b5K9iOQms0HebZ277lf+Y
         zwWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vCbRpYMJ4zlPlZUQJslqljHHrt2FWiRfEgHYPmeVxaE=;
        b=QMrUM5+3Wx9QPeIHY6/FG4HV0Rysgm57UNm445JJctnhFuiRfVxU2JnVlEcZ3Tr+ZZ
         ThqyNTTF6pEiGVIQOoWtrK1G68/Py3geHOIvhKYEx0zPGisWd1yCUQFPVGYYUmxDOCLv
         2ze6fS6CzJb/zhNsf6KL41o3v5jOKG4rSx9/ay2euw0ZlrMwQq35Vrp9boukSg0tfcPH
         rkvsr1CAu+ylzjfuMVXv1sK5pPxDtm55vtG4ezsWgfN273wQGwLseEEzjqBApcHXEsk5
         RfpDTG0LcuDbEDUWntOHBxfjncuSbVhMNPZ0+iAAYGPZ2HFJCc8FyBXlhcTkMLl6nxT/
         ykIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ecnjrk1g;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=vCbRpYMJ4zlPlZUQJslqljHHrt2FWiRfEgHYPmeVxaE=;
        b=rZZ812Dc+WqhXP7Q6x2/PAgV2BGV00gLFlr+J1UdhlHG6ML8KSJUrKTSuxOiOVBn6u
         7D/HbNQfhqz2if5y50dSvT+KO4T8DopdmrYbQeZJRarTZUC5o49dAdlglLgPtIDMNTct
         CTlyX1vkTa8EGtTQe80qX5+5Bv1YGGcg0S5gt0bSwTFXfEhvldR4/Pf2u0QSMsJxKVZp
         2cYIwQXbS43foqC/7Tgv4n3xSZ2NwkMxV+ohI3UfuFDCmWcJTrn8kb0OJxIailKz92Hv
         G9Nbst9Sem+Dc71Rxldcc/g1W/h6JLeICBq2t6LsIZH3pGr5aMqIzAoqocf02nRRLx8D
         l6vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vCbRpYMJ4zlPlZUQJslqljHHrt2FWiRfEgHYPmeVxaE=;
        b=n+OVuxshth7SaPjEoEsHcsKOkS+Aa0EDq+/dNBZZyUw3FDSatWlUmeF9QQMUB/O3xE
         ag78tNmXXBSxHEWjP3dgKCnejlfNFvHCbAm2iU1k2hKGKl2dibqAxXo6i6nH+Kov+ENT
         7nFr7KuXZgskPQWw3K4uXCg50uzwMJaAWh5DG19VRHMprY9ckuc44KQG6c+B32vKgohp
         Mz54IzHpazbsnPwmMy4KpVNKF4zjcavVxrduRorGshmRxZ2LdCUHD5ebIHyc5IWs3wwv
         /mK0R8tox/4rlB0hhaP1P8vxsNHufh5EdXNFrgl5x78PXHq2KcN1NDWXqn0xYQ1T9UFw
         cT3A==
X-Gm-Message-State: AOAM531VvnmLZXsK2CS90bhiO839YC9ofG4qQnLm3vBkZjis14T22Je3
	uGaNTQanebBh6X3WOd6vOi8=
X-Google-Smtp-Source: ABdhPJzqMyjwB9nLzFEycWUx/P0vPjHOEt7Gc3cwtt67Bx07L8Sq2CiAVUMF4nBgT2yTN60DLVUAYw==
X-Received: by 2002:a9d:2de2:: with SMTP id g89mr19879487otb.245.1637825291612;
        Wed, 24 Nov 2021 23:28:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:19a5:: with SMTP id bj37ls1046863oib.0.gmail; Wed,
 24 Nov 2021 23:28:11 -0800 (PST)
X-Received: by 2002:a05:6808:1597:: with SMTP id t23mr13186464oiw.24.1637825291180;
        Wed, 24 Nov 2021 23:28:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637825291; cv=none;
        d=google.com; s=arc-20160816;
        b=MfUoc8vtgZl3b3Zrj2KILtFDLL0wNS2RGOgMQCzv5FAkDubqblBv2P9meJ8wvVUEJI
         TzWLGXwK3To737DfiBEcFlcf/LFpN4lCWZ4ahfcIlfZQYfHtaZrz5gl57ZtEGcdqo8Qq
         HXZdb/pvK6TSUDTJgGk9lOgW0xswMiIs0AqLP6ta/xcO2xgvbCsRenUG7coTH0990GXZ
         AW8x8Hbh/V3Ja191zl0pLmLhfh1t9yXWnzENnS76KkS3hQuuMaeIvSr2D27srHDdClQM
         kuMDNHyzJsbkoIcxdkDYwrcrzX6tj75XfK58kdBxL8UmRwkep4H+aeR6JoOhQBbg725s
         A86A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=He5ttTwEqSBYocxdQ5+pX3iF7zwahYUKtw5IVPqV5KI=;
        b=ZsIgX0CUVU8QrWXyOV62zl1nFyIoJreVo3HDYM/C+vm229FvRzUX149ZAqipcBprJz
         q/Q+YdsP6IshTTTqchAAf3uUeYzctaeM29EzchXR/ZYJ/3nS0KV7YfgV6+1hIjllmEj5
         Gs4yfW5IPNnKSrCVaCaeOjJaJISSSd7vwWHV+j23kRSinMbxILm61vf2CU4g5x8e2ISl
         CejBWGANfzxKStYh2yNjwqS0PTKwc5n4oUcB90NWgJ3ZQJGK2lRN1dAMIPnfxQgZfFuu
         Zhpng0923tDu+F7SmsCsVg+nNYNxbTJPCVXvBhEO91Uo3/2frfZEe9aNCdkZyb+ljNVZ
         p+mQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ecnjrk1g;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id u27si261037ots.2.2021.11.24.23.28.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Nov 2021 23:28:11 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id w6-20020a9d77c6000000b0055e804fa524so8221715otl.3
        for <kasan-dev@googlegroups.com>; Wed, 24 Nov 2021 23:28:11 -0800 (PST)
X-Received: by 2002:a05:6830:1356:: with SMTP id r22mr19256741otq.196.1637825290619;
 Wed, 24 Nov 2021 23:28:10 -0800 (PST)
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
 <CACT4Y+baE0Wn9fCbLF1O_3XVRwiBVpbmTV5KDNdTQb9RSy_FCg@mail.gmail.com> <CAHk8ZdvhcFQPkovXL_-t2NMyGb4H9poC7ysfo8DsjeGioqjPyQ@mail.gmail.com>
In-Reply-To: <CAHk8ZdvhcFQPkovXL_-t2NMyGb4H9poC7ysfo8DsjeGioqjPyQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Nov 2021 08:27:59 +0100
Message-ID: <CACT4Y+b1oza1+sF1V-YCO-OkuxLvNOtU=fr4Yn402+g3BypRWA@mail.gmail.com>
Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
To: Kaipeng Zeng <kaipeng94@gmail.com>
Cc: "JianGen Jiao (QUIC)" <quic_jiangenj@quicinc.com>, syzkaller <syzkaller@googlegroups.com>, 
	"andreyknvl@gmail.com" <andreyknvl@gmail.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Alexander Lochmann <info@alexander-lochmann.de>, "Likai Ding (QUIC)" <quic_likaid@quicinc.com>, 
	Hangbin Liu <liuhangbin@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ecnjrk1g;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32c
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

On Wed, 24 Nov 2021 at 09:33, Kaipeng Zeng <kaipeng94@gmail.com> wrote:
>
> On Tue, Nov 23, 2021 at 2:31 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > I am not sure... hard question. I actually see the main downside of
> > installing bitmap in the kernel implementation complexity and
> > additional code (checking range is definitely simpler).
> >
> > Let me comment on Kaipeng's points:
> > 1. Re edge coverage. There is an idea to remove it from syzkaller:
> > https://groups.google.com/g/syzkaller/c/8AUanXPoWiw/m/gAzSjv8yAwAJ
> > For clang we already have edge coverage (so with syz-executor
> > additional hashing of PC pairs we are actually getting double-edges);
> > nobody proved that edges are actually useful for kernel. Removing
> > edges would make module support easier and will just remove a bunch of
> > code and maybe make fuzzing faster. But we will need to benchmark.
> >
>
> 1. It seems that only switch to Clang edge instrument can't completely
> replace syzkaller edge calculate because it's based on
> intra-procedural analysis, the inter-procedural edge would be lost.

Yes, it's true. But we need to assess if it's really useful for kernel
fuzzing. So far it was based just on one person's intuition and the
fact that it was easy and fun to implement and did not impede other
features.

> Maybe add -fsanitize-coverage=3Dtrace-pc,indirect-calls or callgraph
> analysis can restore these information.
>
> 2. Currently syzkaller uses the length of edges to determine which
> testcases are valuable to mutate. Using Clang edge may meet a problem
> here. Clang put some fake block which is just an edge and do nothing
> actually. But syzkaller would assign the same prior to it as other
> real blocks. And it seems that these fake blocks are not conspicuous
> and can't be picked out unless we do more static analysis.

I don't think we need to pick them out. They are real basic blocks in
the end and can be treated as any other basic blocks in all regards.

> Also, all of these are based on "fuzzer can benefit from control flow
> and call graph information". Maybe support using syzkaller on such
> memory-limited devices are more necessary. I have less experience with
> this. If so, just forget what I mentioned above:).
>
> > 2/3. It should be possible to attach different filters and in
> > particular we could not install a filter at all when collecting full
> > coverage.
> >
> > An interesting benefit of a bitmap filter is that we can update with
> > max coverage during fuzzing, so that the kernel will log only new
> > uncovered PCs. Then the trace will be very small and we will never
> > miss new coverage due to buffer overflow.
> >
> > Re BPF, it can be used only to decide if we log a PC or not. Namely:
> > if (execute_bpf_filter(kcov->bpf_prog, pc))
> >    kcov->trace[pos] =3D pc;
> >
> > Or, if we install just a map:
> > if (bpf_map_contains(kcov->bpf_map, pc))
> >    kcov->trace[pos] =3D pc;
> >
> > Not sure if it needs to be a positive or a negative test (!bpf_map_cont=
ains).
> >
> >
> > On Tue, 23 Nov 2021 at 04:18, JianGen Jiao (QUIC)
> > <quic_jiangenj@quicinc.com> wrote:
> > >
> > > Hi Dmitry,
> > > Based on these info, any further comment and next action?
> > >
> > > # Summary
> > > * shouldn't filter inside kernel which will loose edge info (Kaipeng)=
.
> > > * filter start, end should be enough (Kaipeng).
> > > * put edge info into kernel? (Kaipeng) __sanitizer_cov_trace_pc_guard=
 might be an option? But it will loose PC info for /cover page (perhaps nee=
ds gcov), also not feasible to filter out pc guard value. (Joey)
> > > * eBPF is for read-only purpose, not suitable to overcome kcov->area =
overflow (Joey).
> > > * PC RANGE (start, end) can be used together with current cover filte=
r (start, start+size) in syzkaller to fuzzing file or module interested (Jo=
ey).
> > > * KCOV uniq PC is for another purpose (dropping edge info) even it al=
so overcomes kcov->area overflow (Joey).
> > >
> > > THX
> > > Joey
> > >
> > > -----Original Message-----
> > > From: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> > > Sent: Monday, November 22, 2021 11:25 AM
> > > To: Kaipeng Zeng <kaipeng94@gmail.com>; Dmitry Vyukov <dvyukov@google=
.com>
> > > Cc: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>; syzkaller <syzka=
ller@googlegroups.com>; andreyknvl@gmail.com; kasan-dev@googlegroups.com; L=
KML <linux-kernel@vger.kernel.org>; Alexander Lochmann <info@alexander-loch=
mann.de>; Likai Ding (QUIC) <quic_likaid@quicinc.com>; Hangbin Liu <liuhang=
bin@gmail.com>
> > > Subject: RE: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
> > >
> > > Hi Kaipeng,
> > > > BTW, our coverage filter is for Linux/amd64 only. Seems the author =
needs a coverage filter on arm.
> > >
> > > Let you know that cov filer for arm[64] is available too in syzkaller=
 back months.
> > >
> > > -----Original Message-----
> > > From: Kaipeng Zeng <kaipeng94@gmail.com>
> > > Sent: Monday, November 22, 2021 11:09 AM
> > > To: Dmitry Vyukov <dvyukov@google.com>
> > > Cc: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>; syzkaller <syzka=
ller@googlegroups.com>; andreyknvl@gmail.com; kasan-dev@googlegroups.com; L=
KML <linux-kernel@vger.kernel.org>; Alexander Lochmann <info@alexander-loch=
mann.de>; Likai Ding (QUIC) <quic_likaid@quicinc.com>; Hangbin Liu <liuhang=
bin@gmail.com>
> > > Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
> > >
> > > WARNING: This email originated from outside of Qualcomm. Please be wa=
ry of any links or attachments, and do not enable macros.
> > >
> > > Hi Dmitry,
> > >
> > > On Fri, Nov 19, 2021 at 9:07 PM Dmitry Vyukov <dvyukov@google.com> wr=
ote:
> > > >
> > > > On Fri, 19 Nov 2021 at 13:55, Dmitry Vyukov <dvyukov@google.com> wr=
ote:
> > > > >
> > > > > +Kaipeng, Hangbin who contributed the coverage filter to syzkalle=
r.
> > > > > This is a discussion about adding a similar filter to the kernel.
> > > > > You can see whole discussion here:
> > > > > https://groups.google.com/g/kasan-dev/c/TQmYUdUC08Y
> > > >
> > > > Joey, what do you think in general about passing a filter bitmap to=
 the kernel?
> > > >
> > > > Since the bitmap is large, it can make sense to reuse it across
> > > > different KCOV instances.
> > > > I am thinking about something along the following lines:
> > > >
> > > > kcov_fd =3D open("/debugfs/kcov");
> > > > filter_fd =3D ioctl(kcov_fd, KCOV_CREATE_FILTER, &{... some args
> > > > specifying start/end ...}); filter =3D mmap(..., filter_fd); ... wr=
ite
> > > > to the filter ...
> > > >
> > > > ...
> > > > kcov_fd2 =3D open("/debugfs/kcov");
> > > > ioctl(kcov_fd2, KCOV_ATTACH_FILTER, filter_fd); ioctl(kcov_fd2,
> > > > KCOV_ENABLE);
> > > >
> > > >
> > > > This would allow us to create 2 filters:
> > > > 1. One the interesting subsystems
> > > > 2. Second only for yet uncovered PCs in the interesting subsystems
> > > > (updated as we discover more coverage)
> > > >
> > > > During fuzzing we attach the second filter to KCOV.
> > > > But when we want to obtain full program coverage, we attach the fir=
st one.
> > > >
> > > > The filters (bitmaps) are reused across all threads in all executor
> > > > processes (so that we have only 2 filters globally per VM).
> > > >
> > >
> > > I think implementing such a filter in kernel would be harmful to syzk=
aller fuzzing:
> > > 1. Both two bitmaps would impede syzkaller from getting backward and =
forward edge between interesting and uninteresting code.
> > > Currently, syzkaller uses edge but not coverage to decide if the prog=
 should be collected to the corpus. And the second bitmap actually destroys=
 the CFG in the interesting subsystem.
> > > It's impossible that syzkaller restores such information by analyzing=
 the filtered coverage. While syzkaller coverage filter doesn't have this p=
roblem.
> > > 2. The First bitmap would impede syzkaller from getting full coverage=
 of the whole kernel. So that it would be hard to analyze how the kernel pa=
th gets into the interesting subsystem.
> > > It's OK if the syscall description is completed. But, we always need =
to do such analysis if we try to improve syscall descriptions.
> > > 3. Coverage of prog would be imcompleted.
> > >
> > > It seems the only reason to introduce in-kernel coverage filter is to=
 defense KCOV area overflow. Do nothing in improving the fuzzing loop.
> > > It is reasonable that a fuzzer should collect full information as fee=
dback, then analyze and decide how to use that information and which to dro=
p.
> > > In the other hand, kernel should try its best to send more informatio=
n to fuzzer. Only if the memory is not enough to store such information.
> > > Doing such in-kernel filtering would be reasonable.
> > >
> > > An alternative choice is doing edge analyzing in kernel also, but KCO=
V would be more and more restricted and limited.
> > >
> > > So, I think the pc_range is enough for defense KCOV area overflow. An=
d keep it from the syzkaller fuzzing loop. But not implement such bitmap in=
to kernel.
> > > Coverage filter in syzkaller would be more flexible. A user could eff=
ectively fuzz their objective subsystems and easier to customize fuzzing lo=
op.
> > >
> > > BTW, our coverage filter is for Linux/amd64 only. Seems the author ne=
eds a coverage filter on arm.
> > >
> > >
> > > > KCOV_CREATE_FILTER could also accept how many bytes each bit
> > > > represents (that scaling factor, as hardcoding 4, 8, 16 may be bad =
for
> > > > a stable kernel interface).
> > > >
> > > > But I am still not sure how to support both the main kernel and
> > > > modules. We could allow setting up multiple filters for different P=
C
> > > > ranges. Or may be just 2 (one for kernel and one for modules range)=
.
> > > > Or maybe 1 bitmap can cover both kernel and modules?
> > > >
> > > > Thoughts?
> > > >
> > > >
> > > > > On Fri, 19 Nov 2021 at 12:21, JianGen Jiao (QUIC)
> > > > > <quic_jiangenj@quicinc.com> wrote:
> > > > > >
> > > > > > Yes, on x86_64, module address space is after kernel. But like =
below on arm64, it's different.
> > > > > >
> > > > > > # grep stext /proc/kallsyms
> > > > > > ffffffc010010000 T _stext
> > > > > > # cat /proc/modules |sort -k 6 | tail -2
> > > > > > Some_module_1 552960 0 - Live 0xffffffc00ca05000 (O)
> > > > > > Some_module_1 360448 0 - Live 0xffffffc00cb8f000 (O) # cat
> > > > > > /proc/modules |sort -k 6 | head -2
> > > > > > Some_module_3 16384 1 - Live 0xffffffc009430000
> > > > > >
> > > > > > -----Original Message-----
> > > > > > From: Dmitry Vyukov <dvyukov@google.com>
> > > > > > Sent: Friday, November 19, 2021 6:38 PM
> > > > > > To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> > > > > > Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML
> > > > > > <linux-kernel@vger.kernel.org>; Alexander Lochmann
> > > > > > <info@alexander-lochmann.de>; Likai Ding (QUIC)
> > > > > > <quic_likaid@quicinc.com>
> > > > > > Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
> > > > > >
> > > > > > WARNING: This email originated from outside of Qualcomm. Please=
 be wary of any links or attachments, and do not enable macros.
> > > > > >
> > > > > > On Fri, 19 Nov 2021 at 04:17, JianGen Jiao (QUIC) <quic_jiangen=
j@quicinc.com> wrote:
> > > > > > >
> > > > > > > Hi Dmitry,
> > > > > > > I'm using the start, end pc from cover filter, which currentl=
y is the fast way compared to the big bitmap passing from syzkaller solutio=
n, as I only set the cover filter to dirs/files I care about.
> > > > > >
> > > > > > I see.
> > > > > > But if we are unlucky and our functions of interest are at the =
very low and high addresses, start/end will cover almost all kernel code...
> > > > > >
> > > > > > > I checked
> > > > > > > https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdz=
CAA
> > > > > > > AJ, The bitmap seems not the same as syzkaller one, which one
> > > > > > > will be used finally?
> > > > > >
> > > > > > I don't know yet. We need to decide.
> > > > > > In syzkaller we are more flexible and can change code faster, w=
hile kernel interfaces are stable and need to be kept forever. So I think w=
e need to concentrate more on the good kernel interface and then support it=
 in syzkaller.
> > > > > >
> > > > > > > ``` Alexander's one
> > > > > > > + pos =3D (ip - canonicalize_ip((unsigned long)&_stext)) / 4;=
 idx
> > > > > > > + =3D pos % BITS_PER_LONG; pos /=3D BITS_PER_LONG; if (likely=
(pos <
> > > > > > > + t->kcov_size)) WRITE_ONCE(area[pos], READ_ONCE(area[pos]) |=
 1L
> > > > > > > + t-><<
> > > > > > > + idx);
> > > > > > > ```
> > > > > > > Pc offset is divided by 4 and start is _stext. But for some a=
rch, pc is less than _stext.
> > > > > >
> > > > > > You mean that modules can have PC < _stext?
> > > > > >
> > > > > > > ``` https://github.com/google/syzkaller/blob/master/syz-manag=
er/covfilter.go#L139-L154
> > > > > > >         data :=3D make([]byte, 8+((size>>4)/8+1))
> > > > > > >         order :=3D binary.ByteOrder(binary.BigEndian)
> > > > > > >         if target.LittleEndian {
> > > > > > >                 order =3D binary.LittleEndian
> > > > > > >         }
> > > > > > >         order.PutUint32(data, start)
> > > > > > >         order.PutUint32(data[4:], size)
> > > > > > >
> > > > > > >         bitmap :=3D data[8:]
> > > > > > >         for pc :=3D range pcs {
> > > > > > >                 // The lowest 4-bit is dropped.
> > > > > > >                 pc =3D uint32(backend.NextInstructionPC(targe=
t, uint64(pc)))
> > > > > > >                 pc =3D (pc - start) >> 4
> > > > > > >                 bitmap[pc/8] |=3D (1 << (pc % 8))
> > > > > > >         }
> > > > > > >         return data
> > > > > > > ```
> > > > > > > Pc offset is divided by 16 and start is cover filter start pc=
.
> > > > > > >
> > > > > > > I think divided by 8 is more reasonable? Because there is at =
least one instruction before each __sanitizer_cov_trace_pc call.
> > > > > > > 0000000000000160 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
> > > > > > > 0000000000000168 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
> > > > > > >
> > > > > > > I think we still need my patch because we still need a way to=
 keep the trace_pc call and post-filter in syzkaller doesn't solve trace_pc=
 dropping, right?
> > > > > >
> > > > > > Yes, the in-kernel filter solves the problem of trace capacity/=
overflows.
> > > > > >
> > > > > >
> > > > > > > But for sure I can use the bitmap from syzkaller.
> > > > > > >
> > > > > > > THX
> > > > > > > Joey
> > > > > > > -----Original Message-----
> > > > > > > From: Dmitry Vyukov <dvyukov@google.com>
> > > > > > > Sent: Thursday, November 18, 2021 10:00 PM
> > > > > > > To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> > > > > > > Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML
> > > > > > > <linux-kernel@vger.kernel.org>; Alexander Lochmann
> > > > > > > <info@alexander-lochmann.de>
> > > > > > > Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc rang=
e
> > > > > > >
> > > > > > > WARNING: This email originated from outside of Qualcomm. Plea=
se be wary of any links or attachments, and do not enable macros.
> > > > > > >
> > > > > > > ,On Wed, 17 Nov 2021 at 07:24, Joey Jiao <quic_jiangenj@quici=
nc.com> wrote:
> > > > > > > >
> > > > > > > > Sometimes we only interested in the pcs within some range,
> > > > > > > > while there are cases these pcs are dropped by kernel due t=
o
> > > > > > > > `pos >=3D
> > > > > > > > t->kcov_size`, and by increasing the map area size doesn't =
help.
> > > > > > > >
> > > > > > > > To avoid disabling KCOV for these not intereseted pcs durin=
g
> > > > > > > > build time, adding this new KCOV_PC_RANGE cmd.
> > > > > > >
> > > > > > > Hi Joey,
> > > > > > >
> > > > > > > How do you use this? I am concerned that a single range of PC=
s is too restrictive. I can only see how this can work for single module (c=
ontinuous in memory) or a single function. But for anything else (something=
 in the main kernel, or several modules), it won't work as PCs are not cont=
inuous.
> > > > > > >
> > > > > > > Maybe we should use a compressed bitmap of interesting PCs? I=
t allows to support all cases and we already have it in syz-executor, then =
syz-executor could simply pass the bitmap to the kernel rather than post-fi=
lter.
> > > > > > > It's also overlaps with the KCOV_MODE_UNIQUE mode that +Alexa=
nder proposed here:
> > > > > > > https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdz=
CAA
> > > > > > > AJ It would be reasonable if kernel uses the same bitmap form=
at
> > > > > > > for these
> > > > > > > 2 features.
> > > > > > >
> > > > > > >
> > > > > > >
> > > > > > > > An example usage is to use together syzkaller's cov filter.
> > > > > > > >
> > > > > > > > Change-Id: I954f6efe1bca604f5ce31f8f2b6f689e34a2981d
> > > > > > > > Signed-off-by: Joey Jiao <quic_jiangenj@quicinc.com>
> > > > > > > > ---
> > > > > > > >  Documentation/dev-tools/kcov.rst | 10 ++++++++++
> > > > > > > >  include/uapi/linux/kcov.h        |  7 +++++++
> > > > > > > >  kernel/kcov.c                    | 18 ++++++++++++++++++
> > > > > > > >  3 files changed, 35 insertions(+)
> > > > > > > >
> > > > > > > > diff --git a/Documentation/dev-tools/kcov.rst
> > > > > > > > b/Documentation/dev-tools/kcov.rst
> > > > > > > > index d83c9ab..fbcd422 100644
> > > > > > > > --- a/Documentation/dev-tools/kcov.rst
> > > > > > > > +++ b/Documentation/dev-tools/kcov.rst
> > > > > > > > @@ -52,9 +52,15 @@ program using kcov:
> > > > > > > >      #include <fcntl.h>
> > > > > > > >      #include <linux/types.h>
> > > > > > > >
> > > > > > > > +    struct kcov_pc_range {
> > > > > > > > +      uint32 start;
> > > > > > > > +      uint32 end;
> > > > > > > > +    };
> > > > > > > > +
> > > > > > > >      #define KCOV_INIT_TRACE                    _IOR('c', 1=
, unsigned long)
> > > > > > > >      #define KCOV_ENABLE                        _IO('c', 10=
0)
> > > > > > > >      #define KCOV_DISABLE                       _IO('c', 10=
1)
> > > > > > > > +    #define KCOV_TRACE_RANGE                   _IOW('c', 1=
03, struct kcov_pc_range)
> > > > > > > >      #define COVER_SIZE                 (64<<10)
> > > > > > > >
> > > > > > > >      #define KCOV_TRACE_PC  0
> > > > > > > > @@ -64,6 +70,8 @@ program using kcov:
> > > > > > > >      {
> > > > > > > >         int fd;
> > > > > > > >         unsigned long *cover, n, i;
> > > > > > > > +        /* Change start and/or end to your interested pc r=
ange. */
> > > > > > > > +        struct kcov_pc_range pc_range =3D {.start =3D 0, .=
end =3D
> > > > > > > > + (uint32)(~((uint32)0))};
> > > > > > > >
> > > > > > > >         /* A single fd descriptor allows coverage collectio=
n on a single
> > > > > > > >          * thread.
> > > > > > > > @@ -79,6 +87,8 @@ program using kcov:
> > > > > > > >                                      PROT_READ | PROT_WRITE=
, MAP_SHARED, fd, 0);
> > > > > > > >         if ((void*)cover =3D=3D MAP_FAILED)
> > > > > > > >                 perror("mmap"), exit(1);
> > > > > > > > +        if (ioctl(fd, KCOV_PC_RANGE, pc_range))
> > > > > > > > +               dprintf(2, "ignore KCOV_PC_RANGE error.\n")=
;
> > > > > > > >         /* Enable coverage collection on the current thread=
. */
> > > > > > > >         if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC))
> > > > > > > >                 perror("ioctl"), exit(1); diff --git
> > > > > > > > a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h ind=
ex
> > > > > > > > 1d0350e..353ff0a 100644
> > > > > > > > --- a/include/uapi/linux/kcov.h
> > > > > > > > +++ b/include/uapi/linux/kcov.h
> > > > > > > > @@ -16,12 +16,19 @@ struct kcov_remote_arg {
> > > > > > > >         __aligned_u64   handles[0];
> > > > > > > >  };
> > > > > > > >
> > > > > > > > +#define PC_RANGE_MASK ((__u32)(~((u32) 0))) struct kcov_pc=
_range {
> > > > > > > > +       __u32           start;          /* start pc & 0xFFF=
FFFFF */
> > > > > > > > +       __u32           end;            /* end pc & 0xFFFFF=
FFF */
> > > > > > > > +};
> > > > > > > > +
> > > > > > > >  #define KCOV_REMOTE_MAX_HANDLES                0x100
> > > > > > > >
> > > > > > > >  #define KCOV_INIT_TRACE                        _IOR('c', 1=
, unsigned long)
> > > > > > > >  #define KCOV_ENABLE                    _IO('c', 100)
> > > > > > > >  #define KCOV_DISABLE                   _IO('c', 101)
> > > > > > > >  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, stru=
ct kcov_remote_arg)
> > > > > > > > +#define KCOV_PC_RANGE                  _IOW('c', 103, stru=
ct kcov_pc_range)
> > > > > > > >
> > > > > > > >  enum {
> > > > > > > >         /*
> > > > > > > > diff --git a/kernel/kcov.c b/kernel/kcov.c index
> > > > > > > > 36ca640..59550450
> > > > > > > > 100644
> > > > > > > > --- a/kernel/kcov.c
> > > > > > > > +++ b/kernel/kcov.c
> > > > > > > > @@ -36,6 +36,7 @@
> > > > > > > >   *  - initial state after open()
> > > > > > > >   *  - then there must be a single ioctl(KCOV_INIT_TRACE) c=
all
> > > > > > > >   *  - then, mmap() call (several calls are allowed but not
> > > > > > > > useful)
> > > > > > > > + *  - then, optional to set trace pc range
> > > > > > > >   *  - then, ioctl(KCOV_ENABLE, arg), where arg is
> > > > > > > >   *     KCOV_TRACE_PC - to trace only the PCs
> > > > > > > >   *     or
> > > > > > > > @@ -69,6 +70,8 @@ struct kcov {
> > > > > > > >          * kcov_remote_stop(), see the comment there.
> > > > > > > >          */
> > > > > > > >         int                     sequence;
> > > > > > > > +       /* u32 Trace PC range from start to end. */
> > > > > > > > +       struct kcov_pc_range    pc_range;
> > > > > > > >  };
> > > > > > > >
> > > > > > > >  struct kcov_remote_area {
> > > > > > > > @@ -192,6 +195,7 @@ static notrace unsigned long
> > > > > > > > canonicalize_ip(unsigned long ip)  void notrace
> > > > > > > > __sanitizer_cov_trace_pc(void)  {
> > > > > > > >         struct task_struct *t;
> > > > > > > > +       struct kcov_pc_range pc_range;
> > > > > > > >         unsigned long *area;
> > > > > > > >         unsigned long ip =3D canonicalize_ip(_RET_IP_);
> > > > > > > >         unsigned long pos;
> > > > > > > > @@ -199,6 +203,11 @@ void notrace __sanitizer_cov_trace_pc(=
void)
> > > > > > > >         t =3D current;
> > > > > > > >         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> > > > > > > >                 return;
> > > > > > > > +       pc_range =3D t->kcov->pc_range;
> > > > > > > > +       if (pc_range.start < pc_range.end &&
> > > > > > > > +               ((ip & PC_RANGE_MASK) < pc_range.start ||
> > > > > > > > +               (ip & PC_RANGE_MASK) > pc_range.end))
> > > > > > > > +               return;
> > > > > > > >
> > > > > > > >         area =3D t->kcov_area;
> > > > > > > >         /* The first 64-bit word is the number of subsequen=
t
> > > > > > > > PCs. */ @@ -568,6 +577,7 @@ static int kcov_ioctl_locked(st=
ruct kcov *kcov, unsigned int cmd,
> > > > > > > >         int mode, i;
> > > > > > > >         struct kcov_remote_arg *remote_arg;
> > > > > > > >         struct kcov_remote *remote;
> > > > > > > > +       struct kcov_pc_range *pc_range;
> > > > > > > >         unsigned long flags;
> > > > > > > >
> > > > > > > >         switch (cmd) {
> > > > > > > > @@ -589,6 +599,14 @@ static int kcov_ioctl_locked(struct kc=
ov *kcov, unsigned int cmd,
> > > > > > > >                 kcov->size =3D size;
> > > > > > > >                 kcov->mode =3D KCOV_MODE_INIT;
> > > > > > > >                 return 0;
> > > > > > > > +       case KCOV_PC_RANGE:
> > > > > > > > +               /* Limit trace pc range. */
> > > > > > > > +               pc_range =3D (struct kcov_pc_range *)arg;
> > > > > > > > +               if (copy_from_user(&kcov->pc_range, pc_rang=
e, sizeof(kcov->pc_range)))
> > > > > > > > +                       return -EINVAL;
> > > > > > > > +               if (kcov->pc_range.start >=3D kcov->pc_rang=
e.end)
> > > > > > > > +                       return -EINVAL;
> > > > > > > > +               return 0;
> > > > > > > >         case KCOV_ENABLE:
> > > > > > > >                 /*
> > > > > > > >                  * Enable coverage for the current task.
> > > > > > > > --
> > > > > > > > 2.7.4

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2Bb1oza1%2BsF1V-YCO-OkuxLvNOtU%3Dfr4Yn402%2Bg3BypRWA%40mai=
l.gmail.com.
