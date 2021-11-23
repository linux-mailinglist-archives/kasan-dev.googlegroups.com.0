Return-Path: <kasan-dev+bncBCMIZB7QWENRBM4V6KGAMGQE67Y3EKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CBDA459C5C
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Nov 2021 07:31:16 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id i11-20020a056602134b00b005ecba72587bsf9591274iov.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Nov 2021 22:31:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637649075; cv=pass;
        d=google.com; s=arc-20160816;
        b=oys1lNHCqiu4ObQksibBUKF/ukPjoN/a7zhsRpLb+jGTJ0uxxfiVcIwiEieIUaogSw
         Ej19PriFvQJ58EusjnaRr1qXyNlwQWTME/maAMEur3LVUln5jTIGvy2fmIhhDeW/Y03z
         sZjviy5UJTpK+8kCNguedbuOO92dqcpMd/Thwo1dUF4EzoirerqDwkr6QGtzLk4hXe13
         3qPkzI+c35PrJPw3tKTpRdrZeeJX+agIEzm8tFtD/3ihnWbI0hZCAJfRARblyda27Ppt
         IVP46MfgVnJ+HUwXuOkFqYxsJwh2IOJk67UUZXrkvSElanhyucwvJtlXFXD1KiEbCqpN
         WvuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=D/62iBF4BrFjTxt6RYIBx1KulSC3qAMQOAPlygU40GA=;
        b=A/7IneSh+dWDfkkQoPbbltz2weGxmBHaWEx8f/L4v8twQNswMO8EXh9oCp2eupvo+9
         rs4ZDQMpB1CHAKLDitV/kr4Lpn61jh8Is7vHtuvQjO6qwUcdDNvDrIqpjiT+HXxCaFP6
         hK3z6lfMmHg2Pn6VtbSh6NCq/dHYhCSYZLIofZmZf1P2lZUmelUvRI7uNOLtZXe6hjzB
         EZn5cu5RfAvWCyqs76kuA1BeFKuFWoTB0CsAXDAdEWHprpOWKPxBbjecUVrzngzoy+Bt
         EFbokTjX5l11PlUq1+DGk+SiQq6igbJn9oC5pTTP+VyT6jBnJkuEnPy3H22TZpqxcisR
         Dwjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YcKdhX7a;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=D/62iBF4BrFjTxt6RYIBx1KulSC3qAMQOAPlygU40GA=;
        b=NbCzP+eb4/L6Q511hQPLfCwH7NN0U9aE0Hs2Xlim0c442VlHQpVRK2TPaZ7CJUbHlg
         NaiE0605vB9BP2UrKo52L7nwjJXyMPMLzFxPgtJTkdtAhYrgZhvgKtAp375AvO51q5qV
         3hDBjdvvX/fmvSA3fWlho1SZhnZE4CGXa7Afl1YXWYrx43HuJ96H7l3FXSJwXP9e1FCk
         VSnZyaL7ZMz0FGIvf7zJg0bHY6rnMb8YqMc2pKGcPzIidPzrapp0I0egcujgDwd1zyb4
         AWKTauStQ7ysRQq7bICFSEOPyiPG4fhi832M0G1rfPzGhICTYZodUnHlgrQnsvEDoGQo
         lVpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=D/62iBF4BrFjTxt6RYIBx1KulSC3qAMQOAPlygU40GA=;
        b=Wd1IrEiz0EGgjdhGZ9JA1iewcpPWWViifRAjOISkulNJFqotd7g8mhY3OrWKGx9QTw
         VPv5mhIorKof7MFIvd5BJb3BR7jdRijxQAo08DC1rIRSzYdwIEkBVBovXj1AEr1M/63/
         OAlmh/fI57ytSZgE/BlLnz8ebfr3T/TuMahlPtc9XQhkFFq8l7OKkxL0YftJd/orz2jG
         XrVf4jVy+rogL+Pou5XaHrnY64nQYtxd8knW7sTELazPnQAofISPeSh+R7Ja1Y+uMCWY
         iRiJMC8zBM8VQiNGzvfb/hO4b/6lKVzx20Vh/KlAFjhLylyL8pshsMUPXH58ilkYXkwz
         wCZw==
X-Gm-Message-State: AOAM530QhFuDGQjlomUgQ9E1K3iDoJPYXkSvXLA2HZZN0bp0uATSiqbN
	qXyIudtG+d66nVoWmKJVQpM=
X-Google-Smtp-Source: ABdhPJzAbQ+tyfRthiC/jIMh1UO1cU2RhDs8aBFDOvm6OqDQSPYyzsczyWaq8nAhEE9O9/eCwhkRlA==
X-Received: by 2002:a05:6602:493:: with SMTP id y19mr3504225iov.126.1637649075120;
        Mon, 22 Nov 2021 22:31:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:160f:: with SMTP id t15ls968705ilu.1.gmail; Mon, 22
 Nov 2021 22:31:14 -0800 (PST)
X-Received: by 2002:a92:c051:: with SMTP id o17mr3592476ilf.276.1637649074762;
        Mon, 22 Nov 2021 22:31:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637649074; cv=none;
        d=google.com; s=arc-20160816;
        b=r2yAMAdl4VM+K3Hk/oBNp1lU+McbqFXrzATZk0Jz/h5Lb2IsF9NLihKBO7Z8sjk79Q
         qnjD21N+jpbbu8Vy97sui32lY8KQEz3nL3Rb/cvqBIpbHrt9Snw0lEuTNr/I0GPYVpNR
         47ZvPHxI36mlN5shBOxwbfjOs7xB+zi6axfMvWcWY4LaYRgfJy4K7fl6ervSEyyWWu2s
         VjFslJR6DbMnedqFDe6SEm1QSfsz788SVbccRvmkvhXw9CrecGrVNGlrH7XwKrOFcSEA
         ongR8DomMDEpp3UfFPrINfbrgNeGJM1iPpjua07BFCigYSUIhs0YNOsVNcKeXpOgNRNu
         bNEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1DbV6Qy4vlja/VmqAiq1sSlNc1XazBAAaKtzLNiyLDY=;
        b=bjrhEo7E3k2r54sEI0yuJiFcn7wtMFM+PoBt7qJBn+ogpmGwluzCNbFPB2PcxIKgtP
         rzwoFbzGtsaQzNJ7dnI0ImeCuMZ/Z3AhodE+7IY1K7OOSeS8joLZv6ox1rB+XKmgLNIe
         AuKSRdVOpdGrKDg7rh4SYN1X55KA7dZFhQRTqYW92WuEUIsAOguAV9cHLA3dS5aOKaAg
         7yWMry4H/om6e0jw0MGqiJW3/3/hWfoqjaqK+5LSceGh0Q39faDKzBuzBhYSs1t1uEEG
         Of4najPeybBw/8S+XXW/NV62JfASdAkxG/wzj6ZCiiCP1dqwVlhq9SmP1uCOfO8yxV/t
         l8Rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YcKdhX7a;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32e.google.com (mail-ot1-x32e.google.com. [2607:f8b0:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id w2si868432ilh.0.2021.11.22.22.31.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Nov 2021 22:31:14 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32e as permitted sender) client-ip=2607:f8b0:4864:20::32e;
Received: by mail-ot1-x32e.google.com with SMTP id 35-20020a9d08a6000000b00579cd5e605eso1704154otf.0
        for <kasan-dev@googlegroups.com>; Mon, 22 Nov 2021 22:31:14 -0800 (PST)
X-Received: by 2002:a05:6830:1356:: with SMTP id r22mr2181953otq.196.1637649074126;
 Mon, 22 Nov 2021 22:31:14 -0800 (PST)
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
In-Reply-To: <DM8PR02MB82473E366FA560E2FF214EF8F8609@DM8PR02MB8247.namprd02.prod.outlook.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Nov 2021 07:31:02 +0100
Message-ID: <CACT4Y+baE0Wn9fCbLF1O_3XVRwiBVpbmTV5KDNdTQb9RSy_FCg@mail.gmail.com>
Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
To: "JianGen Jiao (QUIC)" <quic_jiangenj@quicinc.com>
Cc: Kaipeng Zeng <kaipeng94@gmail.com>, syzkaller <syzkaller@googlegroups.com>, 
	"andreyknvl@gmail.com" <andreyknvl@gmail.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Alexander Lochmann <info@alexander-lochmann.de>, "Likai Ding (QUIC)" <quic_likaid@quicinc.com>, 
	Hangbin Liu <liuhangbin@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YcKdhX7a;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::32e
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

I am not sure... hard question. I actually see the main downside of
installing bitmap in the kernel implementation complexity and
additional code (checking range is definitely simpler).

Let me comment on Kaipeng's points:
1. Re edge coverage. There is an idea to remove it from syzkaller:
https://groups.google.com/g/syzkaller/c/8AUanXPoWiw/m/gAzSjv8yAwAJ
For clang we already have edge coverage (so with syz-executor
additional hashing of PC pairs we are actually getting double-edges);
nobody proved that edges are actually useful for kernel. Removing
edges would make module support easier and will just remove a bunch of
code and maybe make fuzzing faster. But we will need to benchmark.

2/3. It should be possible to attach different filters and in
particular we could not install a filter at all when collecting full
coverage.

An interesting benefit of a bitmap filter is that we can update with
max coverage during fuzzing, so that the kernel will log only new
uncovered PCs. Then the trace will be very small and we will never
miss new coverage due to buffer overflow.

Re BPF, it can be used only to decide if we log a PC or not. Namely:
if (execute_bpf_filter(kcov->bpf_prog, pc))
   kcov->trace[pos] =3D pc;

Or, if we install just a map:
if (bpf_map_contains(kcov->bpf_map, pc))
   kcov->trace[pos] =3D pc;

Not sure if it needs to be a positive or a negative test (!bpf_map_contains=
).


On Tue, 23 Nov 2021 at 04:18, JianGen Jiao (QUIC)
<quic_jiangenj@quicinc.com> wrote:
>
> Hi Dmitry,
> Based on these info, any further comment and next action?
>
> # Summary
> * shouldn't filter inside kernel which will loose edge info (Kaipeng).
> * filter start, end should be enough (Kaipeng).
> * put edge info into kernel? (Kaipeng) __sanitizer_cov_trace_pc_guard mig=
ht be an option? But it will loose PC info for /cover page (perhaps needs g=
cov), also not feasible to filter out pc guard value. (Joey)
> * eBPF is for read-only purpose, not suitable to overcome kcov->area over=
flow (Joey).
> * PC RANGE (start, end) can be used together with current cover filter (s=
tart, start+size) in syzkaller to fuzzing file or module interested (Joey).
> * KCOV uniq PC is for another purpose (dropping edge info) even it also o=
vercomes kcov->area overflow (Joey).
>
> THX
> Joey
>
> -----Original Message-----
> From: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> Sent: Monday, November 22, 2021 11:25 AM
> To: Kaipeng Zeng <kaipeng94@gmail.com>; Dmitry Vyukov <dvyukov@google.com=
>
> Cc: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>; syzkaller <syzkaller=
@googlegroups.com>; andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML =
<linux-kernel@vger.kernel.org>; Alexander Lochmann <info@alexander-lochmann=
.de>; Likai Ding (QUIC) <quic_likaid@quicinc.com>; Hangbin Liu <liuhangbin@=
gmail.com>
> Subject: RE: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
>
> Hi Kaipeng,
> > BTW, our coverage filter is for Linux/amd64 only. Seems the author need=
s a coverage filter on arm.
>
> Let you know that cov filer for arm[64] is available too in syzkaller bac=
k months.
>
> -----Original Message-----
> From: Kaipeng Zeng <kaipeng94@gmail.com>
> Sent: Monday, November 22, 2021 11:09 AM
> To: Dmitry Vyukov <dvyukov@google.com>
> Cc: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>; syzkaller <syzkaller=
@googlegroups.com>; andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML =
<linux-kernel@vger.kernel.org>; Alexander Lochmann <info@alexander-lochmann=
.de>; Likai Ding (QUIC) <quic_likaid@quicinc.com>; Hangbin Liu <liuhangbin@=
gmail.com>
> Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
>
> WARNING: This email originated from outside of Qualcomm. Please be wary o=
f any links or attachments, and do not enable macros.
>
> Hi Dmitry,
>
> On Fri, Nov 19, 2021 at 9:07 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Fri, 19 Nov 2021 at 13:55, Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > +Kaipeng, Hangbin who contributed the coverage filter to syzkaller.
> > > This is a discussion about adding a similar filter to the kernel.
> > > You can see whole discussion here:
> > > https://groups.google.com/g/kasan-dev/c/TQmYUdUC08Y
> >
> > Joey, what do you think in general about passing a filter bitmap to the=
 kernel?
> >
> > Since the bitmap is large, it can make sense to reuse it across
> > different KCOV instances.
> > I am thinking about something along the following lines:
> >
> > kcov_fd =3D open("/debugfs/kcov");
> > filter_fd =3D ioctl(kcov_fd, KCOV_CREATE_FILTER, &{... some args
> > specifying start/end ...}); filter =3D mmap(..., filter_fd); ... write
> > to the filter ...
> >
> > ...
> > kcov_fd2 =3D open("/debugfs/kcov");
> > ioctl(kcov_fd2, KCOV_ATTACH_FILTER, filter_fd); ioctl(kcov_fd2,
> > KCOV_ENABLE);
> >
> >
> > This would allow us to create 2 filters:
> > 1. One the interesting subsystems
> > 2. Second only for yet uncovered PCs in the interesting subsystems
> > (updated as we discover more coverage)
> >
> > During fuzzing we attach the second filter to KCOV.
> > But when we want to obtain full program coverage, we attach the first o=
ne.
> >
> > The filters (bitmaps) are reused across all threads in all executor
> > processes (so that we have only 2 filters globally per VM).
> >
>
> I think implementing such a filter in kernel would be harmful to syzkalle=
r fuzzing:
> 1. Both two bitmaps would impede syzkaller from getting backward and forw=
ard edge between interesting and uninteresting code.
> Currently, syzkaller uses edge but not coverage to decide if the prog sho=
uld be collected to the corpus. And the second bitmap actually destroys the=
 CFG in the interesting subsystem.
> It's impossible that syzkaller restores such information by analyzing the=
 filtered coverage. While syzkaller coverage filter doesn't have this probl=
em.
> 2. The First bitmap would impede syzkaller from getting full coverage of =
the whole kernel. So that it would be hard to analyze how the kernel path g=
ets into the interesting subsystem.
> It's OK if the syscall description is completed. But, we always need to d=
o such analysis if we try to improve syscall descriptions.
> 3. Coverage of prog would be imcompleted.
>
> It seems the only reason to introduce in-kernel coverage filter is to def=
ense KCOV area overflow. Do nothing in improving the fuzzing loop.
> It is reasonable that a fuzzer should collect full information as feedbac=
k, then analyze and decide how to use that information and which to drop.
> In the other hand, kernel should try its best to send more information to=
 fuzzer. Only if the memory is not enough to store such information.
> Doing such in-kernel filtering would be reasonable.
>
> An alternative choice is doing edge analyzing in kernel also, but KCOV wo=
uld be more and more restricted and limited.
>
> So, I think the pc_range is enough for defense KCOV area overflow. And ke=
ep it from the syzkaller fuzzing loop. But not implement such bitmap into k=
ernel.
> Coverage filter in syzkaller would be more flexible. A user could effecti=
vely fuzz their objective subsystems and easier to customize fuzzing loop.
>
> BTW, our coverage filter is for Linux/amd64 only. Seems the author needs =
a coverage filter on arm.
>
>
> > KCOV_CREATE_FILTER could also accept how many bytes each bit
> > represents (that scaling factor, as hardcoding 4, 8, 16 may be bad for
> > a stable kernel interface).
> >
> > But I am still not sure how to support both the main kernel and
> > modules. We could allow setting up multiple filters for different PC
> > ranges. Or may be just 2 (one for kernel and one for modules range).
> > Or maybe 1 bitmap can cover both kernel and modules?
> >
> > Thoughts?
> >
> >
> > > On Fri, 19 Nov 2021 at 12:21, JianGen Jiao (QUIC)
> > > <quic_jiangenj@quicinc.com> wrote:
> > > >
> > > > Yes, on x86_64, module address space is after kernel. But like belo=
w on arm64, it's different.
> > > >
> > > > # grep stext /proc/kallsyms
> > > > ffffffc010010000 T _stext
> > > > # cat /proc/modules |sort -k 6 | tail -2
> > > > Some_module_1 552960 0 - Live 0xffffffc00ca05000 (O)
> > > > Some_module_1 360448 0 - Live 0xffffffc00cb8f000 (O) # cat
> > > > /proc/modules |sort -k 6 | head -2
> > > > Some_module_3 16384 1 - Live 0xffffffc009430000
> > > >
> > > > -----Original Message-----
> > > > From: Dmitry Vyukov <dvyukov@google.com>
> > > > Sent: Friday, November 19, 2021 6:38 PM
> > > > To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> > > > Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML
> > > > <linux-kernel@vger.kernel.org>; Alexander Lochmann
> > > > <info@alexander-lochmann.de>; Likai Ding (QUIC)
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
> > > > > https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCAA
> > > > > AJ, The bitmap seems not the same as syzkaller one, which one
> > > > > will be used finally?
> > > >
> > > > I don't know yet. We need to decide.
> > > > In syzkaller we are more flexible and can change code faster, while=
 kernel interfaces are stable and need to be kept forever. So I think we ne=
ed to concentrate more on the good kernel interface and then support it in =
syzkaller.
> > > >
> > > > > ``` Alexander's one
> > > > > + pos =3D (ip - canonicalize_ip((unsigned long)&_stext)) / 4; idx
> > > > > + =3D pos % BITS_PER_LONG; pos /=3D BITS_PER_LONG; if (likely(pos=
 <
> > > > > + t->kcov_size)) WRITE_ONCE(area[pos], READ_ONCE(area[pos]) | 1L
> > > > > + t-><<
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
> > > > > Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML
> > > > > <linux-kernel@vger.kernel.org>; Alexander Lochmann
> > > > > <info@alexander-lochmann.de>
> > > > > Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
> > > > >
> > > > > WARNING: This email originated from outside of Qualcomm. Please b=
e wary of any links or attachments, and do not enable macros.
> > > > >
> > > > > ,On Wed, 17 Nov 2021 at 07:24, Joey Jiao <quic_jiangenj@quicinc.c=
om> wrote:
> > > > > >
> > > > > > Sometimes we only interested in the pcs within some range,
> > > > > > while there are cases these pcs are dropped by kernel due to
> > > > > > `pos >=3D
> > > > > > t->kcov_size`, and by increasing the map area size doesn't help=
.
> > > > > >
> > > > > > To avoid disabling KCOV for these not intereseted pcs during
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
> > > > > https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCAA
> > > > > AJ It would be reasonable if kernel uses the same bitmap format
> > > > > for these
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
> > > > > >      #define KCOV_TRACE_PC  0
> > > > > > @@ -64,6 +70,8 @@ program using kcov:
> > > > > >      {
> > > > > >         int fd;
> > > > > >         unsigned long *cover, n, i;
> > > > > > +        /* Change start and/or end to your interested pc range=
. */
> > > > > > +        struct kcov_pc_range pc_range =3D {.start =3D 0, .end =
=3D
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
> > > > > >                 perror("ioctl"), exit(1); diff --git
> > > > > > a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h index
> > > > > > 1d0350e..353ff0a 100644
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
> > > > > > diff --git a/kernel/kcov.c b/kernel/kcov.c index
> > > > > > 36ca640..59550450
> > > > > > 100644
> > > > > > --- a/kernel/kcov.c
> > > > > > +++ b/kernel/kcov.c
> > > > > > @@ -36,6 +36,7 @@
> > > > > >   *  - initial state after open()
> > > > > >   *  - then there must be a single ioctl(KCOV_INIT_TRACE) call
> > > > > >   *  - then, mmap() call (several calls are allowed but not
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
> > > > > > @@ -192,6 +195,7 @@ static notrace unsigned long
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
> > > > > >         /* The first 64-bit word is the number of subsequent
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
kasan-dev/CACT4Y%2BbaE0Wn9fCbLF1O_3XVRwiBVpbmTV5KDNdTQb9RSy_FCg%40mail.gmai=
l.com.
