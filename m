Return-Path: <kasan-dev+bncBDGYRP4K5MGBBYUT5SGAMGQEWSL3Z7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EE50458834
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Nov 2021 04:09:23 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id v19-20020ac85793000000b002b19184b2bfsf9787278qta.14
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Nov 2021 19:09:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637550562; cv=pass;
        d=google.com; s=arc-20160816;
        b=TzA+qV41NpPUmMBGMvzT5FjrwRpkGHE1yqk76GvFmFkkUDoQgSuZxyN6eVJdxMvmCL
         oGP82TVOQ10J4W12sLVsbwZT+dYA8UQlYQ+UdJloYB7b+M1wYyXsBvxrreIN5Nzl2WSI
         Jh4562M1HvAUfB+tDCzynd0NMNdeqqsBMkcjEpgAIGTqFv7uLAU0o6dnS1H4EMb48c5n
         Ng8c1OLoMlkD0QrxfD6tZaJhujrlEYL3cKw1bGHgVgDdj/bEJzwJHYP/yw7QHpYHTEwt
         rTCRppycsga+QCEQZ5AJQbAIvDhg2Ibz9f967P2qBs+wnR9qFtw8S7v2Gd0MwKTmckjM
         I9qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Mrps9f9jXfiB2IpLgaIimEbQReT+8GreCygxJWv18bg=;
        b=n7/KF5ldYf09DzPTODW5dNzh9nAahKU6A0fdCozHrwgRjXY+H7XH8+h+yXd9/cFvvr
         u1yuK26mkmcKYyQlj/ny1u+ekl1U2UgJpnV8G+M2VEX4jgLBF8ULHMFgdp8Th9LkfW4y
         rZ+297v+Z/z9TiByPhexvnWruV82URFVwGcPhbG8oesJLlgOa+CWAvuazICm+2H8vKbw
         kd8vUHWr2ki5302hLe2UcQsGg2g/sbO4uMTqZyOsAfzYWrdrXcIOaCioBfhz1p8HTZFm
         aGyjEH0lVAXFqu64ZEqOE89jigXB3LH68oiL2Ci/VZW/9wqvLCis7NdNhDuPjJ5HTler
         cPUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oORpft5G;
       spf=pass (google.com: domain of kaipeng94@gmail.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=kaipeng94@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Mrps9f9jXfiB2IpLgaIimEbQReT+8GreCygxJWv18bg=;
        b=CtWdOtzBB0oMByo3T2qxXvCnqZAcrDEWbi5qwhvtiTMKP3bwVFujI13cX6e8fLiqBJ
         asbs38gWOuZ2qVzW0s7EfDGP2D/6tQJSlKTmzLCX0VDcXYlYruaFGf5LsDR1KOSqDVXl
         3BvCsaKbY4R5IePtJ6UCNdt53Qx16ruXF8cT7o11O0TdrgzzfDMEXoDwSepz8/tLs0L1
         VKZ7B9kn1gyJj6MpXPt0nxUhkKZ9jaNtt7A3x8oihDSuuFkCOPnoh74sln62dT1V66N8
         xrr6rRMQSjPPMcpSaQfIXeE8lFyByHDZqmwt205M7GlUqRhHw2kVatJPqyfOhHIoRjlW
         kSrQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Mrps9f9jXfiB2IpLgaIimEbQReT+8GreCygxJWv18bg=;
        b=Ai4c42TKsPwQSPiS2xzkU7X3klRTO+8DvvD/u0luKXLi73H7vDoWpkNs29h8Jjrj5z
         5jYyxOdYDcQKJCJjDQ9+ACR3QF6i6hN4IHdEMqgEeJ3UZlHx66sadS3L7bVcbeKKbRsi
         hdXBgmcsTw5OOQSK/7IK/zOoWjxyZ6IY3Pj05I0bka3XvxbEDIhKNk2mjOEMHlXZxAIq
         P8GOwJNiWQEWGR92T2pgy8q0s7KIz/Wf+F8iLbsK5Inl6XeKmrejiZu7sLj9A77lugqp
         gSyJXQcocM9k8HBfHzIFUrSl70nBVC7SCTBZo7GNTWO68Qo/LWlswEu8Z3VeZcYCfPVw
         8rrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Mrps9f9jXfiB2IpLgaIimEbQReT+8GreCygxJWv18bg=;
        b=NUNdFkJ39P1p+bbhXy+x0QJXhs3kqGAkD6KuVuVzJ9wUXCQEveSxtP+xn68fI7HuQi
         YL8cGo0FeSD/oOBynvRUlqH98TNCDaThlCGTPvPmilcbwuFzDVEGAMH91vds64uBXZbj
         UyKURMK8IIJSPueBOI+5XatpwyhidPjGQp9YHmrOLmxvlgRrJGhYj0j6gR/DBJdbaiAO
         jbxFPdLb2JJIUmq0Wcw/T5stTfdKr+YlvsZbqQOom1Nh4BfNLuxpf+SPSf6DP+buXLrr
         VMEM/bhsw0lUPacvXQ/c+X3OuzcyFc/RH/YvWQoAxie7OaAn/Mao1zj19S5OAi9kem/1
         bYPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530mwMzJubtF052pxPMY4p/SJf8YZeaf0ViAr65mtM+4ZgYgk+Ab
	S7+BJmSr07v0vIAi7FF5GeE=
X-Google-Smtp-Source: ABdhPJz3ks03BA47njl6gbr1nZNeHO8Q24d3L9nZExWEniXsPTgLUDZ2ZavbLDukyQ7wyFYobsDgPA==
X-Received: by 2002:a05:6214:e66:: with SMTP id jz6mr88724084qvb.20.1637550562474;
        Sun, 21 Nov 2021 19:09:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f00c:: with SMTP id z12ls2084533qvk.9.gmail; Sun, 21 Nov
 2021 19:09:22 -0800 (PST)
X-Received: by 2002:a05:6214:f62:: with SMTP id iy2mr95565647qvb.25.1637550562075;
        Sun, 21 Nov 2021 19:09:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637550562; cv=none;
        d=google.com; s=arc-20160816;
        b=zD+5cDxyDDVoNRbYa2mI0Y5nbkhk0wq3Xan9GCUSZ4cOD3JZDrt9ihRjgtcMU7e1wi
         FjZUEXnEjOIJ7MXRSjsxfHt2oPSx9tJIyweFsQBeyc5OloeTjy/vCqD/5K2X9189uupr
         lMh3EMZge/+//CQMyP3PfpOr8RIJoUDpup54SZS1MBmkQDAIcNdvJUBJyk4geo/xNXgY
         Ugr/zh8HeyUG/zSTS3c1oMz78GLk8bnA0BYc6IcZJ18SPyC4E/bbTLvuoLtu8Q+/25Tv
         oI/joZpkqgmjvXbiX4bzKPtO5MI+3pvCjJ0g7L0Wu+oKijnlkbpVd5i+yg6rqA/6glHQ
         Y6pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rgmlx+cUIee7e6jUQzbA8OJEpyg/d4Sfx3iE7KKuH28=;
        b=0jFd8Uk5qJ4j/EUBMcsKnKe3VOSf/QCn1dEjNfDq2JIuz+9Zbf6HXg4xef+NXY4rd2
         +onYCw2DBMn4lnAwP3KtOQaMDkIdHQ1awVVZ14vuecybSJe2cgO0MwOp/lgVIKjXW9En
         iaiEZQUhAJdCeZ5Jgp0B8jDbxwnDqjmKrln82Nf0jsEl6sbBl8JTIC3OsZi1IbqJtHmN
         U04QHa10a3Aqbvb7mCOoQFizC2S8aS9KA25p5Z8jZOiuHqNOH3iirtmUKrD73Dd3EnO8
         1eyHD4zNXWwiM586TCBdC2oARLNzhwD2t2tP9SsALQEViKsk9/AWb55bM+9c4YoBlYGo
         eJPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oORpft5G;
       spf=pass (google.com: domain of kaipeng94@gmail.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=kaipeng94@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id w22si769793qkp.2.2021.11.21.19.09.22
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 21 Nov 2021 19:09:22 -0800 (PST)
Received-SPF: pass (google.com: domain of kaipeng94@gmail.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id n66so35049192oia.9;
        Sun, 21 Nov 2021 19:09:22 -0800 (PST)
X-Received: by 2002:aca:2b09:: with SMTP id i9mr18752686oik.14.1637550560814;
 Sun, 21 Nov 2021 19:09:20 -0800 (PST)
MIME-Version: 1.0
References: <1637130234-57238-1-git-send-email-quic_jiangenj@quicinc.com>
 <CACT4Y+YwNawV9H7uFMVSCA5WB-Dkyu9TX+rMM3FR6gNGkKFPqw@mail.gmail.com>
 <DM8PR02MB8247720860A08914CAA41D42F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
 <CACT4Y+a07DxQdYFY6uc5Y4GhTUbcnETij6gg3y+JRDvtwSmK5g@mail.gmail.com>
 <DM8PR02MB8247A19843220E03B34BA440F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
 <CACT4Y+Y36wgP_xjYVQApNLdMOFTr2-KCHc=AipcZyZiAhwf1Nw@mail.gmail.com> <CACT4Y+YF4Ngm6em_Sn2p+N0x1L+O8A=BEVTNhd00LmSZ+aH1iQ@mail.gmail.com>
In-Reply-To: <CACT4Y+YF4Ngm6em_Sn2p+N0x1L+O8A=BEVTNhd00LmSZ+aH1iQ@mail.gmail.com>
From: Kaipeng Zeng <kaipeng94@gmail.com>
Date: Mon, 22 Nov 2021 11:09:09 +0800
Message-ID: <CAHk8ZdsPDDshy2EVtdGs=rjVOEWDctcNo2H+B5=d4GRcpQunog@mail.gmail.com>
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
 header.i=@gmail.com header.s=20210112 header.b=oORpft5G;       spf=pass
 (google.com: domain of kaipeng94@gmail.com designates 2607:f8b0:4864:20::229
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

Hi Dmitry,

On Fri, Nov 19, 2021 at 9:07 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Fri, 19 Nov 2021 at 13:55, Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > +Kaipeng, Hangbin who contributed the coverage filter to syzkaller.
> > This is a discussion about adding a similar filter to the kernel. You
> > can see whole discussion here:
> > https://groups.google.com/g/kasan-dev/c/TQmYUdUC08Y
>
> Joey, what do you think in general about passing a filter bitmap to the k=
ernel?
>
> Since the bitmap is large, it can make sense to reuse it across
> different KCOV instances.
> I am thinking about something along the following lines:
>
> kcov_fd =3D open("/debugfs/kcov");
> filter_fd =3D ioctl(kcov_fd, KCOV_CREATE_FILTER, &{... some args
> specifying start/end ...});
> filter =3D mmap(..., filter_fd);
> ... write to the filter ...
>
> ...
> kcov_fd2 =3D open("/debugfs/kcov");
> ioctl(kcov_fd2, KCOV_ATTACH_FILTER, filter_fd);
> ioctl(kcov_fd2, KCOV_ENABLE);
>
>
> This would allow us to create 2 filters:
> 1. One the interesting subsystems
> 2. Second only for yet uncovered PCs in the interesting subsystems
> (updated as we discover more coverage)
>
> During fuzzing we attach the second filter to KCOV.
> But when we want to obtain full program coverage, we attach the first one=
.
>
> The filters (bitmaps) are reused across all threads in all executor
> processes (so that we have only 2 filters globally per VM).
>

I think implementing such a filter in kernel would be harmful to
syzkaller fuzzing:
1. Both two bitmaps would impede syzkaller from getting backward and
forward edge between interesting and uninteresting code.
Currently, syzkaller uses edge but not coverage to decide if the prog
should be collected to the corpus. And the second bitmap actually
destroys the CFG in the interesting subsystem.
It's impossible that syzkaller restores such information by analyzing
the filtered coverage. While syzkaller coverage filter doesn't have
this problem.
2. The First bitmap would impede syzkaller from getting full coverage
of the whole kernel. So that it would be hard to analyze how the
kernel path gets into the interesting subsystem.
It's OK if the syscall description is completed. But, we always need
to do such analysis if we try to improve syscall descriptions.
3. Coverage of prog would be imcompleted.

It seems the only reason to introduce in-kernel coverage filter is to
defense KCOV area overflow. Do nothing in improving the fuzzing loop.
It is reasonable that a fuzzer should collect full information as
feedback, then analyze and decide how to use that information and
which to drop.
In the other hand, kernel should try its best to send more information
to fuzzer. Only if the memory is not enough to store such information.
Doing such in-kernel filtering would be reasonable.

An alternative choice is doing edge analyzing in kernel also, but KCOV
would be more and more restricted and limited.

So, I think the pc_range is enough for defense KCOV area overflow. And
keep it from the syzkaller fuzzing loop. But not implement such bitmap
into kernel.
Coverage filter in syzkaller would be more flexible. A user could
effectively fuzz their objective subsystems and easier to customize
fuzzing loop.

BTW, our coverage filter is for Linux/amd64 only. Seems the author
needs a coverage filter on arm.


> KCOV_CREATE_FILTER could also accept how many bytes each bit
> represents (that scaling factor, as hardcoding 4, 8, 16 may be bad for
> a stable kernel interface).
>
> But I am still not sure how to support both the main kernel and
> modules. We could allow setting up multiple filters for different PC
> ranges. Or may be just 2 (one for kernel and one for modules range).
> Or maybe 1 bitmap can cover both kernel and modules?
>
> Thoughts?
>
>
> > On Fri, 19 Nov 2021 at 12:21, JianGen Jiao (QUIC)
> > <quic_jiangenj@quicinc.com> wrote:
> > >
> > > Yes, on x86_64, module address space is after kernel. But like below =
on arm64, it's different.
> > >
> > > # grep stext /proc/kallsyms
> > > ffffffc010010000 T _stext
> > > # cat /proc/modules |sort -k 6 | tail -2
> > > Some_module_1 552960 0 - Live 0xffffffc00ca05000 (O)
> > > Some_module_1 360448 0 - Live 0xffffffc00cb8f000 (O) # cat /proc/modu=
les |sort -k 6 | head -2
> > > Some_module_3 16384 1 - Live 0xffffffc009430000
> > >
> > > -----Original Message-----
> > > From: Dmitry Vyukov <dvyukov@google.com>
> > > Sent: Friday, November 19, 2021 6:38 PM
> > > To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> > > Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML <linux-ker=
nel@vger.kernel.org>; Alexander Lochmann <info@alexander-lochmann.de>; Lika=
i Ding (QUIC) <quic_likaid@quicinc.com>
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
> > > > https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCAAAJ,
> > > > The bitmap seems not the same as syzkaller one, which one will be u=
sed finally?
> > >
> > > I don't know yet. We need to decide.
> > > In syzkaller we are more flexible and can change code faster, while k=
ernel interfaces are stable and need to be kept forever. So I think we need=
 to concentrate more on the good kernel interface and then support it in sy=
zkaller.
> > >
> > > > ``` Alexander's one
> > > > + pos =3D (ip - canonicalize_ip((unsigned long)&_stext)) / 4; idx =
=3D pos
> > > > + % BITS_PER_LONG; pos /=3D BITS_PER_LONG; if (likely(pos <
> > > > + t->kcov_size)) WRITE_ONCE(area[pos], READ_ONCE(area[pos]) | 1L <<
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
> > > > Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML
> > > > <linux-kernel@vger.kernel.org>; Alexander Lochmann
> > > > <info@alexander-lochmann.de>
> > > > Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
> > > >
> > > > WARNING: This email originated from outside of Qualcomm. Please be =
wary of any links or attachments, and do not enable macros.
> > > >
> > > > ,On Wed, 17 Nov 2021 at 07:24, Joey Jiao <quic_jiangenj@quicinc.com=
> wrote:
> > > > >
> > > > > Sometimes we only interested in the pcs within some range, while
> > > > > there are cases these pcs are dropped by kernel due to `pos >=3D
> > > > > t->kcov_size`, and by increasing the map area size doesn't help.
> > > > >
> > > > > To avoid disabling KCOV for these not intereseted pcs during buil=
d
> > > > > time, adding this new KCOV_PC_RANGE cmd.
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
> > > > https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCAAAJ
> > > > It would be reasonable if kernel uses the same bitmap format for th=
ese
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
=3D
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
> > > > >                 perror("ioctl"), exit(1); diff --git
> > > > > a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h index
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
> > > > > diff --git a/kernel/kcov.c b/kernel/kcov.c index 36ca640..5955045=
0
> > > > > 100644
> > > > > --- a/kernel/kcov.c
> > > > > +++ b/kernel/kcov.c
> > > > > @@ -36,6 +36,7 @@
> > > > >   *  - initial state after open()
> > > > >   *  - then there must be a single ioctl(KCOV_INIT_TRACE) call
> > > > >   *  - then, mmap() call (several calls are allowed but not usefu=
l)
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
> > > > > @@ -192,6 +195,7 @@ static notrace unsigned long
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
> > > > >         /* The first 64-bit word is the number of subsequent PCs.=
 */
> > > > > @@ -568,6 +577,7 @@ static int kcov_ioctl_locked(struct kcov *kco=
v, unsigned int cmd,
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
kasan-dev/CAHk8ZdsPDDshy2EVtdGs%3DrjVOEWDctcNo2H%2BB5%3Dd4GRcpQunog%40mail.=
gmail.com.
