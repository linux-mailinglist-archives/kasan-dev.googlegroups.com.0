Return-Path: <kasan-dev+bncBDW2JDUY5AORBJHA32GAMGQEQYZ5S2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id B6214457057
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 15:09:41 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id u11-20020a17090a4bcb00b001a6e77f7312sf4767103pjl.5
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 06:09:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637330980; cv=pass;
        d=google.com; s=arc-20160816;
        b=vipz+4BVR2JYWVFuxtAXXUXH5xx5tV0cRUg1+/bQgaxlAsN1z0yFFepsDQ474/Ac/y
         VUFbQP2WSaFKNScE+ik2ooIJvNX4ry/UukVhPhVFm+fQipDyEGexzsoU+IKKArA4urH7
         LR1ckKsyqZpWqe5RDw8gzBcdZt+pDLxjCbNHHBYtuM8N3z7+mezL4nmbZvpkJ+0NCwIO
         QsLeqnRNx/W851CwbblyNwbwllall49CBpYZmTZ2c9u8Y8vK1Wsql4EAEQDfCJyafIyj
         vZkmKI/rLXoxq45uHervoOEVpNI424OIuJH5xQR/dOgpfE98fplwqiOvGZWzvfD/N9I2
         zXOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=HFTfx7UMgtwMaWfsWTTw/fg+WxB6BtHz56IBvW7z0JI=;
        b=0B+wUmnoDJ5S2tExV8ORXS6YZNKI8xghKD81qUTMMRbGii8Q8xkrS5MDOSffpAlQl2
         RZkmcshPOprzKMFCvc37vjZU1oaS7p1VBuqpp3XVzS3zmK2gvrIvu2ZecbEwtNRGh+rz
         RJ7rA/YqGFA+j8QdMndZwXHNyXdZQhRJzLVc/zba0UtbaKo91gpChdn5HvUv5WIgSZA0
         UOdr8ia4lVfQj3sxgTUqVuQzTM/eROcN6XH5q3qmjtsL5xeZ7lskP01K8bglAFD5s7T8
         BNG132YNqad3yHCtWo+RMY8W/grBJFlfiY2CtF/DyLHRPju5cu1J5hCsAbyBNobn0aqq
         k0dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=is7eXdz4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HFTfx7UMgtwMaWfsWTTw/fg+WxB6BtHz56IBvW7z0JI=;
        b=gi03d1QpeNI4vq3KBBr7PUBEmtMOxq72KfLUm4EZFCwdQSCkWESBB/atQbxt5/oxnN
         jqQSaGFVVYSnKcq+e1bouRiRheYG5fSpJGkJI46jOMcZp5DeMChUUPLNK8vvLfx6cxa1
         W6d/bgq+UZQk7FPRMduuZnjeiQ2KMhjaksvbXnV5wcJakfEm4eqgg8KJjvuqYpYEC+C6
         z5kEE/9JhA5BvIq2hjFB5UVH8Y0JyoFf2RQ75nZdJfUPt48fVyhzkjnT+i14Q1cd9tAs
         h67bIJ4HDeUR3lqK672x8lPqj2UV7JIJ+JLNeJDUDYCM+s0ecHwWV8ybweEcEIMYqRv3
         dmZA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HFTfx7UMgtwMaWfsWTTw/fg+WxB6BtHz56IBvW7z0JI=;
        b=QlewspQXLipZ1LZlxzdwDTJhb13n8WtHsC8Ao9ecAfJjbJPOtbuV+S9xkNf1E8g2Ah
         6YIUbUni+u4SxCdLHInh0n8dAmRETvCBlcDGT+gZCI1KWfSWLZ80eBcDvR8rrDR0dYT4
         jrkMdJLYmEOTkB5NtxY0sTHesNoorBAswqavN8BRueHRVmjmZABgwx4QvY/yR8wnRqK+
         ZbwqHm/Os+Xpl08cc/d6aV+1K776dyTxWqINW+FE0/WSDaCLWjIgL4QxtGe4BbWto5Iz
         JA3r0VdIFm9AzEkzomLgVaTcBeQtSvdIOaGBrmFg5xLqgYC8KHNhjiSrcktERAZSJfRq
         8/mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HFTfx7UMgtwMaWfsWTTw/fg+WxB6BtHz56IBvW7z0JI=;
        b=5QpaesWnh5NrimW5iLKsn81wQna08kjhywRe8z42yUYeX2QTQucRnGbLuevYaLpvE8
         YQ4J1PCAHoAYVeI/TOss0cgDUzcLYZBPasmam4uUpDHuzlmUzaLhOeWCdsVleuXHtMxM
         OKMqYHOIDwAbQgCsU7Xvqy3xrn339qgGw1TGCVsATDyENCj+KopYa+d6Zhu6gQ/mAsAG
         93U6h3Tr+PE0aVtF9/ZcaglnYeOi5rEdnz4dt0ZwVa5dlRSV88Z3srPOa8tXCOIeXqzs
         zPiqmElxlJMdy6MYutfYHoyUHIDm675tbytltNgc/LAzecZw7qT8i1PSA0oO9Tyvhi2J
         iMuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53189fzOG4etDAb6DgpSXR5iy0lfJx5/uioTi8WZIRRR8CBv9Yln
	ldszt67NnJQtlD/0H0JNSZI=
X-Google-Smtp-Source: ABdhPJzcGWq/gCZc5Ss3daltFPACHH7u+NDO//RY3DW6Xaer2ZIgIyxYDLw20BizL/AwyDr7YiR8eQ==
X-Received: by 2002:a05:6a00:1482:b0:49f:d9af:27dc with SMTP id v2-20020a056a00148200b0049fd9af27dcmr64673282pfu.9.1637330980271;
        Fri, 19 Nov 2021 06:09:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1706:: with SMTP id h6ls1191259pfc.9.gmail; Fri, 19
 Nov 2021 06:09:39 -0800 (PST)
X-Received: by 2002:a63:5d63:: with SMTP id o35mr17779793pgm.134.1637330979720;
        Fri, 19 Nov 2021 06:09:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637330979; cv=none;
        d=google.com; s=arc-20160816;
        b=FFcGCuTKV2Z2YYkcotP925dpbgzbZETguyOU7w7GSMBareE6924VwiYnPOSgETm5hW
         YgFcfuqSI0GsjPx7WCf7aKw/L4aanZ+SWFLdmBXeO4vfw0/YFLCB3tVIBv66jvMcd8wY
         23nv6e0sHnLyqU/PJSUaCNOZjVXnh4DxZdbQBcrc8V3sVfAfrGuY/WpfbcwOaJwtAokQ
         i0OD5Ydt0guGGMsUrdzMrFD0+25a2Ss/x4YT1g9sktdGMwOTVW/9DzApW8YbgeZnsihz
         iyUQE1AEptXxQrdY01+9exCOWIBdqdVB8JP3DB7+6NRZuxQ5104cCxcPp+qjN9uEW+RO
         6M9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uH5+LijC2//yZ3zDrCNfSRI5ao+iauirzsE3A/1TQsY=;
        b=EyrSPzmjkZ5Jp+IBCLpDycJ1WlMSW1CPusl/vE47HtZwKYIVqpViHIw36y23E5Jnf8
         E8n9dRTNPctdf+VvHx6qCeUKTgPdhmASG3NQS+kkaZiTRKxhvoXivpiv3knFXvDEx1HQ
         kLnUTitR8LlRlkO5ucHVGfq06pARxb8inoIwVkpxjmRs2KBQTMFFxlJnc5HJutokh+zk
         wQMSpNXk3jdG+T+PjeYdPd2z9kFaqBHL4XZ2rwM5OZZ3jxggvk/0aJGKVe4FUkXa1Dv0
         ED3xiUAWM5J4vR4bc3LuWondUfIuXSlPJ+xebZmU7ryagRTlBoZqi4i4dxqI3LDn0bQI
         ZO3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=is7eXdz4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x132.google.com (mail-il1-x132.google.com. [2607:f8b0:4864:20::132])
        by gmr-mx.google.com with ESMTPS id mq9si1310128pjb.3.2021.11.19.06.09.39
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Nov 2021 06:09:39 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) client-ip=2607:f8b0:4864:20::132;
Received: by mail-il1-x132.google.com with SMTP id i9so4825068ilu.1;
        Fri, 19 Nov 2021 06:09:39 -0800 (PST)
X-Received: by 2002:a05:6e02:1605:: with SMTP id t5mr802646ilu.233.1637330979385;
 Fri, 19 Nov 2021 06:09:39 -0800 (PST)
MIME-Version: 1.0
References: <1637130234-57238-1-git-send-email-quic_jiangenj@quicinc.com>
 <CACT4Y+YwNawV9H7uFMVSCA5WB-Dkyu9TX+rMM3FR6gNGkKFPqw@mail.gmail.com>
 <DM8PR02MB8247720860A08914CAA41D42F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
 <CACT4Y+a07DxQdYFY6uc5Y4GhTUbcnETij6gg3y+JRDvtwSmK5g@mail.gmail.com>
 <DM8PR02MB8247A19843220E03B34BA440F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
 <CACT4Y+Y36wgP_xjYVQApNLdMOFTr2-KCHc=AipcZyZiAhwf1Nw@mail.gmail.com> <CACT4Y+YF4Ngm6em_Sn2p+N0x1L+O8A=BEVTNhd00LmSZ+aH1iQ@mail.gmail.com>
In-Reply-To: <CACT4Y+YF4Ngm6em_Sn2p+N0x1L+O8A=BEVTNhd00LmSZ+aH1iQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 19 Nov 2021 15:09:28 +0100
Message-ID: <CA+fCnZct-Fy6JEUoHgk0h=2aFeBAWz2Ax_kOCee3-i_6zU-wfQ@mail.gmail.com>
Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
To: Dmitry Vyukov <dvyukov@google.com>
Cc: "JianGen Jiao (QUIC)" <quic_jiangenj@quicinc.com>, syzkaller <syzkaller@googlegroups.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Alexander Lochmann <info@alexander-lochmann.de>, "Likai Ding (QUIC)" <quic_likaid@quicinc.com>, 
	Kaipeng Zeng <kaipeng94@gmail.com>, Hangbin Liu <liuhangbin@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=is7eXdz4;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Fri, Nov 19, 2021 at 2:07 PM Dmitry Vyukov <dvyukov@google.com> wrote:
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

Throwing in a thought without a concrete design suggestion: how about
en eBPF-based filter? The flexibility would allow covering as many PC
ranges as one wants. And, perhaps, do other things.

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
kasan-dev/CA%2BfCnZct-Fy6JEUoHgk0h%3D2aFeBAWz2Ax_kOCee3-i_6zU-wfQ%40mail.gm=
ail.com.
