Return-Path: <kasan-dev+bncBCMIZB7QWENRBMH53WGAMGQEKX46AVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id ED118456D6B
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 11:38:41 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id bq9-20020a05620a468900b004681cdb3483sf7437512qkb.23
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 02:38:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637318321; cv=pass;
        d=google.com; s=arc-20160816;
        b=qiiuviXIO8ZystNYPFu7Z4mMSV1aUEFX/oeTDV98xiFmqh5kdDkNhUTkKpfSsGrcfn
         RybCU8aEMVrBNQ4cliTUx7KRlsBpfN1VGo4JcNhp1OBJluSE7eBl/YFUhQQS0TotzoLP
         7ZO4ZJH9LmDSgG6bscG5xUdv+/E0yqJaVsLGV/dwQGYm8F9Gz4E2A7FAFuPqpe5lBKAR
         u+9AkHEy7Z5nZBgL5JugfOmmebNoVbGrWAsRBB4gnvgyMKmzaf1YAfWqIC40X+lwYYek
         SdX9Q2UHhU8Qu0FPlPgsfC5CEL503uogV+QFCx+a1hchiboPN/8N7zfmvKlHOcfydSxV
         ir4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JgEX1KJryDfPUG0IhBtoIuNzY43zoweZEPZaOL4ta8s=;
        b=xD9uQTuhoG9M0HmpU3VCf26bHVcu9FcUytQC1izlW8EJT5avFhdCb9RdvOpHKZKU2p
         2vTywJiMxXtDgF8inNpbW5AL7LDrQv0P7WAKqWD/Z+GU756nLXaPVS1qTXzn3WAGGJru
         tokfXXHIUj7B549+k0UUX6BbJGilHfYwiuyhp8+0MP/WPDOH/Odd8wHdv5ZU6ocfhofT
         vJ2FzesHJQIujxIBp9Ih0wpfXB7VI/g2KFL2TldZZ/lPAmBlNkHZnXnfeym2R4insfKQ
         2T1oz2+gE5wDH/mSPNmII+TML1G0sXBbHl52Z7kA53SXepCZ/eRCcRbzFwxHGhtBoMzt
         sK7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="bAWRE/8m";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=JgEX1KJryDfPUG0IhBtoIuNzY43zoweZEPZaOL4ta8s=;
        b=tK3s4bDvagoRDImK827oRc0fjChYZI4FCHOvNs52f2FtnkDpnGLDU0EZz0hfFiQOHC
         xyLV3OLiUGs9iwxTW/8uLkY/h6Dw1wOdU/QIjw/VVzqUzAk1fWkJgqlYfCrvBNgISpzf
         DMytptAJeGPLEg6Y1rDIVUH5DCCTUP56/4K5pIMcOG2t84i7QNQb6ZbcPvKfv+9quuyZ
         8kKqzfCmVsUN7Qmt2fDsvYIkBdmvJQFcPYyUMQ21DJL2iBHi/p+o0/098TwrftJOfEAP
         F7hiWPrEmpGaG2ojNgA6fftZATZdIYzSMIYjP9hGp28628ZLYBmpLqBeHOf3KABivm5Z
         BqLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JgEX1KJryDfPUG0IhBtoIuNzY43zoweZEPZaOL4ta8s=;
        b=Zhix+vOjturbkqQMIE+OJlWnZXK4u738T9wxsJwY0WajRHfgcSdwHt7BtwNpgWsyV5
         4cnk+NsxcRWbRXUKiIYuczNBgCXjugB06crPpz7vkDWF815dBYNt9lwv5XvpwQwlGMcm
         RlO53JlRJcGt1f5zsv+CAiTzyOYWrDt1qw2KiP0TOW1cMi6WvPUI+q0Gj7JdpcMT6IY2
         5gXWELijgW7DOdD+a2VWy22ALdxoagJ+9N3W2LJFPc0lNVRMhFAIjfIWdoDQ0fe2ikph
         2B9stCY23nUPAqmJ6fyosGnV/QCEKIltaAmOPE+rG2KoTvBf7H6Lsaz+1m5qtthwKmPg
         kFPA==
X-Gm-Message-State: AOAM532Vc2jzywhBZTUYZsPYESW/k7BZVa//2hlR1/1NT8h9rBrZ/cYe
	XEftejaud8gVqVrmudRKL1Q=
X-Google-Smtp-Source: ABdhPJy9rlHzss4wCD7uJlGZqfP4YnxYQnbr37Y24bQcxCDcPgfFVg1ZTiD1yaY/LGYkeF+WtJC2QQ==
X-Received: by 2002:a05:6214:411d:: with SMTP id kc29mr71419687qvb.22.1637318320851;
        Fri, 19 Nov 2021 02:38:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a81:: with SMTP id s1ls1425066qtc.11.gmail; Fri,
 19 Nov 2021 02:38:40 -0800 (PST)
X-Received: by 2002:ac8:58d1:: with SMTP id u17mr5020325qta.137.1637318320431;
        Fri, 19 Nov 2021 02:38:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637318320; cv=none;
        d=google.com; s=arc-20160816;
        b=XHeWOBDq44DZ8ZbF+oc5RamjLQJUvcQ86cCXV51c+JXbFuPPjZQjUt6C0W2o1RJ0zN
         ENjsOfUP6gGr+30rlNQBxOoKfIydLyP7FQVKQ4FxCrmBDj30P+QvfkvyqlE9id8NjV5O
         J3Ye0+rWdULlsKyYdkBBE7yT+uAVJDEHP0TRA9HxAFa5khGAoHCwgCNQYs53LPBShBkT
         EUiIHNnteXBQewAJgpKRNHDE2k8+RLA/q4cmiQkxahXKn+ZOMEx9pfuBMluUkty7Xbbi
         lgVEgcsYJeHJUkjJ019ulEvP9YhCh+wIoxCknn/51oOwH1q53JnhwhXIxqypczpau/0B
         D4CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=AYXZ3Fwirr8SQxJ7wPvNhsrS3JHRNan1bxHGs12//g8=;
        b=WDbc/V+5CCgEz6QW43JvksGeWy+e7My2kPywG/HScvmiTzRuC3ZVt0GJPPbPdTnRld
         jhEwKKBN2qpapAgFoV4/ymkp+CuDGFz7EAe+YwXtjiP/ncugpWyT74hQxFwmPsFDEdKc
         mn1ZZZb4RaeXP7vjab0CqiyzJYOaQ0LuwoFVluaZYuVyk8UcoC8vN7M987kXoBlPmlys
         tJt8gVSWi0DW3Yz1GuvpdIOf2oFHgBymezL9NuP6Kg/R5HlnFexKoVLhKRsnkPnQnbpc
         e5fCLFu46+O8miVD11naw+t5cTfCYvo2aboMZdF35xdft9DGDNvbtdqJRIFwjjtF4bTi
         EfLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="bAWRE/8m";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id u2si525337qkp.6.2021.11.19.02.38.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Nov 2021 02:38:40 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id 7so20950300oip.12
        for <kasan-dev@googlegroups.com>; Fri, 19 Nov 2021 02:38:40 -0800 (PST)
X-Received: by 2002:a54:4390:: with SMTP id u16mr4092034oiv.109.1637318319738;
 Fri, 19 Nov 2021 02:38:39 -0800 (PST)
MIME-Version: 1.0
References: <1637130234-57238-1-git-send-email-quic_jiangenj@quicinc.com>
 <CACT4Y+YwNawV9H7uFMVSCA5WB-Dkyu9TX+rMM3FR6gNGkKFPqw@mail.gmail.com> <DM8PR02MB8247720860A08914CAA41D42F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
In-Reply-To: <DM8PR02MB8247720860A08914CAA41D42F89C9@DM8PR02MB8247.namprd02.prod.outlook.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Nov 2021 11:38:28 +0100
Message-ID: <CACT4Y+a07DxQdYFY6uc5Y4GhTUbcnETij6gg3y+JRDvtwSmK5g@mail.gmail.com>
Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
To: "JianGen Jiao (QUIC)" <quic_jiangenj@quicinc.com>
Cc: "andreyknvl@gmail.com" <andreyknvl@gmail.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Alexander Lochmann <info@alexander-lochmann.de>, "Likai Ding (QUIC)" <quic_likaid@quicinc.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="bAWRE/8m";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::22c
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

On Fri, 19 Nov 2021 at 04:17, JianGen Jiao (QUIC)
<quic_jiangenj@quicinc.com> wrote:
>
> Hi Dmitry,
> I'm using the start, end pc from cover filter, which currently is the fas=
t way compared to the big bitmap passing from syzkaller solution, as I only=
 set the cover filter to dirs/files I care about.

I see.
But if we are unlucky and our functions of interest are at the very
low and high addresses, start/end will cover almost all kernel code...

> I checked https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCA=
AAJ,
> The bitmap seems not the same as syzkaller one, which one will be used fi=
nally?

I don't know yet. We need to decide.
In syzkaller we are more flexible and can change code faster, while
kernel interfaces are stable and need to be kept forever. So I think
we need to concentrate more on the good kernel interface and then
support it in syzkaller.

> ``` Alexander's one
> + pos =3D (ip - canonicalize_ip((unsigned long)&_stext)) / 4;
> + idx =3D pos % BITS_PER_LONG;
> + pos /=3D BITS_PER_LONG;
> + if (likely(pos < t->kcov_size))
> + WRITE_ONCE(area[pos], READ_ONCE(area[pos]) | 1L << idx);
> ```
> Pc offset is divided by 4 and start is _stext. But for some arch, pc is l=
ess than _stext.

You mean that modules can have PC < _stext?

> ``` https://github.com/google/syzkaller/blob/master/syz-manager/covfilter=
.go#L139-L154
>         data :=3D make([]byte, 8+((size>>4)/8+1))
>         order :=3D binary.ByteOrder(binary.BigEndian)
>         if target.LittleEndian {
>                 order =3D binary.LittleEndian
>         }
>         order.PutUint32(data, start)
>         order.PutUint32(data[4:], size)
>
>         bitmap :=3D data[8:]
>         for pc :=3D range pcs {
>                 // The lowest 4-bit is dropped.
>                 pc =3D uint32(backend.NextInstructionPC(target, uint64(pc=
)))
>                 pc =3D (pc - start) >> 4
>                 bitmap[pc/8] |=3D (1 << (pc % 8))
>         }
>         return data
> ```
> Pc offset is divided by 16 and start is cover filter start pc.
>
> I think divided by 8 is more reasonable? Because there is at least one in=
struction before each __sanitizer_cov_trace_pc call.
> 0000000000000160 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
> 0000000000000168 R_AARCH64_CALL26  __sanitizer_cov_trace_pc
>
> I think we still need my patch because we still need a way to keep the tr=
ace_pc call and post-filter in syzkaller doesn't solve trace_pc dropping, r=
ight?

Yes, the in-kernel filter solves the problem of trace capacity/overflows.


> But for sure I can use the bitmap from syzkaller.
>
> THX
> Joey
> -----Original Message-----
> From: Dmitry Vyukov <dvyukov@google.com>
> Sent: Thursday, November 18, 2021 10:00 PM
> To: JianGen Jiao (QUIC) <quic_jiangenj@quicinc.com>
> Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; LKML <linux-kernel@=
vger.kernel.org>; Alexander Lochmann <info@alexander-lochmann.de>
> Subject: Re: [PATCH] kcov: add KCOV_PC_RANGE to limit pc range
>
> WARNING: This email originated from outside of Qualcomm. Please be wary o=
f any links or attachments, and do not enable macros.
>
> ,On Wed, 17 Nov 2021 at 07:24, Joey Jiao <quic_jiangenj@quicinc.com> wrot=
e:
> >
> > Sometimes we only interested in the pcs within some range, while there
> > are cases these pcs are dropped by kernel due to `pos >=3D
> > t->kcov_size`, and by increasing the map area size doesn't help.
> >
> > To avoid disabling KCOV for these not intereseted pcs during build
> > time, adding this new KCOV_PC_RANGE cmd.
>
> Hi Joey,
>
> How do you use this? I am concerned that a single range of PCs is too res=
trictive. I can only see how this can work for single module (continuous in=
 memory) or a single function. But for anything else (something in the main=
 kernel, or several modules), it won't work as PCs are not continuous.
>
> Maybe we should use a compressed bitmap of interesting PCs? It allows to =
support all cases and we already have it in syz-executor, then syz-executor=
 could simply pass the bitmap to the kernel rather than post-filter.
> It's also overlaps with the KCOV_MODE_UNIQUE mode that +Alexander propose=
d here:
> https://groups.google.com/g/kasan-dev/c/oVz3ZSWaK1Q/m/9ASztdzCAAAJ
> It would be reasonable if kernel uses the same bitmap format for these
> 2 features.
>
>
>
> > An example usage is to use together syzkaller's cov filter.
> >
> > Change-Id: I954f6efe1bca604f5ce31f8f2b6f689e34a2981d
> > Signed-off-by: Joey Jiao <quic_jiangenj@quicinc.com>
> > ---
> >  Documentation/dev-tools/kcov.rst | 10 ++++++++++
> >  include/uapi/linux/kcov.h        |  7 +++++++
> >  kernel/kcov.c                    | 18 ++++++++++++++++++
> >  3 files changed, 35 insertions(+)
> >
> > diff --git a/Documentation/dev-tools/kcov.rst
> > b/Documentation/dev-tools/kcov.rst
> > index d83c9ab..fbcd422 100644
> > --- a/Documentation/dev-tools/kcov.rst
> > +++ b/Documentation/dev-tools/kcov.rst
> > @@ -52,9 +52,15 @@ program using kcov:
> >      #include <fcntl.h>
> >      #include <linux/types.h>
> >
> > +    struct kcov_pc_range {
> > +      uint32 start;
> > +      uint32 end;
> > +    };
> > +
> >      #define KCOV_INIT_TRACE                    _IOR('c', 1, unsigned l=
ong)
> >      #define KCOV_ENABLE                        _IO('c', 100)
> >      #define KCOV_DISABLE                       _IO('c', 101)
> > +    #define KCOV_TRACE_RANGE                   _IOW('c', 103, struct k=
cov_pc_range)
> >      #define COVER_SIZE                 (64<<10)
> >
> >      #define KCOV_TRACE_PC  0
> > @@ -64,6 +70,8 @@ program using kcov:
> >      {
> >         int fd;
> >         unsigned long *cover, n, i;
> > +        /* Change start and/or end to your interested pc range. */
> > +        struct kcov_pc_range pc_range =3D {.start =3D 0, .end =3D
> > + (uint32)(~((uint32)0))};
> >
> >         /* A single fd descriptor allows coverage collection on a singl=
e
> >          * thread.
> > @@ -79,6 +87,8 @@ program using kcov:
> >                                      PROT_READ | PROT_WRITE, MAP_SHARED=
, fd, 0);
> >         if ((void*)cover =3D=3D MAP_FAILED)
> >                 perror("mmap"), exit(1);
> > +        if (ioctl(fd, KCOV_PC_RANGE, pc_range))
> > +               dprintf(2, "ignore KCOV_PC_RANGE error.\n");
> >         /* Enable coverage collection on the current thread. */
> >         if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC))
> >                 perror("ioctl"), exit(1); diff --git
> > a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h index
> > 1d0350e..353ff0a 100644
> > --- a/include/uapi/linux/kcov.h
> > +++ b/include/uapi/linux/kcov.h
> > @@ -16,12 +16,19 @@ struct kcov_remote_arg {
> >         __aligned_u64   handles[0];
> >  };
> >
> > +#define PC_RANGE_MASK ((__u32)(~((u32) 0))) struct kcov_pc_range {
> > +       __u32           start;          /* start pc & 0xFFFFFFFF */
> > +       __u32           end;            /* end pc & 0xFFFFFFFF */
> > +};
> > +
> >  #define KCOV_REMOTE_MAX_HANDLES                0x100
> >
> >  #define KCOV_INIT_TRACE                        _IOR('c', 1, unsigned l=
ong)
> >  #define KCOV_ENABLE                    _IO('c', 100)
> >  #define KCOV_DISABLE                   _IO('c', 101)
> >  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, struct kcov_remo=
te_arg)
> > +#define KCOV_PC_RANGE                  _IOW('c', 103, struct kcov_pc_r=
ange)
> >
> >  enum {
> >         /*
> > diff --git a/kernel/kcov.c b/kernel/kcov.c index 36ca640..59550450
> > 100644
> > --- a/kernel/kcov.c
> > +++ b/kernel/kcov.c
> > @@ -36,6 +36,7 @@
> >   *  - initial state after open()
> >   *  - then there must be a single ioctl(KCOV_INIT_TRACE) call
> >   *  - then, mmap() call (several calls are allowed but not useful)
> > + *  - then, optional to set trace pc range
> >   *  - then, ioctl(KCOV_ENABLE, arg), where arg is
> >   *     KCOV_TRACE_PC - to trace only the PCs
> >   *     or
> > @@ -69,6 +70,8 @@ struct kcov {
> >          * kcov_remote_stop(), see the comment there.
> >          */
> >         int                     sequence;
> > +       /* u32 Trace PC range from start to end. */
> > +       struct kcov_pc_range    pc_range;
> >  };
> >
> >  struct kcov_remote_area {
> > @@ -192,6 +195,7 @@ static notrace unsigned long
> > canonicalize_ip(unsigned long ip)  void notrace
> > __sanitizer_cov_trace_pc(void)  {
> >         struct task_struct *t;
> > +       struct kcov_pc_range pc_range;
> >         unsigned long *area;
> >         unsigned long ip =3D canonicalize_ip(_RET_IP_);
> >         unsigned long pos;
> > @@ -199,6 +203,11 @@ void notrace __sanitizer_cov_trace_pc(void)
> >         t =3D current;
> >         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> >                 return;
> > +       pc_range =3D t->kcov->pc_range;
> > +       if (pc_range.start < pc_range.end &&
> > +               ((ip & PC_RANGE_MASK) < pc_range.start ||
> > +               (ip & PC_RANGE_MASK) > pc_range.end))
> > +               return;
> >
> >         area =3D t->kcov_area;
> >         /* The first 64-bit word is the number of subsequent PCs. */
> > @@ -568,6 +577,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, uns=
igned int cmd,
> >         int mode, i;
> >         struct kcov_remote_arg *remote_arg;
> >         struct kcov_remote *remote;
> > +       struct kcov_pc_range *pc_range;
> >         unsigned long flags;
> >
> >         switch (cmd) {
> > @@ -589,6 +599,14 @@ static int kcov_ioctl_locked(struct kcov *kcov, un=
signed int cmd,
> >                 kcov->size =3D size;
> >                 kcov->mode =3D KCOV_MODE_INIT;
> >                 return 0;
> > +       case KCOV_PC_RANGE:
> > +               /* Limit trace pc range. */
> > +               pc_range =3D (struct kcov_pc_range *)arg;
> > +               if (copy_from_user(&kcov->pc_range, pc_range, sizeof(kc=
ov->pc_range)))
> > +                       return -EINVAL;
> > +               if (kcov->pc_range.start >=3D kcov->pc_range.end)
> > +                       return -EINVAL;
> > +               return 0;
> >         case KCOV_ENABLE:
> >                 /*
> >                  * Enable coverage for the current task.
> > --
> > 2.7.4
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2Ba07DxQdYFY6uc5Y4GhTUbcnETij6gg3y%2BJRDvtwSmK5g%40mail.gm=
ail.com.
