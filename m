Return-Path: <kasan-dev+bncBCMIZB7QWENRBHWNUKKAMGQE4KSBYOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 1495652FA17
	for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 10:45:19 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id k3-20020a05651239c300b00477b22d54c3sf5429260lfu.20
        for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 01:45:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653122718; cv=pass;
        d=google.com; s=arc-20160816;
        b=HonQHX+ATcIz/IKQr/BXs9j4nDaLxqn9Q6V5YSKBwcx0wwPjtNomWDAGF5prHZzh34
         rIvkitTdBN1c1DSGzhRbytf/wLXN4UVBJYGu3vW4klibPxJULvfgoKA+tf+BUnYTSmnL
         dHoONHgVcK7svjKLc1rkS2khmdREAj7iN5QsiYJHBCKZIKJbZMw1qlVeXJec3VIbP0Sn
         7l0cBoeHXKu9zOCWxVIogiMbXCplN3FshMMyYbT5MyVSPzkJpovgXH2OkRahjwF4kPI6
         20gkyFybx0oMTRtrfO4Qsg7JazvKtjRGfnIl76ADjX5eU+rx3BbRmSxuQgxHHpOOanEJ
         zOJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gGBRDXip69JY964zPBJNiP44K/9fh1hqWNKKaPdeVoQ=;
        b=CEKKw39yRcxNCiIsHvGnGl9w3m6MuaduKLq1mlAPIr/fHAY+jaS0nCmqfmzFjCB5//
         W3Q8a3vXqhAUiLprrYfd8iNfap50dwUioqBSSJemvJLELQQW3JkqCfiUhk9e4aSZPGoy
         luK9ZvrHpzsue2ieaeQLG7Af2w0H/QXUVbznrCIbEFB3q41P+92BQ7DDEUm50QDFGMUA
         R/NcCKSzCG2U6pfJAGPja8tEFwARCfA+CFk0Gf7q2Mg1ZC6OvdfN1NDHjwuJye/v8ls0
         4agcni3M9brlrJRYF45g0M1ijEX4pC7LKg9JOCp5IowuXGhxXlPV078ch+DsDhwtsJyq
         C7Yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bIBjcUhd;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=gGBRDXip69JY964zPBJNiP44K/9fh1hqWNKKaPdeVoQ=;
        b=MjuiFii+rMEU8JgAL+rV0zCoZS/yAsnw7DWap05iKdVV0fWEPvpeN4hsH62P8ntrAo
         07v2AKK7jKgmdFMMba2pbfTrGEe2jq9znnqWIpMaJ3yuJuCWgLeVWYNpYcE9or0U5Bui
         le/bIeqvyo7bb9poFQJ9CGkRqHnnHXNReFGMNrVeWscTXkSM+rOxBYjogWA2mkGkSPXY
         /l6cpJF0W59HEfFa9U9gRBA+lTee0v2DxJnqDwLtWdtXe2YVv91xxp+8T+KdBmjhLLaz
         DGKsSDv5wPS1QnqDL6Bw8mCVlaafS8mS1eSalzcTvyhnsk9j1jXLgFZi0vbEJn4qC02z
         Bw1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gGBRDXip69JY964zPBJNiP44K/9fh1hqWNKKaPdeVoQ=;
        b=R5Vzj1MpzotQyuSyWrxTOnVIelbMNexdGXc4vayl5JswApN1iEa/7/we6PHkYrpts2
         nfp99ABcXXpkB5881h5vWeG5PEAX2owpDXp4E/abemMkb/HFtaeyVMnpDsa2K6/tuewm
         lEr92CzMyi22uCE8yz4DdUSaDiM4lxBtTx4m/a8+YYC8XQ2v9QYZ7j8C8RKJe0eHYxPv
         hlQinELenPJbB2lquhvDzcS322YZrYoZcir3AI4AZOZtaoUgkJZt1xHeonRN0nQD3+lU
         SgvLWsDRSSEf0ZiEdGg5KMz1GfX1C7f8zSKTh24zAu8pD778VaFFj2wa9Kg66GOFQB9D
         g6yQ==
X-Gm-Message-State: AOAM5317TC4r3LZw37B1vbengs5PzKywB64ZQ3Y18qprAo7/FfvtpDwT
	xxDo2v74p3J69rSCl0AloRA=
X-Google-Smtp-Source: ABdhPJxdxFNxRPhx1wPkbPMD6R1kbzX0hASzMBThYiDmXsrx6f3/FRf2Q+Pt4ENBGjRkREb6SYq0Rw==
X-Received: by 2002:a05:6512:2a8e:b0:478:5b3a:65d9 with SMTP id dt14-20020a0565122a8e00b004785b3a65d9mr2678421lfb.255.1653122718316;
        Sat, 21 May 2022 01:45:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1603:b0:253:9ae0:be3b with SMTP id
 f3-20020a05651c160300b002539ae0be3bls1477377ljq.10.gmail; Sat, 21 May 2022
 01:45:17 -0700 (PDT)
X-Received: by 2002:a2e:9d93:0:b0:253:c9bd:288 with SMTP id c19-20020a2e9d93000000b00253c9bd0288mr7470535ljj.223.1653122717072;
        Sat, 21 May 2022 01:45:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653122717; cv=none;
        d=google.com; s=arc-20160816;
        b=hG1PxgNBlR1ggdJsWUGMyIk/qotDMmPgbpyPfVYobAn0EIkXEJIoFH1izMSvTyuE9F
         qVXPKIMZiZO+rOxgjVZDVqsnsYTjnDHq/xwT8dEbH4xypa62W2g9xiGSCcx5QxwcF7kB
         ZdWzdY0B8UQCKgFmfoZxgP8/2anP9heja2/b/hpMWxhUwJCxajv2yE/D+SGO6WcWnk22
         KIN57kd1Lc7YkXZ4w51wko5g5fXE9WXghslw4pSWka4hp9sHhjyYueIQJyDHzWiEdw+E
         JTfOJl97YfQetRaqA+0s3kSABQn5NOxfs+rJBLT3kQAi+XSxOV32XwUOR+zLNds1+cX8
         EpzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=itZAhxeCXbb0Z6+Q7+j5JbM+lNNa9CxSXTcydNGHMws=;
        b=0A85CepWl/LZtq/WxegTG0BSjKCXfygkZMV8Bu09WUIpuI3nv5NtBFjouFHUoEOm8C
         6qSR6XOQp5pC4yvOn7JyxY+SY6oyYkzNd5tKAH43lB4/niZ+5jZG11ndJ+NA8EBQiWbJ
         pyEPef1/0t1HhFsXp+DI0lFodnlH/SPStidOVWYGvXVgLDM8UH1ZMqlg9kLslvilr4Cm
         elrfy6JvlYEW49BP+eT5owj+0nLkaqRSmvOjrSidurI43193dpGlTuyFpMU111iZwkJC
         XwBxqjjJO+qES6pBewLKgIE0AZpTn8ghOZ2ypo3DqxsNyx8f1SeNahKlYY96Ra0BwL5Y
         igLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bIBjcUhd;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id w17-20020a05651234d100b00472587043edsi416390lfr.1.2022.05.21.01.45.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 May 2022 01:45:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id r3so5009948ljd.7
        for <kasan-dev@googlegroups.com>; Sat, 21 May 2022 01:45:17 -0700 (PDT)
X-Received: by 2002:a05:651c:19a3:b0:24f:4ed0:588 with SMTP id
 bx35-20020a05651c19a300b0024f4ed00588mr7903221ljb.465.1653122716474; Sat, 21
 May 2022 01:45:16 -0700 (PDT)
MIME-Version: 1.0
References: <20220517210532.1506591-1-liu3101@purdue.edu> <CACT4Y+Z+HtUttrd+btEWLj5Nut4Gv++gzCOL3aDjvRTNtMDEvg@mail.gmail.com>
 <CACT4Y+bAGVLU5QEUeQEHth6SZDOSzy0CRKEJQioC0oKHSPaAbA@mail.gmail.com> <MWHPR2201MB10724669E6D80EDFDB749478D0D29@MWHPR2201MB1072.namprd22.prod.outlook.com>
In-Reply-To: <MWHPR2201MB10724669E6D80EDFDB749478D0D29@MWHPR2201MB1072.namprd22.prod.outlook.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 21 May 2022 10:45:05 +0200
Message-ID: <CACT4Y+bXyiwEznZkAH5vRNd6YK3gi4aCncQLYt3iMWy43+T4EQ@mail.gmail.com>
Subject: Re: [PATCH] kcov: fix race caused by unblocked interrupt
To: "Liu, Congyu" <liu3101@purdue.edu>
Cc: "andreyknvl@gmail.com" <andreyknvl@gmail.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=bIBjcUhd;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f
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

On Sat, 21 May 2022 at 05:59, Liu, Congyu <liu3101@purdue.edu> wrote:
>
> Hi Dmitry,
>
> Sorry for the late reply. I did some experiments and hopefully they could=
 be helpful.
>
> To get the PC of the code that tampered with the buffer, I added some cod=
e between `area[pos] =3D ip;` and `WRITE_ONCE(area[0], pos);`: First, some =
code to delay for a while (e.g. for loop to write something). Then read `ar=
ea[0]` and compare it with `pos`. If they are different, then `area[pos]` i=
s tampered. A mask is then added to `area[pos]` so I can identify and retri=
eve it later.
>
> In this way, I ran some test cases then get a list of PCs that tampered w=
ith the kcov buffer, e.g., ./include/linux/rcupdate.h:rcu_read_lock, arch/x=
86/include/asm/current.h:get_current, include/sound/pcm.h:hw_is_interval, n=
et/core/neighbour.c:neigh_flush_dev, net/ipv6/addrconf.c:__ipv6_dev_get_sad=
dr, mm/mempolicy.c:__get_vma_policy...... It seems that they are not from t=
he early interrupt code. Do you think they should not be instrumented?

Humm... these look strange. They don't look like early interrupt code,
but they also don't look like interrupt code at all. E.g.
neigh_flush_dev looks like a very high level function that takes some
mutexes:
https://elixir.bootlin.com/linux/v5.18-rc7/source/net/core/neighbour.c#L320

It seems that there is something happening that we don't understand.

Please try to set t->kcov_writing around the task access, and then if
you see it recursively already set print the current pc/stack trace.
That should give better visibility into what code enters kcov
recursively.

If you are using syzkaller tools, you can run syz-execprog with -cover
flag on some log file, or run some program undef kcovtrace:
https://github.com/google/syzkaller/blob/master/tools/kcovtrace/kcovtrace.c



> I think reordering `area[pos] =3D ip;` and `WRITE_ONCE(area[0], pos);` is=
 also a smart solution since PC will be written to buffer only after the bu=
ffer is reserved.
>
> Thanks,
> Congyu
>
> ________________________________________
> From: Dmitry Vyukov <dvyukov@google.com>
> Sent: Wednesday, May 18, 2022 4:59
> To: Liu, Congyu
> Cc: andreyknvl@gmail.com; kasan-dev@googlegroups.com; linux-kernel@vger.k=
ernel.org
> Subject: Re: [PATCH] kcov: fix race caused by unblocked interrupt
>
> On Wed, 18 May 2022 at 10:56, Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Tue, 17 May 2022 at 23:05, Congyu Liu <liu3101@purdue.edu> wrote:
> > >
> > > Some code runs in interrupts cannot be blocked by `in_task()` check.
> > > In some unfortunate interleavings, such interrupt is raised during
> > > serializing trace data and the incoming nested trace functionn could
> > > lead to loss of previous trace data. For instance, in
> > > `__sanitizer_cov_trace_pc`, if such interrupt is raised between
> > > `area[pos] =3D ip;` and `WRITE_ONCE(area[0], pos);`, then trace data =
in
> > > `area[pos]` could be replaced.
> > >
> > > The fix is done by adding a flag indicating if the trace buffer is be=
ing
> > > updated. No modification to trace buffer is allowed when the flag is =
set.
> >
> > Hi Congyu,
> >
> > What is that interrupt code? What interrupts PCs do you see in the trac=
e.
> > I would assume such early interrupt code should be in asm and/or not
> > instrumented. The presence of instrumented traced interrupt code is
> > problematic for other reasons (add random stray coverage to the
> > trace). So if we make it not traced, it would resolve both problems at
> > once and without the fast path overhead that this change adds.
>
> Also thinking if reordering `area[pos] =3D ip;` and `WRITE_ONCE(area[0], =
pos);`
> will resolve the problem without adding fast path overhead.
> However, not instrumenting early interrupt code still looks more preferab=
le.
>
>
>  > Signed-off-by: Congyu Liu <liu3101@purdue.edu>
> > > ---
> > >  include/linux/sched.h |  3 +++
> > >  kernel/kcov.c         | 16 ++++++++++++++++
> > >  2 files changed, 19 insertions(+)
> > >
> > > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > > index a8911b1f35aa..d06cedd9595f 100644
> > > --- a/include/linux/sched.h
> > > +++ b/include/linux/sched.h
> > > @@ -1408,6 +1408,9 @@ struct task_struct {
> > >
> > >         /* Collect coverage from softirq context: */
> > >         unsigned int                    kcov_softirq;
> > > +
> > > +       /* Flag of if KCOV area is being written: */
> > > +       bool                            kcov_writing;
> > >  #endif
> > >
> > >  #ifdef CONFIG_MEMCG
> > > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > > index b3732b210593..a595a8ad5d8a 100644
> > > --- a/kernel/kcov.c
> > > +++ b/kernel/kcov.c
> > > @@ -165,6 +165,8 @@ static notrace bool check_kcov_mode(enum kcov_mod=
e needed_mode, struct task_stru
> > >          */
> > >         if (!in_task() && !(in_serving_softirq() && t->kcov_softirq))
> > >                 return false;
> > > +       if (READ_ONCE(t->kcov_writing))
> > > +               return false;
> > >         mode =3D READ_ONCE(t->kcov_mode);
> > >         /*
> > >          * There is some code that runs in interrupts but for which
> > > @@ -201,12 +203,19 @@ void notrace __sanitizer_cov_trace_pc(void)
> > >                 return;
> > >
> > >         area =3D t->kcov_area;
> > > +
> > > +       /* Prevent race from unblocked interrupt. */
> > > +       WRITE_ONCE(t->kcov_writing, true);
> > > +       barrier();
> > > +
> > >         /* The first 64-bit word is the number of subsequent PCs. */
> > >         pos =3D READ_ONCE(area[0]) + 1;
> > >         if (likely(pos < t->kcov_size)) {
> > >                 area[pos] =3D ip;
> > >                 WRITE_ONCE(area[0], pos);
> > >         }
> > > +       barrier();
> > > +       WRITE_ONCE(t->kcov_writing, false);
> > >  }
> > >  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> > >
> > > @@ -230,6 +239,10 @@ static void notrace write_comp_data(u64 type, u6=
4 arg1, u64 arg2, u64 ip)
> > >         area =3D (u64 *)t->kcov_area;
> > >         max_pos =3D t->kcov_size * sizeof(unsigned long);
> > >
> > > +       /* Prevent race from unblocked interrupt. */
> > > +       WRITE_ONCE(t->kcov_writing, true);
> > > +       barrier();
> > > +
> > >         count =3D READ_ONCE(area[0]);
> > >
> > >         /* Every record is KCOV_WORDS_PER_CMP 64-bit words. */
> > > @@ -242,6 +255,8 @@ static void notrace write_comp_data(u64 type, u64=
 arg1, u64 arg2, u64 ip)
> > >                 area[start_index + 3] =3D ip;
> > >                 WRITE_ONCE(area[0], count + 1);
> > >         }
> > > +       barrier();
> > > +       WRITE_ONCE(t->kcov_writing, false);
> > >  }
> > >
> > >  void notrace __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2)
> > > @@ -335,6 +350,7 @@ static void kcov_start(struct task_struct *t, str=
uct kcov *kcov,
> > >         t->kcov_size =3D size;
> > >         t->kcov_area =3D area;
> > >         t->kcov_sequence =3D sequence;
> > > +       t->kcov_writing =3D false;
> > >         /* See comment in check_kcov_mode(). */
> > >         barrier();
> > >         WRITE_ONCE(t->kcov_mode, mode);
> > > --
> > > 2.34.1
> > >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BbXyiwEznZkAH5vRNd6YK3gi4aCncQLYt3iMWy43%2BT4EQ%40mail.gm=
ail.com.
