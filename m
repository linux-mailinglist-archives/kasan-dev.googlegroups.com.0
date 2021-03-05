Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7PMQ6BAMGQEU6WQOLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 8860132E474
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 10:14:38 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id 7sf1025266pfn.4
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 01:14:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614935677; cv=pass;
        d=google.com; s=arc-20160816;
        b=FKHaH1z8foo8ZEF0oOj8fMwx1HofQNbFhqPfNfEherpTT8vsLg1XzTeRIBf/q4mIuL
         WjzabL+Ak56+Phf4zL6EZRpz0fDdG81LLWnovBsje3sJr15jDDX/RQmF4Nt/nqTchZZ0
         Q/puoKLVCc8tPnMWmLM5wR4cwTkrYeS1uAPjlf7RzDm9/Zc8EHBn3I1oYeH3VOQvAfO+
         c4WgR2GpaSWi/2gxd3YeAtDR4VrASNCSPAZ70EA0cioGWBY8+2TlHoHX+ioZUosBqnXP
         UrV1ohq4SjNaW4Cu394Ajg+nySM/yYJaIdf3QWMT4qwRxRmH2+E4z6c7YW4Rz5hRCIT8
         FUjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UbsyisQ0xeP1W2V+Apc4eGJ3MI2nLrhKINwDsHCdH1g=;
        b=HtYYQrV5FdOzr2mQzjE20f4GyWltaXvLrcy6W5Py60lZdI0P/CgIqtiVVcA0uHehHA
         R6OxSutPIJpDQLkODsTGdr5LVy7PtTdotk6e/jo2OJxY8HO8Juhb/GIo2WQzQwJKEgc5
         3GrQGX2cRLa9UMhwoSg5uxhoXMKeRvn5IqtbtnQTd//3tN6TUMbTvwmWRP5Xzbe3eqlO
         zbsK6rQwvCsxGaHB6GtoasE4DB9fFHMS+u3xTUxCSjtvAuhhFligedPz0v0n9n6bzeeJ
         x96AQcn8BNY0Asn2+u+0vcyo3vfAidrfyHhabIsMKjtsn0juG8naH3/ovP6j1udcf91z
         ACeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nZ2pVXGc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=UbsyisQ0xeP1W2V+Apc4eGJ3MI2nLrhKINwDsHCdH1g=;
        b=M3EnTlNkKNbOKc/dbBiwi8olw6dW9b9iBWEDUZW0hMOzPMaZkcpKPYdgxdTk6ou0dM
         9OqyWxS4ofVoPfuKKOeEvpqwbxKbKqgJJhVwTkdbwUhURIQH/9xc/kEHQDNAxt+65qa6
         tE/NVyOBvYooXhiE+wJg9BpW0oDBCQ0rnJxmbl+tzC/8lxT3hER8s0Ia71qT0CclZgax
         o+sMbIHE3wyGhfGkV1DkzCrtW1OX7Ew29vFxZXUkb5qyZyHNjavFwpHYWNDsv/GfE+lC
         uu6aQ+G/Myp++/2JcqJhA2r6l8xCeHMf3FJNLJ0OePBLYx5FeQyKPdEwkByEqzTtpZYz
         wGjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UbsyisQ0xeP1W2V+Apc4eGJ3MI2nLrhKINwDsHCdH1g=;
        b=sFAjSmmlK/4OsPpeOoE0/UYqU0mxmg46dXOhsCwQJA+oO2gghnYQcdjm3U54rccYNO
         eA1iP7mjHuX1zEUyDZ4M369qOX2QNTqvEJoVOQUHDHPgYnfLlnWSi/5LH7DdIQ9PFbwv
         cYo42UqwrVPbC1wVM8i2LhV3VTDe2DOx+dgMr8z3LsBVz4A6kLXitPgnLf1RabqFlWfp
         casxTHfC0deDeNFotj3x058VIN9oVuU0OdMYZQmOwiSGbQSMi87scIvwDz//oQZpYiso
         woVgqUHx5RUMym4lFYkNU/oJhnPrCZEj79iyQeIqqS4l8GSZnECfO9EllVYxiRVlbqsA
         Mnbw==
X-Gm-Message-State: AOAM532M7kpVrq395vLMo3n4K3PjIKE5AeJ7qvWEGORa/mn1PG0RILN0
	tI2dNtf1xu4hZPIK3NofCtA=
X-Google-Smtp-Source: ABdhPJxhprsS39AVAftYBXkplEW+KfIoz9htMPQP/e56hOjmBaA7usgL4erb1+vjAMHMj1yMMhMUjQ==
X-Received: by 2002:a17:90a:4598:: with SMTP id v24mr9391945pjg.102.1614935677085;
        Fri, 05 Mar 2021 01:14:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4d43:: with SMTP id j3ls3601112pgt.1.gmail; Fri, 05 Mar
 2021 01:14:36 -0800 (PST)
X-Received: by 2002:a65:5806:: with SMTP id g6mr7345053pgr.112.1614935676515;
        Fri, 05 Mar 2021 01:14:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614935676; cv=none;
        d=google.com; s=arc-20160816;
        b=VLLuiJwVlmSwa3ms2mS8Mq132M1C5ancNtfq35VQZ5x72Kwb1trFXB85Z6oSGcSQKn
         PUVpIhSOQBMxBuNtjaABNM5uR7aDyENqFf5+KXfeBjWwHbQC8iwrp4p0JVeiZzJaclN0
         3z9JE9AqfvbxGZ9pf5zXdWpYquACOOmCETBqS5s5aexcfY/OPxkGB5dJw99ZUi+n/u0r
         BxM4bkIwZbbHWhBTZE6zd2/mEmA32OlmY8sYZXQe1f2phqBwCELViDUpIUh/wk4+fRIp
         2Zxss97YJ6vq8tzNoWOPvqEfQbUsNzORL5gI+ObqEmnsOiF7P1izb4dXB3Z67BAP4+JI
         QmDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NPj0KxMXFfRe8+xSa+Go2DD4qn2EGEmIs7ZK90LXWyQ=;
        b=M7Oom/6q4whKZn0C4ddLVxuu7RkcUSnBM6MtPpSbSbzbtAn8uuRztsLZs69mgLw8DS
         mug6sjYRToZp+obiIZ/Pj72wsaANlsYXKA64ZmbPf6K7T/ign4o1lMkaYfMUBPVeObay
         lp5Y1medfTh2FaN9pGmL7hk8px3VIe5RHwb65+WkzmUhB0BChyfNfUWMab52mTTRSkDm
         NE/yqGUdLRKOqZ0kVV/Bv94RsgH7bCPBA6okrveE75f149x+b/AvSNuCwN0lKoCWH8Cy
         5gNFLgGO7ZxewkkIDM3TJIf7O/TeFHMCCctzUfhhvT4qvuLge0+7hEn5N3+9wN4N+T0n
         /Mmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nZ2pVXGc;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id d2si126919pfr.4.2021.03.05.01.14.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 01:14:36 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id b8so1136937oti.7
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 01:14:36 -0800 (PST)
X-Received: by 2002:a9d:7f11:: with SMTP id j17mr7316937otq.251.1614935675615;
 Fri, 05 Mar 2021 01:14:35 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu> <CANpmjNPYEmLtQEu5G=zJLUzOBaGoqNKwLyipDCxvytdKDKb7mg@mail.gmail.com>
 <ad61cb3a-2b4a-3754-5761-832a1dd0c34e@csgroup.eu> <CANpmjNOnVzei7frKcMzMHxaDXh5NvTA-Wpa29C2YC1GUxyKfhQ@mail.gmail.com>
 <f036c53d-7e81-763c-47f4-6024c6c5f058@csgroup.eu> <CANpmjNMn_CUrgeSqBgiKx4+J8a+XcxkaLPWoDMUvUEXk8+-jxg@mail.gmail.com>
 <7270e1cc-bb6b-99ee-0043-08a027b8d83a@csgroup.eu> <YEDXJ5JNkgvDFehc@elver.google.com>
 <874khqry78.fsf@mpe.ellerman.id.au> <YEHiq1ALdPn2crvP@elver.google.com> <f6e47f4f-6953-6584-f023-8b9c22d6974e@csgroup.eu>
In-Reply-To: <f6e47f4f-6953-6584-f023-8b9c22d6974e@csgroup.eu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Mar 2021 10:14:23 +0100
Message-ID: <CANpmjNM9o1s4O4v2T9HUohPdCDJzWcaC5KDrt_7BSVdTUQWagw@mail.gmail.com>
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Michael Ellerman <mpe@ellerman.id.au>, Alexander Potapenko <glider@google.com>, 
	Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, 
	Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nZ2pVXGc;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
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

On Fri, 5 Mar 2021 at 09:23, Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
>
>
> Le 05/03/2021 =C3=A0 08:50, Marco Elver a =C3=A9crit :
> > On Fri, Mar 05, 2021 at 04:01PM +1100, Michael Ellerman wrote:
> >> Marco Elver <elver@google.com> writes:
> >>> On Thu, Mar 04, 2021 at 12:48PM +0100, Christophe Leroy wrote:
> >>>> Le 04/03/2021 =C3=A0 12:31, Marco Elver a =C3=A9crit :
> >>>>> On Thu, 4 Mar 2021 at 12:23, Christophe Leroy
> >>>>> <christophe.leroy@csgroup.eu> wrote:
> >>>>>> Le 03/03/2021 =C3=A0 11:56, Marco Elver a =C3=A9crit :
> >>>>>>>
> >>>>>>> Somewhat tangentially, I also note that e.g. show_regs(regs) (whi=
ch
> >>>>>>> was printed along the KFENCE report above) didn't include the top
> >>>>>>> frame in the "Call Trace", so this assumption is definitely not
> >>>>>>> isolated to KFENCE.
> >>>>>>>
> >>>>>>
> >>>>>> Now, I have tested PPC64 (with the patch I sent yesterday to modif=
y save_stack_trace_regs()
> >>>>>> applied), and I get many failures. Any idea ?
> >>>>>>
> >>>>>> [   17.653751][   T58] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D
> >>>>>> [   17.654379][   T58] BUG: KFENCE: invalid free in .kfence_guarde=
d_free+0x2e4/0x530
> >>>>>> [   17.654379][   T58]
> >>>>>> [   17.654831][   T58] Invalid free of 0xc00000003c9c0000 (in kfen=
ce-#77):
> >>>>>> [   17.655358][   T58]  .kfence_guarded_free+0x2e4/0x530
> >>>>>> [   17.655775][   T58]  .__slab_free+0x320/0x5a0
> >>>>>> [   17.656039][   T58]  .test_double_free+0xe0/0x198
> >>>>>> [   17.656308][   T58]  .kunit_try_run_case+0x80/0x110
> >>>>>> [   17.656523][   T58]  .kunit_generic_run_threadfn_adapter+0x38/0=
x50
> >>>>>> [   17.657161][   T58]  .kthread+0x18c/0x1a0
> >>>>>> [   17.659148][   T58]  .ret_from_kernel_thread+0x58/0x70
> >>>>>> [   17.659869][   T58]
> >>> [...]
> >>>>>
> >>>>> Looks like something is prepending '.' to function names. We expect
> >>>>> the function name to appear as-is, e.g. "kfence_guarded_free",
> >>>>> "test_double_free", etc.
> >>>>>
> >>>>> Is there something special on ppc64, where the '.' is some conventi=
on?
> >>>>>
> >>>>
> >>>> I think so, see https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-e=
lf64abi.html#FUNC-DES
> >>>>
> >>>> Also see commit https://github.com/linuxppc/linux/commit/02424d896
> >>>
> >>> Thanks -- could you try the below patch? You'll need to define
> >>> ARCH_FUNC_PREFIX accordingly.
> >>>
> >>> We think, since there are only very few architectures that add a pref=
ix,
> >>> requiring <asm/kfence.h> to define something like ARCH_FUNC_PREFIX is
> >>> the simplest option. Let me know if this works for you.
> >>>
> >>> There an alternative option, which is to dynamically figure out the
> >>> prefix, but if this simpler option is fine with you, we'd prefer it.
> >>
> >> We have rediscovered this problem in basically every tracing / debuggi=
ng
> >> feature added in the last 20 years :)
> >>
> >> I think the simplest solution is the one tools/perf/util/symbol.c uses=
,
> >> which is to just skip a leading '.'.
> >>
> >> Does that work?
> >>
> >> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> >> index ab83d5a59bb1..67b49dc54b38 100644
> >> --- a/mm/kfence/report.c
> >> +++ b/mm/kfence/report.c
> >> @@ -67,6 +67,9 @@ static int get_stack_skipnr(const unsigned long stac=
k_entries[], int num_entries
> >>      for (skipnr =3D 0; skipnr < num_entries; skipnr++) {
> >>              int len =3D scnprintf(buf, sizeof(buf), "%ps", (void *)st=
ack_entries[skipnr]);
> >>
> >> +            if (buf[0] =3D=3D '.')
> >> +                    buf++;
> >> +
> >
> > Unfortunately this does not work, since buf is an array. We'd need an
> > offset, and it should be determined outside the loop. I had a solution
> > like this, but it turned out quite complex (see below). And since most
> > architectures do not require this, decided that the safest option is to
> > use the macro approach with ARCH_FUNC_PREFIX, for which Christophe
> > already prepared a patch and tested:
> > https://lore.kernel.org/linux-mm/20210304144000.1148590-1-elver@google.=
com/
> > https://lkml.kernel.org/r/afaec81a551ef15345cb7d7563b3fac3d7041c3a.1614=
868445.git.christophe.leroy@csgroup.eu
> >
> > Since KFENCE requires <asm/kfence.h> anyway, we'd prefer this approach
> > (vs.  dynamically detecting).
> >
> > Thanks,
> > -- Marco
> >
>
> What about

Sure something like that would work. But I explicitly did *not* want
to hard-code the '.' in non-arch code.

The choice is between:

1. ARCH_FUNC_PREFIX (as a matter of fact, the ARCH_FUNC_PREFIX patch
is already in -mm). Perhaps we could optimize it further, by checking
ARCH_FUNC_PREFIX in buf, and advancing buf like you propose, but I'm
not sure it's worth worrying about.

2. The dynamic solution that I proposed that does not use a hard-coded
'.' (or some variation thereof).

Please tell me which solution you prefer, 1 or 2 -- I'd like to stop
bikeshedding here. If there's a compelling argument for hard-coding
the '.' in non-arch code, please clarify, but otherwise I'd like to
keep arch-specific things out of generic code.

Thanks.

> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index 519f037720f5..5e196625fb34 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -43,7 +43,7 @@ static void seq_con_printf(struct seq_file *seq, const =
char *fmt, ...)
>   static int get_stack_skipnr(const unsigned long stack_entries[], int nu=
m_entries,
>                             const enum kfence_error_type *type)
>   {
> -       char buf[64];
> +       char _buf[64];
>         int skipnr, fallback =3D 0;
>
>         if (type) {
> @@ -65,7 +65,11 @@ static int get_stack_skipnr(const unsigned long stack_=
entries[], int num_entries
>         }
>
>         for (skipnr =3D 0; skipnr < num_entries; skipnr++) {
> -               int len =3D scnprintf(buf, sizeof(buf), "%ps", (void *)st=
ack_entries[skipnr]);
> +               char *buf =3D _buf;
> +               int len =3D scnprintf(_buf, sizeof(_buf), "%ps", (void *)=
stack_entries[skipnr]);
> +
> +               if (_buf[0] =3D=3D '.')
> +                       buf++, len--;
>
>                 if (str_has_prefix(buf, "kfence_") || str_has_prefix(buf,=
 "__kfence_") ||
>                     !strncmp(buf, "__slab_free", len)) {
> ---
>
> Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNM9o1s4O4v2T9HUohPdCDJzWcaC5KDrt_7BSVdTUQWagw%40mail.gmail.=
com.
