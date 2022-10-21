Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMVBZONAMGQELLGX4JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id A371B607D27
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 19:02:44 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id e10-20020a17090301ca00b00183d123e2a5sf1987282plh.14
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 10:02:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666371763; cv=pass;
        d=google.com; s=arc-20160816;
        b=tnJI3A/ZllH1oDxKGlErCzzDn7q+3WHB3VFfHPWnaYWqspkUXlV8dPpCiGUDClqerK
         c0pjA7kf1Dh1t5LrLk5bSMYhME+y4O2bgtqyzQrp6hw0IUpVcOTa6+0ohHk7H8FhSBv0
         7u+4AVs4tBBbf66bb4vgTNPxTj7Zuncalxt6DP4dVLnRVT1VVRF+1fALBVNLXqOMs4Do
         Y19o1J+gQ4Z46NPUXMA+NYVGwBM09fO01O6dSxEVTNkBMyGGAl++8h3oAZj/zxHQKqQz
         VXGT5eT02QKPFTWDRyladVHlV/+plkBOM7N965TSBc5BybThbA7mPT+FVqdFHojKioW7
         HPvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+7SVAFoygGa+eu2Be35wp+G8K2D0OzXA3bJ+fblyP7s=;
        b=Iw2+BoN83H7t5CATg1VVJkxk0hy8Ynv/Nv8J8Wmw/zaHjFgD6Pq0Mu+pW/uxpfyJjj
         g3BEVn36TQdOqKrHKTME0e/A90ukKwGmrjgD85oqeMdupxfQLogljzDo0a1M+25bX5/6
         PoGnTSANAl6HZ0u0mrtYpt6mrtgMRaOKtvZJUd+53Ns5tESOF4j+elNBFEzDKI+tWj87
         rBTkIbZBWZPz7omNjZk4wQK7J54H1NyzwiJJuy2Ju8k2+vzirh5OxgJTKS9VZGvRtEXW
         IGiqsMzJELkDT+/Ze8KH/e9RXnOJwTbLB76jiX4oMP+0pjfWnFyIiTcWtepSLfnZnaVr
         c//g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gbQE2uDh;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+7SVAFoygGa+eu2Be35wp+G8K2D0OzXA3bJ+fblyP7s=;
        b=KhmJCpPIwX1d1gz0L7wLzeAVIbEwclDcKQ6uWwmj18MK96rzsAONCQS+SSW4M4SD9f
         k1li4PCrQWnHXeL8DN8pugOFLZOJuDGQ1VCme2PgwjhPGoo7HPXrYO4YsrBP3Ib7isHU
         B0BAQiDyJWHBCPOB3EKtXB1Ob+GUMje424WtJS854rszyYO0ZMpuXa2KOLWtdNBJGcpF
         kwx1xAfGBy5vDuMxsBdvJFAQtL1ZOK63G6L48F2UNewEw/gqSWJlxw6tUkzpFgkK92I7
         iNqmi73h4UIgieKn5VHt9rEbCWZBrScFL58zKHM1IOjX3PAstJxEG60p0xyiOb3pwDsS
         3aoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=+7SVAFoygGa+eu2Be35wp+G8K2D0OzXA3bJ+fblyP7s=;
        b=hcMckgIhm20QGZqxT20vycSG+03YEKXLsC1BdUGRHWMiC9re6BZPXy+ogLPAXMsuPh
         nNBiPJv/rfAD1CUOb1rGvZGIy7RSghSiLafKZCuvMgSKNrZd2kgz1y+OENRH8w870EcH
         2HI8p0/tDdin6HA3pYLivmVc8fk7WaZqRy37Fi5l36LMhMUbL+6nST7+ANd9imCuA+u8
         l2DuLy2fXz4bktFEymROUzA3uICFWreRMPNBZxr6iedP1MKZeP0SfqkeufSDKdJgIYGc
         E/Hpw1qta8K3Uq7QIc4jLtNnW4WFxEzxUGl6LpoMA8flF8SaW0OVCZ2g98QsGRajiUAp
         zRpQ==
X-Gm-Message-State: ACrzQf28kBH6AMLvWYRRNegD28NGKltT2Ts0ydZnv0gmxrVtKvcVgoL3
	Y92YI5+COSGSDx3UKIQwwZU=
X-Google-Smtp-Source: AMsMyM67kWvAYwnKr6EWJKwdH9M5zf+M7KT52yHywdHNAC4ICcgdAg+0dbb8WKwSq5oP2WJDFm9Ynw==
X-Received: by 2002:a17:90b:4d8c:b0:20d:2935:7058 with SMTP id oj12-20020a17090b4d8c00b0020d29357058mr58534032pjb.86.1666371762996;
        Fri, 21 Oct 2022 10:02:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:2582:0:b0:557:cfb6:bcec with SMTP id l124-20020a622582000000b00557cfb6bcecls1463088pfl.9.-pod-prod-gmail;
 Fri, 21 Oct 2022 10:02:42 -0700 (PDT)
X-Received: by 2002:a05:6a00:1488:b0:563:9d96:660f with SMTP id v8-20020a056a00148800b005639d96660fmr20143816pfu.0.1666371762144;
        Fri, 21 Oct 2022 10:02:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666371762; cv=none;
        d=google.com; s=arc-20160816;
        b=r8oy9hzKyeAO8vTU768iIHYF0cqw6OFBpPnktWi7X/4AEWDJ9PLTBcNy2poVE4qGxH
         3bI/3vXOxYXAUQmjkQ2UBANBfxm58DwGFTgHBAJw4Zj98EiyR/qtggQAX/hS/EkpRYUK
         E6GQw23GM8Fy58UyI3HYqI3QgVdZ+8yLlg1p10v3E2R4/+guOUTE6XP/s4367CpVvv11
         /Fym0lSgVIUwykKy7K8x8f2H5D+AJ6oFfrUzSl0e1tRgp2yN0ejs8YjrRO4AoMM+YqE/
         xjmKSzLQISF9BpkiFdN61JcDnq/Ppqy2JeNoim2bNOR6/oQiUyei0U5LK8mlwlZebvl/
         Re4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UE0GQ1KPoluhkzNihpqKRt236ZCdBB8QJMFWTklYcAc=;
        b=rpzjnzCdH4Wi5+A0v04LJEVZ2YZQYUWurkX3C0GjNG78jOhPcJ9fgUZUD5hIVe2/et
         utAnPmGzlwqCwGqYn2opLqMPAHyH4gJ12DCPpEPwLLhCM2y17bXnyBQeDtKju40rcd0Q
         acqS9sIO+gaz3zCTkJcCk0Eiw47TUOr3EL0ouV0s14TuTOTPyTxNtZfNBdTHYoFq6Ceh
         iJyoD9tj+NT6I7UHgzN9I51VzPFDXwELa/kZadG9uK1HQC7TevEgBNVlq/6BwCoLpmUL
         SoehzhzZ3SHiDC5RkwiNPU5YwA6GQjvtF232kYdngOUxPCcEafZUxPRfeofM+NMSZ2P8
         ghJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gbQE2uDh;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2e.google.com (mail-yb1-xb2e.google.com. [2607:f8b0:4864:20::b2e])
        by gmr-mx.google.com with ESMTPS id d2-20020a170903230200b001811a197774si1012280plh.8.2022.10.21.10.02.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Oct 2022 10:02:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) client-ip=2607:f8b0:4864:20::b2e;
Received: by mail-yb1-xb2e.google.com with SMTP id i127so4014497ybc.11
        for <kasan-dev@googlegroups.com>; Fri, 21 Oct 2022 10:02:42 -0700 (PDT)
X-Received: by 2002:a25:a088:0:b0:6ca:33ff:5b30 with SMTP id
 y8-20020a25a088000000b006ca33ff5b30mr9002381ybh.242.1666371761519; Fri, 21
 Oct 2022 10:02:41 -0700 (PDT)
MIME-Version: 1.0
References: <20220915150417.722975-19-glider@google.com> <20221019173620.10167-1-youling257@gmail.com>
 <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com>
 <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com>
 <CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht+TCg1Q@mail.gmail.com>
 <Y1BXQlu+JOoJi6Yk@elver.google.com> <CAOzgRdY6KSxDMRJ+q2BWHs4hRQc5y-PZ2NYG++-AMcUrO8YOgA@mail.gmail.com>
 <Y1Bt+Ia93mVV/lT3@elver.google.com> <CAG_fn=WLRN=C1rKrpq4=d=AO9dBaGxoa6YsG7+KrqAck5Bty0Q@mail.gmail.com>
 <CAOzgRdb+W3_FuOB+P_HkeinDiJdgpQSsXMC4GArOSixL9K5avg@mail.gmail.com>
 <CANpmjNMUCsRm9qmi5eydHUHP2f5Y+Bt_thA97j8ZrEa5PN3sQg@mail.gmail.com>
 <CAOzgRdZsNWRHOUUksiOhGfC7XDc+Qs2TNKtXQyzm2xj4to+Y=Q@mail.gmail.com>
 <CANpmjNPUqVwHLVg5weN3+m7RJ7pCfDjBqJ2fBKueeMzKn=R=jA@mail.gmail.com> <CAOzgRdYr82TztbX4j7SDjJFiTd8b1B60QZ7jPkNOebB-jO9Ocg@mail.gmail.com>
In-Reply-To: <CAOzgRdYr82TztbX4j7SDjJFiTd8b1B60QZ7jPkNOebB-jO9Ocg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 21 Oct 2022 10:02:05 -0700
Message-ID: <CAG_fn=VE4qrXhLzEkNR_8PcO9N4AYYhNaXYvZNffvVEo7AHr-A@mail.gmail.com>
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
To: youling 257 <youling257@gmail.com>
Cc: Marco Elver <elver@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Alexei Starovoitov <ast@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Biggers <ebiggers@kernel.org>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: multipart/alternative; boundary="000000000000e934c005eb8e68d0"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gbQE2uDh;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2e as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

--000000000000e934c005eb8e68d0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Fri, Oct 21, 2022 at 8:19 AM youling 257 <youling257@gmail.com> wrote:

> CONFIG_DEBUG_INFO=3Dy
> CONFIG_AS_HAS_NON_CONST_LEB128=3Dy
> # CONFIG_DEBUG_INFO_NONE is not set
> CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=3Dy
> # CONFIG_DEBUG_INFO_DWARF4 is not set
> # CONFIG_DEBUG_INFO_DWARF5 is not set
> # CONFIG_DEBUG_INFO_REDUCED is not set
> # CONFIG_DEBUG_INFO_COMPRESSED is not set
> # CONFIG_DEBUG_INFO_SPLIT is not set
> # CONFIG_DEBUG_INFO_BTF is not set
> # CONFIG_GDB_SCRIPTS is not set
>
> perf top still no function name.
>
Will it help if you disable CONFIG_RANDOMIZE_BASE?
(if it doesn't show the symbols, at least we'll be able to figure out the
offending function by running nm)


>
> 12.90%  [kernel]              [k] 0xffffffff833dfa64
>      3.78%  [kernel]              [k] 0xffffffff8285b439
>      3.61%  [kernel]              [k] 0xffffffff83370254
>      2.32%  [kernel]              [k] 0xffffffff8337025b
>      1.88%  bluetooth.default.so  [.] 0x000000000000d09d
>
> 2022-10-21 15:37 GMT+08:00, Marco Elver <elver@google.com>:
> > On Thu, 20 Oct 2022 at 23:39, youling 257 <youling257@gmail.com> wrote:
> >>
> >> PerfTop:    8253 irqs/sec  kernel:75.3%  exact: 100.0% lost: 0/0 drop:
> >> 0/17899 [4000Hz cycles],  (all, 8 CPUs)
> >>
> -------------------------------------------------------------------------=
---------------------------------------------------------------------------=
-----------------------------------------------------------
> >>
> >>     14.87%  [kernel]              [k] 0xffffffff941d1f37
> >>      6.71%  [kernel]              [k] 0xffffffff942016cf
> >>
> >> what is 0xffffffff941d1f37?
> >
> > You need to build with debug symbols:
> > CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=3Dy
> >
> > Then it'll show function names.
> >
> >> 2022-10-21 14:16 GMT+08:00, Marco Elver <elver@google.com>:
> >> > On Thu, 20 Oct 2022 at 22:55, youling 257 <youling257@gmail.com>
> wrote:
> >> >>
> >> >> How to use perf tool?
> >> >
> >> > The simplest would be to try just "perf top" - and see which kernel
> >> > functions consume most CPU cycles. I would suggest you compare both
> >> > kernels, and see if you can spot a function which uses more cycles% =
in
> >> > the problematic kernel.
> >> >
> >
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVE4qrXhLzEkNR_8PcO9N4AYYhNaXYvZNffvVEo7AHr-A%40mail.gmai=
l.com.

--000000000000e934c005eb8e68d0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote">=
<div dir=3D"ltr" class=3D"gmail_attr">On Fri, Oct 21, 2022 at 8:19 AM youli=
ng 257 &lt;<a href=3D"mailto:youling257@gmail.com">youling257@gmail.com</a>=
&gt; wrote:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0px =
0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">CONF=
IG_DEBUG_INFO=3Dy<br>
CONFIG_AS_HAS_NON_CONST_LEB128=3Dy<br>
# CONFIG_DEBUG_INFO_NONE is not set<br>
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=3Dy<br>
# CONFIG_DEBUG_INFO_DWARF4 is not set<br>
# CONFIG_DEBUG_INFO_DWARF5 is not set<br>
# CONFIG_DEBUG_INFO_REDUCED is not set<br>
# CONFIG_DEBUG_INFO_COMPRESSED is not set<br>
# CONFIG_DEBUG_INFO_SPLIT is not set<br>
# CONFIG_DEBUG_INFO_BTF is not set<br>
# CONFIG_GDB_SCRIPTS is not set<br>
<br>
perf top still no function name.<br></blockquote><div>Will it help if you d=
isable CONFIG_RANDOMIZE_BASE?</div><div>(if it doesn&#39;t show the symbols=
, at least we&#39;ll be able to figure out the offending function by runnin=
g nm)</div><div>=C2=A0</div><blockquote class=3D"gmail_quote" style=3D"marg=
in:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1e=
x">
<br>
12.90%=C2=A0 [kernel]=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 [k] 0=
xffffffff833dfa64<br>
=C2=A0 =C2=A0 =C2=A03.78%=C2=A0 [kernel]=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 [k] 0xffffffff8285b439<br>
=C2=A0 =C2=A0 =C2=A03.61%=C2=A0 [kernel]=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 [k] 0xffffffff83370254<br>
=C2=A0 =C2=A0 =C2=A02.32%=C2=A0 [kernel]=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 [k] 0xffffffff8337025b<br>
=C2=A0 =C2=A0 =C2=A01.88%=C2=A0 <a href=3D"http://bluetooth.default.so" rel=
=3D"noreferrer" target=3D"_blank">bluetooth.default.so</a>=C2=A0 [.] 0x0000=
00000000d09d<br>
<br>
2022-10-21 15:37 GMT+08:00, Marco Elver &lt;<a href=3D"mailto:elver@google.=
com" target=3D"_blank">elver@google.com</a>&gt;:<br>
&gt; On Thu, 20 Oct 2022 at 23:39, youling 257 &lt;<a href=3D"mailto:youlin=
g257@gmail.com" target=3D"_blank">youling257@gmail.com</a>&gt; wrote:<br>
&gt;&gt;<br>
&gt;&gt; PerfTop:=C2=A0 =C2=A0 8253 irqs/sec=C2=A0 kernel:75.3%=C2=A0 exact=
: 100.0% lost: 0/0 drop:<br>
&gt;&gt; 0/17899 [4000Hz cycles],=C2=A0 (all, 8 CPUs)<br>
&gt;&gt; ------------------------------------------------------------------=
---------------------------------------------------------------------------=
------------------------------------------------------------------<br>
&gt;&gt;<br>
&gt;&gt;=C2=A0 =C2=A0 =C2=A014.87%=C2=A0 [kernel]=C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 [k] 0xffffffff941d1f37<br>
&gt;&gt;=C2=A0 =C2=A0 =C2=A0 6.71%=C2=A0 [kernel]=C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 [k] 0xffffffff942016cf<br>
&gt;&gt;<br>
&gt;&gt; what is 0xffffffff941d1f37?<br>
&gt;<br>
&gt; You need to build with debug symbols:<br>
&gt; CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=3Dy<br>
&gt;<br>
&gt; Then it&#39;ll show function names.<br>
&gt;<br>
&gt;&gt; 2022-10-21 14:16 GMT+08:00, Marco Elver &lt;<a href=3D"mailto:elve=
r@google.com" target=3D"_blank">elver@google.com</a>&gt;:<br>
&gt;&gt; &gt; On Thu, 20 Oct 2022 at 22:55, youling 257 &lt;<a href=3D"mail=
to:youling257@gmail.com" target=3D"_blank">youling257@gmail.com</a>&gt; wro=
te:<br>
&gt;&gt; &gt;&gt;<br>
&gt;&gt; &gt;&gt; How to use perf tool?<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; The simplest would be to try just &quot;perf top&quot; - and =
see which kernel<br>
&gt;&gt; &gt; functions consume most CPU cycles. I would suggest you compar=
e both<br>
&gt;&gt; &gt; kernels, and see if you can spot a function which uses more c=
ycles% in<br>
&gt;&gt; &gt; the problematic kernel.<br>
&gt;&gt; &gt;<br>
&gt;<br>
</blockquote></div><br clear=3D"all"><div><br></div>-- <br><div dir=3D"ltr"=
 class=3D"gmail_signature"><div dir=3D"ltr">Alexander Potapenko<br>Software=
 Engineer<br><br>Google Germany GmbH<br>Erika-Mann-Stra=C3=9Fe, 33<br>80636=
 M=C3=BCnchen<br><br>Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebasti=
an<br>Registergericht und -nummer: Hamburg, HRB 86891<br>Sitz der Gesellsch=
aft: Hamburg<br></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAG_fn%3DVE4qrXhLzEkNR_8PcO9N4AYYhNaXYvZNffvVEo7AHr-A%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAG_fn%3DVE4qrXhLzEkNR_8PcO9N4AYYhNaXYvZNffvVEo7A=
Hr-A%40mail.gmail.com</a>.<br />

--000000000000e934c005eb8e68d0--
