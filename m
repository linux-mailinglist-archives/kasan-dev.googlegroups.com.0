Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7P24G3AMGQEFSVOAHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 880FE96C27F
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2024 17:32:15 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2d8a1e91afasf3807864a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2024 08:32:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725463934; cv=pass;
        d=google.com; s=arc-20240605;
        b=UpfKwj/TN0HHZRnyOdkUA4h2pjPgOYn3Ty2eba0jVmnpmeJGGmGEpQ4JIpq5kwfqLT
         9qUYqtF7BhStSw7KsUXJVg6Jbu26q+GnrJTbjXQiTXcZv7spN5mhyF9Q3FGyg9rQhATG
         AVt2SzQUNY5+vplWFsKhZl7JK2T5IBNsIpdVz1ZCTU5Wc7QWWFH8uG9p4LUjADs7IIZk
         dn6ZFSZnWRFSYV0cr39WTIzqbS/tdkEs5e5GhSDTyxIsjHktLxmm3UFBZ/iNYSnwUjFG
         oGdAq7gXwH/aPIbYUIMjhXaJI7gpDTlMf2tt2q4eEnwnOmFih47paH7BQJP4dlgN6z94
         o6LA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iBgXS75MzLsJrDDIteYZnxL39jYJXHJWD2EAo2CEUmQ=;
        fh=5zG0d5PLETF2xUYdkxkgm+MdacW0F6on90eSlB1jzRI=;
        b=OtAo9peO4rsQBUeGmXQmw2DZb6mBNfBp/cPPOK7m4SDMPUA0SY0Z7Hx51tmTrZv9Lt
         sCQAzzgVlK4pW8+r735sTRZu+R/4zPv2Z28KsCndkIkcmCLzMSV3X/1dlPn4fOlBOBeP
         ky/nxXYXcfiaf1xpFwJUyBz5CYHN5zp75TrbxZPVBwJu1G0F/C3TJUE4qSNqwMvsr0On
         OKOwfovHVbMjPCm3Pb5FydzGhRnWOmiCerwAupCfnkDKH4bmIzrhJH35t7fIJLdVtXx4
         94NXan2jrWlApEW7IDwloB9IkHk0uQJ28BbW8VEFAzwszwRbGTp+QVpBIMC81cNF828A
         gn0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kgrE6Q0x;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725463934; x=1726068734; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iBgXS75MzLsJrDDIteYZnxL39jYJXHJWD2EAo2CEUmQ=;
        b=i6wWf/a0eUvdwAaggxbr3cX/wvVBJklGJEJqkPQE751hEp8NNhEEsowwfMLvB2Q+RK
         wa6L+CYkIXpVCTh+vynnWLHgIZRBtFk5raUTKBP1Q4+CD0SUFfFxPb2tpmIG5q99t5Ku
         +/J6h/KfZPTRwwu77s0opYO1/PPse/bVR3O3QNjT6+ke7ovMdpqsKjp8t/76zAlepXnW
         mIVXFH2FR7MUBY3ikFlFLIjdtYEVhi3uyTj+qmcMnBKiv44TTYNImNYsdsn8qPPy1kT5
         QfmNWycDzkga1MtpZsOKSbfdfvuHKgHSDGzEPyrTv4PvzHbXKi9/8H8Z4KieQJ0Zeq/Q
         VJwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725463934; x=1726068734;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iBgXS75MzLsJrDDIteYZnxL39jYJXHJWD2EAo2CEUmQ=;
        b=UgAOXPjEFrm3194tfqDWPTMtE0+eo7Xg/JxlPwl4BdoGLII6gdNrv/BcBvnKpiEswt
         SATlO87yvZqyWu+vrgZoTmRr2ixsCpW0hV3RZ+77cmJxhEjck+3AIayICBk67AY2hA9Q
         GAsTPQV4pShgcKwTDzxlbwdoSucNJ4D2+D0yf3ytZAPs5NbxN6vSyzEq7T1BY+lM/jRa
         AA72rxQ43nRTTCrGbWWMM5VHrIKk4ZlrPOosaxfMqmf6VDzdLCK96aWp7xFwKc7HTF/9
         1EiL/tFoTFpEH6h+PeMWcZR6WR8eh5T3rGzs+7Fce1DXubNoMGqxNnLRtGZIgM+4UrHW
         hEmg==
X-Forwarded-Encrypted: i=2; AJvYcCXzt490RO8txWrHYVz7HnqOwN+/oTPC44t+7p9GlJYLz+qva2xA2TH0TY4WIF986hihSBzGHQ==@lfdr.de
X-Gm-Message-State: AOJu0YylXIV7G4f/utIQSNPufhrHM5QtQwfr4a5NH8UR6Fm4mq10/EBF
	SwZhONVxOWglUibCy22xWzEwb++P+JOeXTwgLELJ4brCyv1oc8HU
X-Google-Smtp-Source: AGHT+IF7zf87WC/iSUSLLe+S+r/+O4nUO7wQ3squ2VdxvF3zq5CNiAcmoNCRDY90v9cGAVFzyvAx0Q==
X-Received: by 2002:a17:90a:c257:b0:2cb:4c25:f941 with SMTP id 98e67ed59e1d1-2d89051c15bmr12750380a91.17.1725463934029;
        Wed, 04 Sep 2024 08:32:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c70a:b0:2d8:bbfe:6384 with SMTP id
 98e67ed59e1d1-2daae9b986dls2660a91.2.-pod-prod-09-us; Wed, 04 Sep 2024
 08:32:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU31ELvoHVbSp1WTFFtf1cRqq2hojcZXaiQ3Joy4bOfUMjvQ06ZepMXIw15zUM8TwB+7PdhrWVs1w8=@googlegroups.com
X-Received: by 2002:a17:90b:3b8d:b0:2d3:c664:e253 with SMTP id 98e67ed59e1d1-2d8904ec7cfmr14770087a91.10.1725463932684;
        Wed, 04 Sep 2024 08:32:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725463932; cv=none;
        d=google.com; s=arc-20240605;
        b=Yb3mCw8t0ATvkUOUu/m7i3tILENGKDo7QlRs53NEz+Oagwb5gyfG2I9yCDXm6XM5fn
         RSnJoawTtW6XRnyPy4IMZ6ZwXMzVDd1n51hnMj1FbGFPRzvuuOvyDkByzwTRxaV2pZuA
         Lyi7aTqviQEUSIehBBIH9Wg5NAbqSvLHk3UJIGXbZ+C0EGYnDxkMwiOqzfHThGbthVcj
         KwhDActu8SymE5RsmlsoOlT/yn0xPIguNTQd5j9pO+fdle1uYk4KAEUIaqnYm7r+kAka
         wQ1xxq7iMYlQifuOatBiNKXzD5u/4Ef811WX95dCl4xLIltNv2isDIDMKISzMCaO1dls
         wwRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=XM/IFpi5RYBm4yhH7l5IBkkn9oGxsE6HXM9tVqpW5us=;
        fh=HOjOpPu9OH2pG+E1/7tADCnDfk5g2FH6GaPqKHHpomA=;
        b=LmpcP2r/eYR5HImi5G83oK0+QnwGVS1I59HYhwL4nHmAk1tWam9zilKsfyTPmkxqcd
         A1sCqzgSsbnBd0uosJHG1W5nGSvhHjTFUscFRRBoExsjeWIZGbKZKZ3GFLTXzscfEGCV
         B7vtrdRVsRWI0/WGcz885+r5ZP+a6iCoWzQHyoIXBXvgz5bkNbXpmJuDYtKAn7K7YROS
         Vj5Ea/9mphOEllby/3b2XDmQ3eIoZV+3vnQUh02nkL0/v2ZY1SIU+Wg08lwQ8eJXZmb7
         TX0GFSbGlP0AE0/Na2EiaJhqFy95ZUO96T7WrYzKv9wo/r60mzCTgVMkrXq+ZS9UC5OZ
         0QeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kgrE6Q0x;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2d892a14c08si428642a91.3.2024.09.04.08.32.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Sep 2024 08:32:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id 6a1803df08f44-6bf9db9740aso30034886d6.2
        for <kasan-dev@googlegroups.com>; Wed, 04 Sep 2024 08:32:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUL+J6qL466LML2AXFHEWkbXBj7JKH256reUVA1CZmBCsSTnjceJ0I03s9yWu9GXxyiWU6HWi4QnvU=@googlegroups.com
X-Received: by 2002:a05:6214:5d87:b0:6c3:5dcf:bf5a with SMTP id
 6a1803df08f44-6c35dcfc5e2mr151765236d6.37.1725463931324; Wed, 04 Sep 2024
 08:32:11 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000f362e80620e27859@google.com> <20240830095254.GA7769@willie-the-truck>
 <86wmjwvatn.wl-maz@kernel.org> <CANp29Y6EJXFTOy6Pd466r+RwzaGHe7JQMTaqMPSO2s7ubm-PKw@mail.gmail.com>
 <CAG_fn=UbWvN=FiXjU_QZKm_qDhxU8dZQ4fgELXsRsPCj4YHp9A@mail.gmail.com>
 <86seugvi25.wl-maz@kernel.org> <d7a686a5-dfc8-4e26-8e4a-11f90fbf6d68@sifive.com>
In-Reply-To: <d7a686a5-dfc8-4e26-8e4a-11f90fbf6d68@sifive.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Sep 2024 17:31:31 +0200
Message-ID: <CAG_fn=W_Vde+fXhLGDdt0Mu+6bG8LxLew052MdFy2Lqiyj1qLA@mail.gmail.com>
Subject: Re: [syzbot] [arm?] upstream test error: KASAN: invalid-access Write
 in setup_arch
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Marc Zyngier <maz@kernel.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Aleksandr Nogikh <nogikh@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Will Deacon <will@kernel.org>, 
	syzbot <syzbot+908886656a02769af987@syzkaller.appspotmail.com>, 
	catalin.marinas@arm.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=kgrE6Q0x;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

> >>>> Who knows enough about KASAN to dig into this?
> >>
> >> This looks related to Samuel's "arm64: Fix KASAN random tag seed
> >> initialization" patch that landed in August.
> >
> > f75c235565f9 arm64: Fix KASAN random tag seed initialization
> >
> > $ git describe --contains f75c235565f9 --match=3Dv\*
> > v6.11-rc4~15^2
> >
> > So while this is in -rc4, -rc6 still has the same issue (with GCC --
> > clang is OK).
>
> I wouldn't expect it to be related to my patch. smp_build_mpidr_hash() ge=
ts
> called before kasan_init_sw_tags() both before and after applying my patc=
h.

Hm, you are right, this problem indeed dates back to v6.9 or earlier.

> Since the variable in question is a stack variable, the random tag is gen=
erated
> by GCC, not the kernel function.
>
> Since smp_build_mpidr_hash() is inlined into setup_arch(), which also cal=
ls
> kasan_init(), maybe the issue is that GCC tries to allocate the local var=
iable
> and write the tag to shadow memory before kasan_init() actually sets up t=
he
> shadow memory?

Should it be inlined at all?
setup_arch() is a __no_sanitize_address function, and
smp_build_mpidr_hash() is an instrumented one.
The latter is not supposed to be inlined into the former, unless the
latter is always_inline
(https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D67368,
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D89124).

The report seems to go away if I mark smp_build_mpidr_hash() as noinline.
This doesn't explain, though, why Clang build doesn't work at all...

>
> Regards,
> Samuel
>
> >> I am a bit surprised the bug is reported before the
> >> "KernelAddressSanitizer initialized" banner is printed - I thought we
> >> shouldn't be reporting anything until the tool is fully initialized.
> >
> > Specially if this can report false positives...
> >
> > Thanks,
> >
> >       M.
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
kasan-dev/CAG_fn%3DW_Vde%2BfXhLGDdt0Mu%2B6bG8LxLew052MdFy2Lqiyj1qLA%40mail.=
gmail.com.
