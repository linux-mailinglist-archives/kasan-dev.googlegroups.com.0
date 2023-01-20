Return-Path: <kasan-dev+bncBD4LX4523YGBBCPGVGPAMGQEOA2D6OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id EE3246752D3
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 11:55:07 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id pm1-20020a17090b3c4100b002292b6258a0sf2429513pjb.1
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 02:55:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674212106; cv=pass;
        d=google.com; s=arc-20160816;
        b=W2/+V01RUGBAhVa46woR4kYMnluYB4liNZ4XD9Z8b/bheGP77qc87j0Yh897JhT2qx
         yRq6EkUApYzaplSSER6+74dxsUaxQtd7l6bjxfY1FOpnMFQ2tRIOxqNva5uA89GCxJDi
         XgO862k8KFgSW3qUn/7Qx/nlOIPNd0p5J7RiKmXxmo+jJBDkZjbxg/mkivdDqGEVNcBo
         4JSfkmMY+32h6NTpRsbjoiFtKIa0p3zsMzBPUq8BndkKjYo8+NQC9mTpXnD3ORXKLTze
         c5RE9GVIMdcRkPDCV+5xtP2XXBMBa/djuTNa7wjjo43eYr+zcEAmB0HAjjtzv9cn/yUa
         aNdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=wxATh4jqpZHKgBJHXRGNBTJhPjLybEwnIOELIzZt2yM=;
        b=QowekfLYvK+lRW575yHSiE7Hl5RC3Cemr8MlQOpwGiOQAdSWIeELmrbYsdjhteBFJR
         MP+QJTJnpAh8YB8vEU1if45lQmd5RPYHbdfKFt2UwKgrAiio6bI/f/59QND6Id2+c7SO
         6k6jxCyvXF7Ib5dQcocqNrhR/+3rcsGWHk/ZuyBWE8iBKov/42qfcqZBqpsKwkSy33f/
         FXyMwsKVQNuZz9rkGBra8tchMAq4p64wa38c82yl6f8LQcoZw1UT0KkMemItPFoKtSln
         QIlM5Q9Nz038Bivvj5oYcT5I3Ll31nLuHGxMHd9Imh19l2ww7fqdhQo6TZpVqdk0td7R
         ZUfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wxATh4jqpZHKgBJHXRGNBTJhPjLybEwnIOELIzZt2yM=;
        b=fDDO4GJ1grwXVLbAvJGSQFztaMPIOELeLXEySn4agSFY5ZXxGp2nhmEVcWAjXs/N7d
         yyvc/5grJWB7EmLzhxxBYrOJU/ZLcuDGumIdEHmHdqj7yPos5t+jHWqcvhmQXm5qAKRT
         tzTjTOnyz9GTjhMbINpFHX4GPphFJule2D57cUfieMYO2WtjO+05Cc9XQet/hnzxL9Ve
         SWnnTiPKZVCfVEH8Wj5tZwlUoyTecHTM3+jIeLtTMCWFAue/SpcMaTrUk1+nezndkYSX
         9c7Qbtk+ATqJzf4BgLXbobmYnyOrvs97ey7hm5BCMxkvTzcRDAjhoBkTSXwKr9+O/X/9
         v9cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wxATh4jqpZHKgBJHXRGNBTJhPjLybEwnIOELIzZt2yM=;
        b=4Cs34eaP4E5jEbH0bH83sw5okkXzNdyQ83HdcdbnrKtkHhD2lwBvnmSIIIyXO3BThL
         erNi60CX4vw1It36bhqF3EkZqGiNzOeDeZBkVYWf0/quM8KnyS+2n787AGayMnrlfSyg
         1df4z0A+p6ZyzWRQHKc6xOSibvE7bw/cLwLnhOSuiqMrSNt+JUGroupjhWAAaoJGQZT5
         /DbSGeMUD4MhbaQqLYP1reT+3Kj04Az6ym8JCA4LJFlL/E69M+pjwBOZAhFPaHjlbcQ8
         bVT4ZofxhKuHIQZc5BFFdSMVw9+iihZfhDQffHb/rjk5QPrWVMgAA8seMS61OedWz+Yq
         Y0iQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koLnaUWtk5iE+lZ8dEHX2YibcOq6n2rMF64FtNTuaasR2VNajIX
	XLinjtfkMNEHASfMi6u8Z14=
X-Google-Smtp-Source: AMrXdXuoECwPyGA13XsGxk0l/VoQaN8s1fL/h+2L1Mjzist17ya+sEPXLyQz2nMKso+qEHY0XqeE3Q==
X-Received: by 2002:a17:902:8f82:b0:193:15e4:8309 with SMTP id z2-20020a1709028f8200b0019315e48309mr1514596plo.32.1674212106001;
        Fri, 20 Jan 2023 02:55:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d507:b0:22b:b830:313 with SMTP id
 t7-20020a17090ad50700b0022bb8300313ls198488pju.3.-pod-control-gmail; Fri, 20
 Jan 2023 02:55:05 -0800 (PST)
X-Received: by 2002:a17:90b:4f8c:b0:22b:b4d5:ca1f with SMTP id qe12-20020a17090b4f8c00b0022bb4d5ca1fmr835294pjb.12.1674212105134;
        Fri, 20 Jan 2023 02:55:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674212105; cv=none;
        d=google.com; s=arc-20160816;
        b=q9LVSaCJx4AoQVcsouz/u29loFmdWkbQoww0t6rbwG+XnZ1gILJoondc6YBJmD+pUd
         A8txPczcNnClnJRwDmiKmQRabtyrFvQSPMgwrB/xo5pI2qAKQuYYVf7I0ODbzCnrVuWF
         KM5LS+yY8Kv27RVWr201WQ3h0iWxG5pNw3tvTvRtKW+zkocPA0KUz4/j7s3llanWH4Ks
         SpTDW7jpqBDXoEWJTZAuYR6EQK/p2dF/nb4cUj2JjdnbwrwKKBlipCqQGxl5n9HgCMi3
         dXh6xEUFbkruWCMegElI7EqslV6kOc4bLOvBCQ6Xu74z+FYcEcfe6DUYajow+iXJLOdy
         X15Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=S/EOSyVIrS5X23ODndRK0e19RWEfHBY5XhZ0AtnhW0A=;
        b=FyKzDs666wxbIHrtY3ELSS6KDhlR8VnF4ZLmpXuzadCfoeeqvfWIXWNatYhR/GOwKN
         uB7A6THRT17jePtGrTmMBLtoEo7F28WBrpQej6QgCNWgSGoX1843QAaoFd8fklsNMefh
         9sfqMuCf6WXCcUDE3GM0UvOHMmdW1GhyMGS+dSvFvQh6AHaPYq5Y18CQPJLbxDWKjNvn
         hRrtSqR2u5J3olSZoaISzaHQv2jXryoKJcusP+jZVa9H4Cvnou1LSw15LBUYmrJp7tUa
         93tEEW1Q2UMX5n1KUaxH39zZLT8EqMbXFdeUy3v09CUOsF4JLmhiHsal+g46ZNw7P8v8
         DFaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id ml21-20020a17090b361500b0022627a153aesi217549pjb.3.2023.01.20.02.55.04
        for <kasan-dev@googlegroups.com>;
        Fri, 20 Jan 2023 02:55:04 -0800 (PST)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost.localdomain [127.0.0.1])
	by gate.crashing.org (8.14.1/8.14.1) with ESMTP id 30KArkBe026992;
	Fri, 20 Jan 2023 04:53:46 -0600
Received: (from segher@localhost)
	by gate.crashing.org (8.14.1/8.14.1/Submit) id 30KArgxi026991;
	Fri, 20 Jan 2023 04:53:42 -0600
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Fri, 20 Jan 2023 04:53:41 -0600
From: Segher Boessenkool <segher@kernel.crashing.org>
To: Rob Landley <rob@landley.net>
Cc: "Michael.Karcher" <Michael.Karcher@fu-berlin.de>,
        John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>,
        Geert Uytterhoeven <geert@linux-m68k.org>,
        linux-xtensa@linux-xtensa.org, Arnd Bergmann <arnd@arndb.de>,
        linux-sh@vger.kernel.org, linux-wireless@vger.kernel.org,
        linux-mips@vger.kernel.org, amd-gfx@lists.freedesktop.org,
        linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
        Michael Karcher <kernel@mkarcher.dialup.fu-berlin.de>,
        linux-f2fs-devel@lists.sourceforge.net, linuxppc-dev@lists.ozlabs.org,
        linux-arm-kernel@lists.infradead.org, linux-media@vger.kernel.org
Subject: Re: Calculating array sizes in C - was: Re: Build regressions/improvements in v6.2-rc1
Message-ID: <20230120105341.GI25951@gate.crashing.org>
References: <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg> <c05bee5d-0d69-289b-fe4b-98f4cd31a4f5@physik.fu-berlin.de> <CAMuHMdXNJveXHeS=g-aHbnxtyACxq1wCeaTg8LbpYqJTCqk86g@mail.gmail.com> <3800eaa8-a4da-b2f0-da31-6627176cb92e@physik.fu-berlin.de> <CAMuHMdWbBRkhecrqcir92TgZnffMe8ku2t7PcVLqA6e6F-j=iw@mail.gmail.com> <429140e0-72fe-c91c-53bc-124d33ab5ffa@physik.fu-berlin.de> <CAMuHMdWpHSsAB3WosyCVgS6+t4pU35Xfj3tjmdCDoyS2QkS7iw@mail.gmail.com> <0d238f02-4d78-6f14-1b1b-f53f0317a910@physik.fu-berlin.de> <1732342f-49fe-c20e-b877-bc0a340e1a50@fu-berlin.de> <0f51dac4-836b-0ff2-38c6-5521745c1c88@landley.net>
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <0f51dac4-836b-0ff2-38c6-5521745c1c88@landley.net>
User-Agent: Mutt/1.4.2.3i
X-Original-Sender: segher@kernel.crashing.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as
 permitted sender) smtp.mailfrom=segher@kernel.crashing.org
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

On Thu, Jan 19, 2023 at 09:31:21PM -0600, Rob Landley wrote:
> On 1/19/23 16:11, Michael.Karcher wrote:
> > I don't see a clear bug at this point. We are talking about the C expre=
ssion
> >=20
> >  =C2=A0 __same_type((void*)0, (void*)0)? 0 : sizeof((void*)0)/sizeof(*(=
(void*0))

(__same_type is a kernel macro, it expands to something with
__builtin_compatible_type()).

> *(void*) is type "void" which does not have a size.

It has size 1, in GCC, so that you can do arithmetic on pointers to
void.  This is a long-standing and very widely used GCC extension.

"""
6.24 Arithmetic on 'void'- and Function-Pointers
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D

In GNU C, addition and subtraction operations are supported on pointers
to 'void' and on pointers to functions.  This is done by treating the
size of a 'void' or of a function as 1.

 A consequence of this is that 'sizeof' is also allowed on 'void' and on
function types, and returns 1.

 The option '-Wpointer-arith' requests a warning if these extensions are
used.
"""

> The problem is gcc "optimizing out" an earlier type check, the same way i=
t
> "optimizes out" checks for signed integer math overflowing, or "optimizes=
 out" a
> comparison to pointers from two different local variables from different
> function calls trying to calculate the amount of stack used, or "optimize=
s out"

Are you saying something in the kernel code here is invalid code?
Because your other examples are.

> using char *x =3D (char *)1; as a flag value and then doing "if (!(x-1)) =
because
> it can "never happen"...

Like here.  And no, this is not allowed by -fno-strict-aliasing.

> > I suggest to file a bug against gcc complaining about a "spurious=20
> > warning", and using "-Werror -Wno-error-sizeof-pointer-div" until gcc i=
s=20
> > adapted to not emit the warning about the pointer division if the resul=
t=20
> > is not used.

Yeah.  If the first operand of a conditional operator is non-zero, the
second operand is not evaluated, and if the first is zero, the third
operand is not evaluated.  It is better if we do not warn about
something we do not evaluate.  In cases like here where it is clear at
compile time which branch is taken, that shouldn't be too hard.

Can someone please file a GCC PR?  With reduced testcase preferably.


Segher

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230120105341.GI25951%40gate.crashing.org.
