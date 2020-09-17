Return-Path: <kasan-dev+bncBDV37XP3XYDRBR4FRX5QKGQEPONEHNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 2ACE126D9CD
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 13:04:41 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id r24sf1133403pgu.23
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 04:04:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600340679; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z/3ph7u/BMS9JAjETlkig2bc5EgOx38W9215V2YLA7aBYTBevIs7rAkwMZgZlt7d15
         p2A9R75iSkXJdbgIl8ydddlpaQ/oE+eSgcDCuEAMK7AdTdH6+2pmDt3AzK0XVBirUle1
         qIlQywqID1Bx6zFtUcRaIgUzoDD4qehCZJyZoKct9VTyQAObxnmCArKV3qSsrY6nVMOe
         5BgxpfEVHmicUE7++igyKBMXR0ji/TDUCdz3EDRghxdA0kTE/c2mafqr3coyWwbjw+LW
         khfMc2nlFYCQQWmQBaBla3yBzWUt+5qLPKotEsOCMclm8UwZOwrgg1wHEnqf2XwcHu6P
         aiog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=QCP0icBQO9KvMD3r6U6drZz4tEDtEOAyQGipSwM6jPA=;
        b=TuS4WdZwqfcjyt0mHzgQFMm8haukpuxTKWRdpH4v0nc0EjYUA7cv6bIJdd/bxtckMJ
         uKbDYtDPgUFu6emTA2DP8rmn4HfzCz6HSTNEomlypqJgDMnYRRlbCuKpC0HlWJg47M4F
         Iuyy6GZSPCrTXE3ORRJzLz3/JldZLvHuZ5lUFqbzOmbz/dGX52leH28D3lJ9Cfjb1hsH
         BuS1/z5LbHIhtgTE6pdj1UkKbm/FgDXW9O+REQ8m2ZZTFZb4ZOqvXGE23dI4zJVwbfgB
         ZEYKY1XsA4puBC53xYPXIBMtAurPDqZ6XjjnqzyBMVMWKFBUE0rZsUd6fUUxXFPDJo3T
         nDKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QCP0icBQO9KvMD3r6U6drZz4tEDtEOAyQGipSwM6jPA=;
        b=a6YRBtrbpsR9geqzoWQwhbbNVCgsumytWUlsMjAmVPSFTGHA5dMAcWMtkGYlPLSY56
         VaIMPQ0CDFgP7Xpa1iHWG0P6NX9CffM0zIn/3Lb1foFuS8UD33Kdmm8PtAVNcKS8OonY
         Po3usCncgVMVIlj1i2ITed1Mn24Iv+FnTLOR7IndC/uR7C54GFllRZxePQdju447kRLH
         VDS78M9O1YqaYbG19vF/RAHptUK+Jby3vIypXLP+OouluSvNEZpakqbyCFbAnqj0whx0
         0TJhJqB21SzEdsVDRjs6Whm0Hh4R2fhg5KcwdcDlG/5GJvsJXxPNYShHmHdWPQEONvR3
         KTXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QCP0icBQO9KvMD3r6U6drZz4tEDtEOAyQGipSwM6jPA=;
        b=l7JetherhWvhMSPP+GbVx73YAxPJC0yb6UT5XrHvsXep8MkGPmYp3BPAx7HuhBmumZ
         Hbkw1xJB14ipeF7ZVL7HCbZJi0QXB0wU4HT8ux6SAgCgxKR8aMvyB7A6h+/jzfgn21uM
         /8je/fpJiv7laeJX+b6j+5EfJ2mbNDysWZQd4bQ9gIETGR6vxt4P5LzErfFjj0aXbrxy
         VdaBDF6OPuV7jYGayo1ZxhslEGqV16jbzj9TP8YCgF7MnQxklKv/CeHT19vcpdb2jqwE
         6nP/HQm/amN1gCwZWViPsgTGbgLwVwP92SoleInj9tMMTMasU9Cg5B7AG1yc4JExxgFp
         jRYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53334GVCgjZMAJ8GL/1ojHnZ64JaW5le7I5O0paIHmjFDMlIPTSO
	PUD6GHP91wdQJd4/m7ofui4=
X-Google-Smtp-Source: ABdhPJzNZvIeVncC3wqNy/Bu3lPkvBI0FKYM3k+wv/DJcEX/bM5eWLxowuHMROSOBSkgvu9U+vxewg==
X-Received: by 2002:a63:4450:: with SMTP id t16mr22102053pgk.3.1600340679407;
        Thu, 17 Sep 2020 04:04:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:551b:: with SMTP id j27ls736341pgb.2.gmail; Thu, 17 Sep
 2020 04:04:38 -0700 (PDT)
X-Received: by 2002:a62:b417:0:b029:142:2501:35dc with SMTP id h23-20020a62b4170000b0290142250135dcmr10318622pfn.60.1600340678608;
        Thu, 17 Sep 2020 04:04:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600340678; cv=none;
        d=google.com; s=arc-20160816;
        b=LUsreLNErEKXppmIOtHZZ5604br05WpM/+eDiT7dVOTU+RYMEcG6CN89as6kAV6ux3
         KFTe4dKY3SxE37g1d1ar4oddw0pTPllbLo92qRDHL1fWBfwMR5dYAYolsQ/qLwLicAkv
         4xdcbdIrZZQNvUI5FXd1mZJPSG2sJSOZOezr/SVJ6xRFxSGl1O/xg2Jl+HI/KATHX8IE
         xiXpnR+Qsp4ILVMehH9k5nqQYCQ1gvfG+dnPg4ITjxZ5d7s8m+wQ60MdQ0I/1YXEMmwj
         0St3GBRLIic6wYBciEvt2KTN0UStSLeWRi/1fzl5V+9j+V9tcyXshvi67CES0FzKtawI
         8kKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=2URSs4FQcpfXRLo4XEp8qEHWv0ZrE4RGN8BcoRnIgn8=;
        b=fLrfJLtmZSG+JbWc6fYGTH9eZV55QC/dyRok6qf3BTbRWnitYSYL94vz4FBOR17aym
         VXTbYsyNrFeL2DDYBvbl7P0P0nPcr/qL+FD/KMBR/KhYq3RsvweUy2DNMQRmaxzyExft
         2pKveYyOOVEpxScZzLv6A5x2aT5ev9QCloz9nZiJf6cKmrUId4NRwOETYuc6yIfbgRFs
         YSRgMo0EpDDJDzepH5aIhed++ZxM3nqKuFQYBZ4g1smrMKV8AS14AKB8URPEi2/ym4CM
         +iRTcULuqbDm2gxl5Y2gPbihRSG460GMKEdKmxEVXXYlyGNLratrwz2Q45ICNEZCOJwi
         Somw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h1si1189057pfh.5.2020.09.17.04.04.38;
        Thu, 17 Sep 2020 04:04:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id AB5BE30E;
	Thu, 17 Sep 2020 04:04:37 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.19.21])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id F33673F68F;
	Thu, 17 Sep 2020 04:04:33 -0700 (PDT)
Date: Thu, 17 Sep 2020 12:04:27 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Daniel Kiss <Daniel.Kiss@arm.com>
Cc: Marco Elver <elver@google.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Borislav Petkov <bp@alien8.de>, Rong Chen <rong.a.chen@intel.com>,
	kernel test robot <lkp@intel.com>,
	"Li, Philip" <philip.li@intel.com>, x86-ml <x86@kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Kees Cook <keescook@chromium.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Momchil Velikov <Momchil.Velikov@arm.com>
Subject: Re: [tip:x86/seves] BUILD SUCCESS WITH WARNING
 e6eb15c9ba3165698488ae5c34920eea20eaa38e
Message-ID: <20200917110427.GA98505@C02TD0UTHF1T.local>
References: <20200915160554.GN14436@zn.tnic>
 <20200915170248.gcv54pvyckteyhk3@treble>
 <20200915172152.GR14436@zn.tnic>
 <CAKwvOdkh=bZE6uY8zk_QePq5B3fY1ue9VjEguJ_cQi4CtZ4xgw@mail.gmail.com>
 <CANpmjNPWOus2WnMLSAXnzaXC5U5RDM3TTeV8vFDtvuZvrkoWtA@mail.gmail.com>
 <20200916083032.GL2674@hirez.programming.kicks-ass.net>
 <CANpmjNOBUp0kRTODJMuSLteE=-woFZ2nUzk1=H8wqcusvi+T_g@mail.gmail.com>
 <CAKwvOd=T3w1eqwBkpa8_dJjbOLMTTDshfevT3EuQD4aNn4e_ZQ@mail.gmail.com>
 <CANpmjNPGZnwJVN6ZuBiRUocGPp8c3rnx1v7iGfYna9t8c3ty0w@mail.gmail.com>
 <333D40A0-4550-4309-9693-1ABA4AC75399@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <333D40A0-4550-4309-9693-1ABA4AC75399@arm.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Wed, Sep 16, 2020 at 10:30:42PM +0100, Daniel Kiss wrote:
>=20
>     Thanks for the summary -- yeah, that was my suspicion, that some
>     attribute was being lost somewhere. And I think if we generalize this=
,
>     and don't just try to attach "frame-pointer" attr to the function, we
>     probably also solve the BTI issue that Mark still pointed out with
>     these module_ctor/dtors.
>=20
>     I was trying to see if there was a generic way to attach all the
>     common attributes to the function generated here:
>     https://github.com/llvm/llvm-project/blob/master/llvm/lib/Transforms/=
Utils/
>     ModuleUtils.cpp#L122
>     -- but we probably can't attach all attributes, and need to remove a
>     bunch of them again like the sanitizers (or alternatively just select
>     the ones we need). But, I'm still digging for the function that
>     attaches all the common attributes=E2=80=A6
>=20
>=20
> We had the problem with not just the sanitisers.  Same problem pops with
> functions=20
> that created elsewhere in clang (e.g _clang_call_terminate ) or llvm.
>=20
> In case of BTI the flag even controllable by function attributes which ma=
kes it
> more trickier so
> the module flags found the only reliable way to pass this information dow=
n.=20
> Scanning existing functions is fragile for data only compilation units fo=
r
> example.
>=20
> Our solution, not generic enough but might help.
> https://reviews.llvm.org/D85649=20

Thanks for the pointer -- I've subscribed to that now.

Just to check my understanding, is the issue that generated functions
don't implicitly get function attributes like
"branch-target-enforcement", and so the BTI insertion pass skips those?

I'm guessing that it's unlikely this'll be fixed for an LLVM 11 release?
On the kernel side I guess we'll have to guard affected features as
being incompatible with BTI until there's a viable fix on the compiler
side. :/

Thanks,
Mark.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200917110427.GA98505%40C02TD0UTHF1T.local.
