Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ7L2DXAKGQETNGP65A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FBBF102BB9
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 19:34:15 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id t11sf8849522edc.12
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 10:34:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574188455; cv=pass;
        d=google.com; s=arc-20160816;
        b=qL1mwT7gdIeott1R3ZHsslAzvPktiu0xrwgzofjgR7UAtFU5JuTh2OSCYELfc2XFFa
         /0aJTmvbUedgnWzHZsZ2oMaRS+qGCMieZRl1nFRmD6y1bnhzHmwYVpUeH39yyQnaX5OX
         g1B/6wqJpppQbZSw4o5GsdQcRnI8CYsWdVmNv7T3kg61DojeMH0XPE00yhzAD/ISoFwD
         SPHv1JD7YnNBMUatDaeOo+7h1+Vr5L27BQ6gDvPWo1qqs0oWSn4v1odzUYpKLL/eOxbM
         fR6ZByJu5ochYJt55MXV1zKPWg8M4TExnxPGNLP8DGo7YMBUgS/iNcND3W5liqy6uppd
         N2zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=sSsI6gWyWOieth7SgxVouzbf0T7dmkzdmpKbHaXxElo=;
        b=rliTObec084AU7/JlgQpwcopARYStpXPzOp/WnJes7sAGMK/6BQWMK1dan+x2h7vEv
         UfrWI5355bDta3rgYSN/2mwAwrKuok8cMQYwhKjElmHMmtxPP+yTB7kV0cPt4P5w9DWa
         vhwCVoEbUtauBqmGceB2Z21/hdXWVkrwePsFGlUb1T8FRPyab9k4yVu4OXCCotDlP/lL
         yi33uPu4M7n/ggkLkGN31Y8e8UbFEoiYnLCDSqrkTOy4XADXGefOPK1sGiTwC3T1vko6
         wIG2wxPGkEUYbd5yTBdboS4LuPe9EvDoduQ9IBkr4p7Tw4clKV0MSyy5mtKypn3yg0l9
         A5CA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LJwr2bvb;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sSsI6gWyWOieth7SgxVouzbf0T7dmkzdmpKbHaXxElo=;
        b=hpxIvnl83rcadi1ePLkMcnnBTpScIhPaAOqZ3kfsCnwOLAMG2Ro6A/Z57h1y7isk38
         CNXdwU+TI+xiV9TbgOVtu5zpG8hDXwE85xFoTbxaCvrQi699tXEgVM6u8OMLL9ZXz01J
         UtSlwUY5Ad3PvpH5ZOlXsA8mSTSkiMhyZETU3ykYGGQjb1YqBK/6XEz2PaACbrKlVNfX
         pVcodWjqLwD1mXpSEiEw5aOeT7OEK0cimEvd7/k3+3FL5pfywTz+MjU99OcINWEu2w3m
         0Myz4nntvINceyoATpLORtPdMFxgyFghblc2JI3duqvARI2nRtKYuhykHBL9qPxbYMqh
         h9qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sSsI6gWyWOieth7SgxVouzbf0T7dmkzdmpKbHaXxElo=;
        b=XBgHcjPA6AarMyeuRj9mB98phsyViHJSWD5p3571Z9PTelag3ikFApbENvlRCmP1Kn
         NgSxjWCMcpEP72ObFA7POlYyiE5TQhZQCJESAvX3Lxh9Hp+mQNUcVviYGmTY0JTEOa/t
         qf3GHPOavA78vCnTOTIFb+wpGigmXR9mVo/ARxZpJddH8+ygdTAUCBQcpf/szEel6s+5
         7Vegse/Ll7jfWdpQzzJoi26vz9l08ehEat3jPuJgXKKxsO5tZobQ7cJW+PIZXUvyQR07
         ChhGwPKwitqnQo9cO++AIVB7En4w3JOP44b4HG0W/d5MhL+sFoLHVXvmdrs7QJZU+dUf
         VoIQ==
X-Gm-Message-State: APjAAAU3ebzynRci2nbZPrSaBnC61TM+wLmfw58mg6laCmg8hwIokrBR
	IQ5/uHvZPg3dL5pYfvTT2+A=
X-Google-Smtp-Source: APXvYqwAtIKWYfuoz1r8ULD0C/1O1xzJNkLpY2g9XmBDUXFOeZ8I8/Je41rvjYEkAKlnE933zsuvSA==
X-Received: by 2002:a17:906:751:: with SMTP id z17mr36058973ejb.313.1574188455238;
        Tue, 19 Nov 2019 10:34:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:95d0:: with SMTP id n16ls7935132ejy.5.gmail; Tue, 19
 Nov 2019 10:34:14 -0800 (PST)
X-Received: by 2002:a17:906:4019:: with SMTP id v25mr37404362ejj.11.1574188454631;
        Tue, 19 Nov 2019 10:34:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574188454; cv=none;
        d=google.com; s=arc-20160816;
        b=Jzgw34pvToqmswB4cDJRUxVLnfTCwTbOxFa2BxArjWALXhsID5DSWcuKCDeACuA44q
         NWIzTHA4udlPL9xzpTJ13aH5lexafTse90tpYhvu5ns1ZugLImyisOOnObPWFaeLNiIS
         em3yXgI9aHfla4nIqulWUyELkzKs8oRfqb3PNCGgfXGihB+uqMAczuCORLmXU1LYkXPf
         1tsPsvvnw6HVYuXF5HRcfRZMwJvkqq1oGsC/Mxxm90bFOQJ84Lig1wrw6pQmymuXPZpj
         a1vcm4t43bOV3WqSJ127N8SrzyTiP9+5AaYxrQOPkFnfC7OTp6UeqBV/Pe638ZX01C2Q
         VSOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Bn+l2Wf/udyhGlzXiaSqVzyU1KUJVXlbjswoz1SSVPI=;
        b=Fwngm3X9nw1cCyfGYU8z4t9JrpBBFr8xCxP9t28fBbVxF3YcifZK5aWYpCt9oOuGLJ
         N/4tov3K4SURTljsc4+nbrEW2ZUrFvGqrLMKuwZVTQYKYAS7Ktb2gxqFLBpsSKp0zh0O
         /vaY7c9VZj8UX7eUyBQ4u++IjRrHTmFg8bHK6+oU4URWS0fbFhoOONuYG3Q0T3ffGDtx
         oSCMC7fkUcRhWRY2kUxQJt0CLU7cjSBi89FsHm7qXPmKQLC7ZqkulRwxcbxnaDoMDRuB
         C3tIzqGjcxyGnhIxCGbgpFIU99ZmIKqPK1pNWOAbN51NxF1PxLgioSqtiFaa+ciWFs/G
         +5GA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LJwr2bvb;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id x16si75254eds.5.2019.11.19.10.34.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 10:34:14 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id b11so4304531wmb.5
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 10:34:14 -0800 (PST)
X-Received: by 2002:a05:600c:295:: with SMTP id 21mr7306267wmk.43.1574188453718;
        Tue, 19 Nov 2019 10:34:13 -0800 (PST)
Received: from google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id l10sm31930113wrg.90.2019.11.19.10.34.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Nov 2019 10:34:12 -0800 (PST)
Date: Tue, 19 Nov 2019 19:34:07 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Randy Dunlap <rdunlap@infradead.org>
Cc: Stephen Rothwell <sfr@canb.auug.org.au>,
	Linux Next Mailing List <linux-next@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>
Subject: Re: linux-next: Tree for Nov 19 (kcsan)
Message-ID: <20191119183407.GA68739@google.com>
References: <20191119194658.39af50d0@canb.auug.org.au>
 <e75be639-110a-c615-3ec7-a107318b7746@infradead.org>
 <CANpmjNMpnY54kDdGwOPOD84UDf=Fzqtu62ifTds2vZn4t4YigQ@mail.gmail.com>
 <fb7e25d8-aba4-3dcf-7761-cb7ecb3ebb71@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <fb7e25d8-aba4-3dcf-7761-cb7ecb3ebb71@infradead.org>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LJwr2bvb;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::342 as
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

On Tue, 19 Nov 2019, Randy Dunlap wrote:

> On 11/19/19 8:12 AM, Marco Elver wrote:
> > On Tue, 19 Nov 2019 at 16:11, Randy Dunlap <rdunlap@infradead.org> wrot=
e:
> >>
> >> On 11/19/19 12:46 AM, Stephen Rothwell wrote:
> >>> Hi all,
> >>>
> >>> Changes since 20191118:
> >>>
> >>
> >> on x86_64:
> >>
> >> It seems that this function can already be known by the compiler as a
> >> builtin:
> >>
> >> ../kernel/kcsan/core.c:619:6: warning: conflicting types for built-in =
function =E2=80=98__tsan_func_exit=E2=80=99 [-Wbuiltin-declaration-mismatch=
]
> >>  void __tsan_func_exit(void)
> >>       ^~~~~~~~~~~~~~~~
> >>
> >>
> >> $ gcc --version
> >> gcc (SUSE Linux) 7.4.1 20190905 [gcc-7-branch revision 275407]
> >=20
> > Interesting. Could you share the .config? So far I haven't been able
> > to reproduce.
>=20
> Sure, it's attached.

Thanks, the config did the trick, even for gcc 9.0.0.

The problem is CONFIG_UBSAN=3Dy. We haven't explicitly disallowed it like
with KASAN. In principle there should be nothing wrong with KCSAN+UBSAN.

There are 3 options:
1. Just disable UBSAN for KCSAN, and also disable KCSAN for UBSAN.
2. Restrict the config to not allow combining KCSAN and UBSAN.
3. Leave things as-is.

Option 1 probably makes most sense, and I'll send a patch for that
unless there are major objections.

> > I can get the warning if I manually add -fsanitize=3Dthread to flags fo=
r
> > kcsan/core.c (but normally disabled via KCSAN_SANITIZE :=3D n). If
> > possible could you also share the output of `make V=3D1` for
> > kcsan/core.c?
>=20
> here:

>   gcc -Wp,-MD,kernel/kcsan/.core.o.d  -nostdinc -isystem /usr/lib64/gcc/x=
86_64-suse-linux/7/include -I../arch/x86/include -I./arch/x86/include/gener=
ated -I../include -I./include -I../arch/x86/include/uapi -I./arch/x86/inclu=
de/generated/uapi -I../include/uapi -I./include/generated/uapi -include ../=
include/linux/kconfig.h -include ../include/linux/compiler_types.h -D__KERN=
EL__ -Wall -Wundef -Werror=3Dstrict-prototypes -Wno-trigraphs -fno-strict-a=
liasing -fno-common -fshort-wchar -fno-PIE -Werror=3Dimplicit-function-decl=
aration -Werror=3Dimplicit-int -Wno-format-security -std=3Dgnu89 -mno-sse -=
mno-mmx -mno-sse2 -mno-3dnow -mno-avx -m64 -falign-jumps=3D1 -falign-loops=
=3D1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3D3 -mskip-ra=
x-setup -mtune=3Dgeneric -mno-red-zone -mcmodel=3Dkernel -DCONFIG_AS_CFI=3D=
1 -DCONFIG_AS_CFI_SIGNAL_FRAME=3D1 -DCONFIG_AS_CFI_SECTIONS=3D1 -DCONFIG_AS=
_SSSE3=3D1 -DCONFIG_AS_AVX=3D1 -DCONFIG_AS_AVX2=3D1 -DCONFIG_AS_AVX512=3D1 =
-DCONFIG_AS_SHA1_NI=3D1 -DCONFIG_AS_SHA256_NI=3D1 -Wno-sign-compare -fno-as=
ynchronous-unwind-tables -fno-delete-null-pointer-checks -Wno-frame-address=
 -Wno-format-truncation -Wno-format-overflow -O2 --param=3Dallow-store-data=
-races=3D0 -Wframe-larger-than=3D2048 -fno-stack-protector -Wno-unused-but-=
set-variable -Wimplicit-fallthrough -Wno-unused-const-variable -fno-omit-fr=
ame-pointer -fno-optimize-sibling-calls -fno-var-tracking-assignments -Wdec=
laration-after-statement -Wvla -Wno-pointer-sign -fno-strict-overflow -fno-=
merge-all-constants -fmerge-constants -fno-stack-check -fconserve-stack -We=
rror=3Ddate-time -Werror=3Dincompatible-pointer-types -Werror=3Ddesignated-=
init -fno-conserve-stack -fno-stack-protector  -fprofile-arcs -ftest-covera=
ge -fno-tree-loop-im -Wno-maybe-uninitialized    -fsanitize=3Dshift  -fsani=
tize=3Dinteger-divide-by-zero  -fsanitize=3Dunreachable  -fsanitize=3Dsigne=
d-integer-overflow  -fsanitize=3Dbounds  -fsanitize=3Dobject-size  -fsaniti=
ze=3Dbool  -fsanitize=3Denum  -Wno-maybe-uninitialized   -I ../kernel/kcsan=
 -I ./kernel/kcsan    -DKBUILD_BASENAME=3D'"core"' -DKBUILD_MODNAME=3D'"cor=
e"' -c -o kernel/kcsan/core.o ../kernel/kcsan/core.c
> ../kernel/kcsan/core.c:619:6: warning: conflicting types for built-in fun=
ction =E2=80=98__tsan_func_exit=E2=80=99 [-Wbuiltin-declaration-mismatch]

Adding '-fsanitize=3D<anything>' seems to make gcc think that these are
builtins. So this is partially also a gcc problem, but if we disable all
sanitizers with the runtime, then this goes away.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20191119183407.GA68739%40google.com.
