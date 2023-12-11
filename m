Return-Path: <kasan-dev+bncBAABBONZ32VQMGQEVCIMQGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id D193A80DF8E
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 00:35:22 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-33608b00a04sf2741286f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 15:35:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702337722; cv=pass;
        d=google.com; s=arc-20160816;
        b=sEvuhfRvubvFuM6LBvCsFa36cyvkIYsWnlssI5/BtRU3yvNJx09q0wMFVZFTZVlele
         XxSek+aQGSQgVZ9ER3AENioJVEZaS4s2bFVpNdGGMmyUZX2g0HeofAoN14DwVCtCeH8O
         3TTqPOp4V3AHTkH9qFKB0SW/ZDJCYmpX0jM604UV2g5fGwQUGqx92ekY2LLUKJl8h94Z
         DHFaERfUzd72CO3TwsGidGq9Sa0UMqU+lOIhcqC7aSIPqR6j0lHD6jrE9OH218KiKBM2
         +UVKQpqDgl/ccyM1steeCeBNrwKB7E//IZXcojln54fKQFSklHGJmzIqh2l/XQYcSxS7
         K5Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ernjsGDUeI9hdNqtdkPWGriLepa08Y58GvOuFXrPtF4=;
        fh=akQ9pRj0ioS+a5e76cb5m/5897khq+iguQXzkvsNT28=;
        b=cIlLKxCU+ULWF7wRucjaVnw31w5BoPLSE0OrgAzSf/FF5R1RYEVVaeUW5oM0dTfh5N
         eXBmE5Dc4L13sFYtgX+8k9Z5gvdpCxIweBCNPjU4T5VEj97SDAV47XktAkszzzxJgT3P
         bbSfjnTjBsW0Q8qCdjK/twy/4xUzJiaMoe/Ae3MF6YQnRMzUNfzK3Ve0b/t2DSPSqAnN
         mPk4LQtAWPaL90NjnX0OQOYWJGsFgWRZ5/UC4Knv4hsOhXBBoGtDA8tjSOE63r7nE6vF
         MECKninpSNDyPw++O0FLpAGArpaIELVwIVICLUnWJLtMUuauypR4LQnBI0LHH+cd+bV1
         +W2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=XT23O3A2;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 2001:4ca0:0:103::81bb:ff89 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702337722; x=1702942522; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ernjsGDUeI9hdNqtdkPWGriLepa08Y58GvOuFXrPtF4=;
        b=Fw2VvxxlbozfjNokI11nRYuwC8OMNurCIpDUbj6HhzGX74n+htYe9Ff2mWZ46G9f3C
         30fOkPCIBwGQa7r8Vy0Qem4wxmhlfPhPUoQipIcSIqXozWJgwW+0QGQ9WdlXUm7sWC5E
         zdXwyovgLffljhm/Yl38OwxVJo6YDv7Py0QPp+kfU962X2JJwnNGHXQWfIawowUbUkNw
         4vi6vjclHHByLIdUBc+rrHT0Py2hq1nsZpKivo21sO4PxJjcsL/hBpdSFeiFFvLBDnKK
         kcvnez1cbGaq9mq0T8Z1QwScPCb0URSoCxZJu4JsOAyB2fCi8JKns4FNIXbplCzLyHLy
         rtkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702337722; x=1702942522;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ernjsGDUeI9hdNqtdkPWGriLepa08Y58GvOuFXrPtF4=;
        b=R8O0seh5I/sZQbpk3vOy5g0zGsDXr1a49245EvcbgVL5+2zkHIFVGOuYLF5WN3iPMc
         s4KcvrrGAqEcE/+LxyOb/g2SDM35WgQYxOKRGqFT5KjH/086eBQ/98JMOX5la9iUfpqd
         I+46X0YUB3qcs6VyLs/weY61y5D2CLm+H25P0xzuyU7QdSDl7YxmryB+tplI5Gx6HBIY
         DmDE6+h+dvMzmCNSgrZ/tVO/gFS7cmRgye89/6be9Kvqskb7Kj21R5i95hirCvQxPyuH
         IZ4wx4H60SaOCGgeTBJdFeMe4Ck6JaO1nbzaXJORoNydMtmrXhAcZE/MjVniMyb6UmQ1
         xclw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyzNcHi2xMmD0SXOB6nV3Q9uvJK0K/+t4zyqbHFWPnS6T7gsPR2
	tHav3+JNio/U/5zizUuwHsM=
X-Google-Smtp-Source: AGHT+IEE/N4ArhzFEG5zjZtBexajN7wTMtvFzsyVcknLBntSZF13Mb5RtCh2uCFNYW1hiO3AjqyFbA==
X-Received: by 2002:a5d:53c7:0:b0:333:16:7aa2 with SMTP id a7-20020a5d53c7000000b0033300167aa2mr2729490wrw.7.1702337721844;
        Mon, 11 Dec 2023 15:35:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b26:b0:40b:33a9:fb68 with SMTP id
 m38-20020a05600c3b2600b0040b33a9fb68ls1362500wms.1.-pod-prod-09-eu; Mon, 11
 Dec 2023 15:35:20 -0800 (PST)
X-Received: by 2002:a05:600c:c1b:b0:40c:27af:2ac8 with SMTP id fm27-20020a05600c0c1b00b0040c27af2ac8mr2659242wmb.6.1702337719998;
        Mon, 11 Dec 2023 15:35:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702337719; cv=none;
        d=google.com; s=arc-20160816;
        b=E8SkULknIVzmDicN3Ms23L67GEFxPfHqWnbJoYPYPpJ2i7BfHOuzOifnUh+3K+0zT0
         NL5mIfnTgyp2+S7JY0ctr/FFroCE1fD1RUQbCb97fYodTgstxNQmgTa+gFVGFdoheysM
         gMOQoEqYcQIXMV2BJ/F26nQ5Et7H4cMPt8xtsaTg65uiENNdLqLgLRRH2v6H2ufs+9HF
         00NTBKcUx7G1dLYBDRuJRWyZZKAMfJtmJ+Sbz9PtpCGjIvGWUU/0ehzovg0jgsfunQQD
         QUochUK8KE0MoYLasIhg+H+NB4X4U5/Q71DI+pcExAIT1bQ0b/hkqIAuwsiF1qdAW8sh
         K7RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=8idFFu0L0dXkH2zjSo0W/AcVqktD9byVatdWxcpkJGc=;
        fh=akQ9pRj0ioS+a5e76cb5m/5897khq+iguQXzkvsNT28=;
        b=QrkVHWlMQGXPdUnxKqHpegD5VNnV6f/HpvPBvmh+fGGf0qsFYI6Fu/VRffjTXlqJkq
         by9aEZoFZQhsN9RGrQP9/22U87gsqSeEqmjz+zkWt6MOe8DXmigDYRLi+YXmPHelfh71
         +alLfoPaUnixGRWdycwvEFZlDsmYdUbz95kA7DHHR663wpURelxu7ap+VcTrdoUBG297
         fClwax6+xTuElmVYZ+agyLTfdxfIDd2KvcFAjUSbGk3ytEgnkPatx9NE5lwyCvHpC3eF
         +5VNKGKU2z0ibl/YknwnWbDiKfY4vacId3DM8mWHTzC4vW0652Tfxfyilw3ramoD4u5C
         9iew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=XT23O3A2;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 2001:4ca0:0:103::81bb:ff89 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
Received: from postout1.mail.lrz.de (postout1.mail.lrz.de. [2001:4ca0:0:103::81bb:ff89])
        by gmr-mx.google.com with ESMTPS id v13-20020a7bcb4d000000b0040c4605c581si3002wmj.1.2023.12.11.15.35.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Dec 2023 15:35:19 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 2001:4ca0:0:103::81bb:ff89 as permitted sender) client-ip=2001:4ca0:0:103::81bb:ff89;
Received: from lxmhs51.srv.lrz.de (localhost [127.0.0.1])
	by postout1.mail.lrz.de (Postfix) with ESMTP id 4Spylm6qCGzyTp;
	Tue, 12 Dec 2023 00:35:16 +0100 (CET)
X-Virus-Scanned: by amavisd-new at lrz.de in lxmhs51.srv.lrz.de
X-Spam-Flag: NO
X-Spam-Score: -2.881
X-Spam-Level: 
X-Spam-Status: No, score=-2.881 tagged_above=-999 required=5
	tests=[ALL_TRUSTED=-1, BAYES_00=-1.9, DMARC_ADKIM_RELAXED=0.001,
	DMARC_ASPF_RELAXED=0.001, DMARC_POLICY_NONE=0.001,
	LRZ_CT_PLAIN_UTF8=0.001, LRZ_DMARC_FAIL=0.001,
	LRZ_DMARC_FAIL_NONE=0.001, LRZ_DMARC_POLICY=0.001,
	LRZ_DMARC_TUM_FAIL=0.001, LRZ_DMARC_TUM_REJECT=3.5,
	LRZ_DMARC_TUM_REJECT_PO=-3.5, LRZ_ENVFROM_FROM_MATCH=0.001,
	LRZ_ENVFROM_TUM_S=0.001, LRZ_FROM_ENVFROM_ALIGNED_STRICT=0.001,
	LRZ_FROM_HAS_A=0.001, LRZ_FROM_HAS_AAAA=0.001,
	LRZ_FROM_HAS_MDOM=0.001, LRZ_FROM_HAS_MX=0.001,
	LRZ_FROM_HOSTED_DOMAIN=0.001, LRZ_FROM_NAME_IN_ADDR=0.001,
	LRZ_FROM_PHRASE=0.001, LRZ_FROM_TUM_S=0.001, LRZ_HAS_CT=0.001,
	LRZ_HAS_IN_REPLY_TO=0.001, LRZ_HAS_MIME_VERSION=0.001,
	LRZ_HAS_SPF=0.001, LRZ_MSGID_LONG_50=0.001, LRZ_MSGID_NO_FQDN=0.001,
	LRZ_NO_UA_HEADER=0.001, LRZ_SUBJ_FW_RE=0.001,
	LRZ_URL_PLAIN_SINGLE=0.001, LRZ_URL_SINGLE_UTF8=0.001,
	T_SCC_BODY_TEXT_LINE=-0.01] autolearn=no autolearn_force=no
Received: from postout1.mail.lrz.de ([127.0.0.1])
	by lxmhs51.srv.lrz.de (lxmhs51.srv.lrz.de [127.0.0.1]) (amavisd-new, port 20024)
	with LMTP id Cuu56KEaV5jm; Tue, 12 Dec 2023 00:35:16 +0100 (CET)
Received: from cerulean.fritz.box (unknown [IPv6:2001:a61:245c:a01:443b:cc34:8ae7:6ede])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout1.mail.lrz.de (Postfix) with ESMTPSA id 4Spyll4BFKzyTb;
	Tue, 12 Dec 2023 00:35:15 +0100 (CET)
Date: Tue, 12 Dec 2023 00:35:12 +0100
From: Paul =?utf-8?Q?Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Peter Collingbourne <pcc@google.com>, andrey.konovalov@linux.dev, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	linux-trace-kernel@vger.kernel.org, Nick Desaulniers <ndesaulniers@google.com>
Subject: Re: [PATCH v3 1/3] kasan: switch kunit tests to console tracepoints
Message-ID: <rbcdbilhh67fvjdgnstu25v4jnfeesthoxstnzzglynbngu5bk@5ozwgzaulbsx>
References: <20230215143306.2d563215@rorschach.local.home>
 <CAMn1gO4_+-0x4ibpcASy4bLeZ+7rsmjx=0AYKGVDUApUbanSrQ@mail.gmail.com>
 <CAMn1gO6heXaovFy6jvpWS8TFLBhTomqNuxJmt_chrd5sYtskvw@mail.gmail.com>
 <20230505095805.759153de@gandalf.local.home>
 <n37j6cbsogluma25crzruaiq7qcslnjeoroyybsy3vw2cokpcm@mh7r3ocp24cb>
 <CA+fCnZebmy-fZdNonrgLofepTPL5hU6P8R37==sygTLBSRoa+w@mail.gmail.com>
 <fv7fn3jivqcgw7mum6zadfcy2fbn73lygtxyy5p3zqpelfiken@5bmhbdufxgez>
 <CA+fCnZfQEueCifc-8d5NVWEUtAiOG1eRW-LFKbOhab_Y7jqU0Q@mail.gmail.com>
 <osqmp2j6gsmgbkle6mwhoaf65mjn4a4w3e5hsfbyob6f44wcg6@7rihb5otzl2z>
 <CANpmjNMw3N09x06Q+0mFCEeTKfUsDdXwXM2hdgAQ+wwbZGpB9w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNMw3N09x06Q+0mFCEeTKfUsDdXwXM2hdgAQ+wwbZGpB9w@mail.gmail.com>
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b=XT23O3A2;       spf=pass
 (google.com: domain of paul.heidekrueger@tum.de designates
 2001:4ca0:0:103::81bb:ff89 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
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

On 11.12.2023 23:56, Marco Elver wrote:
> On Mon, 11 Dec 2023 at 23:48, Paul Heidekr=C3=BCger <paul.heidekrueger@tu=
m.de> wrote:
> >
> > On 11.12.2023 21:51, Andrey Konovalov wrote:
> > > On Mon, Dec 11, 2023 at 7:59=E2=80=AFPM Paul Heidekr=C3=BCger
> > > <paul.heidekrueger@tum.de> wrote:
> > > >
> > > > > Hi Paul,
> > > > >
> > > > > I've been successfully running KASAN tests with CONFIG_TRACEPOINT=
S
> > > > > enabled on arm64 since this patch landed.
> > > >
> > > > Interesting ...
> > > >
> > > > > What happens when you try running the tests with .kunitconfig? Do=
es
> > > > > CONFIG_TRACEPOINTS or CONFIG_KASAN_KUNIT_TEST get disabled during
> > > > > kernel building?
> > > >
> > > > Yes, exactly, that's what's happening.
> > > >
> > > > Here's the output kunit.py is giving me. I replaced CONFIG_DEBUG_KE=
RNEL with
> > > > CONFIG_TRACEPOINTS in my .kunitconfig. Otherwise, it's identical wi=
th the one I
> > > > posted above.
> > > >
> > > >         =E2=9E=9C   ./tools/testing/kunit/kunit.py run --kunitconfi=
g=3Dmm/kasan/.kunitconfig --arch=3Darm64
> > > >         Configuring KUnit Kernel ...
> > > >         Regenerating .config ...
> > > >         Populating config with:
> > > >         $ make ARCH=3Darm64 O=3D.kunit olddefconfig
> > > >         ERROR:root:Not all Kconfig options selected in kunitconfig =
were in the generated .config.
> > > >         This is probably due to unsatisfied dependencies.
> > > >         Missing: CONFIG_KASAN_KUNIT_TEST=3Dy, CONFIG_TRACEPOINTS=3D=
y
> > > >
> > > > Does CONFIG_TRACEPOINTS have some dependency I'm not seeing? I coul=
dn't find a
> > > > reason why it would get disabled, but I could definitely be wrong.
> > >
> > > Does your .kunitconfig include CONFIG_TRACEPOINTS=3Dy? I don't see it=
 in
> > > the listing that you sent earlier.
> >
> > Yes. For the kunit.py output from my previous email, I replaced
> > CONFIG_DEBUG_KERNEL=3Dy with CONFIG_TRACEPOINTS=3Dy. So, the .kunitconf=
ig I used to
> > produce the output above was:
> >
> >         CONFIG_KUNIT=3Dy
> >         CONFIG_KUNIT_ALL_TESTS=3Dn
> >         CONFIG_TRACEPOINTS=3Dy
> >         CONFIG_KASAN=3Dy
> >         CONFIG_KASAN_GENERIC=3Dy
> >         CONFIG_KASAN_KUNIT_TEST=3Dy
> >
> > This more or less mirrors what mm/kfence/.kunitconfig is doing, which a=
lso isn't
> > working on my side; kunit.py reports the same error.
>=20
> mm/kfence/.kunitconfig does CONFIG_FTRACE=3Dy. TRACEPOINTS is not user
> selectable. I don't think any of this has changed since the initial
> discussion above, so CONFIG_FTRACE=3Dy is still needed.

Using CONFIG_FTRACE=3Dy instead of CONFIG_TRACEPOINTS=3Dy produces the same=
 error=20
for me.=20

So

	CONFIG_KUNIT=3Dy
	CONFIG_KUNIT_ALL_TESTS=3Dn
	CONFIG_FTRACE=3Dy
	CONFIG_KASAN=3Dy
	CONFIG_KASAN_GENERIC=3Dy
	CONFIG_KASAN_KUNIT_TEST=3Dy

produces

	=E2=9E=9C   ./tools/testing/kunit/kunit.py run --kunitconfig=3Dmm/kasan/.k=
unitconfig --arch=3Darm64
	Configuring KUnit Kernel ...
	Regenerating .config ...
	Populating config with:
	$ make ARCH=3Darm64 O=3D.kunit olddefconfig CC=3Dclang
	ERROR:root:Not all Kconfig options selected in kunitconfig were in the gen=
erated .config.
	This is probably due to unsatisfied dependencies.
	Missing: CONFIG_KASAN_KUNIT_TEST=3Dy
=09
By that error message, CONFIG_FTRACE appears to be present in the generated=
=20
config, but CONFIG_KASAN_KUNIT_TEST still isn't. Presumably,=20
CONFIG_KASAN_KUNIT_TEST is missing because of an unsatisfied dependency, wh=
ich=20
must be CONFIG_TRACEPOINTS, unless I'm missing something ...

If I just generate an arm64 defconfig and select CONFIG_FTRACE=3Dy,=20
CONFIG_TRACEPOINTS=3Dy shows up in my .config. So, maybe this is kunit.py-r=
elated=20
then?

Andrey, you said that the tests have been working for you; are you running =
them=20
with kunit.py?

Many thanks,
Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/rbcdbilhh67fvjdgnstu25v4jnfeesthoxstnzzglynbngu5bk%405ozwgzaulbsx=
.
