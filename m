Return-Path: <kasan-dev+bncBAABB7GX5OWAMGQEXDSVCMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id B752D82658C
	for <lists+kasan-dev@lfdr.de>; Sun,  7 Jan 2024 19:22:53 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-3367c893deesf754121f8f.2
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Jan 2024 10:22:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704651773; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zu8uLqCD2qPHVq0phOwtabp6kDAnxJcqpo9GvlIP1FiGe+UPEgoRFN/KQ6GeJfI9b5
         34fb4FEJJ8ZxXngi4ex3YhSIwzUaLJapJq7MO1b+9wJQKw0WyCcMv4TSY3oTFXRPrHUV
         p8SkEESXp1ZoX5wAdvDTrz3mqagBLjHYJXM6fcjRx/l6Y5BNhu86WTGqYXoApLNx3cRs
         deuxmaDstKubfJUy2fdqch+Nwkf2MnHNb4uVKgyovIDwKJmICvByrjVl/bqnvKg6Ed+S
         /fCkUvlqPgF/CnJMeYRfOq67tGshUwc7t++U7PpIbFc+wOgJ9SZqgCQWiGWQSVl0zzvf
         xdVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=5VYd6YEfWKnyMjA5XwaRceQuUGeTX9gA7oLL2foew5k=;
        fh=akQ9pRj0ioS+a5e76cb5m/5897khq+iguQXzkvsNT28=;
        b=ij+QXyUlyFJziYhKpWyAnVvI2VJkCUlz87gAJzs8q5LGke9Ytbh6xiQ9ER4QEL/VD9
         AbJoMrv8zPM9sc8q/V+npmREtW7hg5yHWANiZXXpX5ACpXr5NAjxepfYrPJASyWZGUxD
         lzpuGpcYg5VZp+r7p7rY6+0Bs0PKzs3A8xYPpjmEHqXchi4Kghy2Katcaujn4nTiEOK/
         a4M38qOWeSVyXmDLbjAa6nVndufhgC3t749KooakMUl7VKlt99eh1Llk9WWedk7wvUvU
         vI2OIRm/As9UFzMfyppdGMqHuDmhJmmOE7LOIkmGGmsIaDSKbl3m77O50+lX2Sgu7bfW
         z3Mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=GeWplGkk;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704651773; x=1705256573; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5VYd6YEfWKnyMjA5XwaRceQuUGeTX9gA7oLL2foew5k=;
        b=aSKC+TWdBo2IinTHZlOaXsDktVoiPITJG7ktRAvZCldpoSIy1M46gcOPhL5xKtI4wM
         OqgZavJVKDHpnEK5II3xabKb4/RJ3VbOGWelNmcxgih7zdyjSwzDgFxYRIz5KEc8oSlx
         JAHBYBWc/pQeEDSLz6RvaEnu9DmgP1GMw4W4pRNXLE0sOvedS/P7yQN2QUtc2W2vQ8bp
         vbgCBZaSG9tEb1ekhN3TA0vRu4OFLw+NRBFj7Co7FsFvxgm0LudKKdxa3Ay9d83r/O4N
         iDLdsAqy2vdeRq74l/J9IxfbRkVsTHjJ030HzJOOIgVwd33ohWepxgkFnJpAEU9v/kkG
         o1Yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704651773; x=1705256573;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5VYd6YEfWKnyMjA5XwaRceQuUGeTX9gA7oLL2foew5k=;
        b=nbnlG38ibWf0HCC5Wt2d6qB0xLJ6mNzDGQtfzaJwsNcG9gVfihcLB1/tRPXBorFhU7
         vIK+pGR281aYCbfuRCQZkYNkJbmZAG37QnGzjFAnPFJ4TUD1HcLQvPQu4BoGY0BRCIWx
         6LZI2D3RYVAAuYOcLljOPrV1hyu6pNMUfxt/1TEcU40vV/FMtGb/+wYlaSRPh1tFd2gw
         YwkAndrjbHfw75RrsKvPy0H1iXzyKclhMsAYI63/EV4hTOwkXKsn5+J9mWiaOjjY4eNK
         HCSpzJS3Uo9zOQn3xKmkjoFay/319UhaeztUrj6hVj54MwXXRepGv7FddsqWzpezm2sA
         F9SA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywu5iVFzrgMs/Cls4ElD1KglqiYbOxM4A2JfzJc3qU0NFe2biob
	4xlYkFAjRfNanQIEYYa9g1c=
X-Google-Smtp-Source: AGHT+IGF7+jisQTkK0J8t4pjngazoAFnMAudmnA+7d9LRAbGeserjFPZk30w897tHlnhBK5PXBA2gw==
X-Received: by 2002:a05:600c:5185:b0:40e:4551:8c21 with SMTP id fa5-20020a05600c518500b0040e45518c21mr566199wmb.26.1704651772509;
        Sun, 07 Jan 2024 10:22:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1395:b0:40d:3abd:bd07 with SMTP id
 u21-20020a05600c139500b0040d3abdbd07ls732226wmf.0.-pod-prod-03-eu; Sun, 07
 Jan 2024 10:22:51 -0800 (PST)
X-Received: by 2002:a05:600c:4e88:b0:40e:365c:b452 with SMTP id f8-20020a05600c4e8800b0040e365cb452mr1341437wmq.129.1704651770780;
        Sun, 07 Jan 2024 10:22:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704651770; cv=none;
        d=google.com; s=arc-20160816;
        b=bbfovxMsxDjTPlXc4Rm0/H/MyBDDMq+RCEYVlo3A8LdO3TcUuNCosz9xVOs2eRT3Ij
         qC9+w9KJp/zj87OTEOGqXBDsRtZIRhMywMcpJS0Iyql/JkxsZ5X37qSWM/cE96BoKi7+
         j0smxnlZ93GvI8aASiuHnDbPFi12YENnjK6q4cGjzIY0ZUtYnlBVlLU1FsuyYcns9OHT
         G6QrjFdru1ld2pg8oAz3D2/Wv8aGBmMwWXrxb7zVP6lvVjTvx6QuS7JEd+kqo6wk3/XS
         uuFtPHzqVwK4QaA+Koaypa4K8ZFA512d1xSE/8LcEj6f0JZRB5Mp0fMCHUJSS3xjjQKv
         AyFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=r4TLIXJVf378b8n0ZfXXP0YHeN+RfpBipucVEujnFDQ=;
        fh=akQ9pRj0ioS+a5e76cb5m/5897khq+iguQXzkvsNT28=;
        b=0MPtvj2QG1sPt0m7dF7avPb/2wj493h6TmiYyrygF0Oxn8++gfrbI9NYl2r20XrLF7
         6rxXTdXA6hYbvucVgJwi0KFIwMoDetpRBgghCnq43ktj5boVZGeLreUyHIFO5GDHul8v
         Rd5zJ9Ymb8cBej82LXup0MUB9KIVMFXL6Hq319YKA8Fz5ZBgm1gcIGV9SdSsKJNsyzfi
         vNsKMyALAjyy4DA7pEa13bMy6wcDFRP2PveDG/Y6yQoAsBeTGtoNAVVZznR9DTsqaZIP
         uankBIX85sGzz7xGGEuuX51beFppN/wciOdsrig1nFDwmZbI65TiHAXzDVgaIljsYpmR
         SOhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=GeWplGkk;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
Received: from postout1.mail.lrz.de (postout1.mail.lrz.de. [129.187.255.137])
        by gmr-mx.google.com with ESMTPS id d11-20020a05600c34cb00b0040e45b7c14asi40923wmq.1.2024.01.07.10.22.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 07 Jan 2024 10:22:50 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) client-ip=129.187.255.137;
Received: from lxmhs51.srv.lrz.de (localhost [127.0.0.1])
	by postout1.mail.lrz.de (Postfix) with ESMTP id 4T7QXn28G3zyTZ;
	Sun,  7 Jan 2024 19:22:49 +0100 (CET)
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
	with LMTP id SnoGITx3fP0N; Sun,  7 Jan 2024 19:22:48 +0100 (CET)
Received: from cerulean.fritz.box (unknown [IPv6:2001:a61:24c8:fe01:dd4e:2513:1e73:cb01])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout1.mail.lrz.de (Postfix) with ESMTPSA id 4T7QXl54jLzySv;
	Sun,  7 Jan 2024 19:22:47 +0100 (CET)
Date: Sun, 7 Jan 2024 19:22:40 +0100
From: Paul =?utf-8?Q?Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Peter Collingbourne <pcc@google.com>, andrey.konovalov@linux.dev, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	linux-trace-kernel@vger.kernel.org, Nick Desaulniers <ndesaulniers@google.com>
Subject: Re: Re: [PATCH v3 1/3] kasan: switch kunit tests to console
 tracepoints
Message-ID: <h7qw4rhqovyq5trm5kyvabshqmxcpwlrdr55xadhtv5iifxjem@gz4wjtng7b42>
References: <n37j6cbsogluma25crzruaiq7qcslnjeoroyybsy3vw2cokpcm@mh7r3ocp24cb>
 <CA+fCnZebmy-fZdNonrgLofepTPL5hU6P8R37==sygTLBSRoa+w@mail.gmail.com>
 <fv7fn3jivqcgw7mum6zadfcy2fbn73lygtxyy5p3zqpelfiken@5bmhbdufxgez>
 <CA+fCnZfQEueCifc-8d5NVWEUtAiOG1eRW-LFKbOhab_Y7jqU0Q@mail.gmail.com>
 <osqmp2j6gsmgbkle6mwhoaf65mjn4a4w3e5hsfbyob6f44wcg6@7rihb5otzl2z>
 <CANpmjNMw3N09x06Q+0mFCEeTKfUsDdXwXM2hdgAQ+wwbZGpB9w@mail.gmail.com>
 <rbcdbilhh67fvjdgnstu25v4jnfeesthoxstnzzglynbngu5bk@5ozwgzaulbsx>
 <CA+fCnZf5kxWUWCzK8EKgUuq_E2rYv5aw=SqZMDb93+=7vSUp+w@mail.gmail.com>
 <rgndtm3sawyzdh76oofoqp22jyqdb25sd4326k2heevjmxum7f@wfgwvdf4iuyi>
 <CANpmjNN5Q+byA3sWv1uB_R=QYQxKg5YsLKayqv7WNWokkL5H4Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNN5Q+byA3sWv1uB_R=QYQxKg5YsLKayqv7WNWokkL5H4Q@mail.gmail.com>
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b=GeWplGkk;       spf=pass
 (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as
 permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=tum.de
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

On 12.12.2023 10:32, Marco Elver wrote:
> On Tue, 12 Dec 2023 at 10:19, Paul Heidekr=C3=BCger <paul.heidekrueger@tu=
m.de> wrote:
> >
> > On 12.12.2023 00:37, Andrey Konovalov wrote:
> > > On Tue, Dec 12, 2023 at 12:35=E2=80=AFAM Paul Heidekr=C3=BCger
> > > <paul.heidekrueger@tum.de> wrote:
> > > >
> > > > Using CONFIG_FTRACE=3Dy instead of CONFIG_TRACEPOINTS=3Dy produces =
the same error
> > > > for me.
> > > >
> > > > So
> > > >
> > > >         CONFIG_KUNIT=3Dy
> > > >         CONFIG_KUNIT_ALL_TESTS=3Dn
> > > >         CONFIG_FTRACE=3Dy
> > > >         CONFIG_KASAN=3Dy
> > > >         CONFIG_KASAN_GENERIC=3Dy
> > > >         CONFIG_KASAN_KUNIT_TEST=3Dy
> > > >
> > > > produces
> > > >
> > > >         =E2=9E=9C   ./tools/testing/kunit/kunit.py run --kunitconfi=
g=3Dmm/kasan/.kunitconfig --arch=3Darm64
> > > >         Configuring KUnit Kernel ...
> > > >         Regenerating .config ...
> > > >         Populating config with:
> > > >         $ make ARCH=3Darm64 O=3D.kunit olddefconfig CC=3Dclang
> > > >         ERROR:root:Not all Kconfig options selected in kunitconfig =
were in the generated .config.
> > > >         This is probably due to unsatisfied dependencies.
> > > >         Missing: CONFIG_KASAN_KUNIT_TEST=3Dy
> > > >
> > > > By that error message, CONFIG_FTRACE appears to be present in the g=
enerated
> > > > config, but CONFIG_KASAN_KUNIT_TEST still isn't. Presumably,
> > > > CONFIG_KASAN_KUNIT_TEST is missing because of an unsatisfied depend=
ency, which
> > > > must be CONFIG_TRACEPOINTS, unless I'm missing something ...
> > > >
> > > > If I just generate an arm64 defconfig and select CONFIG_FTRACE=3Dy,
> > > > CONFIG_TRACEPOINTS=3Dy shows up in my .config. So, maybe this is ku=
nit.py-related
> > > > then?
> > > >
> > > > Andrey, you said that the tests have been working for you; are you =
running them
> > > > with kunit.py?
> > >
> > > No, I just run the kernel built with a config file that I put togethe=
r
> > > based on defconfig.
> >
> > Ah. I believe I've figured it out.
> >
> > When I add CONFIG_STACK_TRACER=3Dy in addition to CONFIG_FTRACE=3Dy, it=
 works.
>=20
> CONFIG_FTRACE should be enough - maybe also check x86 vs. arm64 to debug =
more.

See below.

> > CONFIG_STACK_TRACER selects CONFIG_FUNCTION_TRACER, CONFIG_FUNCTION_TRA=
CER
> > selects CONFIG_GENERIC_TRACER, CONFIG_GENERIC_TRACER selects CONFIG_TRA=
CING, and
> > CONFIG_TRACING selects CONFIG_TRACEPOINTS.
> >
> > CONFIG_BLK_DEV_IO_TRACE=3Dy also works instead of CONFIG_STACK_TRACER=
=3Dy, as it
> > directly selects CONFIG_TRACEPOINTS.
> >
> > CONFIG_FTRACE=3Dy on its own does not appear suffice for kunit.py on ar=
m64.
>=20
> When you build manually with just CONFIG_FTRACE, is CONFIG_TRACEPOINTS en=
abled?

When I add CONFIG_FTRACE and enter-key my way through the FTRACE prompts - =
I=20
believe because CONFIG_FTRACE is a menuconfig? - at the beginning of a buil=
d,=20
CONFIG_TRACEPOINTS does get set on arm64, yes.

On X86, the defconfig already includes CONIFG_TRACEPOINTS.

I also had a closer look at how kunit.py builds its configs.
I believe it does something along the following lines:

	cp <path_to_kunitconfig> .kunit/.config
	make ARCH=3Darm64 O=3D.kunit olddefconfig

On arm64, that isn't enough to set CONFIG_TRACEPOINTS; same behaviour when =
run=20
outside of kunit.py.

For CONFIG_TRACEPOINTS, `make ARCH=3Darm64 menuconfig` shows:

	Symbol: TRACEPOINTS [=3Dn]
	Type  : bool
	Defined at init/Kconfig:1920
	Selected by [n]:
		- TRACING [=3Dn]
		- BLK_DEV_IO_TRACE [=3Dn] && FTRACE [=3Dy] && SYSFS [=3Dy] && BLOCK [=3Dy=
]

So, CONFIG_TRACING or CONFIG_BLK_DEV_IO_TRACE are the two options that prev=
ent=20
CONFIG_TRACEPOINTS from being set on arm64.

For CONFIG_TRACING we have:

	Symbol: TRACING [=3Dn]
	Type  : bool
	Defined at kernel/trace/Kconfig:157
	Selects: RING_BUFFER [=3Dn] && STACKTRACE [=3Dy] && TRACEPOINTS [=3Dn] && =
NOP_TRACER [=3Dn] && BINARY_PRINTF [=3Dn] && EVENT_TRACING [=3Dn] && TRACE_=
CLOCK [=3Dy] && TASKS_RCU [=3Dn]
	Selected by [n]:
		- DRM_I915_TRACE_GEM [=3Dn] && HAS_IOMEM [=3Dy] && DRM_I915 [=3Dn] && EXP=
ERT [=3Dn] && DRM_I915_DEBUG_GEM [=3Dn]
		- DRM_I915_TRACE_GTT [=3Dn] && HAS_IOMEM [=3Dy] && DRM_I915 [=3Dn] && EXP=
ERT [=3Dn] && DRM_I915_DEBUG_GEM [=3Dn]
		- PREEMPTIRQ_TRACEPOINTS [=3Dn] && (TRACE_PREEMPT_TOGGLE [=3Dn] || TRACE_=
IRQFLAGS [=3Dn])
		- GENERIC_TRACER [=3Dn]
		- ENABLE_DEFAULT_TRACERS [=3Dn] && FTRACE [=3Dy] && !GENERIC_TRACER [=3Dn=
]
		- FPROBE_EVENTS [=3Dn] && FTRACE [=3Dy] && FPROBE [=3Dn] && HAVE_REGS_AND=
_STACK_ACCESS_API [=3Dy]
		- KPROBE_EVENTS [=3Dn] && FTRACE [=3Dy] && KPROBES [=3Dn] && HAVE_REGS_AN=
D_STACK_ACCESS_API [=3Dy]
		- UPROBE_EVENTS [=3Dn] && FTRACE [=3Dy] && ARCH_SUPPORTS_UPROBES [=3Dy] &=
& MMU [=3Dy] && PERF_EVENTS [=3Dn]
		- SYNTH_EVENTS [=3Dn] && FTRACE [=3Dy]
		- USER_EVENTS [=3Dn] && FTRACE [=3Dy]
		- HIST_TRIGGERS [=3Dn] && FTRACE [=3Dy] && ARCH_HAVE_NMI_SAFE_CMPXCHG [=
=3Dy]

> > I believe the reason my .kunitconfig as well as the existing
> > mm/kfence/.kunitconfig work on X86 is because CONFIG_TRACEPOINTS=3Dy is=
 present in
> > an X86 defconfig.
> >
> > Does this make sense?
> >
> > Would you welcome a patch addressing this for the existing
> > mm/kfence/.kunitconfig?
> >
> > I would also like to submit a patch for an mm/kasan/.kunitconfig. Do yo=
u think
> > that would be helpful too?
> >
> > FWICT, kernel/kcsan/.kunitconfig might also be affected since
> > CONFIG_KCSAN_KUNIT_TEST also depends on CONFIG_TRACEPOITNS, but I would=
 have to
> > test that. That could be a third patch.
>=20
> I'd support figuring out the minimal config (CONFIG_FTRACE or
> something else?) that satisfies the TRACEPOINTS dependency. I always
> thought CONFIG_FTRACE ought to be the one config option, but maybe
> something changed.

If we want a minimal config, setting CONFIG_BLK_DEV_IO_TRACE,=20
CONFIG_SYNTH_EVENTS or CONFIG_USER_EVENTS seem like viable options, for=20
instance. But AFAICT, setting them in the context of KASan doesn't really m=
ake=20
sense, and I might be missing an obvious choice here too.

What do you think?

> Also maybe one of the tracing maintainers can help untangle what's
> going on here.
>=20
> Thanks,
> -- Marco

Many thanks,
Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/h7qw4rhqovyq5trm5kyvabshqmxcpwlrdr55xadhtv5iifxjem%40gz4wjtng7b42=
.
