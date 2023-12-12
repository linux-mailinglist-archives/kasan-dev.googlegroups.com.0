Return-Path: <kasan-dev+bncBAABBNOL4CVQMGQE2ZDFO2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id AB48B80E745
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 10:19:50 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-50bfbf019d3sf4067410e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Dec 2023 01:19:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702372790; cv=pass;
        d=google.com; s=arc-20160816;
        b=A0/BisZ96Jq4FPpTlSmF5H1IY3u+loyxipE5qDMhwhRF4ph2ggWl1CxhlpN6TXHfhi
         o3dxl1GTo3YS/Mwi4NN3E2swdzqrApRoDRgannFUAV9vjMoe+IO3s20FUwl/PSRrzqcP
         +9XFmmYv+CDV0cWXxbNsP1owXn9C5caBFyPAGPUgDRYeThM0fw8KXE5OjfjVL5gZPZ/g
         /p0iPSdEQdypsHbGi3lMAzNp8kAXXh0+UAcQKfc+EDszdHLHlGd8stSujEmTidOkT1Yg
         kw7JUdnVip5Z2v9vL0NwveD6iKC1P/xGwLnpXdenaF0VDLr+u5iRDGtF4srqhbNmURxv
         tjlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=chA6woH29Qk1C+gAClTxvB6Gw0/saKDn9yq9c4Vt/44=;
        fh=fWpG2EFyFDgCrE1mvgdIpn6huS4lG6SyInP1TlGxmoc=;
        b=K9S08xA0sJ1E7IlABBP1Ob7XxnpLktIwgrDaAKUMBFPhbUPduJWA2nkFzFjKmbQsV/
         HqYCoZqPAkAs1XeKcJV8uVyB2dR/xqofOXelbWLkaOQylTYxMzOoFWVbeahZijVpBpiQ
         xiW+hRVPzmd84XqtHx36Q0BrZmtYTRyjQrKvu8fh5ENMVOL43E40FIpiWVYgBzCPmJ+1
         nHO3j+KVqyrMd88qbp/rMsXf/PEVY4+k/YXfPTfDbwHzy8IDt4xl+a7Nu29NYyps8JtE
         4bZRy3/K11dhQN8fJ0/pXx4s59Vxed42cnLqK0LBv6XCyxN8nf3jdzycMu4R9U5S4/Ox
         PKOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=icWpRiDQ;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702372790; x=1702977590; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=chA6woH29Qk1C+gAClTxvB6Gw0/saKDn9yq9c4Vt/44=;
        b=OF/NGXL8yLQhFA3MEYPohu0jM4zkbYZNFeMUSCDTD2Cp33viMOM+TDvBSsyIicWnXK
         yEUEir0lvLeI3uM5NmY/IlgmZJ1IGS6bGByM9UcaT7pb2omFoP/W2kYTX+mc0LVCpO/W
         xUwaoYBFkKk0TYOLg6k630ubdoMZed4zB+ZzrUPiPnkIb9klqBxBgDSb7J7bkEdRu9XK
         TdJCy3R95nhkUi4r17Bsd9GyUck6f0HeQOEQ6jzroTlEcx/fhEJQLT/JRmppJRnIxc9R
         OcSlS7RNea9qatsxbmrFMOZMBlYv0gO8rqhE08kRfPfMeTkVEjK3b+jk7tJwmPr17xRH
         Jpcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702372790; x=1702977590;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=chA6woH29Qk1C+gAClTxvB6Gw0/saKDn9yq9c4Vt/44=;
        b=U8XrI8w3QoleKa0/BCcKkjkGKr/gaDKeMdikkLw2CxZ4t0vUmwHjVOXNqLYERvbFeI
         Ifg51ipDSs0KBJvZzgdPsAyk7is3zT5aS9XRto5aHdOgmllPFNBjYhN2wO9efcZnhBuC
         5ZNlNJgnieyeJvlTT084gIn8kbXSVeIHG8Pw3F8SzF5ZJlkpJSt6+p0jQqHRI/QujC38
         wHm7m1ripK6wCbHU4H01Ynuy/3ZEwXMarFtHLexznVCzSqDdK7IG+RmnHZXijjn6rd9h
         PcdskNKLZ2GmZxjRh/mYuhpMX6cWsygBVFvlBByuFPSAzBjwL/pPjpvwyehab+KV5rwz
         FBCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxhp1NHtlg8sVqGLSLu5gJjiyFhh9OvUm0NuOkaQB7rKP7x46+3
	dPFNXpwagucNIEK0q23rOV4=
X-Google-Smtp-Source: AGHT+IH9+R6VpPJBMKSeCebjl7R6eSHDGFcjzHH6D5mhBqgcosydLlU+OB5JNzellKLPzYzDjvFQAQ==
X-Received: by 2002:ac2:4e8f:0:b0:50c:44:919e with SMTP id o15-20020ac24e8f000000b0050c0044919emr2085917lfr.108.1702372789744;
        Tue, 12 Dec 2023 01:19:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fc91:0:b0:333:33e9:256d with SMTP id g17-20020adffc91000000b0033333e9256dls335760wrr.1.-pod-prod-01-eu;
 Tue, 12 Dec 2023 01:19:48 -0800 (PST)
X-Received: by 2002:a5d:55c4:0:b0:333:2fd2:2f07 with SMTP id i4-20020a5d55c4000000b003332fd22f07mr2839301wrw.128.1702372788263;
        Tue, 12 Dec 2023 01:19:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702372788; cv=none;
        d=google.com; s=arc-20160816;
        b=nuPfWSugGmD1k9dZZA+PuMOR8qwjJl3kJzqxN27fu9sfHYJSSU0pH7/nXYeYKJv1xz
         nEaD4AEa70GIYlvd3K1utNIseo7yd477dqZwDMSa3FhWmm7OWUHn+Ed/26axbH9CNhWI
         +l5eQNDJh3V0SZ+b7rVYhw0nulA2VTuRwK6FeVNXTyXh5blsbMwIep/Pzzy9Zn1+UlCS
         JyNpgJNHXFj3mKGZ7dbXdKKxzCj0+LKd/Z0HMnYrL4ZCK5eypx3sQrhCqNGncOf4xR4Y
         SchTxtuSxm4ChG2vRlAEJEA8J+bQSDjMv03tEwa8HrVZ8xOaVE0You+EauI/CBS6SX8k
         LH/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=n3iXsZTA7DDZEZZBAbZi7ahs/svo8ZJWI4qmMuM5zT4=;
        fh=fWpG2EFyFDgCrE1mvgdIpn6huS4lG6SyInP1TlGxmoc=;
        b=zatXjaPgPgtnHxKt3M7M5C5Vapxt9hXxZ59uAPnbt4eXMrS5OifR3cZ2Z60eweSEFc
         W+KtNy9cgJjT+wUFZ1rqGqtM5/n29aQPefDDTAgJSUlGsiOhyAp5l3FV4/WFuJjg2d3F
         h/jXyAKIKnAQPWLJMcX248o8pB6eX+h29Ygw3h8QJQ/K4CL4Hjf6r8VavcF7SBLIifLi
         ujFKMCQlJJ1cepAI5J9diCbEHm8a3SECjc0G1uX2HcKMOQU/ZlQ6h/XVKvWpOD/blATa
         Bel2RMum4ulha+fRwKbeOlM1oGKL4wZF4olpEPehMhq27UJtdvO3fjHpBt7mdQaIrOEs
         dV9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=icWpRiDQ;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
Received: from postout2.mail.lrz.de (postout2.mail.lrz.de. [129.187.255.138])
        by gmr-mx.google.com with ESMTPS id x5-20020adfffc5000000b0033352382817si354645wrs.2.2023.12.12.01.19.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Dec 2023 01:19:48 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) client-ip=129.187.255.138;
Received: from lxmhs52.srv.lrz.de (localhost [127.0.0.1])
	by postout2.mail.lrz.de (Postfix) with ESMTP id 4SqCkB4ZNdzyTl;
	Tue, 12 Dec 2023 10:19:46 +0100 (CET)
X-Virus-Scanned: by amavisd-new at lrz.de in lxmhs52.srv.lrz.de
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
Received: from postout2.mail.lrz.de ([127.0.0.1])
	by lxmhs52.srv.lrz.de (lxmhs52.srv.lrz.de [127.0.0.1]) (amavisd-new, port 20024)
	with LMTP id U88J6q2Jd8Lb; Tue, 12 Dec 2023 10:19:46 +0100 (CET)
Received: from cerulean.fritz.box (unknown [IPv6:2001:a61:245c:a01:443b:cc34:8ae7:6ede])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout2.mail.lrz.de (Postfix) with ESMTPSA id 4SqCk90XN5zyTm;
	Tue, 12 Dec 2023 10:19:45 +0100 (CET)
Date: Tue, 12 Dec 2023 10:19:41 +0100
From: Paul =?utf-8?Q?Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Marco Elver <elver@google.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Peter Collingbourne <pcc@google.com>, andrey.konovalov@linux.dev, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	linux-trace-kernel@vger.kernel.org, Nick Desaulniers <ndesaulniers@google.com>
Subject: Re: [PATCH v3 1/3] kasan: switch kunit tests to console tracepoints
Message-ID: <rgndtm3sawyzdh76oofoqp22jyqdb25sd4326k2heevjmxum7f@wfgwvdf4iuyi>
References: <CAMn1gO6heXaovFy6jvpWS8TFLBhTomqNuxJmt_chrd5sYtskvw@mail.gmail.com>
 <20230505095805.759153de@gandalf.local.home>
 <n37j6cbsogluma25crzruaiq7qcslnjeoroyybsy3vw2cokpcm@mh7r3ocp24cb>
 <CA+fCnZebmy-fZdNonrgLofepTPL5hU6P8R37==sygTLBSRoa+w@mail.gmail.com>
 <fv7fn3jivqcgw7mum6zadfcy2fbn73lygtxyy5p3zqpelfiken@5bmhbdufxgez>
 <CA+fCnZfQEueCifc-8d5NVWEUtAiOG1eRW-LFKbOhab_Y7jqU0Q@mail.gmail.com>
 <osqmp2j6gsmgbkle6mwhoaf65mjn4a4w3e5hsfbyob6f44wcg6@7rihb5otzl2z>
 <CANpmjNMw3N09x06Q+0mFCEeTKfUsDdXwXM2hdgAQ+wwbZGpB9w@mail.gmail.com>
 <rbcdbilhh67fvjdgnstu25v4jnfeesthoxstnzzglynbngu5bk@5ozwgzaulbsx>
 <CA+fCnZf5kxWUWCzK8EKgUuq_E2rYv5aw=SqZMDb93+=7vSUp+w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZf5kxWUWCzK8EKgUuq_E2rYv5aw=SqZMDb93+=7vSUp+w@mail.gmail.com>
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b=icWpRiDQ;       spf=pass
 (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as
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

On 12.12.2023 00:37, Andrey Konovalov wrote:
> On Tue, Dec 12, 2023 at 12:35=E2=80=AFAM Paul Heidekr=C3=BCger
> <paul.heidekrueger@tum.de> wrote:
> >
> > Using CONFIG_FTRACE=3Dy instead of CONFIG_TRACEPOINTS=3Dy produces the =
same error
> > for me.
> >
> > So
> >
> >         CONFIG_KUNIT=3Dy
> >         CONFIG_KUNIT_ALL_TESTS=3Dn
> >         CONFIG_FTRACE=3Dy
> >         CONFIG_KASAN=3Dy
> >         CONFIG_KASAN_GENERIC=3Dy
> >         CONFIG_KASAN_KUNIT_TEST=3Dy
> >
> > produces
> >
> >         =E2=9E=9C   ./tools/testing/kunit/kunit.py run --kunitconfig=3D=
mm/kasan/.kunitconfig --arch=3Darm64
> >         Configuring KUnit Kernel ...
> >         Regenerating .config ...
> >         Populating config with:
> >         $ make ARCH=3Darm64 O=3D.kunit olddefconfig CC=3Dclang
> >         ERROR:root:Not all Kconfig options selected in kunitconfig were=
 in the generated .config.
> >         This is probably due to unsatisfied dependencies.
> >         Missing: CONFIG_KASAN_KUNIT_TEST=3Dy
> >
> > By that error message, CONFIG_FTRACE appears to be present in the gener=
ated
> > config, but CONFIG_KASAN_KUNIT_TEST still isn't. Presumably,
> > CONFIG_KASAN_KUNIT_TEST is missing because of an unsatisfied dependency=
, which
> > must be CONFIG_TRACEPOINTS, unless I'm missing something ...
> >
> > If I just generate an arm64 defconfig and select CONFIG_FTRACE=3Dy,
> > CONFIG_TRACEPOINTS=3Dy shows up in my .config. So, maybe this is kunit.=
py-related
> > then?
> >
> > Andrey, you said that the tests have been working for you; are you runn=
ing them
> > with kunit.py?
>=20
> No, I just run the kernel built with a config file that I put together
> based on defconfig.

Ah. I believe I've figured it out.

When I add CONFIG_STACK_TRACER=3Dy in addition to CONFIG_FTRACE=3Dy, it wor=
ks.

CONFIG_STACK_TRACER selects CONFIG_FUNCTION_TRACER, CONFIG_FUNCTION_TRACER=
=20
selects CONFIG_GENERIC_TRACER, CONFIG_GENERIC_TRACER selects CONFIG_TRACING=
, and=20
CONFIG_TRACING selects CONFIG_TRACEPOINTS.=20

CONFIG_BLK_DEV_IO_TRACE=3Dy also works instead of CONFIG_STACK_TRACER=3Dy, =
as it=20
directly selects CONFIG_TRACEPOINTS.=20

CONFIG_FTRACE=3Dy on its own does not appear suffice for kunit.py on arm64.

I believe the reason my .kunitconfig as well as the existing=20
mm/kfence/.kunitconfig work on X86 is because CONFIG_TRACEPOINTS=3Dy is pre=
sent in=20
an X86 defconfig.

Does this make sense?

Would you welcome a patch addressing this for the existing=20
mm/kfence/.kunitconfig?

I would also like to submit a patch for an mm/kasan/.kunitconfig. Do you th=
ink=20
that would be helpful too?

FWICT, kernel/kcsan/.kunitconfig might also be affected since=20
CONFIG_KCSAN_KUNIT_TEST also depends on CONFIG_TRACEPOITNS, but I would hav=
e to=20
test that. That could be a third patch.

What do you think?

Many thanks,
Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/rgndtm3sawyzdh76oofoqp22jyqdb25sd4326k2heevjmxum7f%40wfgwvdf4iuyi=
.
