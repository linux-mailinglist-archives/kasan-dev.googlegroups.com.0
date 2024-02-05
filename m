Return-Path: <kasan-dev+bncBAABBRUPQOXAMGQEXSLPMYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 12B648498EE
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 12:34:32 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-51151eccdd5sf524776e87.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Feb 2024 03:34:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707132871; cv=pass;
        d=google.com; s=arc-20160816;
        b=RsKI7YQfkMSafdlTvLgMeCw3VBxE4kx05npRmKkFE+IZRb0DkmQd5hLt8pBspFyWsj
         YImvmDXmx0fvc+vk7l+dEpkSERecoL3fKPOVWCvLx7ryi8QgW5I9Klg0m+f5JoJscFUE
         S3rvS4Q/u++A43RsowP0rp9UBCC/lCYunE2tpZmT8wWpHZDuH/EAhv+xZpRqixoPUPX6
         RIxyFUE9xQ/zl7NLxafvPfHcjnbVMp8FO30wVwfzNWhbR9zN0kyIBFy8u7QkEhQLI+3D
         b0Nkixa8bDdOrtqstEQxfL9ufWp/d4jirk4IIuFRbHx5ZKhfhFm4PKop92Mz4hPE4c8Q
         7www==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=c3xLVj3EXPuuS+KLm/8Wi24wU+9+awklgJgvGSnX+sk=;
        fh=SfYqChfjNSR8pOfe7v4S8cQsRsYk1tnAJpwj5EpqGV0=;
        b=olKrMOh0hQiaT7HekEAmawZHAxnU290J5UeN/Z/eJ9ws3rFjLQhk/Ne8cPccwVChSy
         +qBLW+jfyhrkWtsI0Un03bxd8XpnaokPnD6Hm+OY7sBx/0Z/j0TP/iZWYn9hREqEa5F1
         EB+4H3DS1f9wP43g9tqf/pzwqBBrckNkOgoPk3cwqaAj2sQytz1w2YGCsw7+xpEHSbri
         kPitNibQlL7zh8n7DJzB1h/Fq4loM2WOofa7j82wIvQT5InjU1K9zhCEaA0+VoRzoVbd
         y3dGylxo39Eu6F6hoVSySxcGP8m9rdSS47Lgm6W7SQNblrNZr7W4P0xBfrJX75qrSaFU
         pxPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=AgzJMd+i;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707132871; x=1707737671; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=c3xLVj3EXPuuS+KLm/8Wi24wU+9+awklgJgvGSnX+sk=;
        b=xtNTKrI6f7EYbbwCBHQGJRKkVUPkbv+8IuhkrjmiQNuu56YGJK7QJC59jN7UPONp4r
         k1+XciFtCyNkOJ94ZA+TAeEAV74wXNhXlOlNA0W9ZdgXyJZzNm4pmdxHzWNb1YvQCnV7
         T0Hr40NirCOZ3WBmTMGGNoaeicAgrVWrj+l6rYowxyEFIBeHI6SpQF8RBr9XWdu746I9
         pFCMG3T1uvGV82gkhpLuWPyQVogjqZcqy2IzdSzH67cljrfjrl7WUPeSk1rMujpJSWgq
         QbaT1jydnM5sfT0X+pZ4Wlv6hAqukpBDPIn6pdITS00CbR6SyKnOjEJSiEEC/qs/XFfW
         O48g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707132871; x=1707737671;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c3xLVj3EXPuuS+KLm/8Wi24wU+9+awklgJgvGSnX+sk=;
        b=Z1byU0aF76L5m/iIiovgGY55P6Idb3Th4r+kDVPHcQEHSTwjgWSbl8QBoCTpUP8TQY
         HUAGnxHP22dsqA1Jp+5sQdjKVvHHbKDO3tYo0QoePkXqtn/dYIATxjvKGkSOMOYZyM+l
         YKXkUrOxlc9AKUd4eDgodSinRuu4whvl4zBf0x2MGvgA8zqLyN8KtRBUbVjEEDcNmObB
         C6XRjHdpS7ErW1c/epejG21EHZd4BwL1TrdYAXLduOSh6TiOVdcoCEgYegy/WgUxf2Sw
         yhRNrcMgDJ8GeX53LYiwRJBsmRsNUJvw3vPyy0OZ1IoPxK+ShQRz054xBWhe1fOjICh1
         uPjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxj91/QJtVBLd+xFtx1YAduVOZIdeotBjVFuuRCRQBYn1QUUC0x
	quxnQ6vBwvKfw2x/LN1r0ruMjj3iRTotskugUi7AboFKeKuFWQ/V
X-Google-Smtp-Source: AGHT+IHECQc8RSCHp2MCXgbCpUexrFsS/pUXSeJ72ft5Q/nnU5vCXX61BVFxkh1YDZhyqfBdmaI7Lw==
X-Received: by 2002:ac2:4ec4:0:b0:511:4ebc:5100 with SMTP id p4-20020ac24ec4000000b005114ebc5100mr1614150lfr.68.1707132870813;
        Mon, 05 Feb 2024 03:34:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:e91:b0:511:527e:5f6f with SMTP id
 bi17-20020a0565120e9100b00511527e5f6fls343381lfb.2.-pod-prod-04-eu; Mon, 05
 Feb 2024 03:34:29 -0800 (PST)
X-Received: by 2002:ac2:4a63:0:b0:511:486d:454b with SMTP id q3-20020ac24a63000000b00511486d454bmr3063222lfp.38.1707132869063;
        Mon, 05 Feb 2024 03:34:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707132869; cv=none;
        d=google.com; s=arc-20160816;
        b=T1j/aLcD7yr7ehqwD2SSikH3Y4OM60UFzT+FBwV7FCRTS/ZggdI5KQ0JERpiF+eepR
         QLDDfEgNpBTHO0jTl++tBHl0D0i9RONdyPPonfPmqf0lu8a0pVvLGWvhQrzOhJzED4Jl
         ndp4By/YpFLVmuRIe2uLR4IpDFYl3irnVzhFP3SrAScw964C+8YAhgHXrxg6LraXQ8QZ
         3ZV2HypW7YKK50TX3a7Keatz+lhmRMb79LFedpJ5OQDLCTz3BUFZT9gJ4aHLYd8EexNe
         dzmSmujGQOZk8Kq4HkdH1jjQNREMJhPUtFC++6TG8KPg/i82MRU6ZA7r5khsMPxw70Ro
         tIoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=4yfYSPWejnIMrq1elbAqFQGfVJkEKKXLWsqoOGicgfs=;
        fh=SfYqChfjNSR8pOfe7v4S8cQsRsYk1tnAJpwj5EpqGV0=;
        b=ghYUN96FhW+H07p9tEb6xu/9tgzmX7jHLhAwrIhzJFxI/9xbxS2jHxQTgo0+60Cp1E
         8VOVxhldPgjWfO7vtvdKDYWW87VA0e3/y+uI4q3Cerr9KPVXxRvTBXEaPDUjHB4UJIEG
         yJlLd0ckXz5yn1TP4ochk2edCvB+FDMVt+X2IyZf7W731kg5CzCJrIIGvjcF54LdGAyj
         t1VHKIeeo1Iw0pnTCsftacwlxRMQ1F/06l+9Lu40LxZF34B+YijQIYlUXFCJl6KfVwvL
         ledYRR6VtwJYS+tkeNSsfo7ZuxzYG14WSFuEvFfU3zPVrYOkCSAPuRg50p/Z9kWKXajk
         60ZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=AgzJMd+i;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
X-Forwarded-Encrypted: i=0; AJvYcCX3B+MITw9oqsudqy0d0qNOXlhwLMoXJh4mUPcAGW0d4fcYVPwIlylTcWnxNG2LaKzoKnCsR2THzgShem2GysIOR4nlSeKA/uobeg==
Received: from postout2.mail.lrz.de (postout2.mail.lrz.de. [129.187.255.138])
        by gmr-mx.google.com with ESMTPS id o25-20020a05600c511900b0040fd31815f3si152302wms.0.2024.02.05.03.34.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Feb 2024 03:34:28 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) client-ip=129.187.255.138;
Received: from lxmhs52.srv.lrz.de (localhost [127.0.0.1])
	by postout2.mail.lrz.de (Postfix) with ESMTP id 4TT46C4ZldzyTH;
	Mon,  5 Feb 2024 12:34:27 +0100 (CET)
X-Virus-Scanned: by amavisd-new at lrz.de in lxmhs52.srv.lrz.de
X-Spam-Flag: NO
X-Spam-Score: -2.884
X-Spam-Level: 
X-Spam-Status: No, score=-2.884 tagged_above=-999 required=5
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
	LRZ_HAS_SPF=0.001, LRZ_SUBJ_FW_RE=0.001, LRZ_URL_PLAIN_SINGLE=0.001,
	LRZ_URL_SINGLE_UTF8=0.001, T_SCC_BODY_TEXT_LINE=-0.01]
	autolearn=no autolearn_force=no
Received: from postout2.mail.lrz.de ([127.0.0.1])
	by lxmhs52.srv.lrz.de (lxmhs52.srv.lrz.de [127.0.0.1]) (amavisd-new, port 20024)
	with LMTP id hTsJ2oxF2cFS; Mon,  5 Feb 2024 12:34:25 +0100 (CET)
Received: from pine.fritz.box (unknown [IPv6:2001:a61:2560:7f01:69dc:22b:b206:7a57])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout2.mail.lrz.de (Postfix) with ESMTPSA id 4TT4681dSGzyTL;
	Mon,  5 Feb 2024 12:34:24 +0100 (CET)
Date: Mon, 5 Feb 2024 12:34:20 +0100
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
Message-ID: <8D76B3E2-91CD-46BC-B990-59D6D60AC9BA@tum.de>
X-Mailer: MailMate (1.14r5937)
References: <CA+fCnZebmy-fZdNonrgLofepTPL5hU6P8R37==sygTLBSRoa+w@mail.gmail.com>
 <fv7fn3jivqcgw7mum6zadfcy2fbn73lygtxyy5p3zqpelfiken@5bmhbdufxgez>
 <CA+fCnZfQEueCifc-8d5NVWEUtAiOG1eRW-LFKbOhab_Y7jqU0Q@mail.gmail.com>
 <osqmp2j6gsmgbkle6mwhoaf65mjn4a4w3e5hsfbyob6f44wcg6@7rihb5otzl2z>
 <CANpmjNMw3N09x06Q+0mFCEeTKfUsDdXwXM2hdgAQ+wwbZGpB9w@mail.gmail.com>
 <rbcdbilhh67fvjdgnstu25v4jnfeesthoxstnzzglynbngu5bk@5ozwgzaulbsx>
 <CA+fCnZf5kxWUWCzK8EKgUuq_E2rYv5aw=SqZMDb93+=7vSUp+w@mail.gmail.com>
 <rgndtm3sawyzdh76oofoqp22jyqdb25sd4326k2heevjmxum7f@wfgwvdf4iuyi>
 <CANpmjNN5Q+byA3sWv1uB_R=QYQxKg5YsLKayqv7WNWokkL5H4Q@mail.gmail.com>
 <h7qw4rhqovyq5trm5kyvabshqmxcpwlrdr55xadhtv5iifxjem@gz4wjtng7b42>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <h7qw4rhqovyq5trm5kyvabshqmxcpwlrdr55xadhtv5iifxjem@gz4wjtng7b42>
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b=AgzJMd+i;       spf=pass
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



On 7 Jan 2024, at 19:22, Paul Heidekr=C3=BCger wrote:

> On 12.12.2023 10:32, Marco Elver wrote:
>> On Tue, 12 Dec 2023 at 10:19, Paul Heidekr=C3=BCger <paul.heidekrueger@t=
um.de> wrote:
>>>
>>> On 12.12.2023 00:37, Andrey Konovalov wrote:
>>>> On Tue, Dec 12, 2023 at 12:35=E2=80=AFAM Paul Heidekr=C3=BCger
>>>> <paul.heidekrueger@tum.de> wrote:
>>>>>
>>>>> Using CONFIG_FTRACE=3Dy instead of CONFIG_TRACEPOINTS=3Dy produces th=
e same error
>>>>> for me.
>>>>>
>>>>> So
>>>>>
>>>>>         CONFIG_KUNIT=3Dy
>>>>>         CONFIG_KUNIT_ALL_TESTS=3Dn
>>>>>         CONFIG_FTRACE=3Dy
>>>>>         CONFIG_KASAN=3Dy
>>>>>         CONFIG_KASAN_GENERIC=3Dy
>>>>>         CONFIG_KASAN_KUNIT_TEST=3Dy
>>>>>
>>>>> produces
>>>>>
>>>>>         =E2=9E=9C   ./tools/testing/kunit/kunit.py run --kunitconfig=
=3Dmm/kasan/.kunitconfig --arch=3Darm64
>>>>>         Configuring KUnit Kernel ...
>>>>>         Regenerating .config ...
>>>>>         Populating config with:
>>>>>         $ make ARCH=3Darm64 O=3D.kunit olddefconfig CC=3Dclang
>>>>>         ERROR:root:Not all Kconfig options selected in kunitconfig we=
re in the generated .config.
>>>>>         This is probably due to unsatisfied dependencies.
>>>>>         Missing: CONFIG_KASAN_KUNIT_TEST=3Dy
>>>>>
>>>>> By that error message, CONFIG_FTRACE appears to be present in the gen=
erated
>>>>> config, but CONFIG_KASAN_KUNIT_TEST still isn't. Presumably,
>>>>> CONFIG_KASAN_KUNIT_TEST is missing because of an unsatisfied dependen=
cy, which
>>>>> must be CONFIG_TRACEPOINTS, unless I'm missing something ...
>>>>>
>>>>> If I just generate an arm64 defconfig and select CONFIG_FTRACE=3Dy,
>>>>> CONFIG_TRACEPOINTS=3Dy shows up in my .config. So, maybe this is kuni=
t.py-related
>>>>> then?
>>>>>
>>>>> Andrey, you said that the tests have been working for you; are you ru=
nning them
>>>>> with kunit.py?
>>>>
>>>> No, I just run the kernel built with a config file that I put together
>>>> based on defconfig.
>>>
>>> Ah. I believe I've figured it out.
>>>
>>> When I add CONFIG_STACK_TRACER=3Dy in addition to CONFIG_FTRACE=3Dy, it=
 works.
>>
>> CONFIG_FTRACE should be enough - maybe also check x86 vs. arm64 to debug=
 more.
>
> See below.
>
>>> CONFIG_STACK_TRACER selects CONFIG_FUNCTION_TRACER, CONFIG_FUNCTION_TRA=
CER
>>> selects CONFIG_GENERIC_TRACER, CONFIG_GENERIC_TRACER selects CONFIG_TRA=
CING, and
>>> CONFIG_TRACING selects CONFIG_TRACEPOINTS.
>>>
>>> CONFIG_BLK_DEV_IO_TRACE=3Dy also works instead of CONFIG_STACK_TRACER=
=3Dy, as it
>>> directly selects CONFIG_TRACEPOINTS.
>>>
>>> CONFIG_FTRACE=3Dy on its own does not appear suffice for kunit.py on ar=
m64.
>>
>> When you build manually with just CONFIG_FTRACE, is CONFIG_TRACEPOINTS e=
nabled?
>
> When I add CONFIG_FTRACE and enter-key my way through the FTRACE prompts =
- I
> believe because CONFIG_FTRACE is a menuconfig? - at the beginning of a bu=
ild,
> CONFIG_TRACEPOINTS does get set on arm64, yes.
>
> On X86, the defconfig already includes CONIFG_TRACEPOINTS.
>
> I also had a closer look at how kunit.py builds its configs.
> I believe it does something along the following lines:
>
>     cp <path_to_kunitconfig> .kunit/.config
>     make ARCH=3Darm64 O=3D.kunit olddefconfig
>
> On arm64, that isn't enough to set CONFIG_TRACEPOINTS; same behaviour whe=
n run
> outside of kunit.py.
>
> For CONFIG_TRACEPOINTS, `make ARCH=3Darm64 menuconfig` shows:
>
>     Symbol: TRACEPOINTS [=3Dn]
>     Type  : bool
>     Defined at init/Kconfig:1920
>     Selected by [n]:
>     	- TRACING [=3Dn]
>     	- BLK_DEV_IO_TRACE [=3Dn] && FTRACE [=3Dy] && SYSFS [=3Dy] && BLOCK =
[=3Dy]
>
> So, CONFIG_TRACING or CONFIG_BLK_DEV_IO_TRACE are the two options that pr=
event
> CONFIG_TRACEPOINTS from being set on arm64.
>
> For CONFIG_TRACING we have:
>
>     Symbol: TRACING [=3Dn]
>     Type  : bool
>     Defined at kernel/trace/Kconfig:157
>     Selects: RING_BUFFER [=3Dn] && STACKTRACE [=3Dy] && TRACEPOINTS [=3Dn=
] && NOP_TRACER [=3Dn] && BINARY_PRINTF [=3Dn] && EVENT_TRACING [=3Dn] && T=
RACE_CLOCK [=3Dy] && TASKS_RCU [=3Dn]
>     Selected by [n]:
>     	- DRM_I915_TRACE_GEM [=3Dn] && HAS_IOMEM [=3Dy] && DRM_I915 [=3Dn] &=
& EXPERT [=3Dn] && DRM_I915_DEBUG_GEM [=3Dn]
>     	- DRM_I915_TRACE_GTT [=3Dn] && HAS_IOMEM [=3Dy] && DRM_I915 [=3Dn] &=
& EXPERT [=3Dn] && DRM_I915_DEBUG_GEM [=3Dn]
>     	- PREEMPTIRQ_TRACEPOINTS [=3Dn] && (TRACE_PREEMPT_TOGGLE [=3Dn] || T=
RACE_IRQFLAGS [=3Dn])
>     	- GENERIC_TRACER [=3Dn]
>     	- ENABLE_DEFAULT_TRACERS [=3Dn] && FTRACE [=3Dy] && !GENERIC_TRACER =
[=3Dn]
>     	- FPROBE_EVENTS [=3Dn] && FTRACE [=3Dy] && FPROBE [=3Dn] && HAVE_REG=
S_AND_STACK_ACCESS_API [=3Dy]
>     	- KPROBE_EVENTS [=3Dn] && FTRACE [=3Dy] && KPROBES [=3Dn] && HAVE_RE=
GS_AND_STACK_ACCESS_API [=3Dy]
>     	- UPROBE_EVENTS [=3Dn] && FTRACE [=3Dy] && ARCH_SUPPORTS_UPROBES [=
=3Dy] && MMU [=3Dy] && PERF_EVENTS [=3Dn]
>     	- SYNTH_EVENTS [=3Dn] && FTRACE [=3Dy]
>     	- USER_EVENTS [=3Dn] && FTRACE [=3Dy]
>     	- HIST_TRIGGERS [=3Dn] && FTRACE [=3Dy] && ARCH_HAVE_NMI_SAFE_CMPXCH=
G [=3Dy]
>
>>> I believe the reason my .kunitconfig as well as the existing
>>> mm/kfence/.kunitconfig work on X86 is because CONFIG_TRACEPOINTS=3Dy is=
 present in
>>> an X86 defconfig.
>>>
>>> Does this make sense?
>>>
>>> Would you welcome a patch addressing this for the existing
>>> mm/kfence/.kunitconfig?
>>>
>>> I would also like to submit a patch for an mm/kasan/.kunitconfig. Do yo=
u think
>>> that would be helpful too?
>>>
>>> FWICT, kernel/kcsan/.kunitconfig might also be affected since
>>> CONFIG_KCSAN_KUNIT_TEST also depends on CONFIG_TRACEPOITNS, but I would=
 have to
>>> test that. That could be a third patch.
>>
>> I'd support figuring out the minimal config (CONFIG_FTRACE or
>> something else?) that satisfies the TRACEPOINTS dependency. I always
>> thought CONFIG_FTRACE ought to be the one config option, but maybe
>> something changed.
>
> If we want a minimal config, setting CONFIG_BLK_DEV_IO_TRACE,
> CONFIG_SYNTH_EVENTS or CONFIG_USER_EVENTS seem like viable options, for
> instance. But AFAICT, setting them in the context of KASan doesn't really=
 make
> sense, and I might be missing an obvious choice here too.
>
> What do you think?
>
>> Also maybe one of the tracing maintainers can help untangle what's
>> going on here.
>>
>> Thanks,
>> -- Marco
>
> Many thanks,
> Paul

Hi all,

Just giving this thread a polite bump, hoping that someone has some pointer=
s.

The TL;DR is the following: I=E2=80=99m trying to run KASan KUnit tests wit=
h the=20
following local .kunitconfig:

	CONFIG_KUNIT=3Dy
	CONFIG_KUNIT_ALL_TESTS=3Dn
	CONFIG_FTRACE=3Dy
	CONFIG_KASAN=3Dy
	CONFIG_KASAN_GENERIC=3Dy
	CONFIG_KASAN_KUNIT_TEST=3Dy

The problem is that on arm64, this does not appear to be enough to set all =
of=20
CONFIG_KASAN_KUNIT_TEST=E2=80=99s dependencies, namely CONFIG_TRACEPOINTS.

An additional option is needed to enable CONFIG_TRACEPOINTS. As per `make=
=20
menuconfig`, this is either CONFIG_BLK_DEV_IO_TRACE or any (combination of)=
=20
option(s) that enable(s) CONFIG_TRACING. See the `make menuconfig` output i=
n my=20
previous email for details.

Which option do you think is appropriate here? Or am I missing something?

For anyone wanting to reproduce, use:
./tools/testing/kunit/kunit.py run =E2=80=94kunitconfig=3D<path_to_above_ku=
nitconfig> --arch=3Darm64

Many thanks,
Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/8D76B3E2-91CD-46BC-B990-59D6D60AC9BA%40tum.de.
