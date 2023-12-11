Return-Path: <kasan-dev+bncBAABBJVD32VQMGQE5BWDAUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id D035E80DE8C
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 23:48:08 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2ca005e8de4sf41142341fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 14:48:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702334888; cv=pass;
        d=google.com; s=arc-20160816;
        b=ok7SfLW6fRZXeE3BPYJRUPrtkf5Yj2X8QlN6SBF7iccXpx8XV9TJpYCuumNezzEa8w
         RWmGyjQ2+ojswqkCtmXltLN6zS++O8/IFDB9ckI0HOnnp/UZnJG+Ck2SrRlwsA3V7+f/
         vx18rNXbiWbeo3YrPDJPWehRCz0qhgX60GZqWCgZjFzB1kZB+o09L8WN0d3SUYZy0btw
         5gxWp6buKKLonpkvQrsAawNy8kShN7cBJZzdmnpg07MelPvwoiSgU058eAQbVOiRjh4K
         UjBTy6ok1KCqtlm2Yn1a6r5xcbDcEHG0JoBe258ipIuFZ5Pg/h5L1vQdv6QGToOZC6dB
         Ov2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=XzR1EjNC2Mz03qnjq7da2ygPTqCl0g4eI2eeRfynCxM=;
        fh=DaPmRuawHnAU18yOIjRFb3bKY82uB1AyEdAq5zDOlGw=;
        b=ahJOE5c7KjGTzYA3BokC5Ux+78fx6zZglQMkN3M2SE4+AqId1RIlqKON4PavR9SN6E
         qV6Ox5HXz6bEOAQD4BY9LgQIeaMxxBZD3xhzpaimMhnw0jo2uFIRKGrNc/zval4bduZh
         zpUQ2MwuvIqewRsaZMEzY+Z3B7vTZQ/YSmxNzMQQe9JH2lcuvgkEdupt0Jz/FTH4Ak69
         H69RZabmNTo3xyL+Px4bqiKStj3JASoaJ49ZCfxY2RY5b6ea3hqI+9aG1Rrsg6H13H6S
         9su9hKOGdOuFOnWIJDrSrhX8yueRXVTDN9+WHlXntrQ6hxXzxKWVoGtBsRhJYUMUqTri
         OuuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=MZQYpE9q;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702334888; x=1702939688; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XzR1EjNC2Mz03qnjq7da2ygPTqCl0g4eI2eeRfynCxM=;
        b=RUQBXAMTz8qv83+kECUNxnD1c984pv9c27a+iG7NWYjvGBOpLJP3ni106d+zRgzJZl
         WW7RejoDAvoNx23rRzEj/JRknBpPxrIgqoZFxKz+AXC8qho86Q03sI9LC6E3WPFO9P3y
         8cu5j+Mbx6I3bo/sk8PdVhVtwEn/4UXDHQ8xPi/8wa8Fvm3MnGcAYyF1jxn04ss5mQNo
         6MBdNA3qDwwW0CreBvCOn6uPxtXA/z4pQNp/QzE3z87CkUzNIEvDz82UruuudjPTavXu
         4Q3tn+jFOFxp3KdndQEPBP4fwh3XDHi3rs9Jqt7R1yBN1M9D4jGbtU3/DUg7ZG5RHEr6
         Zskw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702334888; x=1702939688;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XzR1EjNC2Mz03qnjq7da2ygPTqCl0g4eI2eeRfynCxM=;
        b=XSFHQszfbS8CvWHobEj0p1+OPp4KR4J2zOJ7vBnRErVA52GjsbAdzR01+UuHtZdNtt
         LmTvs9hqJyj5wfzwOiPXz9OfeJcIHz6cLw477A+hnKACNYeUBjQDKErE41bbLJIMmGpk
         RzA3b2PJJA2CYH9VQTqs9dqlzDjbCNWw0uThrpnSeYFBbpqj4RJXUqL6RmJQCtRCimhj
         5a7zairgnZhb1ApVE3LL8mCEbE64crFcjdcgTrKBCoTxvvd2BoVsrXFbabnSQBWpAPud
         M0KVzLtcG7Tt1ksAkRjQA7SrKxwX7fT8AVIGcxsvESWmXwcKp3qyUxYtIUjbokOYU2K3
         BU0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywumm9di8LdQar9OY0Z8ivTkfPGM1I1EcIQns2w5KpbR2wccL0Z
	uhoxVBSncucAxiE9ipusjHc=
X-Google-Smtp-Source: AGHT+IG1Q7LP2BV89hg4XhyPOpdZLEusgvYm0lO8D225a37YtSeP+QdSDNYfTcdxey6CrD+ZJd7EyQ==
X-Received: by 2002:a05:6512:39c7:b0:50d:1b8e:b97 with SMTP id k7-20020a05651239c700b0050d1b8e0b97mr2587906lfu.139.1702334886649;
        Mon, 11 Dec 2023 14:48:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d1f:b0:50c:aa5:1218 with SMTP id
 d31-20020a0565123d1f00b0050c0aa51218ls2054209lfv.0.-pod-prod-06-eu; Mon, 11
 Dec 2023 14:48:05 -0800 (PST)
X-Received: by 2002:a05:6512:3e25:b0:50e:4e7:35dc with SMTP id i37-20020a0565123e2500b0050e04e735dcmr359159lfv.26.1702334884840;
        Mon, 11 Dec 2023 14:48:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702334884; cv=none;
        d=google.com; s=arc-20160816;
        b=QBXWR3hGLunv60s7LmS/ImQvR7TbVFF4k9a2o0x7RzO3yaOarzWYZBqZwFRUUGgjNQ
         nWRIZwtilimefY8nZ8ISFFDCp1rResqZMwgOhwILNiC7gvvQMb+abZkax+DLYYC0b+28
         f643yoaMiJAgcWntr0k1q4uLmik9UCC8JndKOfB/Ut8huGhWy/mrGc0pImqqqMnsIO1Q
         ucTZ7mFZuYwlteaAiFQf3nZ7cXLAAXUXAPTWpGnj+DEv7PsXDEcEXDG8IepgHRCbup8C
         VXcPu5Kbtf15eBwff8HcuvqGlVGEGpFLcc01cOUcXqip+WIghcnrFYQL5j6De2mchBg6
         c8JQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=D31BDla4PBMR0dv+0ByYX5fPYZZCLsOgW6S2YQOK1H4=;
        fh=DaPmRuawHnAU18yOIjRFb3bKY82uB1AyEdAq5zDOlGw=;
        b=tFhmXn7osz4sDyPk5Djh9xofKOP34cmSphRlou91+J40Cy8C/f/wLb6Jll7iEOXS66
         wPkDUJc5KRbtpFQ+YfZoTskgqA9du3EtxY+5cj2owi6Q5VixEHK2WCpVIeNj+SVEYkMk
         AmxDjc7AzfXSp5dGphAapsa4hAWa8MAtYwnnT2nQ7RyM7omkBIQoXJmmRuige09zaznK
         /59I7dj7Lf52n4V2sS8BZKZFvr9yAAMbGCw6wtFJE2hlu1hCSfBRL1aN8DzgG3Dtd78D
         oVMO2K8ImmmdsrG/sOxRFdSdbJV4CQUVsi+Hg+9H5zCyWqkb3KdS7mSzhmhVuCufih9s
         RJEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=MZQYpE9q;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
Received: from postout2.mail.lrz.de (postout2.mail.lrz.de. [129.187.255.138])
        by gmr-mx.google.com with ESMTPS id s20-20020a056512203400b0050bc7296c7csi335358lfs.2.2023.12.11.14.48.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Dec 2023 14:48:04 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) client-ip=129.187.255.138;
Received: from lxmhs52.srv.lrz.de (localhost [127.0.0.1])
	by postout2.mail.lrz.de (Postfix) with ESMTP id 4SpxjG5tDvzyTl;
	Mon, 11 Dec 2023 23:48:02 +0100 (CET)
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
	with LMTP id RXtrqxiiQ05L; Mon, 11 Dec 2023 23:48:02 +0100 (CET)
Received: from cerulean.fritz.box (unknown [IPv6:2001:a61:245c:a01:443b:cc34:8ae7:6ede])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout2.mail.lrz.de (Postfix) with ESMTPSA id 4SpxjF04PnzyTZ;
	Mon, 11 Dec 2023 23:48:00 +0100 (CET)
Date: Mon, 11 Dec 2023 23:47:57 +0100
From: Paul =?utf-8?Q?Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, 
	Peter Collingbourne <pcc@google.com>, Marco Elver <elver@google.com>, andrey.konovalov@linux.dev, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	linux-trace-kernel@vger.kernel.org, Nick Desaulniers <ndesaulniers@google.com>
Subject: Re: [PATCH v3 1/3] kasan: switch kunit tests to console tracepoints
Message-ID: <osqmp2j6gsmgbkle6mwhoaf65mjn4a4w3e5hsfbyob6f44wcg6@7rihb5otzl2z>
References: <CAMn1gO6reT+MTmogLOrOVoNqzLH+fKmQ2JRAGy-tDOTLx-fpyw@mail.gmail.com>
 <CANpmjNN7Gf_aeX+Y6g0UBL-cmTGEF9zgE7hQ1VK8F+0Yeg5Rvg@mail.gmail.com>
 <20230215143306.2d563215@rorschach.local.home>
 <CAMn1gO4_+-0x4ibpcASy4bLeZ+7rsmjx=0AYKGVDUApUbanSrQ@mail.gmail.com>
 <CAMn1gO6heXaovFy6jvpWS8TFLBhTomqNuxJmt_chrd5sYtskvw@mail.gmail.com>
 <20230505095805.759153de@gandalf.local.home>
 <n37j6cbsogluma25crzruaiq7qcslnjeoroyybsy3vw2cokpcm@mh7r3ocp24cb>
 <CA+fCnZebmy-fZdNonrgLofepTPL5hU6P8R37==sygTLBSRoa+w@mail.gmail.com>
 <fv7fn3jivqcgw7mum6zadfcy2fbn73lygtxyy5p3zqpelfiken@5bmhbdufxgez>
 <CA+fCnZfQEueCifc-8d5NVWEUtAiOG1eRW-LFKbOhab_Y7jqU0Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZfQEueCifc-8d5NVWEUtAiOG1eRW-LFKbOhab_Y7jqU0Q@mail.gmail.com>
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b=MZQYpE9q;       spf=pass
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

On 11.12.2023 21:51, Andrey Konovalov wrote:
> On Mon, Dec 11, 2023 at 7:59=E2=80=AFPM Paul Heidekr=C3=BCger
> <paul.heidekrueger@tum.de> wrote:
> >
> > > Hi Paul,
> > >
> > > I've been successfully running KASAN tests with CONFIG_TRACEPOINTS
> > > enabled on arm64 since this patch landed.
> >
> > Interesting ...
> >
> > > What happens when you try running the tests with .kunitconfig? Does
> > > CONFIG_TRACEPOINTS or CONFIG_KASAN_KUNIT_TEST get disabled during
> > > kernel building?
> >
> > Yes, exactly, that's what's happening.
> >
> > Here's the output kunit.py is giving me. I replaced CONFIG_DEBUG_KERNEL=
 with
> > CONFIG_TRACEPOINTS in my .kunitconfig. Otherwise, it's identical with t=
he one I
> > posted above.
> >
> >         =E2=9E=9C   ./tools/testing/kunit/kunit.py run --kunitconfig=3D=
mm/kasan/.kunitconfig --arch=3Darm64
> >         Configuring KUnit Kernel ...
> >         Regenerating .config ...
> >         Populating config with:
> >         $ make ARCH=3Darm64 O=3D.kunit olddefconfig
> >         ERROR:root:Not all Kconfig options selected in kunitconfig were=
 in the generated .config.
> >         This is probably due to unsatisfied dependencies.
> >         Missing: CONFIG_KASAN_KUNIT_TEST=3Dy, CONFIG_TRACEPOINTS=3Dy
> >
> > Does CONFIG_TRACEPOINTS have some dependency I'm not seeing? I couldn't=
 find a
> > reason why it would get disabled, but I could definitely be wrong.
>=20
> Does your .kunitconfig include CONFIG_TRACEPOINTS=3Dy? I don't see it in
> the listing that you sent earlier.

Yes. For the kunit.py output from my previous email, I replaced=20
CONFIG_DEBUG_KERNEL=3Dy with CONFIG_TRACEPOINTS=3Dy. So, the .kunitconfig I=
 used to=20
produce the output above was:
=09
	CONFIG_KUNIT=3Dy
	CONFIG_KUNIT_ALL_TESTS=3Dn
	CONFIG_TRACEPOINTS=3Dy
	CONFIG_KASAN=3Dy
	CONFIG_KASAN_GENERIC=3Dy
	CONFIG_KASAN_KUNIT_TEST=3Dy

This more or less mirrors what mm/kfence/.kunitconfig is doing, which also =
isn't=20
working on my side; kunit.py reports the same error.

Many thanks,
Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/osqmp2j6gsmgbkle6mwhoaf65mjn4a4w3e5hsfbyob6f44wcg6%407rihb5otzl2z=
.
