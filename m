Return-Path: <kasan-dev+bncBCS2NBWRUIFBBKOA4WRAMGQEBL6IUFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CB526FB878
	for <lists+kasan-dev@lfdr.de>; Mon,  8 May 2023 22:48:42 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-3f3157128b4sf121322035e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 May 2023 13:48:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683578921; cv=pass;
        d=google.com; s=arc-20160816;
        b=M6fSRDe2JT8RyVql/9FmMCmDLMSUgiuUi5d5QnZtCXVUQWqfiPJs0EQk/QSGIRPkuI
         FqwcRpmyZltfked6jmUOS0getAXUSrAp9R1jvk1WeO/z50oJVq2kbMttkqVfLItF+sJR
         UFYTOhMOnQSCnYKL7mAojPjCLRA4f0xRTFupvEZJnl4aVbydn+H7JiZNlMwrtlUGUDxE
         E+SPQchVOgcAFOZdUkAHBBD1aGDZc4068HHkHwc/MLM99GjDD/heZYH8ndUV5PXv6MXR
         CUG4U1kcHqGW1ijGALfZu1AD5+PYE9Dzh0iXFosMv/4ldi+E02chhA1b10+8ofiEVfSm
         zVPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=sp97q4ePeokQmYbXaLRNWE+R7MdtQaY+CQCmSw49LGQ=;
        b=ESwyDQVTcp5K0t07yhsAdnptJhALLRs+6YDh6/78cVKmFSSqUPW0Cm3Mn+xdAIWMwK
         ExY6b1QniPZtxqZmve+YYbnHL7irfwwu6WtWdj5j9vzTNhzNcrr72eJTM1pewyYF+H2M
         klfxXT4yNFtbZmBL6BAXg6ifg0xUrMeKtn6wTZVWIHqBGyYsdKaTdbvhZ1+G/59oqpW3
         cAwTK907c/ThrD8en4cvZrdouc817+FD5W68M5MvWFqREvCH9nK/PYFBai0m3kmkuvh7
         A1y8G82/xnzRr38lu8ZgThOpTdb6tRae+ztS6zLgag1Gp22DSZiuHiyGwn2vJ0PO71U4
         k3VA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JlOqRkPd;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.25 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683578921; x=1686170921;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sp97q4ePeokQmYbXaLRNWE+R7MdtQaY+CQCmSw49LGQ=;
        b=G+7FCMJ0qK3MeWYfl2mSaO0rhfEYTAyzEpn8YJ+/ZzSsduYLAXoDakIZwc7q1iXdWO
         MtGRzJBoFS7z9GvQAhJXrw4fHCyEPPHz49o8QFg8M2p/HDYlzAaMaCLCxYB8NyM+1zAM
         AP89dwqc/Ulxfi6wcMMnD0Ud3D5y5TZpGz/qcWPLBpuvZN+nwB/MmCrOawaeO7gQZ2s0
         bKlCszrq4JexlaB7ylAL4OdJlzP7JOZPcVDjkrkKtRHF+Flu493o7t4jrR6v35h3nFzM
         aIFlDf/Dx0d0XKMnyZYJkOtnJk3/MmSGA0Q6WGbp0KqRMlqVNXZ1RuIf670YueRNfaQ1
         bJbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683578921; x=1686170921;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sp97q4ePeokQmYbXaLRNWE+R7MdtQaY+CQCmSw49LGQ=;
        b=AVHbLoqCHefZxEihLawkTq+M+/4MO1KILzlKuUSN1cbhVlkvyaNjc378KuJcMjcNaT
         kPYryBEn2btOKWLtAZg/9Fo0EwKwLgwdYJfgwE5vrgoKbkbDJ3oPz8G0PmYoIk77pSJV
         xNjxAsKTqLuw4NMb+A6JlJWNgNsZhZiZXrcXDK4eKavhETSljDkp08xVUlv24878OEti
         vwPi+H3L36qxgEZIJfWo31ZNh+Tg52Iu9U1gpJn39POxGr9Tz/w2kHPRnCCLP5RKt+/l
         cH93bPCgpSAvEmrhwspNSlMSG47RQ512Tey/LWOFcA32K2N+ErA0ZgW29DBqYSZjyf40
         D24Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDy0x4v4g042UZ+1C2Qksq6p0LDAsTH6MEh8ZO3xTsjWg7M4QBnv
	e3fbfsGD3LhcRLN3sp4Bkec=
X-Google-Smtp-Source: ACHHUZ5rQiCcZTwoGqbz+RzHlcazh+HhsZsoo7Kf61rcKOM+bG2e9SUQ6FKKepS9b9a63V/OgR2zxA==
X-Received: by 2002:a5d:5887:0:b0:2ee:b548:c64f with SMTP id n7-20020a5d5887000000b002eeb548c64fmr4014598wrf.3.1683578921282;
        Mon, 08 May 2023 13:48:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:34d2:b0:3f4:267e:9f with SMTP id
 d18-20020a05600c34d200b003f4267e009fls1507833wmq.1.-pod-control-gmail; Mon,
 08 May 2023 13:48:40 -0700 (PDT)
X-Received: by 2002:a7b:c5d6:0:b0:3f0:b1c9:25d4 with SMTP id n22-20020a7bc5d6000000b003f0b1c925d4mr7888994wmk.21.1683578920065;
        Mon, 08 May 2023 13:48:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683578920; cv=none;
        d=google.com; s=arc-20160816;
        b=Vd7snJQapNVm4yMIeAiYkhjpl66hvH4Tgm5JHG5/Wi2Nauuaug1dIPAov0AkY9HPZ/
         cn3hX0d91sOE/IXRkYxsx6mCGN/oThadqjdmQJH9zExCbQB2oa9kVPw39y4RTxmDIYlp
         cnixwk70ICM9YiCZySfBPtyd1Xwzt7ODjdTkSJ2x/sImZ+ptp5cbYEPicNRwUsvrgFjG
         8xiNkd6LZa4j38poy+JEOJAA4wzR8YXlrRYO2HukGyDobiWGOa8+Cc/DOQGKs0ng66tg
         +CzmgPYO1ItsltAwiT/ra1EVSxURUWDe46y77MbUA4d1gE2gffLLmWC/5GYqNH61XFrW
         +8KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=T9yUrg/v5raybQi2xKwTXiJDyugUh7KFNSbnsbVf1ko=;
        b=nqz5xCvof9qHvRT09KJAWmJT5KLI8RJ+jXF5RaTXr/cNJmUNArRO/eLrYTd0S1gQfL
         DGcmgn4s5tgB846PyT92wm8NfROI/6lQCdppb1yeDbX+iPSg7daC47X8P/Sorm9q3E0Z
         E10KBQnJs6LWQsIFoJvYTN6gQEO1kHe2A4Wq6r8iZNvmmGUf52B3itdzyvl7k2iSUO3d
         ovVAC8vpqOUcyorb7V9Ayl1zCKw1yQN3A6LKcM59fnvVFmeC0a3IaHVSBlh0CVMZd3wB
         dCbOUkcznQ3PTowY6POthiTuO7qRJgpfZefAcS23BYd9OvptM0M2jcljQ3Kf4TIsaert
         GjGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=JlOqRkPd;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.25 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-25.mta1.migadu.com (out-25.mta1.migadu.com. [95.215.58.25])
        by gmr-mx.google.com with ESMTPS id n19-20020a05600c501300b003f1951366f0si459687wmr.3.2023.05.08.13.48.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 May 2023 13:48:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.25 as permitted sender) client-ip=95.215.58.25;
Date: Mon, 8 May 2023 16:48:27 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Petr =?utf-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
Cc: Michal Hocko <mhocko@suse.com>, Suren Baghdasaryan <surenb@google.com>,
	akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, gregkh@linuxfoundation.org,
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFlgG02A87qPNIn1@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com>
 <ZFN1yswCd9wRgYPR@dhcp22.suse.cz>
 <ZFfd99w9vFTftB8D@moria.home.lan>
 <20230508175206.7dc3f87c@meshulam.tesarici.cz>
 <ZFkb1p80vq19rieI@moria.home.lan>
 <20230508180913.6a018b21@meshulam.tesarici.cz>
 <ZFkjRBCExpXfI+O5@moria.home.lan>
 <20230508205939.0b5b485c@meshulam.tesarici.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20230508205939.0b5b485c@meshulam.tesarici.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=JlOqRkPd;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.25 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Mon, May 08, 2023 at 08:59:39PM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> On Mon, 8 May 2023 12:28:52 -0400
> Kent Overstreet <kent.overstreet@linux.dev> wrote:
>=20
> > On Mon, May 08, 2023 at 06:09:13PM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> > > Sure, although AFAIK the index does not cover all possible config
> > > options (so non-x86 arch code is often forgotten). However, that's th=
e
> > > less important part.
> > >=20
> > > What do you do if you need to hook something that does conflict with =
an
> > > existing identifier? =20
> >=20
> > As already happens in this patchset, rename the other identifier.
> >=20
> > But this is C, we avoid these kinds of conflicts already because the
> > language has no namespacing
>=20
> This statement is not accurate, but I agree there's not much. Refer to
> section 6.2.3 of ISO/IEC9899:2018 (Name spaces of identifiers).
>=20
> More importantly, macros also interfere with identifier scoping, e.g.
> you cannot even have a local variable with the same name as a macro.
> That's why I dislike macros so much.

Shadowing a global identifier like that would at best be considered poor
style, so I don't see this as a major downside.

> But since there's no clear policy regarding macros in the kernel, I'm
> merely showing a downside; it's perfectly fine to write kernel code
> like this as long as the maintainers agree that the limitation is
> acceptable and outweighed by the benefits.

Macros do have lots of tricky downsides, but in general we're not shy
about using them for things that can't be done otherwise; see
wait_event(), all of tracing...

I think we could in general do a job of making the macros _themselves_
more managable, when writing things that need to be macros I'll often
have just the wrapper as a macro and write the bulk as inline functions.
See the generic radix tree code for example.

Reflection is a major use case for macros, and the underlying mechanism
here - code tagging - is something worth talking about more, since it's
codifying something that's been done ad-hoc in the kernel for a long
time and something we hope to refactor other existing code to use,
including tracing - I've got a patch already written to convert the
dynamic debug code to code tagging; it's a nice -200 loc cleanup.

Regarding the alloc_hooks() macro itself specifically, I've got more
plans for it. I have another patch series after this one that implements
code tagging based fault injection, which is _far_ more ergonomic to use
than our existing fault injection capabilities (and this matters! Fault
injection is a really important tool for getting good test coverage, but
tools that are a pain in the ass to use don't get used) - and with the
alloc_hooks() macro already in place, we'll be able to turn _every
individual memory allocation callsite_ into a distinct, individually
selectable fault injection point - which is something our existing fault
injection framework attempts at but doesn't really manage.

If we can get this in, it'll make it really easy to write unit tests
that iterate over every memory allocation site in a given module,
individually telling them to fail, run a workload until they hit, and
verify that the code path being tested was executed. It'll nicely
complement the fuzz testing capabilities that we've been working on,
particularly in filesystem land.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZFlgG02A87qPNIn1%40moria.home.lan.
