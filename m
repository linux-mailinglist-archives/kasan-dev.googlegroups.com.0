Return-Path: <kasan-dev+bncBAABBCNY3WVQMGQES7ASDGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E27380DA16
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 19:59:23 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-548e2b9fc55sf407a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 10:59:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702321162; cv=pass;
        d=google.com; s=arc-20160816;
        b=s6Mq8I3YA1Fv7kMko9MLJXJqLjjMBKMzmWtAfUa2290gFOeXf4A1yaTlehj7EHK21C
         3SWv1H/ePGPENPdFcKm/9tPnwIl2/ecvlrrCzBVRxpxDiNsuMNOrjL3TUt6vdWRrrINa
         DGVXB8zZydo2GzfOpyuPFDy8b54y2uOTfhrmPao89Bh7BWhYGwDFAPFKNRI1eptkhKS3
         nMqtG11jN5Lr9EaU5Bn9fs5P3DMxE/w4zzeOo+u2U+DL+rmZ5KTO+34sEk8BXgdjE/BS
         Dl5Xp7zKMNZvKYEHv1Z1F5khPwHOTRfuDuCxtmNXFs/iG86jhQC2Ai3Se5Lels53k8QJ
         WFUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=F8JXjENAqMtesJ12ru5zwYXNIOW1yjAMlJiZugzuDdg=;
        fh=DaPmRuawHnAU18yOIjRFb3bKY82uB1AyEdAq5zDOlGw=;
        b=qezXsL7QO42XwGGaBnucE4Y6GeBb4lACq+4ly4Mt1CzAwusPbE0VQmaGU1Xc8tYpo5
         tD6KHkicfSlMnXBGF6B8zwY/zZa7gnhN31UyC/zIV2ll7g8YznfrdhjqjYmwGaV5qkVI
         2j+rLxpaZEc4QArrGp66iUFeM1xSF63kSzy7L7h6ycSKjeHXpWJyMak3xkhQUxKZqlDo
         BrLYPGcd1gHmuS1WdUunkVyGDYKU99rU9oonn7wjGSIQUGObLxxSSwEl+KQTbT+oRXee
         WfVSpk7WtNF4v+x90ahyJulflWGWWsalkPtnLMeFhByd9XqzWDZkz/kLSYt5NMfABfOt
         Crdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=OD+eLULt;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702321162; x=1702925962; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=F8JXjENAqMtesJ12ru5zwYXNIOW1yjAMlJiZugzuDdg=;
        b=vaV4c+G+W6UITxPCwkH+gMnp9RCIftloa6Y5/y8AZ4jG6UtsreYimRCttp04kTFsdz
         T7ekJGaro/FVzGVqbJ4MC6924YmS90t9ZMXG5IUmcztrX1Jplu4vixs7CEi5yXo4nOOJ
         imcL9BkOwVjr93NP+9pp36JWSDabbtf1Cejmi887fLMyaE+gVT6aDqPVkuqu2sKfHJrp
         ktRdW1V5AnuJN1t531vOz7vdxDJ/9GNANI8R3HtzO1jSN4QjPte84qhMUbyUIMqr9HKE
         PI+x93o2JYilEaKW4N3HsvftM2KSJ8HxeOHiEiZANopni21FHaSpRJA7Lpgxsb+IBSGK
         fWmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702321162; x=1702925962;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F8JXjENAqMtesJ12ru5zwYXNIOW1yjAMlJiZugzuDdg=;
        b=TjR6Vlc6SHe2I4CfScIPISKlpZ5OIww70N2aopzDAGPbKIeUltIMiZlB1tac4qb+VV
         489Hd9U6slbiZTWChDZFnSOifYYedzZ8ieZI2XgWpWZufCXfICZk2d7GzRKsSL0EDDZW
         GR5p6DQEj/ifC131RKqHsoO90TfVjtuuogYZm26+7Xj5Xn5NZDt+DLVFmtLUIHiB2h+2
         DFOwtk+kjwbrYb/rXwXDxrOVavbO3atLoCeX8nwBhCTTVV6AvJ6a8laxeHWrjDT3Akdi
         ABdXFDb79bR5H4djLpkPaUJIgY+8vvHNF0svFWXLjxddyz+IEZhrfg2/gF1zWy8r+khO
         kIMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyXcFn7CS96N0wYVKMNBP6ZwsyCWroYAXOsTe+GRI42xATaQHb0
	JMhtzfMVBF1p5zJgzJxabko=
X-Google-Smtp-Source: AGHT+IFoiu+MYveedYhNoqaPi6zuSCttZNWw7zsttX4odCLgf6XAAJ3VJkkSeLlj/em54cdGCzbT6w==
X-Received: by 2002:a50:c082:0:b0:54c:9996:7833 with SMTP id k2-20020a50c082000000b0054c99967833mr240636edf.7.1702321161919;
        Mon, 11 Dec 2023 10:59:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:30a9:b0:54f:4850:fdb8 with SMTP id
 df9-20020a05640230a900b0054f4850fdb8ls760538edb.0.-pod-prod-00-eu; Mon, 11
 Dec 2023 10:59:20 -0800 (PST)
X-Received: by 2002:a17:907:75d1:b0:a1c:ecc8:ebfb with SMTP id jl17-20020a17090775d100b00a1cecc8ebfbmr5373156ejc.6.1702321160326;
        Mon, 11 Dec 2023 10:59:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702321160; cv=none;
        d=google.com; s=arc-20160816;
        b=YrF6yI7koaHWm8A+RphWoB5rJUsbX7kgZMj7SR/S2Py/d1NzWWTe2rjVqptltWyJjo
         c/wd0S66rkfFaTeA8wbCKDNgze9AizqN1ZPcWzbkvdGpVhL3KXV2/TVmwDxx8jiTiuEO
         y3KV4saiLm7qjC6ER4FdhNkK6tfEQB024TwIRCo5AIwd3NqDk4YYBfxNt2JqPwQgWt2P
         I73420aJmQhUp4TLg+GtxyYzvn/kV/s6jmYgz6AyhLoEBBmKDHgxMplI0J4mCRX/uF0B
         6EBFtEQm5ZMjyGhxS7kvKK10+xDSXcWom4a2gUNd/HSTK1jHD3X1xkEvkxBHR78noDuf
         SVVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=KggLwwMr4K2s7yjk+3jiz5Ko6D5Gf137eV//dqR0DIY=;
        fh=DaPmRuawHnAU18yOIjRFb3bKY82uB1AyEdAq5zDOlGw=;
        b=j9zi05MhPquONF2GVEtTx+kuyO6dyqbJ5eXSG5gW2VUVd43YhZThaT9faT7NoNuW+0
         yw4qzwf49GsdtOyQtnxI4vwOB3Gc8d3MxP4frwC2dvv63noSUi74OmGojFwgA6pLugs9
         tHUYFTLvAoO0SzXhNk4y9t7XeM4jZjCHGA1aU267D3JES71TVZvr2FFsIrYIEcGAs6PA
         wWVnmZKcYTH+dKBLz56F8/1vwVq4a/L8NSO006+w3cQewEHG4qEfrwb2bWVzS2F2YxJk
         FN6U5nCywe3TQhbRXt7yROWZh4l2ejbWeLLvsPphqfV1rhpL2UEM5U/zCbxRrL1dvE0c
         V9Vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=OD+eLULt;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
Received: from postout1.mail.lrz.de (postout1.mail.lrz.de. [129.187.255.137])
        by gmr-mx.google.com with ESMTPS id ga34-20020a1709070c2200b00a1caaeae776si266191ejc.2.2023.12.11.10.59.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Dec 2023 10:59:20 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) client-ip=129.187.255.137;
Received: from lxmhs51.srv.lrz.de (localhost [127.0.0.1])
	by postout1.mail.lrz.de (Postfix) with ESMTP id 4SprdL22mNzyTc;
	Mon, 11 Dec 2023 19:59:18 +0100 (CET)
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
	with LMTP id fmaQedN7hfuU; Mon, 11 Dec 2023 19:59:16 +0100 (CET)
Received: from Monitor.dos.cit.tum.de (Monitor.dos.cit.tum.de [IPv6:2a09:80c0:38::165])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout1.mail.lrz.de (Postfix) with ESMTPSA id 4SprdH6P1fzySj;
	Mon, 11 Dec 2023 19:59:15 +0100 (CET)
Date: Mon, 11 Dec 2023 19:59:10 +0100
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
Message-ID: <fv7fn3jivqcgw7mum6zadfcy2fbn73lygtxyy5p3zqpelfiken@5bmhbdufxgez>
References: <CAMn1gO7Ve4-d6vP4jvASQsTZ2maHsMF6gKHL3RXSuD9N3tAOfQ@mail.gmail.com>
 <CANpmjNNvGL--j-20UxqX_WjeXGiAcjfDAQpfds+Orajz0ZeBsg@mail.gmail.com>
 <CAMn1gO6reT+MTmogLOrOVoNqzLH+fKmQ2JRAGy-tDOTLx-fpyw@mail.gmail.com>
 <CANpmjNN7Gf_aeX+Y6g0UBL-cmTGEF9zgE7hQ1VK8F+0Yeg5Rvg@mail.gmail.com>
 <20230215143306.2d563215@rorschach.local.home>
 <CAMn1gO4_+-0x4ibpcASy4bLeZ+7rsmjx=0AYKGVDUApUbanSrQ@mail.gmail.com>
 <CAMn1gO6heXaovFy6jvpWS8TFLBhTomqNuxJmt_chrd5sYtskvw@mail.gmail.com>
 <20230505095805.759153de@gandalf.local.home>
 <n37j6cbsogluma25crzruaiq7qcslnjeoroyybsy3vw2cokpcm@mh7r3ocp24cb>
 <CA+fCnZebmy-fZdNonrgLofepTPL5hU6P8R37==sygTLBSRoa+w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZebmy-fZdNonrgLofepTPL5hU6P8R37==sygTLBSRoa+w@mail.gmail.com>
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b=OD+eLULt;       spf=pass
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

Hi Andrey!

On 11.12.2023 18:50, Andrey Konovalov wrote:
> On Mon, Dec 11, 2023 at 5:37=E2=80=AFPM Paul Heidekr=C3=BCger
> <paul.heidekrueger@tum.de> wrote:
> >
> > Hi all!
> >
> > On 05.05.2023 09:58, Steven Rostedt wrote:
> > > On Mon, 1 May 2023 15:02:37 -0700
> > > Peter Collingbourne <pcc@google.com> wrote:
> > >
> > > > > > "ftrace" is really for just the function tracing, but CONFIG_FT=
RACE
> > > > > > really should just be for the function tracing infrastructure, =
and
> > > > > > perhaps not even include trace events :-/ But at the time it wa=
s
> > > > > > created, it was for all the "tracers" (this was added before tr=
ace
> > > > > > events).
> > > > >
> > > > > It would be great to see this cleaned up. I found this aspect of =
how
> > > > > tracing works rather confusing.
> > > > >
> > > > > So do you think it makes sense for the KASAN tests to "select TRA=
CING"
> > > > > for now if the code depends on the trace event infrastructure?
> > > >
> > > > Any thoughts? It looks like someone else got tripped up by this:
> > > > https://reviews.llvm.org/D144057
> > >
> > > Yeah, it really does need to get cleaned up, but unfortunately it's n=
ot
> > > going to be a trivial change. We need to make sure it's done in a way=
 that
> > > an old .config still keeps the same things enabled with the new confi=
g
> > > settings. That takes some trickery in the dependency.
> > >
> > > I'll add this to my todo list, hopefully it doesn't fall into the aby=
ss
> > > portion of that list :-p
> > >
> > > -- Steve
> >
> > Just adding to Peter's concern re: CONFIG_KASAN_KUNIT_TEST's dependency=
 on
> > CONFIG_TRACEPOINTS.
> >
> > I'm having no luck running the KASan KUnit tests on arm64 with the foll=
owing
> > .kunitconfig on v6.6.0:
> >
> >         CONFIG_KUNIT=3Dy
> >         CONFIG_KUNIT_ALL_TESTS=3Dn
> >         CONFIG_DEBUG_KERNEL=3Dy
> >         CONFIG_KASAN=3Dy
> >         CINFIG_KASAN_GENERIC=3Dy
> >         CONFIG_KASAN_KUNIT_TEST=3Dy
> >
> > CONFIG_TRACEPOINTS, which CONFIG_KASAN_TEST relies on since the patch t=
his
> > thread is based on, isn't defined for arm64, AFAICT.
> >
> > If I comment out the dependency on CONFIG_TRACEPOINTS, the tests appear=
 to run,
> > but KUnit isn't picking up the KASan output.
> >
> > If I revert the patch, the above .kunitconfig appears to work fine on a=
rm64 and
> > the tests pass.
> >
> > The above .kunitconfig works as intended on X86, no changes necessary.
> >
> > Am I missing something?
>=20
> Hi Paul,
>=20
> I've been successfully running KASAN tests with CONFIG_TRACEPOINTS
> enabled on arm64 since this patch landed.

Interesting ...=20

> What happens when you try running the tests with .kunitconfig? Does
> CONFIG_TRACEPOINTS or CONFIG_KASAN_KUNIT_TEST get disabled during
> kernel building?=20

Yes, exactly, that's what's happening.

Here's the output kunit.py is giving me. I replaced CONFIG_DEBUG_KERNEL wit=
h=20
CONFIG_TRACEPOINTS in my .kunitconfig. Otherwise, it's identical with the o=
ne I=20
posted above.

	=E2=9E=9C   ./tools/testing/kunit/kunit.py run --kunitconfig=3Dmm/kasan/.k=
unitconfig --arch=3Darm64
	Configuring KUnit Kernel ...
	Regenerating .config ...
	Populating config with:
	$ make ARCH=3Darm64 O=3D.kunit olddefconfig
	ERROR:root:Not all Kconfig options selected in kunitconfig were in the gen=
erated .config.
	This is probably due to unsatisfied dependencies.
	Missing: CONFIG_KASAN_KUNIT_TEST=3Dy, CONFIG_TRACEPOINTS=3Dy

Does CONFIG_TRACEPOINTS have some dependency I'm not seeing? I couldn't fin=
d a=20
reason why it would get disabled, but I could definitely be wrong.

> Or tests just don't get executed?
>=20
> Thanks!

Many thanks,
Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/fv7fn3jivqcgw7mum6zadfcy2fbn73lygtxyy5p3zqpelfiken%405bmhbdufxgez=
.
