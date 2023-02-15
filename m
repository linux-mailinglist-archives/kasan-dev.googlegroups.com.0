Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKV5WKPQMGQEVPVEZLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id C61E069788B
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 09:58:19 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id t5-20020a05622a180500b003b9c03cd525sf10925986qtc.20
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Feb 2023 00:58:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676451498; cv=pass;
        d=google.com; s=arc-20160816;
        b=BK8aHz19KsKEONzsU+7vKQUWto4S70cx8N4c264+5Qo7gqV7377eOPrCER0ov83hmm
         SInviYzxwwaF4d7nmfP+IYqJPrPIqOtfSaZcyNipuNjjhx/aZSNMIjk1UDDXU/i5qqn6
         05CwkX47uX3CgIvtT9Om0pOZp5F+1AWiQ5b6SNTXBoNJx9lBIO91wCajWqs43/ynoK7B
         2GJuwsoOZ5QcFYa3TJGtj3S1nX7L8460989dGp6+zE3NLFFUM8gne6zTIYpH79CrNwvE
         7zRsH/dABmw4ek9bOlhWGz4NTtXA89lpzwslNLIC5qgfXNNuPR+J5mThGHeb2+itRJ8j
         otgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BI5Q1vlvk8KyRuK6S9JSbSCbZ9ZOZW5p6e5w9C+4aEA=;
        b=g/uVviA+hBEpF1dMHPRGEJU1AkMetFCrcNn4xUPltsHwd0IrAtmWqt61vhJJASQzGs
         olGGnw9q+iEymck2L8PrRrVhG7ARl8myqdfzsjXiY2jj4GFcxdq8isC8V0ivy1kDe9hw
         dASrvBakT55wVkNr3pIGPBqxAkZWknqjFoE2+shATt/T2e2Jl8Ipp2JCkEKad+xGFp1i
         ySvAsrvAWGFnNEANbtJuzlqFZg6qmI1jqiHL1psG4h3SpGEJ49Rs+5AlpLMFznqvcyYz
         4+d8McHeFwbWDc5cknFpbtRP4Do1Xnc/enIile6HlfjEnavoF2rf8dlpbLAKIBVRn6sB
         /ITQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CVBzeQ0d;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1676451498;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BI5Q1vlvk8KyRuK6S9JSbSCbZ9ZOZW5p6e5w9C+4aEA=;
        b=ikI8J+ncfu1V0AohHzDKAw9xEWQCrSNDXiYFyC5bNkpJhMt2jAHlfUma6BQrjIS8vD
         OZmnR1d0FhaCbjTjTXoXdz74wa3cineLMQnmGMjGw5qZQlIQvIa6claSMEDrgciPsUGe
         flC/CpXK3r8l8BxnLr2vewQ2MwKJAir7UTFTjhszH6DWz6Noqd+I0H5X9X04Qovcnqe1
         cgkpDVx0LlJ+/0RHhImfqbmDkhYNGqL21BP+b/AI0sfHSi1DqEMu62PqIEZm021jj6LS
         BweTYjl4JzoUX5lQ1ULQski9TPTDx9S8KNsbHfHWmfeOKqW8xNcw8U+metOP766dOTzH
         iXAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1676451498;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=BI5Q1vlvk8KyRuK6S9JSbSCbZ9ZOZW5p6e5w9C+4aEA=;
        b=YeHF6oYtHvDLK0pvWcRh2seqm5JrlLsIagKEj8Kaj+/R+1s3Y/mkUVSVwQc+yaEZhw
         pMbkzSPfnK8NkwjR2Y5EZrN7PfUw7SKxIusbWnt8LhY/9OMQxXsLAvkwqQqGFsH9wbBT
         89NCy/jrXnQGzuQrsRNvTkho7yxebQfGw90pep0q7u1tg6LZ6CXGR33VxpqbIP/EyeEq
         3K2lNso1Ky4CX35SvV70Nm6UpSOt4N40mM5L+vBk8aYhCmH1//jyN58IDibsQt7lph0e
         RJxLulJdv1kdv8CNx/n646HXaJQpxUipZZDlCTnCvtt15+veIKVytHmY3tCbWDMWCR9j
         7qsw==
X-Gm-Message-State: AO0yUKXuYdcCb2eG0Pn/h4XU1HzQZQdwUjTh5fmLJaTo7Ke0cm8kcIvU
	XCaIz+xtRlv/Kw2M9RI+n0s=
X-Google-Smtp-Source: AK7set+JFiJE5WKQ9QDdLDqtVaWslYV/70gdBta7KrDaACh+CgwE0UftiP7w3j9QEUGxc4VaHg26VA==
X-Received: by 2002:a0c:e44f:0:b0:56e:a3a7:33e0 with SMTP id d15-20020a0ce44f000000b0056ea3a733e0mr94825qvm.66.1676451498544;
        Wed, 15 Feb 2023 00:58:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:fc05:0:b0:4c6:ff53:22 with SMTP id z5-20020a0cfc05000000b004c6ff530022ls9521251qvo.6.-pod-prod-gmail;
 Wed, 15 Feb 2023 00:58:17 -0800 (PST)
X-Received: by 2002:a05:6214:27e8:b0:56e:9c3e:6641 with SMTP id jt8-20020a05621427e800b0056e9c3e6641mr2545945qvb.21.1676451497881;
        Wed, 15 Feb 2023 00:58:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676451497; cv=none;
        d=google.com; s=arc-20160816;
        b=EPOKFYoMS/OFeTSjAZiwBF9R9a80jzYXdgPKGc4+dTLmM5V+hLIwJbM8P1PBsF/+F4
         YbFesvUzlLK7YPYyG17uPWiWNQukFMbapUm3ZMumXjBdxIN6iT54ukafqaOm1+kqsxfQ
         c+MVA0gClIg/HZMfqBxtjosyyijXfQUShzwCq83rR0rEM96BhC4ly/GcqTBEcrhVghc+
         gdGQptjNUtPWk8qrYT/xoUJlaeoTzfo2k5AzyM5rnG2nAAweltoJYxTo3qORRLYvdfFK
         kh00PESrdwk7Lob/+WW2FXy0rg9oIOItf0IRJbyStzNbXgeMOJXjKtAuvA7Cd/XO4+PI
         LufA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DcGGlaYPqY4tYzxSZdNCJiJzK/DPCL1PbAxHODA+Moo=;
        b=049CsyuykndujVHgRAk4HtBIgpzZV0KvoxydmVOlZ09Vh7er7oxPJ8NcbEzY9Bih3A
         4UIOmGHOYfBLJTo2QOD3ipfVlMGt8Y09Cbx/xzhvmXakodRQR+8M9N+zF+nDgSCgyjAt
         ILh2l3mwrUQ1XX9bttJqaMD/1goOTrETe8uFi0L10Y3uHeJXdiq2WDzT5VtLFCqLCekK
         lsRh+gdVR3poSJucc2a/sAwB1uEWEKPSdyLbaE/Oqo5HFRmQX7JeXNVTYJWefKZAVqj2
         vr1iPxn4ydZbxfX8Z4pQXhTKPVrTwvp0J56SDsEqjHXtTm0paCMWdWqzehNOBzVCl9tJ
         S3Kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CVBzeQ0d;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe34.google.com (mail-vs1-xe34.google.com. [2607:f8b0:4864:20::e34])
        by gmr-mx.google.com with ESMTPS id eb2-20020a05620a480200b00705bf2df50bsi1494082qkb.0.2023.02.15.00.58.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Feb 2023 00:58:17 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as permitted sender) client-ip=2607:f8b0:4864:20::e34;
Received: by mail-vs1-xe34.google.com with SMTP id z15so8531549vsj.12
        for <kasan-dev@googlegroups.com>; Wed, 15 Feb 2023 00:58:17 -0800 (PST)
X-Received: by 2002:a67:70c6:0:b0:412:2e92:21a6 with SMTP id
 l189-20020a6770c6000000b004122e9221a6mr311416vsc.13.1676451497458; Wed, 15
 Feb 2023 00:58:17 -0800 (PST)
MIME-Version: 1.0
References: <ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl@google.com>
 <CAMn1gO7Ve4-d6vP4jvASQsTZ2maHsMF6gKHL3RXSuD9N3tAOfQ@mail.gmail.com>
 <CANpmjNNvGL--j-20UxqX_WjeXGiAcjfDAQpfds+Orajz0ZeBsg@mail.gmail.com> <CAMn1gO6reT+MTmogLOrOVoNqzLH+fKmQ2JRAGy-tDOTLx-fpyw@mail.gmail.com>
In-Reply-To: <CAMn1gO6reT+MTmogLOrOVoNqzLH+fKmQ2JRAGy-tDOTLx-fpyw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 Feb 2023 09:57:40 +0100
Message-ID: <CANpmjNN7Gf_aeX+Y6g0UBL-cmTGEF9zgE7hQ1VK8F+0Yeg5Rvg@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] kasan: switch kunit tests to console tracepoints
To: Peter Collingbourne <pcc@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, linux-trace-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=CVBzeQ0d;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e34 as
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

+Cc tracing maintainers

On Wed, 15 Feb 2023 at 03:56, Peter Collingbourne <pcc@google.com> wrote:
>
> On Mon, Feb 13, 2023 at 10:08 PM Marco Elver <elver@google.com> wrote:
> >
> > On Tue, 14 Feb 2023 at 02:21, Peter Collingbourne <pcc@google.com> wrote:
> > >
> > > On Tue, Oct 18, 2022 at 10:17 AM <andrey.konovalov@linux.dev> wrote:
> > > >
> > > > From: Andrey Konovalov <andreyknvl@google.com>
> > > >
> > > > Switch KUnit-compatible KASAN tests from using per-task KUnit resources
> > > > to console tracepoints.
> > > >
> > > > This allows for two things:
> > > >
> > > > 1. Migrating tests that trigger a KASAN report in the context of a task
> > > >    other than current to KUnit framework.
> > > >    This is implemented in the patches that follow.
> > > >
> > > > 2. Parsing and matching the contents of KASAN reports.
> > > >    This is not yet implemented.
> > > >
> > > > Reviewed-by: Marco Elver <elver@google.com>
> > > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > >
> > > > ---
> > > >
> > > > Changed v2->v3:
> > > > - Rebased onto 6.1-rc1
> > > >
> > > > Changes v1->v2:
> > > > - Remove kunit_kasan_status struct definition.
> > > > ---
> > > >  lib/Kconfig.kasan     |  2 +-
> > > >  mm/kasan/kasan.h      |  8 ----
> > > >  mm/kasan/kasan_test.c | 85 +++++++++++++++++++++++++++++++------------
> > > >  mm/kasan/report.c     | 31 ----------------
> > > >  4 files changed, 63 insertions(+), 63 deletions(-)
> > > >
> > > > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > > > index ca09b1cf8ee9..ba5b27962c34 100644
> > > > --- a/lib/Kconfig.kasan
> > > > +++ b/lib/Kconfig.kasan
> > > > @@ -181,7 +181,7 @@ config KASAN_VMALLOC
> > > >
> > > >  config KASAN_KUNIT_TEST
> > > >         tristate "KUnit-compatible tests of KASAN bug detection capabilities" if !KUNIT_ALL_TESTS
> > > > -       depends on KASAN && KUNIT
> > > > +       depends on KASAN && KUNIT && TRACEPOINTS
> > >
> > > My build script for a KASAN-enabled kernel does something like:
> > >
> > > make defconfig
> > > scripts/config -e CONFIG_KUNIT -e CONFIG_KASAN -e CONFIG_KASAN_HW_TAGS
> > > -e CONFIG_KASAN_KUNIT_TEST
> > > yes '' | make syncconfig
> > >
> > > and after this change, the unit tests are no longer built. Should this
> > > use "select TRACING" instead?
> >
> > I think we shouldn't select TRACING, which should only be selected by
> > tracers. You'd need CONFIG_FTRACE=y.
>
> Doesn't CONFIG_FTRACE=y mean "function tracing", i.e. function
> entry/exit tracing using compiler instrumentation? As far as I can
> tell, the KASAN tests do not make use of this feature. They only use
> the kernel tracepoint infrastructure to trace the "console" tracepoint
> defined in include/trace/events/printk.h, which is not associated with
> function entry/exit.

Yes, you are right, and it's something I've wondered how to do better
as well. Let's try to consult tracing maintainers on what the right
approach is.

> I have yet to find any evidence that TRACING ought to only be selected
> by tracers. As far as I can tell, TRACING appears to be the minimal
> config required in order for it to be possible to trace pre-defined
> (i.e. defined with TRACE_EVENT) tracepoints, which is all that KASAN
> needs. (I also tried selecting TRACEPOINTS, but this led to a number
> of link failures.) If select TRACING is only used by tracers, it could
> just mean that only tracers are making use of this functionality
> inside the kernel. From that perspective the KASAN tests can
> themselves be considered a "tracer" (albeit a very specialized one).
>
> If I locally revert the change to lib/Kconfig.kasan and add the
> TRACING select, the KASAN tests pass when using my kernel build
> script, which suggests that TRACING is all that is needed.
>
> > Since FTRACE is rather big, we probably also shouldn't implicitly
> > select it. Instead, at least when using kunit.py tool, we could add a
> > mm/kasan/.kunitconfig like:
> >
> > CONFIG_KUNIT=y
> > CONFIG_KASAN=y
> > CONFIG_KASAN_KUNIT_TEST=y
> > # Additional dependencies.
> > CONFIG_FTRACE=y
> >
> > Which mirrors the KFENCE mm/kfence/.kunitconfig. But that doesn't help
> > if you want to run it with something other than KUnit tool.
>
> In any case, I'm not sure I'm in favor of adding yet another config
> that folks need to know to enable in order to avoid silently disabling
> the unit tests. Many developers will maintain their own scripts for
> kernel development if the existing ones do not meet their needs. It's
> possible that kunit.py will work out for me now (when I looked at it
> before, it was useless for me because it only supported UML, but it
> looks like it supports QEMU now), but there's no guarantee that it
> will, so I might stick with my scripts for a while.
>
> Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN7Gf_aeX%2BY6g0UBL-cmTGEF9zgE7hQ1VK8F%2B0Yeg5Rvg%40mail.gmail.com.
