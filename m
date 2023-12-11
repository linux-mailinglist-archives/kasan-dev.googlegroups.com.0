Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTNH32VQMGQEXVP6EBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id E8DDE80DEB1
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 23:57:18 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-67a696be34csf69675426d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Dec 2023 14:57:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702335438; cv=pass;
        d=google.com; s=arc-20160816;
        b=OdKsU2GSaOJKyMtZuW46gY1ciG/arpo5oxC+R21FkE71/fvHvxjwXz1cQx7QnbnVvK
         /LdPDDe1V/jgKONVHuiy8n+TqSXKNC0Eye7qzM/+R/xM2J0oICzFIzubtAubaH/1S2jS
         fF/mV8sFpVZedJUByA0mzKmKh8RVHuN0Olncjo7jOEi0ku1l24EwML59eRrX1d5QSNal
         p1E0LKKMf84RgP+RUf4M3ISIJ+6sGbWfYyRbCflqcIf0tNGI5NysgzqCPF9Lc3GRcegX
         +CJt3W5UROdMAcHFJq2/czH5WELjrmyV9RIpHvdO1b22MZE92+HIl1cd2NCZVoSx3EPW
         7Fuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=W4PcJRpRQD9+WGbxptBeKDG8tDihfEg6ilfnB1K+zSo=;
        fh=GsT3hAat2TqRvpMYR9O/XV5pBI0aUTywK8FkNd4Ngjw=;
        b=VHNiU+dD7bXoihh99uRXuUiRRMJgsRpU+Hh3NhFncioTFWBSEAGveiuSwp29lwg930
         uT/PG7BNuberrxKMrgM6Gtm0u+m2HS/rvGq1PVOLzqUM2PwaoBKnNHMPKrDkOq/r1YCt
         AQmEgdYuVMXnLDKtpusKJO2TYWYYvyNfZGBSZl4eSbAuvRkvP9INogr6E3nKyonr8JD6
         wOSBnQa30nJ5VOPlpSL7rFOnNcUEdSPjdApeMePdUAviL7oTiLkrie8wdbf3qEfTs/RM
         4GCKg246bdm09Slvjhk+RRGCk6hhwZDxSHZsK4fOc4eQQgmMVTddE1cMwvjaJEOp2myT
         mbMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ah28QOL7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702335438; x=1702940238; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=W4PcJRpRQD9+WGbxptBeKDG8tDihfEg6ilfnB1K+zSo=;
        b=AihSVCIbQGvSI+MY9M+gwr9C+pnuCCthk6Px75XwgDI3gv1Xrf+bonXzsdacdaKSkm
         KsuwE46J0DeE709wF02NM7v2NIoZQygfu84L/vnnVPBuZS9Wh2vOU6Vyd9hHMfIaRk0H
         lQpUb/dctDKfzZ7R50bXKuN57vvrebEewOiQWLTGavAK/d5rRK7N5AlWE1zZ2/uXf1to
         bMrNdGHAPZMLz8VZ4jC4B6lFGgG0k8sFyjtw4Ag0ZB2RtjAvaEg5OH4XP/3cireLIlH+
         uB8V8oCN1pHo+gO4U2PeB2WaPxhHV6cznvKKmrpkC86aXypMJuUlc1gKweAWtRNnJQQb
         iSZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702335438; x=1702940238;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=W4PcJRpRQD9+WGbxptBeKDG8tDihfEg6ilfnB1K+zSo=;
        b=o5a5fpfsQQaONJauxNpjv3jZ4Ual/xoVWe77DgX/vyPpPbuTYwTjlM3E2hvOaODM/T
         YUKg5ubbQYgUlQnkZfjZzC/0+8C90n6PA5cBvsmKOHT9OyljIYTgjDWnvprGzuWMRNgh
         7q+s1ZUuokvD9OEgOGWq4DtLu1f0F/q/TH7tC6o0XYmrgalJ8nVQjvFgBXKE6RZsIFmj
         tOUKz2igoa7Y85Pm5lLXFc9I9dOt5BRKmvPmBZRGTmgePp4Dn642qcU3e53VjvtA3mB/
         XboTKauKSTBEZdmcmalz3zW5djLRjmsko6eMVl8fIRGbVD60mUCyQjEzJ4arOm/IY3ZO
         fgzg==
X-Gm-Message-State: AOJu0YwGWFdFDJ7meN6ZQ+Ji7UuwE48+CuePy9sqbLdlsGZiFDLi8stS
	MRP1ZjwVkOdUi2IihBf/C5A=
X-Google-Smtp-Source: AGHT+IEHkOYwh8dNwUrJJJ/T/jLqmdQPZ+tUD0B2EFVRaZgK94etI7fKabp4hZXDAgExo42ptz36Tw==
X-Received: by 2002:a0c:fb42:0:b0:67a:a721:d795 with SMTP id b2-20020a0cfb42000000b0067aa721d795mr5688757qvq.123.1702335437788;
        Mon, 11 Dec 2023 14:57:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e842:0:b0:67a:3bbd:90d7 with SMTP id l2-20020a0ce842000000b0067a3bbd90d7ls789225qvo.2.-pod-prod-06-us;
 Mon, 11 Dec 2023 14:57:17 -0800 (PST)
X-Received: by 2002:a05:6122:4684:b0:4b2:d41f:e457 with SMTP id di4-20020a056122468400b004b2d41fe457mr3969169vkb.1.1702335436999;
        Mon, 11 Dec 2023 14:57:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702335436; cv=none;
        d=google.com; s=arc-20160816;
        b=vmc3pNuIge8va8o1RNh/JRrePeIzZbhVSkC+Gzfs0FRvvVL6PWSwDdKwhvhFYjuXqC
         EDR3FfJuMQiOF/XpDAe3uy6Rntc+N+aWf/uY4R+8tp6MZ2Q59oB8mNiG0XX1GQvP2MWv
         IDN0J12BKmepKISbfZwtLMUzRWLtShVGx0LZQZ85EDmzXyxAwzdGm7SxKu4NBCxgwOhm
         hAyMElhmNpctIOJ0T5sRVfTlbw0gnnL5xwnCe+GuFCcHDA2rkqnMhvQQK9Ksqgto8JSd
         685uGi2kkETkAjl462j327XudKcDYjTCoa9NmOy2XVFuS2BRkOxvJCngMRwg/XNB4A/R
         56fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VkXKnEfT8eKc5Yh5rOydAPt9sQ7NUY597Q2G+9UH8MI=;
        fh=GsT3hAat2TqRvpMYR9O/XV5pBI0aUTywK8FkNd4Ngjw=;
        b=ExACBUclX8tonMzxtIE3GcVjSYvwRwcfoaEhR6YVq1+LFT4zkqHTkbDknBvwJzr75F
         8NCLWj8PrfyA36cMWPUv5yAZgxQAJjcKnecW35CLkPxEJDOA/sP/0S0nHiIeIyS2nax5
         iRHcNsnx0BoDLYZGNhoCj0oF+PVON83i+8976Jj9ZybBb+p+FgGYmN5euOkHWbYkLgpc
         l9PzI8hq2tF4TUUjHyoJfUv+wBLVDeN09ZUHtxorDtF/ddDS5cHgy61PoYH/ZHPBdqri
         6RZ5D1ji9rF4Gds2f7Dpv15IjL3f7SuJxofhBr5cUNYA/n7vJzH2MqBMALmh9/LhDjYE
         Hp5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ah28QOL7;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92f.google.com (mail-ua1-x92f.google.com. [2607:f8b0:4864:20::92f])
        by gmr-mx.google.com with ESMTPS id fi25-20020a0561224d1900b004b2e4f02055si1051780vkb.3.2023.12.11.14.57.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Dec 2023 14:57:16 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92f as permitted sender) client-ip=2607:f8b0:4864:20::92f;
Received: by mail-ua1-x92f.google.com with SMTP id a1e0cc1a2514c-7c5639267ebso1145974241.0
        for <kasan-dev@googlegroups.com>; Mon, 11 Dec 2023 14:57:16 -0800 (PST)
X-Received: by 2002:a05:6102:38cd:b0:464:811a:9ef9 with SMTP id
 k13-20020a05610238cd00b00464811a9ef9mr3502893vst.17.1702335436511; Mon, 11
 Dec 2023 14:57:16 -0800 (PST)
MIME-Version: 1.0
References: <CAMn1gO6reT+MTmogLOrOVoNqzLH+fKmQ2JRAGy-tDOTLx-fpyw@mail.gmail.com>
 <CANpmjNN7Gf_aeX+Y6g0UBL-cmTGEF9zgE7hQ1VK8F+0Yeg5Rvg@mail.gmail.com>
 <20230215143306.2d563215@rorschach.local.home> <CAMn1gO4_+-0x4ibpcASy4bLeZ+7rsmjx=0AYKGVDUApUbanSrQ@mail.gmail.com>
 <CAMn1gO6heXaovFy6jvpWS8TFLBhTomqNuxJmt_chrd5sYtskvw@mail.gmail.com>
 <20230505095805.759153de@gandalf.local.home> <n37j6cbsogluma25crzruaiq7qcslnjeoroyybsy3vw2cokpcm@mh7r3ocp24cb>
 <CA+fCnZebmy-fZdNonrgLofepTPL5hU6P8R37==sygTLBSRoa+w@mail.gmail.com>
 <fv7fn3jivqcgw7mum6zadfcy2fbn73lygtxyy5p3zqpelfiken@5bmhbdufxgez>
 <CA+fCnZfQEueCifc-8d5NVWEUtAiOG1eRW-LFKbOhab_Y7jqU0Q@mail.gmail.com> <osqmp2j6gsmgbkle6mwhoaf65mjn4a4w3e5hsfbyob6f44wcg6@7rihb5otzl2z>
In-Reply-To: <osqmp2j6gsmgbkle6mwhoaf65mjn4a4w3e5hsfbyob6f44wcg6@7rihb5otzl2z>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Dec 2023 23:56:37 +0100
Message-ID: <CANpmjNMw3N09x06Q+0mFCEeTKfUsDdXwXM2hdgAQ+wwbZGpB9w@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] kasan: switch kunit tests to console tracepoints
To: =?UTF-8?Q?Paul_Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Peter Collingbourne <pcc@google.com>, andrey.konovalov@linux.dev, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	linux-trace-kernel@vger.kernel.org, 
	Nick Desaulniers <ndesaulniers@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Ah28QOL7;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92f as
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

On Mon, 11 Dec 2023 at 23:48, Paul Heidekr=C3=BCger <paul.heidekrueger@tum.=
de> wrote:
>
> On 11.12.2023 21:51, Andrey Konovalov wrote:
> > On Mon, Dec 11, 2023 at 7:59=E2=80=AFPM Paul Heidekr=C3=BCger
> > <paul.heidekrueger@tum.de> wrote:
> > >
> > > > Hi Paul,
> > > >
> > > > I've been successfully running KASAN tests with CONFIG_TRACEPOINTS
> > > > enabled on arm64 since this patch landed.
> > >
> > > Interesting ...
> > >
> > > > What happens when you try running the tests with .kunitconfig? Does
> > > > CONFIG_TRACEPOINTS or CONFIG_KASAN_KUNIT_TEST get disabled during
> > > > kernel building?
> > >
> > > Yes, exactly, that's what's happening.
> > >
> > > Here's the output kunit.py is giving me. I replaced CONFIG_DEBUG_KERN=
EL with
> > > CONFIG_TRACEPOINTS in my .kunitconfig. Otherwise, it's identical with=
 the one I
> > > posted above.
> > >
> > >         =E2=9E=9C   ./tools/testing/kunit/kunit.py run --kunitconfig=
=3Dmm/kasan/.kunitconfig --arch=3Darm64
> > >         Configuring KUnit Kernel ...
> > >         Regenerating .config ...
> > >         Populating config with:
> > >         $ make ARCH=3Darm64 O=3D.kunit olddefconfig
> > >         ERROR:root:Not all Kconfig options selected in kunitconfig we=
re in the generated .config.
> > >         This is probably due to unsatisfied dependencies.
> > >         Missing: CONFIG_KASAN_KUNIT_TEST=3Dy, CONFIG_TRACEPOINTS=3Dy
> > >
> > > Does CONFIG_TRACEPOINTS have some dependency I'm not seeing? I couldn=
't find a
> > > reason why it would get disabled, but I could definitely be wrong.
> >
> > Does your .kunitconfig include CONFIG_TRACEPOINTS=3Dy? I don't see it i=
n
> > the listing that you sent earlier.
>
> Yes. For the kunit.py output from my previous email, I replaced
> CONFIG_DEBUG_KERNEL=3Dy with CONFIG_TRACEPOINTS=3Dy. So, the .kunitconfig=
 I used to
> produce the output above was:
>
>         CONFIG_KUNIT=3Dy
>         CONFIG_KUNIT_ALL_TESTS=3Dn
>         CONFIG_TRACEPOINTS=3Dy
>         CONFIG_KASAN=3Dy
>         CONFIG_KASAN_GENERIC=3Dy
>         CONFIG_KASAN_KUNIT_TEST=3Dy
>
> This more or less mirrors what mm/kfence/.kunitconfig is doing, which als=
o isn't
> working on my side; kunit.py reports the same error.

mm/kfence/.kunitconfig does CONFIG_FTRACE=3Dy. TRACEPOINTS is not user
selectable. I don't think any of this has changed since the initial
discussion above, so CONFIG_FTRACE=3Dy is still needed.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMw3N09x06Q%2B0mFCEeTKfUsDdXwXM2hdgAQ%2BwwbZGpB9w%40mail.gm=
ail.com.
