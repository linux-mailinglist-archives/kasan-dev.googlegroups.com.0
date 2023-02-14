Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ6KVSPQMGQE22BPGFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id B12746958C7
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 07:08:05 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id h15-20020a170902f7cf00b0019a819e2d93sf5226646plw.4
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 22:08:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676354884; cv=pass;
        d=google.com; s=arc-20160816;
        b=jvLIOGbwCb/eF5YVVwNChuNU37Y3hn5uK/fpANTQW5Dk2RHr7NI8ZWzhiP7c5w4TcF
         PyWUXUCSmIXRNC0A6fj9G7S8NtkbJ4suEqU3yvSkmGh4OhpgvdzpzvcN+ya0a5LvGITX
         2b3P9xdp2zE5W2d9M5sg4V8BnhIjEyReVXPZrZsuK9b542/z7LAU3ySgv2X95lZXvoHy
         +BD/Ya0tuccxhh6hO7oeaw+6mMPMN8gsP8oWPY3zyM3QYHtL7CdmxkJ2YI7lG0xDCzEQ
         Ukl1mEe0qScKNNThteSFAQ+6J88jjHW2Az1wcYl24il4IKa1JtamFOAKzCRnyMudS2v2
         +APQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JMXtzvskaWpK+vY/igqctj7pLbQMfR9mLfUdxy1cVBA=;
        b=V7MAhxXOJKqUL0VC0fgTQNEj9/XQC2bSU5Rjs7DCXdJ9qiTezDcWKZZhB9oNsuas2K
         gOm6o/J/EMkUdnAPx0Lqw2jzov00wZXdOAZgSB63ep7UPg7ic2ll2tG3yRioCXJHmnJW
         jXV1tB8RqCVxidGP4iDtdr/XsWhHZwlgwlMfqmvYji5JBiAjqA2YEjp5XsAjjlXwMiV+
         dgarUC1f49mARAI5kSvuIU7mzejHckPkW8K1mkhTy8ONYtgmajnmJ6nP42Yh2IY4587w
         VM9Vz5I0buUMGeCAASqFCv2U+tbc7I7UoIpbqjybjneSJYM6X3hNTxOAe2BIlIiLhvdj
         wz9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="FNiC/1wr";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1676354884;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JMXtzvskaWpK+vY/igqctj7pLbQMfR9mLfUdxy1cVBA=;
        b=hfCrK3X4KnCatUlj7iA9pkxatU7DPDduyxTP8OOLZVcFQsKcpJH1sjrKUreNHkykuJ
         40kOW934PQjb1J2fl1zeM8FB8RIM9OcvB0K4u0qb81FG6Nc9wpjp5t3gdckFZ78tuZpQ
         0sLgdxQ10GbrU69rFWdF4PBxtBNPumOiQrK4+72kZz2iPc+d22VxE9sW+KRUQYgqtpqi
         mjyFRX3Ua3EjUAEjjQLpVBbrnpq1M6MCMVtSIoPGb+KJculAon7OxYZfAbI7Udbqx3YZ
         ZDzccbdHKRk1bXrmZhJltNLuG0dldZeKlwmytbounCS/p2+cAIW7xsqTlTUZATv0ccKS
         0EfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1676354884;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=JMXtzvskaWpK+vY/igqctj7pLbQMfR9mLfUdxy1cVBA=;
        b=bqa96Gs4KmaSqA+lobpM+Tq9E1DKzHxX0kEFzFde13EvIPtFjWuqhQL6BGwiVAyvQx
         MG2s6DFTFidbSTz35crsjOG721ay7e58ARAY8o0HVEMGqhaGzmIgnR811lJDmnjXlD9O
         7SCeVEaLl7+NXwAY92iQoUZe8U7c4AFWfBXs5PXy4os11JgiCmCRljzJWwoXqBOnjXHP
         bMokiBFin/JRY0DcBuxeeV5dp5F8pZSY0WUF2zR4HGV1G3BFsV9wMUt/6OqdmA2as6qq
         NCtIr6b81HCs+FmsxDgHBxs+N8Bc5zPbjkcTQeIEMrtgMhsJwlNsXMb3YGBVljSOg3f+
         5/Bg==
X-Gm-Message-State: AO0yUKXBG+PPum85r6DW09y3P/um1hMlQyA1VXhVIO9A67A+CXjUuG0N
	csyAB1ACm984YQp/Fgn6R+s=
X-Google-Smtp-Source: AK7set/OoRScyQ/6euBhAij+pv9bfFj5B1MjIZXIjgcLctKPhi/3kP83BnfIF8VaDPTvSyvx7nxc2A==
X-Received: by 2002:a62:79d6:0:b0:593:b73e:49af with SMTP id u205-20020a6279d6000000b00593b73e49afmr219636pfc.24.1676354883784;
        Mon, 13 Feb 2023 22:08:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:883:b0:210:6f33:e22d with SMTP id
 bj3-20020a17090b088300b002106f33e22dls7204024pjb.2.-pod-control-gmail; Mon,
 13 Feb 2023 22:08:03 -0800 (PST)
X-Received: by 2002:a05:6a20:841e:b0:b9:24d:8320 with SMTP id c30-20020a056a20841e00b000b9024d8320mr2064237pzd.26.1676354882930;
        Mon, 13 Feb 2023 22:08:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676354882; cv=none;
        d=google.com; s=arc-20160816;
        b=m8hScK2S418gx2Etk7q7fUidp6tu8fRERPUmAv+tDCNG47k49hDToFKiGbTgcpuMKh
         aQ/VY8fiCVLd5CzjRC66fFILM2gJRXCxAFVSPFqs/nnjXnZXrkktM3C/e1ehhm8k87uv
         NgSiHLg6eDPNGBT0xA6tmh2xpnVHl3jZC+fPEkPg/AQxeSZhIKdpdRQPgduHW8L+nYS7
         VeigyhLYdM0AFO1wqwDc9O6Kc5yZnzm+SFRAtGFVRZ1AzRxhZVT/qseVn/462ge2oDrw
         fQcmfybPc1RvGXZi5zK6pvx4Kc0xAoXVHrcRNNNFP3mRpecidufXQLM+vuFVTI2nG45H
         lcLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=i+nVV5Ba3Z7LEjnraYcY3XOVAg4sdVrhWrxDDszwimc=;
        b=ihwaMini7vg4J4tNd4sRqBjDGqNyrwlZJWz/tXt+wXdRN3llHFavzRz5d+HQiRF/AJ
         /dR4McUAr1ZX3WvnQqhZqFd/LdwyL5zY3WTIa/Hy3SrUN5rlzGsWbkkBOWD6ITWTpO9E
         HdoZciuIcO4om7/uTm6Cv1PyIJmzNtIOHCgswJDGl4mAr0kuoKkY3a5EUmdAZ6WBc/cf
         a6C6z1XB0SZoG68GUhb1E15+Cz3G6yphHZ1kgc0XnSbicg2pd2CRBUkHFZMDSdr7jtKi
         YTbOFMhnBVAZeMkUiHyzHiz3drvt1xoC9+kf1EWrKy7tfvllqYW9T8ougsLa8PYGTg9m
         x6hA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="FNiC/1wr";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2a.google.com (mail-vk1-xa2a.google.com. [2607:f8b0:4864:20::a2a])
        by gmr-mx.google.com with ESMTPS id u15-20020a63df0f000000b004f299d0324esi1022033pgg.4.2023.02.13.22.08.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 22:08:02 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2a as permitted sender) client-ip=2607:f8b0:4864:20::a2a;
Received: by mail-vk1-xa2a.google.com with SMTP id v189so7445211vkf.6
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 22:08:02 -0800 (PST)
X-Received: by 2002:a1f:2012:0:b0:401:5cb7:dc92 with SMTP id
 g18-20020a1f2012000000b004015cb7dc92mr191751vkg.1.1676354881939; Mon, 13 Feb
 2023 22:08:01 -0800 (PST)
MIME-Version: 1.0
References: <ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl@google.com>
 <CAMn1gO7Ve4-d6vP4jvASQsTZ2maHsMF6gKHL3RXSuD9N3tAOfQ@mail.gmail.com>
In-Reply-To: <CAMn1gO7Ve4-d6vP4jvASQsTZ2maHsMF6gKHL3RXSuD9N3tAOfQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Feb 2023 07:07:25 +0100
Message-ID: <CANpmjNNvGL--j-20UxqX_WjeXGiAcjfDAQpfds+Orajz0ZeBsg@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] kasan: switch kunit tests to console tracepoints
To: Peter Collingbourne <pcc@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="FNiC/1wr";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2a as
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

On Tue, 14 Feb 2023 at 02:21, Peter Collingbourne <pcc@google.com> wrote:
>
> On Tue, Oct 18, 2022 at 10:17 AM <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Switch KUnit-compatible KASAN tests from using per-task KUnit resources
> > to console tracepoints.
> >
> > This allows for two things:
> >
> > 1. Migrating tests that trigger a KASAN report in the context of a task
> >    other than current to KUnit framework.
> >    This is implemented in the patches that follow.
> >
> > 2. Parsing and matching the contents of KASAN reports.
> >    This is not yet implemented.
> >
> > Reviewed-by: Marco Elver <elver@google.com>
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> >
> > ---
> >
> > Changed v2->v3:
> > - Rebased onto 6.1-rc1
> >
> > Changes v1->v2:
> > - Remove kunit_kasan_status struct definition.
> > ---
> >  lib/Kconfig.kasan     |  2 +-
> >  mm/kasan/kasan.h      |  8 ----
> >  mm/kasan/kasan_test.c | 85 +++++++++++++++++++++++++++++++------------
> >  mm/kasan/report.c     | 31 ----------------
> >  4 files changed, 63 insertions(+), 63 deletions(-)
> >
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index ca09b1cf8ee9..ba5b27962c34 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -181,7 +181,7 @@ config KASAN_VMALLOC
> >
> >  config KASAN_KUNIT_TEST
> >         tristate "KUnit-compatible tests of KASAN bug detection capabilities" if !KUNIT_ALL_TESTS
> > -       depends on KASAN && KUNIT
> > +       depends on KASAN && KUNIT && TRACEPOINTS
>
> My build script for a KASAN-enabled kernel does something like:
>
> make defconfig
> scripts/config -e CONFIG_KUNIT -e CONFIG_KASAN -e CONFIG_KASAN_HW_TAGS
> -e CONFIG_KASAN_KUNIT_TEST
> yes '' | make syncconfig
>
> and after this change, the unit tests are no longer built. Should this
> use "select TRACING" instead?

I think we shouldn't select TRACING, which should only be selected by
tracers. You'd need CONFIG_FTRACE=y.

Since FTRACE is rather big, we probably also shouldn't implicitly
select it. Instead, at least when using kunit.py tool, we could add a
mm/kasan/.kunitconfig like:

CONFIG_KUNIT=y
CONFIG_KASAN=y
CONFIG_KASAN_KUNIT_TEST=y
# Additional dependencies.
CONFIG_FTRACE=y

Which mirrors the KFENCE mm/kfence/.kunitconfig. But that doesn't help
if you want to run it with something other than KUnit tool.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNvGL--j-20UxqX_WjeXGiAcjfDAQpfds%2BOrajz0ZeBsg%40mail.gmail.com.
