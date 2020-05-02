Return-Path: <kasan-dev+bncBC6OLHHDVUOBBT5NWP2QKGQELTVWZ6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4706B1C2238
	for <lists+kasan-dev@lfdr.de>; Sat,  2 May 2020 04:11:28 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id y6sf3786279edo.18
        for <lists+kasan-dev@lfdr.de>; Fri, 01 May 2020 19:11:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588385488; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZYoH0WbJXHHEWSrv5Qk0QQtQNXoNOwahSiqbQtjzROKhLeCEhaIj2wji+8D7lC/eZq
         vzaPQkTcHfGbitNbLoJowZuZQxU0kPpTly13qyHDc5KLyvTzOCY3SU+siGgpKodndMaK
         MPzAeTtSUq2cSxOSTw++JE95fpCzJ4NAukUJxnCTTArXnIp/vkFAYNhgHKoB9UA5q65T
         Q4gq4x+HaL63CRaz6Gqq0QyqJSJnG/R0uC0qZZvVyds4hBCX3yfs6lM1TkUr5lbzB57Y
         Lly8wMeIZ/6NlVPEWbgNVT3p8GJUtVDnkVvj/7+KtyVCEjp09cL2pbfOwwbR3YEWwxzz
         o2FQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0BXvgIbV3KsOyFQMmQpPvwqPAGTNv1k0P2Nj2f/PNME=;
        b=V2D17hkcMAu/ML6abKwJXQfHShfjGTVgdl/gOzWB5pcnsu5KDuYXtfoTafEa+cPwbv
         zqye8J4dM4tOVScV4h2rUMXAb05FjTYouHEcxxds6km9eP5s09+qsIMxuWXiA+H4co1c
         W/Od+UybrTT5b8kdppCgzpANB4Hzu0p8HgyJ5Ia69abtC+oMqPuWOnXNxqxFdeBPV3IJ
         6aySzceNQ091TsUhnvV3t3bFyJb2vsJESbePmRzIsLTMsr+m6pu2kR/jtRAqc/aqXzBx
         mUDugowq1Yz2Ag7+EJbOKo91HKoQPW3ejjblCDL3oFz4sc6e5v27ZGYSkun4+QXqwXOb
         NVNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GoAOXqYv;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0BXvgIbV3KsOyFQMmQpPvwqPAGTNv1k0P2Nj2f/PNME=;
        b=qiO/w3HMZk85NMh/8Pmh7diz/06uszzDo83PBk/N03GzLaIUuCTugbXYHf0c2q1JsA
         oedhfDjS55/Im6vOLTuLzhZHgTEfieVgXp258c46jA0X1TYu5S/1zeUByM8VVkOqUTGT
         voLfJwI6eK7DFFG4Qu+MQY3BeyFQ7YDdAQuPmXxX8R+cUbX+bET1ZdQym0+DB/E4yTKS
         kK0o9DmgyTTmSwCBmgUgz1/X3WR620m9qndypaUFqtM/+KfFmUo5R4cmFK0lyPepE4qx
         TchCWoWXxeWStTDEXGropt1M7Vn26WlyF+Qt6dqB5cEpk5xzo5TSVnXK4+f421jbRvbM
         lAyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0BXvgIbV3KsOyFQMmQpPvwqPAGTNv1k0P2Nj2f/PNME=;
        b=GzJ93UCUa13tEiL2MU4u1vWYTpY10JFeuwItKgDiskv0qtLmDRZE44LXPYXDwpmUHX
         q/6HRs3RMb9CotdRz65LiKDwN/ZOGC1iimU09kHak4jnOmftj/LB2MJh4bKrbz+dUmlJ
         T8cvb+4c4c0zx1reBPngCWM5ELb9mO9WYC5XgrX/7ZDraF5hKMtcSfWec2tH7UFmTwft
         TVwNINCxmEUjr4X/kpyVZk+kZloQ3bnWDE2FKy4lm4c6JC+jFG5RaOx9cF5WosZwYG/y
         kVSFbf3UkA2qYxBPNpRtS3krYLDt2+Mfl4U9uNz8bPLgt74bjOC7MD01FhInpmxgkQ/b
         XopQ==
X-Gm-Message-State: AGi0PuZyjrU6eE7gTjkLQRxHGUoW1RG9l3uwHKxNXlJCnupUvdkYCX+I
	WuJUIfFlrt5CJABOcEYTJ4Q=
X-Google-Smtp-Source: APiQypI+4jAwVOvmsdsBTuZ7ti3gMOELTjC+4IwZML5WZCfRuT/BprsyblJOYDrxSpoL3mXUu8owjA==
X-Received: by 2002:a17:906:9450:: with SMTP id z16mr5737031ejx.166.1588385487962;
        Fri, 01 May 2020 19:11:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1d83:: with SMTP id dk3ls3031625edb.9.gmail; Fri,
 01 May 2020 19:11:27 -0700 (PDT)
X-Received: by 2002:aa7:dd84:: with SMTP id g4mr6101015edv.273.1588385487349;
        Fri, 01 May 2020 19:11:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588385487; cv=none;
        d=google.com; s=arc-20160816;
        b=LzuTvsasoNHFuleKW/4QEPaBvajWQN7YkdwOMzezvPbVfxEqSyMWkEWiw2wS5fXdEA
         IMQePl105etAJC97ejOv5v/NKijv8rb3StjQWCCnp2caBl8fTvR+PgjeG6iB8aiPfHJI
         THw/1NtdTCiDcGgjdESIgoEUoGczyjKQiURKXbimvzA0ecTbjFulaaTO5A8lvrAhlESq
         yGhH72E9vGSe13Olt98sB5qDI4BsGFmdLEHsEzYQJxwa6N1sjGpjCsrDREznuYi0A6J4
         DqTkPA1ErQN0vectU8jZgeZc5cgLCqS1wPJmhxPfBZhTBGNlkYviliBGvBiKUAzSNUg7
         Y8cA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DxgeZ4dWQbsgxzC3vr4Uf0z6ga9GPtUvmnQ6rfH9mnw=;
        b=XBTtmDOKnYzVdpbyF9UucFc9uycx2H43auL1xZy+218J8a41Ir7gKWcs2Bjodhf+hX
         gMAdg4Lhh8obkr8f+pKXBCPAO0HQMTW45mr1dq7AZCE5MGuFFBDCNA8sEVPJXOkDU9qz
         rlkxTJTDWdOavujeqEgAwEn3FYFOGDru1w59XTji/WlVOoyWFK1/Rdjc0ddBo9oBDrUe
         BjaqIW6dFBpvkAFuhB0CvP5hhlzmm+Ag7X5GvjwIrprcB6BqtLR4Tq8ly8dpT1urDCid
         ggk5taEKaJ1Fcy8DN/nRGxDOkKbVYMgUoSlY6P/0BhWK9twWxRrDzZS/AgTqRKnk5IpN
         yJ2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GoAOXqYv;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id f24si203295edw.3.2020.05.01.19.11.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 May 2020 19:11:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id x25so1993965wmc.0
        for <kasan-dev@googlegroups.com>; Fri, 01 May 2020 19:11:27 -0700 (PDT)
X-Received: by 2002:a1c:dd8a:: with SMTP id u132mr2195716wmg.87.1588385486740;
 Fri, 01 May 2020 19:11:26 -0700 (PDT)
MIME-Version: 1.0
References: <20200501083510.1413-1-anders.roxell@linaro.org> <CAFd5g45C98_70Utp=QBWg_tKxaUMJ-ArQvjWbG9q6=dixfHBxw@mail.gmail.com>
In-Reply-To: <CAFd5g45C98_70Utp=QBWg_tKxaUMJ-ArQvjWbG9q6=dixfHBxw@mail.gmail.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 2 May 2020 10:11:15 +0800
Message-ID: <CABVgOSkAAb7tyjhdqFZmyKyknaxz_sM_o3=bK6cL6Ld4wFxkRQ@mail.gmail.com>
Subject: Re: [PATCH] kunit: Kconfig: enable a KUNIT_RUN_ALL fragment
To: Brendan Higgins <brendanhiggins@google.com>
Cc: Anders Roxell <anders.roxell@linaro.org>, Greg KH <gregkh@linuxfoundation.org>, 
	"Theodore Ts'o" <tytso@mit.edu>, adilger.kernel@dilger.ca, Marco Elver <elver@google.com>, 
	John Johansen <john.johansen@canonical.com>, jmorris@namei.org, serge@hallyn.com, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-ext4@vger.kernel.org, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	KUnit Development <kunit-dev@googlegroups.com>, linux-security-module@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GoAOXqYv;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::343
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Sat, May 2, 2020 at 4:31 AM Brendan Higgins
<brendanhiggins@google.com> wrote:
>
> On Fri, May 1, 2020 at 1:35 AM Anders Roxell <anders.roxell@linaro.org> wrote:
> >
> > Make it easier to enable all KUnit fragments.  This is needed for kernel
> > test-systems, so its easy to get all KUnit tests enabled and if new gets
> > added they will be enabled as well.  Fragments that has to be builtin
> > will be missed if CONFIG_KUNIT_RUN_ALL is set as a module.
> >
> > Adding 'if !KUNIT_RUN_ALL' so individual test can be turned of if
> > someone wants that even though KUNIT_RUN_ALL is enabled.
>
> I would LOVE IT, if you could make this work! I have been trying to
> figure out the best way to run all KUnit tests for a long time now.
>
> That being said, I am a bit skeptical that this approach will be much
> more successful than just using allyesconfig. Either way, there are
> tests coming down the pipeline that are incompatible with each other
> (the KASAN test and the KCSAN test will be incompatible). Even so,
> tests like the apparmor test require a lot of non-default
> configuration to compile. In the end, I am not sure how many tests we
> will really be able to turn on this way.
>
> Thoughts?

I think there's still some value in this which the allyesconfig option
doesn't provide. As you point out, it's not possible to have a generic
"run all tests" option due to potential conflicting dependencies, but
this does provide a way to run all tests for things enabled in the
current config. This could be really useful for downstream developers
who want a way of running all tests relevant to their config without
the overhead of running irrelevant tests (e.g., for drivers they don't
build). Using allyesconfig doesn't make that distinction.

Ultimately, we'll probably still want something which enables a
broader set of tests for upstream development: whether that's based on
this, allyesconfig, or something else entirely remains to be seen, I
think. I suspect we're going to end up with something
subsystem-specific (having a kunitconfig per subsystem, or a testing
line in MAINTAINERS or similar are ideas which have been brought up in
the past).

This is a great looking tool to have in the toolbox, though.

-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSkAAb7tyjhdqFZmyKyknaxz_sM_o3%3DbK6cL6Ld4wFxkRQ%40mail.gmail.com.
