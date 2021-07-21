Return-Path: <kasan-dev+bncBCJZRXGY5YJBBD4Z4KDQMGQEELKRLCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A1EF3D18A6
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 23:07:29 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id f62-20020a17090a28c4b02901733dbfa29csf492958pjd.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 14:07:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626901647; cv=pass;
        d=google.com; s=arc-20160816;
        b=lAQ6LPHTyq1YhylTy2Dhk0VtGVZ4ArMt7vt8c3igS9N/fleX8kqkLIpv+Z/BgPeH7n
         6QFpkQDpwX9nwAhr803RV+9f3agx7mFMuL03Nc7EDAFHabi/4Fd3UrT9aYoK7LmUUGfI
         QX8kHvPwKn1lVFFDxxZiQxIbn8HwGNwN2b8QUuDmAfhxmuhuv1aVftD7cAqCMQtd6z0Z
         LLtZqn0P40JyipQyomN+NucYWyBOavWirE3fe1zKcR5g820nAd8q2AYdqUJFT2RLtaBQ
         /tptKLOYvLeOg5JG9CY5pJsHz1sBkggObn/CJRkGiqVUwxnFdhNF98QzKg5EC/wx9a60
         KZNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=PcRnuA6GZ4iaKezioj5ki6e/PVGzLHyEktzkyPuDuGg=;
        b=u7IoloPg04BoCDPIX7UeMZWYzUfbexy+Sc4n/btLETsm5VL+OdZ+n938SNGKZsSVjQ
         vJYLHhFQztXTslyOV8kjYDTkE/3mXePBYDrgCJxj0PyLjZBSZAhppEqn3fNZjRHcfs03
         gornxHrIIexofNuRFNbS9m3jOxZjEy4jWs4CA/pRIG8EBkn1FyjZeX/C8WXrv95rohPN
         HvCn4gi/qQ8R3IycTJjs9bjSw/U2qs7gKWj4u4vzQu4ClSotF1gaS0zJGcphJFkKr7AV
         UtzEk99nbdAXu5seHyl+2zcI9ONuT7xCFK45M+QoXdymyyTKvkAYxmlDiJxEbi47m6Q8
         Txzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OwUN9pWX;
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:mime-version
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PcRnuA6GZ4iaKezioj5ki6e/PVGzLHyEktzkyPuDuGg=;
        b=HSoXGaJSzSpAnc6WY7B6XRll0DFuO5MM2CX/7WvSQknFDHXhjFOUSZGDXYs1eh12ul
         Eh4BdglAJuOu7fvbD4Vt6p4RLcefQUfrWz9WwcOjCMNneB7pBuzo9gHt7Ttxgf5GZge2
         GF2Hj0CQLQmRO93kjChdjx50BWXL1y8m0Ub4VinsEbNVHOp4nwEr5G/QMybu+oqxrZDh
         wAPN/0n9eh8kFrhStZslBMHGoyQVgq3w/skfstFYIDg9sQt1i+YT+KmNw5Xi6uNwMgMg
         OACJMVWhzBlh7QwUhosEPtJohGj6kK7quSZyqY65YDK0oVDxj6CGVKju46aXBaXzszjF
         4gwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:mime-version:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PcRnuA6GZ4iaKezioj5ki6e/PVGzLHyEktzkyPuDuGg=;
        b=lbdJzoPtwt3UsplA/rK4BOYnXMJ1UfbawcrxlpCC8OtbbjDx6GhaqwaWFuXEqzEsGC
         p2lOHm5XuNn9h1/BdyghttfuR6PJq4fgqPgF0F9JBsde1BXRZTanUGdzpJCjkynS2B6M
         GOhgyAxX0wZp2pnWZU3N+85B39x+ihVEV7TsxC8SeqU7HdgKqnRPqJ6ErHhlamSrElMB
         lNhTUoMuGAkofjLMaOP7Sc4XZe8+LLtO/lyF3z8PgKDuv7nnhE4PRK1/6VaV2zZ3wt0d
         RyLdrCvwZrAqBDD5gvP2pB54tV0wYjM+xlRNTkW+Aem5S2FfuNKwC8m17X6mwFwVe77g
         MCYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530djj6meSeUCNWhIe98Gjk+5WK/3e/ZvhoEWr+GDKJo99kVVz7F
	rKnaXZVw7KUV2X7sQGDYb60=
X-Google-Smtp-Source: ABdhPJxoqJDVwSExX8O5a3erZ4XkQ7z5SK9+6S7xj7G2iMJzMYf+K9BHTICwDpEQ9Xt2whUvAZd2wQ==
X-Received: by 2002:a17:90a:e611:: with SMTP id j17mr5643819pjy.48.1626901647668;
        Wed, 21 Jul 2021 14:07:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:26f2:: with SMTP id p50ls1534898pfw.2.gmail; Wed,
 21 Jul 2021 14:07:27 -0700 (PDT)
X-Received: by 2002:a63:1041:: with SMTP id 1mr37994400pgq.274.1626901647160;
        Wed, 21 Jul 2021 14:07:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626901647; cv=none;
        d=google.com; s=arc-20160816;
        b=wAlQK30Vxe85YfiED7Ja72KdjIqLX75W8n4ZhTBE7JJ4LIYzghfHPj2lyerz1d1E5E
         F9AHr5FFAeVpb4XbNTBfQhBPP8LgYhHxIQLK0Fp5DyaFJoRLUFv7JCpacfXBbZ38B6hJ
         ms34OzC6s+sDrXCpfc2UaOqqd2/vGWlT9O8tw31gnb6R/tRTAbLuuxwqM5i/IdaZyR9P
         KvzF/EB8LMdZAm7FzSHJDpQCKLYMaZcM/8JwqfdH+5LbYECAnHDU093Yb5zfnmR5YIVx
         P1dMzvN6aXWR7u9YFWFx7MbA4RxV04eIHrcSl+pHiUmq6Ou7y3f6UsYTr1hIYlcW7JOh
         YBMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=xXrJkgLqvmIjG1dx3APwoEbwtRMFaFbMKZ4G6rBZ6zY=;
        b=Lov3EeaxPUKxTzrXaHx8AUvjYEYDddL2PHkum/+J4HGusXSNol9Li/fdDyQWBF+JHB
         ORZOGFJG7XjX/dkiOF373d0cfdmzSj6o/dplnfc2AFGC91nEtnCnzkxWj5pIuRADnX+P
         vd1+mIYXhBUDqQW35Y1IwYAwhsg8z+oI/LZq5FOSFR+1Qx742mEoY814WSdPPYRWeO4w
         NWkbtX5RESUJwaFqGb0A8gRM8ulBLN/9JW4jg5ZIIlbNT7FdSCNSJTlgYlyTmKq7Mjle
         6c7PmEdLBWGFIrhjl7gBny8+Y6NyT0a+ggSA0NL8vJfcXooGnYfYIJB8c246iQS2CC1i
         0yPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OwUN9pWX;
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y6si1100227pgb.3.2021.07.21.14.07.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Jul 2021 14:07:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id D81AD613E4;
	Wed, 21 Jul 2021 21:07:26 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 970AC5C09A4; Wed, 21 Jul 2021 14:07:26 -0700 (PDT)
Date: Wed, 21 Jul 2021 14:07:26 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: [PATCH kcsan 0/8] KCSAN updates for v5.15
Message-ID: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OwUN9pWX;       spf=pass
 (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hello!

This series contains KCSAN updates:

1.	Improve some Kconfig comments, courtesy of Marco Elver.

2.	Remove CONFIG_KCSAN_DEBUG, courtesy of Marco Elver.

3.	Introduce CONFIG_KCSAN_STRICT, courtesy of Marco Elver.

4.	Reduce get_ctx() uses in kcsan_found_watchpoint(), courtesy of
	Marco Elver.

5.	Rework atomic.h into permissive.h, courtesy of Marco Elver.

6.	Print if strict or non-strict during init, courtesy of Marco
	Elver.

7.	permissive: Ignore data-racy 1-bit value changes, courtesy of
	Marco Elver.

8.	Make strict mode imply interruptible watchers, courtesy of
	Marco Elver.

						Thanx, Paul

------------------------------------------------------------------------

 Documentation/dev-tools/kcsan.rst   |    8 ++++
 b/Documentation/dev-tools/kcsan.rst |    4 ++
 b/kernel/kcsan/core.c               |    9 ----
 b/kernel/kcsan/kcsan_test.c         |   32 ++++++++++++++++
 b/kernel/kcsan/permissive.h         |   47 ++++++++++++++++++++++++
 b/lib/Kconfig.kcsan                 |   16 ++++----
 kernel/kcsan/atomic.h               |   23 ------------
 kernel/kcsan/core.c                 |   68 +++++++++++++++++++++++++-----------
 kernel/kcsan/permissive.h           |   49 +++++++++++++++++++++++++
 lib/Kconfig.kcsan                   |   26 +++++++++++--
 10 files changed, 218 insertions(+), 64 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210721210726.GA828672%40paulmck-ThinkPad-P17-Gen-1.
