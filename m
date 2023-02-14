Return-Path: <kasan-dev+bncBD52JJ7JXILRBIOEVOPQMGQELTGRRLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D75F56955D0
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 02:21:38 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-16de8b67b4csf3276149fac.10
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 17:21:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676337697; cv=pass;
        d=google.com; s=arc-20160816;
        b=LISMtkVcRsSwwtiJSflbpszSznUColAVXjwnQDZwWGPfPO6JUpe5krugjMpJni+p9I
         IkgKFyMDqn5R6tbuEl6whWo2kDcSqOCoyWYx4SW3g3DWNamR+CB7prN2NN+BR4tU4PSG
         mzrvsmXgOny0Mf/nwuBftCltPAz25foBUhw2sE2SmZ+UU/HO8LNFjeJuj7jQKKSK2NvJ
         ubU8Zfk/UfCJcTC33LuPsUylN4MMzMwjb72UNsrmjvuTwXm0G9f1/D5twTgaBblTW2tI
         ScxRkib0KISocuzBabFua0TVLtj/4cWsRtt8zopByvHM6SoCy3/RVq7yPGZNlPdZrEMR
         6X0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ddYJLpfSouUm4sXLMk1hoRXEveFcxHqQ10eFNmvSVkM=;
        b=mY18Siks0Ez62+wX0zP09D5Ky0/Hp6GuWvhpObSak1MboQjQpUvnHjQiBLrtxTdTxr
         AvJv73f1zMkDxgZ+F7wP8Kc7TMvv3KTaaDdfSgBm+fmdqDXU+xa63awFtL8HGV3kMVda
         7nI1xSinCEMcKpO38JaV8hmpjmdPz6v2jp2BCXSLHIxue/WrHHTkAnMuG57un6WsaAqd
         HI2B0cvzuY16Xv7UYPMGK0v8zpK0SaiUYE+V6qnpGh39jC0NTfmOzzJ3GpyqPcz8qPIx
         7Cvmb5/wt8w6bEz4U+Pgudz0moGVY+/HOm9SzSku1r+vWmAcZX6O/AZQXRxIzBIKJLP2
         Y2Pw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mOYk+wlL;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a33 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ddYJLpfSouUm4sXLMk1hoRXEveFcxHqQ10eFNmvSVkM=;
        b=V7MFVU9VjREc54FR/F8VMFBOnkjcBNoC66SmMdz/VxWUizlQB6rysIiRJJGP1s0u50
         Q9ujpyb90otSOKnpgBIYlOFRehzWiqaa6N62VpfZ7I57fSxCVGq06RYuJyPasUI+I+BM
         V5csKgNdpdIogwVMzXvIjbEYTW/M2Hx4la52OutJklhqdPNf8FrUYe4HmPEoug5w3AGm
         qT6/Y4Vwmx3LHHQhQTQGqsuWyBjL7teBuks5vuwmo6v/792RLA1D/LVYqg8Ye8jenUF4
         pOrZZrKPfXup2uIq7nYsop/tcL3EHWCv2aSo77zDrkAq7gG2daPMKjuLNHGh2pQ3KN9/
         WbvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ddYJLpfSouUm4sXLMk1hoRXEveFcxHqQ10eFNmvSVkM=;
        b=a1riI1Vj+RaqBtjdfQEHYoGrY77WT1cOm359lrQb46j6RLMJkGcHiyqjWiNA8Is7uT
         gioCUNrv+a79Y0X24BV874sMixpihMVlEa7Z57kQTMXyHNZHDZSgRVoDGeT5SChQNYFS
         GWdDWvZUdpIvzQ30xUQtVkDOtvDPDHZyUYNhGBLwlih1LvJzM3F1bBDxFxuQQNbiAf2E
         RppPXteH7Q63rOwNnvy+c29LGtC9wmyQSbogNiUYQOMKIOQOrWJoS9cuKMcqMXarsvw5
         rSJq6Z9lUSegQ07EU2aQ/zkOuJDm6DJD7w75poLUsWFnOucZicdD83qfhZ3HentBxnS0
         nnwQ==
X-Gm-Message-State: AO0yUKVk+w0PwOlhSESNdolSj5K5aYHYVEksfY5QjkE+eaDLrmt+jmUl
	3D6tKP6QEKAcoQ8rJkt2tkrWCQ==
X-Google-Smtp-Source: AK7set8WsKpbk2B2BTSW3/3Zb59A0uB73uRSLYov93xn9+O+SMupU8sMFN0Wt+YcxAoXu9W21SSZRA==
X-Received: by 2002:a05:6870:bf93:b0:16e:1db5:ec69 with SMTP id av19-20020a056870bf9300b0016e1db5ec69mr19531oac.226.1676337697468;
        Mon, 13 Feb 2023 17:21:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1706:b0:36e:b79c:1343 with SMTP id
 bc6-20020a056808170600b0036eb79c1343ls3647973oib.7.-pod-prod-gmail; Mon, 13
 Feb 2023 17:21:37 -0800 (PST)
X-Received: by 2002:a05:6808:2c9:b0:364:ebf2:869b with SMTP id a9-20020a05680802c900b00364ebf2869bmr327195oid.46.1676337697015;
        Mon, 13 Feb 2023 17:21:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676337697; cv=none;
        d=google.com; s=arc-20160816;
        b=nMVnHvezc4+YtOOAnqtdLzADOBFe9MGH8uMijw0+eSOBi9JhN3kk/yfkIQO9MthgMu
         kNbRcQJpzc6HwMhg+W/c6KbW0v1R7aoYRNnDCXaHz2JBlmU0v2qgV11SdMH8C4cdKOev
         Slg+R3ib8p+UCalEWl/dqzOKCgW7sqE2YxF40W6U4lbW6t/09NaO5bYDhwWyWDhX0YWe
         P3Zi+pOL+EqF47A57+T7bzU7Z14Cw83OyiFVdlsi7nCuWBgYjlliCKMzpYfsYZuRmjgm
         E8eU0XUi3t8Ub4igjmKYrPj8Gz1Bu4r1NSaxUEFMDdM5NgEUZf2SyEFeN1MKz6oFD3QT
         ODIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VTf6y2rsNM1eSIJ6oZJRGFI8N75zoVA8XUUEZKJwwzs=;
        b=QTr983CX7alryNxYuNd6qd2eTYcitkrGD83Bly8PfdL2f48ElfD0fHBNi8Xr/hQ7E2
         Img6LcY+i89ixfQDFXA4C4S+XdPdH02QAWJC8xCRF/0NHHFtEHx297l4iqPqy35sSPs8
         rhTJhMB/NAAsg1d9e3bALQd88UkcGvcrI9cTIyJoog9CntEHxAY++aAPmf5D4u7D84ZV
         nxMMNfjPQoJU/UaEqyy9kgWhTb1ma0v9y821VgbheWNbuG/V3bdpy4IFv9FJTiOcekRp
         UnO9HSLxOFji047RIbjvs3eGnIhQL41H22pUkzFw7mKRJ0v0yUpaYKG9mst3DP7P/GrZ
         UoUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mOYk+wlL;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a33 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa33.google.com (mail-vk1-xa33.google.com. [2607:f8b0:4864:20::a33])
        by gmr-mx.google.com with ESMTPS id be13-20020a056808218d00b0037803603d36si979413oib.0.2023.02.13.17.21.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 17:21:37 -0800 (PST)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a33 as permitted sender) client-ip=2607:f8b0:4864:20::a33;
Received: by mail-vk1-xa33.google.com with SMTP id 9so7189973vkq.9
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 17:21:36 -0800 (PST)
X-Received: by 2002:a1f:32c9:0:b0:3ea:4912:8be7 with SMTP id
 y192-20020a1f32c9000000b003ea49128be7mr68149vky.41.1676337696352; Mon, 13 Feb
 2023 17:21:36 -0800 (PST)
MIME-Version: 1.0
References: <ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl@google.com>
In-Reply-To: <ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl@google.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Feb 2023 17:21:25 -0800
Message-ID: <CAMn1gO7Ve4-d6vP4jvASQsTZ2maHsMF6gKHL3RXSuD9N3tAOfQ@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] kasan: switch kunit tests to console tracepoints
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mOYk+wlL;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::a33 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Tue, Oct 18, 2022 at 10:17 AM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Switch KUnit-compatible KASAN tests from using per-task KUnit resources
> to console tracepoints.
>
> This allows for two things:
>
> 1. Migrating tests that trigger a KASAN report in the context of a task
>    other than current to KUnit framework.
>    This is implemented in the patches that follow.
>
> 2. Parsing and matching the contents of KASAN reports.
>    This is not yet implemented.
>
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> ---
>
> Changed v2->v3:
> - Rebased onto 6.1-rc1
>
> Changes v1->v2:
> - Remove kunit_kasan_status struct definition.
> ---
>  lib/Kconfig.kasan     |  2 +-
>  mm/kasan/kasan.h      |  8 ----
>  mm/kasan/kasan_test.c | 85 +++++++++++++++++++++++++++++++------------
>  mm/kasan/report.c     | 31 ----------------
>  4 files changed, 63 insertions(+), 63 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index ca09b1cf8ee9..ba5b27962c34 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -181,7 +181,7 @@ config KASAN_VMALLOC
>
>  config KASAN_KUNIT_TEST
>         tristate "KUnit-compatible tests of KASAN bug detection capabilities" if !KUNIT_ALL_TESTS
> -       depends on KASAN && KUNIT
> +       depends on KASAN && KUNIT && TRACEPOINTS

My build script for a KASAN-enabled kernel does something like:

make defconfig
scripts/config -e CONFIG_KUNIT -e CONFIG_KASAN -e CONFIG_KASAN_HW_TAGS
-e CONFIG_KASAN_KUNIT_TEST
yes '' | make syncconfig

and after this change, the unit tests are no longer built. Should this
use "select TRACING" instead?

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO7Ve4-d6vP4jvASQsTZ2maHsMF6gKHL3RXSuD9N3tAOfQ%40mail.gmail.com.
