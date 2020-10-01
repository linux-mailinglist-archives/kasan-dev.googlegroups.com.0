Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6FE3D5QKGQEHARL7KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id DF9B9280542
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:31:37 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id n133sf2089329lfd.8
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:31:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601573497; cv=pass;
        d=google.com; s=arc-20160816;
        b=c5XykOZCVWQZm5L9njVjU8F51u4jQGumj3nIrlkGbaedeCOhT/1bAk8UQKkuzvqz3V
         nsgw6W360Kkaz1rp6NpMXYKrP7QAg41kKPJ6I1xETx/Xl+ZDkjMKY5LvBtCn6KKBQ7Dl
         2xASFKlqER8Sq1EqSKOyrwJyPwQfcKflesz473zinqIG+K0Yr7D+xOr9CW6RdDMf3Z9A
         h61M8LDCt9thUDp7XrDec60RlQZDn5Li0Ry3thCx1e8DpEr7DxiQqqDBCGVU1w+phfsy
         fGeW5G13R+EU9zaZdf6dCrmilE9jrREUyKJg3uuQph/yTuWO3X0g642IAbIpWHGfqq35
         tL9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=xcQRzfLi9rGYTorrrh5NykvGpW+fGRGjQhB/OAEuUhs=;
        b=jxEjuLlLnDWKk1o9Mb4NPhnoWVNLKq592rYAPlNlRocc15nNQBg0BxrRwZeR5HY7zF
         evVQzki9JcJ7tlAE288hqeHj5AOPE2z/WltxR1N9xDhamO4NXlRiue6CybOnSmr1vh/u
         2WztPKK8EdpIeQi00L33abf+irHqUkmnhGHfZpVR0elX5nXl6lTQV4dh1fTYUeA4Xxn8
         5fKuOMPUiFREJOSBG17dhxOxdPzmq5Ovf5bhP2SAe+rGqVmnO18rVz+/CXgmAr7KMhsI
         nQpVqs+ZnX7qOYQ0mhR3KA3uEEa7p9o1VKjdQKtp3/T1k4GHp+qpYfa28hkGqdzMsnL6
         Vjrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=S2VPvy+y;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=xcQRzfLi9rGYTorrrh5NykvGpW+fGRGjQhB/OAEuUhs=;
        b=oGJSneIHfU6PNFUrpclw0psy+zoCJp298nSmiBLUiKpzJ+OOQ6ya6Y1OskF+H35lUI
         bFO2hkAO6oHi6TmeVVPDEaDGCNT7P3fqp5cKCWH5G11xDaZZ6rsAVcfRYhhhFFmcxxAV
         mFfx5O0uaaUmt6Azcn6z6q39X6heHl4yVTNKhIlATut/CEHCM1RPILhrr1zfHDxjcVfV
         E+DH7tXhS9oN/VOaa9sCLGsfxkqMYI9U2neRH610BjmZHiXA/BDede5IPGtrBcbydZoz
         Ph/frQY/SEMQg5g8KZGKt4uD8wT7dLs319oYUAi5kU5COEHkRbLXN+T7W8HDEFFDI+WC
         aWMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xcQRzfLi9rGYTorrrh5NykvGpW+fGRGjQhB/OAEuUhs=;
        b=FHUvtRLi61noD4a8zJ466uejM6Xdgpx8b8bw48eJp972t8JlLy2EJlMIplvdH182TX
         D9ETut21NetWXFphaLzdu68/yog676cUuJkZvGeT+DF7wUVQtC09fUHgwyrrQLqv6qG3
         l8fBTN7su6Kiz92vo4cawI+1X3WW/LzUnOCc+kjAttjLC+PG5Wkmn8V+QNtyArDDRZgD
         5nNgRhCHqVTKW/omN5ah2pKoFKgMiACc545DExbJj4dmTby71iFBKrJPH0lP67HtH6+e
         JW+A/p/UoMJri20E2Np+vBAedlkCx9OtkhymV8KE0J80q8RE9cGiG7WO2uoKgseEwZz1
         cu7Q==
X-Gm-Message-State: AOAM531mLK3aerl2XF1bxLfU6WZyQPw0/6vET6Lw84rnVpb63k6zN8oT
	aphI3Ujyq+G3X61KdEtdQug=
X-Google-Smtp-Source: ABdhPJwXmBljucwv3wbuJjC7Jzswn25FKujXMck+Gc6LJoc3VPn1PnvJv5/aMXxl9SmwM2crYrdS9A==
X-Received: by 2002:a19:e602:: with SMTP id d2mr3348207lfh.514.1601573496322;
        Thu, 01 Oct 2020 10:31:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7e02:: with SMTP id z2ls967744ljc.2.gmail; Thu, 01 Oct
 2020 10:31:35 -0700 (PDT)
X-Received: by 2002:a2e:7604:: with SMTP id r4mr2558804ljc.161.1601573495022;
        Thu, 01 Oct 2020 10:31:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601573495; cv=none;
        d=google.com; s=arc-20160816;
        b=vPXh+05kFbdFzkhw+pEGtTVD+iLtVHpqyAVZtLr/4suCpEMy/rrwU87YcKUS5dUE/v
         uSgX11nyBXvMPlRWy2yv8wLta/oesIF8dkB4sH+oK/4JztVjtZ33WGieJGPqlkl+2jUE
         mUym5J6UGd8DDQGhbrvUZUWxoVGK0eruX0jfs6pFRAVT/rvH+WYH+mwiYVrcjaJO+weq
         nLkFltYvB2s3EAzF7cfIDa32bRkCYrDch3BbROxvW/ZpETrwrYwysLVYyK13OaupMiag
         lMXddJHyQJsuiQK3zW3WrkSiYkQONQx2+IVFCpqVY3K/VzfkdHSZX2QbdMXWYbCceOEs
         SoKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9y69t8F5YRXIJmWOKtKIVuW0N+iZ5Wjjkop2pJOmrWw=;
        b=HB4uOyQ2L6eP8R3K85GE0luHVnwCxCmaTF6r2n7gMmRCd0DfPD30tMA71MzEqf/fro
         YhNRrZ02RcIreebK0tkFRwudI9qPvRSAsfZfIEGqvqEG0VGKnzY42mbCYCMwm4ECVk+j
         lHfzNZ1IxxhQefZkoiSrHJlc8zNkaXF4/tPiiwODcDMaNK6E4Ulv1ODniKX/CRpAdquP
         hp4/JN8cetxIBlVmO3biEBMl1u2wqmQSwY9WgHLKIFYEe1Qo1rhE1u1/gpVXqbdi4Ok2
         gq4le0tggmlhqLkxm/Odknth3R7fUf9o1LC+6LQfcMIpUJAMSubaZdSJOjfYre4puW1z
         KCLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=S2VPvy+y;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id x74si158150lff.12.2020.10.01.10.31.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:31:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id t10so6763678wrv.1
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:31:34 -0700 (PDT)
X-Received: by 2002:adf:de11:: with SMTP id b17mr10148567wrm.82.1601573494286;
        Thu, 01 Oct 2020 10:31:34 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id j14sm10670513wrr.66.2020.10.01.10.31.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:31:33 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:31:27 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 07/39] kasan: only build init.c for software modes
Message-ID: <20201001173127.GE4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <3ecf44f226dac37eb35409dc78568a99343fbf9e.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3ecf44f226dac37eb35409dc78568a99343fbf9e.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=S2VPvy+y;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
> 
> The new mode won't be using shadow memory, so only build init.c that
> contains shadow initialization code for software modes.
> 
> No functional changes for software modes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: I8d68c47345afc1dbedadde738f34a874dcae5080
> ---
>  mm/kasan/Makefile | 6 +++---
>  mm/kasan/init.c   | 2 +-
>  2 files changed, 4 insertions(+), 4 deletions(-)
> 
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index 370d970e5ab5..7cf685bb51bd 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -29,6 +29,6 @@ CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_RUNTIME)
>  
> -obj-$(CONFIG_KASAN) := common.o init.o report.o
> -obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
> -obj-$(CONFIG_KASAN_SW_TAGS) += tags.o tags_report.o
> +obj-$(CONFIG_KASAN) := common.o report.o
> +obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o generic_report.o quarantine.o
> +obj-$(CONFIG_KASAN_SW_TAGS) += init.o tags.o tags_report.o
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index dfddd6c39fe6..1a71eaa8c5f9 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -1,6 +1,6 @@
>  // SPDX-License-Identifier: GPL-2.0
>  /*
> - * This file contains some kasan initialization code.
> + * This file contains KASAN shadow initialization code.
>   *
>   * Copyright (c) 2015 Samsung Electronics Co., Ltd.
>   * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001173127.GE4162920%40elver.google.com.
