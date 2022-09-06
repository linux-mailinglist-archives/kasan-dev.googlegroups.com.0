Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFGE3OMAMGQEPRN6YHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 569C65ADF49
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Sep 2022 08:00:54 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id c1-20020a0cfb01000000b00495ad218c74sf7131679qvp.20
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 23:00:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662444053; cv=pass;
        d=google.com; s=arc-20160816;
        b=V9MgKyb52pAoXWYyBJws/CEITd74xfIxFAOLxd/5vMpLpOFmN52zh6ar3JmhDsPX1P
         J4HonczF0BNC9uvb1b73b7ZJsdVpO22LFIG1BIYHbSQsI+/CkcJ8RjmbRBkF+LHvIXID
         /TvEF192g+xnPFhSwkA1rMF8NdDE/cGwR6vbTFJY22maHE24BaZsDqp/gOhSZ3GRwRiu
         nFFWQvRk+L851XY2fIspePAhHAA20YsABdMzMl1tLz2CsCc1pHtkRnjXyPcb5Ym/6H4u
         xweGvu5LgGsWvxwV7R01c1X6DreSUIs2Qvg+DARkUuWndnoOZLiWtKAGCz8tLmemOF86
         Iglg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Dxh5hUNe9D0x1e7fVCsYHJOd9u5asXKghWOexgFqbqQ=;
        b=yEgkx3cfU+FtCLs14lpSXgmkEBjYqLsbpa16H0sP24hmutLaljc+PGaDE80yvBqVO0
         1XWcmURb7KbMYhBNCLnr3i5YGGX8AGCpE4T9zHCSYAtnmGFk14/bIwq1ekB6UuBIadCb
         eF4sBhUeim+nUOeOW8QQb1qMw7UOLOgPlWWAEy9AH/jenhjYqYHGXGitjT+n7VvbdZwg
         tF84oCwrO0RnWjYU8/0iKBKh43vu8h0WXBEr+FyZyKMBSDAF2cgIGxrT5CIV3m6JcG2o
         GpCiy9dsjY0EV3bqG91I5AEkx5pObZRFteWM1gH001k6W7gZXHIB51VTrCQSb5YhQKJj
         GleA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=d5kvgH2a;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=Dxh5hUNe9D0x1e7fVCsYHJOd9u5asXKghWOexgFqbqQ=;
        b=r8Arn0Tw6TUmGVprIgy8x7xHo6YjK1IAyhvWYFMOkeMUblZBTIGKfoA78JYU78yhZn
         QHayHfbgFG3ZcLVzvKMUiM5R850ieqV6Lby9okVmX0Zwr1pVQlJMfkdGxUQPoXxNQGCN
         RUAzEb2fdVQWDaTDsAhxh/2pX2WDuEFIDWJek92mR0h4fUfJgWqoGoZ5sCjhVAKeoMh8
         pgsbEU6Qej8E5y836cutUU9VzJxZ3AajwSFeSR79bmuREy3ZXd6Lmoqf5gNpTi1wb+iM
         kI/M77vK8IGS0XVRgcTkgLycd65DE+4NDBqTof97UDaQG2tTnPsANv8pEeO2zel9pRPw
         Xqxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=Dxh5hUNe9D0x1e7fVCsYHJOd9u5asXKghWOexgFqbqQ=;
        b=bujbqzWetyuYc6/7sEV+ZXyuew5mYwklI2POVERXnvhPM9wWZWIIzrqYt8OGtsGS7Y
         eTyjK2g7iPcWe8PJTPW+V8669aPxmhZtdPaib706RJg0ZcAsTsHfw8yCFPj6uS/y32+H
         XeETReabgVkoM1ImV//bY7R3we4UpCrjfCCeMdMd2jsACtIsKMUNd1eh4OyitEqS1CeC
         b3xik59vPmVQa057PsdRixLwEmm+uuLZBuhK+kbeZ+CKf8JiT0EeudDswh3slhIf+N9r
         1TxLsP8EEan+6e6rt9fV8r9y+jyHCjxzo+YwGxr6DEmslRa1/YZFsh64TfCmSGcdpUIy
         3dXg==
X-Gm-Message-State: ACgBeo1/hdtXLlle4AH2uKjttmBqx5ZBJN1S87X+OFVmifUJH9AByuGX
	OqzmRZbIWRaY4ZkfKCDD0UU=
X-Google-Smtp-Source: AA6agR4k68aBQfpvKd21kLLHvOVajab2xFpxc/R1EQ0vo10ggsa6c+nrdxH4oiLXn0mVVo+IE34s/Q==
X-Received: by 2002:a37:44d1:0:b0:6bc:2a1f:34b5 with SMTP id r200-20020a3744d1000000b006bc2a1f34b5mr34777294qka.521.1662444052980;
        Mon, 05 Sep 2022 23:00:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b395:0:b0:497:2b03:d8aa with SMTP id t21-20020a0cb395000000b004972b03d8aals7235284qve.1.-pod-prod-gmail;
 Mon, 05 Sep 2022 23:00:52 -0700 (PDT)
X-Received: by 2002:a05:6214:21e6:b0:49b:b7f7:3f4 with SMTP id p6-20020a05621421e600b0049bb7f703f4mr12209763qvj.78.1662444052428;
        Mon, 05 Sep 2022 23:00:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662444052; cv=none;
        d=google.com; s=arc-20160816;
        b=xtCLnTP/HDPR2HKYDJMag9T1G4MrxWNRtJhy9FNUeEbOo2SwNMI7cNWQd7Q2XvGcIY
         Lrs30VhLlOVgr5/F7pJsQxE3WVYW2TeZf/Ld0EWi7tEADa3yu9uOoupr4CJlsmyq5Wsn
         uyaNSviXSCLLvfyf/kIvqYNZuLSbVVWqmjOoGoXRmqg7MUQMcFx8BPjBd2Z2X+PXOTgc
         akBZ8HamH8F6jRNzZc2p5oyUpNfWUtNtZTTKAQthdf8LV0g4RC3ytWp4CKwQvHmGvxes
         G7YGK5/XMmvr4HLtJyO+ndvKvMXOJQbjsj6pRlMT3BK/HNnV6CzA7JLc7yvGPxm9vtYC
         ZqKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dVgxTZ8rakP42g8vhCO3njeR/uRGYZNUUx4gShIILwI=;
        b=fCjYSoY0i1FoP+Ht185EiOfdug9GglabBXUuNuqKdyswRGkbT5XZvLjacgt/WXrT6p
         AF/35zUitTVooiBpEEPaBWad5HVPGMbpSLoQwFRpVsIrzG50+svBnmDGsugDhzWTT2mt
         nspo+Cs5TMc6v7s1JfSs2/6yH9KrCXaGHHoOZJflPELLkSQ1QrwduUg5kbTTr/HsbwJj
         iA/UpTm6WH73l+E8Pb9akwVNvZeOb08GiVqsV/E5AoCLAKHckqxqMhB5W4wOAHLSl6bj
         H0CQzcvsvH0ayB3xJg04tNrdnaMokJfatqqvdbpvAKtAHjxPIgiWWa1JPY0T5w2N7OYO
         WPyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=d5kvgH2a;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id y22-20020a05620a25d600b006b9901be393si824120qko.0.2022.09.05.23.00.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 23:00:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id g5so15311323ybg.11
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 23:00:52 -0700 (PDT)
X-Received: by 2002:a25:b983:0:b0:695:d8b4:a5a3 with SMTP id
 r3-20020a25b983000000b00695d8b4a5a3mr36413414ybg.553.1662444051930; Mon, 05
 Sep 2022 23:00:51 -0700 (PDT)
MIME-Version: 1.0
References: <676398f0aeecd47d2f8e3369ea0e95563f641a36.1662416260.git.andreyknvl@google.com>
In-Reply-To: <676398f0aeecd47d2f8e3369ea0e95563f641a36.1662416260.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 6 Sep 2022 08:00:00 +0200
Message-ID: <CANpmjNN2T=uufbrj3ghr7S6k5E=YxvNpkq2Qa8qCY9NfPeeRsg@mail.gmail.com>
Subject: Re: [PATCH] kasan: move tests to mm/kasan/
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=d5kvgH2a;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b33 as
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

On Tue, 6 Sept 2022 at 00:18, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Move KASAN tests to mm/kasan/ to keep the test code alongside the
> implementation.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

Thanks - this is overdue, and follows what newer KUnit tests do.

> ---
>  MAINTAINERS                                             | 1 -
>  lib/Makefile                                            | 5 -----
>  mm/kasan/Makefile                                       | 8 ++++++++
>  lib/test_kasan.c => mm/kasan/kasan_test.c               | 2 +-
>  lib/test_kasan_module.c => mm/kasan/kasan_test_module.c | 2 +-
>  5 files changed, 10 insertions(+), 8 deletions(-)
>  rename lib/test_kasan.c => mm/kasan/kasan_test.c (99%)
>  rename lib/test_kasan_module.c => mm/kasan/kasan_test_module.c (99%)
>
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 589517372408..31b3e4b11e01 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -10938,7 +10938,6 @@ F:      arch/*/include/asm/*kasan.h
>  F:     arch/*/mm/kasan_init*
>  F:     include/linux/kasan*.h
>  F:     lib/Kconfig.kasan
> -F:     lib/test_kasan*.c
>  F:     mm/kasan/
>  F:     scripts/Makefile.kasan
>
> diff --git a/lib/Makefile b/lib/Makefile
> index ffabc30a27d4..928d7605c35c 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -65,11 +65,6 @@ obj-$(CONFIG_TEST_SYSCTL) += test_sysctl.o
>  obj-$(CONFIG_TEST_SIPHASH) += test_siphash.o
>  obj-$(CONFIG_HASH_KUNIT_TEST) += test_hash.o
>  obj-$(CONFIG_TEST_IDA) += test_ida.o
> -obj-$(CONFIG_KASAN_KUNIT_TEST) += test_kasan.o
> -CFLAGS_test_kasan.o += -fno-builtin
> -CFLAGS_test_kasan.o += $(call cc-disable-warning, vla)
> -obj-$(CONFIG_KASAN_MODULE_TEST) += test_kasan_module.o
> -CFLAGS_test_kasan_module.o += -fno-builtin
>  obj-$(CONFIG_TEST_UBSAN) += test_ubsan.o
>  CFLAGS_test_ubsan.o += $(call cc-disable-warning, vla)
>  UBSAN_SANITIZE_test_ubsan.o := y
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index 1f84df9c302e..d4837bff3b60 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -35,7 +35,15 @@ CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_hw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>
> +CFLAGS_KASAN_TEST := $(CFLAGS_KASAN) -fno-builtin $(call cc-disable-warning, vla)
> +
> +CFLAGS_kasan_test.o := $(CFLAGS_KASAN_TEST)
> +CFLAGS_kasan_test_module.o := $(CFLAGS_KASAN_TEST)
> +
>  obj-y := common.o report.o
>  obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
>  obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o tags.o report_tags.o
>  obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o tags.o report_tags.o
> +
> +obj-$(CONFIG_KASAN_KUNIT_TEST) += kasan_test.o
> +obj-$(CONFIG_KASAN_MODULE_TEST) += kasan_test_module.o
> diff --git a/lib/test_kasan.c b/mm/kasan/kasan_test.c
> similarity index 99%
> rename from lib/test_kasan.c
> rename to mm/kasan/kasan_test.c
> index 505f77ffad27..f25692def781 100644
> --- a/lib/test_kasan.c
> +++ b/mm/kasan/kasan_test.c
> @@ -25,7 +25,7 @@
>
>  #include <kunit/test.h>
>
> -#include "../mm/kasan/kasan.h"
> +#include "kasan.h"
>
>  #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
>
> diff --git a/lib/test_kasan_module.c b/mm/kasan/kasan_test_module.c
> similarity index 99%
> rename from lib/test_kasan_module.c
> rename to mm/kasan/kasan_test_module.c
> index b112cbc835e9..e4ca82dc2c16 100644
> --- a/lib/test_kasan_module.c
> +++ b/mm/kasan/kasan_test_module.c
> @@ -13,7 +13,7 @@
>  #include <linux/slab.h>
>  #include <linux/uaccess.h>
>
> -#include "../mm/kasan/kasan.h"
> +#include "kasan.h"
>
>  static noinline void __init copy_user_test(void)
>  {
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN2T%3Duufbrj3ghr7S6k5E%3DYxvNpkq2Qa8qCY9NfPeeRsg%40mail.gmail.com.
