Return-Path: <kasan-dev+bncBC6OLHHDVUOBBCP2QD5QKGQEXGNSUPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id E0F10269CD2
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 06:03:21 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id w7sf689616wrp.2
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 21:03:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600142601; cv=pass;
        d=google.com; s=arc-20160816;
        b=oTMQnEDuH0hkDfgb3yr7C2IQq6tlDx/FjQIAAl8iM8RQABgt4MsWogLEuSbQ/2u8n3
         3VpmQSky33mensShoCWLhbgYXB4BnQ6CC5i5doqkhbs6P9hjirltWeiCupGpBiBe1DqA
         VDkfenoSvVEaDWd0gA8pRcfV7YSUvjcWhybrZXc5Wmd83iw22W7j+yP6dpBIpA+YKxXQ
         DX0bIKr4qtli6yNV4K17WRFRaMOj3FVQTuVgWi9frTEpyDH7P2j7xMs4ZaGg9oydum1N
         BN45XWO/QN6Wi/YIL2AM6hl0HEA4fVPuzU1hBxFFYiu4yvi1mKmxcu8daIGoaEdgEd5I
         WL8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OdCUZgf5bZoabXWV1xEeyqq2k5DjpOgbkZxT1K09WGY=;
        b=Ce7cwFUyYpZBh7EoT5B7uwgkXltHC1y5/siPHGFJJAJC7wL51mhnKqPbHkuH6k8VYS
         QOOO8tyhU6fFa2qDzuZQq+W4QWpfZxrnnBZMkXFKRiY8XkG/H/+SlBxnxTzZvMfXnN7I
         Jc3NVwhP8fBqZOBRWlCGIxWaiV2e3+1ewsVG4kg562/7a2pBnQF/VnPnTblDoyAYmmFg
         4i+Ar0eSQP+/07td5cOU2Ep/V1M5/EvWxUG5VsDBbGxSByDIPYtYO08L85vBLkJrHV8V
         r4bvklR894HkRaiLB3VBuP1jIwf/EGV+loFgBY9BVzkfCYZyfketRofYyrJAWUXIGMpi
         FRjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hahHnwMl;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OdCUZgf5bZoabXWV1xEeyqq2k5DjpOgbkZxT1K09WGY=;
        b=DgDD8XkRbyYA18o9uKYuZFZksgTclUehsS6Z0MApDGhDYACmj8PR37iRVtsOaQMDxl
         rIRZhbYV2YlUyYmkRfKxNnNhOxecss30kEmcwt9eZ6mdmB95aYuVE6iW7m1rVFa0anCo
         mSwCOH06QAqKvjBhuv7hX9OY165WR0P7/qlTOhUrn3sCUbJaMB9mjUhaacMALZhW38a9
         wwZEI0iKh4rqOsbW3mv+IrX5/hTxWUZvTDcFaoRcVsjI9IxQg7MzRCAi9kEc3+i4X3VV
         1vaKBOs0lVACpAyT2ZKXpFrpfMRmYWVK3YJIh0uqasxy2LoOcLI6t1h/qaFl9uGVc07Q
         60nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OdCUZgf5bZoabXWV1xEeyqq2k5DjpOgbkZxT1K09WGY=;
        b=fm2gve19HLgQAxNQobm6QH7U0QBTAOiEO+Xl2GjFQg7i5iu6Rs8esrXbiElTS/450U
         ha2D+dYxmmGPIr0Mbt7ywnNP425anV++ZqHB4vrs7WDSDLG4qxU/gs7/uOCg43jZbQmZ
         lWmgVu0EvSVPQ3S5vBPO4u9UG1IxrZ5iZbBW+i9lE7E5q+CsolUDHKlJC89tK0y+07pZ
         wrG/WSvaLEEVYTmPBkjfTw/Oxt/ChYgW4q4r/N9Sf3sFSwsBGHd/amzVd1znXZ/PEveT
         sVwc1bnJEyeERSP8ycutu8YoaUOpzkBAjlar1YGQpytgkJC5nUq3PTOqFc4Wu9s0HhgU
         3mDw==
X-Gm-Message-State: AOAM533orMLuMJVkoNcAwbJK/Hmr6yn8NhglMbFA7LgC1Pge1GqeNtX+
	+5b5tCH1/+svuzsp4MExSlo=
X-Google-Smtp-Source: ABdhPJxZZPRpbrc7NDnjn2eSeflRX4GaI63HlFuDMYjCp/Aqt/fcYicv8P7Gf6O6fa26OXN8QI0oWQ==
X-Received: by 2002:a1c:7302:: with SMTP id d2mr2536034wmb.133.1600142601603;
        Mon, 14 Sep 2020 21:03:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:8:: with SMTP id h8ls1372849wrx.3.gmail; Mon, 14
 Sep 2020 21:03:20 -0700 (PDT)
X-Received: by 2002:adf:dd82:: with SMTP id x2mr20176351wrl.419.1600142600616;
        Mon, 14 Sep 2020 21:03:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600142600; cv=none;
        d=google.com; s=arc-20160816;
        b=E9ixZcZyN3yudivCRBKhrFAHmRSglLmg+rs4UkrCgnda5UMKhEQ9j3LeJEBZuVS6M2
         l3cgkoT0cIPq51GWlkXw6fkbtDYCwE55Zn+DNUH5VppV5+LkfOBEExZqtyz6Vaq615nG
         2FrwfYvFdeZrFePp/amaIrOEgEey0vRL5N0Aaqjo4u0VYpUAhhu/cJVS4j4kll2ebqlq
         w6sD8IQa3SNhvfbC1ep21kGUXtJJb6uIpiHGlJ7nP6bGBD1oY4qgPeHQn4CpPbR0NR4J
         xxV6RRmTRIy2zPjxLfciu1i+R62WCVowfAWDqRgqkMEGGlnV5F5jp8nI7u4fZQccMqla
         cpTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IdWyBJyS0oKhGVRiD+UrbYCxAhuM82RyBR7Rd+xcd8M=;
        b=s4LsrUm8RGLXxBBLuAXEthWm5VJn2/RFY8N2xqG5XAsQLnmLvPDRf6dv5DEY2ZbHib
         cmlNTR2COdgQCV9ETOkKnRT79nFtERM5zaVI5W0yKN21Exq8taZSCvcFMyZpW+aDvbtS
         XZpFqa+VieTH4En/KCiD/rhB5B4KCBvsRtC4Q+l4rsCM4Grk/boj0j7KwNOTugFJA8vw
         SpDD1+gUubQfj8PxonU4oXeRPIQI0d31EMNcfRfPpZImWXyGdUbRf5FxkEVGy4cEdzIy
         g84yB0W/pVzMnPR0Hr8IwzFY1h/xSwYF6yyGA8bKq8rWlDRVANzT+YtwaGXlWOdX9vdJ
         BMXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hahHnwMl;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id s69si319895wme.2.2020.09.14.21.03.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Sep 2020 21:03:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id z9so1983631wmk.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Sep 2020 21:03:20 -0700 (PDT)
X-Received: by 2002:a7b:c2aa:: with SMTP id c10mr2445837wmk.86.1600142600065;
 Mon, 14 Sep 2020 21:03:20 -0700 (PDT)
MIME-Version: 1.0
References: <20200914170055.45a02b55@canb.auug.org.au>
In-Reply-To: <20200914170055.45a02b55@canb.auug.org.au>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 15 Sep 2020 12:03:08 +0800
Message-ID: <CABVgOSko2FDCgEhCBD4Nm5ExEa9vLQrRiHMh+89nPYjqGjegFw@mail.gmail.com>
Subject: Re: linux-next: build warning after merge of the akpm-current tree
To: Stephen Rothwell <sfr@canb.auug.org.au>
Cc: Andrew Morton <akpm@linux-foundation.org>, Patricia Alfonso <trishalfonso@google.com>, 
	Linux Next Mailing List <linux-next@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hahHnwMl;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::342
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

[+kasan-dev, +kunit-dev]

On Mon, Sep 14, 2020 at 3:01 PM Stephen Rothwell <sfr@canb.auug.org.au> wrote:
>
> Hi all,
>
> After merging the akpm-current tree, today's linux-next build (x86_64
> allmodconfig) produced this warning:
>
> In file included from lib/test_kasan_module.c:16:
> lib/../mm/kasan/kasan.h:232:6: warning: conflicting types for built-in function '__asan_register_globals'; expected 'void(void *, long int)' [-Wbuiltin-declaration-mismatch]
>   232 | void __asan_register_globals(struct kasan_global *globals, size_t size);
>       |      ^~~~~~~~~~~~~~~~~~~~~~~
> lib/../mm/kasan/kasan.h:233:6: warning: conflicting types for built-in function '__asan_unregister_globals'; expected 'void(void *, long int)' [-Wbuiltin-declaration-mismatch]
>   233 | void __asan_unregister_globals(struct kasan_global *globals, size_t size);
>       |      ^~~~~~~~~~~~~~~~~~~~~~~~~
> lib/../mm/kasan/kasan.h:235:6: warning: conflicting types for built-in function '__asan_alloca_poison'; expected 'void(void *, long int)' [-Wbuiltin-declaration-mismatch]
>   235 | void __asan_alloca_poison(unsigned long addr, size_t size);
>       |      ^~~~~~~~~~~~~~~~~~~~
> lib/../mm/kasan/kasan.h:236:6: warning: conflicting types for built-in function '__asan_allocas_unpoison'; expected 'void(void *, long int)' [-Wbuiltin-declaration-mismatch]
>   236 | void __asan_allocas_unpoison(const void *stack_top, const void *stack_bottom);
>       |      ^~~~~~~~~~~~~~~~~~~~~~~
> lib/../mm/kasan/kasan.h:238:6: warning: conflicting types for built-in function '__asan_load1'; expected 'void(void *)' [-Wbuiltin-declaration-mismatch]
>   238 | void __asan_load1(unsigned long addr);
>       |      ^~~~~~~~~~~~
[...some more similar warnings truncated...]

Whoops -- these are an issue with the patch: the test_kasan_module.c
file should be built with -fno-builtin. I've out a new version of the
series which fixes this:
https://lore.kernel.org/linux-mm/20200915035828.570483-1-davidgow@google.com/T/#t

Basically, the fix is just:

diff --git a/lib/Makefile b/lib/Makefile
index 8c94cad26db7..d4af75136c54 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -69,6 +69,7 @@ obj-$(CONFIG_KASAN_KUNIT_TEST) += test_kasan.o
 CFLAGS_test_kasan.o += -fno-builtin
 CFLAGS_test_kasan.o += $(call cc-disable-warning, vla)
 obj-$(CONFIG_TEST_KASAN_MODULE) += test_kasan_module.o
+CFLAGS_test_kasan_module.o += -fno-builtin
 obj-$(CONFIG_TEST_UBSAN) += test_ubsan.o
 CFLAGS_test_ubsan.o += $(call cc-disable-warning, vla)
 UBSAN_SANITIZE_test_ubsan.o := y
-- 
2.28.0.618.gf4bc123cb7-goog


> drivers/mtd/nand/raw/gpmi-nand/gpmi-nand.c: In function 'common_nfc_set_geometry':
> drivers/mtd/nand/raw/gpmi-nand/gpmi-nand.c:514:3: warning: initialization discards 'const' qualifier from pointer target type [-Wdiscarded-qualifiers]
>   514 |   nanddev_get_ecc_requirements(&chip->base);
>       |   ^~~~~~~~~~~~~~~~~~~~~~~~~~~~
>

I was unable to reproduce this warning: it looks unrelated, so I'm
assuming it was attributed.

> Introduced by commit
>
>   77e7d1c8c356 ("KASAN: Port KASAN Tests to KUnit")
>
> --
> Cheers,
> Stephen Rothwell

Sorry for the mess,
-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSko2FDCgEhCBD4Nm5ExEa9vLQrRiHMh%2B89nPYjqGjegFw%40mail.gmail.com.
