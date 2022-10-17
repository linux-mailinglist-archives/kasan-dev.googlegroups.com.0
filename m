Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRWGWONAMGQEXQI2U3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B81960061D
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Oct 2022 07:08:24 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id e4-20020ab01684000000b003e36660d2cbsf4451565uaf.16
        for <lists+kasan-dev@lfdr.de>; Sun, 16 Oct 2022 22:08:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665983303; cv=pass;
        d=google.com; s=arc-20160816;
        b=HGu2PuMjXdBBqVJegjgyw5O8jC6nYZfkULXPwHOlrcIyROdNSVs6LIwRHQ6t99zLxe
         I0Ov5T/a3ekpAbft4F8/iYXe37fZlxOfiiQ/IOzbTNe2aR+cf5+w+eHImna2KjTBwBB7
         ykp+qblM6YboNABK3jfyiE1w4pn1KpOoXnICMqNsq/Ksn4AZvfO+il1OZGyiifGBtfGW
         0t5AuIAfmyQuoftlh+fLovggb5jxWo2MDC+eHKofXNgBpR8KWm8q1cXDeExftdwCviIc
         sytT/Yz5vvj3fH5UejwZQM4061nPT7Les1l236dJz+CypU7tBLrfU1HaXsyx2AthWdBZ
         tzkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Oya4QrOxzyYgj2JWVj0kox7lEnA3gypuEqPP85nuphU=;
        b=DeVk3RbIVXDUIuOGyenNX2m6lYwcEPCbDx9jj6zFlhUpEvRg2txFBKSfBUrxCKX857
         FYGznxU+Ocq1gaee7/UzLz8AlEl5O8/ewcMq9aKrsx+9g5fMSUiJgByr1KkykegXLQI8
         /k3ISyQZDhQ2uye37tAUOzE3bp+e8qzfkDoHuOX9JGs4aDqMHbMBvtz9a6b/bmOJe2wn
         504ZSHg2zIM50TDNjbqpVV83oXMXEfgI23YSaA1GwU3jHr1LIO8PTpU9YqF2i8Or8dYP
         n2/SaoVfPr9lPN1DpFeQHLioG5y2Y2Pvm7BbooSxkMRvZgTm9SUYiaWv4Akw8dzzRZFe
         9cCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oVZBgyJ+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Oya4QrOxzyYgj2JWVj0kox7lEnA3gypuEqPP85nuphU=;
        b=hodH1qPqLLRYmphT4M1UTtOwtGJEuMXPoyL95RrO0HlyVfzeKcpqh5ux4tb/YAoZsP
         pvXUNR+Op3OuWwdfZz33li2sweYh9Dq5WyyioVZO5peIOWEt7ZMhtiy9fwkpwVp1U5Mg
         VmVVDbwcwsW2Q9m1w6K74Y14e2M31/eKaan+zIeCe4R/p0+VhcV7qrnhNEQ4wqwZjDAw
         1e2tC5BM99T3/qJGV41x4nOsuPzABUvOTon/nG1aiXBa/CQX+y1MKtdhO2RAF8Tx8I9p
         q50v6TbPGlQXFsPi2bucnLLVLNi3EcOR0K48A1czyrVbNkmliL78wGGX58i5mjOhGavp
         MKPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Oya4QrOxzyYgj2JWVj0kox7lEnA3gypuEqPP85nuphU=;
        b=070q/laj7ZQ20/3QY9q5gy6ZnCdQfs9lC81PsSTiIYNDsRIETvSH3hFSReo0ldB/nb
         YY8M41pBJqfiJxreeu9mFZFuCsULAaIwR+duG1rOSeRn7ByUhq0TflzfaZClcOkpRdzp
         IJJuZtmu6Sqiw0oduYGH/u5ERLA6bqHWtxqCjJ7pUoJKD8YK2ltQYmFBTPK3PL+0F1gx
         P2rNujPtmww6acMgaqF2VuDBZTcdHwBRR4+6TF7LZXCTkgUIW0Dg4Dg2wyvzvwizKvLK
         /nF/lEUw55f+eMssNWsDn7YpruxMigu6aR43sRCb6eC7jUiD9WjXVcTmx4yv4dn3sba5
         76zg==
X-Gm-Message-State: ACrzQf22l3RZj8EtO/GTARlLfe75jGBxH19xMlAKpOT9IThTkPyCgqkd
	NvKzfKgHuHRdNxj59g3NgIY=
X-Google-Smtp-Source: AMsMyM7yXxhChxBLDAy+x3Cu86OjmuzoyIpjSuGWkvLA/Azb1rmd6ANW7aOKgAlomoRK4FuSVj0SuQ==
X-Received: by 2002:a05:6102:1c6:b0:3a9:6160:c467 with SMTP id s6-20020a05610201c600b003a96160c467mr2417080vsq.49.1665983302746;
        Sun, 16 Oct 2022 22:08:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c596:0:b0:3a6:d5f3:1d15 with SMTP id h22-20020a67c596000000b003a6d5f31d15ls2083148vsk.5.-pod-prod-gmail;
 Sun, 16 Oct 2022 22:08:22 -0700 (PDT)
X-Received: by 2002:a67:fe41:0:b0:3a7:c1e4:a6b9 with SMTP id m1-20020a67fe41000000b003a7c1e4a6b9mr3235086vsr.60.1665983302071;
        Sun, 16 Oct 2022 22:08:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665983302; cv=none;
        d=google.com; s=arc-20160816;
        b=I2pnmqitMbMlObVK2TVtsKYapcMvTCIxY0r/to9BauN0Q30Hpw7yEcY6wac84fh3iw
         XwxXOZ0RoodJDYUpBT3aAX3dbUl5D8dI17cQbgFWuO41C2+RtOFS6+BZDJO97B7TWpyx
         D9GB4xcsfw5S8jcstb1mCSQfZnJigHIrMZVL3Dn2l+F4/Zpi1gxOZP0771gnd3MQtf0C
         G79XeV3lJIfbYJK16l7moO92g4+ujc79xtaa3zzwlasYMJGrdvJHkKLiTMjs+1uUh2m+
         jWA/UQK8Yemk62Vwd+DBy43Skq6/HX0oncgZsyS471MSs1Yt7e9xU8nQRNfkbBiM780z
         KPMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4lxf09phcZd+RbWiYGHV8D3u6UgUuk1peMBn11MBenQ=;
        b=WBQAEXQ89TBA8W0rK9kCr/qVWPEIesEqjgK5NzUVD2M93i7Bo4oPKuGItahaDD11tm
         jqQzZh/B5e7CEMCWjWtlwH0IjQUOOVXeb4FU2OwHCF0FNYRDRrygZBJ+9F6kb0B0f9IJ
         1qbyvGHAsoSl8VV7ti3vJghOJAvZyeToSw5b2KOrGgnCyZKbNn4q0p6XPmUB8ye0bNZ7
         6lEYkZP8WXlBF7zvDNjfHqugfIc3A4GM+G9Uq3lpN40SdB93cIWbFZt5+JCAmu6I7ekS
         vZGNuDYSrB1hpncX/TkH+pazCpIb5WKuoXujqMR29Eb9ptMBT4T/L4wDiSjV/tl4ujh2
         a7aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oVZBgyJ+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2d.google.com (mail-yb1-xb2d.google.com. [2607:f8b0:4864:20::b2d])
        by gmr-mx.google.com with ESMTPS id u7-20020ab03c47000000b003dc811b4d2asi787403uaw.0.2022.10.16.22.08.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 16 Oct 2022 22:08:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) client-ip=2607:f8b0:4864:20::b2d;
Received: by mail-yb1-xb2d.google.com with SMTP id e62so12011989yba.6
        for <kasan-dev@googlegroups.com>; Sun, 16 Oct 2022 22:08:22 -0700 (PDT)
X-Received: by 2002:a25:3f06:0:b0:6bf:8d1:191d with SMTP id
 m6-20020a253f06000000b006bf08d1191dmr7867634yba.16.1665983301659; Sun, 16 Oct
 2022 22:08:21 -0700 (PDT)
MIME-Version: 1.0
References: <20221017044345.15496-1-Jason@zx2c4.com>
In-Reply-To: <20221017044345.15496-1-Jason@zx2c4.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 16 Oct 2022 22:07:45 -0700
Message-ID: <CANpmjNM7Sca3YJQ7RK14e_pzB5Wq3_-VokLum6MpqKXq7ixzSQ@mail.gmail.com>
Subject: Re: [PATCH] kcsan: remove rng selftest
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=oVZBgyJ+;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2d as
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

On Sun, 16 Oct 2022 at 21:43, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
>
> The first test of the kcsan selftest appears to test if get_random_u32()
> returns two zeros in a row, and requires that it doesn't. This seems
> like a bogus critera. Remove it.
>
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>

Acked-by: Marco Elver <elver@google.com>

Looks pretty redundant at this point (I think some early version had
it because somehow I managed to run the test too early and wanted to
avoid that accidentally happening again).

> ---
>  kernel/kcsan/selftest.c | 8 --------
>  1 file changed, 8 deletions(-)
>
> diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
> index 00cdf8fa5693..1740ce389e7f 100644
> --- a/kernel/kcsan/selftest.c
> +++ b/kernel/kcsan/selftest.c
> @@ -22,13 +22,6 @@
>
>  #define ITERS_PER_TEST 2000
>
> -/* Test requirements. */
> -static bool __init test_requires(void)
> -{
> -       /* random should be initialized for the below tests */
> -       return get_random_u32() + get_random_u32() != 0;
> -}
> -
>  /*
>   * Test watchpoint encode and decode: check that encoding some access's info,
>   * and then subsequent decode preserves the access's info.
> @@ -259,7 +252,6 @@ static int __init kcsan_selftest(void)
>                         pr_err("selftest: " #do_test " failed");               \
>         } while (0)
>
> -       RUN_TEST(test_requires);
>         RUN_TEST(test_encode_decode);
>         RUN_TEST(test_matching_access);
>         RUN_TEST(test_barrier);
> --
> 2.37.3
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM7Sca3YJQ7RK14e_pzB5Wq3_-VokLum6MpqKXq7ixzSQ%40mail.gmail.com.
