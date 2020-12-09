Return-Path: <kasan-dev+bncBDX4HWEMTEBRB65MYP7AKGQEWCCMZAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5794A2D438A
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Dec 2020 14:51:59 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id i11sf1120067qvo.11
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Dec 2020 05:51:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607521918; cv=pass;
        d=google.com; s=arc-20160816;
        b=fAXa02Ss4u7aBAC37+8PBGsZmnFL2CrVtbAL9c7YcrODvcfuhkivRK9qZ8Ily5QxUD
         jJnpRLptYLEQ8iJjQ03EekKJZomCJEtano2bLJPPDqn8+RvAoOhsFg9AceqCCg1mOuRU
         tUCfS640SYkINz1VM3j97wh1Jf0saulkKTEkm5P85hGdl05FPBdYBuYrBu5DdXDp6GZg
         GQYSSE/sMo2PiAVe9o2P2bjn/ixXKmuaJObnOamg+W1cFr8UIXpmU+Kc0pJqPuw5C2Vy
         1ZFFNT7Fahz5sj2WMpZV9UTxjoon0YJWZlHWtP3X6F9QWyt2EVV8jmakhlAUGnoyLX3H
         f+8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rujEGnMmNvEKnSVepA6+Hk1TgPwDZ1UNGi2Ke7nZ7rM=;
        b=nV9RV4ngPnEA9LW+oR1cvYs5M+YFkW9gSzMNHeUE21+/6Kms3tRxZ9BuhX4QqQsFw1
         am3S1pD8waKEzV8sCYpPiPXt6FBkzQUvuvhcW43J/27S8c+v7BR5lyn9F05ggJGzydZ8
         HdrDeZqVoIRmTafSpR8pcsOQSRu8bXtlDkbXulmYW8X6aBm9gRXhzL+R91XsMf2xV6d6
         +zS1OynOInHqxYdiV98OHbjuaa4UY7D+qnR/OE9GNTql8wMgEQLFYgnIsErOUYBDCnAG
         Q2x7jbaWhAUwvSfrCNfcep5mWiCECQCb54vQazkh3JpBYYCQepmfNyXwNKvVdS8fjHyy
         3ydA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=odoVmjOP;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rujEGnMmNvEKnSVepA6+Hk1TgPwDZ1UNGi2Ke7nZ7rM=;
        b=OZlH7HbAsV/981V1WhVaa2HLLD1DxpLvGMMeWWb6A8NEH74eWJSWEf+PyF3NYIQ40t
         LOpneIas6UXnmYVI7nJxuO6fbweCtMH7pofpgUUK0RYknFQhQz33KPBixDjqKTUhi9b7
         Bq1RNTkGuwJHQ+3Um1xxtkxR4AXnBFwvmmOyLQJKCn6PwTAzyEh6x7//lSV/Ev2Mxtin
         6nfjf6nwaZj7jfxUyfK19Ruw/Axte6RQ1gfkUzJgbNuldqSOVTfsi+8Dh0j3rHaDXwF5
         +oY79iAho3bYNcJ3qmigK3uAoxSP/x7hnmzlBkyDcWZaxRWDQ0QjMfemM78WlVmYu7lF
         BjJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rujEGnMmNvEKnSVepA6+Hk1TgPwDZ1UNGi2Ke7nZ7rM=;
        b=I5h2VWsQ7LzoS4bQSFYlboNAW6E/9NaooO/TFBHLRGmnXikA4JOnpx6X4RAW4l0cEn
         pfWv/E4NfYkqYLcLctYhAJdtyzoOzITY48M15I2R1IyiH3Ujpt57DbCChdf9VO76oSu6
         PDyPZ95nA6mIx98ULz+mKM7giJHVleabkKs+r4lC79DgD7RM0DsQAb2Kjx9p301DreJl
         NlbCpxrMdj0tfKXswQ2oN5eVE2WEOCdoE1QS+E59Dqi3x1nG+AAXmxl8NtxAK3Q87DFX
         4cvQb2AjiJsexsralS0Jo3gPccIHW1n5Z8PUwjQen6bEwJh7GSVZwcOGSKN5i5icgDb0
         Nu+g==
X-Gm-Message-State: AOAM5311qufZSdWGiktKB47nmg+/RQn2BmvNp/gHxOW6EMO7h3TLNm3e
	jGOMOy9qJd15pooOyJUscUs=
X-Google-Smtp-Source: ABdhPJwlVEQgg/xvZ1hYbXKbwm4rs6k2gzG+bs1ZkbwowFzRvelkiuaL+CdjDOWGlP1RvyZVoTD+Xg==
X-Received: by 2002:ac8:4545:: with SMTP id z5mr3109483qtn.28.1607521915895;
        Wed, 09 Dec 2020 05:51:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:498e:: with SMTP id t14ls361637qvx.0.gmail; Wed, 09 Dec
 2020 05:51:55 -0800 (PST)
X-Received: by 2002:ad4:5bcd:: with SMTP id t13mr3077794qvt.7.1607521915008;
        Wed, 09 Dec 2020 05:51:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607521915; cv=none;
        d=google.com; s=arc-20160816;
        b=waaH6PzM8c69eGjwu8zhGdJzGQM5EXQpZw4IymF4UwxTOgOxLkgdU2ZqFqdVBMsiSq
         pd0oCztFNmTIggvyH6v5YvRzhasB+Yji4YZwNqbdh0xcvWgMhrHR7B2GGzobRVAkqwfm
         aap8Rb58/UT4s+jB6jtMVck7k3I2JpsYEiZwPpWgB9s38icecpjVM7kvciltGl+trtV9
         CN2C5RoK9LAv3baFdkwqMPO3LpktgFvEdsiDcfPqsoRi342uv79yyj+QVdNMcV9F0gxX
         wwakHI6R+0veKT5Tzu3e0At6NoC+GrP/wpRGFPM2P29giesh/w/pXka1K9L3qnMWr0EE
         UPwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=w4MkXK3tdvL2KD1xeLvIGtLJ1l3YTvntIB2NHLxLGEE=;
        b=SJ3mtgdVtChKLO8IfFYTJYWqJfjRguQRj3s4jpYqwdTzSTTU/tKJQ3trkcHqpjnxuE
         EfVJP6yFZObNo+3Knmlnz6crZzavdIx4tcDPc9oGYo9ReH81Yu9AgYlg5GbkFMiFPeLD
         3ykj0PNOQGe5XhXC8Wr/9l1LvQbWrQTrdvVmm8hvEw19SRR6ZGWwOBbLEwsVEgbv3r0a
         fe8st4Ri7QcMn4Yzqhw4O/sjwxSodaiMqcU34sUc158yG5r6yi3HZMPuRmoejlH747Rw
         +Km10lgBCqwRO2Q6A5OqJQw0GDdaB/oX7+vnUOdAskm7pOkU9iUZ1WPkPstMQEeri/nG
         oPtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=odoVmjOP;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id w10si86400qka.6.2020.12.09.05.51.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Dec 2020 05:51:54 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id p21so745982pjv.0
        for <kasan-dev@googlegroups.com>; Wed, 09 Dec 2020 05:51:54 -0800 (PST)
X-Received: by 2002:a17:902:900c:b029:da:b7a3:d83a with SMTP id
 a12-20020a170902900cb02900dab7a3d83amr2010763plp.57.1607521913989; Wed, 09
 Dec 2020 05:51:53 -0800 (PST)
MIME-Version: 1.0
References: <20201209100152.2492072-1-dvyukov@google.com>
In-Reply-To: <20201209100152.2492072-1-dvyukov@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Dec 2020 14:51:43 +0100
Message-ID: <CAAeHK+z-cWhLGv4qV20_4Ddacw9wSJTsAWoodEJ_L0rohR5p9g@mail.gmail.com>
Subject: Re: [PATCH] kcov: don't instrument with UBSAN
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Stephen Rothwell <sfr@canb.auug.org.au>, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=odoVmjOP;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Dec 9, 2020 at 11:01 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> Both KCOV and UBSAN use compiler instrumentation. If UBSAN detects a bug
> in KCOV, it may cause infinite recursion via printk and other common
> functions. We already don't instrument KCOV with KASAN/KCSAN for this
> reason, don't instrument it with UBSAN as well.
>
> As a side effect this also resolves the following gcc warning:
>
> conflicting types for built-in function '__sanitizer_cov_trace_switch';
> expected 'void(long unsigned int,  void *)' [-Wbuiltin-declaration-mismatch]
>
> It's only reported when kcov.c is compiled with any of the sanitizers
> enabled. Size of the arguments is correct, it's just that gcc uses 'long'
> on 64-bit arches and 'long long' on 32-bit arches, while kernel type is
> always 'long long'.
>
> Reported-by: Stephen Rothwell <sfr@canb.auug.org.au>
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
> ---
>  kernel/Makefile | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/kernel/Makefile b/kernel/Makefile
> index aac15aeb9d69..efa42857532b 100644
> --- a/kernel/Makefile
> +++ b/kernel/Makefile
> @@ -34,8 +34,11 @@ KCOV_INSTRUMENT_extable.o := n
>  KCOV_INSTRUMENT_stacktrace.o := n
>  # Don't self-instrument.
>  KCOV_INSTRUMENT_kcov.o := n
> +# If sanitizers detect any issues in kcov, it may lead to recursion
> +# via printk, etc.
>  KASAN_SANITIZE_kcov.o := n
>  KCSAN_SANITIZE_kcov.o := n
> +UBSAN_SANITIZE_kcov.o := n
>  CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector
>
>  obj-y += sched/
> --
> 2.29.2.576.ga3fc446d84-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz-cWhLGv4qV20_4Ddacw9wSJTsAWoodEJ_L0rohR5p9g%40mail.gmail.com.
