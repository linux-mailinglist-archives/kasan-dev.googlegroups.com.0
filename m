Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBMLSOOAMGQEDEZFHHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F39A63AAD8
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 15:28:23 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id r23-20020a1f2b17000000b003b89463c349sf4655998vkr.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Nov 2022 06:28:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669645702; cv=pass;
        d=google.com; s=arc-20160816;
        b=HLK0XhC39jyYWOpbf2F6VVpUY3LZQwo+y2ANwXkuo07o6KgvRGmWYwYZvgokz8Uv6R
         F5QbXiBZJNxBj96OZf/+GMEra9xOeAjIxF8YW1qNYOZrXdsIzRkPSGAJWaxrBqsnjiIV
         LhCO3DrmkdDHnuoHW0/ceLmztnDjaXVWRR59zjstR7OXZ+Fzz5/wSngn4IYfWuUgbLpx
         3bMBlWojJcsV8L95W2SIj8OYodBRiVC9WsN0AySXUQksY7IiMACNbUJ10mvlXzG66u/0
         IijebwejodyADM1k4KpgBAhiWdcb+oFz5g+AqOVhaNvC1USVwZ75kyVvRO2O08kymq+h
         3How==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AIVrWvYzCP51qoWq6oEjZH6qzsiQ0XAv/CMcP7UTRB4=;
        b=xAPq+uoSeV4pRk29SbSmMqqTnkm6WQGPLVjWNPX7k3g7N6C0lPOnhBAFeb+rxfOlYC
         7JTTYz8j5KGy7eeZFKPo9tINqcK51s6JR/JqVxj7jYa+flDVzxXrXmXBAzSilRGhbJnO
         FCYPCClkufFbdHrNtmYJ/2KDfX5yD6aax4M3YoA96/aiJp5AbMgIkCC1hQyj1qvSmUhP
         mY6OiBQOjoGVBqgdd8KCOYrZg00YGq3yGhGOS+JuvjztjZ0GMJ7S2JGZEGJj0nHcOr3C
         DpKfLS6/szgDcMYdfJjDVnj5L41Crr/ClHQ8qBV8ZhpYayTs7TUGkNSv+FID19tSL1KN
         zY9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fkFQ1Pqr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AIVrWvYzCP51qoWq6oEjZH6qzsiQ0XAv/CMcP7UTRB4=;
        b=JtBpUlQ4hvCczIQBbV0s7hpImn7aUeuqRig00jfOmKTAPbtD54EhoN/NxUJvyqYEt1
         4AVDo2dEkGYBTFL9GFW4DxJL3jPdLnNnd5jdBT/ufcmLJuzDHuxCI/5npiM0Nrfe5Fo5
         xuHRL5LnnoAm2Sox+KrprRg4hZQEmnuRyMmm+uAVxqA2qZSW0JBD3GpQe09FnVGpqp3L
         /ruo1z9EgZBnBsYGQwND1YE1x16CIlblLkDm2aiFzYjrYAuSU/Dgj2sIM4qmoHVVsgc6
         RGR9qukhaTNrY4rxewkpHWG+wAjQBFxsPLWjleP26ZdSj2FY9HEKxgJm80u3qUi8ZuZh
         U3yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=AIVrWvYzCP51qoWq6oEjZH6qzsiQ0XAv/CMcP7UTRB4=;
        b=y7KVNMGq9CtR3szInJNSsxwUH8Km+49aGTdQtoAmlX9bvuwib1967AwzszrcoJ3vRM
         Sio86Hc/gkg7h2ky2y3aNDkQKRB6yq4hnC+CqeZO8TXcTxc8wNEB+DpIHMbGOpsslDLk
         92QsdT4w4hOzjBvdh5ikBqxvvbYAD0aZ3mmUZn2UXdMvjbnbJwKWinbUyhfuARrtElkz
         2+UmV2vyur9pGabX56r6AqiBjv7oyGD9kXiEciKqliqN08kwfmuihWWEp+zE5d06KRLe
         MM+Z+FLntZeNvYb45/YQJH3jJLJ5UlRBLXY/KstxMmRECrN8C/MNoeer7lD3M/+ZjEKP
         72tw==
X-Gm-Message-State: ANoB5pkNIQjxDzwzC5Sp7YdPcLZBRrHoAFa9/PMz963O5gY5HlGXlW0b
	xrDIaauoP8hhupGDN6tSN6E=
X-Google-Smtp-Source: AA0mqf5Wp56kq5yhwmN9KpS43TdsijHaF7M0ZKJn+5oMIRcFY0Hi0YrDFtx1yImsoxDb8oJc+IZEPg==
X-Received: by 2002:a05:6102:c48:b0:3b0:9f5f:e25 with SMTP id y8-20020a0561020c4800b003b09f5f0e25mr2768330vss.74.1669645701917;
        Mon, 28 Nov 2022 06:28:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c987:0:b0:3ad:a50b:4f96 with SMTP id y7-20020a67c987000000b003ada50b4f96ls2269335vsk.7.-pod-prod-gmail;
 Mon, 28 Nov 2022 06:28:21 -0800 (PST)
X-Received: by 2002:a67:c792:0:b0:3aa:9c4:a9a9 with SMTP id t18-20020a67c792000000b003aa09c4a9a9mr17721490vsk.75.1669645701205;
        Mon, 28 Nov 2022 06:28:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669645701; cv=none;
        d=google.com; s=arc-20160816;
        b=L6ExgP09jmMFmwfPAhFEaIhhTWd0jQFrc4CmfkZT4zII4gN7X1A7ybg49dkdRQc8ts
         YrMTTDBSmymHMIxAutrwzYSE/UlND2I1MTyUJewnytOdWB5fMSLPNON6Xs2yOokjvZAo
         9ycMs/55XgschBbYIW76YN/XtWguclkuTEDtiuxvWtMfICGRQ0f2QE/ssThkZqFwAvFv
         TPuPP0VgWSfRittw/hKTZoITX2Ypx027F8Al3SUSqJgKLGW8WlX5sLxB7snW6RfFVjh+
         CQOWe3xWo3HpYU+E303WoZJRVRhLXeIfr9TZtHVWvrQdQXl+nwzAu89AuTAsqO8bOSuc
         KVXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Cl7V40RlzSUp5Y9iM+8a/KVinWUxUFpdf5Vw6vhUvR0=;
        b=SjVsQGnauZH6bbeh3KlYr8FUT6si1BIp9JeI5rRc9jVAgDACknCv/Bap1NHjovjrfW
         C2j7C1SlMHz8y1QnmVrlZOrb8OwAcJ2hvPrzkbt3Rs+/c38RiftZ/wW87t4gT46Biwhg
         zZWB45D75rRetHdChGvysgg25FdfbaPvy2kFB6Ci4vH3gvTLwZX2woHx96/0xK/6qWtc
         msMeJcepEX2oLI8p4hAgk0yRfbkQJTWQAbnr9lhecGlOIyBHHwjnydSqGUzAHsWEcuE0
         UxuYW0M2PVnsItmjLn+sAINau7C6fod8IO+UYglLrBekhsn47eZavlZEQohs5jcbuC73
         JNhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fkFQ1Pqr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id az5-20020a056130038500b00414ee53149csi829111uab.1.2022.11.28.06.28.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Nov 2022 06:28:21 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id 189so12843024ybe.8
        for <kasan-dev@googlegroups.com>; Mon, 28 Nov 2022 06:28:21 -0800 (PST)
X-Received: by 2002:a25:3851:0:b0:6f0:6175:2cc7 with SMTP id
 f78-20020a253851000000b006f061752cc7mr23810478yba.93.1669645700811; Mon, 28
 Nov 2022 06:28:20 -0800 (PST)
MIME-Version: 1.0
References: <20221128104358.2660634-1-anders.roxell@linaro.org>
In-Reply-To: <20221128104358.2660634-1-anders.roxell@linaro.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Nov 2022 15:27:44 +0100
Message-ID: <CANpmjNP8-jDPXJVy68zhkspEac8vutfpTAc1nytnyExSpsT-jA@mail.gmail.com>
Subject: Re: [PATCH 1/2] kernel: kcsan: kcsan_test: build without structleak plugin
To: Anders Roxell <anders.roxell@linaro.org>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	akpm@linux-foundation.org, keescook@chromium.org, davidgow@google.com, 
	Jason@zx2c4.com, Arnd Bergmann <arnd@arndb.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fkFQ1Pqr;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b32 as
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

On Mon, 28 Nov 2022 at 11:44, Anders Roxell <anders.roxell@linaro.org> wrote:
>
> Building kcsan_test with strucleak plugin enabled makes the stack frame
> size to grow.
>
> kernel/kcsan/kcsan_test.c:704:1: error: the frame size of 3296 bytes is larger than 2048 bytes [-Werror=frame-larger-than=]
>
> Turn off the structleak plugin checks for kcsan_test.
>
> Suggested-by: Arnd Bergmann <arnd@arndb.de>
> Signed-off-by: Anders Roxell <anders.roxell@linaro.org>

Acked-by: Marco Elver <elver@google.com>

> ---
>  kernel/kcsan/Makefile | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
> index 4f35d1bced6a..8cf70f068d92 100644
> --- a/kernel/kcsan/Makefile
> +++ b/kernel/kcsan/Makefile
> @@ -17,4 +17,5 @@ KCSAN_INSTRUMENT_BARRIERS_selftest.o := y
>  obj-$(CONFIG_KCSAN_SELFTEST) += selftest.o
>
>  CFLAGS_kcsan_test.o := $(CFLAGS_KCSAN) -g -fno-omit-frame-pointer
> +CFLAGS_kcsan_test.o += $(DISABLE_STRUCTLEAK_PLUGIN)
>  obj-$(CONFIG_KCSAN_KUNIT_TEST) += kcsan_test.o
> --
> 2.35.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP8-jDPXJVy68zhkspEac8vutfpTAc1nytnyExSpsT-jA%40mail.gmail.com.
