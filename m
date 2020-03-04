Return-Path: <kasan-dev+bncBCMIZB7QWENRBEV773ZAKGQEAJBTBJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 091C8179068
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Mar 2020 13:31:16 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id d7sf872481qvq.12
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Mar 2020 04:31:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583325075; cv=pass;
        d=google.com; s=arc-20160816;
        b=E8qg74wfEqCKbP3NCiLsgLyDous6c+xuCD4P7YshDuKEfPoQ03ts0QbSehMrZrmP9+
         NSgEm9lQaH28tOQRbbmaTDoArxELdnsYhs7sbYnyoh8YdIXIMaM3zeUwozXb663QRWI0
         MUIQM7Qz1Hl9S4ZLN3TJqKpEsxZeUdyZJdMbb1WY7RvYrvHxIIz/xKw1GIEzvhQ2ElZX
         KC7FxXK3ouxowJ+SCI80sibkTurpQDxU98cVO6szV8P6HOqKgaRDAsmPLJ+Q0z98yXzj
         4D8+lr4p8n12J/w9TYJA9xfqfx9ISx8xxcOSKUf70oDu8BdiZWYZ0NbZ/ENYjAphKG7z
         6IWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wN09gQuBPMbeN+DYVaTWZNgcveTmqrBBJx1KZFc2sik=;
        b=n7xv6mdzWkOMdwQZTnXRpwlbme9sa6GCewbY1uk9EGOvUxkuTIPZsTA9h6kNNS+Eu+
         0aQb6PC8pZysyoRyZ0WeTeQ8y4HC/1LZO3h2fXD4kvBvf8uX+TxZl28nvPEGup/OIK3C
         gED1DV/0pJHM6svh3iOEdl2qCWQH+gBX4mcesqD8Prwckaxv0evLfXJo9vCf9B7hw8Y4
         GB5/jdBFr/NQArUOmQoKTQ7gGz+H48l2cd76Bfh+O93NnG8ynxy5BsjL+5lTpczJ3aa9
         p75sQGAuHD8rl7SdUNog2YRAkoA+5qN+U7+WvxLwzzSgDpQljoR2PvC7N5yLcS3xlTIB
         KbLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CaI+5g7T;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wN09gQuBPMbeN+DYVaTWZNgcveTmqrBBJx1KZFc2sik=;
        b=WJzTDfp7t8191AVIsRHVuQbR+YUMDah1vkiAHLnKhsQITrrQ8z8UZy4wYGVOdV5Y8a
         U9tAql6KamoTG09DV6lsGPScTYUJi5RYTx5eKLda/nFRLIoP2qGj/ZcI18Xe2H73+8K8
         JYsdLSzLOjdUwu8P/ynqYJtYGbtDBHp4OC1qXaF3DzU49DSIVTK/a//ZOcSdW/ymRnH6
         US3iw9vY09vXOXoRFwhSkISJREaO3y502sWY0G7NA/4matQnD7PWSzXljJ/yp3u2dj2s
         +NrJBpgHTs+h+JvMEgu5l8M/0tt1QlFX6zAu2HXKpVlncQcrEDpDDN19gTmlkDOg1/RY
         /R7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wN09gQuBPMbeN+DYVaTWZNgcveTmqrBBJx1KZFc2sik=;
        b=rPAiHitLPxIdX2KYTmAobGF3YsSvBAlRUe5KgbArrq7yCbL4Pl1Xurz86Re2jX8MbI
         OuIAhtlTghoTIJrvCmGeLaZMqJ3v+57nW/ASmVHlcrNQoMwTNX1rqrQOZW5Ihbbmou6Z
         Z9bCX0m4ljZf00LwqiJqxfEmgDp2dHv6mK21qropMJXqGMwv4kB/SmXbXAcJnuVNMDTz
         8JamxWAK7OB9aZFzEsXwB7CChj12uLNuE1w1YWoagGNv6fhwG6eLfc2CElxpSMV0uifu
         bDRXn0NreQOyeoIDoAqC4zZjyu6YfweWOAYhD9JmrI9e/IoaSRtPx4ArBRLlfmJA99OF
         rXkA==
X-Gm-Message-State: ANhLgQ0pIzzZSLRxLD4cDTvlrIS64QD438v4wbX3W8uNqpZbB9Pq575I
	tIcCvEpn7sTH5fLV50IpsdU=
X-Google-Smtp-Source: ADFU+vv7HuiPA2H6nftgM01A9KUIaMm1XPmMjknpPH3mJ3ZJQYIUBzlo0CmNvC4ooJ8PoDW7CbvcfQ==
X-Received: by 2002:ae9:e204:: with SMTP id c4mr2703395qkc.429.1583325074861;
        Wed, 04 Mar 2020 04:31:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f292:: with SMTP id k18ls423359qvl.3.gmail; Wed, 04 Mar
 2020 04:31:14 -0800 (PST)
X-Received: by 2002:a05:6214:b23:: with SMTP id w3mr1906487qvj.181.1583325074445;
        Wed, 04 Mar 2020 04:31:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583325074; cv=none;
        d=google.com; s=arc-20160816;
        b=0aNlYr+1uIY6hAogiDaxax43blOhkVJRlr2J0lqmoTjOAM3aOR9mafEP/tiJCGFvQH
         zNyZ13w1OtSlv4iwho2dm1t2AV4RVthJ9+72beMENy4k2sqaMC9jpDwsDEM1++6rPpls
         op+Ey+vi2tGHf+jy9HQEuSBalDAhH/qVBQqHqGj3YW1WYzPSr57/WVPAfpZIItbf++bD
         dfHzlWizc2S5W/LBCFwnfcpyp64H03zK//4RNNua6pcta61NHubIbC/M/BjDXFuLIcZG
         tgjXYyXYUEFilPpkuIe+sorYZ5lEeA5pXtTswaG0KZwzV9AgJz6FAKBiHbZJwK1/TL9w
         W5aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=w036UPOsYzhuoZMby32GGE9YAfvIHRaTf3JXEXh3ttk=;
        b=EI35xxExVumpFChR0Yic+ZOpVWKgRiN3nF4X6ClB26aOAv2YBZB9ZUKqMmHagXLlev
         gloZboP6A4xhmNhWit4tymFuvmX701VDSW6SZyxDlIbxt2tHsXHkGbHsJZYH+sQdANKw
         aT4Wbdfr7xjDiJxA3aivqjPBwx8aq+RORA6QDromrKVNAWsXNiRu94J0aEFDVbzeC2Y3
         VWm1wNCv5B9OAFNfGcn5Re1KV6GeJjlI7AbvziXauO1hG2UJa1gmfbv1N9Kkvx0QxFNW
         I4tiNTKCKDWBfKGlMHS2SitPcc2LRaIuI6so05n1SUftcf9tUAW7av1Hpv0doOvDY2d9
         gQAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CaI+5g7T;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id 23si112686qks.6.2020.03.04.04.31.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Mar 2020 04:31:14 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id eb12so668731qvb.10
        for <kasan-dev@googlegroups.com>; Wed, 04 Mar 2020 04:31:14 -0800 (PST)
X-Received: by 2002:ad4:58b3:: with SMTP id ea19mr1924665qvb.80.1583325073865;
 Wed, 04 Mar 2020 04:31:13 -0800 (PST)
MIME-Version: 1.0
References: <bug-206755-199747@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206755-199747@https.bugzilla.kernel.org/>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Mar 2020 13:31:02 +0100
Message-ID: <CACT4Y+YLfg7xixidfsY=TvxrHu+Y0fUdkhZB1=oU5YexEMXOxQ@mail.gmail.com>
Subject: Re: [Bug 206755] New: KASAN: some flags are gcc-isms, not understood
 by clang
To: bugzilla-daemon@bugzilla.kernel.org, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CaI+5g7T;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Mar 4, 2020 at 1:29 PM <bugzilla-daemon@bugzilla.kernel.org> wrote:
>
> https://bugzilla.kernel.org/show_bug.cgi?id=206755
>
>             Bug ID: 206755
>            Summary: KASAN: some flags are gcc-isms, not understood by
>                     clang
>            Product: Memory Management
>            Version: 2.5
>     Kernel Version: ALL
>           Hardware: All
>                 OS: Linux
>               Tree: Mainline
>             Status: NEW
>           Severity: enhancement
>           Priority: P1
>          Component: Sanitizers
>           Assignee: mm_sanitizers@kernel-bugs.kernel.org
>           Reporter: dvyukov@google.com
>                 CC: kasan-dev@googlegroups.com
>         Regression: No
>
> scripts/Makefile.kasan contains:
>
> CFLAGS_KASAN := $(call cc-option, -fsanitize=kernel-address \
>                 -fasan-shadow-offset=$(KASAN_SHADOW_OFFSET) \
>                 --param asan-stack=1 --param asan-globals=1 \
>                 --param
> asan-instrumentation-with-call-threshold=$(call_threshold))
>
> This --param is gcc-ism. Clang always had
> asan-instrumentation-with-call-threshold flag, but it needs to be passed with
> -mllvm or something. The same for stack instrumentation.
>
> There is an interesting story with -fasan-shadow-offset. Clang does not
> understand it as well, it has asan-mapping-offset instead. However the value
> hardcoded in clang just happens to be the right one (for now... and for
> x86_64).
>
> --
> You are receiving this mail because:
> You are on the CC list for the bug.

+clang-built-linux@

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYLfg7xixidfsY%3DTvxrHu%2BY0fUdkhZB1%3DoU5YexEMXOxQ%40mail.gmail.com.
