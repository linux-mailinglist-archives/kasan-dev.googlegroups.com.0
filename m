Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYHQS3YQKGQECV33GHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 82F59142D77
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 15:25:36 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id c16sf6253051lfm.10
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 06:25:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579530336; cv=pass;
        d=google.com; s=arc-20160816;
        b=AQbdgIiCDoyDT0SB2uc00tS9rYqrFEZmhEBZjlu3DxBjEy2uY2Gq/Qc9TxzDRlp7mB
         G5tk8q0rHyuooF1XtWT+9qxbsfNNfvQ+DocVvueYxXSrEtwbsGAcxbvqp8R/n/foYE4j
         QDCbrcQyJcmmYtVH+mZzQGGGrSFgJ+x1lyTsEvkD0G7PzyUryOOahMadEvpxeU76Vfm/
         CbVURK08lHr9CGTcNRWxhYCnVR5GaHDTkS2OX3MdZqLN9tlQ1UC9M8LYa5oc5s9+Hl/h
         Y4kgpqFeAjxVfYt1N9jJfuJRWnR8A1txj5GHIQ/ZsevCeo0uw55JwFWj1wYMhdcThkUC
         x8Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=udLmNRg3HWHSsQ9GmPumHrgS8W9PDMg22jnC3pSZTm8=;
        b=PNoNVnO6RQ+udRyRaGQpBk1VgUKGIG6azEI+yWqLLPIpcKPKKHMJ083cKxba6nCQe1
         whslV4OcZsGmDM7+supAj+Mnj+kL950gBLGeYNQLy5e18Ft1v2qTpJE583iNAbyN5NaP
         jIJi1ADuc8aO+4HOE+KUFVwZMddMFrhAnqvRAVo6JcYCvaWzGxLLa/MYPKuEudw1fVG+
         df6h773qGWU9Km+osad1Zc5OL4QXYVoSGufrkONAkDkFPBdb98Zu3C5tHSGqeB3pJmey
         HS82X/gGGVhr8H3sq7VylrsHFTBxjzhoiULbkPTAkflZrmcxSpl+Z6aEg+uiwE3i8VLU
         uQxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WIaInGW1;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=udLmNRg3HWHSsQ9GmPumHrgS8W9PDMg22jnC3pSZTm8=;
        b=CXmqbHs1nd/4WceRrbrluw7xl1yC8dsEv7RprgrJ5mkaHT3oLh7J0LT1xJJEznumCa
         JjlmWblY3S6acqEx2uXceztPoWQr5wFTNHzG/6NMvH1PZ6JGQWK1PlvIOjczkIeiPIpd
         B5rD5M9YVzTDJhzMBJVVCgdZYWvIf18UJM//xjEDocMO42oM+dDcmQwaduKzOV62+ZT3
         RIST8zDduphhow4ikO3nqQWPeE22079bi2JVggTeEiaWfrpCrWL6DqHuatA+7AD8zqIO
         Ib0yDfQYL1KuFmh3Ba/IcgLPpggprOlt5RCavhi3FI496/oePUvOPTUtkfyQhZ0i7eMT
         J6xQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=udLmNRg3HWHSsQ9GmPumHrgS8W9PDMg22jnC3pSZTm8=;
        b=I47OVtHrMspn+H69Tp/sBrD6Kd5rTlyRqxa57NKSqXjkNCJldC+4V5vwJzqzFuMowO
         TzvjT1RNdK6okhCqRMMaAhfpqpen2E19wMeCl6hG4jG7qsXKgbVBSiD7mDx2M9J/n7qc
         8JPS2EclW60UdMDB+AUjhrqEWWUAHQ8k+ed8noqoEGvKSUo7S0aXiV5gTqhashf2zaGo
         8aglAMKUhoV7b0vID8kjtoyBaZHEG4nVhzPvoIiiOvmLXlsaXKooqy6hHiznOsAAV4SV
         +5sy+Rtme90lF88jLM6Ip71bgMXB5r2rZssRvzR0iHR7FKfUcIPi6/y9M4p116OtjR6u
         R1Ug==
X-Gm-Message-State: APjAAAWAacxTJZ3uzlfceTeoM4ckLh9/rXXgh5pswe638ijRUWxBxPGM
	oc3S97WT81yIX12dP4cC0Mg=
X-Google-Smtp-Source: APXvYqwtPJjx1oCJnrSaodMDcodDz4+B7DjD50B1ah0slZLnsdsGzf5a97Ch39er1QYdf3FcRviR0A==
X-Received: by 2002:a2e:809a:: with SMTP id i26mr13926861ljg.108.1579530336091;
        Mon, 20 Jan 2020 06:25:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9709:: with SMTP id r9ls4361518lji.14.gmail; Mon, 20 Jan
 2020 06:25:35 -0800 (PST)
X-Received: by 2002:a2e:721a:: with SMTP id n26mr13896024ljc.128.1579530335513;
        Mon, 20 Jan 2020 06:25:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579530335; cv=none;
        d=google.com; s=arc-20160816;
        b=BeS6hQ6MqqeoTHZgFbQK1XZXSsi5qoA9HYwEGC6XY1UwmN/9ygWE4c0ft3qfBhSqOi
         smY0gDnHCo+ixe9OkIuke0yQeBZCsUsz2fJ1ycwAVozRWBsXTT9HOHmh9tWoVpmW5mw/
         pKhntbdFGvhGTb4niKDIP1E97ATWK0QG3qJ51r3UxooPmgZs4tLzVImQjVeQ8fHK3iCx
         kUFaFetSGSY1Wy4JBZoi65DjX0Eb5tSIbuoTvjl5FB+lC265GerAcJkKFMVojoxnmgjy
         LcschOip1jk2sA1phEfIMQefiRSDtuPm+dP7Wuw0Dma9BI4ONZxBmbdG6efdc2RXWrzT
         ewww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=a/e5dg21LEzYYUw3GLX+eh4t5Ki915Hi9I2m5nwm1oQ=;
        b=KnpU9f1aRabafpB45wMFTcsu0z0aqOaf8aDVlZkXgo0tbjwvdYSUM8WBPZqqYyW7ke
         GqFzWqd0fgsNgcBFUnlDewvutoAdOcvTisWtq+mtJISE2Zo3j6Bfq0I97c5nHYcJjVAD
         +FjGS5PB9qCYSQmYAu8cphnKDWs2mBfHpnNzB7U+3sg+4tQzJN41xiGB1DiZ+iM6qKH2
         lFpgaOrZCHTxq3OjSk6ebigZBm3XiXsBK3PTMuN4zwLPW5ZbzyIZHFxXzeYwbmPtZ/V6
         Lvx91d9aRt6QisZzYHVJNj8DfIw6ZvQHzOXm8DItV/RymSIhfIatK4EoK25DbvRMZDbr
         N1Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WIaInGW1;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id b29si28341lfo.2.2020.01.20.06.25.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 06:25:35 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id j42so29731783wrj.12
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 06:25:35 -0800 (PST)
X-Received: by 2002:adf:e6cb:: with SMTP id y11mr19036917wrm.345.1579530334844;
 Mon, 20 Jan 2020 06:25:34 -0800 (PST)
MIME-Version: 1.0
References: <20200120141927.114373-1-elver@google.com>
In-Reply-To: <20200120141927.114373-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jan 2020 15:25:23 +0100
Message-ID: <CAG_fn=VyL3t0L-ZhRtc41+fcipmSWrhwb+QFkRZ+ZeZQ=X_dLg@mail.gmail.com>
Subject: Re: [PATCH 1/5] include/linux: Add instrumented.h infrastructure
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Dmitriy Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Mark Rutland <mark.rutland@arm.com>, will@kernel.org, 
	Peter Zijlstra <peterz@infradead.org>, boqun.feng@gmail.com, Arnd Bergmann <arnd@arndb.de>, 
	Al Viro <viro@zeniv.linux.org.uk>, christophe.leroy@c-s.fr, 
	Daniel Axtens <dja@axtens.net>, mpe@ellerman.id.au, Steven Rostedt <rostedt@goodmis.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Ingo Molnar <mingo@kernel.org>, christian.brauner@ubuntu.com, 
	daniel@iogearbox.net, cyphar@cyphar.com, Kees Cook <keescook@chromium.org>, 
	linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WIaInGW1;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::444 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Mon, Jan 20, 2020 at 3:19 PM Marco Elver <elver@google.com> wrote:
>
> This adds instrumented.h, which provides generic wrappers for memory
> access instrumentation that the compiler cannot emit for various
> sanitizers. Currently this unifies KASAN and KCSAN instrumentation. In
> future this will also include KMSAN instrumentation.
>
> Note that, copy_{to,from}_user require special instrumentation,
> providing hooks before and after the access, since we may need to know
> the actual bytes accessed (currently this is relevant for KCSAN, and is
> also relevant in future for KMSAN).
>
> Suggested-by: Arnd Bergmann <arnd@arndb.de>
> Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVyL3t0L-ZhRtc41%2BfcipmSWrhwb%2BQFkRZ%2BZeZQ%3DX_dLg%40mail.gmail.com.
