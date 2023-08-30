Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLHGXOTQMGQEHFBNQ2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 617E678D3B1
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 09:43:42 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1bf24089e4esf68374025ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 00:43:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693381421; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qp1kuwUcCDgPXEA9gQi0ae7T2wN4LuFHhiyXslRU7Nxpy2fWU6trsOlZbJ6sbWbTNd
         jnN+aIlKoYrhWiLF1PNr4lbA+LLTHLpnUcgg6kr+A7SPs7XstOSOqg5YZu6as8jrauMN
         hH5fOrP9X9T4azUXgYyXwczq3u/S1hC1DOTfL0VWYYQjSPTnlgrKt9UMZrvCXQDk9s+w
         Re5OPtjfEvbQU7+SL2tZCzUUyjrIpHCwvsH4n+41yLWxd6Sa0pcRpKSq71UaE6077a90
         /RWGP70HtHj7H7WvZxWcZhoGTCzD3jTg3ryTrY0Svjz//mBZhLYFDokLuGvk5YOkJk+1
         TWLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FzPKoaG1k/yQyqO8wL+N8Uh1mCWpEywVwscbyOHmIoA=;
        fh=2tgrBxnVwcLXHayTK7pIfhTdPsNvlLazimpmxCZaT7I=;
        b=qJgS2gCz25xEfrxRXu+EwqiDai47tuQG1x2vRBnXbfJDLABGBGszW7NJ9FpKfm8S4J
         nooLvTnfq2DDR7VlbZmXMBPqUn2Cm3HsKTUmKJ4rll5ek9nMtUXdc9AVXxEABuaNZPkH
         nAzP7+xZnPUgp+nSZEbAN+FgQchB5ypK7OHavVlunV8oqcq42lj7Wi0QGgHYGrr5O5M6
         6BpuhsQa4ESB9kGIjEOJl/kkB99z/J8WysDAbFtW+MIm8QERQyNRCNwHqXjvmRG03lTo
         7bLgMvg6KGzoVAAGko5ONzzfnOIZWWuO7drmUcSLWz5e8K3Lb7uGGLcdQm/56t8G2aua
         rVnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=1Una8lVg;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693381421; x=1693986221; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FzPKoaG1k/yQyqO8wL+N8Uh1mCWpEywVwscbyOHmIoA=;
        b=D4MFXJbNQ1EFbszMqMJwy5TieEIG4aGuUcK8bu2QHA5a0bF8KaFwaT+y1WignT2uch
         1dk4rZmf12NC1c3FsJZRXxRbVgYjRXtN3SwtqEwk1BUPHAmyOJnrZQrf2XEno8tLxpZA
         MW5vhxzcY2PJs2spjqvObRheIkES9VD6dpclEv45MvWokGf2/Jwljw0s7Y1M38FoREke
         FqJEbjOOcET730Mk4a59TcC0ToAlDZtJb08FdP0bc+bPVonw68Tm9bg/ElkPykv5flAJ
         yhK/zdPeQbwXXZIdnXf0Eo4u1UAOxeCwCO6it/5j7R74nUVd1q23XO1wlqVu2/kCw1uU
         UuGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693381421; x=1693986221;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FzPKoaG1k/yQyqO8wL+N8Uh1mCWpEywVwscbyOHmIoA=;
        b=U2EwMsgsyaaIexyQksGjqzsH0TaK22C1qdX1DBrdceeJ0cI1Gzka5NylCfh5BLyc1w
         eMNnEnRPbjPl4VRgR5DBaHZOdXBUDfO5CWA0lPGQ+dV5tEaEHMxv4coUcjdYSNoG0eJI
         /ZPpgliRndOwixYAVxHfFzK9mII8bkfUD1KOEeHA0st/y3B6KBp9XTKPhUu9CXzuH2T3
         BOK0TM/Si80K0bYRZD2gNA3iX34ARL2sEgXMB5ax5DsQOxmKbpbOZMgJKHhzYh/sd86W
         9jzIC1sGLeMP24bQVubLApnRTjfEdikMWp+1CaEgQS7fy2xD1XaC7Lx2+EWcL2RY50cU
         BdbA==
X-Gm-Message-State: AOJu0YydlTgJ3YHkX//fGLR4yW2P1AVB1FusY5deoco1W1YoQ0ga2ijL
	nThWPuioHLApMINimD66IvM=
X-Google-Smtp-Source: AGHT+IGxbxNGFUTAf0KhWX3k2ImN2zVrtFPeUCxqCTEpwnfx3DNoM/TeqRNzaYRays8JAp/fUhEYfw==
X-Received: by 2002:a17:902:ee82:b0:1b0:f8:9b2d with SMTP id a2-20020a170902ee8200b001b000f89b2dmr1370291pld.29.1693381420459;
        Wed, 30 Aug 2023 00:43:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a3cd:b0:1bf:60f8:e298 with SMTP id
 q13-20020a170902a3cd00b001bf60f8e298ls3682741plb.1.-pod-prod-06-us; Wed, 30
 Aug 2023 00:43:39 -0700 (PDT)
X-Received: by 2002:a17:902:6b4a:b0:1c0:b8fd:9c6 with SMTP id g10-20020a1709026b4a00b001c0b8fd09c6mr1234198plt.42.1693381419384;
        Wed, 30 Aug 2023 00:43:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693381419; cv=none;
        d=google.com; s=arc-20160816;
        b=tXoOUimgn0CEHBcKk5lcyrpiaG70tPZTt0ZJm27tyLIwKJVWQAUeEinfYWUd8VjZyS
         JdGYD70UY9DvMEqyhqMPZS3Z1seDbmZNOm2E4wB+smqfq4h6OHHzk/PBdiRuDoVfF9E+
         UZoT94BPhqwBbpGeTm/Vx7NIqEOMtvA8LIn1gPsHw0SuucC+JYvTpAeZFcbAZkmGLtWj
         UkkpHVgLp/KwKsrK2hxf09byMLgtTlQKV7dqWzQCrwxtDGFqDPLWql6Ou5CvIfMfMwOU
         nGIGDSv6djpxE0bHWIPzDpUFsVuZwlmpgQ+ZO848Hcu2k+3rSX9KVQtjlbQgPnDvZDU9
         LXPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=kGGarPsIuAKKUhNUS4INN8GZ8o0SRnTpA7kSJCMs1/s=;
        fh=2tgrBxnVwcLXHayTK7pIfhTdPsNvlLazimpmxCZaT7I=;
        b=EyNK+/TnyPlG50J1naKv7LvGtSWwvQM3lS3Jmu/qkcLsAp90dp7XCn2ZWdlerG1MDB
         MXW3zfnS41t2BiSgtMUFNarck9G6EZ7oGbkR/uBDTsmNNhQJFRf5RRyh/x/+Ugx32kcE
         Zl7+9t8/m0UmrxM+ywZXMFpZxk5ns5X/1gs86NxpJVqjolbSEJOQI89RPOWBR322abwo
         o87oL8c6LkarIhm4SvaiUoYhA8KkicZWWL2Uxb2xrcdxvmGmCU0lzIWMUASrHRvYR5kJ
         CRArQeMWh8PnSuXhaYAfIjewC3lAqfa0hDQuYG8d/5XhxMMWGCHrBR0izGqVl48WQPyO
         eDrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=1Una8lVg;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd36.google.com (mail-io1-xd36.google.com. [2607:f8b0:4864:20::d36])
        by gmr-mx.google.com with ESMTPS id g4-20020a170902868400b001b8918da8d5si818775plo.10.2023.08.30.00.43.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Aug 2023 00:43:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d36 as permitted sender) client-ip=2607:f8b0:4864:20::d36;
Received: by mail-io1-xd36.google.com with SMTP id ca18e2360f4ac-794d98181f0so96206539f.2
        for <kasan-dev@googlegroups.com>; Wed, 30 Aug 2023 00:43:39 -0700 (PDT)
X-Received: by 2002:a6b:6112:0:b0:790:f733:2f9e with SMTP id
 v18-20020a6b6112000000b00790f7332f9emr1585375iob.13.1693381418668; Wed, 30
 Aug 2023 00:43:38 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <eade4ff3e44769fc172e782a829853127c644737.1693328501.git.andreyknvl@google.com>
In-Reply-To: <eade4ff3e44769fc172e782a829853127c644737.1693328501.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Aug 2023 09:43:02 +0200
Message-ID: <CAG_fn=XjBhiYadLE8=tqHJpcqSsdh+e-=+wHK8=8WddHZxORtw@mail.gmail.com>
Subject: Re: [PATCH 03/15] stackdepot: drop valid bit from handles
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=1Una8lVg;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d36 as
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

On Tue, Aug 29, 2023 at 7:11=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Stack depot doesn't use the valid bit in handles in any way, so drop it.

Good catch!

> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXjBhiYadLE8%3DtqHJpcqSsdh%2Be-%3D%2BwHK8%3D8WddHZxORtw%4=
0mail.gmail.com.
