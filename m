Return-Path: <kasan-dev+bncBCCMH5WKTMGRBG52Q2HAMGQE4PTPWCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AFA747BCCE
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 10:23:41 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id w197-20020acac6ce000000b002c6b577ca82sf55047oif.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 01:23:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640078619; cv=pass;
        d=google.com; s=arc-20160816;
        b=jWwRbN5qarLyUTAsc4elZWMPQnbKTvbkHnjU4hGwi+pnLjbGMNYZjce4JDKDjubh0A
         Qj1JEoIcozOom3D1JVdTqfJ5tYTnk0KBfHTwPomrEQIj6gYaNOofJCg0j4ntH9GgB6I2
         9ynG11pi0Wxkal6QWp1Onk82NLvGEq2yR83hA5tbKMU1Zif0eQ3kdDtJowYXOEu5O2oc
         TJkEoedvYBB/4LPPAE0zZgBYgAa9iP6RtUnVF9RKa6I6wUI9n8u2jbz2CMAA2xkJZi7C
         sWvhTSb4YbB5OjGrsWSex3uw+KpKDGF+9aHcalZyoqH3S7wan/8kDw5e8iU7aS9+ijYo
         W5Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aN7tB6FDcIOrwJJPw0p529+uqhDn4XNZ7ULG/Gj6+XE=;
        b=y7wffWCjY4G8fNca2wHzhDygP40wIbn3IRpjyS83IqIcjHToVY3CU0zuzDNXJlsfth
         yc8w+sPJct6dGrC9lKYOLERj63b+4+XVEg23KwPXzD/H5s7lrdL8iYQwQ4kgqBpeChGc
         6BjtKSK9m9OOqFwBHPPFzZvreKO0v1OHiYMnAZGDqoPsr/zgNneuc5rcc/JPTayR0ix4
         k/kC8kV02BVfYr4wjCKt9rv3nIE8IfDTi9JnpwBDZ2sI/lSBpvIgz+PUJRRas6D7hccj
         9eiFSVRiaa7sLbcloHGv3Xt1X3tZXPbfiXnAHYRfOIkUJTUTqETP7GRZ9nXtUr++VjB4
         L+Aw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VyLPgc+N;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aN7tB6FDcIOrwJJPw0p529+uqhDn4XNZ7ULG/Gj6+XE=;
        b=GZKghwl0C1rVys0hUmzMk4oB2BEgEaXVFMG7vkQ/HA4ngWB8XZlwni3PR5a4hHnsUv
         dCIkvtEtMEWNqB46Je0VA0X914t1jF9DJmMPwnReeG7vx/xn5h6lBz1kZD6BljEFuYr7
         2CvT3vRmoUmp/XcRbHM8jYOyfD2I1OoODFJHR0gfdtAZ99Ai2Lj7tSSRZP/LY4TBkUPB
         wlD3ycMTvhGLDfJeXAdObrUGa0gVH4pv3p2oaJ7htlqnSj0ujnPrXZj9Vxb+HrtoIVYj
         dy8gcTDen5P/2DU3l0dekvAB+yzXXpWPtNmZYYBS2yJkNYDixK2HERWeGrWyL24Io5DY
         sd9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aN7tB6FDcIOrwJJPw0p529+uqhDn4XNZ7ULG/Gj6+XE=;
        b=C6hS8+OaE7udDunKtttsbMrzr1D9KF534MS951wFAkPw/w6r7w6HdatgjNW1M317Ws
         ShLUFiO2rCm+HFilfsmlPFqvoOMzt6hstVm6gYcWLZacqpV4TLJdsyQKYKFAsCd9m2pR
         N/8+PYxtt0A+DF0E7RJgzgWv9CCEsezrZJSBX4Sy9n4xPnYhzMPm117aqEtEGP17TBm2
         h1LX9WaEX+A+Iaiq97qGlzoxzqB1pifG90qwdjaRGsdTB9ZVDGH9GjsIQYlkFH0latPm
         cJ5RdPZ4ydBu982dKaMAlbRg7FIAq2ICnKYyX3LfTDPUNwvQHNZKvoDT3Fpk63jSH3mq
         av9g==
X-Gm-Message-State: AOAM533Dhez4UcMMasN3H+P2jWp1hlhx48N5FbV7AhrQ7Yw8QhpankGu
	TCl+/BlCTcfQIT3pco8ukYA=
X-Google-Smtp-Source: ABdhPJzbrDr0/fAQHPGWocoJVwKhfh313Y2vUHPxXxD00bAgt2JsrPXEsngQy/Ugi7/vY/6wDPAeIA==
X-Received: by 2002:a05:6830:3499:: with SMTP id c25mr1593948otu.206.1640078619625;
        Tue, 21 Dec 2021 01:23:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2466:: with SMTP id x38ls4310519otr.10.gmail; Tue,
 21 Dec 2021 01:23:39 -0800 (PST)
X-Received: by 2002:a9d:34c:: with SMTP id 70mr959809otv.231.1640078619268;
        Tue, 21 Dec 2021 01:23:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640078619; cv=none;
        d=google.com; s=arc-20160816;
        b=PlvMT2TptXVbqvY+f7fybcYWDmGK1gZxPufpSSvg3FNLq1DXBXL20tr5kqwAmrCfsh
         jOxsuPv7jQS6IwbROJPY1GY3/obiOaPGnvIZ1mYlrPbUL9ev30hygY92kb8HU5GyT+cG
         JHA0cXUFonUHy2+HPJQ/Ivx3Ulc6IZaotd6ZlJ9+x5m1ztvGkwko3X4sfC/dnwRLrsD+
         Sg5g5BDWF1vzyGZkyShtZ77xcHReLFn1afgtTYa55uaK4sXYLkppMCcMv7N0ONIscVhG
         zgN7ruXPGUowE1y8lhPTj+1c8X6DdCFlY3wcM/rug3Uyfow0o2tCzZq//5hCZiARFJRZ
         4OzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Xzwisqb1Sy2od8aWgP/bz4IaYgTJ8bQBQSdhNAj9vNM=;
        b=nVqD35kQ1YeXwogWfwIKmNFP4dchHdcOjvo6lE2pkUlpbMhJBg8lK97L/kIhl8lyQN
         INhF9uogRShloNyzAc6PEmDdRip9AjMClbxgGHxq6k30q144E7ye4W9tL6BVajf5a/vy
         T9JBiEK9VSvisdjvvHxnN1InP/Z2vWbhkJxW03McyshjuFpxymgF+lQcNr5Y5yf3MIrJ
         o/si9GpgpMv7IeizplX0DWNN8TKtu//3k5II8GvI7Q+gxA2jQF/pGTsOYUGGtmHVFsjA
         qDPB2HqZf5cpeO+5SsIs2/p5vHPbeepsmzP0A64k2eiS1ebHLo8/sOcrnU5Ot1CFIuhP
         HJ2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VyLPgc+N;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x733.google.com (mail-qk1-x733.google.com. [2607:f8b0:4864:20::733])
        by gmr-mx.google.com with ESMTPS id s16si1584094oiw.4.2021.12.21.01.23.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 01:23:39 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::733 as permitted sender) client-ip=2607:f8b0:4864:20::733;
Received: by mail-qk1-x733.google.com with SMTP id t6so11970864qkg.1
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 01:23:39 -0800 (PST)
X-Received: by 2002:a05:620a:2848:: with SMTP id h8mr1353598qkp.610.1640078618621;
 Tue, 21 Dec 2021 01:23:38 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640036051.git.andreyknvl@google.com> <b929882627e19a4a2d02c13788bd2d343f3e5573.1640036051.git.andreyknvl@google.com>
In-Reply-To: <b929882627e19a4a2d02c13788bd2d343f3e5573.1640036051.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Dec 2021 10:23:02 +0100
Message-ID: <CAG_fn=W_6j08zxpgWeCX_uxN+Jqi93XYtQ_GY-Gjs_Ru2Hb2aQ@mail.gmail.com>
Subject: Re: [PATCH mm v4 16/39] kasan: define KASAN_VMALLOC_INVALID for SW_TAGS
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=VyLPgc+N;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::733 as
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

On Mon, Dec 20, 2021 at 11:00 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> In preparation for adding vmalloc support to SW_TAGS KASAN,
> provide a KASAN_VMALLOC_INVALID definition for it.
>
> HW_TAGS KASAN won't be using this value, as it falls back onto
> page_alloc for poisoning freed vmalloc() memory.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DW_6j08zxpgWeCX_uxN%2BJqi93XYtQ_GY-Gjs_Ru2Hb2aQ%40mail.gmail.com.
