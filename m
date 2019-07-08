Return-Path: <kasan-dev+bncBCC4R4GWXQHBBKOLR3UQKGQESUFI5LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6693762A46
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jul 2019 22:20:58 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id v4sf17383144qkj.10
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jul 2019 13:20:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562617257; cv=pass;
        d=google.com; s=arc-20160816;
        b=hGiiVn1gf3+pN8pPah6IIHY0VAftsQa/y8c4XC6gmjKO+aSB/zmOKL2QWWwxgqiZLa
         45xC8GW2jfwKa8tD8GkyKvt/aA3zbk0uDWdWMjBtpupXeb14pI3lNTTrNBz2l0vLhoKd
         bHN5gTyNSy29ETb7h63XahVIhgKzD/CIMFiXACzLcsjLMENuzg9CP/BQyC5f3wuOIgx1
         RjHiNXcyJ4DxYFfb74AKouVPDPvaGDp58p0s1KmSWqal1u3ALUpWxfXY6c2e9yCkeaj3
         48mNz+ZZ0S79dX5ODvTF2VTJolcT1OASPi9mGXQd89LXkhgY5fN+b5aPSH+OXF21Lc/u
         JR+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:mime-version:user-agent
         :references:message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6spe120QELZrRq6fOU3MlKTj6W8J4sNrBMKBObuY3PQ=;
        b=lY7S06lLLSmIBWt/tAoeHAgv14m56yRI9vVXPVPOJWuJ/fp+gzPZb9XVtMFjZIaJvJ
         m5k4LYVZ/6W0sEVlPehmZU1KxgjlqYuHO9nwlqOVJGNRgdGt0wwJPwsPayh1bbAo6BAT
         oOaI96/2R3YCVb/5wEfrDuPqPF2YkNos4TtdAU7TiKw52YwltXL9Fmh58mRL+BEvNCzF
         oLGDFm2mj7eyIrtnCwRGSdf2iOo49IXF2E9XE2mMvAJXTNf9/rC6M3nbZFZmNkZexdIz
         D0ktZftvTQdkaFCsZB8DqQcK3BmaTM4x0ud7uPsnFn1sbL8gwUMBJu5jAootpUMFsoqF
         LKvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@amazonses.com header.s=6gbrjpgwjskckoa6a5zn6fwqkn67xbtw header.b=WRtxMatR;
       spf=pass (google.com: domain of 0100016bd33f19f3-46ea67c2-d930-4e22-9934-41d6b25d5bd5-000000@amazonses.com designates 54.240.9.31 as permitted sender) smtp.mailfrom=0100016bd33f19f3-46ea67c2-d930-4e22-9934-41d6b25d5bd5-000000@amazonses.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:feedback-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6spe120QELZrRq6fOU3MlKTj6W8J4sNrBMKBObuY3PQ=;
        b=Us1Sl986Ubf18v7BJg6j1lBRdwPnwdrjdtR5VB0gCKZiP5y7eVOmgTGDcpT5yOK8TK
         wvzHU+8j31sTAbctRj6K39fYtiPqrWPMVdZgwDa8q1rVfofObZWm45EB9Xr8z/uVbwzw
         CRatga0Rg0WYo8Vfj250VbkHZgjc1j2+W3OkDv2n6o+haRS0H5MnScYxfUhdeq3G/M9b
         PjQiQXfdrk5baeW7+59JFfAg3Yg7q06EM69nsPUWHVCWN7+gUeMGerMd++RU3PUc1pMp
         VU0dDAMN+idDu8uboERJ/jzNuL4szJFoHt/wZbiiNGet8xko4oJnMa7q8krjSo7Oao+f
         BMRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:feedback-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6spe120QELZrRq6fOU3MlKTj6W8J4sNrBMKBObuY3PQ=;
        b=gPDzvi4s6txSIxMV7cIc4n1Wr6Nvfp2V0dv/4+ymlDyvtaQ8PzDgexUdJTPZpry9uM
         tAYRH2eHX0UP7/abU91RbBxvi/MtdtX9JJLmOwh1YsIXDtR5d/YYm3bAFu93SFUX+Z6h
         toGENsxKsUKUpWgSgZVMMaR93CfI5zx1gDYclwayNWbHvVclxJyvcnUQjjf7cMoC2+M5
         LwvrjQSEuyf2PsQGVZwyK5pxtOx3PbwHNeUWooqkO3Yeo2Z+9UOmrByfXiu7TX4ByuDU
         H7vWTxiOWOy/TZ2SbTuxLDez4Dh2AOq86YyUvzfrnsnBz3Si5DrcFb27Zlw2QQuHoJy/
         tYeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXLAJbe83og3Nc/DHEQuh35gYMNMrlWi38gYTvZIxLiJu1UtikS
	SSo14IJMP3CMCVJ1Lvn9HP4=
X-Google-Smtp-Source: APXvYqzb6LPc2bgUU6fbMK7YMG7Fx+WOhcYhZLUG53prembejxUaE5bX774wTg9mts6DZkniG4CkCw==
X-Received: by 2002:ac8:2c8c:: with SMTP id 12mr15756276qtw.137.1562617257467;
        Mon, 08 Jul 2019 13:20:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4d83:: with SMTP id a125ls3216367qkb.9.gmail; Mon, 08
 Jul 2019 13:20:57 -0700 (PDT)
X-Received: by 2002:a05:620a:1017:: with SMTP id z23mr16173426qkj.60.1562617257238;
        Mon, 08 Jul 2019 13:20:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562617257; cv=none;
        d=google.com; s=arc-20160816;
        b=fQUSXAZuBvPqechie2UycDR5VsSdS70J1wk/uxgeLH4/CcSf08m37b6vETFkbnRmht
         lfyGty6QJ8XXqx8xVuC9m0QGq1eVAwCidqRtyieR+Q+Ri2BPbVDNx6qVbJ0yIDVP1q2M
         nSkBUfbiNle4jk2BtMFmuMrC+SABkNzPiQQquHHO4UD/YP+w0m7rPSq8ImsVm1N1qcvl
         PVKwK4F+xQuN/nh+0WxDlKn3N2QA6k/4B2P9RSWUlT14nzWzZSxvgACEHfhqqsOAMcht
         3nOHnAY13y8858A5G/OqZWdw9fEJz2rP/47FOacnY+3sYRWTwEKruh16PV8WnNik4uNi
         59KA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:mime-version:user-agent:references:message-id
         :in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=uPawzHgSXshI+XHGB6J1ayR3ywnOsHKWmwACBnodim8=;
        b=kzSZBavFczZRAVlV3NiQilQqlqMFIi1XYhIOGBoOEywpfHX+F4zcx4Hj+i9hhCfnby
         OD2XK/Rf2XeNNuUhxZCxKjefALEPPW15bfe6IshJvVLEWM0tlf0rdcsKJHab+5xjVepn
         /J1InZk1V9keKlbuybDab+eGpTd1EEKBJ+pXalgRGQQISvECX1Vd6GCXNDXmE2SXCm3Q
         ixqNZ85icnIW4t/zR5YfcQSIKLeqswZsEPbIXHxzurJ/24bzeYjy2Mrv0578U4T8OCtP
         /B9GIYLPwo/vwXJLu/8Zdwr0bQoaWh8HpNoiDrXGvjmKTHHvrUhB1W02gOInqnGg7GtL
         Y+Bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@amazonses.com header.s=6gbrjpgwjskckoa6a5zn6fwqkn67xbtw header.b=WRtxMatR;
       spf=pass (google.com: domain of 0100016bd33f19f3-46ea67c2-d930-4e22-9934-41d6b25d5bd5-000000@amazonses.com designates 54.240.9.31 as permitted sender) smtp.mailfrom=0100016bd33f19f3-46ea67c2-d930-4e22-9934-41d6b25d5bd5-000000@amazonses.com
Received: from a9-31.smtp-out.amazonses.com (a9-31.smtp-out.amazonses.com. [54.240.9.31])
        by gmr-mx.google.com with ESMTPS id r4si1057656qkb.1.2019.07.08.13.20.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-SHA bits=128/128);
        Mon, 08 Jul 2019 13:20:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 0100016bd33f19f3-46ea67c2-d930-4e22-9934-41d6b25d5bd5-000000@amazonses.com designates 54.240.9.31 as permitted sender) client-ip=54.240.9.31;
Date: Mon, 8 Jul 2019 20:20:56 +0000
From: Christopher Lameter <cl@linux.com>
X-X-Sender: cl@nuc-kabylake
To: Marco Elver <elver@google.com>
cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
    Dmitry Vyukov <dvyukov@google.com>, 
    Alexander Potapenko <glider@google.com>, 
    Andrey Konovalov <andreyknvl@google.com>, 
    Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
    Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
    Andrew Morton <akpm@linux-foundation.org>, 
    Mark Rutland <mark.rutland@arm.com>, kasan-dev@googlegroups.com, 
    linux-mm@kvack.org
Subject: Re: [PATCH v5 4/5] mm/slab: Refactor common ksize KASAN logic into
 slab_common.c
In-Reply-To: <20190708170706.174189-5-elver@google.com>
Message-ID: <0100016bd33f19f3-46ea67c2-d930-4e22-9934-41d6b25d5bd5-000000@email.amazonses.com>
References: <20190708170706.174189-1-elver@google.com> <20190708170706.174189-5-elver@google.com>
User-Agent: Alpine 2.21 (DEB 202 2017-01-01)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-SES-Outgoing: 2019.07.08-54.240.9.31
Feedback-ID: 1.us-east-1.fQZZZ0Xtj2+TD7V5apTT/NrT6QKuPgzCT/IC7XYgDKI=:AmazonSES
X-Original-Sender: cl@linux.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@amazonses.com header.s=6gbrjpgwjskckoa6a5zn6fwqkn67xbtw
 header.b=WRtxMatR;       spf=pass (google.com: domain of 0100016bd33f19f3-46ea67c2-d930-4e22-9934-41d6b25d5bd5-000000@amazonses.com
 designates 54.240.9.31 as permitted sender) smtp.mailfrom=0100016bd33f19f3-46ea67c2-d930-4e22-9934-41d6b25d5bd5-000000@amazonses.com
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

On Mon, 8 Jul 2019, Marco Elver wrote:

> This refactors common code of ksize() between the various allocators
> into slab_common.c: __ksize() is the allocator-specific implementation
> without instrumentation, whereas ksize() includes the required KASAN
> logic.

Acked-by: Christoph Lameter <cl@linux.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0100016bd33f19f3-46ea67c2-d930-4e22-9934-41d6b25d5bd5-000000%40email.amazonses.com.
For more options, visit https://groups.google.com/d/optout.
