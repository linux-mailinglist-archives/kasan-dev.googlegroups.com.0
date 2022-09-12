Return-Path: <kasan-dev+bncBCT4XGV33UIBBVVC72MAMGQEC7UJFKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id B755C5B6202
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Sep 2022 22:06:47 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-10e88633e1csf4002338fac.21
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Sep 2022 13:06:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663013206; cv=pass;
        d=google.com; s=arc-20160816;
        b=QiaXe72oK1hm7mlrDH5AzrVyAaSsCc4OOSNp9mmJrYeAePsuyx6PWCUd/9Q1myBbZt
         iE9KzZPapU/KsCAW/m1rWoXpSojOVF3drnkqq+r4+w3HMWEExiDHokIkkF8LRXoObWHh
         sQVuUNaOmVpeDDiJwsDQqeA6a03qgW8xOIMN/lZBgjvXpMg9dRsxSswnCynlKq70/KYH
         +oox03pRD0w4P6CGSOSjsZHilDqi2Z60K/4OL4nPZCOPNEXl/S8pTeVeAof8mObE8Pk8
         PWPQ9pF4VcCuAlvageIWtnH8rjDx1EA92CgqFaTt1wY+TmVzkelAtItmWhGi/us2qG3O
         mocw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Mq6eCf0BV8YfHAmhJV2FEFVVa/kiC0rgqUKn3bHmSog=;
        b=ScyZJaa2cuRtwRb/+4WRaV/Ktwo0IErrjhZnn8Md+rDShxAqzTWpSl1Vp28QdQZEHc
         uMAvvGD7lB0dMtj/r5m/xBosOD4JKABf9WQOoEKBF94+kWhVIpWESG36b9G0+SvAA+Uu
         gjF1QF1eJGzC6t7fTefvCJRStffc951/HgOdWIfqPK4lnuYE7g8mjSQUZdV9CpfKMmbu
         9W3eqzHbywV/P1nDwVcMtxevSzyFlCnYMmZTERmxa20y4T7VDDvMjcPc19JxH7fYkthn
         t/LJi84LxoVbOEA08MfILpm/HRhrsNaCLrFUVPtUw/QyhftoQu+Uflx2o4xtr81osffU
         g9+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=qd9upT6G;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date;
        bh=Mq6eCf0BV8YfHAmhJV2FEFVVa/kiC0rgqUKn3bHmSog=;
        b=NF/GbXr3kgBlM9ZIc1n7xg/IsltYtNjGhkgfxfyYMU0k6VgOlEe/yYT6zRsIbO6VXB
         iQcmnOAmGA/Vla3yBBHOA3IPsYGGnMUqTcHkRTczOBEMl48GxxAXIIFMuWRgLuvt8uCP
         Lrt7RE3lthMXO33fXJGd3yRFW5qVwMTFls/k8dyAx2wMsOgK2Llhtazz1ittDBu/ocx5
         8amdwlTIhOgaCTrSLD8sXMiRXFffyyzZ4UqK6pljlESScrNcVVl5NwBb62v3Y7VCWald
         JAfnwfsmY9m7i3sjIa9auEcUtO+lth/ZZWm8l+CXI6DQLq3x0a531m5Vgjq6eE58186e
         CAzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=Mq6eCf0BV8YfHAmhJV2FEFVVa/kiC0rgqUKn3bHmSog=;
        b=gv523AM3wDkPgLdHjL1syGz7sY+5f9W1xPgIe3L9KHJBiMANm6PGBojI7IL07Ex3y2
         RpskiBPFdXfMuMEWteC3/Q8eJRflXnFPj0B6WthWKVKhuQJbU0vCpXomG4u79aGuzSsD
         TvPUER4cer6/mP/QxbO+JtU+1XpPkzwJfPw70Vfo4jTPuyoOwrHFsIChTW0YbUDy9DVK
         T60HYFkz29AMsNuqA4Gd1qjmOM7taQDLrF+YBOrotC1HX4HoRd8HP4GZGE4/sTFlLbKQ
         /k1Kalf3J9a/8+dlHswNUmHVc0qLJFXFQ75VLXnvEZCGxJnKnVtuQFX77XoNslAag9rr
         eXsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3CYiNsdAJiEde/xbR25znc4W+vFI9fzLBlyzYi/ymeFb9lpBWV
	mFKLnVqyELDhsPV8/TxUP4U=
X-Google-Smtp-Source: AA6agR5khnuDy9Sxl25+tXsgSt7sHEijuZqOTTF9pMyLQFp/yEUmkIV2hhZFhAqoZzW5X7j3aSqRxg==
X-Received: by 2002:a05:6870:f14f:b0:127:a6cd:16ee with SMTP id l15-20020a056870f14f00b00127a6cd16eemr46049oac.8.1663013206253;
        Mon, 12 Sep 2022 13:06:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3402:b0:11e:4261:68e3 with SMTP id
 g2-20020a056870340200b0011e426168e3ls4579116oah.6.-pod-prod-gmail; Mon, 12
 Sep 2022 13:06:45 -0700 (PDT)
X-Received: by 2002:a05:6870:708a:b0:11f:74d:2dec with SMTP id v10-20020a056870708a00b0011f074d2decmr40710oae.132.1663013205692;
        Mon, 12 Sep 2022 13:06:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663013205; cv=none;
        d=google.com; s=arc-20160816;
        b=WTGI7pDWkqf+PiWl38SvEQ4zI6KXL6Sy3EyoZiKmy0yQ9fwWqYKDX+rzZSTRph/XXC
         dfRXq/79+JaOUCpYqNZPnP355ZQXs+OifkEK7ywrlMnBWAuJwWLgww5wQtwGOlBZiTdQ
         pAc9VR6w9ScZIWdgQ1ePewNBGtChu9hV/P8ikISd0etl3x3gC5RMxcztK+wA25bGG/6u
         /nq8Ll1cvPmS53PKfGKSd5OH/xT1UPuUPNClm+WBO8Iab4BjOz/k1cul6/CHH1bcS71z
         lbRkVtCfCo2Q1nyzkWW81dkg7R7BSzJiAOGvCFR2WR3xMXWMkWJFmbOb8/cFSZAcbL8q
         52og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=eKDMXdb5XhjvQbwhBfmzz7v9Zu5VAefu7dUAvyO0jNU=;
        b=MoZcZjN1BfsqY5ZvrM/erAXz6zdlT3NoE7lpsMf4qgAdMhTEcAqTXO8lBhL3d02jsS
         ecCasj1OWlhsSlgWiBGAMT/xaRNN7Y5pSSrj7P6jHrTQ4CnoJZxrHF2Zn/hlus6CN3kZ
         KGEa3uVAZDVsqRCk2MIRTRa9ALVRz6PFGKGWG7GsaiKC2wAgjI+DYU+Ttk7e5EVi0Khe
         A3SIxVijkyhvTUihsETod2RGxSr7vdMVAKFh8dnPWNRai/0htZ/lIpkgh/tByArbl82B
         LxFsf3GX7eNxOtwEY7EtJRVaJD7Tuj4u2kXmLpBaZJ7OPnynHPJdF3s3aspKCvdgiamT
         1Idw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=qd9upT6G;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id r20-20020a056830237400b0061c81be91e8si378843oth.4.2022.09.12.13.06.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 12 Sep 2022 13:06:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 43E296126E;
	Mon, 12 Sep 2022 20:06:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3FFECC433D6;
	Mon, 12 Sep 2022 20:06:44 +0000 (UTC)
Date: Mon, 12 Sep 2022 13:06:43 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko
 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, Peter
 Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Florian Mayer <fmayer@google.com>, Linux Memory Management List
 <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov
 <andreyknvl@google.com>, andrey.konovalov@linux.dev
Subject: Re: [PATCH mm v3 00/34] kasan: switch tag-based modes to stack ring
 from per-object metadata
Message-Id: <20220912130643.b7ababbaa341bf07a0a43089@linux-foundation.org>
In-Reply-To: <CANpmjNM3RqQpvxvZ4+J9DYvMjcZwWjwEGakQb8U4DL+Eu=6K5A@mail.gmail.com>
References: <cover.1662411799.git.andreyknvl@google.com>
	<CA+fCnZdok0KzOfYmXHQMNFmiuU1H26y8=PaRZ+F0YqTbgxH1Ww@mail.gmail.com>
	<CANpmjNM3RqQpvxvZ4+J9DYvMjcZwWjwEGakQb8U4DL+Eu=6K5A@mail.gmail.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=qd9upT6G;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 12 Sep 2022 11:39:07 +0200 Marco Elver <elver@google.com> wrote:

>
> ...
>
> > Hi Andrew,
> >
> > Could you consider picking up this series into mm?
> >
> > Most of the patches have a Reviewed-by tag from Marco, and I've
> > addressed the last few comments he had in v3.
> >
> > Thanks!
> 
> I see them in -next, so they've been picked up?

yup.

> FWIW, my concerns have been addressed, so for patches that don't yet
> have my Reviewed:
> 
> 
> Acked-by: Marco Elver <elver@google.com>

Updated, thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220912130643.b7ababbaa341bf07a0a43089%40linux-foundation.org.
