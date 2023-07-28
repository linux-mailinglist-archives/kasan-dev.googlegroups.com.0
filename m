Return-Path: <kasan-dev+bncBDLKHL4UYEFBBQ5ER2TAMGQEMU76REQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AE497669AB
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jul 2023 12:02:45 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-56c589f42b6sf1839766eaf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jul 2023 03:02:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690538563; cv=pass;
        d=google.com; s=arc-20160816;
        b=MAxNjr2Bh+o1BgBRIICvBrCZcaWtE5Tcbu+nwMQlY7Eh8o/bJJMp8M+xUSEkr4t8+R
         aGqGgWzeHrXJnS9ekMwVqbBJdQK9icvoEPynJMGs6RGKEVWlh5P2ZsjcKfYyOnGpAPOb
         pgoLId3qQn20gRfZklyeXoLkHcqJLCWqL/eXFCIzZg7gaMEjHgKyNOQEJgOXdI5qs5xD
         Py12N9Vy8NyADEF50bwQODyaB6nnRpxxTiEry9vaHpAZmXEeiYYflo3GtNd7xvL3Jnha
         41KsDfZWnxhRyldP8iqO4NeTM5HojCBnkM3EPjg8FVwDEhwLY/+DjXPOVWT3EX5rWWcn
         zq/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=XiFyf6P9eWFvJulrBi12qnDdSeOcOfn45NNQwsBMDFs=;
        fh=m71XCBCvUgFhsWx/Tk3dB/0QiUCjM2LLEtQRlVGDA5Y=;
        b=eN6HtYiM8XLjMWTnvOx/uR5ev+nDh8RrYld5fUqcpIVJa3UpxcnpO6/YvLciptdLTL
         XREcmqhXQ/OSEBHzhazABhQ+Gy7ZnZRpKeSEDrIXi5f1m7/v/NOwYcKJ9I4hW/iIVtuo
         TZWA6pyMInJzagm+Kj1sL8BvG06bMVdeP1GCKG20vplAjr58pCWU5WHkxxMuh4v6lzWa
         Bpk1v65tplYL7s6KVV1m33eylTg5sWki4TCC8ZB3dReYBLxzQlbzDbmhVkZ4yNbG2cGl
         YPmlGkZSwYUPnv/GJC08dU5bJIgTG7AcVzQsgvDsUGNP4nKSUnVGna99kI0ydWL/nyjC
         eKFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RXTRsuof;
       spf=pass (google.com: domain of fmartine@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=fmartine@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690538563; x=1691143363;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XiFyf6P9eWFvJulrBi12qnDdSeOcOfn45NNQwsBMDFs=;
        b=cjtOJV6Q2McxXZfDYfTeUTOxYBPERTV32Id4ReJjlx4x7u5U4IjpLDGBQt+9wxA4cj
         rmP/3+fedgDvRw8QFsEkTz3y/bdGJrfIvprZx62BSCIy2rWTjC+e+y88ENLHgTtK8ZC9
         x/Ft213oIDC3czMvtiw/X0t3aYQD3+CeO7/WhkBnXqLFsz0QjT9QYYD5rmCDwD1RF9dk
         MpmbLLSkhC1eeD/wShDGXMgH8Au7E4MuGNx0FsRXO35wHGrlX+fLnT5dLJL2AEQXDacc
         LxZGubnPwmR0YZHxXBq/X5coXLUPJwnty0LnwErTLsPh2tCB8j7vH5s5crJVNZohwuJU
         PtdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690538563; x=1691143363;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XiFyf6P9eWFvJulrBi12qnDdSeOcOfn45NNQwsBMDFs=;
        b=ZPm3tesRm6VnA/TEfIebaxAJcd8iCny8dhanJJaqZiPFf6g2/LbVlwm9Kgh2fJGr4h
         9p84cg3qNZ0eKCOlrpRs+5mKcDcitmi7twPe+VZS4ofv52ORaXPacnpLKB1Ssja5tlAx
         kk4H71QMf8y6Go6sSFZ1jUFGnC1vjDKqCTNDsBcm3bA1P1WEfM5ZRkF6Rwy4vDp1Rp41
         0xxUYhy1BWd8mWxA2l6rgoEPwHe8Y5w4lO5L7ada2ZprXtrCpvlt9854A7aL1iVzLuIE
         1DQ174wDjsAkJFDnpzwwIOZvIqUShc7gLOVZyFAGPSND3Sa4uBFDBLX2QhZtaeLYyZww
         NOHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZe3thEiUYbm8q0rHuLtdiKcWQ91G2sLeA/eRRfiZaqPye3wc1Z
	QNrQCpYZCgok3PT2Oqq7ncM=
X-Google-Smtp-Source: APBJJlFxAHHNrgMPGuJMWMjs9PYO4iRoFzgJS8SZvXnFhQipZFnkCrUqQ7dXPXng55O1nVQkprZMXQ==
X-Received: by 2002:a4a:3003:0:b0:566:f2b9:eb86 with SMTP id q3-20020a4a3003000000b00566f2b9eb86mr1985346oof.4.1690538563523;
        Fri, 28 Jul 2023 03:02:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:b08c:0:b0:566:5bc4:69dd with SMTP id k12-20020a4ab08c000000b005665bc469ddls1889614oon.1.-pod-prod-02-us;
 Fri, 28 Jul 2023 03:02:42 -0700 (PDT)
X-Received: by 2002:a05:6808:3a5:b0:3a5:ad17:371 with SMTP id n5-20020a05680803a500b003a5ad170371mr2196564oie.3.1690538562636;
        Fri, 28 Jul 2023 03:02:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690538562; cv=none;
        d=google.com; s=arc-20160816;
        b=G2ba3xN8UuYSeweRNdfdn9Ouys2ouT0Ed3RmchOX9JYX86UsCo9Y0GiQbUpPPWCp/s
         +kOuxzNRcZLvyaJz35JUT9yMs1bHHKTaLzLEfEdYexZlyXJNekOymekdjKxu61fhkDKj
         Ap44it3gZ8RctIBsQDXZgfv+iZRcNAaAH6L3kzePGPtmnBSDrPPC2ZaZQElebTM8OKid
         i6uChCrZ/7d6YYRhnBeK/SwEBR3Zwc308h+FRabc8o+5Za7ULpD0PNpnJDRkydXbylVJ
         jejQ1Lt/qDwNB7AtIoEb3L7AHBMJfGh/iX6qJtEYIC6X0z22QotI4gc+3flaVMP84z6X
         ixFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=WJxfGpxbppzJwgJdPmeEdmGhAfwaruKH//tjBHG7QkQ=;
        fh=m71XCBCvUgFhsWx/Tk3dB/0QiUCjM2LLEtQRlVGDA5Y=;
        b=j3t23P3aogdlQzf8tL60Qaez67IBUT2bzq86nSSZCyXVxJzQf7b2Q/7HvBhinxhRfS
         7hm0n3OeYj3chRyh3f3v0rooF6/hhIVjprf4jcoeqNTaiyHa93xs2eToLskMedOGDm0x
         +z1q13DznrUGrksNvBOxPBY8sKk76Kutjbnh45SQB++CDrlQyg4OM7gIJRxRfmWkKN03
         sKufQhI3U2o0npm9mFUtWZCvwziPZ1gupok7Jhl3/2xRdmHsMzvV8+m0hc6vONPjNYVQ
         v2fM4PDgxfcgn3Z50KCeZYdIKT7cM9q+0hdla+VIfV6UDRLqPrkSF891JnPUw+OTJdYx
         DVtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RXTRsuof;
       spf=pass (google.com: domain of fmartine@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=fmartine@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 20-20020a631154000000b005572dbd4d7bsi197973pgr.4.2023.07.28.03.02.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jul 2023 03:02:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of fmartine@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-247-gLNGPys1NRuW-PeOqGj6Nw-1; Fri, 28 Jul 2023 06:02:38 -0400
X-MC-Unique: gLNGPys1NRuW-PeOqGj6Nw-1
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-3fa96b67ac1so10763155e9.0
        for <kasan-dev@googlegroups.com>; Fri, 28 Jul 2023 03:02:38 -0700 (PDT)
X-Received: by 2002:a05:600c:290b:b0:3fd:1cfa:939e with SMTP id i11-20020a05600c290b00b003fd1cfa939emr1548203wmd.4.1690538557637;
        Fri, 28 Jul 2023 03:02:37 -0700 (PDT)
X-Received: by 2002:a05:600c:290b:b0:3fd:1cfa:939e with SMTP id i11-20020a05600c290b00b003fd1cfa939emr1548187wmd.4.1690538557338;
        Fri, 28 Jul 2023 03:02:37 -0700 (PDT)
Received: from localhost (205.pool92-176-231.dynamic.orange.es. [92.176.231.205])
        by smtp.gmail.com with ESMTPSA id m25-20020a7bcb99000000b003fc0505be19sm3716930wmi.37.2023.07.28.03.02.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Jul 2023 03:02:36 -0700 (PDT)
From: Javier Martinez Canillas <javierm@redhat.com>
To: Geert Uytterhoeven <geert+renesas@glider.be>, Tetsuo Handa
 <penguin-kernel@I-love.SAKURA.ne.jp>, Daniel Vetter <daniel@ffwll.ch>,
 Helge Deller <deller@gmx.de>
Cc: Marco Elver <elver@google.com>, Kees Cook <keescook@chromium.org>, Geert
 Uytterhoeven <geert+renesas@glider.be>, linux-fbdev@vger.kernel.org,
 kasan-dev <kasan-dev@googlegroups.com>, linux-kernel@vger.kernel.org,
 Alexander Potapenko <glider@google.com>, dri-devel@lists.freedesktop.org,
 Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v2] Revert "fbcon: Use kzalloc() in fbcon_prepare_logo()"
In-Reply-To: <bd8b71bb13af21cc48af40349db440f794336d3a.1690535849.git.geert+renesas@glider.be>
References: <bd8b71bb13af21cc48af40349db440f794336d3a.1690535849.git.geert+renesas@glider.be>
Date: Fri, 28 Jul 2023 12:02:36 +0200
Message-ID: <87wmykxsjn.fsf@minerva.mail-host-address-is-not-set>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: javierm@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=RXTRsuof;
       spf=pass (google.com: domain of fmartine@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=fmartine@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

Geert Uytterhoeven <geert+renesas@glider.be> writes:

Hello Geert,

> This reverts commit a6a00d7e8ffd78d1cdb7a43f1278f081038c638f.
>
> This commit is redundant, as the root cause that resulted in a false
> positive was fixed by commit 27f644dc5a77f8d9 ("x86: kmsan: use C
> versions of memset16/memset32/memset64").
>
> Closes: https://lore.kernel.org/r/CAMuHMdUH4CU9EfoirSxjivg08FDimtstn7hizemzyQzYeq6b6g@mail.gmail.com/
> Signed-off-by: Geert Uytterhoeven <geert+renesas@glider.be>
> ---

Reviewed-by: Javier Martinez Canillas <javierm@redhat.com>

Pushed to drm-misc (drm-misc-next). Thanks!

-- 
Best regards,

Javier Martinez Canillas
Core Platforms
Red Hat

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87wmykxsjn.fsf%40minerva.mail-host-address-is-not-set.
