Return-Path: <kasan-dev+bncBDAZZCVNSYPBBEOWYSFQMGQEQ4GTO6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 43B12435D68
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Oct 2021 10:55:47 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id w8-20020a170902a70800b0013ffaf12fbasf623611plq.23
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Oct 2021 01:55:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634806545; cv=pass;
        d=google.com; s=arc-20160816;
        b=zTjtiHqIAojgq1kMeurAiCNzN1gf2N1fMcz2PtHFbAmROGOy+74cZGwuCXr6XTiaai
         iu7vc7JhUHZM3AKQgVSNjGJ/+lIxX4G7h8mQ7r3cQQaE2IBHIHabvx7a6ZX3nLmN7Y6p
         KD08XYrLquTY0xonJ5kDrOUUZV7CgMSpaoL0ihwsbOcaCtpN6FNLFGC0g3gFObdIjdua
         9Y/10ccsx46RcG6gqZuy9UiEeVXfSdPYGLoViVw42blCYrZcmnt3ypFhf5g5EZaXuafc
         R/ckp1N0THLd/jF7C0MHWOVmnQYYXYBBL4Pw1U2Wv7a8r55ezhD5P+BfZN+yiJjo6/b3
         kPYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=PW+lclYAYChdmuZbSRpe9gGAzf5Uh4KfbjTJTWOKOEk=;
        b=FVCs0zLy4xM4Cbp1qbla1XbYYe0/n6rZSGzVM9j57W/NQ1CE+pFbuU5NN6UerL5/nF
         8NiaF/FD+UCWdXd0QFr4rKK7hhAmdXKWpvzOjaL6wqw4DKAdfFSyih2WHN5gwk5DF1Q1
         urRiWOcgb7G5sFkMUaw1ZJ6FUF+7xdpWc++42wR/4q1/5IMg72MoYU99lE8NZepNGIQi
         pmhht8GtdOW+UzS6X7tyVbmjCgYIqQDeWak4r7D6roG9ZLs4ftcGJEGFTekQiAHG0EvN
         yCzCOvC99A9SlaWbXqaA96LcrRVjpqqSr6Ooy3b16pmuK4i58+QoJZgs31L/V+VKByyN
         xBmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GhU+jNx6;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PW+lclYAYChdmuZbSRpe9gGAzf5Uh4KfbjTJTWOKOEk=;
        b=cqbabptH4F7Mm7RRTf3QtbADLsSc/pzvcagamdedj7G59FPhfJTtjFbEx6UN+Y5YXl
         27BIOTTGa6zYbx/liCy0tebFr28RHGsdeox/cIvBAPFU54i9cGeIl7uZhX7LDOcsUa1f
         3kujx0qpH6ly6mGhq+H0dM5yPuZomf5gzPpinLzomRWxAOyXlavYKrlfsitGlIE0FwoS
         TPf7AJJYB/RlWbYw6C3TOSaImp7dhRgTGKJwMptoc9PBlXybxdl+Tb2zXKlrBctA4LdW
         GGxHi8pjszi7SucxWTzWuOnfSmaTqk7tRAwRR52qCYNrBDgm+NbJSfTJA8qBaDVNcHw0
         s7Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PW+lclYAYChdmuZbSRpe9gGAzf5Uh4KfbjTJTWOKOEk=;
        b=Fk51xGQKJC10CyyD0EBCKROfRbK2P6M9wjH5qF+qK7VXg92Fd+HbfPGkJjBEtwnZA5
         ZCKZK3CzkvOBEmXAdMsNJGOQ0kToMw7/EfackBiACDfs7faLBY59ug9Xg6qDwr3t4lu+
         udkm3pn4eyLhnvzqi8JN7N+i4rw7kqMebJqTyfJSeXZD3sh3Vb8gwb7WXwYnPO2r213E
         kWDPisycyarCgpZl0BesYorZGbMVnLICyIkZr1ILbY8r8qmICL1R/SYfXdNm+tJI+zcT
         gM3i9GpdfHSBPAya8ynsYqvSwlqfXk74rChmniWmeMLMMlZix9CecQpuaIaNrKqNFqwk
         vfAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Xrf2eDKeXAh7MkQ5IePF5sOyv2MrMXNN1rj927A5qdXkFkUnO
	xC4PtxK79VkT18Ev3d3r3Vw=
X-Google-Smtp-Source: ABdhPJziSDD+WGDIJn1BrARf44jvNwHKIj3NSjuYmHJ5RVKrukI9XeNkwAB0LsfyHifhse68Ipw2Dw==
X-Received: by 2002:a17:90b:3851:: with SMTP id nl17mr5080269pjb.12.1634806545611;
        Thu, 21 Oct 2021 01:55:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6643:: with SMTP id z3ls1761889pgv.3.gmail; Thu, 21 Oct
 2021 01:55:45 -0700 (PDT)
X-Received: by 2002:a05:6a00:2389:b0:44d:6d57:a38e with SMTP id f9-20020a056a00238900b0044d6d57a38emr4677269pfc.50.1634806545093;
        Thu, 21 Oct 2021 01:55:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634806545; cv=none;
        d=google.com; s=arc-20160816;
        b=zfg67oxbJXqdfz0eZclMo0H7l2cNGYS+zv4cLh9FEzfvf8XG9tVZrDRYD30sQGYqeJ
         Wdu0oJkct675aW8da6CRXK0IfF7Ybhfe3NqWDSwKH00SKcttG1rEerTpUslF2YAgOEna
         yusPOPFN6ztoC23rn3HtqloUZjpKMh3MuleMGqJ7ap+jBhFh4iHOaY91mBRXRjMS8Lut
         nXB4UcN7Lti6ughZNpxd24eM4fRjOCXXLAvh3JRPOiB1MV3EW+dYUGK6kTPT4GEn+n4m
         QoddncQbjO4B3HrnO5vEi7wOM2MiCii1vg9l761sxQtmnxsZfTpi9VmsLrI36e7fhZUi
         IWsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=1yKbbSqmNAk5uwbL3++d+lBQ7Td+YJySuuvHk4+liiw=;
        b=KDaE2MqTqtLbOySdILDpGmPA206pqyxu3G983Fyy9hD1jdbvLEA+rsAQ6g3yTISt5M
         fKrqdspHlIKszwNaT/2lmK9gRl9A16t/GPL/cqQDf117YNMZUVFCI+I6p8kf4kU99vYK
         6QhB3MapA2dxNYucaHJmRBjraC7TX6bg4M4qqM4kIkoIMJKSUdmoUocF7/Yl4AMxzzEA
         TZodA+GNug5mCqlc5XOcCuxNmc+DSdd4KHywaqfhhckntEFmv9Yuaoen/k/WtGbP/Caw
         ty91wucVH9SpHJHDpZklQzTRGr7PXShEZVc97C69gYbKWjbZ7kw2cLSSCag81dGrlLwg
         K9iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GhU+jNx6;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x1si470541pjc.3.2021.10.21.01.55.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Oct 2021 01:55:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 2D8A160EFE;
	Thu, 21 Oct 2021 08:55:42 +0000 (UTC)
Date: Thu, 21 Oct 2021 09:55:38 +0100
From: Will Deacon <will@kernel.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Marco Elver <elver@google.com>,
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	chinwen.chang@mediatek.com, yee.lee@mediatek.com,
	nicholas.tang@mediatek.com, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-mediatek@lists.infradead.org
Subject: Re: [PATCH v3] kasan: add kasan mode messages when kasan init
Message-ID: <20211021085538.GB15622@willie-the-truck>
References: <20211020094850.4113-1-Kuan-Ying.Lee@mediatek.com>
 <CANpmjNMk-2pfBjD3ak9hto+xAFExuG+Pc-_vQRa6DSS=9-=WUg@mail.gmail.com>
 <20211020152909.2ea34f8f0c0d70d8b245b234@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211020152909.2ea34f8f0c0d70d8b245b234@linux-foundation.org>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GhU+jNx6;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Wed, Oct 20, 2021 at 03:29:09PM -0700, Andrew Morton wrote:
> On Wed, 20 Oct 2021 11:58:26 +0200 Marco Elver <elver@google.com> wrote:
> 
> > On Wed, 20 Oct 2021 at 11:48, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
> > >
> > > There are multiple kasan modes. It makes sense that we add some messages
> > > to know which kasan mode is when booting up. see [1].
> > >
> > > Link: https://bugzilla.kernel.org/show_bug.cgi?id=212195 [1]
> > > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > 
> > Reviewed-by: Marco Elver <elver@google.com>
> > 
> > Thank you.
> > 
> > Because this is rebased on the changes in the arm64 tree, and also
> > touches arch/arm64, it probably has to go through the arm64 tree.
> 
> That would be OK, as long as it doesn't also have dependencies on
> pending changes elsewhere in the -mm tree.
> 
> To solve both potential problems, I've queued it in -mm's
> post-linux-next section, so it gets sent to Linus after both -mm and
> arm have merged up.

Works for me -- I'll ignore this patch then.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211021085538.GB15622%40willie-the-truck.
