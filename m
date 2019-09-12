Return-Path: <kasan-dev+bncBAABBZNC5HVQKGQE742NXNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 27BA8B10AF
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2019 16:08:39 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id s3sf5734689qkd.6
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2019 07:08:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568297317; cv=pass;
        d=google.com; s=arc-20160816;
        b=m2LnJaPIk/8EkCjMBEwI8peVadwHAXxBiFtq/BEBnUVZcvc2Lwq+Ev9O1FLyr0T8Or
         Lnu+fmKsBzTccWABurgKhWc/D11fcPuDy1A56IvOHF5fiPDbC4u6xQhrntERV+cKSq8P
         c9qBRARX9mzMvU2Zr+Cpbar2tFr+2Yv5DTmz/A9IBFeJcq6j1W9DxCWZdjgLmjyBLF+f
         BvGC0dkj1FfHPGC89lwqGLaXc1pVwdmQSZ+e++y5at8g1Aknui3x2ifU2UTSQPcGCQG6
         aNW496ayS6+XLocSh/dMlMGQvh2q20yJVlUYSglcrBh1EyA9wiiqXJfcoc/3zMf/aSA7
         EcQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=LnIjHRsMUNmmnFNsJHEHJz7APlFDnlDmZW4QqIhfqic=;
        b=BiNQrJamdBihYoTC4UWqAaLbn1yM7tGZa0JGIW5kLHqenKtiGQCYhWcZf7mSIB7BFW
         LnA6xmy3zcIdRDhLLRjPxoGMs/BY+Cp6Sg2tYNk+b4OTGvh8JVKCNQO2ZnNOaI0J+JVA
         R2DjX47ZByLyT9qixBx77BRa9VklWU3p7nsFiWuodE9tHWhF4TVBUtMKaA9XO8lrWR1J
         03zOuPMnRYndPU7BwDMutmGZWCOvxw3okcQUnfzFnQBELn+6SVH+yNYbVzheWNYUTUMy
         5SNOCXArXrQ3RloBGdJ34xOts1+xtcGcZTQgLTDIdg7m9Xiq/A/Uvb0DhwFG+xkN+f3R
         grFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LnIjHRsMUNmmnFNsJHEHJz7APlFDnlDmZW4QqIhfqic=;
        b=Nd0Rar4JABp7W/+7jB867qYz0NrLpC/29vxTEaCIU9NnH7Au1+nGNXXnyQsgwVHu2k
         8twmRb0teN+puFOe0zm3O75oOsKu45nlSWxwl0i+WFyRUH8NOH4tXdxh7v8wrJ6y3/c5
         CF/hKjETKksTNpxMyyGB8GCaSIvugujm+4cQyZMyVzoRz7ZEfDiwVAtMUeDEFeRXGKYT
         BPp5kOKvspZcRv7IT5cS4l5d7S0OHsPgv5hwyvWPjsJcL7YvjMEY1MXHK3mYTZhxrBKg
         9dy0Bp/IgftPaJ2csUUgwSJuMI7pAlvOmdkqN7vAq4fexVtO8weLW/A8NmhGDsoiFzBM
         sTYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LnIjHRsMUNmmnFNsJHEHJz7APlFDnlDmZW4QqIhfqic=;
        b=tL/RgJF8NA94KiOTmcfN0564R681Pn5ZT3x9X1nT0i2enWXEhd5UFAKQtaWEC8jTWr
         +MGuWthDWqh0rycsWLU13CKIpMHW+kY36UWoBJzwZQqYItSQOGmdDZ30W4HYEZ5+ZbDx
         CmvjHJ+iPfx8FH9s5qWTKZL9OoVkR4u0VLqmrECqGIdL5waOcA93K9Y4bOW7plbx5Eov
         i+led6qiL4p/yB1kuDFWRjZtSqeoxD3wgH8/GiInSuoP9llGB+xrF/iPh0KlnB6ZHWJU
         zTTfqNRqBmL63q/8y8yITaaimDdFwgc8f+MiAVsRhmlBQQeA3ed6t1XT36s4mkRJ8mFM
         FjcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUwlP/4r4r99F7VjcmZdNQsMNdUf4QjOHL0VBGXsBSZppwJg3bu
	TGde/Nz0Ifadowmva/fjon8=
X-Google-Smtp-Source: APXvYqx0/RasEgkxpKkpMCOqgy8n37w+cR4wxI6SMGHgbXpl2Br/S9gStogdfKu5RYZE7xti/YH55Q==
X-Received: by 2002:ad4:4d8e:: with SMTP id cv14mr18925644qvb.49.1568297317325;
        Thu, 12 Sep 2019 07:08:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4852:: with SMTP id v79ls1134852qka.2.gmail; Thu, 12 Sep
 2019 07:08:37 -0700 (PDT)
X-Received: by 2002:ae9:e219:: with SMTP id c25mr14897940qkc.234.1568297317122;
        Thu, 12 Sep 2019 07:08:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568297317; cv=none;
        d=google.com; s=arc-20160816;
        b=E2us6w/WeAGVRWw6Xbcyt3YiUvJzsUTwexsa7M/xgpBJGjwhZ59DAAVuiUgTjyLPnJ
         2477J/cFew447Ix/4nTW1AeqAJzTPhn6ohfUbxNog4GF3mD7HB+FLD10UMlv9quVDpar
         3OrFHfo5qk7i8jS94zmvFhWRtVkzx2SVYOria/uUpRwehJITQJ9wH0A+H0+ihVi9EzQL
         xTJjHK971eHtZbQyU8QRLKokCBCZ/6i0jjekSIQaulnRYwg6zpLQ/0PhHgLysaWQDta1
         LDKnCsyDNNOPsoej9I4aP3UMjnR7VRiXtCptJ0YlVqEWK+CWekY+JTGUuW2ExJY6i0si
         iDdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=XkZczbCDt2l/sxUaS0rSKffilt/iWRQLp6GQT05SWcM=;
        b=svLWRckp6HXB4nlB2ngkWDSLN9WhE5eFea3nbIQAnUb579eGfu35rqZUpb1E1ZvrSy
         Fib6eiBE1vrv2Q4ZvCwm9OvHrh/+UW1G4eKdkpCOV0OYe0Z6APFJCnHV3+5ADHpXeAAt
         Ba7RqKtwKPnGp3A0S1JFYsNS2MMU28OXOABbRBnHymrGTYgdcHEjzlDbyn5C7xT0n4Og
         snMMTdZCnt4t8W9UCK7gnGz1cI7nAYw0W+TsdcjQWkxo+dAnhM/lherCgmLozKrROqh5
         NnJqpJWLQC+VaqG6E7yE6PK325hz2yk6MoyY4TCpzVCbTxnNqnZVaW+cdHYrvD7+1fqC
         JTPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id v7si283861qkf.5.2019.09.12.07.08.35
        for <kasan-dev@googlegroups.com>;
        Thu, 12 Sep 2019 07:08:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 88ef5b91e7cc45ca9b12d53609cb2ee6-20190912
X-UUID: 88ef5b91e7cc45ca9b12d53609cb2ee6-20190912
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1916237428; Thu, 12 Sep 2019 22:08:30 +0800
Received: from mtkcas09.mediatek.inc (172.21.101.178) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Thu, 12 Sep 2019 22:08:28 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas09.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Thu, 12 Sep 2019 22:08:27 +0800
Message-ID: <1568297308.19040.5.camel@mtksdccf07>
Subject: Re: [PATCH v3] mm/kasan: dump alloc and free stack for page
 allocator
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Vlastimil Babka <vbabka@suse.cz>
CC: Qian Cai <cai@lca.pw>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>, "Andrew Morton"
	<akpm@linux-foundation.org>, Martin Schwidefsky <schwidefsky@de.ibm.com>,
	Andrey Konovalov <andreyknvl@google.com>, "Arnd Bergmann" <arnd@arndb.de>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>
Date: Thu, 12 Sep 2019 22:08:28 +0800
In-Reply-To: <c4d2518f-4813-c941-6f47-73897f420517@suse.cz>
References: <20190911083921.4158-1-walter-zh.wu@mediatek.com>
	 <5E358F4B-552C-4542-9655-E01C7B754F14@lca.pw>
	 <c4d2518f-4813-c941-6f47-73897f420517@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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


>  extern void __reset_page_owner(struct page *page, unsigned int order);
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 6c9682ce0254..dc560c7562e8 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -41,6 +41,8 @@ config KASAN_GENERIC
>  	select SLUB_DEBUG if SLUB
>  	select CONSTRUCTORS
>  	select STACKDEPOT
> +	select PAGE_OWNER
> +	select PAGE_OWNER_FREE_STACK
>  	help
>  	  Enables generic KASAN mode.
>  	  Supported in both GCC and Clang. With GCC it requires version 4.9.2
> @@ -63,6 +65,8 @@ config KASAN_SW_TAGS
>  	select SLUB_DEBUG if SLUB
>  	select CONSTRUCTORS
>  	select STACKDEPOT
> +	select PAGE_OWNER
> +	select PAGE_OWNER_FREE_STACK
>  	help

What is the difference between PAGE_OWNER+PAGE_OWNER_FREE_STACK and
DEBUG_PAGEALLOC?
If you directly enable PAGE_OWNER+PAGE_OWNER_FREE_STACK
PAGE_OWNER_FREE_STACK,don't you think low-memory device to want to use
KASAN?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1568297308.19040.5.camel%40mtksdccf07.
