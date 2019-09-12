Return-Path: <kasan-dev+bncBAABBNOB5HVQKGQEBD7M5ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 83FF4B11E0
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2019 17:13:59 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id v6sf6827068pfm.1
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2019 08:13:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568301238; cv=pass;
        d=google.com; s=arc-20160816;
        b=lRy4tjDhgnUnHkigIGjckildFSi4JzPFD8BKAXuKAEVE9RbzVuXbC06ylDvk04KXAA
         kOstLYrlozuN5QLzCiom/F11RqCOpZvnuhDLWsJg/NnSNNYFEessZis66PBfcMNhzR+q
         ryFXPWqz+7zEbqAjfrogfrSwt9I1FBvr0hsUL4mGlAjXdqiRvBvKZinX4tmfr++OlA2+
         bbHyXnISu+UBj64zuYN1wvjr8zPMqn/GY97dlKWOF0YQYOEjXqkdNhQQK1lNQ54+nRBE
         b6QrA0ltQfUB7NHON3fcC4HELup9lCnLpnbOHwYR0xExQt8K8Xzw65uS2+8U0DKT1Sr6
         vA8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=GXChjvxJ68JHY2RAU5txOUPC55c6G3xFJ2zFIHuhrg8=;
        b=coGNePLvFCtDMuVwMKzicYYxWptKoP48Q4iBSsAYtKEBro077tV0vyNK2C7NqxHRUb
         xItV1vTkxKveXpxFLWfKrNobp6fsW9V4elusaQAKtuPu283N8ey//D06L+757D7T3jE/
         6tLVnO1CzgIZHk6KPp90N9kzNC+NqHKCF/03tk+56DCEM0jxudUB+umR86+Xt2R15v+h
         3d7OEoMmkFEiH2X+47bpRO0bgcBeoIaOoghdFwx4vcUFG3z4dHoQaKWaVKb1FgfqaGrV
         fG81YKl415ySVwqm5P+95GdQxLFcu5hchYjlGdAvaelWmRKVINxft8gTh0wcCod4YpHA
         YEgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GXChjvxJ68JHY2RAU5txOUPC55c6G3xFJ2zFIHuhrg8=;
        b=WQo6aOTnJaQKJ3AwG3D/sgPwZjk4JhRyb7w8L9ja0Wa8ggD1e+4x8ZGf3BIvU4mnCA
         lh1A9Ih1yO3Tacm8COO2htP2q2O7oevaTmPbvlx6T8B4mc9LsLTggx23dHVQkCu7LkNh
         1xdNeJUGvZZkzyS/rvAlsbdxODTtJG91B62YCWt45mMBrFkTk8swKKR1eVC5GTUgz4aI
         zOF3Ew2IKtC2JeCIJCfLpriE4Xf59qtocPciZJ0t6fsiNvsmHmZDwkaAzYJTyG1Q/cGO
         celDb4rtiN/fmtp/jVSXGU13c+u9iy+Cnz7uD81A3r3Wy4wjKzssRaIl5pyUbKaC6xUu
         hjAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GXChjvxJ68JHY2RAU5txOUPC55c6G3xFJ2zFIHuhrg8=;
        b=n5J3GWtHZBftiyuhNnHp7NVevGzpwGLHyx7FK5/6U4DwoDpgpa9+NzY5LfZ4O+vPOo
         W/U375k/aUWYuLE5y0pgZeflK7Vh5VmsT97CTWa052luOGRZKa9HZJkkM2qZtAr28v1D
         pcaTwAuizpl8QPWAKdK6kHqkoVvgIrZISlp7ixTsmiCRyrxiC3BD4FwtFCDuPgXl8csl
         ljsPJN3NFpF2YK2Zd+J8fbd+QuROCtYKylzGzAIWlhny9tXc97BPkP1ANJrxVPHk/cMZ
         vamiHoVHFGMwHaD/KgvVATo+5VzTADWS8WZSdAf+XcgWJoPT8lxPe/9eFLjF/jKhRbnM
         WugQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXt5apSbuGwEU20zhQYoBJjLTDjFskCKSUC4mF1Ols3OVL3R9TM
	DJMfKX9Hls46TrWvPJaZC5k=
X-Google-Smtp-Source: APXvYqwLEtyThSHGtc95+2z1grus40Du/SNjWQubpBVG/p9Aes+qA0rSoDxxwlsN3gdBmcygm+FVbA==
X-Received: by 2002:a17:902:6687:: with SMTP id e7mr44563590plk.211.1568301237925;
        Thu, 12 Sep 2019 08:13:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6203:: with SMTP id d3ls5114050pgv.16.gmail; Thu, 12 Sep
 2019 08:13:57 -0700 (PDT)
X-Received: by 2002:a65:654d:: with SMTP id a13mr37792782pgw.196.1568301237636;
        Thu, 12 Sep 2019 08:13:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568301237; cv=none;
        d=google.com; s=arc-20160816;
        b=IfhOZe5ROLJ/IqJmSps/+o1yuXUBgK7jVAV6PSj3cqMzxkuqopzUxHnymu9BHJ2118
         Cet3YANElkEuYtPuboHshIWe8P5TBZwSa6z25u0kgy/btxnJgT43zs+LTEyytTq38/SM
         e54XFd5ucqN9bZMWbW5zo3hDFKKl6mvP2f/qr9Q0t0Dkz0M8jL3dMvSunD5pvVNlFt09
         VEVKkDsGta2P/Cd1HDTeboxbsomc9KeaLFI5g3WYjUPPQ6VDdMAG8YvRXrmQRZTeTSGB
         aKW90vc3ZAohk6AqNi053DD7fUA6zdFWZ2T22tUUnL+GQ4M0mg25625Ir6u0jsF1+5dY
         DOSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=/QLXKsBCZ8S5sLaOpL7JqPQzXABM3X9X8nM3QTVOOjU=;
        b=QhXzJ/afdkv7v8m0Y8nVbabsQ3ezzI5f6UxVx2u3RYNncDhg1JgOPBfYn9L8qnBj9o
         gYjmN1GiuYuPErGCfpHTpR/B8URvqHIyB3HqdBi7GA5m0rNiCQURysQcH3wQDy1ZAwTR
         ERnfQCnHNgwzhFgdnkNT9F8mRRi4H/xYAIOm+rqNmCiF+5tEVupCI46Eo4zlcK7H70PF
         pJBdD1j4vALHOj1opl0o5b1GYHFE0Odfgl8T/lw7TmRpbzwA1W6GJ/QkqdYY7P7iaoxe
         JFX3HuAgDsE11g0rQmdMhIAhHMgELAKJFq3nipWJaQEnRE1FWgd17BeRJEctn8FVql35
         GURw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id 85si1365630pgb.2.2019.09.12.08.13.57
        for <kasan-dev@googlegroups.com>;
        Thu, 12 Sep 2019 08:13:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 1573f0ea1df94009b360989531af66db-20190912
X-UUID: 1573f0ea1df94009b360989531af66db-20190912
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 415036316; Thu, 12 Sep 2019 23:13:55 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Thu, 12 Sep 2019 23:13:53 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Thu, 12 Sep 2019 23:13:52 +0800
Message-ID: <1568301233.19274.17.camel@mtksdccf07>
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
Date: Thu, 12 Sep 2019 23:13:53 +0800
In-Reply-To: <613f9f23-c7f0-871f-fe13-930c35ef3105@suse.cz>
References: <20190911083921.4158-1-walter-zh.wu@mediatek.com>
	 <5E358F4B-552C-4542-9655-E01C7B754F14@lca.pw>
	 <c4d2518f-4813-c941-6f47-73897f420517@suse.cz>
	 <1568297308.19040.5.camel@mtksdccf07>
	 <613f9f23-c7f0-871f-fe13-930c35ef3105@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
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

On Thu, 2019-09-12 at 16:31 +0200, Vlastimil Babka wrote:
> On 9/12/19 4:08 PM, Walter Wu wrote:
> > 
> >>   extern void __reset_page_owner(struct page *page, unsigned int order);
> >> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> >> index 6c9682ce0254..dc560c7562e8 100644
> >> --- a/lib/Kconfig.kasan
> >> +++ b/lib/Kconfig.kasan
> >> @@ -41,6 +41,8 @@ config KASAN_GENERIC
> >>   	select SLUB_DEBUG if SLUB
> >>   	select CONSTRUCTORS
> >>   	select STACKDEPOT
> >> +	select PAGE_OWNER
> >> +	select PAGE_OWNER_FREE_STACK
> >>   	help
> >>   	  Enables generic KASAN mode.
> >>   	  Supported in both GCC and Clang. With GCC it requires version 4.9.2
> >> @@ -63,6 +65,8 @@ config KASAN_SW_TAGS
> >>   	select SLUB_DEBUG if SLUB
> >>   	select CONSTRUCTORS
> >>   	select STACKDEPOT
> >> +	select PAGE_OWNER
> >> +	select PAGE_OWNER_FREE_STACK
> >>   	help
> > 
> > What is the difference between PAGE_OWNER+PAGE_OWNER_FREE_STACK and
> > DEBUG_PAGEALLOC?
> 
> Same memory usage, but debug_pagealloc means also extra checks and 
> restricting memory access to freed pages to catch UAF.
> 
> > If you directly enable PAGE_OWNER+PAGE_OWNER_FREE_STACK
> > PAGE_OWNER_FREE_STACK,don't you think low-memory device to want to use
> > KASAN?
> 
> OK, so it should be optional? But I think it's enough to distinguish no 
> PAGE_OWNER at all, and PAGE_OWNER+PAGE_OWNER_FREE_STACK together - I 
> don't see much point in PAGE_OWNER only for this kind of debugging.
> 
If it's possible, it should be optional.
My experience is that PAGE_OWNER usually debug memory leakage.

> So how about this? KASAN wouldn't select PAGE_OWNER* but it would be 
> recommended in the help+docs. When PAGE_OWNER and KASAN are selected by 
> user, PAGE_OWNER_FREE_STACK gets also selected, and both will be also 
> runtime enabled without explicit page_owner=on.
> I mostly want to avoid another boot-time option for enabling 
> PAGE_OWNER_FREE_STACK.
> Would that be enough flexibility for low-memory devices vs full-fledged 
> debugging?

We usually see feature option to decide whether it meet the platform.
The boot-time option isn't troubled to us, because enable the feature
owner should know what he should add to do.



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1568301233.19274.17.camel%40mtksdccf07.
