Return-Path: <kasan-dev+bncBCN7B3VUS4CRB5VE52AAMGQEUC5DHSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 24AD030EC68
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 07:21:44 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id z27sf1646319pff.5
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 22:21:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612419702; cv=pass;
        d=google.com; s=arc-20160816;
        b=kYLIoHVBrmHRkqDkf2IS/1Fp/wQ+2+XTSiL6GGwe7iP+59pgg5SAAY4/QdZJbygDQ5
         7V1oafLhF42EvnXXFIk0ffTRgE09NZnS126pUSL5mdRGExt11k8Vbdg5rLW/CV2U4wrX
         0fryZEKkda0WlcprHn8hxn5xecZHbMnWGFZTwcaBwoGvqQoz+m5+faTWK8PTQWwODu7e
         BYNZtxf1vU3sNGYByVer/McqSmF9jlKkRLPvI19dvBcuYZGyzz8NW5oDDbYZ96BDQKae
         SDxorR38j8Q48yOdsAhrEeJuED+c3Lu/8aYh6EetoM0G/G60DUFr9T+d4rF8ra9YkvyU
         Hk0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=h85R2rDHgvod0RBetnwSW09BNlYEtWpcK8qQgFueq+A=;
        b=XYS/wsd9NZgj4Qkn6nAzIhj+7VnaHtW9UIUeQ2D6kEbwud9eKP8arjMDo4UxuYqKpv
         VkI6vcxzd7wTq1DA/Mr9eYPh35Ob0HcuW7vX0oD01GL2ZhL3vz3Gh632cPMUTJ4Ok9DL
         1Vap2z3PESTwVoPz82AM1/JY2FUe731gIx4zUPnbO5oneUwPe8J28+GqTwWxV5Hm0+bH
         Y6pVZ5EsfwHAAUYTaoan8V3olfwH6Qo08zYbPw46MEihw4qgHUlYivJZH+FcfALmdLhi
         UCWWFXZATh49ez4PW2CJQc4QX8NZ8MfKP27QTHHYHzFA4lHU7upaP2COg19CD+lOSjFT
         WBoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h85R2rDHgvod0RBetnwSW09BNlYEtWpcK8qQgFueq+A=;
        b=SYqbsj0NvLcW8JkL4nbduSV8PEwmJDePFCoaZch/hQr96bU6aBR0V9wzrGkdUm79Xd
         ORcq5CCLQrT5z9qw/UWvcNr79sIj+MFnVtKtZxUzINzXP4TK4RqOu4cvqjJRwnc1/I6g
         BsqvskJdduPZHmkDjYwIr8C20mSeTdriPHXYYQmqaCE7tGw/GaQG1C/ohtifovf9AWgd
         cbZhqdS1M1t+FXu5pGsJ7w+H22LKGqhU9fSQ0Guw+Xkoz4iCvCJo+xSJB4Ik4yM8ZEQP
         AxAkGG6LM6uQ+Ca+DA+jbJZbCUe92If9C6f1tPFkALE7aQV4oPH+loZP+GiMGRrrmxqx
         yIdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h85R2rDHgvod0RBetnwSW09BNlYEtWpcK8qQgFueq+A=;
        b=nuiSQU9SQa/aUp1cc1u5RY4PoyulDxMUiwQhXd566gzpvvVSMl7bMT5t/QBA3xdxQP
         0oMG4r5wfj6M+LKzkSTQRLRoglJHyYTmS/mmRTzXWK21uMRvd6hwnZIsV/mLckaCtkjW
         53f7Bvy/Uxcl1eJks1Gk2FK6fqRs9qAr7hZXO5N280s0B5PtTSWYHv1dgYCdNRxHBOYH
         Q/kZkgdbayjxRmiqke6y3ru8BvNtkOt47xsU4K/DozkVRQGp5cQFN8IAlKlG4ER6D+UE
         jHRQdABqVJeY9N0o6mUjeXclNgWDvBkZeIhnHNWVIsDr+WAH6tmRklTRPramt93V2hDc
         QJcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533fW8+HcZ8mmR7BJdToXrjProOPAU0/IiUssmFC1k1Zhta1UHz8
	G2OC69nfpCt0zBID3urEhVs=
X-Google-Smtp-Source: ABdhPJzaYSx5HEdlewlsV6nf6zi9htPKM+FJCXixCkfm9pgdJXbl8dOYvHweSEM0XOxkEzBJcU8CjQ==
X-Received: by 2002:a17:90b:46c5:: with SMTP id jx5mr6864890pjb.27.1612419702704;
        Wed, 03 Feb 2021 22:21:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5312:: with SMTP id h18ls1963443pgb.9.gmail; Wed, 03 Feb
 2021 22:21:42 -0800 (PST)
X-Received: by 2002:a63:1524:: with SMTP id v36mr7408390pgl.383.1612419701970;
        Wed, 03 Feb 2021 22:21:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612419701; cv=none;
        d=google.com; s=arc-20160816;
        b=0spt3ccJj4FZLt2Era/QnGByg6WiPf0G2iZ7wAIZ8Lccvxckf69fazEDz2t4RFisJ+
         fY1t3nPy/RB/VBRYJX6SQZTHO3L7u0sQgtmJJnpru0wxuncu4zUe1Qm9CN5hz9GIBp9l
         E58XDdtMhGWDGn3EdXzRrA9Zw2evMT/r3DYl3Xv6XGhY0wl661nquM9gUGXX+pjo8Zhy
         N4sm8TZ2vuJmYhFmO3K56KGDewFRFNe6neo/EvpyFZ5VUzu/AQBluKg0uyTzLwhn8uy8
         5nXx3rKHuNZl1mETEBvhZmogEHZW/LANFg3baaDen3AttINyO7Zc8WLgO7KVjuQU7TDT
         9vVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=hhShLWWlVurQzd3OQgcJUe6RX9YLvyffVUMiQPGyR+I=;
        b=ZdqDsdf/FeI1HI3su/OIon7nkOGKj+gduPyT7vYnnYF2zy8Yf4z7oORsA44KTVQqkA
         qWaFVSQKVzw0jcx8yB5ItYuFubdh2CDLV0/Wlk5aDtkEvy2X9MU42YjhI4ZPjyaanigm
         13BVQXuAQmjJVFjy/Zf6znA1i3CR33ei8K9mVL++dD6FpBmASfxT+7s10PiM8zjtrln7
         FlKFC8tO4CMcF/eYPOF9ZLD7pu2GMrikrgGvtGVdDb39oLH9YBWQZqSQx1SOc+bUEWfP
         pe9kO5Mn31JvMZAd8RqQZfSF2VHwbf1WDHrJvzO+cEVcXkMqBuKkqj+7ey7NBHP96Pij
         deTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id kk5si95665pjb.1.2021.02.03.22.21.41
        for <kasan-dev@googlegroups.com>;
        Wed, 03 Feb 2021 22:21:41 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: a5e46f1b9dd743058e3dbf72b12b937c-20210204
X-UUID: a5e46f1b9dd743058e3dbf72b12b937c-20210204
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 661632920; Thu, 04 Feb 2021 14:21:39 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs05n2.mediatek.inc (172.21.101.140) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 4 Feb 2021 14:21:38 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 4 Feb 2021 14:21:38 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <ardb@kernel.org>
CC: <akpm@linux-foundation.org>, <andreyknvl@google.com>,
	<aryabinin@virtuozzo.com>, <broonie@kernel.org>, <catalin.marinas@arm.com>,
	<dan.j.williams@intel.com>, <dvyukov@google.com>, <glider@google.com>,
	<gustavoars@kernel.org>, <kasan-dev@googlegroups.com>,
	<lecopzer.chen@mediatek.com>, <lecopzer@gmail.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mediatek@lists.infradead.org>, <linux-mm@kvack.org>,
	<linux@roeck-us.net>, <robin.murphy@arm.com>, <rppt@kernel.org>,
	<tyhicks@linux.microsoft.com>, <vincenzo.frascino@arm.com>,
	<will@kernel.org>, <yj.chiang@mediatek.com>
Subject: Re: [PATCH v2 1/4] arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
Date: Thu, 4 Feb 2021 14:21:28 +0800
Message-ID: <20210204062128.27692-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <CAMj1kXEMOeCZTvNqPPk-uL5iA7hx7SFPwkq3Oz3yYefn=tVnPQ@mail.gmail.com>
References: <CAMj1kXEMOeCZTvNqPPk-uL5iA7hx7SFPwkq3Oz3yYefn=tVnPQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
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

> On Sat, 9 Jan 2021 at 11:33, Lecopzer Chen <lecopzer@gmail.com> wrote:
> >
> > Linux support KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > ("kasan: support backing vmalloc space with real shadow memory")
> >
> > Like how the MODULES_VADDR does now, just not to early populate
> > the VMALLOC_START between VMALLOC_END.
> > similarly, the kernel code mapping is now in the VMALLOC area and
> > should keep these area populated.
> >
> > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> 
> 
> This commit log text is a bit hard to follow. You are saying that the
> vmalloc region is *not* backed with zero shadow or any default mapping
> at all, right, and everything gets allocated on demand, just like is
> the case for modules?

It's much more like:

before:

MODULE_VADDR: no mapping, no zoreo shadow at init
VMALLOC_VADDR: backed with zero shadow at init

after:

MODULE_VADDR: no mapping, no zoreo shadow at init
VMALLOC_VADDR: no mapping, no zoreo shadow at init

So it should be both "not backed with zero shadow" and
"not any mapping and everything gets allocated on demand".

And the "not backed with zero shadow" is like a subset of "not any mapping ...".


Is that being more clear if the commit revises to:

----------------------
Like how the MODULES_VADDR does now, just not to early populate
the VMALLOC_START between VMALLOC_END.

Before:

MODULE_VADDR: no mapping, no zoreo shadow at init
VMALLOC_VADDR: backed with zero shadow at init

After:

VMALLOC_VADDR: no mapping, no zoreo shadow at init

Thus the mapping will get allocate on demand by the core function
of KASAN vmalloc.

similarly, the kernel code mapping is now in the VMALLOC area and
should keep these area populated.
--------------------

Or would you have any suggestion?


Thanks a lot for your review!

BRs,
Lecopzer

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210204062128.27692-1-lecopzer.chen%40mediatek.com.
