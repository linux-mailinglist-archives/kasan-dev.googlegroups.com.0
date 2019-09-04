Return-Path: <kasan-dev+bncBAABBS4OX7VQKGQELJ5CKYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DCA5A857A
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2019 16:16:44 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id n186sf16739681pfn.6
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2019 07:16:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567606603; cv=pass;
        d=google.com; s=arc-20160816;
        b=J88jgCFUf0/L+OE3qJQj3RS0LzADeL0pS+/kVIRq7Z3gDisShCeEsUa3+RGWdloSLY
         YCqLbMHq9qPUf7YC6miTE91egTWm4ehGbRyx0Auu+mpp3D3OCYjFBgx2Ds1PP+NlF8SM
         4xJmTPgkrYf5lgHeF/J/laRg+kQIkR3+zqXeTvZWjtZIz3NSfjRJmOozMoPCaIuwGA+O
         rzsOpLIs6yICrQ0qV1PePkA0nNKe+W9dp+DYKBnuV5C9S7RvjuW0Bbo0otOqS/V87Axg
         9j/+9pD3RcFZQEuBAvwYs+DU+p9JIfA9CPNwHSsvm/jsM40U46Sdv7KgB7dOoq3tbJI5
         4XHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=AtfCqj6K6w+wP7NoG64lUAOHSR2NEnRTaadvkM0QaD0=;
        b=ulOpKKi6mqFGypKIQlRzI6GqTj/7RjzXGn1bll/wleiRzSvDSFViMz4V4GVazudZoz
         qc8XcKY8QNrPBiHCfE08moy0wDFGFgDHgEUvv1i179hYIk3ayqohcRGWnc0vvDDE/05T
         +sZBtt8AtoDWNS/+40d5gaDEbipxJ37mRi53jLC+cQABvvqjDClUz0co3mAS+soIe7xV
         YDEs8zzPRdayOP/XU5gwpKdkxjHyftPJpmMUxzW6+D8Czd6zuQdmyAl5JOJfBJTzu13p
         fH9CBw9bKp1kD/vDtAHKHdf03qdpG05g31l0fNF9glQ9oU7S34+s+6SstzhaClU4+ct/
         jqTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AtfCqj6K6w+wP7NoG64lUAOHSR2NEnRTaadvkM0QaD0=;
        b=bMvJbZjDmLhRE7gmad+2iBDojtNCECUqXGs4K+/XsKEthu3+VUtT6gwHLW31lUyXJc
         CnSirO69Sl7uJTjPAiA235O2Q7KSebVdEoT3TapY9eOFQWo/rdIno/RHtRBe10aG1BcG
         RODzVS+o3r3gf9vmTyfcuKxHat6myn5dv7EHgSiJbJ70aUHrlvFpNILrwolDsVHOtyAW
         M5vR0/Ju1IrezWGVIEyMSgjcgu+C6NT7pjM+UG6Dk6Brg0TP2vxowQ9LtLMJwqUY2TPW
         fGjvniXfd4+JqgyJD7MhlAjo6FAueC7/w0/jimRg/ACy0KpTMSiJzfW1Czr+ysUddUOu
         b5RA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AtfCqj6K6w+wP7NoG64lUAOHSR2NEnRTaadvkM0QaD0=;
        b=AhAGvKg5EL7vqNBWlJ7/zCnx7Jeej5MROs4mgkF+RghfSFdlgNILIUAbF6tCeGEe+W
         FELeUdWzg9rYGqsWZtrQv5PhlS7RdKYWUWeEyiM1PtXYEfx531qLarZBmwklsClZUKEJ
         5u8MnNTpoRq48KKBkYgkyyO0hYZcDhKZWVPlvHQcW2UiThFkExx5JZi96xcJBGycZV3J
         zyqrE9pxcZxLHknC/0pteSlfg61UczXr0gwD5/TiT6ql6slnxOjvVUDjNmagXPGacQwM
         0B2cA9nEXEkVXbj2ffoo3uSxw8OF5BKldyaN1otio6rbCg9lceysTaQkwVHCexaNVKTZ
         q3Hg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXl+zepvbTFiWXW65hTnDywKdNrY/YnuNld1UeSWixy569XZ1iv
	ev6ZtU+iIo8XizLfPmERl9g=
X-Google-Smtp-Source: APXvYqxcgPkhzIZtc//jHJ4+fiwiNNlzzkkT+XwlOmhIv8c53VyLClyCieXlCZlQwF/uwoRM2HxloA==
X-Received: by 2002:a17:902:ac98:: with SMTP id h24mr16285016plr.27.1567606603364;
        Wed, 04 Sep 2019 07:16:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9a81:: with SMTP id w1ls2179967plp.2.gmail; Wed, 04
 Sep 2019 07:16:43 -0700 (PDT)
X-Received: by 2002:a17:902:8696:: with SMTP id g22mr41075643plo.122.1567606603134;
        Wed, 04 Sep 2019 07:16:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567606603; cv=none;
        d=google.com; s=arc-20160816;
        b=Y1fxwCqSw7lSVTTzxpwqlTmOwdbVnJjyVGZ3Zacn8zq6QQ6+l7Zu8te3Nn7iTkIhCv
         vKRlWJ9OrLdCrgCtaZbkpPeloLyGUMuKYeLEEdwP7GiLWrIi/3JS7CTqrbYZAIQZO9ZI
         urX3kKBQSUTgLc9McG2h1qQZbikHxwXjnOWpgVg7KEdW5rV8jfGTmkCle4VBnV0WG2WY
         cmb9M/X08QTMQuvvSNX0QJx9dbV/tMRX/yF2ZmuM5dL/ZOmkqKHUqCEOhHQ3wojzK2f5
         akG0eplZlrbKL85/vrHEyxH35vu9NBxY0IY2HGMQCCids+eeRDOVVldt5YLYwzeFJoeg
         WCeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=POmoSiLWyAZnmHAICbI6ShBML6WBOiVnbYFq588ZgA0=;
        b=Tml4tB2DjuxxV/grxe1VK0z6kAylSW0bZfj8GYXYXRNhjwOOzaQaKRwC+Qmf9gxdgf
         H4I0w/q19e5zJ1435rU/wlax1lndCfKnDTHhl0/Japfdo1krqCa5+1YzqqW1OChD+tSp
         RvXTGHhIhdm3WVPTIKjAtue/6+HhbfBIPujq+M8D5lH2jagAZehGlonCIvj7DETIRiyF
         XpegNWmEWxS0xfSp86iKToLBB01BEsZeytXqLSG9RX6LPCmH1Pjrp5532FhZlgAzU3yh
         S2Dl+/ooignhpM2FSibAoxUr+ycQ6XuTEI78uxY4Pm1WuuydYKT4oNy6tRdpmU66MqfZ
         4/HQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id z5si766661plo.3.2019.09.04.07.16.42
        for <kasan-dev@googlegroups.com>;
        Wed, 04 Sep 2019 07:16:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: ec6f2baf4842498f92829352c925dd9a-20190904
X-UUID: ec6f2baf4842498f92829352c925dd9a-20190904
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2114202653; Wed, 04 Sep 2019 22:16:40 +0800
Received: from mtkcas09.mediatek.inc (172.21.101.178) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Wed, 4 Sep 2019 22:16:38 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas09.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Wed, 4 Sep 2019 22:16:30 +0800
Message-ID: <1567606591.32522.21.camel@mtksdccf07>
Subject: Re: [PATCH 1/2] mm/kasan: dump alloc/free stack for page allocator
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Konovalov <andreyknvl@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>,
	kasan-dev <kasan-dev@googlegroups.com>, Linux Memory Management List
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>,
	<wsd_upstream@mediatek.com>
Date: Wed, 4 Sep 2019 22:16:31 +0800
In-Reply-To: <CAAeHK+wyvLF8=DdEczHLzNXuP+oC0CEhoPmp_LHSKVNyAiRGLQ@mail.gmail.com>
References: <20190904065133.20268-1-walter-zh.wu@mediatek.com>
	 <CAAeHK+wyvLF8=DdEczHLzNXuP+oC0CEhoPmp_LHSKVNyAiRGLQ@mail.gmail.com>
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

On Wed, 2019-09-04 at 15:44 +0200, Andrey Konovalov wrote:
> On Wed, Sep 4, 2019 at 8:51 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > +config KASAN_DUMP_PAGE
> > +       bool "Dump the page last stack information"
> > +       depends on KASAN && PAGE_OWNER
> > +       help
> > +         By default, KASAN doesn't record alloc/free stack for page allocator.
> > +         It is difficult to fix up page use-after-free issue.
> > +         This feature depends on page owner to record the last stack of page.
> > +         It is very helpful for solving the page use-after-free or out-of-bound.
> 
> I'm not sure if we need a separate config for this. Is there any
> reason to not have this enabled by default?

PAGE_OWNER need some memory usage, it is not allowed to enable by
default in low RAM device. so I create new feature option and the person
who wants to use it to enable it.

Thanks.
Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1567606591.32522.21.camel%40mtksdccf07.
