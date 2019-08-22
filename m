Return-Path: <kasan-dev+bncBAABBP6467VAKGQEERXK4EA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B853988E7
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Aug 2019 03:22:09 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id s10sf2851809pfd.16
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Aug 2019 18:22:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566436927; cv=pass;
        d=google.com; s=arc-20160816;
        b=q6/URDnVMvWIV665pJmFLw5YblNxgxfiEq0hG7QpNbTTPw63tXXFitaoc2ZcjRV38x
         yHyAep4Mm9fFQX1ssC2jwiTGzlQIDmn+zz/ymu9QxRnRb7BSPFoGhPzJ81Y79+gMspFQ
         cy5rn0jjbuZd38URPqxWkJmdYb4dZpX4grECwctmgTnXmz0g4obIuuOW172gOIugN13o
         CwX+CDneKUUNNHBi1e4b86uXVKy3t1C1LkSbttdX2FP1rwZMeOmhtBHTqYqXzfIsjxT8
         13ukjIskAzSUHpm+WYa3TJuJaKRuMripbZwYET087ttkXnu12cwqXAG4vkvfcr8Llavv
         RbcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=xUGx2192LsvLUAQXAu+pVh6La3PL+aN3ceXJ+eE6RwM=;
        b=ZKKb/4iwtkwdOlzFDXxdotUsNpVQw2cBR79ODii6RifDj0LzM7Cn7ckjVfqnNZzZ9J
         hoVjPBlrSXyxGfOQaayvQc3tjXao8Seoe9BwKvIzVgQCp2/yDg14MAlBwieKHaobad4/
         bSI/A+f0wbIyeXPi3xFwz7qIOGHygLaODgiYai3/DppK0pgH4BoULrOggMRRmhKQpVpa
         s4Q+zQYi4m8yuoZsw1PbBihob6nLZ/Pz9hK9e1BKdXLzr2Ccln5ufHdaVcyPRV9S87EJ
         TGR5gnnFAkUA0ZIXrKrUdE6rsNyM6oP5SqepzhwwEIl2G6Bl5l8RJA6RrnVr2gJYSAnC
         eHWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xUGx2192LsvLUAQXAu+pVh6La3PL+aN3ceXJ+eE6RwM=;
        b=rxcYDiHN/1m/eEtMKPbxrEC+aUJ4KJ1cbDSDfj3c9pxNQN66SLuvihdFIdZdp7bPzF
         A7ldoyYgrOnsWhQPX1UzmWSeFuJBgLrPtouPGoXCz9zaPGkVXh2syho9D+j8RPLKznA+
         El4/Vw4BZZtYKI0iFNSj+0Bq4juMs7lv16ElYvAKO9lrI7Ja/xa4SS8TzOHpyynuZJ3+
         kISS1UJAjwBGdBsSrfNXK6zAagsxVMwWp7BevNFYaQndEOTD4k6yYss9NNHWf1AO8mpu
         UlqmwjJ7FYqC/qSLeiVq88bMBCDCq4JVphsd4GzA+JTsDpcNZzytiDRTHD5/LnwvjnWB
         qUKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xUGx2192LsvLUAQXAu+pVh6La3PL+aN3ceXJ+eE6RwM=;
        b=UThjJOjauhh4SAXfK0Jau988rhSRjncWv4VZ4tMOuMUIBgWgJAO6C2V8AfguE3TOhF
         ngVhQGrbit0UP9SkOKZzx+qid4uLCmd6V1ck1uVG2pidHxzoz3ZizRxiIBu36e10+8sd
         Ia++kg2WFZtuTuGei6VxPElgEiOv+DQ48V9XlHyCV05NScsYM00PUKx1+v9qRKzhuC1u
         qbE6HAcm9n4K20tIMFNUYzDUxR9pSBz4I8QFNlxu+gDLLdbh+U+yERkkOJFc0yoGchSb
         8TobRg5CPtzLJguWTZWCZKsif8yAeJKXgqzUpyPS6VZoJ13eZw8u7aAiVXXHj4dQmd0D
         rJOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWf+x3sRj3xX+iWmD9HAIDNc9SD1TV21sbXvZ+CS5Y9dqidH8fI
	60Qpm8PkM0sGzP1+wlamNg0=
X-Google-Smtp-Source: APXvYqyI8yj7M3wU0b81mIqbssarrgOkdTbWHRKo46kS/V0VfBJIWQcZXJO2Pm/clX2p05vMgRGL2A==
X-Received: by 2002:a17:902:e493:: with SMTP id cj19mr36248002plb.292.1566436927815;
        Wed, 21 Aug 2019 18:22:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ea10:: with SMTP id t16ls1048608pfh.5.gmail; Wed, 21 Aug
 2019 18:22:07 -0700 (PDT)
X-Received: by 2002:a63:d002:: with SMTP id z2mr32196826pgf.364.1566436927532;
        Wed, 21 Aug 2019 18:22:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566436927; cv=none;
        d=google.com; s=arc-20160816;
        b=JqHm7kInbQpSE1HTdc/inTSKmw5FGPC7GCeQr1hyv5hnH/Ew76luzFD3ZwsHFdhWpM
         cHrOpU2VVsHs6pJMRr+q33PGri3XqZjIkaPEUjT1Gi6l/EnkC8pWKGx4I/B0beK/40Zb
         XUvmSOy2tIrKZkWHjRCau9koa5zZlr6FAZg/fXMiT/3HX0Sy5blDswCb6kCnbGw4ak0e
         iyQvXCe26+yrZghdnOezVsi7Cqb2oD+f+Ztkf3cLY2BcqblgJ7WqQ++Da0kNxNo8ykQ/
         0Xrd5I0iKjbRd2JG5nO3eSM7FL2BJ6NrJ5xJP7Ro3XW9nbjDL2MDv0SOFcCBYI4y0BiJ
         XE9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=4zTXT8np2oEv+GXqFGZA51ND/MraAhQ+aSBA7OKvwwk=;
        b=rLVX8+NeDn4zVhI/P/sY7HduNM6xuv7b6t0oEmPYNiphJcrRgk0W4s8zqQv+qNkCjK
         /k/j5aNclnne2MsAaoa6o6mUPrs/2lZDSnF8fqMWDM7t2I5Dz96oHCsA956ibj5YxgTn
         xOImTEbHHgWMwVJpCVSSyObG0qQZqE5OeSVFfwaS4jq3KPcKM3JWMsgpdrGnQA+yA50G
         tE9aXitK1QIlCnLaUJComd6ekof3CCOviSNah7lq923y0/EVsf8xEOU84sP/94dqd3cr
         2/2RynCaly+oAAP2dXubkyjI3HO3IYBDltvoc/HmJ4dNqg0EgJ3Fb9UsuIhMD8PyhH5x
         kjCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id az14si15793pjb.0.2019.08.21.18.22.07
        for <kasan-dev@googlegroups.com>;
        Wed, 21 Aug 2019 18:22:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 2740e10b36dc499fa5282ce2d54ec53c-20190822
X-UUID: 2740e10b36dc499fa5282ce2d54ec53c-20190822
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0707 with TLS)
	with ESMTP id 1416285409; Thu, 22 Aug 2019 09:22:02 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs06n1.mediatek.inc (172.21.101.129) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Thu, 22 Aug 2019 09:22:02 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Thu, 22 Aug 2019 09:21:58 +0800
Message-ID: <1566436922.27117.0.camel@mtksdccf07>
Subject: Re: [PATCH v4] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Andrew
 Morton" <akpm@linux-foundation.org>, Martin Schwidefsky
	<schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, Thomas Gleixner
	<tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, Andrey Konovalov
	<andreyknvl@google.com>, Miles Chen <miles.chen@mediatek.com>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>
Date: Thu, 22 Aug 2019 09:22:02 +0800
In-Reply-To: <3318f9d7-a760-3cc8-b700-f06108ae745f@virtuozzo.com>
References: <20190806054340.16305-1-walter-zh.wu@mediatek.com>
	 <1566279478.9993.21.camel@mtksdccf07>
	 <3318f9d7-a760-3cc8-b700-f06108ae745f@virtuozzo.com>
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

On Wed, 2019-08-21 at 20:52 +0300, Andrey Ryabinin wrote:
> 
> On 8/20/19 8:37 AM, Walter Wu wrote:
> > On Tue, 2019-08-06 at 13:43 +0800, Walter Wu wrote:
> >> This patch adds memory corruption identification at bug report for
> >> software tag-based mode, the report show whether it is "use-after-free"
> >> or "out-of-bound" error instead of "invalid-access" error. This will make
> >> it easier for programmers to see the memory corruption problem.
> >>
> >> We extend the slab to store five old free pointer tag and free backtrace,
> >> we can check if the tagged address is in the slab record and make a
> >> good guess if the object is more like "use-after-free" or "out-of-bound".
> >> therefore every slab memory corruption can be identified whether it's
> >> "use-after-free" or "out-of-bound".
> >>
> >> ====== Changes
> >> Change since v1:
> >> - add feature option CONFIG_KASAN_SW_TAGS_IDENTIFY.
> >> - change QUARANTINE_FRACTION to reduce quarantine size.
> >> - change the qlist order in order to find the newest object in quarantine
> >> - reduce the number of calling kmalloc() from 2 to 1 time.
> >> - remove global variable to use argument to pass it.
> >> - correct the amount of qobject cache->size into the byes of qlist_head.
> >> - only use kasan_cache_shrink() to shink memory.
> >>
> >> Change since v2:
> >> - remove the shinking memory function kasan_cache_shrink()
> >> - modify the description of the CONFIG_KASAN_SW_TAGS_IDENTIFY
> >> - optimize the quarantine_find_object() and qobject_free()
> >> - fix the duplicating function name 3 times in the header.
> >> - modify the function name set_track() to kasan_set_track()
> >>
> >> Change since v3:
> >> - change tag-based quarantine to extend slab to identify memory corruption
> > 
> > Hi,Andrey,
> > 
> > Would you review the patch,please?
> 
> 
> I didn't notice anything fundamentally wrong, but I find there are some
> questionable implementation choices that makes code look weirder than necessary
> and harder to understand. So I ended up with cleaning it up, see the diff bellow.
> I'll send v5 with that diff folded.
> 

Thanks your review and suggestion.

Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1566436922.27117.0.camel%40mtksdccf07.
