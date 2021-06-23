Return-Path: <kasan-dev+bncBDY7XDHKR4OBBL7JZKDAMGQE5QHA56A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id CE52E3B1293
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 06:12:32 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id x15-20020a170902e04fb02900f5295925dbsf363517plx.9
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 21:12:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624421551; cv=pass;
        d=google.com; s=arc-20160816;
        b=F9AWb0qkK0HfS/nnB7YdiWu05+Vd2fMHi07swUN2qqAKz4iozPg239Nnx7+J8cI0SG
         BH1NnACxq/+CQGGFhBnnfdetjBgn0UGouLqFtj10ve57MjvUbnCc7M66AovWJ9Nu55b3
         vnPo7jk4lJ6PI4ddD5hm0R/x199p3YR/+9u//DtoKuILCahLcrBIJPvx2/jKQ+BjqxfG
         sJ7QS+KwI+Zs+k/fzbxzPyap2ZQmXdv6mcTPThbYPWI+fTeHg9SRlhm5K1Sg/JoNVP6Z
         bqok6MbCG88mzPCoja5q1KKLyuo/rHKgBlpzMdZ6nlKL7L5XB2niamQo0fv3HERjgSM2
         5BHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=aJPuXUv7NWZ4NxL3bvDr7bYCeDJfo57b7XIUcmG6864=;
        b=IfYOCYBUg4jrMZaoB/wzFALzkyHG6eVNjpnaMMhLy0tIy0xih7dTNi5yK8yRyDEuaB
         nfh6DWQFuYPCNN6U5Q2bs+rWaFoNPaKKqxldI+kGiCIHHRfPZ+hvEDAO+TvBewMjUJeF
         5HNU+YzCjsPxLaEw299BU6I0LGyBFIZ+3Xox/PxXWU4qP6sHMouAbM+/EZYOtsSSVY/J
         M8jqsvJ5ZR6Q0Pad0CMb3I20GxmqgposIEeipJuOTS77RJ5ExTxiUpTUL6rDhXudubeG
         528ikn3iWwvEoYQA6IDuZIHkILuLdJXH/KMvu/eoxeSUwxovpeSH2aFj9WilqvhISrbE
         5EHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="rEs2Lb/b";
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aJPuXUv7NWZ4NxL3bvDr7bYCeDJfo57b7XIUcmG6864=;
        b=cbuYhe1y1cfBAYAB+bea5UUHy3P++Cz4hxkfhGQBhL/ZxLeseg646Gru1+gwVA+VbV
         b6ljUCHWo2kAs15ZURs+NEdVCUZvPlHhmzv4QqS5i9vAXvURSKplBeQCvVaIxs8MznD5
         pb+T8s8592wFRoc7BkRkK0eZVKLsYo6NR6uvb/NEOJTdmgNQ6LJVr9U55trFCiHspI6C
         ZXE3zTxA1R0a0jtkGge1TYRrpUU8WCeZ5MEkSddnwbpQrV0V7Cm/R9V9HvbKBxgsN1M2
         zvr79uxK3MAch4hoUtyvhAPEXJ61VpFW/ItSxKKy0KArDj/xR4Pj2h6O2v2w+wU9d9Zw
         aocw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aJPuXUv7NWZ4NxL3bvDr7bYCeDJfo57b7XIUcmG6864=;
        b=qoajK4FvXA6/xlmk9+f5H32CgWIsLOVg5ljW5PHchrrUGrc2yVGsFGkyT3TRMQMkPl
         eTGrn3r4VINSwkEOiop4RqMO/sPbSgFTiP/Tp+VBX0ooHX9qo9c8X8o1Aam/k98jFopx
         gu7EqW1y3JIo1sd16g2G5K0h3AMyCQqt00ssZFAEz84fXAXykhpSx9aCYNAlDXxQ2ji+
         n0DtAQxx4lo79oH08R5arpYR27wb9UK28XHDHl/3F4Kdsc9Ho+0GqdUtKFeZvSrcBUhv
         Tgrj26Urlk94S97r1C/OTuazzXXF8Lmsx3feNUN0OEQ541G+Alcs4MINowYujQmkkMIF
         9yfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533HstQC9H7YFTdMjkU2n3ksdZc153PjuyWXwRbpN8n5LqpEGjpD
	40Mp95izn+XQnzWmr8Ppmbo=
X-Google-Smtp-Source: ABdhPJxurIbVhX4GbaND7w8OjSeDFjTaQ37KsEZJQjiECR5rT6S54nm4xus73Prn7fHrc4zI5aO0YQ==
X-Received: by 2002:a17:902:7792:b029:fc:e490:ff9f with SMTP id o18-20020a1709027792b02900fce490ff9fmr25314387pll.27.1624421551528;
        Tue, 22 Jun 2021 21:12:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:740c:: with SMTP id g12ls498384pll.10.gmail; Tue, 22
 Jun 2021 21:12:31 -0700 (PDT)
X-Received: by 2002:a17:90a:7c4b:: with SMTP id e11mr7627681pjl.73.1624421550976;
        Tue, 22 Jun 2021 21:12:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624421550; cv=none;
        d=google.com; s=arc-20160816;
        b=ec+9nz62sKpRc5vVhYGteacnMVzHwHQl0PfCnB5lui98HanHa62iTRrpxoyNfU2rrS
         mUrd/yEI9CS5eZZBSOq8O5By1v36kFBSRKCE7Y7MK7f6jfankFJ26QMpXeYiZVfRRM0Z
         hawH1WUGbilJLQ+aSxV0e1ae4SJb4VLWWliK3b4RQbOKzkIyL6GWhTs/Stc2K2NLoq5J
         9uAPrzbzL1vBI4anfZ00IVW5ur/cvL3QlnCzj3Lv+KgL0JN9vtnR0UfaVuxxQTXTdwBF
         AZIYShuT6Gk9uBivOepRNl9BkxWQqNScAPeSVntktTjj2l9+K0x+cLzf+lcx5yPwQU33
         dHjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=TBxfwLBKGn4+TI8Df5N7zNLI4LFZZ6G306I1NI2naDU=;
        b=lqi3uc4QwBsWSa6AMi/NVbKbSN0gTTuq1C5PVVFlULYPaHDvdl3lkjmTGPR/y7RY4c
         ccB0MDdQDtgm+5hABq0SnN42UcMt2a+u28NgXT63wL0pN3NeE0vy28k2h5Eu4JEIcZSd
         zCklgmu4vvIRfSINF23cscTO+BjXmBym4LFnXyhUj/NP7WQ5mByYbpH9CsfRZv6ONmMM
         nYR6KxI9IobubqWvQmW+vRqNtY8c/jJIl7iTqB7AZ5uJbFOyBvwh6ZcIWvRXRILM+Fd5
         g8CdS5sVyBXnGYyqYR3cDBqwxRa1OS2NpvUqezYfPH9eSup3AnYl7uP7X324yo9fYpFj
         YGKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="rEs2Lb/b";
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id o20si472345pgv.1.2021.06.22.21.12.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 22 Jun 2021 21:12:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: bfc18a5dc5c54696a76ab05f28b8c583-20210623
X-UUID: bfc18a5dc5c54696a76ab05f28b8c583-20210623
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1280553861; Wed, 23 Jun 2021 12:12:28 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 23 Jun 2021 12:12:27 +0800
Received: from mtksdccf07 (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 23 Jun 2021 12:12:27 +0800
Message-ID: <d75209622c3ffd9c2c9743c594fa5ff60d19a9fc.camel@mediatek.com>
Subject: Re: [PATCH v3 3/3] kasan: add memory corruption identification
 support for hardware tag-based mode
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, "Matthias
 Brugger" <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, Linux Memory Management List
	<linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>,
	<chinwen.chang@mediatek.com>, <nicholas.tang@mediatek.com>,
	<kuan-ying.lee@mediatek.com>
Date: Wed, 23 Jun 2021 12:12:26 +0800
In-Reply-To: <CA+fCnZcSy6LqqhbYfiC8hn16+T640uw_rnUzNPg1zsvg_RwYzw@mail.gmail.com>
References: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com>
	 <20210620114756.31304-4-Kuan-Ying.Lee@mediatek.com>
	 <CA+fCnZcSy6LqqhbYfiC8hn16+T640uw_rnUzNPg1zsvg_RwYzw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="rEs2Lb/b";       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Tue, 2021-06-22 at 16:54 +0300, Andrey Konovalov wrote:
> On Sun, Jun 20, 2021 at 2:48 PM Kuan-Ying Lee
> <Kuan-Ying.Lee@mediatek.com> wrote:
> > 
> > Add memory corruption identification support for hardware tag-based
> > mode. We store one old free pointer tag and free backtrace.
> 
> Please explain why only one.
> 

Got it. I will rewrite this commit message in v4.

> > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > Suggested-by: Marco Elver <elver@google.com>
> > Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Andrey Konovalov <andreyknvl@gmail.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > ---
> >  lib/Kconfig.kasan | 2 +-
> >  mm/kasan/kasan.h  | 2 +-
> >  2 files changed, 2 insertions(+), 2 deletions(-)
> > 
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index 6f5d48832139..2cc25792bc2f 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -157,7 +157,7 @@ config KASAN_STACK
> > 
> >  config KASAN_TAGS_IDENTIFY
> >         bool "Enable memory corruption identification"
> > -       depends on KASAN_SW_TAGS
> > +       depends on KASAN_SW_TAGS || KASAN_HW_TAGS
> >         help
> >           This option enables best-effort identification of bug
> > type
> >           (use-after-free or out-of-bounds) at the cost of
> > increased
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index b0fc9a1eb7e3..d6f982b8a84e 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -153,7 +153,7 @@ struct kasan_track {
> >         depot_stack_handle_t stack;
> >  };
> > 
> > -#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> > +#if defined(CONFIG_KASAN_TAGS_IDENTIFY) &&
> > defined(CONFIG_KASAN_SW_TAGS)
> >  #define KASAN_NR_FREE_STACKS 5
> >  #else
> >  #define KASAN_NR_FREE_STACKS 1
> > --
> > 2.18.0
> > 
> 
> Other than that:
> 
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d75209622c3ffd9c2c9743c594fa5ff60d19a9fc.camel%40mediatek.com.
