Return-Path: <kasan-dev+bncBD4L7DEGYINBBUWGZODAMGQEEORSGEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 54DD73B14A4
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 09:31:32 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d22-20020a056a0024d6b0290304cbae6fdcsf1242310pfv.21
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 00:31:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624433491; cv=pass;
        d=google.com; s=arc-20160816;
        b=ulMBfUfnyuDPGVKeNcZ9GntaiPD86LTA/yQllN/oTntCMkQIsX+bk8p9Z5E6JmmzGY
         W//e/Rtfew9GIOIpTjQybRuBqhWYohhMjPnkRRf4dviesVfK3fkQq368petDJEAe2n3K
         VxPaKRwq+jUHnntLQD2Mi4GNNJBd+f+cVffqv0rJwIs5rFvWc8/h/Om3XmLiykUZnnVR
         rC9nAEMfmpQRsIHADN4BY5gG1sxiT3WTZRCmFj4iTntjkqMiAXIasK6mN7RlkacYRjvf
         dj1t05132l1+RnyEU8aVIqViwLyqbCUAeZpyiIuncs6F+Giw5epjigno5HSa6coUiKmk
         V+kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=Up7tB8VdRKOOFMSyJawvxc5YLQIsTn4jxlSEPfzIePE=;
        b=cu5SwapzYiTbv7/rojRlOYBqIPBmf0A3tCACbbVldM5BJ4mvs3LIXNFeqG75FkMonz
         KzJ0KTEapaU2ANFG4Avsq3hUEYMpLYs1b8JaeridMpU3ugY2zGck00gxZcIhI//Sk3c3
         ZJO4UOMn9D8QkCVAqfeY5PlkccAmfJ4izTgjEcwjPeHNPn4rte5yBCEWTEfdba1Ivg0K
         q7nTQ5JxIvnZYDcFn1DGzklYq0FYmyhzC1bImXN4j5hXJaVg1f1uJkE1ADgCnNzVrvny
         x1LUsaRroIV/TkNv+4dy2otYdahlRRi6/rVsRwCJHKaNiws6Rv5JlqHcqUgVDQGv1qj5
         4tig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=I6mxVaE+;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Up7tB8VdRKOOFMSyJawvxc5YLQIsTn4jxlSEPfzIePE=;
        b=esp3dM4hMGo0rPd690FGM81L4oi1RoAPHkHBzfK8thk+yUrT6FURz0wNlAsZwfN1es
         ed/cenRoP3VNa8BHYdP8eaq/nTW3YCO8PSJChE0A6lIUpogEnGTWbISkkdvDsDPlfggt
         7sX4ZH5da2+eCit0vLpTNXtqvUnDguVNzKsO3PVSR6L954JEYIqFK7MNtj1XXAdzalwH
         OgNQYq+5PuyU4d5GBsTpraDMxJC1LM+J5RUVY5/27rqoLtJqAyV20hp/hQJzlAz4SWyk
         dPIseFcTyqYFNCjtEQeZB8NDw2lKubHG6vB/rumWgNi3SY6d4YpFgqHABaDIsGjDf0MK
         fJLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Up7tB8VdRKOOFMSyJawvxc5YLQIsTn4jxlSEPfzIePE=;
        b=rCmWfMMlOa0vkYsCbqiaSSg/McgwugYKMD5ehj3LIbNot3VKtWi9V2yvgld0StsWcW
         CsTUBUqjt0xskxly8OQTKcqHCiDQe5CpWY+D02dRJG6SPHCyMwrFd0o6recOR6F+7tXA
         PCc2cbgLXIBdi1vc3Afj0WYSWmzMeg063EYUti0uxfymJdW0ndRC9ZYc6+YK3FCaFA+t
         v8ftT62yJ/coywat7/yJcSvhAdW/w+glfKrxvbKSCfDCFLqG0vLgJ39wQ62P1ajgVrJj
         Dum/U/G+DpSqEuN4mSQzer7ru42E3wTgNX/nYM69oD6GhOjfwhLiOtAoM5BIN6BMBMFv
         BmUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532sbN2+TDXDTSYiRkbKhjQW76oVztys+8EbM9x3Dd2CdJNb2ePX
	fiyiueN+pZfA7zIQgpf747Q=
X-Google-Smtp-Source: ABdhPJy+lCZkgkA8abzUuIWWBnM/Ll8PxhfADJJfxoJ+yc8rP9KoXhXb+Nj/h2hJ8P4ns6xtwx09/Q==
X-Received: by 2002:a63:1f43:: with SMTP id q3mr2652397pgm.225.1624433490929;
        Wed, 23 Jun 2021 00:31:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fa8b:: with SMTP id cu11ls907786pjb.0.gmail; Wed, 23
 Jun 2021 00:31:30 -0700 (PDT)
X-Received: by 2002:a17:902:ab88:b029:11d:20fa:8ca6 with SMTP id f8-20020a170902ab88b029011d20fa8ca6mr26184417plr.67.1624433490444;
        Wed, 23 Jun 2021 00:31:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624433490; cv=none;
        d=google.com; s=arc-20160816;
        b=RPspjr8TbNEvnrYEcefg8IOs1CzI625j3gEd5FUzelHHgYh2ywD/272hoJRPE50b6e
         vLhYEnXzwTZz0GEYtEROCI8LrasgSun6QJDy2QrXcekl0vtXKKTmKiW1rPJlds0sO3gJ
         KmwaUJ/+kwBIGe41zCF0Rq7aLsLZie4igN5lSKXWXpnZHdAOvWpRQG8GS9y7jRxEhF17
         vSYCKD6QH5HyuP5ljXz2SZCUXd96NbZCtscYTsmLUM4kE4l2ZWLbEdeGIeMUeCE1wEuf
         aXFqa9ncguEo+6ASATTysTYKq75Y719hRahp1RUAQQ0cxdEthwODh/namh77AgOBUFDx
         Gu3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=WaJYFsLLz2Mjmi3C64qa1RVI/b2GIwG6q2aJoTCrFsY=;
        b=Q3i+fUMvOeUI4TetcNeCWQXZWeXtVrFvExw4s9eM5Wv1RDsflAdL6hlLLjm94ZoPCX
         y0DiTdJoAauKxelJY/RplB42wZzdo70HtXGXmcgZhYQB3EIx9tQHsKVTZgoeNo+dnQmJ
         wxJz0vslDJ3W1t3tHzN3k9QMGJT10BmUPJDgm+bVLv8cXUSTF9wgzyG5UvmX4ddjYhGN
         TFIKMMxB9sIh+sT50IBB83YUen+z0CJVjrMPrYlfSvalN5Od+gBUP13oK+cv81oN8CGI
         gazlxqa22ZFJ6G0mW3fxbgkohzsYnLFsydEO3J1PKiZC5Mo2BIpar4BL64JKzplS3eJG
         jvEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=I6mxVaE+;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id f16si307190plj.1.2021.06.23.00.31.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 23 Jun 2021 00:31:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 0186910b791f409ea17c120dac1f461d-20210623
X-UUID: 0186910b791f409ea17c120dac1f461d-20210623
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw01.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 476945307; Wed, 23 Jun 2021 15:31:26 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 23 Jun 2021 15:31:24 +0800
Received: from mtksdccf07 (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 23 Jun 2021 15:31:24 +0800
Message-ID: <c874a47557ec256664e4cf0914a5e9840a335fe2.camel@mediatek.com>
Subject: Re: [PATCH] kasan: unpoison use memset to init unaligned object size
From: Yee Lee <yee.lee@mediatek.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: <wsd_upstream@mediatek.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, "Matthias Brugger"
	<matthias.bgg@gmail.com>, "open list:KASAN" <kasan-dev@googlegroups.com>,
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, open list
	<linux-kernel@vger.kernel.org>, "moderated list:ARM/Mediatek SoC support"
	<linux-arm-kernel@lists.infradead.org>, "moderated list:ARM/Mediatek SoC
 support" <linux-mediatek@lists.infradead.org>, Marco Elver <elver@google.com>
Date: Wed, 23 Jun 2021 15:31:24 +0800
In-Reply-To: <CA+fCnZdPwKZ9GfhTYPpWGVEO7bS6sSrh8cioZmRJet2maUjSVQ@mail.gmail.com>
References: <20210621154442.18463-1-yee.lee@mediatek.com>
	 <CA+fCnZdPwKZ9GfhTYPpWGVEO7bS6sSrh8cioZmRJet2maUjSVQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: yee.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=I6mxVaE+;       spf=pass
 (google.com: domain of yee.lee@mediatek.com designates 60.244.123.138 as
 permitted sender) smtp.mailfrom=yee.lee@mediatek.com;       dmarc=pass
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

On Tue, 2021-06-22 at 17:03 +0300, Andrey Konovalov wrote:
> On Mon, Jun 21, 2021 at 6:45 PM <yee.lee@mediatek.com> wrote:
> > 
> > From: Yee Lee <yee.lee@mediatek.com>
> > 
> > This patch adds a memset to initialize object of unaligned size.
> > Duing to the MTE granulrity, the integrated initialization using
> > hwtag instruction will force clearing out bytes in granular size,
> > which may cause undesired effect, such as overwriting to the
> > redzone
> > of SLUB debug. In this patch, for the unaligned object size,
> > function
> > uses memset to initailize context instead of the hwtag instruction.
> > 
> > Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> > ---
> >  mm/kasan/kasan.h | 5 ++++-
> >  1 file changed, 4 insertions(+), 1 deletion(-)
> > 
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 8f450bc28045..d8faa64614b7 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -387,8 +387,11 @@ static inline void kasan_unpoison(const void
> > *addr, size_t size, bool init)
> > 
> >         if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
> >                 return;
> > +       if (init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
> > +               init = false;
> > +               memset((void *)addr, 0, size);
> > +       }
> 
> With this implementation, we loose the benefit of setting tags and
> initializing memory with the same instructions.
> 
> Perhaps a better implementation would be to call
> hw_set_mem_tag_range() with the size rounded down, and then
> separately
> deal with the leftover memory.

Yes, this fully takes the advantage of hw instruction. 
However, the leftover memory needs one more hw_set_mem_tag_range() for
protection as well.

If the extra path is only executed as CONFIG_SLUB_DEBUG, the
performance lost would be less concerned.

> 
> >         size = round_up(size, KASAN_GRANULE_SIZE);
> > -
> >         hw_set_mem_tag_range((void *)addr, size, tag, init);
> >  }
> > 
> > --
> > 2.18.0
> > 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c874a47557ec256664e4cf0914a5e9840a335fe2.camel%40mediatek.com.
