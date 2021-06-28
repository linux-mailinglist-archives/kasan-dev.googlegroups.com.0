Return-Path: <kasan-dev+bncBD4L7DEGYINBBBWU4WDAMGQEWIFBRKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id E115E3B590D
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jun 2021 08:19:51 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id cv22-20020a17090afd16b029017071bb3b48sf208336pjb.9
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Jun 2021 23:19:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624861190; cv=pass;
        d=google.com; s=arc-20160816;
        b=x/qIooWZjS/J0DbvLp1my7HPH8b/MfRNfUT7YhfATpBVgooaQzMfrsxFuDm5uThW89
         9+c+OQWrPS8XtaDK7xEPnXdTk8FgFVSAkkNJsgc69h5CBi3MsMegHvdZAyUDbvugFaks
         TL9SVjvnGKtHlOt7hRJ3J4M0rITKuU6dbGii+45ZUwvCxDNU8EwBJoBdSqnvUyMrZNVn
         gZiO/UwAm4ebD5oJfvJ+fNmYAkkmmM85aGWUsfnU8lTioyid/tyk27LiKDIpsMlSmmKt
         KZNPtkZDJHfvoXsNvdfLqVoFxH3iWzJxbceRx6UHmv8HLAY/aK5KIh9rXWyIf2+vvjdb
         KOpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=STM+UP3xN9lvKBPj7DSY8BwWoNCMP0iim67R4LIyuxU=;
        b=h8SCHbgi4WR1VZ6w6WaXPsjN4GdXhIAdxtc7oFMs4n8Qf8X7RXFWS0ao1DbzjBemHe
         mDNL+mimdxkikq7F/CdnZmI4xeaes93YB8eAavpLqwPq9FnBBZXJneZMdnqrGmvzlJON
         lYHlYiyoQ5XTZcx5QuB8eIm7Wre3cLvleBDIJBAld8ukTIjJzeOE+C/aJu4652xS6PcV
         Gywwx/hy4z0CSDDLI78SX0D5b9pDZhhuZNp1jEmJWoHZbU83JCNSaZu/L8ygttQisQUL
         H2xwYKsgnjXCLM2lZsTcV+qviM+2gVLFYp3AcWMDvNnEuzJPPNte54qCB69YCOXnKOc9
         CIzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=l+etoZbU;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=STM+UP3xN9lvKBPj7DSY8BwWoNCMP0iim67R4LIyuxU=;
        b=nbu4s2PY0+n08CopBdv4lotZsPg4626URJlPtrVaSMz8zh5DH52rY+JXThL4hjLd5r
         diuQSofldByLHc7frFeilzz45oRZUQ4oHN/caGEQcse3VPE2EKKMe4Uop5VDgPEgroW+
         nCOKTcCWcWKaNNfQV4isLI7kuSwwUBEVDf3hfrlUFPY6e62VDVjWPSMwA/EX3Ak5wAF4
         G1COYMR3rQBu9d7pChtLjfhbOWlOONbCgF3P/a2CjOfRzzxEa+zViahSSO8l949k1bWD
         +lPT1Sb/zNIlvEooSc2ZXqP7nLxiQupPWcxEwi++louRcpWDzSG1PuQca9WtOsG4m2LS
         Ggsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=STM+UP3xN9lvKBPj7DSY8BwWoNCMP0iim67R4LIyuxU=;
        b=f8dl5HfyJsCw8zt7Lph2ofYeLtqb9YOuns/CTAMw1gKN+H6t73hwfwQQeTUAlDlI1s
         lmkSPWNXok2U505Jyp6DFb/oxZro6iy5OFRkXcbae9Kqg4ROMflXXsM7c2SufouZY3rS
         UO6FTG3Jn1EmGxi8xtz7/l9n+xBNzj8k0N05YMLo6+nJkDsEyoy7FEOHuDqsFHg2qtWp
         Miu2FkTl6bsi0I0aP7QSyv6e9vHZpE3Nn1QfI3bYxa+zYEFDhuFTiiNGetfQqAVhcGUR
         6rj/kx4pJrldg+7IvKy8ckLIaXr3Ma6nWdmOgK+Fd+HjFm3PeCOugHgAlCy1g/xnlW6D
         4kLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5309jyUUEWuJ7kEbtwITuVMR6gFLuX+2+aCSbcxGfmGPyhRdmbnF
	LeOJdeZ86QXogPtoSJQY/rk=
X-Google-Smtp-Source: ABdhPJzr0MoiU31eqk8p3OOQ8MAhk17QK+HlN/MqxSUdAtkXoNHSsmgNEhbBqvi6gx7QT6Q6Qqsg4w==
X-Received: by 2002:a63:5b51:: with SMTP id l17mr21618794pgm.408.1624861190341;
        Sun, 27 Jun 2021 23:19:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d14b:: with SMTP id t11ls10777879pjw.3.canary-gmail;
 Sun, 27 Jun 2021 23:19:49 -0700 (PDT)
X-Received: by 2002:a17:902:7244:b029:f5:2ffd:37f9 with SMTP id c4-20020a1709027244b02900f52ffd37f9mr21283493pll.26.1624861189851;
        Sun, 27 Jun 2021 23:19:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624861189; cv=none;
        d=google.com; s=arc-20160816;
        b=iRDgrqD1c+6INGtcPMGXn3/y+MBtq3Z0YwAqvqHM7zvdd0gQOSmAtXZEqb2EdLTrJ6
         YB9XQHLHmTHZ2WxlFdEHiEinmM2coKvWS2IVkoI3M8fWc9HwKeVSDiqlrDVs2kB9vUpV
         7+3NL/OzITD/12lalfFOICZNHm8ZlMfZW2az0CYIrwJEUaAbbPxPlQdTkQhYE0+Hzd9w
         KIa0ND4rQ4eZOaJhuaOuWJTGNLNa1RMiC7p11/vDiF3q/sI28efC1pPgSoA8UVHxsqEf
         Lqv6jlz5+lv33pgVZuETco0wu0SsZG3SPp0QlU2MujpFCR6cpGKbaLTa+tMjaXBc7ZOD
         2egQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=MoVeeFN8QQduQIE2H+ETIc4pO/33E9CcY+5cMgsP0BY=;
        b=tujGOOonoTiozN/jN87y2mej2irUffR6dGr8JxChMApTkk56keXo9/NUNG+jVrHLVB
         gxASeNvwwjBfaJHxqbgJFTPYLBAqH5TuJkPBkSTLirR9QMiW5qtJPXI36lhAThxrgI8J
         nutSOuJJAU0tF0Mx/kdFoswQP/a7Lm23dPRs4zSkkr5hyKlI7MyO6KAWObXGe1+OWd+c
         A4DxbpKJ2FZwvaVPjrfTcI95d7NE35RYiRDGiLoBww0aR0Yb+5rtNO7OJ+fvbmxBhJvf
         IHTp5lV0FKVTivEnVv0YO5ipKJuDw6hLEqiG92eSU2ayORyxtcuS7df04pfYajGCFmCb
         1vuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=l+etoZbU;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id u25si461912pgk.5.2021.06.27.23.19.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Jun 2021 23:19:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 6356ae1550ee45a3a444a23da326cc3c-20210628
X-UUID: 6356ae1550ee45a3a444a23da326cc3c-20210628
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 211629925; Mon, 28 Jun 2021 14:19:35 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 28 Jun 2021 14:19:33 +0800
Received: from mtksdccf07 (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 28 Jun 2021 14:19:33 +0800
Message-ID: <1147252f497e5529de8215486b184af649ac0a0e.camel@mediatek.com>
Subject: Re: [PATCH v2 1/1] kasan: Add memzero init for unaligned size under
 SLUB debug
From: Yee Lee <yee.lee@mediatek.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
CC: <wsd_upstream@mediatek.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, "Matthias Brugger"
	<matthias.bgg@gmail.com>, "open list:KASAN" <kasan-dev@googlegroups.com>,
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, open list
	<linux-kernel@vger.kernel.org>, "moderated list:ARM/Mediatek SoC support"
	<linux-arm-kernel@lists.infradead.org>, "moderated list:ARM/Mediatek SoC
 support" <linux-mediatek@lists.infradead.org>
Date: Mon, 28 Jun 2021 14:19:33 +0800
In-Reply-To: <CA+fCnZe0fng4-53U1=5MiYszCMi97twKut3eQNaNHgPV2HOVug@mail.gmail.com>
References: <20210624112624.31215-1-yee.lee@mediatek.com>
	 <20210624112624.31215-2-yee.lee@mediatek.com>
	 <CA+fCnZe0fng4-53U1=5MiYszCMi97twKut3eQNaNHgPV2HOVug@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: yee.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=l+etoZbU;       spf=pass
 (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as
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

On Fri, 2021-06-25 at 17:03 +0300, Andrey Konovalov wrote:
> On Thu, Jun 24, 2021 at 2:26 PM <yee.lee@mediatek.com> wrote:
> > 
> > From: Yee Lee <yee.lee@mediatek.com>
> > 
> > Issue: when SLUB debug is on, hwtag kasan_unpoison() would
> > overwrite
> > the redzone of object with unaligned size.
> > 
> > An additional memzero_explicit() path is added to replacing init by
> > hwtag instruction for those unaligned size at SLUB debug mode.
> > 
> > Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> > ---
> >  mm/kasan/kasan.h | 6 ++++++
> >  1 file changed, 6 insertions(+)
> > 
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 8f450bc28045..d1054f35838f 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -387,6 +387,12 @@ static inline void kasan_unpoison(const void
> > *addr, size_t size, bool init)
> > 
> >         if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
> >                 return;
> > +#if IS_ENABLED(CONFIG_SLUB_DEBUG)
> 
> Is this an issue only with SLUB? SLAB also uses redzones.
As I known, hw-tag kasan only works with SLUB.

> 
> > +       if (init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
> 
> This needs a comment along the lines of:
> 
> /* Explicitly initialize the memory with the precise object size to
> avoid overwriting the SLAB redzone. This disables initialization in
> the arch code and may thus lead to performance penalty. The penalty
> is
> accepted since SLAB redzones aren't enabled in production builds. */
Sure, will work on this.
> 
> > +               init = false;
> > +               memzero_explicit((void *)addr, size);
> > +       }
> > +#endif
> >         size = round_up(size, KASAN_GRANULE_SIZE);
> > 
> >         hw_set_mem_tag_range((void *)addr, size, tag, init);
> > --
> > 2.18.0
> > 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1147252f497e5529de8215486b184af649ac0a0e.camel%40mediatek.com.
