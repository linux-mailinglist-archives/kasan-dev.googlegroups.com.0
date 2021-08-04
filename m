Return-Path: <kasan-dev+bncBDY7XDHKR4OBBBFOVGEAMGQEMDCNYRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id CD2743DFD89
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Aug 2021 10:59:49 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id q63-20020a17090a17c5b02901774f4b30ebsf1523040pja.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Aug 2021 01:59:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628067588; cv=pass;
        d=google.com; s=arc-20160816;
        b=JNpcmwoMbiynLq5uQAeDOuS8+bNNauBEj2FhdT3NmkZ0sPP+EKAa4Tbj1uuuI8v88k
         FiFkdNOIt1wDrr5MKLo3sx1Ifr2NOqwalOWm74Td9IzWIDQqckTtIOKOkKYY7vtBx9gw
         KlDtS23eDkpQaaPkSThIEM+RRY0N03rbMX4x21E388B3ekar7JzC80mvcfiJpqpcwTHJ
         oBY8xos1VacXZatO3zFGDLvy0TTueOstam0qB15z2ihKUCsCyY28NWNNM/lWZcp+xGm5
         qdX0NtTfqOhOVxSwkWf49ZKmP+0VNnRkYYN+Xg25qkWyssCX9HyiWhnQ4e0raTuQZb/+
         qg7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=1q7ePSwIh20v1pGUz156i1DoAzuyL31b1S0vS0LE26s=;
        b=R7Gy8TTFtQbtH0XZpTfge9lXzDbqmCGvgLQ8yv5PPNMNv+3hloLs0Yj95KpemEtn9a
         u4pML6C+zJMPQy9YeznBRUSyhAOWqo6mgcB+bYr5cVyN81S7uVUknG+tJpODeeZwjSjp
         s1zJtSS7hNPiJOl3QUYNzCCFH4hhuZ4by2JJTcHxqeV3M07CDj5s3Fk5jdNKB10Bnmfy
         /Zud0/X3ySlLXOcuNyYpPXdl7mcWXsi/v7rTq5fjNb3ILtVZZmKG2qobFNr9RO0rVBTj
         3NPs8BAPvJSF0jVMoeuRvQw6hYLfoFW8YO79TM7w5EscaBGJhJ7zbRLF1NsyzZKhZU+Y
         5OWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=KZGWTiBR;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1q7ePSwIh20v1pGUz156i1DoAzuyL31b1S0vS0LE26s=;
        b=SMW/VHY9P7yPSMCvXbpuODSf2vgBlf9whSBGiMKGf2vfju6PMrU2QVg2ifvdDgRJ6I
         IuONhVRNYHNwsyU7qB4vBG4oA+giJxXGuYOAxl9/XPzibvVR66sm3m4zeI90X5r7dmja
         maqu3lZqvJ6v1FYMMmvJH73eZjdxkYYyHT4VXq5c1Y6XP00rCMlPCTC6BDme0V9Jrjf0
         rTfe+nqnBCrb/bk7F6cwbpJHCFfmg5i3CsefzL8RKqY35YXZSsCl/ecUSvUSUyLXBxCv
         Ti8CwaBQiSgY0YFmbLEJ49wDYfVgMCg4Pn3E7eVca44Irvy5jvQ0ANPpQl4I7nEMkZEE
         0dbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1q7ePSwIh20v1pGUz156i1DoAzuyL31b1S0vS0LE26s=;
        b=AMvKuQpAuiID+NsJKTNXV6qMj90mQY37rEj63oDtKlKAP9KUkVItKNBzeOK2vxOkdO
         66nz0Mug2so8esquSc5Q71wRtxw4627ol9HbuUBh8t53+o9sTLhaJgeOlJvDTWb7/rFt
         MoFjYdq01Mgt9i5XQsbed6QsUMxXCxqgFx6wIQazYeFTC2AI0P6WmnlSdC4sGoTk+9UN
         /iT5xY2XkWNsciobnza+uhVU+ZUX8/+G9xumFnIMffYx+lEF1fiPMXeDM6MINh1KKWab
         j6YfDcFlym4qUfqS6PSGT8hvEseeqhngi6Px8vh8IzMO3oIDg8OvvBAk40BSrqHqG5WC
         vEcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531J4ggafCpatjtJghm6nLcy5VUYGiCHTt+Drip2XDoffOToBNjx
	z5zCv8OrUo7fpR6INDn+McQ=
X-Google-Smtp-Source: ABdhPJwmG4J2agAlzennjNbozXJWwNAMx3ZAIHrCaTpzk3E+oeouAfEObprngugb/pwjEx1JdxsPgA==
X-Received: by 2002:a62:75c1:0:b029:3c5:f957:1ca5 with SMTP id q184-20020a6275c10000b02903c5f9571ca5mr439982pfc.4.1628067588485;
        Wed, 04 Aug 2021 01:59:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1e57:: with SMTP id p23ls801233pgm.3.gmail; Wed, 04 Aug
 2021 01:59:48 -0700 (PDT)
X-Received: by 2002:a63:e250:: with SMTP id y16mr236712pgj.247.1628067587949;
        Wed, 04 Aug 2021 01:59:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628067587; cv=none;
        d=google.com; s=arc-20160816;
        b=kwGErC0YjCWXnsc0thSyTqC1I0NHCNfnvtIf5RyGWi4zWHThx9LNevzzu/LsN0LV/Q
         7rgDI7kNWYx+a9yrRfBFGmKqKtKG8r5HcU73CtkC7U7OmYJdHD5vCIjD9cj8yUncQpqI
         Nka45rdS8PKnpelPwnhvtXexof3hgV7pZ1iuhhVbfmsAYl2963KixiETHYXVLqGGvuF8
         R3Giqh2gk04yd85y6xE501rN+j///hc09JEdiDDTDJP5kHGOnlqdqx3vRCIj26gT6gDd
         PEFKE8uVSi43e2aEwj7LmBND2GGJzEkUK/3Bf9l/VHTNSxLm5iAgzhx/Q4nWGeUM2Sxd
         QFsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=ZfWcoCPDwKOGCJtFhr1e1qhJiHIkyO0ox6qkE+5EVlw=;
        b=xTHNTcrUIHnUMzTThfTPUletvLpHvVuwCVkfRnYuz8vv49VEWprdhEMHGDNquaKZsi
         aZoJYB1pDlzpirpy0VCiuHvMH3XIiDTaJRKAx0Rc+4rF8ilzydlA7IgvyjFko998nFrR
         UtUNSP8lsHYjHT/JC5P01b7SnkzF0Kv2LAPukVoDrRxBxGoBWB+XVyiGljJP3PpKSWjO
         zV3M1a8ys4aY6pVCE/YUXT7jKSKELwvbxrs4ia+DL/4MY02N8Xjo0YJR0PF4rHHtJUhC
         R+wvKpIu2lI/qaC1VxyttDNoQpL/i0mqQ4+aGA2Hj0WW6ZxBLfvYlALUskIHH+zkDKlt
         bSwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=KZGWTiBR;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id x20si52803pfh.1.2021.08.04.01.59.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Aug 2021 01:59:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 50e3ba141ebf4269bd5d62aed36500c7-20210804
X-UUID: 50e3ba141ebf4269bd5d62aed36500c7-20210804
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1666230122; Wed, 04 Aug 2021 16:59:43 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs02n2.mediatek.inc (172.21.101.101) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 4 Aug 2021 16:59:41 +0800
Received: from mtksdccf07 (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 4 Aug 2021 16:59:42 +0800
Message-ID: <27f393ad9a926a96bfb9291b21cdd2a86ada2d4d.camel@mediatek.com>
Subject: Re: [PATCH v2 2/2] kasan, slub: reset tag when printing address
From: kuan.ying lee <kuan-ying.lee@mediatek.com>
To: Marco Elver <elver@google.com>
CC: Nicholas Tang <nicholas.tang@mediatek.com>, Andrew Yang
	<andrew.yang@mediatek.com>, Andrey Konovalov <andreyknvl@gmail.com>, "Andrey
 Ryabinin" <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>, Chinwen Chang
	<chinwen.chang@mediatek.com>, Andrew Morton <akpm@linux-foundation.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <kuan-ying.lee@mediatek.com>
Date: Wed, 4 Aug 2021 16:59:42 +0800
In-Reply-To: <CANpmjNMAw=rcp_V+G_vjRjArj+09AkOxtC+wUNs-e1RRvfQm6w@mail.gmail.com>
References: <20210804082230.10837-1-Kuan-Ying.Lee@mediatek.com>
	 <20210804082230.10837-3-Kuan-Ying.Lee@mediatek.com>
	 <CANpmjNMAw=rcp_V+G_vjRjArj+09AkOxtC+wUNs-e1RRvfQm6w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=KZGWTiBR;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
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

On Wed, 2021-08-04 at 10:41 +0200, Marco Elver wrote:
> On Wed, 4 Aug 2021 at 10:23, Kuan-Ying Lee <
> Kuan-Ying.Lee@mediatek.com> wrote:
> > 
> > The address still includes the tags when it is printed.
> > With hardware tag-based kasan enabled, we will get a
> > false positive KASAN issue when we access metadata.
> > 
> > Reset the tag before we access the metadata.
> > 
> > Fixes: aa1ef4d7b3f6 ("kasan, mm: reset tags when accessing
> > metadata")
> > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > Suggested-by: Marco Elver <elver@google.com>
> 
> Note, in this case Suggested-by is inappropriate, because I did not
> suggest the change in any way (you already had it in v1). I just
> commented on the fact that it's missing a Fixes so stable can pick it
> up and some clarification.
> 
> Reviewed-by: Marco Elver <elver@google.com>

Got it.
I will remove it on v3.
Thanks.

> 
> > ---
> >  mm/slub.c | 4 ++--
> >  1 file changed, 2 insertions(+), 2 deletions(-)
> > 
> > diff --git a/mm/slub.c b/mm/slub.c
> > index b6c5205252eb..f77d8cd79ef7 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -576,8 +576,8 @@ static void print_section(char *level, char
> > *text, u8 *addr,
> >                           unsigned int length)
> >  {
> >         metadata_access_enable();
> > -       print_hex_dump(level, kasan_reset_tag(text),
> > DUMP_PREFIX_ADDRESS,
> > -                       16, 1, addr, length, 1);
> > +       print_hex_dump(level, text, DUMP_PREFIX_ADDRESS,
> > +                       16, 1, kasan_reset_tag((void *)addr),
> > length, 1);
> >         metadata_access_disable();
> >  }
> > 
> > --
> > 2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/27f393ad9a926a96bfb9291b21cdd2a86ada2d4d.camel%40mediatek.com.
