Return-Path: <kasan-dev+bncBCT4XGV33UIBBQW4TOAQMGQE6M42TPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0943531A689
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 22:08:20 +0100 (CET)
Received: by mail-vk1-xa38.google.com with SMTP id c69sf390738vke.14
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 13:08:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613164099; cv=pass;
        d=google.com; s=arc-20160816;
        b=kVsbFA6uwtuN82wib2VQOwsLs8pAq4u2kLtNOt+hMzsbiiDNlHJZcWP3E0uLYPKmbq
         nmM3HoIEWft/Wv/ZCUA9CNDBj99QFNdAu9FSW+VfPBjGVumyJPPlSCO7mMD51KaCqMp0
         SjeQaksDaKGVtgBirriJXwHvSMFyjMxPax+rsCc6Pmagv67nmxaci1rbIv4VdXhqY7ky
         XyFyKTs4YsQNJu8GT9TRIPFuh/q/atJMeDRRQyRBccpD+AZlUBT4XjB8/hWeYpBTqg+Y
         Sg8WJOzdisUjmODgp/LWCJkaaV8cZtKeOvOsalEFIcbZr4BUgfG6lm0le4Fe5jBCPvER
         ZxzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=F/S+MEOy2JhVLDGCAx8+R0Pna0rMaMgD5sDPx7oPC7w=;
        b=lfahsaxKfRmxSRWohpn56e7HnMaaVH6Mirblv6ErLmU8deWJGNLCkBqBRvALm3Re+7
         4P3HDL6L5v3S9DkDi83a7jChGRCTGoIu0slumZRIpggXFUNdAZG63BwCQZ3p55jcUJ9E
         i5LuKxkLSYYzsaSSDBu1UvVaqLpvdy7nf3+piLR9nJqRzdkWtgvm4DUR14/kpFw3H2Ec
         wGcshKWIZ59jubHTfY4y3wLaOfsn1syHygvcCkDNujtFG38K7p+CgVfthAevCxBNOOeO
         oyQic2Uf0udmY1A3G+t0D/2JMqsXM+i62EU860c2VHshmj9E9l0YkzV75HcVTV68jmyE
         HrCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=dU5l63E+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F/S+MEOy2JhVLDGCAx8+R0Pna0rMaMgD5sDPx7oPC7w=;
        b=jYB72E2EtBpJsguZVYHUfFuqtdwPB2D88kBAPsXRgYlZASH7YYSS0put2xokFtK9px
         A155iIrk8f6CzrFpQi2GVPw7xlfBPSUTdt8+wSYOGNkZYZFAKM5ZExWjAT4tLzhvleFH
         7NysSZySmI9uWG6rWYXa8fFs1EzquxZpBt97/HKIL4GCPoGdYmq0QBQECkWlvrcqsrJx
         hDZ6Oh07+G2r3N5Gq/tZRV5POgxcBZAySh2dleIS4YcpPkhEG35OBWhIbwv9va08NMfr
         nm3ivAaJ2Rwxe4/byYyeQ46oBvMplXP3BaYNClJeSJ0H4bCa7wcnHvcO7vbnTz7Ant2F
         eb/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F/S+MEOy2JhVLDGCAx8+R0Pna0rMaMgD5sDPx7oPC7w=;
        b=YqNP9vC/T/QMWI9bZF39fh9QV6nFnwajAyRS7Q6QTz7HcEM4cJi3peso2yjKxQAoG4
         Vsipcn8QmGn29HkvLUhfUZe8Ngcttwka53xoLZ2Xj4nrGAWvmbgWl1ZoYoEHVeItWZkH
         x+aRFgHuBbErSQLHplrJ+j9BaITO+UTYp9wZwpNY7UpZhiT+Gsy6Az6Q3MC6+EVB+0ue
         jfOX5WMUh2DrkU/PyOkp/OgZF57zgobh19tSrjjHPxLf/tlPOdLJyJjVXmvlcFSj74w4
         rYP3Lx3gf6jFh2ntHOkaA8+kh1k9PHZu+YoSOpHataTnBP2HUzQlsghbHebjHDGfMFvy
         La7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5319iseVtsQf68PDSx8aGP6GulZpznUcAOcyHwKRbo5cVP6p0uX+
	T6UDt++iVllgdMcaUJlpaOA=
X-Google-Smtp-Source: ABdhPJxJlXmyJjlP1jy0noFWlmiqysMU9lq0VXaUjOvqhRKHIu41zOeRnZF781l3zvM7nfNxPWbX1g==
X-Received: by 2002:a05:6102:22db:: with SMTP id a27mr3218126vsh.1.1613164098969;
        Fri, 12 Feb 2021 13:08:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2645:: with SMTP id m66ls1252262vsm.3.gmail; Fri, 12 Feb
 2021 13:08:18 -0800 (PST)
X-Received: by 2002:a67:8d42:: with SMTP id p63mr3123920vsd.55.1613164098524;
        Fri, 12 Feb 2021 13:08:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613164098; cv=none;
        d=google.com; s=arc-20160816;
        b=nAdooCwkkXABtSvOmWhMluZ5pTF8qoDMFSq3vGfRAi2reK5pCdhhMK65cxV2QwdcoN
         VFUiXoY5J+ixbeIEwMYl9ZdV5gRrwG8iWMUN/TgcprUdIQ//PYMO4NjDWihIHCRQzstj
         LhJZ75chjo8frYvOvSqc5YvbLMqoJNmpcq96Q6kwbpxieWeDLqMAldxRYmb934kXOnDN
         qBAhYRsiztV7OLzKhpDj+HlJIeG3M1f4nLBTqr7NO267jNo8cy2Pu4byUP/jBgZdf+/f
         EEF3+py9GkTLjmkcXw5/i5cFzhpQzLBzVbF79vwnkP6j/OE9x30EKg8cm5flAOPDFa4p
         oXYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=mZyKbkdDMu0MKT78PU74CX+OvPDtOK/WA93Ky3pQof8=;
        b=FuEvNgTpeRSPFmuRVN1tk1WLf5/S2gVLqHs73zmpdyGLbVfXC9bzxEcgynheNPP8U+
         u4y/QBx5AxLz/VFjkSKcYl1Jj/qFm9CeOodXmGbJR+EqJJvkbj8TPoKqg4f76tfT8PA0
         ZXvzMUmSILfci1wrZx6Vaw9y6dgpopk15HtR/7SyAgTgSrHLuXuPkGg3poIEjiB/LWR1
         BQvYRQs0TR7bHpjrx4v11OtBDLb37HxB/F8sbkL+lAlw4TLe6pMU2NkqJcVLJ6KBMMZZ
         NQTYo9pnMUfxLNVMYbFcsOg4z+bZjjBRMBvm39WZTVpxveSaoO0GAN0poEcCyhaz2Xu+
         cxVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=dU5l63E+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e11si604137vkp.4.2021.02.12.13.08.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Feb 2021 13:08:18 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 0CAEE601FF;
	Fri, 12 Feb 2021 21:08:17 +0000 (UTC)
Date: Fri, 12 Feb 2021 13:08:16 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino
 <vincenzo.frascino@arm.com>, Will Deacon <will.deacon@arm.com>, Dmitry
 Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Peter Collingbourne <pcc@google.com>, Evgenii Stepanov
 <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, Kevin
 Brodsky <kevin.brodsky@arm.com>, Christoph Hellwig <hch@infradead.org>,
 kasan-dev <kasan-dev@googlegroups.com>, Linux ARM
 <linux-arm-kernel@lists.infradead.org>, Linux Memory Management List
 <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH mm] kasan: export HW_TAGS symbols for KUnit tests
Message-Id: <20210212130816.cde26643a6b9b24007be4e54@linux-foundation.org>
In-Reply-To: <CAAeHK+w6znh95iHY496B15Smtoaun73yLYLCBr+FBu3J57knzQ@mail.gmail.com>
References: <e7eeb252da408b08f0c81b950a55fb852f92000b.1613155970.git.andreyknvl@google.com>
	<20210212121610.ff05a7bb37f97caef97dc924@linux-foundation.org>
	<CAAeHK+z5pkZkuNbqbAOSN_j34UhohRPhnu=EW-_PtZ88hdNjpA@mail.gmail.com>
	<20210212125454.b660a3bf3e9945515f530066@linux-foundation.org>
	<CAAeHK+w6znh95iHY496B15Smtoaun73yLYLCBr+FBu3J57knzQ@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=dU5l63E+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 12 Feb 2021 22:01:38 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:

> On Fri, Feb 12, 2021 at 9:54 PM Andrew Morton <akpm@linux-foundation.org> wrote:
> >
> > On Fri, 12 Feb 2021 21:21:39 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > > > > The wrappers aren't defined when tests aren't enabled to avoid misuse.
> > > > > The mte_() functions aren't exported directly to avoid having low-level
> > > > > KASAN ifdefs in the arch code.
> > > > >
> > > >
> > > > Please confirm that this is applicable to current Linus mainline?
> > >
> > > It's not applicable. KUnit tests for HW_TAGS aren't supported there,
> > > the patches for that are in mm only. So no need to put it into 5.11.
> >
> > So... which -mm patch does this patch fix?
> 
> "kasan, arm64: allow using KUnit tests with HW_TAGS mode".
> 
> There will be some minor adjacent-line-changed conflicts if you decide
> to squash it.
> 
> Alternatively, this can go as a separate patch after the tests series
> (after "kasan: don't run tests when KASAN is not enabled").

Thanks - it wasn't obvious.

I staged it as a fix against "kasan, arm64: allow using KUnit tests
with HW_TAGS mode".  To make the series as nice as we can, and to avoid
bisection holes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210212130816.cde26643a6b9b24007be4e54%40linux-foundation.org.
