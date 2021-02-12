Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPWZTOAQMGQEOG64UJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id E02E631A66E
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 22:01:51 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id y18sf433183otk.2
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Feb 2021 13:01:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613163711; cv=pass;
        d=google.com; s=arc-20160816;
        b=GAcUvjTZ5DlcJ5WuwxcjWtNhEw1AzOXhLdhmxpK1E3xHjCXUx1kX8TvfTpEHBW7irx
         d96L3HKsUrjiFOB4phBStNkgcaYe0fKBgMp1A6zcS4e0ghFXP/NnbnKhcnYiqN+hZeOu
         pnXUBvt0MRRZkN91CukhEe/UKs+KtribPzepexuyWCoGYtPc6g6NZwWu2ezXRHPWuWEY
         rGmyX8agRkvnEds2c9etzgrkZYExCdmD2ExPk6Z2fGYy0X4pQZX43G2wD+9l5OcaXB0J
         qX7sxIAXAK4CIe3PyHUv0O7Gdt0IX2boaepxBUuHY054G6JLoBSK5ZX10VjQezczGnIr
         qGyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jOp9XuAJeuU7rv4Jrp6ulDhW01ftvBAhsNbVj3Uxc3M=;
        b=bK1usM79iis8eLF/BZRdIQ1wd19XwnWCimyKUc7KFuMLncNXJqhVSTJsOLaNImI4L7
         aDVeZ6MFc8NxHPxjPlpenkMiBBWmf5uhIkAsVZM5BCbXfVKFAqepmnPhwNiPIcOgLXDD
         +SDUqboHAA9K6u6S7hKE/y2uogrhiePIgBeYKRSAq8VDjvwEg6bwsooiqWTxfh7JcOUE
         Z7/AoYOyBXWdEaXDQMt7Ta35pxI6vTlEv0CJXWbM+t17DIxBqhQ2WR08D3OK+5BiR7+4
         y0XucVA2jIG0jX7XDgAM6GRQdv/VPmvZOot1ZHT54uzB9dVWvyfDDyXZI3ckSCi5KTgH
         LNBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a7+YT18o;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jOp9XuAJeuU7rv4Jrp6ulDhW01ftvBAhsNbVj3Uxc3M=;
        b=i2DGk2pZTRjc4yab9aBFwYTI1vyS/Z577SqRqhWKMqPTp1TrdwTrB6eZDmwoBS992V
         NMgzf552uhhS+epn26Ezb4ko/iYpHwH7+CA5SDlrfa0WqsKCoMDsNBiteZaR8I/Kbp/I
         I/t5fg3Je4SC3yDWnlcrkhjNZhwgXRGwvXFW2oYV6LscodsQxKFtbzF9AanYD2HBio1T
         UlAxyyjqRUy01BgVzFQ3cCBJfNJISa56D4N9/WvHX88t6wEVjl+jkHyxk2Y/5jB+GZSu
         gUQtVaXjaHqsQMfTV8mFe7Zf089ZJBMo9qGMMjEXWh+9GuQLQ/5hGfuHTqbO+0MOaR7C
         F44Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jOp9XuAJeuU7rv4Jrp6ulDhW01ftvBAhsNbVj3Uxc3M=;
        b=aIj32uN8l1BKA3KJbdeSndUGF749KNTvPo25Kl0F/FUE83k6UykA0IPycJyOZ+dNkL
         EoIXjSkpH04c+k+AElNyfr2FTzzV1rxxKzTKhm78sdkcqX8nkAgYBLYtR3n15d3mxDPB
         nqYXXHzP1R6ieScGPgOoComLkUI2D7sV6GGwFpW5kuK6dnZHGZdP+NI8qezCjX6wQipy
         MOCitEgg6tJWRHn5r0Kcv945XoQ15ct9o3Yoc+HLjQdRG2R7rYGBCqerjOtlHI29F/4H
         g+vTq7yStTnRvNGmaE+9+POrbcqh4APKkE5Ar2kZeZfsw33wXuBkBgyDFPc0Ul/Auund
         6quQ==
X-Gm-Message-State: AOAM533fjaXkuQtQZ2t86UGrIXmqow6IPrHlq93nhOgk8SLwW2t+aiS7
	vwqmR1NeuPghVcGrXZlWrUA=
X-Google-Smtp-Source: ABdhPJxcTpdbgY1bLMnPPH/xZHrhvnWkrz7ZB+tV2nuVE+ewN+vwdRqPqIl+ZxGT28yl2U5y9b2qyQ==
X-Received: by 2002:aca:acd3:: with SMTP id v202mr945811oie.107.1613163710959;
        Fri, 12 Feb 2021 13:01:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:734a:: with SMTP id l10ls148164otk.8.gmail; Fri, 12 Feb
 2021 13:01:50 -0800 (PST)
X-Received: by 2002:a9d:411b:: with SMTP id o27mr3456861ote.0.1613163710658;
        Fri, 12 Feb 2021 13:01:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613163710; cv=none;
        d=google.com; s=arc-20160816;
        b=f61wIvbuZMJT+3GNbr4Uocst9EZlKQdlaZNMHSDbCugNir6zC3rUcBr8dX2mvZudma
         QdLlM3xe0Xs8MU8MosoWTasUSdIPhDNy+bi7BT0CeItYmNQ3az2JEAMw5/h62v1x/ZwT
         rU8z6obuJG+7ve9EzrJSUUSjFuaUoJOPVXxn+Gk5ZmI/hzEDj0x54fmzGemn8UMC+CZD
         +ci0UNTe+HHF2UUFpm3msqXQWESI3s3xJ5t1IdGxtvZeUNkI4Zk9xENrHj/9lFZxrNeE
         MrO/VooFdGaUISpnWytk9LAoD71s3sJDB3zMSK+kGPkeHk9mlkhDB11u0Cgj8mTO5JJg
         cIJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NT+Vr+SuI/IQr/HdheHFCPYtSKxGIwwJN+vDof64o90=;
        b=1HOgfRkxY2f8D9EUVxz38JL16ufn2F5tg+/NoEWnYicy3yUgR8i2NeJFVtKrg8QlPa
         +hKp30ij3LGy8/W6SGwJy+JvtHQ6VTNGP4Dkzq13Um7ESyTIExaRsX50Yxy/Vohi7/mb
         T2EDP5dM2W5m+OQDVFt5JP0rRY1UiiFiIEIj3SpJXjCS6ip85pFBGoHi5q2WVz1okH21
         iyUTcUbS7Tl4Bcbu2aFE64zj4vuFzAapf7+t8141EFjngnnvQmGITrtvVtAqmCROhDJy
         NlPpAuoM2YKRYhS1ddmF6wIaO5a7JOpUmvuRHH9ZTJFuBQTIarStDTLD/dMGdhi569Pk
         Whbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a7+YT18o;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id g62si787502oif.2.2021.02.12.13.01.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Feb 2021 13:01:50 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id k22so479932pll.6
        for <kasan-dev@googlegroups.com>; Fri, 12 Feb 2021 13:01:50 -0800 (PST)
X-Received: by 2002:a17:90b:350b:: with SMTP id ls11mr4351810pjb.166.1613163709768;
 Fri, 12 Feb 2021 13:01:49 -0800 (PST)
MIME-Version: 1.0
References: <e7eeb252da408b08f0c81b950a55fb852f92000b.1613155970.git.andreyknvl@google.com>
 <20210212121610.ff05a7bb37f97caef97dc924@linux-foundation.org>
 <CAAeHK+z5pkZkuNbqbAOSN_j34UhohRPhnu=EW-_PtZ88hdNjpA@mail.gmail.com> <20210212125454.b660a3bf3e9945515f530066@linux-foundation.org>
In-Reply-To: <20210212125454.b660a3bf3e9945515f530066@linux-foundation.org>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Feb 2021 22:01:38 +0100
Message-ID: <CAAeHK+w6znh95iHY496B15Smtoaun73yLYLCBr+FBu3J57knzQ@mail.gmail.com>
Subject: Re: [PATCH mm] kasan: export HW_TAGS symbols for KUnit tests
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=a7+YT18o;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62e
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Feb 12, 2021 at 9:54 PM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Fri, 12 Feb 2021 21:21:39 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:
>
> > > > The wrappers aren't defined when tests aren't enabled to avoid misuse.
> > > > The mte_() functions aren't exported directly to avoid having low-level
> > > > KASAN ifdefs in the arch code.
> > > >
> > >
> > > Please confirm that this is applicable to current Linus mainline?
> >
> > It's not applicable. KUnit tests for HW_TAGS aren't supported there,
> > the patches for that are in mm only. So no need to put it into 5.11.
>
> So... which -mm patch does this patch fix?

"kasan, arm64: allow using KUnit tests with HW_TAGS mode".

There will be some minor adjacent-line-changed conflicts if you decide
to squash it.

Alternatively, this can go as a separate patch after the tests series
(after "kasan: don't run tests when KASAN is not enabled").

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw6znh95iHY496B15Smtoaun73yLYLCBr%2BFBu3J57knzQ%40mail.gmail.com.
