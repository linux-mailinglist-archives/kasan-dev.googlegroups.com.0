Return-Path: <kasan-dev+bncBDZKHAFW3AGBBY4S5GTAMGQE6U6GJHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DF9C77BD1C
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 17:33:57 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2b9da035848sf43202311fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 08:33:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692027236; cv=pass;
        d=google.com; s=arc-20160816;
        b=vP3hd5DDm4TTf4a99SL85SsCMyVTguuHG3yUKLHGLjm3Cg0mvvMkZSp/9f2/R7cwZO
         LZA4VVE5vSjxlO+QbfCAviHfRvSH/05FYQJ/QLmrXU5K0MiR/KX9c9iwKoCrZYYMK1wt
         iIjxZf7Hb1lJd/3sixsI0OFJ5P3qIzAaPUJN1NjWc96nE9Z4Az5Vd7Ln93wlKLm3P3C7
         eVOwMwm7dyOj1xi/TpXL2Q5RjYhp7deDmPG8Mdz9vUB3zBzZoaoC0ciADZs4TB3qKGu8
         mgzBMhQlr50CkBWM7U9TDUudX7PdH1+2DswkRoypuld3+siAL/a31u1FtV49dUdh8gAP
         xIZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ORQMZExaoLMkEVlEgvlZH5sZZ0kLY82MxsKgKWBBd/c=;
        fh=u/gF7ZyBGMmmo/UTc8bA1WEwOtMaWAUQBwUz8Vu+LGM=;
        b=RpgV++qBjwHRa/07ft7FTQtZ0RvicII+5TD24bZAUu9x2sHw9X3dapGsQzI06uhN9E
         4o50wVb68nEnmTdxSttIUcSzSPr8TTLZq+6TaGXdkcHmH4w7sK7xwcK/I8bawwedy4ln
         fMGa6ZnjmnaV6rNVE42Ryi1LHDrZvvCTWf2lHBQ/p4unZuoHHgtZX11LiVFn4HMxCitW
         zXUsgfj+s+FnTIZKCY+FkWAln0XPkglhNW07Dx3qucolppgao8hJMRT//j2e/ohyVIw8
         nUP4TFGmo0M6T6nFKmWqVdMkrSjgUL3xuySTv7rjrlotS8wVlCyd+EZ3XnayfnQuLGAS
         8+TQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=akFhWRIw;
       spf=pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692027236; x=1692632036;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ORQMZExaoLMkEVlEgvlZH5sZZ0kLY82MxsKgKWBBd/c=;
        b=YyAt5DBbhvUBL8zBBE/glocoFgVYrjjQV49EuLPtK24fAd5B7fC9NTZF0aMW1nO9St
         8jw3e/VKP7hvvSPf/MUfRAcrbuAzJgdsC9KmgOmBS/S2N+DCXSFrqUSLcXioN4lRC/eZ
         SuGdPrTTjvqVD7AGGLaUKolNuxAD34aAmFAMDLfNR/VGcr7zcTd6gvth/CNbsPiqKluC
         5Uprq45aFCWy4L/MDNAn2Dzd4ChVcWfpD9sggpesTgQ0T79teVVNxX+Zve59ey8BdNYi
         n8yUzjp+2Atcxeltkotd+Efbwf8ZfT1gW3c3AXx0nVDQ/vk876hr6JDJ+8giLlTQxy58
         /p4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692027236; x=1692632036;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ORQMZExaoLMkEVlEgvlZH5sZZ0kLY82MxsKgKWBBd/c=;
        b=kmEtVfRcKUil8YaDswFT6GV06M3Dz9sBsCRVzw1Me74UuK/WqKUMkWVx6Zju5jEP7E
         ct+OWg7YcqPVReoDzSr4OZ+sviaXf0aiEwBmjdrKPsQD6y2BHbn4mknjH7j7prfOrXog
         COP2adC7gtTSYRNNyHy9CsMdJYMcd3qo2jUl8wy2ZjG5lG/Kdh97Dke3NXnbysS6qjOr
         wzCnN2+1wC0T+CL+zucc3woEb0q6P0e+QmI88wCyjyS5hdKJ3FA0Ut2JPhK7zoL51gpk
         k30JgpJV439LJhwuRPmxZbR8AcuLDpo6yXArBHA+cHaNvG4HCJM2kOT5ige3Bo1iJM72
         hnlQ==
X-Gm-Message-State: AOJu0YxHwGhB+TLnFAW/7KexILpZpTVzMDwrh8W9AEb8HiXt5z4d6kF6
	zt2/dcigV8LQoNcZSSJIxrU=
X-Google-Smtp-Source: AGHT+IFPCGAnpjfaGrfT5u4Q1IaMIeSDH3LXBzl69kmX8+g8lZNPIxr62My29bn8zKrfJ1R+ot5nAg==
X-Received: by 2002:a2e:3609:0:b0:2ba:5ca7:230e with SMTP id d9-20020a2e3609000000b002ba5ca7230emr6438371lja.37.1692027235878;
        Mon, 14 Aug 2023 08:33:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a785:0:b0:2b9:35b5:8529 with SMTP id c5-20020a2ea785000000b002b935b58529ls364382ljf.1.-pod-prod-07-eu;
 Mon, 14 Aug 2023 08:33:54 -0700 (PDT)
X-Received: by 2002:a05:6512:70c:b0:4fa:ad2d:6c58 with SMTP id b12-20020a056512070c00b004faad2d6c58mr5595433lfs.61.1692027234077;
        Mon, 14 Aug 2023 08:33:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692027234; cv=none;
        d=google.com; s=arc-20160816;
        b=zlhBamQL2PgTlKCesgmQYK01RGhxzwRSvMHS5//WBwxeJJxp/13cx4nAi0BU4AvkKF
         FYnd0pzpNe02np+xgLxbe/HRdzZRTAZTyllU/Rk8BN/RXJmRIP5SYjPIFd1NEDe3rDEB
         YLaWExOkRG1ygSDgeYezSIShlw5rCY/gK4Cg1wnjBOUJEZpnO/92kX/nzkbf6bZzVdyy
         V9piFj14P/C4A1KNnhw5pMwVfN+Iib4aYeS655MwwnvEQiDqcdVq+7pKbvUI9rOJqYgX
         bKcu64sSxehXZoTBVOW6wUSVSxaK6NnHHAd/3n6CGAkGPGAimCN3GT4z2sZgCCBmPL4K
         +rvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=PQUYAWAb1k9Z/YmXHKlOUY17GrFAyEmuzFZMJMKUnBY=;
        fh=am7PL/OkltPhRBlSqiRNdvZyQXhf053wUWF7t3kZnH8=;
        b=w5vFgV6ja7325WFfic8PQNPsKVmkFofg8I/U5yReppM2X8FXVl6P3332QB/r3A5KBI
         bOTTTVQOY0MahZ9tYHZqDO7cbMOWILLqe7Xeuc4pLJCjGjKqJpYxB1JSCtTkEC7f1paN
         v0XVA8L+cCPWOTAeS2rQGbJpEXXHVCAHBm6IilSotOQ8BDcVmN5USFZqgNa4zVuDcqaK
         ujmkB8X9BWLSgfFeK3VG8Gwld5TY4MjE1mVXVhHqcRHGAFBgvprw46x1PbT0xkCd40wj
         lcm2N/McVEgPG+7POPMRiOIhebz0wrJtjTsmFVBalWEHixb6aRNwZWsrCKi8fBw/gI1s
         T0Zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=akFhWRIw;
       spf=pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id n26-20020a05651203fa00b004ff76606e55si172464lfq.9.2023.08.14.08.33.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Aug 2023 08:33:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out2.suse.de (Postfix) with ESMTP id 5B2311F45B;
	Mon, 14 Aug 2023 15:33:53 +0000 (UTC)
Received: from suse.cz (pmladek.udp.ovpn2.prg.suse.de [10.100.201.202])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id EE8C92C143;
	Mon, 14 Aug 2023 15:33:52 +0000 (UTC)
Date: Mon, 14 Aug 2023 17:33:49 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Steven Rostedt <rostedt@goodmis.org>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v2 1/3] lib/vsprintf: Sort headers alphabetically
Message-ID: <ZNpJXapjZcYqJqFG@alley>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-2-andriy.shevchenko@linux.intel.com>
 <ZNEASXq6SNS5oIu1@alley>
 <ZNEGrl2lzbbuelV7@smile.fi.intel.com>
 <5eca0ab5-84be-2d8f-e0b3-c9fdfa961826@rasmusvillemoes.dk>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5eca0ab5-84be-2d8f-e0b3-c9fdfa961826@rasmusvillemoes.dk>
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=akFhWRIw;       spf=pass
 (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

On Mon 2023-08-07 21:47:17, Rasmus Villemoes wrote:
> On 07/08/2023 16.58, Andy Shevchenko wrote:
> > On Mon, Aug 07, 2023 at 04:31:37PM +0200, Petr Mladek wrote:
> >> On Sat 2023-08-05 20:50:25, Andy Shevchenko wrote:
> >>> Sorting headers alphabetically helps locating duplicates, and
> >>> make it easier to figure out where to insert new headers.
> >>
> >> I agree that includes become a mess after some time. But I am
> >> not persuaded that sorting them alphabetically in random source
> >> files help anything.
> >>
> >> Is this part of some grand plan for the entire kernel, please?
> >> Is this outcome from some particular discussion?
> >> Will this become a well know rule checked by checkpatch.pl?
> >>
> >> I am personally not going to reject patches because of wrongly
> >> sorted headers unless there is some real plan behind it.
> >>
> >> I agree that it might look better. An inverse Christmas' tree
> >> also looks better. But it does not mean that it makes the life
> >> easier.
> > 
> > It does from my point of view as maintainability is increased.
> > 
> >> The important things are still hidden in the details
> >> (every single line).
> >>
> >> From my POV, this patch would just create a mess in the git
> >> history and complicate backporting.
> >>
> >> I am sorry but I will not accept this patch unless there
> >> is a wide consensus that this makes sense.
> > 
> > Your choice, of course, But I see in practice dup headers being
> > added, or some unrelated ones left untouched because header list
> > mess, and in those cases sorting can help (a bit) in my opinion.
> 
> I agree with Andy on this one. There doesn't need to be some grand
> master plan to apply this to the entire kernel, but doing it to
> individual files bit by bit does increase the maintainability. And I
> really don't buy the backporting argument. Sure, backporting some patch
> across the release that does the sorting is harder - but then,
> backporting the sorting patch itself is entirely trivial (maybe not the
> textual part, but redoing the semantics of it is). _However_,
> backporting a patch from release z to release y, both of which being
> later than the release x that did the sorting, is going to be _easier_.
> It also reduces merge conflicts - that's also why lots of Makefiles are
> kept sorted.

I am afraid that we will not find a consensus here. I agree that
the sorting has some advantage.

But I would still like to get some wider agreement on this move
from other subsystem. It is a good candidate for a mass change
which would be part of some plan.

I want to avoid reshuffling this more times according to personal
preferences. And I do not want to add this cosmetic subsystem
specific requirement.

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNpJXapjZcYqJqFG%40alley.
