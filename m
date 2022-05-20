Return-Path: <kasan-dev+bncBDDL3KWR4EBRBR5CT2KAMGQEP44RW6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id B375252ECCD
	for <lists+kasan-dev@lfdr.de>; Fri, 20 May 2022 15:02:01 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id h14-20020a2eb0ee000000b00253ca8c5c87sf1732959ljl.9
        for <lists+kasan-dev@lfdr.de>; Fri, 20 May 2022 06:02:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653051721; cv=pass;
        d=google.com; s=arc-20160816;
        b=OfoXWhzrUhxvCY3k70Ldhb80RDkwHnoGj2bnr9A9dVS6AIFdMwBqbb08Anjf/WVj8f
         XguLKGWJWtkwTKDbNeKn9Vks0d8IKBndTtWgfkpJjIKtUgYqMYxDc2C7CLONxvX7G/2J
         TIV+bDYHA/Ps7RdnKxcZOK7zg7rJC5h5u7EwwmQQNGbYkFYSpS8ZkfmPATpzcmBpidc6
         pkf1ZrVp36l5eL+nspOt8hRlVanBt9SE2tNDrvO+f+ZmAJ9SUqQg1xF8ob3rPw6mhtgU
         15lomzGp+atKo9bW69PXTFAi3RiOSmJd1ERxT4/EUGzURkqwJlHEsk4UYWZKwg4cD9oG
         WGwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=iCmEkifdvS9cYu2wFnHsF8KrRpvsMhvhs8f7WcYrWCA=;
        b=vhF4S84lk+ObPZQ7rTnjH+4OS717abbBr45ch4QGv6/fIU7SeYBrIBBFXjlXCON2qY
         9SgODVGx0a9/19GLopnScK34LqOLASfyQYQ1VhWHvan9/hR4wM42GaqITRtNaQ3bU5et
         9bRPPLt+f8FUgF/ScSktSLIdnzvxxn6k949AjMoMFE8viHzzxb9KOLKBvyuemollcHjH
         iQZkz8/YftX0iNstMHu7QHMZnf8Q0lDEhNCdmhdn7IguME/yLJv+gRL9+IO6M9x3Twey
         f6tTvmkEs+ojM8xUEHOhuR97U/71nECnQI7S5YIX3zr6uWB7fqI0zbTuAG1jLKg3fbck
         1NyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iCmEkifdvS9cYu2wFnHsF8KrRpvsMhvhs8f7WcYrWCA=;
        b=asaaNRsjyrqMt18Ul9ar51iTq9yA8v/ESao/hpFxdNEv3J7fCctsQytHeWZxuti5Wr
         PVHC+XrHEA23/AWo1ZWCYaqLh/rmJbAhdn2ec3mbOCIXo+OykrIdJf2SK1JmuObIspt/
         HfZ0tFr+/qLrpO8kGaaUpp35mPEdSwzldt97lITRj8fWZlb9zoYYSr832lZ9EIBX9ERQ
         sCVkMEcYG4X+sG1mjycmq/VHu0zh/s+b2ytnFIgMR055MKdD/BEfZDruAKiRgNAqWPgY
         SY+PGNi09neTgh0kWy8gP/LI3pGQ+q7hleIXeQn8UqkbqcFsEiTLg3ohscn2DYJ9a6Am
         p1mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=iCmEkifdvS9cYu2wFnHsF8KrRpvsMhvhs8f7WcYrWCA=;
        b=2MAWGSxfsTkRfToZS/UMk1ca9+YIvon1x/lcFcqHQeiYd4DEKOrpEvy9ulquWN2ot6
         QSzda5TG5UzIaKFX0o7tgWrX9EGgnG8ci5Wdu7Iurbg8Lgi2jS79DiEsQv+xkXTkeoGt
         bBhgmMtfStAdkR416LBxtKeWw3qzijk2/kom4UxN4ZfD2snks2Iy1hKxLV/J5xKPnmTr
         Gq/oNhKxkfB3Qr8ScQnjx3mwhLJQ4ICqZQITf4b2f3ncPH5MFW59ghaA+fc3s+RMU+Wi
         /vypyEO5PDsxpulZUMctICNf3y5p4enCD8918+8fvrSAsWZLkNGRCuXSwVVcc6lNJFvb
         Pqpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532NJ34LB6Fq72guBUDZFuHT9YxAugHI0ED3/PN8mSSO/aJYjIuX
	MJi83fMxn6v0iUmiW1gg1Xw=
X-Google-Smtp-Source: ABdhPJzUo6gW9hHLVopKgU6V8s+y+Yr0vRvsSL4sHTdL5lY2gyHOxhIPDOihu8cF7Eb53+P0PKgJYw==
X-Received: by 2002:a05:6512:3047:b0:473:cf43:6d8f with SMTP id b7-20020a056512304700b00473cf436d8fmr7243687lfb.380.1653051719498;
        Fri, 20 May 2022 06:01:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als1321235lfa.2.gmail; Fri, 20 May 2022
 06:01:56 -0700 (PDT)
X-Received: by 2002:a05:6512:398a:b0:477:b81e:cb52 with SMTP id j10-20020a056512398a00b00477b81ecb52mr6947652lfu.102.1653051716088;
        Fri, 20 May 2022 06:01:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653051716; cv=none;
        d=google.com; s=arc-20160816;
        b=HhLZTjM7JeWmDaKqunuVmzq359VbG013DvxwEKFKZg2VQTN4c2vxOrGTYHno5qRUJP
         9xUG3BzxWJGvfSUqht4RwnH0bgLxSsss417Xitl5bxXQpxrUCBn9Oy+JUEV7zrQELd7p
         ZyEm9JOQMi4OSVk4X96nwDz1NghUowNc7T6qLvtbsShWNtciErb8KbGliHtO7Uz9Knud
         9zbHhfDLwXPw638jivEzNIrGf0WRHzPoP905zT9ZNUMJTZc38CF/wmPSaX/fusODbo1P
         G41T6zEiJH8J48HkPyQZkaLHbtb6uiXFm2W0K/jAI1LM42ABEDInEBmhBVAEf973h4jp
         Da/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=uGPSYvDR5gVhqEIal4vChkKMO5ksGnVBqsDHbWwrhCE=;
        b=XehusAyiZa+BQSyBRMDPyJ7ccTNrGJY5p96jBgb1rA1hSSygGFGFRww4p2rO76HEft
         UGp4/bQm2fLLQk6oaMHF7apqqFDVtLlS4LQ74R7KhzPbzgG0fWGQUBVynFk4PL5NQRnb
         5ApfqX6DGBXqsw5+bHwXPTD+J5Jxu2cpv/SfZxuJ6BnT8b1GQVvi1riXOiC0FdD1DVv3
         1DxgIGwjElSmD+36naCabVfM5EaeNFD09er4vb9U+cwgFowDEU07a0sZ7LPuaEaCTal+
         w+DTzV6AjdDw6shhZq781wGuCld3kvCI7I4EJY7EdwofdlfZA7vyVvwYMsMbZF2816no
         p0VQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id m2-20020a0565120a8200b00473b906027fsi263337lfu.4.2022.05.20.06.01.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 20 May 2022 06:01:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 4E9CDB82A78;
	Fri, 20 May 2022 13:01:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 83A18C385A9;
	Fri, 20 May 2022 13:01:51 +0000 (UTC)
Date: Fri, 20 May 2022 14:01:47 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH 0/3] kasan: Fix ordering between MTE tag colouring and
 page->flags
Message-ID: <YoeROxju/rzTyyod@arm.com>
References: <20220517180945.756303-1-catalin.marinas@arm.com>
 <CA+fCnZf7bYRP7SBvXNvdhtTN8scXJuz9WJRRjB9CyHFqvRBE6Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZf7bYRP7SBvXNvdhtTN8scXJuz9WJRRjB9CyHFqvRBE6Q@mail.gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, May 19, 2022 at 11:45:04PM +0200, Andrey Konovalov wrote:
> On Tue, May 17, 2022 at 8:09 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > That's more of an RFC to get a discussion started. I plan to eventually
> > apply the third patch reverting the page_kasan_tag_reset() calls under
> > arch/arm64 since they don't cover all cases (the race is rare and we
> > haven't hit anything yet but it's possible).
> >
> > On a system with MTE and KASAN_HW_TAGS enabled, when a page is allocated
> > kasan_unpoison_pages() sets a random tag and saves it in page->flags so
> > that page_to_virt() re-creates the correct tagged pointer. We need to
> > ensure that the in-memory tags are visible before setting the
> > page->flags:
> >
> > P0 (__kasan_unpoison_range):    P1 (access via virt_to_page):
> >   Wtags=x                         Rflags=x
> >     |                               |
> >     | DMB                           | address dependency
> >     V                               V
> >   Wflags=x                        Rtags=x
> 
> This is confusing: the paragraph mentions page_to_virt() and the
> diagram - virt_to_page(). I assume it should be page_to_virt().

Yes, it should be page_to_virt().

> alloc_pages(), which calls kasan_unpoison_pages(), has to return
> before page_to_virt() can be called. So they only can race if the tags
> don't get propagated to memory before alloc_pages() returns, right?
> This is why you say that the race is rare?

Yeah, it involves another CPU getting the pfn or page address and trying
to access it before the tags are propagated (not necessarily to DRAM, it
can be some some cache level or they are just stuck in a writebuffer).
It's unlikely but still possible.

See a somewhat related recent memory ordering fix, it was found in
actual testing:

https://git.kernel.org/arm64/c/1d0cb4c8864a

> > If such page is mapped in user-space with PROT_MTE, the architecture
> > code will set the tag to 0 and a subsequent page_to_virt() dereference
> > will fault. We currently try to fix this by resetting the tag in
> > page->flags so that it is 0xff (match-all, not faulting). However,
> > setting the tags and flags can race with another CPU reading the flags
> > (page_to_virt()) and barriers can't help, e.g.:
> >
> > P0 (mte_sync_page_tags):        P1 (memcpy from virt_to_page):
> >                                   Rflags!=0xff
> >   Wflags=0xff
> >   DMB (doesn't help)
> >   Wtags=0
> >                                   Rtags=0   // fault
> 
> So this change, effectively, makes the tag in page->flags for GFP_USER
> pages to be reset at allocation time. And the current approach of
> resetting the tag when the kernel is about to access these pages is
> not good because: 1. it's inconvenient to track all places where this
> should be done and 2. the tag reset can race with page_to_virt() even
> with patch #1 applied. Is my understanding correct?

Yes. Regarding (1), it's pretty impractical. There are some clear places
like copy_user_highpage() where we could untag the page address. In
others others it may not be as simple. We could try to reset the page
flags when we do a get_user_pages() to cover another class. But we still
have swap, page migration that may read a page with a mismatched tag.

> This will reset the tags for all kinds of GFP_USER allocations, not
> only for the ones intended for MAP_ANONYMOUS and RAM-based file
> mappings, for which userspace can set tags, right? This will thus
> weaken in-kernel MTE for pages whose tags can't even be set by
> userspace. Is there a way to deal with this?

That's correct, it will weaken some of the allocations where the user
doesn't care about MTE. And TBH, I'm not sure it covers all cases
either (can we have an anonymous or memfd page mapped in user space that
was not allocated with GFP_USER?).

Another option would be to lock the page but set_pte_at() seems to be
called for pages both locked and unlocked.

Any suggestions are welcomed.

> > Since clearing the flags in the arch code doesn't work, try to do this
> > at page allocation time by a new flag added to GFP_USER. Could we
> > instead add __GFP_SKIP_KASAN_UNPOISON rather than a new flag?
> 
> Why do we need a new flag? Can we just check & GFP_USER instead?

GFP_USER is not a flag as such but a combination of flags, none of which
says explicitly it's meant for user.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YoeROxju/rzTyyod%40arm.com.
