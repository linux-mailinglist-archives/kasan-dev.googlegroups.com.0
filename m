Return-Path: <kasan-dev+bncBDW2JDUY5AORBP6UXGKAMGQEUY6LRNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 02C08534252
	for <lists+kasan-dev@lfdr.de>; Wed, 25 May 2022 19:41:23 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id a67-20020a676646000000b003376e0a052dsf3426921vsc.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 May 2022 10:41:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653500482; cv=pass;
        d=google.com; s=arc-20160816;
        b=xtYEHAI23rRG3iq9L1EjdnBTjUOvwENL6wlKvxPz5kWOpCKvBmZFUe5PiluIVtjJxh
         kl4EOQnglvTqFTHKCXhLHIkU9X4XbrrbzbyKParzxo67GuGe3Xr3V0XWxU2h0bel/KfL
         /OrwiY2hlpNpnTqWxaf36zSPW5mLl2ka8KbKkRguh9qXmWJcG9f1OyEizfAiz8d5oGZe
         f0t2n6kA8YReoBFrtHiYntDY/6Ni3NryhTKr+S9by4h8IM3nP3nSaF0oIyZ45GjUG+nY
         h+kzfCfRdAB1896clxfppV7rHoHRrsbyutt6WUITRp73goAbvcb+4v+tq9xkKRgHwV0y
         jFJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=4b5LDVYx2aobE5kjzDN4JZHxAL5O0AnfIT8P/HskS9E=;
        b=NZeeWS/zLrEB07+Y6dh/gfVXwYLVFkrvMtctmxOatuw/D63Rt7rCVpQ7Z7vzGagWYV
         YqIRrgJTd61l5+6jfP7/yoQoGhs6CWp9hOYiwjkSX45mhtTtGq/cTKjKXUkkFIrxfB3F
         eUFQ2Hm5U7eE010fxxPQYFGjosjGpcSptqB4oxeswSBrkZzDslO1Yye6/Pk89wQ2KE1M
         H2faX/p0m5eBOoiHzNhAAv7gVYmDsH54GqGfdRTBKGnGLm2SPxKeioDpGfTKFZP+YZQ2
         zhkigJhLvyT48e+7bXSVK98O6SeQ8eQj0c+qSobsR7Lto7S7nx+sxouSQQfud9z195i4
         Oq0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=pemBLcli;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::130 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4b5LDVYx2aobE5kjzDN4JZHxAL5O0AnfIT8P/HskS9E=;
        b=HoNip51rzz7mtN3C1u00Jnpq32qVFbKecwWPMv+6NlfNwsSbSq04pjdUGMJ5iWS5kQ
         BkuN3CKgRRNAfkAfsxN2wfQcwuK1HheMrjm1x2o9ziTJC5LxOAj+UqMSrBuo0OL7v0YZ
         X/0sKrztwJP253KJqrQi6lFU/ocjHgtqPO94O8HZ5Z0bf3EEgfScvhQcyAfkXsn7ADC/
         6v1PMJeNKjnibcrAGQwcasU9CgEiARQoH6JuNxn4KDmq17E2q4FNbSvAF49hWl7fXJ6Q
         sDPW3gdIPYLaBMFCniY5H9YkmaC5YLra28cCz98Ad9EBI4ECmkKiTDCQSmVHkY8kNUuM
         iCkA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4b5LDVYx2aobE5kjzDN4JZHxAL5O0AnfIT8P/HskS9E=;
        b=bKKtWoxont3aJ5rhZIJFIfSTOOXqfwAe4WZvllMeadre+ldFx+/+THb7NGwiimteHe
         VRhMJop/1NXUFTv/0igqwiWc6TkXGgELs3KJZPm3uDVyK8PDo13ZBJPMaIXCXNdeASes
         gskA9/IR0GsEJ2mz3pMp/JAP5cc7NamafuNQI1cDSKmJ6LF/Puu+R0v8l4dQ+6psmNue
         xZXLZfJgBNlw0wZJ9r1Ok/c/Mict10Y3vH+rWDYXTpdH43st7ODR+sv/Mm31PHvdMH/L
         AKOVj6pCp+qAt+75j9DrjD9+M5wLO7uHddsAeUDx37D67jjVO6JWkCT8MaCQYBVVEZ7b
         qhFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4b5LDVYx2aobE5kjzDN4JZHxAL5O0AnfIT8P/HskS9E=;
        b=smzIFHJgCTNYzlUqOpNv42vuEkO+DrD3u8emPJCyyeEihbyjqsuTGRnC/gWpdy7peG
         i2vjSL9802wTUJbPNpTfps3mb5Nu7la1hW9v1CPxN9wVcRxxX+qEZ+9MHY02afecXEcr
         gQHrUflCQbJDv9h8OHZntBFxj/ygomW1SdMMNiXUPx8cxcU9BSIqtV2VSwKb3nxFPDxy
         DZ/b+P+hX1fBO0Ft+0yKk8uuNVTQvzO0yOwNgPpxRxnMqNXHMX4M5Z6WNtLTLQp4eZA8
         tv3bfFeRk8/jwn2XEWjO5rcHI5/zutqSIzL0saBSL85ktQbbbssCK0o3AWc7kySZs64+
         S+2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531QKQ3LHq9KaWbnRh3VuGGYATRet0R86pKfNg70yvdeyvkQEQdr
	yDKW22SnkJdFCTtrdJVmbtg=
X-Google-Smtp-Source: ABdhPJz9dBnf+ZcEv/rFYGVBCJdrK/WN5FCUni6F7ZmL57ONOo/R0TqjJ43vKR43lTV4urtmJzdMpg==
X-Received: by 2002:a05:6102:ed4:b0:337:972f:61d8 with SMTP id m20-20020a0561020ed400b00337972f61d8mr9858726vst.40.1653500479854;
        Wed, 25 May 2022 10:41:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:42c2:0:b0:325:3637:6662 with SMTP id p185-20020a6742c2000000b0032536376662ls4111997vsa.4.gmail;
 Wed, 25 May 2022 10:41:19 -0700 (PDT)
X-Received: by 2002:a67:1c42:0:b0:333:bf07:5ce6 with SMTP id c63-20020a671c42000000b00333bf075ce6mr14205597vsc.12.1653500479355;
        Wed, 25 May 2022 10:41:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653500479; cv=none;
        d=google.com; s=arc-20160816;
        b=nZOHu3Dt7f/R2Fay194CK80fvUxP90ReFbHI/aohJi5+bPl9eIEcHYUa9XjCxhWSKF
         GWKb8dzf2qy+amoa8T9VD2fsp0IyjeSyuBKW2FmcbEdUL6VooSt2gBigfzPfphk07M1R
         PVsDvlr86qWnwIT/LjH6P1b0LBUZE6tI9bfN08oLZJOzZPgKgOU04TxbapdLqWZUgcSi
         PvCHr8E5bnHkIfwkv0rTU+u5pLBhdNF20QjL+y+ds2zKZLeLG6FCpWkzF+79ywIve/YY
         CHamQrBwWiKkv98vgbl6eYe3r8DmXXLEkfxYASdla8alywNeBOSxD9zLlqUPA0FsbMIi
         ZXBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SHh+F5QjRRXvKKbUW3PJK5nDgnCrKXzAfsKecyJT+o4=;
        b=HBUox4gzTLrgg8sRrGRTukozNOPf4Ns7QUW0G946QR2apUTYk3cof2OpgRUPlPcgas
         ZcJ7uTAkzOihbX6Odbq2zpUtoHwbmedYb+GkBlRz+rhhAfW/PYZws2o08x+t1Mp3tLpU
         BNhjrtnl8v2zNHkTkedX5Qhej9/4FMh7FIxPmcZt0Kmqz+Ud7GexncAlu2C2p20N3UxK
         DLw4RThcF7TTPMATi0jTRj/mWd+tYOkcbo2wxEjATTIrB7/4kiwH+2xoAclpWwkcwU7g
         Unwle5LorEZ+ICOVjfu1Q6AhNDE2B5orZg2xgbFfg9B0PGNqDfuUseOfQJsVYPdpTGHO
         viaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=pemBLcli;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::130 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x130.google.com (mail-il1-x130.google.com. [2607:f8b0:4864:20::130])
        by gmr-mx.google.com with ESMTPS id q11-20020a056102204b00b0032cddd78670si250468vsr.2.2022.05.25.10.41.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 May 2022 10:41:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::130 as permitted sender) client-ip=2607:f8b0:4864:20::130;
Received: by mail-il1-x130.google.com with SMTP id e9so9834077ilq.6
        for <kasan-dev@googlegroups.com>; Wed, 25 May 2022 10:41:19 -0700 (PDT)
X-Received: by 2002:a05:6e02:1be2:b0:2d1:5818:a454 with SMTP id
 y2-20020a056e021be200b002d15818a454mr18031573ilv.248.1653500478886; Wed, 25
 May 2022 10:41:18 -0700 (PDT)
MIME-Version: 1.0
References: <20220517180945.756303-1-catalin.marinas@arm.com>
 <CA+fCnZf7bYRP7SBvXNvdhtTN8scXJuz9WJRRjB9CyHFqvRBE6Q@mail.gmail.com>
 <YoeROxju/rzTyyod@arm.com> <CA+fCnZe0t_P_crBLaNJHMqTM1ip1PeR9CNK40REg7vyOW+ViOA@mail.gmail.com>
 <Yo5PAJTI7CwxVZ/q@arm.com>
In-Reply-To: <Yo5PAJTI7CwxVZ/q@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 25 May 2022 19:41:08 +0200
Message-ID: <CA+fCnZc1CUatXbp=KVSD3s71k1GcoPdNCFF1rSxfyPaY4e0qaQ@mail.gmail.com>
Subject: Re: [PATCH 0/3] kasan: Fix ordering between MTE tag colouring and page->flags
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Will Deacon <will@kernel.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Peter Collingbourne <pcc@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=pemBLcli;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::130
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, May 25, 2022 at 5:45 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> > Does this have to be GFP_USER? Can we add new flags to
> > GFP_HIGHUSER_MOVABLE instead?
> >
> > For instance, Peter added __GFP_SKIP_KASAN_POISON to
> > GFP_HIGHUSER_MOVABLE in c275c5c6d50a0.
>
> The above commit was a performance improvement. Here we need to address
> the correctness. However, looking through the GFP_USER cases, I don't
> think any of them is at risk of ending up in user space with PROT_MTE.
> There are places where GFP_USER is passed to kmalloc() for in-kernel
> objects that would never be mapped to user, though the new gfp flag
> won't be taken into account.

Yeah, those kmalloc()'s look suspicious.

> I'm ok to move the new flag to the GFP_HIGHUSER_MOVABLE but probably
> still keep a page_kasan_tag_reset() on the set_pte_at() path together
> with a WARN_ON_ONCE() if we miss anything.

GFP_HIGHUSER_MOVABLE is used in fewer places than GFP_USER, so if it
works - great!

However, see below.

> > Adding __GFP_SKIP_KASAN_UNPOISON makes sense, but we still need to
> > reset the tag in page->flags.
>
> My thought was to reset the tag in page->flags based on 'unpoison'
> alone without any extra flags. We use this flag for vmalloc() pages but
> it seems we don't reset the page tags (as we do via
> kasan_poison_slab()).

I just realized that we already have __GFP_ZEROTAGS that initializes
both in-memory and page->flags tags. Currently only used for user
pages allocated via alloc_zeroed_user_highpage_movable(). Perhaps we
can add this flag to GFP_HIGHUSER_MOVABLE?

We'll also need to change the behavior of __GFP_ZEROTAGS to work even
when GFP_ZERO is not set, but this doesn't seem to be a problem.

And, at this point, we can probably combine __GFP_ZEROTAGS with
__GFP_SKIP_KASAN_POISON, as they both would target user pages.

Does this make sense?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZc1CUatXbp%3DKVSD3s71k1GcoPdNCFF1rSxfyPaY4e0qaQ%40mail.gmail.com.
