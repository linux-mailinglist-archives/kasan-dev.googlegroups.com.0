Return-Path: <kasan-dev+bncBDDL3KWR4EBRBX4LVKPQMGQEZVLGD3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8146C694FB1
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 19:48:00 +0100 (CET)
Received: by mail-ej1-x63a.google.com with SMTP id ud13-20020a170907c60d00b0088d773d11d6sf8099341ejc.17
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 10:48:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676314080; cv=pass;
        d=google.com; s=arc-20160816;
        b=Iv2s3Ep1+Yw3Oxlva47cwUCTLrojdeJkXsEAmfm+ZSOAKgV6Z7XxIILxcjDxZ4vUZN
         lhOQftmm3CAB2dKQKpSNn/sxy1EpYIXBGcIFVollMBDgmSpYTaFeAesGY6mG1G3d5z4O
         Wc/UgXzRB2PhZ2Pwg79ySlAKOp5CnM7+7b1KUeO0WBSuv9uZQfbbmd3k2gQrKNz8mnHo
         xgE8hvQzB6qwyd+nftDS/K3UjrXKK07AXW97q57Wv4a0sDetxDMdClwXDQsFoSznU/uh
         woPQYXsUxjrfF9X4WFNwB/mz9J0EukaWXppdr+tIfODSSm7XPSY5XdT3X1w2cxF8vSFw
         W86A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=DX5wRKaX+rPq+sKVaHPyvV6Sql/mTsG5Ap5eibCyhC0=;
        b=GdHMbO/80qkYS3XLQRxUmU1ZWilPHj8kVL7PqXzCWniq5aHj2D9KsBC6Ko2A1fWutk
         MhBl9GqiDEC0nVyVC5JzQLRVJX1VekfQisOw5+xypesF2WwKeDBKh68WNvQWfAKe3Ect
         WVhRi44R/lVAxl8pa2DgYrqxgQVZidVZ7WtaHXx6mjtmvZCPxbQtce/+2BXBjWXKiHzL
         AVi9r2uWYWhQZ8aUZz6lCIalEG2Muk944GAOyL4kGqIIf+Nf9eoZY++e4uU2USx6RkXz
         GhL23IOCLnUKpXDKN9694ppfGglZ1VILTsRAW0RxQ2mLUkevVIA15sEJKubBc63w0YE4
         CYgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DX5wRKaX+rPq+sKVaHPyvV6Sql/mTsG5Ap5eibCyhC0=;
        b=B2O4KwomDHWbFIarjuecxWd3tGl4vDTib4SAcK1b3zzcCT8jUTJQ6wrSJpHgorehmH
         ZpY5ihh4ptwMjT1yoI93+b5YxBTwj8KCJoAwGDqwaSh1CuCxCHpfMAfByeYxyJt0CzaZ
         hDtkWb/YQHALVqFrxOdfVvomDuYuLBV8kswdYd3AXdVkpMeQqNJaqZPlX3LLKykbtqIy
         bk9vNW2Kc8nvv9pKRsIgdBP5d+NbppvlP69JnkSGBYh2kOE/NK1nhrypZmkSf3zu1ACH
         gzpltYKhI5Dj+QABb/oM83EkXmmiH11ISFpvJLT2i0Th74AfaImg6qJuNWjEobQX7Od8
         SANA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DX5wRKaX+rPq+sKVaHPyvV6Sql/mTsG5Ap5eibCyhC0=;
        b=Miu7WEUkMbyZt1uesmvneG3I6NlYXf2FTjWx9aNxjFI8pkec8LNC9ZwgFISd73qULA
         TPUhFvA3xIukz0jEZx4Icnu0KmHlvd00zbZ3q0grMQUyA63MdTPi+mtazWnvo03aqSFu
         Sb8JldBM5favwzegcK6kBr8R5kKxbHh68YA25hwaUGJjm78s2IZBVNC0IB42tk+0Gg0U
         5Ghns4z8FFfF+wLvhlJ2vtsc4RlKzW9v+MROkIXJfwTQKnoBBHX3epEuG16QQQY5RbL3
         d1/MaX8Ohrpix4YGV4F3ok3mE7OyoOG+/vkBHt5NfnR6xl3UrptYGK8gGYo4wNZYQTo2
         dpTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXo0zipV5P8rBPDlo5vWZPkXK+OhjPl3BHZldNBi88Pkvma7xl+
	yF/zZJmv+zBX+SVUs4TCbo8=
X-Google-Smtp-Source: AK7set8+vUw2DNK55EcpTUCus3/Us89jRnTqb7WFyPuRmnO/pdqLzgciJoVwfpZNeM+JefQIBnLleg==
X-Received: by 2002:a17:906:5a62:b0:878:1431:2d03 with SMTP id my34-20020a1709065a6200b0087814312d03mr8169ejc.0.1676314080013;
        Mon, 13 Feb 2023 10:48:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:350f:b0:4ac:d2bc:e0cb with SMTP id
 b15-20020a056402350f00b004acd2bce0cbls1877321edd.0.-pod-prod-gmail; Mon, 13
 Feb 2023 10:47:58 -0800 (PST)
X-Received: by 2002:a50:8d12:0:b0:4ac:b95b:f1d7 with SMTP id s18-20020a508d12000000b004acb95bf1d7mr7796454eds.15.1676314078433;
        Mon, 13 Feb 2023 10:47:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676314078; cv=none;
        d=google.com; s=arc-20160816;
        b=zbvVzx66ylZzxDhxzx750MIj2AfzayY2gbAGlK8jna2NYXZjaybIAmGQ9QDdtldGme
         fvPZSUxXrx0e7AKKTAIS6nTMMXlnBmhWGqKhr9muNmN5XCwYQpdbvU7TCE6WkTstSVlZ
         roqdb/dHvaypDZfkW1NzlXF5zr5SJER3NJCD8vmE2aOO6Z/CBqyMrkKKG2GvlW+gIwB3
         FmA4qB8zUZzSKgF8RfCFm4EaasdRAr+Ej8Y4cIVWsHe+S1XP33hWAHxD9GMdtzRQnU9H
         RQtCFo02gl4OTwgCh2iApk9TQlZeiBOAmdWD8qPZpBfuRc3REF3v2aWDAjj6g3NGtVSi
         YCGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=jJDmGVRHisD7Zk5+MGHj8DbE5N9qhAi9JCHTlG6fNc4=;
        b=plqZcmAhQYWG9vjNtxDZzOeRSgjjRppZ/Jgw6GsFlfgMXcmwRihTWyE4TgEsjeztiC
         saeXzZTgXiVt8ttAAdzSQ5j/DfsNAIzKqrKp6ceMhXv/u4dM2RYw/iwTFuk2q8hxxumA
         JwlNqHluViCqFn/P/KIxBLWtzWyVYY4LRz+RMYqupjIviDlptFrjHu4V2WRppZFjQHi0
         DcnumxlZi7kDKDbGswb1oHmNvtJraMtrXyqS/pv85KlidaWvLjJZWIYIfouBJQu/ZCR0
         1GXLo1UKasg+ZB2gLTpHeuvCWwulFrCH44p3VNvoRsjQflw0NceSFYIQtqJo0fheT9+n
         gzUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id b16-20020a0564021f1000b004acb5d81250si428464edb.3.2023.02.13.10.47.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Feb 2023 10:47:58 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 27989B816D4;
	Mon, 13 Feb 2023 18:47:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D7B06C433D2;
	Mon, 13 Feb 2023 18:47:54 +0000 (UTC)
Date: Mon, 13 Feb 2023 18:47:51 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Peter Collingbourne <pcc@google.com>
Cc: Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	"andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	Kuan-Ying Lee =?utf-8?B?KOadjuWGoOepjik=?= <Kuan-Ying.Lee@mediatek.com>,
	Guangye Yang =?utf-8?B?KOadqOWFieS4mik=?= <guangye.yang@mediatek.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	Chinwen Chang =?utf-8?B?KOW8temMpuaWhyk=?= <chinwen.chang@mediatek.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>,
	"will@kernel.org" <will@kernel.org>
Subject: Re: [PATCH v2 0/4] kasan: Fix ordering between MTE tag colouring and
 page->flags
Message-ID: <Y+qF1y4+8kQGaN6l@arm.com>
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
 <66cc7277b0e9778ba33e8b22a4a51c19a50fe6f0.camel@mediatek.com>
 <CA+fCnZfu7SdVWr9O=NxOptuBg0eHqE526ijA4PAQgiAEYfux6A@mail.gmail.com>
 <eeceea66a86037c4ca2b8e0d663d5451becd60ea.camel@mediatek.com>
 <CA+fCnZfa=xcgL0RYwgf+kenLaKQX++UtiBghT_7mOginbmB+jA@mail.gmail.com>
 <a16aa80c371a690a16e2d8bf679cb06153b5a73e.camel@mediatek.com>
 <Y+Xh6IuBFCYZhQIj@google.com>
 <Y+aMvBozFxma3A/q@arm.com>
 <CAMn1gO7Xw_txFx_XEqbDQHk5BSfQaLZjKi6=9rQzE=Wm6YMM7w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMn1gO7Xw_txFx_XEqbDQHk5BSfQaLZjKi6=9rQzE=Wm6YMM7w@mail.gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Feb 10, 2023 at 11:03:45AM -0800, Peter Collingbourne wrote:
> On Fri, Feb 10, 2023 at 10:28 AM Catalin Marinas
> <catalin.marinas@arm.com> wrote:
> > On Thu, Feb 09, 2023 at 10:19:20PM -0800, Peter Collingbourne wrote:
> > > Thanks for the information. We encountered a similar issue internally
> > > with the Android 5.15 common kernel. We tracked it down to an issue
> > > with page migration, where the source page was a userspace page with
> > > MTE tags, and the target page was allocated using KASAN (i.e. having
> > > a non-zero KASAN tag). This caused tag check faults when the page was
> > > subsequently accessed by the kernel as a result of the mismatching tags
> > > from userspace. Given the number of different ways that page migration
> > > target pages can be allocated, the simplest fix that we could think of
> > > was to synchronize the KASAN tag in copy_highpage().
> > >
> > > Can you try the patch below and let us know whether it fixes the issue?
> > >
> > > diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
> > > index 24913271e898c..87ed38e9747bd 100644
> > > --- a/arch/arm64/mm/copypage.c
> > > +++ b/arch/arm64/mm/copypage.c
> > > @@ -23,6 +23,8 @@ void copy_highpage(struct page *to, struct page *from)
> > >
> > >       if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
> > >               set_bit(PG_mte_tagged, &to->flags);
> > > +             if (kasan_hw_tags_enabled())
> > > +                     page_kasan_tag_set(to, page_kasan_tag(from));
> > >               mte_copy_page_tags(kto, kfrom);
> >
> > Why not just page_kasan_tag_reset(to)? If PG_mte_tagged is set on the
> > 'from' page, the tags are random anyway and page_kasan_tag(from) should
> > already be 0xff. It makes more sense to do the same for the 'to' page
> > rather than copying the tag from the 'from' page. IOW, we are copying
> > user-controlled tags into a page, the kernel should have a match-all tag
> > in page->flags.
> 
> That would also work, but I was thinking that if copy_highpage() were
> being used to copy a KASAN page we should keep the original tag in
> order to maintain tag checks for page accesses.

If PG_mte_tagged is set on the source, it means that the tags are no
longer trusted and we should reset to match-all. Otherwise if
copy_highpage() is called on a page that was never mapped as PROT_MTE in
user space, PG_mte_tagged would not be set on the source and no tags
copied. In such case, we should keep the original KASAN tag in the
destination. Unless I misunderstood what you meant.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y%2BqF1y4%2B8kQGaN6l%40arm.com.
