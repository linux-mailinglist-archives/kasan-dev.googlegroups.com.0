Return-Path: <kasan-dev+bncBDDL3KWR4EBRBRMZTKPQMGQEQ2KJ67A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B0EB692558
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 19:28:22 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id bx20-20020a05651c199400b002905fdb439esf1784388ljb.23
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 10:28:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676053702; cv=pass;
        d=google.com; s=arc-20160816;
        b=DofWVcpl9A9U4Xn15md1A8+bydVS4Iud8wLD98Axh5xDI5WEdA3v32/Vn3yGD1LABc
         DOh8AsBovE9Ezq8tgOKV590X06MfBcdYROo/SatZQ73GA3IpxZS7LSxsfqInMi+XpHcM
         iTmbA49CVKzujE5EiUtCFXqmc9aafsgXwCE/MsuLEg981tB9GDlVhPRnjYhX123zYr7P
         o7XTBZrgahHsGGOa9SXOfmTkSJ/fkHPDtR46xhhQtSW2c/w9yE92yVe2fUXBn7vurRSg
         mkVKrvoEi5w95Hb+gg1T0ID+HsIAolAxA2RGKK5w36hSTFn9yWsO9iYL+DPxJ1fy18WU
         VkXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ftBDINKBcyCD4bzplgopasm5b4OCHErWoBlD53phGSs=;
        b=Ohvk85wbhAF3SDJmzcbWkA8S3iofi9c0ydcxZde2PtTeJtuadRQQYzigHW83XP4O++
         ulMVgUmqWkJMY4YzZ8kM0RuRgCJNuiVg2e3+L2wB5n2PC99zNlqLUBNqFyw+vSEyT1mQ
         cadEPEkeARuVK/C0RkjKLyte7VzS8/Q/+kIMm7yZaNnogx9bCJfuiiULI7ze3T4CwB8Z
         P7dB/4wEQ1dS1+JLRBlpYGKuuxLFB8+qPDzvbFSlW87MSkuuBA796K96vX/Yckn6860x
         iD8+pvH2AoXJJRlhKP2jjJqxcx82JHQEgNfFS08d0OtaB0E4cTK45WcULHdE6s9fGeoo
         B5tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ftBDINKBcyCD4bzplgopasm5b4OCHErWoBlD53phGSs=;
        b=KWnJa5u0972/Pm5T4OXHiYSqHTeyMWSWBBKwRlZQpY8umAXzIqaQ7kvGMJXFmeo9Mm
         Nx398LgkEegW9bbtBqFXPr1yAF26/H9KXK9Xevb+nGlCe+zfVZ5iRIXpiOZQ8dY9mtj1
         NXfouRe8blUN75Qk2DBQWAiw4QnXnQ+vGIfL0jkZb3UzvMYxTz2EqkG7c2BT9FCaJvvA
         DInhCOpx6+EdPjMTPZmTpkGZt9ahES3XbY4ptZrVZQLbBWg5H/YDvDrdJ7CQjfxYLQF4
         eO7ihMFAVMk4oSPsi+E8/9M1r+z6SDLRIDjbDBzA17L9tJTSAfHDxhoIEqABKzm6Jap+
         tVLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ftBDINKBcyCD4bzplgopasm5b4OCHErWoBlD53phGSs=;
        b=uDsY1foDyxEmZcgObVrOP3gV6AhFvzEfWKF6+EtSfr3QQG30MLP+qcBvgVP/9ZYYjf
         12dUNhMzqiPmtbvCwtU0+hYquU8jX9xzyKxMDlrPyeN9PBSwqGnCvflTzHeI3THMYf7f
         PTrIFZdeOAnm1uWM1fxQYkeK3/bkYNaG1oewzHPAxgBI08SLNLL7TU9IjygmSmC5eMBz
         Zf9/QXHD6Uz9jPr9XIyGOt/DQCkk/GRxqpjC/eijV+NsBk6I9xLxW+vg1Un2NkPWPkzz
         y8q/t1XO1K577fUUc81jTj81XNFDkOraBUmKkY07Yq0/ReLrhrBURf0vfw9k86NoFMhD
         TRDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUws0ODSpjaf2DYm1EPtL4bW3GLuhgwhnOgkb52qUj6uqACGJgT
	VYuX8waSF7+6PsyWYXzei+k=
X-Google-Smtp-Source: AK7set9lvdrUjF6mS4dz8BQP/EZb8vlVfazjjrhXmagNSQfD5S+C5jBKTmdRP7nGxWxhKW5+Wn5Thg==
X-Received: by 2002:ac2:55b7:0:b0:4b5:6dbc:b719 with SMTP id y23-20020ac255b7000000b004b56dbcb719mr2857113lfg.270.1676053701765;
        Fri, 10 Feb 2023 10:28:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a178:0:b0:293:32ba:16c6 with SMTP id u24-20020a2ea178000000b0029332ba16c6ls926735ljl.3.-pod-prod-gmail;
 Fri, 10 Feb 2023 10:28:20 -0800 (PST)
X-Received: by 2002:a05:651c:220e:b0:290:8a13:c222 with SMTP id y14-20020a05651c220e00b002908a13c222mr5951191ljq.35.1676053699997;
        Fri, 10 Feb 2023 10:28:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676053699; cv=none;
        d=google.com; s=arc-20160816;
        b=E0w+2DIAc36NMs7UqJzREJdPy8QfUEaXMG/812ldh2V+8Qu+pBMiEIjIsQV8WAFHf8
         Az8I932neCa/c2D6iUmzIESCQUtB7eAJ8L2Ua42Wal1rJISOVxzCVm7kmkwhJ86Bdpbo
         XHjfIEcCCwRs5UUsNJjAgbE5pdXTFGuWNbs1XgcesVqbsBGOuzcDmBSSyRADKWYR0kMl
         MqfhIcGF8fMql9AZConABpU0r+A7QlOLrSIoHfG2fdjAR2GPu3JFJngWD5Nsocm9QKsk
         58qbkOX9UFc37aRTtahFZhAkKmChwAYW9tW17qkw3TwUwXZeX1U5N3FMIXSkeCCazihA
         LRgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=8N4wrGVcwiBGmfA2/Guzapu5gF1TGABEtfn81WOTSKE=;
        b=kDdiycfF4Q81rcHk9MtlgPRvhFu45tygKgGB8PsY1jwXE8uZnjB0bBztn5YQw2LD0Y
         XW4CIxisG30hK232ip9kNKJbAGPkoyovTXwX2E5xB289U5bscNaNxx+OItZh3mPZ3RuG
         /3HeBr9uc+1eCR+OKF4iqi5nnXcf969b23BLLXJffcNmsQE45lOjOLhcK/e1kJ7VWzqM
         jDMc96rTVkNiLgcAZxq50K8OsWkfrTf5IxZ4INpS0SqkMRWcnWtvpaujcIfb8VA4f4cx
         ZIiWGd/M6P+99vBN9UZedmnzfpaK1XUBwLnEufiZmY/3AuWHPfnSorpgT3sIcX0anGt0
         8wlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id f23-20020a05651c161700b0028b731e8e20si255510ljq.1.2023.02.10.10.28.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Feb 2023 10:28:19 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 617EEB824BF;
	Fri, 10 Feb 2023 18:28:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DCD4CC433EF;
	Fri, 10 Feb 2023 18:28:15 +0000 (UTC)
Date: Fri, 10 Feb 2023 18:28:12 +0000
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
Message-ID: <Y+aMvBozFxma3A/q@arm.com>
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
 <66cc7277b0e9778ba33e8b22a4a51c19a50fe6f0.camel@mediatek.com>
 <CA+fCnZfu7SdVWr9O=NxOptuBg0eHqE526ijA4PAQgiAEYfux6A@mail.gmail.com>
 <eeceea66a86037c4ca2b8e0d663d5451becd60ea.camel@mediatek.com>
 <CA+fCnZfa=xcgL0RYwgf+kenLaKQX++UtiBghT_7mOginbmB+jA@mail.gmail.com>
 <a16aa80c371a690a16e2d8bf679cb06153b5a73e.camel@mediatek.com>
 <Y+Xh6IuBFCYZhQIj@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y+Xh6IuBFCYZhQIj@google.com>
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

Hi Peter,

On Thu, Feb 09, 2023 at 10:19:20PM -0800, Peter Collingbourne wrote:
> Thanks for the information. We encountered a similar issue internally
> with the Android 5.15 common kernel. We tracked it down to an issue
> with page migration, where the source page was a userspace page with
> MTE tags, and the target page was allocated using KASAN (i.e. having
> a non-zero KASAN tag). This caused tag check faults when the page was
> subsequently accessed by the kernel as a result of the mismatching tags
> from userspace. Given the number of different ways that page migration
> target pages can be allocated, the simplest fix that we could think of
> was to synchronize the KASAN tag in copy_highpage().
> 
> Can you try the patch below and let us know whether it fixes the issue?
> 
> diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
> index 24913271e898c..87ed38e9747bd 100644
> --- a/arch/arm64/mm/copypage.c
> +++ b/arch/arm64/mm/copypage.c
> @@ -23,6 +23,8 @@ void copy_highpage(struct page *to, struct page *from)
>  
>  	if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
>  		set_bit(PG_mte_tagged, &to->flags);
> +		if (kasan_hw_tags_enabled())
> +			page_kasan_tag_set(to, page_kasan_tag(from));
>  		mte_copy_page_tags(kto, kfrom);

Why not just page_kasan_tag_reset(to)? If PG_mte_tagged is set on the
'from' page, the tags are random anyway and page_kasan_tag(from) should
already be 0xff. It makes more sense to do the same for the 'to' page
rather than copying the tag from the 'from' page. IOW, we are copying
user-controlled tags into a page, the kernel should have a match-all tag
in page->flags.

> Catalin, please let us know what you think of the patch above. It
> effectively partially undoes commit 20794545c146 ("arm64: kasan: Revert
> "arm64: mte: reset the page tag in page->flags""), but this seems okay
> to me because the mentioned race condition shouldn't affect "new" pages
> such as those being used as migration targets. The smp_wmb() that was
> there before doesn't seem necessary for the same reason.
> 
> If the patch is okay, we should apply it to the 6.1 stable kernel. The
> problem appears to be "fixed" in the mainline kernel because of
> a bad merge conflict resolution on my part; when I rebased commit
> e059853d14ca ("arm64: mte: Fix/clarify the PG_mte_tagged semantics")
> past commit 20794545c146, it looks like I accidentally brought back the
> page_kasan_tag_reset() line removed in the latter. But we should align
> the mainline kernel with whatever we decide to do on 6.1.

Happy accident ;). When I reverted such calls in commit 20794545c146, my
assumption was that we always get a page that went through
post_alloc_hook() and the tags were reset. But it seems that's not
always the case (and probably wasteful anyway if we have to zero the
tags and data on a page we know we are going to override via
copy_highpage() anyway). The barrier doesn't help, so we shouldn't add
it back.

So, I'm fine with a stable fix but I wonder whether we should backport
the whole "Fix/clarify the PG_mte_tagged semantics" series instead.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y%2BaMvBozFxma3A/q%40arm.com.
