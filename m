Return-Path: <kasan-dev+bncBDDL3KWR4EBRBCE6XGKAMGQECXRTY6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F661534094
	for <lists+kasan-dev@lfdr.de>; Wed, 25 May 2022 17:45:15 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id e17-20020a2e9851000000b00253bc1c3232sf4655413ljj.10
        for <lists+kasan-dev@lfdr.de>; Wed, 25 May 2022 08:45:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653493514; cv=pass;
        d=google.com; s=arc-20160816;
        b=HOJFKkG78Wfz0/45eUJViUVjc6UGrgLWnio0KfiUg1aDKBXZH7P0JcdoetppDH2BID
         7ulsek2Ue52Q8udER+yXtQ960MMq8cclSsrlbMY2TX7EcBx2O/PUimi6S0m361MAkpUS
         tWXWwZyCq+P3SSAe3ueLen8d4bibIVuwXQDo9uJi+7xJLUrI8JtKSFQ+pOHfZTtPHEHz
         OWPzp70sU/Lb6DAf9LKmRMybxR7YVuchS8g4MepOAHkXhffqc8N9sIr7C7CcnqEW5Age
         fsDTV+GkaDKfdOW4K+EgxzxBgt4UWlBoXHoJaKKh67ENx4F4L/FDKPFWz1m4NIzQXMio
         1L/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=nmwlBxPCn1KCgRxGLNfGdfisWEnX59k/bY4uLdYhQMI=;
        b=0WfINEVCsbWu9P35nZ3XWEpBoFRLOVdmAVama0EzDggMcl4+jaPqDbk4t9J7dJbIhQ
         Bbrc6mPMZHNnYPNpBQzX2KRgeafwmL8p/zed6N62oYsyEUwGst5psUu3fNTvvCyuPWvw
         lFpKW1wPETJ2/zTsxOrqg/6KLnklkcLudAkZi/TZhUXzzXC5PYPM2b4kmMiPCt7ok1LG
         OC9WC1L8MV/njGkU389OqFEAFxsLLTU1e9gPKOWLVhtySXkEmYMwTsgaRlVmjoFAh6lk
         GtVc9wXZ69XFh54dz3koFCS9gXRHbipXQ1Vp42KKKfEW/AW7zEg4PAs3jE6ZsZVILTOp
         Wy3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nmwlBxPCn1KCgRxGLNfGdfisWEnX59k/bY4uLdYhQMI=;
        b=KMuGkwVRa9H3rE8ko08JISUBVi1XZ/0s2iVmcV7LfYJ3h2FtAlrBy4yUlvV7jFTvLs
         1f5UXwija6YHuSPGqOSIPR1D1PQRqIlagvH8SvNFTQfLPsURuw8B5248UgFjJG/gKyzY
         rSCFKuQuX0oPXtMfYtvIbarqZoNXWQe/G2qckRsVjUjshx4o70BMyU9GHg4svtzsIvnz
         nSMmZi40tstOOsq1iDhJn85uVZOQj7h67PnLAFfcCpVmxP8nGCs6sDQD3yrXmFIBG3We
         cPkwlViaXLq7wZtQX30b2g9FywgmBg1VKTMLNaxGMl0Bal37FuLZ6/SpIH9dSgiwPAPK
         0p2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nmwlBxPCn1KCgRxGLNfGdfisWEnX59k/bY4uLdYhQMI=;
        b=I0b7/X+4HhQo6Sdsk/ysF6gKiOupIEIQIw/02Zb6rMA+vPMf8dy3IiN+wyr2J8UtrL
         LsGWygX8krs9OMuhVASNayt7zWIHEr3prw/NI5+4BBSrLUMhXMKUsuzYjm+SFLLkIV1w
         XHD3NPD89qe+e27nOXjG1KMpA77nmN3xsK1nc1jK/y/+iFYVIk2lDNIqOILOSLhBOR94
         kyzpzr/Gg+gb5kcSVa8NX3/5neqSg5WDVFiYZHrboOUhM5IJQEAu0SQs90NEdwvlxBwS
         BKN8XsN79R8W/MYXuZVz+pU3ZqCnMl1BOg6xiQ4nKaqo9mZ5zi7MECWF8EZZn05SeDAr
         wC+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HBoblzxlHHIQspCjbNdK7hD2OrR1fePQxvQwFIe7zMKl93pKe
	vNX1ZsdQSpkpYLvtyfjgzGI=
X-Google-Smtp-Source: ABdhPJzZmqgZ9oOenS/iydt5RW8ka5+S3dhq6iFtcj9rN6ql4npfbyEG9FwMGBy94NoGgjrpaZJXZw==
X-Received: by 2002:a05:651c:1a12:b0:253:f101:86b5 with SMTP id by18-20020a05651c1a1200b00253f10186b5mr7198175ljb.249.1653493513032;
        Wed, 25 May 2022 08:45:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b896:0:b0:254:c65:c6d8 with SMTP id r22-20020a2eb896000000b002540c65c6d8ls546619ljp.6.gmail;
 Wed, 25 May 2022 08:45:11 -0700 (PDT)
X-Received: by 2002:a05:651c:105b:b0:253:e0e7:4747 with SMTP id x27-20020a05651c105b00b00253e0e74747mr13783472ljm.319.1653493511574;
        Wed, 25 May 2022 08:45:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653493511; cv=none;
        d=google.com; s=arc-20160816;
        b=0KPOyZX0fSv7bcaf/9c2Zldiu4eHxmPi+YRnJ2xEK2/2c/UHUMV4BwlLMGiSdctEs3
         w03pKTok17gC8RRPkXLTzdzbWm0223WTCJSud0iYVDWvaWk7t5FHU95wEmk9DON3aDGy
         tbNq1d74RT+l6t24FkBjDYrOIdASlwiWrR1fcIf2kJMIxsjrffEJmg0i5cnDFeVRk9Xv
         s0LwzPyLc5Cp6vJU++BESvIJJYYH7VPd/u/z2QEU59XTCSIGS8Tjcf/NhGIUdDRnczwV
         DJT0tmbejiIhNpC+8edBnpnnjSAVgcFawhVPsALRe/Kh0m4gltIhDHtvnKE7pD3YVEgU
         JC0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=Af2pBEHHr29hu5INWLUOOHSBD34FBIIRNBBtagJZhNg=;
        b=ktdbLFALAtH9JLTAhUqBphYkiJF4Pu8FzXP4GFMSCuOrk5R7S0VFCPr6MMQo9w5s6/
         9Qo1UmikxG/F9dY/n3hhvaRT41belBxSGLKTHrSpj78IjP/tTJui77POAE6QbO0JuPIs
         8otPpZF3VAo8BJhSIqw3jgDnO7nXOUSC9wUt2E9aU4h6q6fjONVVg5HZZWEhZ1PUcFFz
         V/PF/1aSyE8HHRmuWaqs2TMmuinE3tjZQU1kNfxWzh48y1G8DiQdpn7JX9jialUfyIc1
         KWZT1jqJiEKnxwz9yGNEV45Tt8DQEnYhjVQpUkp2t/Uf+BJh9wJKYL9b3w5BNHHtkFuU
         GbOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id u5-20020a05651206c500b0046bbea539dasi876550lff.10.2022.05.25.08.45.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 May 2022 08:45:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 2443EB81C3B;
	Wed, 25 May 2022 15:45:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 59743C385B8;
	Wed, 25 May 2022 15:45:08 +0000 (UTC)
Date: Wed, 25 May 2022 16:45:04 +0100
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
Message-ID: <Yo5PAJTI7CwxVZ/q@arm.com>
References: <20220517180945.756303-1-catalin.marinas@arm.com>
 <CA+fCnZf7bYRP7SBvXNvdhtTN8scXJuz9WJRRjB9CyHFqvRBE6Q@mail.gmail.com>
 <YoeROxju/rzTyyod@arm.com>
 <CA+fCnZe0t_P_crBLaNJHMqTM1ip1PeR9CNK40REg7vyOW+ViOA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZe0t_P_crBLaNJHMqTM1ip1PeR9CNK40REg7vyOW+ViOA@mail.gmail.com>
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

On Sun, May 22, 2022 at 12:20:26AM +0200, Andrey Konovalov wrote:
> On Fri, May 20, 2022 at 3:01 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > > This will reset the tags for all kinds of GFP_USER allocations, not
> > > only for the ones intended for MAP_ANONYMOUS and RAM-based file
> > > mappings, for which userspace can set tags, right? This will thus
> > > weaken in-kernel MTE for pages whose tags can't even be set by
> > > userspace. Is there a way to deal with this?
> >
> > That's correct, it will weaken some of the allocations where the user
> > doesn't care about MTE.
> 
> Well, while this is unfortunate, I don't mind the change.
> 
> I've left some comments on the patches.

Thanks. I'll update and post at -rc1.

> > > > Since clearing the flags in the arch code doesn't work, try to do this
> > > > at page allocation time by a new flag added to GFP_USER.
> 
> Does this have to be GFP_USER? Can we add new flags to
> GFP_HIGHUSER_MOVABLE instead?
> 
> For instance, Peter added __GFP_SKIP_KASAN_POISON to
> GFP_HIGHUSER_MOVABLE in c275c5c6d50a0.

The above commit was a performance improvement. Here we need to address
the correctness. However, looking through the GFP_USER cases, I don't
think any of them is at risk of ending up in user space with PROT_MTE.
There are places where GFP_USER is passed to kmalloc() for in-kernel
objects that would never be mapped to user, though the new gfp flag
won't be taken into account.

I'm ok to move the new flag to the GFP_HIGHUSER_MOVABLE but probably
still keep a page_kasan_tag_reset() on the set_pte_at() path together
with a WARN_ON_ONCE() if we miss anything.

> > > > Could we
> > > > instead add __GFP_SKIP_KASAN_UNPOISON rather than a new flag?
> 
> Adding __GFP_SKIP_KASAN_UNPOISON makes sense, but we still need to
> reset the tag in page->flags.

My thought was to reset the tag in page->flags based on 'unpoison'
alone without any extra flags. We use this flag for vmalloc() pages but
it seems we don't reset the page tags (as we do via
kasan_poison_slab()).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yo5PAJTI7CwxVZ/q%40arm.com.
