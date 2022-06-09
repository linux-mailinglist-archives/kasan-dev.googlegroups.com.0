Return-Path: <kasan-dev+bncBDDL3KWR4EBRBVHZRCKQMGQEPOO4XKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D02E54542B
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 20:32:53 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id k5-20020a05600c1c8500b003974c5d636dsf59672wms.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 11:32:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654799573; cv=pass;
        d=google.com; s=arc-20160816;
        b=EkBnuOfsXiXECBTQZaOle4w6mCqdVmag7mTJK29BrOeWGyJ5CBhbSSY6c+2qSPpwOS
         1m52UO79AZxIPE4+g/lb2+YW7tbfMrhbIX/njVWhKWn7RmZfYwdudN2sdvsLTrHN2peJ
         GyLVjHsHLQmfh8t0pzyoL3e+4ULNeYXQyObcIwTPPAE3qrf3JeVapFLhDr9z5SPnRWaH
         Bs59sO7woX7KgCsm54zyxGORG49dE/8d8CVkLXyUcxb0/JXJoGtawCT7/SsnzkxAGOKv
         yKLu5aoQ/+s4z141kgeo4MDxxryYAn1Pliws8VdVEoEtUhzrK0ZwLu8US47YsEWhzfHi
         3+ZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/2mGinuhDAYC1UoUafSrXB4JFxn+R8+iYCgeQxrm39s=;
        b=UXv1jynzzwAexvfpSy7T3oOQnzcKbh4cfuJGwYtGB1PY4Hm7QUUuF2iw5MhqLrKqWk
         E3Tpqx1vhfvz3Mmyn24BIv7MOzPnSkfshzF/QqWC5zIixbRKIrXJG8aOKItmDG2GkYpR
         2kALX4ouLxys8iEgmWGf3ZzeOuJqKPNXOldth7esZUdZP9JS564jdjrf7MoWKghvQ8d/
         K0Xf1ebfn656dO6LF6aQ4R2GKNGI+VgSJPSshlayK5jR8krG99fy9OkIeeY7gcPmUGJF
         JHj5rnOIhB3pYqMh777HVFBMQYxN78tY6XNRSkfY780PI5BTE1YaoV4Ll6Vp2BI6eS2k
         GGlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/2mGinuhDAYC1UoUafSrXB4JFxn+R8+iYCgeQxrm39s=;
        b=jIG+42k1dRbT0JfKYcf8AiVV/iFbnwV6qudMP+YkzhWvOqxMdzoHEmOkJVrBK/MZyU
         ukBWxvLVU0iYRmJY1VpJajO7wy8yQlU2xKdA0SVC1InVWytJCkvvzPXaZP9K2BG15qfR
         T8mSqSQCmPfcvhdCqJPDGPilHu7gfW/e1FGHEl+MUyKAeHWxtJX3Cd/BgBi6WG0ZKeYB
         8D104FJnCYSq9c+gHlrnGtKI8X1sw/P7zu8fJSLWOWtpnYhFp+gpjlCKVH3bGFS+VJi9
         ADdi6ZXuU4qMWoS4gJXwPcJEBP8RYuO2I/TiRnSWJHKLCpxv1opqGZhQWWRkmeb4GtNK
         FWUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/2mGinuhDAYC1UoUafSrXB4JFxn+R8+iYCgeQxrm39s=;
        b=bNsW6wP/sWlVGUluABJvY5cqaDC8KS8S0m86gRIsTjIP6KsNajPiuqgq0j+IeMT6TN
         RJFv9FVu5VgViVBXHLjLTUkdkGL3AjQBUeiO7YdZNOlXtoxkfM577dMB3PN9tUfLAye/
         /BdXuCFiIvLpCzVX7lWhMzPECn/UDBMnUV7WEyMN+y5fGG9ExIKjgCG49a/c1GXnPD3s
         tzHyJYIH6sQC05RD8XCdtHPE+25IrJdL7dZi39m1e2HrvxRbI4g+6DFfE0Ba3aCbOBUV
         gycOXf1dnTl8OcQrorpoHl6/eOBY5tD0UWzbwqC3FRD5zDRCxHvaeah56AQ3gv9F6fDG
         mLIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531smTC5fk8VaL4qtrPcPFHoEKOeaSdJq9ODv+rf6hII6EEWJBU1
	OqIFRTLMKitr6zT939DZORw=
X-Google-Smtp-Source: ABdhPJyeDfR0yaLZJOXiubnXOIdXpQc+YQgMcKqemopu/cw9c8sZ1oUtJ6OOg6M708suCM4b2DJ//w==
X-Received: by 2002:adf:fd0f:0:b0:210:32d7:4cb5 with SMTP id e15-20020adffd0f000000b0021032d74cb5mr40025536wrr.565.1654799573123;
        Thu, 09 Jun 2022 11:32:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5848:0:b0:219:b7ea:18e1 with SMTP id i8-20020a5d5848000000b00219b7ea18e1ls2843437wrf.2.gmail;
 Thu, 09 Jun 2022 11:32:51 -0700 (PDT)
X-Received: by 2002:a5d:64c5:0:b0:218:3fcb:d909 with SMTP id f5-20020a5d64c5000000b002183fcbd909mr22910221wri.308.1654799571806;
        Thu, 09 Jun 2022 11:32:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654799571; cv=none;
        d=google.com; s=arc-20160816;
        b=ccKv6OoP0LPHGghf2k6eeXkzWP+tzA6ksQDGwU/1uBYrBRm/nTZW/iM8P2bFtaj+oc
         HgXvj0q2CzjZayviXvx0m1TgG5LLyfLxM56zPP1InpSO8m5zh0exrvnEVWjCXzIIq124
         diO6ueWP0H7a8RU0zwGhK0FJAu0DcsjBPvEtQLpVtye4O3/vgpFdlujzSnwmFFO/hOYd
         r8tihy4oRqHTEdZLw+kMz5pVYVJsSQXd+3W+33MJpJzAzBq0AOYUnABMZExFwdcgFhTl
         DlPGoHYq8tDrC7+dOp8sFi1AQgqum30ItBq7yox+XRYHbGKP4bHVrw0kPV2lk/3dz8zm
         4ypA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=W3NEPlZRtdoJE5gZr//+f3onrus2x6Ltw/Knl3Z38go=;
        b=p9A/Uer+eue6YL6UOKj5TemizeI0e45Qp/olYSP7rRT6ervNoRp1vtcyUhxk39Jv+b
         gszcNMl88hOCQTLSG9zzT5REepMh9Lr/34kBmL65St+4V/oI10QnzuQwA9txwO/v+zZ0
         ef2Y6JdRc1MjpHas5iaUzZwJSuUWZSEqlUiORmCUNVte6NrjqKzkSGACnQH8ZWxrVnUF
         081DSmdjjyYTA/p6DbElAqjltJGf3A20nq9AiAvkHxtkWCOybMpmAaHM6egYYUAkpt6s
         fwhfljmclqa4J0X3c96NaXU0dNnC0+hyDA16GJLnROlwy/03Wejoz/UyAbNTMmMadmiN
         nw2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id x13-20020a5d60cd000000b0020c6d76cc7fsi919066wrt.7.2022.06.09.11.32.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Jun 2022 11:32:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 74E07B82FC7;
	Thu,  9 Jun 2022 18:32:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 68B3DC34114;
	Thu,  9 Jun 2022 18:32:48 +0000 (UTC)
Date: Thu, 9 Jun 2022 19:32:44 +0100
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
Message-ID: <YqI8zGRKa6GE+K1A@arm.com>
References: <20220517180945.756303-1-catalin.marinas@arm.com>
 <CA+fCnZf7bYRP7SBvXNvdhtTN8scXJuz9WJRRjB9CyHFqvRBE6Q@mail.gmail.com>
 <YoeROxju/rzTyyod@arm.com>
 <CA+fCnZe0t_P_crBLaNJHMqTM1ip1PeR9CNK40REg7vyOW+ViOA@mail.gmail.com>
 <Yo5PAJTI7CwxVZ/q@arm.com>
 <CA+fCnZc1CUatXbp=KVSD3s71k1GcoPdNCFF1rSxfyPaY4e0qaQ@mail.gmail.com>
 <Yo9xbkyfj0zkc1qa@arm.com>
 <CA+fCnZfZv3Q-2Xj1X6wEN13R6kJQbE_3EgzYMyZ8ZmWogf28Ww@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZfZv3Q-2Xj1X6wEN13R6kJQbE_3EgzYMyZ8ZmWogf28Ww@mail.gmail.com>
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

Hi Andrey,

Sorry, I got distracted by the merging window.

On Tue, May 31, 2022 at 07:16:03PM +0200, Andrey Konovalov wrote:
> On Thu, May 26, 2022 at 2:24 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > If we skip unpoisoning (not just poisoning as we already do) for user
> > pages, we should reset the tags in page->flags. Whether __GFP_ZEROTAGS
> > is passed is complementary, depending on the reason for allocation.
> 
> [...]
> 
> > Currently if __GFP_ZEROTAGS is passed, the unpoisoning is skipped but I
> > think we should have just added __GFP_SKIP_KASAN_UNPOISON instead and
> > not add a new argument to should_skip_kasan_unpoison(). If we decide to
> > always skip unpoisoning, something like below on top of the vanilla
> > kernel:
> 
> [...]
> 
> > With the above, we can wire up page_kasan_tag_reset() to the
> > __GFP_SKIP_KASAN_UNPOISON check without any additional flags.
> 
> This would make __GFP_SKIP_KASAN_UNPOISON do two logically unrelated
> things: skip setting memory tags and reset page tags. This seems
> weird.

Not entirely weird, it depends on how you look at it. After allocation,
you expect the accesses to page_address() to work, irrespective of the
GFP flags. __kasan_unpoison_pages() ensures that the page->flags match
the written tag without a new GFP flag to set the page->flags. If you
skip the unpoisoning something should reset the page->flags tag to
ensure an accessible page_address(). I find it weirder that you need
another GFP flag to pretty much say 'give me an accessible page'.

> I think it makes more sense to split __GFP_ZEROTAGS into
> __GFP_ZERO_MEMORY_TAGS and __GFP_ZERO_PAGE_TAGS: the first one does
> tag_clear_highpage() without page_kasan_tag_reset() and the second one
> does page_kasan_tag_reset() in post_alloc_hook(). Then, add
> __GFP_ZERO_PAGE_TAGS to GFP_HIGHUSER_MOVABLE along with
> __GFP_SKIP_KASAN_UNPOISON and __GFP_SKIP_KASAN_POISON. And replace
> __GFP_ZEROTAGS with __GFP_ZERO_MEMORY_TAGS in
> alloc_zeroed_user_highpage_movable().

As above, my preference would be to avoid a new flag, just wire this up
to __GFP_SKIP_KASAN_UNPOISON. But if you do want fine-grained control, I
can add the above.

Thanks.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YqI8zGRKa6GE%2BK1A%40arm.com.
