Return-Path: <kasan-dev+bncBDDL3KWR4EBRB3EARKRAMGQECWIGLZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id C9FD36EAA4F
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Apr 2023 14:24:31 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-2472a2e72d1sf1965056a91.3
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Apr 2023 05:24:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682079852; cv=pass;
        d=google.com; s=arc-20160816;
        b=lQEELwHYqRhaUwkS+lnhq/WjXviGvEJQjbywHl2cTuZY1avA6r6KX9TfQsqK0hGxS6
         nR419gC4MJPpsN80W25RAAYPEdBAk3KrR2xS/mQgGNo3Drz3LQf/dtaKxaK7G9IFxhdG
         sNCVit+OcGjp44TwZTn655m6GcKoxWLvAwYqWbnr6rgArG93ecY+hCyE5XxL6CYhnIHx
         /5/p6Z3BPXDG88yQS7Pl3qlgQJphzsyBe2nKV9M1PIz9OrBPYYFu96S71QLTQf2uXeeg
         0WneEPMa1FMRfINWIPOe1p19E2ERp4v5jxcb1jjTPQkPxzz4NdkZG0cUyffslq/Qq/Rn
         LNsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9Ene5DnoLcj37uRPfjCb4KoMjh3AfAorK0X9GiqTqHI=;
        b=bxuMFtNx+6cGfvIy+Do/Hlu3ItoxRGQJBdZP7P/UGzNxiuCw+q2feWm+g7oKZVvLmF
         RFjH2Gyk/njDNMSSGpJ4l/ZIo1ZIXf1uouOPkVdfgKp4Hayn3BgpgcdcSPB4/KgisOVd
         NTckuYpXgp8F/bu2L9gQS+buicbwMXCxPt60fqk8JEGn+TnomaNp0/2bIg6goV3pfnF6
         l5VSgIFghMvPoa4sCZofP/b69XGn+WMwXS0SKU/BvSQeFXc3hAWQFUdUYOZd0E5iirg0
         /cE4y8EP1+tjnzqVxZp8EnMT2r/glR5MyGedMGH/h4QWZK3CLpN0JG5bvcjMmoGGw0LR
         j5TA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682079852; x=1684671852;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9Ene5DnoLcj37uRPfjCb4KoMjh3AfAorK0X9GiqTqHI=;
        b=GsHr2jvQexOUygQGFjPjNBSTirnsSISVPJB5Mbomhs5DPdu5/GgOTaPhraCMNqFapT
         uNyMn4aLV4rWNCZ16tXH01lSSyyLfMVJkZ8e/kHcbmJbITmw5V4u/ymavKqULNNlW1Vx
         66ERJiPlLki0mrKgOCO9y4pyL73bIVihe8rEVDezzUSqPZh3pKeTwahSyG0lbzx6YAKM
         Hn7dTkaCINOFO17axI5g/DBqlq9VW4ZcXJf3lXxKOgxRX87h6b9OqWX9pNK4Ch2qlL0w
         VOaeSteYTdxs0Z5nlLdHfGR7NMiTCTfsbWxLUqSouXzaLUbKH5clvHrNXQtZfbhh/nbk
         Dr0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682079852; x=1684671852;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9Ene5DnoLcj37uRPfjCb4KoMjh3AfAorK0X9GiqTqHI=;
        b=RLISfiwFEwRPWDDQHw5aqsQHto251saRWIPE7dA1n8LIQj3A1fsCX+aZmDLXDRY4c0
         I0gjb3D9ygDh8n2I/c6zbQhFxCisgPhchRMpd5hFS37tJxJlblRd1HmC8/wMk1YgO0CG
         m8Ts2A+6bYRtluNXM4ui6BUo1GJBhkxTy+tqNwtPp2MKCO02rkc+UMr3QD3tnYem5jHp
         gqKOAoAQ1QZwiinvZxKb1NUIWUK8gJa3gAQG/ruTuMO5Wjlt0NeC+2amUwVEZNm4a2ZN
         TS2IXluHuWINZwuxL1uy64BICyNigWfNtEDJoP0p2ILt3rgxE85Q05yBxd75UeskjlCq
         monw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9dsa3q9HmabPn9AfFsfuw9Q2Mdzfo3qMQ9DtvcgepxxUlyr3Jof
	GdnH6zNSH2uoI4VIyWEzuWI=
X-Google-Smtp-Source: AKy350aOGqw3jE8EYEp8bu6mKWWo8exDI51p07domh/YadgmnUQUv/k5Lh9NqDZ7TkGzfx0Y/hEccQ==
X-Received: by 2002:a17:90a:69e4:b0:247:2a3a:48e7 with SMTP id s91-20020a17090a69e400b002472a3a48e7mr1364025pjj.3.1682079852594;
        Fri, 21 Apr 2023 05:24:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c793:b0:1a0:482d:27cc with SMTP id
 w19-20020a170902c79300b001a0482d27ccls4768348pla.3.-pod-prod-gmail; Fri, 21
 Apr 2023 05:24:11 -0700 (PDT)
X-Received: by 2002:a17:90a:ca09:b0:247:6a31:d59d with SMTP id x9-20020a17090aca0900b002476a31d59dmr4843815pjt.1.1682079851672;
        Fri, 21 Apr 2023 05:24:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682079851; cv=none;
        d=google.com; s=arc-20160816;
        b=d3ep4lDyQNoKw7dtkTKJLOpjdc/oxScauf2jXLt8TNJR4vrhBPtNcxr6nNIHfdswh1
         QF6UexsiNKdaQAAphZKbXPmjqx0sla3gTRn3UbcRh1+bumXBtDBXUi0NIP+P5LMaK5la
         LFbm1x2fPNni7K6hNtVVLkYkY4X/2MZ99BzXvzbJfCmgfP/99dIc4ad6+FfkPxuz4jQq
         FSXX2rP1P7lph2d3ukGjKSkVQGgU9p+GW2JnfMPZhmlvtLdThz3Kbd/6A3z/R+MYOnsi
         t5T4N8YHfuxGctACR4TN8dJi8S2qcKPmcwez3zP8LbQzgYHQLj8n5MwupnvfD1nB3XH/
         a+lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=fB6TT068dSAv1YZvlFK/YP2ZzpZfRelP40a4NOIfQHc=;
        b=SYzzgAKS4xAaRek8xGLpJ6L2ZIe8BvlUwephCsDV9mmXqq7vfHz69ZzeFUrliBvMEY
         C9G0DqlnPPc0Km6+3CCeNeyCFcanY1XXHTVi7pmzq9ocCwKUEr9V80dr3xht061lNL7S
         Jqsp//e24adQ4FrEVcBacal68NY25+t0pefoqbsKcuaD5Gqaz3OesmbEBa6K8NYeUup7
         yxJcqYQ822eBSlS3s9DrF8TmMmh3v3DRPNQ6gGxEQ4RM+9Z1tIEmyPP56y8X+KXYG4vx
         PK+qW8XgQe+CjIn2fsJs1oi+oB6PV5PaYzKIu5GQvdYdxZD/6pjEm0WuXQ9kgPYyFO4y
         ZlzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id pb10-20020a17090b3c0a00b002478f1bc73dsi348793pjb.2.2023.04.21.05.24.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Apr 2023 05:24:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 264F865043;
	Fri, 21 Apr 2023 12:24:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6E292C433EF;
	Fri, 21 Apr 2023 12:24:08 +0000 (UTC)
Date: Fri, 21 Apr 2023 13:24:05 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Peter Collingbourne <pcc@google.com>
Cc: andreyknvl@gmail.com,
	Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	Guangye Yang =?utf-8?B?KOadqOWFieS4mik=?= <guangye.yang@mediatek.com>,
	linux-mm@kvack.org,
	Chinwen Chang =?utf-8?B?KOW8temMpuaWhyk=?= <chinwen.chang@mediatek.com>,
	kasan-dev@googlegroups.com, ryabinin.a.a@gmail.com,
	linux-arm-kernel@lists.infradead.org, vincenzo.frascino@arm.com,
	will@kernel.org, eugenis@google.com, stable@vger.kernel.org
Subject: Re: [PATCH] arm64: Also reset KASAN tag if page is not PG_mte_tagged
Message-ID: <ZEKAZZLeqY/Vvu+z@arm.com>
References: <20230420210945.2313627-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230420210945.2313627-1-pcc@google.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
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

On Thu, Apr 20, 2023 at 02:09:45PM -0700, Peter Collingbourne wrote:
> Consider the following sequence of events:
> 
> 1) A page in a PROT_READ|PROT_WRITE VMA is faulted.
> 2) Page migration allocates a page with the KASAN allocator,
>    causing it to receive a non-match-all tag, and uses it
>    to replace the page faulted in 1.
> 3) The program uses mprotect() to enable PROT_MTE on the page faulted in 1.

Ah, so there is no race here, it's simply because the page allocation
for migration has a non-match-all kasan tag in page->flags.

How do we handle the non-migration case with mprotect()? IIRC
post_alloc_hook() always resets the page->flags since
GFP_HIGHUSER_MOVABLE has the __GFP_SKIP_KASAN_UNPOISON flag.

> As a result of step 3, we are left with a non-match-all tag for a page
> with tags accessible to userspace, which can lead to the same kind of
> tag check faults that commit e74a68468062 ("arm64: Reset KASAN tag in
> copy_highpage with HW tags only") intended to fix.
> 
> The general invariant that we have for pages in a VMA with VM_MTE_ALLOWED
> is that they cannot have a non-match-all tag. As a result of step 2, the
> invariant is broken. This means that the fix in the referenced commit
> was incomplete and we also need to reset the tag for pages without
> PG_mte_tagged.
> 
> Fixes: e5b8d9218951 ("arm64: mte: reset the page tag in page->flags")

This commit was reverted in 20794545c146 (arm64: kasan: Revert "arm64:
mte: reset the page tag in page->flags"). It looks a bit strange to fix
it up.

> diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
> index 4aadcfb01754..a7bb20055ce0 100644
> --- a/arch/arm64/mm/copypage.c
> +++ b/arch/arm64/mm/copypage.c
> @@ -21,9 +21,10 @@ void copy_highpage(struct page *to, struct page *from)
>  
>  	copy_page(kto, kfrom);
>  
> +	if (kasan_hw_tags_enabled())
> +		page_kasan_tag_reset(to);
> +
>  	if (system_supports_mte() && page_mte_tagged(from)) {
> -		if (kasan_hw_tags_enabled())
> -			page_kasan_tag_reset(to);

This should work but can we not do this at allocation time like we do
for the source page and remove any page_kasan_tag_reset() here
altogether?

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZEKAZZLeqY/Vvu%2Bz%40arm.com.
