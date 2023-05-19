Return-Path: <kasan-dev+bncBDDL3KWR4EBRBOGTT2RQMGQEWRGPS6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id AD8B8709CF6
	for <lists+kasan-dev@lfdr.de>; Fri, 19 May 2023 18:54:18 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-52855ba7539sf2031655a12.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 May 2023 09:54:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684515257; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vra/fd84JJyXtQY6myecSCT1q2AHwE7Ia8+kg4s06QxRjyMKkvV3qyjefdspLMqLS+
         3r3ywL7ajgReaK1RYHAFTY950UOy6CLbSZWafo8yvdzGxnRPoZ6FSpws3kTeeXXxwwV9
         PcIVx/yXREMyHtxD2DSDogp9rDJjJImE5d9Q1XuvZVBlqeYBFkp0kLK+eqvP9fsCQpB4
         DMFWU/bYe/d2nMvvfJNJNPXp8BiR7NtQ9t4h6gb0T1Q8zf92UWsW1wqAgVZlUXldYclI
         OoVp7GWM+mxb7mjHLsMr4cVjMLAJZhB29saWak341YFGesk+7QGUPjSbhJupGLPv5TIw
         NNKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=vUaHUxUixdwuXYU5Bct+vjbTNuAHC0AnsBEHZu0g5ts=;
        b=TnzvjbAD7Vkw1dhJUm20E6sygt+edLBY8Fx8eqXZxVmpETcLa66ond5lrAG8RSKxsB
         CeHr3NeywMOOeHVXegF3q8/I2RmMb1oxw+sPzXgS8G59pjVIuIleGPdhwXex/1MtdBgh
         yXQgP/tzf0zpvHBOCKRmDaJZrlFkqHncGQ0I3yR05MiaX7jqDreUWnRxGYypv5E9zUpP
         uNDSbVjY7iUusQ9pxiNpZf3HVfIqiPZg1XyS/cFUMBPD1etZtYqdsbL3wTAKIKITnAZG
         qiiRiv2EWHncdgEot9oGXj8pxJB3XsRbtxtnDBQEuB5PQkfBOoMwA5uCqhfkP69mN4ao
         lj8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684515257; x=1687107257;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vUaHUxUixdwuXYU5Bct+vjbTNuAHC0AnsBEHZu0g5ts=;
        b=UYbaL4PH/Lj548H4s0XhdnszN/8jfaKuTB58HWhcEzqCnCVvw4bwWeG4bs2fIneu31
         rEaVaCXAbRMNbNq0//+fXEe99QhZV9mnk8WuFg2qenBRgcY/R2kHDFAwse7U8hoso+ME
         JwfiXiDlCvEeOapN6dlMh+AF/IW3tJlnq3ppwpcgYvOa8GSKUHGaTXWTGtZ/wdhHcqhS
         ftgJa1tvCcU7ziSV6gHe9KhupIgo4g87NRzVlAQ7FFCLrXgxirnTCpb4Zg79xrTAQPqm
         aorho4mDVY2Ua9e4KXHc7MpBbBN1Vekk119O0IKwGe92UBpTekp2WKtRCGUEbTgcChwi
         Pj9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684515257; x=1687107257;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vUaHUxUixdwuXYU5Bct+vjbTNuAHC0AnsBEHZu0g5ts=;
        b=E8qFWL9QGoteClgBL/zo5Wg99q8AG+N6g+x9kBU3TCkMsb9gaFD1av46XRyr4Zspg7
         1Z1oC0Zy4WhawE1Ayjc1+QchwO+lEJLNtJu2C3kXsqIzBS9L1Z0dmISq1OoVYMB5nUGi
         nwgllh4rBlhDo/jLknJvaTZaeQ9IKRHA4dHJ9BMRJU6TEnSOGdRRKau3bPhLGwkPC3Dw
         5274rUwUCNgBpk1VsYMXG9GhSOus3E3UJG9aoZKOB2d6+5pdd7cuhiKZ2hhoQ8EG6kti
         AdYBpImP6NBjJMMZtWdgu04jySF6QRmvExsxx9asy5hbaUORZtAz8S17p1W0p6JDmeLT
         1eHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzhUx9hvnQNktim3oF2nmU16XVDe4+Ne12ynuv6LH1Hs51oNvOM
	IXRzCTIS0HJZv6FUfRbc3bU=
X-Google-Smtp-Source: ACHHUZ7zM76WDVHD6yEBwiZXk2UThcMCcFA0hs9G+P3uOTmvmac03xpAjB6qqlv+rct2QNhhDd8ANA==
X-Received: by 2002:a63:706:0:b0:52c:8878:65e1 with SMTP id 6-20020a630706000000b0052c887865e1mr613457pgh.0.1684515256848;
        Fri, 19 May 2023 09:54:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f28c:b0:252:b4dd:a584 with SMTP id
 fs12-20020a17090af28c00b00252b4dda584ls3193272pjb.0.-pod-prod-00-us; Fri, 19
 May 2023 09:54:16 -0700 (PDT)
X-Received: by 2002:a17:90b:378c:b0:23f:962e:825d with SMTP id mz12-20020a17090b378c00b0023f962e825dmr3458478pjb.1.1684515255879;
        Fri, 19 May 2023 09:54:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684515255; cv=none;
        d=google.com; s=arc-20160816;
        b=Zqx7KVQzm5tVhj6x1bEd6SwIjw5Gi8sAuY86AXCm8YILQtsI7Tu8bXkkeIcyyc6bzg
         Tlw7/hb7vrD+pLrDyOdxDMEdjUfz0E2LkvKup14RAV3XtlWmPWnfwLTdQn3aWhDjzKOA
         hj8Z6gOFABjmCdbsWq+5Yn++MBy8ilp/FDGNW3kiMp9hUyICHGqKsjZuGAdmwkblFSyK
         MzOG1/77f/CksifrjDN4sr0yUtBCSXDN8LY8eE/2RJ3ahZ6DTckZt4RneOtMVw5Jo6+g
         zkPfSbi9DZjMAPo4F/HemTF9vHa+xhF2L+QXeK0a3TJUeIbNRxCkQ47l8jt/bz9ahfVL
         6fPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=xjWr6uAP2eX48tFLD5mVkLGnd5r/LJjSY8IVA9YiNK4=;
        b=KyMUG3GW1aw2S4/if2dcc1jLFpt39JE13ekbjUYsRmfnuvjdERwDRul6ZuPG8sIEOP
         OpPyrR0Ltx5f36X3kTf4kGsebVsDcp0i/Zs/Xdyz4BIy0c8zbyh/Nd7arorq6sUMc8cY
         ph9LnrIjpOrU58xko5vqu2cj5AwRIQTDufxZNWj0Uz3kPYKjSDDJNH5ZN//cdPR4w1XS
         c3MpWEE4IrP7U/i+bbX6Y+QxVIcAWI3i6RyVb+aCj+EEtiiSgIDynlMkMJlLS0j9J0Uz
         mRcjwjM+MtQkZG5M8q8F/Rp0HcygwOqUAGmg6FDt2IX1AspmgoaGQlJxMXEPtitRzuw3
         hLhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id q11-20020a17090a9f4b00b002504e396db0si179981pjv.0.2023.05.19.09.54.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 May 2023 09:54:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4C41165951;
	Fri, 19 May 2023 16:54:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DFFBFC433EF;
	Fri, 19 May 2023 16:54:11 +0000 (UTC)
Date: Fri, 19 May 2023 17:54:09 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Peter Collingbourne <pcc@google.com>
Cc: Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	"surenb@google.com" <surenb@google.com>,
	"david@redhat.com" <david@redhat.com>,
	Chinwen Chang =?utf-8?B?KOW8temMpuaWhyk=?= <chinwen.chang@mediatek.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Kuan-Ying Lee =?utf-8?B?KOadjuWGoOepjik=?= <Kuan-Ying.Lee@mediatek.com>,
	Casper Li =?utf-8?B?KOadjuS4reamrik=?= <casper.li@mediatek.com>,
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
	vincenzo.frascino@arm.com,
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org,
	eugenis@google.com, Steven Price <steven.price@arm.com>
Subject: Re: [PATCH v3 3/3] arm64: mte: Simplify swap tag restoration logic
Message-ID: <ZGepsWDEfG+gk/t3@arm.com>
References: <20230517022115.3033604-1-pcc@google.com>
 <20230517022115.3033604-4-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230517022115.3033604-4-pcc@google.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1
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

On Tue, May 16, 2023 at 07:21:13PM -0700, Peter Collingbourne wrote:
> As a result of the previous two patches, there are no circumstances
> in which a swapped-in page is installed in a page table without first
> having arch_swap_restore() called on it. Therefore, we no longer need
> the logic in set_pte_at() that restores the tags, so remove it.
> 
> Because we can now rely on the page being locked, we no longer need to
> handle the case where a page is having its tags restored by multiple tasks
> concurrently, so we can slightly simplify the logic in mte_restore_tags().
[...]
> diff --git a/arch/arm64/mm/mteswap.c b/arch/arm64/mm/mteswap.c
> index cd508ba80ab1..3a78bf1b1364 100644
> --- a/arch/arm64/mm/mteswap.c
> +++ b/arch/arm64/mm/mteswap.c
> @@ -53,10 +53,9 @@ void mte_restore_tags(swp_entry_t entry, struct page *page)
>  	if (!tags)
>  		return;
>  
> -	if (try_page_mte_tagging(page)) {
> -		mte_restore_page_tags(page_address(page), tags);
> -		set_page_mte_tagged(page);
> -	}
> +	WARN_ON_ONCE(!try_page_mte_tagging(page));
> +	mte_restore_page_tags(page_address(page), tags);
> +	set_page_mte_tagged(page);
>  }

Can we have a situation where two processes share the same swap pte
(CoW) and they both enter the do_swap_page() or the unuse_pte() paths
triggering this warning?

Other than that, the looks nice, it simplifies the logic and probably
saves a few cycles as well on the set_pte_at() path.

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZGepsWDEfG%2Bgk/t3%40arm.com.
