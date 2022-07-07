Return-Path: <kasan-dev+bncBDAZZCVNSYPBBZOLTKLAMGQE43LKUHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E13E569E7B
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jul 2022 11:22:46 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id f29-20020a19dc5d000000b004811c8d1918sf6079272lfj.2
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jul 2022 02:22:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657185766; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bf9sgxyUk98TEp8N1k4obv2U8kCiu1O+jSSc7UWDi9YkgcaKefy7ujgArX3agHPkZA
         bHuPNbu/8Zo4niCLwtebPCCcjkm+qFWBA8Ot1NFvNXIWvUPadQXaAJjBuIqvfHFRmnOo
         x4MjkrOTmljocHK5vv+pCe86x3hhCsMLJCHUd63Zkrra9QPXMJn5+z0vc1Xfbp7yMtv4
         BZqV4k76XXuUa1DhJN2Ct3KmmZUkwPfOf0CcZwke/BEeCCFsfiHt90GkBdMy3fRmOKWl
         3z5Wkle+ghwOC9M9NNXimVmU3L8ONz4Ki1Y3bpnWoY+g6JwUkkR8iotWr9ZGxxgIEzjV
         hjMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Rk+BbB6BBN3xerHD+e7ZJZcpjGVM7NsGBKa8pCgNLrM=;
        b=i/h2wff+xRBgEV0hGIfb4m4I59NbcvoJN4odceEITP6WK9DMqaCQsm+TYyLrVRzmvS
         zR12XKF5qUlp2BxHWXZV0oQEQmbnaUAfbpQdWpHF0kJGbBOU3oNXF29k4U0CdAYZsccS
         +NrfSyUNPIxI+fPMapeY6FQOdtWMD6TkkH+fHSa6JSDe/XFijpy7uHhYzauca/moPwM/
         OZkmY02vR+A+wKypYGaFzgjn4CAQYLYW/2XAvXv0vpHRuDZlOcCZzpHxPixim7NC2QtW
         5Ub4rEnYVHurxWrVJ14/aDIRsuxX9/Y42DR67+hWUDIGpZ1zsnOJAqzu322ThQaiQ7z9
         GCuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GL63VyMr;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Rk+BbB6BBN3xerHD+e7ZJZcpjGVM7NsGBKa8pCgNLrM=;
        b=AqY6cjaZCUl1OIKyqyMz1eW+oNHgUFKumAoAezXjxnoz/ASetw3QXlA28/omBA93AN
         iy0HDV/sUJTsqbHC3JC3uu3zr0A6AkUcL2fGM74ysgaxjPVxkHi1vjkYgM3Ghv15tKvU
         Xsbb2hfNDOUDhQvjiAHU5qpip7Nje7qmSw08Ge4GRoSnXu9qe5MkIyilx8UfqDMQ2+Qi
         sou3UDrWZ0tAugfXxe8OuqbOPAOn8PjWFL6OOdaTkrKcXJ+gUWL76sSnGJ10Z1H7hTaJ
         DkMFu8E8SAaIPq/SxtCYsBdFYlgbn80mkjkszi/bfr45xzDwRE7rsX8oTcUSWDrhwKzf
         NCPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Rk+BbB6BBN3xerHD+e7ZJZcpjGVM7NsGBKa8pCgNLrM=;
        b=Z7aPBUTmyfGCHgks7GVBgLlRT/YvsXKonzDwaUzMPmzBySwGAEFkVPKNtaDceNWj5M
         5hQvNcAE1RnIYjFA7Pef0o1Y3F/+hBV1bEgCn0uXaDqFHc0h+smfJgBuWlMAfgFqxfOz
         Q8j0fj8R9QAmBBX1nKFHfL36I4djQSSTUBcWSloXF3HjqQjb1cqDcV9UKgZglwUqufao
         yRSgNTg69TG7cfmGtjuA2VUq7ixCKso5iafQUm9UzuomZw+Eo7eWRe/RTqPyzEg0lkSB
         2equ71q6h42f19oEreAh/qZV12hyICwy+VH9VnEqSjMsU1uVLPbUd5m70S35feEeB3q7
         aTrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora92gT8JwFyJq9SZGgi6VxzJkVtEJxxfiqQPkY7Y/p7uWs9BTF/P
	WvdWSI44Yvxn+Gjzg1vNDv0=
X-Google-Smtp-Source: AGRyM1sQmbMHs0213T9lymzdfXUg6Of+Idb61Jf159sH1MGhOmtSGVbodtNlqSyeKmeMmOpjL+FhKA==
X-Received: by 2002:a2e:98d2:0:b0:25a:5edc:b445 with SMTP id s18-20020a2e98d2000000b0025a5edcb445mr25632151ljj.492.1657185765775;
        Thu, 07 Jul 2022 02:22:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b6cd:0:b0:25d:5128:d32f with SMTP id m13-20020a2eb6cd000000b0025d5128d32fls140005ljo.2.gmail;
 Thu, 07 Jul 2022 02:22:44 -0700 (PDT)
X-Received: by 2002:a2e:8795:0:b0:25a:926c:e45a with SMTP id n21-20020a2e8795000000b0025a926ce45amr26348277lji.438.1657185764427;
        Thu, 07 Jul 2022 02:22:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657185764; cv=none;
        d=google.com; s=arc-20160816;
        b=CyUQPx2xQnHWu7gNiyjGL/9VKcDf+JPPtqvS4H/WezSEoNSyQpIjWr5Bxa+XNfC/kb
         aitBKMBoLAxGQgzy9VmTIt7qLcAhR9xfu0rhJhqtddytgBf4JYibs9ewlyRVriTr1Nae
         m10PTAeW8Iz+AJTenxv5FoXNLJspW0d4U/PQObfTMcT0AK5wzKYx/ciO+yWWuGBchMlj
         TJ8vZhfVW+6iwm0v4hCNcgD5OTJOjTh/UQM00SSqkNFeKtEPt9Va3gZmRBbERrf14ssM
         Z3CD5WRlPO4LgOHQYOlM8WeZhUJPkJicC8n9erAExCksjA850UhIxk6xuA1BQTXMNTvm
         OLzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=z9GxHCih9xdUkN3bEI0ym+gczVQ8oNvHCNw1GBSJlno=;
        b=EhT44KwFv3slFHX4wAYQawDCvPwWt9q2AkIR1XUxhVRMxeK4HxN4WlWZGIrn0qXVNa
         JTFvUqCqp/m/zXhLk+yJgrdTgnSM/dMy3D/C7xK/KffD53lPlEUtBMEH0xCChRUZAfcs
         9RnO4qG58xq+7rtZWSGH1z31dMxYOqYKlyCPxLA1/3M6ej5xk1kGreCffdd3KM7bLzvI
         cB/0oceumGgsUFDe9eD/Wnbi/IWtOg9roYxZL3o7BxMJRB8U69kUeXQR2xBhardGL2uT
         xvF2ZT9mq2tEn0JOxKywhkey16NLarUpP6XeimD4pUHAsgc7pbN7Z9uzVjCTYZTV9xrN
         f0pg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GL63VyMr;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id cf26-20020a056512281a00b0047fb02e889fsi1466038lfb.2.2022.07.07.02.22.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Jul 2022 02:22:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id C816EB81990;
	Thu,  7 Jul 2022 09:22:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F313DC3411E;
	Thu,  7 Jul 2022 09:22:40 +0000 (UTC)
Date: Thu, 7 Jul 2022 10:22:37 +0100
From: Will Deacon <will@kernel.org>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH v2 1/4] mm: kasan: Ensure the tags are visible before the
 tag in page->flags
Message-ID: <20220707092236.GB4133@willie-the-truck>
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
 <20220610152141.2148929-2-catalin.marinas@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220610152141.2148929-2-catalin.marinas@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GL63VyMr;       spf=pass
 (google.com: domain of will@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Jun 10, 2022 at 04:21:38PM +0100, Catalin Marinas wrote:
> __kasan_unpoison_pages() colours the memory with a random tag and stores
> it in page->flags in order to re-create the tagged pointer via
> page_to_virt() later. When the tag from the page->flags is read, ensure
> that the in-memory tags are already visible by re-ordering the
> page_kasan_tag_set() after kasan_unpoison(). The former already has
> barriers in place through try_cmpxchg(). On the reader side, the order
> is ensured by the address dependency between page->flags and the memory
> access.
> 
> Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  mm/kasan/common.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index c40c0e7b3b5f..78be2beb7453 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -108,9 +108,10 @@ void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
>  		return;
>  
>  	tag = kasan_random_tag();
> +	kasan_unpoison(set_tag(page_address(page), tag),
> +		       PAGE_SIZE << order, init);
>  	for (i = 0; i < (1 << order); i++)
>  		page_kasan_tag_set(page + i, tag);
> -	kasan_unpoison(page_address(page), PAGE_SIZE << order, init);

This looks good to me, but after reading the cover letter I'm wondering
whether the try_cmpxchg() in page_kasan_tag_set() could be relaxed to
try_cmpxchg_release() as a separate optimisation?

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220707092236.GB4133%40willie-the-truck.
