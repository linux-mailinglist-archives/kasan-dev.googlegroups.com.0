Return-Path: <kasan-dev+bncBDOY5FWKT4KRBR42UCXQMGQEQL4FD3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D1EA872EE6
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Mar 2024 07:29:30 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-dcc4563611csf10140719276.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Mar 2024 22:29:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709706568; cv=pass;
        d=google.com; s=arc-20160816;
        b=mFPtugh6qfdjgaYZZaWGvW0f7bvCIFb2iMzcZuPW8aBjmyljS3U7iJaqALdMBL6u1p
         qCXOskwxRcfuCz9l4gcRs2UT2V+DHR7aW2+8KTKvtzN80ibi0tqgpWbZvtUqtTK9tbIA
         pe46YRfL8n6b3nD6ijlONPoWBXxvof/s+tOoGN+3+5bRILpcXhGlL6VZHBRjyksZp5+2
         uNaKiyNJpnXocFhURFaHG4OJrGj8IZhiO1jV9WcK75ZfYACBFviMwcjYxbYvyaYwTv5H
         Nxxnx2g52LyzmE0gT8tTjn/2keVWRoKw0iL5jMeJspQFX9nzwMrHuwNFL/Dos4JoMJB0
         DSKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Iixk1Cz5yUWXw7olNSfxlFkOHm4L0/duaiF8ek12Gj0=;
        fh=nHKsWls9Q6cixQWr2qz6hxnzjEClaspPuCH+ReeEF5Q=;
        b=egLStZXq6g77zGEA9t/CDqMIeDjKJoYqbAGxwZejU4TzLDtTAGaadMZf/xTUT0tELe
         o8ucq44kwX8VPC2IIeldDi0y21DdwPXexpA9teEsnEsb3OOckZP4o/2iraBnPVtwyu9+
         4VUMM+9QMnuqmENv3uvu/kzv+Ga4iW8ojAyfE14Ja2F1jOGrV7i/LRo1/bjeguuG7qJx
         tqLYvBY9IsEj23K2cBAn5lUIzitpPRNw0VUeLMqOLfCSh/tWH+KX095gkAsnXqhM3Ujj
         hirk/KsEvIA8YBlVyQlw2QgDK8XEfh9CczSmW/ZJKcXtj1/4p7ONwSn3bvAKfJs5ldzH
         DrsA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MfRhLri6;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709706568; x=1710311368; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Iixk1Cz5yUWXw7olNSfxlFkOHm4L0/duaiF8ek12Gj0=;
        b=CIjKRNbw1jMhgHDyOzvyoIIvhoEp7yDrqoxYXKmQcsGHvTpgPUaRu0ulkQuTkLIMtL
         mHaeSk+TVsQcWR2Vtq9iGBTUYqkOma50QvYH0ucJxj5uLx8uAdyYIRFM+FnAHuk676vA
         ZsvVMJTFrcEV3BLh5GfUkUEXsO1qoBI6RGdUM3+B0Bub0na9v4tsJTdvAAQcTkmDXMKd
         FlbVXd71X9V9/PveqB/P7yhdPCff21cCYJSHzEtrWCpWGBsbLZ41nLT/e56WggU4cxU8
         2aP+4IingRV5YlIK6JaE5Bk/HOcUH3CPtRezSigUcSUf73MC8fmml7oJ95gq/JsSvXPc
         OS8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709706568; x=1710311368;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Iixk1Cz5yUWXw7olNSfxlFkOHm4L0/duaiF8ek12Gj0=;
        b=hOU0O4ZXOn6TWs7ysAvwRwdIJoP1l0lrT6z20cflPRlIqwvz4jUMvSB5Y0sZdA1Msc
         kPICN2s9IDIkj/9JniWgPqexxvl5EnDLIpGGeRdEZurQdkv7pEwTl28NrxUhL34/iiN3
         TeRf5/EspwaApVTbHlQdigoub8sJYcVhhXBTK3ZyJKcJCaf5w6HV96L6SvnUFCzivqn7
         IF7yG7yBKL+j9quguMAkSaUP3329RbvuMT34+9ZhcWZYQ8jozJ1aE2Gsom5Ux9fp0nNR
         XVXJXvdnxf8tiSUbvH2SJVqamewpls9dvMUOGKHDzMJtUFrkDNL3ee1WW/JtveeKN5Ul
         CtLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXkcFES8K0T1k2OhCszA8Ai1eHpv0FyvDeYi6FzpDKRYJ15fu/MYRr9JpRL2iFsKyCHrCPCjlry+LnA0ND8SGXhwQKjIlsRMg==
X-Gm-Message-State: AOJu0Yx8+2h/c9GMOncbZ1cHnNQEs5SA6i5amOy6wpqsEiUm63ioo03d
	r/0Yejv3KtBKCC+rNG9lEZDss+Y7sSnCeteFaaGVzV60cvYCtbUe
X-Google-Smtp-Source: AGHT+IGXbPu1tMDf4Ii5MOt4uiyN9na5chUVBQkpNVnDkL+kLfWrFvK5q8UjMQesBWUkdk5m526dIQ==
X-Received: by 2002:a25:d305:0:b0:dcc:efa2:93fb with SMTP id e5-20020a25d305000000b00dccefa293fbmr13027362ybf.45.1709706567309;
        Tue, 05 Mar 2024 22:29:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d88b:0:b0:dcc:be89:34e3 with SMTP id p133-20020a25d88b000000b00dccbe8934e3ls424505ybg.1.-pod-prod-05-us;
 Tue, 05 Mar 2024 22:29:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXb70B+6kGVvchpp8S/gxjU29tUdh36PQcYuzJqFkZU0VjN1DecgYGp17gCJdQjGtIhVWSN8DwIyDXZ9lvvO3WXVv3eyFDW/GHEFQ==
X-Received: by 2002:a05:690c:f89:b0:609:7682:b8ac with SMTP id df9-20020a05690c0f8900b006097682b8acmr17714863ywb.35.1709706566308;
        Tue, 05 Mar 2024 22:29:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709706566; cv=none;
        d=google.com; s=arc-20160816;
        b=nIJSp3HzPO6CYpvFh9GYsnAUktaplqFJFAc253pITPjFVL/HbbSAepXuL9YTp76XwF
         R5PvWzVN2MZs17gqSM09DA0diH3bHr1wxDy8nCme7Ah0UM4EdmDZpHsXA4Xvz0+rfZLr
         egQHbXpfQFMRjWFWUS8HLgtC1jzI7CkRtAUksTPJqxWVI42K2BGr+rBwV9m81smRgoAF
         7Y0rruIfDNfd+LTobl3UHLlzwdsNhm7Dh50AMKgSVtGyIsSG1hM3UaLSTRYNXxIpg+kx
         83sRMDwupb2no2upf/Ng8c+ySynf6kpnvfgy8SptpWTAFZBd8oCicW4zzKzuXEDCRymG
         Bm1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Qyc7uUfABoD9IcjrTXlAmcqLlDUePbIzkZ9Um7DxAU0=;
        fh=IwDpbKdKb0JBD1tL/z3k//Mw9eRwG2nG4Jy/x4efPl8=;
        b=dww2OyFyqVWawH8lKTeh9uNLMuxfndppM/cqYgJfVmKHl/IeA9EBk0CpoAWKjluLwQ
         PddeEoSbxJIdahBR7em7k7xp/WFTUcvRDxqNBj4SLy4+VEdhiBJPA3y/rdSogKM8a0x3
         88LzIVz6B9QBXvEFyfwwETAtPLrZUaXJEVbVhOmQaCpCaenFNyozwG2ztYJymzm9Snjd
         lZaCb0BGAIlsnHSTArDleLnd57kZfMMKF65vs2D+yXtaVSfaI2TZKfrFoIg5918UQGJz
         3CmlCindMD0sgflnmUuuajQXbZfmKqEwzNAugA7+EwfnMp6V3lF/GlAe8YTHNMAZmtzm
         57Xg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MfRhLri6;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id y200-20020a0dd6d1000000b00609da8cc7ebsi54026ywd.3.2024.03.05.22.29.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Mar 2024 22:29:26 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id E5F2A61939;
	Wed,  6 Mar 2024 06:29:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3D312C433C7;
	Wed,  6 Mar 2024 06:29:20 +0000 (UTC)
Date: Wed, 6 Mar 2024 08:28:30 +0200
From: Mike Rapoport <rppt@kernel.org>
To: peterx@redhat.com
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	Christophe Leroy <christophe.leroy@csgroup.eu>, x86@kernel.org,
	"Kirill A . Shutemov" <kirill@shutemov.name>,
	Jason Gunthorpe <jgg@nvidia.com>, Yang Shi <shy828301@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linuxppc-dev@lists.ozlabs.org, Muchun Song <muchun.song@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 06/10] mm/kasan: Use pXd_leaf() in shadow_mapped()
Message-ID: <ZegNDhbFjPHTC3Pp@kernel.org>
References: <20240305043750.93762-1-peterx@redhat.com>
 <20240305043750.93762-7-peterx@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240305043750.93762-7-peterx@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MfRhLri6;       spf=pass
 (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE
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

On Tue, Mar 05, 2024 at 12:37:46PM +0800, peterx@redhat.com wrote:
> From: Peter Xu <peterx@redhat.com>
> 
> There is an old trick in shadow_mapped() to use pXd_bad() to detect huge
> pages.  After commit 93fab1b22ef7 ("mm: add generic p?d_leaf() macros") we
> have a global API for huge mappings.  Use that to replace the trick.
> 
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: kasan-dev@googlegroups.com
> Signed-off-by: Peter Xu <peterx@redhat.com>

Reviewed-by: Mike Rapoport (IBM) <rppt@kernel.org>

> ---
>  mm/kasan/shadow.c | 11 ++---------
>  1 file changed, 2 insertions(+), 9 deletions(-)
> 
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 9ef84f31833f..d6210ca48dda 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -199,19 +199,12 @@ static bool shadow_mapped(unsigned long addr)
>  	pud = pud_offset(p4d, addr);
>  	if (pud_none(*pud))
>  		return false;
> -
> -	/*
> -	 * We can't use pud_large() or pud_huge(), the first one is
> -	 * arch-specific, the last one depends on HUGETLB_PAGE.  So let's abuse
> -	 * pud_bad(), if pud is bad then it's bad because it's huge.
> -	 */
> -	if (pud_bad(*pud))
> +	if (pud_leaf(*pud))
>  		return true;
>  	pmd = pmd_offset(pud, addr);
>  	if (pmd_none(*pmd))
>  		return false;
> -
> -	if (pmd_bad(*pmd))
> +	if (pmd_leaf(*pmd))
>  		return true;
>  	pte = pte_offset_kernel(pmd, addr);
>  	return !pte_none(ptep_get(pte));
> -- 
> 2.44.0
> 
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZegNDhbFjPHTC3Pp%40kernel.org.
