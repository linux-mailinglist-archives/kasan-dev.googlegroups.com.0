Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBW5KRWBQMGQE5KSZVJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 7152634EE1B
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 18:44:12 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id v16sf5649414lfg.10
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 09:44:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617122652; cv=pass;
        d=google.com; s=arc-20160816;
        b=uSTo+SrMAAs/a2SQX6L4G3BAS84VeoZRMXDGC1cN31hF85zbom53x3Eqd68emWH1iu
         03QoUqkfo5idKSETysFja4c4pQd1qdfs35lvTSt9AkDi9JDYfmM+U8i9xKzuhid3miwZ
         +M2w255OKRHPnHM2DxZwEUMlkR0UU6L5+i3QLTX/sjBN37dSWqi+Y+Emi0WVt8mJbhpm
         2c0cvRmfsSME5vkz8btmLLjdLl5XAJvUgdWEWyc24wNO6UzmgmxO2/AufLD0j08MV3zD
         hjZaJE7iqKizi+wBHl/ySxKhVw0MJmkDV515yZaznR+jKm/+tYpk+0yFTUWwflUL3Q/E
         RT4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=8ZYdv5AvTp8RzMKoQo/lAG0KpH4fFQt4blzt+E8ppdM=;
        b=vKzrFk2lXfKVw9B70qSb+xTkYwa2eqgmBJMhDEBlVmVXDnbjydr2I2KOVwRY7SuARO
         8c+Gl+HTFWSaPpZdhOB4vJuNmQngHpapE2nfU96OWhYHCGVUsMFriTCVf+mSzh0kC6Hr
         UDVEkvF0OlcjiMp40lRhQ+px8kX0ZQ1F3vTo0aSBTp4LeCYpP2uThbB82kIj1UNHiD3k
         UQ6yxabNpYfUXDnU5mYQ5M2BZ/l+M/l5cOj5UjkS51PBCh7UhszpDe4TP1ujbCx53skc
         1bWrsejvxIV8Di49YUDIi0zsLgGv/9HofeuC/M/V6fr/VpK7T0bbT7xu4LrcFFi0D1e8
         CwRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8ZYdv5AvTp8RzMKoQo/lAG0KpH4fFQt4blzt+E8ppdM=;
        b=NDaskCZZ9DJsdNAHt0LynzDIIkB+5C+QBT7qnDlOGF3SYpHG3MYunjZSNFtishc+mx
         weCL0+VrJ84D+/8ewl+al2+fb5zC3CyOmQ46Lz3NjJBTrbTZnndgCpnu1ZF4mkBe2zUW
         Vsp5Wel0kzV7QiynkeKoD5pSpXoiRgQUQ7ShLj4qMoZZnSn2fR8t/ntaxbV9mk+P1opT
         IRySNv0X18tDdIWCJBDWd1a5yjP/7fXXtGD2uUOffiwdmUHV5qfL+GJ9wm3t/U7fkeeu
         K6CgIw7Kwl+HXu6ptq31o9e7NcBubjmqjiUnSmZmiSr2FHf4JmR4KctPKXBjcxQDXiR5
         AEUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8ZYdv5AvTp8RzMKoQo/lAG0KpH4fFQt4blzt+E8ppdM=;
        b=I+pXXjjh0wVSdCnlyOWB611h5RH+zrLUfuysRXsLzVCx6as9JbgZqw7b312gn2mz64
         j90B0Qs9e8Woq8N97cvbMqLoEyyKOa2tfIcRgVzrK87Rkae3ZvwQm+d1QC5s3vtKSH3b
         l5tzAlFV/Y9y7cMRBhefiNBHcipEDgHV/YJmDK26rnKk1JOX2DuBTChVzMyRSmBfNhIz
         k69l/w5I8nqWpVnPmnPCeiuW+Gi7QJiojmRABqpEDWm2KBoyEUluKuNLvpx+DATkSK0a
         MJGg7PjurCP9yPDXk2aB/V5qXsHOG/leAHsoj4iyb5uLozxZTwqVP6TPG4f930ZFLA9e
         V5nw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530qXRvf1Ahmseg4Voii+B5NeJ2SH8/ElKm+4IKmBDvz9B8CPvwj
	0w4OUXsj+CIQb51GNDFjZ7I=
X-Google-Smtp-Source: ABdhPJwYXejPBg15yVqoE8TkCXHYxgMmua/KlpmJdpEaVw9pIPKOVX8cdo3Kk3Tyxa+yH00KqCPAWQ==
X-Received: by 2002:a05:6512:693:: with SMTP id t19mr19546904lfe.205.1617122652038;
        Tue, 30 Mar 2021 09:44:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d16:: with SMTP id d22ls7524733lfv.1.gmail; Tue,
 30 Mar 2021 09:44:10 -0700 (PDT)
X-Received: by 2002:a05:6512:36c1:: with SMTP id e1mr19738665lfs.132.1617122650879;
        Tue, 30 Mar 2021 09:44:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617122650; cv=none;
        d=google.com; s=arc-20160816;
        b=l/p3KJW3m1SwPiHv4yazvNGAmIVtt7DyDKFfr0ybjbqGzEl7rHSfJsvZrSzEaWw/B4
         GLLVaaAap6pSRroylAfpIieIM5rNZeK9NcK9555Gy2zsH40PR+MRUBS5uv/6bIIRFuY7
         ny6NdyOL/QXXkzGzJGmh7bGE0PxGQzfE/v6ZJs9v9aR0uNfij5dxU+WFBnZEGcCycUul
         FX8fGBOY7ZHLEnO+UcMsEC0TUplpk9qfDLfndwLDZbxroJnWTJkpK7AsKEg5gGB2Y/BC
         gYZXTZLqUgx5eZfRRI0ke9TbLxSqwkVibtR05QAVxBrAjOws3V8qbrhyMjs5H7mEe6CJ
         zAVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=BblGTPjukWoa8VnRbNefv63l5EwB6ojoSWVnFIKy4ac=;
        b=JbFo3VKFK6hXs9Ma+xve0wS1wa/MPq6fHmZevHjQqvHlfcWJVnMae9SVvWdzF+jrzV
         /c/zX8ZcRATyX0tGuf9wAcMJ7X2a6sHyClqmiLqP77Xsh5ijapdgWz9hxv567q2aDZKi
         K4fZ2E81Fzka+RsD+RBeyjmATaTBvChve+ZcSQJtga8jpyVo9x00zwnQ1rxY0HJHDamF
         n5L6lGOdbTZ7LxXMovsawc8o1HBPlhz9j8t30l2FxLXwB9AlLuwa/DCRBCtkY1/g9PC8
         H49zxLe15YZXl3d3qjurNI0jjVJ+7h1CNO/ghIIM/gvkqzOU/gfO0eaBcahT4kBQJaAh
         aEYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id f21si934505ljg.6.2021.03.30.09.44.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Mar 2021 09:44:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id 207D0B02D;
	Tue, 30 Mar 2021 16:44:10 +0000 (UTC)
Subject: Re: [PATCH mm v2] mm, kasan: fix for "integrate page_alloc init with
 HW_TAGS"
To: Andrey Konovalov <andreyknvl@google.com>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: Sergei Trofimovich <slyfox@gentoo.org>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
References: <65b6028dea2e9a6e8e2cb779b5115c09457363fc.1617122211.git.andreyknvl@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Message-ID: <404ad944-ab46-cffb-5fbb-3dd7ae25caaa@suse.cz>
Date: Tue, 30 Mar 2021 18:44:09 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.8.1
MIME-Version: 1.0
In-Reply-To: <65b6028dea2e9a6e8e2cb779b5115c09457363fc.1617122211.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 3/30/21 6:37 PM, Andrey Konovalov wrote:
> My commit "integrate page_alloc init with HW_TAGS" changed the order of
> kernel_unpoison_pages() and kernel_init_free_pages() calls. This leads
> to complaints from the page unpoisoning code, as the poison pattern gets
> overwritten for __GFP_ZERO allocations.
> 
> Fix by restoring the initial order. Also add a warning comment.
> 
> Reported-by: Vlastimil Babka <vbabka@suse.cz>
> Reported-by: Sergei Trofimovich <slyfox@gentoo.org>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Tested that the bug indeed occurs in -next and is fixed by this. Thanks.

> ---
>  mm/page_alloc.c | 8 +++++++-
>  1 file changed, 7 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 033bd92e8398..d2c020563c0b 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -2328,6 +2328,13 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>  	arch_alloc_page(page, order);
>  	debug_pagealloc_map_pages(page, 1 << order);
>  
> +	/*
> +	 * Page unpoisoning must happen before memory initialization.
> +	 * Otherwise, the poison pattern will be overwritten for __GFP_ZERO
> +	 * allocations and the page unpoisoning code will complain.
> +	 */
> +	kernel_unpoison_pages(page, 1 << order);
> +
>  	/*
>  	 * As memory initialization might be integrated into KASAN,
>  	 * kasan_alloc_pages and kernel_init_free_pages must be
> @@ -2338,7 +2345,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>  	if (init && !kasan_has_integrated_init())
>  		kernel_init_free_pages(page, 1 << order);
>  
> -	kernel_unpoison_pages(page, 1 << order);
>  	set_page_owner(page, order, gfp_flags);
>  }
>  
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/404ad944-ab46-cffb-5fbb-3dd7ae25caaa%40suse.cz.
