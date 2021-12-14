Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBR4K4KGQMGQELK2CNQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id D70B04741D6
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 12:51:35 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id j23-20020a05600c1c1700b0033283ea5facsf5566431wms.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 03:51:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639482695; cv=pass;
        d=google.com; s=arc-20160816;
        b=rI/UCrlVz780RDorSgucoEdZ6yQJfqI9jbTVp5z4PZ0cI4scofucCSglKyLbUp47Nj
         Gs3Z9TP3cC2kaKHFv7ROw4ZLjQ8ToLdfGQjjKxZznfMGAzxg1Tf2VHbpkjT/QajE42Yw
         C5bFLFdBcelI2F6CaqfcfPIbrdRHpL/8jAkoPJNSapEVbEp//KZNTI1C5wHfd/Le7/aG
         sC5QeX7duQnb3Bb+3Jz1QP69+N6Tu7bNPeYIHyR0Fbz5IfzSWIoR6xRAr/mx/DI/dTwD
         wCUk9Qfk7Vs2AlFmWNw4DOMN2OAhwUD21+qJ7EDEkp74Fc71YqNDiLItRW6aqUytfqRO
         EJZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Hjmq3ysfhS5V6WIba6/cQiyAA+wfv93ZTCe6oBqs4Fc=;
        b=vh5KGgEzdBrJqldVTEzzwxYISVSxPbrptfHFqu0VMwmI2iSZ/r3sqKtRzN95BUiFKD
         yeKRaMekODHvRgpIeQbXM2oCjn9HHu676aQi6fgVM7rcIn8iJChiaQWCt6k3L9oqZ8Qp
         6WVQEq2yo0bLx13+Koawp0prrKhAuNm5nW9k+TxPTtB/GY7sm/dfIaDtE69cJiRDgwjS
         hDeK9GNlyj2o2GUL7Pbb0i3X+WVIn1288anVI0Cg8idcrKD2FfqyQwc2NLH8IqJHDybL
         QlOYwlhuXMH+1r7RMK1W4k1KQ0ZX72PhOxEbyJsEu6Gzju6xILge5zXEZkZmQBkopJpI
         BGtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="N+yr/RKD";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=6UFyUQfv;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hjmq3ysfhS5V6WIba6/cQiyAA+wfv93ZTCe6oBqs4Fc=;
        b=Dq4/55jUeaLJStO/U+5/ygzqCKgn2rVezAK0Abp+MJkYNbC0/5wDjTSEcCHSzZIPew
         Nwx2ZUH1kvB4O8FjfMO7IYqEi3wGgOy22BAhiV+klrj9FNUbC6AB+73BhVk6bHkI6fo1
         7imYqCfUcnRFXGiI2GOfilF6wnzFGi6Jh19cg4Z9dsMxNkWKY9SmQawKetSseuWIzgjB
         r6nZ7L0xamKK+YYXoCW3cTSJZ3sneraJDJ+mumt1Tq3gzrAHQu4KUKs7sjBgdBnHQ06p
         kT0ytZaQInHKgfwubJfxtOFDztxB2iwvVLnZZ7gA7qUQIGoeyy7zqAuGV0QX9LBjVXWr
         OvBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Hjmq3ysfhS5V6WIba6/cQiyAA+wfv93ZTCe6oBqs4Fc=;
        b=UasZYWlzW7ZY2BvhVQdA/GdFoZjpen8teyW01psOigikBMk/S6R9RkgLxmxbsS57jY
         KEoTzuAKA/yET+AOSA6axV0ga3jaqBfYEwotjO4mtE7yOwFVCLtZiKVkOozDyHZo7kzs
         7wDVYVr5C0QW1KNUHHmHw+FPnjQoM9um6pk27APb5pEuZ/CLKe8RcSaV9ucf2kY9oDIh
         HtNRbtZ2MLZg4+C/aLo/LPqJy6iGyYSLTOx7v4Zp+4eaHoGeXsIvxNms8hgsqKgvA1J+
         P+OKF+ojRUtPQUGymaRVHQqwuzT/+8OkpruU7MY/C12T4b+pyncG5t/vCgZ5oEDMM3/n
         czvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531b8hCAKmZ7liV7J6FEl995r3zCx+7Eecv+bkAWKAZT/WDj5Bll
	Cvql0eY25OSRCwU+rYmjC3s=
X-Google-Smtp-Source: ABdhPJx467UkMtRB+jhUso6DH7oykj+HULsz09HJuDJgNzB3Mynw8FyEcNYvypvKHu5G8nrDCnB/VQ==
X-Received: by 2002:adf:f00a:: with SMTP id j10mr5422745wro.339.1639482695497;
        Tue, 14 Dec 2021 03:51:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a4cc:: with SMTP id h12ls166961wrb.2.gmail; Tue, 14 Dec
 2021 03:51:34 -0800 (PST)
X-Received: by 2002:adf:8b19:: with SMTP id n25mr1348264wra.619.1639482694522;
        Tue, 14 Dec 2021 03:51:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639482694; cv=none;
        d=google.com; s=arc-20160816;
        b=L9CgqpHyE+JCrbFzSWYJ1BAMHRaBNDeUSpPGDg98uubem8SZlLXEdML90oQ3OmFEB8
         vReKUxrNNwWyUV6Bl080dVKP8OitPSkG5M10ZrQ7b8edqixSLUpG2v91Q7AQBpCfPhYt
         I7ctnBuRzGmvWgw/iE5uKcCAPG4pDjCfF0j30/wzTgXSyrw7g9ul3D6liN3PNSStuqNe
         SuUfslwX+E4f8NbP72Gx/wjB6kZBiXJ90BPmL+8F+bUq8nIuIRaiiIhD8UtwmhVoqnzz
         TY3fltzAlogmFFOK/0EpfJMVjW1uHv8oQkco5c+P7eQuiqNMOE4RNwE3uC9DNhc4B0dJ
         9LBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=E6efcRJNZehu3o7Pp7wg4mncnN1XYB+O+/iUJw08HrA=;
        b=WmBiP8LCA9DmKmoALl2otJbZ/OYys2O18Hgh4fGPqS6iV9QmR71Z76yZTE6UI/VMi2
         NiDHaSUMNzUwUZI5f7tL9Se06ZgQENR/53Ov5gnG0SupMkdhNmA1WeNj5DTsrPmVp9St
         4RdrNuucdXK/Z7j+TfOVB8WYNK1yTI+3PUamFgGKkVfr6LIrFXNNoeN8ftsQkeFqLKZR
         HShnCluIaAJQ66Yd8XReO5CR4rcvyvtg/rONJOj5k+JYCVmShJJknRgxcVV/CU6rVTz+
         wB3kcpvXhxocArgmAZXssQHrNAsGE2bk9KmMU0RU4q9Dux+Poj8L/U2BzZypei1lCIqt
         Eg7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="N+yr/RKD";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=6UFyUQfv;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id 125si87508wmc.1.2021.12.14.03.51.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Dec 2021 03:51:34 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 2DA891F37C;
	Tue, 14 Dec 2021 11:51:34 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id EC7E113BA4;
	Tue, 14 Dec 2021 11:51:33 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id VeH+OEWFuGGbeAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 14 Dec 2021 11:51:33 +0000
Message-ID: <765ffdf0-491b-1f44-21a4-d57138477daf@suse.cz>
Date: Tue, 14 Dec 2021 12:51:33 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.4.0
Subject: Re: [PATCH] mm/slob: Remove unnecessary page_mapcount_reset()
 function call
Content-Language: en-US
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
 Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
 Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
References: <20211212065241.GA886691@odroid>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20211212065241.GA886691@odroid>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="N+yr/RKD";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519
 header.b=6UFyUQfv;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/12/21 07:52, Hyeonggon Yoo wrote:
> After commit f1ac9059ca34 ("mm/sl*b: Differentiate struct slab fields
> by sl*b implementations"), we can reorder fields of struct slab
> depending on slab allocator.
> 
> For now, page_mapcount_reset() is called because page->_mapcount and
> slab->units have same offset. But this is not necessary for
> struct slab. Use unused field for units instead.
> 
> Signed-off-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

Will add to the series, thanks!

> ---
>  mm/slab.h | 4 ++--
>  mm/slob.c | 1 -
>  2 files changed, 2 insertions(+), 3 deletions(-)
> 
> diff --git a/mm/slab.h b/mm/slab.h
> index 90d7fceba470..dd0480149d38 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -50,8 +50,8 @@ struct slab {
>  	struct list_head slab_list;
>  	void * __unused_1;
>  	void *freelist;		/* first free block */
> -	void * __unused_2;
> -	int units;
> +	long units;
> +	unsigned int __unused_2;
>  
>  #else
>  #error "Unexpected slab allocator configured"
> diff --git a/mm/slob.c b/mm/slob.c
> index 39b651b3e6e7..7b2d2c7d69cc 100644
> --- a/mm/slob.c
> +++ b/mm/slob.c
> @@ -404,7 +404,6 @@ static void slob_free(void *block, int size)
>  			clear_slob_page_free(sp);
>  		spin_unlock_irqrestore(&slob_lock, flags);
>  		__ClearPageSlab(slab_page(sp));
> -		page_mapcount_reset(slab_page(sp));
>  		slob_free_pages(b, 0);
>  		return;
>  	}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/765ffdf0-491b-1f44-21a4-d57138477daf%40suse.cz.
