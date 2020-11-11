Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLXBWD6QKGQEFUXKTSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D3192AF858
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 19:42:55 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id a14sf777597lfo.5
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 10:42:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605120175; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZASUtGHqfsMKTx79HSf7YcZjVfha08+oNpp744pz4jhP+ZU3fVhYY7C0O7vWUeDNkK
         g67BZWEbdCfDSlsN6v1GiugY3JFmvwkalNLJ192PlMNUAjwuI2lefQnq2nSzrSbMBoEk
         F9R++I4ZwkzD0q7VJobhsmkT35VzcxgOtcEcNH2RGp8UTK2GF7d6t0xm+PSAJ8rcT+dj
         60Ullaskv7RGpad5ip9eva+kN4g9jYZBzYBHvlljf8bMgHlJu284ZJQbKf/FPwd+A02s
         7coAq5/avFfbYyPDrLv0tD99wm5O07XY6dD8E0NgpzY2G670fgvTfS8Kk/6j6fqHSTGB
         Dy1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=d6Ur0pm1ezIOcOt5HBGLzu4OeZMoFLoIG2d/4BotkbU=;
        b=Axun8t6TLabmXYsdpOm6tbAfg+BhNBGUwhLy6qdh+oe4ythAuLWMB9qIJYJb5xQmQk
         HnAbVTz2nbmP0iqRh9YP33Pg6wT5NQEZ+BgwLdOESN/D0bqRdtsJj96H2hQZPD/AAywJ
         yQnbNqvqzy3Q0Rjl/rlGK5zsp7/b8czfw+BVISNC/q5FhTxE9Av4C8Qorvpsy8FkjlIJ
         dRPtDV52mOy+ThGr3po+FocThRwZClWnVHYUCQ8nXsCESCheRegqsfrrkdMlMWh7ALyW
         EAtahR+itUDPZr/NFVhED4vcmgxw3i0Z066S8hGGgF8pTu+tBYnr7qtseiknRU6C9gTM
         WnJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q5lLWorc;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=d6Ur0pm1ezIOcOt5HBGLzu4OeZMoFLoIG2d/4BotkbU=;
        b=iPdOS9/KcTY5DuNlIaYCFXXrzARcShaFqPVGU/18HUWsVP2q9Z+MGJTKIiastyq05w
         pidf+Fcs6nbLl2WAsa4FTJe6aPkGVdTQ+hj0z+nH/+lPzrfIBY+DhnTL7HgkI6RYBYBW
         kwfQkk6NjGLxywhnsfV2h0mmkCc1N4yljbIKglG3iNFX2l3jJSHedryAZYS8AEW+gQMP
         Q3e+EF+WZE1ICuMcTK+E+GC5Qb8oIzlJpZKgyQjtxR2ir0U4PO3+yCmQ2hRb3oA+5kng
         q5ByfmTX+gfzlkhsZzENRTCSiniTpUZD9ix+xFrXfEunfwj0BAfYWCvAZhpAq3hgDTpU
         zySg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=d6Ur0pm1ezIOcOt5HBGLzu4OeZMoFLoIG2d/4BotkbU=;
        b=n9/HqY6bNay9MMjkJjbrE+fP2wagtBzKIGphn/pVMKEt9B1tR/msVs4JT827uLSBf5
         78ItVLw08UI/LJ9XyT79xq5KiRFRqn3e4s52P81cJ1gP3KcUByrUH3dkavS9ogeTKNMs
         W8CeWmHREWLpkIJbNaw6BMk5tRQt5YlczHVxc0q9nWQwdnuFkXU3RD+o4WuQSWW/I50v
         YiSVCoavDyDwjD+PAJJuWk4WdsbxVD+dcfMUgk45PL7ss45nOwRerb3cR+Sg4v5MeEwm
         VMjz49kFkDo0R05uLLsOPqz3cJ9aJq//BtOySElYDlskkxOOlCssZCet4Ob9MkzzkKkP
         rHzQ==
X-Gm-Message-State: AOAM532/HDXvkMX5sKpsG1DyjT7TZK9vPNqkwcUxWJxC7Ew4jSbS3aLg
	1Akl6L+AAvGma4jukWZsmSQ=
X-Google-Smtp-Source: ABdhPJzEb2FVpKwTZV6PtMVOHiIO/sbEt/oXDmWjv9HBsAf3cuIRp7ooXNMwI4cN1MdSBtMAc96I/Q==
X-Received: by 2002:a19:6003:: with SMTP id u3mr9532348lfb.317.1605120175114;
        Wed, 11 Nov 2020 10:42:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9f48:: with SMTP id v8ls86433ljk.9.gmail; Wed, 11 Nov
 2020 10:42:54 -0800 (PST)
X-Received: by 2002:a05:651c:1213:: with SMTP id i19mr10312974lja.407.1605120173986;
        Wed, 11 Nov 2020 10:42:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605120173; cv=none;
        d=google.com; s=arc-20160816;
        b=N7qJhQvqtkKENM3pgJiFL9dYYSYUYk1E5F3BDM7Kg4KRdh4imrCoRqlRtk8Q3RCSyv
         yCYWH0ZbFQAJe22NIAlrUJkecxGjRbartKShQ4srqO9BKCEGhtzQXcVr4lmQSWYIQJ92
         J+TB7bZ1a6dKcLltibiUpvAes1j2jswncMdGXAIyLWuURhJaaunmAbTjBxn+LV1Qmyer
         scxSdnISukAhl2hsPDqL43Yta/oRrNPVowFj0VUtgWgm2TcEGGnxqPh4aMGgaLRXgjpF
         m5wlJTHkBPzC18L/OCkrO7LUZc6FGpNV6DcnwzEhnZ4yhhotBM8HhfAK918kW94KwG0C
         +ZLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=VohxCgmaGc6F7Ktsca4rjVlrZ86gTh1fROnDD+cvua8=;
        b=WK0AP4gMsRiWCb/9z1axToXqyDP12dQ0Z2aZhJMbW58toGPne/GYUwMgkorrsk3qST
         Mgmys0C2rJcdauxlXHp2sjpIw4oNNamIbd3iltihmKv2QSyvkM2WRoS57NluZaxyQlgH
         CzNK1dDcBFllycPLADxkPqSPv4UFGBVPUTmtvsJ7WGCK+8Wi7KKnGUNIlkdi2CWLIrfw
         JIVeigLTBk5vhIo1c9jFCgd09UjuytrSidA8IL9Cg9TcGhiHkHf6FrKXWGaKfjAYyRfA
         hxapYYnnUzWxhHd/CRrSzOS6yOspOdglb0fZgl2FBQ6j5hbaRxzLDi9PNthwRQUu3omx
         30og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q5lLWorc;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id q16si80874ljp.8.2020.11.11.10.42.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 10:42:53 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id 33so3521753wrl.7
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 10:42:53 -0800 (PST)
X-Received: by 2002:a5d:66c3:: with SMTP id k3mr26447563wrw.123.1605120173432;
        Wed, 11 Nov 2020 10:42:53 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id n10sm3431496wrv.77.2020.11.11.10.42.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 11 Nov 2020 10:42:52 -0800 (PST)
Date: Wed, 11 Nov 2020 19:42:46 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 13/20] kasan: simplify kasan_poison_kfree
Message-ID: <20201111184246.GO517454@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <a1c57043fb19effce240355e7c57b0d9a58d389e.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <a1c57043fb19effce240355e7c57b0d9a58d389e.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=q5lLWorc;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::442 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> kasan_poison_kfree() is currently only called for mempool allocations
> that are backed by either kmem_cache_alloc() or kmalloc(). Therefore, the
> page passed to kasan_poison_kfree() is always PageSlab() and there's no
> need to do the check. Remove it.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Link: https://linux-review.googlesource.com/id/If31f88726745da8744c6bea96fb32584e6c2778c
> ---
>  mm/kasan/common.c | 11 +----------
>  1 file changed, 1 insertion(+), 10 deletions(-)

Reviewed-by: Marco Elver <elver@google.com>

> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 385863eaec2c..819403548f2e 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -432,16 +432,7 @@ void __kasan_poison_kfree(void *ptr, unsigned long ip)
>  	struct page *page;
>  
>  	page = virt_to_head_page(ptr);
> -
> -	if (unlikely(!PageSlab(page))) {
> -		if (ptr != page_address(page)) {
> -			kasan_report_invalid_free(ptr, ip);
> -			return;
> -		}
> -		kasan_poison_memory(ptr, page_size(page), KASAN_FREE_PAGE);
> -	} else {
> -		____kasan_slab_free(page->slab_cache, ptr, ip, false);
> -	}
> +	____kasan_slab_free(page->slab_cache, ptr, ip, false);
>  }
>  
>  void __kasan_kfree_large(void *ptr, unsigned long ip)
> -- 
> 2.29.2.222.g5d2a92d10f8-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201111184246.GO517454%40elver.google.com.
