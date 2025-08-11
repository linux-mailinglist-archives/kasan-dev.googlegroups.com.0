Return-Path: <kasan-dev+bncBDH33INIQEARBB4E5HCAMGQE3ADQUZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id B43BBB2153E
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 21:18:32 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3e5584a4cc5sf6193585ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 12:18:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754939911; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZMthIZ+dMb9pmBpHjv62Ycl3Dk7tKe49LWm7KKHYqpr/8sqQIy6apPzdi2p8Kq8glU
         Qyvx7Qm8Uiu4376NRNmTtPgKxtx18LaqaGkMN9pQa+ij0YHQNh+KSr5fpMwIprEIQe6d
         hYp/cWKeLENzI8LCGFA8Hyead3W3RdHxW+E4hKLCmW8Xticf5DAmxFxcxMIqYtWNYed9
         dOh9/LftzXKelxgjV3hHa4+oEVVcsVT49cGlabr5cwEOCd29typ2yk7RehDqzA+Cbw1V
         dSTMr7J2QtNgqaO9/mbGle1rrXWnQ+SUKufJzHKozKcGPKEcMlJnRKCbz+h2YvUx9tIe
         VRkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=kU95sGe/y4DQMA5+wfXbBwbSzS/9i0bfY48sWDoc6Xc=;
        fh=nUfGXyrOtMDpZo2P6wxf+WVTrmkcoS2UY0nArT/f5Zc=;
        b=goZ86Ldg47t+qd0K78OrJ2n0MYKPF7MiyenLZBTBOCQZAfnin1KfRSVsteIQ8Pce6Q
         lbIxc0jS9lrIsQ/b21PHPGpB46FqfzKLaZ11vtVQNpiQ/Jmvj3NlDysoTUvYKeH0mgt0
         0+xDNdfhdhEwRJYgaf01Lu6zTVn7VBIY0zoECd7TZKjU/HTRo+B5oIqaMFEIcyXidd4u
         OEI+YHSpX1JGML2S/bPQvZNYXOLljcqtvwHvyprng4YikoPBq/5XeRA5QxD2AkpVIHZz
         K2b/xtO1Ndz0mFSKyiOLpGtvKVFkZsbGKdgmkeI5U3mah/KNYWEMkPeGgusQUOuxEJAN
         HrFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IbcnafxI;
       spf=pass (google.com: domain of vishal.moola@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=vishal.moola@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754939911; x=1755544711; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kU95sGe/y4DQMA5+wfXbBwbSzS/9i0bfY48sWDoc6Xc=;
        b=jqn6Oc7B0SXh6aDUqauKXBLyrul7lfhYaEa0I1zqXtN5lE0r8bCkoddTegkbfKBhej
         ZSWr1qT2zXgmYyCr1uLyFXdFVXEdV7z6XM3fQuRpeghvLiDYp/qV2DXZhfCPzt69a7R5
         UR6v2WK0+BbsbGhK1TL2+xuPztGrQ7d3UHZSrxwFNOUoWdA8lL2aGr+6c17BlD0kIPe1
         aXFqBTQnxXvEOQRUreB/adRnA/taLQ7Yd0Hur5B0Gcj+Yyywchl/l1J0gGS8rD4coksK
         areBjrmTMvb0Fs+8Jlxie4SSpDCH1ZY9ywcrFDlzsclmjZePv6s34elKj3avHidoCkgw
         fXcg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754939911; x=1755544711; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=kU95sGe/y4DQMA5+wfXbBwbSzS/9i0bfY48sWDoc6Xc=;
        b=aKG6FtiIDSa/TR5IAYVSy1kJaux0m6ipn819VGpPGeV8LhfZyQGFLb4zTsY5hpawei
         KFFnsQ25UbNzH6nGbSsT4Hi1Ou0Bx9F0MMrDs+lg+MI1tOoxQmIZ9DHRxEtJttLs5w7J
         p/jal/WYwj/0Q9IFCgATBW84yAq2Vq7RlZvaRSPpHn3/zOACc5QVC6Gw7knTrdygdmff
         7mVYTHq5gJV4oG2PLeOf5nZuWVouvhIAwquj4xZO+StbMAntnU39Ptsc6VhAyxE24OHh
         J1hEG5M5ZSR0W9hqupwntZSJPdtBzmSONiepkI0r9wiAX0XxjRdsIthLgCF/jgHbpl/v
         7S9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754939911; x=1755544711;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kU95sGe/y4DQMA5+wfXbBwbSzS/9i0bfY48sWDoc6Xc=;
        b=NKisNmroi87PqZQQoiNQCR1jGrPvjr7Sr2NBzbeJClR437xbRV6zvyMOAFfcq2o/+C
         DQ5XJpPPCzGmrCMG7xPrE+z9OAKhjDLGe+kRrlytjD+6+scAa1P1Sw4DrMzaexdZDLPv
         fHWtjE8ZC/tsnHCpa8xWYnEOMwo9AJWzw+7YZNDOU/3+dygEdvO81B8YGiRHI8tbTl0V
         kvnQf5J3BGZnF8UicnHiTiLEZiTgU98BwZlGsnCnbbnDZLpfmZAZg2j3jR4St/covAGV
         64iHZqbZvaNLQ9g6aaOoWsuH/WMSr6zbIwr7G00va89CXAxZU0seG/1/L4lRVxf4wTSu
         LxHg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXm11AbdA6S/NdIL7H/wOnfzJBUUyyXgJ112S4x+MFkyoX79/0Fjg8aRKK0DPFml6G4lu+h9A==@lfdr.de
X-Gm-Message-State: AOJu0YwGYp/E+okrMlBkST9/BIQDGGQi45es6Bjkxq953UFH8zB4Nl6k
	k58iUweyf+Sb0vzqrlbI72VYrrzJ5UYhzhs81sAHrId8NUZ4vbRG3spQ
X-Google-Smtp-Source: AGHT+IHm+9G8GQwACsPqyG7YHEzRW/XJi0UXlvghQvcUvjI1+pJAlnDFvAmnep/7S6+v+gOqDPb5iQ==
X-Received: by 2002:a05:6e02:2301:b0:3df:5333:c2ab with SMTP id e9e14a558f8ab-3e55afb9903mr10219295ab.17.1754939911170;
        Mon, 11 Aug 2025 12:18:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc4CTZzuaAzDqU+3or+Ic6WlEvBQDcqCvqcf3FR4gbTiA==
Received: by 2002:a05:6e02:4619:b0:3dd:bec6:f17d with SMTP id
 e9e14a558f8ab-3e524af4783ls43406585ab.2.-pod-prod-06-us; Mon, 11 Aug 2025
 12:18:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWJW4wfLSOW1RaDVyzqQ2nGiRXEWk6mon6rsHoiUGiMxgkGk525OE0pqr7V8rbfMvETXgWOCOe4hjw=@googlegroups.com
X-Received: by 2002:a05:6602:2b94:b0:883:e1b3:19cc with SMTP id ca18e2360f4ac-8841be8a3b1mr209623339f.6.1754939910317;
        Mon, 11 Aug 2025 12:18:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754939910; cv=none;
        d=google.com; s=arc-20240605;
        b=T9M9bbYTqoPtz5VJWzgNiWQniVz9Lg7qykwV3KnRG8PkpbFELIHl6daRuFL8+G3WA1
         FbQaFoOWP1YtgL2h02mvcWoJIP1eQ1iCB7TURx1DUC6h14BVJyNAQcVk2F2NblFIRAp9
         ojcz/mCYszQZ3tm8DHs6EDPapixiAAvGr1ZVGvf8WxykmQuf6VNZ+MncFw27jQyC7obO
         KRBBBXyrUIGZ0KpSpnce0sXeriervkHAat1llgtQpi/v5BsUoJTrzqwXzPSXXBHuDt8a
         6iWO+nt3W0JK2W0v5cmCKqOvVCk2alBzwTGI4sikvSLqhwU69qj+XFVOWZxnLiXDbOsN
         8Byw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=C+y9z0wbb7UZ5PYTp6B+LzKdJrgF2sCfiImrK7E1sdo=;
        fh=vZQsFjngTFM8K9fQHqGTFO8PtPxInnytKD3aE2hrsKU=;
        b=drP55NtyNV7s0FcRZOL3RwRmEoQ+CPJ5SXQTaLEdJVW+PLPix0LX972AQnzTjHdVay
         dc901HTf11nSQbSrXy+XPdb+I9ml9LyZY2xXfpfoB/hLNtNJtldm9HwnWHL4loP5z6lh
         eRpb86Xx9cUIlJhV7yB282z6/cCfzAcJ7zQIraJ0jjEdXlHpMHqvh3d+p7wF4z7sRDpR
         9hxh4CWqIggjxXJOzeyebf/ywpN2FtOmmjADbVv7flz6n79S4fQ9UgWfAgW/oH2fz9xV
         Sw/nE5obNls/248XwaN82evaxEQbXXos5sIFFyFaKF/8phvvzCKWkkcCCHwJG/Mwd3Pm
         bs9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IbcnafxI;
       spf=pass (google.com: domain of vishal.moola@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=vishal.moola@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8840a297750si14642639f.3.2025.08.11.12.18.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Aug 2025 12:18:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of vishal.moola@gmail.com designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id 41be03b00d2f7-b34a6d0c9a3so5452986a12.3
        for <kasan-dev@googlegroups.com>; Mon, 11 Aug 2025 12:18:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUTnzbJScmqqwE8+vLiH4cZlElg9nFr17ggc4Lij9rqxLOPQsyPt5EpMaKZQTSCeelq0lABhJAMU+I=@googlegroups.com
X-Gm-Gg: ASbGncsdNm+Gnm3VC5wrKh2ywmROlKgk9T/awmhTcFbUzDrpz53iBfWXMyDg/CpyE7q
	4TADXJoQ3xtYy3G4Fazu4NP4Jcd6mb1aZW24k+teWEAHdcZC1GQzTcuyv87DnkCDTNubid2gI0/
	OQz9ZZcherhxtRQJBruIMUzqaXVhmnWVnXYEHTONiXEg+V3b9EJ9Y2YlWHVCr/HPaec79Ka62L5
	NPcT3pfoiA150ofle2YNCzaG4fpKYkTJcBenEzd7CDdoh6iWzd1GDOxGHA9Rcrog5I0utxsN9k5
	U+K5HQf9s2YqNydeBVbsVF96S9y51UxY8HcjasUlCTpMRTqOb0KQTp8277DrVFp31leqALAQ+p/
	f2OqRYri7X2Hu3FYAZxprnDGT0k3JcplZ/+tTpTvA9hcIY/QA4CDaDg==
X-Received: by 2002:a17:90b:58cd:b0:312:ea46:3e66 with SMTP id 98e67ed59e1d1-321c0aa6dffmr950367a91.21.1754939909511;
        Mon, 11 Aug 2025 12:18:29 -0700 (PDT)
Received: from fedora (c-67-164-59-41.hsd1.ca.comcast.net. [67.164.59.41])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b422bacbb74sm23639347a12.42.2025.08.11.12.18.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Aug 2025 12:18:28 -0700 (PDT)
Date: Mon, 11 Aug 2025 12:18:25 -0700
From: "Vishal Moola (Oracle)" <vishal.moola@gmail.com>
To: Xichao Zhao <zhao.xichao@vivo.com>
Cc: ryabinin.a.a@gmail.com, akpm@linux-foundation.org, glider@google.com,
	andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] mm: remove unnecessary pointer variables
Message-ID: <aJpCATXWQx1hEyta@fedora>
References: <20250811034257.154862-1-zhao.xichao@vivo.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250811034257.154862-1-zhao.xichao@vivo.com>
X-Original-Sender: vishal.moola@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=IbcnafxI;       spf=pass
 (google.com: domain of vishal.moola@gmail.com designates 2607:f8b0:4864:20::534
 as permitted sender) smtp.mailfrom=vishal.moola@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Aug 11, 2025 at 11:42:57AM +0800, Xichao Zhao wrote:
> Simplify the code to enhance readability and maintain a consistent
> coding style.
> 
> Signed-off-by: Xichao Zhao <zhao.xichao@vivo.com>
> ---
>  mm/kasan/init.c | 4 +---
>  1 file changed, 1 insertion(+), 3 deletions(-)
> 
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index ced6b29fcf76..e5810134813c 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -266,11 +266,9 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
>  		}
>  
>  		if (pgd_none(*pgd)) {
> -			p4d_t *p;
>

Nit - Get rid of the empty line between the if statements.

Aside from that, LGTM.
Reviewed-by: Vishal Moola (Oracle) <vishal.moola@gmail.com>

>  			if (slab_is_available()) {
> -				p = p4d_alloc(&init_mm, pgd, addr);
> -				if (!p)
> +				if (!p4d_alloc(&init_mm, pgd, addr))
>  					return -ENOMEM;
>  			} else {
>  				pgd_populate(&init_mm, pgd,
> -- 
> 2.34.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJpCATXWQx1hEyta%40fedora.
