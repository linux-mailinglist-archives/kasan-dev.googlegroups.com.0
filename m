Return-Path: <kasan-dev+bncBCSL7B6LWYHBBHUA3K7QMGQEILLWB5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id B1A51A8274E
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 16:11:44 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-43eed325461sf22942565e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Apr 2025 07:11:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744207904; cv=pass;
        d=google.com; s=arc-20240605;
        b=E00FI+uHvzYa73x3pnvswZXz6KMdyzQllrc+9UIev0d7wFUhmJWzJhDJPk9cJ8wl2b
         t8bGvfwh186t3vSNKL8vz0y9TRF3oJi/KhhCd0r0X8qLatx94/neMIPdsB69Q+3bkngl
         3icnGc5I7QcGa623cIaWGgTZMfIKQLDIYZTmSnipWbYF/doMxIqOuJ3UTGnwGPOMVRHl
         FY6HXrytbjiEc6tQm1iI/NV4Jsg/CS3uVnF4rPxkOYKCvtzHgdAt41ecMIFdQY7VFi04
         hlitqBhcbQbfNcm1dIQagpfAvojJ9rHAcfjqKbVNSZI0OGH/ykThAE+mirgBA/+vfz5j
         z3Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=hqoeQcoTatyjD3PwA4fLTk6s4WE0Qvsbm+eUre7zqCM=;
        fh=Jarfn2XTn/cOPuE+O03nZ6sv7AR6Aj3DNuPvnh6TSpw=;
        b=DCXXvDT+/Sz1sI54LsxZ5ySTm87NWf6yN9Fo/mkp7TpgVbzic9SjPEPmSMIBFE7laq
         GMC9xT6cOBnQgaEs9NjcUq1zzRyPujx0QeOYj3NcTl1MyI2Jh2WK1y6lqBejYG0ZTFgK
         iE3arMU1Qxky3fJ2kIjuL55Mw8W1Inxnxnf3GDYSAzsbI60pd8aBzkiM1p9xMEC5GWwa
         9eD4estkkLxdYMCTMV1PuxYXz/vDjhk1W2Kuja1LWr+cETR3roAZPBCLwktISEn47BlU
         O0tkLUqGyonul4zrkPy9DsPDu37NJkjvxVi5RO3uXLDDTP+4nJH2dGN99GgsKI9sfe3P
         djfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Y/aGnTKT";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744207904; x=1744812704; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=hqoeQcoTatyjD3PwA4fLTk6s4WE0Qvsbm+eUre7zqCM=;
        b=fy7CXq7CIeZoeaNz6FC8i2lFCKzAHJCOI53Mlf/Z8xPujywwxysFlspIKl0SI6+0kc
         t7tnRV+3RHwkhRySq/CmkdTtN8XlokqTzgezmv+0Yh1T/xu0uGlADEAfAwDKxRbrCOVy
         D4V1S4NF+II9G8LcYaBiEznby1LTKVSMHP3oSgFnYC9XOK73p9TQDg1QlQ6COpoGbDi6
         FqlO+nymaPLTMpL8HRXbJXHSgrnXb3OEZZLHsSwm9jN24iL3EUXWWQ8YPfQRDwT7nzoC
         YdYBkxd1aPX8fECaBVVKJz572YsEIU5F6SLhcwN9U/0USrLsdIfnc+uLcKWXA9fXwSIV
         Y/lw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744207904; x=1744812704; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hqoeQcoTatyjD3PwA4fLTk6s4WE0Qvsbm+eUre7zqCM=;
        b=XAL48LG7MvKNtMC+GV2ztBmEPZBITz0IdgPUqG2DmLOjoduHZcElDqqG0meXj5sQgv
         R+sBkB+GTkrv5Yib3tkbToTb1HXqbJ3UoNvk4l2Y5SWKxdWJOoTmJgFhJPtIpJI3foxz
         4poJs8oASF3qC81jeGi0RKnD0qwNTgPrTSDOJldtqrHkseaZBh6hNKLX3/O0xC8pmA0K
         kig2IKqJkxAzr/xeWD1Rq0dmjIIspx81Gi1dlj2Il4Nz8qneEydQ1n+T6h65km755uSM
         7w0b+zXjfIhbYgD+1q4iOYChknw1sQ6hWOMH1En0YK5ra3CNxW2EXfm8PNGu3RhcuSXi
         dIoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744207904; x=1744812704;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=hqoeQcoTatyjD3PwA4fLTk6s4WE0Qvsbm+eUre7zqCM=;
        b=LubMf3wuuy5K8y1E/nAv0YMAtw71QajDoAZLhztvxI/cMKXY8BiFCFOBxNjQi798Dj
         ASOzKwqng6QImXfe1tagqeS4ciFn02G624H5oNnFO2Mre52FNJHdYvTA8EWt81W/s9JN
         KfBl5z83rERQJJXszQTgelPnzUcpLUpCk9bqOVcf60BjglnO7B7s3FVJdBD+vDhx+rLe
         jxhsoYPAreHGkCPapXcxeCc51y4m1jfeUaI/ySO6ZK5HS4pFzbbcgAPZRJOQtwjVlE/G
         7w2Kmj4tTCCRcOVbkriHBmJKakxT0jGFwjVo6J/a3pG3AtOIItoslDwDrFPtM5oFuPUy
         q5iw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWVkeqjw1OEW2jv4sBOwAzsi+EopHHjuwTJ+N206qMlPJ7KJ/8AkH+KQk/YiGG9sU+kf3hENw==@lfdr.de
X-Gm-Message-State: AOJu0Yx8TX8193ENFqspIk8/LpE+y9Ni0ToKdoZ0bUKb/v3MgjQZxZHk
	LoVpFNHy9+VoQRfx9igr1o+LCKOaKJMln1oZiQ3Qr6rTNLzxtwoE
X-Google-Smtp-Source: AGHT+IEtoZDIYw15yC1GD7aUNwPKcqo3zJHo+i73iH1t86MICfioacNYT83nIkFSb7v1NCnHbWMLOg==
X-Received: by 2002:a5d:64e5:0:b0:39c:e0e:b27a with SMTP id ffacd0b85a97d-39d8852e7a9mr2808227f8f.23.1744207903156;
        Wed, 09 Apr 2025 07:11:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJ5rUT50bXROgJtML5W8pSjyjMkbgvGXhMyjz9jFQ1kNQ==
Received: by 2002:a05:600c:228e:b0:43c:ed54:13bf with SMTP id
 5b1f17b1804b1-43ebec5cb8als731165e9.2.-pod-prod-06-eu; Wed, 09 Apr 2025
 07:11:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXCt9rQ5iBWFw74397LrTMfIBJ7wPTvqNcI2k+z58BNO3NP+2hbjAB+tJFF0lYCO9skvjQvHUnSjOY=@googlegroups.com
X-Received: by 2002:a05:600c:1e1c:b0:43b:ca39:6c7d with SMTP id 5b1f17b1804b1-43f1fdbf661mr31043465e9.3.1744207900230;
        Wed, 09 Apr 2025 07:11:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744207900; cv=none;
        d=google.com; s=arc-20240605;
        b=BK2VNKIANm5VAL2UHC/BtYKTX/c8pVH/iRAUoE5MhPyaScto2KpbZMO9OAMGv0QrS9
         nQX/Ch/kGXwdur+YLDOq3zfKiIYdarH9ZQmiEhin6m27yFeCOctcqd3/pfITKNsGpf/d
         AXNRt1Khoq1KxfoYgkV5df8rfH4eUWsxvkcFW5GfIsJEtpEVuK8v6LfwLPZRit9DbQRW
         4ZHDue+l91eo9IugEQJ1yH8ax+QRaVAFRs5jAuVA10C1Dtn7hWDGVe6Ps3RLCNM0wNqR
         YjnGJJq/v7/DLvCxFiZu1rR+YqFhs1ZYQXkrzOFEVDFXRFyiZhSM7m9Fi2XR7C67/0C8
         8Xyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=79dRAhMX6hAzgdIihnfQk7TyjpU16Gt/P7A1hHpHnDM=;
        fh=ib/djmnK+pr5DHQp0A/NW7iQ3AE0SRmWDYtCNi8ZJSM=;
        b=QWwk9lEExcirhoY4uiyzcPwN49TqQy962eX/q5uHeCk53T164ZZZGELznSITIRmdnY
         i1d4ekTZranr6fQvTrr0eVGEtom6aadoRn2Y6f1mKtGA31r0BL+eruxoKabBRE4zJXm6
         YHskYmKStn7BPJGrCi1KZbnPO19QRhLtuh6NgBk0J4AMivY5QotjrF+eLAI11vrhDe9f
         ivgLMN1fcNllk+5m1iCjlOvwVes7t4E7DQgITRhodCf5DzJbjXWh8HDr6aqoJ3rU8UWW
         pW51Ygw554Hfxr8C34itVLLoMlQQh9ltLsEDNhEHSBbuWd1LUl7cRfI/FT3Ez0yN92D9
         7Tsw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Y/aGnTKT";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-39d893ef9a4si21380f8f.7.2025.04.09.07.11.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Apr 2025 07:11:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-3912a28e629so954559f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 09 Apr 2025 07:11:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUupW5of9Sf2LCy88uWiXOeW6xPADPZOiRmtHQJcWnscaedhNzXjDCo5luta7ytsor27tRmgKVt80Q=@googlegroups.com
X-Gm-Gg: ASbGncvDlAB5Jc70mx0GLauzBQWPmSsr3mgqNsrCrteCR/ZOk7eogV5mWksQC4IGw46
	6pSArDbVDNJjVyIjPi6cVRaSKWUviHs+NgzPdBTQabwm6Wpvbg8x+S83PeOumCJj07fVCQ1Mioc
	YuJ/ci//rqdcmAoYckohGRVBqgcHXTuGKM5odwe9f7k5N4diUO3mGAy6s2hayv15gi4QptJ5+v4
	9CquMGCR1ccdpAAsICnzgwtKq2/x6Pi+TxoBJO3dVO53RSSNFhSBv3V1rX9w90ch+56swhsZG1z
	6t7YmdgBzfNxRTlNBeXx/QAPKb0wI4rUp9VJ7AT16DOYaSvMaLm/myZJRrmAGCRug/vDrQ==
X-Received: by 2002:a05:6000:2901:b0:391:2acc:aadf with SMTP id ffacd0b85a97d-39d87ab626emr1029141f8f.6.1744207899192;
        Wed, 09 Apr 2025 07:11:39 -0700 (PDT)
Received: from [172.27.52.232] (auburn-lo423.yndx.net. [93.158.190.104])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-43f235a5d31sm17305755e9.35.2025.04.09.07.11.37
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Apr 2025 07:11:38 -0700 (PDT)
Message-ID: <3e245617-81a5-4ea3-843f-b86261cf8599@gmail.com>
Date: Wed, 9 Apr 2025 16:10:58 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 1/3] kasan: Avoid sleepable page allocation from atomic
 context
To: Alexander Gordeev <agordeev@linux.ibm.com>,
 Andrew Morton <akpm@linux-foundation.org>
Cc: Hugh Dickins <hughd@google.com>, Nicholas Piggin <npiggin@gmail.com>,
 Guenter Roeck <linux@roeck-us.net>, Juergen Gross <jgross@suse.com>,
 Jeremy Fitzhardinge <jeremy@goop.org>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, kasan-dev@googlegroups.com, sparclinux@vger.kernel.org,
 xen-devel@lists.xenproject.org, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org, stable@vger.kernel.org
References: <cover.1744128123.git.agordeev@linux.ibm.com>
 <2d9f4ac4528701b59d511a379a60107fa608ad30.1744128123.git.agordeev@linux.ibm.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <2d9f4ac4528701b59d511a379a60107fa608ad30.1744128123.git.agordeev@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="Y/aGnTKT";       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::435
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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



On 4/8/25 6:07 PM, Alexander Gordeev wrote:
> apply_to_page_range() enters lazy MMU mode and then invokes
> kasan_populate_vmalloc_pte() callback on each page table walk
> iteration. The lazy MMU mode may only be entered only under
> protection of the page table lock. However, the callback can
> go into sleep when trying to allocate a single page.
> 
> Change __get_free_page() allocation mode from GFP_KERNEL to
> GFP_ATOMIC to avoid scheduling out while in atomic context.
> 
> Cc: stable@vger.kernel.org
> Fixes: 3c5c3cfb9ef4 ("kasan: support backing vmalloc space with real shadow memory")
> Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
> ---
>  mm/kasan/shadow.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 88d1c9dcb507..edfa77959474 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -301,7 +301,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>  	if (likely(!pte_none(ptep_get(ptep))))
>  		return 0;
>  
> -	page = __get_free_page(GFP_KERNEL);
> +	page = __get_free_page(GFP_ATOMIC);
>  	if (!page)
>  		return -ENOMEM;
>  

I think a better way to fix this would be moving out allocation from atomic context. Allocate page prior
to apply_to_page_range() call and pass it down to kasan_populate_vmalloc_pte().

Whenever kasan_populate_vmalloc_pte() will require additional page we could bail out with -EAGAIN,
and allocate another one.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3e245617-81a5-4ea3-843f-b86261cf8599%40gmail.com.
