Return-Path: <kasan-dev+bncBAABBGGB2OZQMGQEXMUTOEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E07E91184A
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 04:08:26 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-25cacd5a16asf1975034fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 19:08:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718935705; cv=pass;
        d=google.com; s=arc-20160816;
        b=zqdylmVI/filkgfrv2gNzGHCdasC0+7pJp1Rw+9R0EegzYfLs3pRrEYYeEeHzHoc75
         QBvJJ0KHo8bgtPdVA+cFYlUos2FAWWqtiFuOpeFdXTf6lc9GLKCEOt1Oc6rdDLOZWyh+
         Q8PTHReTDu6gMr860I1DcxhWZcK60ZVUUQTVwmO8g6bWENycUhsBxXhoaxBLUIqJYr2E
         HUltCs3pKbylDlmVwgpNxG/Rh31qIUebOXh9SRkscJ2oNRv1R33XZl0Qm+x7LBYeGELh
         DoAW6/XM82EkjUz4QyMSO7tetFxgGRPzc1C2HYb7yHftOReJHtDwXhh3lGZnLEVrdakz
         J2Vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:to:subject:cc:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=qp0O6CRAHQwfOGv9i9rh1K3FeaAfWFmhCf5W31yLras=;
        fh=ntPfdhrLs1sG+U2vUr8KFaLxFMqD7epLJGkQx2UpDdo=;
        b=zMzUPYGZzUMSFv07QoeBIGh963b/Hkspj/t0PLVUqiNIuN8UGWnQSDzYgZzslWVzXV
         s3xbWixFTv+xEUJUjcjqEMJ0nQbBxYfXD87YircV4xvmGWMyTJCff3U0hWRFzx+hKEHq
         cBerE5j0f6d6HXMUhn/9IO64LQCmTl4sTlhnE242mvJHxvrgt5fkUVrBb9SrJIaQVLhE
         Le+l9wsBqwY/81TAOHXEM9Unn9V4yqRT65gGZGzdJNy0EG22+9eBCPWyBcTTkn4dHdZc
         1aPTr1ASI5BR5i6orrGiq7Fo3Yyn7G/AG52BVExZFsny22rpdPT6nkK2P5fkMGtlhyYg
         Zbew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mawupeng1@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=mawupeng1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718935705; x=1719540505; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:to:subject:cc:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qp0O6CRAHQwfOGv9i9rh1K3FeaAfWFmhCf5W31yLras=;
        b=f9ZZivRI2ra+kyHDVkY8sUw9LKOXmkezTV1a38zyp/dU2AEHSLQEBDIZfFQCtq2ANQ
         CAKKCHhq1J2fxJ0EqSIEV4oppJ+wjGOmBEth5QShLtjc5e+jOCurvlB9vKuLKCPNE+g+
         PuExsG7LHwNQIo7nJ5DNkNEljKLl9D59MsYgbFAs9Zk9JsXN8nDTsgG9uPNtUL/x8gT3
         yWoGVTwF3+yEQmcwdZUBbF64svyUK/UX3Lhib0Jra/apvVP1MBrKbu1d0g2eyZWD0X9j
         jBZVV0XnQ8iIbILxKzalvMHs7OroXMf/JZzEAyQSwDDsCBQYNKUDnrPSyP0GtLej8BOH
         DKqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718935705; x=1719540505;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:to:subject:cc:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qp0O6CRAHQwfOGv9i9rh1K3FeaAfWFmhCf5W31yLras=;
        b=nOkrypRVMdjltTlHspjokXpcmq/Slc0rxFGzgI2L85HxkGyjyE4bvr0t341ncCvcJ6
         u2u10PZeHik9x9XYFmkCajABpw0U7qGAGgEfAxbPVJZS5TVtP558WD+evRwD5AG2c3AG
         ktIr928xg4LIpxnmFBflWDIsJsKQCOsLWtVGByEIr8R6yePR5NdzJVbcoyStf1fL4PxM
         OAf4kfrfBlvyoUGpqVIrTXsjJzyRkEj++w7ESGFZ6JXE9AgiNn3uHpdwA9rkv3l9UHlx
         NagWP9zDfxnVhONb/I+prwqlrZg2/oevz3l0u3pPc1iwIeWfRyEP6e28M2EJlZp/mRML
         fGsA==
X-Forwarded-Encrypted: i=2; AJvYcCWNhZAIG99ts2PKmWD/s5qMFie3oEdLU9a6ZUwYEGS1CooNQi1d7E70Gn78njFr+4bZSFqM/inIYTF6CM+Wm/dD19DqOmfCbQ==
X-Gm-Message-State: AOJu0YyueOdBF52XsYa2Iqix7MaUaYw6lpLHEDNzGVfd2qPdpb/5WQb2
	RFHwSPwmyVul1EZYM2E2dFxGTJgX4lbLNOauN52JlNx4pIsItd7T
X-Google-Smtp-Source: AGHT+IGq8eaCuJ0JQ5O6B372kY9rd4bPT63nQ7Gt7eGtrDIiAlti3/MCLNR6uzSOgj6Ansg6K6fpZA==
X-Received: by 2002:a05:6870:fb8c:b0:25c:b834:7481 with SMTP id 586e51a60fabf-25cb834b617mr4465648fac.56.1718935704898;
        Thu, 20 Jun 2024 19:08:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:280d:b0:258:3c95:19a5 with SMTP id
 586e51a60fabf-25cb5f324c3ls988998fac.2.-pod-prod-06-us; Thu, 20 Jun 2024
 19:08:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXqKy3+guOzr0IILaOsk51IklhJyzh71A5V7gqSQstjkKqYCn7hA/iAbd4iEwjaADlCAoJy86avD4zNCSSfeFFwaVfA8V89iMYQCA==
X-Received: by 2002:a05:6808:1313:b0:3d2:692e:8dda with SMTP id 5614622812f47-3d51b9984b4mr8022195b6e.17.1718935704048;
        Thu, 20 Jun 2024 19:08:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718935704; cv=none;
        d=google.com; s=arc-20160816;
        b=DQ+paO4mkxl4nRkCIRtKiMi4g8mV/PYMO3kCJ0hZH8ejbwa+d/FmR22fdGZ64Vqdrv
         GmZ9EIvda1HABSbGg8y/vQIZ/qUBSxRWOcg8n03jM7iwO8A0nInUxRaElozMKpXerA2c
         FZD3gnIjzsR0CG2qnnFBB6WTsP5YD7vX/RIoN1ZxmGgO2emWyWwVF0RHycRhHxTbzqgf
         Bv3+QKL2wr9yExvZYnbn7R9TJccbWk6vq2CFHOTMbiZMcJP0gXmWhYzS7fH3+yOTzADU
         QjkG++F1oVaiNUT2mtC6cikqw7BXJpHj8Y+V7l51hPKR7LWRQCXA8THH+k9IxCYIVwOI
         Pvpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:mime-version:date:message-id;
        bh=3TUC2TvXpgK6JLKjFKWIhf/CL7q8Rvz4X6zOLvojveo=;
        fh=WWH5nxB8NmGM+xgKqaD/vz2drHXNHfWPRpP+uRF1MWo=;
        b=O+nngT0tiHelFUSrCKEbl2n0OaCt6sl1fsEm4Pd0z0USQzYmw0L9mLGJe+XJZLp858
         9eIeebHRilqiQvXHYozF9+6L6mHgGIs6uhHlY9XPdtf5qTLJm2BcL61qfEribDTsIV84
         YvLBDNBWfzA5SVFwUyFrdRLrqAXOWxgBjzHRGelSAzTs9BjjcVolj1NRqyvK8HaAk2Do
         uPmjv+7xFzPZgo+C84RfAFMnTjCfT93ablefhFRUV3rSvxXu5TMIWTHS5xlZ33B7luBv
         VIGpT5JaPbwuxO4QCK/O0+cMFPlj7oguhkd7mAL8mcNXH70WqcbQ4PNW1jxGHlHszptA
         I4IQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mawupeng1@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=mawupeng1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d5345107dbsi32542b6e.2.2024.06.20.19.08.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Jun 2024 19:08:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of mawupeng1@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from mail.maildlp.com (unknown [172.19.88.105])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4W50y43BvWzVm4r;
	Fri, 21 Jun 2024 10:03:24 +0800 (CST)
Received: from dggpemd200001.china.huawei.com (unknown [7.185.36.224])
	by mail.maildlp.com (Postfix) with ESMTPS id 55A5A14011A;
	Fri, 21 Jun 2024 10:08:21 +0800 (CST)
Received: from [10.174.178.120] (10.174.178.120) by
 dggpemd200001.china.huawei.com (7.185.36.224) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1258.34; Fri, 21 Jun 2024 10:08:20 +0800
Message-ID: <dc0294ea-0724-4403-ab0f-d968fbf36586@huawei.com>
Date: Fri, 21 Jun 2024 10:08:20 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
CC: <mawupeng1@huawei.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
Subject: Re: [Question] race during kasan_populate_vmalloc_pte
To: <akpm@linux-foundation.org>, <ryabinin.a.a@gmail.com>,
	<glider@google.com>, <andreyknvl@gmail.com>, <dvyukov@google.com>,
	<vincenzo.frascino@arm.com>
References: <20240618064022.1990814-1-mawupeng1@huawei.com>
Content-Language: en-US
From: "'mawupeng' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20240618064022.1990814-1-mawupeng1@huawei.com>
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.174.178.120]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemd200001.china.huawei.com (7.185.36.224)
X-Original-Sender: mawupeng1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mawupeng1@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=mawupeng1@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: mawupeng <mawupeng1@huawei.com>
Reply-To: mawupeng <mawupeng1@huawei.com>
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

Hi maintainers,

kingly ping.

On 2024/6/18 14:40, Wupeng Ma wrote:
> Hi maintainers,
> 
> During our testing, we discovered that kasan vmalloc may trigger a false
> vmalloc-out-of-bounds warning due to a race between kasan_populate_vmalloc_pte
> and kasan_depopulate_vmalloc_pte.
> 
> cpu0				cpu1				cpu2
>   kasan_populate_vmalloc_pte	kasan_populate_vmalloc_pte	kasan_depopulate_vmalloc_pte
> 								spin_unlock(&init_mm.page_table_lock);
>   pte_none(ptep_get(ptep))
>   // pte is valid here, return here
> 								pte_clear(&init_mm, addr, ptep);
> 				pte_none(ptep_get(ptep))
> 				// pte is none here try alloc new pages
> 								spin_lock(&init_mm.page_table_lock);
> kasan_poison
> // memset kasan shadow region to 0
> 				page = __get_free_page(GFP_KERNEL);
> 				__memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
> 				pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
> 				spin_lock(&init_mm.page_table_lock);
> 				set_pte_at(&init_mm, addr, ptep, pte);
> 				spin_unlock(&init_mm.page_table_lock);
> 
> 
> Since kasan shadow memory in cpu0 is set to 0xf0 which means it is not
> initialized after the race in cpu1. Consequently, a false vmalloc-out-of-bounds
> warning is triggered when a user attempts to access this memory region.
> 
> The root cause of this problem is the pte valid check at the start of
> kasan_populate_vmalloc_pte should be removed since it is not protected by
> page_table_lock. However, this may result in severe performance degradation
> since pages will be frequently allocated and freed.
> 
> Is there have any thoughts on how to solve this issue?
> 
> Thank you.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dc0294ea-0724-4403-ab0f-d968fbf36586%40huawei.com.
