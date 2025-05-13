Return-Path: <kasan-dev+bncBCSL7B6LWYHBBU7NRXAQMGQEB76ENFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7492AAB5A66
	for <lists+kasan-dev@lfdr.de>; Tue, 13 May 2025 18:44:05 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-43ceeaf1524sf96015e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 May 2025 09:44:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747154645; cv=pass;
        d=google.com; s=arc-20240605;
        b=a+/FOMKpIFax6/zMrgNI4klLWqhu/2G2SwVk0dEQXr08i+mWj7++rJvLO9Wu1J+cT6
         17PfbfdCn5w7X4qKsyUgxd6b5EuuDzQPQ4eETTlxookAm3Yjt8EU7fkF0fxsbNUkYpI/
         Ms3YEI0fNslH3wPKz/JLtKQfvBTLjTWnLqr2rw0iYHfPF/g598wIog1hDVHtX6tqQBm6
         ksNK5uvDC1/IfIEdYBPgqt1ehjhWgk97do7uw5OJ3Q3EIYh2GZJI6/OTKDHvOJtDln+A
         YjTWYcdzQRvLvGg28u0r25WZu0ztX8w2f2m+0OEQX4Co867we+rf2kIB9+2OC6lQruPT
         msuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=G1E85lho4D6795FIVzBzYL+EJcN5Rb2UojZ7Zoe5nC0=;
        fh=WbEjckVsUiMdcb8k0vZh0OHt9aZOn757Kg+oHsap1fA=;
        b=C9aOwzS9XhPWt04vydPbeg85puS/ImPVJ7o7DGpsSN834RxDaXMWQfrzj8OjAjVLB+
         UTguYmia4bl9OK2TZg4finyTK6aUkVSZ6kGS1pSCuM5+tQuGcOfXyFxcPTSvQi4F70Eg
         zNW6kQOzndKHet1h445gWdsfIyqFE+K3/EajX+0UahatMb1P9kt7RCSVqBcYNTXdcUqc
         Ev8Ex0HDNJII/oua7+UdCWMzriRoBmSkdHNNagtiFo4qfm1G2JVlRMv8ZFZhWX54m0b5
         QGuh7bPAcrjZ7hPVBdNjelDv+V52tIPAQEkM5Mp/bxPokojhZFoDoQyfDJqyuk0hjOMQ
         +bEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RkTG98UL;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747154645; x=1747759445; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=G1E85lho4D6795FIVzBzYL+EJcN5Rb2UojZ7Zoe5nC0=;
        b=fPiJC7WP6kinEX1wdjIMvZlHof7kcVsKmu5KmhyHoa1wuBOh4cV+ZtUbnVj0ifpflQ
         ab6YfmnJ9ybN+YaT6T/3Mn98nz2jenKS/4WcM5iz+bZl513FLR4kIH2eqnVTdn/ydpk3
         Gq/thbENP7JzsZzOUnFmWUddk6D1ra33mRJyUw9WKqrEJc5/Hbpt5ucqHql5AOj+PK2g
         74MneeWjG/cHnSAgsdMxp1Q5ANudT4QJba0rQBj867kSY6B/8Ksro9DBPPOWleD9hHOn
         BLv6m5Z/oUzlncukODglyy1oDEa/hVm7w0gXZELNJHnlgnQ6BsRPFXnwB4k7Vqsd4t59
         J9dQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1747154645; x=1747759445; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=G1E85lho4D6795FIVzBzYL+EJcN5Rb2UojZ7Zoe5nC0=;
        b=Yb4FwG9kZ+ju2Bb/iHQxw7/4T3KnCl129IREGdz5ED3mQsTrrwsSjvRCnUB7bM/sVM
         r7J95BhXVJS2Ml9/sajyA3/Fj/8GXAWd9LG+tenY1NUsEAMwvIJ0OuvVP4RwPnpmaJsL
         uRfMJgHaH3AmJqwsc1mNEOsnxeQ7oRbC3xzIQhLULHt9pjU+Rz3UoJKZ7QlWqqvCJ/9s
         D9PXZm9vxJVNN0uiAtbatOQgL8fPMVb/ha7SkElaY6wI4zBwDjd+ebLtXZNgUYpPJTqs
         1fvcNc/D2/uPPts9qBALHle0Jz+Hfofj0FunHxzO41x5ggwfkmyastHOpEsSwQxFzO+k
         8B+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747154645; x=1747759445;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=G1E85lho4D6795FIVzBzYL+EJcN5Rb2UojZ7Zoe5nC0=;
        b=m47zaFdZ63gLpWQEO77kfrzhlGLtbU/P0dN+E6cavc5+P+UlcqxSiIiqtF0wRe/8UT
         BjJQA3K+M1KzMBpzpfebmngiho24f2WNBO2ZJwj8k1rcWR65JYsokLYULn1Fy9Wk8BY6
         uNKSKcA8wqhfzK/sQKF+5A3A+LK3QAH+z3kxYJ5njD2zViH3VTS5BikNcFX7TJDKZml6
         sYilGpldNUVG+dwqk3BxGe8EgXiZ29Mqior9heboJ+W4BJNSrpJQYkoXpQcN6w6wgNm1
         giL0JlMGxzS5x1i9MOFNpVCrII2qt1Gnb3HPOX3aCwpPqJo6O8VqP7bUZo4PJ/1/OXJv
         GMLA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXwWJRI9viDkp847oOBHCVJuPAMXeFPVgSZA+mPg9vCApb3EHRgu/TAYWWX1FxEsnrRn5AbbA==@lfdr.de
X-Gm-Message-State: AOJu0YyTZBxaGUBcdBeiFymw4Cy1s5r50HVlrA/qClr90jpVWkVoiBZw
	iksQUq3RNdFDoTrsG8nFBUy6FP5kH4htl5kLEHFI139X6uV9K+Hs
X-Google-Smtp-Source: AGHT+IH4BEjgja0T5Dhteo5JuCDFWnnVpTYBOLCFI9LUsUIwPqY3AcM7giazJweuL1lBy908qNrhIA==
X-Received: by 2002:a05:600c:1ca0:b0:43d:5264:3cf0 with SMTP id 5b1f17b1804b1-442eb8855bcmr27568315e9.11.1747154644567;
        Tue, 13 May 2025 09:44:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBECg1V3SQ0fl9xvTDH+jPT730L4OLEJCRxA4J3EFdnrDA==
Received: by 2002:a05:600c:1e09:b0:43c:f636:85d0 with SMTP id
 5b1f17b1804b1-442d0783b75ls6029175e9.1.-pod-prod-00-eu; Tue, 13 May 2025
 09:44:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWKM0Oha2Ka8FUiNaBu1hwOvq593Abm9gpiKNXoEWb9WS1rl46xXL1Qf+b0qzwghy6n0K5xYnVa6Cs=@googlegroups.com
X-Received: by 2002:a05:600c:5246:b0:43b:c857:e9d7 with SMTP id 5b1f17b1804b1-442f1a25b36mr2523745e9.5.1747154641695;
        Tue, 13 May 2025 09:44:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747154641; cv=none;
        d=google.com; s=arc-20240605;
        b=Ex6ga/d1boLPfwMpLHI/QvmwaiY9J3J88q9B8ytSdRu/aTJT3XvzCkAcNdECcjjIaM
         gsS9g7RyRZk+lmeJw9Vp9NXLSr1RAH0VyIEyeC/yCgTc9oYAY8W6Y0yfOXHPExdzvxah
         QEg98mBcPOCWBByb+9fmzjyrZfxWHrdhlvf96D/g+cud09sd9ZXPZDd4aQ8bQWZcoGis
         KFEhYiPzoyzzScEJHXFwR11O9T9VGgHwqGGVaOIeOIe4pEXmCY5+DFgeHBiVzFRfMB2e
         OHbTKJcaepwEZJUL5M6MBV4a3Y1hYblfY5u8wKBY+AG3P4zr4Nx2Is7b66op+PhrC/LN
         Wlgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=A/kRqYaGohmL+rCJZtloL3u0VjOq+d/hFBIY4Q6MI5o=;
        fh=s3Idct+eDMt6irCJBVdf6dsiOEaiq15agaEpl4oZWEo=;
        b=W0JSSFhsTNhE3f65I0w5aYlurWJufcewPoV+4SCFQEWsA2pu6EDqO//JPARYMW1YHS
         /sj2H/qI6eU8ZvWzu6Ak1qKPHpVYmb5fLVRX+k2IDy2DE20qEuu7TlrM2sUNo+GPTBnY
         jm1AoTMUOOvzvnCr4M9IZCzVnrC60dbTLJgR68ZJCmFTdiwjBE9451+N/kn2v8OtbuY2
         +3X+/5Id6tXrXhkh3XT9DykgYZEl0Hknks3dCEjTIIXUSjQLqhbaj5ffbvV2uPJ3cWUp
         KSB3Lgp9/qLBBet3L3f3rTJ2DqXE9VsOq/JMp/7OBFOlKApN/ODnqgvczfwQ6+A43/dP
         394Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RkTG98UL;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-442eb83e803si862645e9.0.2025.05.13.09.44.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 May 2025 09:44:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id 5b1f17b1804b1-441c0d42233so6142355e9.0
        for <kasan-dev@googlegroups.com>; Tue, 13 May 2025 09:44:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVAepa++UD6hOFfI/3SFL2IT92mWedFT5jo8m3mj3HXpB4JwfCeASb98KgMZo9S3ddlA8RWaQaRx5w=@googlegroups.com
X-Gm-Gg: ASbGnctc9eLvhBBwdDv2QQ73/W6vHLLoirjcwtcsikSb4iAmpc5UcFGBz7ea91MGMR9
	PR8fP/3RqhLbGGUAVBYXb3OdBj1cQZdmME95jiBF2VtL/FF5Z6oos0ytFzqu15WQEvWgdVIEFeK
	PLyHURJ+Y8nCM1zWarHyxTD50GjQmAxsKp4NWH89rQrfDDXRZf5IKwb9QqRUdHf2kXWaVuHRNOw
	OUfsfasPKBMeTpSOwoy0SdJqFrp6kkDC9du3nEL4t4LzC7WIeeCuYgmanmjJuVJi2HnX3+TJZrt
	iL33Ib6xtZR0pqY52z7V4WjMhmN1Rfl2fIMY6Drn7dB8tmajAIn5e4f2MD0HQM9PVryL3DIBbwf
	SMkO11QckfNqJ7cJhUAw=
X-Received: by 2002:a05:600c:358f:b0:439:9a5a:d3bb with SMTP id 5b1f17b1804b1-442f20bae5amr175275e9.2.1747154640856;
        Tue, 13 May 2025 09:44:00 -0700 (PDT)
Received: from [192.168.0.18] (cable-94-189-140-39.dynamic.sbb.rs. [94.189.140.39])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-442d67d5c7bsm176462675e9.4.2025.05.13.09.43.58
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 May 2025 09:43:59 -0700 (PDT)
Message-ID: <53a86990-0aa5-4816-a252-43287f3451b8@gmail.com>
Date: Tue, 13 May 2025 18:43:56 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v8 0/1] kasan: Avoid sleepable page allocation from atomic
 context
To: Alexander Gordeev <agordeev@linux.ibm.com>,
 Andrew Morton <akpm@linux-foundation.org>, Daniel Axtens <dja@axtens.net>,
 Harry Yoo <harry.yoo@oracle.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, linux-s390@vger.kernel.org,
 stable@vger.kernel.org
References: <cover.1747149155.git.agordeev@linux.ibm.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <cover.1747149155.git.agordeev@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RkTG98UL;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::32d
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



On 5/13/25 5:21 PM, Alexander Gordeev wrote:
> Hi All,
> 
> Chages since v7:
> - drop "unnecessary free pages" optimization
> - fix error path page leak
> 
> Chages since v6:
> - do not unnecessary free pages across iterations
> 


Have you looked at boot failure report from kernel test robot ?
https://lkml.kernel.org/r/202505121313.806a632c-lkp@intel.com

I think the report is for v6 version, but I don't see evidence that it was
addressed, so the v8 is probably affected as well?


> Chages since v5:
> - full error message included into commit description
> 
> Chages since v4:
> - unused pages leak is avoided
> 
> Chages since v3:
> - pfn_to_virt() changed to page_to_virt() due to compile error
> 
> Chages since v2:
> - page allocation moved out of the atomic context
> 
> Chages since v1:
> - Fixes: and -stable tags added to the patch description
> 
> Thanks!
> 
> Alexander Gordeev (1):
>   kasan: Avoid sleepable page allocation from atomic context
> 
>  mm/kasan/shadow.c | 77 ++++++++++++++++++++++++++++++++++++++---------
>  1 file changed, 63 insertions(+), 14 deletions(-)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/53a86990-0aa5-4816-a252-43287f3451b8%40gmail.com.
