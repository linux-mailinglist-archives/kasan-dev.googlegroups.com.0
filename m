Return-Path: <kasan-dev+bncBC32535MUICBBU4KSDDAMGQEMLKQ3VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F43EB54B0A
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 13:34:45 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-70fa9206690sf53416126d6.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 04:34:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757676884; cv=pass;
        d=google.com; s=arc-20240605;
        b=B/rSynVV5ItP9E1WeAxlyl+5uEq3AMIFJu51LIKHRosRJpZClNkzR+ZlnuL+GK8hrz
         DYHePJpy3xSd/YsEpyHP41fsmJVf/awFiCnHVZ6HgJ6ngjV/4fwdx0ZdZFKjQ9jlylJF
         RY0RJO9kA2b95BQHCAAXWaDWikEGoNS+MWrc3nNp8EI4c3UabbBXV42BFau9JUvfoJAc
         SkV+gdVM5DLaHfTYEiwA2nFA9uG3+XgYtth2fTpKkUXWkOMNJcGlfQvmKQTqGK1XzhNy
         G7RrT576xxVzrrexEGd78mU7EXhdDG8b/BSKpke8rH8CErDhagdh/gNZ+6jMkUbUpksf
         TszA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=/yVOHbZmnXbtkqyyOKc5V15itILRw4c+q+ZC4PoEXR0=;
        fh=X7foHeO7CFXGqBPOGcbIPzCSqjwVCClhx88auK3I2Ck=;
        b=XljeMXUTiHPr1/QcEd+l6Afk8h0tuGWqskwD+JlBuCTzXz25k9tbfCZNy87xSUbUxX
         PXBDKKMSmUqRXyBLEPw6zNE7mVy6DbsRNa2zmXidTkubxdggEHnG+g4iq6q8uQV9mJ1B
         Wok48y58uLvgELtv3jnTE782SdY3GM2vKUW+hW0sqnDj9zjIBpmt27Gtf6YK1UyGT6qQ
         pM2hp1E+u/p68YCndy4I7VYhLLBA8MY4Xwbo9MU4B+K6ss6iZ1Sw/BB5Rjg6i3h7MKNa
         SKAY9Us7yXObh3SvuRpProBoYcllLH5SxGxW6CdQQrWDUO04w5rYboPEaaRa35o9TJEt
         Sx9A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Lz3BmvmO;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757676884; x=1758281684; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=/yVOHbZmnXbtkqyyOKc5V15itILRw4c+q+ZC4PoEXR0=;
        b=f9484PxFNYFEpefwcTlcTVcPktUrvykh8ijasiMnYA/AFeAxlWTIEQcUv5XmQPnUBs
         MCe5fyu/3ZWcJf2K+4HFUiPgmLUxrZnYDyip3We00J3B8Sp5oeosxGtjxZTa4bhAoWgR
         paq7vVl9z0XnEs3RgfRypgYWrB4maLskgc59rLOZGjU+4IHoT5AXIykybA86I1W7cLgf
         iSQatFhCuWyFe2HD64785VcFXFBY3bNG4y2TUVlx2aJXzDyXGbqWGzdFRk+jTZHBWR0z
         67naEFUlvKZ3FB1DCYOnp1K9xX6acJkiblZkVxW+5PFBzjVqqqJwL8L9bqpRDcg5P+C2
         yDtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757676884; x=1758281684;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=/yVOHbZmnXbtkqyyOKc5V15itILRw4c+q+ZC4PoEXR0=;
        b=Nt1zQPiYdrr6A7hFFpuV7uNcqqM/k64b0kbExT0YlMqJp+DbQQsHLvFjakb22Y47aq
         +qs8ilmoiy4daEp4q9DpmJ1FlZ51ETCi7DDXdjRi+Toe4UPre4bsB8hef0PJw9yHc/E5
         xqD/HPfQgwycKenirWIb0NulXUJXvzBgtZYJaECxCnkgXjv4yoCRXFxKHOO8YCNrJgzZ
         LKUVenXV6RFEv3FwNZcHmWFNgL7I1h0yTHjPCo7OShmkIGx6DxONtzYga+tYuK4T5Gux
         n1589o/UoReit8aejwPLq/e7Kfl2JFXSFHIrqxVHBxpi1r2+FnG5naCVZfHsUG4rghSZ
         lz1w==
X-Forwarded-Encrypted: i=2; AJvYcCWV+BUrcYX4ko/h4CShb1Dsx9FFOoQpRopj8DIsoGOdrSyGkko9qaY6NM034fm5ufPvihRsYg==@lfdr.de
X-Gm-Message-State: AOJu0YyezxNeakL389C1iTK5q0rwmvtnrjkN/xjO2MNFyqZ0Mjum8ujj
	dPb4g8YCgDmsYmwzrNxNRqwMOVGn6eNWqq3QSSFQJemdQDjP0jCs+ZVs
X-Google-Smtp-Source: AGHT+IFkhvw5ipyJppROipnz9sYPgfN2GgDGoWyUIkJHE1eTHATecpt5kERSEcuuNnT0qWqmQAs8ug==
X-Received: by 2002:a05:6214:268e:b0:70d:cabf:470d with SMTP id 6a1803df08f44-762262daa1cmr80843966d6.27.1757676884366;
        Fri, 12 Sep 2025 04:34:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4WImUbsF0H1wZa1ns/BKECh9fRBfa9qSif8aDoR+i48Q==
Received: by 2002:a05:6214:8017:b0:76d:ac47:1aa2 with SMTP id
 6a1803df08f44-76dac471d5els1434776d6.1.-pod-prod-00-us-canary; Fri, 12 Sep
 2025 04:34:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWkknc2Dk+gDzI7NtjK73ZU6A2LIUJIUWT0Z6sMWVkOOUQRWLuwYJy+TCUB2fAC6WMtJALBSkb3lXw=@googlegroups.com
X-Received: by 2002:a05:6102:f0c:b0:52d:9dc0:3c04 with SMTP id ada2fe7eead31-5563cec250dmr902916137.16.1757676883092;
        Fri, 12 Sep 2025 04:34:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757676883; cv=none;
        d=google.com; s=arc-20240605;
        b=a3PfTHbHWLXJxQBIkMN4X1sSQYJtFfYSUny24SBbxCmk5gQ/yD8QfqReR2Wj5zbO3U
         ebD6z/oEWnZuuHhj3wEGxsNR4zVjb/aIu7V8/yETVy+Vc+tRqw17A0nqAT2z8YMaf7OU
         qCgct0b2JfQjIhc4NVhDwa93LEd/L5RyMXhdC3ToSUTljvFg53DCUbNcR62vAQsgdjJi
         Q4HO4PJ6M/yiMSGOmUTVjpV4MJNaE+0DV3OQSZ3j8yn5bTghWe+0lTnJchkCIZK+xIUn
         5/T7NIUAgWsk18nDWR34Hd+c3l+s8QDZegQAdHUJk8uBFB7XrYVS1vIPgSK32HeScpV5
         ulWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=ZWd+C+6xlO7ZNnElus07Td372OLIDupg0E/fPHS2G6s=;
        fh=goqtwUCCiEDV7kXLLpI+Y5pNyYZ55jghmzOBiNn6qes=;
        b=kMmcuWmd6+OrT55Tm6b7qvnuR+067gYbyI4dRPIwXUCQ28FT7EOlAEoVFT2KEXAWoP
         TY1DNnLB264haAJkc45kP08A/11fBwVPE4I4ofwM4E5gVSDMhjY56VdcMEL+XHOFdQJo
         v55NgIGV6d/k9YDD813SpTRjGOfq7K9mtmGT/TDwuKZ97yfS2ebCrIOPVykO2X5CG9iX
         3+ng1B+6POFY3+Y5zUh2xxXGoCMAU30eP6GBmS9Db41r1FNSsWp1vOnCT7wS3H9DEjyU
         xB/QW7fNdMXBjXcN5nZs8jrZIhYHCMcikzUDCeBrGc0D34Ct3aD1fjm9GJSjkGtITO2m
         bcZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Lz3BmvmO;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-556485008b1si93006137.0.2025.09.12.04.34.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 04:34:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-159-Faa13sxONIqPplxNWTD7HQ-1; Fri, 12 Sep 2025 07:34:41 -0400
X-MC-Unique: Faa13sxONIqPplxNWTD7HQ-1
X-Mimecast-MFC-AGG-ID: Faa13sxONIqPplxNWTD7HQ_1757676880
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-45df7e734e0so11479155e9.0
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 04:34:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXLnGawoGgP10gyztSBQ1tlsAdFM2dPHvvBrRa8u1EWEl/eJEk35VReqsWE3o6LfiR5J2IyygS3M4s=@googlegroups.com
X-Gm-Gg: ASbGnctKwJ1hHX8S/7U5dukOLOdbfSbyx9yuvqPqCHShqmdM7jHmwb1c33kxoRquPM5
	CtIBb0BEgUE4uWMpjhcv93OD8I/TxQIBbjmugTpXIOkvozPc1Fmo7fN4lqmLONWs823gqK+V7n9
	Qi+awsnCzASD38Xxcyq8SIbxsNdUOaZQOarAMu6tu+6Jhuv9/1ZnumfFl0+IMHyj3K5r3Z/z5d2
	QxEDa5eXzSbUUg1jtd2cGT8X+/+ji4A0Bs4lpw17Vo4pETmXR+QP4ded35F22a39dUomQMXW2Xy
	miRRRsnxJY8LkSR8ZkFVKPyrQkKQMDn6uednSzk3Q5odlgF3xoREuzG3n8sVOHxXcIoOy3er5IV
	n8eI4Q/nMKjYJcl3F70/nfD8w74G4dAap7q8F2uhfFPVGLFZKhty2f7X5rkC2UY0F0cA=
X-Received: by 2002:a05:600c:3b85:b0:45d:e285:c4ec with SMTP id 5b1f17b1804b1-45f216696c8mr21980555e9.4.1757676880116;
        Fri, 12 Sep 2025 04:34:40 -0700 (PDT)
X-Received: by 2002:a05:600c:3b85:b0:45d:e285:c4ec with SMTP id 5b1f17b1804b1-45f216696c8mr21980295e9.4.1757676879669;
        Fri, 12 Sep 2025 04:34:39 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f20:da00:b70a:d502:3b51:1f2d? (p200300d82f20da00b70ad5023b511f2d.dip0.t-ipconnect.de. [2003:d8:2f20:da00:b70a:d502:3b51:1f2d])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3e7607ccf9esm6158472f8f.40.2025.09.12.04.34.38
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 04:34:39 -0700 (PDT)
Message-ID: <d7a03a2b-d950-4645-80f2-63830bd84f76@redhat.com>
Date: Fri, 12 Sep 2025 13:34:37 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: next-20250912: riscv: s390: mm/kasan/shadow.c
 'kasan_populate_vmalloc_pte' pgtable.h:247:41: error: statement with no
 effect [-Werror=unused-value]
To: Naresh Kamboju <naresh.kamboju@linaro.org>,
 kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>,
 open list <linux-kernel@vger.kernel.org>,
 linux-riscv <linux-riscv@lists.infradead.org>, linux-s390@vger.kernel.org,
 lkft-triage@lists.linaro.org, Linux Regressions
 <regressions@lists.linux.dev>, Andrew Morton <akpm@linuxfoundation.org>
Cc: Kevin Brodsky <kevin.brodsky@arm.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Dan Carpenter <dan.carpenter@linaro.org>, Arnd Bergmann <arnd@arndb.de>,
 Anders Roxell <anders.roxell@linaro.org>,
 Ben Copeland <benjamin.copeland@linaro.org>
References: <CA+G9fYvQekqNdZpOeibBf0DZNjqR+ZGHRw1yHq6uh0OROZ9sRw@mail.gmail.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <CA+G9fYvQekqNdZpOeibBf0DZNjqR+ZGHRw1yHq6uh0OROZ9sRw@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: tYqU2SlUV8cvk2e2oewuP6gsN1fG1vZpA_cP96iS-ko_1757676880
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Lz3BmvmO;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

On 12.09.25 13:32, Naresh Kamboju wrote:
> The following build warnings / errors noticed on the riscv and s390
> with allyesconfig build on the Linux next-20250912 tag.
> 
> Regression Analysis:
> - New regression? yes
> - Reproducibility? yes
> 
> Build regression: next-20250912 mm/kasan/shadow.c
> 'kasan_populate_vmalloc_pte' pgtable.h error statement with no effect
> [-Werror=unused-value]
> 
> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> 
> $ git log --oneline next-20250911..next-20250912 --  mm/kasan/shadow.c
>    aed53ec0b797a mm: introduce local state for lazy_mmu sections
>    307f2dc9b308e kasan: introduce ARCH_DEFER_KASAN and unify static key
> across modes
> 
> ## Test log
> In file included from include/linux/kasan.h:37,
>                   from mm/kasan/shadow.c:14:
> mm/kasan/shadow.c: In function 'kasan_populate_vmalloc_pte':
> include/linux/pgtable.h:247:41: error: statement with no effect
> [-Werror=unused-value]
>    247 | #define arch_enter_lazy_mmu_mode()      (LAZY_MMU_DEFAULT)
>        |                                         ^
> mm/kasan/shadow.c:322:9: note: in expansion of macro 'arch_enter_lazy_mmu_mode'
>    322 |         arch_enter_lazy_mmu_mode();
>        |         ^~~~~~~~~~~~~~~~~~~~~~~~
> mm/kasan/shadow.c: In function 'kasan_depopulate_vmalloc_pte':
> include/linux/pgtable.h:247:41: error: statement with no effect
> [-Werror=unused-value]
>    247 | #define arch_enter_lazy_mmu_mode()      (LAZY_MMU_DEFAULT)
>        |                                         ^
> mm/kasan/shadow.c:497:9: note: in expansion of macro 'arch_enter_lazy_mmu_mode'
>    497 |         arch_enter_lazy_mmu_mode();
>        |         ^~~~~~~~~~~~~~~~~~~~~~~~
> cc1: all warnings being treated as errors
> 


I'm afraid these changes landed in -mm-unstable a bit too early.


-- 
Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d7a03a2b-d950-4645-80f2-63830bd84f76%40redhat.com.
