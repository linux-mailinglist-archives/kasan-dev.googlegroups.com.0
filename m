Return-Path: <kasan-dev+bncBC5L5P75YUERBZGY4HWQKGQEAV672ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D767E8CF7
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 17:44:21 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id d25sf306632ljg.13
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 09:44:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572367460; cv=pass;
        d=google.com; s=arc-20160816;
        b=WPMSRcHW86cxhxH2xzS7gFInwrlt0A4TCPjEshErd1NK5QBTjH0XMyT6/Nh4U8GXUg
         KT0lt8QbButwKylJO7b1oIr8wfZ57HkaD277pI7qy5a5iDwN95ATePVZXTlS20CK5hRA
         0IUSdCvJ/+MrJ+QKdgjRNeMW2kNqbEw6pPIyVphNU5EqBjNiyZS4Hte0AzLSU8TivHBa
         A2XUDfZ+/jDlvFnL1yrGH/XvzVCAqijLH4ocOZFcg21ZghPDHNtVWI6gUERPCCxm+7FA
         +dnLlBKerKr5Dn04V4lwG+TxBXiR4QiEBpke29vjNevnKl7bjJ+1EIT9Gr6t1mzl2vrh
         BqXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=46JEHmzA0eK9orU1ZE4EkLd5YMHw/6GOZYUfGETMXWM=;
        b=pAaqkerYRA8IvXQa8/i/88zk3rBM/oX25/aOVySOIyO0WUGPZKTpDY7f1s5Aqd4o2i
         fLaLX5ZM7RWpfTVFKY7M7IliKb57ne6waU8P+unwslmJqtQW5QaXaBwBOWwpycoF6NTU
         61p9qeL+hIfWoPk3V/7dxT+59Sh5b6sdA+db7XfuTOzdIrWKOONPC7sedPZE0Rh1CPi1
         ExyRS9jLan5LvraeWb3ruFfXvTklNH+j/dym9e0hTdP20j/ymQEVmm0z4HS9u3EP2frs
         7OWAAQ6YYqqG8OYSl9T9g56GBLKQ0I9jVLjaYCImbdRcvXGEaomWFUFCStoq37JIBPI/
         563Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=46JEHmzA0eK9orU1ZE4EkLd5YMHw/6GOZYUfGETMXWM=;
        b=LEMfkIBvgvwR5+JZwEP2CpIqpH+Cfw194ZbS7VDkvW5dYO5iS8fE9el2zxfXNJErMY
         p8NiHVPYyNqOX/2hAM83kFgVcyM/c+8/hcRj365LMVMuUPXlnllqMgpvFRU1lctpoaYC
         PB6v9I1kVzMroJNpNwc9LsLgFGVCnWWi8cEJmj5mth8ZZ6DwAZe5m6tWCH28ErH2mOb9
         Ief6icHnGTu6U2R1/xPRWSpDZ02f2eMAbvYA4sPkySkByecxI6xkX9Rrk83T9XFJ44Bu
         cL5dEIxdT5Ro6dp3jxfXNOo26yaqloA2vLgZeMzwp+OKi9BnN2/ujY1fr4olo8zOcIfq
         2dZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=46JEHmzA0eK9orU1ZE4EkLd5YMHw/6GOZYUfGETMXWM=;
        b=QguLuNp+a94FSGayW2KHzjrGQNIhpWFK/kHyYQNCElDTg1RP6+BfgA24/pBv3DL4Ov
         j+XE2+DV6jOoaIQ0rSiOSW/KXHQDCuHMG+km/YbyHGMvvZ1davePFBnAvFvGpipmrLPi
         ZQULSV69kdwA6CX9b9+FZEq/zVTGiffbyQLI83icSecHeSWJctv1f0/bxPwJB0UU4ZyF
         2TUBtpo6mhbLEvLgTk+m5zPkmWQtRfVqy/Mv9Mee3ZgMUpDqH8ZB6VWkLiamt2T8riX2
         UHEk2Oej7UmQylaAAG5SfcOHW+OCYDoLlhtZjh3fe+AlsrwLFlQZ2e67/UX3uhAkSBs8
         FPxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWxz+dK9DfiOp0jVwXXAXSBJD5TGpPLUQdCW9RIljdZAc9o5dwL
	kG+TB8iTbvOgC/f2Lr3THU8=
X-Google-Smtp-Source: APXvYqwdZj9e5/F3aVgB/Fx+igp5tlkiuCIhye1nRZib3M3Cr/iUPP8YClG/FK8fnwFYU3sVzTLaGQ==
X-Received: by 2002:a19:c192:: with SMTP id r140mr3156740lff.48.1572367460684;
        Tue, 29 Oct 2019 09:44:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:4349:: with SMTP id m9ls2312416lfj.8.gmail; Tue, 29 Oct
 2019 09:44:20 -0700 (PDT)
X-Received: by 2002:a19:ec02:: with SMTP id b2mr3023003lfa.121.1572367460203;
        Tue, 29 Oct 2019 09:44:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572367460; cv=none;
        d=google.com; s=arc-20160816;
        b=QHujQMqg8pOxTXkIsL8NjQhXFTvJzk+huowFplHT5XT9w/oPuY9h1dw+lBuFJX6KnA
         3+tEfMpIUxsP9f4wCTXMaLYhjtz394k6dPXXsDay6JcBAbZ1F+p769fDbWuR3Qen7fNL
         3HJOHNhbD5cdsGK9EXiUy/T5jDKMYAmu07uOtrWH/emNdf+pJ8p2Qwy6HG+poDGBd+6j
         NVBRFQLwZ91Z1sgbyhJJN7uTmhRVwb6B+cJF2WXZ/s0WJ481yabLFN8pY7OkqTCpD2vA
         k/7nvtVRakX2UHxZDVxaDTD+o3Z3pD2Ym1nvK+YWbJvlCGXB060DTuZhFrxOw5zSijpk
         uOFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=qhQrDa/HgUXOaFkyqYYJRMd9hElY+dd93yza8anbyW0=;
        b=W719dnZTqyVrJd3unMnVfnkAeUnne3AYx0jdprqeoe5VCeCOFubnWRkTjQPpDZFl7K
         Y5+26/U+9/xTCpO0tMlX6iGr/CX2M2B+tG0xbI7bU5lK4BEwohjNEvoKnIs3u0Lt4Wuq
         4mnW5v/UBZ4inNJ/RTVcgGvcg2CQ6BInJCaotbGUaVUQKshWzK1bXftdbCI4KgVBTW4m
         Vo1krARBkvGOn2zyxZ2owG2yIDdrm29ZChJE9xLh59JbDXhjTcwa6fSU3GrD4+RAbUbv
         Qntmc/mzLx2EWQHuVKD2HnuqRUYlqAHnaslTbEH2hNsOCY+QkUWEjG8cjq/eM/upboU3
         MmDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id s4si200921ljg.1.2019.10.29.09.44.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 29 Oct 2019 09:44:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92.2)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iPUbL-0006X9-ST; Tue, 29 Oct 2019 19:44:11 +0300
Subject: Re: [PATCH v10 2/5] kasan: add test for vmalloc
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org,
 linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com,
 christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
References: <20191029042059.28541-1-dja@axtens.net>
 <20191029042059.28541-3-dja@axtens.net>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <780d2085-5bfd-e206-b760-ea528844b68e@virtuozzo.com>
Date: Tue, 29 Oct 2019 19:43:53 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <20191029042059.28541-3-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 10/29/19 7:20 AM, Daniel Axtens wrote:
> Test kasan vmalloc support by adding a new test to the module.
> 
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> 

Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/780d2085-5bfd-e206-b760-ea528844b68e%40virtuozzo.com.
