Return-Path: <kasan-dev+bncBC5L5P75YUERBH65TDUQKGQEDV7LI3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id F00E364C16
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jul 2019 20:29:51 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id m2sf268280lfj.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Jul 2019 11:29:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562783391; cv=pass;
        d=google.com; s=arc-20160816;
        b=aueAx7FXQlBw5SzZMb60XFz89gx9woNDO+ihbMhtLNKoFjT5U5Ip8Yb2Oj8DZlsYNP
         E0hSMDZ8LukBXPQHnNrej1xyn0cObOpgOyaVVDuKocCWwbUqTX+IDZu1DxQFzjZWuqyO
         fahq9pkUK5qKsLZ9Gx6zTZ1S4FCPbYMqQG94h62WfVxh3pIU9eNCg19BucdJrQxTnDDn
         y5T5bEWTg4PgY2bWJ/YaX000xGXlb+DtV+UPMJOCdPUW++WoBHUsoW5oSrzjGPWb/HT5
         PHHdTsaUBxFhKuW8TdGiuLydLl9wZB8EerGXqln2LY3eVPrHEpFsQKPF7wGTOTxzK+h1
         myWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=STeGCB/79El0H6quk1gRHpolLMNmLcVnjynOGCILSE8=;
        b=zt0ey9gLo8iGSSsfhDnWWlxAtXT5LtClH62XUaWeW1vcPS49l5KOSYAA2PznP52orY
         6uWp6/OL7THn7d0rLpfE7fpmUC+PN188r7AY2xEvdURxzZRHc7ZmWUjeiT4E3kLH0q4d
         lrpUfjA243m3DDlfFRKwjCpuD+i+Gwp/vKcniTxfpGX8o6bpi9DhSvgYuwCHcxvlgsTM
         fm6M6A7YKRFTz8TTLnnQKEshQ8bS/15LY/mnc66mRtAETmZoKyHS5VULcV7q914wG8zr
         MJZqT4ht57w0VtexpzSxjkJvqE/V3DwITKSX90HU5i/3Q7LfV1eWoP+AtLcUWn9ri7cJ
         dXaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=STeGCB/79El0H6quk1gRHpolLMNmLcVnjynOGCILSE8=;
        b=YumLuaA+XnA73LudPbakwTXHk7ujuArKKnMYvmeMmWXiuWkk85OIqYSjpzfQBy4WEo
         b5jDoyXTRmDlEScGvMtyMmDEMklRp6tDSGjpelwIrhUY52V/uj6UXjwV+2rJPhPz/g3M
         8vYwpS6EP17/pvvdrSl9BluJh8HChey4TiTMn+WlLlPfLd89jqezLI+KdM8YVllOQUoU
         b9D9JLvgz8mYjDMXEt4CbBSvw5B1eWHjJxRJASWMtgJlhit8jn1gF1hKp/W3oXN554xS
         tRtwODj62blTaLI0+Y8n1w97mmrOCqxmh2veniE1Y5V/bxSzjgtVQqq2QYuclGqrlt+Y
         zuRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=STeGCB/79El0H6quk1gRHpolLMNmLcVnjynOGCILSE8=;
        b=MmuyRfMR1WAIU7bx/1DiskAH9gtaJXJxP1taBPm3II4cQZZvpEN1uEnANBQyCENTPD
         6l65cpZ/z1+dqGsjDIK8C8BGkzcvE2RGRctq5GPdFmmv+WoOJcGY43B7Yvd0zPGnSrbi
         IFeTaqq0ECO8vw8bNPMa+cifc+ZLmZ0NKZRqQY/v9u8M2LsReum+noVCwfBZa+Ixv5zU
         SgdeLlAlMkTAwEkr3asbk5GhtpasNUImfpSV/KIFfqI6OCowdOZ/aFITG8aDhdTHZsFT
         8e77+kBxAgprx2mcvng0sh4pKmjG67z2j3cVRKT5AbYJ6UWSxrdLhJF0krq2+UmUUSbC
         350A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVSHuQcl54aQjhvh3pdTAOR5x8q/nfOBwFrU91aBLAEvylK+ip3
	yLCnHbB06HWsumfcA+9cb8c=
X-Google-Smtp-Source: APXvYqwxMp4wkC0XUiwqo0o0t8urxvY9aFVidQHvKJEsVIwrWPBE3ueKJzRSzuhb+Q976VAlZH9NbQ==
X-Received: by 2002:a2e:63cd:: with SMTP id s74mr18266953lje.164.1562783391536;
        Wed, 10 Jul 2019 11:29:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:7b01:: with SMTP id w1ls286985lfc.5.gmail; Wed, 10 Jul
 2019 11:29:50 -0700 (PDT)
X-Received: by 2002:a19:c150:: with SMTP id r77mr16774600lff.76.1562783390926;
        Wed, 10 Jul 2019 11:29:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562783390; cv=none;
        d=google.com; s=arc-20160816;
        b=YztIUPdgCfnZ2ANzBc0B8QJ8yozZ9FJSATkWu+CIeMbc8OzBMEHkRFUJYNg9brgnXg
         NyRYyKzOGQuiJh+xgBWpOkHpli2trC4/XyUAIewm97H21JcU/yjskITnneMwUWe8GrLs
         5YY53HAM4GSC9hNzSJft4gkISfCJntSNdSuTjWGaW0WEHbnOgICZkV9joFvNCr64zfDR
         ZCU3ewnGd9nfgGAQ10cXN9toy0DXbMALDbYdEzlQ2wEQdVtENayIVlYN7SM/cz3KRb3R
         aLfIgbqsN3Wd7yOORc8ymklL5LSuZdqoyb+7H5VZgATqOhwYMhxYJsMUmhDgML5rhp8k
         TtaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=V64pBGGyvpGpIrNKWa5fgZ6XjkccPPsATaZLEP7yVGI=;
        b=V+JNoGlsI6HBYodqOqHPn7mQPdr4Cou/5RQ9jIlxZbMyt0KkZiEn9wC2Tcas+5SKTt
         vspeUZnlj/R9GvsqsM1mj1eNqtPFUlaOJ0iSDsOXNpsC3sbtEo5KsGz19jInPSu5tGJi
         n770UGuUq2s7t6xZVDYL4eWYsIk6Z2+x6opygtd7H111C3lCaC94y4O5ynCVJiKBCsOl
         meE3k8RIRpjmX7tCxUILaa+p4oQR4+e5FR1HCnbaHlJFwfhsfvtJQSP6K8T2kxe9KZts
         q6LOh0Wpre6qSE50xXA5ZDls9wE/JPF2EuYFk0SI8bqlmIlZgY8dUTZV1eS9DR4tvOdQ
         EbcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id v29si177060lfq.2.2019.07.10.11.29.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Jul 2019 11:29:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.12]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1hlHLb-0006Lj-N7; Wed, 10 Jul 2019 21:29:43 +0300
Subject: Re: [PATCH v5 0/5] Add object validation in ksize()
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Mark Rutland <mark.rutland@arm.com>, Kees Cook <keescook@chromium.org>,
 Stephen Rothwell <sfr@canb.auug.org.au>, Qian Cai <cai@lca.pw>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 kbuild test robot <lkp@intel.com>
References: <20190708170706.174189-1-elver@google.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <75963ba0-7ed2-9e4a-171b-d2cb5d16af2b@virtuozzo.com>
Date: Wed, 10 Jul 2019 21:29:38 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.2
MIME-Version: 1.0
In-Reply-To: <20190708170706.174189-1-elver@google.com>
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



On 7/8/19 8:07 PM, Marco Elver wrote:
> This version fixes several build issues --
> Reported-by: kbuild test robot <lkp@intel.com>
> 
> Previous version here:
> http://lkml.kernel.org/r/20190627094445.216365-1-elver@google.com
> 
> Marco Elver (5):
>   mm/kasan: Introduce __kasan_check_{read,write}
>   mm/kasan: Change kasan_check_{read,write} to return boolean
>   lib/test_kasan: Add test for double-kzfree detection
>   mm/slab: Refactor common ksize KASAN logic into slab_common.c
>   mm/kasan: Add object validation in ksize()
> 

Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/75963ba0-7ed2-9e4a-171b-d2cb5d16af2b%40virtuozzo.com.
For more options, visit https://groups.google.com/d/optout.
