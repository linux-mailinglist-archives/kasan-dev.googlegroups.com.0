Return-Path: <kasan-dev+bncBDH7RNXZVMORB5GV3COQMGQE3IDRNQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D8BA65E290
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Jan 2023 02:42:14 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id j18-20020a170902da9200b00189b3b16addsf25293287plx.23
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Jan 2023 17:42:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672882933; cv=pass;
        d=google.com; s=arc-20160816;
        b=zR3ruOkEugWTPKqUnYBJb+ShbkvXGRNM2q6wP2IPAOqp4FRgbKZY1P8u9MAh/KxGcx
         9PHqPRtSCLKgDbdfm8yE1eatcMUDqHn/d1pNW7tIvQnHDL+KvinXjzlzd1Suvrt3AUrH
         nEgu07aycHHn4Wm5JhGlGFpBX+47Fp2mp+mn7Osjy5CNvfgzmFZf2ZNjKNOGAbaKnzMh
         8gowfsawpF2GyBJXPC3lTIyirlOnGrSS9oC9SD40A1vncX/vDSeUra3SIeq41zbsD9aJ
         as1rs1cpNRHOh8/jA3smex6gsYA7VU6aq3J88bnRca7UH0DSs6cW+NvTkqQaEqGZ+5pW
         Fk4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=By0bl4zBkihsvvsnJI7o31+X8v+BuH3cWWLuHIUEhks=;
        b=THCj/GvR4xWRZB9gdsJeBvPd0L7gUONpqS3/8CBifGTeq9PqfikHrbUNqrpbbjqmI0
         misDIqhAL28TXczHKvVf0xiYDEHfcffD4lA7GvioeLETG2uJNVwSUeOx7T7GsZluyI89
         T8yQbZHhsyH2uEB+d1Cbs8kBdtFKOR01AXknbRB/qQfsjAeyxWNyBBXcQ1Pp4WZ7mUa/
         A90YgaMV7BzaEDImvD3eHjHvmPi58HA3hYtsqdIp9WXGmGpAV6wIO4Cmg4d3D4AnDcFF
         aywIc7NBPuBL+ijkGVFDhnTKSw1/WgUu7k5mfKYYv8+XaFbgVPerZmvjZSQJtVEq3u36
         wGsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gtIa7MIV;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=By0bl4zBkihsvvsnJI7o31+X8v+BuH3cWWLuHIUEhks=;
        b=Ln5RBRU5MfTw1HG9pu1KqUpuI/b44KPdqg65SHXOQ1OirzkgOBtu+RNTDYPy1z3nPf
         ol43zgKQiuY0/Q8Meabc0TXix0iXxKAnKBNCs7Wc3SGpmlNt7It42ua5OK+znbna2l+R
         mjQxQL9PjVNqgBaIfq0siNI6CaUNufbVAmdeeVIfVbTbAKHNpCtlHvxIAiTC6WU9BNy/
         a4sRghgpYypzBRWJC//7wxuc0RS41TGUjx6PlbRt0mHwKQGpwU35rRSIirEYuflpoGYu
         cfe9OZXD6ownYw5ketuBohiANI70qrwFhjJt9FdjRgYK9OFGyG06EVa80TM3MBY0frAW
         2rfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=By0bl4zBkihsvvsnJI7o31+X8v+BuH3cWWLuHIUEhks=;
        b=fMwbvjcKOJPgIsNgMhvewBJlzL3sc8DAlTVcrHoipqpNZ8kROXf9VXXJH8S20PjVKL
         YKtNDcaJ8g1eOZiqwRVZm08M8sDGOmtTylcOHHeKbd2apIYuHKPyoOKFapZuw1R12QLD
         mQnByoVzT3sVAcptQeTGiEeWQ3ODMdI8+PBX/XRv9ZqPZj2GU4M6xhsNsbi/GJqFtLkw
         lL1izOesLqK8ej8hN27A22VGuA1aa4/0JxpW6mvEMEt3jEQ/72N1weTWK66k/zPOmFk/
         Xd6IL+uQNfhsqqJRbAYHtLvI3O/l/7SfhucUAPHhZh8ZGhWQPFbVoGVjP4SPini6dSuS
         /4KA==
X-Gm-Message-State: AFqh2koVt03c7y3L2XQ6jPQD0hq9q/XK35Z9rqZdpwFFcVvV7vKngIy5
	uyn34sGR/dfexLj47uaPYJ4=
X-Google-Smtp-Source: AMrXdXv+mCjnIwJR+d6A181BkN2vAe7ScIMosns1ft5k5+CNw5XKbbPE4N3d+axIze67bjBVKA79oA==
X-Received: by 2002:a63:1812:0:b0:470:2c91:9579 with SMTP id y18-20020a631812000000b004702c919579mr2695147pgl.22.1672882932802;
        Wed, 04 Jan 2023 17:42:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6897:0:b0:475:7659:869 with SMTP id e23-20020a656897000000b0047576590869ls8209331pgt.6.-pod-prod-gmail;
 Wed, 04 Jan 2023 17:42:12 -0800 (PST)
X-Received: by 2002:a05:6a00:1813:b0:582:a492:f302 with SMTP id y19-20020a056a00181300b00582a492f302mr10927565pfa.16.1672882931958;
        Wed, 04 Jan 2023 17:42:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672882931; cv=none;
        d=google.com; s=arc-20160816;
        b=ASoRf+VZuN8wl9GIHTeKzwLIp+TYF7O8CXMulZLO+1taz6pFkT+tLbalZZammsxZ5l
         e5H76VyidZ3WHdgJaeycFgQN8Z3IUmozkkUqvCNGHJbrYMGG/iGu0oMEASjz/DgvEIYJ
         Wz0ECMXU4GaU0UlrzI2RlXs90BqCD46QvsLk/IDhacrif8QDbAAOwJpPmOsVK31S6S1F
         huRGhmY1Fdho9gDYJk9MOoZEagOGSrFEovWVPgBmxTWEAahQlJQqfSlhyUMju08ilP5v
         DTi7tkSrNuo2ru7vTXb11qpmEIE/F3nlyQvAeG+92IpB3vyAhM76vNoD4UBHNmqqRx+J
         3/tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=hUrfx5rymV6PAvjGCkeIctTq/mmMCexOy9WfgvwN1Yg=;
        b=0043ljN7kusfI3q3AtI7zY6u1Oj/fBqBglm1eqA4b5mPohBqjbhmlSByYlY3KvubEK
         fEoYZeJy+zsp+Ve+Lw0Uc504NyMMenRaWs7HZ8TBcZpOXfg33zhyXnNAAgtCZlht8xjN
         9eCjcEJlpZGaEQPnCRh6xHwsHhE33UjIBprHIa5jRvfkquGhaYSeHmf55bsOEYpAXZLA
         Ec5RB8thjtCs5OMurrWhPLXKyXRMwbVIHkajGkdgk0tGWWExsjBrzCukkl8/679QnceU
         Qg3N332L5odscnFeIUfHzPn4jEsnkx7IraRKAon4Tt6HqU0Em34rxyNs6bon1K0iStMx
         l1mA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gtIa7MIV;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id u80-20020a627953000000b005819980b1e2si1380409pfc.1.2023.01.04.17.42.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Jan 2023 17:42:11 -0800 (PST)
Received-SPF: pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id g20so16045522pfb.3
        for <kasan-dev@googlegroups.com>; Wed, 04 Jan 2023 17:42:11 -0800 (PST)
X-Received: by 2002:a62:e413:0:b0:582:13b5:d735 with SMTP id r19-20020a62e413000000b0058213b5d735mr62623pfh.0.1672882931539;
        Wed, 04 Jan 2023 17:42:11 -0800 (PST)
Received: from [2620:15c:29:203:fc97:724c:15bb:25c7] ([2620:15c:29:203:fc97:724c:15bb:25c7])
        by smtp.gmail.com with ESMTPSA id p5-20020a622905000000b005749f5d9d07sm23726355pfp.99.2023.01.04.17.42.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Jan 2023 17:42:10 -0800 (PST)
Date: Wed, 4 Jan 2023 17:42:10 -0800 (PST)
From: "'David Rientjes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Feng Tang <feng.tang@intel.com>
cc: Andrew Morton <akpm@linux-foundation.org>, 
    Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, 
    Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
    Roman Gushchin <roman.gushchin@linux.dev>, 
    Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
    Andrey Konovalov <andreyknvl@gmail.com>, 
    Dmitry Vyukov <dvyukov@google.com>, 
    Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
    Alexander Potapenko <glider@google.com>, 
    Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org, 
    kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [Patch v3 -mm 2/2] mm/kasan: simplify and refine kasan_cache
 code
In-Reply-To: <20230104060605.930910-2-feng.tang@intel.com>
Message-ID: <b0d265fb-1b0a-902a-c23f-176b29792b37@google.com>
References: <20230104060605.930910-1-feng.tang@intel.com> <20230104060605.930910-2-feng.tang@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rientjes@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gtIa7MIV;       spf=pass
 (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::434
 as permitted sender) smtp.mailfrom=rientjes@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Rientjes <rientjes@google.com>
Reply-To: David Rientjes <rientjes@google.com>
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

On Wed, 4 Jan 2023, Feng Tang wrote:

> struct 'kasan_cache' has a member 'is_kmalloc' indicating whether
> its host kmem_cache is a kmalloc cache. With newly introduced
> is_kmalloc_cache() helper, 'is_kmalloc' and its related function can
> be replaced and removed.
> 
> Also 'kasan_cache' is only needed by KASAN generic mode, and not by
> SW/HW tag modes, so refine its protection macro accordingly, suggested
> by Andrey Konoval.
> 
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Acked-by: David Rientjes <rientjes@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b0d265fb-1b0a-902a-c23f-176b29792b37%40google.com.
