Return-Path: <kasan-dev+bncBDDL3KWR4EBRBLM727CQMGQE57U2KJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id E53D4B3ECB9
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 18:54:06 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-24868b07b5bsf88651555ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 09:54:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756745645; cv=pass;
        d=google.com; s=arc-20240605;
        b=CktuOlsEtg+LmzTFPYPhHpFU9zKQHwQVhH2KFj0hIzLrGJrhzRx1mEsf3kLhI5WzJ3
         53fdJVg03vNgtvuFnQb5ulbTeuXrsU5LsaGEMdVhvaFyTmV+wPywUmCFble56uPdYktv
         1Icq43seZHVd+nLt66NEYZSPQ8oW3Fu73xrd7RvWHMOahzqMDNz68NiwauU7ogkOyg+J
         Sxe82mbewV4rimBgz6z7s5m+vrBYqzshkHC2NWuTwZGppWVH5u4vJxOR9FrtC8tsF6PZ
         //I7Xzm7QuNY0A10U4SbzCSIeZy1/9rQAfxjUO76hUl0T8x9WGY8y2btRR5lFf+RC75f
         l08A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=LBwXjKzTnxeNv0JzUpxo2Px5KPgZqIlCYLZs9pWy9tQ=;
        fh=73agoOTF1zoesNrMwhX3H9jpBKXnMNJ6O4q5McChlFk=;
        b=Q5wQuEWNbwn9sdss9RGHSmZ6MYHCfp0xkvbJSojgoYBs7yRX07frVoNNXw7D0Y8PQU
         0SuNkP702xX9DxLJpd7SXet2AwckcrpnUZ8iVqC4hwgX4dVksZlbZrIbYz4DKcmmzT6h
         UrdbbRvtkLT9idh+uqmdxagvccg9/UN3bUPZ+/31n8DYI3+HiAytiCtBPvQONktVeMN4
         m5rYk9hMFfjIEPuj8BvEZ0ybIS9fNUdLy+siwWacEIrhEzgPGqODGjpKw5xRtaAxA79x
         aA4U0yg6CuHNwM1MLVkENJi6v/fQUXlszvaTfnUKY1j7YqPaiXWBOR8qZ9XnvR2ZK4ZT
         289g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756745645; x=1757350445; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LBwXjKzTnxeNv0JzUpxo2Px5KPgZqIlCYLZs9pWy9tQ=;
        b=jVfBtQzLxtwp8kHaLMNRHFdRpoaEYB2RFKzslXfVu8wACrYjxTmGnjuYr+NNhY/8cN
         bGsvuLZ73RX0QnG92B1+JIumwx7pmQ5dWyo5Hw/90LTWATSulExQ9s5TnldSgSf8113j
         kPFzfE+9R2HvTD36GPkvgJXcsH5pbxGqpMTTIOepFkcfk7kuLVcy3uGWRkmV5SWv88tD
         4zF7QIapdyZEzYl7guGSCKPoIDYoIDNerup8Cyieb+txuomXUcX+5TwD2pdyAHyuvnTj
         75BqlaKvS7Hr7xxKxQHwbdu4qozmBN+2eLfMcIeWba5qG3oaL1xUvparfgk+muUhtyxt
         Q3bQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756745645; x=1757350445;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LBwXjKzTnxeNv0JzUpxo2Px5KPgZqIlCYLZs9pWy9tQ=;
        b=CyqblRtwvYBj/MVfrdgA1uh/dRsv9180R0Iuk52uNllaVZoJ9Z4MI1r4qkBC456dU7
         EQO/fOacVWxEp8mA5hiMU8Qq37LQFFRN0tIM8xYCy0JW0Ql58B1y8aalk/Lv3CwUsxwH
         tMT4Z8onUzX5Vu5H05F5ynJAfp68yedlOPpFYj6cF3RHSzxICCBzfEJIpVen6jrw2pVL
         gGaYTQbuFvOtMW+AqQ3QTXgPtDhAFdd4Atxkg0XBXgKjvWlG2R4xV6X7Ri0/Jbqy+goC
         0hNHUFUqmzRkqcVM07Bp9KbpNT3kWyBQdz8MUxe4CPFnt76Wx+0pFG0LERKedV2UWjdS
         JqvQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVnD4LlLbVAROGn6Zwe1CikUrGP7rZl2JfscGAzQlXWtyWrTcBKfbFXB8YG3c+4bJtLL9FOWw==@lfdr.de
X-Gm-Message-State: AOJu0YytqIVD/CouvUD/4xfkrIZWMviz0A+HWqOGcIrzze31/ZgE85aT
	tVIcVGxD/VJmd3fT4NbcbQL1wYo/D/PfYxRvNScX12+s442QMJcCvrpR
X-Google-Smtp-Source: AGHT+IEKwC8sfEpqyqo8PbYjkH1lgsOgfu1Z3MmRKwL+Cfg8DTwCZOHoOIdbl+/PxZ2GZtIm6KQ3+Q==
X-Received: by 2002:a17:902:f641:b0:24a:f79e:e5c2 with SMTP id d9443c01a7336-24af79eeadbmr21429805ad.12.1756745645313;
        Mon, 01 Sep 2025 09:54:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf1AbCWYIixjcVMkwVpgjPXHHzkyEHgkSZohaI5auBblg==
Received: by 2002:a17:902:f7d4:b0:248:894e:7740 with SMTP id
 d9443c01a7336-248d4b17bf4ls33519135ad.0.-pod-prod-06-us; Mon, 01 Sep 2025
 09:54:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVIaZOe0XMJXSgL9Qo2NwlZjX7eP2tVjPdPKqsvFFXfNAqssY5BX8te3tHCQeE1Zl0uvTyaoZud3Ec=@googlegroups.com
X-Received: by 2002:a17:902:f641:b0:24a:f79e:e5c2 with SMTP id d9443c01a7336-24af79eeadbmr21429155ad.12.1756745643872;
        Mon, 01 Sep 2025 09:54:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756745643; cv=none;
        d=google.com; s=arc-20240605;
        b=gVeHUHlesFRCCwMPK51u/PDOHe4/r2P5Wk8cEQcfgnk8soX19JE6hbWOQ29xGCu2nd
         BdaXUsLmL6M/3rsRoXk62i5loBp+sTGbziDMFTdWXPtJGrPsYSlr974lKUU5NZ8YudJo
         FSF/dr7rBsdGf7rd9dUsen/XyYg00zmlQ/cKdIYdkljfLI1QOYjs9J1kKi6vI3+yWUY6
         2doqvc+/Hb8jf8TVLPfZrccg0K8ofNcFgLhVohR23KVBy+lAUvnDuk4XgrWuU+6JtdPN
         tSHHZFvUIlfnnFjh61Ho+ltQF62//Gjvdl876lEql7s/z965RpyW/G2IXokZO73v5MBQ
         tkag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=lx60aYNhHUxGjmY6Dd9VkBXb3EBDBQjnPwbyMtD9Gzo=;
        fh=EzR/B+1KMqNd9XTm1o6Oe7qwChDN7wGXNwHOALRhjRs=;
        b=GJ+oYyZ7fKJ6bzHAQJFWIViGIhQhGv5Jqk3kq1xq2d7ZOvvu6lYnAIgvOq1EQShmFu
         6jTejOVvj/4KB1x/LVYmhotd/VfoOZN1bUC0twhN7ooZ7XHfRBHMMkuEWexCxwo+Mw12
         d3Lgddk064qIbZgwC5P4GE5IZfsiVWIK8GSHTCe//3MZlSUHe7S2CyB3klC03/B6VKT/
         WiSi9CGjrkE9sQAfIl+f77fQW4FKKVWZu/UV14Fzqb8jwXSf0l98Z0Mq6HTr0bi/tV4B
         8UMHrnb3b5SLM7FJmUpps+hJDzhRbGamqKnuvXrlbrLWuPy0CYJ5rsb6WEEf3YVEk5wD
         L8RA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-24905da342dsi3015855ad.5.2025.09.01.09.54.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 09:54:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id C9CB0601E2;
	Mon,  1 Sep 2025 16:54:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E6DB8C4CEF0;
	Mon,  1 Sep 2025 16:53:57 +0000 (UTC)
Date: Mon, 1 Sep 2025 17:53:55 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com, corbet@lwn.net,
	will@kernel.org, akpm@linux-foundation.org,
	scott@os.amperecomputing.com, jhubbard@nvidia.com,
	pankaj.gupta@amd.com, leitao@debian.org, kaleshsingh@google.com,
	maz@kernel.org, broonie@kernel.org, oliver.upton@linux.dev,
	james.morse@arm.com, ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v6 1/2] kasan/hw-tags: introduce kasan.write_only option
Message-ID: <aLXPownoCikoHvZP@arm.com>
References: <20250901104623.402172-1-yeoreum.yun@arm.com>
 <20250901104623.402172-2-yeoreum.yun@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250901104623.402172-2-yeoreum.yun@arm.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 172.105.4.254 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Sep 01, 2025 at 11:46:22AM +0100, Yeoreum Yun wrote:
> Since Armv8.9, FEATURE_MTE_STORE_ONLY feature is introduced to restrict
> raise of tag check fault on store operation only.
> Introcude KASAN write only mode based on this feature.
> 
> KASAN write only mode restricts KASAN checks operation for write only and
> omits the checks for fetch/read operations when accessing memory.
> So it might be used not only debugging enviroment but also normal
> enviroment to check memory safty.
> 
> This features can be controlled with "kasan.write_only" arguments.
> When "kasan.write_only=on", KASAN checks write operation only otherwise
> KASAN checks all operations.
> 
> This changes the MTE_STORE_ONLY feature as BOOT_CPU_FEATURE like
> ARM64_MTE_ASYMM so that makes it initialise in kasan_init_hw_tags()
> with other function together.
> 
> Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLXPownoCikoHvZP%40arm.com.
