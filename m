Return-Path: <kasan-dev+bncBDEZDPVRZMARBRFMQ7DAMGQE5RR73FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id A063EB52164
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 21:49:26 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4b5f6eeb20esf301261cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 12:49:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757533765; cv=pass;
        d=google.com; s=arc-20240605;
        b=WsLuVTBXzgGLxPrrLNQvBhUgYanPlUTrg/SfL7cnRDPPF/oFuOvy8U46t+ESGRtu+P
         sKOzT3gW8fxN9+A2B8xqa88lbOeLmkXhHuQylSoVDkVDx5E+kp7CSEnGwlLGd1iPetnL
         0ZQ3tLfH7vEpIb3M6Y3XdrM0+kjalkiP+lb1fquoOiyt35bpGshIHumiDFIM4whqDSBT
         zDmo5fxE9W/O3aCIUjIz4J60vdu+I6ypvMkNHy/I2eLBUEcyf+9kIEIJm3lZAzAWESOA
         WCxhmlqgJG+AtUIMoN3HhoDsKV1zhL3t6onJC5dRdAlLULaQxZQalp0tkEzVFLPC5R44
         GSEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=RQ2ce9HZti9LM+RtOhNwiV/BAU4SAOm44scHDo3J798=;
        fh=7zwDXFtKpp3LyqdCMEj6bnsnecXMNApIRkD/EpP38Zw=;
        b=Yn9W6IwvHBrY1gIc0DQ84GqPa1cY8CCPn8t47kCILDdy2/PzOBwcnUkHWNvzWCfcXS
         SwNY3qm02gjhsFiQ+HwvT3+1iP3B8ZQl1K27BbSMXoQoC4MBJi7ECgLDK26xpOcJoOn1
         IJINrSfKZXYzV1rvySdFO8LMOVKDJQg1YBMoN2z/ujW669BKlTtwwUAPVIGVYnNLDLp1
         58/KqWmg2H59EFV/ToL/RZLNuU1DTCnVG0d2gt0RCFiBis9bbHXN+Yq6o5QwdFAivymy
         m7hx1zLmyZqWBAtV6+v50QaMb2Onx0rolPB+FQgQPnKZInW9ol/WuM7+BQuoPFICuRWv
         eA0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=B2QUeXsF;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757533765; x=1758138565; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=RQ2ce9HZti9LM+RtOhNwiV/BAU4SAOm44scHDo3J798=;
        b=CehI19fOUF1pjffkhjUTqKciW3AVQAfMplrBwY5tPy5QVuPS9usI2QBioEUSVsYHB4
         X92XKpm+iDGRD7bE5dDkJjS0/sEYAn3yZR681ET2jR+HNcPsJ2EF5V/VJvQc3KKbAMih
         u+4rrxXLHI86He7jtewn753GGwkaPZBvIINF0aQm3ELRhkQki+xVjZNNQCWJvdHe57G9
         FKdK/pyO0/ZBz8PBTMWg32tLAkFldAKEw7FtUYTmGtgvvPXl2Pg3HVMHdMtjiaHY3hsi
         HLyUS488K5jZtUNwcrLlu5zQmMOB10k3KuL8cvZoTCOZyKvcfiN7HRBzRjFOWFqJeMl4
         FsCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757533765; x=1758138565;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RQ2ce9HZti9LM+RtOhNwiV/BAU4SAOm44scHDo3J798=;
        b=EIqkdfpJ1Pv3towyQnjmM0hCYrtOvq/xXv25ErQx2uq8+UAQdEEFazjX5PmtxQXh9N
         zGzjja+QwR2zm9G0MMw6mbTvAjqsihc5GbtCM8UttTh77HAttPOSE3NZx/+K8g7gNlmu
         3cGLCjUQdayxCJ1zC94VxZmT3+yaDMl+ublNcJNoRxaKEAAn4W/vkmaCrQJRVG8sAv/e
         uynzoAv0sHG6cEKz8Ph4oquNbmL6NAI+WW+IxJHUbVVQKE+okywYQg8Vw2K64puir8jO
         vBNoVhpavWD1O5+j54ad5QZcC7pbuy/RBY9/pPWwZSuq9ZhjUdxkZUatw+4L4SunEOWV
         YoOg==
X-Forwarded-Encrypted: i=2; AJvYcCXzR7LI8XF7qe8uHCvtmS3SdYb8IBbQOf3zW0U34naauQTXtQZPgdtWyhoMqueMBC5XLT+XlQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz5CBWStcYaPuSYlYMUvxQMT4enCxHkMHMFEoG2/0FTgm1P5eNd
	mjQkRZ6OaJ1iiIVoAMFSfIzSteota31KLsu80sEqwigvAzmwIYqDU1bx
X-Google-Smtp-Source: AGHT+IEqGaLhKqAuRgk8GcCLV17AiTrjn4x6he/LncKY0n2OSOr4esZqKbFCzKlLHtBr6CLx0SzJmQ==
X-Received: by 2002:ac8:5fcb:0:b0:4b4:9773:586c with SMTP id d75a77b69052e-4b5f847c957mr187451851cf.66.1757533765142;
        Wed, 10 Sep 2025 12:49:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdUcg5pBCLXBLsVUDFgqj8MNfvNhs/9KXOkKYNVfBzhGw==
Received: by 2002:a05:622a:3c8:b0:4b0:889b:bc70 with SMTP id
 d75a77b69052e-4b636ccb94als866911cf.2.-pod-prod-04-us; Wed, 10 Sep 2025
 12:49:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUN+A7wrHC4kb0YQMKHBVLzsit8sQgvwKOeOv/ASe/nBIfSy3jk9tCkjFH3rXhdNFEBISf69BGnAnM=@googlegroups.com
X-Received: by 2002:a05:620a:28c3:b0:7ff:e9e4:46e3 with SMTP id af79cd13be357-813be1532e3mr1793075285a.16.1757533764156;
        Wed, 10 Sep 2025 12:49:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757533764; cv=none;
        d=google.com; s=arc-20240605;
        b=U79HU3uTtT/u2kkiZCoIjuHmcNRvh1l3/KzfE7+JqpKKFJLqc+SJNkkoWzHEsFihjn
         mPAPlJQ6CAklfIM9RXSLkanYVoN3Lt0valbitCIoAoxHcwxOuMGxIhPmKYm5yfziIoxi
         kgh0H+cuBD7RdzoM9E/Yky+mT7UWHOzT29ZjbKSwoNfae0hN+/oSYMzyQ5BuaCGTsAAs
         05fLlrPxoecEakMj3Adbp+KGMzvzNNqhwaCm+FB7IR+BCPxn67WbGbqwLKC4Hph9D3iv
         8/tm5pktU3Z87x7I65WzqBsK0B17Qt4vE+dLNW3QIdtkKWcGu3MZDgRorI/SDeeOcfMi
         rfuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JoH38RtYXmoZLN0q81m7nCOC2Xpz+em2/gxxRmxSaNM=;
        fh=Grgi6KL3YGNL545HcJ+hOK+fN7xpeX/8dfcXrBw508Y=;
        b=hcLAnVfx8Vnfkkyblz9aV8awCiZfQxFck9IppwVNApNwQnvk646vpiTPBIY0ONo6iz
         C9wNOpSMqp4w+pHRX1uClJzJNQ+2X2URudKlCKIrW7YiSjFehAzczykXlKS6rVQXkM59
         Bp0+cjPHBuEcoPgoKoRgZUFWjiNDMzha1fxpH42pz3ikLZEx76a3m4Cp9+9z2zCOabNx
         BhbWz7YEoJp07OkfiPvxQIG61bz3i0H84NmtPOiILm0hpVOcgVZRMIcTIjlLPL+paShc
         HJncT1dQ+AzsLwexjZILU5IL8xRfob0ligYaJMGTVqN8VZ/eX9J16h6XHdEterqY/fwo
         XMSA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=B2QUeXsF;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-81b5b2c10cfsi26495185a.4.2025.09.10.12.49.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Sep 2025 12:49:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 6CBE9601AB;
	Wed, 10 Sep 2025 19:49:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C09E9C4CEEB;
	Wed, 10 Sep 2025 19:49:22 +0000 (UTC)
Date: Wed, 10 Sep 2025 19:49:21 +0000
From: "'Eric Biggers' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	kasan-dev@googlegroups.com
Cc: Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-crypto@vger.kernel.org,
	stable@vger.kernel.org
Subject: Re: [PATCH] kmsan: Fix out-of-bounds access to shadow memory
Message-ID: <20250910194921.GA3153735@google.com>
References: <20250829164500.324329-1-ebiggers@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250829164500.324329-1-ebiggers@kernel.org>
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=B2QUeXsF;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Eric Biggers <ebiggers@kernel.org>
Reply-To: Eric Biggers <ebiggers@kernel.org>
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

On Fri, Aug 29, 2025 at 09:45:00AM -0700, Eric Biggers wrote:
> Running sha224_kunit on a KMSAN-enabled kernel results in a crash in
> kmsan_internal_set_shadow_origin():
> 
>     BUG: unable to handle page fault for address: ffffbc3840291000
>     #PF: supervisor read access in kernel mode
>     #PF: error_code(0x0000) - not-present page
>     PGD 1810067 P4D 1810067 PUD 192d067 PMD 3c17067 PTE 0
>     Oops: 0000 [#1] SMP NOPTI
>     CPU: 0 UID: 0 PID: 81 Comm: kunit_try_catch Tainted: G                 N  6.17.0-rc3 #10 PREEMPT(voluntary)
>     Tainted: [N]=TEST
>     Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.17.0-0-gb52ca86e094d-prebuilt.qemu.org 04/01/2014
>     RIP: 0010:kmsan_internal_set_shadow_origin+0x91/0x100
>     [...]
>     Call Trace:
>     <TASK>
>     __msan_memset+0xee/0x1a0
>     sha224_final+0x9e/0x350
>     test_hash_buffer_overruns+0x46f/0x5f0
>     ? kmsan_get_shadow_origin_ptr+0x46/0xa0
>     ? __pfx_test_hash_buffer_overruns+0x10/0x10
>     kunit_try_run_case+0x198/0xa00

Any thoughts on this patch from the KMSAN folks?  I'd love to add
CONFIG_KMSAN=y to my crypto subsystem testing, but unfortunately the
kernel crashes due to this bug :-(

- Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910194921.GA3153735%40google.com.
