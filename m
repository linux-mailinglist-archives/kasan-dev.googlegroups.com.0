Return-Path: <kasan-dev+bncBCLI747UVAFRBRMIRLDAMGQEUAUBZ5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E575B52B46
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 10:11:51 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-72e83eb8cafsf7914086d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 01:11:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757578310; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mjf4rsfGxiIc4MTFtavK4uKcXbaYSkWHYj0CoFkxKwn3WedpKGvNkzzpfYv3noTouo
         LWb8QrwDItHTgyGYgn37FFeiOpanLgNEcwffzsg3/toS5f7SvuKOTbkDQ2xK0JHSRV2B
         9yku9gltpMt0YX93Vc63zgkxtJLlDP9aIkUVx0vX4bwR5XGEB5T9fl2zm9Wlle+tNxjV
         fCHViXlHUkfhCkO8AhjNQ2TU7shzf3l6ekWVrx07OCPRcdU4doYY8qiPDFu2RIhyx8nA
         SMhkHSl/k0IL0HJzuFLWa3ZPFSRdpGniMcF5or7bS54TAv9q4ULmx/1Z6uYAD7N2AkOh
         ChXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zVGvWgjWyyVonAcLGC60JGZR8Ua7LLzw5WslFZpQDjc=;
        fh=sBSxq12DLM98m8kZ/f39lfvbvYflAD91BSEsN87uZRM=;
        b=OU4PQI7yOpOoJ1boP6P31eYPQkdUwNE6eQi6qEu0AGHy7DHGQ7dW/PyeN5cHKCmYuz
         2dVG53PARLNdGjE7F2W7DK9r5EOKsNMiKHmdPZ7Zv6r/OtqUPx0+QgDv2Z8a1nXRik+a
         GY84F5MNc/uhWq7+dNPMYSxHrZnbCHAnxGgeJYf7nny7zWUY8tduGmCVgjMuMbVeYqR1
         FebS/YdhSAdtRlPxCCwxjvMbeV4chae1Ku5HZBcanNSFFS/dAwDTSktsM+5u1zDXNJTv
         8XQVYaKMlF6d/CZswIx0ctDbkMIU46/5RQEkMCtUTEWopoQorYklogQ+GjQPKcxxy55I
         vBuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=XK8UCkAO;
       spf=pass (google.com: domain of srs0=isgx=3t=zx2c4.com=jason@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom="SRS0=isGX=3T=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757578310; x=1758183110; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zVGvWgjWyyVonAcLGC60JGZR8Ua7LLzw5WslFZpQDjc=;
        b=bYCL+4JiWgfQX9mr8TnJcWhy1+NSKoxGcLBHp4uyt+E2oU8R+Cy/kEE9Xsiazg8bk0
         +eDHumYnw5Sznll4roNmZvhVJMb2hK7vmWM5EsO8brfYIA2RBhzhvUI2L+mhURaBxEOC
         /ZZGQUMarypxitxsxIlaFeh9sGouMg4fc++58D5hhQgozInMCkHl5wfRC9htOdBV04KR
         3VQsPWtcVEfUMwlhjbu/aasYRN52+tRdJQuJjVH7w8y6nfVhimgp8y/x6YRiOdCxD3Xp
         VzKGpB17EZZr7jZaHM+n/iuSte6zhkFsvwlQ7M/9Vwc5scbBsqVg6PUgwvUvP9aPFHFX
         oPjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757578310; x=1758183110;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zVGvWgjWyyVonAcLGC60JGZR8Ua7LLzw5WslFZpQDjc=;
        b=rvpxYJ4xId5FFpfLb9oWXtCMPcso6zUNRj/1zTX18TG4CIOVWVKRF+ajdteqsPcN+F
         /3glhn/YWtCwVx7SIZ4DEo8tYL4C6dBtikdGQJK7NFHRxonRSm+MWvPqKQnqNKNfFQa0
         gQR64qnMEX0I6OwAUyDflXWua33a0VX7RKwfcxhlE8WLdaQRoacD1djeo1q0M9RI5OKn
         qUWdF1yd0SLw6w+VnofGFQaLdqM2dbiAPoLI+prE7uNG6vH0koQmCWc7kKwCNjHW+Tfq
         NxRe3B0CQ+/KTpOUjXaQK/h3Vx31D7hmNMgwTxMDlAQ5U7sk8VnfvyE7CpVdz2200fhb
         pqOQ==
X-Forwarded-Encrypted: i=2; AJvYcCXwFKxcKi8U+SI5NNbly4+Z9vfWPKt2XDoFqD4jcjHmqC5NfsDEKQvytmNN7UXJB2jp/rRNhw==@lfdr.de
X-Gm-Message-State: AOJu0Yw0ahRoERcsJA2d4tYPMNjhNLWBki0nGbGqiuz/FZGPNnPPPIlC
	VmArODg/YXp4icB9nQ4buHB36GBxFTx8eFI1PP7tKAh/22m13u7z4VTD
X-Google-Smtp-Source: AGHT+IGXCur7NsKr1jIPvg5Alq4Znk7a/ctj5FN1ROctfGzHEaKrDvnRjC6dJffurQob+pv3iMHlww==
X-Received: by 2002:a05:6214:2a89:b0:71a:e4c5:72c7 with SMTP id 6a1803df08f44-7391ea6cd88mr230241686d6.7.1757578309755;
        Thu, 11 Sep 2025 01:11:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6o4sl0ruOorCAwdI/BGUDYtdW+oP1Um5wBn/PhV6mbGw==
Received: by 2002:a05:6214:f6a:b0:70d:9340:2d97 with SMTP id
 6a1803df08f44-762e4c92309ls7795776d6.1.-pod-prod-03-us; Thu, 11 Sep 2025
 01:11:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXjZc8S0O4sXgyFcSrf3qe6+wmM1awqIGBRLm07gqMCCS9pfWbL+BOCWbc1Q2OQ49b0wp9z8TNIShQ=@googlegroups.com
X-Received: by 2002:a05:620a:3728:b0:7e2:9c28:c310 with SMTP id af79cd13be357-813bec099c3mr2123264085a.21.1757578309207;
        Thu, 11 Sep 2025 01:11:49 -0700 (PDT)
Received: by 2002:a05:6808:13d3:b0:438:241d:e72f with SMTP id 5614622812f47-439b15cc7eamsb6e;
        Mon, 8 Sep 2025 09:48:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/vucsWnzDayUi+19rCByRWeig3dFVs7A3fD5KpYIvyi/xhTAOhGAGPy/Iq+XRL5Cy75BU/Ak2rKU=@googlegroups.com
X-Received: by 2002:a05:6808:448a:b0:438:22cd:2996 with SMTP id 5614622812f47-43b29a70bf9mr4133348b6e.5.1757350101312;
        Mon, 08 Sep 2025 09:48:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757350101; cv=none;
        d=google.com; s=arc-20240605;
        b=OwyX8uEVMlGc4fAKQZCJri/vYc4liRG3q01IWStEpBx904SHLHVU7vbL3EcdSsurux
         hYlarkJk/qermHE84JX6QqPSYKPmrPHngPe19JbkL+/Cj/olH4N5zNzcaKWt1Xjh+8n6
         t0Td/IajWdGXdPR95NWeZMqG2I+HYKZpkwL53oHqS33WgrQmRn4N3Mb3RxARg93RttSS
         CCgfyl8tRjvXfa1hyA/fD0MEPnMwdZ1eW0azGa+x7eDVxpfeanP+iieZFzqyf/2/XYLW
         7/WDPyIcmIXGkxrmaXDPQ0qPGltou/nF1jnaL7ttJjuwAyuRBeoWQw+X9YDvSHO5jo/W
         uddQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uSnlDYAkih0wYrWYP/wGKkJTrA/JIOiBaO0koXzi78I=;
        fh=LcO1+pIeyWYdJU3EA8OYxnL0FeBDZL2bgowHwUp9VuI=;
        b=a9uOnGakmolpC4k0xTh3mJNxLTe7zOcgJATA96OIw7DdxrdBtPezlZ2ulXHkPB1FYW
         NVH6IbO+zbEZagtO5Fx/NVvCqoGbS0PdBVz8fCAJRt8x7+nHAFB6YofGFrrennRRONNp
         BcOBMYX8xmIh14sSgeFn3FKWPHGjQuLfChF70TWNra9F86q+OIN9bVvbs71sHF6PhBv8
         szngW4yCUYTPcBWIIh8UQCKdiY2Z4W6UiVgypN63tWSrViif4wSBnVUPXCKb/8dUVbNN
         sjl+vWtvHq9L63kgMkjiHNs2vANAYj8AlaSWcZpd5JjtFATtNYLaWS6+XxA95VrrExOc
         tNIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=XK8UCkAO;
       spf=pass (google.com: domain of srs0=isgx=3t=zx2c4.com=jason@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom="SRS0=isGX=3T=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-327d52e98d7si150015fac.5.2025.09.08.09.48.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 09:48:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=isgx=3t=zx2c4.com=jason@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 94F0C44447
	for <kasan-dev@googlegroups.com>; Mon,  8 Sep 2025 16:48:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3D18DC4CEF5
	for <kasan-dev@googlegroups.com>; Mon,  8 Sep 2025 16:48:20 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id ae832061 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Mon, 8 Sep 2025 16:48:18 +0000 (UTC)
Received: by mail-ot1-f43.google.com with SMTP id 46e09a7af769-74381e2079fso4511257a34.0
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 09:48:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXkq44npJXKPd0Bwi8EPJWQi7BtYlPqxKxU1gCht4+UilzwdJaXdaIiWLQvKzHvAXhE4fH0QU1Gens=@googlegroups.com
X-Received: by 2002:a05:6808:3447:b0:43b:2976:6080 with SMTP id
 5614622812f47-43b29b4b108mr4340525b6e.23.1757350096055; Mon, 08 Sep 2025
 09:48:16 -0700 (PDT)
MIME-Version: 1.0
References: <20250901150359.867252-1-david@redhat.com> <20250901150359.867252-6-david@redhat.com>
In-Reply-To: <20250901150359.867252-6-david@redhat.com>
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Sep 2025 18:48:04 +0200
X-Gmail-Original-Message-ID: <CAHmME9okig=9NVGS_vSt525C-kR0mAyCnzSn9iypvu8uj0zA_Q@mail.gmail.com>
X-Gm-Features: AS18NWDEbovQfzN2Y035qma21yXmLeYwXyIh1FHAB52eeHDgW6bSgyj_MCTfArc
Message-ID: <CAHmME9okig=9NVGS_vSt525C-kR0mAyCnzSn9iypvu8uj0zA_Q@mail.gmail.com>
Subject: Re: [PATCH v2 05/37] wireguard: selftests: remove CONFIG_SPARSEMEM_VMEMMAP=y
 from qemu kernel config
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, 
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Shuah Khan <shuah@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org, 
	intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev, 
	io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>, 
	Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com, 
	kvm@vger.kernel.org, Linus Torvalds <torvalds@linux-foundation.org>, 
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org, 
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org, 
	linux-mmc@vger.kernel.org, linux-mm@kvack.org, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>, 
	Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>, 
	Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org, 
	Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>, 
	Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>, 
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, 
	x86@kernel.org, Zi Yan <ziy@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=XK8UCkAO;       spf=pass
 (google.com: domain of srs0=isgx=3t=zx2c4.com=jason@kernel.org designates
 172.234.252.31 as permitted sender) smtp.mailfrom="SRS0=isGX=3T=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Applied this one, actually. Thank you.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAHmME9okig%3D9NVGS_vSt525C-kR0mAyCnzSn9iypvu8uj0zA_Q%40mail.gmail.com.
