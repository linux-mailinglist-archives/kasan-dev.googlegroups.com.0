Return-Path: <kasan-dev+bncBCT4XGV33UIBBAWZTTDQMGQEBN2HGEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id BC84DBC74CE
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 05:31:16 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-9048fe74483sf107140539f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Oct 2025 20:31:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759980675; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ww4O7+MoytIZZQgUItte7+eryVOiLcHFvMeguOCQWobgESs9XTpCetGstPQgQvl71/
         TTheN99w4qQt7z/lYTUHdsIcVTETbUlH3a1Q547eoIHpnTXqkw2C1ixAZDmifp4lsxTJ
         RWCMztdz0G1g6I1myZBClTrAbPYwDZ+F7vk/Y9BEo9vzsgBVSphsI/uZSMXeC5XeQtDZ
         7Zra6A1S/xvJNqUdHMJctYFn/6Cm5Eyc3qjHB9yrbIO2yX8sPehsb19iNNZQbjypwtjP
         h5QoPcsLttakh4+61Cf2sLwsKzdftqMY3jPUEXJsvsNIHyZQvDTJ2+Nz6aMImh6BLvHn
         YpUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=JAihCqSEf4t4sWdiNAf9cjQ5shAdgzDtFmgNsEHyoEc=;
        fh=9ZnIH/Az1vCKiJGitl4W3YaB0Vg5wEwESf90UVQfpjA=;
        b=T2TGQo68k5xCiEz472NVgEw4p8nez6ZdVJ05pLsaKWbOOkj7plDcvuHk1tNJ7EFfrP
         JOW0R94W/4vxObXT1ASZLFnyZsAikfCJvboqOQRmgKYZk/psMik+sHdTfNKGecWj22SK
         wdapFLiNJZvqZZHJdhu1mV2KBU/j3CCgkRvFZ7i8VkxmCXgEd28xHqF2dO/WHk4tQfL7
         eM5hrywl8vSsxi9omXZ3qPfWdSQt8L/NjTWfA4hw9eL9KiLZND4tX93ZLq26u+DScY4Y
         LSRHDCKIzWl0jDUNoZUnZvOtaKSOgoeIJRFLeUKKR3DOQAXGUTPcZDiVQlT2zLHnhQ9R
         s1dw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=SYNWnuJD;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759980675; x=1760585475; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JAihCqSEf4t4sWdiNAf9cjQ5shAdgzDtFmgNsEHyoEc=;
        b=X+4Jj+7J3TCm07ktXd34zBAOfCqWQp9YsU76q8fxk4aU+IXl+3hGAxbBFgts90xIvW
         BbgcCtYaUdXtdQjRzXqvLUwZKNAIwkwxE2Jf/HH07qzl+15KkUsEMP1nKZRjSBZaP4Dr
         u6sE4/C3dt4R+V1XwIHTSd0V1H1Ixti3OezPM37dUfRc9+1XnEnMqwsGzhsG2bnPHZn5
         WCI+oQT8gAHwazEgd+CTAoULK0u7D1oy44lSZOLEkenpe8iqsoSoJUIU27HlTxb0CLd9
         yW8X/smAP6T9nTmohn4GDMmL3UMkic2LDIFT83oxMP6lDJRvRqAbeEfbmgq8Ygco1VBN
         GQpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759980675; x=1760585475;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JAihCqSEf4t4sWdiNAf9cjQ5shAdgzDtFmgNsEHyoEc=;
        b=vj/qaq+BPWUKjd1qgGEZ74dlM+LjNMpTuh+oOcYSKo5EdvxsKW8BRN+W9PXs+u8yJs
         IvBIE+c77XuXNck+jK7SFA6DWVavXd+axAhbbLZJcJNUM3WUA5RCqnTnMVRLpHJAHOko
         HHCm/HnlO9F/A2vNZDLhuLE1rdh6QsPUAqtzuKSVsu5DfrEdypGmbfQQ4QK6bqmLnID3
         i3mWkqqiDNqnVlilgoXnct8rlOBoLDjbCxhJOUNGsU0Y/GreJvdBz/3Kmk3JW6NOxsDz
         3Qco9CCMapVOHMnLAOKsdXALd28HDS3gKawJjsBvPgZcLMLEqyJCDBsbrZvknIVgHEqG
         uz+w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUXbRIGDQdfmWVL6ODRStrEKjatvVX92470N0SIdH3GalYvPUDAMd/qSsU44ypBhLnE0vamFg==@lfdr.de
X-Gm-Message-State: AOJu0Yxt36kLUAA8OBXBJCpUPU4p0NQbppeGnQd+e555CkdtAajFGqLy
	fXu0e2b27W6pWnvTKDsKJdjDlEcuARv5XpX6J8gLBLb8dqR73GWsBBRm
X-Google-Smtp-Source: AGHT+IHvSO9IB5r4/HkXFlw0UA4rD/yrZHG1nqP2vZwHrjdeIzANYW+ieX5XQZG2VXvopWXYmRy04w==
X-Received: by 2002:a05:6e02:1529:b0:42d:8bc6:d163 with SMTP id e9e14a558f8ab-42f8736a9eamr53469885ab.9.1759980674691;
        Wed, 08 Oct 2025 20:31:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd51gZEYwGDoLs37k0vr0aPze4JPATl9D71zT1iQrCor1Q=="
Received: by 2002:a92:d690:0:b0:426:769b:69dd with SMTP id e9e14a558f8ab-42f90ac79b7ls3101915ab.2.-pod-prod-07-us;
 Wed, 08 Oct 2025 20:31:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWosqVts1FyFslyKjwXGVau1VN8rioAwevxJqlKMQCOtP6zsI6kqfYxEd+hp6ayg2i+1a2Q+5+wdfY=@googlegroups.com
X-Received: by 2002:a05:6602:14d5:b0:93b:c6aa:5e14 with SMTP id ca18e2360f4ac-93bd18f6adamr658684939f.7.1759980673518;
        Wed, 08 Oct 2025 20:31:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759980673; cv=none;
        d=google.com; s=arc-20240605;
        b=DyZzJbOwrjwSbd4vllFgodnqUo4XvJM1vpamAQjdSBmO1D8GU3iBvA+hOGDP7PYGTR
         EPIWhjPlTmqBe0LhVVr9SHffEKF5BGpwI1Lluj8y25Bn928kNpNh5VDlbACIimw/A4F3
         xao/uxSvherWbLjhx2jdMmQcR6j4YjyVZiq98etotW6NJnokcxIbmBNW3ARW2slWwm3w
         afOOPx5tyZN3sRsKZR9Yi3NK8oByAbqEmq5yeBgP79PfKl9CzYmBM8MZN88lJ7JjyMzd
         DnUH0Y2FVYsQo82V9vkpD5AMoE+2W9Xm8I6rlszqya2+1Nxw4NJRWeo7iorMZredXnGG
         zuyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=GPyJ+XxDSeeUab2Vl3VncVhD7wMmFqzNrLSUKqmU6m0=;
        fh=NqOeMzn7/0z6CQPmk8Yj04zsECIQaf38ZywifjCV8Y4=;
        b=N0duyOClQEClQmdTyAa/BUerH1BVKwT+IUndlg1mtXndhmx725/JBLTe5iFkHcjHO3
         X2INQAhW1IKtAB+tXO1luXCnDWbRIQtxjiP1Y6t2+jftuOJrylDzoHm/gjSk/Blj7aHL
         y4ssGmfupgHfGccbgBhTnce2UYDtf6lolLIsLDdG/FozjvOnLIIfJLDGv+DIYNfVrSv+
         8HfmW4JRLBXrtoFG8cAJH2/4Yh75jOFpGH7ZHa4hrcahS8Y32izulNrans9+52AJWQqU
         fpnaFaxk8rZO4jIcZquX7lOav2VHK4SRpUo5+mpWDXilDLZPMsysIKeItJUh3vEPLuS0
         shoA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=SYNWnuJD;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-57b5eba1af5si43202173.6.2025.10.08.20.31.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Oct 2025 20:31:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id BCA76611E9;
	Thu,  9 Oct 2025 03:31:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2D026C4CEE7;
	Thu,  9 Oct 2025 03:31:12 +0000 (UTC)
Date: Wed, 8 Oct 2025 20:31:11 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, Ilya Leoshkevich
 <iii@linux.ibm.com>
Subject: Re: [PATCH] mm/kmsan: Fix kmsan kmalloc hook when no stack depots
 are allocated yet
Message-Id: <20251008203111.e6ce309e9f937652856d9aa5@linux-foundation.org>
In-Reply-To: <20250930115600.709776-2-aleksei.nikiforov@linux.ibm.com>
References: <20250930115600.709776-2-aleksei.nikiforov@linux.ibm.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=SYNWnuJD;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 30 Sep 2025 13:56:01 +0200 Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com> wrote:

> If no stack depot is allocated yet,
> due to masking out __GFP_RECLAIM flags
> kmsan called from kmalloc cannot allocate stack depot.
> kmsan fails to record origin and report issues.
> 
> Reusing flags from kmalloc without modifying them should be safe for kmsan.
> For example, such chain of calls is possible:
> test_uninit_kmalloc -> kmalloc -> __kmalloc_cache_noprof ->
> slab_alloc_node -> slab_post_alloc_hook ->
> kmsan_slab_alloc -> kmsan_internal_poison_memory.
> 
> Only when it is called in a context without flags present
> should __GFP_RECLAIM flags be masked.
> 
> With this change all kmsan tests start working reliably.

I'm not seeing reports of "hey, kmsan is broken", so I assume this
failure only occurs under special circumstances?

Please explain how you're triggering this failure and whether you think
we should backport the fix into -stable kernels and if so, are you able
to identify a suitable Fixes: target?

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251008203111.e6ce309e9f937652856d9aa5%40linux-foundation.org.
