Return-Path: <kasan-dev+bncBDV2D5O34IDRBZX5XKMAMGQEY7JRMAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 33BF55A738A
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 03:52:40 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id cm10-20020a05622a250a00b003437b745ccdsf10148295qtb.18
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 18:52:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661910759; cv=pass;
        d=google.com; s=arc-20160816;
        b=CnA9zgkfGfpuX2rkMmSbgs+LGkl07Obgs5NW1jmPSRIORqc8RU598XeP77fhEFGWVS
         iu3LOlEOhrAWeN0kw/V5wLfYA6jWDu400jRJjIKRO6WDCLHtzPWcJev1tUW1h8UM1bNf
         Cuu/bymH9a0QMrDZBfAPR++f2q4nJVmP7aBIFuGRi8sSg/7tPyK198YMYgotIyPjUn33
         r1RJomNi84ghwhcCBNdrdg0g79rzbQLgbPNyTbcN1M7EJSKm15MfUvW1S0K/+5in1M5Q
         cSz6DA6yjw3aoSVP7jSZbtwfBzYuIwP57puNNjJynlsQFRAr0Df9xtjV3PvbLqeH5tuM
         0ihw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=DK+4fKHDr+CpQlvmD0T++KiOs+YD1j1Wh5Yq7xEgFLc=;
        b=O7b7qFBRC5mhT/j94mJ8KDq7UIxbakjnYA4Ebum3jDqdCrPDguh2Pvj8FzFe368TXZ
         TPfQNTYDvjbymXWM5EsucMUn1e8uh+rWB9ilomMkzXKBVwbFOEODK3Fsd9QFOyZdvKm8
         tF98GsVqxu46M5UKCmdBcgE7vVYUKobI0eJ+f/xVpx3wHcbfEq+mAhfv2piXS3HpbBJY
         Qqb5Mrlci3m5kMZIN4ZCJytUZyElLCeXRrOJcCTa4oK5DfLec8Jbe2hJ226jXAgO6iz6
         RAIoHQaSrZ+GEWg5NLcfo4hPdfkE26M8kEWblyQ47x3OfzC7yVYL1wN+7MwAjutCfwni
         VIkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=fE7O2deJ;
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:3::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc;
        bh=DK+4fKHDr+CpQlvmD0T++KiOs+YD1j1Wh5Yq7xEgFLc=;
        b=dV0WNhZdVkccJunm6PAR5mVMcdF+awlxBBGT7fdCmRb1Ml1AMaPPJWbUZ5GY/x9c4H
         ErcEO6uYAAHDHOJIzGXSyHrCyEQGy8e6u0R2vNcSPgK55f3F8EeAkMbkMhAP+DMz/67X
         lvKwStPwi43DZu9d6O+rjcS649xpzcqQ0AmdqmbHG0l1jsaM9h37z2B9hZ7c8KWuxdG6
         QV0f3OsNYoy1oZQc2PHOdsJmE3eX3p7u4+KBphoTgr6r1BVp8/MItVC+EVtpDKBYsdVS
         8P/RHCZSQJFqY62zPqZpmpbhP7nUuLzCbs29Pqum67AjlKFdL4OImdZmNVqkaxW8uuHN
         aTTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc;
        bh=DK+4fKHDr+CpQlvmD0T++KiOs+YD1j1Wh5Yq7xEgFLc=;
        b=GiYOk/lYfxF+BGjr1pvtpg6MXcUhf+mCOS2iq1aUGyrcPhnq1++x0YtdnXeFlaHTi1
         INkLbQjL4ezq6fb2vuQxmqepngCQ8uwLN5M9jaqsap8y7XTOakEko6vqjEeu2zH3n7Kv
         hiDoGCK6W9oGIjgBg6oKPXtaA6y+Dc2X50mkaYkmQLxT+kZEorDRIaCZZOiphspLLO4Y
         pv/5/YYxBPwTxSCdgdLaAM+SMy34z7dtAZSEQi4wfpeR6uz66iy2B/NnVnU9byBavmKa
         wRFsRNmVFEWS70ABOa1tpYTkq3ziyMUcha0jj2ZIiHTYWLKYxZt+JSD45svLOPfH8yJz
         QZow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3O483HXWhSMAiGDfY6PxgkfzQC4RRv6yL3CdHGIyHwFBouuuDr
	U8XTqpRptCOm1jFAfiH5/PM=
X-Google-Smtp-Source: AA6agR7KcVYZTeFqrxlyML01coHvpT9pm7EXN1Fr1CTgqKesaPv2r+5oPkLKxkZNgW8fCRplBHzL6Q==
X-Received: by 2002:a37:cd0:0:b0:6ba:c1db:6aa9 with SMTP id 199-20020a370cd0000000b006bac1db6aa9mr14388301qkm.232.1661910759061;
        Tue, 30 Aug 2022 18:52:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e30d:0:b0:496:eeb7:301c with SMTP id s13-20020a0ce30d000000b00496eeb7301cls5846751qvl.10.-pod-prod-gmail;
 Tue, 30 Aug 2022 18:52:38 -0700 (PDT)
X-Received: by 2002:a05:6214:1c0f:b0:499:9b8:fc1b with SMTP id u15-20020a0562141c0f00b0049909b8fc1bmr8277823qvc.54.1661910758470;
        Tue, 30 Aug 2022 18:52:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661910758; cv=none;
        d=google.com; s=arc-20160816;
        b=Q1+rO34A0hHa7tARzS1dqrS/OUiS10xZC9lU1Rn6rwDUHJSfqxSCdTauJhpWoWctgP
         CZdYPucDSkSraebf+E7nAoTx83GIAQPYYGf/gTbRRZp7moKt4PWDZaXVZbe89viKvzRt
         uxoU41cCWXDRmqcbQRW0NfX3vB9Bu22Rxo5Rs0NVmgkfwTY6B3OcCz3ofuvTf7ptx9GO
         4DSNUkqw7pnFiofbijXPDFa/xBkD5KhCF+CkhtQqwWZnflONyP0fVN3Cw9/WWS+j5jA7
         Luldt0YBvq7i4LBPzfTmiHyR71PAJR1nMyvr5jIbMMSSORRxxFk6oSskydpXpiuIcnRp
         hLkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=/x61W8ECxcYp6VApa7rbgykWRp7/DFT2S0h+uIWuEt0=;
        b=oYzPX4crarvfJaJCyz+5++aZwoCaI44nDdJIyf2f3t7ALJM6+Rjbiz0uHtKLZhLWhh
         o8GFBPtpme3OkiaNJnKBvtmoehT+rYXbfOAxDmWLOtiJIXRPd+r5AzskeOMXaJUUdGT0
         ohT8w9rCHsy114Z0DxrKdZ1D7vzLcZF3t7IzCJh77KrG96akikkaVJVDUWTjpyAMtIJd
         OS2TkE28Uirg9oiS4P9rD5gB8HrQqGtCtfRD2rUu/uqkNo+DBYPkMpOs+Rz0xCt/nK3t
         mRJfDcG8iJSSrmf3f9KaINXFF/Lt16R8j0SxUt6xPj1IETRzE+5lF226TwNAUTfoMO5D
         01wA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=fE7O2deJ;
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:3::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id x8-20020ac84d48000000b00343082fe19asi506138qtv.3.2022.08.30.18.52.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Aug 2022 18:52:38 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2607:7c80:54:3::133 as permitted sender) client-ip=2607:7c80:54:3::133;
Received: from [2601:1c0:6280:3f0::a6b3]
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oTCtd-0036Mt-9k; Wed, 31 Aug 2022 01:52:01 +0000
Message-ID: <b252a4e0-57a1-0f27-f4b0-598e851b47ea@infradead.org>
Date: Tue, 30 Aug 2022 18:51:56 -0700
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.1.2
Subject: Re: [RFC PATCH 22/30] Code tagging based fault injection
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
 ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
 mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-mm@kvack.org, iommu@lists.linux.dev,
 kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
 linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
 linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
 linux-kernel@vger.kernel.org
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-23-surenb@google.com>
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <20220830214919.53220-23-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=fE7O2deJ;
       spf=pass (google.com: best guess record for domain of
 rdunlap@infradead.org designates 2607:7c80:54:3::133 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
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



On 8/30/22 14:49, Suren Baghdasaryan wrote:
> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> This adds a new fault injection capability, based on code tagging.
> 
> To use, simply insert somewhere in your code
> 
>   dynamic_fault("fault_class_name")
> 
> and check whether it returns true - if so, inject the error.
> For example
> 
>   if (dynamic_fault("init"))
>       return -EINVAL;
> 
> There's no need to define faults elsewhere, as with
> include/linux/fault-injection.h. Faults show up in debugfs, under
> /sys/kernel/debug/dynamic_faults, and can be selected based on
> file/module/function/line number/class, and enabled permanently, or in
> oneshot mode, or with a specified frequency.
> 
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

Missing Signed-off-by: from Suren.
See Documentation/process/submitting-patches.rst:

When to use Acked-by:, Cc:, and Co-developed-by:
------------------------------------------------

The Signed-off-by: tag indicates that the signer was involved in the
development of the patch, or that he/she was in the patch's delivery path.


-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b252a4e0-57a1-0f27-f4b0-598e851b47ea%40infradead.org.
