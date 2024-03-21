Return-Path: <kasan-dev+bncBCT4XGV33UIBBG5X6KXQMGQEPOJYMOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 785038861C5
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 21:42:05 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-29df3d9c644sf1040913a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 13:42:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711053724; cv=pass;
        d=google.com; s=arc-20160816;
        b=jc1zQrnTCmaMLGEXC9BggwyG1yztyWKDKCoKkoVUNFDoq9XsrxgluJ57wwdjSDMedV
         lW190JpZAaaQSkxlSlLdhz+y4ra4L6RpgWOVDynKHcxP6Gec5DVCad3CWQMaxuwv7aG6
         ytJgCHY5dIbWbnLSdvaQgNBjOpXxHKXlLJlmqzaWLeYiwQR547RZAqlyLIZOP8redyuk
         cHQI5d7Mw2e7D90MwyYfQjK58iE1JvFB2nCTAZWgfMo3tb1nWAGB38Iq5AZxn11d7L2a
         JmROImpOv8PrawTnjVgZk34z+kn0bMT6q8QMI13yEvqqfQXjHDk0TnXB6uk/61gAVp9A
         jxyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=YoEIBie0KnwFRN3YMoxgng5ge5nGaPWaPd3g0rPy8BQ=;
        fh=o/NAuhBmomtfT29p9zoPsDqlmPEOSQKIPoMldgczOCg=;
        b=KdNAvloRoAlFsg5qsPargkZvM3xUgaTjT6gybsJv+rdWkVb008PHW/S8iCXJ2t/y80
         6GNWLW6mX9GGbWfwzZAICEUs84adynuKeUidhsn5mJLQyWDCAoIQIzWBcPzQ/H73gBnK
         k36MkVGHDoa4RtSTgYdzYy28r7dNAdAnzGBpNul34mgxaQcfeTqQQCqzdHOLjca9JSFq
         y20DhEJzmS4OXWLMpYzZ4hZ+mD3JdsMoEaMLQg/+0ioPQrAu2ZjzaDlk94moC6Wgx640
         ASqyL7Om/cXZgrOTSlsS0mbLkcPiIIQafe93prTEFLDHuybKioMrwIa7X16wXncnEyzI
         OqgA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=sk1DY3Jk;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711053724; x=1711658524; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YoEIBie0KnwFRN3YMoxgng5ge5nGaPWaPd3g0rPy8BQ=;
        b=QzkGz0vVBbFChbO9MO0qwdx9Sj3fBZhPlEXBWRu7HcXqov+T51BdR19XOB16Douqce
         VAr/S6NfT729WCV6AedZX3zfz8IxwbCB9v4AZy1FeUFI57r6UMJoZRUivsswuLsn//Nr
         0ISwpa6ukrrGZbON/BIxnM3Kl0uDzRgX9D/GW8Tqf+BhYXkr1Yw1oREsUxns6JOFJjk/
         lyz2SWPXBUOioG7AyXWB2YOUFngKftQGg+PpyzQ+n2/GVD0FtHtTfcGRsIFrDPPgDrzy
         gE/F2i+HxoPc60c8X1eNYxkzWfJqajqGniawh04Bbkd5+GFgZGOv3guAZNfNDFHXwXDj
         gCqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711053724; x=1711658524;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YoEIBie0KnwFRN3YMoxgng5ge5nGaPWaPd3g0rPy8BQ=;
        b=Ddc6XhQ7QrhDBx/cA3Rg/5kSo82ENXRWCgGqiYclK7k9Dl10IZk5NbbCnpsNoQFtMq
         Vvz9okZhTZ3+zl160A2sr2Vv5zWKfxnVZ9ATP8HGchTVCsQXo6jgW2H+gCCY+7FJpM00
         ZQpsntd4uec2KwuxfH8obWIcvNi0vZIn2FX24QmYsAomOuxPf2DKwq+13LRPLTBxRJaB
         wNrhanSTRE2/3DRm1Z3N0EE3EyHbwYLw5jnEUQByOKLsoKTE2ytuoNmbofoHCv2x+tya
         Ng5qyjwHhhbvq4eYDKwMepwqzB9jnNdmzdPKtLvqGlstkCZOlnCScQAECYurwRMjwOFa
         12gQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWLEV3P7TsKedytDjn2UcpJyUX08tsU2+LaSu6YdxoT+yAFMMbXk4dPZjV2ub+xbGHdgiWoA1vC+ooBUNyvJEGUzsLjv/4dRA==
X-Gm-Message-State: AOJu0Yz+pIHadELgnmSqFVmF+1GCghodFQSaQhggSGymbRpEbi27DU7A
	WppxArlMH5x6byAcMk3oPF/lu3JhfvaUgE0VLTARf/PvkMOz9Xfe
X-Google-Smtp-Source: AGHT+IGScPJMxCXUrrBWLlz/ec1So7w9neLT/l2zxjCd/YS1xTwr9Mo6Oo4COpp7U9A9E5+wzgVq9g==
X-Received: by 2002:a17:90b:209:b0:29f:b11f:8a85 with SMTP id fy9-20020a17090b020900b0029fb11f8a85mr477918pjb.35.1711053724002;
        Thu, 21 Mar 2024 13:42:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a90:b0:29c:5a19:1c32 with SMTP id
 x16-20020a17090a8a9000b0029c5a191c32ls913518pjn.1.-pod-prod-06-us; Thu, 21
 Mar 2024 13:42:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXytY1COScOTo6++yEUyL8bUaWkFVegb5UENxQmyuXGP4axn18N+3jVW/FL/7Z2YkxYdi90mdiMB1xZQ3Qb8NrUPjtcHJ4pnmuqkA==
X-Received: by 2002:a17:90b:8d4:b0:29c:45f1:8984 with SMTP id ds20-20020a17090b08d400b0029c45f18984mr538438pjb.18.1711053721786;
        Thu, 21 Mar 2024 13:42:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711053721; cv=none;
        d=google.com; s=arc-20160816;
        b=MCKnoEWpFvbdngq4osT1q6My6xkhR6jQmq4id7ZJz2pyRiJfAS6XfNoUhRjeor46Hm
         Is/FO1soJopTrSD2KK8TIWBFOD6z7uZMPjBIFsT638CX5KPeFZiau8GV1qUbpoqRjsjE
         M6yuM3u+LnBvVzHbd6O++HjkRDo1TGxDNYMTPaZuW4tKVxkRcLk2LoXxocMvzuQZegzl
         BGeyVk0wQxww5lGs9Ke1DKVNxzYaBOn8+tVi1x9AxzpQxuyklxCeiuuOBGuJUh7fKcX1
         nnrUB5mXs7stnjx5TzMTFmHBk9nqlaihL763TjFuc6G6unlm3Sxm0QeKbLea2VBitEJM
         EH6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=QP+JQo1CgM5u8YYrCl4YjBve+Yz5RLgzVzonW1Zokc4=;
        fh=2ZV7FJ9C9uO2H+RZFZd8VjeiJooxPEKZ2+K0KdRSGMA=;
        b=W4M+7+/VT0lLYrcdUSN75EeADDzVX9cxT9sg8prrHh2ts8ec6pTTWPdbMBM7pDKnTV
         Ee4x5DwgEaCoYgQMpRP7dGxL5Kro+ynP0kTGmyWocfHFat/Ciehym0tYb3J1E7S2s6YK
         znxDQPJwiOZl1hKyI5s/ZpqAN+y8L2W9N/ZTcC0uh5aP5sOOxXNOg8ExOJdHC8Zg2kW6
         l1jyXl7pG0N7HoReAAlgsrznRYbrBS3RVKrzbNpHlEukrWQBFfbPot5HyZnR44cHTvIu
         OpcTQjd7zUb6iPVffNEP7l+xbxp5xm/8yA7LZYLxepaAJhxfJMEPcpm5stfxcH8yxdfX
         5+vA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=sk1DY3Jk;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id a4-20020a17090ad80400b0029bbd2c38d1si573086pjv.0.2024.03.21.13.42.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Mar 2024 13:42:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id CBFDF6125A;
	Thu, 21 Mar 2024 20:42:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6D384C433C7;
	Thu, 21 Mar 2024 20:41:58 +0000 (UTC)
Date: Thu, 21 Mar 2024 13:41:57 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
 keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v6 00/37] Memory allocation profiling
Message-Id: <20240321134157.212f0fbe1c03479c01e8a69e@linux-foundation.org>
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=sk1DY3Jk;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 21 Mar 2024 09:36:22 -0700 Suren Baghdasaryan <surenb@google.com> wrote:

> Low overhead [1] per-callsite memory allocation profiling. Not just for
> debug kernels, overhead low enough to be deployed in production.
> 
> Example output:
>   root@moria-kvm:~# sort -rn /proc/allocinfo
>    127664128    31168 mm/page_ext.c:270 func:alloc_page_ext
>     56373248     4737 mm/slub.c:2259 func:alloc_slab_page
>     14880768     3633 mm/readahead.c:247 func:page_cache_ra_unbounded
>     14417920     3520 mm/mm_init.c:2530 func:alloc_large_system_hash
>     13377536      234 block/blk-mq.c:3421 func:blk_mq_alloc_rqs
>     11718656     2861 mm/filemap.c:1919 func:__filemap_get_folio
>      9192960     2800 kernel/fork.c:307 func:alloc_thread_stack_node
>      4206592        4 net/netfilter/nf_conntrack_core.c:2567 func:nf_ct_alloc_hashtable
>      4136960     1010 drivers/staging/ctagmod/ctagmod.c:20 [ctagmod] func:ctagmod_start
>      3940352      962 mm/memory.c:4214 func:alloc_anon_folio
>      2894464    22613 fs/kernfs/dir.c:615 func:__kernfs_new_node

Did you consider adding a knob to permit all the data to be wiped out? 
So people can zap everything, run the chosen workload then go see what
happened?

Of course, this can be done in userspace by taking a snapshot before
and after, then crunching on the two....

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321134157.212f0fbe1c03479c01e8a69e%40linux-foundation.org.
