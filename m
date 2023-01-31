Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMPZ4OPAMGQECKN4IRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 75128682B90
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 12:34:11 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id w12-20020a170903310c00b0019663abbe88sf4951161plc.20
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 03:34:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675164849; cv=pass;
        d=google.com; s=arc-20160816;
        b=M9W1Qlh3dbTsUOVBPChCPgq721PDB2nN8iMNbl6eQfywAPLLnVXzlIEga3ZZ6bz4JV
         AvYie9J91VjrPTGo/JORmcxJm2o0JvAwClWft/H36nnXl9CNc3XtI2Tvy3ILTtS5AEzU
         MRuSAJkSC6NIAY140+h1Kx3wizLeSfKqijREdlgn+kA1qKGxzWRxRGlEdSXxH5azZRPr
         i3eSB6yrITolq1WVg+x1bri9nrJMGelnAcD5uJt7nkZwBm4BZWQ484saXrB3dXKKkj5N
         SyfD+uexW/5qtb7JMzo2uahX+IkuWrGv9HWP0K0JYCiMP2lnIDQ/O5CAdzyFGHi98eCE
         vw0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ufc0cgfeI8Emp4p3AXEmhXhAxJzUqdPXM/moHeQCLJY=;
        b=i33RdffjTsb4Znyv/IGd4/9438KgxY5GW5vX7753QUK9gwpBoooYmbUNvPcYhAexNF
         LkWuqW9/MnVAdDj39ebOAu0LGidg9RV106+QIVPfLlGYQ4f9XL2Oj8GwHzQEzk0a9qm3
         5joJZDcrIwQPDZyMOo4jgEh3zidudbHEWvqaTkLfWhJVYa+bGz8bncTGaUJYVZ9QgXea
         5P7Cq/Jy7FRJ7i4dAr+sncf2G3sWzwFVE2ulCZUyE1N+3CX9+m0g92Kh4G6GZyZ5NDBg
         Dl4wKEovI4vgyxJLP1Qy3pBj2/Gy4sNuHFJi/o6Pa4QQKZiFH7nvtDMATBnzl9Gos6yq
         wuSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Hu3jY71l;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ufc0cgfeI8Emp4p3AXEmhXhAxJzUqdPXM/moHeQCLJY=;
        b=J6elENgs3j7zt/ewZjw2fwxo+pHyFfX6z8YqPtl6Cj6MMUG5ZV2OlrrwUqOEE5aqZ5
         /6znrNv6thKgtbIOYrTIWo5PiQsKXs2Ko8OINNCeb5L6KpNsO3YlxvGHin9WVJp8hT2Y
         LkXGFMc4vA15V0zomeeFNfdiAR/et98u7KdCfN4p6jhUbDOQ3YKrA2nBWQbpxhxz6Wo2
         kZTMBXCR9jmbu87CE1K6aLjCbBKlDBF7vwneV7c8siumqROlUOWgqMJMCMVMziwmJpBQ
         MGpuXmK+Aruw1CtzjP40sfdWuv9BY/bcXc0Gy4G3mlk5nATrU5y4i2OySoKrtvEGxORm
         0wnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Ufc0cgfeI8Emp4p3AXEmhXhAxJzUqdPXM/moHeQCLJY=;
        b=d7a/QeVGwu2IglCePAUvBQ23HbNtivi/g5qzYsJ1OABXJVBc72gEA9VjQRzDjazm/3
         fIua/mWP+9Kroaww7WYDCSfQpyVEmWsx4GQVdrwYdotLmscrz54HBViuZ6GosFvyIQkm
         ePtoEzzLPWCkr5QZmNv+FRct0CHOh5OOFA5rrjEuTXfznQyx3rodP+XW7fnJsaH0VgY9
         mB8fHxl4Qmt+Wz7eOjaZPW6NW+BThO9BvsS2BiZ9KdF5TmjQI5yEqFWudlF3zOFrY2Ge
         DQb4GCI8/AgDZ5eqiX5k6ROEYgah5KonZckTY3GTUzqVnhmJuS6dRTGh2TRl1p2uAvwC
         bMjA==
X-Gm-Message-State: AO0yUKWeR4hV8GqhAdsw83xJdOmRsA8d6pfHEXRghfrBw5C1MczyyyCv
	6FSW24nbaA9bG5+kYDntMdY=
X-Google-Smtp-Source: AK7set/ngUSbpKvUBaKFreWEp75sOFiayChBklAciTQQa3Ouhzo8squA2xMO5DdcY5aP7KQvmPOgXg==
X-Received: by 2002:a05:6a00:2136:b0:592:5eb4:8ebc with SMTP id n22-20020a056a00213600b005925eb48ebcmr2776278pfj.41.1675164849563;
        Tue, 31 Jan 2023 03:34:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9732:0:b0:582:392e:8bbb with SMTP id k18-20020aa79732000000b00582392e8bbbls4205070pfg.9.-pod-prod-gmail;
 Tue, 31 Jan 2023 03:34:08 -0800 (PST)
X-Received: by 2002:a05:6a00:1d96:b0:593:893f:81d7 with SMTP id z22-20020a056a001d9600b00593893f81d7mr10961323pfw.16.1675164848812;
        Tue, 31 Jan 2023 03:34:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675164848; cv=none;
        d=google.com; s=arc-20160816;
        b=qNL5nnzYicPb31x23u/R+SmSFWOvdvIcvYp2z12iUgvasM3nqpqfJi1PXQwM6PSN4l
         0Gc9YevIRXQxegdQ6ceJcauVdf46TUeUd4/j82sK3+N2P+VNMVZcq1UKN3iGaX9uWGb5
         IoVwWjlVQqSf9ILYLTXW1TaWSvYQy8hGP7iMpbT5r6W/A47RbKX5n3uUKw/K/T4gqZCZ
         SOuOsFxs0CbKCqMRVUk9YpDX+dzKAm8kOibv8bCPGWm2AdPHoPrEd2nvsy0rRvpnbxHJ
         ObUgKHSpElP8yLjJa2IaRsRvyH3G77qTAADPu/Vk10OTgHmuM5bZ34RMoe6v57VxFKio
         vx7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=i8eUarQKx4zlWnr8p6102+JRBW/gc9YxRunt0DbrPaA=;
        b=SviER3JDoQ4kQNlHH8TIfGGNqOPnWMKe+tc6h6OlXSrNnYr5vCzfzsPM9Zt4y6cE8D
         Kvz5/32D3qgiVN0h+nUuTvspM+qy1+RE4DX9FGnTSmrygxOtuXRvxY/SSzFnOK6N6xQg
         2MTFFvRc0QBmQf5i0r5GkPF68br5UJ6QFWAkEc8QAeBNyR60r+OTxxzfp1wcjki0A06I
         nXorzM8Zb1SVnITw4eba9vDalZGKqPonQzIhEiP3XFePCFsnocztLLj34GHhMyUiD453
         hDNV+4oSQFhaNZ8ZXZGpPr+V2qMBJ+m9AVDSvJJEDS6fUZmoWR0IRbovDw3NWcw1/UDB
         uDIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Hu3jY71l;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe2a.google.com (mail-vs1-xe2a.google.com. [2607:f8b0:4864:20::e2a])
        by gmr-mx.google.com with ESMTPS id cq23-20020a056a00331700b00580950e1033si1156447pfb.5.2023.01.31.03.34.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 03:34:08 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2a as permitted sender) client-ip=2607:f8b0:4864:20::e2a;
Received: by mail-vs1-xe2a.google.com with SMTP id j7so15680194vsl.11
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 03:34:08 -0800 (PST)
X-Received: by 2002:a67:ec91:0:b0:3d0:a896:51da with SMTP id
 h17-20020a67ec91000000b003d0a89651damr7123043vsp.44.1675164847883; Tue, 31
 Jan 2023 03:34:07 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <5456286e2c9f3cd5abf25ad2e7e60dc997c71f66.1675111415.git.andreyknvl@google.com>
In-Reply-To: <5456286e2c9f3cd5abf25ad2e7e60dc997c71f66.1675111415.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Jan 2023 12:33:31 +0100
Message-ID: <CAG_fn=XhboCY1qz6A=vw3OpOv=u6x=QBq-yS5MmA0RbkD7vVJQ@mail.gmail.com>
Subject: Re: [PATCH 09/18] lib/stackdepot: rename hash table constants and variables
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Hu3jY71l;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e2a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Mon, Jan 30, 2023 at 9:50 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Give more meaningful names to hash table-related constants and variables:
>
> 1. Rename STACK_HASH_SCALE to STACK_TABLE_SCALE to point out that it is
>    related to scaling the hash table.

It's only used twice, and in short lines, maybe make it
STACK_HASH_TABLE_SCALE to point that out? :)

> 2. Rename STACK_HASH_ORDER_MIN/MAX to STACK_BUCKET_NUMBER_ORDER_MIN/MAX
>    to point out that it is related to the number of hash table buckets.

How about DEPOT_BUCKET_... or STACKDEPOT_BUCKET_...?
(just bikeshedding, I don't have any strong preference).

> 3. Rename stack_hash_order to stack_bucket_number_order for the same
>    reason as #2.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXhboCY1qz6A%3Dvw3OpOv%3Du6x%3DQBq-yS5MmA0RbkD7vVJQ%40mail.gmail.com.
