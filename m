Return-Path: <kasan-dev+bncBCCMH5WKTMGRBOVEVCPQMGQE4Q7FIEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id A7CB96942E9
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 11:34:35 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id m6-20020a9d7e86000000b0068db7d59df2sf6155446otp.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 02:34:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676284474; cv=pass;
        d=google.com; s=arc-20160816;
        b=qk9mDXUZgHas3suJkDuywx/OH0R9CZfIQoXVZD3S7cYMU66eiQKL2ze6F6j046h1G4
         aHwH75GYJg2XzJwdIzfT21TmHVuXDson3TRYGK/D3OkugpIG3o/3kNHPlx4xhMvnYaj8
         DbDhZX+l2cp61U4SWIG6WT2WIQGgRe1ogQlfv61ZU/N0o4Di/CNWmNDwGrWLWzjmfxud
         VrmaCn5r67RetDhT/Y+ZhbkzcJwpSiUK2s1mS9AowZn4lqxvRTbELRENY12rmU/Xotnj
         bAtTMf9VCqOantO5b3olIkIt59TMDlbl5AEONp1z3H4Zx14Cd+NWbMhUmfQqtXMVliY3
         aYrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3iRFtrWvoBzu8t8Zp9SX/q7oHfONaARolnn2L69XyO4=;
        b=nSoLZBFvZ2HCh4YOdor6GVw/aby1oDKGgHDME2cHTrQaerTE+pXoYi38t2h8ElRs/G
         snUjZsNd7Ez19CPsLSl6+y7nJA3nWeVArmgCCMkqz3+JqM3Ejb48nfNepboDc3DNvxp9
         e0VxZRTzDiSBdSKYqbktqXv1GFGSNmlS8992NXHFu0/zQEAMI647gtsbXBynS0T8SNI9
         Khvc7eH0WQKK91aHJ/7eKujGP05VgyWe+etp9H9psIZmqmbBR9qHV0EnODOKpJ/Hcf6u
         I7Vx46WaznS7T0R4TpHCjJjeu45Fdwm/eEFhaYfNgjeD5b38xSd7LzZmjvK84Caqf5EZ
         9DyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CVEWvj2k;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3iRFtrWvoBzu8t8Zp9SX/q7oHfONaARolnn2L69XyO4=;
        b=onuEQpuht1tDLGzRObKNfEJf5RJ2wcWITSmpkKpmdJ99dzig2kA0z30y48jNsQPCWL
         /tHcGJCtdm1/0z7ljgIeIw/q+yaNrSLFDOJCeQexjgXyX5C7wR6nDcMdByTiU7VZtFb7
         KnhCKthiv9x5OERmdpvZKG6RlSR34WMOqo6dqzrpYmwol//K9nNmjasoNbxzsGAhDk8e
         /H2gT9Fi6/OQYBto36T5+fp+JS9R/imtXZbvSWFT1BNEvg1JK3WdLFku/WUosonO60vq
         ZjqNXpSfRKJ8rlra8wTtaZQVdX+OnZfQd5TkGL/CojVtaIN1yrUEpayR1uMP1de7/73j
         1cCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=3iRFtrWvoBzu8t8Zp9SX/q7oHfONaARolnn2L69XyO4=;
        b=MGzzGKM1rsPMVB+zK9b2J2yBd2goH3LATGoHfD5Rm/gJplAB8AcYMlzSlFnr0vD3vW
         emm5wwaYq46QNYMQIV3ig65nO2cs+QseS631dosFqiK6ADRyRDDbXpDHgbRDFg6v/Dpj
         8xJ39ITTe/BoiULZAQjEnp/qef/A+F5b8/9PflT6Syumdiz9XLlhUueB8inFpMTQHKnf
         Q2EniFw2w1Hlka/qeSFXdem9KD7ejvTGsm8hXH65QuTq3ynhHcUGzY0JW15X0C3M6nag
         uPxnAjT9PnNJZynLHQi32Hnc34O5+5az3WAiL0otTB75TIPDJZlvci81BIFU16BnYhA6
         H23g==
X-Gm-Message-State: AO0yUKXskORQ/GOs0ewrOOoCU7YPIomBf27MKhIw3nVyaINYuNhJPTmA
	L4xmt1ElJ2oKrTWw/VQLcGw=
X-Google-Smtp-Source: AK7set9xxG9CnEV2+AM37Mob8GfeurXuKx+H3EGlZHxhAuxPVg1B4SJmG8jke78pVS93bcUMEWlDgA==
X-Received: by 2002:a05:6808:23c8:b0:37a:c636:6b05 with SMTP id bq8-20020a05680823c800b0037ac6366b05mr931555oib.192.1676284474180;
        Mon, 13 Feb 2023 02:34:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9d41:0:b0:517:a303:c960 with SMTP id f1-20020a4a9d41000000b00517a303c960ls495090ook.4.-pod-prod-gmail;
 Mon, 13 Feb 2023 02:34:33 -0800 (PST)
X-Received: by 2002:a4a:430c:0:b0:51f:acf8:d451 with SMTP id k12-20020a4a430c000000b0051facf8d451mr129446ooj.6.1676284473733;
        Mon, 13 Feb 2023 02:34:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676284473; cv=none;
        d=google.com; s=arc-20160816;
        b=tQZp3YJ6uRwdGhtWtKdEq+IL7uvEXp3Z3SGpXZuZDGKPlsQI4qjCxjyxDYl+weFj/+
         Lq3fqtZBOd2+ZCALjl66yx91DdnLM73kQRC9G00/7DiB9xx0qlKfEtdSzbOcq/39GEkQ
         eEgU2f74Cv8u6KhShGwPxQpzw6SaxRDA3xG/hCf9TDf5UNkL/nrh4PdZNlyne9vb0wnO
         0ka2e67BZVAZ5jWp3GWryf4BwuKdM/QAV/snyD3aqEDksFVr8dSaQCHiB8kSl27bLC4K
         coEf/kklg7nPAQbBDVzXfEN6CPOWrhat2FBmFDWdBSBz9ISiSB57kviOTpjhVpUvydsI
         n2GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EG8YreyKgfIxXVMHClXkHdhKvtNnPhGwPY2bkC9invg=;
        b=mdcJZei7wNz7pTO0b8xZpltFEKWqfR97Rb4I4LBkzJd0lAtIqc3c7t8KaVpxrI52e7
         KAieCLQsLZCpwADbcszQC/7cJ5BN0gJST1sM/JlGyE29dio9D/5/2jNwcrBNrv/nb+rp
         YLiI7eO6lq7Cuc13tDN0GIwDcPOGDr8Nh8aJM31LmER/j8i5YWb4bDPZh4vkykhE0fXw
         xr8+++mAcP/avJ4VXN15AsXYtTmfQjzwH6Q8OmB8HzNczGYjxys5mEVfhteAW0Hw43FD
         XV1Bpad+C0t6OWDVfln2iMqN8dipE7tffi4AQXVQKDiqIZyLo5zNBh35E8k0IhkUXT3c
         oEMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CVEWvj2k;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x12d.google.com (mail-il1-x12d.google.com. [2607:f8b0:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id bt40-20020a0568201aa800b005176d876205si1116779oob.0.2023.02.13.02.34.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 02:34:33 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::12d as permitted sender) client-ip=2607:f8b0:4864:20::12d;
Received: by mail-il1-x12d.google.com with SMTP id h4so1561210ile.5
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 02:34:33 -0800 (PST)
X-Received: by 2002:a05:6e02:1007:b0:313:d1b5:82cf with SMTP id
 n7-20020a056e02100700b00313d1b582cfmr2475453ilj.5.1676284473265; Mon, 13 Feb
 2023 02:34:33 -0800 (PST)
MIME-Version: 1.0
References: <cover.1676063693.git.andreyknvl@google.com> <5606a6c70659065a25bee59cd10e57fc60bb4110.1676063693.git.andreyknvl@google.com>
In-Reply-To: <5606a6c70659065a25bee59cd10e57fc60bb4110.1676063693.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Feb 2023 11:33:52 +0100
Message-ID: <CAG_fn=VMiZJaFRNiG5wdYP=rfJiJXuKYWcx5mFEmD+nEOrvTMw@mail.gmail.com>
Subject: Re: [PATCH v2 07/18] lib/stackdepot: reorder and annotate global variables
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=CVEWvj2k;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::12d as
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

On Fri, Feb 10, 2023 at 10:17 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Group stack depot global variables by their purpose:
>
> 1. Hash table-related variables,
> 2. Slab-related variables,
>
> and add comments.
>
> Also clean up comments for hash table-related constants.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVMiZJaFRNiG5wdYP%3DrfJiJXuKYWcx5mFEmD%2BnEOrvTMw%40mail.gmail.com.
