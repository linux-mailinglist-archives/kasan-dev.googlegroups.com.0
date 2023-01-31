Return-Path: <kasan-dev+bncBCCMH5WKTMGRBV624OPAMGQES6I6MNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A87A682A7A
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 11:28:40 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id s4-20020ac85284000000b003b849aa2cd6sf3317112qtn.15
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 02:28:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675160919; cv=pass;
        d=google.com; s=arc-20160816;
        b=QXQNdGLGnWfhSLD71m3WbXN+6HHbcIR3a3fOk98F/09QG6Y6006/SrG1+wlEcPMLUp
         aOjU8cl9BTidex6THWgUyK71eLzqHXa3w4vM9YWcJhzBQ45jUEWf4zchMjLPKT4y4jKO
         aYZbh8hDZCW+N1qyyq6njaS1XBJ57VpBWCa1BmPU9aXGGnm+zLhdZYSUx8fRhMVAMETz
         oYbnHptr1h6RED6MwmCa6zqPH9q9MCjnImz2uCLgRmnqPYK3HmtNciMeVOtHXPrPAM7p
         //30WdLgUrIsm+zioDHYoC7AkfcZvScYKFBkYHDdzVPQQnaSgrLH1vwCB3A5se4GDXIF
         /fwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=99BADBVvfeHglDHWvKAz3DmtT5j0XxOeXkBFidujklE=;
        b=YzMUgJZa8xsIkCM9cTStYB2rlUhaZekxK8sND3HfsYVSBp6PqG3EpXCz2dmDngCmEs
         1O2vEHCCUvqjlLNSfy/YAKh7eZN43IBpB0qBIeKVye2diwdjAtnl0c2o057ZWSPxHwT9
         JdD4XqTrGm0kX0pQ7U2PvBoZpyH6Zc6bieYvmzJpjR4cFCgiKbqMpMXSIeBRa46drRUk
         bfNXe2UITXBNyOMRzFwfLOkZexFSH2Y0D09dm0PVAV2pvYng/UcNPfHRF+sU7wbEZNlJ
         Pr40GWRCUksBqSxHDnL4bXEVjbfEh88wBQvR3T00Fx6IBlkEjanPKkyf9d8nZAS9B66I
         eqfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hJF5vaV+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::933 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=99BADBVvfeHglDHWvKAz3DmtT5j0XxOeXkBFidujklE=;
        b=KLm2IE9KxjR/B2qYpe4yNzcMa7ovkxH96ZAEI69XeyumeDfxvsH2F58whZ5CiCPRqL
         ih1Mg6HaeNbJNu5BU0tidbq4oVyv/i9HPKb2nuGj6r2lNI/8mYI3QInIQ9i9DVykPu7Y
         XQib5EzKWWLW36mKH8bB/nRmKsKQDo7kgRannVx6i3kObzRYNRHedXPVSU0AN0k7VeKC
         p1fTaztA8VKfb3zthbs5sDMJBrwKDf58FAx4MYq6/hZvpkGvxMKPflROCjM7Bc8TDzMD
         qYobUDHYSjoinsyZOCqSoFdREuAmXZwaqQ4CfKNJdCA5wVidRcG+hykYC00VGe4lqCji
         1rpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=99BADBVvfeHglDHWvKAz3DmtT5j0XxOeXkBFidujklE=;
        b=aDmFXqZaO+2z5osDY/K0EM0BWCk7MByLSVkTilmYi53PwVMrUpTLcjPxC3EuojenEs
         Q/jloGaCNxcrOmJrW5Y//xrgXLjvGT8X7JtmolZCnhYCbPCt95vApmQHDGvNeMetulTx
         GANcg64MEsyCW3HPPqJx8E0RZqIBmude7prrGELLzpjItPhCzmB1m35psl5fMgAaUtf7
         LvrSDSibaafwg1XJSVBHEJKLg0yXTfM7JlV7509VMlwLQSmI0dAbRqc4KpbeOnp7EHvA
         iWDu2MhRh6Dm5Z98w5cqD5Y9JuBCV3N1rUVeI67aDe7zJLmgGovGHq1UBGlmm8rZ/qzC
         NZzg==
X-Gm-Message-State: AO0yUKUeqIvHve8zsv3kByWY2SSC7velAbVJ0J38jV9akXE1UFtQzK6r
	e/L5FYux5h71oJOvTF4mJuA=
X-Google-Smtp-Source: AK7set/hlxiFWQCqpFf31teJ49CJDnDBHXaTRZDUusmPUMA1fa9fFi+v9tt1fRLNOhaygAnAQeIU9A==
X-Received: by 2002:a05:6214:2aab:b0:538:dd83:7f87 with SMTP id js11-20020a0562142aab00b00538dd837f87mr961397qvb.38.1675160919351;
        Tue, 31 Jan 2023 02:28:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3c8d:b0:532:149f:9c2e with SMTP id
 ok13-20020a0562143c8d00b00532149f9c2els8440119qvb.3.-pod-prod-gmail; Tue, 31
 Jan 2023 02:28:38 -0800 (PST)
X-Received: by 2002:ad4:50cc:0:b0:538:3980:88aa with SMTP id e12-20020ad450cc000000b00538398088aamr23958509qvq.41.1675160918860;
        Tue, 31 Jan 2023 02:28:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675160918; cv=none;
        d=google.com; s=arc-20160816;
        b=isP7MPRB1BIE8+bxcXoLzluwx/HxYJQbfQSkR+jbD9o6irELCJLt5hRXwDrVHKZXfV
         egIuOB+gXfp8gu9NoJV7mAWBVbaMUoCCxzqIc9ny1TSNYY/mbHTM+cNcxGTZ9sQtngG+
         aniugZ6sKM2h2YJ7mN+C/gpuKFEJNcJdj0FfLLf/QJhQoDI+Xz6bELKWD3z5i3wMBaeO
         uvM2ezT8TsBmeC96zxEpqeLYdsHxb0YxlP03ZTsInaDiHK6gVYQV51cTHgQdezrJRozl
         f8AYjl9ic9LpjtYDyQX4/ZovOUJgwLm9kXX6zWJAwspetMGKLAaQLpbT2OAPL5fxJJQj
         NNZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=a6g8bNkySwa49lfZtMhX0bn0GNfblJVVbDTJj9FWuJw=;
        b=b3MKK8lBDFdL8O1u/kitot8K9foGBQjKw/hB0oGKbDk03ko/BdmyIAY/5hyIr1LCon
         8g62Ip9k3ePZCdaIPDIojz2zS05l9ud6UB95EQXfKonmKUXT92jk40ERgLmy+r8brIWb
         ohupWAjMC/FGRF6qZ4PjSbnBGlJ5sEHarkb4TEvXpBcL1nFLlIQLvCpKBB8RgoDdbWRh
         sAyFIFek151wpeZE1ppBPSjO6WZ/ZxVwgdBnCveNwmuYwld9JtYICCySvkzhBAFnoQsE
         XBhhzV1JL3yFL09X8AtsuAixM5a9pxDLdl1s7mNd/ZB70n+rC47oQqNn+7b3FYEBFgB8
         RT9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hJF5vaV+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::933 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x933.google.com (mail-ua1-x933.google.com. [2607:f8b0:4864:20::933])
        by gmr-mx.google.com with ESMTPS id dz10-20020a05620a2b8a00b006fa81f6aaf7si1031499qkb.7.2023.01.31.02.28.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 02:28:38 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::933 as permitted sender) client-ip=2607:f8b0:4864:20::933;
Received: by mail-ua1-x933.google.com with SMTP id j1so2837326uan.1
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 02:28:38 -0800 (PST)
X-Received: by 2002:a05:6130:83:b0:655:5dfb:9d10 with SMTP id
 x3-20020a056130008300b006555dfb9d10mr3561535uaf.63.1675160918398; Tue, 31 Jan
 2023 02:28:38 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <293567627b0d59f1ae5a27ac9537c027a5ff729d.1675111415.git.andreyknvl@google.com>
In-Reply-To: <293567627b0d59f1ae5a27ac9537c027a5ff729d.1675111415.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Jan 2023 11:28:02 +0100
Message-ID: <CAG_fn=Vs5SEdCRDEKQGd=ijMas_dgH=VMeoLs9zq8PBmjY9rGA@mail.gmail.com>
Subject: Re: [PATCH 05/18] lib/stackdepot: rename stack_depot_disable
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hJF5vaV+;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::933 as
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

On Mon, Jan 30, 2023 at 9:49 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Rename stack_depot_disable to stack_depot_disabled to make its name look
> similar to the names of other stack depot flags.
>
> Also put stack_depot_disabled's definition together with the other flags.
>
> Also rename is_stack_depot_disabled to disable_stack_depot: this name
> looks more conventional for a function that processes a boot parameter.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVs5SEdCRDEKQGd%3DijMas_dgH%3DVMeoLs9zq8PBmjY9rGA%40mail.gmail.com.
