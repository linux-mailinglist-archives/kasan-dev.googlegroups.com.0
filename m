Return-Path: <kasan-dev+bncBDDL3KWR4EBRBIWIW75QKGQEDOXDSEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id B99A1278756
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 14:35:47 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id e4sf1792940pjd.4
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 05:35:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601037346; cv=pass;
        d=google.com; s=arc-20160816;
        b=rXwX+kTrDx2ncdYSnG9CvQjDcg6ttHUevdDlJzqb6PSa2+HPSSp3yPefc2jmW+T8s3
         /CAVxUHsDcViAGxpJwAej92Bo8kXrnq3m2N/ezWVPElIBmRX1PMPSd15Jp/j8Yczpb3I
         ICTM/+EBaXHmVDHQugI0yTHMvCTKdzO0h976YezHtxCoKRqKmNfFhdlQ7svo19aWoHSh
         BBqe3u9/t5q43Oav6FLCHI6HnntLNamGZDF6Hk8nc9lyr7jG7umLuh4KPknuEMDxeBmo
         Pltw2bkKw/Q4uabR0b/Vpytg0uClG8PE3CeieEm1uNiAB4ukS7Buq/pedY/xNqjQKiBT
         Ul4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=cYKQCPdauRu42o3l29XuoUC4L8+7fkxHXi+CDewynHU=;
        b=GMt9KqrYb/G2JNiP+ZHvhh3rNNvH/QFXZ1cl3n1mkNrNKA4SIdezJzEuqydwRMpsR5
         1AIdnwxxSV+I/cyWZCVVBreG0G4UE8k22hbdwEe2jZ95YhI/HYcfdcCxKaSbAhCTgZxu
         lYtElTPQrFnwasllxMc9/ckvN+pzgjdsJGYXPxUT39bMhMdbeR/q+/X7MPrYAduaaBfE
         2vfwwWceP8/aAmdgwLaBM/RT0edoSfg7nzN8p6PAhaQWnTEPq16GpeQVl8kVqKV4cqsR
         RD6ju43NELUpOSuxJKg1o2mJsY8zwql8n3Qf9jzpzoqK8fHVyflbBOJIp10mS0idmnrP
         ik+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cYKQCPdauRu42o3l29XuoUC4L8+7fkxHXi+CDewynHU=;
        b=gqlhv/vCxjnfwH0qmf/AGOvuPwO/PNZzXvGLKQpqhJh96bFyLIG5cr7B/gGztTvOXg
         aKfF6c3D+r4GuhcrlfI2jiWd4cQOQqI+U8RxME7FSQyLxGs1xMT4OZt1/V0p2Vp1VOJ2
         OfKehY2q8opy/gXMvtfHG8I+/dPhqUg+SlDfLT42p12l0/NZ0qmURk3ijXm8a3WAuUER
         oCNIn4qYiChqWoAL1ILMUwRiEDZEjEeKly1xagIsoHnOnNLOIoZH0vQdUWcMgCkp0ojO
         Fu0EDZjbaVCer+VY1VqixI8SPhJ9KN0/57xFsGYRW/UmeEbaNRSrZUPOnb7QY/QDieGJ
         PziQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cYKQCPdauRu42o3l29XuoUC4L8+7fkxHXi+CDewynHU=;
        b=gC1Gwl+tTth3sU5hSFRAfSIOYk6yrFWXT947EMOvoRFaYyCWscAlJr99TMGA0HVmSO
         sk9NKU5rLJDdH4RUxZr6ShWlGZpALwznX1bpG1pKo/QJoMIQSxyvLNK5ItpM8ITVKtW9
         fzWWVUMtTlhQFvwbAFVoL/vtUOYQaGHimCj2X6AnyYnZ6c0g4YMu+ZAeuAOZ9Lk5krtf
         lRJY8Zq7iFsaIqW0iu2rmytzSAfufkdCCI33QYa0IV1wYy+l0aMSydUShyXkc9N2geI2
         YpTmZz4kt+2lfbBHMFtaerLkwDp5Rx7NJNY+m+C010tah+JutBi1ql0SyrkRqsI45KIJ
         iyQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Ewx0l4dlUM/Q91IKQTq7dAN/1EP4Lh6zHXrlMxkWOneiuyVbD
	lEwXI4GGTpP0hB7vvgL1DkU=
X-Google-Smtp-Source: ABdhPJzskZBwHiz4LfMjDM1Bd2DCy87BwIHmkB7xyigpKtHQeSxtS5y9bGaTamEc6gAQpDoGtczWWg==
X-Received: by 2002:a62:2581:0:b029:13f:ba38:b113 with SMTP id l123-20020a6225810000b029013fba38b113mr3798995pfl.15.1601037346509;
        Fri, 25 Sep 2020 05:35:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8201:: with SMTP id x1ls1487213pln.9.gmail; Fri, 25
 Sep 2020 05:35:45 -0700 (PDT)
X-Received: by 2002:a17:902:8494:b029:d2:63a3:5e87 with SMTP id c20-20020a1709028494b02900d263a35e87mr3091655plo.40.1601037345870;
        Fri, 25 Sep 2020 05:35:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601037345; cv=none;
        d=google.com; s=arc-20160816;
        b=0mtoMC9MA15n68vKWDsk7HvQDM+nsLaHeiTAykIxZT8JrrkFw3wxdghLBXCAGe8goI
         oDS1bnasbeNUGN6uVyt2hLYdZWcPx2YNeu7jcV5JQVVmlm8iUIaGbCaZK3clpCDAaJ1C
         zXdVgM2Qg/TLm6Ah0paJxjlCAbSuyrDb7zVsw5zzLM5ksI8Tmc1B6XKficxEsH8GtNuB
         2ioS7A5RuA6dpWIVkwiuNYtWNI7QtiIj91zLRzNQNk85+J7u+x4FccCo7RnrXOzl4Vqc
         4zyfIuVKzV8FZRmRYeT5hO7L1VQq4yFZUMh2dSx8g2+NVbDbnu3aGC5eAFgQYDEqx2kB
         fEGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=LCm71YWq+xpLNew9LftPya/b5NDgevpHLpdHO+b8/d8=;
        b=PlfKAq8SnX9E+03kaE/rUtTOxD85o9NuzarWe2v8dIeulLwfo17TOTKbCVIGFN5EdH
         W6Cw/dn2FGKdVbLUJtYFBd8xIyzVGmLRSOhcTDA3tVRsQyWHtdGdqqxiqyXvolBlOvNi
         /maDwJ87sKcexoUMYMsYyR5G8Mb7bY7hNrMkkbWhu6LmZnuOI5j3qFy+1Yw60dG5rK6A
         IlqWGrdSqz8nIp+1r12Sh6QcMqWk7azmO34M2fMjpOwF4lwCzGGY23QhfFRpiwQue97D
         O/v0VU4gfz6vTxWSJCZBbTUN4EdFshV7ymOypWMV6wV+2ovby+qIE7wqSitmkc6RLLk4
         u2Ag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f6si142012pgk.3.2020.09.25.05.35.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Sep 2020 05:35:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 067B2206CA;
	Fri, 25 Sep 2020 12:35:42 +0000 (UTC)
Date: Fri, 25 Sep 2020 13:35:40 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 26/39] arm64: mte: Add in-kernel tag fault handler
Message-ID: <20200925123540.GK4846@gaia>
References: <cover.1600987622.git.andreyknvl@google.com>
 <17ec8af55dc0a4d3ade679feb0858f0df4c80d27.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <17ec8af55dc0a4d3ade679feb0858f0df4c80d27.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Fri, Sep 25, 2020 at 12:50:33AM +0200, Andrey Konovalov wrote:
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> Add the implementation of the in-kernel fault handler.
> 
> When a tag fault happens on a kernel address:
> * MTE is disabled on the current CPU,
> * the execution continues.
> 
> When a tag fault happens on a user address:
> * the kernel executes do_bad_area() and panics.
> 
> The tag fault handler for kernel addresses is currently empty and will be
> filled in by a future commit.
> 
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200925123540.GK4846%40gaia.
