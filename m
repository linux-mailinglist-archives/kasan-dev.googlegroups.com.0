Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTPS67YAKGQEX6X5PIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id C643013B0C5
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 18:24:29 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id u18sf6743054wrn.11
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2020 09:24:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579022669; cv=pass;
        d=google.com; s=arc-20160816;
        b=zf7xF24xXwHAqOsXhNk1sgw2sC+a1hFOXnshjaQIzepBCrNUVOwqQNkLbWxsv6LVPq
         rOBsx095l4UwQQgVJPOxmRvzLGd35IZicOPFLvepN0H0gOI22hescD6lwpaFx4vEvbZR
         vAS6TnI71LK/zE4kHmMilrKqiZbHF0lb4gXwtIfZjk4t+K5WZED5hVn/FrlgXZ419kZA
         QVgDOOzyVQsl7+D/T+w5/426TZEBU7DuYrWESNZibcx3zf6rf05YAoKQSAbZYJNbnccq
         hGfcY/MEd7vLpGEmmCXW3W6zFRuQqrYd1McoswAJGisiWdbXq2aHwUofDsxH0qZyRQMh
         MTzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tFuzEtjU3Iv28zyrdCdRGV1Yvf2FfMatraGGd5byHA4=;
        b=j+5+SjseokFKvoykhujalBDoKlpD5TQA9FoDFU0Z1bDKd5Dc5p6DT4ga9nmAuGVhhf
         fDh0xkoK3hI7FxFrHXzK2KSikuBGv2z3Sep1QoWKy3+nqRJxhlRmfZgOLsbDtZglSmrv
         9DiWmP2wFYPKTWclP5GBqfSvMGefmNd+pUaiOa7MmGidMSMonAZoSyP0kxgex8aycUND
         3Q7j1vf8iM0ViLgPIw9kgW2vOjVYBox+fewNNYkCQeoBQ05WamEYhswCC8iGjKTLFGXi
         3PENmcTv9gEnlw7sOSBU+l30twG0lI6b0MQLTgUWNuhzDxgfCn3H2QjJE9cL/xzZB3LM
         bolg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ArcAMvR7;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tFuzEtjU3Iv28zyrdCdRGV1Yvf2FfMatraGGd5byHA4=;
        b=VMRGCIOyQHgcWZtyBArbwIiy0OrfHfnpvuOYMV1KNgb1GvA35InkFdkdeJL8NvzYt3
         HCRjjgjfrhVVSfwi1MvVXNAep3DwNFzZR8FbNBd5yy4pQYaruHnkCmlmCbP1c6hlSy+A
         HBfbMyHwOFybdwWpAd9Y1Zjpk9EgIitH55waKrySa5cg7pMXyQmapH1QpkhLSH6kfCQJ
         BiQgGf0lhLCUm6+dod4RloX6MnoPFb22y/rEAm+/g8Uebj+Bwt9nko/QcFuBVLpuPFNz
         RDnoqHHZ1zTvyngB54lrBLtGfoGyEGWTYBYUeE96QIDTBt24vRu/SxePtvcPXxYFuks3
         +UbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tFuzEtjU3Iv28zyrdCdRGV1Yvf2FfMatraGGd5byHA4=;
        b=JqvNeJe3nVTBP72tj7RB0NE5/ZhBpk2lizrKD3IrJpHoou60e26rjc3ilaEq9ollOU
         JMES7Bf3pE5ZNIxp0y38K7y5DG3cYprcZD+ytgUC1LN6iiGOuUWyTgbU1scDHJRY5wCK
         MXXGlpAmP+O3njt6dmgIRToOXvgZzRCXSpjQ8QS1Qj5hc7popNzDfZp3EgCyqk+Id2Hw
         QRQa1VL5m40HB8HeTkBkrdVsx95Wq8JzTdIlLhLhQL/WY2ZFAqC7IqoZwbDdY2STFwoX
         R/8fsVLVRTILhPpwlXGc1liFARtD3UvGU6pvagw/9eCLZh9ZMM0rp8wT3ab7j15ekU/M
         9SDA==
X-Gm-Message-State: APjAAAV4Y6iTobkxbEXVGgIqyvBZ+bTWO3NlkwjX9wqTXXJtyrinHZ6T
	I92HhvimdYSfx2Gj0NRDB5c=
X-Google-Smtp-Source: APXvYqwvuM1ME02e5qDWJxhpRKuZp0+TKMbZxrLvOQyKDltbGXXl9tggqhbkR+iKSb0PZ6Rz9v+f1g==
X-Received: by 2002:a1c:4d03:: with SMTP id o3mr28635973wmh.164.1579022669456;
        Tue, 14 Jan 2020 09:24:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:6385:: with SMTP id x127ls8116289wmb.2.gmail; Tue, 14
 Jan 2020 09:24:29 -0800 (PST)
X-Received: by 2002:a7b:c851:: with SMTP id c17mr29435155wml.71.1579022669000;
        Tue, 14 Jan 2020 09:24:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579022668; cv=none;
        d=google.com; s=arc-20160816;
        b=NViNneZvWLSLo702u8EP+71WxiRp2AmBEFaYwhe+rL0SC1tlRJH46CmEnrbeVTne8r
         QTeWW4fbfhTXu7TnnOaOT1C9D2C+XDgoZ8hw8OnIlqC9sqvhVSCPPO6keLpUIGLvjGiu
         YBxfL46NtzR+qzITquSiIBtdvmA1I9hc4pJX6Uz+LPoyPSzRm9h0bP/JFfNscozEhRBo
         +Lczrh5lb8GgzZ3t6o8ho7XlYw9U8GJzJGF6GT04J/vgMjucUl0m10ZgrlMheGiNEubF
         14ZRp8FVPNWL/N5qKxk0SRt6JiGIkIiHvcdX3hvb+mSm6qXw7lknlvvJ9Hs97P3hJAP3
         gSbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=m6aoFKbKaSXKUSg/Zz8IkoRTb5Zfu+nxqGB3mWWn4Q0=;
        b=R0IjZ3IgbzcVi6nfEjnNqsIZDAnpyCffbfv9g5U5HCjr61cc/zstQhqsvPkcvV4CfO
         q5Y+rTrYMobzmU36V0gL9WlVa9Fp6LMQ1rpMaFJ4R58GZub8M+As2Mq2yengvR+w3KGI
         CVsPmkS0vwWmGL+0FNe6VDlwehhY0ZgvRvC2sGinthlRDn9Y11w2l8TP5tEV2IAVHWC4
         Z5SF4kMGr3tpAG6VZ5/LO1cd7/QN1ARpqJJyCesGmrUM096JJbqIFck5WB3sAiA1XJyn
         Nywo1C64X1JTmtcyumjqJQvuz+LxHCN/de74jHm1WHlkl/FZG+u26xUa8v2FVVWLtBvQ
         4SWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ArcAMvR7;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id y13si635029wrs.0.2020.01.14.09.24.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Jan 2020 09:24:28 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id d73so14765680wmd.1
        for <kasan-dev@googlegroups.com>; Tue, 14 Jan 2020 09:24:28 -0800 (PST)
X-Received: by 2002:a05:600c:246:: with SMTP id 6mr29500320wmj.122.1579022668374;
 Tue, 14 Jan 2020 09:24:28 -0800 (PST)
MIME-Version: 1.0
References: <20200114124919.11891-1-elver@google.com>
In-Reply-To: <20200114124919.11891-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Jan 2020 18:24:17 +0100
Message-ID: <CAG_fn=X1rFGd1gfML3D5=uiLKTmMbPUm0UD6D0+bg+_hJtQMqA@mail.gmail.com>
Subject: Re: [PATCH -rcu] kcsan: Make KCSAN compatible with lockdep
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Dmitriy Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@redhat.com>, will@kernel.org, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ArcAMvR7;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::341 as
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

> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -337,7 +337,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>          *      detection point of view) to simply disable preemptions to ensure
>          *      as many tasks as possible run on other CPUs.
>          */
> -       local_irq_save(irq_flags);
> +       raw_local_irq_save(irq_flags);

Please reflect the need to use raw_local_irq_save() in the comment.

>
>         watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
>         if (watchpoint == NULL) {
> @@ -429,7 +429,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
>
>         kcsan_counter_dec(KCSAN_COUNTER_USED_WATCHPOINTS);
>  out_unlock:
> -       local_irq_restore(irq_flags);
> +       raw_local_irq_restore(irq_flags);

Ditto

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DX1rFGd1gfML3D5%3DuiLKTmMbPUm0UD6D0%2Bbg%2B_hJtQMqA%40mail.gmail.com.
