Return-Path: <kasan-dev+bncBCMIZB7QWENRBKXKRGJQMGQERJXNYVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A37750B408
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 11:28:11 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id j41-20020a05612221a900b0033ef6f852dcsf896063vkd.19
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 02:28:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650619690; cv=pass;
        d=google.com; s=arc-20160816;
        b=HcPt3U7ovzn2xnENdWuLZYf6Pcf0gZNSz8vPs/gJgm5iPLUMZbFdGxnZTlgyMLQBj0
         OY6oFTffoojbW3tmE+4xatN7t3ck3eYdzD+aIKgDMqQMu7OqGtYtOzVNcoRLwoE3YzO8
         iVQLyvGIoDv7B99kZNTdhNJyhMonjQU/uy/k69vRwlu2xx600WNUNwJ0CdrbD6i5Qe4V
         txtS2EdR8tfMVQLO0FyRSbk7WbSHU/3VRxj8kT2FsPgqLJMsFX2q/QDnAzBs7VxHjn1j
         FY/AmnhLmtBROkli7NDyPWHOadVA8Haz9gmcsKPWfwiZHV7nH6C2gBKFVVAhCTLn+A5K
         Y1ZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=d63VXzCZlumoZkG8oejUiA0r4we0psDD8qSpsxXlHpU=;
        b=cluqgUGgA4YEFZvCSRI/kGLuCE2NoGkuHUxfNpB0yS3S4d8TWRMUn2ZQV9InISgaAs
         L6cNqDVZQGH0hZvtFGD8MzeFgClOjT4XFzGSG4oRR+gcp7jsXshf47PdKn2xV9WMHZDI
         1iN1DWnN2jNq4VndBZ8KDusDKXMSsAdggw4H3ZsRDZ0jrmfpd4gAcab/q69EhuFwifNo
         61zAujgVAYvIzB24W7MtCHFgzsWwdK0vGtNx8zdls61zStT6bb9hVWrsAUNopiboqCJA
         JuqY3ZdXJ3xOz/YQdzXfW+8YdZJi818MKK8RqPuniWMep4IWpDTX1oVC5JKzdCiwXI1s
         6DEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Z3KEFqZX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2001:4860:4864:20::33 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d63VXzCZlumoZkG8oejUiA0r4we0psDD8qSpsxXlHpU=;
        b=dnsEEf8gkJKkT7r8j+94jU0i3VConaJpx47fhc1Q4R/bt0ybzWJCYgR2U4uak8k9+b
         eCFYX7JmvIxpfeiMWfOVPuJKXIVTuNn5mt0TWM2/zXElvZVIPQzK2mElzfjpWS1j7Inr
         Ax9KbyAwe9j8jD9acQyVNPMgsLwRV2LO3OTIcN7jdxmVvnjXk2IRNal1vpmEedBT1rmS
         THIqEIvFryfsMDffXHuJ860OTIg3rMV2XkeEaVHuA/REudkwI/RMSgmgi75o9+zrsqAO
         /eA82gDkeKU4vtUW/KhiCAAd/HcKaXUiSCet1skZs9VjFhZwPVjIjNY1sN/axngOIJeD
         bEgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d63VXzCZlumoZkG8oejUiA0r4we0psDD8qSpsxXlHpU=;
        b=mKsL5PrW82OGUePXLHrJG2zEwtlBEdRVbpY6KbdKfFnWWGZkwhIa36KmKRYtfV4j6a
         XGiSjyucdYgugumYcoxTEL+N5u9AzNgyKHLffZsJczx6pob3nNKGgl4f1fsQmJmyzdgG
         jtc+lCbE6q23XD6KLN5q5fNS2gHinGV8zVteP00fzddrnVwZNHYgGIFvZA1q/h0txK4p
         68YCNNlpUhQTH3IwUhSSDkaQVtqmQvUN/1Z85zY2bcoBjPocyynbAukuwajDQ1+HJ4me
         gf9eotnyuVYUXFv6IY8uyqJU1gGswTeW/GWlF0jBOiwlKf2+COYloIKsrnJMIqMzFZoK
         pQJg==
X-Gm-Message-State: AOAM531tczLejHeZteYWEbkZGVlUe2UAD8qap9wlh+2kfNmqeHNN7IIC
	tgjxYZ5tz0F4DIpkam9RvZM=
X-Google-Smtp-Source: ABdhPJwlLktCT/5o7WW8tr/HL3sb5YoDqDx4WDq5ADP1rSSc7K2Z+gAIvaDms9Lpg5Sgpo9SH0gzMA==
X-Received: by 2002:ac5:cdb1:0:b0:349:acfc:29e3 with SMTP id l17-20020ac5cdb1000000b00349acfc29e3mr1225412vka.20.1650619690396;
        Fri, 22 Apr 2022 02:28:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:7d1:0:b0:35f:ae0a:471 with SMTP id d17-20020ab007d1000000b0035fae0a0471ls913033uaf.11.gmail;
 Fri, 22 Apr 2022 02:28:09 -0700 (PDT)
X-Received: by 2002:ab0:6695:0:b0:362:73a5:1e85 with SMTP id a21-20020ab06695000000b0036273a51e85mr607497uan.49.1650619689846;
        Fri, 22 Apr 2022 02:28:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650619689; cv=none;
        d=google.com; s=arc-20160816;
        b=MByYF7cZW8sno6oqIlqIbJyo7UTzXTq3JSVOwN91yrwZh29HzGKdznlxp4Zsv+z3HS
         HqwqEHuXSQTlJ3OMDMh9kvh203lTuR307W6xl7uGVPOTxOlUb0SGZ8Sdon+Afddc5prU
         LukpP0pUE+MNt9X1JuoOxWXFphHp8JUohf1FvdjJTZfbdglgW2cKtNrxsv7Yh+lNlpkk
         qcvm1Th/ypeVRPLjWZK8YoL+bCSDK0n/d8pBXnTexLihFroO3KBYxrOCdUIs/0RsmGXU
         GioeVWbnQ5QheU9iPjC//e/N67YL5BciCDrPb3e9bdD2Kzr8XsOSUQoYzq1AzLn95kt3
         3sLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZWymUxmdfVUMI3yqwCTohfwWtEzgJE9q82Iv6yHI3Dk=;
        b=IxwVnEpagIcil4qH4gS+gFBdtpG1OAwcRpYvfhZ50D8jk6NPncjTrChNHOjqh4JO34
         Je9rjnJ5768czh/V8lyLh5QBB4GzJxoxzdCFiTG6/mEyUkh8Wxzn6INahBItgFw8LhEU
         M5maGIZGFPEkUhFmv9Bol9+Djz3pmL3cHOFARbza2tD0oAeZnLVOm8VhZZ+8mEKIZyBb
         DUqv+aOTXt14rWGAXBPtUhAxvfxcxewQ6XKz6thvY/BvFh/HOc/qPyBSSdrknKja2suS
         4YDWTscox0P8S9AhLklqY5kd3MgTEqlGHD5ADAtMsG1LymZjFxN9h1x27fiULXdkeaiT
         7xxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Z3KEFqZX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2001:4860:4864:20::33 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oa1-x33.google.com (mail-oa1-x33.google.com. [2001:4860:4864:20::33])
        by gmr-mx.google.com with ESMTPS id a16-20020ab03c90000000b0035fc4b18c67si1508166uax.2.2022.04.22.02.28.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Apr 2022 02:28:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2001:4860:4864:20::33 as permitted sender) client-ip=2001:4860:4864:20::33;
Received: by mail-oa1-x33.google.com with SMTP id 586e51a60fabf-e5e433d66dso8050137fac.5
        for <kasan-dev@googlegroups.com>; Fri, 22 Apr 2022 02:28:09 -0700 (PDT)
X-Received: by 2002:a05:6870:468b:b0:e6:7f11:523f with SMTP id
 a11-20020a056870468b00b000e67f11523fmr1478203oap.163.1650619689161; Fri, 22
 Apr 2022 02:28:09 -0700 (PDT)
MIME-Version: 1.0
References: <20220414025925.2423818-1-qiang1.zhang@intel.com> <20220421150746.627e0f62363485d65c857010@linux-foundation.org>
In-Reply-To: <20220421150746.627e0f62363485d65c857010@linux-foundation.org>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Apr 2022 11:27:58 +0200
Message-ID: <CACT4Y+b6+MpuWGPhKZx19tLtP0WHsgiuV7XPKqj+yMBs2Tnd0w@mail.gmail.com>
Subject: Re: [PATCH] kasan: Prevent cpu_quarantine corruption when CPU offline
 and cache shrink occur at same time
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Zqiang <qiang1.zhang@intel.com>, ryabinin.a.a@gmail.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Z3KEFqZX;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2001:4860:4864:20::33 as
 permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, 22 Apr 2022 at 00:07, Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Thu, 14 Apr 2022 10:59:25 +0800 Zqiang <qiang1.zhang@intel.com> wrote:
>
> > The kasan_quarantine_remove_cache() is called in kmem_cache_shrink()/
> > destroy(), the kasan_quarantine_remove_cache() call is protected by
> > cpuslock in kmem_cache_destroy(), can ensure serialization with
> > kasan_cpu_offline(). however the kasan_quarantine_remove_cache() call
> > is not protected by cpuslock in kmem_cache_shrink(), when CPU going
> > offline and cache shrink occur at same time, the cpu_quarantine may be
> > corrupted by interrupt(per_cpu_remove_cache operation). so add
> > cpu_quarantine offline flags check in per_cpu_remove_cache().
> >
> > ...
> >
>
> Could we please have some reviewer input here?

This is very tricky, I think can follow this:

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

If q->offline is set, then kasan_cpu_offline() will or has already
removed everything from cpu_quarantine and freed, so we can return
early in per_cpu_remove_cache().
If kasan_cpu_offline() hasn't yet removed everything from
cpu_quarantine already, it's actually problematic for the
kmem_cache_destroy() case. But since both kmem_cache_destroy() and
kasan_cpu_offline() are serialized by cpus lock, this case must not
happen.




> > --- a/mm/kasan/quarantine.c
> > +++ b/mm/kasan/quarantine.c
> > @@ -330,6 +330,8 @@ static void per_cpu_remove_cache(void *arg)
> >       struct cpu_shrink_qlist *sq;
> >  #endif
> >       q = this_cpu_ptr(&cpu_quarantine);
> > +     if (READ_ONCE(q->offline))
> > +             return;
> >  #ifndef CONFIG_PREEMPT_RT
> >       qlist_move_cache(q, &to_free, cache);
> >       qlist_free_all(&to_free, cache);
>
> It might be helpful to have a little comment which explains why we're
> doing this?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb6%2BMpuWGPhKZx19tLtP0WHsgiuV7XPKqj%2ByMBs2Tnd0w%40mail.gmail.com.
