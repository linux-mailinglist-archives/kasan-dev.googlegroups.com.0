Return-Path: <kasan-dev+bncBCCMH5WKTMGRB65PQ2AAMGQELFTBN5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F84D2F7C82
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 14:26:20 +0100 (CET)
Received: by mail-vs1-xe3c.google.com with SMTP id u66sf1456109vsc.12
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 05:26:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610717179; cv=pass;
        d=google.com; s=arc-20160816;
        b=pYYvw25Kra2jCnyJB8PkkBk8ctHERzveCexH7RRwb0B+DzLGlk2dLZxnQ/OSsNeHuX
         vBKCuRQHC2pb5X87YqNHtTLAll8ZZ3klq8pH1nWRT4oJFvlBCq6O5lkdoTItczpl6Hg5
         4U9pdJ574ezILszgdJKR8KbmSOi6R2UpUcSZEnRZdyhgabF2M+tJwf3BQjvZ+Kz6Qjq+
         SncfjBXtffqEDuUkFA1ozv7WEeElMFd8lqN6BkV4zEO/JaX+Z4cOXj2UXoqiEC+p4Yh5
         e+RcX2kOEVW42lBHPC/BOMZjIJlVDIe3qpqRnTCNQpwdp5eCwjWdckBqIkuvpDHD9IIt
         HfGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Qj/zidPdIJyURGd6y+CEB1plAipjWhhqxZ12Hccl5nA=;
        b=Nk5I8Gc2uPJoPOJTEaoaCw+KeIXKxo3rP3Ks/ag2Z8wFBYzvO7NLMkxJu2P+r5PO/o
         tHhV6FHGDzlCh4oISyX1OzN1yeWjBaRL2QFRZHpJg1xOOFrQarsaOE/BKBk2/RXjbDCM
         YVaBcvviIzkscNOiFVtlSSO//9OlbkOi/j1R7K+8qeYOiCloalv3GNMC2Vd4V/YN0/ud
         oTuniMcYNVrA7/JIe/9YpZ7azWZVsuu4mvXGSGpVgSoNPpoIvmioxgqGAKj5Rb5qOthk
         6MdPb6qtbsXAw3HYrOtpaLu7hDdW6UQqDgu0foVt8rmwOt9S3Jb5TpH5EA/aZdhED8rn
         sjLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QG4SkeTa;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qj/zidPdIJyURGd6y+CEB1plAipjWhhqxZ12Hccl5nA=;
        b=pxO6W7KbspYYkAZWIeUP/vzp5Yju12eDgffpfRXuyTx/XcL/0/+8zJ11NfpiDkolFd
         5GvDMH9QS3QljtUFxEgRfDaF738H9oeV4Z3moAqI8blTIQ2TCVRY3aEzRGVA6nHmBTsM
         JHw61pvZ8SBW49POqbAQjIVWRFhjZu3iFkY67NqOrsrToEJOgqzCR1RTaPXhQKtaDhhG
         am0RfTv5d7Nuy+dSx0nhMS4XFFIas43ZY8PZfpcRiChgL11UstNxQ2yFeJVf6usgbr9R
         c9zoo7bK0OfzUHi0kjvmCEApIiAjfF+1XGqy4bNv+QQ4jm1wwMW+sXwsVPJYwFFelxrz
         dsWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qj/zidPdIJyURGd6y+CEB1plAipjWhhqxZ12Hccl5nA=;
        b=qXfC1Sb4NaFeeGoU+uoTXTfpe6iGlyusRQm1D4xdt4mgfBGdVL/3AEOpM4ma7reQTa
         Tov2BCQpQF6eVn6GHV69kisHom6vY5ExtMQmnv88P9FOuLeea+kZIebVit3Yv7Xxj85r
         +czugMcOGAThh5G5f1wunpIkGr7yzLPKbVsClBIOdayrf2w6Si2xrWzjvPCBURLzbdXM
         SPojO1bHR5/QC/S6cdf2tgy/3Axhl21nrl/LHBa+m8xpeyvxWKZrR++iPs51WyX7u+UM
         XSHzCmSFbRtcA+ioiA3AKXzGObWWJ8oJ9IqKdocSooD4z1G9T+pDAHF6vPMuJNkowJpq
         SNRw==
X-Gm-Message-State: AOAM531caZmFxgc0u/1a68tLTWc3UWpiIVtYfyEy0yp+dgHlfSPfo9Ty
	qM33pkkiVWOjGa+kbLwBaRg=
X-Google-Smtp-Source: ABdhPJxkdNvBWVOmR+MqAi91peqLUq+SAVgzLdHRu092elMcAdhT1gaJKgLbKBFSW+3u8yfYZsMe+A==
X-Received: by 2002:ab0:23da:: with SMTP id c26mr9391887uan.11.1610717179407;
        Fri, 15 Jan 2021 05:26:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:ab4b:: with SMTP id u72ls495433vke.3.gmail; Fri, 15 Jan
 2021 05:26:18 -0800 (PST)
X-Received: by 2002:a1f:8d92:: with SMTP id p140mr10078832vkd.19.1610717178899;
        Fri, 15 Jan 2021 05:26:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610717178; cv=none;
        d=google.com; s=arc-20160816;
        b=omo66OW1IptBI3ksnmkC2rQkul7UFYfxsVzi4wnleddmcLSHGcwxTcB7xlhfX5Wlmo
         H+4ZzlyjPcz5HTGkR7qqbD8NjM8D/kO27AL23eXFb54HBw1ZwetV2UpOFfcBmFXKvwQp
         ThL/0W8O/8JfNFAx8gNplGEvbnobZXojtzQpjbzPG6E17DcGt4sww791fnBcJDD735uo
         eJG/JQLuBLFhOUP96tqN5qcMXo95fBjqNcvJO06cVkWXiOXr5hyM8xRu48Vk6bG3OSOi
         aQqUhGQvRyyREDZUAGMpXworYQDLbPVeEvcuac0NWfTyRXfOi8grIZtTPrMS9ZCrD23G
         rPdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MoaYJzIC4vPrLHOiSipsh4VQdU0Tic4GnbeNL7DPOG8=;
        b=ZnL7jdSE2ZpBu4E+wPx9hfWqPeFEdcC21Cpqhvoiuw51xPRw/ke5xIzqvCGgU7IfwI
         4Tu7Tux8gtPUJTIUKBkxfnYOC8apTGfhq2qDPuIkKLo6LgijSL9uDDETX4HtzxgSXz5n
         gwmz3Wttlto01RUd1IFMR0QaUe8FyG8ONpjFFpW6jOgh9APnodtrWwlfFe4yg4H60umF
         /eQWhvErdrl4KK4NNmKI0NviYwWISigXPSFU8BHhC8CVPv700YShRsZr0TdWxjJ14Lfl
         +Ud0aroWvkz2vBz0ndCdUmDk4yy6qyNaJKS3hkPUu62jFmadBi5001zvKCrHy7Ld2md/
         rh9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QG4SkeTa;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x836.google.com (mail-qt1-x836.google.com. [2607:f8b0:4864:20::836])
        by gmr-mx.google.com with ESMTPS id g17si648450vso.1.2021.01.15.05.26.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 05:26:18 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::836 as permitted sender) client-ip=2607:f8b0:4864:20::836;
Received: by mail-qt1-x836.google.com with SMTP id z20so5947006qtq.3
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 05:26:18 -0800 (PST)
X-Received: by 2002:ac8:6cf:: with SMTP id j15mr11577066qth.180.1610717178400;
 Fri, 15 Jan 2021 05:26:18 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com> <e926efdba3a1d9cccccbabdfcc17cef0aa8a2860.1610652890.git.andreyknvl@google.com>
In-Reply-To: <e926efdba3a1d9cccccbabdfcc17cef0aa8a2860.1610652890.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Jan 2021 14:26:06 +0100
Message-ID: <CAG_fn=UfAbZ6J0WNzkg_XsYJx7zMioUtMwYX3j6-7NqcLZSrQg@mail.gmail.com>
Subject: Re: [PATCH v3 03/15] kasan: clean up comments in tests
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QG4SkeTa;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::836 as
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

On Thu, Jan 14, 2021 at 8:36 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Clarify and update comments in KASAN tests.
>
> Link: https://linux-review.googlesource.com/id/I6c816c51fa1e0eb7aa3dead6bda1f339d2af46c8
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUfAbZ6J0WNzkg_XsYJx7zMioUtMwYX3j6-7NqcLZSrQg%40mail.gmail.com.
