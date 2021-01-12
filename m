Return-Path: <kasan-dev+bncBCCMH5WKTMGRBA6J6X7QKGQELJBJTKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 356372F2A69
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 09:57:40 +0100 (CET)
Received: by mail-vs1-xe3a.google.com with SMTP id b18sf287115vsd.19
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 00:57:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610441859; cv=pass;
        d=google.com; s=arc-20160816;
        b=T9q+3fM/eJz0qaehfB5IP88cGBuTxI2cOECEPlDzbStbUjRwEDUfCiRAPA87xPsW/D
         XdBxD8qQTOkadhcz2P8R1KCsgYG2XNmaFieJf/cHI8y0Pl+QZReHDvlMnSTQdorrKhuL
         15aeRdmAe7Usehyh2ZXnsa45psiatm+FD0iRBb3XCccF18DK9fIVmripR3phlO8TnF6Y
         sGzy9obRK3HI1tZ30Iaru28D6c0ZCK0cwsJzFhqeLLai6p4SckeUFgTZgmIoicWfUMA5
         7DvDZQUEMC7VQoCpZbI3QIUP/05nZ55Cj/kb3y7oLFKIcYE5w7WpgsVf7lldsODJK+z0
         554w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bUDGH/03wbcBdNvDA2ohUKmMYm8GgugtxlgFPm796/w=;
        b=xsrI8S7aSeT/7g18qMSkV8deNSgyzWWogF7z+UEz95Zlj5ngd31vuK8OHDanHICnTq
         mzjHRYN/KlL+522K7pEu/3+lmsszO7YiEkCLf/IQrhWb3cE1Zg9M+ts7Sfo3z7/4LIRu
         v10eyL1Yboqww3h4aehg3+L0zyezXFA9leBHcnxoYZcW5OB+p10s61sM/Y3gr3z6xqPn
         dO9wTT02k0/eeRKVoOwKwt8h2UQx2NV/h7DbAqClbrG8jFr43JPy9qpYyrGfrgWauPxt
         86t+gOEO2qMupj4EKUlgusIfdrGClUd7xagBfhtM523HSVT8SolSa2+BCn0r+CX1O/yh
         d+Nw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bPcct8nv;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bUDGH/03wbcBdNvDA2ohUKmMYm8GgugtxlgFPm796/w=;
        b=U3Ct7oCzhVLgYqvWFLRJ281ItkG1hW/iEM1arstS5xPPV0UvrPpgoUMFBD5o/o9wwQ
         6ZtT1Asrx7PeWvQ/ZQw8KBbMXTrf+tOqPCtWb09GjOK8RUQ1oH83QPKFR0C31WXhtn7K
         YkrZo9XsHLD40xhFbNISnISqFNu7jOKAXiM5+jAbWu5s7CoYKuBGm418jdqFnN/amQyC
         KuRWcCjVvca94YIEf/ImuApl+T1FjkI//HtGhLX7SYP69wvFDfDJ2Dw73HJ5Zrl+GLuf
         eMN/Q7HVC51DnUzjWaPAOFuQktQ6fMC10KQhMlZjiK6lsj/F9NRJJe0dMjATSFTO6QSN
         Mf/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bUDGH/03wbcBdNvDA2ohUKmMYm8GgugtxlgFPm796/w=;
        b=dO2HcKI1KAB+6N06Rn/hOG6DxirVeseZHIHZJr+z+VMlhV6n8Ay7hkGxGBN81nF3FW
         U/RLCIcVjcoF3JWPa8Id33MPSnqv1E/3M52HcU4OWsqpgLEhKeDIucDdEEpJWK1fEDSq
         cXq55j45w3uhLA1YHMRgugrp32urhTsMlgFcBpDqaaqdJQkYlay4mK8fvCdQ7tGZQdUM
         NjUgp35+3E1EfN+mv9718aq3L71k+ooEAhXKKISJ6B524ApRGXPTHrdoCdSQqe4CISd4
         DBRJN7Ny9kz2bUhCvuU54YZtZ+USbiz59WVBzhXbgGXkNyfn5gdZ9Tp0ZBkwVI98KGGU
         y/2g==
X-Gm-Message-State: AOAM532WauoPyUpagj1hjTLRVoD9GDXsE3odtg4D7yxfblcZi7Z6zrfv
	K9Dsz+q3dMxL97jpGByHWmk=
X-Google-Smtp-Source: ABdhPJz3hPX/Ze11DawqrxWJvBwr3eBAs/blhiYR/ZdwAPs3w3TC7VgPVe5e+gVLCmP8+jV5aItMtw==
X-Received: by 2002:a05:6122:8c:: with SMTP id r12mr3151515vka.24.1610441859347;
        Tue, 12 Jan 2021 00:57:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f457:: with SMTP id r23ls76290vsn.4.gmail; Tue, 12 Jan
 2021 00:57:38 -0800 (PST)
X-Received: by 2002:a67:5c03:: with SMTP id q3mr2860853vsb.47.1610441858850;
        Tue, 12 Jan 2021 00:57:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610441858; cv=none;
        d=google.com; s=arc-20160816;
        b=w9Zf/F0BZoOSB2vV60N7EEShgTiSnxb43Kh2WUDwVTpGGjsuOoFEYw0GSdM8v6/e0x
         WWAC5RLxB+Ik3erW/zQZaXtXlMXaK0KXNlha5VD01iNTWZYhLT8DMan5NojU9vaLaMaW
         llXf9BCyV5TM1JlKwMWoKsraKl4erng+ZcrM236aNIQ5RvP/Cz9cQlnNImM7mQxdUC29
         psnaV7bPpmetR505s9BjNccxwTpm7h3ZI+4BEqSnPgbbRrkT0KY3xjZSIdzC6uuHal0N
         QZTZgMfltHsyzfNmo6ZAyREOMrwTqRiPHnMg9W+ny77X+/1AA1iEaiORNoDOFfAscYNP
         ymaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hebm0dWwRuXQzzZ6zng4XzueSgh0hzQ/w7cKVtFlvCM=;
        b=qdfVrXghePhveJt5/a4Xd1nDNClvFJ0zllN+Y2p4Hlck8mc288K7oK4grAlwlfl+bP
         KlplVkLBMayb44BnubTOkqxmFwvl9ENPl1URRYmsvzI5b+5U4V/jAXj3xVLMTaI9bVMW
         KGI9n7LmRfQzcOaZG2/2dy7xidKG8ytfFNUPSWK2lf+MQUJPuuRDnK5k6xOf9Yp+fiQp
         piGchu/MWO6HVA9vjCdKLJmTkB2yiH/wjLGGw7ir/CdCjmDaiQUCJMWJfigSZMWWPBHs
         33WlDkbAXnvugJjY7vII39c96387LXDcSI2CyiamZMRGcJvkdMnhLYurYl1JfcZyUgZe
         jzYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bPcct8nv;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::731 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x731.google.com (mail-qk1-x731.google.com. [2607:f8b0:4864:20::731])
        by gmr-mx.google.com with ESMTPS id e11si198584vkp.4.2021.01.12.00.57.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 00:57:38 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::731 as permitted sender) client-ip=2607:f8b0:4864:20::731;
Received: by mail-qk1-x731.google.com with SMTP id b64so1206660qkc.12
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 00:57:38 -0800 (PST)
X-Received: by 2002:a37:70d:: with SMTP id 13mr3424840qkh.326.1610441858281;
 Tue, 12 Jan 2021 00:57:38 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <15ca1976b26aa9edcec4a9d0f3b73f5b6536e5d0.1609871239.git.andreyknvl@google.com>
In-Reply-To: <15ca1976b26aa9edcec4a9d0f3b73f5b6536e5d0.1609871239.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 09:57:27 +0100
Message-ID: <CAG_fn=UiqTFkrDz=0vPdWgjvVA8702oYXxvUh5fDadgC1cm0MQ@mail.gmail.com>
Subject: Re: [PATCH 11/11] kasan: add proper page allocator tests
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bPcct8nv;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::731 as
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

On Tue, Jan 5, 2021 at 7:28 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> The currently existing page allocator tests rely on kmalloc fallback
> with large sizes that is only present for SLUB. Add proper tests that
> use alloc/free_pages().
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ia173d5a1b215fe6b2548d814ef0f4433cf983570
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUiqTFkrDz%3D0vPdWgjvVA8702oYXxvUh5fDadgC1cm0MQ%40mail.gmail.com.
