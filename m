Return-Path: <kasan-dev+bncBDW2JDUY5AORBC6VY6MQMGQEW2AJRBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id AF8D25EAF36
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 20:08:12 +0200 (CEST)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-349f88710b2sf69574907b3.20
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 11:08:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664215691; cv=pass;
        d=google.com; s=arc-20160816;
        b=i+ZavATpzCXYo799UlUx5eOnileDtBbXEgUX6oZCTvj7ZD8KuukXCVAeNQrIwV9lVT
         qtu9SRUapi2ZgcjfuI9suF4zPjLrFKkS/vfQJyqg6gO9HpGKuWyG+cZ3aRx68eVm9J4Q
         W2N5BVakSHDeJfNyxnL6vXNrUQPcMhplyH2372ip9Ql2aYvg85R+OCEFZPHD3kuFAz/x
         1FjvPPM8PTwuvJeZqFGl0UnB5m+0QPZYev2GLxI4+hNoyrYXmRT7To0XjfX++zZFVtVR
         W1yCaez1DJU2dm9LgnYcJZKb4PnPsHq8W9ObCWm2tjRm3mbMjRflBG2mc+bhwsgbnW5N
         ofHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=h7xk32oV1spxlpnLWgSKc0H9t+jJVqVqLsfIAuqAQLw=;
        b=dUlRoxegpRwQYChDjYAhY94wo/lXoy200isWqqKmx9aVokk1zZvdTh/VypzH45vJgn
         QFMihsBB6BH5gsN42LU2oK/a8YoSVs5fUav2Ndueqr1i1qWZu2BoWoqqpGPMtg7BRIrg
         C3oatsW6N6l0OLtO+VMUR0xwViRaD2RZrHNONLi8Bmt/av3zTomlq3iO0SXYm8LOELAM
         B+g23UkaXDhe/V81nAFPCvS9xrrxQie5FaqRrDGszAJEwA4JVKA8mHgWGw/8ks6KHEAp
         7JkwkP+C5KPoZfdL5KNatAZFpe/PKzHLwtZlw4yjdiMquJg5FaevnVE3Pwsa6VXPBxLb
         5jRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oVxNzol0;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=h7xk32oV1spxlpnLWgSKc0H9t+jJVqVqLsfIAuqAQLw=;
        b=sVR9Kno1A8kQtD4goJeVfZhhBkgtC+0aZQTLFnetLeACdg9Vy3zAmj0EWMVlOlSOvZ
         O7xkw7qerypJ7R5RT3Mudki+wMoCxtssiSWrnxQVW6k/EVBR55ZMnkXR4YH0OfK8Bxrt
         ddUKt32MF/XS9Oy70GC84E0p3ipSgd00IAdwm6zJZEUG5GvQjunyHnwp6ZbXTfBT/ZKU
         Z36INOv+POIGm74D7eTplapKm2R/IPrsSEnAWVt5dmwbhDGkqg83t7CkLMeUx3UdtEiY
         gYRHizNltlNPvedlebAIrm9t6vmJpk3+0/ItMP8wgxpFEDzSFQQnN4/FFG6RPX5WxTqa
         kztQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=h7xk32oV1spxlpnLWgSKc0H9t+jJVqVqLsfIAuqAQLw=;
        b=qqDQ1G2QFdT2R6VCMrjG86hYm8P4nq118vrYMIlNxNBIJBKMWt+TE1NpmVUPdZgLIb
         fTyJUHbmfze3ZNkSoXYC6IeHTr8n12CEDMhL/hVkl/Hq3v1yVTnN+RUagMHVdGrtVfw8
         NXuTSkf1G83TcixSolpfiPmbztgfFGMUoVEdHyWYtoS2clMpVzhm0+1zZzhbP8lnz01c
         yrSiWP2Q/L4a6IMttdDopu0gLb9QDy6nfRglKskDJzj/XB4IlPiAveovG1RbE7ymCH+8
         vP3nc5w7D47znk6LTZ8hsxnDl3K4VJpui74utiTdQpoP8Yo9mHODzUGggMFFjP65xqic
         7vBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=h7xk32oV1spxlpnLWgSKc0H9t+jJVqVqLsfIAuqAQLw=;
        b=k9cyXUJW55KDffCzp+1fOxkpBxUX3cxHcxxwIVmqJvreRG9A2QbLcXc2Qwe/qaSF0G
         90ArjcvKMutcN0EGSEg/gJIRMRg0oeEp84a6t8Dtrv697pVB4BhzikbDGLrH2IQrErZU
         +YlJOuxg3t+UNQ+Nn8E8eWHi67Qoxv4+QxZYrf/fx/0YJSxdyIv/n/ifB7RHP/y0ltJ5
         kj8o2KcH7Tk2Z9PJw02iwUEc0jZRKW1ki2TpozRbrnIwWksWr0Z28+/odq5G065APp5G
         J2IkqiB9qEys96JCCmU1BXcPLqL29jid85bAPx1faxpu5pLM68IMtPgATHeluKotKNE6
         XuXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3EKv48cQJ/e9jgqks1QrE4Y7AhKWJRemdhp1nSCpEsc2W0+gnT
	yNMZu16hgJidJ5a2SM5zRZI=
X-Google-Smtp-Source: AMsMyM7skFrBV+hlT1/+jTd0fecT6L6mKJXmEusLPUqg9iIYM3y9h/SA4dglTvCaWrCOJ7YGXtCH4A==
X-Received: by 2002:a0d:df44:0:b0:34d:901d:8734 with SMTP id i65-20020a0ddf44000000b0034d901d8734mr20420853ywe.265.1664215691503;
        Mon, 26 Sep 2022 11:08:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:668a:0:b0:349:d173:3c0c with SMTP id a132-20020a81668a000000b00349d1733c0cls69579ywc.4.-pod-prod-gmail;
 Mon, 26 Sep 2022 11:08:10 -0700 (PDT)
X-Received: by 2002:a81:1dd6:0:b0:349:c9c9:eb61 with SMTP id d205-20020a811dd6000000b00349c9c9eb61mr21649761ywd.7.1664215690905;
        Mon, 26 Sep 2022 11:08:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664215690; cv=none;
        d=google.com; s=arc-20160816;
        b=GGX5N/TcTaJGhvwGxQcDI3BG5ekrvjF3q4T2nSo2VVYjyTmAFzhfQB6tfjQCPxvZWo
         ry9tbaquMOgPJYaHl2B3C7QhUs0+5H7jcOJK9EwgSVW817hchHqHD+3vmHmQBIjRJ16H
         fQuaClXAW6OifHp5vVfwkJf3Dilq3SMAufpo4XaC20d5RfkcM0ZM259XX8U6Xg7K7EB/
         wkPpSqAjao306Dp95rQYq8nXCzeEuoGs8N7/05dFQUihYZmQnqE0B8CLMOIaz7ZZgi0A
         ZcrncAeYYH5BcvL5CAb0B3RL6UIC3bClPcS7KTvqmWZquH+cIJ/4UDHoBWurrUu8LTHL
         dZ5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zbTeqblGxrVphEvYs4g+Za5JLZuDmNmIQK0NJlTmwT8=;
        b=DBQ6IuI+Q+BRkDX3NgEGJRRU8cgxA6uWQ6pe9hU1JpThfWwC9m39ZE/p4uNl0uua0D
         onC4+jaEZWJkLO3qvBeEKC9+/dm4J3zY/m8cX82KBRi+0TdEp1vSsBkjYdIxQZJSDLeW
         FC1j+QETcliLf6cN0dKWovIBr1KkXcsl+8sdSMAlHwTvGTZMC7yvV4bwuCK6TxLKfLkc
         JX5gldLCWr1uv0JCB2cjECkSUQgyNxSAYy3sW0wX8KiIsO8Z/suimsToB5WDgaHmxcwT
         Rh3NUdwEpi5OBqRIMu5DbZVX20W8DgoimQA8WlCdph7KDaACdlUIOWeZe+d9ODBRHcLU
         cHxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=oVxNzol0;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id u196-20020a0debcd000000b00345525beb25si1575284ywe.2.2022.09.26.11.08.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Sep 2022 11:08:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id h21so4626911qta.3
        for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 11:08:10 -0700 (PDT)
X-Received: by 2002:a05:622a:8b:b0:35d:430d:e53d with SMTP id
 o11-20020a05622a008b00b0035d430de53dmr3962001qtw.391.1664215690624; Mon, 26
 Sep 2022 11:08:10 -0700 (PDT)
MIME-Version: 1.0
References: <9c0210393a8da6fb6887a111a986eb50dfc1b895.1664050880.git.andreyknvl@google.com>
 <20220925100312.6bfecb122b314862ad7b2dd4@linux-foundation.org>
In-Reply-To: <20220925100312.6bfecb122b314862ad7b2dd4@linux-foundation.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 26 Sep 2022 20:07:59 +0200
Message-ID: <CA+fCnZe3SYq1c50hKdR3eoALz+kHE2MdUkbcbG0dhUFjaKkPNw@mail.gmail.com>
Subject: Re: [PATCH mm v2] kasan: fix array-bounds warnings in tests
To: Andrew Morton <akpm@linux-foundation.org>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Kees Cook <keescook@chromium.org>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=oVxNzol0;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82a
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sun, Sep 25, 2022 at 7:03 PM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> > --- a/mm/kasan/kasan_test.c
> > +++ b/mm/kasan/kasan_test.c
> > @@ -333,6 +333,8 @@ static void krealloc_more_oob_helper(struct kunit *test,
> >       ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
> >       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
> >
> > +     OPTIMIZER_HIDE_VAR(ptr2);
> > +
> >       /* All offsets up to size2 must be accessible. */
> >       ptr2[size1 - 1] = 'x';
> >       ptr2[size1] = 'x';
> > @@ -365,6 +367,8 @@ static void krealloc_less_oob_helper(struct kunit *test,
> >       ptr2 = krealloc(ptr1, size2, GFP_KERNEL);
> >       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
> >
> > +     OPTIMIZER_HIDE_VAR(ptr2);
>
> What chance does a reader have of working out why this is here?  If
> "little" then a code comment would be a nice way of saving that poor
> person for having to dive into the git history.

Will add in v3. Thank you, Andrew!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZe3SYq1c50hKdR3eoALz%2BkHE2MdUkbcbG0dhUFjaKkPNw%40mail.gmail.com.
