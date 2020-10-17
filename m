Return-Path: <kasan-dev+bncBC6OLHHDVUOBBAWBVL6AKGQEN6GA4MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id D4CA0291096
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Oct 2020 09:42:58 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id h14sf3095059ljj.3
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Oct 2020 00:42:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602920578; cv=pass;
        d=google.com; s=arc-20160816;
        b=wORm6pvYZfbvh7ACl2fKedhj++xaMskafaN9yeYhcTYiaulVJsC2lOPzZHaXN0zTgd
         vd9c7y6IncrvKYLSdyE7HTmKIaxpJ5vjXpDRKMadOcIGx0/VFyUZZBnt29Fv7ZbNoRyo
         c7Lek6/Z4AfzoCWiO9BGkfJDP98sljRcS5OBxMmqS69NBW2DYdEW3Rm9oCJg7OvxE9+6
         qngFkIfRBTNP7Xt9+YE7JZTgFLMM17iMotAzkcztbbtSLVY5lb08MhTbjdQs8t8yHSji
         hYlmzdZVNPCRBlcGWJZwV40IL3cmU2te6zcOC/lRRLoyrHvP/21GP6y5P9OBUgJPBfPk
         eBHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6kkTZniX7TUgk4OUoJscDkePOE1+VY4dLQ5gFIW9R+E=;
        b=u9lH9yfGqNgY1xjbXVnXM+sy5KDckTiTjaquVpiqZ/xwuVC25HkA8exJ5FvsX78B3n
         sucGQ9qSerkJmhXa2A+Ow5cFK6gfgKGAIQWH5Joi+RJL0RIRFwB1W1zsiXZs453C2U3I
         /wp4cqlDaZWaYePomOCGQUHj+HrUNAiOTEwWtMwuj4sIa+4l+V4dcH6njWyo6SYiOuMQ
         EAItchfigiWaIkIDGXFFQEDJS11PCwsQdcd/QYGXVQhjyXSwiOpcKj4tDiX16sjeJHL3
         Zs/UvKuaks2/5Ew3qevG0+3J03KMRGhDaTK5ncxhYx/ZiuJdfuWJD5TjFSt/Oac6fU+O
         3vqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=S8DTt5Vg;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6kkTZniX7TUgk4OUoJscDkePOE1+VY4dLQ5gFIW9R+E=;
        b=tkj/m2yTzA9BLJcHRdpYXDWvaZCVyRqAeovHrizGmjlfJCciUy8Cdnsx3W3aeT5RjN
         QNkOQWfw4lfw/SLlsvbafuvNe2nzamuWpiJPKZAx50MosQutU1fIVQkpHV1tP6BPAUnT
         H0TYRex3U6AuwiFTk5bRp26OKkOLw/N7pUfuXAjVjAUoMg5HSBr3ZUc7DHFxDRPbCbcm
         cMgypT+Us95RycXwNc3UAktEKTfRUI2ZtIPvi0svz4lDlJRGvwh8dhAO5ee41pPe4ffl
         CdDOIAD+JQeMSTD01DbpLbpb6JU9UrDRWjwBuQkvv22+uA0cJ5+NIqpsKGACiGIryPJK
         aaEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6kkTZniX7TUgk4OUoJscDkePOE1+VY4dLQ5gFIW9R+E=;
        b=OBbsBJ4r+P3wEnQzef5MjMSjDtcGYey67MUbj+GQT7fApjvxt+WTAhWsSPS7QZwZal
         aAItp/W32IAkaIfICx49JtmS+yKvYN9GLnhk7VbYt4wBmfvmy2VTOsQ86E6V8pYUeDkZ
         LXoA2bEydDGMoQgV4qwGxCZvxiO3gnviCCjtzePUCu13c0yWwaocO+PehhguTVHE6duG
         gmRDjJJpr0lEl16s8PxqDfQnh9KU5wGTsWavjH/p+tq0YaiUpQszbwvr9B9nWIn9atbu
         K3cUHI5uZQwxSCgMuzwR4hn0VRRcIwb/IGUm+LBt7WalyHCjWVI7LFHSXJP6gk0AStvz
         XHVg==
X-Gm-Message-State: AOAM530GoYACU6emDhMQH2zuEmXdAUHXjfyyLFyEivj4KC+WdLqwAMZT
	KpEuxOyieC/MqPdA55UebdU=
X-Google-Smtp-Source: ABdhPJwXkCJ29HoCIOmbcNx4FaRbRn8KmR7Nst27nRlr7Pwzfp58lpbIxf6VM3gcAzlOYbFh3aPM+A==
X-Received: by 2002:a2e:9583:: with SMTP id w3mr3075956ljh.25.1602920578369;
        Sat, 17 Oct 2020 00:42:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls1577669lff.1.gmail; Sat, 17 Oct
 2020 00:42:57 -0700 (PDT)
X-Received: by 2002:a05:6512:6c8:: with SMTP id u8mr3019596lff.438.1602920577113;
        Sat, 17 Oct 2020 00:42:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602920577; cv=none;
        d=google.com; s=arc-20160816;
        b=pLEPppqw6qj1lVlXVyWztDf794h02kN59IOCSC2sevO/mBgsMn4cmchihjYZ1limBF
         7bmOV3N96TmdgaLqGSFKDYbBOSz8aUKmNLTfwm5EEVOVsBPlZLm78ZITNjlSSpbiZE9U
         1Rbu/RnoHamtH26w3+Gx/FweQLKFdZl2yRoxhQmVhRvjP8JXV/Aj7lTO8A/SSbS5siSV
         6c8G65ozz7yjxB52VSwesOaq5M3+zmCJpknytgoJWBL81JAKBGx1cXenkPg9qrbWFoDe
         fw1xyWJJUlkV25fDdiWruUwLzS6YbRTwPQYL3NnwicKMZWlDbHqHvRHdJypMjjIrnEaE
         kr4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8nuuz9yi8Y031tKgDWok/ahu1bW/JJ2vJv28TM2RgTI=;
        b=VpmmpPsDJYr4LKP56ReUDGUWCipcM7ysIKCYcMYA/vNPCWq6SuGJALSFP1yzOGXEe+
         O9UjHD4qdcAlxpBxmD6q0KxIvPcppsDRxWA+6YILpGVxMcQX7JgCn9QCD9WYnmPU3trC
         5acCkN/IFCq2gDImsYyNEp+MHQ5FyHMKPXdVhzLUpgKa9XJwQdvI034sJkk8pMTCKGTI
         sLGDKgMTVQ/FgebSQmU9yaNvu25EYnitF36gq56C+3aKVQw/a4vDHOe/W4HLum9W5poE
         DvFoU2hx9wcn/zfVA8dj24dSVx6ebg2t/KbI9wQEKVJje7sPgZdNE1nxHxlSm5TJeTWb
         7RUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=S8DTt5Vg;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id a16si161341lfr.5.2020.10.17.00.42.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 17 Oct 2020 00:42:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id g12so5891325wrp.10
        for <kasan-dev@googlegroups.com>; Sat, 17 Oct 2020 00:42:57 -0700 (PDT)
X-Received: by 2002:a5d:488e:: with SMTP id g14mr8889936wrq.203.1602920576419;
 Sat, 17 Oct 2020 00:42:56 -0700 (PDT)
MIME-Version: 1.0
References: <44861eaca17ffbb51726473bc8e86ad9e130c67e.1602876780.git.andreyknvl@google.com>
In-Reply-To: <44861eaca17ffbb51726473bc8e86ad9e130c67e.1602876780.git.andreyknvl@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 17 Oct 2020 15:42:44 +0800
Message-ID: <CABVgOSnMiNHZoj36NfHTuQ3xLOu-W7FqMnE93cgJv465Kv1QUQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: adopt KUNIT tests to SW_TAGS mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=S8DTt5Vg;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::442
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Sat, Oct 17, 2020 at 3:33 AM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Now that we have KASAN-KUNIT tests integration, it's easy to see that
> some KASAN tests are not adopted to the SW_TAGS mode and are failing.
>
> Adjust the allocation size for kasan_memchr() and kasan_memcmp() by
> roung it up to OOB_TAG_OFF so the bad access ends up in a separate
> memory granule.
>
> Add new kmalloc_uaf_16() and kasan_bitops_uaf() tests that rely on UAFs,
> as it's hard to adopt the existing kmalloc_oob_16() and kasan_bitops_oob()
> (rename from kasan_bitops()) without losing the precision.
>
> Disable kasan_global_oob() and kasan_alloca_oob_left/right() as SW_TAGS
> mode doesn't instrument globals nor dynamic allocas.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

This looks good to me. Though, as you mention, writing to freed memory
might not bode well for system stability after the test runs. I don't
think that needs to be a goal for these tests, though.

One thing which we're hoping to add to KUnit soon is support for
skipping tests: once that's in place, we can use it to mark tests as
explicitly skipped if they rely on the GENERIC mode. That'll take a
little while to get upstream though, so I wouldn't want to hold this
up for it.

Otherwise, from the KUnit side, this looks great.

I also tested it against the GENERIC mode on x86_64 (which is all I
have set up here at the moment), and nothing obviously had broken.
So:
Tested-by: David Gow <davidgow@google.com>

Cheers,
-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSnMiNHZoj36NfHTuQ3xLOu-W7FqMnE93cgJv465Kv1QUQ%40mail.gmail.com.
