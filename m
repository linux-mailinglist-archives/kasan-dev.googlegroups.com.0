Return-Path: <kasan-dev+bncBDX4HWEMTEBRBK6JTSAAMGQE255WI5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id C93EA2FBEEA
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 19:27:56 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id k7sf12522700ioj.5
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 10:27:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611080875; cv=pass;
        d=google.com; s=arc-20160816;
        b=wnDD7AwUTg1ary38W9O7h8JrzZ1nqemZqYeOedcsKzYmVp3B9/7GXTO0zttagaVeSL
         blM304HVmXFWPZhUEsCYPUS7JltdNDup7OyH9vHpQSLxGmchXFvuKWRD19uAog+tnel+
         JG3SRfJ9Q/jMJNc5CFbGGwz8BmcIL6crAaTaoAq4lCyclhvmWBmaGCrgU3cAaVofwXFn
         hOin4b9w+3c2X80nPiVHGNeFhwiWGWBAqtO1C3Lb428BwVKOlWG8Npy4xS8cLOVv8AGV
         cb2qZks63+1PoxdzY43AkdDCavKU15cFgk57YN5/shm5X7TgwVvpKknqwJ+mG/MXAn2O
         SVsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=D4a1OmEckZFFPIMIYXcG+Hv81h+SxbeC3cYUjEzzlGI=;
        b=GIbCnyOXI3mgv/MZLoJtlL3eFvsv0ZE1gsBGTSy33EJg3qxsl94sjZTJb73YirhQ6b
         WiSzlWT72BXXQF4l69m0F8I2ZNW7MdIeY6GuunkzrNTe2RQnzlIBEmAiuWrnQmzQs7sG
         /oJg5DmBHhEyr1fVvR6T9kzMw3V27dQYgoTwcfp232+37Y3AByw5vImvyep8y2/GAoFt
         WI7XPC0KnpShQSc/q/WFkOy8SFqRJ+SxjdkNP3ePa5WMyJO6ywZCLELCaCRdppehiIRy
         04RgU3TSp66xIbT1dUDqcz73BCkbfXqjY07WTJfLISxSCXgjEzJLP9ArfTNG4IQBACQt
         z7Og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Uiq65l8V;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D4a1OmEckZFFPIMIYXcG+Hv81h+SxbeC3cYUjEzzlGI=;
        b=rVvjvCrc86CyccvLv9olOEkc9baqwauV8PV/4/9dwEL74n+vaDW3W68A3kkpodTFOa
         BR4xkUR7dr+4a7m/mXcfjd+c8itvWebD8xErTuOyitTSGbVlCDv0jCCSV0WskUMkr/iL
         q8bX252sTXvKFsvA58v5cGkyBYa93gzwak9VKvJXCJPIngHMIVlTrlpkVbype+EwpmMo
         UmE9cCbWAA5grWGlIgXtwz77qKgoxSk/qWpjvyV9TVWec0GnaD0McCOL8qeoXVDEJEsA
         z3AsshHGOmB8s+vqGE9ZS9OoA+QvtRwvO8qetXwSXEbqvo785/ZhiE+BTTY5NBLb7Crp
         rUPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D4a1OmEckZFFPIMIYXcG+Hv81h+SxbeC3cYUjEzzlGI=;
        b=BGndwM7YFPFssn/cUAAL37nX4yhNF8N3Or+r0qxiE4dwQ4A67FcHOTs+sfbJdQFmLk
         RYeq+K2t7VkDCLf2PXXrJNCUTs2WpsxAvEqW+zlYNLtCMfCXwy3KLbuOzlWYxBRKZHmM
         8tmXni6qEVflOpArpapzEB5eytCTf5yUQlndODGMJ+GM+j+Htnr4+jhn8bmUn9BCnL8/
         9KbxAtFGveoFznLGg8Jvz1LXwH88hr13VO9FrP6whtxOmeax8lFV89yPLEVzpqq0+Pv1
         xUpgUEwNNvZUGr4jkEsJd2eb7fBFjw1P+1S3YaP0HhW+3mlrjB1lcryjVk1GIsTd5PVj
         /mag==
X-Gm-Message-State: AOAM532T4veD1ss61roGDX4iGHbPRWSrIIhWd4z730fedZSkSczKCDnl
	7U/Gc0fWUkTJf9W1TbcTpnw=
X-Google-Smtp-Source: ABdhPJyJKhAI6LY3HlANyIF0ueq5iDbxT6OhRClk0WJH+Un55YWvTz78M10zxDlgfJ00qKGkCPFHPA==
X-Received: by 2002:a5d:940d:: with SMTP id v13mr3913687ion.193.1611080875620;
        Tue, 19 Jan 2021 10:27:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1c9:: with SMTP id w9ls1269943iot.2.gmail; Tue, 19
 Jan 2021 10:27:55 -0800 (PST)
X-Received: by 2002:a6b:f714:: with SMTP id k20mr3954588iog.70.1611080875304;
        Tue, 19 Jan 2021 10:27:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611080875; cv=none;
        d=google.com; s=arc-20160816;
        b=Ma/e7BDTbalz1uu5LEX1pPLf9YJCAjhOa4CHFm6c5uqRjwnITasi7kV/L6PRJ6GriS
         IPW2O9u9QaM+rnSM3eUwchGgJsGvT+0W/Vufhulk7tIUzum0ipLRssoo7SjNzIV7XfBE
         8WGXreiWLaZvJieGfsULhiys1s+zk/Brsl59gSGS6SblfkXE4AiVXwIC6pM6wWQDNWej
         eW5OVh7pnHHiB/aR5i3JCERGxGMApDnwksU+KvlVt6M1k7/DIGfDPr8n2G77z+28CywD
         acscPQCFR0A+555pdkBlfO4mvrE3jUBDSksOQX9aFZ8MOUyuUGdCbdaOzXkCqWPShUkD
         0Ltg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xFLxK6nMCFTrJXHPH6YcjllJugTgrT1zJQopVJstuMw=;
        b=H0/BTwS+7cT+IvMZMqckVz3SPh9U93b2+uzoImObM8A6EGuTWf1EVwF/ciP5VHO+I0
         zr5MWXlO4KlNnHxl798FeX+TQ8ePFgglZfIN6qxAIM8s8mGLXDZTzKjafMy/EdqSMcbh
         hSTLwkkNv7Jj4ORRQzeAr58YVDkPTt38Ng7wQ34iwKWz883EXQFTKpR5ukRVU2h07M5K
         d8rRjZxL34Woz2KeG9xaFDYK78cysVIhavPggCwnydwx9kVNw7ZlxTbOrgvfzPWUUXvU
         ZqFXYGUgDQxdPxduFgLJZ+BwxMJtZ5MwTehb7bnuVMK7JhMEclmC1DyL3w1rOn9g0ptp
         7xYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Uiq65l8V;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id l6si718667ilj.4.2021.01.19.10.27.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 10:27:55 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id c132so13496578pga.3
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 10:27:55 -0800 (PST)
X-Received: by 2002:a63:5d3:: with SMTP id 202mr5563083pgf.286.1611080874934;
 Tue, 19 Jan 2021 10:27:54 -0800 (PST)
MIME-Version: 1.0
References: <20210119172607.18400-1-vincenzo.frascino@arm.com>
In-Reply-To: <20210119172607.18400-1-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 19:27:43 +0100
Message-ID: <CAAeHK+zpB6GZcAbWnmvKu5mk_HuNEaXV2OwRuSNnVjddjBqZMQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: Add explicit preconditions to kasan_report()
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Leon Romanovsky <leonro@mellanox.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Uiq65l8V;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52c
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Jan 19, 2021 at 6:26 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> With the introduction of KASAN_HW_TAGS, kasan_report() dereferences
> the address passed as a parameter.
>
> Add a comment to make sure that the preconditions to the function are
> explicitly clarified.
>
> Note: An invalid address (e.g. NULL pointer address) passed to the
> function when, KASAN_HW_TAGS is enabled, leads to a kernel panic.
>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Leon Romanovsky <leonro@mellanox.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  mm/kasan/report.c | 11 +++++++++++
>  1 file changed, 11 insertions(+)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index c0fb21797550..2485b585004d 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -403,6 +403,17 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>         end_report(&flags);
>  }
>
> +/**
> + * kasan_report - report kasan fault details
> + * @addr: valid address of the allocation where the tag fault was detected
> + * @size: size of the allocation where the tag fault was detected
> + * @is_write: the instruction that caused the fault was a read or write?
> + * @ip: pointer to the instruction that cause the fault
> + *
> + * Note: When CONFIG_KASAN_HW_TAGS is enabled kasan_report() dereferences
> + * the address to access the tags, hence it must be valid at this point in
> + * order to not cause a kernel panic.
> + */

It doesn't dereference the address, it just checks the tags, right?

Ideally, kasan_report() should survive that with HW_TAGS like with the
other modes. The reason it doesn't is probably because of a blank
addr_has_metadata() definition for HW_TAGS in mm/kasan/kasan.h. I
guess we should somehow check that the memory comes from page_alloc or
kmalloc. Or otherwise make sure that it has tags. Maybe there's an arm
instruction to check whether the memory has tags?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzpB6GZcAbWnmvKu5mk_HuNEaXV2OwRuSNnVjddjBqZMQ%40mail.gmail.com.
