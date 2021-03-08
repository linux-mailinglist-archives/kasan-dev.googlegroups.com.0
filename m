Return-Path: <kasan-dev+bncBDX4HWEMTEBRBT7DTCBAMGQEMOSLQAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A657331093
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 15:16:48 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id s18sf6509970pfe.10
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 06:16:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615213007; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gk8y7kpMbORCn52FZljzel1TnFkH0RVh9Yn0Wqu66mVMnIp+coRgvGkZ9wy5Aitmhl
         G3PcXC0CzT0QOAMQEr1z38QV508aWJZKLSYTF4Mzjn8G2OaqdXH5dSm90lZwDDtFI16y
         IbgSdPpcv6pQQQtAQaRC4zMuWY9XkcgmyAGk0tjd+OAO1q8mK2hbCYe4bBy1ciNTj/Zx
         uE6fG3frN/PWluDAgn94xyUWfR6FR0R/jhBerOtvX06alR82w7U+IaePUfH4GWHNig4N
         1ncyP35txb1M++CJce+b54Cc9i8fhTMy1qZuBtL0Gh8clYW9hQXGCEZeKLaS8MYcsO58
         fGNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DWq86z6maqmoAQzdN7KLYlujPjvw07FewNWypHisiZg=;
        b=Nujx8MIpYryuKKapqSZnYRmetSSHXS1QfMdMXZlPTnODKE+mZQVd81LjWth6wqF7+Z
         GhlBzlXQcaSuZMzNvqO/RgpMwCL7Bn2uI+8kubRl/6GANNxMuQJ5htHQBk4cBZQvimGM
         r4OVU//uTzM32VQiWNyTrRxwlKtx1oqIq7XEO/6Xao0RYlsg0sP/WmnZOmjc+INgEHFM
         LTBowB30A15GpnXizpTA5/gE6e19mM1JtTKoSDaCqS4kWC4nAvEAydXmc7gTa5ioKOUA
         I/cDSFYvcxNUV+e8Gh2aNCsN7vVgvRQOPY/nZt88rc3cVBN8aQWlTgKBOkfiY+oBtG/7
         /JLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="o+U3uLj/";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DWq86z6maqmoAQzdN7KLYlujPjvw07FewNWypHisiZg=;
        b=HF0RORSgkpwTMXtVq6luH/EE1b09qbcwixSIVo8AhUg0KW9tBJGwyazb1i5EkD2MYY
         OIe9oiK3QfLkTFyrZOZss/t0O6o6+Kz1Vs/qSw2ypg4GeCrY7zhJePaMrpGnAkfro0bD
         VuaqLgSqEnZ46jjvnw4JTcsSeG6DLlQVoTmfRpzotpPYIVhSAWHogwRRA+nPbO/e+VmA
         xu81NiiLcV3Volzi8momXb3iFcvoQp/3gmPb3i5laZSvIbrz+lMTVRSCfFIfII9fR8ZU
         82xPEvGDDkixt6fpAvFp6kqC+sbgIAKo2Zw4igwPX2aGQeuK8BJrV/LheOx4VXgAhxwS
         2KnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DWq86z6maqmoAQzdN7KLYlujPjvw07FewNWypHisiZg=;
        b=DohWCUb04lw/hS9o8uKKDEHY7diPDisvTtV0YSAjI4VlXwBcADu/i103N2hXVCtP8K
         RaBdwbk80pbtUOz3rFrAp0Ch+cU9TGgcb7jwlWxpjuzTWXR38C16fA9L2q1VM4DI7kl+
         nxaY/T3WAmUZTawvh/juT27UDkbSLVOgYlGIhNkGBDpABh36idSlAdcNxFhKR8psYLWX
         46z5R2l15llrhWLIxkivOY62JUFFSjQqKYpxx9NjZKy8IWPUU8S8zBl2Z7JONt9IQbc3
         zofGMd1U9TrKv0WafSIRSoCa0EcmPv109GxzfoOj3RIqUjCGoFFgAj7USIoxMwEEDSeo
         rxqg==
X-Gm-Message-State: AOAM530hC4Scjdt+Ye/TFl0ko5s/l4+o82imIm7zOMBcDQnEK8Ha5KDA
	xjwlckNXSwMLfcpxKwchpdE=
X-Google-Smtp-Source: ABdhPJwtu6QEwKtiTL8KWIS7qoE3PK8zox2zfJ+9ydGcjmd6xfI6a3vjZXM+V98z+RQkm7S635glgA==
X-Received: by 2002:a63:5416:: with SMTP id i22mr21065227pgb.43.1615213007333;
        Mon, 08 Mar 2021 06:16:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:ec9:: with SMTP id gz9ls10236021pjb.2.gmail; Mon, 08
 Mar 2021 06:16:46 -0800 (PST)
X-Received: by 2002:a17:90a:9303:: with SMTP id p3mr23964202pjo.201.1615213006830;
        Mon, 08 Mar 2021 06:16:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615213006; cv=none;
        d=google.com; s=arc-20160816;
        b=W6JzkL/yBTIGw5DcaI42j92ttevdzZJFdrBQZY2vjOHSJR1WYwAbd4TAyREv8uMAVA
         e5Tw8Lk+dFLvDLx4iKZUzE/7ihnNI0gx/hc+puHl+z13oDiWlYLHQ7WiZHIlf67cyAcX
         ECj+rT8672XFY/5bLEq5ExCEethQkVh01y0BcUxy1c+VPzRmrpQdRds+k2OiYYobh6y5
         ZwJlOn89xD/6bvRw35e0p16LB8XKTY3zHNTyyVFkojsBqPI1J6ilxbYZjTFuKK8TiyQt
         eOsjIsGKpRZSeeIj0W/lqGRwNTIGUUj18ffDQWQvnOz9ejwK34HC36TKGQOZe+VmRI6I
         uuLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cEz/5tRpd1vxpBiKzm6wcWNrysLEXvrjN5n42Rt2ppk=;
        b=FEDo+3AlRGNJO+gaIZ8gPD2vScVFIVo8Ik4MmzgEiyyCNoH/DvJFHhRbQResYG6K5v
         kr85HrIyrje7yAYFpZvNxTJZV8osrIlIDOpsp7N5p4LYc/mJaRqD2za+NVc8vpjxotk0
         Sh5FHmVVHmHJY+QspBLIIV9R5CkSeYg4sEBthCI0XjmTLcn7hlLEWBa1NMwrxkx9lLQ7
         RGHQJ7bB317Xc5WP4hJSnUBHjUuwUNEJtlT2G2wAX9fs/dUXWlOnMZLPyK8MiqnrTixb
         yY3VJtY6DGTOp1j0X+JTX4aTZa0rUFcA2eGCUex4k6cFv1gzex1q9wG93KYzIIj15EyI
         /Deg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="o+U3uLj/";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x533.google.com (mail-pg1-x533.google.com. [2607:f8b0:4864:20::533])
        by gmr-mx.google.com with ESMTPS id n10si675867pgq.2.2021.03.08.06.16.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 06:16:46 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::533 as permitted sender) client-ip=2607:f8b0:4864:20::533;
Received: by mail-pg1-x533.google.com with SMTP id l2so6486384pgb.1
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 06:16:46 -0800 (PST)
X-Received: by 2002:a63:f14b:: with SMTP id o11mr20763989pgk.440.1615213006419;
 Mon, 08 Mar 2021 06:16:46 -0800 (PST)
MIME-Version: 1.0
References: <cover.1614989433.git.andreyknvl@google.com> <a313f27d68ad479eda7b36a114bb2ffd56d80bbb.1614989433.git.andreyknvl@google.com>
 <YEYOaR5jQXe6imp0@elver.google.com>
In-Reply-To: <YEYOaR5jQXe6imp0@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Mar 2021 15:16:35 +0100
Message-ID: <CAAeHK+x-V+VqGGpjFL8wSSNazOUjJ_OMq=nk0O1mTJoZwG8XmA@mail.gmail.com>
Subject: Re: [PATCH 5/5] kasan, mm: integrate slab init_on_free with HW_TAGS
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="o+U3uLj/";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::533
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

On Mon, Mar 8, 2021 at 12:45 PM Marco Elver <elver@google.com> wrote:
>
> >
> > -     if (unlikely(slab_want_init_on_free(cachep)))
> > +     /*
> > +      * As memory initialization is integrated with hardware tag-based
>
> This may no longer be true if the HW-tags architecture doesn't support
> init (although currently it is certainly true).
>
> Perhaps: "As memory initialization may be accelerated by some KASAN
> implementations (such as some HW_TAGS architectures) ..."
>
> or whatever else is appropriate.

Will change the comment here and in other patches, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx-V%2BVqGGpjFL8wSSNazOUjJ_OMq%3Dnk0O1mTJoZwG8XmA%40mail.gmail.com.
