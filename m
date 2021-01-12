Return-Path: <kasan-dev+bncBDX4HWEMTEBRBX6T677QKGQEDLPXCZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 854352F38CA
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 19:26:40 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id c21sf2186837pjr.8
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 10:26:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610475999; cv=pass;
        d=google.com; s=arc-20160816;
        b=giyYYfiQlfgOjstKjJ3lE/CqaFLISJB7pOWdH5Cttb2M9mnfmo7bK++/Z6UBWbhuDF
         RG/lwz59L4kB1rF678wHxwUU0yovIO9AzPuvJoR45ojLnLTsOXUH64zcZN3wjql57EwS
         kql+FQ+zDYWR8YIsgTJKBhuckkGIiSJ6WE+w2I1JAoXTu3gu5Cg2bNTuriJad3RVmeSZ
         QEopT/6g/ZnX1NgrAtlE8i8rm4HSlKzD1FQO3Ssl1gNhk5W2N/1yXlLSC+G6oYkXxUOc
         arxZwdItfFReEZmVITBiGqR2oZgxgj1FE20q6bWc4FDksH4/fNkPFq0Y5euFHFYo9jwo
         ZUmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nR5c65S0h7SP6OXM/wNOZQyvfws5a3ff7+YpNqF2XCg=;
        b=Ii/0CSpLvC75xo7sjWxZKzcVeHNnzQu7zf1CC9uxcYPMOUWlYHzJJX59i7S+V4yY6X
         tmcPFMC5C6GjWeLyVyLfLqtMKXWwtDh5kz5PLkM7gsvX3pox0jMznOQR1g53DgPd6OhL
         6qdhK4a8nDyCMQS8iAmTJziZxi0OhJAD+FghtoNIVf2Q3ZPQO9R+MzO7C75PSWRvVFzB
         Y5ODrRDiyFxBjNHxGCpMIXxfEWzjd7bxubFBLaRSWLjg2k/6YH9/Rk1tY0qOQBkvUNKx
         j7CG9X4WAL+BlWWSgsPszT5sX7F0kER3zBIrOqH31la1cBrvzYMdiHCLOgKV+rEyYRDd
         2gFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=R0DjcdFX;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nR5c65S0h7SP6OXM/wNOZQyvfws5a3ff7+YpNqF2XCg=;
        b=k14/He4EuUNTF3TYs8n2TzWQUjpWd1u2iJ2iIuefS+XcV0Zm7+IEBsOy3N+fB6zEA0
         8RDENOucSw0vfrLOOqezcTy/PjDQ1AO4GMPlZaf3esiL9JAFGLPMkC0ZGshgQtstwfjp
         6uOF0gkU6ryuUdo/f4H9hCqcu7qjJ68ZL8X3nexxc7McLKWvaTvQZ/c4Pu+QsgQIMAVZ
         Qc8JYlqR9xHuc0AAwsYR2fmJ/GoZ6KurrOu48z5P56ORWVgmPJFvg/w0yPo6dhoxtuo/
         F8FDlWq3xM9VFtmpeeLvEQyLg5ObIaWZw+E3BSiAoldYdxOlVwByro2gYe03hIcBKTjF
         Pomw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nR5c65S0h7SP6OXM/wNOZQyvfws5a3ff7+YpNqF2XCg=;
        b=EXOZEJGk4b6nW8hg5WHu44CthRf7zVYPx6Slwo1FJxYgwIhYU+/FurcjEtVgTw3XQA
         8yghzJGwZ1gP85+cHj4Q6+xLgU8JOfb03BbKyN9cSbNQUseBE86AwVwwWf3RqGXG5ANh
         OghlC3hl5CnbfQlwElt8L0l5ZmBBhmS3FqXK0shRK0vPDNG9vyLNasxwmUcUF4LDeBMx
         EMedVIBwcUXZYQKQmCK3b3k7FgIjhiofCyAJNRNou+DMu0Gnk22r5PwRLcPyU8W1SRht
         5pmf0XPu3zPKyccacwg+R7wjqGIdSBePy2UjYSWBJ5qAbeNLHeo/zeblqeSiCmUUxzqe
         658g==
X-Gm-Message-State: AOAM533uH2ZlGH+zsePiLJSTW3Z6Vf6OYD4XJhpKiB85o/Vua4mXlAvQ
	wR22hr3JcQqDvZ121sJ3kiI=
X-Google-Smtp-Source: ABdhPJxOvNDU2aQhDg8PWoa5EbC01Ovi2Ohf7qH/3z6WOs9Qn/FnBMxx9se916BrJZcklulo91SYTg==
X-Received: by 2002:a65:534c:: with SMTP id w12mr311875pgr.179.1610475999111;
        Tue, 12 Jan 2021 10:26:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bb95:: with SMTP id v21ls2001185pjr.0.canary-gmail;
 Tue, 12 Jan 2021 10:26:38 -0800 (PST)
X-Received: by 2002:a17:90a:8043:: with SMTP id e3mr478210pjw.20.1610475998546;
        Tue, 12 Jan 2021 10:26:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610475998; cv=none;
        d=google.com; s=arc-20160816;
        b=M0jP13HoMqo2NgBgnA9atbGpS8ybjQTlc/qOGgqExPPaAH5vlFmo/6tYdyOPAI6cMz
         ERQ9zSieN5Y9p2EgVJ58XWNcCxJ845rjVaRwa4uyanXuQ+AOaQfSZoC4S3UdpzwugwB3
         j35b3mWpx0IqqFbk0P3c+YmrNqdxE1ZjRJNViQ4zJEt9P1LO2sJcaiLLBJAnXwlZ/ZKd
         6Rf30CBhDVCscSC1FkG5NCNWaj5lpIQwTP64b6rCBnPPCbMaktBxnEuaO0r2sPajbj+2
         VJQ1NbNtPGjossPxXjWpJfgXcbPkxZdhHosWBt+sIiSGaNMATtwlWOxRd+GhDETACduu
         fzcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5vQT4NtiVFJodkrD1RgJ5Y9lFxIHZicjdW+dmh6bdf4=;
        b=AmzgZf6TOmk9+RHeUNAaYW1Ksmi2QYID+GBVlU7aw9nNHItxcuOd5mNCzYUvjuo8+7
         MFLWwPrm/3hXDrqGReR5oqIFU3JoUQ/jCd4/2HK/sIrhsgLZELG8588Sr09XTDuhnUPa
         zpIpqJBfQ3oudq3ltdps3HJ5a5iXaSBiZOWeVasBNktNOnK2yMGDwLAknH1cWzuhGprG
         L+bCYeJzBUR6DqazSQkr9KFuNNZ1U1VPa/alXvmwj0rvues12kqBz/Whvdj9L4hIyD10
         1RfebPa94qj7JpTrkAXmf4DsJ0v44IVzBVEL7mk9zNClz5g5zI9yY/1YTnzYPTfGuleE
         O5Lw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=R0DjcdFX;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id c3si256895pll.0.2021.01.12.10.26.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 10:26:38 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id n10so1967691pgl.10
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 10:26:38 -0800 (PST)
X-Received: by 2002:a62:e309:0:b029:1ae:5b4a:3199 with SMTP id
 g9-20020a62e3090000b02901ae5b4a3199mr543993pfh.24.1610475998075; Tue, 12 Jan
 2021 10:26:38 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <ae666d8946f586cfc250205cea4ae0b729d818fa.1609871239.git.andreyknvl@google.com>
 <CAG_fn=U86QGTTp+vgQQhjMBY=_dQgPbWKJ1MKt8YHdyLi3deMw@mail.gmail.com>
In-Reply-To: <CAG_fn=U86QGTTp+vgQQhjMBY=_dQgPbWKJ1MKt8YHdyLi3deMw@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 19:26:27 +0100
Message-ID: <CAAeHK+wkqPwtbBrpZ3dgEi1eRH6NmyXYKx6R-3vi28JdZm1c-g@mail.gmail.com>
Subject: Re: [PATCH 06/11] kasan: rename CONFIG_TEST_KASAN_MODULE
To: Alexander Potapenko <glider@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=R0DjcdFX;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52f
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

On Tue, Jan 12, 2021 at 9:10 AM Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, Jan 5, 2021 at 7:28 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Rename CONFIG_TEST_KASAN_MODULE to CONFIG_KASAN_MODULE_TEST.
> >
> > This naming is more consistent with the existing CONFIG_KASAN_KUNIT_TEST.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/Id347dfa5fe8788b7a1a189863e039f409da0ae5f
> Reviewed-by: Alexander Potapenko <glider@google.com>
>
>
> >  KASAN tests consist on two parts:
>
> While at it: "consist of".

Will do in v2, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwkqPwtbBrpZ3dgEi1eRH6NmyXYKx6R-3vi28JdZm1c-g%40mail.gmail.com.
