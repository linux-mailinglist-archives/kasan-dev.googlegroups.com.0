Return-Path: <kasan-dev+bncBDW2JDUY5AORBFOX3GKAMGQEB75V4PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C4375396F7
	for <lists+kasan-dev@lfdr.de>; Tue, 31 May 2022 21:25:10 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id h7-20020a4adcc7000000b0035f78252066sf7707300oou.6
        for <lists+kasan-dev@lfdr.de>; Tue, 31 May 2022 12:25:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654025109; cv=pass;
        d=google.com; s=arc-20160816;
        b=HsXI9rabDILQwO0Ei/q6bmoGVKZeXcOB1rPgmR6nxHigBZFi6QdQROoHBWrvT+yNqq
         8cHIb9gGkl3yBDG1Gy+JIBFSVtBYx+6W+9FIyDbY8fAoV4ZAC9hR17Ytic/0ANKbZ5I6
         oVeSOXrOgyUR33rhkuRwcfyaho2+JJiUwKH+rb3OiayN8Mkhoo9hnf5e6cdVdiPDGlNJ
         vqVRKbIJ4p0gngyxvOWmji4M6KAtt9rhU+ey5uNR7tXgzC1VLjvwho1m3Ja6hdf6o8j3
         c1HxrX5saXd7DarGIuD14ruU2s9FXvFmRrZE1rdyh+sn1uTotCd/s1zpSALBKXbUM60T
         ZXuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=NT/XMF+GBPCxDp4pfWGUfWrtx21073tFZgsfeRaEOeU=;
        b=xg5w1IkELRG2I7NRB0g9ohfaVnQ1PiPdXQ5AGBavk7nf5sTjV5w6Qu4TJkvSvGqerI
         +Ay1fgs74zWJZybSrde0t0OltWpgOkBsK18xAPRZGxsOboD9W34g0ZMlM7OE4tZaPWPs
         9Et1gzS+Nbb4NGBpSbVmhtW7ENwBzfrjMnUQmGuleWoPFmpxPZj455JYCEPwICHibPDk
         H89iKa6sLggwJ3w32m3AQmP3SmS9Ngcg5ryi/3xkkw9LJML7D5yG/bQo/YLnHd7+7mhC
         RRNk+uZg5NGV/kY0emVv/YvEduNYZMAlFrDM8clP16zRH54cOSpoI/Bo9KEDhWkH9KnU
         1RXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qeNPEzon;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NT/XMF+GBPCxDp4pfWGUfWrtx21073tFZgsfeRaEOeU=;
        b=QQgwGZkW7WY8Uy/fxct42NulGephcSv3dgdn7KCMiGUrb1WK+DjlEYc9LeU5cTLx0T
         3uJQocrQADuZpxHy67vfVzy6EzQKKjME0I1I3uzNfu+K4yH/dRxuJ9GSbAMRJQ+x+ALj
         DMjqRpU+Qb3lmDSFpbFOISwGBmvFBRMiUlh2icMYnICaXs1GDhqZiT2VwQqz+5qnwngO
         20dYtJIX6BbOO/JgmcwrVXVq1gx0l2ZbFwb9hHk7sxg37XxpeA5VCFi1TjFHAugAM9Vc
         s8COTfYZfmrjCCxqzWgzlWplYvnelH4Ce5/WMLWWbOAEX+eSlodTdQX51U/+T5he4F+a
         2BmA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NT/XMF+GBPCxDp4pfWGUfWrtx21073tFZgsfeRaEOeU=;
        b=PirA27/gYJF5HxZ6MVTne326hvO2AxhckYKa8xIRKGzQ3sxim+7Eg7BA//kqqm4Jbn
         fA/lggQd4UajsrQHFHw/FVNTY4R9+4cGf30ikNFb0sDuEsPX0VAnowlrb9a1xIOxZQO+
         QGogvgvcobRgBy3hUuY2BxDZ+I0/QphfR2Dhll77zypjpaaQYPF2iSnr0EOdxdTxNjtV
         Yb906fNxzc/89Rkr37MRau1J2gKlYqXJDXDqbSiAAkJXS5wnaJsqF7VoNqgqLQ2FKowp
         2L2hugmV9MZAMTxstLzjUlLOrOPRLk3R90vumtFkNUcF0ZaEbW4lZdIfRLOXDuvhGTNz
         DSkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NT/XMF+GBPCxDp4pfWGUfWrtx21073tFZgsfeRaEOeU=;
        b=b4XCFCFbFfTojSeQVW77NknEQ7s+DUWQLrufPDBt+5OR/nyGyfa+mc28nCnfL98uJE
         Nid9gz9rkAw6DwKd2RXKYZgP/EdKKsjuPGzbxrw9cUvRMeQ4+0A3rQLZHxiyBrBnB/Xq
         upEtfkeKL2wru/a0ddgCf6NrtXORtOPnsKYgOecaBKZcb2l9zx7Totjv9BlOtLJtsCKr
         R95DCTNq67yKF6xecnl9CxIQWgeJzi9CpZrK74nb8klkBuKIICcZ5fE9dfyUh9DJ+CLc
         Qj+DYKPnYqtjsCdbQRUB9INibCszgCDaly73CF23W8Dg5tyAzRxtGiEtWtr+CeLrWey8
         VM+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5320zms08Ntqr3Hvqr0NEzfwFGrv0mPu0fa6pR/14rc0FVD93Y7g
	wi30+ThQKvJVc4zm6BsPtX8=
X-Google-Smtp-Source: ABdhPJxmJMAcFPnTAKHdJY4jJOUMPSdj/O3IvL3gmrjidtnjmHGiK6/XLNuZ4jqHcpkMZ14TBo79HA==
X-Received: by 2002:a05:6870:1485:b0:f3:bd4:aab0 with SMTP id k5-20020a056870148500b000f30bd4aab0mr10264730oab.229.1654025109459;
        Tue, 31 May 2022 12:25:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d583:b0:f2:fa89:6a9 with SMTP id
 u3-20020a056870d58300b000f2fa8906a9ls408938oao.6.gmail; Tue, 31 May 2022
 12:25:09 -0700 (PDT)
X-Received: by 2002:a05:6870:4581:b0:e5:f311:fa37 with SMTP id y1-20020a056870458100b000e5f311fa37mr14800024oao.58.1654025109132;
        Tue, 31 May 2022 12:25:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654025109; cv=none;
        d=google.com; s=arc-20160816;
        b=JZqlU6wWkidzT6yfwS/85Nd0cZTnoLXtpvMh9fVY4A8NOlHDTH/6FdV9gF1/hbModz
         OJGEQ6DOJwA6LFIINEipAUsEJK+vUAqm5qyCYvj1wDL0KpsDj0duauk8NZQzPnaaNOgW
         EccAE/JeLZHck9KayrGZAkkmp9aI1X2QEQJF9qxMwxH7divqs/jeLyLLOdFdUpY0Miry
         TJLU+jbrY8nJJPggo0dfkMQGStmqR+jEt7x6eZxtTlRb+BH3u07v3y9IZy+PAdUAe/Eo
         vdh2QAjkjElH6XH7CLxdElhS4UbmTzDLL8PN/XrNnExfQ4zwQ1Kmf6u63SVn6i/8KTQl
         m3OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=laksvj7tZyE5VfjRjxemXKqC6M/6B12dc0r+gd4pLSY=;
        b=UBRZ5ZanJdxcOytna7G4863wDW8FffK1SykTHbMCrp0i2fuDyiH8I1lhZiw63uMnGo
         eEP6Z2OptW+VXpeQ2Wl6s+tN+gyF31KyB+pLIBgiIgEsek+hNYLwh97qaWfwrCpYxSAq
         56eSs7JjVSkxm0dSOLhqiUQ5jZ5awBaA/UIIS1MBlzknqTFrW1KoRZnv3HkG/oPGAA2s
         dlnY1FVMRrCgUU79jIfqeYgqY8V0A5s9oqqJp8RGb9MsO9aNES2IlGoBLf6hp7KEApLg
         4x8icqIjYn98hAbn4byYL/U9+YsGpcJo32ltFZ6KsXf9if9JM/jmybQeuylrzVMVWEAr
         AEPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qeNPEzon;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2d.google.com (mail-io1-xd2d.google.com. [2607:f8b0:4864:20::d2d])
        by gmr-mx.google.com with ESMTPS id x10-20020a056808144a00b003222fdff9aesi1052582oiv.0.2022.05.31.12.25.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 May 2022 12:25:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) client-ip=2607:f8b0:4864:20::d2d;
Received: by mail-io1-xd2d.google.com with SMTP id y8so15149920iof.10
        for <kasan-dev@googlegroups.com>; Tue, 31 May 2022 12:25:09 -0700 (PDT)
X-Received: by 2002:a6b:3115:0:b0:660:d5f1:e3b6 with SMTP id
 j21-20020a6b3115000000b00660d5f1e3b6mr22025461ioa.99.1654025108757; Tue, 31
 May 2022 12:25:08 -0700 (PDT)
MIME-Version: 1.0
References: <4c76a95aff79723de76df146a10888a5a9196faf.1654011120.git.andreyknvl@google.com>
 <d6ba060f18999a00052180c2c10536226b50438a.1654011120.git.andreyknvl@google.com>
 <20220531105200.587db61db99f19e308a05c5e@linux-foundation.org>
In-Reply-To: <20220531105200.587db61db99f19e308a05c5e@linux-foundation.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 31 May 2022 21:24:57 +0200
Message-ID: <CA+fCnZdyu-iHjsciTs35bCtXuH0X-UJkfhs4P=tLq2_sHK-Rfw@mail.gmail.com>
Subject: Re: [PATCH 2/3] mm: introduce clear_highpage_tagged
To: Andrew Morton <akpm@linux-foundation.org>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=qeNPEzon;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d
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

On Tue, May 31, 2022 at 7:52 PM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Tue, 31 May 2022 17:43:49 +0200 andrey.konovalov@linux.dev wrote:
>
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Add a clear_highpage_tagged() helper that does clear_highpage() on a
> > page potentially tagged by KASAN.
>
> clear_highpage_kasan_tagged() would be a better name, no?

Sounds good! Will include into v2.

I also noticed there's an extra empty line at the end of the function
I need to fix.

>
> --- a/include/linux/highmem.h~mm-introduce-clear_highpage_tagged-fix
> +++ a/include/linux/highmem.h
> @@ -243,7 +243,7 @@ static inline void clear_highpage(struct
>         kunmap_local(kaddr);
>  }
>
> -static inline void clear_highpage_tagged(struct page *page)
> +static inline void clear_highpage_kasan_tagged(struct page *page)
>  {
>         u8 tag;
>
> --- a/mm/page_alloc.c~mm-introduce-clear_highpage_tagged-fix
> +++ a/mm/page_alloc.c
> @@ -1311,7 +1311,7 @@ static void kernel_init_pages(struct pag
>         /* s390's use of memset() could override KASAN redzones. */
>         kasan_disable_current();
>         for (i = 0; i < numpages; i++)
> -               clear_highpage_tagged(page + i);
> +               clear_highpage_kasan_tagged(page + i);
>         kasan_enable_current();
>  }
>
> _
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdyu-iHjsciTs35bCtXuH0X-UJkfhs4P%3DtLq2_sHK-Rfw%40mail.gmail.com.
