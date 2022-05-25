Return-Path: <kasan-dev+bncBDW2JDUY5AORBQGVXGKAMGQEYSLCWVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id 501D6534254
	for <lists+kasan-dev@lfdr.de>; Wed, 25 May 2022 19:43:30 +0200 (CEST)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-3004ae6bfffsf24239037b3.20
        for <lists+kasan-dev@lfdr.de>; Wed, 25 May 2022 10:43:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653500609; cv=pass;
        d=google.com; s=arc-20160816;
        b=IULQdb4o+MLjvN/tjBdyy9efXQf98VQBuRzPb23lh0dBDIf46CbRZOPRGOBUF1pnV8
         tA9MzZQnf9iyTIp0TSO9ZQmZWgdepTsG+EwHUwB9df94Zh8w0oqbgvQVRemSUnO0YjzP
         oP7AI6FXtLDNZtpsJf/6b8GJmppAW5JQScDqSKFntDDQYmMqXWFbCVs6XRo+dCLywecx
         C5Kw5VPLLSx0efq9UF9D/MTXy42NIVpXzBi6HFtRE0EaLbuK5g9ifxZXN6ubCj3vBWyq
         csnFENNQQMzue+I/pZbyHuXHNz03VjcQG+ZV9DoGqhrTKXSJe9NV3221ToQfuf0Ny/eW
         iJmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=y5GCN/fDjdgfHrCwIPMlKTbsEUYbSuLJVhzKuoysR4A=;
        b=K4m2CuId32IfXFSrAqi+DeNGl7rQLE+DWjoXf95KIS5rw/g9lI+wu4IiKD3SDMGzI4
         0ZxFBbjnhzzx8h0aTNHDNuqsoK7HeE/qHwOXLE3jsWuqO8Tuq19SH5jAEnui0kvLmda1
         BH83OtuhFdTmOoM3QTWb/Ku7xd0KtvbHe+hwYBdbF0LNfYvseGAoVgJEZt6z7/NNnAJ+
         Z01jAlCWbw49vp2EId/WPsGFYIjTZxCf+jt2yUXfgoscGyqhzUf6vATSI99AL5luZ/R/
         h/5P9sSury8yPr+DEUZ0cRu/o3BLqXrAaXVC9eTiYi8GdlZ+SFmaRZ1cle2+2CQ0+Okn
         0lTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Lz+Il6Th;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y5GCN/fDjdgfHrCwIPMlKTbsEUYbSuLJVhzKuoysR4A=;
        b=UfBwCF1Vn+N00saw1tkA+kNVx3yZZ1xlKgwk2ublK7gLCuqQ71CVRjNQF4duJwMHkD
         YGuJ5deVOA7FUpoOF4meIO8hruBbbscGJl1ZBiKX4W/9LjjKiry+WAzUshyw2WgZS4WD
         KiufF18er8skTwiKET4D6CC7A0z/xVfBUWFQIMWVCZd+SsYKNWzlUrG6gJ6O+hBNArT0
         fXhBJ68liPvb4oje5VFHQ86rK9J2lqFc7lKsxDLdSifwvyW9Udm8rHoDz3tJn3dhW+JJ
         w/2cFSGj7WvUa4LS1VGoy2DeEkwvLJ+CkvDxaaQQkHbz1KqqLidWigi7B5NtiiTcxLQL
         85kw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y5GCN/fDjdgfHrCwIPMlKTbsEUYbSuLJVhzKuoysR4A=;
        b=KpVuZFyFLDJ1s8DonwGMEbJrNv7KXpP7JJNwASqGm5x+ZhhezFKPhwECnPtxyIR2Gj
         XG0xZtkIsX+z4P5U/ThZuxcx2tGgmbcbtrbCxxIC13z2EbKuOX0yjxNfZwtT6tqXZOhP
         RtCL0GnItTe6ii/VFB8bcGSqBI3Wcy5xdgAIFvM+nETP+hTO7IQ6AqVfO95DD/jrVikJ
         U/5WIfFKZ/KJfX6QfqEULGS+8pKD8LXc76fHyGbpnVha7xqEjdwsVMzBmY8sPlAJwecJ
         CruhWjG3s0JaFfnGzwLk9OfKirm8wx1Du3MoHjdRIWp3PdY1ZdvJxHVgo6V7J/LWMxoo
         Fw+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y5GCN/fDjdgfHrCwIPMlKTbsEUYbSuLJVhzKuoysR4A=;
        b=iYWEQ33jpxsLhN98zxU9hLv57P9NbQiMk+y40CDr4hdil6f2+9zN8NZ0V8L+fLpB89
         husl8jscfuakB++do9QfsRW+l3pT2J8tX8MXE5hQjLyNMgKGiuce7KpJB7UCOx9nIUND
         kwj4bP6xA2TORwHws1nBOXZow8wO4LmDW4jW1t+/79vYzlhwkYjGUW2X7FiOtXASG5fJ
         Z/zADWnjqcXfnzu7DP5JwKgpU7EyEuNRxM4tYQjNABcHvO5mLDLjVIW7dl4lup3+vwNT
         P1dGTlSZ57XCdd2/HrIwO1E/RBbGygrwKIKOjCEaZZCcZw2/8m0r1b/BF/MXBTvC7vNK
         L9nw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5334LuDRUeXG5diXijsAhFMdPF2ywXye29v6uhuEKanRi1niRdcm
	Uxh8pmFnL9nUhXLom7KwuNo=
X-Google-Smtp-Source: ABdhPJylMARLbicYrahln3A43RD95WD9T6YE0JkuXFwT225QIvptiUTi2d/8debDcF/4PYw1fqRp2w==
X-Received: by 2002:a81:138a:0:b0:300:6018:5336 with SMTP id 132-20020a81138a000000b0030060185336mr2720694ywt.97.1653500608978;
        Wed, 25 May 2022 10:43:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:7015:0:b0:2fe:ffc2:2e83 with SMTP id l21-20020a817015000000b002feffc22e83ls4379523ywc.3.gmail;
 Wed, 25 May 2022 10:43:28 -0700 (PDT)
X-Received: by 2002:a81:980c:0:b0:2f8:be8d:5100 with SMTP id p12-20020a81980c000000b002f8be8d5100mr35459845ywg.52.1653500608489;
        Wed, 25 May 2022 10:43:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653500608; cv=none;
        d=google.com; s=arc-20160816;
        b=zgawfnMhtMHi1JEp3labA1wP1NGEL78QedGRE4EaxIfsopKskpzx8Ukfk9ZzSsvsjq
         z1tkMIdlsuF01vTx8l7vDSaxG7mvCPbzp6GOGegl6l4fF+4b3h960FcFAHporRQmATWH
         JzitH08l75vPUgvG3ymLxbGn8bH2xIG4ABHzTCgXky2uwF74MDCcjV4uM5/OYK36ZQMZ
         Yxla1l6AIh/Uruv4hqalk/78efN33oWRzTxEA3m6vwsaa4QOuso5hRSE3TcC0VI32IB1
         SIvuLhfIPHSPH02wWISL809ThYkP0Xq0hnJixbRgWEmCPDLuYIUiy0EB77YuidSC69G0
         7CIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9Y1ppk7B46JVKK7NkaOrpQ5493dk2qksQrupKiexSz0=;
        b=dRJh+dxUZZnEjRs34pFO9vGetflgNq2B5hJqGJY5O+i0FkkztiDJEdXLnXYGJhmzzN
         kWqc6U2hhoMmkDgHCCOloDoxqvEqZGCtxR3dWjNtQVfp434m19qQsLJSIw3BXRjOGAem
         BcqA47t6adKhtAIdwWGJFzGUaT9pjRFZD2uv9d8nEomlKM2y8dmmXduwbix3LboHc+U9
         nqn+dbB8RZCbfs4lM5Hfs/U1kCU91AxuPXllL1DJCS+ufH9mMfguDxcAb6GdD1cpNtAK
         g6jqCZlK+/YBHelg6oqhXpJLir6SJbLJSOgfMIv5h8sXhym7E7W3kks4AYu7Jmt5mKNU
         4xFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Lz+Il6Th;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x131.google.com (mail-il1-x131.google.com. [2607:f8b0:4864:20::131])
        by gmr-mx.google.com with ESMTPS id m145-20020a25d497000000b0064ddc44f675si228847ybf.4.2022.05.25.10.43.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 May 2022 10:43:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131 as permitted sender) client-ip=2607:f8b0:4864:20::131;
Received: by mail-il1-x131.google.com with SMTP id q2so5910082ils.0
        for <kasan-dev@googlegroups.com>; Wed, 25 May 2022 10:43:28 -0700 (PDT)
X-Received: by 2002:a05:6e02:1be2:b0:2d1:5818:a454 with SMTP id
 y2-20020a056e021be200b002d15818a454mr18036546ilv.248.1653500608130; Wed, 25
 May 2022 10:43:28 -0700 (PDT)
MIME-Version: 1.0
References: <20220525120804.38155-1-wangkefeng.wang@huawei.com>
In-Reply-To: <20220525120804.38155-1-wangkefeng.wang@huawei.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 25 May 2022 19:43:17 +0200
Message-ID: <CA+fCnZf_Aphbje1aJCyp0Sarz3DgbfGLXHLisiHjT=ttS6pjWg@mail.gmail.com>
Subject: Re: [PATCH] mm: kasan: Fix input of vmalloc_to_page()
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Lz+Il6Th;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::131
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

On Wed, May 25, 2022 at 1:58 PM Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
>
> When print virtual mapping info for vmalloc address, it should pass
> the addr not page, fix it.
>
> Fixes: c056a364e954 ("kasan: print virtual mapping info in reports")
> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> ---
>  mm/kasan/report.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 199d77cce21a..b341a191651d 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -347,7 +347,7 @@ static void print_address_description(void *addr, u8 tag)
>                                va->addr, va->addr + va->size, va->caller);
>                         pr_err("\n");
>
> -                       page = vmalloc_to_page(page);
> +                       page = vmalloc_to_page(addr);
>                 }
>         }
>
> --
> 2.35.3
>

Nice catch, thanks!

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZf_Aphbje1aJCyp0Sarz3DgbfGLXHLisiHjT%3DttS6pjWg%40mail.gmail.com.
