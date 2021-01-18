Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4GFSWAAMGQE2UIMPSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F8E52F9C53
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 11:29:05 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id y21sf13005678ooa.23
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 02:29:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610965744; cv=pass;
        d=google.com; s=arc-20160816;
        b=QbWuR3sq7pSavwuC3CC6EBL0WFtR+fBC8m6Cnv1sW2qgG1wkJFZ/ZGLiKQOl+DhFdf
         2Q+x5eHIqSk9ENPc+E+wx+cwzhX76/iz2j/j1PzYJ6DNVKi7HGcFg5oEeZJNiwXI/Xa0
         GeZoOirWWw0RphFOkniR88/Kh3xAia39LvmQF1+y/9RhneOpmhNK1NKj1CHDvQpCn0ZG
         6fD3/A8Plx9GllxkIEgF+28Hb6PNVJBABfAyVlHx9Gm9s1ReFrI9lHjCEi0ya5Brb3S8
         VnL60M0g9h08Hgrax79bHvlVc8kZzKiDLL6Y9Bq4kwlbLdJGiZqds+KcUFKji2rwdTgU
         GumQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VKYaF3wvAvKA15eB0wIxKSApxB5/KzIpkxcPdY7sB3s=;
        b=eOM4q9zS6+eHaXEyRj17avt9QSP2i87J14VtPx/yHQLNeFWPG/RNDtgliOCBAdSCi0
         +uM7HJqN9wqDVF2hQXUEIl6A4UtGmfiql5/gm1RW85k9WapqoPHc0EbAQ6ig/cf6/i+L
         yQ1wFRONk1bb/HsrpxF/ipN/vk7LQpVkTe8/5uvl11rita8Uluge74HV7Y7XlcBLQ/L+
         uFHE3qeM1jJo+zI4vQaq9xdocNvmtPJwMl96tQo4L9oyrBJaOQbK/zyxoz1T2N4Vz4aS
         2rHKPXFjD5+7GY4Kw7sjr3le2B7BHgPLSRSE10WscNoVG8VMcG/RZeB+5LYX0K+GBgzt
         J28g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ITpteuLd;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VKYaF3wvAvKA15eB0wIxKSApxB5/KzIpkxcPdY7sB3s=;
        b=rsHf+Ub3qYi82SPa7RxFKIuxTsNgq+L8cxKojeGNt7fmQjp1YurkVLm9EFHcuTrKg8
         HIT0AWIT7RojgM/OueBEXUM/IGdS/Lkp3Al0Q5nXHYRxpMsEahTkx66/YALNxcXhjdG1
         314K+crTEqfR0C/cyFO5RK0z1jT72daQyu1vo5dxhv//E5YlT4cnNPcl7ikw9SFmQYHr
         RfJtB98tDX/5asqFl5EJL9Gpdgp/BqmNg+TF0koxYat3QNKYoRw4kqIRwVg8kVAVRSt6
         EFOeVu3qXGdrfjCIBwe7hdpv1fVuOSG7+EHHe1XFV4y6pun0QFBzfT+BYb3Nt/Jkgr+Z
         Jfkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VKYaF3wvAvKA15eB0wIxKSApxB5/KzIpkxcPdY7sB3s=;
        b=s/kQ9cJuQUdtWP/XhnLmkGakJUZ/hFnoQc3laSm/8tSJZf3lGBPw76IO8srjAVux8K
         dJ7Qk+EVKsxbJvOgp0zCeY19vefqyizgX7xk10w+vtv3l6GRI2nXqLl+aNRNtcnOb7P3
         lMStu+e0j/n1X8JvERkMSdcxA/oR7VtjMUkLjVkgHKaUwAOY5QMQGRQirqRU0vokTv0P
         rMjRFMvBE/ZAAX2nR3FYMyx7w/R+anMVm9kNp9Pr/Aq3bol8ScwPMBHNARWthspLTD7K
         4rReYihLVrSEj5FEBsN2wqzISY2uDYGWEyLuuQ2vWopBl2137UWi/M8iVt9sNztC9qjK
         LXFw==
X-Gm-Message-State: AOAM533DA3FUKT3+wUVM1DV8b0WObPUcGIIqlyhcY1A3GwDaDtrftspJ
	Y0hYr252EMlAKowdC2ZjzeU=
X-Google-Smtp-Source: ABdhPJytOadOvXYw5R9P+liy8tTOWThpY4Ma8rUg5kW/CSQhblOtb0w6J7s5O0wyf1HkDMe2BfsrMw==
X-Received: by 2002:a9d:313:: with SMTP id 19mr9045877otv.147.1610965744359;
        Mon, 18 Jan 2021 02:29:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:2413:: with SMTP id n19ls4209161oic.7.gmail; Mon, 18 Jan
 2021 02:29:04 -0800 (PST)
X-Received: by 2002:aca:fdd6:: with SMTP id b205mr2535943oii.172.1610965744038;
        Mon, 18 Jan 2021 02:29:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610965744; cv=none;
        d=google.com; s=arc-20160816;
        b=Qsu2wh9gwXffIG/7ewpy1ZMu8bydhWl7dhqYnWyFZC66Y1h6bcj+HlTvXBc99Vsj//
         kRCqLVeyw1WSf4GJCQOnrK6bMX2ou0X7FmPBxyfKEqrD2Kt5tTq6lG6saAryFjN8/qwK
         ucXodM7b4ok1VlGR7XjkJzuAMxAWIQkPDs41VhK97eDQEPIHARMeniNDhm/LfKpQrifu
         /MV+STcaP8/3IUOqP/kgboihQGPS86pq4P2b9v2z1BeVc8+iPNg7rI2I5fYHR0AMBbnT
         Z7YBDzx5hSws73pPR3yRgOGlx5N0qkF2uT3xpBO0cUUaa0h2dKk4ztG8WTfxcckJWLay
         2PYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OYvmTRg9VE7k01lzg0q32naiEw2p5pLxGQxdorBtVnw=;
        b=BaHu40f0XClOiAHH0YldSUq7D+dRfdwqm0ctYF+nJiN8PFwMrMRq3nQyQEgkGCleeT
         khRaCzXKwYuwC61HNCCFB5AJdp+H+0H1pRhmHf49StVpXxOlFt9HPB3IJjPB0PhWTceR
         6Hcxo3b7ApeFlq9gwmTaNO0PEA59WGrwnxLSBcdLg5XkO84DQvN+LBn7c86MiA9r0yrP
         LRnjjagaXP7DJb3tanNDec5gCTFEmIMXKOQDrPawMtaWycKTmrZqlDYkIsP09kwHOEOM
         Tq+oD282IqhmatUxd2/VT95boOHJgsOdC180eAdxVXcmSRDkzFPZgXOHfCp950uPo9gu
         2Y3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ITpteuLd;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72e.google.com (mail-qk1-x72e.google.com. [2607:f8b0:4864:20::72e])
        by gmr-mx.google.com with ESMTPS id r27si1518660oth.2.2021.01.18.02.29.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Jan 2021 02:29:04 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) client-ip=2607:f8b0:4864:20::72e;
Received: by mail-qk1-x72e.google.com with SMTP id b64so18163581qkc.12
        for <kasan-dev@googlegroups.com>; Mon, 18 Jan 2021 02:29:04 -0800 (PST)
X-Received: by 2002:a37:9a09:: with SMTP id c9mr24291484qke.392.1610965743584;
 Mon, 18 Jan 2021 02:29:03 -0800 (PST)
MIME-Version: 1.0
References: <20210118092159.145934-1-elver@google.com> <20210118092159.145934-3-elver@google.com>
In-Reply-To: <20210118092159.145934-3-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 Jan 2021 11:28:52 +0100
Message-ID: <CAG_fn=UXo-o5HvwHtLi_axC8YzCmhjByXT9Xn9k0PAQ_DyPw9A@mail.gmail.com>
Subject: Re: [PATCH mm 3/4] kfence, arm64: add missing copyright and
 description header
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitriy Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ITpteuLd;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as
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

On Mon, Jan 18, 2021 at 10:22 AM Marco Elver <elver@google.com> wrote:
>
> Add missing copyright and description header to KFENCE source file.
>
> Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUXo-o5HvwHtLi_axC8YzCmhjByXT9Xn9k0PAQ_DyPw9A%40mail.gmail.com.
