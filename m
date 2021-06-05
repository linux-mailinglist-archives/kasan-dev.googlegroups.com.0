Return-Path: <kasan-dev+bncBDW2JDUY5AORBYFW56CQMGQEXB7Y5GA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7821B39CADB
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Jun 2021 22:15:29 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id r3-20020a19c1030000b02902d8e3c1c829sf4780151lff.3
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Jun 2021 13:15:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622924129; cv=pass;
        d=google.com; s=arc-20160816;
        b=AWkw/ABThjcJHJZdjH7HFvyKh0lMjqN5YvxsTZdlqFdNFyl5u8FM2pR6ho5QZuB5ri
         tuoJ+X5sSFp2LhQUBtQvTeFdBzNiE7AbJf1oH1gXO7tQL8Vv3TgC5i2xQuO7RCOIPBm4
         SMqwd6qJMRXbcVaR5cYv5sUzHOKX+NeXQ1pb4zJ/861q+ZulNd3UaWrGxphF+vKrnY5r
         0e+xcQty1FX8LOvX15R1Zld9e+B2ZlWhKG6JLdCp9vOhoNSFEX+SuMc2Y/CZxyyYtOrR
         R1FLat1U0cUy7UYrkP51bTalLX28Zq7q0gO++Rrouu1SSqCu21o+lsJT+GZXdqvTpgdw
         BiBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=IwkK1LpOZ0ElTD52DDXjrArTfUX+ts3y1mqgksb//es=;
        b=JUu0YYThUBgwZOZaxUBnQwrt4unFtmI8cWbXL4i+DCILa7oKbpn38dYHECYoG4Z5SD
         x2nmCU7aDoWPkGY/Rf92l3nimRZZDP3zHqSlyZtPLNnnCJJie5jAhCFWtqA1fLxNXcMu
         IjoDpWWJ3WBiED/22rUiGCcAnAhTeoN5uikivHTvYOtQp1BoBmkeT1ImVvZXVAP4myMC
         R2AfYtphapTpgXtOex1AIS9WX6dV50o/xjj7KpdCixUZNVw0OmaFAdROepO3xX7x5IiZ
         WuWXUr9N4nsNYN/BoKveSSxfkTWqBCmb/k+9APtb6+Ik0deSKkdANC2epsU8V3epPGv/
         MFjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=gtPYTa4m;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IwkK1LpOZ0ElTD52DDXjrArTfUX+ts3y1mqgksb//es=;
        b=U3KsFDEVQNS6P1luQ3L26pvdppgxUS1dsmlJiSg836SSbLAhcCgmyR2oaCedDcWiyw
         YgYZSk2WLPAzcmKC4C+Tev9XzqCY0r0enQ7XnQksG95jMXU39yI1hX+7gaFm1quHOmXn
         Xl+xl5vsfkIjAdI8jL0CO/CbcWIO1/j1oqskWwWl/XkLyF9jg6xKjzMK3OKrijwBUFN5
         +znksjmfU1yjlAHH+8BsImKT/75NQK7n5VTpQUFJheKnwSD62XmmqldEl5rHqENWqsuf
         iPtmJfsljfLRd45Uack4VPirF3h8LVD/wOZqqUZCWs09Ltbger/SdupKEhk/vxDbrVqV
         NCwQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IwkK1LpOZ0ElTD52DDXjrArTfUX+ts3y1mqgksb//es=;
        b=Nlqq5A1r+RIuIhUYKGn/YnTuGIspnelFqh6Bda0GplWb4F/3XqtsBGAGgnPCJpO61A
         yUdP1SMfi2bdB+uw8ok75E2Fy7lN5e5low31yGVDlbe3aETQ/bwuNvBzJDerhodWyODK
         e6jdb6nb0d/XAGdlLLkcufPmT9pTpZWHSMhJb1syMjz80STIBIVH4mPgS9wPR+N2Gr83
         dvcBPVU8HkYBrAefh4mUOgHIC5qlyCD2TaRzwmSzulD2pmFIzI0TU7ZPGuUJ/mXvmsXP
         dMe/yp+HAOwXZeSj/vqcjk0D46FO3IX1ytfTvbJHmsMCH7rZ+YNWhUWFhpwHnrl0E5oV
         1UfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IwkK1LpOZ0ElTD52DDXjrArTfUX+ts3y1mqgksb//es=;
        b=Ki1KSYealzjz8gNglpZPO8y1cemG7hdxhGTIck9gQcHn4oTpXzOhwBGYs+46YcnXgt
         uF9db1aXTDH0gZwgQ2wrq1j/LyKt1PmZisSPaqd31RYpdE6NvsbQHGY2yuUE6GzCq4GR
         //NbnkQfG1MWP8rA3BxfUsRXbqrXEaU2N4tZ1BIJrP3i7fKtD857t6fKpuWZQ7nMwMVF
         1wCarcUAcHej9UH+/FFyy4wM+prKsdUQrnbJtMFwLeQE8eXERlDLW/SLX3+9ivUZK1nx
         MZuNUdI5nwOFs6weMQmMO/Zp65m61VNtf1tZH+ztbFBf6ix1NnzciVArLO81m8pYIR3U
         JUcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533d8OA4o7iAnDoqni0ggXcTQYqWagz3v//MpdwJ2hVPRrxHCgVM
	EXaGdSOX6vq4abOHAp0O4o4=
X-Google-Smtp-Source: ABdhPJwfJ2MDMMAQXmxYR+QQdJ37pjMcH/ZPzjATJEkXV6VFeyZy27398zK88JdTkxrd2S3FCiJFew==
X-Received: by 2002:ac2:5fcb:: with SMTP id q11mr6423379lfg.221.1622924129068;
        Sat, 05 Jun 2021 13:15:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:32f:: with SMTP id b15ls1352911ljp.10.gmail; Sat,
 05 Jun 2021 13:15:28 -0700 (PDT)
X-Received: by 2002:a2e:700f:: with SMTP id l15mr8497469ljc.52.1622924128041;
        Sat, 05 Jun 2021 13:15:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622924128; cv=none;
        d=google.com; s=arc-20160816;
        b=EkSb/DTcZO5kYWllThflU9HwK9F2yJdgCErrtSU+93zbODfi9M5CHZrBDiZU4yH54T
         Lo7bMJV0eZ+/fngbe4ErYp6sreYD2WX0Q+7xwgZI/5+EaFpNhyz80AhQYSMEfulw9Aej
         nzK3V3rnU7FxTGhrBpYJbupuiJ+OdblwH4PCaLo+zsIvbF4qiHkexmHMDjTvtgZwLxhR
         ds8lsoP990YrwWmJtzmkMZkBNqtwtzTmvnb3xfkIE3+Dzuk8fZ2K7t+4VDy1KUMPQxXS
         6cBVbMzY2dqFZULw6SycO++mwfiSKENaMt/AymQvZOVkQqCW5owM/l8lQ19V9d0dcwvO
         1gsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/mjD4/+PVhor5FQTGL1NBpfMmrk3n9PK870plLcDafg=;
        b=RWrdCwoOsmSPqXWOT+Veum0kR/7UqfuDB9Tfvhqpm1XZT1rinL+ByTXVmZWOOdDtpE
         8dIwiSwsib6G17X/pX6wtUJzRfB5GgOZEWlvhIf2N+yJpPwgIR55beWfDTDH2rqe5XB7
         vuFjOSUVA6MuhSEszToYt+OC5urYqkpLELDpvVYS7iWryQUWJI81n/+R6dO/x7BaiNgx
         Jnx0hOx7ZchPHSPna/pxQvY8a/O4uYKXIYJii9Ia7nh3PMYnOi/7kxlom57vytYp+jNR
         +lTJy2dCjlvtG7g+sIBL5G+8peb2BAcBNsp1b1N+/5qjgZNDsUKd0Dz9SOP8GZBaHU/r
         5Q8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=gtPYTa4m;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x635.google.com (mail-ej1-x635.google.com. [2a00:1450:4864:20::635])
        by gmr-mx.google.com with ESMTPS id 81si373759lff.11.2021.06.05.13.15.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 05 Jun 2021 13:15:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::635 as permitted sender) client-ip=2a00:1450:4864:20::635;
Received: by mail-ej1-x635.google.com with SMTP id k25so14349040eja.9
        for <kasan-dev@googlegroups.com>; Sat, 05 Jun 2021 13:15:28 -0700 (PDT)
X-Received: by 2002:a17:906:a945:: with SMTP id hh5mr10485042ejb.227.1622924127566;
 Sat, 05 Jun 2021 13:15:27 -0700 (PDT)
MIME-Version: 1.0
References: <20210603140700.3045298-1-yukuai3@huawei.com>
In-Reply-To: <20210603140700.3045298-1-yukuai3@huawei.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 5 Jun 2021 23:15:16 +0300
Message-ID: <CA+fCnZewY8MNf1fWaTg0VLwSivEejn1-msRXiuy7WGXApfBJYQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix doc warning in init.c
To: Yu Kuai <yukuai3@huawei.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, yi.zhang@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=gtPYTa4m;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::635
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

On Thu, Jun 3, 2021 at 4:58 PM Yu Kuai <yukuai3@huawei.com> wrote:
>
> Fix gcc W=1 warning:
>
> mm/kasan/init.c:228: warning: Function parameter or member 'shadow_start' not described in 'kasan_populate_early_shadow'
> mm/kasan/init.c:228: warning: Function parameter or member 'shadow_end' not described in 'kasan_populate_early_shadow'
>
> Signed-off-by: Yu Kuai <yukuai3@huawei.com>
> ---
>  mm/kasan/init.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index c4605ac9837b..348f31d15a97 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -220,8 +220,8 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
>  /**
>   * kasan_populate_early_shadow - populate shadow memory region with
>   *                               kasan_early_shadow_page
> - * @shadow_start - start of the memory range to populate
> - * @shadow_end   - end of the memory range to populate
> + * @shadow_start: start of the memory range to populate
> + * @shadow_end: end of the memory range to populate
>   */
>  int __ref kasan_populate_early_shadow(const void *shadow_start,
>                                         const void *shadow_end)
> --
> 2.31.1

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZewY8MNf1fWaTg0VLwSivEejn1-msRXiuy7WGXApfBJYQ%40mail.gmail.com.
