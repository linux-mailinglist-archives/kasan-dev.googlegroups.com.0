Return-Path: <kasan-dev+bncBDX4HWEMTEBRBH7XU2AAMGQE2YEOSAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 517172FF20F
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 18:36:32 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id y4sf1580468wrt.18
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 09:36:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611250592; cv=pass;
        d=google.com; s=arc-20160816;
        b=sZzxtuqqr7Zh8Fg0Lt70wcKk58Y5qzvMqqmcXAzIK8lLAbwEVNl+qkl6FU2nbAiZkb
         C2Vc7LjWM/yL3eTbSSJI3epP9Dxkh1IM6AZSowves92N8FyVDqCLWkxBM0rLqh98Bnnz
         lO9TN9MUxJ/KeKqf7Cib5iaKTbgG5lbEmdlLvOkZ14lcgtWUJu9B31IddrblrEtA+/u3
         zoxGuVVpDYfMLg9h3JXO/W9ClpCEV3KbCqznGGiEY5qaJgZh/1EbyeFDoAaW/u88VjZY
         nMEVYFTymLLjGFr3BhkjoG54rA/87jkhtmnhhxhFnHvzCWfPIWgTBvnzvCKwahzOXbAZ
         9tFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JT5jxVhbsWquZzLZ7eAgpDxzjEOmS0JaNcnTbO/ot9Q=;
        b=YBzDsfBLJkQKVkaZsrJsMaVxB/+F+ROAH8UmCP7Nz0IcUpyEvL0V+V6qCOw3w4rguL
         1eSsa4CSCPsvX7Lj+L12HAn6rUz6TIwjSCOlVJneWsKqrANSet5a13pt7h/u/5c8D+mj
         5rsvGCw5l96rdmMl5Y1uYrge6CCpYm3P0IoircvvBmRgOZ28YjdGf68RcqNyH4l3XruV
         Js9CVkVlvGFMl11i/uEJmTF+k2EFXdWEarQzN7TWN355KTgBfz5DE2Ud+or9aBLaMDr6
         w///gTkE7YG41i22MbaGzbyxJw6STX5NjQuawosd0aKrmMzvZB28CfPHtn+hee1huxUA
         9Vsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="XsmwIVO/";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JT5jxVhbsWquZzLZ7eAgpDxzjEOmS0JaNcnTbO/ot9Q=;
        b=SwYslO3ZFJLKHLX2aPxqVB73J9xiacpbpLknBDOADWJAotFKQl/z+mSB+tiT2OHgV8
         SxbDo8/n9Bm2dJ0LpkbSkVC1q+5HBylm/DpHGCVgjCy2fTFM7vCIlHm/2XjTvE+Alof0
         j+m5yyV3S/EvyV4QoiK7RhfpU0BSDnDGhPOq7LqEKx0OND3P6pSnMzHEPPKPaEgtN/gO
         wxgPiuPWDffqNa4ZTob2THMR5UYPcLVhABJmcSMmOhmSbzYffs6LGFA4qE1exAVCE9Og
         gi/57bhtkT6BkPqoighfQEuzXQAeJn+zCJ1JT+y2XVz9uZYhaNPWA5O8gbjtWhy5Veqt
         6PEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JT5jxVhbsWquZzLZ7eAgpDxzjEOmS0JaNcnTbO/ot9Q=;
        b=lEoLbRQwCw5QqIVbpamQ9Jhl/Jn4bocGqNyETmzuJauERtD9aBKzzpGZvvazjHatMh
         Z8Cid0DSy2n5oXGdutMkRQ97uPfb/D8Q9jn07GhWTm3tmTxg57e3YlDjqTzLJLVGMHhj
         6TSP/IsprJR54EXBKohdE9HAN9zQ33Q9OQvKHy2pJYQlZYXN7m6rx751ZanUHgmqI1lZ
         0/5DzdJ2xzAqrXuVVBYUpdG4ALs40kBHlVu8xspsVtX3bYLV7Yvo5ynBfntzXnVG9iSe
         8zcEXC/7sK9xdtlydv6fuXlBlOVydyp/F+jcRTlruonFv5Aq1vNKiP6KaP6MnpquIXxN
         wJug==
X-Gm-Message-State: AOAM531XbRJ/kDiToAGodrWxv/6hfJ5/G1vUXBcILjqgbMKtzXAp6xwY
	0Ua/UMO09ik9wY7w3ianM/8=
X-Google-Smtp-Source: ABdhPJwrUORJZNLxHE50tV49doPY3Uf3zmw6Mj8E0Hlm0Dar5FjceKzJPoFZTVvjDqZC9ZiTwpAsEA==
X-Received: by 2002:adf:e348:: with SMTP id n8mr590169wrj.148.1611250592058;
        Thu, 21 Jan 2021 09:36:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e608:: with SMTP id p8ls2890024wrm.2.gmail; Thu, 21 Jan
 2021 09:36:31 -0800 (PST)
X-Received: by 2002:a05:6000:124e:: with SMTP id j14mr573266wrx.310.1611250591262;
        Thu, 21 Jan 2021 09:36:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611250591; cv=none;
        d=google.com; s=arc-20160816;
        b=ee5Y6lPD+1iziOJqah75vbWqsgFB4rvZCC45QEv7QDvt6ZG5KWTnevdPoskXBZXxvr
         XnpUOXGiBuFzxm7OuY3stp9rdS6U1rHlhJMrUCMzEXTLVEeR6hlufSRdaDAlX2EMhYeQ
         NAfS3wPM0G10SmCUpPwcPl2DCwteYry3EQgGGrPaKBZXD+X5cIrhNhoaqdBTms9ZwBAO
         Gvxh+bCkieo7gU5t/Xd3rCRzaMpqSpjyyrXeCJHK6dB4IG1emAFta+M+u2zwQj3a1SQ4
         6pUYU/fLoBgq1n+CKtSOrflJl9oYteTJ1SxcRTQ0nVxIK5mO0BPQ+TGg+HrH26mWswPZ
         e1cQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3SEf/V9yt14A7uM1ShvJd/4xdflgWn5dGZUA33xKMms=;
        b=mJ7KHDdJQdB9OycPrBKw9KHm/4XvxybHYWYQyegxOY5cu6zUOieLvYw3ykgjC8NJ6A
         Hro9uq74gSi2Y9feRo7lnjw1kyEAVBBIqoqRFSNoobkqMh7sUBAQ+VnEn3rYybIJcOTw
         VPMOv3HIu+PCCjR+T5N7RVmcvXJI/fBqUcdD2deDvAKbLFNjREaJGvOx3Flh2mrhejoS
         /dPVlzKJ6nLUtJ2j3bk5XiXZ7f+0LHENc6hVRyid/m9RZFTKkqO+Of0+r+gLMUAtnDE4
         vmkSKNx0NYXW6+5D3u/2yRdpWuMxUg89rk5g2zEonwSDQJ5pZGN5+qpWTiFgbdJUxCBx
         c1eQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="XsmwIVO/";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id w11si290171wrv.0.2021.01.21.09.36.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Jan 2021 09:36:31 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id o17so3679857lfg.4
        for <kasan-dev@googlegroups.com>; Thu, 21 Jan 2021 09:36:31 -0800 (PST)
X-Received: by 2002:a19:4191:: with SMTP id o139mr154189lfa.224.1611250590545;
 Thu, 21 Jan 2021 09:36:30 -0800 (PST)
MIME-Version: 1.0
References: <20210121163943.9889-1-vincenzo.frascino@arm.com> <20210121163943.9889-4-vincenzo.frascino@arm.com>
In-Reply-To: <20210121163943.9889-4-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Jan 2021 18:36:19 +0100
Message-ID: <CAAeHK+wS-HCrayJrWkD=HSS2xLzVfsgTFcAAQZL8DSZ2o3tCrA@mail.gmail.com>
Subject: Re: [PATCH v5 3/6] kasan: Add report for async mode
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="XsmwIVO/";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2a00:1450:4864:20::133
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

On Thu, Jan 21, 2021 at 5:39 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> KASAN provides an asynchronous mode of execution.
>
> Add reporting functionality for this mode.
>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  include/linux/kasan.h |  2 ++
>  mm/kasan/report.c     | 11 +++++++++++
>  2 files changed, 13 insertions(+)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index bb862d1f0e15..b0a1d9dfa85c 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -351,6 +351,8 @@ static inline void *kasan_reset_tag(const void *addr)
>  bool kasan_report(unsigned long addr, size_t size,
>                 bool is_write, unsigned long ip);
>
> +void kasan_report_async(void);
> +
>  #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>
>  static inline void *kasan_reset_tag(const void *addr)
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 234f35a84f19..2fd6845a95e9 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -358,6 +358,17 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>         end_report(&flags);
>  }
>
> +void kasan_report_async(void)
> +{
> +       unsigned long flags;
> +
> +       start_report(&flags);
> +       pr_err("BUG: KASAN: invalid-access\n");
> +       pr_err("Asynchronous mode enabled: no access details available\n");
> +       dump_stack();
> +       end_report(&flags);
> +}
> +
>  static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>                                 unsigned long ip)
>  {
> --
> 2.30.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

FTR: this will conflict with the Alex's patch:

https://lore.kernel.org/linux-api/20210121131915.1331302-1-glider@google.com/T/#m8872c56af85babfc08784e2b2fcd5cc1c0c73859

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwS-HCrayJrWkD%3DHSS2xLzVfsgTFcAAQZL8DSZ2o3tCrA%40mail.gmail.com.
