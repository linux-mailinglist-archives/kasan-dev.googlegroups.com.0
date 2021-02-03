Return-Path: <kasan-dev+bncBCRKNY4WZECBBCFG5CAAMGQEP6WHHTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 406B630D1DC
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 04:05:46 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id y19sf2460792plr.20
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 19:05:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612321544; cv=pass;
        d=google.com; s=arc-20160816;
        b=z5qxWypuIOrBegeILCw2Ms70M6qKNCBPKOT8WrN7oVP+RJAG6SErRyLTx2G9vOebTd
         5+7usiopMtqD9kCCuN8uYam0g2IMeCeZKk35tCRfkIhlAzQUZHOodkXXPqvOehEl2v4o
         vCK9m+eMOGYbJnZ/YcPzUjeHT5zhbCKKCTb8nF5LAJavqVvXT8FWodaBOajjhxPhqfvP
         Aq83THAisS3m6webnzgZR1M/6bq98i3z4YBo4H/1FnKK2GpaotZUI1BJkxDmde5LWJcC
         RY3UyPob14VeFTjljHZLt2g0e025bzZkDVdzhDnSQj5OqmPwCdjqtSCvJfPvDF7kY+Lh
         Op/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=aY4S6Y0YtyXNdnjskoyEzbi+CbBFf3OtD+BjtpT+fnE=;
        b=qtmjfZ+n0weebp/4hiSXWZSFWeuU8g4VHgSjW6tADdmjtb9VyliDrj+dyyp0UyfCcb
         brFEgCRuO5+R8x9PYrd+8fkU0NgF9OApmy4L5Neo/hYeLZy4usnYIp4YwkSNgRFS8tt/
         De25OycyTEeay7x77Tb49gKBM15PzB4gWdWz5zEncW10YBdTwt3Y5v/q4G5j7fa1WvgX
         6mIDjjA/4Ue8Y8HNn22vqPLmHNFzehLfY0De7BFJuC31u1XVWrjPOkXFpU5xyAAOe+0X
         M630Q4vugdYNRaD/b4nVhBLCjfVgikaVBu67ohXpZ0BvOENKWu7A7ta3l5btli2Y/6+b
         weJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=UZ4hGLaf;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aY4S6Y0YtyXNdnjskoyEzbi+CbBFf3OtD+BjtpT+fnE=;
        b=YHVV1x0JjVQ020+wQRGra8Rb30Fn6nEDnd7Am36f8aQIH0nT6LFr5v6K1ckFbr0uH5
         bxvx5H0ism1jNciNIjUGGA62dnTyGUN83H1FlhtrJ5+hDuszwYjcWiNiNpZ5rrjwjYQj
         z02Eh8jAYaknnejizZpVjoDLGjw9Dljb2b9d+OWwLe5wA6a0pfFbz2SDqdyHTGqI3tCq
         QpCxmjaIV82dynIczT65pSSreXzKQG6+xm3+SmOLkBB6FL0Nx4KpdPdUuVJxGHiswP2r
         v0LjQe8XRSORz2s1aQda55VWGlyi1bibUuAVXfLoeM+NOpMVNiXKgiTzkJgL+KwCJuxv
         PPyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aY4S6Y0YtyXNdnjskoyEzbi+CbBFf3OtD+BjtpT+fnE=;
        b=eP6Ug6KINP+qG06KLLRxDLM8/my0X7b4XkWQs++4N7OzGiK5W/8nXrgYDWKLWm7w/M
         tWtCJSvygAMVbu0wM6eHu/JPvyY7bWv9v7HLeDjLaLDSDowel+Hb3xXEgy+eJY+YdtKl
         vYAH1NNJChg9ATbF/sICfrw4TQVQPGAVLrhX8E2W9/dAa7Fy67qiCVzg/FFQ4z8l0SaJ
         HCLIYblXMTY4yWx1Fn2Jl/h3hLv/0Qjcr7eKhYaLmcUF2bphsr0LCFXDB7wlDiuPKNIl
         uCuYdkeveNYLYZXkSo8MzeSLq0mRGhdZk+0RLl+hz6x/W+oP9Ic1iwAAZ3cnplRH6qo5
         Y6Lg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533DVFISmNZa92oTTpow4Cbq7YM/HiTnyba7fm69llJwJMUYx0XQ
	u2GXMsedQ/DoQyfa1mNr8Ek=
X-Google-Smtp-Source: ABdhPJwhXM/4aYPzFRw6Q73Uo6GjQosd62Drkwlln7aM/I+/Js1ckUYYBjO5yDJZTQnWSZc0Sgp9Pg==
X-Received: by 2002:aa7:9637:0:b029:1c4:db58:97fc with SMTP id r23-20020aa796370000b02901c4db5897fcmr1045905pfg.81.1612321544593;
        Tue, 02 Feb 2021 19:05:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a707:: with SMTP id w7ls352898plq.9.gmail; Tue, 02
 Feb 2021 19:05:44 -0800 (PST)
X-Received: by 2002:a17:902:bd4a:b029:e1:1ccd:35b7 with SMTP id b10-20020a170902bd4ab02900e11ccd35b7mr1298662plx.30.1612321543950;
        Tue, 02 Feb 2021 19:05:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612321543; cv=none;
        d=google.com; s=arc-20160816;
        b=FohK7CEKBVs1tgw5AexRqZlH6y8CLXBVmuDYnCFIKBUosGYsPG1sf/D+v9CqD0GU8E
         hKAx6J78xC90KbzRhDpbm4rABtBMczbJZOP7fNhZ2OtNNh8OxA3GcRBumb9gSbL8vfXt
         677vgiIDr8GsVJEnJtipIYa1qPtXCs8JXyCD5yuW0szLmaiAdV8qsxYE2f3HZYnyA2Cq
         YVYV66U1q/zIfaJpajosQ7//cUGz+mKibi2jye1pJ1H7e/F4K2gnHerBW3wx9GhhguDi
         sji6b9FCY90AQEq2f7645YAaLenonrkbI1mqh2twhlXOzwdjkDR5H2+zOcwDBaVwqCzJ
         rWAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=ZMWBq3ACFJJAx15ObrNGTwgdYr+KZMK5JwRK+RWgkj4=;
        b=PTCMewXu4BdDIr9V0nThOBvrzZMCRK5XKb1GrSwtK3V9K1jRoiXp4lQMXyEAfJK6Jr
         eQNQriYcRB1o1Uup1bFA5aIyugsUmYhMKkTn/mu9tJI6Gnx21tluunVskvlTutqKLnte
         FtVllMIO6fV2fu26yFDFg2N3/kePksKMXM2cmOPeG2OVYgWI5zrzX8lXDyAOn13Sf5zl
         A3dM/cC7oUYnS48eJouJL1qOuk3CbJtjJ52lvMMk6wjK2PlwRp6AC3m6wVtjFuh8ei4M
         EYwz1Usjd1PH+IieNLAW3IF1qQQHVYgUO7x05M4mE0gACYP2zCL8KMu8myg+pndjmVY8
         pDHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=UZ4hGLaf;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id f24si342726pju.1.2021.02.02.19.05.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 19:05:43 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id a20so3550485pjs.1
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 19:05:43 -0800 (PST)
X-Received: by 2002:a17:902:241:b029:de:17d3:423e with SMTP id 59-20020a1709020241b02900de17d3423emr1138151plc.44.1612321543577;
        Tue, 02 Feb 2021 19:05:43 -0800 (PST)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id n73sm329565pfd.109.2021.02.02.19.05.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Feb 2021 19:05:42 -0800 (PST)
Date: Tue, 02 Feb 2021 19:05:42 -0800 (PST)
Subject: Re: [PATCH] riscv: kasan: remove unneeded semicolon
In-Reply-To: <1612245119-116845-1-git-send-email-yang.lee@linux.alibaba.com>
CC: aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com,
  Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, kasan-dev@googlegroups.com,
  linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, yang.lee@linux.alibaba.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: yang.lee@linux.alibaba.com
Message-ID: <mhng-1a6dd811-fd09-409c-a664-7bbd9f9d8315@penguin>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=UZ4hGLaf;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Mon, 01 Feb 2021 21:51:59 PST (-0800), yang.lee@linux.alibaba.com wrote:
> Eliminate the following coccicheck warning:
> ./arch/riscv/mm/kasan_init.c:103:2-3: Unneeded semicolon
>
> Reported-by: Abaci Robot <abaci@linux.alibaba.com>
> Signed-off-by: Yang Li <yang.lee@linux.alibaba.com>
> ---
>  arch/riscv/mm/kasan_init.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index a8a2ffd..fac437a 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -100,7 +100,7 @@ void __init kasan_init(void)
>  			break;
>
>  		populate(kasan_mem_to_shadow(start), kasan_mem_to_shadow(end));
> -	};
> +	}
>
>  	for (i = 0; i < PTRS_PER_PTE; i++)
>  		set_pte(&kasan_early_shadow_pte[i],

Thanks, this is on fixes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-1a6dd811-fd09-409c-a664-7bbd9f9d8315%40penguin.
