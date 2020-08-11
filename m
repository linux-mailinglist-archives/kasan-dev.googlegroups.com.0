Return-Path: <kasan-dev+bncBCMIZB7QWENRBBF2ZH4QKGQEO7Q5EAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BD96241891
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 10:55:33 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id a17sf9931727ilb.21
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 01:55:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597136132; cv=pass;
        d=google.com; s=arc-20160816;
        b=L0SJFb1CXfDE6QaVKzwE46sEmcsoQKLUI39/tthHgeNaeIPE+562XTatTRz2T9B5jt
         rglkcolYfTz3eCBTpV8iBPqZo35OW9w6tYrrR9uqPUuSOOIS2NvXrKafLZYnuf6sm/dt
         ir9KAc11NXMvLled7lOioJK+zeCguElNWlepULXFa5Xdq16+DuEzWvvQUyZSInDhoMPy
         DUHqzQ+JjiSgQaA0STG43bWrgAXUOmvd/CAECTGbw9i53K1JyG8k2642MDHbfdGRUMdY
         5egNOv+1v1xzedyCktpNbEgI0gTzvNw5kNzXULAfMYkalSZaO5Zos3gkF5XVOhKdftOz
         q8Bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ho5YETaDXS9i0eMu4dPrhPnJZyaPbOAY0VOjHQr72CY=;
        b=wEGCHyhSV8ugIIrdtqsQ1lZvnngoWUqROA1OqfKl/kYWBYOw2HqJ6Atog25Z6JcQEH
         EgO4e4urt3VG1YMSlcrOJh3a5HhSi8W0IRm/1YFZBj4VXOGyX7COHEIEVEodqsCr9wyM
         blbewNhA4kfB1qJJtHCi4hY1Dz44nCiPdenRtkG/dsUv35p1HlvfnIJFBk/ekAU9yoNh
         XG+PvXQ0ssyWVPc7YUTPHl0gmarkELBjMEwuqmHdVFxWnz26c422CqHPGfOuz7/bbQQI
         xuIVMSy6vQXnjYU9fL8LY0b5dTWOT6DJeFNGv9c1lweyTQnGd/PwigWi7m+MAGJBHLev
         qxNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SsY8bDBb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ho5YETaDXS9i0eMu4dPrhPnJZyaPbOAY0VOjHQr72CY=;
        b=H1wB9TxyNKN8JKzn2gVnb12Ps5PrTULsEV488bACok0QO4niKlriNml+XUnTAF9Y8u
         F/G4Ejq/Q+S9kxnCSDFQCoLPMNVaGIhXQuFZwhc29nZ8dTIRWpNlYcXnEgMoBulUjZWz
         Mj2OwfSPWp6pastYWZ481OlDmr0eZEOVIkEc82kQn786rfJFBxTeww2li34iznh1G0cf
         8UCKS+5uUeOHVbvopj0ETc2sI270Px9guZjfgQdV7DbPJo+515s2cD20NKTZSPIwxQXE
         Rpr97O9hfmFszCYAcrFH8UeMlPBXHeoWv1E4gwTeTN9q0Lz3+TRRSYauAPnvuPY3hEy0
         t+qA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ho5YETaDXS9i0eMu4dPrhPnJZyaPbOAY0VOjHQr72CY=;
        b=WLr5i3MrXFiaYQxYkELkOxPiPkmmC21w6gVodQlhtgBnKuCBD+TMKkxUmtBGQZQP50
         T9261iDCkIM5SMWVubx0JtLrxxu2LINfsVMBhYSKA3VohAiofZ90C9+SjtKc0HKuh6pa
         rdLjgZ6CSirVup0XhJA2f6I05zgb9qUNAa4jjBQUGfmWpB8YMr3iZuiTXFcjWTYqpKtU
         4OBc559Kgo1fgBU4NiP6YKWUDc45BNMabFtQzTkPxvyoBmOwQOLkufJhiwl18o5/mR3Q
         XoMg3yIhxZIKXFozO6CZgLVkfuHtNnyARwPxo1RPW+sjmwBCrotYtMOJ0CfYCCSbmcja
         yJgA==
X-Gm-Message-State: AOAM5315cjPZ1Pg808i1aRbSzhbnrPrcYbed6UxMj6FnipivRYJHZXMC
	v+5BfulruHY232UjUr6NOvY=
X-Google-Smtp-Source: ABdhPJwCE3HcsY0MijN9l49RWuD7DZbm5rlHVsd5Q03Nn9Ll38uLHVyY7zPLIXf6ts8xuhDEiFfOLw==
X-Received: by 2002:a05:6602:15d0:: with SMTP id f16mr22073433iow.45.1597136132442;
        Tue, 11 Aug 2020 01:55:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:5210:: with SMTP id g16ls4757556ilb.9.gmail; Tue, 11 Aug
 2020 01:55:32 -0700 (PDT)
X-Received: by 2002:a92:84cb:: with SMTP id y72mr22164031ilk.106.1597136132058;
        Tue, 11 Aug 2020 01:55:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597136132; cv=none;
        d=google.com; s=arc-20160816;
        b=A4Gw/D+oRsqwkm7RAXwHyQKEdElYiWtrqOlAT6YnZH42V7hC/hAzmszvNGpP1apKgb
         QK1GwTpO1ws5sapufLu1tt+V6GBaaHndMn/zZOux6hy+jCgneBr6i+s6htqKOCRY+VR6
         u3sxYMm4ff90zrEygIaVOzbJrxUbzdZMe1I391/jTc12sc4hujnGI+nHFJ+YfKGLpZvz
         1035eb0PjZK6ZKwimSlvwKgk27OvEVWxiIAULQXS/J4/h1F+ubD75UwLthLF3LQGD9Jm
         gWnPn/WKTzeBX1BhnUeeWG/YXtgnRDFl0LnycLqAEQkmmEGf35u9YwvISLqvDW700nFh
         gmtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1/+1dxe5pxWlvYwa30JpSFgW/DG88w6OLSnfiPvmVL8=;
        b=w51bv1TzJdoFfZ9ZFrjD47ACPrGecQSgEWwIOuOrPXE8OPvyxF3QRUsWdFlaYbdK0+
         4gc37jCxGnct9VQ5KDUGRmIh5CqUYoisVQFkXgllmIW8T1Wgy04yKmEZ+v9F+uFaQGwD
         MPQdkYlrctT9l8vZSMcyFVyjV3UMqZR8ULryfsN2zgFCEV2WOZgreDrEa6lo2w91ioFL
         /jPVck3ZgUtEGQ0PB+Gcd9yR0ICujOgmjouwU8gaZJvkn7SQWFrSQipIkqIVjO0fC3gu
         PMPKWfY3HLEbwB2Z/Xg2F4Cw/IYKo6on95+liK4bAOFyZq0qfyjNj0n6sS/ZR6wyAwtY
         CsRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SsY8bDBb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id j127si1127510iof.4.2020.08.11.01.55.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Aug 2020 01:55:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id c12so8884486qtn.9
        for <kasan-dev@googlegroups.com>; Tue, 11 Aug 2020 01:55:32 -0700 (PDT)
X-Received: by 2002:ac8:470e:: with SMTP id f14mr14262qtp.380.1597136131343;
 Tue, 11 Aug 2020 01:55:31 -0700 (PDT)
MIME-Version: 1.0
References: <73cddb98-c52d-4db6-bf19-3fd0e2c9d5bbo@googlegroups.com>
In-Reply-To: <73cddb98-c52d-4db6-bf19-3fd0e2c9d5bbo@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Aug 2020 10:55:20 +0200
Message-ID: <CACT4Y+ZQJ2OK3_GS74Nj5jB=saGzw5mVKt5yfcdScdPnx0GByw@mail.gmail.com>
Subject: Re: KCOV support for i386 Linux kernels
To: Alexander Lochmann <alexander.lochmann@tu-dortmund.de>
Cc: syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SsY8bDBb;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::833
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Aug 11, 2020 at 10:29 AM Alexander Lochmann
<alexander.lochmann@tu-dortmund.de> wrote:
>
> Hi folks!
>
> Syzkaller supports i386 als target arch. The Linux kernel however does not support KCOV on i386.
> In arch/x86/Kconfig it says: 'select ARCH_HAS_KCOV                    if X86_64'.
> Is it safe to simply remove the constraint 'if X86_64'?
> Why is KCOV disabled on i386?
>
> Regards,
> Alex

+kasan-dev

Hi Alex,

To the best of my knowledge: nobody tried to enable/test it. So you
will be the first to find out if it's enough to remove the constraint
or not ;)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZQJ2OK3_GS74Nj5jB%3DsaGzw5mVKt5yfcdScdPnx0GByw%40mail.gmail.com.
