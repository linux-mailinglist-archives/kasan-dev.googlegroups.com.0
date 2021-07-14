Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC73XODQMGQEBY6YV2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E64D3C869D
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 17:06:52 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id b1-20020a4ac2810000b029024bec618157sf1857477ooq.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 08:06:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626275211; cv=pass;
        d=google.com; s=arc-20160816;
        b=eMeyxAUM8cNo60y8YVplkU8oTP6jtmd7YR1Lrr3QvopLYHJsZ8/aFXFtwLKS0XEqMS
         Ciu06BAUWSIOek+H+ioyG1JRtNJx8djB39LzXr3Jn7GAwFDBkhWe1kY92ffW/KrpJKOz
         6/zqJSvvBxDqyId+BicHYyh6LBzJ4lbmcgJiHdGFI/uL7a6WNQqOYNGXHDmBcgxLRnrq
         0FzqxJq/WoqWsshp27lz74VkDPdUnmu4L77wCbeHKbGDzeRwLSc35VhHa1Ln0lITcPrf
         DhBjnoRMsQjdMBgCoLlvh2P/aZFixXn8AFBmhXZiHj3JYgc9Xr6c3FGVthGIew5GMUdy
         gd9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WdNKflGqTTBCjC9skpYS+reVvcvKyhMxzTGLwcoydHk=;
        b=lw9j7dE+D5g6Flg1wx49bqHMCOqmd76K/z3befPy5BwLkprpa3asf6hnIk0jm/ILyZ
         EWKmxnFJY5KAXyWgEpNxRsLP2zE5dUGrPHXegv3N5umKgsLSMAee7gotrFtPuglH1con
         eE00FX+/iY2JUhre/B+cX/wmds6dQV25CLMQ3/QErtJHFfH+JTgSflOk+6DOmDW3FSGq
         DYeUmsCpMjN493sClx60wJa0rw4+ZByCN0jCscRpJcbawRQx0yftukB05wOYQ/XIRUzG
         6mncQUhI0JhX/+LZqbnQtjlUNySlz8erB258oehgWAClzgW8V9XOQDdaVHrtzj4UmZb1
         fwEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LP05I3Dg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WdNKflGqTTBCjC9skpYS+reVvcvKyhMxzTGLwcoydHk=;
        b=kkjVKygBHhldf6uIASXXRvnbP/j/4Tzi8sK2fNPBjlrccnPghhFWY+OwaTP4qTZ8Qi
         2LkIlSDJ0WyW1niaU/v/Xb2YHll/TiIWAIGqcRON/Lk2nzK740XMShSAcKFVFTwPLLXJ
         T2ybOJAft3H+vmPmZ7mMv8/HZOELlbp3EOLKz/CSZiWb7vvn/altytiIbhZTKduLz0lq
         3tBWsVBYr/e4hOzEEcV1jVUiGoHwLW7la3xL8wW+Gk/jytxB0q4RnRiXpx3TxtfSyagT
         jZz16bDRndLfkpXvxnFnTGfom8BQxE58Tf9GsN6dTBO7NGUUxlY2HspoMpc7Dx9Julaq
         sLwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WdNKflGqTTBCjC9skpYS+reVvcvKyhMxzTGLwcoydHk=;
        b=WtsUmMmNN3CS0FbY57FLfrgglEYh2ftunGBIBmfU1b9LLRksRGVJwLUQIpbAj5Tf7/
         4eWqv/RvCgowOL8Y/wKdj+YVP2Wg9Sod+LKbiQC7QpEhvQG68O3o6VHkCvidGDcBN0Z7
         juEV816hV+9zOvIwbrdcrdxgiR5G/1Ph/ADVIqzVK2ZNw1C+y7ujkSgxNAZtw8kRJKYv
         VhCZdO5gxetWzMtXDY3CXw9OqbQhssm93Y2P0Vstwotmua+Bughgt5iX/oku5VvwGAB4
         KUGw6TE6Pz1dom36Uur6SN4+9fHoS2zkTQMdk+v2HXkydPP9hCYaDocgwVS/vfLF7olR
         yXsw==
X-Gm-Message-State: AOAM531c66bwswxsCtZ1CkpNZ4l0vMSVHKM0rbX/lGAQfw5r1dQyvgMW
	AR/D/wCfISYrqBIL7OjO+dE=
X-Google-Smtp-Source: ABdhPJztVvNybNeRxpb0ikRXqYjDaiJx0xoJ7QUaV21asP8KgNbRlUm74DwEn/JQAIUnYPguHPV1FA==
X-Received: by 2002:a9d:6e8a:: with SMTP id a10mr5897942otr.51.1626275211527;
        Wed, 14 Jul 2021 08:06:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1215:: with SMTP id r21ls952815otp.5.gmail; Wed, 14
 Jul 2021 08:06:51 -0700 (PDT)
X-Received: by 2002:a05:6830:4118:: with SMTP id w24mr8284859ott.36.1626275211166;
        Wed, 14 Jul 2021 08:06:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626275211; cv=none;
        d=google.com; s=arc-20160816;
        b=LMKfJTI40q0gz2hk2vfSg0PSbpWolzVlXGSu9kLZjrlgVm1w9+pxRgIvLNGZF43Y6k
         xrjA1asB3xjV1eFmt/FPcMxIFVQnMMXO3VOKV3XfO2uy6H/fW5eVanJM6YW4Zh4dz38A
         NrV+vfLy/MPVkanUmPRgfI/m6Huk1TuwJUD4DDmSKkiumI62MWNaBAOhPjh0HSwOsRs7
         ju8fZIx8oVnwWYr9YLP1qrh5ayP0mU0+3sGmiJvAXI4cCxqxOU0kjGdvwf0oVTSfj/ou
         HtYezvwQllf58/UeOHIEHUJ800JwcQtH271zabBVKf/5sl8zJ8+3Heb5d1XwheJs427p
         NKjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8YiH8+P/GYggmS9FkGJgJ7JmHee/6ylMrnanql7uyQo=;
        b=pdxoxqCCjq33x4g34cSbVojqYuTY/HeMAEmRhbb4+shcozEc+oqQhGeO7l6UoGcE94
         +1XWoUOwC3lQ9vqd08xpYV5tUDhOblGrpreaaErr7mk44jUygumpzVzku5QLc1R873vk
         RSTAZTKlOXeP6A/gZcRF8wukffVGTWn+odd2/+GQLI+Zg7Z5imd623Out3diYRFdrGzC
         W+UI2/FH4F+U8vKpB+LjTZ7MBXOmDcUdlG7jdaHwB0uAGKEJUatZrs77AiolEIXrBJmu
         zXv4KPVIPN7GQwXPuTHovCEg4pJa+lsWgXULBLahYv6I1K5ZktUbGO4VxggCJSQ+1gqc
         jZ9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LP05I3Dg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id k24si255713otn.3.2021.07.14.08.06.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Jul 2021 08:06:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id o17-20020a9d76510000b02903eabfc221a9so2856106otl.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Jul 2021 08:06:51 -0700 (PDT)
X-Received: by 2002:a9d:d04:: with SMTP id 4mr8898501oti.251.1626275210727;
 Wed, 14 Jul 2021 08:06:50 -0700 (PDT)
MIME-Version: 1.0
References: <20210714143239.2529044-1-geert@linux-m68k.org> <CAMuHMdWv8-6fBDLb8cFvvLxsb7RkEVkLNUBeCm-9yN9_iJkg-g@mail.gmail.com>
In-Reply-To: <CAMuHMdWv8-6fBDLb8cFvvLxsb7RkEVkLNUBeCm-9yN9_iJkg-g@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Jul 2021 17:06:23 +0200
Message-ID: <CANpmjNO7reWQQCce+grJsfEjNcGzvrrsF2450DhE4CzCkvFt0w@mail.gmail.com>
Subject: Re: Build regressions/improvements in v5.14-rc1
To: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Steen Hegelund <Steen.Hegelund@microchip.com>, linux-um <linux-um@lists.infradead.org>, 
	scsi <linux-scsi@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	netdev <netdev@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LP05I3Dg;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 14 Jul 2021 at 16:44, Geert Uytterhoeven <geert@linux-m68k.org> wrote:
[...]
>   + /kisskb/src/include/linux/compiler_attributes.h: error:
> "__GCC4_has_attribute___no_sanitize_coverage__" is not defined
> [-Werror=undef]:  => 29:29

https://lkml.kernel.org/r/20210714150159.2866321-1-elver@google.com

Thanks for the report.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO7reWQQCce%2BgrJsfEjNcGzvrrsF2450DhE4CzCkvFt0w%40mail.gmail.com.
