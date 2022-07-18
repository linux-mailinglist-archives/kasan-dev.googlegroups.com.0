Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNW32WLAMGQE4N5R37Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 94A5F578553
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 16:27:03 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id s9-20020a05620a254900b006b54dd4d6desf9441926qko.3
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 07:27:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658154422; cv=pass;
        d=google.com; s=arc-20160816;
        b=sL9JkfF4APDZjaas0OJ2yb9vltht3Voi/sTAhA1oFE0PIFdSdMXq06fYuT7AcwZAoT
         L6/Ztmfa3f8TX3E0TGP8w8lBR+mShYdgMp195bBptrr4f3O2UDamPd+EoW+uCM4HebPE
         ncv6ZPHlKCbI4v5OIWgF2E1yjZv+5yUmwMlocXmwdU6ybDhf+FpYqg9m03AkQdwdqjz3
         rgV1suwejIwvttrcN5+s80v6+NLpnECOQQ6nG9FxLNzXuFgmqeM3IliykcYpjqQUr5Ik
         8c7ajAs0SiSwqxXL8tx1Nn3a9BZFRp0skAvhyHNLdvZDP7q2sCWN3hLzodPT7FzPNo5y
         Hmrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=apZpZXQ6psRu0bdck3rzBAhjhMGHzGWXjqKpkz6lq20=;
        b=FKmzy68R+lm2X1VNQ30zRDbEJ5ofNTNdQWgmoxPqwX7nJmS/wnaasJ9HlXjnAMTaJC
         lJ/uS35tJZsuc9bId43YtyMrgAc6ilzWvUHGkFiIvVAODKhAcIlcwyB8CFSgS19f86QA
         uRV+84W4SG8z+ffWgEE4xaVeGROrESj8FA43x4GPyBrsHU7nsnY+UCQdnxb8k6HEvI7G
         FM3JD/2xclIitH1TY1AVp1yQV0b8NWtQdo++aEq/gcJNVOlyEfBrxXaMBItnD7MKl6Em
         aMs/ciN9un07LeHBK9nwc0LROkd7R38AQzv7G8S9WfpMA++U/0rabeF0brJCknvyZlhM
         kAng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sdl0ANPh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=apZpZXQ6psRu0bdck3rzBAhjhMGHzGWXjqKpkz6lq20=;
        b=LD80SPej4iFvsttKTk3GCY0zsdmDjEJK7uuwRRm0ycKwS8f+LUm0EuL7Xw1jiFceoo
         c8jWYbTNQVBa5jXor+C5TVAGVc0hwLTMSKAfH7RSFJ/uPL3px4YXrczdJOfi+1LtJPu6
         WkSQ7MMyfUewgwNKQhjf5e6woiSAmLAChs3d6JrAUOZBpbxtgJXyldkGXKbOT6qjeSdm
         k/owLWFsP/LBrxIp7EDDsx4ngcgq8GrzsOPqBDkrKfuDi0CYstDtn0pZC0ZoD7h8GxXg
         DZkX/4ybB1QjYiMabwZum3FCPSs5G0hPr8IRAQj0dMi5dYCFr+I2FrdeehUzYQfmulxe
         OMig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=apZpZXQ6psRu0bdck3rzBAhjhMGHzGWXjqKpkz6lq20=;
        b=BJ1Z8Zo7+eJ+B1A9X9FmmVl8LswhIX2loo78LkxpJyViwTFSQ7QsehBqzhkEgMSOQ/
         GiU4kGodldyoYb9vbGIvxamFqR7Y2Rpv7XRfozQw61YrB3eB44gVPkI2tC9WXlFOS3zW
         mJKkK1eqj6Cep3vH5urgcmRqsPI03XSdf0yP2XoS2OD03riLiBNFACB3M4lTUDFZ1KNm
         0EqpMMMFawpYVRIqoxzVkW83+xwseJCV8b8dDIKLG6UvqB09o1jaYnExHKLyWAqld6oy
         YMHElcRtA2N6GKFtzow79euZfl6HiUGMVnC20EJAn0ZWha2WRcPBzETCBnun7oeZLldF
         gjaw==
X-Gm-Message-State: AJIora+Twq+LFCYz58nK8mcOlJhSAX7dMlJmiQG9zlkCD1bnXDUUHLq4
	XxslDTzWopc5FWxz9Dyuz5I=
X-Google-Smtp-Source: AGRyM1snQoRSocMDPEkfZUShfB2j066Kfa73vG0NW2aPW9/X2JLN4vGq+0pEiJ4d7lyFuoT+90hg8Q==
X-Received: by 2002:a05:620a:28c5:b0:6b5:e48f:97c3 with SMTP id l5-20020a05620a28c500b006b5e48f97c3mr3922359qkp.451.1658154422281;
        Mon, 18 Jul 2022 07:27:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:60d4:0:b0:31d:3211:a72a with SMTP id i20-20020ac860d4000000b0031d3211a72als181742qtm.1.-pod-prod-gmail;
 Mon, 18 Jul 2022 07:27:01 -0700 (PDT)
X-Received: by 2002:a05:622a:315:b0:31e:e250:c5f with SMTP id q21-20020a05622a031500b0031ee2500c5fmr9265971qtw.206.1658154421708;
        Mon, 18 Jul 2022 07:27:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658154421; cv=none;
        d=google.com; s=arc-20160816;
        b=cqgN4uZEpds8i3wO3/4ZB9G7xacPab49lc/JfxvAAJhQS1hN2Ls3lyB839FVyC/e66
         ioljLiXt3nFmz8SkCufKaKlQg3Vg0CnZT2FnSDd350HOEbJZdq554C/gb+FgAb59NkLw
         9CkujA+eE80rKDBVmr9xAYYu8959pl1KVUuPkeQx4USdTwxLqG6SWN27+k+ovtOEREgp
         1srKP+aJc44vHKGPRDJtxAkUFRGXmQPtsHx7VdaCSPF9DDdXq1LYPTOpPe4xnqM4xL7J
         H8az4BvAu2A6urdXgMSelnpwzsx0A1FSAJovlukekv2sHWYEGA9lXxnumwMGvIXECd5e
         pN6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Mtj0EAXN9U90VAEHDyJp+h4NOUaHKEG8aPk/GVml+8g=;
        b=mYqI7/lXKI1iVsrwgtznmygxx83edNt/8cDVQqrizrOGB7FrkPegaEHIzPH+ZdePB+
         nweaCs/lkAloQwhghFjsI/TS8G9AmiyRHMmiFEzY22cFqiep0Kt+jTTwPpexct3/n06I
         zbzN6cvGdT8zbKddJH2A4fQ4ObnyMMk226eucQsLrHlPoB/E/3V+szm8XPzLxtVeCSRh
         aeROLPDWDkUUZKTY46cVBd1TYc60Pr4w1s9E3gcj0WNuUOVU42YcgwbxII5TXaOI6Qfl
         XqMh7RoxdOTwzo4vvRUOtNhl4DbfjQrtPHs99SUxgm+1s14LWoDaYT6uOO0pwqQIc9tT
         vuow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sdl0ANPh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id f17-20020a05620a069100b006b5fa3b62dbsi7332qkh.6.2022.07.18.07.27.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Jul 2022 07:27:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-31dfe25bd49so71594747b3.2
        for <kasan-dev@googlegroups.com>; Mon, 18 Jul 2022 07:27:01 -0700 (PDT)
X-Received: by 2002:a81:5a0a:0:b0:31d:ad7c:8fa5 with SMTP id
 o10-20020a815a0a000000b0031dad7c8fa5mr30075011ywb.512.1658154421240; Mon, 18
 Jul 2022 07:27:01 -0700 (PDT)
MIME-Version: 1.0
References: <20220628113714.7792-1-yee.lee@mediatek.com> <20220628113714.7792-2-yee.lee@mediatek.com>
 <CAMuHMdX=MTsmo5ZVa8ya3xmr4Mx7f0PB3gvFF42pdaTYB6-u5A@mail.gmail.com>
 <20220715163305.e70c8542d5e7d96c5fd87185@linux-foundation.org> <CAMuHMdWSsibmL=LauLm+OTn0SByLA4tGsbhbMsnvSRdb381RTQ@mail.gmail.com>
In-Reply-To: <CAMuHMdWSsibmL=LauLm+OTn0SByLA4tGsbhbMsnvSRdb381RTQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 Jul 2022 16:26:25 +0200
Message-ID: <CANpmjNPhhPUZFSZaLbwyJfACWMOqFchvm-Sx+iwGSM3sxkky8Q@mail.gmail.com>
Subject: Re: [PATCH v2 1/1] mm: kfence: apply kmemleak_ignore_phys on early
 allocated pool
To: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, yee.lee@mediatek.com, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "open list:KFENCE" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sdl0ANPh;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as
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

On Sat, 16 Jul 2022 at 20:43, Geert Uytterhoeven <geert@linux-m68k.org> wrote:
[...]
> > - This patch has been accused of crashing the kernel:
> >
> >         https://lkml.kernel.org/r/YsFeUHkrFTQ7T51Q@xsang-OptiPlex-9020
> >
> >   Do we think that report is bogus?
>
> I think all of this is highly architecture-specific...

The report can be reproduced on i386 with CONFIG_X86_PAE=y. But e.g.
mm/memblock.c:memblock_free() is also guilty of using __pa() on
previously memblock_alloc()'d addresses. Looking at the phys addr
before memblock_alloc() does virt_to_phys(), the result of __pa()
looks correct even on PAE, at least for the purpose of passing it on
to kmemleak(). So I don't know what that BUG_ON(slow_virt_to_phys() !=
phys_addr) is supposed to tell us here.

Ideas?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPhhPUZFSZaLbwyJfACWMOqFchvm-Sx%2BiwGSM3sxkky8Q%40mail.gmail.com.
