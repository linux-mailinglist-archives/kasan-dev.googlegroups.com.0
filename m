Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMXURGBAMGQEH5KS2CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A65532F2C3
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 19:36:36 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id b7sf2357034qtj.16
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 10:36:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614969395; cv=pass;
        d=google.com; s=arc-20160816;
        b=LN0WgxZc3GSs6BrBzS/u2v5qjNinboq0ogd0WW7j93+/hN6Ysr3XuzCewvHmezfRrl
         1NYDrNWIvXFlTXc1sv1CcQqv0NxFBQgdy+Aiqzo5et7+JZpWt75HT3fXXoCDv4mfbc85
         w34CsnQCGQX6JKmmO7Dnreu3QvUn73uhwWTJYWpvqPZc8JPkC3h6+Gr1pNafsuMpbUnY
         onsAkFKJ08e7LWz5MY+0opVSVKu1d97+GvLM6x9uDS2B2756ToqAYy2d8gT6Z0jcrUjz
         FLaMSDWWFCgMgb4hOUUfpbdtZT5i80HkVoyUyL1YO35NzSLk/vnQynydRib7NC3J+rXn
         E8gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mul53v8nu3gsmpxy4Jk5qLdrm0Gefv+LnuOx4K8eNgw=;
        b=armyjETbaBrbBL3o87wyVKv6lesMmIXw2YoPqFopk6DpjzfhXT47amFSnsU8tjM1bH
         IPzhIUUOdpLZXnPU6Gk3xvXXrWB4dARegD0sxmRICnFEBooXmGr2JsV6uiX7xrdOcmn5
         gksHHdCpkslPVmogftXTQQ/JYBDU3zfJn4MPVzEw0pww8W8238nMw0Q6Z3w1PuhLMI/P
         f0fyB+30PjdqCIprUZzfuY2opJOdij7RzzplfnPoCNLVYdGK+mXFSIR0rKsm22Tasu5f
         7xdeZkPCQzvBMF2qHxBHPXsA3F5SKdAvzkjDVgIJt2NgsMAjWYm5XhrIILn30abJclSe
         jARA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Pr7TbG/K";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mul53v8nu3gsmpxy4Jk5qLdrm0Gefv+LnuOx4K8eNgw=;
        b=JJyBMa5CfBUU3XBqcSczVq+1fVvH8xau+asd1bYFbBpZOCHo15AFT71eOweJvF7Jg3
         S9m9MZfLK6EcBLlVSlyZcBSIjihcMCIQ5qbbosuGhzyZoQbEjN1x2NZAnSuzG78IiTP4
         /2xnt0SQ8J3VML43tXuJvSfm6GHKUI1DrjxdC5WvQx6w+1vKhWRpPJ1WDfMWkoBZ/541
         Lgm+vbkK336YSYP/sCfNTzwDuhp0X2PdYZL7MqC6NZv3RRSQ5Z5lPwNeJ4lZSHaqYscg
         2k1QaueJS0igNotM9eU60Bq2135fpWiOY0KvLBA5km4MhLQG3KYczSNxjCpLRTvEz0Ah
         SLFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mul53v8nu3gsmpxy4Jk5qLdrm0Gefv+LnuOx4K8eNgw=;
        b=M885AydiWfiJWLgOnG2Tg2438yZKVnXCXxx+Vu1NcfNEYyx+PtcUtYNGe9Xu2zT5Lm
         oiuoTZMG0A97RMQAY9WVlPG0CLit9vnhbEfTuplongBSHvudNktU2lWcbKinZDqrJA9z
         VwtLDCxMgpVwGYVE6qDv3nLmqZ+qax4bz8a2XsnqhFnkWYjbh5Yiyu765FTleExHSOcr
         VG7DNJWLQE+NMobmRaZ/amuIdVxJNDaEJjr4PYTUx7Q5w996A3gLEZRBjftmXjMX1942
         EDDamsRGtvHDLqsEVV2tvd8iujOtszGdYR0wd2Kt3DvXuwkyIGo0p86/vl7+CJsk65nY
         Q9Yg==
X-Gm-Message-State: AOAM530oDnD2cjp1CGje+XP+UZ9gMUj0aCtvhb8WFYypopRpRdzQljsu
	E74b9PAvIJSVougxTNUucG8=
X-Google-Smtp-Source: ABdhPJwydByW+VtaEWyF4Q0gvhdA+El1TfXvAzpe/Iagj/KwDKl0G1P+uY60MEUZkM3E9aimfoeFMw==
X-Received: by 2002:a37:c441:: with SMTP id h1mr10512277qkm.123.1614969394933;
        Fri, 05 Mar 2021 10:36:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:7c5:: with SMTP id 5ls5393474qkb.8.gmail; Fri, 05
 Mar 2021 10:36:34 -0800 (PST)
X-Received: by 2002:a37:660e:: with SMTP id a14mr10083638qkc.35.1614969394530;
        Fri, 05 Mar 2021 10:36:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614969394; cv=none;
        d=google.com; s=arc-20160816;
        b=Zsz09R04AOAR2A7I/CMRwW+sssE3VI+CZMeUvEeR5FVA3cp8xbn6f7sX0WVzRBqZas
         9cvifr6gNV15y9b0SWKiOy/AXvs9TlWpDszGc/HY9gxY+59N3SLkVvfYjGYMoCLPk+3m
         3DmaEAA+KvnMTx9N/cP1+lIgE2zbsnKQZhtnNGSv7FYc53iYIyFbrSkpMDd9bZHZpIHJ
         6+l7z7v5Bqdd5eDPGrL1VnlW8m3OjUVc13pMfXQ0/u91pbctU+s5Ncrykj/IQYwZ8iag
         72442lbP5SA7kVUJJPw+uD6E/p5vMEPsEm7zQG6XDD0rMGbAQfDgB10qwc6ZEQ3LlH66
         iYcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FIKDSeJcyDRF/JcIaMALQVFMevv96FuXnOuyi9T8H68=;
        b=kpVDjk41THZuU3QKbTn+/KwjyJEl7ky+C/0mnGA8mbjd79lRN2VnMpWEGgt1kA0tRq
         8xEoJYIXS5AsdWRxsxi35W7hPg4rSIwbDJUrIY/zcrb7hFFqQ+r5yitdSOZjLANhuYln
         bN0qC5+v2482tyuAy1dUQddTO90CpGjAHlgWOSVIPKMMxfYgx/XdIP1WgYxY2jqNDdAH
         dxmA6Dr865ZO987dn3KP8oS+/l0/k4RlqCfrG/z/6ZQX5YMIpnTn6gX/OnWgi/wcxoSJ
         96ukk8uV80vkZGNN86PkOVFI37l/gIUmdXNIducEnI/hb7+dGY/HS9lBYacMLtVXFNPS
         GF+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Pr7TbG/K";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id i17si85119qko.4.2021.03.05.10.36.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 10:36:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id 192so2807592pfv.0
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 10:36:34 -0800 (PST)
X-Received: by 2002:a63:f14b:: with SMTP id o11mr9952406pgk.440.1614969393622;
 Fri, 05 Mar 2021 10:36:33 -0800 (PST)
MIME-Version: 1.0
References: <20210305171108.GD23855@arm.com> <CAAeHK+yuxANLmtO_hyd0Kg4DpHh2TLmyMQEXP58V8mLoj0vtvg@mail.gmail.com>
 <20210305175124.GG23855@arm.com> <20210305175243.GH23855@arm.com>
In-Reply-To: <20210305175243.GH23855@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Mar 2021 19:36:22 +0100
Message-ID: <CAAeHK+ykdwBXETF5WkrWnbzzS6RAJdmqZ3DrFdM_7FoXZR3Wqg@mail.gmail.com>
Subject: Re: arm64 KASAN_HW_TAGS panic on non-MTE hardware on 5.12-rc1
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Will Deacon <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Pr7TbG/K";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::432
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

On Fri, Mar 5, 2021 at 6:52 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> > > This is weird. kasan_unpoison_task_stack() is only defined when
> > > CONFIG_KASAN_STACK is enabled, which shouldn't be enablable for
> > > HW_TAGS.
> >
> > CONFIG_KASAN=y
> > # CONFIG_KASAN_GENERIC is not set
> > CONFIG_KASAN_HW_TAGS=y
> > CONFIG_KASAN_STACK=1
>
> From Kconfig:
>
> config KASAN_STACK
>         int
>         default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
>         default 0
>
> and I use gcc.

Ah, that explains it.

Could you try applying this patch and see if it fixes the issue?

https://patchwork.kernel.org/project/linux-mm/patch/20210226012531.29231-1-walter-zh.wu@mediatek.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BykdwBXETF5WkrWnbzzS6RAJdmqZ3DrFdM_7FoXZR3Wqg%40mail.gmail.com.
