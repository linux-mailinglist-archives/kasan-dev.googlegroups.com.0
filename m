Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHHQYSDQMGQED7CSJNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id DE6C43CB36C
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 09:41:17 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id p13-20020a9d4e0d0000b02904cdb63ceafcsf18860otf.6
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 00:41:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626421276; cv=pass;
        d=google.com; s=arc-20160816;
        b=rMLcBddT+kj4HXb8mfHf3/HU5bgZ7rha63IxWYWw25u5Nf8KxgvQVsVxn1rghyCbrN
         BCXpX6N14Q3RDOHi5nrVT32NYFl2vjNBk4gXLRSKfzJuANK2QZ8nSqCnJexSMhlkM4fU
         EMKL/Mu4YF88hxUF1lGhDl08L8onBVMk07wZn5A+YbRse326JlA0yS984G9CdlEdte9Z
         wdHp2qWTltJXbBFo4TkpUnHiRwv9280GW8eUXXs0uIWSoMJxuw2uIeli5pQWgf00egtt
         wmY84rk1WxfocLBERRxgMkSmrRTJYsfsX4sOj5emSzAQ3b+5TB+1OCJP0yzKRXJRA7zG
         v+GQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cLJOlvAfrAfnK/yrNtNHklVgX4/C7WiFsnJPy4e/gZc=;
        b=dX2JP2Th/VIa1ZQLaD82m4g4cZDHZZoFaGxYdhESd1yNBjAS0ri/95uINgFb2Ci1el
         DpV+3KqXMBImrT/8UnvgrIVpyNvIcFFemaKkE9h1VvOUHI5HbEoyoR8d4FTuL+5O5cIL
         vXAes3qbGuf/IZxgM0qOU3ZvWncd6LZu1NIZY1eJ9ySqXsAfTkM2uNyMql9WAo3dp/gN
         UylKR0z/sl0LtOt8kGt6uzSpSSzPs08F9s/zt4OivrrgTlBr318lrP/1sq5pvMv9gzd7
         KMAN5dHdOgeps4s/pBznB8puO1D9mjKhqNX2+6iHXJyFZPyBsQAJ57o0yNPuNOvdwYa1
         VR6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cJEwK2QZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cLJOlvAfrAfnK/yrNtNHklVgX4/C7WiFsnJPy4e/gZc=;
        b=gm3LEAqZDNK1x7yf5OCqbFScE/aOFHtbkbscTVTCrBAOtGvMqV8OKheoIaicuUhRLV
         xPnqjMJ0SWm05ivVYNA7peQgvpAUl2vBgtjGPIpzClqffvITDQmNnJWrFGUv4khPNLmS
         7cPaaeP2dQ38CoyC+F8mz2I+YYu6e1WD9ZRTXwlL1idJaKcfeg37RV/tY6qeV5fnkCv3
         YCVcA85hh3sF/MIxvhUnXIYgGVvT6qPjaTdNoECzqxpeqKYkl8on3eYH+IQ6ZC278vI4
         txiHS2+nvuH7ppvh6dz8rpvS063SoAsaVo5yE0HaLw+03RiagHtselQ7cOxtuhc9ATff
         5FbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cLJOlvAfrAfnK/yrNtNHklVgX4/C7WiFsnJPy4e/gZc=;
        b=nGGjlWn70JNd8gmKqCKnbcVoJ+vvJ9hYF5UcATpeAofIntuIzzoOqyuk9QVdBwnXxt
         5Bplbk/CbAAFjgnMl5ui6DPxzIYuhVy0TWy9CoiD7wHOnKP3W7IKBvUVOmm/VXEZOm3F
         hgjZwiG9Cni/laWYhTS+WEX/fiZJPyNtjNH8RoeM36FjhRGbGcoYweqDhFMNYT+60xvx
         Rrg6EEmeaCd7PslwZCW8O3hTa2uCs4lmqXmuIrp3oyy7aP6kw6zJPaUSZSduCH4Uy+X9
         pgGuVSqqj8n2yLJQ99npweFFPHo7jB2Dku7NuyprUQtbML8TfTUwliEWn/tnTfO66mt4
         T1nA==
X-Gm-Message-State: AOAM530fv7fV+Sp4YceGUwbYlPN3SkvkS7VVn1gP5HV63Vav7HztzkzN
	HQbeN4SE1xUtrLuhhRT/L40=
X-Google-Smtp-Source: ABdhPJwaS8c58VOuEzagH5b6vUm9q83bu0Kfd9qhAci4LnrIhEDvR81Pdpu0pbYqZTMTrhW05HSnuw==
X-Received: by 2002:a05:6830:138b:: with SMTP id d11mr7044540otq.341.1626421276616;
        Fri, 16 Jul 2021 00:41:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:bd6:: with SMTP id o22ls4223547oik.1.gmail; Fri, 16
 Jul 2021 00:41:16 -0700 (PDT)
X-Received: by 2002:aca:b902:: with SMTP id j2mr7045874oif.128.1626421276284;
        Fri, 16 Jul 2021 00:41:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626421276; cv=none;
        d=google.com; s=arc-20160816;
        b=SOHkwQbr/jZXpcZz0U+oEeDFf2ZzkuePAZIRzTRTdwOfavNWMTgJ8INM951X8vr29w
         AOfeX6K3Mso54yILeHwKDSYuU8FXkiSHlGpgGyVmKQZWyHEQdEeC3UlDnt1xdt1gPiS3
         n4MZ4eTXOkJb0Ne1u61i76iuE6zwZmWKmE6n27x0yxdxEo63HA4thTfhJcnhvVtM++Q6
         uUB2b+Pln3BeOhboxKxlJHHObEELBJ9p+ALPRKodkaVWbP5RlRjCImxMaZDMaq3OouFV
         2GfVoTLPQo2O5MtimNMgGFCAEJUWoUBFtYOo/ngXsAGyd3/cIXKGUyTwQIzN45KfWtqJ
         x5iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ca6CcvN4gIl6bM0OQN4a/p1N8Quw1yYHoBlszGmTDtE=;
        b=kyZxy9fDB39w7kpyDRXEJQ3HbfuRtwvxyorpssHhHTNR4WDTc3hK4y5+v+kcxvi6iE
         RtcdOLnGrj/Td4JDwf9hkmUb7nXTMty5UxUUpZj9I8gJgAyA3gKosGTfeMuwL2tIMy0N
         9f50/gNqkM8su9908+JiGoXQpLFHz3kpvPgKq53b8gH5YaQOsfD2dkAWPAxwW4APhivm
         xunON185nbG/VReUIL2c5rxOgY+rcGb632oKNCQIca7NN74gTH+ZFAP7Mn5/YEFhwoSY
         WXFDVL3C0SkwfV9JIIM7zEWYPYUuNG+7HlFFkTegGx88fPO+W4o42PAV///rTJFBAyNF
         YjlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cJEwK2QZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id j26si1366004ooj.0.2021.07.16.00.41.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jul 2021 00:41:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id t143so9896482oie.8
        for <kasan-dev@googlegroups.com>; Fri, 16 Jul 2021 00:41:16 -0700 (PDT)
X-Received: by 2002:aca:fd44:: with SMTP id b65mr6942794oii.172.1626421275836;
 Fri, 16 Jul 2021 00:41:15 -0700 (PDT)
MIME-Version: 1.0
References: <20210705111453.164230-1-wangkefeng.wang@huawei.com>
 <20210705111453.164230-4-wangkefeng.wang@huawei.com> <YOMfcE7V7lSE3N/z@elver.google.com>
 <089f5187-9a4d-72dc-1767-8130434bfb3a@huawei.com> <5f760f6c-dcbd-b28a-2116-a2fb233fc534@huawei.com>
In-Reply-To: <5f760f6c-dcbd-b28a-2116-a2fb233fc534@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Jul 2021 09:41:04 +0200
Message-ID: <CANpmjNP8Js3nKeVfwPqV7oQaBbGebKxFYRWe8TifTduP2q86xA@mail.gmail.com>
Subject: Re: [PATCH -next 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash
 with KASAN_VMALLOC
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Daniel Axtens <dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cJEwK2QZ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as
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

On Fri, 16 Jul 2021 at 07:06, Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
> Hi Marco and Dmitry, any comments about the following replay, thanks.

Can you clarify the question? I've been waiting for v2.

I think you said that this will remain arm64 specific and the existing
generic kasan_populate_early_shadow() doesn't work.

If there's nothing else that needs resolving, please go ahead and send
v2 (the __weak comment still needs resolving).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP8Js3nKeVfwPqV7oQaBbGebKxFYRWe8TifTduP2q86xA%40mail.gmail.com.
