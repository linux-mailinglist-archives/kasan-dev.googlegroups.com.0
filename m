Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBGFOQ76QKGQEY6XI5SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C1852A59E8
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Nov 2020 23:18:01 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id q15sf8350398wrw.8
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Nov 2020 14:18:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604441880; cv=pass;
        d=google.com; s=arc-20160816;
        b=GPMSgMRB1uoOD7QhK1AdgZAxZl2M2zi2L1L2Tewt7JgOAL3DvkloM0A4JBIpyYFJvi
         sHrHY06b3ES52W9sIb82RxFv7HRtFIbpuLYpC+q5jaKGqJcN67DTIIPzgApGbkXAXbU6
         y17n1SjUaYTaVASX/8So5EXuCAW9DQkMsjDb2pHgwi3wzYSqixm2rzosMvfrkseXSlLB
         cs9bSk2UAMTixGoj85kqZ5gZhEM689jVFaP04kOyL3ohq2tyTP0bzM+BFI/A2WeE1t8E
         60MSuquDvdqnCnr7MdeQxqVvIeWghIHllHdNsRTRyNiBBr7CbH4Ptm96qyolHkRPKtVk
         iNDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jzEjgswqKSQa0VF9p3+JtvuDAyRq1H6YdLjW9/Lvwc4=;
        b=BMvcT4R0rKM9CbFjV3U8KV9MHhluqL/iJ2jlDRDmrXE4jcK950dncUuqjBnNDisAEv
         O39TEqdk23h8ISGJpXf0vgd6BiozZupNnIEbtJjSf1TXpayueDwblxxfbhj2d+px0C1I
         3wHUyifDUJW7xIFCIrhNm4h/QMOQZJsvibJh5fTnhoKPnN6I6RyO1TD9U0qiejo+6Xlf
         gPr355jLjKZgJRyXGIrHagWkDw8gIjChFpXqeC47rGFjw4XAci13NYr8Uc7ZQxTe4/Rh
         ZgzTs95z3HNSmytxDncXK7407RrmaB5gMrLFoL/EuC029iHiOS7jMEiRqiiQFI6OhdzX
         nD8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="FeZn//b1";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jzEjgswqKSQa0VF9p3+JtvuDAyRq1H6YdLjW9/Lvwc4=;
        b=H/0QeYoTJFtr/e0DMZJ3N+B/m/S3Cp3947dFsmREewnmlBvB9hjgQcLXlmYex89OUr
         umKO193v91c6T070mrqV0bonab8g+AFyGYXx/eAahyQG4j1iJK0NNeRRs15mrvKXtKTb
         feeZRXekCk9x1KAwjfBB3eFBiaTAZASpju4hX7+KkfZTUgWVLZxc6eVlMW4S4SQDlPvJ
         qBCTdEapy4mU4N744DySy+yOUZr2BhytNlV4r0F2GSCEztmEHO9rhBOlk0+7fS5qhuuL
         SeMYPFAh+xQYpxR+CS/X4oxdCngj9uj7COt6AXZP4Eu9WObjfevk71uUxWpnvqx4KbZ7
         mA9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jzEjgswqKSQa0VF9p3+JtvuDAyRq1H6YdLjW9/Lvwc4=;
        b=HahuTD8xLlmqS7JC0r6J3ud58NC75ZKynaA4GWa+1vDmgbKbjxBxGXWZaWLH2BIfqk
         IUX3g3KXtZJpJ4jlSwP4dxY5CWLwt1O/LGFjdLLPu2DLkYNwNeFxy//jb2QwWWxIMItS
         OtiY25Y8b3v4MQOCsE/1BSGhXHq+OlTwkoAsv3fcA8jYWPDG+nLMOUSw6GBgyodflpNG
         FHHoPIkjVOAnr6BO1tBU/GjqkhQhWxIOF4BmqgSAWLxXssTxUgE7znFfQQzSR7GI7AQw
         pnHi1VnfgPJkzvRzmoPwbQWQbefuc9GuzOkkf9rhGgDfd0xCrhC8kP1+Saco/Vkyl6ed
         YF6A==
X-Gm-Message-State: AOAM533nwZt/lXVutGu+Mijz907WPrhMKvJqOIAX4u3fhdKsIgfm7uE5
	BjzthQIgSjdovoIgXcsFmEU=
X-Google-Smtp-Source: ABdhPJxgHf9yLRQhOLYhzpONxg2UsiVWMJ67F5xohZRRMz/lkqnKQNM2FP0Xli1eqWoC/o9+4fHMOg==
X-Received: by 2002:adf:8bd5:: with SMTP id w21mr30754169wra.301.1604441880768;
        Tue, 03 Nov 2020 14:18:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f00f:: with SMTP id j15ls194333wro.2.gmail; Tue, 03 Nov
 2020 14:18:00 -0800 (PST)
X-Received: by 2002:adf:f3c7:: with SMTP id g7mr30392776wrp.394.1604441880021;
        Tue, 03 Nov 2020 14:18:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604441880; cv=none;
        d=google.com; s=arc-20160816;
        b=mTTMW72imZpIKJz/vLYEtYt/micoPnrQaNcqENVzcXxJmF1gw/lTHCI8CdwyPoU7np
         hklaw8On2L9UnqB2iVyMm7mbtKrUcelMmXjuqKYyzldsaTVIiO49Kl1erZ7eSyFSUd9Y
         Ffsh8Sh58Wwzm5QEswLWzJmaUAxs4fXKoNVLnA4lyQHbD44gpF3D1IGSXA8A02VZeYsf
         dxrznchv2Brocn+4QMfpOcjoy9XkUW/yPIkCUveT7KM8jt+oYZteZvndct0FRDGQBRMb
         nVBjXS1bWoN/B7QMXQrZDiKeytERLoyqaOP1LV+vW5puLe8ElTwvu+d9GlSh3rt14Dzz
         y2Zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=z0GfssSb9lxM+saQ7V+1ta/Gt8yaqMW9vqfv+WXLTwo=;
        b=Big7U0yY+lt56FINH0ARgrOgr2B8/K5fuGFPf/MdMJcLWZehzrMRmZsIwwowukLETE
         ghyx5F2c9O6SNsLjjoJmqImd7Cx8bZH9VUAotZgMrWyFwJEXq5Vmmk3ewO72TSPLqSQm
         l/BR71brvFsYVICfd5iatUEaaLy/bHMOr4/MNNywOnppOZ2Nu5ZKPHa12fCCno346RVJ
         EPFQpzp072XfgYZSi8p2813ZGRwED1L+sG1GnGdCrtP36ncUitnsNZHkmzfojGxdnOF2
         rPhgdA1F5z9HXliGAaKFBqXlMEd9vSSyU+Nu17n4OIqA4IaEDbb/g29/wrX4C9pv8/Zs
         9PBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="FeZn//b1";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id w6si7833wmk.2.2020.11.03.14.17.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Nov 2020 14:18:00 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id i2so20808487ljg.4
        for <kasan-dev@googlegroups.com>; Tue, 03 Nov 2020 14:17:59 -0800 (PST)
X-Received: by 2002:a2e:9c84:: with SMTP id x4mr9140798lji.326.1604441879292;
 Tue, 03 Nov 2020 14:17:59 -0800 (PST)
MIME-Version: 1.0
References: <20201103175841.3495947-1-elver@google.com> <20201103175841.3495947-8-elver@google.com>
In-Reply-To: <20201103175841.3495947-8-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Nov 2020 23:17:32 +0100
Message-ID: <CAG48ez0=_ZoUsZvh99UJo7GziiTqZUKYgqHzvd784a-Fs-kEcw@mail.gmail.com>
Subject: Re: [PATCH v7 7/9] kfence, Documentation: add KFENCE documentation
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	=?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="FeZn//b1";       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Tue, Nov 3, 2020 at 6:59 PM Marco Elver <elver@google.com> wrote:
> Add KFENCE documentation in dev-tools/kfence.rst, and add to index.
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Co-developed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez0%3D_ZoUsZvh99UJo7GziiTqZUKYgqHzvd784a-Fs-kEcw%40mail.gmail.com.
