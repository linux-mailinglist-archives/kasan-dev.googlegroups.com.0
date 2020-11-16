Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQ4HZL6QKGQETGR3YSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E19C2B44FD
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 14:51:01 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 4sf6678664ooc.21
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 05:51:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605534660; cv=pass;
        d=google.com; s=arc-20160816;
        b=t5mbVzs+BUu6bpmtUMiwDF5Zp3AsTwMHBISLHQUMUasIjGaBD8a06QYaQsoIZDIh5P
         C+3blXxX4z1ugBs1GaOMenvsok4Kf9zxf4KjEtjqdwiT2LZk1Fhj+zNLLGK1kBaACjJ8
         U3NyH4H/aM4UWhFaT0KCZIuJAaevBdof373z79TvRixPftvlDhFwXakm2yFWwldNDwRl
         Mvhy1edOq/6J3IAczucjNP9aLbI18QBGyh4cmbIZdwm+uKR1Qq/HVvEJRfhQzyIN+IhI
         a3DMmyiRmmiRTk5HKzvNK2KcNYxrbjE8krPLtysh4ovclUK3p89CqWImdvSQxlfEvTP8
         umgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oJDCZymihL7cr6xzAoxQHgbPSgKgB34TQkvY5tmvabQ=;
        b=phyoJbqGeD+8w2sjTeormYw+ni0iu2517RfyQJUctkGOGBqRkXtsRPWowrQ83r4HIe
         XOJdoaLWIFe1/tU2BIsi9JJVcI7loaH3kK+p8DTAsBDVqsgAoxTAywAbJIQQI0rvUgsR
         LYN8Vd3Inv5mgrlwNIQVWuEz+gKZ2IT0WZll/FKa6DgVNW9NvTsv3kPHMZQjHZOQCTaG
         6PQB4E1wgjB0NCxlwCIXBQ92I6pZ7hZnvSUkhhbpsZ7Fh6Iu652UZ9N7HwvF6wevSJUP
         z7iOx49Qgy9CG9BWLi9XkidQiNW2reQUojXRRKVFebmSFF6sOQQ6j8H/5T/7Ow4ubaF3
         tagw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Qd0w7ayR;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oJDCZymihL7cr6xzAoxQHgbPSgKgB34TQkvY5tmvabQ=;
        b=Pp/Lav61rtCQM7gs/SiQww/WOX7phgM+oTbmFQL35gchK/A8lPSLjBLmZ+pTweY++X
         +wVtG5W0uLRwOv5KIxwG0u7PBVEHhX6rJt+5YO/gdYNMVbX3TtQKs+2DT+FqR/x4a8Ub
         1l1ft6uDoRrVm2EMOUELtRagREeAw+DoHET9QBIQfBJCGDLvpiq/5aksJr7ClVbaOfFM
         CdC3xQ+PHSjIFVCBgSX0qV7zLl1OxS7NJE9nt6rAGmqalc1vznFg6t1U/kQw0sdLutAS
         fxwFB/g4fNggThwHGow+A6M+YotTg5HaQdmqwp2OueVIqdFYGG8nm/EDvGi0r3GZnmIh
         CDZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oJDCZymihL7cr6xzAoxQHgbPSgKgB34TQkvY5tmvabQ=;
        b=m2eQ5Hhh/4Zd2rHFDKuCTyyDs2JJUurc252hOYneicXczENluvc/tNBBx1Fe7nFB2B
         3JVv0UoAzrbw6PVDafwnlkWY70cFgDgzDrdRzdPoqSLBXpdtzZ1pcuT8s1Eoctec++Kw
         hYNGeeKKrLOihL0n5OlKSXcRrGPfJ1aACVb5FNDeBjs6+aM+07cLwutZLpgq0hX6a7Hs
         SZa1l72aBPcSGQdpzu95b1OPmB8ykdQk7ZCEWO3RxH+V6NKw0QTrxCqE8fIyO1bhZTlO
         c9y07ExGFJzHusGtPrEY7mTN9nQAEgxupwiz8yQ2Mut43rS3uyklLjsFwDSOgc+a9ZH4
         aHKw==
X-Gm-Message-State: AOAM531uTeRvyX2114j2KnOtMqqkOYxkZ3FEZdeyFLm4rQs1uu75QOgl
	VlLGos8ZRa75kBJI0S0JYP0=
X-Google-Smtp-Source: ABdhPJzPryixm+uVyMVgxmxSSiGGB2pXh24QDCYsHdqG2ujLDZ26lj5SshdqnQK5nTmuRltDMIannA==
X-Received: by 2002:a9d:76d7:: with SMTP id p23mr10842375otl.180.1605534659926;
        Mon, 16 Nov 2020 05:50:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:1ca0:: with SMTP id l32ls3271273ota.5.gmail; Mon, 16 Nov
 2020 05:50:59 -0800 (PST)
X-Received: by 2002:a9d:27a5:: with SMTP id c34mr10285651otb.303.1605534659490;
        Mon, 16 Nov 2020 05:50:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605534659; cv=none;
        d=google.com; s=arc-20160816;
        b=C2pIy5ww55Qecm1GhY41GkzHccODkOKfk2Z2wA5ExntPeErBaU1jHlq4kReEiqCtwT
         VGMrysS++Lp10iRBHvLsP62zwy5bMyfamC2HHfYoGm8j6iLVzNuPcMmVrSew9RL8RV64
         CEskLTr52L4Yzyern7km/wTnixMYSjwPzxf5zKxrEJ2swbnqY5t/2gslvdD5R5yhNjzN
         w4QS2cHP+Ftfz6w9dotTjzz0kg7GoxLq5ZfB/LMdhaWr1TUBZTI5F4FnZx9NBGiJ7uQr
         jJRMsfnJEmddeQ+KQELOphvSIHy3OWsJ5chgVmW+fEFPP1CwsjxdKkIwTG3R6yE4HSMH
         IiIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Rn/GWbCehAJ+GBDtTEnmHyxU7fKIylPW3sz5YfB6oF4=;
        b=vM/XJg0mHCVJIa6NSTIirahllAJILCXmMnzNTEI3Ww3q9wSye43UzKUxTFcsaHkHIi
         dGlMHsIkJafPI+Dlzoe8tX6uTpCu0rDmNY3+7/UC9CualTTPX071jOHYfz5q2bSb53L3
         /aDDvHkdRgKRjIopwUrlLTVbbkkMykc07dZByCCxgG6fClSKFOSWCVZ5ffv74tIPqR6x
         E4IH2Go5zLTQBy6E1deQ9CmqRDDmDhpwFCUeFmfH4iOr5DvrMdt7oi+DAV6JenvXtLRk
         fo/3u1MMYpsoDuCZhP4FuPMm4FbN+YD/hfVk3zRcLOdcUWY7JqhIOhhiPFq763hn3VJ/
         yz1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Qd0w7ayR;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id i23si1149316oto.5.2020.11.16.05.50.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 05:50:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id j19so6482475pgg.5
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 05:50:59 -0800 (PST)
X-Received: by 2002:a63:f20:: with SMTP id e32mr12949674pgl.130.1605534658700;
 Mon, 16 Nov 2020 05:50:58 -0800 (PST)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <ded454eeff88f631dc08eef76f0ad9f2daff0085.1603372719.git.andreyknvl@google.com>
 <CACT4Y+Zys3+VUsO6GDWQEcjCS6Wx16W_+B6aNy-fyhPcir7eeA@mail.gmail.com>
 <CAAeHK+xvGZNwTtvkzNnU7Hh7iUiPKFNDKDpKT8UPcqQk6Ah3yQ@mail.gmail.com>
 <CACT4Y+Z3UCwAY2Mm1KiQMBXVhc2Bobi-YrdiNYtToNgMRjOE4g@mail.gmail.com>
 <CANpmjNPNqHsOfcw7Wh+XQ_pPT1610-+B9By171t7KMS3aB2sBg@mail.gmail.com>
 <X7Jthb9D5Ekq93sS@trantor> <CACT4Y+ZubLBEiGZOVyptB4RPf=3Qr570GN+JBpSmaeEvHWQB5g@mail.gmail.com>
 <9d4156e6-ec4f-a742-a44e-f38bf7fa9ba9@arm.com>
In-Reply-To: <9d4156e6-ec4f-a742-a44e-f38bf7fa9ba9@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 16 Nov 2020 14:50:47 +0100
Message-ID: <CAAeHK+xb4w1XSe_cXeV77d3VkHq6ABAKkKuEaFN-uFVY457-Ww@mail.gmail.com>
Subject: Re: [PATCH RFC v2 04/21] kasan: unpoison stack only with CONFIG_KASAN_STACK
To: Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Qd0w7ayR;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543
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

On Mon, Nov 16, 2020 at 1:42 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> >>>>
> >>>> Not sure why we did this instead of the following, but okay.
> >>>>
> >>>>  config KASAN_STACK
> >>>> -       int
> >>>> -       default 1 if KASAN_STACK_ENABLE || CC_IS_GCC
> >>>> -       default 0
> >>>> +       bool
> >>>> +       default y if KASAN_STACK_ENABLE || CC_IS_GCC
> >>>> +       default n
> >>>
> >>> I wondered the same, but then looking at scripts/Makefile.kasan I
> >>> think it's because we directly pass it to the compiler:
> >>>     ...
> >>>     $(call cc-param,asan-stack=$(CONFIG_KASAN_STACK)) \
> >>>     ...
> >>
> >> Try this instead:
> >>
> >>       $(call cc-param,asan-stack=$(if $(CONFIG_KASAN_STACK),1,0)) \
> >
> >
> > We could have just 1 config instead of 2 as well.
> > For gcc we could do no prompt and default value y, and for clang --
> > prompt and default value n. I think it should do what we need.
> >
>
> I agree with Catalin's proposal since it should simplify things.
>
> Nit: 'default n' is the default hence I do not think it should be required
> explicitly.

Fixing this sounds like a good idea, but perhaps not as a part of this
series, to not overinflate it even further.

I've filed a bug for this: https://bugzilla.kernel.org/show_bug.cgi?id=210221

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bxb4w1XSe_cXeV77d3VkHq6ABAKkKuEaFN-uFVY457-Ww%40mail.gmail.com.
