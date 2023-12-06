Return-Path: <kasan-dev+bncBCKJJ7XLVUBBB7HWX2VQMGQEXZYXATA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 8484980632F
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Dec 2023 01:08:29 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-425613509a2sf3798641cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Dec 2023 16:08:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701821308; cv=pass;
        d=google.com; s=arc-20160816;
        b=pn50MCzQWMFuZKUd4OdsuBFBniqhAXyIL7fgyTRz5Ne3V+xCdN4Q3NeCSJy2EyS3Xh
         ko+LzkHXV4lc3hRWMpOP9BMCktQOoJnlx8jItWYql0KnXyDwtLJUznIQRDmWusJvQFWP
         Si8yyyomF0UH+MUOlyTVwjkEVbEQcrJAT9RjOjokCGuTGIZCtKurfPBs4e6OfAo3767B
         UDZrQO1XzdhvLUtCjxzfwaXoGn8at/WtttBTbJy4kusfsaIZgVQb0QnzR1O2Nu8ls9tk
         Pr166o2rC7cjxAbkZQkcn30lryGn2NSPNGYHJhfzNK4NhGykJYpCWKZpQayZdIs7VdoB
         h/kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=RQFZqqnCuTYmoswhZ8eQ6/A6J0wmF0eRvi6iuX/B2TE=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=F4ha7Hz0+WzK8aaLsVolD0tRxCswYSrqFgpb9+U/aF2ATKCdpgzdjrFvmorjgWb6nL
         p9Q7rpVkdD87OCuCYeL1bqtGhJHIU7a5YOuxnE9Z8oQ5fU3f6BnrcTHdn9pNXkKo/08H
         Dd/QGo3RuPHJ8aPZDCRPPlFVtM67ZfYe6EZ6Y6O1LpMa/XK1Pg88ebS0A7t7BzXYU4Fg
         Fy7vqlndLEvMBr5p7cuUitVOHCV92YVikehcoVkbqDbxIRV81Ci3ttss1ERA1Fw96LdY
         cept1Bi4qSOhRHdnr9/lbyUDgRnEFcWgkyBPFr3E4T1B/cVfz/7NjaZN1SQ6OgiVlF2S
         JLzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SO3vPxFY;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a2e as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701821308; x=1702426108; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RQFZqqnCuTYmoswhZ8eQ6/A6J0wmF0eRvi6iuX/B2TE=;
        b=JbYqs63ubtrbA7ZtOvozyMGkSDdnkZHLBQuaOmcehR4aMLq2fIQ+PmhzCbhqkmJZ8y
         Cso10IbIoEWEFCzZNZ3pgAdQRB6xuaYIU5cuIhUZaTmdMqPDmuHmhwjYNN0a5JYHCNgs
         KiKDB3Yi+Kd/1R6IyEJOxCzj75d9yKd890gDhkwu2uUFwXkXTXKg/Nee3FV6KFgoQArh
         x40hz80xwDFff3EuyRTZeRX+G81Llo+9XvZMr8XEC578IsYWnJezhbm3GL1ETl1JwWFa
         BWqgo8NXQpovcNXK5kAZnef+QPeLjE2B6a5i3Xyw/ahbvsIc9PBN0ouhzIupZmQpE2dj
         SJWg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701821308; x=1702426108; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RQFZqqnCuTYmoswhZ8eQ6/A6J0wmF0eRvi6iuX/B2TE=;
        b=TRv9143WlINEFcfoEprmTcj5leRR7I6S5/jFC1P3YRhplSxno29sbo14Il8KhbSUY8
         pJyeJ5LVYXiu6F5CaUD6wOJ6bKJ+anfnKzdv9wauVuY4FYXdq8KDtn5XRAzZov4j9yH4
         scLrhvYu0KLa/rU0++Nxs2iwSXIBgIo9MaPzsU+LDw4QKMmCGiEK2Y0uTVAMbSlt7JUT
         1SOuIHG3zACUUxUIoxCVBb5MJyzDv2Q8Rgslf7EqnUmsNoxHw3qUy1d31vTlrBXA8CbV
         J+YA11/cBMUDEisgmtptBEGJ9r1yDn9tndHV5ElzFxqCgjkUarF8R2haLUwTYvU0H25H
         aBzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701821308; x=1702426108;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RQFZqqnCuTYmoswhZ8eQ6/A6J0wmF0eRvi6iuX/B2TE=;
        b=viOb5e730xMWSZ1/d6nGJc5MFsvHP1qUxXGOW6tyPZWwJmPSMeuZsxeGV8Yh41Dug3
         9wcwywq2HUCNGw1ElNc4AkanJhiBA9KW+efHIY0xoOx8nE20SDXt7yYOf0HJ2CHafGae
         y0QMQKjvIF0ZOkjZJFCmLvmLbH1+6/4geKtckEDbzFTwTMKUiHUYp0Vo0KzXjGU8pkN1
         /qozQoKDFJ4snENF4rOTXeFaSLGqLrLtXbSH9UPMb3bQFBAjEH9G8IaWFae+kX/qiGZb
         JnA135VZlNxoV4rc/1BHsAgddqj0d21Wl4pvxHkNBTZ/yvIA0SlrHbXPk8Zk3jaj542w
         lMlA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxJD1+P11bU/PtZ2/z6YmqATqMWbFYDPujIw5mRzqB1XnprekCb
	WGVnR0LNThKMfq2BDgM/WlY=
X-Google-Smtp-Source: AGHT+IHuMFDaImbJqHMuiMWToGpDRSUix6rnNUL57nzua6cc2JxPWgpntw20BSPcyNOZ/ZXWUYAu4A==
X-Received: by 2002:a05:622a:181c:b0:418:11c9:ddb5 with SMTP id t28-20020a05622a181c00b0041811c9ddb5mr2962088qtc.25.1701821308221;
        Tue, 05 Dec 2023 16:08:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:10d:b0:423:7e09:49c8 with SMTP id
 u13-20020a05622a010d00b004237e0949c8ls415461qtw.1.-pod-prod-00-us; Tue, 05
 Dec 2023 16:08:27 -0800 (PST)
X-Received: by 2002:ac8:5c4a:0:b0:423:dccf:9dc2 with SMTP id j10-20020ac85c4a000000b00423dccf9dc2mr3170528qtj.12.1701821307206;
        Tue, 05 Dec 2023 16:08:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701821307; cv=none;
        d=google.com; s=arc-20160816;
        b=XvMWNc/ORlq10cOX4fWITSt+qQSbt8s7cUtg4dcsaqvV4YWhfDIxP1nhdbe96xp+xX
         r0zEmTWbnUu8tzu2OFWkbYnORffrEyg5xJE+o1gkbAJW++LoZkOwX2RJKn5fsYYKUrpp
         O8xkC/5eV6SNZRIj6J7b451ivyew6s3n/0oLZqQ6bHb874cKcOfDajp16uaj0wuibg8o
         dMT5JDd7Z8dIWmN4NQtQPDr9e2XpZrdSaStz8mt950CPzGDIN5POvmeJUYeiLrj45U2L
         n9i2MLgSdmNx8qVFrZy3lozsPOttHWR+Lry9YR3TTzz0kl7IXA9YHcpvVo4ExoBCQnhm
         tshA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=mZmoOpShnlOr1bQVRrl+GknWd+PtQJEUK3TXoeEYCts=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=WqMIU/Kux/j1VAU/7P+dVx28ICrmzGXUYq9g05HqE/BbKjN56GAa4JyyrbrEx6SHxZ
         lTrjrHv9MwGimQRGgwAIWBgxRCuuN46Wq1nCMR7SmF/8EcF5yNUrsZpyfzu8CFmE/j39
         b3nmeurj60cuML8zXx9hawPWnV4NtUV4s3gRArJjG1dGszlM/8rr0//G8BIhVoevvUSF
         /yRz8GEa/IFrzaoRzWuo+xCzqYTB65F43XoWfwsq+Yh9Ly++nSFKArhWkKRrTS/lm1tW
         4ROMRd0n20fzNsCwOpEGYNgJErY2SkHVQQihAVXNLX01QRYIA/zpOa/mxsNFGJ2K/B5B
         RUbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SO3vPxFY;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a2e as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vk1-xa2e.google.com (mail-vk1-xa2e.google.com. [2607:f8b0:4864:20::a2e])
        by gmr-mx.google.com with ESMTPS id cm26-20020a05622a251a00b00423e4674d16si3372135qtb.5.2023.12.05.16.08.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Dec 2023 16:08:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a2e as permitted sender) client-ip=2607:f8b0:4864:20::a2e;
Received: by mail-vk1-xa2e.google.com with SMTP id 71dfb90a1353d-4b2d64a368aso202314e0c.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Dec 2023 16:08:27 -0800 (PST)
X-Received: by 2002:a05:6122:3187:b0:49d:20fb:c899 with SMTP id
 ch7-20020a056122318700b0049d20fbc899mr2686639vkb.4.1701821306644; Tue, 05 Dec
 2023 16:08:26 -0800 (PST)
MIME-Version: 1.0
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-2-9c9c70177183@suse.cz> <ZW6j6aTpuJF0keS7@localhost.localdomain>
 <93a8a67c-9cb7-0d36-6b14-ce15a30bea3f@suse.cz>
In-Reply-To: <93a8a67c-9cb7-0d36-6b14-ce15a30bea3f@suse.cz>
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Date: Wed, 6 Dec 2023 09:08:16 +0900
Message-ID: <CAB=+i9Q_FWy3CvJAJPx_ZGncezSOLSST9BX_dZ901=8oemrSUA@mail.gmail.com>
Subject: Re: [PATCH v2 02/21] mm/slab: remove CONFIG_SLAB from all Kconfig and Makefile
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, Michal Hocko <mhocko@kernel.org>, 
	Shakeel Butt <shakeelb@google.com>, Muchun Song <muchun.song@linux.dev>, 
	Kees Cook <keescook@chromium.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
	linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=SO3vPxFY;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a2e
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
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

On Tue, Dec 5, 2023 at 7:14=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wro=
te:
>
> On 12/5/23 05:15, Hyeonggon Yoo wrote:
> > On Mon, Nov 20, 2023 at 07:34:13PM +0100, Vlastimil Babka wrote:
> >
> > Looks good to me,
> > Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
>
> Thanks.
>
> > Nit:
> >
> > - Some arch configs enables DEBUG_SLAB
> > - Some documentations refers to {DEBUG_,}SLAB config (i.e. "enable
> > DEBUG_SLAB for debugging", or "use SLUB instead of SLAB for reducing OS
> > jitter", ... etc)
> > - fs/orangefs/orangefs-kernel.h uses #if (defined CONFIG_DEBUG_SLAB)
> >
> > $ git grep DEBUG_SLAB arch/
> > arch/arm/configs/ep93xx_defconfig:CONFIG_DEBUG_SLAB=3Dy
> > arch/arm/configs/tegra_defconfig:CONFIG_DEBUG_SLAB=3Dy
> > arch/microblaze/configs/mmu_defconfig:CONFIG_DEBUG_SLAB=3Dy
> >
> > $ git grep SLAB Documentation/
> >
> > [... some unrelated lines removed ...]
>
> Yep, I've wrote in the cover letter that to keep the series reasonable an=
d
> limit Ccing other subsystems on some patches, not everything is cleaned u=
p
> thoroughly

Ah, I see, Okay.

>  and is left for further work (some already started coming in
> from others) that can be submitted to relevant subsystems.

I'll focus more on correctness rather than doing further work while reviewi=
ng.

> > Documentation/admin-guide/cgroup-v1/cpusets.rst:PFA_SPREAD_SLAB, and ap=
propriately marked slab caches will allocate
> > Documentation/admin-guide/cgroup-v1/memory.rst:  pages allocated by the=
 SLAB or SLUB allocator are tracked. A copy
> > Documentation/admin-guide/kernel-per-CPU-kthreads.rst:          CONFIG_=
SLAB=3Dy, thus avoiding the slab allocator's periodic
> > Documentation/admin-guide/mm/pagemap.rst:   The page is managed by the =
SLAB/SLUB kernel memory allocator.
> > Documentation/dev-tools/kasan.rst:For slab, both software KASAN modes s=
upport SLUB and SLAB allocators, while
> > Documentation/dev-tools/kfence.rst:of the sample interval, the next all=
ocation through the main allocator (SLAB or
> > Documentation/mm/slub.rst:The basic philosophy of SLUB is very differen=
t from SLAB. SLAB
> > Documentation/mm/slub.rst:                      Sorry SLAB legacy issue=
s)
> > Documentation/process/4.Coding.rst: - DEBUG_SLAB can find a variety of =
memory allocation and use errors; it
> > Documentation/process/submit-checklist.rst:    ``CONFIG_DEBUG_SLAB``, `=
`CONFIG_DEBUG_PAGEALLOC``, ``CONFIG_DEBUG_MUTEXES``,
> > Documentation/scsi/ChangeLog.lpfc:        CONFIG_DEBUG_SLAB set).
> > Documentation/translations/it_IT/process/4.Coding.rst: - DEBUG_SLAB pu=
=C3=B2 trovare svariati errori di uso e di allocazione di memoria;
> > Documentation/translations/it_IT/process/submit-checklist.rst:    ``CON=
FIG_DEBUG_SLAB``, ``CONFIG_DEBUG_PAGEALLOC``, ``CONFIG_DEBUG_MUTEXES``,
> > Documentation/translations/ja_JP/SubmitChecklist:12: CONFIG_PREEMPT, CO=
NFIG_DEBUG_PREEMPT, CONFIG_DEBUG_SLAB,
> > Documentation/translations/zh_CN/dev-tools/kasan.rst:=E5=AF=B9=E4=BA=8E=
slab=EF=BC=8C=E4=B8=A4=E7=A7=8D=E8=BD=AF=E4=BB=B6KASAN=E6=A8=A1=E5=BC=8F=E9=
=83=BD=E6=94=AF=E6=8C=81SLUB=E5=92=8CSLAB=E5=88=86=E9=85=8D=E5=99=A8=EF=BC=
=8C=E8=80=8C=E5=9F=BA=E4=BA=8E=E7=A1=AC=E4=BB=B6=E6=A0=87=E7=AD=BE=E7=9A=84
> > Documentation/translations/zh_CN/process/4.Coding.rst: - DEBUG_SLAB =E5=
=8F=AF=E4=BB=A5=E5=8F=91=E7=8E=B0=E5=90=84=E7=A7=8D=E5=86=85=E5=AD=98=E5=88=
=86=E9=85=8D=E5=92=8C=E4=BD=BF=E7=94=A8=E9=94=99=E8=AF=AF=EF=BC=9B=E5=AE=83=
=E5=BA=94=E8=AF=A5=E7=94=A8=E4=BA=8E=E5=A4=A7=E5=A4=9A=E6=95=B0=E5=BC=80=E5=
=8F=91=E5=86=85=E6=A0=B8=E3=80=82
> > Documentation/translations/zh_CN/process/submit-checklist.rst:    ``CON=
FIG_DEBUG_SLAB``, ``CONFIG_DEBUG_PAGEALLOC``, ``CONFIG_DEBUG_MUTEXES``,
> > Documentation/translations/zh_TW/dev-tools/kasan.rst:=E5=B0=8D=E6=96=BC=
slab=EF=BC=8C=E5=85=A9=E7=A8=AE=E8=BB=9F=E4=BB=B6KASAN=E6=A8=A1=E5=BC=8F=E9=
=83=BD=E6=94=AF=E6=8C=81SLUB=E5=92=8CSLAB=E5=88=86=E9=85=8D=E5=99=A8=EF=BC=
=8C=E8=80=8C=E5=9F=BA=E6=96=BC=E7=A1=AC=E4=BB=B6=E6=A8=99=E7=B1=A4=E7=9A=84
> > Documentation/translations/zh_TW/process/4.Coding.rst: - DEBUG_SLAB =E5=
=8F=AF=E4=BB=A5=E7=99=BC=E7=8F=BE=E5=90=84=E7=A8=AE=E5=85=A7=E5=AD=98=E5=88=
=86=E9=85=8D=E5=92=8C=E4=BD=BF=E7=94=A8=E9=8C=AF=E8=AA=A4=EF=BC=9B=E5=AE=83=
=E6=87=89=E8=A9=B2=E7=94=A8=E6=96=BC=E5=A4=A7=E5=A4=9A=E6=95=B8=E9=96=8B=E7=
=99=BC=E5=85=A7=E6=A0=B8=E3=80=82
> > Documentation/translations/zh_TW/process/submit-checklist.rst:    ``CON=
FIG_DEBUG_SLAB``, ``CONFIG_DEBUG_PAGEALLOC``, ``CONFIG_DEBUG_MUTEXES``,
> >
> > --
> > Hyeonggon
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAB%3D%2Bi9Q_FWy3CvJAJPx_ZGncezSOLSST9BX_dZ901%3D8oemrSUA%40mail.=
gmail.com.
