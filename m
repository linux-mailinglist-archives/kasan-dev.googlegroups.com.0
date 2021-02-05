Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEGS6WAAMGQETUT4GKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C4F31310D67
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:49:37 +0100 (CET)
Received: by mail-vk1-xa3c.google.com with SMTP id d202sf1649296vkd.4
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:49:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612540177; cv=pass;
        d=google.com; s=arc-20160816;
        b=eWGQuaTLr7MA5DmzNltNYwR725RXSwqVXwcSDE74LWt4zfnnfZnzjPKJpj7XRjDtrl
         vC4t1FhnOvlQOLwSNp9I+KqOkBr3EohTWaJqs24AQzYe7fY+ZNEhr+qTIWD9yEk7oFmX
         z0yUKQLw/8VxEjSYVyn5SA2raZXOVClBQkZYcaLvFPiiJdgUmtU/Chjsy5KY6Jt/qLWT
         oM2C4UgYsFvAjGKEPTyLIR6Zv0Jypkj6LzbyYQMvxqwhWORNDajtW39AWyA/H61h+2Wp
         WOplOrvy27+XhA4KCRUstVv/A5GZlFD7gG410Ch3mAFV+CGcHDxM513jA9LyIdTxrHso
         F6yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vKsbvtKwIlAD7obZ6UF0d0mfhKvogKxMOI81QySz/b4=;
        b=F8NauQLoL4hfwHdU4Uo4TbUAofhO0x/gFDjpyCvk+lgIdw/JVvnjod8o3Zw6HQUSrc
         3SN9locs4KqXkDLURyjU/m8qWAd5bv7VhumFiQZBQYevWfWFjI+YLBekbGw8ku74ZnWO
         RZrh8eG8qrB6bOAaCIVu+34enzGeB9luISe8Kq5wYDv7K/HNIbimb60wmSi5kWKnMNln
         eCkivRMZUo+70KuF2A8DowFgKKhZr2pKpgn5uoMY7GJzMVzP9VLZyh0np9rG9mndorIc
         Cli8MalkZJMf3BsRF7ZioHaoK+XqJ40bmy85npkOeOjCETHAFo41u1oDOlHICSJmSf/S
         bQRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oWjE1+8Q;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vKsbvtKwIlAD7obZ6UF0d0mfhKvogKxMOI81QySz/b4=;
        b=ifVtO7tw9Kcrg8HOCh1lPMYU/d0sjoQYRxHp7kmUIcApJY2K4SfU6+yXEF31QIyUKP
         cj8G82PuRygn9CaFH45dAzBmK1BdzWJT1e8St6rSKGlbHPv56fXLPls/m0JC9HORKIQA
         Xs0LbgazFfJgEi45pmVJ3A9d1wSqsL3J48m3BE/RVsDmS1LRfVtmMfAvVPPfdUAL+u9S
         iEBsqDw0bUZY6jMUiqsDUM5D8ObDUe7bs7mxmaeH5R1mBE4Zj+8YmmVk/Nx+sKajabOS
         2p05eDn6aCmRKwLpWGkdBej1dRcDfqxzUH7GtleLnE+5OP1wpwJodUUenM3QLZz9ch8S
         /Gng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vKsbvtKwIlAD7obZ6UF0d0mfhKvogKxMOI81QySz/b4=;
        b=N3Qff/oRnHORpskWtuxqA4NXDLOvlgEzrTiNWRfxNtHPUiy9N8+KXWKe33pt64qlwD
         KtbYC8gv6wqPG0zHOttkuhXum3cCjJpuSKRpxxj9vRxL7wMKZAR7qcOCbdDkgyltvOV6
         ZxknI+vLGVRYOHhWfsH5LDhALv7FTpu+vDGfMSAhsQrXHM7uIq7vf6bLHY+2cFUaawxz
         AJgjxG4RWpbp8Rs43o45UL0J9KNOkahqXbJoMCkmfniF86cyOqhJUtMuT/LovJuxta+J
         mm6oRuwizeKeLHeiOkcyEt09mRhp0CX7lLSs0KlFShrk4sjFbFkVT+25LH3pRYJS+N3T
         el/w==
X-Gm-Message-State: AOAM532lQk8Xw+xH8uByP+Lzo49u/RZEtHJilDSMwi4dAFmwi/LG316i
	T/GFs4SccCtQCbSYS1UZ4DQ=
X-Google-Smtp-Source: ABdhPJyfs3CIyBshKF3PRYLIwsGuHPTBEq4fc0H0sypl+FgUC8iIXNF5BAyoEmE8L72gFq6mmJ6TKw==
X-Received: by 2002:a67:ecd5:: with SMTP id i21mr3395483vsp.18.1612540176880;
        Fri, 05 Feb 2021 07:49:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:804e:: with SMTP id b75ls1215480vsd.1.gmail; Fri, 05 Feb
 2021 07:49:36 -0800 (PST)
X-Received: by 2002:a67:8e4a:: with SMTP id q71mr3469485vsd.10.1612540176373;
        Fri, 05 Feb 2021 07:49:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612540176; cv=none;
        d=google.com; s=arc-20160816;
        b=K3XuF9TeyopmXR4GVFjXcRUr427Gmpxc8xobR4sMJ+I9Sd1bbgz4f+0ELq3PN+H3NU
         XVbEeJY400IWR8xX0mUabAIhQjVHf57iZTVDVEt+FuC8/GkB9EH52R5lCitu69IiTP7V
         3OAZ+H43hXK8E8mhyUKdanAkTlOGy1hVxfqn5Ynlxx3b0E6MLgJye7PCp3TM6YxF8NHi
         /TMolEew00NpSfpYyMUd/4RM/F8dA5/CM/p3DsaMxl3MB3J2eXD+90hvG/CCWKRHqXRG
         ulHOxuftUxhaNEeNkENMi1KOzorL/+CmXxK/LalZX3ggr8OYTNH5Ban/OCwpVrKsyiA3
         ulyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=d23/bHc5IAw+57pFfXazVH986BI0xYsnbVaaC5Mmtdw=;
        b=u3fQdtFTrIlUJQvgJjPqm+9mj9OIkk1AuRmv1OZFoV0nUdsRCRBaqvXGE0yPkkO8BN
         aVC7zqO23dq6V7Zb6v6keLKsK9Ep1bfF7pa4F+0iAElsmTc+2jcZRz2W9wQY6s7lsjYm
         wPBvnhzqCcjqm0mzUtLtron9SY92UXAwFT6tVE7Fm/mjKrVfQcMom+BmNW0Mu/a1IxEN
         ph4QC6znXefaq8vjHa+VpQ1iHk0QrLuXL7YWRH8fZCZxVfNIBHVdiWf85IrwuKlyoDNj
         jcmeToHq+UwJcoVbODdUxbt0xwvXaxCuFoOdj/s1kNGsoQxu+IYpMWO6TFNWgthUjzlt
         ZDRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oWjE1+8Q;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x102b.google.com (mail-pj1-x102b.google.com. [2607:f8b0:4864:20::102b])
        by gmr-mx.google.com with ESMTPS id c4si511924vkh.1.2021.02.05.07.49.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 07:49:36 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102b as permitted sender) client-ip=2607:f8b0:4864:20::102b;
Received: by mail-pj1-x102b.google.com with SMTP id fa16so3409518pjb.1
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 07:49:36 -0800 (PST)
X-Received: by 2002:a17:902:9009:b029:dc:52a6:575 with SMTP id
 a9-20020a1709029009b02900dc52a60575mr4437121plp.57.1612540175353; Fri, 05 Feb
 2021 07:49:35 -0800 (PST)
MIME-Version: 1.0
References: <20210130165225.54047-1-vincenzo.frascino@arm.com>
 <20210130165225.54047-3-vincenzo.frascino@arm.com> <CAAeHK+y=t4c5FfVx3r3Rvwg3GTYN_q1xme=mwk51hgQfJX9MZw@mail.gmail.com>
In-Reply-To: <CAAeHK+y=t4c5FfVx3r3Rvwg3GTYN_q1xme=mwk51hgQfJX9MZw@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Feb 2021 16:49:23 +0100
Message-ID: <CAAeHK+wdPDZkUSu+q1zb=YWxVD68mXqde9c+gYB4bb=zCsvbZw@mail.gmail.com>
Subject: Re: [PATCH v11 2/5] kasan: Add KASAN mode kernel parameter
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oWjE1+8Q;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102b
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

On Mon, Feb 1, 2021 at 9:04 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Sat, Jan 30, 2021 at 5:52 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
> >
> > @@ -45,6 +52,9 @@ static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
> >  DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> >  EXPORT_SYMBOL(kasan_flag_enabled);
> >
> > +/* Whether the asynchronous mode is enabled. */
> > +bool kasan_flag_async __ro_after_init;
>
> Just noticed that we need EXPORT_SYMBOL(kasan_flag_async) here.

Hi Vincenzo,

If you post a new version of this series, please include
EXPORT_SYMBOL(kasan_flag_async).

Thanks!

>
> There are also a few arm64 mte functions that need to be exported, but
> I've addressed that myself here:
>
> https://lore.kernel.org/linux-arm-kernel/cover.1612208222.git.andreyknvl@google.com/T/#m4746d3c410c3f6baddb726fc9ea9dd1496a4a788

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwdPDZkUSu%2Bq1zb%3DYWxVD68mXqde9c%2BgYB4bb%3DzCsvbZw%40mail.gmail.com.
