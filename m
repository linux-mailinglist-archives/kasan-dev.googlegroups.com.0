Return-Path: <kasan-dev+bncBCMIZB7QWENRBOHB5T7AKGQEKIMWQAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DFA9B2DCF66
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 11:19:37 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id b123sf17549651ybh.17
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 02:19:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608200376; cv=pass;
        d=google.com; s=arc-20160816;
        b=FBEZigVwTHHP5pMvkPVaCHGWtmnrLhzlNubSpBL1n26NgUbXgYSpe2J+P+E9m46ChP
         ax7eXbLhp0gZwCpedRImgmX/pkG6lRaiWEeCRU6OqXDapSmN9upQAQ3RW2vH0qEfsTtX
         j6QKZcMCH6lXdIqsLTsn8tBObJTNeOW7fmnLnLJLYDPg2aeKA26LZx6I2ZTg5y6jg+w5
         Wq91kCkmykkJqawMEWw+9MQ9kprhtPYXq7N6nKE15TFlNcoc/KCwyCRR/FOx9QJVsxmo
         soeNVW87uaZ3i0PDh0lr+KC+5o8gLFhGEFDR3FDGUQ2AxDpQ/lkWZGJax53ODG9gloYT
         Pu5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9QNO3y4CRwUHilit8gBj7fVAiAUTDDtK+WtXVQl0m7s=;
        b=KXu06LiVOVgcJeh9+IGCMhcl2ledrwrPmZEVRik0JQ8nqUhFDErQ6YZGdehMOc77tx
         H3DsddVaN5I3OP5LeqXz0wtYmy5lpwCQztVd4Wm5i8/ZRZojHXQ98Qn3581Yg4wyzk88
         R7Jty4ou3nalHfs1FbM9ld+X+dGR6KPEzNUiqSsYT+YK3T4TFX/2eMn1ftiQFA0EC8om
         w0p+V7qXlF1Gb8PYHb/D5Cse65eb3fN8zeTwmXo0Pg3UEioDB/Xgqf5H5JSgnhxR5x+1
         YNWMFkJ5+QbdnX5/xdQN8NthzkHgewFsttB1X3UIQkM4aao5QOtIGAWxlBdMAbck59dU
         RkWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QNOKmKNX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9QNO3y4CRwUHilit8gBj7fVAiAUTDDtK+WtXVQl0m7s=;
        b=j8jsY1cyAcSz+F/1qnpAab98Aafixw5CDgctS0Y+wIfpj1mzEPIagINjUUTN0Qu7pv
         doIdNxAC7p4z1IzuF+0lvwL93eg6m3ZLRp66CTLbef6/8949jH7tzrp+H43PK2K0LEXA
         XWakkAqvivIBaa1U4+wE4IpuSEXpFyWmtsUjFNA0wdGIozShrMSxn/sVeZC02Uakc/8L
         YgloWDn6tsIa1cBmTNuKp6rjR9meYqems4arwlxqfWB+TqNrp0Djg6nQA+AGGT+wYj8u
         wcSvs6vdqZ9W7G6AtjgUoa/LivgMySLKDpxwueQ1FK+neziuuTI3/qhI1JTm93mkFWwP
         bIGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9QNO3y4CRwUHilit8gBj7fVAiAUTDDtK+WtXVQl0m7s=;
        b=ZHCxAyAnc4ibxKfTeYam3HCG1pUNup+6QtKyVyBrxNwgEPgOX7+WX94FdGXLFJ6ckD
         QL494QID4oOtwh6qP+rotrLTj731b1X/HTs7ri1LTDv1tkH/Y3DWu55WZ3YYKkJaY/4L
         cksejlDuJ1+CMX2gUQ8aMlH9227sJartuwFyxboyFuDO/o5+vsQe/NpB+vfOFFrWhzm5
         ZWdXdHtzRf72cuzIrSw+QQ+uWeily4VpwA62+7TZaoD55C8iEnavo7fCZgsmpDFQJieV
         YlHvwHZVScR9uyY1q8H6AHSHKyVnT6qJqaoWvnfNrE2A5Cb9ZdthdxYs0sqq4rAqJAoy
         uK3w==
X-Gm-Message-State: AOAM532ZJTc9YDn/YO5Rg7kZ+tX1cLNTGp3Vg/5J4RhGbjj4tdhJAgzp
	NtagJnCTfqfS1ear9+XsXOU=
X-Google-Smtp-Source: ABdhPJxpsnFphUgvXMMlwo4Z4TZGQtjevfjmu2DG53PGcJh2gMY3cmt1lOOr3kGmsQ/c7qoOF9AN1w==
X-Received: by 2002:a25:6145:: with SMTP id v66mr40638708ybb.146.1608200376764;
        Thu, 17 Dec 2020 02:19:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:f80c:: with SMTP id u12ls8446633ybd.4.gmail; Thu, 17 Dec
 2020 02:19:36 -0800 (PST)
X-Received: by 2002:a25:778c:: with SMTP id s134mr54725533ybc.411.1608200376271;
        Thu, 17 Dec 2020 02:19:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608200376; cv=none;
        d=google.com; s=arc-20160816;
        b=1KT5QNN2s1swPWT7ijYjzfKqNu05ezosZ6lFRgto3Q6z5O51p0Qau5c6VQ8crAw7um
         3bmBRvv3W5SHv55vLBkYKPvVTtgZpuRXS8tFUCXUV9EU8zYGfXbqHbl3RFnhsIzPnka5
         js8ldp1uihatjsBjLgoameBKnw2ZBBaUNQilfZoxEIH2vBhH1hAtoXinCtHIsR0p+p44
         3lhcEd6s0x7eqwPO9HAh98H3JjGDGu+uFlUppSCcwlbD/XVYFZDL1JqbolhUtZYgqnYo
         Hi/9CZHTx8PRDcbqdLGujUZmpDqKYbVTXCmwVY0u4LRoHP9dyLU/ifP4Q1eu/l1368u8
         P8GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lIbOVthlNTcsi+l1tR4PevWTEasEI2Fetl3tXpPfOGg=;
        b=ibmQV2W0zJUCdHcckNpXKdggNkO+SoUTqqqvTEnWRDldFWEioVTLqyMrYc9DT/Q8iv
         3nERs3WLlAoNE2d3C6RbmTMhjhAy/hDnPlzdBANDwGCCGMNvDZSBAddvaerTwQuqo7mo
         PAXviGHnnc0LS2Rrt9Zg5PL3C+vrMTKO65GqZY3096sxWXDQK1ILci9SgM+kVZeWuYpj
         afJzCeh6SfJUYUIk76A3VdNqcUgjKpfUQze7fdIAYiaWgHe3P1lpcGEWvHThQG14C8us
         iAvTOa+1EZQlyPVbtalY/cCOP/udyKsv7SZYOr9qnODSiqesMg7+vm2oMC/DQHbcKjiu
         +bwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QNOKmKNX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82f.google.com (mail-qt1-x82f.google.com. [2607:f8b0:4864:20::82f])
        by gmr-mx.google.com with ESMTPS id e10si627679ybp.4.2020.12.17.02.19.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Dec 2020 02:19:36 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82f as permitted sender) client-ip=2607:f8b0:4864:20::82f;
Received: by mail-qt1-x82f.google.com with SMTP id 7so19752484qtp.1
        for <kasan-dev@googlegroups.com>; Thu, 17 Dec 2020 02:19:36 -0800 (PST)
X-Received: by 2002:aed:208f:: with SMTP id 15mr45442386qtb.290.1608200375684;
 Thu, 17 Dec 2020 02:19:35 -0800 (PST)
MIME-Version: 1.0
References: <1607576401-25609-1-git-send-email-vjitta@codeaurora.org>
 <CAG_fn=VKsrYx+YOGPnZw_Q5t6Fx7B59FSUuphj7Ou+DDFKQ+8Q@mail.gmail.com>
 <77e98f0b-c9c3-9380-9a57-ff1cd4022502@codeaurora.org> <CAG_fn=WbN6unD3ASkLUcEmZvALOj=dvC0yp6CcJFkV+3mmhwxw@mail.gmail.com>
 <6cc89f7b-bf40-2fd3-96ce-2a02d7535c91@codeaurora.org> <CAG_fn=VOHag5AUwFbOj_cV+7RDAk8UnjjqEtv2xmkSDb_iTYcQ@mail.gmail.com>
 <255400db-67d5-7f42-8dcb-9a440e006b9d@codeaurora.org> <f901afa5-7c46-ceba-2ae9-6186afdd99c0@codeaurora.org>
 <CAG_fn=UjJQP_gfDm3eJTPY371QTwyDJKXBCN2gs4DvnLP2pbyQ@mail.gmail.com>
 <7f2e171f-fa44-ef96-6cc6-14e615e3e457@codeaurora.org> <CAG_fn=VihkHLx7nHRrzQRuHeL-UYRezcyGLDQMJY+d1O5AkJfA@mail.gmail.com>
 <601d4b1a-8526-f7ad-d0f3-305894682109@codeaurora.org> <CAG_fn=V8e8y1fbOaYUD5SfDSQ9+Tc3r7w6ZSoJ-ZNFJvvq-Aeg@mail.gmail.com>
 <9e0d2c07-af1f-a1d3-fb0d-dbf2ae669f96@codeaurora.org>
In-Reply-To: <9e0d2c07-af1f-a1d3-fb0d-dbf2ae669f96@codeaurora.org>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Dec 2020 11:19:24 +0100
Message-ID: <CACT4Y+aUEdNjFsnMxFAbh+cWMGLG1bqX8-7uo8SQ0HPeNeDZBg@mail.gmail.com>
Subject: Re: [PATCH v3] lib: stackdepot: Add support to configure STACK_HASH_SIZE
To: Vijayanand Jitta <vjitta@codeaurora.org>, kasan-dev <kasan-dev@googlegroups.com>
Cc: Alexander Potapenko <glider@google.com>, Minchan Kim <minchan@kernel.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dan Williams <dan.j.williams@intel.com>, 
	Mark Brown <broonie@kernel.org>, Masami Hiramatsu <mhiramat@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, qcai@redhat.com, ylal@codeaurora.org, 
	vinmenon@codeaurora.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QNOKmKNX;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82f
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

On Thu, Dec 17, 2020 at 6:42 AM Vijayanand Jitta <vjitta@codeaurora.org> wrote:
>
> On 12/16/2020 7:04 PM, Alexander Potapenko wrote:
> >>> To reiterate, I think you don't need a tunable stack_hash_order
> >>> parameter if the only use case is to disable the stack depot.
> >>> Maybe it is enough to just add a boolean flag?
> >>
> >> There are multiple users of stackdepot they might still want to use
> >> stack depot but with a lower memory footprint instead of MAX_SIZE
> >> so, a configurable size might help here ?
> >
> > Can you provide an example of a use case in which the user wants to
> > use the stack depot of a smaller size without disabling it completely,
> > and that size cannot be configured statically?
> > As far as I understand, for the page owner example you gave it's
> > sufficient to provide a switch that can disable the stack depot if
> > page_owner=off.
> >
> There are two use cases here,
>
> 1. We don't want to consume memory when page_owner=off ,boolean flag
> would work here.
>
> 2. We would want to enable page_owner on low ram devices but we don't
> want stack depot to consume 8 MB of memory, so for this case we would
> need a configurable stack_hash_size so that we can still use page_owner
> with lower memory consumption.
>
> So, a configurable stack_hash_size would work for both these use cases,
> we can set it to '0' for first case and set the required size for the
> second case.
>
> >>> Or even go further and disable the stack depot in the same place that
> >>> disables page owner, as the user probably doesn't want to set two
> >>> flags instead of one?
> >>>
> >>
> >> Since, page owner is not the only user of stack depot we can't take that
> >> decision of disabling stack depot if page owner is disabled.
> >
> > Agreed, but if multiple subsystems want to use stackdepot together, it
> > is even harder to estimate the total memory consumption.
> > How likely is it that none of them will need MAX_SIZE?
> >
> >>>> Minchan,
> >>>> This should be fine right ? Do you see any issue with disabling
> >>>> stack depot completely ?

+kasan-dev

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaUEdNjFsnMxFAbh%2BcWMGLG1bqX8-7uo8SQ0HPeNeDZBg%40mail.gmail.com.
