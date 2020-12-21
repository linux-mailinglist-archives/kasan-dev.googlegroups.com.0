Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5XSQL7QKGQEHX3KOGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 37A782DFD29
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Dec 2020 16:04:24 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id a3sf3931640oon.19
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Dec 2020 07:04:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608563062; cv=pass;
        d=google.com; s=arc-20160816;
        b=AIb0JxibjS9ggmg2ICuF9RCcJW+LG8KYtt5nomEu8e6qAHO/OHgOBxMdx4PdqF7SED
         gRddjjd4z2TGnwCtnv+vh8JsOUo/hAFnDU9/jX/GvxSgxcJ6X70ABFwFLqOnpVIVSGcH
         nlrZWT7OcOYqNJW51z+3pr+qepIv1aGOjfb8QlrWXIcWWQu2fafRYK1mvcCexZYFjomi
         MwbKVZAxsvFc4NHK2qOT2AHXqpfg7cttCx/99k3g6U+zfVXnCzVQAR6fzLYYUd06SNce
         vxAK+yPreXrYYqIV8NJeIjiKVF4srm/X0vrP7I52pjI7qssjkRECETLtV6WgOjgt9ttV
         GceQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5Q974ApnV/6N758KfmTpbiY6fFlT6H1EkkqkvFt9750=;
        b=vcwteAKJVCEanq4zuxOd8P5nTElMAoAg/BJ5QDTlG9kRX7XsOFk5MIAax8XbA44Sek
         9Qmf7H4Jk4F6vuUc00miNFqkV+8duqoY0hrL/ut6mzpkVZHIvXE2COSz0yA61OKUt0nL
         lGblz1RmcgjK3ZUIX3nQf9jK1fwHjHhKFg3qEY0eP56F0ehbIvEFUZWEaNpJFyeOanDD
         VeHdncsLZ8PUTDF8llf0FdNnKs0q4JK69+BDsloU0hhuLZ3eyk4Tl0bDujHeog2lEghK
         iHCQKDex/j55Bl3b18Zvta5W8zzhY+AU3PuE14fQGgpLEa9L26/3LMu7pOHA+7Y8vPaL
         Tr8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WNR++gqS;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=5Q974ApnV/6N758KfmTpbiY6fFlT6H1EkkqkvFt9750=;
        b=X/hsJBxo76Lg0JF9sSJKalOr4w/a7QTiVpy69GIMLKHJZWg4cTo2GGu8nDqvUbvpWJ
         vh0CVgrafZGKg/wA3MhfhWC/db4Wx2QZHB5zwgHkRrV22qgDlGRLyJphswwTnVGzcrnk
         bjPsKd4PyI7PL3hcOqrSgx6ovqx5rlDRVuCqkWHsX0t09+/2qETjWvdEbkNBNSq0YQMO
         PIjwWfgadtSEfl0o+ygUawynvK61ljf0ASd5HgKzQeORZOwl440Y5jST3e2sCAaf8R9y
         EWkz3o60apNdb8QWIEM5pmtTLbe+Y2shGm3D0Mhdw843AlIDZcm1AQjJMHIKh5PSSW+g
         gR4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5Q974ApnV/6N758KfmTpbiY6fFlT6H1EkkqkvFt9750=;
        b=Xp423M3PQxcZvTUttuATyDqzP1svWxc+Af1fZ7au2gxz1EV4igIfOJQZzGmL3qSsEz
         L2Q0hpCTXwMxLZxJg6/AKUCJR15lStWKw3nH3UYTAsMrJcmstE0EH6K/gWdivPPEF9d9
         9RVTttp5UpDuQiX1Ib0rgXzM/p8lYzmJmly7oWnGIq3F8kEhw4Z8Nl7qLsciov4xzlpz
         byikW85iYLWazfiUslfWsYx9qZDzjXMyyEuIuew774aJgjIqyqyDwNkFHJqxkeLIW5M5
         lFf9f9AyQOAFSSDlm1FRjwQjUUMOm6D+RTVXRHB33HD6hi4UmMaXhzQbJ2/jFbTdEXfC
         pGOQ==
X-Gm-Message-State: AOAM533nL3kI1SnXaAjCzHk550TmbLHVSPr1Xht4PKM3zHhcVNH0SL85
	RQn+p91cBfZtRcjGgydyLgA=
X-Google-Smtp-Source: ABdhPJxhIiEsHNxX1DHpZVGhPbjbVnQhZImjkdhIACssmHlBwq8Ka8gw60ca3hD/DUz0cwarHWbOPQ==
X-Received: by 2002:a05:6808:313:: with SMTP id i19mr6659896oie.110.1608563062110;
        Mon, 21 Dec 2020 07:04:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cdc1:: with SMTP id d184ls9723961oig.10.gmail; Mon, 21
 Dec 2020 07:04:21 -0800 (PST)
X-Received: by 2002:aca:ad89:: with SMTP id w131mr10983112oie.112.1608563061800;
        Mon, 21 Dec 2020 07:04:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608563061; cv=none;
        d=google.com; s=arc-20160816;
        b=FdwkWQ3uuRdC9swoj5JU2jOOOKtO0lbdiG+R/6PwTV/4tyj6T0jwgGh13oy6Jtwqf5
         +B7zhw3GkZFCYlVinY0pDhO8w2gGE1GHHg76WDnG/HodOl6VPoRJ+C1f9ls0iflKP5ca
         KgyBd4s2TC08qWALxzSQiS0rD9fXaKrLLBtRW3EvTyFQ+hQP5zCJezizUlXuBjLicT1v
         PrUZDxZluj/Jly7epn+4IMvIOAFVHjMb0/5/0LWhH9Oi/2X52jHkabEzVLd9pGGdKhDF
         t84dVAX0RGWV0eIOK7Dxi7J9hKWtv61KyFRZc4C8AXRK6dIwJ+17cMMXTcXaURpfGJlA
         jxYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9Gs1qnHni/7JgGg8DxLHzFHnG72behPmmY3QIu4VsAE=;
        b=d0X82F6l6EcKyVP4fFh0MXgxFo7KcbT0Rdf7CX4PvuVnlV0viddP5jdLYMV1xPRKr0
         LHe18QEAinU3KYm76tAWS4QXT7QYwkwVIgtQeikAPivqRkiMDss3pZb7xByD04GPOrDq
         Wqd36JvKv74DVtoLnlEWgIpXksDebp3/VSlhDjGtCnr68LBPU/tGCWARn0fPBfl9mMji
         dHh62zxpReB0NHwwC+vszMERYgokg8Dku5L7YXxF4jzRHSeHQB0rljVlBPOjfQr983ck
         Mxx9BgHLsT7V8p4Iv880noK+X944fMYHx/cbUQmN7cJqJY6y282EHLrBEtjr/wMvuAGV
         ebiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WNR++gqS;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x831.google.com (mail-qt1-x831.google.com. [2607:f8b0:4864:20::831])
        by gmr-mx.google.com with ESMTPS id e1si1745928oti.2.2020.12.21.07.04.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Dec 2020 07:04:21 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::831 as permitted sender) client-ip=2607:f8b0:4864:20::831;
Received: by mail-qt1-x831.google.com with SMTP id h19so6726446qtq.13
        for <kasan-dev@googlegroups.com>; Mon, 21 Dec 2020 07:04:21 -0800 (PST)
X-Received: by 2002:ac8:7512:: with SMTP id u18mr16624678qtq.300.1608563061279;
 Mon, 21 Dec 2020 07:04:21 -0800 (PST)
MIME-Version: 1.0
References: <1607576401-25609-1-git-send-email-vjitta@codeaurora.org>
 <CAG_fn=VKsrYx+YOGPnZw_Q5t6Fx7B59FSUuphj7Ou+DDFKQ+8Q@mail.gmail.com>
 <77e98f0b-c9c3-9380-9a57-ff1cd4022502@codeaurora.org> <CAG_fn=WbN6unD3ASkLUcEmZvALOj=dvC0yp6CcJFkV+3mmhwxw@mail.gmail.com>
 <6cc89f7b-bf40-2fd3-96ce-2a02d7535c91@codeaurora.org> <CAG_fn=VOHag5AUwFbOj_cV+7RDAk8UnjjqEtv2xmkSDb_iTYcQ@mail.gmail.com>
 <255400db-67d5-7f42-8dcb-9a440e006b9d@codeaurora.org> <f901afa5-7c46-ceba-2ae9-6186afdd99c0@codeaurora.org>
 <CAG_fn=UjJQP_gfDm3eJTPY371QTwyDJKXBCN2gs4DvnLP2pbyQ@mail.gmail.com>
 <7f2e171f-fa44-ef96-6cc6-14e615e3e457@codeaurora.org> <CAG_fn=VihkHLx7nHRrzQRuHeL-UYRezcyGLDQMJY+d1O5AkJfA@mail.gmail.com>
 <601d4b1a-8526-f7ad-d0f3-305894682109@codeaurora.org> <CAG_fn=V8e8y1fbOaYUD5SfDSQ9+Tc3r7w6ZSoJ-ZNFJvvq-Aeg@mail.gmail.com>
 <9e0d2c07-af1f-a1d3-fb0d-dbf2ae669f96@codeaurora.org> <CAG_fn=UXQUGiDqmChqD-xX-yF5Jp+7K+oHwKPrO9DZL-zW_4KQ@mail.gmail.com>
 <48df48fe-dc36-83a4-1c11-e9d0cf230372@codeaurora.org> <6110a26b-dc87-b6f9-e679-aa60917403de@codeaurora.org>
In-Reply-To: <6110a26b-dc87-b6f9-e679-aa60917403de@codeaurora.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 21 Dec 2020 16:04:09 +0100
Message-ID: <CAG_fn=VjejHtY8=cuuFkixpXd6A6q1C==6RAaUC3Vb5_4hZkcg@mail.gmail.com>
Subject: Re: [PATCH v3] lib: stackdepot: Add support to configure STACK_HASH_SIZE
To: Vijayanand Jitta <vjitta@codeaurora.org>, Minchan Kim <minchan@kernel.org>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, dan.j.williams@intel.com, broonie@kernel.org, 
	Masami Hiramatsu <mhiramat@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, qcai@redhat.com, 
	ylal@codeaurora.org, vinmenon@codeaurora.org, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WNR++gqS;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::831 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Mon, Dec 21, 2020 at 12:15 PM Vijayanand Jitta <vjitta@codeaurora.org> w=
rote:
>
>
>
> On 12/18/2020 2:10 PM, Vijayanand Jitta wrote:
> >
> >
> > On 12/17/2020 4:24 PM, Alexander Potapenko wrote:
> >>>> Can you provide an example of a use case in which the user wants to
> >>>> use the stack depot of a smaller size without disabling it completel=
y,
> >>>> and that size cannot be configured statically?
> >>>> As far as I understand, for the page owner example you gave it's
> >>>> sufficient to provide a switch that can disable the stack depot if
> >>>> page_owner=3Doff.
> >>>>
> >>> There are two use cases here,
> >>>
> >>> 1. We don't want to consume memory when page_owner=3Doff ,boolean fla=
g
> >>> would work here.
> >>>
> >>> 2. We would want to enable page_owner on low ram devices but we don't
> >>> want stack depot to consume 8 MB of memory, so for this case we would
> >>> need a configurable stack_hash_size so that we can still use page_own=
er
> >>> with lower memory consumption.
> >>>
> >>> So, a configurable stack_hash_size would work for both these use case=
s,
> >>> we can set it to '0' for first case and set the required size for the
> >>> second case.
> >>
> >> Will a combined solution with a boolean boot-time flag and a static
> >> CONFIG_STACKDEPOT_HASH_SIZE work for these cases?
> >> I suppose low-memory devices have a separate kernel config anyway?
> >>
> >
> > Yes, the combined solution will also work but i think having a single
> > run time config is simpler instead of having two things to configure.
> >
>
> To add to it we started of with a CONFIG first, after the comments from
> Minchan (https://lkml.org/lkml/2020/11/3/2121) we decided to switch to
> run time param.
>
> Quoting Minchan's comments below:
>
> "
> 1. When we don't use page_owner, we don't want to waste any memory for
> stackdepot hash array.
> 2. When we use page_owner, we want to have reasonable stackdeport hash ar=
ray
>
> With this configuration, it couldn't meet since we always need to
> reserve a reasonable size for the array.
> Can't we make the hash size as a kernel parameter?
> With it, we could use it like this.
>
> 1. page_owner=3Doff, stackdepot_stack_hash=3D0 -> no more wasted memory
> when we don't use page_owner
> 2. page_owner=3Don, stackdepot_stack_hash=3D8M -> reasonable hash size
> when we use page_owner.
> "

Minchan, what do you think about making the hash size itself a static
parameter, while letting the user disable stackdepot completely at
runtime?
As noted before, I am concerned that moving a low-level configuration
bit (which essentially means "save 8Mb - (1 << stackdepot_stack_hash)
of static memory") to the boot parameters will be unused by most
admins and may actually trick them into thinking they reduce the
overall stackdepot memory consumption noticeably.
I also suppose device vendors may prefer setting a fixed (maybe
non-default) hash size for low-memory devices rather than letting the
admins increase it.


Alex

PS. Sorry for being late to the party, I should have probably spoken
up in November, when you've been discussing the first version of this
patch.

> Thanks,
> Vijay
> >> My concern is that exposing yet another knob to users won't really
> >> solve their problems, because the hash size alone doesn't give enough
> >> control over stackdepot memory footprint (we also have stack_slabs,
> >> which may get way bigger than 8Mb).
> >>
> >
> > True, stack_slabs can consume more memory but they consume most only
> > when stack depot is used as they are allocated in stack_depot_save path=
.
> > when stack depot is not used they consume 8192 * sizeof(void) bytes at
> > max. So nothing much we can do here since static allocation is not much
> > and memory consumption depends up on stack depot usage, unlike
> > stack_hash_table where 8mb is preallocated.
> >
>
> --
> QUALCOMM INDIA, on behalf of Qualcomm Innovation Center, Inc. is a
> member of Code Aurora Forum, hosted by The Linux Foundation



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVjejHtY8%3DcuuFkixpXd6A6q1C%3D%3D6RAaUC3Vb5_4hZkcg%40mai=
l.gmail.com.
