Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6PD2P6QKGQEPSN5PLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 47ABD2B7AE7
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 11:05:46 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id t8sf495849oor.19
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 02:05:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605693945; cv=pass;
        d=google.com; s=arc-20160816;
        b=YsJVYKHb5fR18uADpOD93ZaczxkH6XPZcoVlx5au6SwsUJJFIqmxBqpl9bkeDIlLHe
         9NOg/C2dn33EyqKEU9f+Noo/1/+lXyAWRKrOoLj2GbPKElGNVVObqvGRId5ciblyUsEv
         CD5U5eAdbNY3AMqab00w4Jk1NgZXY6QawzNjXvSsA9ipZ2/QMIcNXCx7ZT6/FwJ4Ax4H
         A72RI8BjQ6hI89rYVuQvkirtRN8LnIA/UHkniTl6MX3/qF7Ink3tKrg3Okz/zid7SPOn
         S2xqrJ11eXdygMg1w/BNX8pQXO0nk5RPYILkFs2QO1A4SsOxokz1NjGdrfxsPP5NlHlw
         Qgkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wRk5xryLkY4vteeacR0iqKzccSWcw+ul4vjfDhvM6Rk=;
        b=P8ggFJU4x7y9N7YhpOsCc7NdlmGGqPddZpW4PyQpE9drJhIMudbOuotzyKCoFWzUIi
         BJzrX43vssrLCQP1GxDZcd0njH6VhB9cLBLtVdjhtVfz0XczoziSnPDev8rqu+IANpZg
         pGQoiiBnrmUQOMY/Ga2n65GksZ9Khd3SnE5vajKpyRW7JQ68D+kVh6WV8AR2T2r2o5tk
         kQiDl5mhXDpio4ozXiEKpy+mLKAskgQf4BLznfLv+atgbTl8zs/i01sDl9lAbi3bj7qP
         0OxvNHW88gBMNhDgdZ9XlZSJv7VfjzmCFWbhxs8T1mmcd6Wvnalgo5D12EKcNdPrpQ2p
         k90g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NzJi5eSk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=wRk5xryLkY4vteeacR0iqKzccSWcw+ul4vjfDhvM6Rk=;
        b=nkif6xXkJGSPlXuCSjRgztaHzw0hHq3YVixFS4fOiXISXkaKuq2938lGXgZP0y46UU
         IkhsqX/Rw8qIH7ZQjm0mevGrs5GTySRaduqKYV/oDMl4dAIqwJEUoV2FdXN3B18RajAw
         n7yhPYxN0McBkEoUMMl8fmfccjCFCR7kTZ7WEgwau9ai2AlODWQIy0eQooJPijZQl/2u
         C08uZ7dlqkts+nWLqYEDrsJDOffi/r7hWPx0vWzUWSE8cN4KgW1IC72Qjliqm6q50LP/
         GXtEJG+QqyD9c+qAzvovxv2FECnDIixg8gQYAIRClW/zKEP3h/UgejGgJD+6KhDDCuvs
         HIyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wRk5xryLkY4vteeacR0iqKzccSWcw+ul4vjfDhvM6Rk=;
        b=XaedSzxSdtuGbNXO+CHI/xdkDlJn8+I4Eg5Y2e1czhyHTubuHLBObRh951FCTOZPsM
         r2DIen8caipY/tNGkHh/n/XiC9WDb5P8wK3rgsWqkXIwQU2KK1vC1QdZF74RTBTbMfoP
         Wnb3rgDA7BQIKBPPrANqeJWUPnIFDlvIjkGtKRuMCNIyupRDmO9qasS7OazEu2eJ5vfQ
         Z9CtLQ5rdbXfoIlzp/IbRL9gr9HobJkSWPnaV4cU+pl1k31IVbJ9kCmBLhGzfAZ9m/rr
         DZ7U/KuoY/Ej858M49CP/oDkoEgXB749lh52Z2++wtWLav/3pMHoXGyl5H3QL2zykvRC
         lWFQ==
X-Gm-Message-State: AOAM532t9Hi+ATx2jqh0EtQVJv9tfXDHSc7R2K/TNQpIb+DAOyyf3xaB
	QEWHk0SIUMS6+jgxSNe2YQ4=
X-Google-Smtp-Source: ABdhPJwB9zRQRFbZSIOO/nHSeSsJohFnBOb497fqsHNAdDi4r/hEInRgh9voxgQfFDn10IbriEpb/g==
X-Received: by 2002:a54:4101:: with SMTP id l1mr2067383oic.151.1605693945179;
        Wed, 18 Nov 2020 02:05:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:130e:: with SMTP id p14ls4897866otq.10.gmail; Wed,
 18 Nov 2020 02:05:44 -0800 (PST)
X-Received: by 2002:a9d:3a76:: with SMTP id j109mr6142186otc.186.1605693944831;
        Wed, 18 Nov 2020 02:05:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605693944; cv=none;
        d=google.com; s=arc-20160816;
        b=IytwtacBhvCPbJ6g4Sov6L0jcJpu8+UR+gbX0+hkx3uMaklFfSiD2vCqGqmOS9F7Eu
         TyHGKxwanow2/tgtz6xFPS3dqhHweyIL4yCqM1aIF+T7Sut8jSzGyGi2D8Fo/t/+/vHh
         59Yb1UWrXHqgJqZx3I+r5B4dH+3Pzmt9xqH0361E7KWqQNcR+o/+C4Wq9VKBV4CGHqrN
         mY17tErhzlIFn4F1a7tcFq/UGhD/lmZuQhtQ831Ihd1gcbYtW0ZntWupBnquPXNp+ncp
         f7QDIui4euUEbY6wRtsfJZzYcz6E4u0zz4HtUckoo5iF8drnpKqq8XbKolxZV5DCnb93
         3PvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tvXAdDQlu+PDci0rdpXioH7lfJddHnkL++EjTa78+y0=;
        b=0h+vZ7gFbwOkHiLusklNfmPGdsRFHL+RB0cr3KLR7taKk1psa8nLBL0uRFtl9l4Xb/
         sSEccmuJtS919WN0De27PCerN97aqKkioTIHfHcMseSloZLGrXiUuuc4GFFrn5v7Y7Xk
         U02DCvk0heAzEjNYgoMsk+RTk13fpnbd64j8/TbkYEuPehNu+jXWnfyu0mtBA6OCUyJO
         /YHhSJtbtI+XeJx+bltXE3c2J6pPCDPskbSYW3mD0FQy5tuNsjWIsLjUu0Gaa3o4C6vV
         QxcZ7xZh7r0CPJXo/x8aVvZB7M+c+UCqxEvIAJQV9v1Odea3ThZDEKQ/eUKXnNt0C4wv
         gaKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NzJi5eSk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id i23si1651714oto.5.2020.11.18.02.05.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Nov 2020 02:05:44 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id m17so1602478oie.4
        for <kasan-dev@googlegroups.com>; Wed, 18 Nov 2020 02:05:44 -0800 (PST)
X-Received: by 2002:aca:a988:: with SMTP id s130mr2149816oie.172.1605693944364;
 Wed, 18 Nov 2020 02:05:44 -0800 (PST)
MIME-Version: 1.0
References: <f4a62280-43f5-468b-94c4-fdda826d28d0n@googlegroups.com>
In-Reply-To: <f4a62280-43f5-468b-94c4-fdda826d28d0n@googlegroups.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Nov 2020 11:05:32 +0100
Message-ID: <CANpmjNPsjXqDQLkeBb2Ap7j8rbrDwRHeuGPyzXXQ++Qxe4A=7A@mail.gmail.com>
Subject: Re: Any guidance to port KCSAN to previous Linux Kernel versions?
To: "mudongl...@gmail.com" <mudongliangabcd@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NzJi5eSk;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Wed, 18 Nov 2020 at 08:09, mudongl...@gmail.com
<mudongliangabcd@gmail.com> wrote:
>
> Hello all,
>
> I am writing to ask for some guidance to port KCSAN to some LTS kernel ve=
rsions. As KCSAN is already merged into upstream and works well to catch so=
me bugs in some kernel trees, it is good idea to port KCSAN to some previou=
s Linux Kernel version. On one hand, it is good for bug detection in LTS ke=
rnel; On the other hand, it is good to diagnose some kernel crashes caused =
by data race.
>
> Thanks in advance.
>
> Dongliang Mu

There have been major changes to READ_ONCE()/WRITE_ONCE() in Linux 5.8
which make backporting non-trivial since those changes would have to
be backported, too. Your best bet might be looking at the version of
KCSAN at 50a19ad4b1ec: git log v5.7-rc7..50a19ad4b1ec -- but that is
missing some important changes, and I question the value in
backporting.

In particular, we have the following problem: The kernel still has
(and before 5.5 it was worse) numerous very frequent data races that
are -- with current compilers and architectures -- seemingly benign,
or failure due to them is unlikely. The emphasis here should be on
_very frequent data races_, because we know there are infrequent data
races that are potentially harmful. But, unfortunately we're still
suffering from a "find the needle in the haystack problem" here. Which
means a backport isn't going to be too helpful right now because we'd
only like to tackle this problem for mainline right now. A better
approach is to backport fixes as required.

We are slowly working on addressing these problems, the most
straightforward approach would be to mark intentional data races and
fix other issues, but that isn't trivial because there are so many and
each needs to be carefully analyzed.

I recommend reading https://lwn.net/Articles/816854/ .

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPsjXqDQLkeBb2Ap7j8rbrDwRHeuGPyzXXQ%2B%2BQxe4A%3D7A%40mail.=
gmail.com.
