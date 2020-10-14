Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNWSTP6AKGQEH7KET4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4402428E040
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 14:04:07 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id z68sf2850291ybh.22
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 05:04:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602677046; cv=pass;
        d=google.com; s=arc-20160816;
        b=TvykHbYVDL8IquT5y5Tcp4CZ7N/BxO2E0pXKnx05zLCXxjDAHXH2JUuuda1L2t8l67
         qta1K3jjmhWniI6wyYwX8oAOHieOnNQi1wrAR/HH9w9NC1TS/cWQWgH5FImg3KLo5NAr
         tBSf4vyNMEhduECtmIKdTdSIyv+uQvHjG1632AWAFG5pekoI59ZRtwmCrxok+H8KbdUC
         l9/ck3fXZKMN1gCGAIkEIYNUCIcbD9GB3wGBAFEudLaZhKWdKGtNRCAkUkf23ZlwvYcW
         uqJohQ2efgin2RPmGcsu0wJ6VXKfwHzZtHXa08EVzhTAXLLbLAU7ge45PKAyCEpGeW2L
         CU0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=q4AvBAk734bTr2Iq/VR2lG/C1PTmVfh39L0s0tY0Ph0=;
        b=RfeYETUWcb4+Hep43cWhbfypwT0eDVh0AxeouHBiYKgcc9dP4+k/GQH7rZFOFYWf2o
         XSvEh00ixJ3ABCzflJ6mFg7a9Xm4h0cPGOnwpw5q0SCadjJc8Z4h95TCYkpy7cIHgDt/
         aj7M1Q8GLbfpfM5epbwD7YKQ4kNBCH3uuRMxx7B++XhZqm7sM5pLoGGBivdcD4hg20xZ
         VhrxxHJ7mVBl+wfJeVFYrPNXVCHR89Esx8eu3sxh+VOzF/Y5VO6p+OiZ1JKS44MGmPhI
         q2YLk+ZNB0tOd65qgWhBi4IVwD7Ipizuwu1Dt4qrk+bpVvug4h1F7xF89HSv2Ru89G7Y
         qAFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g1tGhnaq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=q4AvBAk734bTr2Iq/VR2lG/C1PTmVfh39L0s0tY0Ph0=;
        b=KGNcv6QeeqaWk/+5cQLn8uBTdt6vVFrTjLzlLREthxKA6ghoD8rGu+WpNYgO8Rsn9B
         xQdaCK7oBC5Myno246iTVJBnTl4wcwmV1dl9IdEwQFDrAWSX8u/0CfPqeGg1NUXs3TKx
         7BxwXUsjGUeRN6LabHJTfq6wmpaDzDDowGDpgrRfNe1xAld1BmznvfnzRLPv8VBrBF2q
         6oCgWbG+kdgrztzL28Cq2a/MDn03Fj658vd54VgkyNVtOuk2ep2QJyistOxdEBN41AYB
         b93gNUdId1ZtE914F5CQBOh6UdVgRUXKpIOe1RZBkPS3DytKpR4tFUkGhy0jYDfJAVWi
         lvGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=q4AvBAk734bTr2Iq/VR2lG/C1PTmVfh39L0s0tY0Ph0=;
        b=AYKuXa/cxpHljWVWlYsXaDPhUTbGdjkzUjDt7Ij1gXtrBUZwFmIJzCWIJ4ApVCNVIE
         TFQR9xmrPoeWZQNmeDHyGdCShpxSMwpXUx4QfKLKbCL2kWDnlOoo0MP2Yui8Np+z4ywm
         ULJBwC/Hq/UXaF0TKQmw9RSbVoo90btj/lzLlGvT55Ou2f940xuFG6RjZyK6GIPt46jv
         n//gAYOzdGrzlrv3RlrBSa3B2URapA66sw3v8YI20sPKH2295xDDhEkrIgdU2I+/VwY/
         9YB+EyyY8YemFhV8YVkKHZzIqlWfkcy+x/sQJsdpNY7xnh3oj/I9K4n9NObxHgAPgiNf
         ZyIg==
X-Gm-Message-State: AOAM532bDkGXRAssHQaVYPdCmu/6hUpUERRcANmtW0U06GkUnneydOEw
	xd3YKh7ZRQgBvQ+vj3V0DvU=
X-Google-Smtp-Source: ABdhPJwfRIF578klE5WsLFao6TbmmMhIc7z4gq3hXda+EbBu9Md8wf5uF0Vwl07qJzTRbdoJn+otXw==
X-Received: by 2002:a25:7287:: with SMTP id n129mr6619870ybc.90.1602677046190;
        Wed, 14 Oct 2020 05:04:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2a0b:: with SMTP id q11ls1586085ybq.8.gmail; Wed, 14 Oct
 2020 05:04:05 -0700 (PDT)
X-Received: by 2002:a25:61d6:: with SMTP id v205mr6638834ybb.294.1602677045667;
        Wed, 14 Oct 2020 05:04:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602677045; cv=none;
        d=google.com; s=arc-20160816;
        b=gVItpDGK6gkg6dFcejdNoRiuoMtbA81/QbF+jnfslb8rBJ1BL3Ev+4gj9pICJQRUfU
         culv5OVjPkWC+neBIxe66SRR8CU1DAgUqu1w+PQuI9GAl9LGGkKVvnVvpLg5rU3+9d/u
         PDSjjvx2wqZ1YUhrWdh/2NyXEJLT0nVQUriBx3uP2VLdIVEGJjf+Vm+CMjRGCvD44rWB
         ZcwAP+/sI8andCX/At75mC/kKLOIIjOn/It6+FlWdJHiXZtw4Jsf1kJ42Zt89pSJpLt5
         iU0AnrjKex3O9nk+r+M9jQkTbTOjjqyzy5IfIYPbwzpmKHAEw9IPnzLrep2BsKO+QXbC
         1v+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ATFXDPatXvPj/2h2inqfF7bUexJDc1ZXDGjjpQmdA/c=;
        b=cN1k1ngcuvGgui0dGWBd1BCg/8SYMLh1mO1i+Fb7nvqAyJamjUsq6XQndJMdBSiiWV
         f4kUCAutiURcaBAfCIci9C6qUCgn8eZ+MTB2vF0NlcFhkWThsFkF6dNhk5VYw0Gnesh+
         RVwTpzsP0ayZi0De323ckpxkvKUIT4goKN8vd5ayfwQDCRkOjS7Q7gofNdzm1mlmTeYn
         48y1+EA23GDnIAUC5xJ6sHZMjKL1ri9/tNKQRhj0q9doQqAzGctRTxg/rZIPaW80wF+n
         TBOXil3+CaZx06hBClKTSVEt7rzLqcUjKUXr7xkRxKS2xaJ5w3ccoEWDUQ/Swu0HwKyZ
         DV/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g1tGhnaq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32f.google.com (mail-ot1-x32f.google.com. [2607:f8b0:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id r8si208999ybl.1.2020.10.14.05.04.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 05:04:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) client-ip=2607:f8b0:4864:20::32f;
Received: by mail-ot1-x32f.google.com with SMTP id n15so2059460otl.8
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 05:04:05 -0700 (PDT)
X-Received: by 2002:a9d:649:: with SMTP id 67mr143451otn.233.1602677045138;
 Wed, 14 Oct 2020 05:04:05 -0700 (PDT)
MIME-Version: 1.0
References: <20201014113724.GD3567119@cork> <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
In-Reply-To: <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Oct 2020 14:03:54 +0200
Message-ID: <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
Subject: Re: GWP-ASAN
To: Dmitry Vyukov <dvyukov@google.com>
Cc: =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=g1tGhnaq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as
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

On Wed, 14 Oct 2020 at 13:43, Dmitry Vyukov <dvyukov@google.com> wrote:
> On Wed, Oct 14, 2020 at 1:37 PM J=C3=B6rn Engel <joern@purestorage.com> w=
rote:
> >
> > Hello Dmitry!
> >
> > Thank you for your talk at the 2019 Plumbers conference.  The idea of
> > sprinkling a low rate of instrumented allocations in is just awesome an=
d
> > I have implemented it in our own malloc fairly quickly.
> >
> > What I haven't done yet is create a variant for kmalloc.  There are a
> > few things to be careful about and I simply haven't found the time yet.
> > Do you happen to know if someone else already has a patch?  It doesn't
> > have to be production quality, I am happy to take prototypes and
> > collaborate on improvements.
>
> +kasan-dev
>
> Hi J=C3=B6rn,
>
> KFENCE (rebranded GWP-ASAN) is right under review upstream:
> https://lore.kernel.org/lkml/20200929133814.2834621-1-elver@google.com/
>
> It's already production quality, just last nits are being shaken out.

The (hopefully final) v5 will be sent the week after the merge window
for 5.10 closes, so probably in ~2 weeks (will add you to Cc). If all
goes well, KFENCE might make it into 5.11.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg%40mail.gmail.=
com.
