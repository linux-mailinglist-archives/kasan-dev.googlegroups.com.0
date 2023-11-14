Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD6VZSVAMGQEMZAEL7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id E21977EAB50
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 09:06:40 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id 5614622812f47-3b2ef9e4c25sf6164583b6e.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 00:06:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699949199; cv=pass;
        d=google.com; s=arc-20160816;
        b=pRCehz/So0tqEYSuGEaxFQgaJdVYMeFiTk4x5h4mnum1iPoAJf1U6W1qnTeTHBRtie
         pIK2K2h9v7ByOLJ7ABRyxNRYUyjeiTwpTyAGGs2ELMqLIOQ6wuUQtbQnHPeC2axgV/p4
         jCLqARWM6SxBIZSfIgf81EXEVE0/Y56weUqeq0cqfO5uV8UCckisu8tgKrlly3HCz+Wi
         AO1ahSWLynNbwXhE+LqD/0ry9GUJZH6JP4IvUP0aez4J/Fp4jFq5FRkXliKhwlOP/VzE
         rc7fNNhsn2bX8aZ9JkJiSTAvrvU5z3Xum3KESf6QhVtmjH1lfbVast2gMYh2oK7NVvbD
         M9Bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=523lIES1Rfh8zpnnTN5tOirKSgVUgqFJBv1Oed18k10=;
        fh=pbeCvjYvRJ8IBn2aQRheHH2sWFEJWhpwAspw8Z+6Ap8=;
        b=KAiJEeuIN6RoKhdVdXJh1+hpUzSB92nK+nmQuEc3bLJT4uZA9YBwLKe1/67533UIfP
         UbYFUzC2YEhpG24iA374KmjRyWtj7qAxZWkFVAHIt5yACbOtqlTQCpYEBpDR4BsLS/45
         CiAQ2+yW2ppNROIqv1aMHerdqJ1dJo4ufaxvunHSK9mouPiqHStG769rxu8ft5lMNjCB
         JaKMJQQrRzmN66ArrlmnJWcuiXTdGmyR9R2IuY9WtFRiKEwEHwLgSmpW9ov5P279sJ9j
         3NuFvwcK5AxLwTW/kt75jyrkik+b0oc3G+W8t/w4rOT+GIpXmCLsQBYZD7O20zcVXr+H
         akbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=a5hFi6pS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699949199; x=1700553999; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=523lIES1Rfh8zpnnTN5tOirKSgVUgqFJBv1Oed18k10=;
        b=US2TGU66m0zZaFTDXAeGTjONlFJcwpEuScWFasjQbyFVmFWIFvYoMfC9CpgFZklZdT
         UWdhwByaxOnqAVgZdiTa46lvgMCFLKxBdvf8TS6aluN/36wZnqPuHjaNRDq2mCotqfmX
         Kf8vsn+VeruBn9o+ez5BfVtdapaEDokgVpgP1DHYl+/5QGKDPTXHm2FBJJtZPPevlLPJ
         VHrTf84JilOBrUCG+JHRWM/gFKUmsu9OQ1dseT5Rvo7UxYejC7aFzLNgKVAZKKLjC1ZW
         H1b6NYHcQKHyOCTXEGKT0skZJxtVm1A20Q/JHEZF1/gBJMWCSYQlflsraU3BVMcslfEK
         38UQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699949199; x=1700553999;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=523lIES1Rfh8zpnnTN5tOirKSgVUgqFJBv1Oed18k10=;
        b=fEDpJ8sn3TGb3luTxnHf9Vebf1yRrCYXmPPxFkgRFa/+yphwUtJIsoU5Fxn+ZI9hfD
         x34bxtBsbIjTg0IqnnSypt5Gb3wa/74GVmTlKrXWydbRJQAnLtnpiqaGnEYtw+Kcudp/
         eT+UfCzvDKA/J7m7UmAqzOoH0QSaVbuumIEGjdcnZyzv6YOBdJ0CEIpZgyKm9k38xNrh
         mpU/4Ep+Y4a1R50xPucnTRvMD705pBxB8bNdpojL2YZCKJJeCPXmI/LLuP9DdBIo5wPP
         GeaC/s2NVaYi7JbKC3n5hU2/snBrTkrbbUJtmC3C2ySvDU7/j7P5pJEUKyaspNaDN1fz
         sr2Q==
X-Gm-Message-State: AOJu0YwRqWYebceG7+NJ8XOS5S9uHf1ExyeEOgW9ucb2k5oKl/dMdUnb
	EDbIGRuiWoxipMIaeQQYsJw=
X-Google-Smtp-Source: AGHT+IF5Igj0NOikLg4qGRieq6cfpRgp1wKLJciojpXNV4Tnxvkcvxyy+RRqRx3LrGAWCLV2Pp1tyA==
X-Received: by 2002:a05:6870:414e:b0:1ef:3916:2d80 with SMTP id r14-20020a056870414e00b001ef39162d80mr12258276oad.46.1699949199447;
        Tue, 14 Nov 2023 00:06:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:2116:b0:1d0:e2e8:7edf with SMTP id
 sa22-20020a056871211600b001d0e2e87edfls4953oab.1.-pod-prod-05-us; Tue, 14 Nov
 2023 00:06:38 -0800 (PST)
X-Received: by 2002:a05:6870:7ec5:b0:1e9:e0d7:3663 with SMTP id wz5-20020a0568707ec500b001e9e0d73663mr11275742oab.49.1699949198555;
        Tue, 14 Nov 2023 00:06:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699949198; cv=none;
        d=google.com; s=arc-20160816;
        b=dv7bz6HS1jnjD+JjBGW7aoXKolJNYfqvp7p168UKS9FzLjLfby0bPOVIW9BT2tb7v6
         wKIvgZmQb8VXtgx7bmuVxM9Lliu4NqqAJ+ARX67hAs1EvEd8P/r0mKCEAoOXR1gxWMBf
         zCAnhUh8ny2H5Dz43K0iPexCktollWh5GCjr+1WE3rxRNTYel+nVAqk79DwmCQWzddGh
         gKepEkkCNHQeCRKq5Y2roLHWE1baMugcV0176xwK3pOW3KLOqcngGzrYG33r48ek5oQl
         S1MH56ecg507VpAN6fdlszVOYDQR7JJNZwbLlBBNtH8YL6h1vhIqTd/O8amzE/qzPB8N
         ib+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7LGBUC9KsVeG0zIgCHu5xE4QSpLiIpSfaSXOL0b9rF8=;
        fh=pbeCvjYvRJ8IBn2aQRheHH2sWFEJWhpwAspw8Z+6Ap8=;
        b=SjzZDhaivrXKfVpGbsDiYDxlp8gMzLWuU2fm/MoHPFbfboSjyyDFDv/DD39ZSOKKm0
         RBTp/gc+bcVkukO7YqnfA4u8zF7/w6mKcpSdgg2t2lJrzOeWadawc9WNQwn9ZtEl/pPL
         MGNHIpkmQs4K1wMxO1ATiq67Ja4h/3x7erLncS27VbmcwRe1m35mWkMswXpYz6czVgOi
         h3k0+jNJJRwZNyyOABUV05EsRhxr70d6wB7x4khC7hymIlA6wndK5ajUGcZjx+TE6PUd
         smt5l8d2q6pVSpUr6r6BvrheThvtH9Rod7xhdQltNPzyVbzAaziXHf2xlGGC+9YACLQR
         vZ8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=a5hFi6pS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92f.google.com (mail-ua1-x92f.google.com. [2607:f8b0:4864:20::92f])
        by gmr-mx.google.com with ESMTPS id c22-20020a056a000ad600b006c6930e755asi361859pfl.5.2023.11.14.00.06.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Nov 2023 00:06:38 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92f as permitted sender) client-ip=2607:f8b0:4864:20::92f;
Received: by mail-ua1-x92f.google.com with SMTP id a1e0cc1a2514c-7bae0c07086so2149711241.1
        for <kasan-dev@googlegroups.com>; Tue, 14 Nov 2023 00:06:38 -0800 (PST)
X-Received: by 2002:a05:6102:474e:b0:452:6178:642c with SMTP id
 ej14-20020a056102474e00b004526178642cmr8315473vsb.1.1699949197540; Tue, 14
 Nov 2023 00:06:37 -0800 (PST)
MIME-Version: 1.0
References: <20231113191340.17482-22-vbabka@suse.cz> <20231113191340.17482-30-vbabka@suse.cz>
In-Reply-To: <20231113191340.17482-30-vbabka@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 14 Nov 2023 09:06:01 +0100
Message-ID: <CANpmjNNkojcku+2-Lh=LX=_TXq3+x0M0twYQG2dBWA0Aeqr=Xw@mail.gmail.com>
Subject: Re: [PATCH 08/20] mm/slab: remove mm/slab.c and slab_def.h
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, patches@lists.linux.dev, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Johannes Weiner <hannes@cmpxchg.org>, 
	Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>, 
	Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
	Mark Hemment <markhe@nextd.demon.co.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=a5hFi6pS;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92f as
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

On Mon, 13 Nov 2023 at 20:14, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> Remove the SLAB implementation. Update CREDITS (also sort the SLOB entry
> properly).
>
> RIP SLAB allocator (1996 - 2024)
>
> Cc: Mark Hemment <markhe@nextd.demon.co.uk>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  CREDITS                  |   12 +-
>  include/linux/slab_def.h |  124 --
>  mm/slab.c                | 4026 --------------------------------------

There are still some references to it left (git grep mm/slab.c). It
breaks documentation in Documentation/core-api/mm-api.rst

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNkojcku%2B2-Lh%3DLX%3D_TXq3%2Bx0M0twYQG2dBWA0Aeqr%3DXw%40mail.gmail.com.
