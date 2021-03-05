Return-Path: <kasan-dev+bncBCCMH5WKTMGRBI7FQ6BAMGQEPMHQU6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C7C732E40A
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 09:58:12 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id s197sf860759oie.12
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 00:58:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614934691; cv=pass;
        d=google.com; s=arc-20160816;
        b=YuGuLfvoGrdPXWU0r/wJocrhlW4nvPB0yy/OP6CqOvNCEA3N2nvU/5nLpIbIG79kX6
         Bj0M8o/F76+50/YlL2j7gOmmRyvkM5p9cZphuP9PJbBeFukojAL1Yve5N4MKT4RFx2B1
         e+nHc1/5G2kq5QnhlwvMDGgZEgXO0fieg24MyM+SSyeQVI2oQ3Lbn2pFN01N0DGAzBAj
         yJ/y4atdSo9jQtycGO64NR1MFIxg6EWwTgwKPirWKC5SoGK5YvBk6GbnhDYkUgLN0imm
         4RWU8a+dLaJIFB4088sfj2wFUrSZX9ZPz40545A/Bc13/9zxMY8izdfyotcuhcvkOUQN
         qGew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6vgsYY0uWvCKBrbC3VqHt2zjKxyT6JJxC95Zp3w0hMg=;
        b=LDvQCrK5VRRS+g7HbB+Q10SmTcMBCLXEAfH/4PWxsid+GTfkVFMC5MxIMrDfeHeIwn
         CrUpPcuAKrqKJEXxFSD24l77RUZpuVaUy35UcUXhrFduZeibMt3CIwvkMxfzdP499l1M
         M4m+CkBMlNbLCixsDKy9muXj4pOlA04HggzsPwEfrDnvsWP2pKuS+++H2VH53ZtKbvlZ
         ElVUuvR33Ga6d8uNM1AJoAbXRgUu07yFg0okbaQcygAq/mBGdEPShEC1R8ym8v1wtdEj
         VzXRC/xj/jyBgHqCpA9hMv2+GxJd+ONWWgzl/rQlYvmAehxWSc8TorxLwCQUe7QKKgO6
         kgtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=POZV7tLm;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6vgsYY0uWvCKBrbC3VqHt2zjKxyT6JJxC95Zp3w0hMg=;
        b=KDoFjzKnz4ni60+5J0qAlpQULFfYsLG6QBJujpN/RxHlllx7OfU4+kHUi7T6LI1b99
         GDWu/Whk38aT+oZAqHWCweOA/6/D79KXSI1TRLmDmoejbtG3naVxCCWQKVDV1WtW/sTt
         ZAjDH/BBceBWgIFzOnVWgKWjJHbL8FyLOCgQ3NigM/sJeb/uKeTRcnVwi/wL8CWf3S/6
         +hyt344e1RaVaTVupSbpgtOHPoJr1MVzEoU+8BfVc9Otp2wM5E1JfPlD8omgpgHiychw
         xkDQDsYNhzYSY/AkwcBvENshldGLQk56qvkrh9YjqbMyiLm6941pUuCEbTLaK48MeeqJ
         8A5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6vgsYY0uWvCKBrbC3VqHt2zjKxyT6JJxC95Zp3w0hMg=;
        b=LcLYkD1OWQzzgEJN1VKZuSR2MXykOPYYVo/D6A2XYCQftFVNqr0oHoRxbgfLQoZ6Fk
         OCDOVmMJp39BGx3lJot12JSS0gjooIWs5lxwM+8jpLAnq4OHPCClGsPZhxY+VaAEv7Az
         AqYDe5wZe7bD5XxahGE/gwNg857ll0Kj0qhfe0lULHjxoZef1JZVOehGrzw9Db9l4x0f
         cJDQcpnGTpkTUpb1+voqQx8oGNRbGmhRc0o1QUiYLPKw2BU2cGYk/sa81Q8AkEnUJrIx
         9rGCk5EMS2LvjmlsSAzTTG+UmGCsCttblgWses12WhF2LgmVwDpAQ/U1HO/KsnjtN/AX
         6RPQ==
X-Gm-Message-State: AOAM530A+SQUP+/aI5dK4yM7cS58xXo2iCNI3b3NyA2SNV4oEX8ApR7k
	dimLhf+Gx/hDZAPQocqeZbc=
X-Google-Smtp-Source: ABdhPJwaVFsrz2TVT5/I1eFk1VeYSbcpN4K8OIbHKK1LZlnTBkFDB/s0btRB4UpWnF4kTXu+Y3xgtg==
X-Received: by 2002:a05:6820:129:: with SMTP id i9mr6791220ood.80.1614934691376;
        Fri, 05 Mar 2021 00:58:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6ad2:: with SMTP id m18ls2377905otq.1.gmail; Fri, 05 Mar
 2021 00:58:11 -0800 (PST)
X-Received: by 2002:a05:6830:1afc:: with SMTP id c28mr7148823otd.99.1614934691063;
        Fri, 05 Mar 2021 00:58:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614934691; cv=none;
        d=google.com; s=arc-20160816;
        b=AJRZA/GfECPm2+Eh/PnyB3ZOfNo57ytjr6WQQb4Y2nLljKEQypbJ7GcUN15OlrsdwA
         +Rehrvpue+dZ27jrEgpbpCWccsDC4JZ2PhJn1gBreD46e+KNSuIRj8sUpczljuZkQlUV
         e8u/kKW5l0H5TLq49mgrcQg0LSwvRDyErr6Qf7g5bv8p5CZqYfZxpkSUbuB5+UEpFp3D
         gJfyWxLpqnp92SuBKThSqlCZkqHX72p48SxX8zNqLaaHtsIA6+OwkbQRa4+iQCmu/5+d
         1YUOX/oCEEr2fG4gPl5UeJe+cNT2a27juPrN3zUnRJQviwspvrmhuT//tRrVqByChFUb
         Nb5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=229AXg85Pog+hgsT/zw/Y21FmddYbB2y/IxgWdPynj4=;
        b=mv1WUDehyA/DMj2K01R2vNwFtU/v23eunK1vdh+ehVvf0K+Cz4MSkl4q+hzj0nTNvQ
         2xCN51EAcH3a7QqCm3qZqy94p9oy46XDh4DQ11wTCQFAy3Xt3W1eO5wkK0qJRlEpkSyz
         CLygHQop0R7AMfgvGOfWtEAdlUvl+h546mMAzrCg1lVP5IeS98iGQPd88e48HlrZIm7i
         K+OSGh3fFZxDvVLFZxd74m7V1YTt0cnHMyJeedz2DKaAV94x/Sfzg3KMJz0fUyNMo0ir
         Mpg0qai9GB6Ef8fXSAyS0uW2dYgxpJbRFYgoUZtQREmPwu/N9zRqUo87J3U0+9bdjz6X
         Bj7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=POZV7tLm;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x729.google.com (mail-qk1-x729.google.com. [2607:f8b0:4864:20::729])
        by gmr-mx.google.com with ESMTPS id v4si173966oiv.4.2021.03.05.00.58.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 00:58:11 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as permitted sender) client-ip=2607:f8b0:4864:20::729;
Received: by mail-qk1-x729.google.com with SMTP id f124so1259526qkj.5
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 00:58:11 -0800 (PST)
X-Received: by 2002:a05:620a:1353:: with SMTP id c19mr8364887qkl.392.1614934690350;
 Fri, 05 Mar 2021 00:58:10 -0800 (PST)
MIME-Version: 1.0
References: <20210304205256.2162309-1-elver@google.com> <CAG_fn=XVAFjgkFCj8kc6Bz4rvBwCeE4HUcJPBTWQcNjrBLaT=g@mail.gmail.com>
 <20210304173132.6696eb2a357edf835a5033ee@linux-foundation.org>
In-Reply-To: <20210304173132.6696eb2a357edf835a5033ee@linux-foundation.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Mar 2021 09:57:58 +0100
Message-ID: <CAG_fn=Um2FW2m9y0iZ6J4L63-2bBVVrgu3hMQ0-GLwHxU6Hiiw@mail.gmail.com>
Subject: Re: [PATCH mm] kfence, slab: fix cache_alloc_debugcheck_after() for
 bulk allocations
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Dmitriy Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Jann Horn <jannh@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=POZV7tLm;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::729 as
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

On Fri, Mar 5, 2021 at 2:31 AM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Thu, 4 Mar 2021 22:05:48 +0100 Alexander Potapenko <glider@google.com> wrote:
>
> > On Thu, Mar 4, 2021 at 9:53 PM Marco Elver <elver@google.com> wrote:
> > >
> > > cache_alloc_debugcheck_after() performs checks on an object, including
> > > adjusting the returned pointer. None of this should apply to KFENCE
> > > objects. While for non-bulk allocations, the checks are skipped when we
> > > allocate via KFENCE, for bulk allocations cache_alloc_debugcheck_after()
> > > is called via cache_alloc_debugcheck_after_bulk().
> >
> > @Andrew, is this code used by anyone?
> > As far as I understand, it cannot be enabled by any config option, so
> > nobody really tests it.
> > If it is still needed, shall we promote #if DEBUGs in slab.c to a
> > separate config option, or maybe this code can be safely removed?
>
> It's all used:

Got it, sorry for being too hasty!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUm2FW2m9y0iZ6J4L63-2bBVVrgu3hMQ0-GLwHxU6Hiiw%40mail.gmail.com.
