Return-Path: <kasan-dev+bncBCHOVJEZYIARBP6MW34QKGQE37MGQSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C42A23F2F3
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Aug 2020 21:06:40 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id u17sf2334395qtq.13
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Aug 2020 12:06:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596827199; cv=pass;
        d=google.com; s=arc-20160816;
        b=RlsJDiwhW1lWMX46yiyeo6Z/cjGbiN39nKWiU1bfkP0SYLGd5n/hPSWwjLfgdeCScq
         sQdkuyqUYcgNx1F5rLeM09GmesggdF2SOV6Mo1ISF8so4htgUUq/YhAg1QLmTozIVJ0G
         7OeKfikQ3hktJO3yh9+XL7qzjvFVlelpanmpZqd0E17gZgT07Uuycpjk+Gq7/oBhJotq
         NVkKiTbwrBNL57GjGZDIK8jAQEAbW6hEi9IQSKE8RoXrlzwiBMJ58CDEUrs8FwKQuVMz
         N3+hfXz14dK66dIuzlIeeLBbju/3ClSmDhfTbufKqUiwcrBua/DBaC7vj21S155/Oh/+
         Ulaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=aNH5wAI/nnFENTFZHlLhM2zFIsiNSV3ocGGzEolU/JU=;
        b=t6yL5bKTb7fQETU7U+fAFIwA8dEg3ReagOMhKwvXUaGn/zwV2+9/47GoN53AV7MW+9
         Sm5RM6GxGy+nQC8xGfRPPmEXPJieqeHYKcfA4d8FRCpBpLQQK8wMItICp+8UoSOLuMmx
         3Ry6hf8PRK9Qo08uD0QivITv4QIF/LMjGPu5T7Y7Zt+maRsRrRs7WW/V2O1JH/M5avcH
         qcclHTi3++9ql6ux17IezhI2FSiWM/r86LWgeQCNPCafyVhoZq11Zcyq1EowioebjGPa
         Bi7hKrEja4XVxG1bifJu9JFiAQsxk/t4xPKKH53xtQR5aKPOTkapq0EdWMk6rgXOcdKm
         zWjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=FWbrx8uq;
       spf=pass (google.com: domain of penberg@gmail.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=penberg@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aNH5wAI/nnFENTFZHlLhM2zFIsiNSV3ocGGzEolU/JU=;
        b=rEAXGAPiwx6BqfwEWrUV94fd/MuFuRkW/l23HnY5QYFUQJkYVqXTJaPaNLGLRMNlNL
         rUdJ5iY9M38byy/05y14ijhUzKqGppK//7Gk2sZBQnVWSG0kyBvFMfIqY2XSxb1U31Zb
         w7ou86cRwTp8K75j7AKzD0uRmmUigUatRPcPfomhHoxv+o6L6qBpcbpPkwxsHiFPLtWI
         8jR9ruEIEHxg18DO39c7UrtE9MiKN79wqI9oPV5F6CFy5vIJ6Ue0WHgj1uq6uAjHEEqS
         muO45b8xx1EARsgmY4ubHhh2jiBxnEUul5c2Utz5ZBiDj5QVB9og59yR7JcFyPACijxL
         qHGQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aNH5wAI/nnFENTFZHlLhM2zFIsiNSV3ocGGzEolU/JU=;
        b=QBOXO7FngDqJYHu8IMjgb10l/EqitM8UTjw+cBU0NIhLou5Ep4HxKuoGPrwt+mQC9Z
         y5jhUYvr2BaXmZj+pysWiHcWpeUFVUsnLYtfFlh7Q8B8hA0utM7Nob4ddvL/NwT4FxcV
         WJFRD0jUJwmlapr51iQG0d3ivTbOAYWKlcaQK/mxYhQIFcQpjAzL503w43a/aPYw6Leq
         3nk0Hp7eNInnWnpfGtSFZiM48zqLCgENm14DhV2cYytvxzp3+jb8wHy0BrpQUlrgjl4+
         h6fh33BxKfJOrktUSDdkr6TdGIcbJL5NwkbI2HOq28ZSz5RwhHMDCdxxJZTu0XETBv09
         JXdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aNH5wAI/nnFENTFZHlLhM2zFIsiNSV3ocGGzEolU/JU=;
        b=i9fb0es9qyUNzFKYMRdUEx/T/hSdpiIEgbvWqIloYHtDSae4RJ0NEgBUk5EDUeRapF
         9H1AAWopVqZVrv7HsRNETR2Cb13RhYpUG33aaivQkisiNrErBMAZv8b1Sv1UXYtRtmRB
         6/at/gcfbo+08ND0heZgiFTLgCqXx6jSkrI3Zh6bJYPdkVvismB4xm0fezFjrQDNcI1s
         duWNYu96afKO03Qvq8Zz8Shb5Foa9vCeZ5nCiPpq6xXxsXjd/fzqOgZb5UQ4Dts0nMmf
         i4DMacnixis/b2cV67lAyN5Wgq94tfswS+HHJ9QgapmcyH+2h6UTleA8zFoicf7tOSPt
         fj8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530auOtmDFl57MMDUAxGXmj3xTVnvdpXmUD85hSmlzwjhhkKi/FP
	Vx06O6bNvAYM+wRp7bHDNVc=
X-Google-Smtp-Source: ABdhPJzLmpKATGnAy9pTqkOVtmoE/z4m/rHHrbAZgqb9YNbSbcVY9Qt4br1vHc6Av3h3io7ttuUmHA==
X-Received: by 2002:ac8:3fd3:: with SMTP id v19mr15574845qtk.58.1596827199385;
        Fri, 07 Aug 2020 12:06:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2f66:: with SMTP id l93ls4210381qtd.8.gmail; Fri, 07 Aug
 2020 12:06:39 -0700 (PDT)
X-Received: by 2002:aed:3c1c:: with SMTP id t28mr15335121qte.74.1596827199067;
        Fri, 07 Aug 2020 12:06:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596827199; cv=none;
        d=google.com; s=arc-20160816;
        b=WukRy0uK6Iei2xdu5YolH4DiIOUoNP0t5F1ANsEV3GepnpwIIRP6jNKrtjLBwFaFmv
         cXG/kJ5Uw8HRGbWmT4y9UaFkWfRpRonoUB2ndgXz0WCi9JDhiBKHaeK4Xr3R/cafrqWK
         iGY2/E7WDTCbsCagg8kf4pJLxB4fmgyPSk5TQ2kblq88sc4ATDsiN/nV9gqClL7nhmKJ
         bTkOMCqcxKvuqqniYawNPmAC6hhy0xmwJK5Y0BNZ1Zsg7PuX84jx/0d2KI0Ih34gbbyl
         bPr1xs8Xl07GOIDCIM5e6iOleytc3i+cv8unjH8/I0Qz5SWe7HiQrRKiZljI0AXh6n+0
         xLVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zLv6z3MDMuVW61EC2fkzzHGi8++0GERRj/VmpMRNPpc=;
        b=SG5sKR5KEV4ZitVl8wCT2c9yGGqdFgwVkkvVjNoKV1HBc8tpMWAirWFtPf3K4BPVN7
         l++TDeoPkLVJ5lS1qUy6hScNOCEUUhlJFCPcydWrdbw/b81+9+WfYlc79WggPfBPAxRT
         c+8jNAjozhDRpjeO9WO5b3MHVrEGUYQ+LhBwnzdcRDYxxQoJRmt146JcK7eoMYWZDKAS
         01e8E644aFNzbgk84Xd9xjuX/BDzuUYSyzPpWfkWlsKKWyGoejCOVdO2XgRYmQYM7BL+
         D7EUsKZeMEtp1g+W9WYT780yAp1C6xVeCAKYakWnVpY4FQReicIFxeSxjmezqjIM4EH4
         zWFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=FWbrx8uq;
       spf=pass (google.com: domain of penberg@gmail.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=penberg@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id o24si531614qki.7.2020.08.07.12.06.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Aug 2020 12:06:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of penberg@gmail.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id h22so2389972otq.11
        for <kasan-dev@googlegroups.com>; Fri, 07 Aug 2020 12:06:39 -0700 (PDT)
X-Received: by 2002:a9d:3d77:: with SMTP id a110mr13124283otc.11.1596827198586;
 Fri, 07 Aug 2020 12:06:38 -0700 (PDT)
MIME-Version: 1.0
References: <20200807160627.GA1420741@elver.google.com> <CAOJsxLGikg5OsM6v6nHsQbktvWKsy7ccA99OcknLWJpSqH0+pg@mail.gmail.com>
 <20200807171849.GA1467156@elver.google.com>
In-Reply-To: <20200807171849.GA1467156@elver.google.com>
From: Pekka Enberg <penberg@gmail.com>
Date: Fri, 7 Aug 2020 22:06:22 +0300
Message-ID: <CAOJsxLEJtXdCNtouqNTFxYtm5j_nnFQHpMfTOsUL2+WrLbR39g@mail.gmail.com>
Subject: Re: Odd-sized kmem_cache_alloc and slub_debug=Z
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Christoph Lameter <cl@linux.com>, Kees Cook <keescook@chromium.org>, kasan-dev@googlegroups.com, 
	LKML <linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: penberg@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=FWbrx8uq;       spf=pass
 (google.com: domain of penberg@gmail.com designates 2607:f8b0:4864:20::341 as
 permitted sender) smtp.mailfrom=penberg@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi Marco and Kees,

On Fri, Aug 07, 2020 at 08:06PM +0300, Pekka Enberg wrote:
> > Anything interesting in your .config? The fault does not reproduce
> > with 5.8.0 + x86-64 defconfig.

On Fri, Aug 7, 2020 at 8:18 PM Marco Elver <elver@google.com> wrote:
> It's quite close to defconfig, just some extra options for my test
> environment. But none that I'd imagine change this behaviour -- but
> maybe I missed something. I've attached my config. Also, just in case,
> I'm on mainline from Tuesday: 2324d50d051ec0f14a548e78554fb02513d6dcef.

Yeah, it reproduces with defconfig too, as long as you remember to
pass "slub_debug=Z"... :-/

The following seems to be the culprit:

commit 3202fa62fb43087387c65bfa9c100feffac74aa6
Author: Kees Cook <keescook@chromium.org>
Date:   Wed Apr 1 21:04:27 2020 -0700

    slub: relocate freelist pointer to middle of object

Reverting this commit and one of it's follow up fixes from Kees from
v5.8 makes the issue go away for me. Btw, please note that caches with
size 24 and larger do not trigger this bug, so the issue is that with
small enough object size, we're stomping on allocator metadata (I
assume part of the freelist).

- Pekka

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOJsxLEJtXdCNtouqNTFxYtm5j_nnFQHpMfTOsUL2%2BWrLbR39g%40mail.gmail.com.
