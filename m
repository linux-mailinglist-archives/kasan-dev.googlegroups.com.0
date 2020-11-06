Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3P6ST6QKGQE3QLGHIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0089F2A961B
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 13:19:58 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id t17sf407790wrm.13
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 04:19:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604665197; cv=pass;
        d=google.com; s=arc-20160816;
        b=fEQVZNLwNb35kXKA9bzxuLRB6mvQ1pWTcExXp7d4pm+OOJ73X8sVeB04qpSSFrvgwj
         BZKqX3C2MvFGQFZYtzV6jaVc/dzCkN03ToAb8JkBIjzSjIsLqf4YgpnJuEOVSxwEOhJN
         2bu0/qxk4lL/UYRvSFgLu8pZUM8X1lknMd1kDKFdvuI6NR/9ulHHXr0YL67Q/Qh3lH6C
         sKY3ILKBezezJOTzcnZ5/ipkx14OdF41XKRQpbqYmh8Gb5mLLaMlM1rnrFO8AysNXp77
         KpnUvE87lXaj+mJO5B4AydBEWlNd6LGVkFjqwYFB5GkFJFVVvpcUe01vLK8r+ZWVZl22
         UAYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lH3T8+K3k2glJFm5rmY0BGJJNDStBKUMFJ+CJWvQgE8=;
        b=ZFp/nUlMcpbtQKbDidilZ6hUTPWVFsM0vJ4wlHchwU9pW/upWd7xrBYR2tUyPgELOT
         QIJT/8ZJfILWku+S6gV8Vd2iwULCZpRynd17ff1xcnCdxqTZdpagFzLJPykRzfp+qaOo
         MVsV3xBhWXXiHZ+RhKNXG+3geYMpD4L71R4z85OxMDKo1EnIwCmhWjTPDlRrHWsXCnF6
         6VQ6wv5JwzJapDzd8cGqW785wsh9RpwgxsKl83GoRGFUXCoA1G/YcL+iJ1P6TR4bRpTC
         wf53r4NRTRllCLfZrRb5MwXNu9jV1IjPBiL8JVHCeKsp4EWoHR78EAAIdngPJWBoHpJ1
         vDJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AuRaa9NK;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=lH3T8+K3k2glJFm5rmY0BGJJNDStBKUMFJ+CJWvQgE8=;
        b=sgop9ia/oNkvK7Mfgm1Yve/YjA10fysp7hXHm8j1fBVYFHfACHbja4Q7Z0WVqMZ38U
         5j+cmF6yAn7e+DG1Kt02pJDT9KDbSZhuGw1jSdrC4R3DH47rUNWm35YO0tW8FiHXnxIQ
         C73ARdPxFWVapN8ulK+VxhQfIxU8UqoOastWWPogJZ/PRVne7lkfozFABSRulvMw46fC
         juifl7zo2MT2U2dDSUt7LowZqf4dRUz+nMFrHh75BrEHbO08qIO2bYJfs5Jy2PQKnnA8
         p/YulZLoeiqijnxXK9tyOpOnAmQPJDZa5eQTrNnns+HWbFiJ6scysPcv62ktDYtJRPPP
         oMlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lH3T8+K3k2glJFm5rmY0BGJJNDStBKUMFJ+CJWvQgE8=;
        b=Qnk4CkjxyhxVnOqqbb5F2Y5/6rwCfgN2Vti7o6nV4RmtqiuO4oXGjgt6ar8mxE93w3
         +FCFE+nK2FjMiqBnOvWedCxV3MjEkGMkQ4ujXOjXTmVbKGmJUeUmPqBqTABP8YXjMpfO
         9/wRl7xeBQzQReYXv42tAhkyXuSmIVlkGV3JZ5ySITghrtbR1YdH/f7+hc9voTIGyFtG
         JdBugoyMsD8wV4d+0hCq8saOZiqrtc5tPtpPvjc+MywOQd0zDQExDXRk2hKs8kZt3tLk
         9YCXChhrGENEJo7Bpo117LGWalth/4OTo8U+0FNu3kkOr+cAdghTa1mZhWAHM4rh/8Uw
         joXg==
X-Gm-Message-State: AOAM533hNvCQ+XC+PK9r/D9UBcWAZeRSSMoRZK/zJj3kmFCCdgZ0M5av
	3rP4jAFduabsavs0sZaSewI=
X-Google-Smtp-Source: ABdhPJzStFyDLhQ/rMFYD3xRo13Uz7NoUnD2kQ2ZFSkEaM9HyIEF6qd6ZNJKTIvT2HYStispTiHypg==
X-Received: by 2002:adf:f643:: with SMTP id x3mr2543197wrp.180.1604665197724;
        Fri, 06 Nov 2020 04:19:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7e4e:: with SMTP id z75ls631203wmc.0.canary-gmail; Fri,
 06 Nov 2020 04:19:56 -0800 (PST)
X-Received: by 2002:a1c:b686:: with SMTP id g128mr2309722wmf.128.1604665196872;
        Fri, 06 Nov 2020 04:19:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604665196; cv=none;
        d=google.com; s=arc-20160816;
        b=GXYfFUQtU6AGTG+5ZLmZXzQgQ23gaZUxk8blXuMJAUUY0BZPwn97JOQvC6Xj4B9PH6
         eDQuithRJ3sxhg7m7XKyz0S6MTU7xlGyQ/W8W5mSerlacVPPixiQxaeK7zNZ/bfXkOJS
         9H6t4VOrK+qXP4BDzV964EWJNORxD9Z7Y1BJxbUypkVVacLN3kWyI811YH5nzxgJwTgL
         yomcVLnMddbfKwxgHZWLZnKdYUOGQ7uMPTb69GIcYBsZIpUquHD095md3bFw8keLo2yQ
         QUeYpd7oXx+bNmPZrltc+bgOPgZicfQIYn+HtZHrukMKv8VZ4SIopPVrw6R66KYxaG/+
         fODg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Wu0yuz1Rqywdt2lXVmkZwBU4v10ZmblZwj+lb/B5gns=;
        b=GLfzjPWsN+NIsSr6D8uCQeuDJx7Zx0ZEJ4EZUntbh0/zVBSJDaeFCso8KVMvz1wmKp
         3kJWX+Jn+f0lJ62ZJu9AZR7Xx9aR6/46mhoC8jjJW//Y09xdG9shJiuQA+Ur6Dj/it+l
         r3yPSkffM4jDSVMOvoWKKhcrq8oRszB6pDlF1k8wZVSzJW5EOqjnpNTkTudnM4cFEVSy
         W8+5mdb55khYxoXw5uJhROZVO8L9gZEGsl0q7RWgq4HOssdZoIHYBG2mz5x+yDszlVb4
         PdocoB+VgGDswC0kGR2qzO1Um0PK4tmU1OwHU72bLdPO0lHiaveqRZXx8l9zk8qO/ei8
         8a1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AuRaa9NK;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id y14si49987wrq.0.2020.11.06.04.19.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Nov 2020 04:19:56 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id v5so1202906wmh.1
        for <kasan-dev@googlegroups.com>; Fri, 06 Nov 2020 04:19:56 -0800 (PST)
X-Received: by 2002:a1c:c906:: with SMTP id f6mr2300366wmb.9.1604665196366;
 Fri, 06 Nov 2020 04:19:56 -0800 (PST)
MIME-Version: 1.0
References: <20201106172616.4a27b3b3@canb.auug.org.au> <20201106092149.GA2851373@elver.google.com>
In-Reply-To: <20201106092149.GA2851373@elver.google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 6 Nov 2020 13:19:45 +0100
Message-ID: <CAG_fn=Vf7vX7r1kyqd3pqPZnNN9kKO6gtmum+E=X_PLmxG=Uqw@mail.gmail.com>
Subject: Re: [PATCH] kfence: Fix parameter description for kfence_object_start()
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Stephen Rothwell <sfr@canb.auug.org.au>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux Next Mailing List <linux-next@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AuRaa9NK;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as
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

On Fri, Nov 6, 2020 at 10:21 AM Marco Elver <elver@google.com> wrote:
>
> Describe parameter @addr correctly by delimiting with ':'.
>
> Reported-by: Stephen Rothwell <sfr@canb.auug.org.au>
> Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  include/linux/kfence.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 98a97f9d43cd..76246889ecdb 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -125,7 +125,7 @@ size_t kfence_ksize(const void *addr);
>
>  /**
>   * kfence_object_start() - find the beginning of a KFENCE object
> - * @addr - address within a KFENCE-allocated object
> + * @addr: address within a KFENCE-allocated object
>   *
>   * Return: address of the beginning of the object.
>   *
> --
> 2.29.2.222.g5d2a92d10f8-goog
>


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
kasan-dev/CAG_fn%3DVf7vX7r1kyqd3pqPZnNN9kKO6gtmum%2BE%3DX_PLmxG%3DUqw%40mai=
l.gmail.com.
