Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2OHRG2AMGQEBRAHWPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 80CBE91D9AC
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Jul 2024 10:08:11 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6b057a9690bsf33301846d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Jul 2024 01:08:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719821290; cv=pass;
        d=google.com; s=arc-20160816;
        b=aLemg+N/kPLejmoqTY8sx9wSf5n9Z4uuE785Ox+nRa+WqHTjx9gCZTLfWbK4TDj16s
         nWzaJ111vXAzgomIVTnkpdhMHfRi5kC5+Ss4ze62pxCKusZo035haNyosLBRvO48VZBA
         +5qBN3tAFtExGYDmcO9NikIDIm4QV9SeQOehs9PcIl0jMmG5yOtwR0Xkr/47kQj5QdmZ
         5QbH6rro4tu2M0mGquecBiBAX8p0okz1jou2Y3j6Fyiw0YGM0SA5dhDprViSR+yVpOg8
         3xjVpac2SfGjjm5xiDaK33ptDvw40rFL5X7JiQKky3ZobrUzhKg2857GlBJLkqt0ror+
         a7qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7enkNpIsIfyluIfWKzQxDHXvyVWoVu5yBbxsBlg8kHo=;
        fh=gCyJg8xHy/gzoIC/8PvQEznXTnwnGY8pWfHEqaRz1wY=;
        b=JvFTyh9EBhagncrNxll8+vlctzxW5czB4dCus+v+bAyRLCbW9Ot94UzaqX7aP/7Q1W
         fBAf8XCQtSh/d+4kYrqxldvMqeEffjNauOwZaE4HWJp8Tl41lW/Qgj/yfSPN9TE2ZcLd
         r67HsFQml30WlKkiI1MpPPwPNskeYxW9R522ByjaqeA0B+vZMMaCpebGLKylN/LSIVWK
         UvAhhsf+Qc5Bl3t+lYY83R+H62NmVQjlIGvD3FY12BjmS2WgviFT87/+aEeO5mVqEeBn
         d3CRJ2MZ9hX1DhcIXVXqJ5ydzDtTVEGqShZ2/2gHJARAhrsWlCNv1NZ+2UZ67/HMykCl
         vq2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=q0+pbfV6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719821290; x=1720426090; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7enkNpIsIfyluIfWKzQxDHXvyVWoVu5yBbxsBlg8kHo=;
        b=mOuLKAqkQHhqDUJ3kl590Qw+9NsRUuZjJIe+Nca+KvrArrcePa+HZbhhSlzdXUN7aJ
         yAx4HgQf//071sDAyCXcR1mXV19Mcd0r7LF1c59k/qMQteC4p4lRNhk3EU8SkjdVLjo2
         W6bnAP3pALeIbkr0QLO2um16Wc6uZQ7GH+7eRLJq0UcNZnAoZUWjnL0vRiRfrYXmzrYj
         X7X0vn+QOSqzxwmz0YkGr6B543xPBc475ycETMLJBcoyDaQJUoe77ZJRlU82g+xhSBc1
         1mGKpM83wxPm/2vP/jf8RC9Mbo2+M9R7+KLCDZYybtfZzKP/B8NCH7n/qk7WoedmrcSp
         E0SQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719821290; x=1720426090;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7enkNpIsIfyluIfWKzQxDHXvyVWoVu5yBbxsBlg8kHo=;
        b=CVajdqnt/b+jC/N2FSBIkbVLky1Ubetjf1rgJUcRK/nJgkXzMwTlMKMnOBrG31r9qi
         L4E8lC0ZXeV0mnLDSlLrT7yiXyxjhrud9A6674iUkneGEPnDC7mSoq0utvOjP0/ZEgd8
         Bi+3hvoqTRyD+LWrqDZPwQ7x8YwJE9CDNddaLpr95K6cVY4QxokU125JzYgcHu3XLypN
         iItxXhCNDpjl9BRWf9ZNDCiNHUVucorR9Yx0odbnVJzR7iF496Xdmqrmp6IQ8unX9WVh
         5TWQ9lB3xZMfFDwYliDi6JKz9pGf8bCnZAMdWgQxu0vosquwfq0FMLDlwWj5kTnt7xZT
         61Nw==
X-Forwarded-Encrypted: i=2; AJvYcCV5gLwBK/6PmPUurVTB/cvNJn5+280Ezlme2fw71tcaVdUu5yK0o5Wbq1nhmqL8ve1sLQW9ocGiL0d4rOaRpPAurtsWpzOneg==
X-Gm-Message-State: AOJu0YyAddBviaGPTl7jPQfrA265wd542EXTj1AaxSakTBIR+320cME+
	itpoTg0HH685Iedea8np/175YAUPfNu6HuyO0tFwRIK6yMKD8qJO
X-Google-Smtp-Source: AGHT+IFYkhWPB29wRjj/fSjKr8eF8B74oaZbl69cOoPH9+PtcmexMR5r/DYbe2S8J3T8qOydIr/pLQ==
X-Received: by 2002:ad4:4eed:0:b0:6b5:8fdd:baa6 with SMTP id 6a1803df08f44-6b5b719dc1cmr58995456d6.51.1719821290181;
        Mon, 01 Jul 2024 01:08:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5be8:0:b0:6ad:7b3c:b7c7 with SMTP id 6a1803df08f44-6b59fca07a1ls44972316d6.1.-pod-prod-03-us;
 Mon, 01 Jul 2024 01:08:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVc05FV8baRQxSIOpf2IR/7t8SWAM62t4F3namDj/rh8y+etSOQ8Wadx9sqr+/rQnhiDhBDwsdYuO/ladfowcwX4dxxoa4sLdBd9g==
X-Received: by 2002:a05:6122:4014:b0:4df:261c:fc0c with SMTP id 71dfb90a1353d-4f2a56f27e9mr2234081e0c.13.1719821288598;
        Mon, 01 Jul 2024 01:08:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719821288; cv=none;
        d=google.com; s=arc-20160816;
        b=WZ+j+NFyOYOj/2K58xG9AdBNBp/psSxSZoUF8rCi8oEImFaTi8yvafrlJYdqTExeZh
         eEkW8VS0Bd2FNsvQ4I3lH3FTLiLaXscQh33f6OD87T6Y5PQtvbyjSwt+V7NO0ymJCXHs
         YMZyDZl5J+46BMmJLrdfU6uttCGDSUGMS8hPbsG0XCIJb35SpshjU2BJ90jkFH/N/PDn
         O1SCIPF+TDxluN0GjnIgJVFkqz81Z9gxx9oyJ3zhaXYfAPUdGUTkvaMSDYARQasU0GcR
         5MPDrXwUXsLc/Ysgx/ZzeMQ0KVJ1GzRboMuyOGaF/LPl+sMD1eSgyFz/H0TNFwWuE2Qp
         yBrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6aSwYtSpfHiZc4CsUqleqrbbtIAk9e+BSHL8NQ5ures=;
        fh=WO9WomVyVY345y866gsC11uVJknpZOTZpQaJVEMvmtw=;
        b=Ks8osX5nGCSGgeAjKWxGnAAsRwLmogSK3WtzweBkV+NWKjdWTumAkbXDFcEc8toZB6
         YCAl2rJbzmgsGO2gTyvxpeGZRgN/Yb2lnR4lYJYwkFSJZuNZNCKDbwshnWnqN/sniYUe
         F8jHuuTEaxtH1NzwxQ3DlNFAr2nmfQhdel7uh7UNslHHXXR69WVXEBTijch03cPWqd6Z
         q2Pr+dz1F0HNkZY5nyYarNMiXwyhYIrV/b5GVqPU5iakTYAUjUEfVV0Ks4NGJTaSQP5E
         WRrZwe3ylLM4UuBHv/icBQ1ZhWQMLuQxTpliG+eQASX6HWyiLze0y66cQjKgXQ9FBE6b
         nvxw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=q0+pbfV6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa36.google.com (mail-vk1-xa36.google.com. [2607:f8b0:4864:20::a36])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4f291e0cde4si91880e0c.2.2024.07.01.01.08.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Jul 2024 01:08:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as permitted sender) client-ip=2607:f8b0:4864:20::a36;
Received: by mail-vk1-xa36.google.com with SMTP id 71dfb90a1353d-4f286fe242dso836261e0c.3
        for <kasan-dev@googlegroups.com>; Mon, 01 Jul 2024 01:08:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXWBMUUIldvYOrsaHY+GxH5YkW+vT4ECFudh5KmJ/A66C33S9AEexKp+PNnd5tZp63icAmKLRS4OxX2iqN03otrhyyqXAvAnhOVpw==
X-Received: by 2002:a05:6122:4014:b0:4df:261c:fc0c with SMTP id
 71dfb90a1353d-4f2a56f27e9mr2234065e0c.13.1719821287938; Mon, 01 Jul 2024
 01:08:07 -0700 (PDT)
MIME-Version: 1.0
References: <20240630200135.224108-1-thorsten.blum@toblux.com>
In-Reply-To: <20240630200135.224108-1-thorsten.blum@toblux.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 1 Jul 2024 10:07:29 +0200
Message-ID: <CANpmjNMXOn_N=9CY2iGLC=r=FAP4J2EFJbwDsAEuhKydwh6wtg@mail.gmail.com>
Subject: Re: [PATCH v3] kcsan: Use min() to fix Coccinelle warning
To: Thorsten Blum <thorsten.blum@toblux.com>, "Paul E. McKenney" <paulmck@kernel.org>
Cc: dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, David.Laight@aculab.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=q0+pbfV6;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a36 as
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

On Sun, 30 Jun 2024 at 22:03, Thorsten Blum <thorsten.blum@toblux.com> wrote:
>
> Fixes the following Coccinelle/coccicheck warning reported by
> minmax.cocci:
>
>   WARNING opportunity for min()
>
> Use size_t instead of int for the result of min().
>
> Compile-tested with CONFIG_KCSAN=y.
>
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Thorsten Blum <thorsten.blum@toblux.com>
> ---
> Changes in v2:
> - Add const and remove redundant parentheses as suggested by Marco Elver
> - Link to v1: https://lore.kernel.org/linux-kernel/20240623220606.134718-2-thorsten.blum@toblux.com/
>
> Changes in v3:
> - Remove const again after feedback from David Laight

I think I was clear that the removal of const was not needed in this
case, and my preference was to keep const.

While general and _constructive_ comments are helpful and appreciated,
this level of nit-picking and bikeshedding about 'const' is a complete
and utter waste of time. I'm sorry, but I'm rather allergic to this
level of time-wasting.

As KCSAN maintainer, I'm just going to say I prefer v2.

> - Link to v2: https://lore.kernel.org/linux-kernel/20240624175727.88012-2-thorsten.blum@toblux.com/

[+Cc Paul]

Paul, if possible kindly pick v2 of this patch into the KCSAN tree:
https://lore.kernel.org/linux-kernel/20240624175727.88012-2-thorsten.blum@toblux.com/

Many thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMXOn_N%3D9CY2iGLC%3Dr%3DFAP4J2EFJbwDsAEuhKydwh6wtg%40mail.gmail.com.
