Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJWZ5GBAMGQEIQW7BFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D416346D23
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 23:33:12 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id md1sf2737883pjb.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 15:33:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616538791; cv=pass;
        d=google.com; s=arc-20160816;
        b=KEFUwrtKzIPxG7PJQFfwXHWBBfVQ07qRTfpljrKcSiYlxF+vkIs56VrOKiTrvdQo1s
         A1PpmwsiGPuSH35VnqkyYO3YaQ36+uWZXByJTabY5M0inqtLFXUHmuqB1a20SZ9W02Xc
         7dNQq8pBjhPsQcATkzf79MtCofxv0xGyQJdSHVP/Sfna3jhWlCtaZ6tfbxZEXbdK1OE7
         h2SqKvc+4eU7JfYNu0tyI5MygcHIiwZcDgbC4Rum6QzdFrKCqmUSNyGDYIwRZqXEcs+h
         82MzFZg93rB1d8yTpv5m6Jyh8lLK0wSZpWIKc5IsCNCLMfgdap5c9DpDtP0LO81FrKL/
         v6Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Fv/wOxF1XJxd3asAT0kbWyASZsuwwAJWUvEjpKY+jkc=;
        b=XYd4spkkaYsUVwK99I1hHDeGqcamBYfWfsSyKVVxWkX4BLY9b6Je98J9bz9sNzHP5C
         zZ8haYiF6XniAgHlvqIXSYanmfsOy5ZUqbKW5Ywf13R+A4zyuUcsxiJnmJzOQ7rNQtPf
         e/60Rw+ItuBKpzuYuVYFmU1QwMbyZS+F4zO8e/qAAw2HmKlsfJiA9abVzFMeyN4E26Fn
         ZoB6KqEciIXWlvfdcYMYfujdycUtAtNwiPNVzMpoRvsCxDOxu3lNZokvbNrwjKA6enWi
         EFTdInEHDZqVGof0tDM0RHitk2m5UPPCFpewqFVJoALSq5QriIBxwQat0mJwRLMoQzkq
         +Kvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ln3YC/bU";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fv/wOxF1XJxd3asAT0kbWyASZsuwwAJWUvEjpKY+jkc=;
        b=QyXw2Hl9Cwgz3GbACEOYqG46VwLjcfAuPUBdNKb0X3eCjoTyQBZLkkC+A1L2OR9aB1
         1bynssNiHvLDB/ICwd9z1fz7kahPnOKLV8vRkOK4kEl9GJj2KJZIXh4UrAXq4g5kLcv4
         gImvoEseCXVwl63MU/2wbnoWmHNcmOVOumJdgd9bLZ4EY70U0WNLrVGxunrFkXOBvlC/
         Z7Ze083JvDi81HY4w58YhCeOp84jUHg7N3OoiZ2T4qq0fjftl3UJsNfX+3ilh65eWnkn
         rL4KLFnlRRJJQ/saPOsZU4NqZINrKY7qL+i58VRRlH18dvugAVG7gZAMXCD77C2g21eV
         2IvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fv/wOxF1XJxd3asAT0kbWyASZsuwwAJWUvEjpKY+jkc=;
        b=mWhfq7UvVUA/amN5HFRHCNu9YmaPZVnGsjg02ZWSnlatnE7rmsTquro4b3Sgnzyn8a
         Tu7qAG5u+z3tfd8edqifSGZcWm6JxXOgik2pgvvdlCD7yWghYO9VxvOImw17OcLS8YLc
         TgGrvrMvDvhun+N4d8llC7xOJgKUng7B8fujP9TUK1E4kiTvUi/cFtkTJKmEclYxuKaZ
         59Zsik9iNejVyiMcoDJwCeN+tofDSbpwsSgIdvdH3UwAEwKY2WA2fffeaWhkg4bpphTz
         LmRTvGIu4dcr0SVJ6HY/0nYwoyMk+qiKoh8fWaMVw9IEm09I/7WPzJU+pQ5HJD93P2KJ
         Bu9Q==
X-Gm-Message-State: AOAM53344O7uz0/75zm1naHLdd23vTz4VyeXwZSUAvlZujV307bqCryD
	MNdT0hwopIGvGOXIZAJPmXk=
X-Google-Smtp-Source: ABdhPJydKf2AflANZGgmV9u2vimaLNU2nkpQgpQgfI7zZGHitlWB+jIhuSEXyH2Q94BdaaPoOvg6Xw==
X-Received: by 2002:a17:902:f68c:b029:e5:ca30:8657 with SMTP id l12-20020a170902f68cb02900e5ca308657mr488975plg.78.1616538790908;
        Tue, 23 Mar 2021 15:33:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:183:: with SMTP id 125ls34630pgb.0.gmail; Tue, 23 Mar
 2021 15:33:10 -0700 (PDT)
X-Received: by 2002:a62:6c6:0:b029:200:49d8:77ae with SMTP id 189-20020a6206c60000b029020049d877aemr377891pfg.61.1616538790158;
        Tue, 23 Mar 2021 15:33:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616538790; cv=none;
        d=google.com; s=arc-20160816;
        b=l8UX2rW/dglgAYSLSFgzjzPsAKcyvvXbwB1afl/S6iz2G66OvIkZLd5PJ1U+rf7iIN
         lx0BK5DPxbiAeeGu8YYlxP/eS7b5hy0Mceo+hmJGakgYVxoDgr7jgLDtdXbV9YenjrIp
         Y8jjEc/2xC/BVRGFhIkb2MEWFXOglQMkI+HGPdyQgUdd8d+TgDqSJjc7ZxvYJzRyTbtV
         DKiSvX4udKfbMe6MKkRiErb8EX7PJBzrQ/xzCP4J09RNq9OTXv8BxlKw29fH70pUbWt2
         XSlhuNrRqLWjv3fk9Bgy5BaiakPqxLnHdoPiuhsmDMcPI3NE5txLavqAorVs+L2drhos
         DHJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wQiKUKE5LLzicC3GKIFkGS/5vOBpAIjzN60rfAG7hx0=;
        b=XjiDuV2W8cZpfCKdHSntBFDnPM41+NXBLHJhoLCDdPkpg37wGmMlD46/VaAZ1x9yje
         C0AhgCdCrDXKjZsYg0WpIo+IIpAsha61m/1CfQBj8nbgR2aFnXErvXxFJuvrxxXxrb1F
         IDEaTe8qAyZPr2wvYBsTe2wZRc63oxYnWUC6058k2ZHZM0bhRrW22F9G3TDQnJcvJfTx
         oCAlrppaxLPV2vczonh1fo+E0hSoTZoDF85IW0ldgcISZR4LLWBQyppslXljX7kDYGVz
         JvFoFSGuwgRVe0DDcjG2r+Flr6c9smSMYnQraMLS1lsdRYDLaIeUqdai84cpibvtjwSb
         Pj1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ln3YC/bU";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x336.google.com (mail-ot1-x336.google.com. [2607:f8b0:4864:20::336])
        by gmr-mx.google.com with ESMTPS id m9si18095pgr.3.2021.03.23.15.33.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Mar 2021 15:33:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) client-ip=2607:f8b0:4864:20::336;
Received: by mail-ot1-x336.google.com with SMTP id 31-20020a9d00220000b02901b64b9b50b1so21089312ota.9
        for <kasan-dev@googlegroups.com>; Tue, 23 Mar 2021 15:33:10 -0700 (PDT)
X-Received: by 2002:a9d:5508:: with SMTP id l8mr475105oth.233.1616538789586;
 Tue, 23 Mar 2021 15:33:09 -0700 (PDT)
MIME-Version: 1.0
References: <20210323062303.19541-1-tl445047925@gmail.com> <CACT4Y+atQZKKQqdUrk-JvQNXaZCBHz0S_tSkFuOA+nkTS4eoHg@mail.gmail.com>
In-Reply-To: <CACT4Y+atQZKKQqdUrk-JvQNXaZCBHz0S_tSkFuOA+nkTS4eoHg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Mar 2021 23:32:57 +0100
Message-ID: <CANpmjNMFfQs6bV4wrigfcWMwCvA_oMwBxy9gkaD4g+A1sZJ6-Q@mail.gmail.com>
Subject: Re: [PATCH] kernel: kcov: fix a typo in comment
To: tl455047 <tl445047925@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="ln3YC/bU";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as
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

On Tue, 23 Mar 2021 at 07:45, 'Dmitry Vyukov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
> On Tue, Mar 23, 2021 at 7:24 AM tl455047 <tl445047925@gmail.com> wrote:
> >
> > Fixed a typo in comment.
> >
> > Signed-off-by: tl455047 <tl445047925@gmail.com>
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
>
> +Andrew, linux-mm as KCOV patches are generally merged into mm.
>
> Thanks for the fix

FYI, I believe this code may not be accepted due to this:

"[...] It is imperative that all code contributed to the kernel be legitimately
free software.  For that reason, code from anonymous (or pseudonymous)
contributors will not be accepted."

See Documentation/process/1.Intro.rst

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMFfQs6bV4wrigfcWMwCvA_oMwBxy9gkaD4g%2BA1sZJ6-Q%40mail.gmail.com.
