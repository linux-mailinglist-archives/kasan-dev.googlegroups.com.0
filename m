Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNHHT34QKGQE6GW4B5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id E45B4239FCB
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Aug 2020 08:50:29 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id y9sf27046617plr.9
        for <lists+kasan-dev@lfdr.de>; Sun, 02 Aug 2020 23:50:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596437428; cv=pass;
        d=google.com; s=arc-20160816;
        b=pSva+NVpvSweFViXiWxhKrvYMW/nK0ziBBssA0JIoKlNRTtilanyy7+Sve3NoKk4SU
         H4mgossqrD4yGqsjjmOVEOKECI6dZ4ZaH6Y5/mHJye1l/nbNFAp6FWHod9lQjVL6jaf9
         s4rLG3RohalCodMS7ht1elisgL8VfTAvG2sLFT47f6NB17tdFzDQuwZ9oFf/AycLB1XE
         NS8ZfIKh56Ot4uZMd0YXR4iQbQpAWsuv/fhpUVLN1dYJdCFiqNGBLM5/TaTSlJEXzAi3
         ESUQXvj33XaSdZ+kfteOJv6JIlwsNN8fSV+GJUm9pg6qMPbKVPjwVCE72Au2pRmLONRf
         QtUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2YUsVOIR5wwex8k46Nfw5+ot+B94WZg9Vu/V4suC8Rc=;
        b=ackAU2QzUeFpdNySXK+XfYOpjNiwcQbeuKt9eC3R2MkKJmCtlEhy1FFArX8Ul0YtdF
         h6LQDFcsE6gMkfqsyjgqghh2msgD35wecNNHnajqk5mLD53OOg/wXGLbuUxpwRHc8rk9
         WxeGGAJTy5YeP+HVvQBK/veWltJcP6tS8XMkpxF2cM+OduobM/BBABWE4IimLj92uFUj
         Ruyl4xZRErUTqP5Y7p46d0DC+Br3EKLBWlS1RT2TYbtD2AtGjneQlbWDlL8Rjt4uZHmi
         zZZZOBJfjjYNrH8kc9CkfKiLN0kc8RVKT3sNJMFy7aMGRRc+Z/DiI7qzpmrKIrJuTw5K
         PMDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HjvwRpvo;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2YUsVOIR5wwex8k46Nfw5+ot+B94WZg9Vu/V4suC8Rc=;
        b=Pm7vofMz87KNRuE2LxZU5LI5WfPkfu/pDuA1uzeDf7XeXuog3nSgBiT9ck9j43saAT
         KZ5MLRODyQrcV7JYz9I+lQF2CekNjfRgohhISilxm7DjqoH58gA7J792NfSm7wwdtwRP
         VYuMXYJ7vjeUK8Tx7OtE8vZ0k3eNy8Y7AXe4koXW5k2KVh8fa4GyCWBsGlipPw2aQXMJ
         gpdYW5a0a9UJjKbA5TrLrD+x4r+X0ByPN93DkUFefYOeB47ho8Xyx3PW9L2hhKUjLNQG
         GZgbS6ZiqkNPAB5dbNv8dujVpfNHMbGWqvvByCqTGjVm9mC2h1ON80akBK2h5aecJaF/
         iZZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2YUsVOIR5wwex8k46Nfw5+ot+B94WZg9Vu/V4suC8Rc=;
        b=nsi2uBEaB880LS3sUbNYYvo+nIudVDj02mnY9u7XQ9gwgWt2MfzuM4K3s+nr/4Cdfy
         FFfl4sQIZ/ZziUaAwTOhvMeX6nAt0Bz9ifWscG8A+XVPRuh4+FyTZf4I688lb9+F6qcp
         xpZvS0sngFyWro3kDd0s1QKPcllCspfmFqanQie/7cjHT4PRMKZaLkjYo2Y57aAcOgUe
         Bn+nvYRmzyJjM2ahmAz6nk8YY+UtUwRWhZpm+kQpzK4jnTScfIYNVzuREnCtKitiJhOO
         L52EIuPtUhDaa1hw4f+1wyrkmWscY6FXFpluFDKDk3lO+8ioBjw8P2JWKO4WwGYdK4fN
         ClHg==
X-Gm-Message-State: AOAM530gqrDNEXennx81wNtY3sP+SU5d5LXmzps9ZFQop+x31A4/NwyE
	YNF6GvVmdfV58UiLO3ST4Zs=
X-Google-Smtp-Source: ABdhPJwmC+/p306DczIHvV2t0+9TBabmxK6+E/UYlTGwU/7TvNpSY+JMTaB+x/zXaZ+7VgiCndclbQ==
X-Received: by 2002:a17:90a:20e7:: with SMTP id f94mr15586843pjg.121.1596437428654;
        Sun, 02 Aug 2020 23:50:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:a102:: with SMTP id b2ls5258307pff.8.gmail; Sun, 02 Aug
 2020 23:50:28 -0700 (PDT)
X-Received: by 2002:a63:1a16:: with SMTP id a22mr13804076pga.142.1596437428190;
        Sun, 02 Aug 2020 23:50:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596437428; cv=none;
        d=google.com; s=arc-20160816;
        b=glpEUvey1M+Qypa5+MQX12nJfcJxA8/nkjIJkL6cipGzruwryJShZf27R7LXpbmitc
         3dCNcAG7CsTLLhFzpcHqt8d2lr86c8WtuT3EQd4y6tlPd6rL5UPnAXkjZ6Gh++nZ7Mxo
         ESOuZ0C8hLPgSxzkLJWujPhzBst0zDMxaLfg6n+SZ9YUF2RhtXFGExugoQl8viaXXQfm
         L0c71ieAyAQ9Dq9eaoQrfGgv/qHlO+0/2VbCqO1O8yCZBdX0i8oDHl05chypXBsY9lpd
         bYI6Nr3VxsmR7kFrdZj3HoLFWzLgY93kTyYGQBX2mdLCdJOHk5nnSIISaicmjgubSMa+
         Chog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4KSdlAYLfq6oYXP5DVeyrt3CYvkgO3dsvD8hzUOr0Pg=;
        b=JVqWjikVhvoX2b3SWSyTt1+cgK/RS2VdpRboPiuKipEkiNwvAS9B/J6+C8oxQcp54M
         87/k5D5522jJaRsC3xvUKvb+xAcetmFHgUgCBra7Iiaeuk5HPB3Ts9wwwFswfx08Gwtf
         NTagGxvtLiS70Bh7lWYh5MZRnzpPUKtb1vMF+ObEh9T8nIJUOaqVNDwTGrn/ROw3TCZ1
         Z00r+ZHEO5k8SPpyjrSssADDjJIcLD8P8KhiTU6IFWu1ouU2ARn8E/4avYQAjl8OMoF8
         9BWCkFPAnxd23Z0WQbwSRTDYqROVrueDsynxMl0BY8XDg3KJ4NyqOPbhafvuTvXdm209
         FxsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HjvwRpvo;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id ml3si1001359pjb.3.2020.08.02.23.50.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 02 Aug 2020 23:50:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id x24so3053837otp.3
        for <kasan-dev@googlegroups.com>; Sun, 02 Aug 2020 23:50:28 -0700 (PDT)
X-Received: by 2002:a05:6830:1612:: with SMTP id g18mr11624412otr.251.1596437427272;
 Sun, 02 Aug 2020 23:50:27 -0700 (PDT)
MIME-Version: 1.0
References: <20200803064512.85589-1-wenhu.wang@vivo.com>
In-Reply-To: <20200803064512.85589-1-wenhu.wang@vivo.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 3 Aug 2020 08:50:15 +0200
Message-ID: <CANpmjNNH7Szgnbg+7Q_TGCma6z4OXcSELtvgvndx=6zvok=sAA@mail.gmail.com>
Subject: Re: [PATCH] doc: kcsan: add support info of gcc for kcsan
To: Wang Wenhu <wenhu.wang@vivo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HjvwRpvo;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

On Mon, 3 Aug 2020 at 08:45, Wang Wenhu <wenhu.wang@vivo.com> wrote:
>
> KCSAN is also supported in GCC version 7.3.0 or later.
> For Clang, the supported versions are 7.0.0 and later.
>
> Signed-off-by: Wang Wenhu <wenhu.wang@vivo.com>
> ---

Nack.

Did you mean K-A-SAN?

In which case this is the wrong file (kasan.rst also has the right
information FWIW).

>  Documentation/dev-tools/kcsan.rst | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> index b38379f06194..05a4578839cf 100644
> --- a/Documentation/dev-tools/kcsan.rst
> +++ b/Documentation/dev-tools/kcsan.rst
> @@ -8,7 +8,8 @@ approach to detect races. KCSAN's primary purpose is to detect `data races`_.
>  Usage
>  -----
>
> -KCSAN requires Clang version 11 or later.
> +KCSAN is supported in both GCC and Clang. With GCC it requires version 7.3.0
> +or later. With Clang it requires version 7.0.0 or later.
>
>  To enable KCSAN configure the kernel with::
>
> --
> 2.17.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNH7Szgnbg%2B7Q_TGCma6z4OXcSELtvgvndx%3D6zvok%3DsAA%40mail.gmail.com.
