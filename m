Return-Path: <kasan-dev+bncBDRZHGH43YJRBTEV4KBAMGQESLMCG3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E11F3440A4
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 13:17:17 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id x20sf27814492qvd.21
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 05:17:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616415436; cv=pass;
        d=google.com; s=arc-20160816;
        b=K7PJYxm7p1G6mKCjUtAL3RHG+ccF9hIH2WyMdfmPyQaTpVta6nRoffn6inNBAPszuq
         nf45VySKKy0xvO1aYZ4GbtAimjfiw/4EREBhRYthtFV+MG9lobmEf/v/iDS7n+83WrUU
         5ZFhAy/0Vb/T3CWMDb2hoyXP4d3CWZuiyn2/5Wihkt8zzJJJ6dXnr6V7ZSQfIF2nPhSa
         nTQiaIbixVulcnxwYPUFjLy07JLlKFWEqCGCkvH6FWHFAUqDYTNXn2ndXO1dUFCRCILA
         A5kadHV/Jy9YrG0dVgSOPCxNZeHYNJ8eCGxGcapaV7jru5XIsFF1f5r3NI6XAN6kIdck
         upoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Uq2CuoNQvhTSWTSbSQC8pFvYWJ3mshGIZQoPYYF67/8=;
        b=gbXMflwsJBX57tWX8YE8ZLWk3exDGRL9Z1lMVUAz3Cc1sN+A44n5AHKCa0zyjlFKo4
         DGm4MoELDNI+pGRVoFL8K61+Jw0aYg8ffTlVa9suVBTolid1buvDSXUI7WhmZeIUIZAO
         7jLaS/oLSCmGsQxLGtvlAPpNt9P5szh7viqxnSvPrzsDttMSctzP97Rwsdu10Higwn0I
         owQS00AGCr0upKAPwZmvGJurZ7X7876FCTuxXfidVC24IhWo7M8wpyk4i9OZYh22MAL+
         jhc31oMe7vJZKqNYASTdGtWM1oJpVkF4pT/mAimD27vYUTeeIxzufCdx8PiYyKBWN/7Q
         Wq2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="s/Ibu1OQ";
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Uq2CuoNQvhTSWTSbSQC8pFvYWJ3mshGIZQoPYYF67/8=;
        b=EC71SswrAdOxY23hf5ompGv3YAJpBjvtpABCweOu1VWBdA0Am3Gvc0HUl/eOYc5ypO
         XGs+SXPaBNV8u2f8V0E811WfExT36u4PbfCQK0tgx/8RU90AesG2FzncHQCeX9hROn11
         SJr5XPMAYRLPxRqzbf3+7ImgwSOPniXQ0ln9RLD5PxQzh6WGTBAnQfoA9NCtqNGs0BrB
         JmkZfU1Dc+XUmyL0v3XB1yozT/k1DZzILhUWFnzJx+W3wZXkX+eciHLlcybWCLrsjX+4
         4xVB/ZOBmzz1yI7XPLRJCuy8VryhAjYw9A5ytYxyKngybuFE935SK3CiQz2pUwc4WhmG
         pZiw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Uq2CuoNQvhTSWTSbSQC8pFvYWJ3mshGIZQoPYYF67/8=;
        b=mQT36SOWr8DcKuVNDddSEXp5q0yczYIvmn3bx1t/XI2FW/QFjjWXObJ3WP9w6D4FUJ
         FC9RScbZx8Jb2RY4sz+qa3s2fJmWrVCtvF0OmmFDSo+4tNcg/CZvdsi78O0tm62lmy+U
         Hlx4bfZdjqrc2aOnL5tWwvzh370I6LXFyDS1VXbzB4t7wXqjC0wyarjH6tSNm+C7SZW8
         9uMnEnCTFii7eL60rB1E9DG6rhsnSakeEBpM0iBCwqQTUJUeySACZDmTetsbnPigMiUQ
         6f+AhJz8HSREf+sM/PWzLJKOgFjrRan3IFFebKPxGblcMKm1QQqfcQnIDQYWLXI+friU
         f6dQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Uq2CuoNQvhTSWTSbSQC8pFvYWJ3mshGIZQoPYYF67/8=;
        b=K26B2a0B7fB686R4E7rua14Ietuk/lymR0Yf9jnd1emUETExJYq3dlxF88H/GmNeAQ
         1ge8gvUf64v8IQWSFYxqWrg1oJoitqLqaiT7932cTNLhvTBBvgkIVX9DGpUEKKF+dDoS
         YhPslPNSJRDgzuIr+5Mw2vk7e9TH7hN9xXMIA23Xzb3O+mczGOx3mDxr8raJ7l2SqcnT
         y7GzpHbJuNVnNyn1MU04arSKjjpgvtQVwGVZrIHhCRjNaYFjj/OvnInsrvrSJsiTQKyo
         R0kGNExBnDJFFnoQQsffkTpsQ6HyV33MJl7wgznElRikt1buTmkGi5WuT0AkmiFIzQfk
         YDFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533nB00mi663VOmmBfaYxt5yV6otX7ZG8P080A3pHc3haTrci9D6
	RbXJYp0JH25L+xu2uXWTc4w=
X-Google-Smtp-Source: ABdhPJwaU544ujKwdLQNtF3nPq5/gCWZ9fSjGTggQG7jwg0QDLqsmbt036FUcelApOZp4yEwEP9rWQ==
X-Received: by 2002:a0c:9b88:: with SMTP id o8mr20966353qve.28.1616415436294;
        Mon, 22 Mar 2021 05:17:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:12c4:: with SMTP id e4ls6692261qkl.4.gmail; Mon, 22
 Mar 2021 05:17:15 -0700 (PDT)
X-Received: by 2002:a05:620a:749:: with SMTP id i9mr10927393qki.40.1616415435898;
        Mon, 22 Mar 2021 05:17:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616415435; cv=none;
        d=google.com; s=arc-20160816;
        b=dX7Yl1QCIikcbnnrAou17dgzO44oyMmPwtXe+ZPzbaz587jfLeNNiE1xcwZmcyFnvL
         dxrynXR4rjtXGXgKEZM0Ygw3HIkS/ZnWp7cLsSRbvEdEKtpleOnl/I37WB/6SeWe5xx1
         uMzbxoesp99VHDIP0+LK3aI+Qo6N9nrgtkUkF8D1+CTU8xcgdRnXw7NBGR0Ua2x72PRI
         2DNWdniNjzC5d6xBpPh2nxg8REn/AI0K5rdv4bDnCcR91W29V+wlk/7bcYXqFcL+GwNX
         t2Vmb6PLucCiX68kyyWTxN/cLFqoGD3fYHiDgXtkO6srPJX+QLPAuVTpmbB3M9KBz1L4
         jaLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=djp6rAThn/JMZBuvzCFDPT3cc+3P/h3ppC7XfOEilpc=;
        b=Ktja9ZXHBf9UG0ZwDtQ30tldyPSCTQ2tg+ocUr+T/xkdXzTSIIQhuc7vqsEam2EBOj
         gfUj3KWL+uheTOoWDU8+rTh+CjZ3Lc6kmnvNyCpdKCmZkfKB6Si8Qr+pDLRLZ+xzcYoA
         lAM2dBWTeTamzCfoiaEAQgN8PCO427c9QCsNWG7+RJurusZge4OvdNXEr02Ea1Yql4kb
         mk/JoiSrcNPxwQdda6tU3faaDvHhhuY0REn+I6pg7xFyTrszpcea5/c3EPIjEsIQ8gkp
         XfV3N7lTgyUQLTmNS57FLFAe7U11N4IlhB86Rnci9RVo/w9I25szBFigCsjmtVMyKg24
         TSlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="s/Ibu1OQ";
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb2e.google.com (mail-yb1-xb2e.google.com. [2607:f8b0:4864:20::b2e])
        by gmr-mx.google.com with ESMTPS id o12si276527qkp.3.2021.03.22.05.17.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Mar 2021 05:17:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b2e as permitted sender) client-ip=2607:f8b0:4864:20::b2e;
Received: by mail-yb1-xb2e.google.com with SMTP id x82so6312462ybg.5
        for <kasan-dev@googlegroups.com>; Mon, 22 Mar 2021 05:17:15 -0700 (PDT)
X-Received: by 2002:a25:d94b:: with SMTP id q72mr22707676ybg.135.1616415435700;
 Mon, 22 Mar 2021 05:17:15 -0700 (PDT)
MIME-Version: 1.0
References: <CACT4Y+bdXrFoL1Z_h5s+5YzPZiazkyr2koNvfw9xNYEM69TSvg@mail.gmail.com>
 <20210321184403.8833-1-info@alexander-lochmann.de>
In-Reply-To: <20210321184403.8833-1-info@alexander-lochmann.de>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Mon, 22 Mar 2021 13:17:04 +0100
Message-ID: <CANiq72n+hqW5i4Cj8jS9oHYTcjQkoAZkw6OwhZ0vhkS=mayz_g@mail.gmail.com>
Subject: Re: [PATCH] Introduced new tracing mode KCOV_MODE_UNIQUE.
To: Alexander Lochmann <info@alexander-lochmann.de>
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Miguel Ojeda <ojeda@kernel.org>, Randy Dunlap <rdunlap@infradead.org>, 
	Andrew Klychkov <andrew.a.klychkov@gmail.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Aleksandr Nogikh <nogikh@google.com>, Jakub Kicinski <kuba@kernel.org>, 
	Wei Yongjun <weiyongjun1@huawei.com>, Maciej Grochowski <maciej.grochowski@pm.me>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Doc Mailing List <linux-doc@vger.kernel.org>, linux-kernel <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="s/Ibu1OQ";       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi Alexander,

On Sun, Mar 21, 2021 at 8:14 PM Alexander Lochmann
<info@alexander-lochmann.de> wrote:
>
> diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
> index d2c4c27e1702..e105ffe6b6e3 100644
> --- a/Documentation/dev-tools/kcov.rst
> +++ b/Documentation/dev-tools/kcov.rst
> @@ -127,6 +127,86 @@ That is, a parent process opens /sys/kernel/debug/kcov, enables trace mode,
>  mmaps coverage buffer and then forks child processes in a loop. Child processes
>  only need to enable coverage (disable happens automatically on thread end).
>
> +If someone is interested in a set of executed PCs, and does not care about
> +execution order, he or she can advise KCOV to do so:

Please mention explicitly that KCOV_INIT_UNIQUE should be used for
that, i.e. readers of the example shouldn't need to read every line to
figure it out.

> +    #define KCOV_INIT_TRACE                    _IOR('c', 1, unsigned long)

Trace is not used in the example.

> +       /* KCOV was initialized, but recording of unique PCs hasn't been chosen yet. */
> +       KCOV_MODE_INIT_UNQIUE = 2,

Typo? It isn't used?

PS: not sure why I was Cc'd, but I hope that helps.

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72n%2BhqW5i4Cj8jS9oHYTcjQkoAZkw6OwhZ0vhkS%3Dmayz_g%40mail.gmail.com.
