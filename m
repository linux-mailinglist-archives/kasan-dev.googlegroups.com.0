Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY4BROEAMGQECPXFU6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F9873DA6E4
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 16:53:24 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id a2-20020a0562141302b02903303839b843sf4040974qvv.13
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jul 2021 07:53:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627570403; cv=pass;
        d=google.com; s=arc-20160816;
        b=XId5shXF3b7Rr+flAc3Yt7KkgaCg1xbEm+QfoLl39+ewmHp3BR1HGdcNRPckqdsji+
         tlGTKTHGqY+7tzHbqQJBD6IH3RO/y6O9Cy9mwu3zGowHTAee4G+X38d8TfNxriiLdUAN
         ZFQJTnkGXcwbcdekRWxnKIuSQMyDFRQmoKfH8Sv519Gk6xlcfbyHhY2iqCdQ3lOiQ9HQ
         sn47yE+mjXPhJ5mPc1RgLstMqytZsGyQjkUipQKueQ/TLhqBO7/VSE+bZ85rEjCo0J/D
         G7zbRzbI5VulZC/2PQKvxjg6kjEKs7QY6chNJleFhIgv+FzjD+R7BnNjEG6NhUp8OQEY
         L0DA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TK3BnW6lpL3y8EGF4MAElSkokizglXV9TahwwqsB0RI=;
        b=XjzOaNuDJjOrzErSCE3Ht8Kn31z9Dg/nkxvlAFoe48d5MfjIf+2c7RnsUMGFixurT0
         eYYvVKQXYjKEoNrhMiB6a03Gekm6cAofY5BY5zQBm71tbDGHKG0cBZ+yRigOhk218Mhr
         2HQhAUDIR7bMbgBjle/6U7siIQEkjHqLBYGjOkjUb20giGQwN7qhXMDqIt3Oh3z9NpRt
         D0KtjYUFe97Y4Viz1QyUunfIUZjZnMCtPj1H5f/x5mr5Bw7wQuD12UQu7rdhljnDO8ad
         pUCZP4CIZTbut5JCQzWk/8dCcuiiER2mGDaWdY2L83R5IOGEamEk5zYFhkqpquuMGzec
         STJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ze6QRgWW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=TK3BnW6lpL3y8EGF4MAElSkokizglXV9TahwwqsB0RI=;
        b=YvHofnprVKY2MZg1/qm7JOQpwEKZN5imWaXiZhToJ7t1E+1Kv+BFxQmFbfDwstrDyb
         24gzK3mrXraCxApoAcsvR/2MfDoByIok8luhSaKSbG7Je44OKT6IflB+av49xkS7mzY8
         sjEanEejUaR+0G64TK7QoRcygH26FrrtMgHdrnkeWS1IivOGdZfOOwoLGzkg3uRT5fHM
         UWOwP0P96VsYrxP9r7OcwRWUk85MYGXMJE/jiUO1uuVF7FfjoRE1IDfJ+rbuARJbUTMb
         y8cN3jGTtPjt86u0tQTgdmyznQGeef0BlnobBUZeiRIFKC2KjHOFnDuriFFkwglSfbJu
         FJuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TK3BnW6lpL3y8EGF4MAElSkokizglXV9TahwwqsB0RI=;
        b=nXS8bLxmhZ4xhsWlrvbF8V+b3ixVXL5v4KRnlsT7gFw0eVgWMWgzDhZmuNZRF0+p8K
         1VBV4IcEjTb3osjU1a8v9KP60evsQXmN3Yhpb0k4OOW06oexGojb2fuyPUTke/I9W40U
         PXEOjQS2czw6R8kx5oVHdaFYQEkqqGTpnpkv28yqUXtKvQElPhQsN0n04w+SDkGvM6L2
         wAEkmaqcOIe6qo3H9lPg109g0BP3fedl+swbaxpEvMgt/BnK7fTpBykRJZo5d47kFUYm
         CE9ESpx96Wu2B0Y6Sy5aGckma3c+pezZ0aDODWRlefI/M3nUjSq5e4ImuIIp7nmTs0RC
         pGiQ==
X-Gm-Message-State: AOAM532+OIaYFQoglJQPixPNCQ3/C3k0mvj40vvUXbrNFaw4bm3slY5t
	wSVl1w54TIbc52LW6pDZoyU=
X-Google-Smtp-Source: ABdhPJwA6xUBpOsDs8hqrTaqxjB5qJCJUhwy+N2kAFC71MlBkKoTe98U4P6GJndhYcF5eMpgArgKqg==
X-Received: by 2002:a37:a147:: with SMTP id k68mr5805054qke.196.1627570403412;
        Thu, 29 Jul 2021 07:53:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:61cb:: with SMTP id v194ls3462805qkb.4.gmail; Thu, 29
 Jul 2021 07:53:22 -0700 (PDT)
X-Received: by 2002:a37:b145:: with SMTP id a66mr5767554qkf.329.1627570402913;
        Thu, 29 Jul 2021 07:53:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627570402; cv=none;
        d=google.com; s=arc-20160816;
        b=Zmu2NL+GSXZqvhWh92J0iOdYkBz/EfbYmKdCgdoX/iadyp8LVhvyQzAabnSC3t59uJ
         cp4TDeL4YuaXVgL6HRWLJ3MFX8Pdi7cZlOjrioLsJqZiAkzKtbADVHbx9YGtweCR1kEQ
         9jipsm8pfymbLzlMlBarancQXfZnyqrXFXeklqMRWJkIuVSwopoJZKRArUsImv1uhAi5
         2bf+cAZUmqQ4KFrLereHl0be3Qz1gg5UBsTKj4bIIaNipgKh7B9N+1yDQAkCUAotKVIR
         5qJPxmqWPm0uGfvpxA6fF/DEagEWA8DxnnByQl3eQyxkaNSAjTVVNVTKCQ6udJDzuduZ
         4E4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rz/FWXWJIdJs5D3kcgNlgtx454VDwz/C1hhNbH4bMzk=;
        b=Z4kmebyrsrHtFay8KK0HA7aSAd9ztYcHqU3YJTfccrFXTYGIa5OAJxmjZHT+eoJK86
         nfhjQXXoOF2dY35qZESt3QCMIKnaC7x6aspcd8/PH4tRIlFdySPOQogR2PuPgxWdbseD
         v0E3wHomY8GjvggIxhrq2W+iNFy2xCJFMIsS48697BMaBk19uECfB8UOiDCwOOpdv0L0
         LCLLv2N20eldGu/vzcO79oQ5ARmtQPwgAgGYsJl9Z/Rs/DAGmkLoFFu/CyiRQ0kqEDFa
         NQR4vQW/G5leiPxizMuOVDevFhvKHfDfSIyzKuDHWkWwu+YNaDfU/ETQKLfXS3FMrVnG
         QbsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ze6QRgWW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22a.google.com (mail-oi1-x22a.google.com. [2607:f8b0:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id f10si216271qkm.7.2021.07.29.07.53.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Jul 2021 07:53:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) client-ip=2607:f8b0:4864:20::22a;
Received: by mail-oi1-x22a.google.com with SMTP id u10so8767840oiw.4
        for <kasan-dev@googlegroups.com>; Thu, 29 Jul 2021 07:53:22 -0700 (PDT)
X-Received: by 2002:aca:c402:: with SMTP id u2mr3281466oif.121.1627570402255;
 Thu, 29 Jul 2021 07:53:22 -0700 (PDT)
MIME-Version: 1.0
References: <20210729142811.1309391-1-hca@linux.ibm.com>
In-Reply-To: <20210729142811.1309391-1-hca@linux.ibm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 29 Jul 2021 16:53:10 +0200
Message-ID: <CANpmjNM=rSFwmJCEq6gxHZBdYKVZas4rbnd2gk8GCAEjiJ_5UQ@mail.gmail.com>
Subject: Re: [PATCH] kcsan: use u64 instead of cycles_t
To: Heiko Carstens <hca@linux.ibm.com>, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Ilya Leoshkevich <iii@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ze6QRgWW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as
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

+Cc: Paul

On Thu, 29 Jul 2021 at 16:28, Heiko Carstens <hca@linux.ibm.com> wrote:
>
> cycles_t has a different type across architectures: unsigned int,
> unsinged long, or unsigned long long. Depending on architecture this
> will generate this warning:
>
> kernel/kcsan/debugfs.c: In function =E2=80=98microbenchmark=E2=80=99:
> ./include/linux/kern_levels.h:5:25: warning: format =E2=80=98%llu=E2=80=
=99 expects argument of type =E2=80=98long long unsigned int=E2=80=99, but =
argument 3 has type =E2=80=98cycles_t=E2=80=99 {aka =E2=80=98long unsigned =
int=E2=80=99} [-Wformat=3D]
>
> To avoid this simple change the type of cycle to u64 in
> microbenchmark(), since u64 is of type unsigned long long for all
> architectures.
>
> Signed-off-by: Heiko Carstens <hca@linux.ibm.com>

Acked-by: Marco Elver <elver@google.com>

Do you have a series adding KCSAN support for s390, i.e. would you
like to keep it together with those changes?

Otherwise this would go the usual route through Paul's -rcu tree.

Thanks,
-- Marco

> ---
>  kernel/kcsan/debugfs.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> index e65de172ccf7..1d1d1b0e4248 100644
> --- a/kernel/kcsan/debugfs.c
> +++ b/kernel/kcsan/debugfs.c
> @@ -64,7 +64,7 @@ static noinline void microbenchmark(unsigned long iters=
)
>  {
>         const struct kcsan_ctx ctx_save =3D current->kcsan_ctx;
>         const bool was_enabled =3D READ_ONCE(kcsan_enabled);
> -       cycles_t cycles;
> +       u64 cycles;
>
>         /* We may have been called from an atomic region; reset context. =
*/
>         memset(&current->kcsan_ctx, 0, sizeof(current->kcsan_ctx));
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/20210729142811.1309391-1-hca%40linux.ibm.com.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNM%3DrSFwmJCEq6gxHZBdYKVZas4rbnd2gk8GCAEjiJ_5UQ%40mail.gmai=
l.com.
