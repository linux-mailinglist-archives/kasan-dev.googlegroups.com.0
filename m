Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSWETCEQMGQEJSZRN4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id EA3E43F73DF
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 12:58:19 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id h135-20020a379e8d000000b003f64b0f4865sf10878353qke.12
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 03:58:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629889099; cv=pass;
        d=google.com; s=arc-20160816;
        b=KGbMgl5l3/IDxQ5bn3aJjAeLerOjfCq4kQFYWHpWQuyDBpDAZ44prgAE4NP9qrXPCW
         Y7OW9DiYKRQk0UtOCvOz/ramiBTh0ekmsMuD96ftsrAS02fi42YlNCtteh8kzSy3MClS
         E6UGI29kmiVgwuv3BdANXTtNS2HmNwHkkfMY+FP+KkteWwtJYICE1B9XA7zqPg5gfuiC
         ylx0vLxsOa0uFZ4d6/Nf2qv4xh/+LmCIqMiOawCtvkyNCzMw/j3FD2Qc1it02oTQUgj3
         sjcllQReQION59HRCMcnBgPMiV7+335FECmlr6ZQ1MV+eRDKM6v5Vt6+SKJb9wHyGR6L
         0Gkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ErD/0Hi0X9/+dX3QfGnSn6z9jdMOyQDX4a9AP3kTlys=;
        b=GYo6XK3Et0RVufNKKyR58HdeHlXXllgsw5zHMoRmpdIdWJ+uTgSw5rQeTUo7KMKf7A
         rdWgWfSf32sNW5qg8mS1P4Mp28l0Y7bhCKAEPmgXJRQDDwi0cTkxeTbhlZqaPazSOk4P
         fg218liHx5aeQl52Q9PlbZshD8tdklXu+T5mlgxjBpW83G9OCI1R4+as9beRrnzCwIah
         GVpHaoBECuITQ+6OJC5Aj83fCCZWOpq+RW8SZF2XQjZeas8T9wNdcLp2yFl9mA/PV0Em
         K4/i4/EqitrAjSO+oi6RJ+/Xf69s0b3Kd90gjKZa9huV9y3VAkjpldlkcY2PpnNk6nwU
         9tGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K6fcAHHW;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ErD/0Hi0X9/+dX3QfGnSn6z9jdMOyQDX4a9AP3kTlys=;
        b=Xngc1PJ5LjKFfKLj1b0leVLDckRoLOIwMiW9Yx0fFnkn6JjlZBkQ6jJA1vjid2Xmfs
         fsISYyiCDZ2/mnyWWCK4qo2jiHRTVnCtvOEAnZE2dD4zJ+HCwrjW+Q0sk9u0eBTeTLsR
         VgxWkuWhMGRjayAi2rcIn8SB1HQdrK8lzTyuKmDmTwGSMkoVg7cNu4z7FnQ2mtzpIszZ
         lIK9JSYsbKP/hPNzqIfw73ZtMBKM51zoWH01Y3yxdRaZbIX58rnYLeKkw+9u0a3yZNCG
         bkGuRS/lzFDnhJ3ELuj50JkKbYXjr9UaBxEAPGXFTykGt6XPwwDgTeAC4GNvVaGc+dWt
         aSog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ErD/0Hi0X9/+dX3QfGnSn6z9jdMOyQDX4a9AP3kTlys=;
        b=WzOwGKl3GfWzlZt74HTEV8t8fND/NkjZyAV+cJqUUweOko3wz5lAQGJY2YmO1qe00N
         44BGvE17RkQ4WF1I+KUDU++4XPDdaoEf8HetcGa00VrDA2lWh3GoVauod+uLIMYNXncK
         0gky47YiHBRZceq3RwP3o5MdDem8VISn5Oa9O1Ov4o8ZPc4HEeU3t0JfEhbyQ3PGy1UA
         0tMM/sjuFxh1rx1Rgc7Lcgg3sO1YjFtAQ4CRaXo3WeIP0nUtwNnq/LjIwroIFYb1aBoH
         W1DMsq1ncBzNeEdsYxaSA6lPncCbds6O9vUVlKXeNsOXKoB3kkTSX+y89g0nWKWZ+H7J
         WKuQ==
X-Gm-Message-State: AOAM533Wl7G2h3D5spNdxwb/MF6CaZaJ2zuguv15YVPe6sk/LHYn6Bk2
	7uZAiEr8epcphQK7RqIzMw8=
X-Google-Smtp-Source: ABdhPJyAccWi+hasTgNtP06Jk91A9rWDGNYKwprzzcr6JO/jJr6cQKQAqetyj5S1EZRBaw+SB8n7fQ==
X-Received: by 2002:ac8:5ad5:: with SMTP id d21mr39263574qtd.200.1629889099052;
        Wed, 25 Aug 2021 03:58:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:404b:: with SMTP id j11ls895072qtl.2.gmail; Wed, 25 Aug
 2021 03:58:18 -0700 (PDT)
X-Received: by 2002:ac8:5911:: with SMTP id 17mr6939725qty.104.1629889098509;
        Wed, 25 Aug 2021 03:58:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629889098; cv=none;
        d=google.com; s=arc-20160816;
        b=Es/aEO6tXql2ZBPvlyJco7BrhaaLm8/Wv2Ul5ugxDhCQjj42/CH6ki8ueczF/+TNaU
         asfDm6uHV3eIcSue1uMI2ZCime3c5ySQdE6TcJBT8cQWlXQor+ZPs4dYXezIjzK9ODYL
         hMfXu+cuX/RobKN3Y7O3luCkngaxorTi/fsmcvmTvOjOBtKSB+PcVMd0xUFAaWaZRyuK
         k9mHZ4PsVZcC6hauUSBakW6zcHjAFXY2FAfAv5UPQN1/fMrd5M/MeMNOjM2/dmefOMhe
         fp4yzd/2RtqKn/Bx/3ccH3Sv1VKFsBXVNAO9+dz65kNyK7MJxdqGbZv0F+ifF0LHuUs4
         MTsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=814QjR6zkCfIOSzonK+alcyMN9fiwOlsyyZrKehQu1g=;
        b=Gf75FfT+q6UBwn1qlBlWPZ60KrFgmjSW1pkbtU0NSlZ8a9IbcU1n5jkrxTkAo9+fz3
         WKt3BMkAVrcjkr+09w6Rx8zHGxnZGzAwrrHUoDwubsuMYJ5VRsncFFqDecnFTKwpXB+N
         qRMNmUEI2zXIdZkm6Olbe6f7n2V/sPtflOpXLK4sYRnqB0wYjvmF8V5vhdl3sZtIGu1m
         H3WfypglBSlTLnHIUsKDBBhgHepVqsRrDrGAo7ELrCKX2yzy2tUluXJIMJj35cuDKaiB
         bI8ItHBA1QImbJFlseGZvBqfEr6WEyQlI0wK20+WRXmr9mjik0+ay/uSC+612Jp+nCCV
         advw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K6fcAHHW;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id i4si1697016qkg.7.2021.08.25.03.58.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Aug 2021 03:58:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id s32so3153463qtc.12
        for <kasan-dev@googlegroups.com>; Wed, 25 Aug 2021 03:58:18 -0700 (PDT)
X-Received: by 2002:ac8:46cd:: with SMTP id h13mr39096818qto.369.1629889098034;
 Wed, 25 Aug 2021 03:58:18 -0700 (PDT)
MIME-Version: 1.0
References: <20210825105533.1247922-1-elver@google.com>
In-Reply-To: <20210825105533.1247922-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Aug 2021 12:57:41 +0200
Message-ID: <CAG_fn=VMqbOwDkpae02EsE4QoEk_vbW3sM0KzsXWLDceOYGSzA@mail.gmail.com>
Subject: Re: [PATCH] kfence: test: fail fast if disabled at boot
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitriy Vyukov <dvyukov@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Kefeng Wang <wangkefeng.wang@huawei.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=K6fcAHHW;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::832 as
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

On Wed, Aug 25, 2021 at 12:55 PM Marco Elver <elver@google.com> wrote:
>
> Fail kfence_test fast if KFENCE was disabled at boot, instead of each
> test case trying several seconds to allocate from KFENCE and failing.
> KUnit will fail all test cases if kunit_suite::init returns an error.
>
> Even if KFENCE was disabled, we still want the test to fail, so that CI
> systems that parse KUnit output will alert on KFENCE being disabled
> (accidentally or otherwise).
>
> Reported-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Alexander Potapenko <glider@google.com>


> ---
>  mm/kfence/kfence_test.c | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index eb6307c199ea..f1690cf54199 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -800,6 +800,9 @@ static int test_init(struct kunit *test)
>         unsigned long flags;
>         int i;
>
> +       if (!__kfence_pool)
> +               return -EINVAL;
> +
>         spin_lock_irqsave(&observed.lock, flags);
>         for (i =3D 0; i < ARRAY_SIZE(observed.lines); i++)
>                 observed.lines[i][0] =3D '\0';
> --
> 2.33.0.rc2.250.ged5fa647cd-goog
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
kasan-dev/CAG_fn%3DVMqbOwDkpae02EsE4QoEk_vbW3sM0KzsXWLDceOYGSzA%40mail.gmai=
l.com.
