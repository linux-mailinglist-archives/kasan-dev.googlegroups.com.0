Return-Path: <kasan-dev+bncBCV65OUPVYMBBLURZP7AKGQEN4UCH4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id B61522D6D28
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Dec 2020 02:17:39 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id d30sf5167316qvf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Dec 2020 17:17:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607649458; cv=pass;
        d=google.com; s=arc-20160816;
        b=EDbrmRQ2+PeqRexmmVVjAq0VvqdmhPQpan+37YZi9GDmWppKxItkPh0RHV/oGR4Z7L
         cLGYfdrk9yK9gwM0U8WV3BkUB5Vy0iSk3M/liKrPfOkMOcbmG4tfOk5Yggb4WuziYipX
         DYRze9YyCcV40dbqJ0sCGSs58jz4s4YyLPTicyCJscKtdCN/qq/0zeZXG+s0yYpZ+KDM
         G6olAOnxpyzKvsxQR0nIwIJiqk6f1SMxplypxw2sXjRxqtFuhOqwXIOeoJjKkIzuKpvl
         bhwmaVF4s3P2SQP4efmJFZ7QKSnUp79ly/x4XcFSNBJN3c1UGy76EP54voNIma69FIy3
         9gEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=koDdrgV+SjK+RO1bjGxY69c+meHJ7BvPjwDC2ojUZ2o=;
        b=gexxt6UY/u1BcmOWUdPHyDgdV7N/AFi3PpTCTJXlSxdG8HaTnWxrL7NuQBergohnWK
         wuSd3PhtT84u/0x7HX31DojtkGn5JIxhae00X37IA1nVfQRsG/0rRG5YBbNM2B9rlj73
         9EckTMfrsjQouUaxbs2c+hSRPKaC1ORZKPc5z9GclaYZ+N5DTr7Mx91WDONo4BRGn3VQ
         lIuqH5zFfcKEilTAnk27y/ahXQNxlt2pV9d1vVut1Bx1vc5gSTnDBDro2F4qqe2cCPgw
         OpErh3YJZZk93+7OtyxestLTZ135C7+5IJ7R5tbEB3Xq9t4BpE9QY35HXFFdeEF3Xk1Y
         /mUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=JukTSVza;
       spf=pass (google.com: domain of js1304@gmail.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=js1304@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=koDdrgV+SjK+RO1bjGxY69c+meHJ7BvPjwDC2ojUZ2o=;
        b=hj5wIUNtF7L6flIUSYWy+CJoR9BVRtZt9zOxo3F03PU4SlK+t2Z/kDAhph2b8zEPQL
         zpQf7zba2IoJqBaViaMYEARXdI2Xax/sq3Xkh9Ih2BLu0ciBGdKOi0UVuKVM/fnIxX9I
         0r7fmWvt2xVtIiMLSEv281D2GuspgKb2fhCl9vFGHlIeYeuS+Gj0hcfLzZeCQIqj/PVk
         eu9H300yZ7FFt0FO8gd4p15CWJLtw5dTjD1nPH17TH4Oqgx41itIE9Hc7l/sOoyFvSMf
         DhXyv7sbFtJJkWbslCTMeZjW91yYMUCWz5Yrx64VAE0U7Yjn51dBaL0gfdqWNZCWw+kg
         CdWg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=koDdrgV+SjK+RO1bjGxY69c+meHJ7BvPjwDC2ojUZ2o=;
        b=s3vD4FZ6+2WT5SrNiPEvnbAwJUxvyWnj+zRi+ITh0xj6qT1prOIZLvtyjRVMgWCDvW
         sUPNk9nssz7QYl2MH3rsyM+b72kHm6wXlaY5DQ1rUatLy27Bp5UyFeRfS4g3AMGDj8kD
         SL3f9KE9MXiB/5qZDKe0VTAjnG2ctjPMzm16c7T3/DCd4AiNxx6MbYiILXSeWYmJLYxT
         ZzAtx0zSRJw6R55XOYzP1jglAvWfcbdZlcXvxcBHSqBWNRYOxAaBnb4BE7nhwjP7ArN3
         MMBPXGRHo46Iiee4S6VM8YgRpb0Zf2BnQcP6GOKmj1NlG2Q5llTCd+S2TyoQlR18m0x3
         06uA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=koDdrgV+SjK+RO1bjGxY69c+meHJ7BvPjwDC2ojUZ2o=;
        b=OQUYPuxAkDuh5CVW5vZ0kiArhy3ZhBnsyFN1q1PimqKNKFizXUsRLPD4tVdVsSddv7
         a4di7+q9jjZCCS43sH+k9YcjXwAg/XRbkwahos4XBDxbGv2FFKo3DjRnVgAuG3hjZF5p
         NSSS8w3jF+Rhu1F8PHt1V+EOZLWUtIJ5yUCqaQand0Y9CyAuVAKboNKreQkh5REtiMi4
         9bRKr7UZEgsij2Ymeu5oBLPReWSR0QasMVy8nT/NYxhx3XFdlZ6YEIRSYNnBb9mbdMbP
         JEW9nhrNO6QFF+nQTAR/CHidwwD4sU9F3SZHa0CIzbcAM9zIzvHrTw5nDh7pLD8Urixf
         yE4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xgnZZkb6QWp4IP6IwtA1B8FaVqnhfbyacPFkNwPXb04lAwp6/
	M872ypxXZV9Wo9DkN3rnJNs=
X-Google-Smtp-Source: ABdhPJxFUmntLli3fhYnMP/BWrePv3UqrO7zurfxTkRbcg0kgbs+RRhP7o8UnM/SiEAqyBuueesaPg==
X-Received: by 2002:a05:6214:1764:: with SMTP id et4mr9115670qvb.2.1607649454874;
        Thu, 10 Dec 2020 17:17:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:242:: with SMTP id q2ls3380375qkn.9.gmail; Thu, 10
 Dec 2020 17:17:34 -0800 (PST)
X-Received: by 2002:a05:620a:2051:: with SMTP id d17mr7961338qka.403.1607649454281;
        Thu, 10 Dec 2020 17:17:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607649454; cv=none;
        d=google.com; s=arc-20160816;
        b=bstz7yDE6BrOIAQbvUaZ3iCFgW5fNUeTalohA9TJvxSuYRYaeW+Yncc9Xvkh3ODPJN
         0xcHv+d4f85LzlwCCAMN5Fs9xd52CnQnu4gSPp8h6g63jYSgIzjEZBfm0F6odLtB4wML
         v5vXu92kHHaAruNvhgu6bH4TyyHooDVedKfSdDWVPj40ppqHWBSHQddKVAsiiBNSpoML
         8ngRLcfpEyMQQQo0WOVlhpAERfMsyEHNVbanngIHwOyviddZ9SjUZ/uvgW4oxcLM0NdQ
         w/3SsqBhzA1ZstDDU457GfLXMagkKMjRKcRWNsZhkl5uf067VrH5TBHuLamLwIJd01Z6
         gPxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=JHA1SclwwNflc1fMREqK5MdJqK9jjD1N+6vraV7m6o8=;
        b=g6MrTKCWVrIUW0PBfJETjS+gOc1vLH1goOb+wj+zW6Ke6R/g4EbVAS+9RWazgx8Jmw
         BYM/bZleqU37IsZMuRvL5+xNcqzJju6JF73gszYbvPb7EcQXQfoHpusiyuvDlvRWsvNW
         XuYsYJxe+T35pWfIfe+tI8Sn5Qj7eyDCfhmUpSBmT/QeeLy2ncQu5K2qAlX5WcLQ5klu
         ZgpuIvW9ZLcsWDB3zjBszxtNGhpU3FehzAQEZ3Or3JGajX1htqdUdd+gTfX0lLRCLF5p
         Djrb+kVJQHslXNkm9isPAqheXr9fBN7S5TvPW137ME8hWMFbfz2yeNGQ5ql4rhvGa/JP
         FCAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=JukTSVza;
       spf=pass (google.com: domain of js1304@gmail.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=js1304@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id t2si20884qkg.0.2020.12.10.17.17.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Dec 2020 17:17:34 -0800 (PST)
Received-SPF: pass (google.com: domain of js1304@gmail.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id b64so3017045qkc.12
        for <kasan-dev@googlegroups.com>; Thu, 10 Dec 2020 17:17:34 -0800 (PST)
X-Received: by 2002:ae9:c013:: with SMTP id u19mr11921227qkk.59.1607649454106;
 Thu, 10 Dec 2020 17:17:34 -0800 (PST)
MIME-Version: 1.0
References: <20201210183729.1261524-1-alex.popov@linux.com>
In-Reply-To: <20201210183729.1261524-1-alex.popov@linux.com>
From: Joonsoo Kim <js1304@gmail.com>
Date: Fri, 11 Dec 2020 10:17:23 +0900
Message-ID: <CAAmzW4PbivLRBMDR1HykzpFS_ekF4Z-pkAm3n_a5En-TArZuPQ@mail.gmail.com>
Subject: Re: [PATCH] mm/slab: Perform init_on_free earlier
To: Alexander Popov <alex.popov@linux.com>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	notify@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: js1304@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=JukTSVza;       spf=pass
 (google.com: domain of js1304@gmail.com designates 2607:f8b0:4864:20::741 as
 permitted sender) smtp.mailfrom=js1304@gmail.com;       dmarc=pass (p=NONE
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

2020=EB=85=84 12=EC=9B=94 11=EC=9D=BC (=EA=B8=88) =EC=98=A4=EC=A0=84 3:37, =
Alexander Popov <alex.popov@linux.com>=EB=8B=98=EC=9D=B4 =EC=9E=91=EC=84=B1=
:
>
> Currently in CONFIG_SLAB init_on_free happens too late, and heap
> objects go to the heap quarantine not being erased.
>
> Lets move init_on_free clearing before calling kasan_slab_free().
> In that case heap quarantine will store erased objects, similarly
> to CONFIG_SLUB=3Dy behavior.
>
> Signed-off-by: Alexander Popov <alex.popov@linux.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>

Acked-by: Joonsoo Kim <iamjoonsoo.kim@lge.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAmzW4PbivLRBMDR1HykzpFS_ekF4Z-pkAm3n_a5En-TArZuPQ%40mail.gmail.=
com.
