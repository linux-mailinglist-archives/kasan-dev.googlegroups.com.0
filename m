Return-Path: <kasan-dev+bncBDW2JDUY5AORBNPRR2UAMGQEZ2EY3DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 23BB07A134E
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 03:51:51 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-5712ca11ee6sf2102827eaf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Sep 2023 18:51:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694742710; cv=pass;
        d=google.com; s=arc-20160816;
        b=ReDe0hrfeIV4YBDT8+Cb6ytbC7GFoSAu4VN1wYIGAfCFHDrUwuFaMuS/YI1yDIKhiw
         A6cr+i0dcO60pbzow+BDyuKq/04Rgu92zgsM7dH8t3Aux7O6Sx4bwyxg8v4ITeQ+7ZFR
         NOB8PzCNt8yKd/GBrzZrKk9V8PyDdOUT1L33sllN0nYLQS1v42wL0aF4CgGaVexl8eLF
         cU8l8Rk6Paaej5OOGV0bLpjfqX3RzGEHSxiASY4rXExAVeniPfqhriQ0rtEf1YIwgk4m
         0i46F6KCg5vYGIhbSxuS4HrJMvyT8aYBXMqOYlMfeSkJiTNe6VDhY57jQPWiF0W6Osui
         Ei8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=X7MbttbbM12DnatH3/y6YSh/9SfP1E0PJYGobLowj7w=;
        fh=+gxP9MmviEtshzpAVR0BRblIKw8YPx9MamjkLCPhuJA=;
        b=dEhgkSecTV4dd7lnf6vUQB9JVsQU6DEoJfzCP6Zz1dIhiwT3lp39rxLWh2uMXoJbpS
         xbRDJdmbL1WRzYQ72pUBlsC70ITixCPPruQUpG3NqODy/BHFm9h79kRvuNuTSrzI5oFR
         ne3zAmiJbbr8HTqMl3hyabpPz+aJfldIpAwRImp0xINMBm6nDCc6pLZ140zuhrnWhcHS
         vOIRvC4Ux1i3aUS72Dp4SbDw4QtFi0GhL64I5rVq/pLMSVwUtrEAwCzuxO0X3NI4jGgW
         FE9TFEyq04eYWDE00PfRAbW+0/z/jCD3NVPbW/FCi1Nuo8RxzCIFiOwE2RvTfBOzebk4
         ihow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kaFPpMdx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694742710; x=1695347510; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=X7MbttbbM12DnatH3/y6YSh/9SfP1E0PJYGobLowj7w=;
        b=fWYZRDjwz4GehpumgPJX1WPRdbpRRL6dPoiSWtbeZibcewl3rEIpblI/z0/8zFks63
         1ro4hlr/xMWmz1dQ2Yv2MuDb4hjdvUxPebArE1bYMHJ4wPEDir+9tUcyXluhO494EksY
         PKQfCGfuLL8g+IWRrVlbAgF7eTj+by1P1Hdsi5co0FS5wdwqXrKw0NplKclmdP/RlAzL
         DFnyevV/7MJJwfA6YWGBaWxczqGT1BivlzBSqtrPT/Z2jCIpARwHdRf7+4idk+zlX/E1
         X8oc7vXNtTmv2z0TMkl/i6tSPR3S/5o8RMQ+wdltDvtHrz0GIi4/Ms52daUiOZdh7/lL
         W7qg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1694742710; x=1695347510; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=X7MbttbbM12DnatH3/y6YSh/9SfP1E0PJYGobLowj7w=;
        b=Y9Ew7jaXBAbLZ3nR/YzfvHGDHRG6Yl2AZStMY3IWHsOaHIGPOEreWOxbOKBFW3FaOd
         exnZnVNAx7AAgteOMzUwLSDbVbQaWROzxaiBLjT6dA3bNasAlEB0esHpCn+sKb4zrDpg
         XpkfG4UUELB+4MGj8T7GK9ZubuTqzSIFhJhZQ/WVyK6WrIK/brKVssGUTOGV5EmNTmEg
         0vqvQSSOcT6/DlsGMipu6mLQUhP81fvSHDEXzlQKF2RCVTOk8NLjh8qxOBeI+PvA7x8m
         W4Q2+3VkH+zwMTqV9mF1loPDBYNK6WghOLa9XIVC3D4zWy3NKx5vDoNn90wo5RVQn9Xq
         lqrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694742710; x=1695347510;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=X7MbttbbM12DnatH3/y6YSh/9SfP1E0PJYGobLowj7w=;
        b=UY2PlS3svrUUgS5OZVjD3hGB8BAg4Zc1owLA0cT9FEMJRLEzD4h5iRy3hUONYLYXx2
         47cbTDW5hacm5QauTUYFMPocZ/ENBkTlsn6C6a70eW5joaEpTPZFQdBm5o13xxXhLTme
         WmOat+kx+UPqyq1mJ7iLIdSI7ogk3XCmw7hTTiHT3Sc4juueHZ+iKrqo/+YKoj3DLsGG
         ExzdPJB1UpNNdV7vlB3Ukzx8kUT/cZ5Vn2BxEC4frTpqQvxJVkWYgsATUYifAAk5DbOA
         ZL4X2RRbHE+6z1M1TorK/3OfSIOaqD6/vIgYki1a397/cQonYx+x2hBRZi6ohGBIMfh/
         GYOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyJObn6b0IL1UmdV8Y96pXWNpNMdGtpDnGhbqcLHKZmhAv1vUFa
	+j8bsQJJPlxr7X4pgwCku5k=
X-Google-Smtp-Source: AGHT+IGwPe3ODSIMUDKuRNcfHzuIfJ1+0aVNuIGAqPMtsyyfOkMs8bhMKGe05jyIo/rJNYGlzneCbg==
X-Received: by 2002:a4a:7249:0:b0:56d:c55b:4792 with SMTP id r9-20020a4a7249000000b0056dc55b4792mr367636ooe.6.1694742709724;
        Thu, 14 Sep 2023 18:51:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:49d5:0:b0:573:29e8:8f8c with SMTP id z204-20020a4a49d5000000b0057329e88f8cls1343686ooa.1.-pod-prod-08-us;
 Thu, 14 Sep 2023 18:51:49 -0700 (PDT)
X-Received: by 2002:a4a:6f0d:0:b0:56c:e17e:72ab with SMTP id h13-20020a4a6f0d000000b0056ce17e72abmr394650ooc.2.1694742709040;
        Thu, 14 Sep 2023 18:51:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694742709; cv=none;
        d=google.com; s=arc-20160816;
        b=jr2pkGZ+lNr37hnaAnjSfFkPbjpX+NRguwloOpleuKLT30XUxqjzD5cUkgMqFg9Lit
         TClMi1GPaUqu4/eIjG7E9Qu78EwtGjayA+VroIuJfC+LkHBw1xspKlRlefW6L4ceTvQc
         QL36ZCrIQXc+6gPax3NEsaOh6SBKj1QMWloqFxAXuysgLN5h9nQY5j4y6JSczdkaTf8J
         za8uxx8qC6nIUokOTi/MaAbfYKSt8GnndHSq7TfAWkU+QqZ0fcstWRrbZr1Um0kvK+bt
         Fz/QabwLUHxP6dqetDUsQH7aDha2R9f6rk33uif5YU+BDCiiOjSuKXEgyC3L/++soE2a
         2Bsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=qqLoBm8H6ZiMRz1kerNsf8O/I1x2KB0Fau5qTkJBuRw=;
        fh=+gxP9MmviEtshzpAVR0BRblIKw8YPx9MamjkLCPhuJA=;
        b=eYWqrnlULi0UDvJTlBZ/1dsGhx8kcER8wN/s1eFBi6dTcoy4Vi1C6F04duPGuQtG/0
         q/EPXtFMWN2PagTK7Rj+8US3XQFjRVOX55icRR8c+Qa4G17LtGa0oHcDz6gxcXxxO7zR
         x3+oWcupg381FrA6VG/EK0SaxByJIEW1uPTtFkqFN0yFjxdzLTimpIQLM2qXeL9Lc5/7
         gTMdyPeMhhDHtEDbq2Q+3kfJ7AkcvMdY7lusiuhbxxnRk+KZzEyaO6K4AGKLQqYQ9Gb4
         +04W2qm2DeZBBUEv0tfp211QuD3j7Jp+xGbyq+XEVVY28E7grTmsPoZhzo3KeO/HaM4l
         Uiqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=kaFPpMdx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id m5-20020a4aedc5000000b00570d0deceb8si329444ooh.2.2023.09.14.18.51.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Sep 2023 18:51:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id 98e67ed59e1d1-2749b3e682aso122923a91.2
        for <kasan-dev@googlegroups.com>; Thu, 14 Sep 2023 18:51:48 -0700 (PDT)
X-Received: by 2002:a17:90b:a49:b0:268:60d9:92cc with SMTP id
 gw9-20020a17090b0a4900b0026860d992ccmr210845pjb.43.1694742708242; Thu, 14 Sep
 2023 18:51:48 -0700 (PDT)
MIME-Version: 1.0
References: <20230914080833.50026-1-haibo.li@mediatek.com> <20230914112915.81f55863c0450195b4ed604a@linux-foundation.org>
 <CA+fCnZemM-jJxX+=2W162NJkUC6aZXNJiVLa-=ia=L3CmE8ZTQ@mail.gmail.com> <CAG48ez0aenPmr=d35UGa4_BiCwYU1-JHhD_2ygThvjOEXEM7bQ@mail.gmail.com>
In-Reply-To: <CAG48ez0aenPmr=d35UGa4_BiCwYU1-JHhD_2ygThvjOEXEM7bQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 15 Sep 2023 03:51:37 +0200
Message-ID: <CA+fCnZePgv=V65t4FtJvcyKvhM6yA3amTbPnwc5Ft5YdzpeeRg@mail.gmail.com>
Subject: Re: [PATCH] kasan:fix access invalid shadow address when input is illegal
To: Jann Horn <jannh@google.com>, Haibo Li <haibo.li@mediatek.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-kernel@vger.kernel.org, 
	xiaoming.yu@mediatek.com, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org, 
	linux-mediatek@lists.infradead.org, Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=kaFPpMdx;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Sep 14, 2023 at 10:41=E2=80=AFPM Jann Horn <jannh@google.com> wrote=
:
>
> > Accessing unmapped memory with KASAN always led to a crash when
> > checking shadow memory. This was reported/discussed before. To improve
> > crash reporting for this case, Jann added kasan_non_canonical_hook and
> > Mark integrated it into arm64. But AFAIU, for some reason, it stopped
> > working.
> >
> > Instead of this patch, we need to figure out why
> > kasan_non_canonical_hook stopped working and fix it.
> >
> > This approach taken by this patch won't work for shadow checks added
> > by compiler instrumentation. It only covers explicitly checked
> > accesses, such as via memcpy, etc.
>
> FWIW, AFAICS kasan_non_canonical_hook() currently only does anything
> under CONFIG_KASAN_INLINE;

Ah, right. I was thinking about the inline mode, but the patch refers
to the issue with the outline mode.

However, I just checked kasan_non_canonical_hook for SW_TAGS with the
inline mode: it does not work when accessing 0x42ffffb80aaaaaaa, the
addr < KASAN_SHADOW_OFFSET check fails. It appears there's something
unusual about how instrumentation calculates the shadow address. I
didn't investigate further yet.

> I think the idea when I added that was that
> it assumes that when KASAN checks an access in out-of-line
> instrumentation or a slowpath, it will do the required checks to avoid
> this kind of fault?

Ah, no, KASAN doesn't do it.

However, I suppose we could add what the original patch proposes for
the outline mode. For the inline mode, it seems to be pointless, as
most access checks happen though the compiler inserted code anyway.

I also wonder how much slowdown this patch will introduce.

Haibo, could you check how much slower the kernel becomes with your
patch? If possible, with all GENERIC/SW_TAGS and INLINE/OUTLINE
combinations.

If the slowdown is large, we can just make kasan_non_canonical_hook
work for both modes (and fix it for SW_TAGS).

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZePgv%3DV65t4FtJvcyKvhM6yA3amTbPnwc5Ft5YdzpeeRg%40mail.gm=
ail.com.
