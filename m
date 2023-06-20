Return-Path: <kasan-dev+bncBDW2JDUY5AORBYNCY2SAMGQEVGL7K2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EB3D736B59
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 13:45:38 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-62fe90ce2fasf43734406d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 04:45:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687261537; cv=pass;
        d=google.com; s=arc-20160816;
        b=NhGW2pTpGM3dnpcHKvWr6ZmVHFkfgdXphw0YtKoNutCIrx3wxCqXeZAo0bhyne1vgp
         uLInC1A7uMTJghx7TDwcewSJftzb1zFQ/qHIhCZXjf/NB+hMNCaG9etUKOZmAquBz38G
         x57nyYFew7KNd+aHIZLglEPR023Q3hkQ49sFKMeSZzVKyS2LmFaaKr/eP/qDyuILmJeM
         HVrcZ86xn73gVYFaZ2YBkJ+PpVgDwoFO1nbBlYu53Ql9ByI6B0pogSvTDBOgjo+s6on/
         rTzv3sYLNdoOX4hwSQCpnDX8QkdwPcXO0qKQFDXiFMzRmEeQmGYGZQLtJGACDYt1zlHT
         GbBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=sS7ql/ZKzuJvE5y+DmsAZ1DI0s8I7V1OfUrlqd8qa3Y=;
        b=TrF/v/FEW4QbvjOIS+daDY8lghzoMRjHLNaQiq2JpJkvPzwkKGRxQmBiivJ+TFo0G4
         azXhrhGhLlNil3DY6XJG3eWRSkHALvqxcotEIXBB/bDt/sI9MbfjjBZ/E52g0NYn/qAS
         i4Q+Ub2BUaHAIlXjCb4aCBEZK2+j58URmagmBoWVdjFnhtUM1Vt0WKxJ1ouAmXUH//EC
         BxhbXZpBZ3oIiTq9Kyg5QejG4Avml98Vaqv9G5+opd5hghljIigyF7LJkujaQoe5ZKrj
         NDKLeVnVVVPqZKo2OxbasnwJZoONdoFcpvvdWDKIyWIkSspmhd6kVRMOFsi/laJHwN7e
         E5Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=JafGBlk8;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687261537; x=1689853537;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sS7ql/ZKzuJvE5y+DmsAZ1DI0s8I7V1OfUrlqd8qa3Y=;
        b=pHztHFshHOjR07AcSbr1A7GCmxIZGcg0ayyMAILy5xyOixofU5xZqZJQGBZUzJd+39
         HcK8HoFbmGffzXOSG29OP/qtApjQGn9RS63O7zu+goZFicFY4h/f9/4j7c903kAvL1X6
         loS8+RjD0HrFi+iY+3VvykZfl4YeQXRcRYBIV3UQ45jHfUkgG7ojxXFTa2ZxDHrdxy41
         1QYie7Azm3k4EnuqrV1MkzIiefrw/UBEdcKO8hWXCqCZ+J2Bym97zYqgH3rT+Ags+5ur
         WYOqGbLHSM5Vwv3L22x85U8ihIvvJsmZvvNlhyGIpKoUh9dOzYQXmoohK+bHfVaw2jFk
         VmiA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1687261537; x=1689853537;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sS7ql/ZKzuJvE5y+DmsAZ1DI0s8I7V1OfUrlqd8qa3Y=;
        b=sUAQz4ba+P+nwDuzg4kCscadn+W13UlenDUxZonLjhzdf7H5xYmBU96nAWqwpFJW/F
         6AZXn1vytxyPGY1DEWJ2Ds3ZY047Vb4XMVmqNoRQZ47RoEne4h/qQ9rWl4ezC7HfSq9q
         OLUj5/3+pqwRkchgkALhdVneZrWYxobf0lalIcXhDD7LnnIsqYe2jJcZIvrnMxsyMyNA
         be75kle7WjVEa7ONB6YRtm6m6yYLpxYev0yAoKSm0CI3Oftkw0RE+EYroy8VlP+p7tWH
         FoTd+K+ZaE/mqMDdi7W9kLIfVeNnxDfxLy6HcqSIQod0Ve18Df12N04VLVgcuag852P2
         XdOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687261537; x=1689853537;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sS7ql/ZKzuJvE5y+DmsAZ1DI0s8I7V1OfUrlqd8qa3Y=;
        b=kzxQN64pnOrWHuYcupNoqhwRoPuHf5tzSQ8aPqP3f1nN6LE1FsTC1KzE7AwITIgFiX
         tjOFYOZIVwgzCGyQfmKgPW0Vf+kfykLPjb/HN51+8MzV9plNxFaOXk3jEpdF3ii0puJY
         lUYfNnD+/CjkqbAE7m0QZ2zJgVdi78v8ZI5Qc2j+VgR73zQk+L32ssJmqnUR9zddNTcp
         bt2Qpy0vpx8YnBH9GdhpYVlsqcEBuC6gz7ypDezPtZWRVmEX4oGllfm/Qmct627cLjUv
         N4cm4EWupuAe3JQ1UaDXkQwqy9FEgXqRtB2yWzqUnJIUQ3lUbt/XLfeY2Ofa27SL+OZs
         XPiQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwOS58lDm98Bx5t1xtDHbc0VmvfGziS1jC3RihP+CoFxA6YAZIA
	v3hF8Uae+s57jmRfwGkNiz8=
X-Google-Smtp-Source: ACHHUZ7TfEfwrXKH7R4/vsUELZZLjC/JSSbT3yKCNMOnwoOczkxQwqBxD4JdDd/pOLlJl/Mg8IeaEA==
X-Received: by 2002:a05:6214:c22:b0:62e:ffc3:a9cc with SMTP id a2-20020a0562140c2200b0062effc3a9ccmr12581715qvd.58.1687261537284;
        Tue, 20 Jun 2023 04:45:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4e0b:0:b0:631:f072:e45d with SMTP id dl11-20020ad44e0b000000b00631f072e45dls1532931qvb.1.-pod-prod-01-us;
 Tue, 20 Jun 2023 04:45:36 -0700 (PDT)
X-Received: by 2002:ad4:5c81:0:b0:62d:fd62:45fa with SMTP id o1-20020ad45c81000000b0062dfd6245famr18719940qvh.54.1687261536768;
        Tue, 20 Jun 2023 04:45:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687261536; cv=none;
        d=google.com; s=arc-20160816;
        b=Jy4py5qiEU0GG8/d4Xk4WuZP8N84f6s2aFls6uI6x2prGMcoDmIhJPBsr5+Nri4RjA
         bltMlITp6ptJvMYksnYWugzbuk/z9wKHW9M3dZKAVjjLf7QQdL7WMZXGKC7USK4y3sAa
         hxfPQMbktBwj8U43ftAHyptLyhzpq9LLnD0iTCmZLgxtlfuG+JbndMLtKoMEcrDDXl/o
         W5mgQYNG0raFfmQHbmt4XEHc2HUlVgmicr0pXMf+bPRL2YA449dEL6fO0c4eBGjVfk7N
         pZY6wft5vy/lSpNyTinNmYCRWXqkpx2QMJA8kySqZIKa2YIfAhCDYTw1a6CHIakOgekP
         89Hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tJCMKaRS9iIUjy75SMVgQ9VDcAREfFkBluEAU4z9ags=;
        b=ZTCZo0HyuIV3OmX4bpjUMZg97eahEXJmwvvz4wLvYqmAARxqHcYmqfNPVa+pq5vwCO
         IqKYENQDgzPnUO5gv6aK5kOUE+tOxEKuZPiF5pIjHorQ+cqSJFAHTMRpM7Gqkug3muBi
         ib8cme4LkNHEmElRN0k9cHJW1yGkxp96SbOsqYWIVxyaJAu0Nu5WpZ0KKxOECEoXZKZ9
         /f9b/UBnLyppLt7/ZHGtwYnyeKVdvpwlSNsBi9mCXvUZFH8Nl3Wta71jrNk2EpWuxDqk
         H5zwYzk6OBkF30pPGgWZxXKmWPWYUzVZEIYLON4qJRgTIMZf/UZgGtVkJkfD1M9ehEHi
         HNUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=JafGBlk8;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oi1-x230.google.com (mail-oi1-x230.google.com. [2607:f8b0:4864:20::230])
        by gmr-mx.google.com with ESMTPS id cs1-20020ad44c41000000b006260dab0171si177046qvb.3.2023.06.20.04.45.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jun 2023 04:45:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::230 as permitted sender) client-ip=2607:f8b0:4864:20::230;
Received: by mail-oi1-x230.google.com with SMTP id 5614622812f47-39ecf9c3eefso1772943b6e.3
        for <kasan-dev@googlegroups.com>; Tue, 20 Jun 2023 04:45:36 -0700 (PDT)
X-Received: by 2002:a05:6808:2110:b0:39e:ce9d:1a92 with SMTP id
 r16-20020a056808211000b0039ece9d1a92mr7992873oiw.4.1687261536152; Tue, 20 Jun
 2023 04:45:36 -0700 (PDT)
MIME-Version: 1.0
References: <20230614095158.1133673-1-elver@google.com> <CA+fCnZdy4TmMacvsPkoenCynUYsyKZ+kU1fx7cDpbh_6=cEPAQ@mail.gmail.com>
 <CANpmjNOSnVNy14xAVe6UHD0eHuMpxweg86+mYLQHpLM1k0H_cg@mail.gmail.com>
In-Reply-To: <CANpmjNOSnVNy14xAVe6UHD0eHuMpxweg86+mYLQHpLM1k0H_cg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Jun 2023 13:45:25 +0200
Message-ID: <CA+fCnZccdLNqtxubVVtGPTOXcSoYfpM9CHk-nrYsZK7csC77Eg@mail.gmail.com>
Subject: Re: [PATCH] kasan: add support for kasan.fault=panic_on_write
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Taras Madan <tarasmadan@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Jonathan Corbet <corbet@lwn.net>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Catalin Marinas <catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=JafGBlk8;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::230
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

On Tue, Jun 20, 2023 at 1:33=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> > On a related note, it looks like we have a typo in KASAN
> > documentation: it states that asymm mode detects reads synchronously,
> > and writes - asynchronously. Should be the reverse.
>
> This says the documentation is correct, and it's actually called for
> writes: https://docs.kernel.org/arm64/memory-tagging-extension.html#tag-c=
heck-faults
>
> Who is right?

Ah, right. I did a quick google to check when I was writing the
response and found this: https://lwn.net/Articles/882963/. But looks
like that cover letter is wrong and the documentation is right. I
wonder what the point of the asymmetric mode is then.

So the current code that you have should work perfectly. The only
change I'd like to see is in the documentation.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZccdLNqtxubVVtGPTOXcSoYfpM9CHk-nrYsZK7csC77Eg%40mail.gmai=
l.com.
