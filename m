Return-Path: <kasan-dev+bncBDW2JDUY5AORBFPW5SBQMGQEE6HLATY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 5252E36320A
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Apr 2021 21:46:30 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id s4-20020a2eb8c40000b02900bbf0cb2373sf4266363ljp.18
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Apr 2021 12:46:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618688789; cv=pass;
        d=google.com; s=arc-20160816;
        b=FetK8BhcxeBw3Yl/gEqhgVn3EOaN5Yb/ShZS8Y3795vMgZhwycc9IoB8tcfkSEvJLX
         ZnyIT5AQEljkR70j2ykvz1cR8juRgnxXCKSiO+Vf3GZUg6qUpuHaASh/AUYzq+26BtXZ
         caKYtnIjvmtlt2z+CKnHHj+1NUBQrbAPvTOq7ZLl+ppSLcBkBlpZfi9lz5TEa/A2X93u
         GnmvZLuayn8lCudB+ovuldaYB5I/gLF46N+pZxdqD9/KdO11HYRq4lGwVt6EIO5+nnby
         sDs4Mr7Klp/jUl40WwTaKLVg/JhE7y9KwA3NdGXp55RHfZ48i/5sUFZbZ0xnAmsChmTe
         Othg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=v6MPKp0mHZmiuIBjbz6RPgv4FW90LH2qQGaPHEPbySM=;
        b=RMQV0mGIudVla5jOg9A35706QR4fvcgCztp0S59Gm+cg66IRz6jHN3cYjZv5V4w+xD
         QPlTSvrxH6I8WLJnjwgwfvfEJUwlovc00ksdgNatqnnnvq4qb38Q1YZLUmnhDj8Yv/z1
         eFp7lJAM7YDRgz+AFbjqBhDJeIEowftATvC4ahBYDRln7kdk67CUN5NAq1qF9qUwmZch
         44f2xGbd+on8+zN1bsNb7nd2ZQo03on9jGomLiCh0X9PcRYyoRh3mJdiJGtui9XsHO8m
         6mNjd7wILVdffgd7uwz1TQ5NMFS6lsQhU5ID9qmjeRhNtxLDBo88VWf1ypbZqZlbx/+i
         ClAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=sfo1ZL4I;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v6MPKp0mHZmiuIBjbz6RPgv4FW90LH2qQGaPHEPbySM=;
        b=aIFlET8IPVXDNalQh3M/EOnh/4uaLwzepQXJCAxsx9MG4Z+DOfmBSrBSbVXNNVOF4W
         H+AXeT9xyyP1VAUTJRbuwoNdN6P73BWjMa2BAjtGsZyzxx9x8HHED0vh3hfdtWVbPswS
         xvR5j7aRh4Ej5dfPFvhxpbjfDxwUEbT6XAf3Aw3TWk9dhbvlWzYf7NIr0MJz+y4yhRoh
         pj6N4PNcAUqgODVrpoZhmLat5oy3KSz/vn1PYItgoyLamAy4GAPdH+3L7Kb8wR1i/doO
         LYAIEUfj+AY5SddBEbiQVOpI4C4CT1nLKYTXTHa4jBWBjyjdwOcNRmmkjF1gGNFPj488
         j2mg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v6MPKp0mHZmiuIBjbz6RPgv4FW90LH2qQGaPHEPbySM=;
        b=kO7mM1RtcCjuTW6J2BOIoM5T6GFoLuhEJrdjWS6utNlyF1+ADYQSqh2RUxbOBZ1Stj
         +eSBXKtiWNWIkmMaNo6kc2RTnVXWN3REkLLIRpzCw0q+VTMBd0x3YenA2c9YUMTXEfkQ
         SJcXmAP2IxXr01dxYNsQt1riBUQ8UIEpTQY2ywfgHdyXiOKmvGi8ShbcnqsHc6nTAAAu
         8y5+f9uOSWMQOpY9X7PUO0E9EgjQ7pNB7SpMCmvHNm4DyDw8iD0WQ87sOF1MWbxYazrR
         oPUlQ85YxahSISs37PnpshGbCRgiwDcpWZEL0PMGTe63XgujkmZW+g3rnOidj74h7N8t
         /e6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v6MPKp0mHZmiuIBjbz6RPgv4FW90LH2qQGaPHEPbySM=;
        b=c2c51NrnM2RM9oR+UiQhhYO06PcUx8nkONLVR98i8oQmLasbPYWLI9ew6LswSj+G8R
         ruSrp0bsgKwh5Sn3TgTPH/HoHV011Yo67rGXPmVDmrUdKGpLcX16T5r8e4qiNbImg7Fm
         UKXRNlMACS6aglAKaN+GGNU6s19skcO6qYDgK/j6XsNESe5XBbZZnaDL3oNIiWo0WCtu
         xf6ZZX4rkqIoi8GeEh1FGlb00BhHCOhLRDXWDA5y0oaHRHidiqjtuPvze7pEXWX29NN1
         P6opTar60r5Q/Uq3TQ8aoSapRpECopxuTAzCF8XdPDtav1DuB2I51WgYqdNEFTErS77q
         EHiQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Dj0zSZzDQmphlvdlxBlS8X9o8ETJm1WbXtYFN2d4chNthWvzA
	sLimX0Ou4G9suM71NGyCKhc=
X-Google-Smtp-Source: ABdhPJyUZ0qZv3u/EuQh/7s4mKPacaduZcKYP1DEXXButopGen8RxNg1/g8x9N1oS17xR0nyG8KiiA==
X-Received: by 2002:a05:6512:3618:: with SMTP id f24mr7097988lfs.34.1618688789828;
        Sat, 17 Apr 2021 12:46:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc23:: with SMTP id b35ls2566937ljf.7.gmail; Sat, 17 Apr
 2021 12:46:28 -0700 (PDT)
X-Received: by 2002:a2e:3511:: with SMTP id z17mr2669488ljz.32.1618688788873;
        Sat, 17 Apr 2021 12:46:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618688788; cv=none;
        d=google.com; s=arc-20160816;
        b=fhDY5cg7Pw3NWkTki6NXLNe+Ca8Tmq1KIvO7kJSKnfr16vQmDEryk5dcFaydqt+wuz
         AraZk6AB+paqxVkZRngybPLvANrjiH6M3/c5TbqMaZaPSl2f5G9Aj4c2gsnvcgyaoCbO
         w07DKPhVj5xLBEJcvKFxRdT3LggbQ7u3HvvTpLA/sW3iEfEoWNX1Lcirb0nHYWia3zCD
         16e/Sm6ZGoIBj5+5f+4VDx0br17wyBTymamWe7ejuYbxeZf9SFGRfQF3NBkvkOUw/JdV
         MxOFmGAcgZ4Ng18cn5gF0rSBrVlUcaqgCGbDb+DNgpaM0zYbfnkpQPRPfgRP6zA3rb5r
         WCLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eSOJMwvIJkQU2JYaT7cb2vTqKYf6iPw1ySzK9GIZ1mE=;
        b=ZyJ97vMaez9lKqgIydQz9JwYZhdgaNoFdLUlUVN+4Ri5GPqDuQnkszPlxO29vMuyjx
         iV2CNebH0kFu5JXGoernVrYTrxNOVGBlsyLHO0z1OFJRIrw2k2kGq1qbMTLDHGJ9g2qC
         50F3VLrT8YCVQeuIbt9fSeFeZ5ONNHehNAZNwh3kgJwn2BE0lwHpHgmJXzpN+U5/+Ld4
         Eo6IRxnzhvl4JrRITgOdH/XQDe6+XjdZLMwKvz8tZ9iIgqQePixBxk0qsCPYuG/px3wx
         WruMMJSitktTMW/EytBIB0g+VaLZoXtoNOwnL0qNUt04hyPu4LTOWrLQAhIkunq8l7a/
         pv8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=sfo1ZL4I;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id a10si499191lfs.11.2021.04.17.12.46.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 17 Apr 2021 12:46:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id h10so36117008edt.13
        for <kasan-dev@googlegroups.com>; Sat, 17 Apr 2021 12:46:28 -0700 (PDT)
X-Received: by 2002:a05:6402:4415:: with SMTP id y21mr16888070eda.70.1618688788715;
 Sat, 17 Apr 2021 12:46:28 -0700 (PDT)
MIME-Version: 1.0
References: <20210326205135.6098-1-info@alexander-lochmann.de>
 <CA+fCnZcTi=QLGC_LCdhs+fMrxkqX66kXEuM5ewOmjVjifKzUrw@mail.gmail.com> <CACT4Y+Y_PfAhjV26xYf8wcEv0MYygC14c_92hBN8gqOACK7Oow@mail.gmail.com>
In-Reply-To: <CACT4Y+Y_PfAhjV26xYf8wcEv0MYygC14c_92hBN8gqOACK7Oow@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 17 Apr 2021 21:46:18 +0200
Message-ID: <CA+fCnZczmfDROOLbQ-7w7a+-YXM-D4z+Jo-_7FZF+3G0yKYc4A@mail.gmail.com>
Subject: Re: [PATCHv3] Introduced new tracing mode KCOV_MODE_UNIQUE.
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Lochmann <info@alexander-lochmann.de>
Cc: Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Randy Dunlap <rdunlap@infradead.org>, Andrew Klychkov <andrew.a.klychkov@gmail.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Jakub Kicinski <kuba@kernel.org>, 
	Aleksandr Nogikh <nogikh@google.com>, Wei Yongjun <weiyongjun1@huawei.com>, 
	Maciej Grochowski <maciej.grochowski@pm.me>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=sfo1ZL4I;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::536
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

On Fri, Apr 16, 2021 at 10:42 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Sat, Mar 27, 2021 at 3:56 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
> >
> > On Fri, Mar 26, 2021 at 9:52 PM Alexander Lochmann
> > <info@alexander-lochmann.de> wrote:
> > >
> >
> > Hi Alexander,
> >
> > > It simply stores the executed PCs.
> > > The execution order is discarded.
> > > Each bit in the shared buffer represents every fourth
> > > byte of the text segment.
> > > Since a call instruction on every supported
> > > architecture is at least four bytes, it is safe
> > > to just store every fourth byte of the text segment.
> >
> > What about jumps?
>
> KCOV adds call __sanitizer_cov_trace_pc per coverage point. So besides
> the instructions in the original code, we also always have this call.

Ah, I see. This should be explained in the changelog.

This means that a KCOV user will need the kernel binary to recover the
actual PCs that were covered, as the information about the lower two
bits is lost, right? This needs to be explained as well.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZczmfDROOLbQ-7w7a%2B-YXM-D4z%2BJo-_7FZF%2B3G0yKYc4A%40mail.gmail.com.
