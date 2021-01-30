Return-Path: <kasan-dev+bncBCXJLOX644DRBEOI2WAAMGQEY3YFM6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id D7202309585
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 14:50:10 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id h16sf8055318qta.12
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 05:50:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612014610; cv=pass;
        d=google.com; s=arc-20160816;
        b=RJZ8/8o0MqvGQ0Pj8kTV2wI/J9L5HMnSLyKswb/kE4P/Iz87faDQywxRCdcsBVseBk
         fIYYfdsbb2ZgXJrfp8jMG4Y24zatzaGnnu5XT0slfAjtG5pVM9GTOjSjcA/aXf/lBKDm
         D3FdVPW6CDUEjzMLg3BmsgiVylZR9ueV35qq6dltob5/hkT/U/T5QAFW9L1G84PP9jl6
         n8e49m5/JbZ5xLtq0gQocENQW+SuV38xnRoNx3ufatM42RHWKCz/oMTccAssGG/P5mMr
         eB/o0Nn4cLu3714LWNJmMpi66qpJECdeD3B11T4O7qjw2bsoVmGrgyKP60rPxvEHjV7d
         qxiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :sender:mime-version:dkim-signature;
        bh=WX4+y0FqMyxst5HekiRXkvOiaSAu4mfHLj9mqKAqsFo=;
        b=lafBS2s8GaAHgwueh1sxR/K6FqWKpS2zS1MJV+WPNkWh6tuTiumhdSXwvdBlVEGXgY
         xIV/wgMHm0hRH+zS9VQnejRsPGpQCErpiRoRDav5u21wJ06ux6l9TvpHX0Y7XNa2TZvb
         kyZocOY0BM82Yum3DgNiB1WxpVrXpmdsKv33yJYTPLSFAEXJyh5u/RZQxebK5msb0DTv
         bP0y6ayaBHcfvMVx6wkNyIIz7rJA1ZX82CDpDX+wWRmHFbTWzhb/vgOmi//sj81YJFiP
         u5Xm0Oy0QCfmRSSVcJCSRJ+n6ulpxp5rpEZ03rH0j4SzK4RU10xsqXviYWbjAk9oppj+
         DKlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=OFWI0FxO;
       spf=pass (google.com: domain of mrs.doris.david22@gmail.com designates 2607:f8b0:4864:20::e2d as permitted sender) smtp.mailfrom=mrs.doris.david22@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:sender:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WX4+y0FqMyxst5HekiRXkvOiaSAu4mfHLj9mqKAqsFo=;
        b=o53BL0k8yqfdMf6V9gNZC7+IwmReZtJqS3z3fKJIRDEhmMVS7LQKZZPt2Kct0B8DRM
         7k9/wdGf4Yq0QnaNQW2AjoyVUCL8Ye5cEkeAMnngVl84NJdW23SNLzgPaVI9T0C1sJlN
         HAdvbPGob5exe8c5p3AtvOlrR/QDMm1D/lRgso6JsL/pKCsxOM06aZWIVxIiaxv5GLWs
         owHsrMLHjykaBiI7YTuhs+zURueUY6nBseSc60SXK+KiRFiWOqpjCf8R61oMGVV8j6sD
         Bx8U0wQM7bUxHQHLEmIwALyhN5lsiVGivW3tvjPOKQt7uDR6Jdwtf7ayxiuqVg6mzTiM
         PSzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:sender:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WX4+y0FqMyxst5HekiRXkvOiaSAu4mfHLj9mqKAqsFo=;
        b=kS49S7bUgKYyn3ohYx3ssojMwHhDe8qrVtylLzR7yvGF4zLis3/6d1GEPQ6VQVnAZR
         26EyLade+UxhvzTRdaEmckroZdL/pDHVWJ4s9FwPhEv5djBnNMkqxarI95+tHWJrq1ER
         Hy4W6w580NXP6GscfPXeJa2J4C8iz416uGE2G5B27u/V7k+ALiN4tEmrdZuNE4B4d3CV
         0lrITecxaDVB83k3RcMaA20FmfojOMFkOc92ttdAMXIuaAM1g+Ggjp5iwH6ELCwDCEJ+
         GpkEp8FLQpApFA7Qo7LYY1/3zwtV/0H3+K0dPznCvArpLHmCaZ0WlVwfsGHpjxaWcRnK
         JZwQ==
X-Gm-Message-State: AOAM533VLRT3EmV9I5iHzSubQHpwA4Am1g+DnXK3JbTS5L/d1AR9Lg8w
	YzQQf18I0ooSggcvvl81dEg=
X-Google-Smtp-Source: ABdhPJwV71D5klVq8l++Y4GGK8+pfofLiI4rfPt+OgpxcIsg/C2rV8IiRk5m9iygDzmlqCI38/GPig==
X-Received: by 2002:a0c:a905:: with SMTP id y5mr8362838qva.55.1612014609781;
        Sat, 30 Jan 2021 05:50:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:e904:: with SMTP id x4ls5816752qkf.6.gmail; Sat, 30 Jan
 2021 05:50:09 -0800 (PST)
X-Received: by 2002:a37:67d6:: with SMTP id b205mr8246379qkc.69.1612014609412;
        Sat, 30 Jan 2021 05:50:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612014609; cv=none;
        d=google.com; s=arc-20160816;
        b=AYGxgHrlUPTXOQ4rRG6LRt6sgSKQu4fkn/STi1ieKHKAuqFrqTWqyEsstzlVzsAyYv
         lJflPjt18fVGtzV/bqR1gAz/uKYdSWUy7Qa1Aar4bvfL72Tzfvjgskh1UNIGkE1c3Hkk
         Vx82zvaQhIXF08xcig38cnAMwCv971cl3DGzkgmvm5ETN5zDPF40W7gGPyGO8Qr7zRUe
         ULDdnDtSwwT8LugxWx0T0NntA7A7K/5ruivHcVSrSNvin6kPHnnclxtar7do4wu0G+hW
         gKmaTIDSS2QvOpDbl6X0E9S5dndmkWe2+m4nn1C/zdhCiaN6/KmL2vRwSKVNtda39QWO
         oW/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:sender:mime-version:dkim-signature;
        bh=7iI1DekgaHBZksx2TGvGc1WMRd2snjmYIH7XSR8Ig2g=;
        b=uFt2eva6/h+W1EwmbeF2WglF7c3Xu5TifCOTq1NdGAaLZI7bWbL00jroYfPO2koGbV
         uAEZzFt3nUI9tux1MIq/F4/5BC+kMdcV8u2l71wHc7NTdDwJgm4BDLVkdWy31yp0hUX2
         wvU1qFmh67Vz/BbOIgvbxHbnMMBoZsvf2ShTvxf2IWuD8ybbOpNsgq8g8eij81yBu9YT
         6WHyMZqMtrmbVRSfVtTJ//9rx+fzYQI5U6SddnC7tAf/qAosySXaCwOzN6z8zELVJJBU
         /9DaQXLUo/7EYFbWGNIpeqpSN1gg0434r5I4OFa97d0pLbsigr7BUd77buF0Y+9VO59t
         YD0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=OFWI0FxO;
       spf=pass (google.com: domain of mrs.doris.david22@gmail.com designates 2607:f8b0:4864:20::e2d as permitted sender) smtp.mailfrom=mrs.doris.david22@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vs1-xe2d.google.com (mail-vs1-xe2d.google.com. [2607:f8b0:4864:20::e2d])
        by gmr-mx.google.com with ESMTPS id x2si202281qkx.7.2021.01.30.05.50.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 30 Jan 2021 05:50:09 -0800 (PST)
Received-SPF: pass (google.com: domain of mrs.doris.david22@gmail.com designates 2607:f8b0:4864:20::e2d as permitted sender) client-ip=2607:f8b0:4864:20::e2d;
Received: by mail-vs1-xe2d.google.com with SMTP id v19so6451517vsf.9
        for <kasan-dev@googlegroups.com>; Sat, 30 Jan 2021 05:50:09 -0800 (PST)
X-Received: by 2002:a05:6102:199:: with SMTP id r25mr5120763vsq.56.1612014609052;
 Sat, 30 Jan 2021 05:50:09 -0800 (PST)
MIME-Version: 1.0
Sender: mrs.doris.david22@gmail.com
Received: by 2002:ab0:34c:0:0:0:0:0 with HTTP; Sat, 30 Jan 2021 05:50:08 -0800 (PST)
From: Anderson Thereza <anderson.thereza24@gmail.com>
Date: Sat, 30 Jan 2021 05:50:08 -0800
Message-ID: <CALSkaMApfiGi=Wj=BpAJZ4z1uN6g3YdU5Vcst=qUUinz0mfF2Q@mail.gmail.com>
Subject: Re: Greetings My Dear,
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anderson.thereza24@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=OFWI0FxO;       spf=pass
 (google.com: domain of mrs.doris.david22@gmail.com designates
 2607:f8b0:4864:20::e2d as permitted sender) smtp.mailfrom=mrs.doris.david22@gmail.com;
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

Greetings My Dear,

I sent this mail praying it will find you in a good condition, since I
myself am in a very critical health condition in which I sleep every
night without knowing if I may be alive to see the next day. I am
Mrs.Anderson Thereza, a widow suffering from a long time illness. I
have some funds I inherited from my late husband, the sum of
($11,000,000.00, Eleven Million Dollars) my Doctor told me recently
that I have serious sickness which is a cancer problem. What disturbs
me most is my stroke sickness. Having known my condition, I decided to
donate this fund to a good person that will utilize it the way I am
going to instruct herein. I need a very honest God.

fearing a person who can claim this money and use it for Charity
works, for orphanages, widows and also build schools for less
privileges that will be named after my late husband if possible and to
promote the word of God and the effort that the house of God is
maintained. I do not want a situation where this money will be used in
an ungodly manner. That's why I'm taking this decision. I'm not afraid
of death so I know where I'm going. I accept this decision because I
do not have any child who will inherit this money after I die. Please
I want your sincere and urgent answer to know if you will be able to
execute this project, and I will give you more information on how the
fund will be transferred to your bank account. I am waiting for your
reply.

May God Bless you,
Mrs.Anderson Thereza.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALSkaMApfiGi%3DWj%3DBpAJZ4z1uN6g3YdU5Vcst%3DqUUinz0mfF2Q%40mail.gmail.com.
