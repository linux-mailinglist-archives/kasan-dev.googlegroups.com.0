Return-Path: <kasan-dev+bncBCMIZB7QWENRBRGITP6AKGQEUKIZKQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0030928DFF0
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 13:43:01 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id t14sf1233321ooq.8
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 04:43:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602675781; cv=pass;
        d=google.com; s=arc-20160816;
        b=eYDFYkpxYReXHjvYuFw1862CmCYAeQWb7OnUKETn6jH21kLG0GAJS+24flziMnla/U
         9fUgfr45iBxeqRKrPXEmu9petg4JeXUZAmsdez6nwCaYjhqO3ICmBqHD0K5Gu5aK6l9Q
         PcygduOF/T0WkURAxjaR7B051miZnq2KFmF/mChSrOfwG0+Gy6m2AU2MqP15VSPkijvy
         fztyvC2RI731dQxlKz9yy1BTWXZ1PIzYxwCPvDHFN4rA4LZKjlOVzMwHUpCDHPste0vQ
         U0BNF0Gn1FMFkFTmUbdMr5gshftLFFbKNW72iAyDUVGqJkHEZ5L2VcRWr+f4E9Ecy2OQ
         R26A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Uc2tRIGFHZwNFMXacYlXW7ahm0YTk8NIvdr86gYN04M=;
        b=zkg4V+vVkADRLNCfwb/dN/OJFLttauwvSxH/y1DS/gqoTwkBODiFBwenGfbuzUyhWP
         B0tifLXhwBr8p4bTQQ7JH+3T9odPSpSe/cNXIpVD/q9N5p5MVrm8PhwJJ8/94R6l3e9I
         l2wTPVsjOHhGN3aZI6TeKeU9rTutn8Ci2tvcl7rG43BO98w7dDGuDzvEfc86KsK5Ma0S
         VCa0FFw4Qe3n6giLpkezP/SLU9OtorwkIlNcyBJBj2YVa/z/bPoIcc6V1lyqe6sPJkVm
         XiVa9zblRcnDvNmSSY73TvkhY2IUR3ICiL/7ew/ZHep3o5bmASXTM7rZcPB6Nln7lREC
         mPfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P0Kg5kw3;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Uc2tRIGFHZwNFMXacYlXW7ahm0YTk8NIvdr86gYN04M=;
        b=KsxNjWozGIwdOaeOBEiFfozwj4+xFo//CMS80Wxoqg9/v1cSqfncIy24PM0OA1Y8Zd
         mmPqFefi52FjjaS6gC90kQkm9fo7vrbehpDHSPsd+ijcwA8BN6NVl5hMAfC6QFLuX3So
         0UjbjkTTtAf8yiULCmMy2a1vY0qzELJVcM1IwfIy+c4ly+cDG2gzS9reD4pFMBeo1UBk
         OQX3o00QRn6mtMVju73ECwtkVPweYqY3EC5O5RPD0bqtjSzh/avAb1HvggjMLyGs0Hem
         L/KcBU0+1bCbW/1x4xGT/qWpOaVYCiUSD/2ReKDmbecFfzdtG7/1LP3Nv3nG20ZuFPh4
         zjSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Uc2tRIGFHZwNFMXacYlXW7ahm0YTk8NIvdr86gYN04M=;
        b=qTh7Y1d2nSsk9D8DrLAApbRnx2SE5thD1LBHf2/zlC0a++XElgfljkg/o6gi24x14+
         UmO/A2Hva4FXG2J7UdZtVFCz/3ZASSEn8Cxo2fAwCMvKW1zmWw0qPs0LibnZdIK9ciCW
         AlG/ik/HU9hmq3ktq7D8r7OIXy2RsoHX7RFhrP0Q4PIkJNsAok7s6EeevhqgsY1jtGBF
         UtBKsatxJiNYf2PHFleu3ofT5l1R0N2mM+FGqynqaUge5quJLaV8wI5X279kd946GX6d
         ROchHPrP3f4kEvnMqSX84wPVPUp25sBasfDiDHdi7ErhCv2Hwx1YRqPbO/ggQsICMx1J
         X9tQ==
X-Gm-Message-State: AOAM531MSIujuPaU24jBmUh35kvGXVEwRTBxyre2gYVOvc76xxmmxFzR
	dB6Vi4q8DDyv9k7FC2kIrgw=
X-Google-Smtp-Source: ABdhPJwQwEJZiz3UXRq2NDA+udaoMe9J2PuYC9+3ZGTYFbgvkfqkl8mB8FSQkS5VYW6O4WaXwYD2JA==
X-Received: by 2002:a9d:875:: with SMTP id 108mr3086333oty.243.1602675780929;
        Wed, 14 Oct 2020 04:43:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:119a:: with SMTP id u26ls704022otq.6.gmail; Wed, 14
 Oct 2020 04:43:00 -0700 (PDT)
X-Received: by 2002:a9d:3626:: with SMTP id w35mr3274228otb.206.1602675780598;
        Wed, 14 Oct 2020 04:43:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602675780; cv=none;
        d=google.com; s=arc-20160816;
        b=HYLGA0smYgTLYQpoMf6C1/eo3WOQA/2d22YzZ+fi05v1SHaVWFnZiiUpmT9vtlNybo
         c+z4BCYa0Zi1GWYnOP0qemtQhXHoL6eyXZvxjI8qM9VrxIXFfgtz7AHx7RriN1IVa/sm
         TP1p3UptM4sH3qWOvkaHLsciYR7tsJnWhcUTQHQgBBRDCLs2NX04FOAh2+L/aSGy7Oab
         cukSNKoDTOXQZwYh13ZZk0+JFnAqUV7xDcQan92ONZPV6TXIGfwou4fRU2rF1IGNd7ll
         S5Zqrkw9FuL4gAkNgbiWOHhScG78sFDzKGBLRwRNftGj5U6J54NyacJ/WZluXKmKQrK5
         4BUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3X8oKwPinLljLozk2oIqdaO/ROpHqL/aaYh9BBnOL40=;
        b=m7x7iYzELk+ExEfUQJ5qnSDRBpQk4ot7S0rXJGMZUqKR2+SUFvnAIVpQaSzeICDYRe
         BmiKpWbq3R3RAeCfEuvdXev1XYmB8spvQ5RKMyZJ9dA/aAKIHpBleMRlw7ZwlrsCc76W
         jTX6NAvVV3jhpPzsTbJen9a219xkRxzDQcBH0E1DDRZ1Ae2Nnbh1SkiCB7ucBGzFkj0D
         WGEAzpjpNH0kM2PyGvM5KrgatXTs+x40wWFHunDc21Vanjt6EIdbirrAuIMeNwj9iudB
         GVukzKudEPafUTz+QpaV6JmxB0D2AxsZgpioVnulsqnCu6cuTHF+OqXJZ+kfvaoN3pmd
         SBlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P0Kg5kw3;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2c.google.com (mail-qv1-xf2c.google.com. [2607:f8b0:4864:20::f2c])
        by gmr-mx.google.com with ESMTPS id n7si194164oij.0.2020.10.14.04.43.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 04:43:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) client-ip=2607:f8b0:4864:20::f2c;
Received: by mail-qv1-xf2c.google.com with SMTP id s17so1330676qvr.11
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 04:43:00 -0700 (PDT)
X-Received: by 2002:a0c:80c3:: with SMTP id 61mr4525327qvb.13.1602675779795;
 Wed, 14 Oct 2020 04:42:59 -0700 (PDT)
MIME-Version: 1.0
References: <20201014113724.GD3567119@cork>
In-Reply-To: <20201014113724.GD3567119@cork>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Oct 2020 13:42:48 +0200
Message-ID: <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
Subject: Re: GWP-ASAN
To: =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=P0Kg5kw3;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2c
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Oct 14, 2020 at 1:37 PM J=C3=B6rn Engel <joern@purestorage.com> wro=
te:
>
> Hello Dmitry!
>
> Thank you for your talk at the 2019 Plumbers conference.  The idea of
> sprinkling a low rate of instrumented allocations in is just awesome and
> I have implemented it in our own malloc fairly quickly.
>
> What I haven't done yet is create a variant for kmalloc.  There are a
> few things to be careful about and I simply haven't found the time yet.
> Do you happen to know if someone else already has a patch?  It doesn't
> have to be production quality, I am happy to take prototypes and
> collaborate on improvements.

+kasan-dev

Hi J=C3=B6rn,

KFENCE (rebranded GWP-ASAN) is right under review upstream:
https://lore.kernel.org/lkml/20200929133814.2834621-1-elver@google.com/

It's already production quality, just last nits are being shaken out.

Thanks

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BZ%3DzNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt%3DEnA%40mail.=
gmail.com.
