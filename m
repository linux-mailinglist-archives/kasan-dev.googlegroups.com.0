Return-Path: <kasan-dev+bncBAABBPX7YTEQMGQEWEOMXEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id AFDF7CA2B9D
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 09:01:03 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-42e2d5e833fsf323949f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 00:01:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764835263; cv=pass;
        d=google.com; s=arc-20240605;
        b=lWrexBTANOI8WWkyKjIfR9vb+rRPSCv4d4KGauqvIgnCTaAs3hfDrziTwd4qPwJRP9
         h5/iuXgPx0INQNVDXZXTKhvFPxQo5pukkVKzeIv6t5+xxxsXIWH+84bZecLLkkf4ca7+
         ir3cuShgbF1HZ/NZ6Gt8IpJvZTnD3rKpglZtmiYdOiqlRozkEcW6XI/sQEArxE+zmh0B
         i2GSvVYy3FwPwlFAP9+KBfFCpCYbEjAFmfVQfLAJVURVv9fWJLLrnAE5CMOE/Ieb5zps
         R29Ob+gltGG3F7YRPGuHZZS9re75GvyGMCM0TSVBwj5dt/U02YE86qT98nA3wSzZSF3c
         kF5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=PvjgByWX1vrrp0BBwrVTHvpo4Se0J5IhrqlxqBUDfQ4=;
        fh=Xl1PKTnsx2ONYWPoiS6Dkze37bpnNZlZBi285SNf2rA=;
        b=BrkvXmdHcq3wOn9GOR2Uxyjy3egOfnb0E9rTY1KYbbzdhUDaTzZULOi+48VLzlPHtA
         icS8Wkwo71LSQeAjoXobN6L0sW4qdWhPf6+EUCYExbi8ZAXISmro9sssLRj2gsJQXKMx
         +7afd1G49AjRXxlMT5J2tS7/yEjMeofUeOqZcdd4RbYHPXxDHPloN+oX9kX2RwQwagbZ
         4p4xA71+4s837xaioxQ65OTQzhYaJyoKI3TuX9wGwKWAQf5vEmg1+Ez5Lic08cf7mPEb
         RWaI3sSSdhPSbJRvXQyMqvBfR5TKzmaw3UmcA69g/o6Cac12C0ltCqTvhN5lBCjlpqmC
         dPsA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=cKTHayI7;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764835263; x=1765440063; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=PvjgByWX1vrrp0BBwrVTHvpo4Se0J5IhrqlxqBUDfQ4=;
        b=FV56C/yIag2Gd6FwrXZCQaTT/3XO7gR9od531YTi3B9mHFOO7VnDQMJ3fWIbfzkKaQ
         iS0ApzQ/PGxTgmh0NAYr7VFXe06qDQPEAympQgY+cPXuOvwJ5Z4ONE0YVNFgXki4/6Wt
         d7u2z9zo+Ci3ONmdW/DZ0GP+bg+NVHqkxQDcFSawDYmqergTuFINRiTwnrG7GcVUjqlF
         6vwt70KarKZkjee+u3nxGaFeEm4aRCuDa65FDooNp1wscCXNPukSNK5jPhL6u0qhlQ4j
         JoTFqTxRdN09wWRKaU2clGv4nwYLA5BIGNoixcrfwmeNXocgfJMtlVxjNXmhHd4wJxcs
         YARw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764835263; x=1765440063;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=PvjgByWX1vrrp0BBwrVTHvpo4Se0J5IhrqlxqBUDfQ4=;
        b=wKOWDGvxFEZSHNeJq4SWAvzBYUTdmRYDEfBcWBaeTaB06sR1jfWhSyQ1SLkaWlvYJb
         taiDYoMh2hgZXJDWkze5E9vCtr9ipVGnYTVkiN+H5W04T9A+1eHZ8Gr31mTszUeq83Sq
         U7Wnd8O0Eqe6Hod0NGwIy7uXQ1qdExtXOjKIqBIPYJhl+ATeOI9KhXePmSaPLVsBDmQi
         NRRkV5kP+EEPEnsqkvXjJMs60HZ6gECZP71/JINGA+93NC3LWid2yUWtqgNfV2hARx4o
         MfwvBHTgb8t+SHz8RFjDSrW3SJRfgBnSqTzqKbv+XHAe4swWJ39+1/658FjSLtJ/6uke
         cNEw==
X-Forwarded-Encrypted: i=2; AJvYcCXxyu+UUd9IuDH2bk9eAm/RsjSVABMd9qRfziAZLpbu1RW6KQ7WpdXmesN9iXHgPnLhC5S5CA==@lfdr.de
X-Gm-Message-State: AOJu0YwyFCVUFs2A/F/CZJqdqrlJFBhpFOYUtVYLYjKIy4pbsN9dlboV
	xTNyie0JAnA/X3OWkwNnZYc64gUTm5lgpkYYFxTSJPvBxd37yk0OYb3u
X-Google-Smtp-Source: AGHT+IHzMMADqvBul5uBScQ1LEV3BOWTA3F1XfJY5XDoXfn1Q6xxS7A0/z/RkBXSmqW9/vl+dyzSxA==
X-Received: by 2002:adf:fe4a:0:b0:42b:41d3:daf8 with SMTP id ffacd0b85a97d-42f73196803mr4076666f8f.18.1764835262818;
        Thu, 04 Dec 2025 00:01:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aqK385I4urmlku4oBx49QS89BQ5Bdz5GxObxPHOF+mNA=="
Received: by 2002:a05:6000:401f:b0:429:d66b:509e with SMTP id
 ffacd0b85a97d-42f7b2cea44ls202227f8f.1.-pod-prod-03-eu; Thu, 04 Dec 2025
 00:01:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCULxJ61R7TzJw37NMBRYYaE4W3HN5wujMTaIu3+gn9ixVKsbzo6pNHgcF1N4hXI3IxWArdT2kAEmNs=@googlegroups.com
X-Received: by 2002:a05:6000:613:b0:42b:5448:7b11 with SMTP id ffacd0b85a97d-42f731e92f9mr4787727f8f.33.1764835260587;
        Thu, 04 Dec 2025 00:01:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764835260; cv=none;
        d=google.com; s=arc-20240605;
        b=ZsBCztO2gGxJ8ofNuSvodzTTDMfmx82rAKHRRSAZmwa0fVA2nw3aB2JlCWIbTWI8fC
         0ZN5F30GQ59fgc9fuIwU/woA2l89TRu3iRPiFtPyP1wRiIKkXOW5M1TnggD9GfkLx3nK
         vcaSyrThFOW0obXVUPGL6xKckv9gBFJ9bOgILETc7LQuApEq648jcEYoRLL/pbbxXfnu
         /gpuW/6ivxno3XbgrmIMIk5SXLCaGrRQ57nA44BuEy4S6op3g5FzkST4mcm8mFIhnQlz
         aYAAwnQgiAkNIeFl3RXIo1AqTNHA6qSxOdcBpmcCCfAIaIOOqnrqfMFQXL7sntvObnwH
         QWaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=i4FXTFHzuPffFYRyp6V0hVOyP7tuWfTZncVwhcPuX9A=;
        fh=QzcK2Dcdv6K6M4pd0fn+L+4VbdC8Fq6FyGZNcuDHObw=;
        b=PwHs3vaIVNVOCAp3OJkr4msYX+qQYy7QXNqzVwVE2QWIc8ddWO9mtR2t9uRA2wNxwp
         Egjt2CnKkcsHa3OOxq+/JE7lB3ntTkebTZys24kQrYqrp/d190Zlb4O6Hro/b4SWd0DS
         EhXs5YHo0auwro6kshgglGL4TnZKzgolzX9Ldz0YeZoCW7jhSzUYsqOwEw/HeErg49W7
         R1m9DXP8R23nzd+tdbzmHBAhwq2uzzn6noD0rLxd3SWVPEDfxIHXCO3prXC88RR4pmcE
         7XcrBEc+DmfrH8q9XivKoqav0RtY3QxvCdJmuZ+UVArSVkM6ptSnk0vJAIzVnPzebikG
         ULlw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=cKTHayI7;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106121.protonmail.ch (mail-106121.protonmail.ch. [79.135.106.121])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42f7cbd41f6si10618f8f.1.2025.12.04.00.01.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 00:01:00 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) client-ip=79.135.106.121;
Date: Thu, 04 Dec 2025 08:00:54 +0000
To: Andrey Konovalov <andreyknvl@gmail.com>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: jiayuan.chen@linux.dev, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 2/2] kasan: Unpoison vms[area] addresses with a common tag
Message-ID: <yb3cniky6tpgwmdkp5652dzrbkkplkzsrywl76borcb7b4zmya@s4smffgybwgf>
In-Reply-To: <CA+fCnZeCayQN3448h6zWy55wc4SpDZ30Xr8WVYW7KQSrxNxhFw@mail.gmail.com>
References: <cover.1764685296.git.m.wieczorretman@pm.me> <325c5fa1043408f1afe94abab202cde9878240c5.1764685296.git.m.wieczorretman@pm.me> <CA+fCnZdzBdC4hdjOLa5U_9g=MhhBfNW24n+gHpYNqW8taY_Vzg@mail.gmail.com> <phrugqbctcakjmy2jhea56k5kwqszuua646cxfj4afrj5wk4wg@gdji4pf7kzhz> <CA+fCnZeCayQN3448h6zWy55wc4SpDZ30Xr8WVYW7KQSrxNxhFw@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 25c7909c6bfc2f467818931ed514a481d5a0ae37
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=cKTHayI7;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

On 2025-12-04 at 01:43:36 +0100, Andrey Konovalov wrote:
>On Wed, Dec 3, 2025 at 5:24=E2=80=AFPM Maciej Wiecz=C3=B3r-Retman
><m.wieczorretman@pm.me> wrote:
>> I was sure the vms[0]->addr was already tagged (I recall checking this
>> so I'm not sure if something changed or my previous check was wrong) but
>> the problem here is that vms[0]->addr, vms[1]->addr ... were unpoisoned
>> with random addresses, specifically different random addresses. So then
>> later in the pcpu chunk code vms[1] related pointers would get the tag
>> from vms[0]->addr.
>>
>> So I think we still need a separate way to do __kasan_unpoison_vmalloc
>> with a specific tag.
>
>Why?
>
>Assuming KASAN_VMALLOC_KEEP_TAG takes the tag from the pointer, just do:
>
>tag =3D kasan_random_tag();
>for (area =3D 0; ...) {
>    vms[area]->addr =3D set_tag(vms[area]->addr, tag);
>    __kasan_unpoison_vmalloc(vms[area]->addr, vms[area]->size, flags |
>KASAN_VMALLOC_KEEP_TAG);
>}
>
>Or maybe even better:
>
>vms[0]->addr =3D __kasan_unpoison_vmalloc(vms[0]->addr, vms[0]->size, flag=
s);
>tag =3D get_tag(vms[0]->addr);
>for (area =3D 1; ...) {
>    vms[area]->addr =3D set_tag(vms[area]->addr, tag);
>    __kasan_unpoison_vmalloc(vms[area]->addr, vms[area]->size, flags |
>KASAN_VMALLOC_KEEP_TAG);
>}
>
>This way we won't assign a random tag unless it's actually needed
>(i.e. when KASAN_VMALLOC_PROT_NORMAL is not provided; assuming we care
>to support that case).

Oh, right yes, that would work nicely. I thought putting these behind
helpers would end up clean but this is very neat too.

I suppose I'll wait for Jiayuan to update his patch and then I'll make
these changes on top of that.

Thanks! :)

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/y=
b3cniky6tpgwmdkp5652dzrbkkplkzsrywl76borcb7b4zmya%40s4smffgybwgf.
