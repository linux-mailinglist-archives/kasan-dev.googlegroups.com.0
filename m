Return-Path: <kasan-dev+bncBDW2JDUY5AORBIMEV7FQMGQEA7755DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id D1721D38FF7
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Jan 2026 18:08:51 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-64b8f91e4ecsf155215a12.2
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Jan 2026 09:08:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768669730; cv=pass;
        d=google.com; s=arc-20240605;
        b=e3IlVvG24CvjelGEz6l2B29LupO6APMWjFPU6vIoUsi8Ea9hziCSrQH19nHPZE5xiO
         mvIvIT0nSHiS/z/FTBcHJfmtFweGAJXZJG69WzxC2FnubbvK20J0RfM67LTVfE9zRQK2
         09UjZu8zjmrxCEVY0m/RU3992HWr154i4E/0WWInLSovGl0qmy5/jVj56PRnl9Wky5HJ
         4tc70BoLG9FgKIeFcjyCg3Br33+Ew8vCWen+dWEsxMmhi6PhFTUaPy4Big/VU5oHqSh5
         0DauBejZp2phGNmPg2ujGbB8zREBdSl46bx4ejILEyU9mkXCFYNUfFJMBo+vpPVwIoiN
         9zsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=VMl01IF98HNaq7gqYqPx+Y6vBUWz95oXsYDutH0gI0k=;
        fh=GmUZMWuYjtOfExduQMU9vhib0NSXuZov2qCIsPQ6/1A=;
        b=Ok958VplHVdmoE8SBHImX4H1axMn72kmeJbS0R7S1TfCjWXUD4UVhnUhjRRC8oMEdv
         kh9i8KWDUOKcqIyGUpx2GCxPelIfXJzQEUvf8Gw1m4BtJVkK3jBo3XXizbvhhTmPUFpp
         cEDPFAclmvbBQ2F+bAK9p6X/b4KKqBByO1cvP89A4kll5AkDxwStGVL9GjuJfgL+lmWA
         kNl1sqdkFu6LFTEdFXoEdQ+ghhTRAYnXUBT6Ba+nSx9PudgkUeahexlJLh9V1TalR+bA
         1Zlr/7UBYH5dbVarCRGBp1zjOKde/d/ouANPIK8HLSukzN6IyyN2LB0rY6YixCEZx9vq
         nfCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=L+6E0b6i;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768669730; x=1769274530; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=VMl01IF98HNaq7gqYqPx+Y6vBUWz95oXsYDutH0gI0k=;
        b=pU4gXcAOhcnKJOS0XqL8iwaU4onxGtvs0MGat8/dVzrtIhwpUnzFclsSaEvsTFFSf6
         HL0Aj+zX6guLdO2zb8hVELu6i2U6+FscP7cIUHj1ygCSDhZmH0cUYC6OV8Zp+tH40NpO
         HEHW2qHnn0uIOEIZ+rEqplQTpelyUmIWaVLT4rAdnlbo/cirCZhym789tTCfNc37WIxu
         1IcjD4EeuiuCLbERnvffEdEgUF4f6vyXcjZSL4UHR9173adG+aQjPriw9SDgtEk0ea0I
         1TF/ciC5KkajDHV42tJTDqBcY1wK53rGkOwB2Lcs/BQLgb3UQcp1eZAyFgmQPyqPblGS
         t9/A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768669730; x=1769274530; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VMl01IF98HNaq7gqYqPx+Y6vBUWz95oXsYDutH0gI0k=;
        b=AUwc5xYzkJpLWt3YBo1Yxf7McVBYeZwMTDwAxYg4/nO56fBAO/BXByL+csnTAjhCtR
         Gj2/RTHY5E5V6Fe1EIOOdg2OrEaNtudGDn8Vla9eZf/vZD9og8+z4mBjYZ9KuByYpIvL
         n2K/Hwvf2vDK26IgacJx8eDkQyk9ZXiI5Y4ma8Vu/wkHurtxd+oJEb8TxJzd9bRU3T/w
         AOGnPMprFJsksCyX4xrKxMJAMLoZtMv+u1DlLJejjNESykbNPVTXDYpniIzl2zzTYIn6
         zn91N4ngYDPTefMr4jCtFVLeeArAu9eNyv1fM9WYZ2IybETPFTvB9SnFgrVScIhmpVfB
         u0xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768669730; x=1769274530;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VMl01IF98HNaq7gqYqPx+Y6vBUWz95oXsYDutH0gI0k=;
        b=hF/11ghpn5NO+/vF5n156h/8nTey0wDyp7rGhOunc++diGH6tfwfGDcARA9VCDLAOq
         UmTV6al5gjiGnXP7WUDyWnVlnwjO+bq9RA82qmsfccFcLNXoNTUnr2hz/juqppRtarDb
         hr2vtCM+DvhptzF7kmPMpz2Y2jGdD+GoZgHhxPMZts3A7j/fTYsxrmy9ybLsJyUttB1T
         Jl7E8XmPDicMBsjYRSu4LAG547cIW/GulCQegthHhiFJJo0nECwiJ1Dhp9bjPxfuYqSf
         Ednj5pk64I7QjrYKeJ25obWQVaPwV0yda7b/er7CQ0F9BAc4FsQ06cyESmRtJHQ3CdiO
         AVxA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUSKkVFxnBicyEgAxZWziXFeYc/ICvVepC94yuedayDXuFwnKc8AJgN5PFtjnvFUY9yTqe4DQ==@lfdr.de
X-Gm-Message-State: AOJu0YxoRutiMnoyMOrCbt3PfHn05uU1hLuXh6RUnggZ0kCTd7YPkjon
	pUSk6qkkMp7tL8YY3EgD2y7xW3WUc2Q0SM1YXx5EQBrJgMdphyC9cjdl
X-Received: by 2002:a05:6402:520c:b0:64d:23ac:6ca6 with SMTP id 4fb4d7f45d1cf-65452ad0b19mr2814790a12.4.1768669730030;
        Sat, 17 Jan 2026 09:08:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HIedlPrUlwU7fC1/jStbhXHwMS95P3A0DNlKb5qNDgVg=="
Received: by 2002:a50:9ec4:0:b0:64b:7641:af54 with SMTP id 4fb4d7f45d1cf-6541c6d8088ls2360300a12.2.-pod-prod-02-eu;
 Sat, 17 Jan 2026 09:08:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU/C5DddjG+wq3B9p6nYdhBvLu2G5dkESXdyx0JX4gtMcOM042XmMIMnJckzyPjkhM061dtAinI09M=@googlegroups.com
X-Received: by 2002:a17:907:84e:b0:b87:33f3:6042 with SMTP id a640c23a62f3a-b8792d3be6dmr574404066b.9.1768669727767;
        Sat, 17 Jan 2026 09:08:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768669727; cv=none;
        d=google.com; s=arc-20240605;
        b=ilrgVGZOJTeF5Ieku+ogiqYcWBUg+g3HCaFPplaNzTpn2JH5/lQ50C/pJpfDBXdnAx
         ZhqTruQsRl7FnzAGfWzW+x3FQ2tW+A6a03Zb5pSoO/POF5HEiHTTogImNT4x0UmePZPq
         LUkuY3Cj4G9+HVtpKyuaYSyKZYnrp6PV7aZebWBPD+XtuEmdNxp7P958tV9ApZqZoqBN
         NfyKNGxW05L909UrU1tVqsVr2VQBtdYqLY2DRAZEWVH/BwHN3N1wl18Ld9mFpyqFBiiS
         yijnANHbZnEtBfDk4kYAe5SN9Z6i+U68kuLrjU7vbKywTGdQFey89npKqJ56BRHpkIIw
         6S7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=aEphG+uJA/ZTSP7N9fDLUX1nKXTIImKyAsN5fw6sI/U=;
        fh=CSIPcs4szk2569iiEYhTiW363IDdUNntppxhkyOpBZM=;
        b=ASaEs066zGXL9jQlqZhyN44GADbbS/t66wDcGfn6GW9FB0+AIT1jUCLp5yfzFbUzqC
         WVOrr5aEwo4Dr92/dXAoEgJsDSxv8vCvEurkvJ7g+7UK6hYkVy8L1XSj9K8CO0VzZUzz
         nXu2qbmtndkvtPpFQzSqZ1Du4VxStApgQDR3opBUXD9oIITI0VLrPEgBMofhbYsLzzer
         XPY4ejJYXdKIw2WVWEvHNeWhP22rxJEEsLr4hb/RxqImU/VAYhxWg06/eJBGsB9BuQFm
         6l4QH7rIfcSzSxCGeuKuIUCDi7KJE5ukvwXR0DYQw7YkwhEbL36P70Z/MAbThW/cYtZM
         7DcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=L+6E0b6i;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-654532cebc4si136313a12.5.2026.01.17.09.08.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 17 Jan 2026 09:08:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-42fb6ce71c7so2742773f8f.1
        for <kasan-dev@googlegroups.com>; Sat, 17 Jan 2026 09:08:47 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWZuwe7XWfYuVx2kJLzcYZIEVwd8yixUyMmvSc+CRb9hdl9u4wSlbDDJYS07jZsQ3EhSeEBILJt4OY=@googlegroups.com
X-Gm-Gg: AY/fxX51wXi/44T5ntxLtXTkeZ94SmQAlHfEB0q4YzJjHy6+IzvX3CK8jJlhbAe43SK
	pf9N6JBYxVMwaBMPXDYWBx7EeRcd6bCOp6zPDSlQOENuU15gTYzknQ5u0hq19I0V7NygZtAnmQx
	auYN6P3lOe0WNj2/QA9D+9o7eOoOxAVIOiBDs19uZdjGCq7Srqa88Y4BemzMe/oPxSBgt/y8ZRd
	eqaLYUadkPm8ffliFHMxeHcYTFsDID2e+zQ0FfkMuhddTvQlhwbXI1bmB9v9k2tOdRnst3g/2rU
	89GTJPhi0pM577CqVZbF63c6KiaRlg==
X-Received: by 2002:a05:6000:2910:b0:42f:b3b9:874d with SMTP id
 ffacd0b85a97d-43569bc4a81mr7718897f8f.37.1768669727114; Sat, 17 Jan 2026
 09:08:47 -0800 (PST)
MIME-Version: 1.0
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
 <20260113191516.31015-1-ryabinin.a.a@gmail.com> <CA+fCnZe0RQOv8gppvs7PoH2r4QazWs+PJTpw+S-Krj6cx22qbA@mail.gmail.com>
 <10812bb1-58c3-45c9-bae4-428ce2d8effd@gmail.com> <CA+fCnZeDaNG+hXq1kP2uEX1V4ZY=PNg_M8Ljfwoi9i+4qGSm6A@mail.gmail.com>
In-Reply-To: <CA+fCnZeDaNG+hXq1kP2uEX1V4ZY=PNg_M8Ljfwoi9i+4qGSm6A@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 17 Jan 2026 18:08:36 +0100
X-Gm-Features: AZwV_QhGpsGfhcwUuOSjH1-DI0GRyW2mW52xb_iVw_QKkxgQTpbCVoSbyZvTIyw
Message-ID: <CA+fCnZcFcpbME+a34L49pk2Z-WLbT_L25bSzZFixUiNFevJXzA@mail.gmail.com>
Subject: Re: [PATCH 1/2] mm/kasan: Fix KASAN poisoning in vrealloc()
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, =?UTF-8?Q?Maciej_=C5=BBenczykowski?= <maze@google.com>, 
	Maciej Wieczor-Retman <m.wieczorretman@pm.me>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, Uladzislau Rezki <urezki@gmail.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, joonki.min@samsung-slsi.corp-partner.google.com, 
	stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=L+6E0b6i;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::435
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Sat, Jan 17, 2026 at 2:16=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Fri, Jan 16, 2026 at 2:26=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gma=
il.com> wrote:
> >
> > So something like bellow I guess.
>
> Yeah, looks good.
>
> > I think this would actually have the opposite effect and make the code =
harder to follow.
> > Introducing an extra wrapper adds another layer of indirection and more=
 boilerplate, which
> > makes the control flow less obvious and the code harder to navigate and=
 grep.
> >
> > And what's the benefit here? I don't clearly see it.
>
> One functional benefit is when HW_TAGS mode enabled in .config but
> disabled via command-line, we avoid a function call into KASAN
> runtime.

Ah, and I just realized than kasan_vrealloc should go into common.c -
we also need it for HW_TAGS.


>
> From the readability perspective, what we had before the recent
> clean-up was an assortment of kasan_enabled/kasan_arch_ready checks in
> lower-level KASAN functions, which made it hard to figure out what
> actually happens when KASAN is not enabled. And these high-level
> checks make it more clear. At least in my opinion.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcFcpbME%2Ba34L49pk2Z-WLbT_L25bSzZFixUiNFevJXzA%40mail.gmail.com.
