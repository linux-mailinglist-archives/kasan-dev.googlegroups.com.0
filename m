Return-Path: <kasan-dev+bncBC7OBJGL2MHBBL4AZTCAMGQEVPFMMPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id A73C0B1C106
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 09:11:45 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-3141f9ce4e2sf8983870a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 00:11:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754464304; cv=pass;
        d=google.com; s=arc-20240605;
        b=EYzw2w4EIE0yFM89ldwXc9phGYXw9t/dGs3gb10asHy0mVI/P34pbIC4CJVgb9cfLk
         VsTCxxMKFEiZvzQW6paxvwwzG018zVItC3V4Lv/7BTFt8P/h6a0FzFfIH8vwHwLoxfKN
         2T259fVp3fPMt9vIbPBL2kKSPE6Gi1a7WrxmatJdMQYtZzTrb0E/h9Ikn3nCTWW9s6VM
         xvA+7RoxTttp3B36sAEiQJhpMzXBMF6IRCEx7VyaCPHCdMdH4e60A7Kj/AXy+/abAbpD
         +KtBFUqFWw1hTl6nnIcqhN1iMBnpDK9G0RjqgAcDIwUsk5Xd5tZ9yhJjR/jOErtKkK5f
         8V5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Nb5B4tKS70FkC6lZ+2QaKIOFJlUv0LppM5LcRIb6vzM=;
        fh=gbtBcbAv+aFvE6Zta50bTrKwD9mX+AhSIzDxpmG8OY4=;
        b=juJh00zIncDTFYm+PDmE2rkflAh8LMEULDdECK7fhVQQjuAdEiBKx0mIzD9DIHvbfj
         rLe40GUBtUSUSlkxm+h/HO2r8yI46bV4SsdzvPuZUBhlZm0cD8TRoGxc87GuiML/wb1F
         0V72VOjM6uLG4/0loki2U4ZYnptWaNmVQkSSqN9CNIKv+wLS7ya2BpSA9xuP1GGyX5Ur
         ejfm9nnorVdZghb2hGc6Rb3qhM/+IxRmfp6SkoufDpF/w+ye+ru78hN2k4RP0bLb/rWP
         saYZ7L183EVMUAolEq9YPVBla7hx3WWH6MMgXMuNPiUWYGBMP0N25N+YUNusFe7kXv6y
         c2Tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yhvyOX+X;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754464304; x=1755069104; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Nb5B4tKS70FkC6lZ+2QaKIOFJlUv0LppM5LcRIb6vzM=;
        b=tnPIH3GzmXfrHizy+ZmnF6G31CRiJm4FduOCnwrm/1CdT293ZlyUtUtuMyv8k0E/G7
         lREoxvR72Ky7NjOuoo6ABcVnyTWX/R3Pyzq+2myKspEXIfQaM/ZySguHuCenJMkPqJJZ
         NmBcxg89dBQVr4dnZ/KYBWg1HBqInSC69ouPz9WGHbxKmpyBX4424KxhfKgHY8lm85kL
         nHjHy8IyEkAcYV0Ln4n95+KCQFypFspDPGqiFnu+TPiSTS1j3UVHvcKQHBSuprtPUBcJ
         XOD5Ojm2F8JCZ4k5sRicshiFgJJvLA6EXoNHX2yhyv5eOCBQO/O+hl7y1BAzBwuXpxbX
         IG7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754464304; x=1755069104;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Nb5B4tKS70FkC6lZ+2QaKIOFJlUv0LppM5LcRIb6vzM=;
        b=fXdWHMDlc1fEMedzbdUUX+WwiMX92VzruR5dF92ZpCZWQGWW7zoaBD79Cyt06RfCqP
         qIszEsjJUjMuw4wNRZT3yPjUsM/uPTQkBb9fOTls9Ez6xz5ua2JKJ/wDIPHPowou1bpM
         XU2+1CRnHfsVT2238tqgqTW/m+JWiVlooD3DlRE/3diKCAaHCGPdkC6VFOz7ltmGlaGV
         08BUuHA98bhTPFzqHyxdlwzaFqTp6LUYWOJO3AHleA2kozC696aKX8Xdq5dBp3IdhAJa
         ExzOnRuFfQt2bYg15fkJkj4p/YvTyGQuETs2PWflfAWk6aodA/SDmROqlP/+jOnyKqUO
         rvLg==
X-Forwarded-Encrypted: i=2; AJvYcCXSAI8vZiskwjSqRdfZIMagICPzlckf8VLsbOTgVPjFSa7xk0SoVFMMPZiyIok0fjLdHFBRUg==@lfdr.de
X-Gm-Message-State: AOJu0YwbW+g49F87lKXhxmFhx+0sBNE0oXwGQZM/r9vwC5rk1KozGZF5
	ILUt4m8sf/SeF3jhtMKJmrLmXhczuFeNofwf7upq0bBGclr8ypLxwxt5
X-Google-Smtp-Source: AGHT+IHeXJ9+BLN2G5795mafJYHzjcL8rxo5hi0YeLv1PJqL8Loe6m2O4oBUDzngI/Y6o47T7kS0Gw==
X-Received: by 2002:a17:90b:4a0e:b0:31f:eae:a7e8 with SMTP id 98e67ed59e1d1-32167104f94mr2274735a91.11.1754464303716;
        Wed, 06 Aug 2025 00:11:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdArTlOLin/td5AgRHyHwAXFHIpU84bPKA68AOdthisKw==
Received: by 2002:a17:90b:4cc7:b0:31e:d9ef:bdc5 with SMTP id
 98e67ed59e1d1-31fabf49167ls7656113a91.2.-pod-prod-08-us; Wed, 06 Aug 2025
 00:11:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVBBO/VLF0/2rM8Ww87seOm24dkDrM1IVwywr4l27LgzvYLHdE8NEXmFJcGpl4uy9dUNvCWaIF+eDw=@googlegroups.com
X-Received: by 2002:a17:90b:5645:b0:31c:23f2:d2ae with SMTP id 98e67ed59e1d1-321673f402cmr2486920a91.15.1754464302303;
        Wed, 06 Aug 2025 00:11:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754464302; cv=none;
        d=google.com; s=arc-20240605;
        b=jBMmykCWApQLYt5nXwFgN/e8zjqQIaa2yPJTShU96QVYztiGy0b4neJIU4r6qBA6GH
         CIyp9ILyQGypsVm3dgj9fSx5MvE8LO7JxpL2LHOVDWGemoNUDLLT1lc76GkEkuQ35EXj
         QKMdg4OypnQvLdsDI8z0tZXKoJbyMN6CqmYt0QS/Zqzeu8sYzzbQBqjfeUWJpnpZDJD5
         Sy8ed5+ggQ+8m/+S9RzqvanuUpUMvh1ZWstnbaLPvrCDEpqv7FGAVVRluWr6DdvR9C5y
         BjjWkWCAIwZPB6EMbA2Q8z23xPV7qQKe/BfPNA8LSGtSWc2w0Iy13OYlZ/y/XTcEDllS
         TOgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CIQROcvGNDvP322fenFV06FYLfCBAUlOFBfGGGTH+sk=;
        fh=4hh9bixbTiw2Jj0taOuJgsbxy9BkKf9liR/1JctGa5U=;
        b=Tu2hXiAhpPRXBf94XUGw0aKF0+ZphIJn7APh6/1RaBF1LtfgZwjNGWiIErtzJuhoyK
         sijeo9i5CBWFzh8Lnywcj7pppnktAsETTYYTfma0o0BH56wv93mz07cEsufMATXv6y27
         ev+AtA6TPJlaudXdU5m8smxun7aH23T41y+l0Gz16kGhdhzAYL5FRgvU6esJp70dyykt
         nYRE4d9Yht+I7xLAVEeQ0OIlLPaFWI+YQn4+F6sD4gXzQQnmM76AjpgdcFOCOGlUt2uh
         +rNq/jZExOXM314hqGetkulnNj4CgUb8eimPsy2S8U7OPe+3fEGli0qpG5SoJiuNcrHK
         FuqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yhvyOX+X;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3207ec5d581si744565a91.2.2025.08.06.00.11.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Aug 2025 00:11:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-73c17c770a7so5990212b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 06 Aug 2025 00:11:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWW/PGE/+b8rafE3617ygVQikXDYUfbpbWB7spOel3l3WyETHe8rY+rY/0SBI2WCUZX6scO19PWweU=@googlegroups.com
X-Gm-Gg: ASbGncsENc7B+xEGhGBzWT2uAu+7FRoxS5UDvWkqBsyiIT9MSnSlDyRUO6eO7EHIoxN
	YnxULsMaxi90gh06IE0tnA1XvXhlsWI5+Qu95EvWr8q2QjIc47/bpbr76nfh8fplzmow0DVBVew
	VrnKYDaneLSqadk5L8nEhC4KI3YD4v9JgKJcerpIjgSaTyrIUiD/GYNr1Sw97XROu+Pnh373QZp
	7p1RGezGMpUyMsMpKoUanhQdUNFxwCXudWDepw=
X-Received: by 2002:a17:903:3c6b:b0:240:3bb7:fdc3 with SMTP id
 d9443c01a7336-242a0b6eac4mr17702345ad.28.1754464301762; Wed, 06 Aug 2025
 00:11:41 -0700 (PDT)
MIME-Version: 1.0
References: <20250805062333.121553-1-bhe@redhat.com> <20250805062333.121553-3-bhe@redhat.com>
In-Reply-To: <20250805062333.121553-3-bhe@redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 Aug 2025 09:11:05 +0200
X-Gm-Features: Ac12FXwvxDclvgbX00BaC4VbF0Z298SA2kuazPxeIBtYynYYBydJBukUdCOs9jk
Message-ID: <CANpmjNNr7e6DXQrZva8k46jELr1JSkjExWvQOyrkY5VD8mOadw@mail.gmail.com>
Subject: Re: [PATCH 2/4] mm/kasan: move kasan= code to common place
To: Baoquan He <bhe@redhat.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com, 
	andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
	akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=yhvyOX+X;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::42e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, 5 Aug 2025 at 08:24, 'Baoquan He' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> This allows generic and sw_tags to be set in kernel cmdline too.
>
> When at it, rename 'kasan_arg' to 'kasan_arg_disabled' as a bool
> variable. And expose 'kasan_flag_enabled' to kasan common place
> too.
>
> This is prepared for later adding kernel parameter kasan=on|off for
> all kasan modes.
>
> Signed-off-by: Baoquan He <bhe@redhat.com>
> ---
>  include/linux/kasan-enabled.h |  4 +++-
>  mm/kasan/common.c             | 27 +++++++++++++++++++++++++++
>  mm/kasan/hw_tags.c            | 35 ++---------------------------------
>  3 files changed, 32 insertions(+), 34 deletions(-)
>
> diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
> index 6f612d69ea0c..32f2d19f599f 100644
> --- a/include/linux/kasan-enabled.h
> +++ b/include/linux/kasan-enabled.h
> @@ -4,10 +4,12 @@
>
>  #include <linux/static_key.h>
>
> -#ifdef CONFIG_KASAN_HW_TAGS
> +extern bool kasan_arg_disabled;
>
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
>
> +#ifdef CONFIG_KASAN_HW_TAGS
> +
>  static __always_inline bool kasan_enabled(void)
>  {
>         return static_branch_likely(&kasan_flag_enabled);
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index ed4873e18c75..fe6937654203 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -32,6 +32,33 @@
>  #include "kasan.h"
>  #include "../slab.h"
>
> +/*
> + * Whether KASAN is enabled at all.
> + * The value remains false until KASAN is initialized.
> + */
> +DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> +EXPORT_SYMBOL(kasan_flag_enabled);
> +
> +bool kasan_arg_disabled;

You lost __ro_after_init

> +/* kasan=off/on */
> +static int __init early_kasan_flag(char *arg)
> +{
> +       if (!arg)
> +               return -EINVAL;
> +
> +       if (!strcmp(arg, "off"))
> +               kasan_arg_disabled = true;
> +       else if (!strcmp(arg, "on"))
> +               kasan_arg_disabled = false;
> +       else
> +               return -EINVAL;
> +
> +       return 0;
> +}
> +early_param("kasan", early_kasan_flag);
> +
> +
> +

Why extra blank lines?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNr7e6DXQrZva8k46jELr1JSkjExWvQOyrkY5VD8mOadw%40mail.gmail.com.
