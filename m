Return-Path: <kasan-dev+bncBCSL7B6LWYHBBFU2WK6QMGQEH4XHPDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 071AEA32582
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 12:59:20 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-5de909cf05dsf2729612a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 03:59:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739361559; cv=pass;
        d=google.com; s=arc-20240605;
        b=A/w3C2QTCvfwtK3BUPHJD/Qef+WFA4xU53kYcXVsUAt1yPvB0A3QuhgZPUpKfeSaRF
         n7uo+TS+6WZWq0+1nCa+sdrBM2qzXxTSZSms2mLB0+5MBaFIlX3SpXHmSilhjJ4v4OIx
         XtZ15YLkExBD7PDLL6QZCsVAVIxLXr32ZN/us3TQ9muwhQWBdaqSugv84y5xatSngSX7
         qzixTSOGBvHGd5A7Ku5miTm2lxiLd6c+Xt5dVw/JE6qmNd4IZXnZt5zfjDlSWSydj6a+
         HED6lKfm7A4Nc0Ya+tbK22Dzb2rqFB466ZqQkKfgAfDUFaVlCXcrFFm2cH0Ws7YEIWNT
         dRGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=S/D9U815bs2NwhUCpH1QtXyaK8VLedPfu++rp4l+N0M=;
        fh=1jqYou+kVEdKCEhMgY3Y4CvM4ihOHLACgDyn1o+bJiQ=;
        b=LBshYxjSlJP+xzL5j+hpLezLPMMaPIMb3Hq+SxYP9dkEc29/ILRR5Y5GKCnBITRm2D
         CBA9Df7D6/VlSGlWlrWMbgwyLrfkkydDuLaoBbBdDW347tJc0YkA7rr0susN47eq7uab
         jAD3V24k7hNg5nDRGNVEeROqFDENjRrJmc/Edzm7RxgBCmB8Qdcpt4doBz53Y1VE5CI/
         EFoWn48CImEN6DPi8H0rIHtJ3LpXHZ/3hZEREiJTg34wgcFpd0u2AE1Kddcv45zidHRO
         rfIqW+zrgbVLfFRQa/rKoRNzp2l0QUeH2upWw4ohgT5In2ExcoCV6NH2K1JRnmkJF/B+
         pBmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=V5QPSHHM;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739361559; x=1739966359; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=S/D9U815bs2NwhUCpH1QtXyaK8VLedPfu++rp4l+N0M=;
        b=JcPx19f9gmKK9b5MVYvMteu5pNvDpaeHMnwdEIaA/2gSPLmYk7KhEjLTMqeypzjYFb
         RExKkniZ/cQXRuUA9YY6EECgJ6jh2/DwbXZbbJeKdlEuOea84PrcDNK8JFMDBlkccHSm
         zP+x38d8MnB4Njbem6b+NA7qDAHTllH/lOmW28fsTXTyePqKWvwrOzgibaP4Jc4HIlaQ
         Q+bsK5odpQeADGds3NcYXRH1OXHJI2I309tXyak9psDhgklAqbv1U3TNIjN6NxPdyc7j
         Jt/YNkcl37l7y1tKCkpU2UcInIcOFvnmKIE0ztB8two3OCvXkBCwJsoyWHYbADnP7XaU
         iFow==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739361559; x=1739966359; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=S/D9U815bs2NwhUCpH1QtXyaK8VLedPfu++rp4l+N0M=;
        b=RHb2SK+RUMISWTYodZvuuG25I/HNFL5z7PPjBhfb25W2yj2rnOb7yXMh2K8HfXzSzG
         hHi1QLbropTpEU6Jpc6VftYtn4keRxBNZksTleTjHbAZzRj3EFW1JtGhWH3HDHd948dp
         lRYkiKBukyMx3X0WF/F6orBgX2HYn2fy6qrmvM7NQ2UaHFkdM6XTeg50YFISlPjrhyg+
         rWUv86om8scNZPADru2uQQk/rEuuI9ay3+FiY3Z01/bd7199R3BCLCyk/dIOoMtw/Mqa
         r4T6opbmxfYc+0cZb3BA5mIxZkFqYK5W9F7aDCO4CF2NsR8MKmgiphLOhvPepsOhhUoj
         xSwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739361559; x=1739966359;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=S/D9U815bs2NwhUCpH1QtXyaK8VLedPfu++rp4l+N0M=;
        b=jVEjsOrHln8XscmAgWR5cg3siLLrW+InglNmq7GB0vMrv45dVYDKeeEJ2h/cTSvTTu
         rZNJQ7+46JPhF3LWUiDnwcNUgvwF8M4RNqjllvGanAKt7GVBjhMe3j5q/VUjldZ3Exsl
         zxk1NbU2CP3OgXAJA/TgoJC9GsNrDD5MA6BA83/Pdood28X0PfbWtopSWW7yhjvAVejP
         API+37gZC0nZM/z7gxHMJXW+w7mcvA2jSZrNd5yRNOOV78QFkE87li1Dr936H84zFSMW
         7CHHWTwZde10z1+9VVOTJMV6LwrfN6TvNY6ELxfclFC8cNV8hrlQtWDVAb50dvP4vYJ2
         Nnrw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWneFZ5g1og/oOqfGwZSBKWHa+H1A1qDvoCAE7NuWd0hplLEWzj3dB2KR/QL4Qxe+JlOIjSpQ==@lfdr.de
X-Gm-Message-State: AOJu0YxXxL3XybChSBlbxPK3PdwY3x7TeNQi7Tmcv2iKWGzkRYhKLKaa
	2Mo8TXt3SVJWUlZBwlACTlMMBzRKlCVgejfUfVx5rtLWLIwudyvV
X-Google-Smtp-Source: AGHT+IGa7X3DCpEHiRjMsQqNC9mhRyYSw+Xnu4BwJ09o5xZhhWFnoFzjnflzfitei7b973qFXYPI1w==
X-Received: by 2002:a05:6402:254c:b0:5d0:d9e6:fea1 with SMTP id 4fb4d7f45d1cf-5deaddb98a3mr2325088a12.19.1739361558684;
        Wed, 12 Feb 2025 03:59:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVG864xYJiU1mHSUi/5Bi/6JDUXOurSoSPGM2wr+xLu8Zw==
Received: by 2002:aa7:c517:0:b0:5de:bc62:17e4 with SMTP id 4fb4d7f45d1cf-5debc6218b0ls427969a12.2.-pod-prod-06-eu;
 Wed, 12 Feb 2025 03:59:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXLFaeRLY2UYknkgoThuoNj6UbRYgJJBouNes58tQHwCT4v3KEb4wpTeOMXVqcE9Z1aeFA0yIGvqO0=@googlegroups.com
X-Received: by 2002:a05:6402:35c4:b0:5de:5946:8a01 with SMTP id 4fb4d7f45d1cf-5deadd7b7femr2299226a12.2.1739361555740;
        Wed, 12 Feb 2025 03:59:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739361555; cv=none;
        d=google.com; s=arc-20240605;
        b=Qwaqak7NPHura4qUaG4iOvYYn6GKRisXpaiuMI1R5ohYKtVSfK7kCcRR5Ow2PfmDBs
         y8zT30sVQ1f7PDzBPPP60XiOIvRctDJ2JIDUwQdaHrz2piLaoFt/9ZIFnN/d3ppUYyiZ
         pFtQQgX8ff16Fl14nqBouuhdEbhPodd7sRrCO9c5B6WWg++WXTKo9lgO8b7aZ+9CDwUx
         zFOEMMc38LWsmzYr4zI1tX/1LuhFfFQgnL3cQLSamfwu0CxidH39NMIoqTHRR0UTQ+dh
         bi5668PAlylbBhwtofhXN+TAK7z4GYabLa2EPfs4DywjLGFHu3YsDCJ3fLacfrDp0qqf
         xtSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1eSl5YfX4v8OgkeO1jdSOmTgQstGlkukMTg9/pwP0Ps=;
        fh=9feQ84Cj51TzdkykjcMvH+xwAdpKwt6E3+TetW7mkZ8=;
        b=W1uXMQR3F+k19tuTQ767+LUynWDZMaCUaCDzoWb8334YPTc+X5geLq3zDSCzNzMat8
         S3PjaXTbhhD07nKE6TjYvHhzVPY8h6zD5fOsSMJvJTR9MfqW21smDbapMrvN2hJ3cDdo
         p+vpAaesXhZKTPGD3HVv+tC8smWHkgnF6R8uS9HNMICEVpYngvGJv+674QU0ZM/RNtmq
         hdccEe035HJmURXSNausEzcsumLdabI69xTIYtkQAQm6derzl54jVIfkCJJ6ox5jr9GT
         HNPdsdd/bYyEDjUKG9+dtkN89VTCaMRb6KrySlZFCPWAUaDkMtZLiOwN8bMZNdEP/40S
         lbxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=V5QPSHHM;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5dcf5d1bfcbsi395725a12.3.2025.02.12.03.59.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2025 03:59:15 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id 5b1f17b1804b1-4395e234c02so381705e9.3
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2025 03:59:15 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVeKtnJtmeKGTSB2p16LDYUVK0aLGVIU5EcKdEMrk91673LolWSbv3DBJBPn7zqxsavhQywxe63RbE=@googlegroups.com
X-Gm-Gg: ASbGncsXLzBN9AWxVkaMQH6T1VlLjsRNw7KfnKSBW2c4NZi9L0qCeqigMGCe02/ooVM
	BN1Qxd+Ql3MQnQH9hLE0FhCJ/8KdNGRQSPvt+CxPCYENJufP2bclmgwFPU9hvaj/WLi93E1yORo
	Ky/8sSMzsk8HIYJT7ncTFbhP3cj2Q=
X-Received: by 2002:a5d:64e4:0:b0:38d:be5e:b2a7 with SMTP id
 ffacd0b85a97d-38dea2e98e7mr967564f8f.10.1739361555145; Wed, 12 Feb 2025
 03:59:15 -0800 (PST)
MIME-Version: 1.0
References: <20250211160750.1301353-1-longman@redhat.com>
In-Reply-To: <20250211160750.1301353-1-longman@redhat.com>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Date: Wed, 12 Feb 2025 12:59:01 +0100
X-Gm-Features: AWEUYZnaqmNFQ_lbBc6EZt7NZdSpHvlmvNFB56VaHucCrwmsBCcCq_pnMuQNjtc
Message-ID: <CAPAsAGzk4h3B-LNQdedrk=2aRbPoOJeVv_tQF2QPgzwwUvirEw@mail.gmail.com>
Subject: Re: [PATCH] kasan: Don't call find_vm_area() in RT kernel
To: Waiman Long <longman@redhat.com>
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Clark Williams <clrkwllms@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
	Nico Pache <npache@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=V5QPSHHM;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::32d
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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

On Tue, Feb 11, 2025 at 5:08=E2=80=AFPM Waiman Long <longman@redhat.com> wr=
ote:
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 3fe77a360f1c..e1ee687966aa 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -398,9 +398,20 @@ static void print_address_description(void *addr, u8=
 tag,
>                 pr_err("\n");
>         }
>
> -       if (is_vmalloc_addr(addr)) {
> -               struct vm_struct *va =3D find_vm_area(addr);
> +       if (!is_vmalloc_addr(addr))
> +               goto print_page;
>
> +       /*
> +        * RT kernel cannot call find_vm_area() in atomic context.
> +        * For !RT kernel, prevent spinlock_t inside raw_spinlock_t warni=
ng
> +        * by raising wait-type to WAIT_SLEEP.
> +        */
> +       if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
> +               static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEE=
P);
> +               struct vm_struct *va;
> +
> +               lock_map_acquire_try(&vmalloc_map);
> +               va =3D find_vm_area(addr);

Can we hide all this logic behind some function like
kasan_find_vm_area() which would return NULL for -rt?

>                 if (va) {
>                         pr_err("The buggy address belongs to the virtual =
mapping at\n"
>                                " [%px, %px) created by:\n"
> @@ -410,8 +421,13 @@ static void print_address_description(void *addr, u8=
 tag,
>
>                         page =3D vmalloc_to_page(addr);

Or does vmalloc_to_page() secretly take  some lock somewhere so we
need to guard it with this 'vmalloc_map' too?
So my suggestion above wouldn't be enough, if that's the case.

>                 }
> +               lock_map_release(&vmalloc_map);
> +       } else {
> +               pr_err("The buggy address %px belongs to a vmalloc virtua=
l mapping\n",
> +                       addr);
>         }
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
APAsAGzk4h3B-LNQdedrk%3D2aRbPoOJeVv_tQF2QPgzwwUvirEw%40mail.gmail.com.
