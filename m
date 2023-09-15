Return-Path: <kasan-dev+bncBDW2JDUY5AORBZ6XSOUAMGQEBGFPJQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 58D057A2B0F
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Sep 2023 01:42:33 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-34e44774ce3sf531765ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 16:42:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694821352; cv=pass;
        d=google.com; s=arc-20160816;
        b=cXF7TNNRzYGxl1ur58FKlfVXmTPm6f5F6iIr3stEbpRIxUHCsclDgLOkL4loVb6lYD
         6BHRfyxBlMKWA09rvJNwOUV5LRZR1+X6uv3Yg8crUbDtQIRjRXWawandEE/nyCthZePc
         W1AXtmWOZ4DobGWMv9b+4DcpGrdd3x4uPv1uWSSRaTStLWoSCPi8Jz8KTqVrNbRvMEhK
         DdVr0vGf3Sod73VXda63r9Jx1kMvW8T2RmxnZ+sLeC5IQTQkyJfd2D1Oo32LKSb03XB1
         wMIsWQOuKu+FfjfhFzd3ryh7PlW+pX9UDNpYRXr0KagHOzb+HBWiYETY8bZZ57KlZLnl
         nVOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=3pn/VgffQR6+OQmRSx13VihUB3ha6dvrIlEXG5cp2gw=;
        fh=eLBvtPgIPGXrKWkSllAgQrmoJJNmy3KaT4bQ94uM2hU=;
        b=mdw/cdn025Xw7PCuecxjQHjjKDh+HBNmIa/kaAj7U/JOKdOJKYkcEoSHulqTH5wm61
         zwUju955qWyHYxoQlYbfD965ryZabQlgvp+s3AUbCfcb+V8i5e7LV3fbD9iqqYYP/bb7
         EGHHhUyuvxkxqtTepU4OJvS0LL/WncJo1J/xhoig9S9ggShXHfXvF7YE2JzJoPQ/m8hf
         qsaZvMSzgrxkarvurszjmtfZKLTUrhfecvBPmgvn/k3LgHVT+Nt2ODe+Jo69rb8iXQE2
         0LAvfBPFFftrKwOzt7/BMO/KIzcAEjYfZQp5GEwPMF5ZB+wgxRp2b48swU47rYbRfr8j
         sKBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lTje2eio;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694821352; x=1695426152; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3pn/VgffQR6+OQmRSx13VihUB3ha6dvrIlEXG5cp2gw=;
        b=e8FxCfjmmJ3T0U0qgqnfcSp2vfunHcy4fwG83/+Lg/LcRz9ku+NFW1co0PwpreqsUJ
         m+rPF6xSHyMIYJxKwxLAvqgKzV7RVkwNp5KgXISoYteHXaLoC0ErZ/QkPsJNc6+yo3M8
         90QikhJ2GgjMr2Ahe55ZnIVYSyoNWnuhZsFgbG3OIGQUNAGfApfn1ZiuG1N0fPU9F5Ug
         E9ozzNB0XHDEvFrJY/oeBYBNCveB/ci+IkRXagJQbcPMuxzESOPh+aBam6nqsQyO2H03
         D8Gmw6WBTtNH/HEU0ffNxGCahycFVP57DgmvgpR2bKJUTOVY6NwdaOQM20IhQk3vW30G
         VraA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1694821352; x=1695426152; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3pn/VgffQR6+OQmRSx13VihUB3ha6dvrIlEXG5cp2gw=;
        b=IGN1bK9mHuc4yH38q8RmwNTGF8gZNy5UCf+jO2qSgZSsrwfvwwv5bwXQ7thJZYyo2k
         jb4ctyxUuOKody+Y7xT6YhEWmELHQ1A/cHiv1hLvKchXj6RExVVoJ8fa+kDsHcd0h4mg
         f75veQLyLM86hKu+yoy5Z4ihXTioVjPA36Dnrylzz94l+CRtql4qXCZS0phDlgtsXvR/
         5cU/xD6MTB2jk0WY5fx/dlGepyjz4pX3Tb6wImaG9CP/FpTvX8mqWUgA06PfatTSadND
         ewAT0PPqIF/weKSKnB7xTYs57PQLQu//yIBV73pcsn1K2cUhABXrTtgyA5FYvJ54ixIT
         O59A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694821352; x=1695426152;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3pn/VgffQR6+OQmRSx13VihUB3ha6dvrIlEXG5cp2gw=;
        b=igHQi053AiT2CvSGq1lLo8zlD6Gz8BNeGN3Ir7OuBOuG1eVBnLJVX7QXUfQYsbKAoS
         8PUm9n6GDUtjrQtR3Fteek7phOAWX7xKiTPpYx0M05/uB/Q67EDSJKpDi+b2KtXXFBSo
         owCxk2XhSt7RE9jxKE0P8TEQ2ct7VxJGDZo6LWINtZ1NGDgcZyNNXocVpkXLLlMMGocI
         FqKxkZr4Hcerat83E26xhAE/eOKRPi2z55kXx7yDe+DFjOGxBh9XVf/DsWbkk5LO0dOw
         XQSaHjEahUL0rpYDinYnBZ5PPpWUF7GHlaH+l+vnVkNuRNJxZK2YAgGCUDj8M/vB7Jgx
         vNWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw6WGME1FI9Cn0lOd5ad+Tp5WCpwOIEm2d50kNTXO9FXH8ncKb9
	qXus4a5elMbziSbvEPpvb90=
X-Google-Smtp-Source: AGHT+IEt96ho10iTpPT3SbTH849E95Sp207hLCeLHcmrizfHeCQMEbfIl0TM4SSjZC0OBzlDw59iyQ==
X-Received: by 2002:a05:6e02:1aae:b0:346:48bd:da43 with SMTP id l14-20020a056e021aae00b0034648bdda43mr113430ilv.4.1694821351840;
        Fri, 15 Sep 2023 16:42:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7414:0:b0:348:81bd:2f88 with SMTP id p20-20020a927414000000b0034881bd2f88ls254750ilc.1.-pod-prod-00-us;
 Fri, 15 Sep 2023 16:42:31 -0700 (PDT)
X-Received: by 2002:a05:6e02:1e0a:b0:34c:f9c5:f375 with SMTP id g10-20020a056e021e0a00b0034cf9c5f375mr6609268ila.8.1694821351195;
        Fri, 15 Sep 2023 16:42:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694821351; cv=none;
        d=google.com; s=arc-20160816;
        b=k4I+gelSoW8u+ROuK1HgUcEUJ8tIMLCI5s49FSRReIwgkIub5tBbgWjqLqm8WsdQck
         MdtnPL4YQndZx0ckqVa57uxJ7EwiWyaxxnAl5Ciym61Ybs2f+p/PZNIIWUv7zeXANkTk
         sa+WbupfYnI3lcXzsSMgSuxeMrLhkcqWA0nOkCJ8xSP9hp3548f6ixE/OHpNs5p3Smjr
         8oMXW/pyzCZg97XYcQ6stZmsfnj5fO8PSns4txjzWoZJJ22dip618I/yXgl7bZxvy4qK
         WcY11aIeB8TKA2A16OgnS6wzjW5m7TTCDOD20QWuJdwhQZwdSISCIcD3/D3OpplNhyk9
         FY6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HvSLgTTIgHIGD+l7tl19R4elC30zzIy17VfAeigIAQE=;
        fh=eLBvtPgIPGXrKWkSllAgQrmoJJNmy3KaT4bQ94uM2hU=;
        b=aAnynwsCYUxwQ/OVWj5cSWM/yg0PffW8mc3wxxW7bsjiUp3nUvxarvwnp6n/JEMbDw
         2ftP5Te2y6/H9EY9S/2FCkocWAYqn5fAJm3RJK2/05YsvVaSheB84dVEJkH7pjIbTSmv
         PgyxjY1fqw6yEgzmRUitakwohlhdEgnm6t1jnFvK6YXgs66C/uwNoi4lyn5pVKIyrXJG
         Yv6APboqDZNJ8ank9eJ8ULVlJcrQIoes7t0fmDb+BBmm7a6aulSVqqm2wIWF6jJ1vYee
         Ugo6KFZM5+kAPB2lk+sFZUOB6OtbFf2MvNwRKt3/Lsw39ueqN0bkoWMfVfX5G33j2I9C
         9z4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lTje2eio;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id fg10-20020a056638620a00b00437a8b1170csi796062jab.0.2023.09.15.16.42.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Sep 2023 16:42:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id 98e67ed59e1d1-2749ce1aa37so771801a91.0
        for <kasan-dev@googlegroups.com>; Fri, 15 Sep 2023 16:42:31 -0700 (PDT)
X-Received: by 2002:a17:90b:34a:b0:274:8951:b5ed with SMTP id
 fh10-20020a17090b034a00b002748951b5edmr3968062pjb.20.1694821350468; Fri, 15
 Sep 2023 16:42:30 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <2a161c99c47a45f8e9f7a21a732c60f0cd674a66.1694625260.git.andreyknvl@google.com>
 <CANpmjNMfpgE0J4e-nk7d0LQi2msX9KcMwK-j37BPuvnPhKPYKg@mail.gmail.com>
In-Reply-To: <CANpmjNMfpgE0J4e-nk7d0LQi2msX9KcMwK-j37BPuvnPhKPYKg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 16 Sep 2023 01:42:19 +0200
Message-ID: <CA+fCnZfGqpCO_4rhKDaQJBD-LSB7vJmD6vMgp-ri=xeg5+acEA@mail.gmail.com>
Subject: Re: [PATCH v2 14/19] lib/stackdepot, kasan: add flags to
 __stack_depot_save and rename
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lTje2eio;       spf=pass
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

On Fri, Sep 15, 2023 at 10:32=E2=80=AFPM Marco Elver <elver@google.com> wro=
te:
> > +depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
> > +                                           unsigned int nr_entries,
> > +                                           gfp_t alloc_flags,
> > +                                           depot_flags_t depot_flags)
> >  {
> >         struct list_head *bucket;
> >         struct stack_record *found =3D NULL;
> >         depot_stack_handle_t handle =3D 0;
> >         struct page *page =3D NULL;
> >         void *prealloc =3D NULL;
> > +       bool can_alloc =3D depot_flags & STACK_DEPOT_FLAG_CAN_ALLOC;
> >         bool need_alloc =3D false;
> >         unsigned long flags;
> >         u32 hash;
> >
> > +       if (depot_flags & ~STACK_DEPOT_FLAGS_MASK)
> > +               return 0;
> > +
>
> Shouldn't this be a WARN due to invalid flags?

Good idea! Will fix. Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfGqpCO_4rhKDaQJBD-LSB7vJmD6vMgp-ri%3Dxeg5%2BacEA%40mail.=
gmail.com.
