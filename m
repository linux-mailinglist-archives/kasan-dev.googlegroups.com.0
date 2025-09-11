Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZNDRLDAMGQENKIHODA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id BA31EB52CB5
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 11:09:58 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-71d603bf1c4sf5410767b3.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 02:09:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757581797; cv=pass;
        d=google.com; s=arc-20240605;
        b=hxT1fnaNO7gJ/IskoIKT9mPbmep8yFo3NAcQo6me+2RZL5MAnFXWDChvMDYjkgmLeK
         GxVpbrT1MkDeSR5FpIKJKi1D+sJADcc70nWTbUZ2Yr7BX63BqYJ5bYS9BWj51M5NG+H0
         2LU/hDOw4ZvjKNokeqrqQAcEbjotR5WUh8Huq2enHh3lPaoP1HiN5q1MP2j5yZ8EWLUa
         W2KIaqi1LR83zxowzymzllO993h3OeHdRz2ASTzxMA+f4Cy5tgL8ZLRfXQcAhT7HFkx/
         ny0JiSUekVxKb4KNhtbaozExcKlR/xU46ioNwoE7Ql2bJp0ZY2emQdrD6PSxprHexpZG
         EwTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AEAr9pTWmZrMczQ+RJk+IRnCmQsmhs87tv/Nkcr6hZk=;
        fh=PdFJCuX7izj1tmA7t1jo+W0W2dkHlNp/73J8qite8Kg=;
        b=gkSgIG4rJZ1XfoFQ9l2neQRsaPa8V9RCo8CYRjYJUo2CKJ8Uxi8xbVz9pdd4tDpENq
         AJu2vIsDq4nd956zV9BDDTuGg+j672n+jF14mt4OtlS98zRi7hhGYYyUuhxFuO45qE1L
         JoWU47p/YpzLjSfYO+n7KrwuIhbnqc13BJKXlnCyOiitkIcoQiLwlIOdIGTlH97WGbBN
         mW1yRN/8z4rIFu+gfwIBVURzNwLTQuFDBIuxtinmD88TqLizdC2823ByxV97XkKbC2+E
         M/FMbStg4j3rK3vy8pHwVAen15qIWrCL7QHHO3VzYSaUrzk6ND2Eb6qu2oXmxHhR6dUs
         VUcw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WbAw+NVG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757581797; x=1758186597; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AEAr9pTWmZrMczQ+RJk+IRnCmQsmhs87tv/Nkcr6hZk=;
        b=i4d5SilBW63A5iB1GWXVZRaWTy6UrW2DkDqGb/KIFAuMsjU4CyBaGoiIIuBf9KuoIb
         qUz9gk326qBRJKg3j+HhERspDjrmDCrPeLs60OqiFsVuAMhE8T7L0nwlnam6AMGBXTrs
         GAVEqU/HaKSi0VsoPkNFxDVb8I18Cs7NrLm6P36vtJ8vck1KlTbklUL/ZL5uvu8v4jtc
         uC/RRIhX2idExj4ArBaipMSAz1hPmIpzSpI2ti5eR5ywNcC9/Ln4mbEykzx+lzVlyobQ
         fz0spoFHoqYY2e6burDxUW1MclVyqlsZzcEM3/30aL4cuVvqj9I8xsUZM/amyOzEOSXY
         3JmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757581797; x=1758186597;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AEAr9pTWmZrMczQ+RJk+IRnCmQsmhs87tv/Nkcr6hZk=;
        b=gIDZnHApSj9x5qgl3rnIrEfcjtQKjP0utXWFuxeeTeb3o4EEpqQz2RCBkKZy/cIsCi
         nkdD6gKEW+ImTSZU0300oueddLrueZnbn7U7/2vFV9du4PjDBamki0IwobRC6ymEYX8f
         z6aj3QPb0JTKab1s2Hu7Q+PsCOJ0nMecfehwh8p7AeWsrXsCUPlpOQG9/VQJwkQWE+1o
         fWeip2rKmeiaOdoqSmd3XYRWBHflmse5gBkFBC6vM87w/FvyK6DcDgyIlfrRrSVd9uqG
         RZZmcjNZZl/a1L7MnZAJHKLRtDaMlaiAurhUTeR9GmTBnLf0Jb1xY50we1ldVQWeoGou
         mVUQ==
X-Forwarded-Encrypted: i=2; AJvYcCUFPlsJfUcCb3WIgncux6VXfEfE53choaqsfe1F7pwEe1mqFALQ1fchZRD0rfoPRcQYJdaWqg==@lfdr.de
X-Gm-Message-State: AOJu0YxtUseBCLLbP4w6mlFVbLmRrxRiNdepeeV8b77xGCguyfVfK/X4
	TtWmZn6iQyFybZRzjqfhFNmxmtpDbAnuYS0FmwH3Jg8f0uTCOoApU8Oc
X-Google-Smtp-Source: AGHT+IGuTPNipRddB84QHKsSvCD75FcUQqa/2R21QeTG5xBLu4CPaHaPjBctrQdj/cmbkTjC9HLryg==
X-Received: by 2002:a05:690c:a084:20b0:729:d9a1:ce0b with SMTP id 00721157ae682-729d9a1f25dmr112500927b3.32.1757581797324;
        Thu, 11 Sep 2025 02:09:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd55ozepJPoQTgAP72O6fShOG3/Hw05g3eOQ6+Jbx1fB6Q==
Received: by 2002:a05:690e:4185:b0:5f3:b6f7:98fb with SMTP id
 956f58d0204a3-623fca80b75ls309293d50.2.-pod-prod-09-us; Thu, 11 Sep 2025
 02:09:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWnyPE/iymiujzhRUktOpRysRXI0zaF31Ld+rNj2Q8gvmwFAPNZVQu8XM8slqLYVTgt1aopMI8Pp64=@googlegroups.com
X-Received: by 2002:a05:690c:6204:b0:71e:7dcb:ab37 with SMTP id 00721157ae682-727f30ae7a8mr155562507b3.16.1757581796232;
        Thu, 11 Sep 2025 02:09:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757581796; cv=none;
        d=google.com; s=arc-20240605;
        b=Y08Sh6V0sIq5VBWeCyiW33RqQiAs9PFzHvl3V5LyMgbcaIWuvFOWVro+CvYfVuRpUQ
         F/EpxTgb/fqs/DXdQntOdrkeQtKzBfBBbkMN2mRy1Jcj6CVM9s4VFYE28CN5CbCzChXS
         J0zQStU01MAoaW0yk+2BMIZgIkW9NKiYVF9sZYaNMGMBLi9RhKJUc8raOM83+LEWPev3
         yrKC+sMWvLnQOJFxKs1sLCvyGSSRWyW9CVkxCOKZJF5B7ny/hwuZnpE9O+ygieRWiEmS
         4ThqFivJkMwazI6O7DAHcn4kaDiAPSj/5DhLawEBvAv3YxP+TwJUB+7nChZTGXyopvHm
         3teQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=110hIxZl/DIKAtkNXDUZdekwbiGKdHIJpSsuT6OGVlM=;
        fh=83pyAweQoILcg+P3CCUf0QRdq1BLVDIJxPrF1PDYwpI=;
        b=MqssAah6qCMe7igQIIhbvEY5/pWZtNRRKlRzaaX7Sd9I0nDZXyP9zLspAIdK2rg+sC
         oaQfcfhceug815m8gIS/tOAtQADXJoMRKHOKbbHuKSfCYPVZMz1QFZQ0GqHIoM7AfuxH
         2WhAXWeU9r+hXfKSLUKd4dQz1b3mSZ4pq8besrGoXWQGC7gEoX7hFa0UYIsDOQrnegr+
         Es/N0PVxXawBIFxeg80tSkftRCvUXA05kxXBxW2HAFeutyGwnxvOtM4YTZ40CBIgbwAG
         m4EcU826bq8LeOsq8GXJRG83ULMZNYsRFOsjhc7INrkwHX9ePZSJtYZdCLAiJiP8ZuiJ
         ZFEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WbAw+NVG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-72f7355a76asi285397b3.0.2025.09.11.02.09.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Sep 2025 02:09:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id 6a1803df08f44-7211b09f649so4491066d6.3
        for <kasan-dev@googlegroups.com>; Thu, 11 Sep 2025 02:09:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUzXfl67SgoOUib2PnBk3SGONgwLJPgEO5i5r4l1dTwn4ywfr/7D4EURMQOzKnmJLtwxKMQlQLgbVc=@googlegroups.com
X-Gm-Gg: ASbGncsRgpP2HZFUIoDJyi3VTdcu7Y64+fr8viHMB/7YCSw8OoWMVkkZofFujQFEOrY
	3vzIbBcSsHtevt8nSoyeglGwLRDPvcdv7a8qj+mDDNjZ96bBfLYqM2oJ2e6EORC6WLetD5bRhsG
	irmCgv37GysTmM94QAwSCdCYHADDBn3sSZMiKj0YKSnK/5zCdj557/JFvH6rDjp/nfB7yS/X51M
	AFDmz8QYpx1w/0n0ROQ/YsfoNy2SvmURHeYkFqaSSwuIqQh5iVlBfI=
X-Received: by 2002:ad4:5ba3:0:b0:70d:eb6d:b7ea with SMTP id
 6a1803df08f44-73940411c14mr198047276d6.33.1757581795396; Thu, 11 Sep 2025
 02:09:55 -0700 (PDT)
MIME-Version: 1.0
References: <20250829164500.324329-1-ebiggers@kernel.org> <20250910194921.GA3153735@google.com>
In-Reply-To: <20250910194921.GA3153735@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Sep 2025 11:09:17 +0200
X-Gm-Features: AS18NWCx4E3OdC7mBgPGgVUBUT-xLxLcqqp44Vqxj-OTHUNQdAnrn9pPMhbFdkc
Message-ID: <CAG_fn=W_7o6ANs94GwoYjyjvY5kSFYHB6DwfE+oXM7TP1eP5dw@mail.gmail.com>
Subject: Re: [PATCH] kmsan: Fix out-of-bounds access to shadow memory
To: Eric Biggers <ebiggers@kernel.org>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-crypto@vger.kernel.org, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=WbAw+NVG;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Sep 10, 2025 at 9:49=E2=80=AFPM Eric Biggers <ebiggers@kernel.org> =
wrote:
>
> On Fri, Aug 29, 2025 at 09:45:00AM -0700, Eric Biggers wrote:
> > Running sha224_kunit on a KMSAN-enabled kernel results in a crash in
> > kmsan_internal_set_shadow_origin():
> >
> >     BUG: unable to handle page fault for address: ffffbc3840291000
> >     #PF: supervisor read access in kernel mode
> >     #PF: error_code(0x0000) - not-present page
> >     PGD 1810067 P4D 1810067 PUD 192d067 PMD 3c17067 PTE 0
> >     Oops: 0000 [#1] SMP NOPTI
> >     CPU: 0 UID: 0 PID: 81 Comm: kunit_try_catch Tainted: G             =
    N  6.17.0-rc3 #10 PREEMPT(voluntary)
> >     Tainted: [N]=3DTEST
> >     Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.1=
7.0-0-gb52ca86e094d-prebuilt.qemu.org 04/01/2014
> >     RIP: 0010:kmsan_internal_set_shadow_origin+0x91/0x100
> >     [...]
> >     Call Trace:
> >     <TASK>
> >     __msan_memset+0xee/0x1a0
> >     sha224_final+0x9e/0x350
> >     test_hash_buffer_overruns+0x46f/0x5f0
> >     ? kmsan_get_shadow_origin_ptr+0x46/0xa0
> >     ? __pfx_test_hash_buffer_overruns+0x10/0x10
> >     kunit_try_run_case+0x198/0xa00
>
> Any thoughts on this patch from the KMSAN folks?  I'd love to add
> CONFIG_KMSAN=3Dy to my crypto subsystem testing, but unfortunately the
> kernel crashes due to this bug :-(
>
> - Eric

Sorry, I was out in August and missed this email when digging through my in=
box.

Curiously, I couldn't find any relevant crashes on the KMSAN syzbot
instance, but the issue is legit.
Thank you so much for fixing this!

Any chance you can add a test case for it to mm/kmsan/kmsan_test.c?


--
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DW_7o6ANs94GwoYjyjvY5kSFYHB6DwfE%2BoXM7TP1eP5dw%40mail.gmail.com.
