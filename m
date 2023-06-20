Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEE5Y2SAMGQEFYLRBZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 37A7F736B13
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 13:33:38 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-4f618172ed6sf3189684e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 04:33:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687260817; cv=pass;
        d=google.com; s=arc-20160816;
        b=fuSAzE+vO8KKxqM/7XVLHuiG6zSXG3AUqdEXbNkX3yJ6qF2MB1Hp2pK6x0tmn0b3TP
         +cw2tX7e6WfBuEg8P57Bhd09vlA0oa9iwxl5DaBcvRY6BlRGKRi2rPZrYjmZwsXFZn8f
         4sYdjs4fBxK+6NvLchAciE62JfHlkV6YLoe7rYqQEMDXzw/plz6brzgL36aDga3LbJKD
         al1AMRiSg3KgqR/bVdNwFglvQvYRBlmhnt7fiXqYt4agWEqqL+FIHseRSzMISRXEFHzW
         WzWCSqYawsryC/f78mWoxj/1pUzlL+E6qSXIpyhFb/7Zuc6Y5zLONEY8bpvY2gibCDHx
         H0cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RaoCh+lCfzsCU6AAmQtJrk69fHH1rrqAKyGx4QRi1/w=;
        b=hK865pNniO0cP4HUOCOLefsl/9EFaULkbr/vrwbeHStPkxXjd+2sVd7BoSl+PGh+kB
         HGM3tlerpNuq/Av1nP14FVvoGS83Fer3uYuqhsH1zlOD1M7PZky4elCHu8pkOmCJTKRC
         JydhcCCh0qgt7Mkyq6OtvO/Ltv3+zMXe2y1Pi9KUseaEhEbxhs2aZOe62qVvoaVeSvtv
         Sr7qHgGMr31pv0M+t00IYFujVe+akkznPGedWQ+cPzkI0j99aqh0ScvN+DfW8+k2oyxl
         pwzPCtUt076BGaBs0sxxYISDS4wWfPgLl7VXQRuc9DgfMZ0kbTKGd914L3nEYYa6Qq1u
         7FIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=PkVmSxkx;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687260817; x=1689852817;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RaoCh+lCfzsCU6AAmQtJrk69fHH1rrqAKyGx4QRi1/w=;
        b=gn9tcEE/mPYbLC8UsdsiwNwa70PZiMtN+HRX8rJqTpzzhWDCBtwAabJ3GgfjFPudR7
         2QqeC7XvvkA7cDuOVzDSgamPG4Qe8a8tZD2ajcFN3DWiROcmD7Hrqy6dBWZBwFiuc+dP
         0f1qGMQipOdldl3xLzeclO/Fz0C/L8T6tRVhFIu1al7DuSnuTiv6qdQdVBxpDruRL522
         kf392gjbgedWvAU4qlW1cDweVPlgNgoVxuWDSV2FjnWgDHENh/hSSAuo2nibPZYsf5fZ
         QvNywNlzIHibCrnaZtGeU3qwGVn3Eaz5EBs7q22O97j2E3uCM0Ho7/L8s5BSh20sc1cW
         MfVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687260817; x=1689852817;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RaoCh+lCfzsCU6AAmQtJrk69fHH1rrqAKyGx4QRi1/w=;
        b=KRl7T7bG5PLYLfd8diASLZNmJlx0rGjVWlqKWX05a7feI/XOuiGqjfoPC9z0/5siu5
         wdLlMEXSY7VA8h1oMUUuYD8ix2shygIxvO2MELr1MII3yK/t9L8qY1KXoxopiduCVVew
         rJZ+EsnF7D7o5ptI4SKm27DyJXPZZSey3FF8xXvFB62NovomK4VmDZPLZ9nGhGRzcN2c
         biCcMtOlGUwqCT17AxDbXfnlUsaKeEEj0JwomEp/SkwRbcmPp4olvuGUAWbpiBUhwWxQ
         VEiNOFyHBq5BCb9VLcigP56OTVhxYsVuGGrYTWY8xLRinqYRA67ueW/CSB/I9oR1Dlvm
         8AMw==
X-Gm-Message-State: AC+VfDzQdOpQPOGgGzhx6f9fv50aj/onMDfAmIViBaX4SeuZHdNfH6jG
	DEqnEnEdcYOvSwd0Ov8H4zQ=
X-Google-Smtp-Source: ACHHUZ4E/fBvmHtnwj9CdP6Z1OSKg+AbwAWVRuuiD09kkDV63+ibyv2UegmVc/1LByRyfrFzENcRgg==
X-Received: by 2002:a19:e308:0:b0:4f8:4673:26ca with SMTP id a8-20020a19e308000000b004f8467326camr7487925lfh.47.1687260816661;
        Tue, 20 Jun 2023 04:33:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:5e18:0:b0:4f9:5593:bef8 with SMTP id s24-20020a195e18000000b004f95593bef8ls114297lfb.2.-pod-prod-07-eu;
 Tue, 20 Jun 2023 04:33:35 -0700 (PDT)
X-Received: by 2002:a05:6512:68:b0:4f7:4098:9905 with SMTP id i8-20020a056512006800b004f740989905mr6880486lfo.65.1687260814912;
        Tue, 20 Jun 2023 04:33:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687260814; cv=none;
        d=google.com; s=arc-20160816;
        b=yQB5aPJ22vXeYKgqZr6aE8TS4gIxY7W1PwzTHa6aRuw8EGTAhT/VmQwyuM0uFh1C/k
         1K7rUrLQfcDM/tMnGNfoeq9mvqj22q+lN5Hfgdy7SxHf5VaT0WQHkSHEjX5qVKSrEeub
         5HtZHm867r2MfVvf17jvJbuindA5AKMh0eJbkzHGwrr8TAc6F+xLYFDIFD2KUTnAhl47
         b97VW3UY3h+uZ2Ly1Zoc9Q0xqJN48VTHO997SIODsFF5OTKRc98NdsWK6ZBv/Y8yQWVv
         zlACsIm1wV/bTeezQ90DCmp4x76NPOE5dSmYyEgSrtx7Xx3l975n9mdsTlX1u6OXASoW
         IrZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=XVsib4qKyB82Osq6CfMX+p3Eul3U7zE2OWUFnDtEhvo=;
        b=TlePCzEWwOKSzlEH6Vt/7n+gSKWWSZiw8+KgxLvUNKjFr3mBxbRz7RqyAdHu3zeqjf
         XCjMFFmc25nRw9eZur9sybwkZaJ+Qpx2QUmoLADA0a2t0PQy556Wex+2b+WbcnV5Uy1p
         DCAEXGg6xjdTbsHvDUXx/KhJOM3WNmLazrwzVvoTHulqs1G6X/WkNrLKvAUlZVt9LKs5
         7IegOX+Hn1Aeht3dASav7egnw7y8sLy22GNO1q/CchZIfMOqVXkMDRrIf/7ImPqZWyM7
         qxE4MnZV7rrJ117HqfkYZ9UvjGqRjNlhECGTuB/0aB14A6WvtLT+6QhuuVfe1xTPqhha
         /wUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=PkVmSxkx;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12c.google.com (mail-lf1-x12c.google.com. [2a00:1450:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id j11-20020a056512108b00b004f8576a0334si101406lfg.1.2023.06.20.04.33.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jun 2023 04:33:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::12c as permitted sender) client-ip=2a00:1450:4864:20::12c;
Received: by mail-lf1-x12c.google.com with SMTP id 2adb3069b0e04-4f86d8a8fd4so3352567e87.3
        for <kasan-dev@googlegroups.com>; Tue, 20 Jun 2023 04:33:34 -0700 (PDT)
X-Received: by 2002:ac2:5b0c:0:b0:4f8:666b:9de8 with SMTP id
 v12-20020ac25b0c000000b004f8666b9de8mr5150573lfn.13.1687260814348; Tue, 20
 Jun 2023 04:33:34 -0700 (PDT)
MIME-Version: 1.0
References: <20230614095158.1133673-1-elver@google.com> <CA+fCnZdy4TmMacvsPkoenCynUYsyKZ+kU1fx7cDpbh_6=cEPAQ@mail.gmail.com>
In-Reply-To: <CA+fCnZdy4TmMacvsPkoenCynUYsyKZ+kU1fx7cDpbh_6=cEPAQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Jun 2023 13:32:57 +0200
Message-ID: <CANpmjNOSnVNy14xAVe6UHD0eHuMpxweg86+mYLQHpLM1k0H_cg@mail.gmail.com>
Subject: Re: [PATCH] kasan: add support for kasan.fault=panic_on_write
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Taras Madan <tarasmadan@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Jonathan Corbet <corbet@lwn.net>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Catalin Marinas <catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=PkVmSxkx;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::12c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, 20 Jun 2023 at 12:57, Andrey Konovalov <andreyknvl@gmail.com> wrote=
:
>
> On Wed, Jun 14, 2023 at 11:52=E2=80=AFAM Marco Elver <elver@google.com> w=
rote:
> >
> > @@ -597,7 +614,11 @@ void kasan_report_async(void)
> >         pr_err("Asynchronous fault: no details available\n");
> >         pr_err("\n");
> >         dump_stack_lvl(KERN_ERR);
> > -       end_report(&flags, NULL);
> > +       /*
> > +        * Conservatively set is_write=3Dtrue, because no details are a=
vailable.
> > +        * In this mode, kasan.fault=3Dpanic_on_write is like kasan.fau=
lt=3Dpanic.
> > +        */
> > +       end_report(&flags, NULL, true);
>
> Hi Marco,
>
> When asymm mode is enabled, kasan_report_async should only be called
> for read accesses. I think we could check the mode and panic
> accordingly.

How do we check the mode, and how do we prove it's only called for
read accesses?

> Please also update the documentation to describe the flag behavior wrt
> async/asymm modes.

Will do.

> On a related note, it looks like we have a typo in KASAN
> documentation: it states that asymm mode detects reads synchronously,
> and writes - asynchronously. Should be the reverse.

This says the documentation is correct, and it's actually called for
writes: https://docs.kernel.org/arm64/memory-tagging-extension.html#tag-che=
ck-faults

Who is right?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOSnVNy14xAVe6UHD0eHuMpxweg86%2BmYLQHpLM1k0H_cg%40mail.gmai=
l.com.
