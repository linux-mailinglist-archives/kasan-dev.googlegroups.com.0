Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOU6SL5QKGQEPUKRFWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id EEB8D26FACE
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 12:43:07 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id z18sf2391611oic.14
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 03:43:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600425786; cv=pass;
        d=google.com; s=arc-20160816;
        b=wBdGKpLhOK4IPU9vh/XfPurqabwsnrq/N4tcKvKdlLErLRO8h8joFYul4aEb3+mDNj
         2GZennKCXmncttc4D5i4jI/BxxIYZVT1fRP81pqh+SLY+QhNbDQ4OIAPqodXdE0Bf8/n
         F2LcprwtJdJm9pdpmsb/j0pgcPZo+mnIuQa3ngLTcVlxo6g7rV/sf1yAC1fs61/ZQa4/
         b4E6C/wH5ahlLJHYmGQRIvpKecuu2u9zkFr6glMkYI6qns+xvj7lT1ZN2Wkt1HqmLXUM
         vJ/fTFHyzL/62ocsrpWGzyUaocsionLL5is0lIO6n/nqI5uT7Zcsftwc4IiYwwCyABnL
         KIxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tMkni28vBvNJY1iAfVlsvIywOjLhWIaF0gd8SJOYsjU=;
        b=g/okYQpfSM5Wr1vwCYT/tgi2ZWX+53l+fmlx/iTlSt5rHz+0+9Pq52qihFSovDoGcZ
         bvK8u/LadGCGaFU/+BTj1PPSpRvVGua6uNzhNGbzvvkMQEvSauyIgICESSZz1fnlKR+y
         XEOtnZse8IafCW4EIlb+l5ee1+keUKF6Tfrn+Z8mgAlzcrhMOBurM4hnDHVZ8gCHpPor
         u46oSbzppXtuQqMyOzgFPlChpQNrAUCve7YL0SjGYLcTvprlWkR44cyBwe6PfaYaE3Hd
         ofFZd68KaepPPf5eC5vWIE61zhc2K40FznxEv6CNqRPzcb4fG5Q0TBtgmFhbJsiQOFXf
         73xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bOdZjXxZ;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tMkni28vBvNJY1iAfVlsvIywOjLhWIaF0gd8SJOYsjU=;
        b=XcR+rP+eVRt5cutF+k1x4JRxdISW3VrRUbjWWpJaziy59y3j1XK70Nqc6yUCsvKb+c
         l1GVrH25+unFU8Tpe75EJvYcTaBduv4UcZ3S7ubF8nZLVAPb5BxxYRmPzpC97qW+3HkH
         OEsvGl5vL32A/yieEBfBXrV4oylcpl237Af69qLychO8KJv2DWoIzuCpejrtKQzZ78PV
         y+Kz1CkZxPZhSl4vnZK55fSPJZ1vUJG+gcrlbbG+2SnRZ4jZke5bEclbb8pKSrH0iA9h
         2h9ZV4hvf+MPDZhzDgH5Va2zMB1k7PHvYKYPa5pWYolN924+f/+Fku1LvSQFO6gLCMuv
         B4yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tMkni28vBvNJY1iAfVlsvIywOjLhWIaF0gd8SJOYsjU=;
        b=P6QvssOUnIodCbsjIsJ1a2SO7Lhvh9Nz8sFOfKjXNIpKM6QChslgXgVcyjr1YgSstv
         BsIWwtg3TQZwIlbZ7wJKEfUtcgbzPFwW6I8pRFxgfRcYWNOn2DSLvaIAjeiKHce/8tss
         EQQx6o3r9aAvum/WOLmrg8bI7njSME1TBU8qgYFUPUpEH6edSInfy1jotyey4PhAODDy
         w9jt2KN6kPb+Pj1ZaUOZLrQg6XhpoqAESB1M3sDLwtBqHGyj6JtmHDHDpkGUkSHnarBB
         X2FisjHHEcaMoVPv+6pDUCtEKUIwuBDUi+SOFvu9/GMEx7rkr6TkyKTuOUozUdovHkaY
         JkpA==
X-Gm-Message-State: AOAM531M+qlPR64DRntVMyZRg2BVnEjVsV844AqR2DjL5VdYecbeztP8
	qP3r2ZttL5D/W0okGB4mR4Q=
X-Google-Smtp-Source: ABdhPJwxAT2MmL3mlWDaC49D6/dWd1AVjr4TQdb9izmMMbkPkNHsK8rYq9sR4nqnxwj53TpQR397IQ==
X-Received: by 2002:a05:6830:1008:: with SMTP id a8mr20835762otp.107.1600425786450;
        Fri, 18 Sep 2020 03:43:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:a84:: with SMTP id q4ls1189138oij.8.gmail; Fri, 18
 Sep 2020 03:43:06 -0700 (PDT)
X-Received: by 2002:a05:6808:914:: with SMTP id w20mr9349503oih.72.1600425786126;
        Fri, 18 Sep 2020 03:43:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600425786; cv=none;
        d=google.com; s=arc-20160816;
        b=rdbcHue7uN9MutMK8WRHJCuu8d0nMkNC2L3IyvwUmNFK/uWMqRljEGkad+eboxwYGF
         v7N53pHk7f2i0AvTkUf0zZF7BActlor3kp+zjmVyv38i1gcj0YmMHdSJ6M0fP57KARle
         v62AY6ALQOo3c7QmKn92dLJtY1JTP/84Cc7JbVN7WG1QQepLgG3UO0AvUAVG2JeRrhVD
         BphvN5AlQEHTg3igLjJ/O/M9vG2ZPxeY9E1Qe0jzcCiqptdzgbnU9lUYIpOi3JIHFmNF
         1wxv1WRDMpfOboqpXaG52b5mbJwcCj76iesuRY/scC8xThWFEmvO30MQz634d+MeZX/Z
         sKlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=S9SAa/84nB2osuzsORgaf8qh3oxqH7rlg5G0FU1VaYc=;
        b=GYQ35l714jrPdYKxmoQjw3dillcJqbfb37ZG2idAX+DsibQPgPdN7o5SPgQbKqPcJc
         DfOnR/FFZDtZm4McVTAxGbHNOfm6rRXjruDHUGwoWQQpoperzp43HZX19CUP+5K1ACez
         oKkivGZR4gLhBMsxmvVtHpEbQxssBExC8+DUPRfNCq82OFV3XUdie8DChPJokxFuBQRr
         Gj6Fcs0S3I1C+Wa/i5f2x7Fxd6av4ky/8h95DELW/lRc0LDc1+T/1rEanqR6nGNsosbQ
         qK7092r+Lykuaj0BhBri9qtkLphpzDl0F9Ta3nI1HYOhkPZoAbFozqblg8KpEDlbQzrA
         aAoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bOdZjXxZ;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id l19si219476oih.2.2020.09.18.03.43.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 03:43:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id t7so2952351pjd.3
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 03:43:06 -0700 (PDT)
X-Received: by 2002:a17:902:b117:b029:d1:e5e7:bdf5 with SMTP id
 q23-20020a170902b117b02900d1e5e7bdf5mr14202673plr.85.1600425785327; Fri, 18
 Sep 2020 03:43:05 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <0d1862fec200eec644bbf0e2d5969fb94d2e923e.1600204505.git.andreyknvl@google.com>
 <CAG_fn=X8uQoZUXM0cU8NwF41znWiFQS1GjSNtrh5-xM02-nnJw@mail.gmail.com>
In-Reply-To: <CAG_fn=X8uQoZUXM0cU8NwF41znWiFQS1GjSNtrh5-xM02-nnJw@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 12:42:54 +0200
Message-ID: <CAAeHK+y__nEtGeS2iQ5Uj+tUB6AwFDg3u3FdF7kcTgmq73OGpA@mail.gmail.com>
Subject: Re: [PATCH v2 05/37] kasan: rename KASAN_SHADOW_* to KASAN_GRANULE_*
To: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bOdZjXxZ;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Sep 18, 2020 at 10:04 AM 'Alexander Potapenko' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Tue, Sep 15, 2020 at 11:16 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > This is a preparatory commit for the upcoming addition of a new hardware
> > tag-based (MTE-based) KASAN mode.
> >
> > The new mode won't be using shadow memory, but will still use the concept
> > of memory granules.
>
> KASAN documentation doesn't seem to explain this concept anywhere (I
> also checked the "kasan: add documentation for hardware tag-based
> mode" patch), looks like it's only mentioned in MTE documentation.
> Could you please elaborate on what we consider a granule in each of KASAN modes?

Sure, will do in v3, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By__nEtGeS2iQ5Uj%2BtUB6AwFDg3u3FdF7kcTgmq73OGpA%40mail.gmail.com.
