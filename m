Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2NQ4OMAMGQEKEMFBEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id CF0215B0BB5
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 19:44:13 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id f26-20020a4a9d5a000000b0044e0692f7d0sf6195130ook.19
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 10:44:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662572650; cv=pass;
        d=google.com; s=arc-20160816;
        b=bPre0poARPY5WaI4BylJmQSJfEDmAs83Ph7vgIo1ezR17FFSamRIpZ2jXZEf1IOO/U
         i/npn/LUF4dKuMlNuBeOf5BOZzqusrbFsoN9s6aaP0Zh7FZ2sFqyYIf4npz3QveoEak1
         kHm0/sRV2D7DOXJpqb/QE5Z7Kdr7HPT4NccVubScMzHp0mzuHIDlyNnbJ2vbumvurIgr
         wFBI/zytiYHlOl+Pxx3hXb7WVgPtqZyoml6Ml2YjBvIzkBI4MPxzQQZ+tRuAmEPSznIM
         0RWPO+S0g03ljR0KNXB32frsMUA848wM4sBVkuWITd1JQnC4s9Y/U8esHDbMv3dJ4g6z
         RutA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mRzb+kMozcmwiDsL5yWbKJ6L2N7GSAeNrD3XdSt7j6E=;
        b=FaZc1MMmp3jWh4MvtzOIwjbq+dKlVYdUbulVtrbkqe703Ig6XgGHp9XR9llpsd/8c1
         Batm4UfEvGzO1yntAOOT2Jnmo5da4zrYI8d9wokESQ6rc2aSahoVJC50FkPHrLkkXEXX
         5yR1CvLaOFc77KcA5vrcgq41oHL6dZ37gEVT5wHC6mGWkN0LyMQaH5TyMx6tOn5olUXq
         atvQDHSh9U61Wew5Gn6xRa++bEazNHhnRMca1me3wZroDZjxQiA3aSqL/dZrlpaC+U43
         5sVEgsaOe4Opad+qb4A1MBRHg1nAJZrOf3BDQMBqC7IqDoH5M7EfI3ui3p4dh0SOP7j0
         5ahg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Aoe02Mj5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=mRzb+kMozcmwiDsL5yWbKJ6L2N7GSAeNrD3XdSt7j6E=;
        b=RSEYpfc8+zzOP9tMA+zZ+wj7Itt+rSK0EJREMG/HvYKjc9NqvPzi56loIf22LkIcg3
         CcNKF0VTrtSBOivBk+hVLaRGhFoV41xCqBjSsZEqizy3k6Bf+Qu5PkKEZolhJY1AACkB
         pwAuDV1uDh7BwEkMp59CLusPZOxeVdDOBBtk63lf23kdFWH7vZo+5xQohMTKImCik1DB
         OxIqelUYJFMLpSkVxNaK6/JHXhSEc9/yJmrh3dFug2TAPUnaBjXAfM5SLq6vcKLQDV4F
         MWxoieJiIOpC3BAnKRLOncQ1HGDDjUMYGsQwQWeZJCe9cT8KtnEGd3WQwPqyQo5f+64B
         TI7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=mRzb+kMozcmwiDsL5yWbKJ6L2N7GSAeNrD3XdSt7j6E=;
        b=CWmVRQ/DFMtmFC/bhGiUMk/X1OOolFe7ifZA2ATFs2cruHJ7eVLcRYqAeuTqAyMEDU
         trWDAl2CAIA6B/5flJVUjVA0BhtyKm9QIbaZWx729+ed5bduGdJT0oHrmW63j0KpjO/a
         UvM2QAtQaWVG80o3ZUNfARwloYZ5pLJliUdQZ+uEM0Dw1di6qEtUPcdRWWZ3cXrkWC+N
         YPpxplL5ex4pKZf3QPl1DFKLPIL+anYVssCzQYN+f4257QdX8C03n88mnJYa0tpui5/R
         VCQRx3zwQj6FfyYrRh0FH1ISfKS/w/dcH9DnXW9dNkZPrw9XzTHAsYXQNfbUkYxrnfAL
         Js0w==
X-Gm-Message-State: ACgBeo1Wx43V0r4JGNd0cwbYGmSVd8IYp24yJyTBZNU8dG0lQH8WzNbk
	2sbrkL6U11aHNlpeBzpkw3I=
X-Google-Smtp-Source: AA6agR6ilefYvTWpi+T1PHK8MEwbUIZoM7vj/EfpymLeqXpIZtM8Je8JLE5zdUr8D44J/4GB5DW2Vg==
X-Received: by 2002:aca:210a:0:b0:345:443d:5c41 with SMTP id 10-20020aca210a000000b00345443d5c41mr11759391oiz.89.1662572649352;
        Wed, 07 Sep 2022 10:44:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d8a5:b0:127:2be3:37fc with SMTP id
 dv37-20020a056870d8a500b001272be337fcls3831880oab.10.-pod-prod-gmail; Wed, 07
 Sep 2022 10:44:08 -0700 (PDT)
X-Received: by 2002:a05:6870:6109:b0:126:e1a2:12bd with SMTP id s9-20020a056870610900b00126e1a212bdmr2350939oae.243.1662572648853;
        Wed, 07 Sep 2022 10:44:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662572648; cv=none;
        d=google.com; s=arc-20160816;
        b=vDBA9veXBApcfHzoLHf1xtsxGp0zM0hJ2PZWsN8CXm+QkaqZtybh3324/5xIbp663V
         oW4ylKY8nELi6x2qCSkfSiCWo4Fgi1J0Z+krvCDbk9Amhju/xoJOuK1WORL4THMPT4is
         nfTJdslJRrA74Rt+ZbWJsxbcoX8gAvHeeLXveyUPf3Ec6cHilZcEgezBL/0VKssx4Vjc
         cnOBK0mudDrjRvbWbu12MfVqtktG3Hld4KIoc+HYBXBMh8ylVeZ6u/HDRW09B6PxY7+2
         6iRvlxJQ83Wba6J0WxpSC8VsJMfU59GnDg2y7eJp1z2FdEYOSQbsaw/k+0LADhXfVFQk
         SUVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=N+KH0bFLs52wGl8kzsXXlEDsvOIn0U7dgBgJ6SkG/So=;
        b=AJ1XHgPNWnEU6dFCLmvOu6RuKz+fXjr/mLeq77A2NfEB7jueOZYPNY0b5l28OmnveQ
         HKXujfYNDlZefosBUhj0vsXrkFdzl2mn3hD8xRumtAKQITwwoGauCqCOEwfH5qCRxxtd
         IOB2omIk0CXVaV7kR4ccR9EIf8JD5Pwhjz3QmpZmpM+qn/cVdBK2Zyg7l5oX34Xhczge
         pd52nWGCtHxgN/lK1J7GCK9/nsPo9G9f14DnnduySKriNd2qUPHAKbdrcaAnanZyZImn
         FTVA9+KrunC2UpajJH8twfLe16tRKbjULla7ayZQgS5/pdYJBsNgf0pZwwOZxXvyYak3
         cVMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Aoe02Mj5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2e.google.com (mail-yb1-xb2e.google.com. [2607:f8b0:4864:20::b2e])
        by gmr-mx.google.com with ESMTPS id z3-20020a056870d68300b00110b77f4e1csi3234883oap.0.2022.09.07.10.44.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Sep 2022 10:44:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) client-ip=2607:f8b0:4864:20::b2e;
Received: by mail-yb1-xb2e.google.com with SMTP id c9so22703036ybf.5
        for <kasan-dev@googlegroups.com>; Wed, 07 Sep 2022 10:44:08 -0700 (PDT)
X-Received: by 2002:a25:602:0:b0:6ac:9a9b:f587 with SMTP id
 2-20020a250602000000b006ac9a9bf587mr3750619ybg.125.1662572648292; Wed, 07 Sep
 2022 10:44:08 -0700 (PDT)
MIME-Version: 1.0
References: <20220907173903.2268161-1-elver@google.com> <20220907173903.2268161-2-elver@google.com>
 <YxjXwBXpejAP6zoy@boqun-archlinux>
In-Reply-To: <YxjXwBXpejAP6zoy@boqun-archlinux>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Sep 2022 19:43:32 +0200
Message-ID: <CANpmjNN2cch+HDVUYLD27sF9E39RaFrCf++KN=ZZ7j0DH8VaDw@mail.gmail.com>
Subject: Re: [PATCH 2/2] objtool, kcsan: Add volatile read/write
 instrumentation to whitelist
To: Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Aoe02Mj5;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as
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

On Wed, 7 Sept 2022 at 19:42, Boqun Feng <boqun.feng@gmail.com> wrote:
>
> On Wed, Sep 07, 2022 at 07:39:03PM +0200, Marco Elver wrote:
> > Adds KCSAN's volatile barrier instrumentation to objtool's uaccess
>
> Confused. Are things like "__tsan_volatile_read4" considered as
> "barrier" for KCSAN?

No, it's what's emitted for READ_ONCE() and WRITE_ONCE().

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN2cch%2BHDVUYLD27sF9E39RaFrCf%2B%2BKN%3DZZ7j0DH8VaDw%40mail.gmail.com.
