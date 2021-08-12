Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUED2WEAMGQE546MKIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id E70193EA7E1
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 17:44:17 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 61-20020a17090a09c3b029017897f47801sf8332749pjo.8
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 08:44:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628783056; cv=pass;
        d=google.com; s=arc-20160816;
        b=OIAH1Dhjp0475Vk7rkcaOZto86n1PoV8oWdCeWy37Td6ee5lOvDozsG19+KZIERZ3B
         kJseBxJfaQOz9Nyq4QxlZRsYbMpu/cqVKlh3fmbbUtVZzsDxQAwR9/h2GThpNf8jfqgC
         XkH/lbloEeNdL73RngAH8pFyCU7zQz9uvd26mzke73pnvTJ6ZI8WObJ30ARjH4L2yM7c
         3CCYUNA+9StyI5FJyCQUiLgcoBLrt3bzy8+cMCr8Xkk12XzdUdQkaIRyzgF1chZelNnm
         XCL7SB21Y7kM15TNsxJcqYrzTll8I+IXm7+O5eylDCDDaBITcsRyHbZ1Mxbs26U1cB1E
         HAvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tah75nOTVLh0UA5R3VuQqOZXYlNfIgUrOTlxaJFD6xc=;
        b=w2dPK2T4nMNTRx+lkM4qdughGoRXJwtp6YCyKAqg+Lwegww8hGUp7iBTxSm4YOghYH
         ZRL8aPQSe6axzBddSLecYRHpOSeroe2cU1DdmuTrZ+nLwFkovH5EB4Ebvc/j6HFYL0Ch
         DsbwYSuLDIsyhlz8KUIJOj+SybIbVLltp5I8Im04J89Y9FLRHy7VLwYNq0Pt8J3XBXNq
         MOvaH0VzOBMeXCIf10KIKFBj1lZaclaAAdfd+q/whYrg1enMQ/8NPDq/6k8bzLyym6SH
         hiqEaMw7H54SwHHl+s/VDga5QnG0rL6mBdc7pv46RyNsUdBr8ZNODuMmT1ZiLq+VLIhS
         jdlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vRiM7MY6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tah75nOTVLh0UA5R3VuQqOZXYlNfIgUrOTlxaJFD6xc=;
        b=rYZWLl3vxpYNJxb+6VgBx9xik42Ks0/wcPEIpnhx2tINllnTho0qtK6rNhQMf2n+MP
         U2knATN11j/Uojlm+Mph9k5brAfOoWCRtf/iYMgfl5M7ZCc+8HFHiYNJoDcTGjUEMec3
         uHDURqaSXlSza3osrsjmb+km89mN1Bz+WVvXNz2FXCJ40pMwRlv6hx8sjL2gfjz+BN1A
         GBBCnv2rbqMsgW1dNiArc7sLhjikaRywyVh+BsvgTp7L8r5nO8QrRB8Ar9Yi3gjaqYu3
         fbDkfkSV86kgCLuo8sSp2D4smwDwT7wC81LRWlAWEVQrJ3BUx0w85q+PDkiFtUmGCKAr
         S6KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tah75nOTVLh0UA5R3VuQqOZXYlNfIgUrOTlxaJFD6xc=;
        b=EqIN4tikq0728lB8JAgKSqKn4yq8ZXKTEEf2aRCNj6dU4GhGKZOLREN272pKWc2vW5
         QQKEkpPhU96kaqGEzKQKd0rYX5zzooDpLGJ+k/flHKTkPFKAjyzIv/6h9JFGjPte+RDA
         bhlvrpOuR7jpWSE5Kw1I3nfSkPyABE4U2FcHav2wHKfMCLGaPW/o1cmhsQlF+wQHa/a4
         Ny8zXghxw54jFmjrjg6SbsjDfTTvhV3AabTJNy/TCbfEEIbPyHV+guCF1ebtRNXWGFH6
         jT8i94pi0eQoHJ7x9HtOLsQJIv0c2Fd23uDyiyGF6rtaMmZ5Qb1xvKIIAmXRS9qtd2sb
         xnug==
X-Gm-Message-State: AOAM530rPAOyu+rq360WsD8uWn8CcqjQ8lgSxSJGieaFvfGZPUprALpG
	UlQnRDtrbpzVHhji3gSNHDk=
X-Google-Smtp-Source: ABdhPJwwhqMPrAoq2GOvxzzu8MQ3PalkVJZDsszEwj2WymPFtVHlitzQI6JgCD7JJ8e8Qtdz1hQybw==
X-Received: by 2002:a62:3895:0:b029:3a9:abdb:d558 with SMTP id f143-20020a6238950000b02903a9abdbd558mr4722336pfa.19.1628783056251;
        Thu, 12 Aug 2021 08:44:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:aa8d:: with SMTP id d13ls2714925plr.4.gmail; Thu, 12
 Aug 2021 08:44:15 -0700 (PDT)
X-Received: by 2002:a17:90a:c213:: with SMTP id e19mr4890648pjt.58.1628783055682;
        Thu, 12 Aug 2021 08:44:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628783055; cv=none;
        d=google.com; s=arc-20160816;
        b=jqCKM73o62QDlrKQZNToMWq9/20aOSFIaUk2bZflOprbMJQ7J9Mml9HJXvVTJPudCv
         1SaWVRcARYbwt30hXx9xT6h/z1mj87fyzmvrN06J4RZMC1TmmMI9hPKaqWT7cdHsAQBu
         DzbvylfpAbQ5G+9DM5QsRtKgPhachIMma67SAvBAFDmIlF87nmxvgK3DBJTqWeGgSC9F
         WpF9WJTW81zvzMG+jwJAWtgCYbgxVB+qCsT19dBA1uKznSiz1soMB75z/IEJoWDVlA6i
         jJMPPh2A5Lcu1n3E8DPl8blT7rIp1TG6Gt/6Nb+zd/JXOPBnPj4juK2xi+CJNeBrqO7f
         syKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zpfP7I/jc2+BB4WhfHjvO/EMXto5OQE4zX/MsZU99j8=;
        b=sud3EcFzku8q+Wb2C/8kI8S1k04oxg05bBaavjGCV9MzLHnHkGbVKoO7yF1sy2W2Rw
         2wdu9Fo+yJHXW1WLr3LNTMtWZjdxb+iUkVfDVUFCW/ARG18AIwOJUKlXTz61nOsBzXSF
         l+bA/E6T4cS/XRusg9q57Zro9WGaTl2PS7YQGo3nbnI0LhIfBy+CjImaU/gurMMyLBlZ
         3Op7KhC2oQHtjeoSlM1YXs1hrrkVPXIUvu4PWbl2mbk6r/vV+F2HUeXDDP7zM2a5SBq5
         gjewkQt7gBP1GvjvHhPadmhNqlEowl2ijTpwMuOX5dd5i71deobmvKSK6uYv8HoEE1uP
         C7Nw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vRiM7MY6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x236.google.com (mail-oi1-x236.google.com. [2607:f8b0:4864:20::236])
        by gmr-mx.google.com with ESMTPS id e1si489719pjs.3.2021.08.12.08.44.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Aug 2021 08:44:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) client-ip=2607:f8b0:4864:20::236;
Received: by mail-oi1-x236.google.com with SMTP id t128so11026302oig.1
        for <kasan-dev@googlegroups.com>; Thu, 12 Aug 2021 08:44:15 -0700 (PDT)
X-Received: by 2002:aca:eb8a:: with SMTP id j132mr3817727oih.121.1628783054859;
 Thu, 12 Aug 2021 08:44:14 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1628779805.git.andreyknvl@gmail.com> <CA+fCnZfjsfiAsfnOxJhMaP0i7LaDgsVSkrw_Ut66_E_wQ3hE_g@mail.gmail.com>
In-Reply-To: <CA+fCnZfjsfiAsfnOxJhMaP0i7LaDgsVSkrw_Ut66_E_wQ3hE_g@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Aug 2021 17:44:03 +0200
Message-ID: <CANpmjNN-0C8Q4q_Hx988RPSVeb0_54C=cRxfch3H+V3Pb5wWsw@mail.gmail.com>
Subject: Re: [PATCH v2 0/8] kasan: test: avoid crashing the kernel with HW_TAGS
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vRiM7MY6;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as
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

On Thu, 12 Aug 2021 at 17:06, Andrey Konovalov <andreyknvl@gmail.com> wrote:
> On Thu, Aug 12, 2021 at 4:53 PM <andrey.konovalov@linux.dev> wrote:
> > From: Andrey Konovalov <andreyknvl@gmail.com>
> >
> > KASAN tests do out-of-bounds and use-after-free accesses. Running the
> > tests works fine for the GENERIC mode, as it uses qurantine and redzones.
> > But the HW_TAGS mode uses neither, and running the tests might crash
> > the kernel.
> >
> > Rework the tests to avoid corrupting kernel memory.
> >
> > Changes v1->v2:
> > - Touch both good and bad memory in memset tests as suggested by Marco.
>
> Ah, I forgot to include your reviews/acks, Marco.
>
> Perhaps you can give one for the whole series now.

Reviewed-by: Marco Elver <elver@google.com>

Looks good, thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN-0C8Q4q_Hx988RPSVeb0_54C%3DcRxfch3H%2BV3Pb5wWsw%40mail.gmail.com.
