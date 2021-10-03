Return-Path: <kasan-dev+bncBDW2JDUY5AORB7VT46FAMGQEBV6I3SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 04AE14202AD
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Oct 2021 18:27:44 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id a18-20020a6b6612000000b005d8f6622bafsf14032292ioc.12
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Oct 2021 09:27:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633278462; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fp/CsKLFK3V8FUadaamQbCmg2lOB12Lu2DlDOluw80d+FWCLc+ySBtNeRUaznbELtV
         7czniyMsh067BxvcwqTZRv+qleYvud4t61oUyFWCwmw4G8w3irz6b1ojCo+p+3OFFdCb
         iEBizeki5MWCMWbFX/Fko7aCgDIHcI8NABFD0nmVHEtIGODW0HgLUQl33BGZYqGRbPno
         uitB2TLXC3XIksGaYgs0IhzXZ8gl4SdKh54MHrwN0sJXOODKRQnVoAZINaCSs/ogC/QM
         odkc40bQ/FftWz3Drbb48vfPyJRwOFAk4i4HMoHLnUZmGPWEXuZz8CbrlcKC3a8l4WzE
         720g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=w+GlEuhDgLIUhtjEkLS1rcEaSLTXWV7ZmAVaJDW74JM=;
        b=YOFAZFYjCM+CvZNf8JLTHugoMB8V3IGZv8RcjH51h6VZ+fJzJa21RSt2HZbzGXIKWR
         xhoLA7ga8sHG4DW6j8ThjBJHPob45Q8cE6Fgoh4GOCNiJ9SBztD9LVNE8Z1qIkPforMT
         BHniE3YY02gkYTDNZrCm07F57aFwhvQhNpUrCG6y0zygE7mrOV9WoVRhhw8zp36F26LO
         TnNV5WTKMC4+feKMi0eAadM1XNIxSLga1sfxTjemSTwz4v8SsnO84Q8sbKIzOJbwNCll
         5ByLABi1XdD8JGajJcmNngyZomKDWnss5bV2JuFyOG2RTIBixkq2pxX+wCKZJGG6h4+3
         XIfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=MXjrW9mY;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w+GlEuhDgLIUhtjEkLS1rcEaSLTXWV7ZmAVaJDW74JM=;
        b=X0HN4L3ILrgVhYLWzzR6ZgfMrrno/saZSPhHCxJJg+2T9q4RHf92wQ3I7J40wHltke
         hqqX0xpClZag6K4YJvhCx1EsahY/wAmaWpMStBv6PppHNX9wYAQAmztCBoL+KWqqNDna
         xeGTQhuKVHpJ9aJs+6X+l3VgXJbEcJZUoqpFc7i8Ij8ew2Xwizj/G4Pz3ROU1C3IZ38G
         u5t5gpaAxYD0lw6FL6ZuFwS/Rr9+3QDiA9ehlxpBLNAQlWtM/FX8ZYEg+xBOl5J4yW58
         gEkuaiZCwhXXLT2xTKAbQbS5VdlOEY7yz8K8B41N2Sdqhr2oQGOMm4G4F1L4+mpoNpL+
         MCmQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w+GlEuhDgLIUhtjEkLS1rcEaSLTXWV7ZmAVaJDW74JM=;
        b=qg44nW1mdt7d/bgfHcAdrU08ZYuW8TY+ZWL1P+hYhVKLcT9jIkIi1DdyGp+971B9Bg
         Aw0Qz3NSJa5vSi/Pe7Hbd0Xd3HR0Iu27Jy74Q0/RSml8ImHID/4ceXNqEGmiWZjRR0HX
         L6UrCnKhgt++bE4KkBbpME+AO1UPIT2ssV3pE7IggeFPtFZi3fHGiUCOITKjkf2SXl2Q
         4eeXx0d8hNiL7CIcB5iuyRLs5uu5ty//8nJvvM7tfrO2zU/ZcTudqF+NKfhltuh1oyyD
         OgLqst/Ju32lDrHS7hhuOyLOuUcjRf+scBV68yMmCdu6aOrggixn1HNjD6ieZXZIdPxc
         XYrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w+GlEuhDgLIUhtjEkLS1rcEaSLTXWV7ZmAVaJDW74JM=;
        b=sB7zUfiYGOngrcW8Z0nQhTLqLr9p942aMsftPejzKdf79ppB0C5UZdTDvjStVbN6x3
         UbspYS8fpn0XTY2yQl20aiQwBa46ieszkHdtPt+21K1v9RSD36QZW3o30rdiGTN6ifNE
         kp4VAUgUnWHX9PmWny/3R5Et1HCDE/SzO/RmwsiCQJd1xXB1R0OVfWJWo2tKI40J3LcN
         DFb4ZprPQFfm6H+XaN6iO747u2739buj03IGwGmshMxT6tKkNldzuFb3Xp24IWxv0j76
         CCjR4YwWPVdyS2cWxMz5MAA3Ln3QX5YtrKJoXCxXrDupfNKd/u5xWIdlQhNCnLkCXyFm
         lacQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532SrfrLn/uWVVcMtRf+5kWDHMDYubc5JMjpfMIc9Ekmn2l9IfQR
	7poaP2EC9nk+2iNs3yjIuiY=
X-Google-Smtp-Source: ABdhPJwuuSFcSRCRHAt9/RmuJB6vuemjbPJ6zmD5Qx1VZhABBkCaYKV40AjGgENT9zZYXly2c9RMyQ==
X-Received: by 2002:a05:6e02:148e:: with SMTP id n14mr6721985ilk.319.1633278462629;
        Sun, 03 Oct 2021 09:27:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9f59:: with SMTP id u25ls2259310iot.10.gmail; Sun, 03
 Oct 2021 09:27:42 -0700 (PDT)
X-Received: by 2002:a6b:dd18:: with SMTP id f24mr6295049ioc.165.1633278462241;
        Sun, 03 Oct 2021 09:27:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633278462; cv=none;
        d=google.com; s=arc-20160816;
        b=e5lW7r0WlZH07faIrHA/YobtL1TlLvdxJxtnxW3d83qyfSKCoFtEfzp6RCb/1SxZHe
         MCZ6yhaZhDSJWNr0dmOJPv1Y1e1n5Zpc7B8wD1B/2WUTujzhUdGJ5u/ZXgtk6gGsU7hj
         psaN4cYMwh3J764zhil10grAjYbrQFoT12psH5fEybtLKXPA0O9AF5eps9QnwzEAql00
         PGyaG+yCmikI8Y+TCS0EyJzjPCg0lXI1dyRfN2UnXreYZvyMHmMDpxf597gug5hAMdXT
         WbZOZGstZm1Jsk5PyMfrp+beggbDgSIi7ZvFxi06/50ESwyws+/W2cqhxNdDoX1+Ki7M
         i3QQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=U5w14pACpoxsQ3TFrs7KmyZVY7r/vaDnkMZUZO1ngik=;
        b=UhLAZQyh4Wv+yS8wgpHI4YsQTKXSpJhMrmNqHsJGN3TVLi7lITg9/ogaN4zIFu9OWh
         d9Z8p0EaghBap1aETKzsCvCXrUpprfuvOQT7Wws3uUQm7nwhxpokhcs5cGoSSdyw9AXi
         sN5ywMoNZj9Ad1KJA/Ljkfv6xRYNPDFmvekwgT/3dhLa4e8N0YzCAMqo63qm+/NriK5E
         XlOzbICul7honwQ1pM/2lfUtak0llCnTxyWm4WFUGQGKH9nf+EwI5Stck15n4BxTB4jA
         Ht3aR53qwa4106Vm9ejNW8y3G4LmmG7wksFSg3pIKjDzmHya5DOf5WAhPJtPbaITRz6i
         6Llg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=MXjrW9mY;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd29.google.com (mail-io1-xd29.google.com. [2607:f8b0:4864:20::d29])
        by gmr-mx.google.com with ESMTPS id x20si824250ilj.2.2021.10.03.09.27.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Oct 2021 09:27:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29 as permitted sender) client-ip=2607:f8b0:4864:20::d29;
Received: by mail-io1-xd29.google.com with SMTP id 5so5002222iov.9
        for <kasan-dev@googlegroups.com>; Sun, 03 Oct 2021 09:27:42 -0700 (PDT)
X-Received: by 2002:a05:6638:16c5:: with SMTP id g5mr7339293jat.130.1633278462090;
 Sun, 03 Oct 2021 09:27:42 -0700 (PDT)
MIME-Version: 1.0
References: <20211001024105.3217339-1-willy@infradead.org>
In-Reply-To: <20211001024105.3217339-1-willy@infradead.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 3 Oct 2021 18:27:31 +0200
Message-ID: <CA+fCnZeJ1AdvEmNmwo8r+ue0qtQVUoQyeMSsq0DMXyK2EQxj5g@mail.gmail.com>
Subject: Re: [PATCH] kasan: Fix tag for large allocations when using CONFIG_SLAB
To: "Matthew Wilcox (Oracle)" <willy@infradead.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=MXjrW9mY;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d29
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

On Fri, Oct 1, 2021 at 4:42 AM Matthew Wilcox (Oracle)
<willy@infradead.org> wrote:
>
> If an object is allocated on a tail page of a multi-page slab, kasan
> will get the wrong tag because page->s_mem is NULL for tail pages.
> I'm not quite sure what the user-visible effect of this might be.
>
> Fixes: 7f94ffbc4c6a ("kasan: add hooks implementation for tag-based mode")
> Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
> ---
>  mm/kasan/common.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 2baf121fb8c5..41779ad109cd 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -298,7 +298,7 @@ static inline u8 assign_tag(struct kmem_cache *cache,
>         /* For caches that either have a constructor or SLAB_TYPESAFE_BY_RCU: */
>  #ifdef CONFIG_SLAB
>         /* For SLAB assign tags based on the object index in the freelist. */
> -       return (u8)obj_to_index(cache, virt_to_page(object), (void *)object);
> +       return (u8)obj_to_index(cache, virt_to_head_page(object), (void *)object);
>  #else
>         /*
>          * For SLUB assign a random tag during slab creation, otherwise reuse
> --
> 2.32.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeJ1AdvEmNmwo8r%2Bue0qtQVUoQyeMSsq0DMXyK2EQxj5g%40mail.gmail.com.
