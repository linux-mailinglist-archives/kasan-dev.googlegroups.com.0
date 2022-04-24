Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBVV2SOJQMGQE2BFRPHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 909D250CFD2
	for <lists+kasan-dev@lfdr.de>; Sun, 24 Apr 2022 07:17:12 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id t3-20020a656083000000b0039cf337edd6sf7184783pgu.18
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Apr 2022 22:17:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650777431; cv=pass;
        d=google.com; s=arc-20160816;
        b=q9h99eXzCQYNIYWGSVA1TPn+yPP7dmmPernGdjl3XXZGs1S0sw0KPvAZhzBz8DzSZG
         25ivqmH1MKzQD05HeZhDGPknMjoPsG8/mTplJcDyV1kKmd2gcO20zBYqIUjx04em+uvA
         0B1WH3jwGJkz+D6uTxkwTO1oCa/bpgPcuZjyehWmYw6gbGHkpz5zGSuV/rgcf44TITEj
         //rTqHOmIDf/usNmvdmdFuyrYS1tyfwi+DsEix1VKqCmTfHeT757CqB0TxjSPjkL9AYi
         cG92XPNQAmBWP7iUmALRPNhC0+5kHj+KrNMKPRizbdgLrnQBQf27vcM77uLDs9o4L8Sm
         fh/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=XfUlnIcjvqqfjoFvNUKbFcWVmDWfUwSxjsK4a47SsTk=;
        b=qHUvRq//xq6pScE35ugvUi4ySSPsrxYgC6ONg2L1tp6bBc/KvAtjGXK5wkxloCgN0H
         mv5CfbOr96TwHxtDaCokJTuUq7kHR0n7E4PVa7K6/waTgAqbuVYOp8ZjLImN/RhHG8ku
         0/TXXRdiuVeIck50hU/pxHC/Bq23BiNrSEA2y60Yd/85Nxnuxz5IbE20iijYUxY3n9pF
         M4esjwZCRhnDKTEohq0lyEp0N9reDhjVuG7zt2iAVaP6HTo8ZloOIAkxI54ZQu4aUT6a
         rkvBllBxvnZkUN7rg0AsyA+6bxdX24kOOR35az6fO4wjuskhA4W59TUmgqhhtEanPk4Z
         Cdtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YGE4UXFL;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XfUlnIcjvqqfjoFvNUKbFcWVmDWfUwSxjsK4a47SsTk=;
        b=UY6nqujLogxRzbtwoj+AMm5YesigZ4sL6KJjdP5zULjf0QSIqMSR24orNDoBkE0wnh
         Hg+NQVdII4Il0GszAqPODgOjMXYW2ikOpoeUyR3wHVEQDEp1pOc84nhzhyRMwYdgGdOQ
         lRzZ4KkdYXYMT8GKo0JD1vQMEjXVEm+kdXORPToZRv+jdeqmwtc6PGGFIHpDNaw6o8WB
         JDfJKZoNcajtGMkGcVuX5uzZAMSgaTe+7DLaRrUlcw62l0h0GwCntjIxM3tH/a+Tmq5a
         uHeX3uEGTT/QRiB4LDxo8bToaQ1t2KkQWEYIdO13mcqOtBwfEJHLm7KAPPYHd/RuzL98
         a1Vw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XfUlnIcjvqqfjoFvNUKbFcWVmDWfUwSxjsK4a47SsTk=;
        b=NozDEbIP8WNx3ztoWIXshRulKnnstbrhfSQkGkClOs6wmnZRcF89kZLlVRV+RNlFFt
         rAquPLdb3S4jn/jQtwp8mC1XOFA+2ldV+CBZM14wLRCv49KFQLxCsbrUq3RWaL61Dee4
         z7kF5XW2K96qw/3FcD/BPaMZZSa1XlIDO1PA++dw66qcexrT63F6LTex5USxXfexH4Ix
         ViMQfaHUq8Yv7XgvjTceFeeMs/fA6NEE/1mhfe811jI6ReqnuWH+++DOP8skGfrn+bsP
         vWGylSGZYXY50LAOZLJl7A5byvI+PoKHgGisJboCAl5g7rI7E3l2z2WAxseHD7iNo0oB
         7lUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XfUlnIcjvqqfjoFvNUKbFcWVmDWfUwSxjsK4a47SsTk=;
        b=OxK8g6aCmD/m8pZZsggDOcyGpXpky9kAhH7BfMBs4m4edCY0Z1X4BhHx84NH1qgGGk
         EPA8m0kJM3KcCkKQlV3YctT1mCJFPQN5oEQfJnEJOcVIcd7HbOPPwekqG2pwWZV6NQRG
         k8FFs0/dfYf/avtBhGdL9mWftuw+S5EnZs1ZaHzN1KoLQ5p/LpA9c/yBKe+w0SOrJV10
         dYo99roKUua6qoZ/x7B6JteGauq1M4CLGSqhXr1fPDjHcfElEALXq/IjHqmsJsTx+pT+
         Ars06dm8g/KnvD87j/vdjwtIBa+zlKLWtkLNa2g/qKf7b0JqNwFKM/YolxoqSjcTBwab
         DRaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531jUjnKIlv9HNpMZ8hDmXIzNKdry46eWzXYHv4MYe9N++4ErYZj
	7bRf3yfkGGSQ+NjADNGjbBk=
X-Google-Smtp-Source: ABdhPJyyrKZ42PTuxhfYpADvzx6kGVo/0pMe/MAfY6nyD9LVezyD8Xd5qLTqd4b89jxaJIz+JogDrQ==
X-Received: by 2002:a17:902:9a8c:b0:15a:a21:b52a with SMTP id w12-20020a1709029a8c00b0015a0a21b52amr12024821plp.86.1650777430628;
        Sat, 23 Apr 2022 22:17:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ecca:b0:158:f6a7:5bd0 with SMTP id
 a10-20020a170902ecca00b00158f6a75bd0ls11154493plh.5.gmail; Sat, 23 Apr 2022
 22:17:09 -0700 (PDT)
X-Received: by 2002:a17:903:11d0:b0:156:6c35:9588 with SMTP id q16-20020a17090311d000b001566c359588mr11832996plh.50.1650777429662;
        Sat, 23 Apr 2022 22:17:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650777429; cv=none;
        d=google.com; s=arc-20160816;
        b=WzrWfI7h8mwuBOgPBcjkWREUvw4pgjzsaZZ5AYDXG9ug+iebjEv0cyl8ePSksK5oyG
         2eR5XoibTjtQR+Ex9rhBbF4pJ8fXPibMgnCOtdhnypjlOFGsdRadXqMxVYx2DipUGrUf
         heytj79HGCbfrpLuJ5QAD8Myr0vbQkS7YXsYatOMDKCU/qbtDnMV1xmc0fEgqldT4nem
         +6ei2oG2sTRfPUJeT1lYwI6H7n8LharKgKwB9Nu1Y41NIlPJr3/yUXbeL9C8eSCHW0D6
         XzMzwuZz7iAhNZgC7raenYWD/bhrQ9Rlgpk8FvTpBLxEA8i1Gd810rLlZ6f+y/rE+l8l
         CiNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZFmcLn/pFDeMh7htjVTnOwoz+IWHDFfopBWIvebvgp0=;
        b=hq4g8WUVWx1VVoDH6YuUsUaZz/VubkEh4YwbPs3stZpCW+sZCU3N79KlJafZsP+4I6
         fT2to8WaOBGWYtjIcoTwmcpP4wNtKT+in33oq0d1LPgiJad7qcQHkCpbIvgexvMp7rtH
         RPmgn2MSqpcV8eteLv2XtarvCxsFiDIXNwuXoGkQtUSdJi6xvw1KzE4FK175H9+Tpq7G
         Trn4DoudzPxdBJU+G1+INsAfI8uac2ceT46vor0iMp8qoollYJvQaW1LBISZQzsvNgfC
         lXhZNWchFGdiSwFzyCM+S5fdVyrFsnnvhFevUEOyUCaq8QADaXXxJGWwyVpBOVS0eXE9
         mthw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YGE4UXFL;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id n5-20020a170902d2c500b0015887731c60si817307plc.11.2022.04.23.22.17.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 23 Apr 2022 22:17:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id j8so19900568pll.11
        for <kasan-dev@googlegroups.com>; Sat, 23 Apr 2022 22:17:09 -0700 (PDT)
X-Received: by 2002:a17:90a:730c:b0:1d9:3f5:9a00 with SMTP id m12-20020a17090a730c00b001d903f59a00mr8862014pjk.109.1650777429249;
        Sat, 23 Apr 2022 22:17:09 -0700 (PDT)
Received: from hyeyoo ([114.29.24.243])
        by smtp.gmail.com with ESMTPSA id x129-20020a623187000000b0050835f6d6a1sm7109881pfx.9.2022.04.23.22.17.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 23 Apr 2022 22:17:07 -0700 (PDT)
Date: Sun, 24 Apr 2022 14:16:58 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Vlastimil Babka <vbabka@suse.cz>, Pekka Enberg <penberg@kernel.org>,
	cl@linux.org, roman.gushchin@linux.dev,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	David Rientjes <rientjes@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Kees Cook <keescook@chromium.org>
Subject: Re: [PATCH] mm: make minimum slab alignment a runtime property
Message-ID: <YmTdSq/OcXls6scP@hyeyoo>
References: <20220421031738.3168157-1-pcc@google.com>
 <YmFORWyMAVacycu5@hyeyoo>
 <CAMn1gO5xHZvFSSsW5sTVaUBN_gS-cYYNMG3PnpgCmh7kk_Zx7Q@mail.gmail.com>
 <YmKiDt12Xb/KXX3z@hyeyoo>
 <CA+fCnZdTPiH_jeiiHCqdTcUdcJ0qajQ0MvqHWTJ1er7w6ABq5A@mail.gmail.com>
 <CAMn1gO4WOcFqwkcAFi1mXbBrPxz-BqgQ027unx31iCO2fyL=2A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAMn1gO4WOcFqwkcAFi1mXbBrPxz-BqgQ027unx31iCO2fyL=2A@mail.gmail.com>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=YGE4UXFL;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::62c
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
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

On Fri, Apr 22, 2022 at 10:40:08AM -0700, Peter Collingbourne wrote:
> On Fri, Apr 22, 2022 at 9:09 AM Andrey Konovalov <andreyknvl@gmail.com> wrote:
> >
> > On Fri, Apr 22, 2022 at 2:39 PM Hyeonggon Yoo <42.hyeyoo@gmail.com> wrote:
> > >
> > > > > kasan_hw_tags_enabled() is also false when kasan is just not initialized yet.
> > > > > What about writing a new helper something like kasan_is_disabled()
> > > > > instead?
> > > >
> > > > The decision of whether to enable KASAN is made early, before the slab
> > > > allocator is initialized (start_kernel -> smp_prepare_boot_cpu ->
> > > > kasan_init_hw_tags vs start_kernel -> mm_init -> kmem_cache_init). If
> > > > you think about it, this needs to be the case for KASAN to operate
> > > > correctly because it influences the behavior of the slab allocator via
> > > > the kasan_*poison* hooks. So I don't think we can end up calling this
> > > > function before then.
> > >
> > > Sounds not bad. I wanted to make sure the value of arch_slab_minaligned()
> > > is not changed during its execution.
> > >
> > > Just some part of me thought something like this would be more
> > > intuitive/robust.
> > >
> > > if (systems_supports_mte() && kasan_arg != KASAN_ARG_OFF)
> > >         return MTE_GRANULE_SIZE;
> > > else
> > >         return __alignof__(unsigned long long);
> >
> > Hi Hyeonggon,
> >
> > We could add and use kasan_hw_rags_requested(), which would return
> > (systems_supports_mte() && kasan_arg != KASAN_ARG_OFF).
> >
> > However, I'm not sure we will get a fully static behavior:
> > systems_supports_mte() also only starts returning proper result at
> > some point during CPU bring-up if I'm not mistaken.
> >
> > Thanks!
> 
> Yes, either way we are going to rely on something that hasn't
> obviously been initialized yet, so I think we should stick with what I
> have since it's used by the rest of the KASAN code as well.
>

Okay then we should anyway rely on something not initialized at early
stage of boot process.

And I don't expect much problem on current version.

Thanks!

> Peter

-- 
Thanks,
Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YmTdSq/OcXls6scP%40hyeyoo.
