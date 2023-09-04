Return-Path: <kasan-dev+bncBDW2JDUY5AORBX6L3CTQMGQEDDV4GWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 84351791D57
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Sep 2023 20:45:53 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-68a3ba17c7bsf1721254b3a.2
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Sep 2023 11:45:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693853152; cv=pass;
        d=google.com; s=arc-20160816;
        b=MGS5QII9o52hRfD8Y5mJFd3+hyCaWFgP/mheLlUNXq30lfkr0UAyDvCl+xrbd4Ra5d
         TAAdGTT27Byc8jUx5z0el4lWsO9QgfbtMjtJwY3G/5pITeVopAuZ3glEyxdMfBhEYN+a
         5n5e58nD6r3s0Sa4QIMdhdMCxvh4V5jzXQHdNhGYHzfYzZLwQrJVoAQ878puj/0+/Wp2
         8KzGzF5NGNCgv/NUu4K2Tglpj5Ny0GmihMA9uo5MXKp/XDpXi0vL9mGly/vHwA7PXELg
         v9bP+5hBz3KoFs4nMTOWFY09FDnc8le4S2OLX4ssjH/+aZA2fP45dVI5tQ99dtFgu9hl
         LD/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=p7mbF8smBWcN6ok1k9FsXAAnD0wdUmcKDCDU7oug2MY=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=SHc7o6rIq6ddRMQ0TJulp40WhWDuv/w3FBlvNxdl/+tLooKz8SVnZvcRqF8uPcfMUW
         VAu3EJL169VB0chQdtWaZBc1sIYZGJM/iFVCpuae5AmWVsrFSHR2/OZAfQS02NN563gg
         H2s4WFeYioetucKOo/C9A6z9a1VPGkCjQ+e1kZ2K8F+0jpKHMUgGoMlb2yC+1dwqpl7e
         e67zFZRRRJXkcU+jF/jtgZQy1wdwS/s1fVJqtRadtEkqN1ljYhUR727Xm9kb/O3WYfXm
         D3UeWbQFE61fFbIzMK+syts1syBZ3aLDNlm4MQVIoLhizvSScIj4A+wfuOaaWYDmDNZd
         dD7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=TAsqQuj+;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693853152; x=1694457952; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=p7mbF8smBWcN6ok1k9FsXAAnD0wdUmcKDCDU7oug2MY=;
        b=IVdY6WrMuGZNrjO0xql21MJLtFIurWHma6TX5IvtU+tFXpsh5zeGD33nzhhcxYkBKP
         kPoQqQntTz2lX8cjQ+aGfNIekXopL7Clk/EAdcBrMaRrlfwz6wnLLdpOfEDHOezubn6i
         PRimmEs7A4ayOHgQvg7qNKiiqqsjwmq7pkZy/1hxCYq/epP3mWJm/OIYiyeCq8NeFBhg
         rpHQipPEObVt9ttsFwKFnr+9nYFeUV0TPsLzM7jqj/kQbwIfJfERcFgoPZimtDV2dSLF
         x7e0g9mtxKpa6ZEvKN9mVqrDZzRenvLzEtSnMdzftykLQjZinfqgoMkDu3bQk4HbHWQ6
         QvLw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1693853152; x=1694457952; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=p7mbF8smBWcN6ok1k9FsXAAnD0wdUmcKDCDU7oug2MY=;
        b=UHdGbEYQr1fA9xAnsBHBeMXTHu+kQsrQSz6zVKo5S36pMv/kOVZhufTw21p8kTkGcK
         W4O3A2kbFz4FUWcylRXS1eR+UU/om1kQg58xdwOwqzNDXRTxGXl8NuWtoUxphBvuWsU6
         C0+AinwLZnI3w2D/qEJt6OVwaBKQa7L17QRAguOpz1Ua/z+5k3DYrpgzkYZssPywzJjy
         E6q9uXJeGsV3+5gwydCprLjdRr6i4L/XzTkRlWA2L9okxCCWsIlBavrUiqHRY8IyPfvQ
         e8KKlaaxAP9mrIxk6RNOwdbwlr1EgavTVk15tNj+c/S8IuzWD6zzpCN95umWBctKNjQX
         CjVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693853152; x=1694457952;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=p7mbF8smBWcN6ok1k9FsXAAnD0wdUmcKDCDU7oug2MY=;
        b=jevUMAyhImjCxGLL0NCX3ptj8qt+hMOKQP2w4btFqdReuDyxzcd6ztFBmwAWfWvkJS
         FspfmG88rfMTY+X3afSvrGOrT7bseCx+L3FnT/rotiSe3h606XwJpWIAyiKLbXApkF/R
         +tK15sfSzq3EyHTNqag08F7mZQG8gVUuZptjXeZIvFSGv6VcNhcQqp06Jp7D2UjGm0+Z
         0ejPdJL+JuV3dhOyeAQ2OPIL0pR1XV2A8KzgVtvHsZCqGvk7pk5fnzYfVmzc3ip2LZm0
         KUEwNqnkOh0Ipy4O2lyT2g0CHXfpwauJJLD0CjMoTUmHKKq1OaUTQwNJk4ZXz7ebLWQg
         Aqgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw5XEPiT51zG/60Y+mv7SlkiuMnScmQEFP4blygQ94D0hHzBfUv
	yyYGQMK6JXheTTq2tJoc8SI=
X-Google-Smtp-Source: AGHT+IGVngt7llL7gfndQtdMpQ+ifu1Q/Yz90vWxVfQD3pwtpjp16C+nsV4feSOs8wixgN6NbawLJQ==
X-Received: by 2002:a05:6a20:d403:b0:14b:f86f:d9c3 with SMTP id il3-20020a056a20d40300b0014bf86fd9c3mr8373527pzb.61.1693853151444;
        Mon, 04 Sep 2023 11:45:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7fcf:b0:1bb:2468:23c3 with SMTP id
 t15-20020a1709027fcf00b001bb246823c3ls1452222plb.1.-pod-prod-01-us; Mon, 04
 Sep 2023 11:45:50 -0700 (PDT)
X-Received: by 2002:a17:902:d4ce:b0:1af:aafb:64c8 with SMTP id o14-20020a170902d4ce00b001afaafb64c8mr10646253plg.21.1693853150526;
        Mon, 04 Sep 2023 11:45:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693853150; cv=none;
        d=google.com; s=arc-20160816;
        b=Cp/tMxsVVT1DueWSSMM9y3NKoiK3V9Sdpzbek2oKppHO9+X04uBbxe2XRDDKEsikG0
         opE3/gqi4HYdNxEQLP+qPdCI/Wv2zAuxwNo+Hwd0p0l0HwPulv56o60OyVhtyxWzGrbv
         MsygjZConHUnZGeOTqRUgHO6sSuCBlKdxcGJVSNO1jjA0k6etBx7mDd6oU7gPKHcg52y
         5gEoVWGa8dff2b31U59OKU+LFWEqMu9Ym4qaSltRwblKJTdM3xSzGzxjNAsJV/IfNw3v
         6awH1mKXFPA/Rl2GqWIIVCehaAC5VPH9WpCPK5Mfoz0LbxUGKBqjNTCFqGucGkGxUFMw
         pXEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WZraNgcOpe7Ut9pr2LDBQ0Wst9d1OxSHG4PF5uMFpp0=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=Ip0IAyukkkeNvxnn+fRw5B04McC4lwlra8Jf2ZqFzq5sLasjPO7MpUL28VCRhJIQjY
         RLyzL7UWXgsZC2k0ixSXsH8a9HxNPVEtRPURfEsKVKl3fnh3pNbKYQXk7/YZfLn7qTU8
         xmnDxIpOieOLX3drCj1VmddXtrUakQXkp9Klw5YQa86msEwhc6fi8gvTk1tko6at6hsl
         Bi4UzCidojmU9lbBOq3c2o49QleaNtP32wwuB7eoZu538oj7GVsFU896QJm8L4EE8Du7
         ZHqkUfND0wMtWYS6Yqudl16cztCSQCkAGMvzE7XAwmliDWJ9xpubzw9O8320INO0TK7J
         b29g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=TAsqQuj+;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id l1-20020a170902f68100b001b878f9e121si769508plg.0.2023.09.04.11.45.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Sep 2023 11:45:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id 98e67ed59e1d1-26f3e26e55aso921175a91.3
        for <kasan-dev@googlegroups.com>; Mon, 04 Sep 2023 11:45:50 -0700 (PDT)
X-Received: by 2002:a17:90a:7e02:b0:26d:2b1d:1982 with SMTP id
 i2-20020a17090a7e0200b0026d2b1d1982mr7353698pjl.24.1693853150181; Mon, 04 Sep
 2023 11:45:50 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <8ad8f778b43dab49e4e6214b8d90bed31b75436f.1693328501.git.andreyknvl@google.com>
 <ZO7/CqwhzqulWP7K@elver.google.com>
In-Reply-To: <ZO7/CqwhzqulWP7K@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 4 Sep 2023 20:45:39 +0200
Message-ID: <CA+fCnZdg4p3Lea6HpiKojSgtMEX+V-K+C5FBoGxpfSosDCcH9g@mail.gmail.com>
Subject: Re: [PATCH 06/15] stackdepot: fix and clean-up atomic annotations
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=TAsqQuj+;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102a
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

On Wed, Aug 30, 2023 at 10:34=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> > diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> > index 93191ee70fc3..9ae71e1ef1a7 100644
> > --- a/lib/stackdepot.c
> > +++ b/lib/stackdepot.c
> > @@ -226,10 +226,10 @@ static void depot_init_pool(void **prealloc)
> >       /*
> >        * If the next pool is already initialized or the maximum number =
of
> >        * pools is reached, do not use the preallocated memory.
> > -      * smp_load_acquire() here pairs with smp_store_release() below a=
nd
> > -      * in depot_alloc_stack().
> > +      * READ_ONCE is only used to mark the variable as atomic,
> > +      * there are no concurrent writes.
>
> This doesn't make sense. If there are no concurrent writes, we should
> drop the marking, so that if there are concurrent writes, tools like
> KCSAN can tell us about it if our assumption was wrong.

Makes sense, will do in v2.

> > @@ -425,8 +424,8 @@ depot_stack_handle_t __stack_depot_save(unsigned lo=
ng *entries,
> >        * Check if another stack pool needs to be initialized. If so, al=
locate
> >        * the memory now - we won't be able to do that under the lock.
> >        *
> > -      * The smp_load_acquire() here pairs with smp_store_release() to
> > -      * |next_pool_inited| in depot_alloc_stack() and depot_init_pool(=
).
> > +      * smp_load_acquire pairs with smp_store_release
> > +      * in depot_alloc_stack and depot_init_pool.
>
> Reflow comment to match 80 cols used by comments elsewhere.

Will do in v2.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdg4p3Lea6HpiKojSgtMEX%2BV-K%2BC5FBoGxpfSosDCcH9g%40mail.=
gmail.com.
