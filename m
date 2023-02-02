Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQ4V52PAMGQEX5C722A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id DA29F6879BE
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Feb 2023 11:04:53 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id jp14-20020a17090ae44e00b0022a03158ec6sf774097pjb.9
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 02:04:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675332292; cv=pass;
        d=google.com; s=arc-20160816;
        b=LHBlTZV8Ay3r+j/3s+gioFpFzBfMEyPaEir4QC8pzuq+DujP2S0Z8QcOFnVKtlsSxO
         uvERlOjUS3i8bFBP+6MSuKHlGg7YYl+iomsgUFt/FeHFoMejNEG9v95nmDeq+6g5jbXe
         3wpVgbGCNoX396M9TdSlfCZxHn1DjEtln4Lmf2MHe9diU39rzCkCPC866mYJbmxfkfsF
         SFj+H6TPCDrxa1zwyVM7VLxsYIO5m5+t2F31KRpp8RcEtCC3M6wJZDrXloEEbxfnLetz
         t7mVFJ2EAoyVO+90G+n5AvFNgy3oqkYp56ByZbcnxdl0mrUvcB5TxuyFCliWaKjLeFMg
         QEPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LnEJ4VmoovFVrv9ghTu0KNNJClYbSSZknjQ1HVPxCOA=;
        b=o/pd1HNnecd36mmFZN7buZHsauKKdfqi3Vx9ivIMoOHkKSA9t7DXlOVTsn/y7ToKYy
         OOByuOrnGb4xX3o1gAfIUhpBPMAwrqWpgClJfbB8FT1/ZN78oaYy1gCLagsq8bqObjOo
         b45/YML0OLJIoT6099kC+1SDdMf8ykbc5VjbkMZ2+f0AEQ4bb6hjGAiH/h3yDR+G+6yI
         gtIbCOY42ZidxIRE8Mo9/4sVkfHTrtrQZQJiq0SFnOYWx424DO6TqDtxb/2JU3Pfi6ef
         foR98MSVVUHnmnuulF1uLXyAupRBMvxXUVm3aokK+I6ZdUKtB6Gk7Qjer7LTHiGeyy3Q
         palg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Y7i97OuP;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LnEJ4VmoovFVrv9ghTu0KNNJClYbSSZknjQ1HVPxCOA=;
        b=Lqgoy6Qu7hVkenL7YP+1Gl1YVZvlnZNumlbvF+0NwkTkVo1lLebEyI+T4wMldDxa/g
         BARwXUta+eUSUsoqTefK704awXWXjgSjPJq5GEHr7bAJDOFVmY+5efVR/rthtFRz9Ix+
         eKN5VC89eRJ08DY2D0VOdc0YrLgDPOjFjEB/EV4cHz8YxreOwQes+7BkEo/FX7tE5zjc
         LKefVAfVz/rkBgC91uRBO0XRBzH76u0k/z/YFq9GMd3/xGc5XyxIDAuSnOoPzq8/MiA8
         NE9j47WjSsenezrrTmaom+IOcXQXK2SzhQEDnWFjice7Hl08lflNmuMXVigVcyunccwv
         zY8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=LnEJ4VmoovFVrv9ghTu0KNNJClYbSSZknjQ1HVPxCOA=;
        b=iHSAShSeqilPaiiPSzz8x8bzKjRdnemoMZRHJfHIwQjofbcJdaGb33gpB9Lp1GIfBw
         5rf0B8lFYcdV2uAQ2k2c5llEQjM6aTL1+w49mrtYogjczU2doKbSOVsTGmZNyWzORG4U
         SPcQcJGO7M7YGQaIQmX/sFKS0LdGViQh8PDdXs3SqMfSqYHv4A9ModpZn6s8+32Jw6a6
         ZoI4d25lx3bTxkg/51pJVLH+E8117PYKVUU4qH5yGxPd1oHItkzTGZlcBr6X8aQbpSmB
         TmcCxC4sfZgHonmQEOSgAOem+ITrd/F3r1UAnNiY5KcwW+ND806CCSEKJQSSiOYZhFPE
         FkPg==
X-Gm-Message-State: AO0yUKXSYq6wKPrdtXOt+XKxaRP0T+NGYrybLN9c6pjQHHV4qN1P6VDE
	5csxaQWQ9F4fVM0HM1XFwsw=
X-Google-Smtp-Source: AK7set+gvGXoBof1AkIQ2zh6L/wWXbOHcK75N3Pr+q/NmB4hcX0s3GDNVSwJWl8jECoDpWYnkm4vyg==
X-Received: by 2002:aa7:80d0:0:b0:590:6afd:7aa1 with SMTP id a16-20020aa780d0000000b005906afd7aa1mr1275294pfn.7.1675332292013;
        Thu, 02 Feb 2023 02:04:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e9d4:b0:191:1e85:3329 with SMTP id
 20-20020a170902e9d400b001911e853329ls1675728plk.3.-pod-prod-gmail; Thu, 02
 Feb 2023 02:04:51 -0800 (PST)
X-Received: by 2002:a17:90a:1a0a:b0:22c:912:b80d with SMTP id 10-20020a17090a1a0a00b0022c0912b80dmr6094511pjk.33.1675332291221;
        Thu, 02 Feb 2023 02:04:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675332291; cv=none;
        d=google.com; s=arc-20160816;
        b=aUKcqe2KC/1McpyruJgQT5bXfNDZfSW5EvT+s8KYEV5SIFUaUUdsbuog3sxac8BpkC
         laKCc7f2I/lCXrxcQt9JNmvPFHuN5axIiPHKHwRV3EMGgO+rnOc5KpUR1pVLUqFpG2Ws
         bC3RKV5DQrYQdcC7/Sazq6miYdVRG4gWZtjHfZizxxHnGxbUKsBjzJDyiIGzZx22QyH3
         Rl+bz/9o46q1LCFv6ziYfl8x51Ep/Oudtz4964SScMO0pKfmfHct86RQCbAzQhkPF8dJ
         eojgcybU3UcxecBVZuf8rIe3XQoGoSYCsqVFea6bnjvgWO6kA0hHKveOgJuDMaqhF6sd
         PxkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OTOvqWUVVZlijg12oIE77cCshSPOfIDDk+4jVZ655+k=;
        b=oYckOhfBUGMYVGiSc16zaYoVEIoLfeZepvbfmnTeRXKU9q7DwByKLmh4k1L02Fg6MX
         gXaeizAGN+zuqT4g9Cdr5RMKv4dTg5/3UXVCfKpidofnv8DidsoOWWvBee2rvhrJlvQy
         Z0XyGGkFOSW+Jdu3e4TjSuxX/0joLy8e1Nt5MS7TQe86X+F8yFi3kuhP6aNjNxdze93q
         UCGwYOboJJqhT8QZV2IFhRlOyyA4lEtqtwv/xyHduQlQsIJShU7MBJppqQYDjC1JUdDz
         2PROFlA5ZBEb+IiIInfv/v44OgCI6qRf6HyzkZAoyuCykHlcU+TkB2VvuZnkPxkXoI6i
         yhJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Y7i97OuP;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe31.google.com (mail-vs1-xe31.google.com. [2607:f8b0:4864:20::e31])
        by gmr-mx.google.com with ESMTPS id cx3-20020a17090afd8300b0022673858f16si427047pjb.1.2023.02.02.02.04.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Feb 2023 02:04:51 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) client-ip=2607:f8b0:4864:20::e31;
Received: by mail-vs1-xe31.google.com with SMTP id 3so1257222vsq.7
        for <kasan-dev@googlegroups.com>; Thu, 02 Feb 2023 02:04:51 -0800 (PST)
X-Received: by 2002:a05:6102:1343:b0:3ed:1e92:a87f with SMTP id
 j3-20020a056102134300b003ed1e92a87fmr927918vsl.1.1675332290796; Thu, 02 Feb
 2023 02:04:50 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <fbe58d38b7d93a9ef8500a72c0c4f103222418e6.1675111415.git.andreyknvl@google.com>
 <CANpmjNPakvS5OAp3DEvH=5mdtped8K5WC4j4yRfPEJtJOv4OhA@mail.gmail.com> <CA+fCnZeOs6R_Wk=Da-aC5ZUzz_tOPVQWu1DoPsYVORS=dJ6cQg@mail.gmail.com>
In-Reply-To: <CA+fCnZeOs6R_Wk=Da-aC5ZUzz_tOPVQWu1DoPsYVORS=dJ6cQg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Feb 2023 11:04:14 +0100
Message-ID: <CAG_fn=VVZGc1pyC_zuo3Dzky0rFU_AX2WAWDn2Z98jO61bqvXg@mail.gmail.com>
Subject: Re: [PATCH 15/18] lib/stacktrace, kasan, kmsan: rework extra_bits interface
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Marco Elver <elver@google.com>, andrey.konovalov@linux.dev, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Y7i97OuP;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e31 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, Jan 31, 2023 at 7:58 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Tue, Jan 31, 2023 at 9:54 AM Marco Elver <elver@google.com> wrote:
> >
> > > +depot_stack_handle_t stack_depot_set_extra_bits(depot_stack_handle_t handle,
> > > +                                               unsigned int extra_bits);
> >
> > Can you add __must_check to this function? Either that or making
> > handle an in/out param, as otherwise it might be easy to think that it
> > doesn't return anything ("set_foo()" seems like it sets the
> > information in the handle-associated data but not handle itself ... in
> > case someone missed the documentation).
>
> Makes sense, will do in v2 if Alexander doesn't object to the
> interface change. Thanks!

I do not object. Thanks for doing this!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVVZGc1pyC_zuo3Dzky0rFU_AX2WAWDn2Z98jO61bqvXg%40mail.gmail.com.
