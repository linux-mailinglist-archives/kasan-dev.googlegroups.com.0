Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGWA6WDAMGQEAZTOBIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 897923B8DBB
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Jul 2021 08:26:35 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id 15-20020a9d030f0000b029046552076e5csf3343366otv.20
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 23:26:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625120794; cv=pass;
        d=google.com; s=arc-20160816;
        b=FCPJGkapWSkbq0GQE+dDu3oqwm3C4XjfHDxFikOX9nbD4exnTwdX9T9u61bgMz6KvG
         yHBQ2Ckp367s/HfQH54Tls+rTcZYc92gRlXeSctK+gMiy5GfuVIn2xNcqLOdvQIAPGIS
         Hmr3EYBgh8puIgVfHu5Ei8Wokqeg66ptqtjeUopFpN8fgsVYsd5bAEB3KR6DvgWxWLSM
         CUtMhw+Xwn0u53i27BeLjcM2mZTFwl4weCMZI22gq/GSWsojvnDBN37FN5S9Z+9DKOZ2
         Y/5JT9ke0v01YQ9jrplnQGlNBY8JUVAjnbJX7SkbImhPfjC3Qurm2beld1kPGcZYHB79
         fGxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=eTMPwZk+X9matf20hGe9Jpz2SgZWayBr2e1GvBM3WPA=;
        b=1Cit0rwdrzCdDExpc2BzHaoh/sygdU7C0NNcdvetJ45t2G2UctrYKzL3c4rJm+hz5u
         pB1THECUgDmz4TYmRQlMlg2rOmSpPpZFHh+3zcQ25wLrLTul/aGzv6kuxhmN24+jbU8Q
         hofZR9nvZuIZrjw7JBFw5FDYAT/CyNRr1rYI5pZ/fPtxBDENMcalTPpHAZp5BmswdX/l
         Lo9HiPvFq7kI/VNlpJHBbNqjba+ukOw2bmiRSkX8PKT9oijrVznzxQEOUSKMszuw0IOh
         MhJdLQCoNvgtbGKf1oyMRkRslWiw+F6r5CSBpLh7DPIUUWcNVIM5vzVewmyza6nz5Fmp
         FUCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SqGXprIA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eTMPwZk+X9matf20hGe9Jpz2SgZWayBr2e1GvBM3WPA=;
        b=dGsjt6x42vvc1fQ7U8dToXv89rBguIjLdLdQlWmhfWTLuj7JY4C3nkduaQqavKLFcK
         DM10KZD7c+EbvufTtmW+5QlTq47L+qJZ7w+GNrkdvEj50PdhA1rw7FutY1JEtPtD8jWT
         zIJPfDBfZfTXOrjZWUtXArYxknfD2U1CjcMwcCEMpyjIraVREQ4jQlZWy/U7feYm7mM7
         Caqkcf681qUuvuUEWpby8Dfao8UdXWrnd2+X8bgTKjwI7sANUFeivVqIA4lyH1pKZHHo
         ORdl6IxaKxtGSXu3HKRhgEWVokAdLTsbC/JbV6WN+Ul439gUFYLDn6m7avV5xT+ijIiY
         lQ2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eTMPwZk+X9matf20hGe9Jpz2SgZWayBr2e1GvBM3WPA=;
        b=BPZ+hzQMLL2b5CFl85Nwn8az1FIZRpUxSdByVSSs1HVxeFghiDKpATv2n7jncL8oVV
         QXx3biLrGmbel1DPs/bHLKeXFOUv+IQXQaK3g5zky9Zrr5bwtZkhk9tgBCx3qr9v/6Uh
         JCngzgDYLsVu+so1aWP46pwcyuTFj0/gJQ7mbxM+447YY8qAF5C2b58pWotQ67XJ7hvc
         zenOBMWNaOhOS4RjHlfaKH1Mxm3FNEPss8pXDT/O4Y/FIZfQDS8bkp8mzgcEJKXst/vF
         IsG3yUSE4JEb+VUB4Bnv9jiuPnh8DlKVt5MERDscTCE2+9bF7ncqOwN0aQDL43Ec5rgh
         H5Zg==
X-Gm-Message-State: AOAM5338hLcoxkupvVkR7iZDOAyKfOs5vE0YwhxdDnPUxsXaaxlp5RzL
	Xc3j+IH04ljvGZuhFomgzFk=
X-Google-Smtp-Source: ABdhPJw1HdE2n8ijR/ljYtjOqlvyEKplFec+xXN7XAkKmO9Kd7kxcTiZj/1NYRgnWQrj2qW/suijmg==
X-Received: by 2002:a54:4199:: with SMTP id 25mr6168256oiy.16.1625120794156;
        Wed, 30 Jun 2021 23:26:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:eb97:: with SMTP id d23ls449587ooj.2.gmail; Wed, 30 Jun
 2021 23:26:33 -0700 (PDT)
X-Received: by 2002:a4a:9644:: with SMTP id r4mr11840650ooi.52.1625120793757;
        Wed, 30 Jun 2021 23:26:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625120793; cv=none;
        d=google.com; s=arc-20160816;
        b=xGeo34TNDMcE+79z9S06WiBy9SLor0ortFqcVgum9OJq2gFT2svWMUc14hXoK38Cqx
         pKiPFVJLJNIDhbNxh+mQqnZEWXdw0gG8AA80O3ey42Ih/plc1/kcikyklOPJbuUHqNpn
         TUnpON/iLNJ4PzZTKDaJOZQIBWOGvmksg9wyVOR7T5SCHBGbcOQfNAoDAIJqPDQiXjEI
         Ssgp9Gszl2r0qDH79zMu539ccItTttcdL2eIb/1ZWj3ARSl8b1QRFzpOSq6LrJwyqGSI
         Iiqy/oVe0L6KxJqOPzsuJ39WDKy6Zh/+3YHjgLnoukq01S/XV+fQcfqLn5fcIHB+9+Up
         nO8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=weLO0U8CcMdO2GwWr9sKBhxG+qWHdNo4kkTxiwdSbK4=;
        b=KSsmaNt2RhnOJK/fqiDGLlHZXHh2m/toA03mkokjndKdtqU9NwSw8x16RWtobakWqx
         71po3r2d3PZ7D+gOTL6SgSqyiIrqU8v2bZOxl3Hj3+T8Cx/f4aFPYYrQbprZQZ+QFSXj
         cpq0nXDjRBPi5fSeaGp86s33SSNpYkHgaOa5n74BqxpQxBEJJd0MUsvQLSUUN7JbGPwC
         xu42Xm8nb7WKPRd9FCxFI/X1FanA63Z4P89+LBfQ5/bcSDiNKc9gdxTtw2pPr//4k+W7
         rTP6UjyPCuOxa5ZWFqsn2O3DY9vb2LrHH95j8JW/w96gJtzRgAgK44AhyLIi/bYRKb1W
         RRrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SqGXprIA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2f.google.com (mail-oo1-xc2f.google.com. [2607:f8b0:4864:20::c2f])
        by gmr-mx.google.com with ESMTPS id l8si288281otn.1.2021.06.30.23.26.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Jun 2021 23:26:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) client-ip=2607:f8b0:4864:20::c2f;
Received: by mail-oo1-xc2f.google.com with SMTP id x62-20020a4a41410000b029024fb8f731dfso735187ooa.12
        for <kasan-dev@googlegroups.com>; Wed, 30 Jun 2021 23:26:33 -0700 (PDT)
X-Received: by 2002:a4a:9406:: with SMTP id h6mr11669704ooi.36.1625120793225;
 Wed, 30 Jun 2021 23:26:33 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNMh9ef30N6LfTrKaAVFR5iKPt_pkKr9p4Ly=-BD7GbTQQ@mail.gmail.com>
 <mhng-d63a7488-73a5-451e-9bf8-52ded7f2e15c@palmerdabbelt-glaptop>
In-Reply-To: <mhng-d63a7488-73a5-451e-9bf8-52ded7f2e15c@palmerdabbelt-glaptop>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Jul 2021 08:26:21 +0200
Message-ID: <CANpmjNM4nJBu_7HyEGdb5x-me25duwH_kLU01XBZANEBTO3EhQ@mail.gmail.com>
Subject: Re: [PATCH -next v2] riscv: Enable KFENCE for riscv64
To: Palmer Dabbelt <palmerdabbelt@google.com>
Cc: liushixin2@huawei.com, Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, 
	glider@google.com, dvyukov@google.com, linux-riscv@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SqGXprIA;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as
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

On Thu, 1 Jul 2021 at 04:38, 'Palmer Dabbelt' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
> On Wed, 16 Jun 2021 02:11:53 PDT (-0700), elver@google.com wrote:
> > On Tue, 15 Jun 2021 at 04:35, Liu Shixin <liushixin2@huawei.com> wrote:
> >> Add architecture specific implementation details for KFENCE and enable
> >> KFENCE for the riscv64 architecture. In particular, this implements the
> >> required interface in <asm/kfence.h>.
> >>
> >> KFENCE requires that attributes for pages from its memory pool can
> >> individually be set. Therefore, force the kfence pool to be mapped at
> >> page granularity.
> >>
> >> Testing this patch using the testcases in kfence_test.c and all passed.
> >>
> >> Signed-off-by: Liu Shixin <liushixin2@huawei.com>
> >> Acked-by: Marco Elver <elver@google.com>
> >> Reviewed-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> >
> > I can't see this in -next yet. It would be nice if riscv64 could get
> > KFENCE support.
>
> Thanks, this is on for-next.  I'm just doing a boot test with
> CONFIG_KFENCE=y (and whatever that turns on for defconfig), let me know
> if there's anything more interesting to test on the KFENCE side of
> things.

To test if everything still works, CONFIG_KFENCE_KUNIT_TEST=y
(requires CONFIG_KUNIT=y) will run the KFENCE test suite on boot.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM4nJBu_7HyEGdb5x-me25duwH_kLU01XBZANEBTO3EhQ%40mail.gmail.com.
