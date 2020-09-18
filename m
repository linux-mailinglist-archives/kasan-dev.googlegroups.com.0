Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGEDSL5QKGQEE3PS7LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E6F3726F981
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 11:44:56 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 20sf912446lfg.23
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 02:44:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600422296; cv=pass;
        d=google.com; s=arc-20160816;
        b=PBFdCYnhNlWbc2fsFU54s+9aUryObk9KcxEgZyoGSRAtCjHFqb/CsBubyRf8CMiMZ8
         YEflOmtABxXrbI1xVoCO4O8lMRwCQsze9oW9zDmacZ+Y4vUVFcxzHjbqaSvWsqsbKstj
         P6ZebI6xJtxXehpi4Nq2G7oxwZTYhMz3OzHdPw5nSeigqH1zOZp76sNzgFfGvfpq10cb
         HwcqqWPc/rwwXrhbpz1Fel2oiOPtzXpKrkFaFSVjNDfpFLXcMqOjIRxfTeSosoRyLVFJ
         O83X5xKazHXMeZ2qH3fv3tOEA+ZiVgVdx28rz+t+b8b/w+3swMgZbGPB6G+Eoo42n96R
         Is4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cW9qlA7DrDzBLMVtja8ajTmYycLVIqu6cKdXfIXphVs=;
        b=qgkOnycO3PRC+SkIrqvyW3g2EZ3A4vq34gYTjth7sXWpteJs3JmQ9JojqZx5mfXvLB
         BFHKA5JX0O5eVSyFNL/xiIg1cmuZ7WsqADVL2dMp4tW8XnI10OLNgU1g/TL4+MRcjHw0
         Uvk9fJKjIUhhbWylHfGQPlXE8X00XlKUmNasT6130iNGlT7YD7ff7NO9Pz0kcF+1yJzM
         W9WDA1DZMiOyy7q+PO4nlG8+ASNeUGbKW0HXxfBruvoAMOHzJf+KQLdO8EFNXdF+TQdZ
         r+ebihmnPOZVcETH4Xry861unnVHTXF5F1krUc+1w31ObMjqu1bX/V3BdWhxTs0C/krG
         akig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sgJDFSBw;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=cW9qlA7DrDzBLMVtja8ajTmYycLVIqu6cKdXfIXphVs=;
        b=W5JuBIkeRPKroaFbj4ufMevqw2B+yUFxaF+fkG8AdPhLZ02E9YYI8eHbxjZ5APcMKY
         aElgGcpDUd4IpoFJY7YBNZpKc8HpqHrk8pSsrSXsrn5rKXiIAa2eRBoK7Xf5/S54iWBm
         /fxHSwvJhTbFLsuSW+0vL96iQ/u0yWTQye6+ZntwIZL4nh66KAz/8PWTotppxolALU7A
         O2LJx+Xd+qOmn1ArWNselTqOZuqdk1K7++b2ADKxobZQfrzdHMtVtu2/5atWU2iQtYDE
         meNLsYDlUCZHvEmeDJNrIDsFZoKBVmxhs9BFEE/mDrxWeYm3iDdlr8NaGAwOcGchZ4Vu
         e4PQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cW9qlA7DrDzBLMVtja8ajTmYycLVIqu6cKdXfIXphVs=;
        b=f61c9BFY40pfj1OatZN9xCCWQhbgWTFTAzqMdKieeUFrgu8rBQ9CAZiSevvK0VOyds
         lSmmQ3l8Fwezir/Y+fqbH0C7ZkQlDGZs5dyqIyEvlytvkYbuAaeOstsGZyX4dcA58tAI
         3DqUloRt7PfSsIJAw05CS3fS+fBzsWEZ4vsrq1bV5SI44QCmUvg8MUox5jEoG4AYRtaM
         cLhyiW3XU51OVimbqRJJ/VUH9GQQGfCj0+p9Efy8zDxhN9+GgIl3N8jOibs70RCMo6v2
         PglyppBj++T0dWOMdMjEsIxaOXcy7TH/Frq2mDPb9h/3O14OHmhs9oHTn4p5g1hpRcNQ
         ohig==
X-Gm-Message-State: AOAM533QXtXUnCTBuOpCnU1t1olJ30ofvlYtdoiK2ON2NsapeMZzvuo2
	kmtwyuqPHP0ABKXfyupRNA8=
X-Google-Smtp-Source: ABdhPJxGT6A1bZOr/kwx8/ltYYr9OPbcY9Kmgurd3bPaA6vOdkbyBB2moeBgHROaTwuodZ0ACGa2Sg==
X-Received: by 2002:a19:8a0a:: with SMTP id m10mr9821678lfd.244.1600422296462;
        Fri, 18 Sep 2020 02:44:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a556:: with SMTP id e22ls734569ljn.9.gmail; Fri, 18 Sep
 2020 02:44:55 -0700 (PDT)
X-Received: by 2002:a2e:a288:: with SMTP id k8mr12082872lja.234.1600422295461;
        Fri, 18 Sep 2020 02:44:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600422295; cv=none;
        d=google.com; s=arc-20160816;
        b=xfwNQVN8cvnf0/t8WH9dU0BrmX2mkpxQCRvFj7ieXvus8TiVtDPNqurJN5jaWRPKiP
         pMSAoUG709/uytKdnGSydjiLSC0WjDnPNhS/6H9nEA38ienowS8GN3zVqAJD4r5LTaW2
         y9OHpKFsbFAqyeL1eEoLQDdvtJ36TvkoBPgNIDsauBvBnZCFPQamrTxp7Vbkb2wHcAlu
         aPqhz9V1lZTDR+Moh7Me6QIzFDFCBfS7e+tzcRLZBm66pl6xOTIxgk9l8JAwzkpKerzq
         emP4UIDiLnx/CIA/6zyWGYkaM2i4cJ9qKb3/gyF1dNbWaX8nrNJaocx4te20qkcexHWB
         1GDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LO/JMXpkI2PbHh8j0Ay5k/YAYJdyl7P+uRkiEmvpGOA=;
        b=JSP047Q8mVEcBsU46VJB1n1pGocXAdNWkD7Vel2qwuYJHRqL5Yz/TuxT5QMkmSc6WY
         3sm9Weo24InbtITXPzZAT0km5u1gcKDGlwfZ9O5C+bD6YbXARS9nMFfIKaQADkJWBbxC
         SniDrSr/RLLRXYnNHjHduTntzwgoKxjhp8geZi3Zjlsw1ZC+iFCaHbcaVBQJ9wiKlbG5
         VXOubIllppB7JOC0lU6LqMI3guD0PXIo7DYaK+Ekq8k/jpOSqvO/vvgwTL9CtTT9M9LT
         whzbi4Kt6jZ9zvSsTIy24r8FsccKnkmLzx5lLA119lhBh0r7GLYxdedBpyCnmjDnsm3F
         keaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sgJDFSBw;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id r16si60226ljg.1.2020.09.18.02.44.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 02:44:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id y15so4873807wmi.0
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 02:44:55 -0700 (PDT)
X-Received: by 2002:a7b:c4d3:: with SMTP id g19mr15304732wmk.165.1600422294758;
 Fri, 18 Sep 2020 02:44:54 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <28d17537bbd029104cf7de4f7ca92246449efa50.1600204505.git.andreyknvl@google.com>
 <CAG_fn=UACdKuiKq7qkTNM=QHcZ=u4nwfn7ESSPMeWmFXidAVag@mail.gmail.com>
In-Reply-To: <CAG_fn=UACdKuiKq7qkTNM=QHcZ=u4nwfn7ESSPMeWmFXidAVag@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 11:44:43 +0200
Message-ID: <CAG_fn=V2MT9EfS1j-qkRX-TdH4oQxRbRcBYr8G+PV11KJBO26g@mail.gmail.com>
Subject: Re: [PATCH v2 20/37] kasan: rename tags.c to tags_sw.c
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sgJDFSBw;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as
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

On Fri, Sep 18, 2020 at 11:41 AM Alexander Potapenko <glider@google.com> wr=
ote:
>
> On Tue, Sep 15, 2020 at 11:17 PM Andrey Konovalov <andreyknvl@google.com>=
 wrote:
> >
> > This is a preparatory commit for the upcoming addition of a new hardwar=
e
> > tag-based (MTE-based) KASAN mode.
> >
> > Hardware tag-based KASAN will also be using tag-based approach, so rena=
me
> > tags.c to tags_sw.c and report_tags.c to report_tags_sw.c to avoid
> > confusion once the new mode is added
>
> I find it a bit excessive renaming the same file twice in the same
> patch series (tags_report.c -> report_tags.c -> report_tags_sw.c)

Also, as we are going to have CONFIG_KASAN_{SW,HW}_TAGS, won't it be
better to call the files {report_,}tags_{sw,hw}.c ?

--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DV2MT9EfS1j-qkRX-TdH4oQxRbRcBYr8G%2BPV11KJBO26g%40mail.gm=
ail.com.
