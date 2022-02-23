Return-Path: <kasan-dev+bncBD52JJ7JXILRBJHL3KIAMGQE2YL3RGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 692F04C1E78
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Feb 2022 23:31:02 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id n135-20020a628f8d000000b004e16d5bdcdbsf96016pfd.20
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Feb 2022 14:31:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645655461; cv=pass;
        d=google.com; s=arc-20160816;
        b=yPZrhb/W/AMJG/l+XHMVLaSgxd3lS7ju1YS2zLvgomD8U1L4nYDFId7CR1a1k2gNNf
         jZMRWGS+kLR4ipMjqcgOVQDwWEowcPezba/yZdC6CFGPS6aJaGR2qjF0KXmaCCb0fpGT
         0RFz0zjH0SdlDgVUQ53r8RRtiWGrvt/jHL660QjYzn1OGYMh1m6oZ4Ieb7BpuBw7V/OC
         KZWO9/q+u5yzORxyPgecaPeoXxzonpmrfs5JE8RszFvavfYh0hrnaLB3cjqeJPf7E+OA
         5QTUnwgrjxSOtC1BfaW8DOkdYNucq8uCmuuFhKLKLrtkFUtzBXV9JDau5hEbHLSfQtMP
         NcdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rx60IzS92cPH+sntn3ijIH57Fi/o3sa2L1dT15Eo3J0=;
        b=im2n0MULC9GI9wmWLvQ6qJ4wKzlwwZ6JCMDOGOMCkZmYPuZN1hOCLe4Cyfck2gIafw
         osbUpKv3UljadIG8/SfHAOOV8aYV8zejO8aV0yavQfD/gLWrN9enZdfsNXgsMZR2270I
         XwH+iSAE+oPjH79kdpUjUi0GDqWz57lsuZjfX1d9et9/0olJJ1wd79iRK2NIh7DcNv/h
         5oCQNqOi7no5S8Y4LXzktemIz8MpEmha+A6Gw3HujhHOJQ7EvGSitYGLdv8s/C76SFIn
         Ij6sYY2+O+cH1CI31jr3IdTpVr+Fkt3LueC0/O6veDPdImwLCs1A0wvPHWe9FKxNpgyG
         Gh8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K0CZpAID;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::933 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rx60IzS92cPH+sntn3ijIH57Fi/o3sa2L1dT15Eo3J0=;
        b=s12SDGMExfOQeOvX1LbuJrQ/R9Tfl673sho+7JEqUajpC3ucNm9jNpBanjI9PlSHcB
         ezw+u+a7TZDKyasOgxSuJPvNeFFdfUhIaSl7VfFC7DrK1QxVnRVneYfvuxEKsUNjhysK
         xbvKGYY5CemZLz1ec+8MEPt2s+KVs+BqNRXxyweodvAommHFBLnuXdRgYaXcaex5cPGq
         +xSdVxhcSmXM4bIQs+5fE8iEbzUl8qVd78sm97rvk68sebsH0NAph9DNRpvhu2IruRSi
         2pR5lf1hyojLxWX1NPZ1bfrvVpZsPrqs3W4S3fuMtl7llJAVhdwa0oBk5kOTf0512asj
         CO3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rx60IzS92cPH+sntn3ijIH57Fi/o3sa2L1dT15Eo3J0=;
        b=YPPpRqzKfDDvPWIev83p1VcFuu7KbaQTMyMDjbKRBq+w9Rc2bnJbGDEhlxWXAroBrk
         81tSjKbo6+zN6NtNaz2AtI574LCsE/KXNSKElgDRMGqF3C9Sgct5GgzVCOWtgRjV44a6
         EormlS481olfOhZSjPe0XOi68QVvmy4vm9ZmdLrGYhN3tEB2xMtLklYFpHO3dUu3Yzqk
         jWh0k6G4in6NsUsJVrTiFFSPEIqDnCbJLob51ssyqt1puxI9/cbfSVl6vzgrwxcc7TKe
         z8HQSdnJ2WkeLjRjyJVgSYb1QDEyg8YsOQlxuatq24lzmno4trM9hiXfoR2dnsiQyhT4
         lbPg==
X-Gm-Message-State: AOAM533YwxRoV5y56MzrgA+xee0rddIVN4zYTkI555FIPxjBWSbSutzt
	dUqaDP0P4DXUuy+ZIePt6rw=
X-Google-Smtp-Source: ABdhPJxr+9IvWlX+kbsyNZQvQtG0qwV3gahgapmXKQaDf+/DBloekn7CZWaz0pSFV7oDv6wE/uCCzw==
X-Received: by 2002:a17:902:ba8c:b0:14f:d9b7:ab4 with SMTP id k12-20020a170902ba8c00b0014fd9b70ab4mr1872981pls.23.1645655460766;
        Wed, 23 Feb 2022 14:31:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bb92:b0:1bc:46ec:e156 with SMTP id
 v18-20020a17090abb9200b001bc46ece156ls634841pjr.2.gmail; Wed, 23 Feb 2022
 14:31:00 -0800 (PST)
X-Received: by 2002:a17:90a:160f:b0:1b8:ab45:d287 with SMTP id n15-20020a17090a160f00b001b8ab45d287mr1508165pja.91.1645655460170;
        Wed, 23 Feb 2022 14:31:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645655460; cv=none;
        d=google.com; s=arc-20160816;
        b=yuNzVSxw+z/yuc8z49pAvhFpkoGLaNaoN8wOsAkGGTjjA/qiHylGHnrwrMzkNbo9Z1
         b/imQURs4gr7grk8Qd+oK4zW8P/cRB64GvIBrBRrRotukaY0GV3eF2cM7H8BmcZi2c6w
         1YAsw1/oRJG1FOHFmlxKccaXQEmhjV40loJvc2hmoTBMgr1gHL/PGKaFEvhyDrC98WqB
         4EzlXw/Aenp8ZiVnProvTJh5J582BLJNmzqQ/93nsvXACGycIZnv0RDXuyhMuc+DeaEy
         UfyK9H/RYLigJmDInTjjgDo5epeAcrfL0tSZS8N8A9dUOzvKbaeV01B90IsM7DY9URKM
         ddBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1RPwSA1q9Nzhq0/2Be8zKvMRRcdwuPwwh16qax7HGnE=;
        b=WE4U6s9hDBp5IOqoULzN09W1LG3yZVn7I/b0+uOvGiG5C9HbCToyIGPs2OzuMTuX3e
         Fnp3LRdQf6oIN8R51/CjK78qCVTHkkwrrKzWGYvKi+7qeLJGHVg3aG0mVPPIfhuZ4HPL
         FFCzeJ4y03mmDrInhM5CY5cAygdkZAMtP0Xh0z3h0SMQknYRnGMLZCeqrGE9DSS1WYxn
         nSitAAOFuLqSP6Zo3q7Rtp/HMZXvJB3RSzdmvOeimgzhWxi7hUEigbK6WQvYgQ8ldi9e
         FxHeGNxjCeCBL4OpVi40k1j+hixQCynnLuBrl/VhLtMDq5jVFxylZPDfwbl/ToYZvBWW
         kBmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K0CZpAID;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::933 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x933.google.com (mail-ua1-x933.google.com. [2607:f8b0:4864:20::933])
        by gmr-mx.google.com with ESMTPS id r23si45490pfh.4.2022.02.23.14.31.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Feb 2022 14:31:00 -0800 (PST)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::933 as permitted sender) client-ip=2607:f8b0:4864:20::933;
Received: by mail-ua1-x933.google.com with SMTP id p33so10173uap.8
        for <kasan-dev@googlegroups.com>; Wed, 23 Feb 2022 14:31:00 -0800 (PST)
X-Received: by 2002:ab0:69d0:0:b0:345:72b0:ee12 with SMTP id
 u16-20020ab069d0000000b0034572b0ee12mr946042uaq.78.1645655459242; Wed, 23 Feb
 2022 14:30:59 -0800 (PST)
MIME-Version: 1.0
References: <20220219012433.890941-1-pcc@google.com> <7a6afd53-a5c8-1be3-83cc-832596702401@huawei.com>
 <CANpmjNO=1utdh_52sVWb1rNCDme+hbMJzP9GMfF1xWigmy2WsA@mail.gmail.com>
In-Reply-To: <CANpmjNO=1utdh_52sVWb1rNCDme+hbMJzP9GMfF1xWigmy2WsA@mail.gmail.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 23 Feb 2022 14:30:48 -0800
Message-ID: <CAMn1gO7S++yR4=DjrPZU_POAHP8Pfxaa3P2Cy__Ggu+kN9pqBA@mail.gmail.com>
Subject: Re: [PATCH] kasan: update function name in comments
To: Marco Elver <elver@google.com>
Cc: Miaohe Lin <linmiaohe@huawei.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=K0CZpAID;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::933 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

 On Mon, Feb 21, 2022 at 3:15 AM Marco Elver <elver@google.com> wrote:
>
> On Sat, 19 Feb 2022 at 03:00, Miaohe Lin <linmiaohe@huawei.com> wrote:
> >
> > On 2022/2/19 9:24, Peter Collingbourne wrote:
> > > The function kasan_global_oob was renamed to kasan_global_oob_right,
> > > but the comments referring to it were not updated. Do so.
> > >
> > > Link: https://linux-review.googlesource.com/id/I20faa90126937bbee77d9d44709556c3dd4b40be
> > > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > > Fixes: e5f4728767d2 ("kasan: test: add globals left-out-of-bounds test")
> >
> > This Fixes tag is unneeded.
> >
> > Except the above nit, this patch looks good to me. Thanks.
> >
> > Reviewed-by: Miaohe Lin <linmiaohe@huawei.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> And yes, the Fixes tag should be removed to not have stable teams do
> unnecessary work.

I thought that Cc: stable@vger.kernel.org controlled whether the patch
is to be taken to the stable kernel and Fixes: was more of an
informational tag. At least that's what this seems to say:
https://www.kernel.org/doc/html/latest/process/submitting-patches.html#reviewer-s-statement-of-oversight

> +Cc'ing missing mailing lists (use get_maintainers.pl - in particular,
> LKML is missing, which should always be Cc'd for archival purposes so
> that things like b4 can work properly).

get_maintainers.pl tends to list a lot of reviewers so I try to filter
it to only the most important recipients or only use it for
"important" patches (like the uaccess logging patch). It's also a bit
broken in my workflow --
https://lore.kernel.org/all/20210913233435.24585-1-pcc@google.com/
fixes one of the problems but there are others.

Doesn't b4 scan all the mailing lists? So I'd have imagined it
wouldn't matter which one you send it to.

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO7S%2B%2ByR4%3DDjrPZU_POAHP8Pfxaa3P2Cy__Ggu%2BkN9pqBA%40mail.gmail.com.
