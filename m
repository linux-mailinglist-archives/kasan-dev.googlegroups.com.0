Return-Path: <kasan-dev+bncBDX4HWEMTEBRBB46SL5QKGQERGS2VOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 467D226FAC8
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 12:42:16 +0200 (CEST)
Received: by mail-vk1-xa39.google.com with SMTP id s194sf1068543vka.13
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 03:42:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600425735; cv=pass;
        d=google.com; s=arc-20160816;
        b=dwgYKXR1v+YqdX78NE/3CEpBQh73j3a/PDEzzrhTgFwAFxEAEghZrj8rVYU/9UY4AJ
         OqJ+y8nqMGsnidJ7236FmMjZ50RkTHrcoeykPHZjfWiej17PcQEHthpJaT+8h04n38I3
         gdOHOFIenrPSq8lC6JnkiOkEhc01GUxysVTXXApedOiQWAPbFUbx8rRteFitmKRZRUAw
         hGKuCbrnfoJmmGBsqOrQFOmg5NTcO7J+KRxE9o222SstQ8bO1W1Er+3/+cT3BZUeLocx
         vdiKUFh0QRUNKXHPS0Y6TJPXBV9LKN492yWiQaTie/uYegCaYyrXbH2rK6o4P8JPNFgE
         nUdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qiPcrh+YhZ88nYOwrWxZaMzKOHPhWXbtLyg7R69wVOs=;
        b=gs6ikUPWP72AEa/lNQnzO9okJNjWclXMTIaS4FicO0gMZrXllhbQjqnA4Psd1JbDjQ
         A3MZ/MVjU57QJWuXvyMqyX4BJAmiZO4u74X43ZCzUQXFtvVu3d/8seVskbXAFB99AliQ
         TNcI6MRYMy4J67grRiMrO8CIXR17Rm/Ycc24NZbYCMYWoiWURO7uF83RRRzTOPugiej5
         NaQqtx/zBOvXoUHV0GltUE4cVOSHJd2c4PBwreb38KDIN+XXzDlN5qcKE+0K9n5mngr2
         OU4863h1zrSsH97zcvAJSGvZRTZDaKWRO1d7h70gaIo6HB85ZXytqGz2VxWykPGuDYWo
         HqoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HQLdYPkq;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qiPcrh+YhZ88nYOwrWxZaMzKOHPhWXbtLyg7R69wVOs=;
        b=Z0HK03nn3WGjk5D9tk3m2zyxEba3Mc2rPWjVi3i2srFsnCKo6tsYY/uoyVJEFPtUbY
         p7Fpa7V3TLh4iD+2GmcLUGqjHpEhBpnR6eeN+SaXrQ0rUdkHG0S50q/xmANqhdybuiMZ
         af3Qabjn+TKWYBqslpsw8XXiwj+ImM3LxFZaUtei0B0+rnDPWplhGWkgIpdZU10HzqZB
         iZlWJ9OIE1D1zDiRDV3jlpuWPt+JUyyjr8cMbDcualKMiu9+wu1Y2Wg43yIc4ORdyTRH
         LdkPnJQwKvtA1vcFSlCSGyArUCtlAOF66/qzP2bepKSQmJ5uyxTaNDhraz5hQ6qiim+u
         z6kA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qiPcrh+YhZ88nYOwrWxZaMzKOHPhWXbtLyg7R69wVOs=;
        b=PJJ6ZjNfR8buIXT+W/ewnSad8USlGe7g4WUxuBZIuYGitKC/ZRWXHSY/zr1cjI9lwE
         vqV29y8LSAmHs4h4+X4WGMHEcNgWXa4W4XmhZdyky0PXTIgFqJNqc9GI3Eg1g2UDjcpQ
         eZGGbVrWqpLcZCQ3Bib4CGLBOWMTmIutDEgWWA6KPUP9rPEmuvmvGg/MxZxEFwHx5Xmt
         EwfenMTq1S0jaQvZa8Anb3W0ITPMJb94RoNu/EQepIu1E020gZKwZKwdHIcZvHKIZvyx
         m9mhcS1Aol6jiW25Bivx7jab1/ARvTUYSlr7Qk2y7ettq/vZeQYfmK4OY9D/bbl80avZ
         4u+w==
X-Gm-Message-State: AOAM530Cq049dUaRR6ST27C+hpDBLDvd4LnFdci2D5NndxxhANhtXTF2
	thiLS7ixyMpC8FkFm/+IYQs=
X-Google-Smtp-Source: ABdhPJzUmBMTIPnPuzNxUoN3c0dPx/3URAIzSGywt5zjY7ByI7ZNBCN1VvA/nwFI8eKFe5tvSc7PJg==
X-Received: by 2002:a67:2cc4:: with SMTP id s187mr19458140vss.19.1600425735398;
        Fri, 18 Sep 2020 03:42:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:441:: with SMTP id 59ls337176uav.5.gmail; Fri, 18 Sep
 2020 03:42:14 -0700 (PDT)
X-Received: by 2002:ab0:2741:: with SMTP id c1mr17941780uap.98.1600425734886;
        Fri, 18 Sep 2020 03:42:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600425734; cv=none;
        d=google.com; s=arc-20160816;
        b=dKa+zBoTy4gWv+tkwaFXFk2ZpZbOSSQX3R8jq2XAFieHa7lvPq//jkygfJ/1g91N7b
         LTaUintITupyOtF+X+sUsHkMf9SbbG1vHe1lqMcC4HlQb5AC7RGwElm8vkyHAzh7a+aD
         NKxGFjkd+WnpTystPOeMoba/z5rZsxQRCispmKEInyg97xcm8+SHT6EMseHwTNo34CRf
         SFrTOTwu4E8JG8+RiJachHtmxk3UD6iYIpt6/8yvq5oE7VJUn3GbItENOYZuT3urYOju
         MfS9WodAwb3tNk2vyr+9+kRoFv4LIT61cfkbbWSmdVahnNFF9p3fNE6hhqFRzJUZTMMM
         VD/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jyCshTFjDIofsUJ8ZxHei4ByPrM8q28xDy+Y4pUMZwI=;
        b=bzamKudtW0pdh1PjiEUqhYOERuhdCtEQUlMHyhCvm+UfA9MbbRCltz1kFuAQw43b1d
         WXc3tnYq6za8RIY9ISNSS9yQUzyZptQTSmQkkmAsSWKhiNCCvUhoaTLOepjg7KRM/eMr
         7OkG0XqD4CUjDxiXIhPrrgfkp10rHu502Rt1O+EQOdEywgi1KqXcSgFq4/mAsNmRi3EY
         9Uj2pbdzPBHfHuFk3XlX5UJhWEM58WZfFWoxkL6kWUTBEtefJcBaLamZ6L4S8iWJBt0n
         bWxRS8VNXTW59zE5NRS7iecTMrqIjgNR3F/U4ThuOP12trYCjmAZ19ynV9coHZXZ4Oqd
         YbFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HQLdYPkq;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id y65si164098vkf.1.2020.09.18.03.42.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 03:42:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id k13so2676025pfg.1
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 03:42:14 -0700 (PDT)
X-Received: by 2002:a62:38ce:0:b029:138:838f:dd53 with SMTP id
 f197-20020a6238ce0000b0290138838fdd53mr29677349pfa.2.1600425733832; Fri, 18
 Sep 2020 03:42:13 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <28d17537bbd029104cf7de4f7ca92246449efa50.1600204505.git.andreyknvl@google.com>
 <CAG_fn=UACdKuiKq7qkTNM=QHcZ=u4nwfn7ESSPMeWmFXidAVag@mail.gmail.com>
 <CAG_fn=V2MT9EfS1j-qkRX-TdH4oQxRbRcBYr8G+PV11KJBO26g@mail.gmail.com> <CAG_fn=WpOoAf4t1iKrWcD+LBaCvL6tf_QYeqoX65UWPi92h=6Q@mail.gmail.com>
In-Reply-To: <CAG_fn=WpOoAf4t1iKrWcD+LBaCvL6tf_QYeqoX65UWPi92h=6Q@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 12:42:02 +0200
Message-ID: <CAAeHK+yHUXphDsgA=BT8GZNNZ_RQTe95dZo3jDGHm7_LrSw4Ug@mail.gmail.com>
Subject: Re: [PATCH v2 20/37] kasan: rename tags.c to tags_sw.c
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
 header.i=@google.com header.s=20161025 header.b=HQLdYPkq;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441
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

On Fri, Sep 18, 2020 at 11:46 AM Alexander Potapenko <glider@google.com> wrote:
>
> > Also, as we are going to have CONFIG_KASAN_{SW,HW}_TAGS, won't it be
> > better to call the files {report_,}tags_{sw,hw}.c ?
>
> Sorry for the typo, I meant "{report_,}{sw,hw}_tags.c, mirroring the
> config names.

The idea here was to have common prefixes for similar parts, therefore
I put "tags" first, so "tags_sw.c" comes next to "tags_hw.c" when one
is running "ls". But I can rename them if you think it makes sense.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByHUXphDsgA%3DBT8GZNNZ_RQTe95dZo3jDGHm7_LrSw4Ug%40mail.gmail.com.
