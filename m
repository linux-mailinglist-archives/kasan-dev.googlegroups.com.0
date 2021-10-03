Return-Path: <kasan-dev+bncBDW2JDUY5AORBX6K46FAMGQEFMZPG7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B3CC420310
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Oct 2021 19:16:17 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id b11-20020a17090aa58b00b0019c8bfd57b8sf8168043pjq.1
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Oct 2021 10:16:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633281376; cv=pass;
        d=google.com; s=arc-20160816;
        b=pAssyoRVEJSQgq7Txv1WnIGxMXAZQtWS6dK3wbikkxO0vi6Qnxrcxpya9x5cWvmXkX
         9oIOn1l+O5S4wejuwew7eLsFS+DoZytNwDBido/E3dXqH5P/+kHn7sQo3mq8GqSX47Ze
         Sg3G59p2KCitCwp4+2R8ttxKkJ5PdO+IWcsfnlVRwZy9MqNYioiu9MP8qR+1ieS6pKBK
         9tTLMRRtM0dnSstzwY8nk2zwJ+cXCBQ7pHaoQOY/eF4QhRynrJdImjiGCOIf4JovFp0D
         215au9gH8VBpTVhwEvzNH//P3GSTF7iWjXPaZX8T8syz8Wk49KGwPIoOXnKEU0XNag5o
         EbHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=3GH2OmEGtJioKtTQY62gxV1njY/CexNS4bCr414yXjU=;
        b=U3J//xJTemkVe48b5sa/F22Tavi7zhhBIU8G3hkUpLbG0gzKnM5PeZ9ch1bj8FxRI6
         GXKJTDPBckYYPSNGENwuK8P1hGrGRbeO2MVEvFnuN0lLatF2WIrKlReYoV/F3Vq6UcjE
         CwEZQiOdaX541+OHaxd6wYqu8P4GZNHwzCtW+gUahcq6nAZ3rcqaUdljRSQ1ScjNJi0h
         4LrPOHf9n/i91AxvZf5X8Ehi4uyiJrbXYjSP6rnnr7brX4DVOB5U3JTthHhjYCh3FdcD
         7zzJLaXU/aUiW57VxaVwSdkhZr3wcKp8fSt9uxTwO4jJ2htW7R7hipjFIPd/GyNkGse5
         +Vlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=GpnNmP4B;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3GH2OmEGtJioKtTQY62gxV1njY/CexNS4bCr414yXjU=;
        b=HXpubis32vchhJTWBfgA3Xv2lMBYj118F4qOfMES3ZJ7k8SQTUpg6/ET93FCyGHfiZ
         8kM1PmWj2BM4GULkqyIzlly9xJXGWUjO64rRahOVAy7O7Z5thpobeAK5ExNY2u/Cun+/
         gOsi0zWuq8oIicPbrGcBA92TAGrp7klJ3FxQ+6h30UCD9T9ifHkFMIIga0FtaTAORkvO
         DZp3t3uPNkIaoIO4X1/5lbkfY45Fnw5zpeJk4NQ/JIUmETxb0CQlmVcZlzr8X6X1ZgQr
         3PU60RWsJC+BjdBY0JWlq6u6c+FzeTidrPZyYloNHXdmH02/yihMZkG8xJzbCEbP9981
         hb3Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3GH2OmEGtJioKtTQY62gxV1njY/CexNS4bCr414yXjU=;
        b=KNczMrbmjDxukLR6S0eyJTlmaD5KjqnGYhb86haiNRG97g/lUYHfQi6bxT/HnzaRrB
         B2c5c4fGRFrJpdGq0iK6ZCDWyf8X/gHvb6IbKzTjk2xwskwz0O8fWE1/9wdJX590H7Hj
         xpqXniWRlZKMhQLN6e2ADlr23qKuJ7/CxH3dlNmE+USfNwxYfyQI9JkgUpS8EbIdgMeU
         cuQHYfd/OTrpvJbJq8cmyhZ5ECpWwrQCN8Xzs3uPSEAom2tKZMxxiG0n6DP7McDVBihD
         YI/sMcqYn++/QqgPzLJxZdUhJLDiSqlkx1D3t4SvO/9jSZ6QWol92HNmt9tgXQsKW2Dd
         B58A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3GH2OmEGtJioKtTQY62gxV1njY/CexNS4bCr414yXjU=;
        b=EaYAzfmiTjs+FAaBkg7T+DqUOGNRIhdICHs3yw91lHHV+ic4IVFzdzCxGMP7+axoKe
         goFl42csLBr9gntNAhOrs1dTZ00tQ2rBmYG6wBvNKGZiUxh7Uiajbo+WKhxdP0aDUwsR
         ahAEI69Z1YD1ab6OvVEniWaNVLjhShVviNNY5AJ4j+lMNJnU3sWPzPG6Jk1lduWIxooP
         hMD7c5+zybejhlM3jGqFRLX+vMUgGF0GJ9Gds7iK+dgpdoQY9RsJ5HL9i4xhjsQI1G02
         zmU9+4+0zvE1exhih/x5cbWrVNooOVtWEkfRmqhO+0fD7pphVoFyZJyNknv6wGzKXgb3
         bYOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533D2In4iTgANFHFOlrH7YQF+ENbVkglWi0p6F9ih/JMd8MdN+21
	y1V0RzUbz9NQkvqddQoLy9I=
X-Google-Smtp-Source: ABdhPJwMtcsUdN7ZUIgqMevXUZYxsnziIB2hdxZ+nW3e49mV8SDsRYqXtrnmn5y6qdacEkmDzaRpBA==
X-Received: by 2002:aa7:9a50:0:b0:44c:26fd:caad with SMTP id x16-20020aa79a50000000b0044c26fdcaadmr10040539pfj.6.1633281376027;
        Sun, 03 Oct 2021 10:16:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:67cc:: with SMTP id b12ls229506pgs.4.gmail; Sun, 03 Oct
 2021 10:16:15 -0700 (PDT)
X-Received: by 2002:a05:6a00:1a4c:b0:44b:1fa6:532c with SMTP id h12-20020a056a001a4c00b0044b1fa6532cmr22060103pfv.64.1633281375541;
        Sun, 03 Oct 2021 10:16:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633281375; cv=none;
        d=google.com; s=arc-20160816;
        b=BRdytWrPTua82vyLDPNeqvcuyb6U/2GbSnS/KCWLHmJEyUf1JkliaQd1da6swovxV2
         6JlFXeyFq6efKvVKRC2By7+2PvmsbJacxblzEMJLrjPSVni3y/6dKLbEJV6bxB83ZJ9Z
         xpUtZfIkQNoUVl7IxgY0ddiWAj+v1QpiXgzrl611F82hQedo1R2be9YIC/rlYeLnrX3q
         iFYiT9/sjsX1cqOUNLepXf1Cv2IyVzCYEd0I4HIIPlYCrDTPsj0O9GaO0PjtVCYXt5zL
         M1hREeAlfd96KwzCY8bJXz+OtDsbZFYdPmRVDLxCdXtG/0BK2ROypyltQuGw//8FTJzK
         kQMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LvbtWHhJ2QLzR2m5rN3+eMw6+xLJZ5dbABBjFP9K8VA=;
        b=VeB/5TLV4lPyGGgrxU29lmVw5EWk79nVmFs2dWtaqUJTwC9HYSZuwxVXdYF8x14O3i
         JsQK7jiImsKfycQl4eN4B1FM/4ja7pzyHzMMog7V9qe1l5uu8zRSMMJwOTDT6R0C9VOA
         H2GN/EPJ+rdr5Fo+usRsVsgEsyUQ+LgtCIrflvjt7esFzUty/NsBvtOq54mH8+NeogK4
         rnnUzqiekgeCreClISuBw777CfP8KVsqGKkP81f+MV5FW6jUplhVAzmcF6cicHdtrmZg
         iOLQMM6MfMgoDDgh2iF/5T0E8mCBHedWDW6Ejeea6HyoFHnuuXmtdmvEmrgJACtuZkG0
         WISg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=GpnNmP4B;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12d.google.com (mail-il1-x12d.google.com. [2607:f8b0:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id t6si56793pju.0.2021.10.03.10.16.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Oct 2021 10:16:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12d as permitted sender) client-ip=2607:f8b0:4864:20::12d;
Received: by mail-il1-x12d.google.com with SMTP id i13so15914886ilm.4
        for <kasan-dev@googlegroups.com>; Sun, 03 Oct 2021 10:16:15 -0700 (PDT)
X-Received: by 2002:a05:6e02:1a69:: with SMTP id w9mr1245501ilv.235.1633281375073;
 Sun, 03 Oct 2021 10:16:15 -0700 (PDT)
MIME-Version: 1.0
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
 <20210913081424.48613-6-vincenzo.frascino@arm.com> <CANpmjNN5atO1u6+Y71EiEvr9V8+WhdOGzC_8gvviac+BDkP+sA@mail.gmail.com>
 <f789ede2-3fa2-8a50-3d82-8b2dc2f12386@arm.com>
In-Reply-To: <f789ede2-3fa2-8a50-3d82-8b2dc2f12386@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 3 Oct 2021 19:16:04 +0200
Message-ID: <CA+fCnZe-gogW1yMuiHhXmKXTsmfkb+-iWp1Vf9K6ZY9madtxfw@mail.gmail.com>
Subject: Re: [PATCH 5/5] kasan: Extend KASAN mode kernel parameter
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Marco Elver <elver@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=GpnNmP4B;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12d
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

On Mon, Sep 20, 2021 at 9:46 AM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> On 9/16/21 12:43 PM, Marco Elver wrote:
> >
> > Shouldn't kasan.h also define kasan_asymm_mode_enabled() similar to
> > kasan_async_mode_enabled()?
> >
> > And based on that, also use it where kasan_async_mode_enabled() is
> > used in tests to ensure the tests do not fail. Otherwise, there is no
> > purpose for kasan_flag_asymm.
> >
>
> I was not planning to have the tests shipped as part of this series, they will
> come in a future one.
>
> For what concerns kasan_flag_asymm, I agree with you it is meaningful only if
> the tests are implemented hence I will remove it in v2.

Hi Vincenzo,

Up till now, the code assumes that not having the async mode enabled
means that the sync mode is enabled. There are two callers to
kasan_async_mode_enabled(): lib/test_kasan.c and mm/kasan/report.c.
Assuming tests support will be added later, at least the second one
should be adjusted.

Maybe we should rename kasan_async_mode_enabled() to
kasan_async_fault_possible(), make it return true for both async and
asymm modes, and use that in mm/kasan/report.c. And also add
kasan_sync_fault_possible() returning true for sync and asymm, and use
that in lib/test_kasan.c. (However, it seems that the tests don't work
with async faults right now.)

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZe-gogW1yMuiHhXmKXTsmfkb%2B-iWp1Vf9K6ZY9madtxfw%40mail.gmail.com.
