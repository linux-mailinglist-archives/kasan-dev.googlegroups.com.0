Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWNS6X7QKGQE6QAOT6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id E0E132F29AF
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 09:10:02 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id h9sf787752oif.13
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 00:10:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610439001; cv=pass;
        d=google.com; s=arc-20160816;
        b=aLzTC0x1/PWjnzKubctxShrjPBnzuKoMxZTWDV3TbslFK3QmUXBd1z368Qfkv5AJvQ
         PCj90wv5i2zSwig/pOLQZuQPzw4NIGE/5pBi0jRoGBrb6U2ep/nka7u2NHJIzyWSGUD+
         OvijbGsGinURhYdPl7uHQ1c/um1be510Qg3ktORsMcXqR/1xUWQuG6+aoAf+iRwuVUjP
         WNbHBKFXsLJ3lKyljOtfABsNZ3mR8S1Oy1/+PPOc5j/hsfheV3rqEbi6H8dW1UBd6v2U
         5Qbiky6ZYHmTllajaHb4s6MMurvXmUMpw191tq3B4xdpBkNn+MRZz2MiDd73Ra8CoCyV
         zNIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KwFm/TqqLdX2a+t9N6WvqhkokybkddYH4Fl5G5/d5D4=;
        b=ULQqwqfaYL/M08hO0DaVviYE/ztPAfL8ffQKRf/b6Dl8Kl4pvzKe0OW87uYF1rkLMB
         1/IIBrUpI7jyHkhkOM8WawSjrHftvVsu7ubG+2GvjeLoQ0lABquhLWQRdJNBFwHORbmk
         caI197snnPceiTJDqA9w0VZybB2v97E2U2TaNqUREZqjf55wjFqtBm7uwzM+r7XSsH6X
         WKqVhWR1hVPAnb3DAteRIqKvsgUGYsd6Efl7/MEjdpU+kRaHOqM8k7PQ2n/qKqU0bFbf
         QtqWqfzI3IVQkcHyq8onm2EVs5gIXjJutMIgh2/j/PKXer4q+pBwLHYHLK4ydiNiE3wz
         9exw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IkA2W0Um;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KwFm/TqqLdX2a+t9N6WvqhkokybkddYH4Fl5G5/d5D4=;
        b=WetWm0lesXHCJNRICLG9LgpfOz1zvD7JR+JaS4Dzb/pzeycU4Xtwrsd6LdkTu2hajN
         ofO7fFxasq1ULluCGziGMPqdfXZ56VMeglS6MYQjYAJamD6fyQgxd3G9LAHE0OvyVXXW
         kgJ/+PXDukGHTCArtMQAE/jMAk0BWxaRt2eoNhSHTFWgYCpuRqkS3AKNv/FHNm6tXoLA
         DtuelIIveL5vYs9gXx+fhmpIGfSJt4fhbm831bwTmjILshzpyqqYLuls5GJBpumFNTaY
         PD/NDKJKDUZmVn911z+jEECmyD+x3VfFPmzI5GFija4nIeSF7sNPQisqG26CAJdxMjcJ
         Vbsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KwFm/TqqLdX2a+t9N6WvqhkokybkddYH4Fl5G5/d5D4=;
        b=O1PUVqRNDMRi0/RiC/jzI52AbPpoctaIqaMHHVwEa63PFNcjVqttSlxMuaT0p/DUPW
         bz0wgiQTKKnxFBuRqKtgFx7V6ejfnKTHUrcqk/PkJBWDcBGvW2V5vYv7HmSbyJf//33V
         PyuO2XicSpd2HiuF1W2eazUChjZ6xZmixwetloVhYAuOGGd7FeWZxDCk+cfkAv3fEjfF
         tU2GLLtlMOv4mHiudti+mvmBSMMNdUxm2x8100Pd0H5QGGN23Rj5TcnzJxn+6gXUYwTA
         xPao1jX8Z0yOP5gaKdv8YDXf9/xPoRyGxIbTxUT1K4pZTVRNHqTrBOxeP8sNUKxngTqx
         WP7A==
X-Gm-Message-State: AOAM531Iid6A13IBfwlztQUPpS9aeSOFXEKEWYZX9QMh9Og03XZKESTS
	YPV6zozhgNbF3O8b2GfwYQ0=
X-Google-Smtp-Source: ABdhPJyFlsBBDHlRu7yYur2HatzX88oekHkRtBkU01++WtEMdGoOJknSUEZFWd06vdx6CRM6JqSHpQ==
X-Received: by 2002:aca:dd09:: with SMTP id u9mr1654985oig.73.1610439001648;
        Tue, 12 Jan 2021 00:10:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:714:: with SMTP id y20ls580772ots.9.gmail; Tue, 12
 Jan 2021 00:10:01 -0800 (PST)
X-Received: by 2002:a05:6830:1c24:: with SMTP id f4mr2031870ote.108.1610439001366;
        Tue, 12 Jan 2021 00:10:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610439001; cv=none;
        d=google.com; s=arc-20160816;
        b=iQXhKOPW/SbmlKwEK6Nr42EGHuu0lLiz047Dya31inKivYyqIkw1diMG/rwd5mPeg5
         zFPDv0G02s2adT046cOqRnO6kMBOWuPRT0z6EsgTcOgqAzZhYD05qPBbHXSsXFICAzcb
         4k7JwJuttaT+74dgqQWESIPbm7mW/mCx5DutXCsD5zex7f1cne/q8jfKX7/vWQhpO5Wj
         QxtU8U07SLxHpgLIe7BqzBSXqJZJkF0TPyCrSGmvWnOI7iV7WYS3szuOiXi62D5MqFTn
         wZG2OvvaB5HQTUc0j+9Gyk5Ex5TJCygh9v/lxtSk9a0r3fT46KUXx8/hDKavLVzHGhQT
         qoNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=s05pwcBYuLFgatCtLuiKcXyLuPX0VE24Igc6LpSnaVg=;
        b=GxLnn0zLQGzTTReeZCsgvXaEr4SSY8zwcODtvyrFWvODEVGibGvGd+RQDiD5e4j4Wz
         e74YDqQ1O4yaL2J+HVB2OOvEa7T44Ty1K/l+yfLvM9mCJ1V83yjsrMJDv+nwPXE2WMK/
         YaNA3CGSgYnbL6dZspyxtXejwPDCyd8qRuy1ECY34MLEP8oUSTq5Z4Ri2OZkh6hwAZ1I
         8A8GbW0jGaBExVk1dLKckwO2El97xER2MPMb2o+iNl+yRsPFHdlfi5DUs7kSYalhagJ3
         HBCaBvPgqAmZaiZ3S+ry1aWWLVtimGdXzbsjWlhfpli4iDP6uANZechV0fkkzfWnafig
         /eBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IkA2W0Um;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72e.google.com (mail-qk1-x72e.google.com. [2607:f8b0:4864:20::72e])
        by gmr-mx.google.com with ESMTPS id f20si165247oig.2.2021.01.12.00.10.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 00:10:01 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as permitted sender) client-ip=2607:f8b0:4864:20::72e;
Received: by mail-qk1-x72e.google.com with SMTP id d14so1129560qkc.13
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 00:10:01 -0800 (PST)
X-Received: by 2002:a37:9a09:: with SMTP id c9mr3334368qke.392.1610439000729;
 Tue, 12 Jan 2021 00:10:00 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <ae666d8946f586cfc250205cea4ae0b729d818fa.1609871239.git.andreyknvl@google.com>
In-Reply-To: <ae666d8946f586cfc250205cea4ae0b729d818fa.1609871239.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 09:09:49 +0100
Message-ID: <CAG_fn=U86QGTTp+vgQQhjMBY=_dQgPbWKJ1MKt8YHdyLi3deMw@mail.gmail.com>
Subject: Re: [PATCH 06/11] kasan: rename CONFIG_TEST_KASAN_MODULE
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IkA2W0Um;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72e as
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

On Tue, Jan 5, 2021 at 7:28 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Rename CONFIG_TEST_KASAN_MODULE to CONFIG_KASAN_MODULE_TEST.
>
> This naming is more consistent with the existing CONFIG_KASAN_KUNIT_TEST.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Id347dfa5fe8788b7a1a189863e039f409da0ae5f
Reviewed-by: Alexander Potapenko <glider@google.com>


>  KASAN tests consist on two parts:

While at it: "consist of".

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DU86QGTTp%2BvgQQhjMBY%3D_dQgPbWKJ1MKt8YHdyLi3deMw%40mail.gmail.com.
