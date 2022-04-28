Return-Path: <kasan-dev+bncBDW2JDUY5AORBGHFVKJQMGQEX4X3UNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id B4628513853
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 17:28:25 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id k5-20020a636f05000000b003aab7e938a5sf2569817pgc.21
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 08:28:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651159704; cv=pass;
        d=google.com; s=arc-20160816;
        b=pBMYcdJEXwaIz9T8bnb6QmQYgOKvrXMxuj2fuxY2ZUet9RzPXRv3AP2qSFrhK/9Uw6
         h+vwWNfiuTFpw6asejtOaRFNZ+OBSgFUWzBUtQWY4JcwShf03aFQu4ilz0D1fzmzxHzf
         weDAoS0MzNdtK9yCDj5almKQ/R2CsiApF8xcFCIXX13a5kHIYJLcds4rhGGyzxze+Apv
         ZLM134hkFCSOQFvVZAzw6cy/6mfMjOvHFKkZ0mBGD1YP+r7Sy8Qp/KgVS1md2uXjOYEl
         z0YDtx66EJoYAD77fc3BT4kksb+CayqZ4P6VWYEz2HUG4mspdMSivmzEaxSOpeRsOnQE
         ENnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=2ax5WiZwkOeOQInvEg2/ke8ZQHfv/CV+LXbNdEB/Jsc=;
        b=qzBZ6sW5Kee4f4mx/qVA2pgzKVA+8yr9WDXMWv4h8p4XPrIW5GX2ws862a3OdMtSeO
         FWPZZ0Qi53qoeAgB+sU220UfqdHFUcwcHtOdvxbGzrS19xJEcKZJWKXvAE2dBal5FpaH
         LDZLyj4qMfhMVL5HP/eOn1c6v6gF8WH+O+WD0+hyeuFWfJRhCKFF7zKZrJyg+3mDIsIW
         7xSQVgQIQ599TmCgUdgkR56qXfqNfsgREKDggw2AtQhlO4GpqDlCAd1lWS9PQQPSGqHe
         pWqjVq1aw/cdJ1FzWXQ188QO0kpRXixuMBzV6HhnrdJxP+0RriI955Q+RKBUNiOpiUHX
         xYYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="Z/o1bp8J";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2ax5WiZwkOeOQInvEg2/ke8ZQHfv/CV+LXbNdEB/Jsc=;
        b=eiH5YgkSv4TUxJUQV39p+Njx3IU5PokhAkNa2XVpZB3m3Wd1GnlYXs6sMBQWK8eAfP
         WqLQr7pp5YfYxUQtoFCmUHWtVF5/JNFrYehOdoSDhly/sL99ULw04gKWIJgwS5huA5Lj
         3p3L6+Q9hJNDod+bPXv7NuN8KSWxH2fofC9B17yoAjwMS7BlmeOsv7M3R6Xwq7ULwwdm
         owAYKQ75p1IGkbdE0v01qQqQCr19dcvvPtRM1qIV7w7q+G8yhiRcTFlhMPvK9EEX70u9
         mwA/Fl9cRyZ12OTchCvX2JtK7bP70LkaL4/9TC7iQx+YHf7IX7g8H7uXml7xfguY+Bae
         9hdw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2ax5WiZwkOeOQInvEg2/ke8ZQHfv/CV+LXbNdEB/Jsc=;
        b=hpcOFShG65aes/Rzp6NYFnUJh2kvA2Qw90vTnZhwr8esvzxDKB3JeTEVuFuWCE99W1
         VdZc179yViywV/OOO5X01iEUfjPr6Bk6OjSir90Vo6mIkUWnPh7JPLwL96BjjVHfGrCh
         36LsNOI6h2rbPGSN8s7unGOT1g6ZvCBgEgSBb2IWxgRg4gW2od5FCvc2OW+5704yhJWx
         4oJbt29SN9gyORMidZ1vphEcrpwiFqiSKPtlRXrEnpDkzmOr8qry2KTszHb5xOHJ4GrB
         6KjIy+qXKnOjT1qq7A2PnWDQwGTXso99IMZWs1VxTxgyWGCGGuq+Y2MKZL1OTnOR2MKB
         MYFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2ax5WiZwkOeOQInvEg2/ke8ZQHfv/CV+LXbNdEB/Jsc=;
        b=T+BSXTsHWeMFAjBElhAE2RDV8whE1wI5jmqa6cZWzINEy2P+xkbyFTFBVCspTX7G+o
         8NsiZgia2J7FkWAmnpifw8uHoLnjtbkrBjQeyDUYrIYEllCLrJKPk3KV6/wL1K03217l
         Bk/a6pfnmaj9+42Wuh6FlIR/Xt4ILbMYK/R8wZd7B5Ck10rkWlS+2SJIcSh06E9Ujxmn
         eQVU7u+448sO/XwsCugPnXwR1ImM2mt53kd0OdwLWkoh7JqRDiX/70X+tdP+QGaqd1Kn
         8bmnK+/1IhYtcna1gTfaZTzTBJ3v6KG2+kTTkuIaMAqU1LQcjEUWiSl7vVqbh5l9g8va
         OgcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532IGyjP/oosaYAvWc2HmeHI1GK8i7YHyKgWy/DbRWfOaCGRJOj3
	SCK3dH7lZf90ApFK+bWMnXY=
X-Google-Smtp-Source: ABdhPJyVDUGJEzCZZFBENR8b6PvhwIuUWSsmHBQPwgDX39FlDRkrA7N7E2tnPNA3A4dxAclyI3q8Pw==
X-Received: by 2002:a17:90b:384b:b0:1d2:df41:3213 with SMTP id nl11-20020a17090b384b00b001d2df413213mr50448066pjb.164.1651159704177;
        Thu, 28 Apr 2022 08:28:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1595:b0:50d:a5fc:43e1 with SMTP id
 u21-20020a056a00159500b0050da5fc43e1ls99108pfk.0.gmail; Thu, 28 Apr 2022
 08:28:23 -0700 (PDT)
X-Received: by 2002:a65:418b:0:b0:382:250b:4dda with SMTP id a11-20020a65418b000000b00382250b4ddamr29127110pgq.428.1651159703620;
        Thu, 28 Apr 2022 08:28:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651159703; cv=none;
        d=google.com; s=arc-20160816;
        b=fhFQ4+Zg+IzKVqK8vRJCzbp6My2D+HpzgSUL0te/HBh1MAm7bn5ZEW63cJJPS9ISEn
         TB4IiD6Vzii6y34LggfGZ4q4c+UXkghP2tUrUhqNXcnQZDubJSKPuWOlLKFCCOVRRZEy
         OWLlRLb7ZqfXE7CY3UYJA98utmaXb1gJJkJ0HT18Ze6ic7nigV3DboaQEaBoGbns2naO
         ZIo85+f4KugIXubW+cUg/JcDmZ6EqDhXj04hiXiT4MuyEqlQ2BdnkHfCsYW4XxNTYBTe
         quz3zwH8LOJyR3+06+OBcUN02+4BQSuEAqnDG+lCdww/4/UosQqRJ/DEtc/JHLKfEdvm
         nhrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Zmt/HybSZxPjdQpw7T2VvzfrhcZdhwr2P1u1idPPwIg=;
        b=eztD0DaAvFfBCz9EL6LiUlEu41DzYqAvxKHLMV7O7w4FBPMCdFW9KnteQYm173B/kG
         WwHw/eLIuHvZFFobZzWP/Va4kx55APbanIAm2POMxLYc0yVmQOhqaGU6wVLpRYAf3Z4j
         IeSkxOojHFvsCTQt9hsH6O72rV+hvbApUFN2ch1Nd16K6tXi4o3kuJ5Sp96fh1LWAHPr
         cg5lZuWuZn95ObC+GZnAcMWJu7dV5zoa+NqpbvunpJngD2sYtsws3GwsQ2JgkKb1LJ+W
         0jsMsImE6xw4slq1jX5WowMP4UkP5czsPMFgng2BU3JrMjHY9XTE5lQdM460U/81Z/Km
         ld8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="Z/o1bp8J";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x132.google.com (mail-il1-x132.google.com. [2607:f8b0:4864:20::132])
        by gmr-mx.google.com with ESMTPS id y3-20020a170902d64300b00156542d2adasi215624plh.12.2022.04.28.08.28.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Apr 2022 08:28:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) client-ip=2607:f8b0:4864:20::132;
Received: by mail-il1-x132.google.com with SMTP id r17so2206735iln.9
        for <kasan-dev@googlegroups.com>; Thu, 28 Apr 2022 08:28:23 -0700 (PDT)
X-Received: by 2002:a05:6e02:1c24:b0:2cd:96ad:8b8a with SMTP id
 m4-20020a056e021c2400b002cd96ad8b8amr8162420ilh.235.1651159703117; Thu, 28
 Apr 2022 08:28:23 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1643047180.git.andreyknvl@google.com> <20220428141356.GB71@qian>
In-Reply-To: <20220428141356.GB71@qian>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 28 Apr 2022 17:28:12 +0200
Message-ID: <CA+fCnZesRG_WLi2fEHtG=oNLt2oJ7RrZuwuCm_rQDPZLoZr-3g@mail.gmail.com>
Subject: Re: [PATCH v6 00/39] kasan, vmalloc, arm64: add vmalloc tagging
 support for SW/HW_TAGS
To: Qian Cai <quic_qiancai@quicinc.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="Z/o1bp8J";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132
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

On Thu, Apr 28, 2022 at 4:14 PM Qian Cai <quic_qiancai@quicinc.com> wrote:
>
> > SW_TAGS vmalloc tagging support is straightforward. It reuses all of
> > the generic KASAN machinery, but uses shadow memory to store tags
> > instead of magic values. Naturally, vmalloc tagging requires adding
> > a few kasan_reset_tag() annotations to the vmalloc code.
>
> I could use some help here. Ever since this series, our system starts to
> trigger bad page state bugs from time to time. Any thoughts?
>
>  BUG: Bad page state in process systemd-udevd  pfn:83ffffcd
>  page:fffffc20fdfff340 refcount:0 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x83ffffcd
>  flags: 0xbfffc0000001000(reserved|node=0|zone=2|lastcpupid=0xffff)
>  raw: 0bfffc0000001000 fffffc20fdfff348 fffffc20fdfff348 0000000000000000
>  raw: 0000000000000000 0000000000000000 00000000ffffffff 0000000000000000
>  page dumped because: PAGE_FLAGS_CHECK_AT_FREE flag(s) set
>  page_owner info is not present (never set?)

Hi Qian,

No ideas so far.

Looks like the page has reserved tag set when it's being freed.

Does this crash only happen with the SW_TAGS mode?

Does this crash only happen when loading modules?

Does your system have any hot-plugged memory?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZesRG_WLi2fEHtG%3DoNLt2oJ7RrZuwuCm_rQDPZLoZr-3g%40mail.gmail.com.
