Return-Path: <kasan-dev+bncBDW2JDUY5AORBCHAY2SAMGQEVLWWDYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 527B8736DFC
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 15:56:26 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id af79cd13be357-7639ab7a736sf320977785a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jun 2023 06:56:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687269385; cv=pass;
        d=google.com; s=arc-20160816;
        b=xJo++1YiBhmZZw5tFSflK1OWZI/6jiJfQeE/TKAXfX7gUj3HqkmZ85BmNa8eq1csYN
         /23THifrd/ezrRZhMHC5u3sOubHL8m+FDSzDJE0nLdMybBOXRpHe9YvvycHnrTwVZ5Jz
         0TH/3hPcaj/rpu4Eqhbfwzqz1YGDG0CptGwcSOcdGkHvIoTPH6+PTF+jetLLe/25d5b8
         /x3t6xVgMHisY4oa9WPGE46jSbhqHceVOr5dQPz8oXcJ6qbSqqb8FDe1qit+Lua15aDW
         4jMY2VmKVobgsHwe2N71Ux4SJCPYjX5gqRJTUZuWSWxohqKEhqf7SUsklISGP+mZenTT
         I1sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=4Fsh99jmMGdIijYjiCVPiscfnbsX6hmhLgTxHS7RESA=;
        b=i/Shgmn61iV63SGFYx29StUQ1ZplCWWbKjKMfVgmTQLdqNnpF6MxXjcM2RNC6dGNrz
         JZQHgw4x5D3o+Nj4fr3yMZQsMOCxDHtZQorbVY47vO1W7Nn8/8MsBlcn1Uodl3Py104O
         0IK8LhaXAniWx+BVsHFERRbbtFPWDvsq5IfDrzEAOMjdnXHc5fIeoRH4PBJQwlDNiVho
         k33NhhRpAcvvMJjFfWgrBMM6RutZ8dyJiy1Z+K5nExwcxmhcXVee4OMm5i2SWicorlvO
         UD0EiOpLqploCu92Ydn+DcIZyAlia1EbYFdi5QdnH9j0sjEFXpDfFVmwKFtIH6uc4/n3
         vRUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=CnJeqkL3;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687269385; x=1689861385;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4Fsh99jmMGdIijYjiCVPiscfnbsX6hmhLgTxHS7RESA=;
        b=hDFyk4K7b+MLPkRYLOHeGETWP2yEDDl2/Z0ArX2n2a4U7/m/o8xwYGGDUWIMe29/c6
         IRRyXTB9QTK+Rl1ROJYUx+jNTIqc+TfchhZkMQTxw3Ix1twkdnZgtj433wt1gFUolGTr
         h+3+JmYLeSL9/ICwNRTwI5a35ewfRF9GxPYlWP+0F0HUnSZjLMUBmELQ26018RUhzV/m
         mjqaE/8gaGrSZWEUGtZ/ODcy7YQF+Dcoib2moHq8z+w21jTkaBH/0LPmR3+M3Gtvsb2q
         jRwyRB/7XGAfQgcasUmVxseREQRYRWu0iECFl8gWRj7flGBn6pCLLkUFu43qtxoXkdFR
         NAfA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1687269385; x=1689861385;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4Fsh99jmMGdIijYjiCVPiscfnbsX6hmhLgTxHS7RESA=;
        b=lAUOqeNH46O7O6XeZO3MbZBUlhSsj/E8Px0qPKDlMWF2eFMd5t3jUhKkyOY+WzTB4O
         AgsRaLvRfDYNH72KDxwiyTzK5yNrhC1QjrAJL6CfOIeGqycGukkWLXg47kiGaLHKgpcw
         /ZOTR8ll++HiHz1Owrr1zHw5n46DlRxsoJP0gBeSMWjKaz8XWlHYWA9nAbkrJKSsxyU/
         3rDqmhNXX8mBPdB3tyab7994NOH24bXBOCpp3yK6EisGYBfwKKMVdkv0hvmwJONmH/Xw
         cCGHTgKseJKNGo729Ywx2AB89MIYHixd3ASsSUv4/rhzlZT5L4YUYxkF3PO6Nh6AKDCv
         bnfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687269385; x=1689861385;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=4Fsh99jmMGdIijYjiCVPiscfnbsX6hmhLgTxHS7RESA=;
        b=Wq9pcwWdxkS2lhiXhMK4X7nBuuxiv5wJem7LKfmjvS2DBDVmHFrBoxTvrsyzqra2GV
         /9D9JFUXW8e0lxh42LK5KP0KVHXMcqZrrqWj9XLKzF7XsEUgGKf5ihggTXKIFnmL215U
         iHLsKZduXZlOpz7cfdxGC+Hx1tPXUqvsSk2X0guC6w1Bw4DqUhzlPG327UAT+3hbNK1q
         3AEyEbrsTR1pZ+wFvzvAxi31VAe2QtjAlyTYgCnA3N+GZBPteCt07dq9UHsqUTJvcO9X
         wAAaNsplSthsMjJwTZf0ylA27daw9CCrXxZBmkCwDbOTCCiza6PyJx/s6gQGgGLzZmKT
         xjEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyJjRPlFL3OBc6lGC4pyx87OGH/hb03mkP0w74tdDREhFwhsFz4
	iR8OqA5S/8lv6WgB/bcY1x8=
X-Google-Smtp-Source: ACHHUZ4Q/ef5izd3fsGyJLnWZepsbJDjGwv15sjxN0SrxyzEKs4GJCjAaH0DvnqJWh6spd63/xSQiw==
X-Received: by 2002:a05:6214:d42:b0:62d:ee5a:514b with SMTP id 2-20020a0562140d4200b0062dee5a514bmr19115842qvr.11.1687269385076;
        Tue, 20 Jun 2023 06:56:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:55c5:0:b0:62b:6fc8:9122 with SMTP id bt5-20020ad455c5000000b0062b6fc89122ls2243305qvb.0.-pod-prod-04-us;
 Tue, 20 Jun 2023 06:56:24 -0700 (PDT)
X-Received: by 2002:a1f:ea81:0:b0:471:93b4:7b4e with SMTP id i123-20020a1fea81000000b0047193b47b4emr3113558vkh.16.1687269384531;
        Tue, 20 Jun 2023 06:56:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687269384; cv=none;
        d=google.com; s=arc-20160816;
        b=P2xKz3UEcRaU4wnb5FkcKvi+8YEgPK5NSwPe07h6s2lbG5hYr/uWdNnhcjBhxWbbtD
         ovoJkJT1OZagObu/W+3yQGQIfuW9V4UpbaVMkD/97g/JzI4JxunjZOLbLVMPOyNtB9bJ
         92J8tjwgbjaHigtm5Qqz0UNZxM25vXed2GdWevlMHkhSeGxGqBq3zASWR14dWEbUjGMo
         BYw65U7nka1v03UYRCtGyt494g0fbH2Wl8nO3cztLseMSYQELGJ0VmFcB/urz7muk5Fo
         fSMMzJqrGLUuEJeF5akk7DgOekDfzVKR8LiKLIRmFIiAT7vGTqzRGklPwVfkKoU/t7vW
         hzQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Xu/aiaH31TZLMVI9Tp+a0lmhaF9umbZZEeQm47dZ8JI=;
        b=GwBnL2huouCcboYE48o12/qAVpcswfyhNRo8ZCwn6kc1/hFi/i9PxLOSUp3bEARljt
         4OqWyWHTsOZEub2DBClq1enf1NVdQOpiFv7/W9HJ8F4dJVpCQNpcRAIfHPm0gUijQuKS
         qmvrgYKj69pgwyD/PPPjrd1MH/8GXsuGGDnI9f3YmZbj+5LyPenw+PgZw1NqDIroaGO9
         REGdCu/PNQ1TnECaOLJSKwJgUsxQid87Po6fa7lExTD62dS6fwTyeMbJ/1KscX4ASJBZ
         DEjE9LyYm/YNVUs6NI3Z0He+Kmc3JTtJqyBwYnJ2Rb9Rw0f0WjailsDSb4uQEgBcy/AZ
         N3Aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=CnJeqkL3;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id ci19-20020a056122321300b0046557175e54si146867vkb.1.2023.06.20.06.56.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jun 2023 06:56:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id 5614622812f47-39eab4bbe8aso2983581b6e.1
        for <kasan-dev@googlegroups.com>; Tue, 20 Jun 2023 06:56:23 -0700 (PDT)
X-Received: by 2002:a05:6808:6397:b0:39c:767e:bfc6 with SMTP id
 ec23-20020a056808639700b0039c767ebfc6mr11697031oib.10.1687269382925; Tue, 20
 Jun 2023 06:56:22 -0700 (PDT)
MIME-Version: 1.0
References: <20230614095158.1133673-1-elver@google.com> <CA+fCnZdy4TmMacvsPkoenCynUYsyKZ+kU1fx7cDpbh_6=cEPAQ@mail.gmail.com>
 <CANpmjNOSnVNy14xAVe6UHD0eHuMpxweg86+mYLQHpLM1k0H_cg@mail.gmail.com>
 <CA+fCnZccdLNqtxubVVtGPTOXcSoYfpM9CHk-nrYsZK7csC77Eg@mail.gmail.com> <ZJGSqdDQPs0sRQTb@elver.google.com>
In-Reply-To: <ZJGSqdDQPs0sRQTb@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 20 Jun 2023 15:56:10 +0200
Message-ID: <CA+fCnZdZ0=kKN6hE_OF7jV_r_FjTh3FZtkGHBD57ZfqCXStKHg@mail.gmail.com>
Subject: Re: [PATCH] kasan: add support for kasan.fault=panic_on_write
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Taras Madan <tarasmadan@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Jonathan Corbet <corbet@lwn.net>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Catalin Marinas <catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=CnJeqkL3;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::229
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

On Tue, Jun 20, 2023 at 1:51=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> > Ah, right. I did a quick google to check when I was writing the
> > response and found this: https://lwn.net/Articles/882963/. But looks
> > like that cover letter is wrong and the documentation is right. I
> > wonder what the point of the asymmetric mode is then.
>
> Maybe not as strong, but asymm mode makes sense from a microarch point
> of view, where writes are always committed into a store buffer, but
> reads can only commit when the data (incl. tag) is available.

Yeah, I get that it can be a bit better than async with a similar
slowdown, but there's little value in catching only reads from the
security standpoint.

> > So the current code that you have should work perfectly. The only
> > change I'd like to see is in the documentation.
>
> Something like this (or more?)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index 7f37a46af574..3c58392d931e 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -135,6 +135,8 @@ disabling KASAN altogether or controlling its feature=
s:
>    fault occurs, the information is stored in hardware (in the TFSR_EL1
>    register for arm64). The kernel periodically checks the hardware and
>    only reports tag faults during these checks.
> +  Note that ``kasan.fault=3Dpanic_on_write`` results in panic for all
> +  asynchronously checked accesses.
>    Asymmetric mode: a bad access is detected synchronously on reads and
>    asynchronously on writes.

Could you move this to the section that describes the kasan.fault
flag? This seems more consistent.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdZ0%3DkKN6hE_OF7jV_r_FjTh3FZtkGHBD57ZfqCXStKHg%40mail.gm=
ail.com.
