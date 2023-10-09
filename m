Return-Path: <kasan-dev+bncBDW2JDUY5AORBNNQSGUQMGQE2ZPORKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id B74B57BEACD
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 21:44:55 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1c877f27f46sf2635765ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 12:44:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696880694; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vr/Bi8InweWjgr0mM/w8UUwqi4S0j4D/NKh1iSsI40TUY7gvH2mFMnuW6Vp56bjYec
         kAQp5gnKqcvJ8dIvZJyXmXOqNYQOVV8DGrFkiu94RoGnfHsp67bMr6JGyeilhDWS5TaO
         kz0C5oKFNqAynxTCmztmrabo99UnE6kVtLyNh0fqJJDpUTQXwbYrJq2fLm1xjaP23jy2
         2FuE3GKHbHsKKxECZf5BhVVGQngPigOGDobiNgIlXMbvBXjqdDI5IbWY8FdalKcooq9j
         wM/Axu7GuTnGXMSRJRI6gYEqrafoGahOtfEOQx1Anv9c2f1inbDmFQzJifmlvJheUmAc
         01YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=ellwjr94LqKxvdb1CTTErKTq/YIa9TrsbkuXfeEesAo=;
        fh=7igJxN9LckRTWOqPqITFhKv7QvF9IZfOm1aZGp1o+b4=;
        b=YI9+ZepHMNiz20ytgEGUmOiCxxm2KJrSNY/YDIUnWVy8he2RvEFaoIX+2h5yRMKjHr
         R7OsQEXertvw/KRrvtvDiPss+nlxVzAbjxDByVTrqTEs+Qoqke66FFKof3fWbpAQFToT
         AynkfYsKfooBW47zJSonlZwesed8oqSh5U0wJSMIey70SbXnUTH3+EE5gGah8nfkYM/N
         Tov7VSElX2keKgwGh3gt+ZKDAL5rVo/h8XCgJB6TiXlTY04MXXSi1uj7zDLjoUfqzPCz
         r/NNFHuU3auGABTbV9jvp7MG7dwEc1rGpsnFMkr6DKIkwYn60Ks21ttTFjcEgJazJyS1
         q3XQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="A0o/AdOn";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696880694; x=1697485494; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ellwjr94LqKxvdb1CTTErKTq/YIa9TrsbkuXfeEesAo=;
        b=Haj1wXm5CY9wNYvOlchuavWKtpz9GDvrP4nSCABv+6rpS0DeYQ8x81HJqR666T29HR
         ZFtrkphzXpzSaPMJWXaW1lR/ECgY4u8uHr1AHqK+9l2y9ca3RQesb1kt5vOQ//jA8NGL
         GJRvzGvQmyrF9fpcRTF0WuVNkzhbVsQ8lerWt6HcvNyimZ3bVzjfGquCZ3PS/YH5Ijyf
         cQJmWJVzx8mUxPwKEKKONkQ1F3iGXWX/ZoUyJImpGPY9XSdatotRYtN3xiCVUwsGbRAe
         efXssS6wPWYKKsxJEiUGEx0aTpNuAJPnuOQ0Er57nuF7S4V/DD978Utqbgs35VMarR8l
         J9aw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1696880694; x=1697485494; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ellwjr94LqKxvdb1CTTErKTq/YIa9TrsbkuXfeEesAo=;
        b=DRKG7gLqtpB8MPFDOgbWXQwl0SEY1VMD3pX+NHy0bVoJg9TXZ3Bhsz/hCNzUkcF7lK
         J87nMoSVoRotmpWjQa2wUx1xMeKGG9cETqzetIpBr1grIyUTmglyDZw0WE/8/dleQExw
         aQlEKjeOtyo1DFIKNI0SIYIwg3R+mWUMDJSsVT0J0QkiaUP9LR+vbELSD1oIv/d5KghA
         wnFPwgEPbsdmAZYXDzFDGhtA+GJb5CVAiFFtecuiCpaxK2pBT/rV0k1Bj7lVWKktB//C
         oSDVI+fLKG3i02WagWCca5RXx6s1cTkl6x77RSOc45DRvBnqVMuGfFE/hbcFsJXLgS48
         0+Og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696880694; x=1697485494;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ellwjr94LqKxvdb1CTTErKTq/YIa9TrsbkuXfeEesAo=;
        b=n+on/JSa09gCQ9S/AcQn82TFiUoiyLb0z5vYLbwENPGFTkb7Qo6fYq+e1amsArH6Dc
         vHB4NXe+H1btMFnddWy07Sp5HFLG3CXVBuWX5HRqHH/2jUya40llslM4eWu2RzuK0zUI
         8ZpSqHhnLE7fDDjIrD1mTOuRVA6ClKyRqulqZjeS8ajcQSJwlkXm9qgkkKgCSHtSEKi2
         5JnUVFP7UAItmVXWmgR3FMdfa6SeDNNxqV5r0cZObuA5PJJnIIhkgb8Xg3vyr2diDI+S
         UKD8HgIZKpjO7nLsLw0lthBHXSRJq2qQ0WcRJxmMfwt4OXclwcES3cKGfd+QUf1qRZSd
         t/JQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzDFfswfVS0X6knRsAW0wfOh7slXQqG2mHiJy16fikwhz9wq0uX
	Bc/BMWBvswPXxN64b4rW7yo=
X-Google-Smtp-Source: AGHT+IGvB8h1tzkvz6/8mybl1jcmMmgmbJ7Mv+RyWuA/gCkILMYV1jFZuAPkZVtFjd0PrtSZtLgGWQ==
X-Received: by 2002:a17:902:e849:b0:1c2:446:5259 with SMTP id t9-20020a170902e84900b001c204465259mr772449plg.19.1696880693521;
        Mon, 09 Oct 2023 12:44:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:374a:b0:278:36c5:4255 with SMTP id
 ne10-20020a17090b374a00b0027836c54255ls2565058pjb.1.-pod-prod-02-us; Mon, 09
 Oct 2023 12:44:52 -0700 (PDT)
X-Received: by 2002:a17:902:c40a:b0:1c7:5a63:43bb with SMTP id k10-20020a170902c40a00b001c75a6343bbmr19962139plk.8.1696880692655;
        Mon, 09 Oct 2023 12:44:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696880692; cv=none;
        d=google.com; s=arc-20160816;
        b=XjLUr+q8lnI+471r6W+89W8YOcnkFQfXxpjXdPyM6Toy3EXuN0u5G4XY43WbHvtEhI
         qI5QRnHh8CdRMooxvNzVQp93iucSRNvL4wkWgfsVLovh7VNjsC2LELVrAsOR4rwpOEBI
         7fDstfTSt7LsZegsNuHmPm7sbMsH9TUG2VPl9mri7d1FyUezGsIPYJckzhOPOzD4BpeU
         VOdCJqHrFoP3co3LOSbdOmet81ZnKTSVcSDYixR5+nlNpmZ5jThVWugdLThjBS/ZVpb0
         3v3nVuex8538ClInDriAql49TbZ8vwkiNvtxv7CSpfyWyJPfpGc48bbulHwK0EgwVi6B
         iRTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=CRsKl3JqqRRAbEyiv7681Tqjj5VSz9Ev6khWg1QXw4E=;
        fh=7igJxN9LckRTWOqPqITFhKv7QvF9IZfOm1aZGp1o+b4=;
        b=nnFxk69HjNGcZkU5prJ4jhrxCXq5+Pn86jHCAbq9LY4V6sGI5nugiKJia6/ZdgePPh
         RJRsW53N+EKtQKc+PrpkS1G1Db7SQZEvpi361/PecI/RkWJ1zZ0b1lV1vjYpc/trmHwm
         yzn+AWQC1Xg039o83Cvj1xmaLA3XQojARhHwRpXtim14Kv71S0m2+hKBeJWQYQ4DFjGM
         IA8RCl/6CHffUHyiPMwzScSFWuZoLJO8wCvUBDbCcF6HPhjmTKmPSXyounK7YIRTyjTl
         MF1SZTA5ugI/BCXXp6SEJwpfSp0j4RWlDEvY20on4LRt/Lb+klm4MA9RI5BJUYIi0R7U
         1Eyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="A0o/AdOn";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id kx6-20020a170902f94600b001c46b1fb682si447913plb.12.2023.10.09.12.44.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 12:44:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-2792d70ae25so3120390a91.0
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 12:44:52 -0700 (PDT)
X-Received: by 2002:a17:90b:384c:b0:276:caee:db4d with SMTP id
 nl12-20020a17090b384c00b00276caeedb4dmr12491204pjb.10.1696880692336; Mon, 09
 Oct 2023 12:44:52 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1696605143.git.andreyknvl@google.com> <1c4eb354a3a7b8ab56bf0c2fc6157c22050793ca.1696605143.git.andreyknvl@google.com>
 <CANpmjNM7rytkGRjyG3Pf5PakCdibtpvsm7o-K3am-U0kT-d2Rw@mail.gmail.com>
In-Reply-To: <CANpmjNM7rytkGRjyG3Pf5PakCdibtpvsm7o-K3am-U0kT-d2Rw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 9 Oct 2023 21:44:40 +0200
Message-ID: <CA+fCnZdkug_UEkj7de7YeYn7Ynre2mR9kgH_3CNQG7VC-WzCEg@mail.gmail.com>
Subject: Re: [PATCH 5/5] Documentation: *san: drop "the" from article titles
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="A0o/AdOn";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036
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

On Sat, Oct 7, 2023 at 9:01=E2=80=AFAM Marco Elver <elver@google.com> wrote=
:
>
> On Fri, 6 Oct 2023 at 17:18, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Drop "the" from the titles of documentation articles for KASAN, KCSAN,
> > and KMSAN, as it is redundant.
> >
> > Also add SPDX-License-Identifier for kasan.rst.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  Documentation/dev-tools/kasan.rst | 7 +++++--
> >  Documentation/dev-tools/kcsan.rst | 4 ++--
> >  Documentation/dev-tools/kmsan.rst | 6 +++---
>
> UBSan also has it: https://docs.kernel.org/dev-tools/ubsan.html

Ah, right, forgot that one. I'll send a fix up next week.

(Once again I wonder if we should rename UBSAN to KUBSAN. :)

> Reviewed-by: Marco Elver <elver@google.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdkug_UEkj7de7YeYn7Ynre2mR9kgH_3CNQG7VC-WzCEg%40mail.gmai=
l.com.
