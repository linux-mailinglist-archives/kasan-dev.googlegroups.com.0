Return-Path: <kasan-dev+bncBCCMH5WKTMGRBU5CU2SAMGQEK4ILO4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 51E8E72FA19
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jun 2023 12:07:17 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-3fc3ddc42dasf20379171cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jun 2023 03:07:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1686737236; cv=pass;
        d=google.com; s=arc-20160816;
        b=DWDxnajnUWzWVKbLxnEg/asUiV5sVuwu4D0nLG5tv+PTXOuAkM2QT7USYstj8l5qO0
         PCLuPdPrtYheTvI7HYrxiZcPGepiVLzOF/mL1EOEVYrkJ08vwvCneX/RNN+5U/DcEMhU
         OxK3IsTY+EkeE1dwK9wvnBdL/KBiScFYDnHkdm6a5WmfZNyfgz9oM1Zh4k6gk/fBllCl
         tYfPjjkvJgczi1H1fTcWepngiG2633mZ5VMouBorscGANFtIvoMxf9SkHiAFfkw599/0
         al1fe2eeSQPpJt0XbGbf/XbEHvRMIAoNVX1bdzCgNrqjzqJ2yBLb1L9zIhXBEYtx/nFY
         caXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=61H9oaauipy5++8qfPojkmLq/BHUxVtDTEOi2cYjQuY=;
        b=BQ+sik8hPdj9UeG8pMEpcSIGSbaogFGk3r6BtgywMiVGFT07ROi6Pkc0HJapl/yKEa
         Kr0RvOYY6CquN7hhI7N3fMSZZTOcvfvbbHte/AzXT6BlXZ42SpH4Cc5LcQWkdRLOq3FY
         +nV/nLsjnIiQU7ISUx9C3BoeK77vjR15X4wlRLoaBCCY87fnVwgZP4XHvoUVm74xCP40
         aaVEZtqeRVV9O9408aRfd8otxn3ferhxSfm6tgiwE/JyRn8NTDqZYreeQ5HyvpKeiAa8
         lqL6EME36ursJiSOqaUtVJgRqF7w2uz0HP9kHcA6+uJG/jRDyPVy5l0rJ9QEsrZd8WSS
         WJPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="dN/RPc2u";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1686737236; x=1689329236;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=61H9oaauipy5++8qfPojkmLq/BHUxVtDTEOi2cYjQuY=;
        b=IZCtb4q2mVoPtDh6mwdDwcP4vf3xMpXnL1rly6K5ULAFkbxxnxiLkTQOkj0IjvoNCg
         1n6lFBygLLPg63bYXwyjY7dDoISgh3b1LYgCTxVp3NXxh086spYQW0kDjrrn1qCcBm/J
         +O7DIr36N9W1HRG5JAJlCNxECiIn9j2AI676Gu+YApLadpUCdwGqDlz8c7HVMUx3RN/m
         rk+oipGLtiZ2hwoRIWX/s721nWfJBh+3pawnvpCuTv997jDchGJw2QDoYoAWkxdWS1S1
         7GRNMPy4nzdlt2u0F0M7j0eMdkV8ALARIduF63ISovlBN//q3WAUZ+mkADeiUGchXtIu
         Tgzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1686737236; x=1689329236;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=61H9oaauipy5++8qfPojkmLq/BHUxVtDTEOi2cYjQuY=;
        b=Z3IgBAGTAMzF0CldWslpt8vgLuwqh8XALax6I/mMQSnQIis2Gtm+gP2R7DNNlgxir1
         meDV2okSmCYXSqwZzilE1ex0WaSoDDExeTcVbvPaKm+tGsrEr5/fNZ4DNmwxk5/7VDke
         +OGjMs1EXJXVeXU5LLq8yyJ60Qqzegvx2FN6tS3hYJU+daAoOtdsYnECIdcG+1Sumo+j
         JDayILpzB7AxE5NPFXluNqL8XzWTzb0bA7+RM2uqkfAms6incc074nxDPriErdfpSxt+
         4JCkY67p/xwI35ItSMQlc4jlCt1+zbWy9XYrmLiuWmDlrfRRypYKdjvpbfYyOvGQx291
         Yu3w==
X-Gm-Message-State: AC+VfDyzVKKztSyfayXVnPPLcPzex94kGSl7XBAAJKfIPk13ip7nuXE6
	lXRVF452PRnkMgMJfZvQywQ=
X-Google-Smtp-Source: ACHHUZ4stKy0AFGKC0XRsrlrfh2gjWR9B/B80Ffkc5DX58bpmfStq8960A/2CjObkvmwJRWT77BBQw==
X-Received: by 2002:a05:622a:1816:b0:3e4:dcb4:169 with SMTP id t22-20020a05622a181600b003e4dcb40169mr1921187qtc.16.1686737236028;
        Wed, 14 Jun 2023 03:07:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:664d:0:b0:3f6:824f:575a with SMTP id j13-20020ac8664d000000b003f6824f575als588755qtp.0.-pod-prod-07-us;
 Wed, 14 Jun 2023 03:07:15 -0700 (PDT)
X-Received: by 2002:ac8:5a54:0:b0:3f8:473:165e with SMTP id o20-20020ac85a54000000b003f80473165emr1877011qta.53.1686737235470;
        Wed, 14 Jun 2023 03:07:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1686737235; cv=none;
        d=google.com; s=arc-20160816;
        b=LoCs8I2M8LYIjwBv26n/Ql3WBEG5Rgpdm0A26VQT7ixt3JqPFGjoESKLZh4Ghryq55
         seBc1cZPwAJUm+l2yusTi7SnVWS2+JAZ59k4nh7hBTzWw/MDFiyGVs2f4UcJu69ILjbc
         vFI9p+xzOUElPbHe+S/lPj9cNy1ngWlS0whp0gq0zmknW9ahXGDIz584X0dMVqSDy5RB
         SJGajV7IZ8TSdC51u2JNWXfRFeI8NZNauSS+YmeyCrDu2JbY2O+7o0dy6AOudY0UcNJJ
         bzSRxHuSlNbpOibE4+L+hOOOmi55ZSfUh1W3TsnWR9tIM+cQYmlgh+Hi+icqTOYhdTYt
         LXGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tjCmMtFWwB2mu1iBP1u/gNAJuDezygzcIcRRdC5qhOg=;
        b=WQe+pDq15KgF5Olug4jKDrp+TWzVnK8rwky4TEjBazpKo35nsTBvVVztXFr7waLWHD
         zkMS9Gu2xJqAwelb3cyVFACuH7/q8W3NErlrXUCmc9WZNE0hTknwpql31ZI56Zm9bEr0
         C0Msb1ExJNekeQiuwdJD8Izw1G7sMaa0MX8Oho43pc1Rw9d0RUOjALz8WIx/vSR8dc/f
         r4TZwA5rb13pFuofnFxD2+pCmEfUPUVErcyARNj5SGA2WugN/cATME1h8gyeWO8d6sCg
         eodulB/qufzMKnkG5EdGUKTOrCjSWiLesPgorR5V7wBlW9KY8PrKBHH3T5tMJnlQjH3A
         wbtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b="dN/RPc2u";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd30.google.com (mail-io1-xd30.google.com. [2607:f8b0:4864:20::d30])
        by gmr-mx.google.com with ESMTPS id d8-20020ac86688000000b003f9af493c42si855631qtp.4.2023.06.14.03.07.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Jun 2023 03:07:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) client-ip=2607:f8b0:4864:20::d30;
Received: by mail-io1-xd30.google.com with SMTP id ca18e2360f4ac-77b94cc4101so55266539f.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Jun 2023 03:07:15 -0700 (PDT)
X-Received: by 2002:a6b:dc11:0:b0:77a:d2d3:fbfa with SMTP id
 s17-20020a6bdc11000000b0077ad2d3fbfamr12536786ioc.6.1686737234757; Wed, 14
 Jun 2023 03:07:14 -0700 (PDT)
MIME-Version: 1.0
References: <20230614095158.1133673-1-elver@google.com>
In-Reply-To: <20230614095158.1133673-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Jun 2023 12:06:38 +0200
Message-ID: <CAG_fn=UDZFa3D4JwkEMFoy-d6n-sNB5ARh+3b4ymgtzZCUe8uA@mail.gmail.com>
Subject: Re: [PATCH] kasan: add support for kasan.fault=panic_on_write
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Taras Madan <tarasmadan@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Jonathan Corbet <corbet@lwn.net>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b="dN/RPc2u";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as
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

On Wed, Jun 14, 2023 at 11:52=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> KASAN's boot time kernel parameter 'kasan.fault=3D' currently supports
> 'report' and 'panic', which results in either only reporting bugs or
> also panicking on reports.
>
> However, some users may wish to have more control over when KASAN
> reports result in a kernel panic: in particular, KASAN reported invalid
> _writes_ are of special interest, because they have greater potential to
> corrupt random kernel memory or be more easily exploited.
>
> To panic on invalid writes only, introduce 'kasan.fault=3Dpanic_on_write'=
,
> which allows users to choose to continue running on invalid reads, but
> panic only on invalid writes.
>
> Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUDZFa3D4JwkEMFoy-d6n-sNB5ARh%2B3b4ymgtzZCUe8uA%40mail.gm=
ail.com.
