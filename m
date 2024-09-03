Return-Path: <kasan-dev+bncBC7OBJGL2MHBBL463W3AMGQEBAJQJWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id EE35896A610
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2024 20:02:27 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-277ed534946sf2359399fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2024 11:02:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725386546; cv=pass;
        d=google.com; s=arc-20240605;
        b=jsZIRTWgmbsTZ0K6u1bAvk3a/SlI2QUDxdfH4wUJzABVlcDb1D8MrUC/Enx/tvrx74
         FJt/FxwuT1Hu3TOm4TEvfeNKQEYzKwTsm7cjzIGgCZ8llTJELwx4jm7kZ27y3GbjCLN3
         XK8oH4SBnbC8Z0wBtEXdXFdAJQ/y6cquDQkXPRq4vMP+oAqKPcKqeJtDpNvkkbImdfFV
         xOEJOB3AMUDfFJRnvHOuOarC2uUk0uVto6MTyb4P0vE2Jik558Fg91QJA2VfskWkSTCA
         bT0eqlALUSN969MD4Dlhp3IzOu3JNX8+gVDY7KP3UQ2Mbl5LX9wkBzMLqJifM3Io2zJ9
         zsjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uUWy1KWTp/wSgG/ABJ9zKF2TMJgHPSMMrVMig8xC3eo=;
        fh=CorxQATL+BIKcFqo7jTei3cTqGEy0EiOQBk+J325dpI=;
        b=QqXECfLP0F6T5303s4e88ItPktK15qa6lKfwffQkcdk3L9G4oomRxlN+XM0Mg1Q0gL
         aB2FG+YBD3Loltd89Bhe+RjyB+aDKZxkr54fh+5wkxMo/1zA5KAzP33QbtIcft55gZk+
         IKihcXG87hCyHqS/MuT8q8ta5gFS9KnXeKQmRuocj0R4kenTXfHMwwxLzhwgrLo5QYKr
         wx+KZgZpEfC6NdFIdzr7YBIzhmyjUdtmSijDryrr9WxmSsQoal1A4hWXOvO7otWXWhdv
         iByWA8WnXSzc+dFoUO7PQh7rJBw7E1iMyJO5Qmo3jyN59eoMuTz/FvMomqAissqQbDtk
         hd8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yLdsmjGt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725386546; x=1725991346; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uUWy1KWTp/wSgG/ABJ9zKF2TMJgHPSMMrVMig8xC3eo=;
        b=tSGAkPURwp4fqaKVLlrdTpKlTFAq6sIqBMiotD7x+dC2Qkh/7m5/V+eKqPB2txPByA
         3fdl9K6XV7P0EFmiuEeHa3zvLcC/08Fdz6bndlMfT97aIZGp4PgNXOfTwDmE9N9JjlmV
         2Uay7ru9hBQNQxObCFvq/hOpAx3EkbMoAkRdO4mc2HkdUo0FqaQyEkMoateS/tsTlJnY
         fOPezoPWKPVmH4Pc6aSHHgl50ZMesOVWiAhLTJgk1vyIiD995otLRc7L9T0SF0JQMtPN
         lyF11KtPJE2+ZBOiArrJM3i4DP+rmXHbptj2y5pUiyBJwLe18dSkz1TDLIi1LOku4muY
         a4Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725386546; x=1725991346;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uUWy1KWTp/wSgG/ABJ9zKF2TMJgHPSMMrVMig8xC3eo=;
        b=W26ctrD91vw32/y1UiWBiaQcY24NJKEmfO94dSuGtHkte0kyhvLmTM4v7quVaRCpO/
         nQE4WUuZxm0Oa6n61sLJ3tzaN4qdJA74LDgn+Q1a7QnshVsSj4p6VG2QXJOnCju6xZlh
         Bf8M+i+KEVVGrv7FVFbdU50IrdU3OLlKa6JDB+0S1Wy1Mbdr9Bc+O50reSUTOjUmQlN8
         5FcIoL1ZuNOiO7aKDJ83rVzxd8Xl0uoS91pag9jpE2eGlvg0dC+E6fNSMP1O5o46O1A4
         GoEPvUiRZBUQJ5OPdTloeXPVd04KDvF28NoSwalyexhL6OWDpP7FuCRbSC+vMupZaNUO
         1d2Q==
X-Forwarded-Encrypted: i=2; AJvYcCVyRag5vTeQ0iHKWWU9AKcONTQ+XU7WeNIZgsH5uVRVxLegrg7iNqdpq7JOb/CEX8i5BBOOuA==@lfdr.de
X-Gm-Message-State: AOJu0YwVAArvThYnWS/BBu0g8k6jeOrs+v/s+4DByoeWkTWOU2X1xoNc
	2U8/9OKamW/AsY2DWw2sMBrI7DHzUvO+Wjvs88k+1/weJGLqr3ba
X-Google-Smtp-Source: AGHT+IG0RwS+PtXdqLf97m/eLmajranP0YmhXMKgy4itfMegJvCKVronLcl8Ol3Fqxtoq1Ge4Uof0g==
X-Received: by 2002:a05:6870:eca7:b0:277:e94b:779c with SMTP id 586e51a60fabf-27810b95fe3mr5297175fac.19.1725386543320;
        Tue, 03 Sep 2024 11:02:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:df48:b0:277:c40a:8a51 with SMTP id
 586e51a60fabf-277c40ad1b6ls2076542fac.0.-pod-prod-04-us; Tue, 03 Sep 2024
 11:02:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWEausWY0MySFliVZy4v52iSdN64AZKaBu+ColrdzjXxbcMnAdcd/ru3A9s7wrkXetTxANOsKqD0Ag=@googlegroups.com
X-Received: by 2002:a05:6870:e0c9:b0:264:9161:82e8 with SMTP id 586e51a60fabf-27810da1c0cmr4526862fac.41.1725386542103;
        Tue, 03 Sep 2024 11:02:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725386542; cv=none;
        d=google.com; s=arc-20240605;
        b=X+ESY2Kj/J6NmZssviHpCvt3PmBa23hL9Toeq4J7dfyFe+6kSGaM/0BOGVMrmb9/xO
         rwfy3NsLEU6hNBM22hf7321tFleTfIDS9BGD5Sx53q8FBHUttWTYwG8dPU/4tWRZ1jhM
         W6ChOi0rApVUaO4IYhWTZ/G7706nynmneAZi9B0nyqAFxSdl+W75bT+IzAv3l+iKbrJz
         Uj7d8VB481Ss8mviN2yrHqSEL+P4o5dSFoi3urLjcskm99EvfPIeuTb2ET876jauW6sC
         aipY+A42lnh9B8SneS+vnHQnAmN5mx3V7vHKd2daXQgmhXP6/ckugjWpSSAojuVXce74
         w4Qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=yvGiNFbJVYVvUlbAp59wn+lmSLXIjtX8rqRd77LaWMc=;
        fh=AG0hr97yApm36obHVk40ciMfBXza6Bub4CAKOhTvz3w=;
        b=UxHK/OCeliLgPRy1S02Ax5V5Xp2E+ZAdWhWkn7m9xpw7rYsQWg09jNAOP9W5Qdv3os
         dQm5Ku30jPVOSrdf0YXr0kLXnL7W12vA6IKwX9ar8NNQ2Uu7EZsKyGuxvlpjoafpUSGH
         lcrrLB7gjdpAypyaCW1pw/VOQojBnr62RnQ9uXQ6zjIzRYYcGWFkoZ8E5R2D1uRRTe6j
         P8YkvZBbM52DoNm8+QAl3Ikd1cW7o3y9Ae/cB4X9VJo1oxC5j3lYykjx6+J6h/EN9CJu
         iB97XsURlrTWyAAaUoHKJHwU0sa0Y2nuczTj90IblmjEi4CW0e8Ys/JqhDU+/nFXmbfq
         IfCw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yLdsmjGt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4ced2ca7e17si433502173.0.2024.09.03.11.02.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Sep 2024 11:02:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id 5614622812f47-3df02c407c4so3267466b6e.1
        for <kasan-dev@googlegroups.com>; Tue, 03 Sep 2024 11:02:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVYbz9d8suo7wmrU4Qmg48FA1pCdzEDn31dld7O39t7b/3Dv/56RRfiFoacpSI3h+bK1mWgsNHPW5c=@googlegroups.com
X-Received: by 2002:a05:6808:201b:b0:3da:a48b:d1e6 with SMTP id
 5614622812f47-3df220f2742mr11368929b6e.16.1725386541400; Tue, 03 Sep 2024
 11:02:21 -0700 (PDT)
MIME-Version: 1.0
References: <20240725174632.23803-1-tttturtleruss@hust.edu.cn>
 <a6285062-4e36-431e-b902-48f4bee620e0@hust.edu.cn> <CANpmjNOiMFUM8KxV8Gj_LTSbC_qLYSh+34Ma8gC1LFCgjtPRsA@mail.gmail.com>
 <bd647428-f74d-4f89-acd2-0a96c7f0478a@hust.edu.cn>
In-Reply-To: <bd647428-f74d-4f89-acd2-0a96c7f0478a@hust.edu.cn>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Sep 2024 20:01:42 +0200
Message-ID: <CANpmjNMHsbr=1+obzwGHcHT86fqpdPXOs-VayPmB8f2t=AmBbA@mail.gmail.com>
Subject: Re: [PATCH] docs: update dev-tools/kcsan.rst url about KTSAN
To: Haoyang Liu <tttturtleruss@hust.edu.cn>
Cc: Dongliang Mu <dzm91@hust.edu.cn>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, hust-os-kernel-patches@googlegroups.com, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=yLdsmjGt;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, 3 Sept 2024 at 19:58, Haoyang Liu <tttturtleruss@hust.edu.cn> wrote=
:
>
>
> =E5=9C=A8 2024/7/26 16:38, Marco Elver =E5=86=99=E9=81=93:
> > On Fri, 26 Jul 2024 at 03:36, Dongliang Mu <dzm91@hust.edu.cn> wrote:
> >>
> >> On 2024/7/26 01:46, Haoyang Liu wrote:
> >>> The KTSAN doc has moved to
> >>> https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md.
> >>> Update the url in kcsan.rst accordingly.
> >>>
> >>> Signed-off-by: Haoyang Liu <tttturtleruss@hust.edu.cn>
> >> Although the old link is still accessible, I agree to use the newer on=
e.
> >>
> >> If this patch is merged, you need to change your Chinese version to
> >> catch up.
> >>
> >> Reviewed-by: Dongliang Mu <dzm91@hust.edu.cn>
> >>
> >>> ---
> >>>    Documentation/dev-tools/kcsan.rst | 3 ++-
> >>>    1 file changed, 2 insertions(+), 1 deletion(-)
> >>>
> >>> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-to=
ols/kcsan.rst
> >>> index 02143f060b22..d81c42d1063e 100644
> >>> --- a/Documentation/dev-tools/kcsan.rst
> >>> +++ b/Documentation/dev-tools/kcsan.rst
> >>> @@ -361,7 +361,8 @@ Alternatives Considered
> >>>    -----------------------
> >>>
> >>>    An alternative data race detection approach for the kernel can be =
found in the
> >>> -`Kernel Thread Sanitizer (KTSAN) <https://github.com/google/ktsan/wi=
ki>`_.
> >>> +`Kernel Thread Sanitizer (KTSAN)
> >>> +<https://github.com/google/kernel-sanitizers/blob/master/KTSAN.md>`_=
.
> >>>    KTSAN is a happens-before data race detector, which explicitly est=
ablishes the
> >>>    happens-before order between memory operations, which can then be =
used to
> >>>    determine data races as defined in `Data Races`_.
> > Acked-by: Marco Elver <elver@google.com>
> >
> > Do you have a tree to take your other patch ("docs/zh_CN: Add
> > dev-tools/kcsan Chinese translation") through? If so, I would suggest
> > that you ask that maintainer to take both patches, this and the
> > Chinese translation patch. (Otherwise, I will queue this patch to be
> > remembered but it'll be a while until it reaches mainline.)
>
> Hi, Marco.
>
>
> The patch "docs/zh_CN: Add dev-tools/kcsan Chinese translation" has been
> applied, but they didn't take this one. How about you take it into your
> tree?

I don't have a tree.

Since this is purely documentation changes, could Jon take it into the
Documentation tree?
Otherwise we have to ask Paul to take it into -rcu.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMHsbr%3D1%2BobzwGHcHT86fqpdPXOs-VayPmB8f2t%3DAmBbA%40mail.=
gmail.com.
