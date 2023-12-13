Return-Path: <kasan-dev+bncBDW2JDUY5AORBZE446VQMGQENJNYGPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id F2C0E8116E7
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 16:31:49 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-dbcda1ff95bsf347669276.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 07:31:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702481509; cv=pass;
        d=google.com; s=arc-20160816;
        b=UxL4/yJcLXb8jjHP+btkp9oqAw1R3eUfE9GfLzr86ks4O3QkdBbLQ935PSkvTZD7QN
         Y6l9zGVk5RnWs8GxnhoW/kXRc+WcABZl2vY58P/iOMXOg1iav+LbZN73EZRZo41vhlKs
         IkymKcsQkb9CUTLU3ZdBRwmyvH09kvDkuUspF3IKBZxuWei0QjK/1bidQApIr/L8OSyG
         tus6/RZOVZpV9dnbrLQkpOmkh5gy284/7OWHdXLHmCotGgfJ2XwU8tmyiHqnIPb1hoB4
         xesucGHzPf8abI69Cwvq2+pApLGKAmCrGMAtZFE3/NrcBPHihsntwPmA/AHMWtn2KJaR
         Go3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=IJ7yHCQzkaYeRMDaHZByz65hqrgmaUzFWwzTkmP9Z7A=;
        fh=XU11cspKtg5ebvhPqSK1SiwBAh+gVB9lWPcjRO9BNAk=;
        b=PS3YGEG9cUKaS1CpkdeJ2kRRxwMw7rYZq2JEdu+BE/We7mMkaQID3Wan9jtzHlqfaW
         DWzQ6xkTqmp/RXD5j2snXbAHNFTPFmimLTPA4h9kdccwoK75eIFFSdhsp7XzpIag6MI7
         XqNTDBd7bx95g09vWXLcZ4vE1d4/9LB5QW+Adwx2snmiGb8KJAWIZaw9JC4zmcMp63tH
         k6R1+/HRNgIEnr8UpfrOr9eEOWEvehYC95OMrxq5pCyBv2XQ1pAbN4fSSkEtAuDUKO4j
         Jk2oeaEpBjsss9H0YOEtNOMFLHpXZThtacOkgR44LpqLpS7eJ+yqjqJmwBanbLT8YYwP
         h12g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AMVFN4Rd;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702481508; x=1703086308; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IJ7yHCQzkaYeRMDaHZByz65hqrgmaUzFWwzTkmP9Z7A=;
        b=KdFn7mW54vqGJ1/0Ug1CalaVxMXEv02SahtBJWAmqGIGcSQ05YaiuuRHLVS6dV46MC
         JALMs0T4FJ5eU3Q4tE1dHyRGb+g4jmcRACvjU0E0pVJzauIaIIw3315lmOaVm7/rCpOo
         sTQwvBkVYtVFMm0nRGypkVJiXtMEUu60xnzsuN0zOmNd8rJ9gJHhhR/GgEsn7KLwHg/w
         5HlmmUjzoj22GkHdfvjC98pjHF10Ox0ZSlSxdEPtBkoBohk8pRpQ3WSM6J3/Gtz7DuDv
         HHSb15+LZnzEv/hOt1y/qavjsBoi3mPsime8NcPTbHtaKFjCHp0DtM6O63WLMCserx+x
         gyyQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1702481508; x=1703086308; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IJ7yHCQzkaYeRMDaHZByz65hqrgmaUzFWwzTkmP9Z7A=;
        b=JNf4K8meWJ1IZGo3E3RzOzMjmykr1Q1IJ0EC7HmWu68liwrAjX6VCfh6ugg+vVKjfX
         L+fFqiPRYayWDs/eGAfTyecxx0XX4wKXQjjIBF4RzrOAhLG6ozSLJOGl/wcprfc2m6vB
         UyQQz/YD/N7M5eSTyZkFgFRCuyO5DNYIq3WkqxklPEK0Uzc0m4qwB+OzfVEjeJuM8yCM
         DYjqnF9ZAoqRwRQ6uwjMdaDBA+UN0N3LjjTI0UyioOCV3wJJslnE9ZOWgEep3KSM5NPJ
         vTZEaZkJYkIYdAm+LDIE3Z5Jh0wZiDdFPS1eGJq5dxIjlTJciMA7OaivtpQ46EacTM2m
         k+ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702481509; x=1703086309;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IJ7yHCQzkaYeRMDaHZByz65hqrgmaUzFWwzTkmP9Z7A=;
        b=RsJDWkL+vwdFdcYMLaSGYsfRnPTjVqEswjTmx9IzYvdWtGA4iLZtEL3TBaz9aKJyPM
         96HYsBPRA2uUNliTYlhptZgdbNZxrmWVmaIHmn0chr2KbZHhB2pd7Ds1brEGd+ZYfJ2G
         Rq3XLqgOlPRbVjM7geJOS8fWCRcQN4W55fs2z6GjKxpFDfqUysYa7QPamseaHWJTLUwm
         CssaB9n+GjdNirpQQuzpv+7+fJljvYiJLMd8A55wMpDT9dWoZYsoxu8mG7DisXBr5mLQ
         2olF5KpE7j79YM2qGZZ1ckmdPqSsUKJc1a8FOaX86LkBr+2cF6E1nIaVq+E1A9X4EY4+
         IfBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzwrehkt7l6e7TyHr8KR+8ti3c1GvvHm+q1yPRFKZRxS0V3h17J
	GrowoJQIpVVrLWWc2dDxghM=
X-Google-Smtp-Source: AGHT+IHXCwVDf+2bN4Nx6XBC3fQQlvb0VnzCzcnhslMc6FYfn+r4434M7IpAzNImDJIW9CeblfoNhg==
X-Received: by 2002:a05:6902:e0d:b0:d9a:ce53:4942 with SMTP id df13-20020a0569020e0d00b00d9ace534942mr6202200ybb.0.1702481508754;
        Wed, 13 Dec 2023 07:31:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:50c3:0:b0:dbc:d36b:922c with SMTP id e186-20020a2550c3000000b00dbcd36b922cls721541ybb.2.-pod-prod-09-us;
 Wed, 13 Dec 2023 07:31:48 -0800 (PST)
X-Received: by 2002:a25:ef49:0:b0:dbc:b93d:5497 with SMTP id w9-20020a25ef49000000b00dbcb93d5497mr2104041ybm.108.1702481507888;
        Wed, 13 Dec 2023 07:31:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702481507; cv=none;
        d=google.com; s=arc-20160816;
        b=roZL9fcs2TxzNnnqud1+yULlLjd7E/kmvw1SUMBJPrS2u1whVyPaxrkxOj5FQNeifV
         hmIa2guQYMZeMridz0IZiY7FOdGfB8QsrNx1c0i+/2josMqiCKnKfUc5TWsSMNYzqhCO
         EroczGExDWbuooqJ+o4AN4kwsJ/qJlDOltrZM+qLBfI/tdxF/nx6irpxMFI2duVZWGSn
         7uGCyAJ4qFwk4hhy+z1p0YqulEorBv2I9aHi9RpKFeSXtAzoEsgBTg/5kg2d+Ax1ictg
         qU3qiv5t8Lfy/yHzTTkEzSzu6Lm4Cf3nHKEU+hoASqdoywLEXc40Wfx2SZmaZ3FhBBRP
         yT1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oZzlMKqeaQDgaUycRwSe7fFFE/6tq3edh0ES7fNxHN8=;
        fh=XU11cspKtg5ebvhPqSK1SiwBAh+gVB9lWPcjRO9BNAk=;
        b=wTNDZQv3iwYAP0DYKJ5t0UGDzVweqqmZtlt96KkuNtoC1MsFEe6V9Dl/IJRP5IHnM5
         FWHV1ooO5jGQVYFdX1Yy3hYdBtZ+/kgu89ns6fgKrImOug51guxBk2CfFwFeEXlwB2JL
         ZMYiR0/XP+o7/vfLkdXpLKp5bhtqaGBycznZLh3tTlB4xBgTuAuQzuUn6g1xV4ceYaMG
         G/EepOCAwwfIFOms/KyAFs5y5QxPIgsg8mF1po41jZMDq5tcTpJujUKR+XgXpQNavtus
         UWbSH+FGFBKDQSfBQ1PJIsl2MkAKxO08iHMsAobO8hsZXTInW7OvMs7dpo4FpwYYEgtf
         UyYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AMVFN4Rd;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102b.google.com (mail-pj1-x102b.google.com. [2607:f8b0:4864:20::102b])
        by gmr-mx.google.com with ESMTPS id p136-20020a25428e000000b00da06a7c4983si1370794yba.2.2023.12.13.07.31.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Dec 2023 07:31:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102b as permitted sender) client-ip=2607:f8b0:4864:20::102b;
Received: by mail-pj1-x102b.google.com with SMTP id 98e67ed59e1d1-28ae571b2edso326127a91.3
        for <kasan-dev@googlegroups.com>; Wed, 13 Dec 2023 07:31:47 -0800 (PST)
X-Received: by 2002:a17:90a:cf85:b0:28a:b3bf:3c56 with SMTP id
 i5-20020a17090acf8500b0028ab3bf3c56mr1926683pju.20.1702481506962; Wed, 13 Dec
 2023 07:31:46 -0800 (PST)
MIME-Version: 1.0
References: <20231128075532.110251-1-haibo.li@mediatek.com>
 <20231128172238.f80ed8dd74ab2a13eba33091@linux-foundation.org>
 <CA+fCnZcLwXn6crGF1E1cY3TknMaUN=H8-_hp0-cC+s8-wj95PQ@mail.gmail.com> <ecf38b22-ee64-41e5-b9b5-c32fc1cb57bc@moroto.mountain>
In-Reply-To: <ecf38b22-ee64-41e5-b9b5-c32fc1cb57bc@moroto.mountain>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 13 Dec 2023 16:31:35 +0100
Message-ID: <CA+fCnZc73qNqNiCMcKFKRuoBki=Bmhdw-mOY9chV=CjAtm0R+g@mail.gmail.com>
Subject: Re: [PATCH] fix comparison of unsigned expression < 0
To: Dan Carpenter <dan.carpenter@linaro.org>
Cc: "Liu, Yujie" <yujie.liu@intel.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kernel test robot <lkp@intel.com>, Haibo Li <haibo.li@mediatek.com>, linux-kernel@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, 
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org, 
	linux-mediatek@lists.infradead.org, xiaoming.yu@mediatek.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AMVFN4Rd;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102b
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

On Mon, Dec 4, 2023 at 5:12=E2=80=AFAM Dan Carpenter <dan.carpenter@linaro.=
org> wrote:
>
> > But I actually don't think we need to fix anything here.
> >
> > This issue looks quite close to a similar comparison with 0 issue
> > Linus shared his opinion on here:
> >
> > https://lore.kernel.org/all/Pine.LNX.4.58.0411230958260.20993@ppc970.os=
dl.org/
> >
> > I don't know if the common consensus with the regard to issues like
> > that changed since then. But if not, perhaps we can treat this kernel
> > test robot report as a false positive.
>
> I would say that the consensus has changed somewhere around 2015 or
> so.  Unsigned comparisons to zero used to be one of the most common
> types of bugs in new code but now almost all subsystems have turned on
> the GCC warning for this.
>
> However, this is a Smatch warning and I agree with Linus on this.  For
> example, Smatch doesn't complain about the example code the Linus
> mentioned.
>
>         if (a < 0 || a > X)
>
> And in this case, it's a one liner fix for me to add KASAN_SHADOW_OFFSET
> as an allowed macro and silence the warning.

Hi Dan,

If this sounds like a good idea to you, please add an exception.

From the KASAN side, I think adding an exception for this case makes sense.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZc73qNqNiCMcKFKRuoBki%3DBmhdw-mOY9chV%3DCjAtm0R%2Bg%40mai=
l.gmail.com.
