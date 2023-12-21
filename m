Return-Path: <kasan-dev+bncBDW2JDUY5AORBUV4SKWAMGQELCYUTRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B4DC581BF84
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:21:39 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-59127c4e538sf1156364eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:21:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703190098; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qme3QcI13RreZmlSAlECplFdggSRHlVLPGvoJEhX0nSEcSHQELcM8qEokqxAHnexvD
         i7XbUCEfRbDzgiRxDu/LQdVilDCSjgyL6XXZcRUiAcXJqcqhE7nfl6kj5Bt980CqNV33
         aTA9z4CB/Td0SHxE5gOMScDWcAQ9Nf9lChiGk8MdaPwx7fH8mgpizuzpusDpfkJ8mX0a
         L44gm4F0qAUkEMgEteynv9n7tIgl/FDPk2est7ArVy8LfRqCsFCSu86r3KbiDAeu8U2o
         PO2fZgYRmV9S+vN6XWPbfznXfyFBDGt8GPK5l2p102dEn+YlWawPRMdwl6+P5JiSPGuP
         8OnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=OwRr4QbGY7cwnZkkP1i6nwPYuDqxlPMubBWQRCXerYs=;
        fh=qObQPquzet5p+fCG/gXi9YGx8Kjp+xLTApIfLaO5n2U=;
        b=kzWXS/lU+lUV2ObPTTYAeKGrTR3N8OybMFT0A6KPUN8TtnV15WUSrhHb29T8gv/Dy8
         KSxj4yvpChf/RTc1dWwVz6HvRlaujdV2Z/ifcTDlKsGXF6EeSMl9dIG0L2ggAJ6ygXY2
         cWDEO9DAFFiAHEA1+r2srS7hGFgh42lu0dwWYz6MMidDrX1IJn3G4H2FxNSXrTAg+whg
         PfKYWkfKL5aj2X9bmhOu4eyg5z/ythFSncOP4/935HPZzTSrHlpXFbyOSOlyZg23q9Vm
         8PHB2aDV+2kEydkCYejGIBoCaoBNwLq9nhyoNO2AxoIxHjnDzREyHwfPP2AVl1dfgIBH
         xOQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m4+Ahsqu;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703190098; x=1703794898; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OwRr4QbGY7cwnZkkP1i6nwPYuDqxlPMubBWQRCXerYs=;
        b=GB+nCwgxO8jGRUbYvJrS8zUtw8eapSKG6+KquYgeMpBFi5O87oMR52hWR4X7xiqWvv
         2Z8a5dDoAV3Jwcb0v1uQdRFd2Qu8K7BKxAsPWouQGzrzg6MqOM8dwvSE7NqJ7WLLDhXW
         hFEaCQpfAue26/Gj0Kc4JBc4DPNZn7dAW1axRYq9d0yfSDZLD3LjGsuVYEABYIbpCirI
         6G+Pov/ay1tD9kNsWxT52QfGsT8xgxFzFDrSOh+QyZSSmrAMkZkZinq/4JsfBr0SKvBV
         qotKBrDYvoiQpMTmLxl7+g5tgrOMd6snxuOS6GRgXQ/QzXT80DyFV4Iyd2KMKwv2u/32
         XKZA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1703190098; x=1703794898; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OwRr4QbGY7cwnZkkP1i6nwPYuDqxlPMubBWQRCXerYs=;
        b=YWTiSFNzhWFnHXRprAvnMirvXFdiwraDE9oaUGKRzbLLbh/OI4idLvT+ETF0WnMadE
         bh62WKN9M4Cy9SGFP81dHJ+ThMKfJ0kkNIxbRJVDdiT8lUXxQLVECFnwSJll0RtZxXg9
         At8xTgejZR2iKyvqW2UimQiazWDeGnIrItPx4+lPjtIFShdqD76JllTASoXQZz8rsvaO
         nF2Qlu8B/eBXgNVvl9ch6aIEvbu6DejOriBy44258fLrN7Y7M2fe/MnGOdyOirIPq1wO
         F1ovSUENp7svcepbnWimub4/qa0kIxGiVS8VufM7xo+jZZL6yjnPF25aHRPxMMbL8DqW
         fKhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703190098; x=1703794898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OwRr4QbGY7cwnZkkP1i6nwPYuDqxlPMubBWQRCXerYs=;
        b=l4zGas/ZqQPLi6O3B/41Qi4LuxDx/moczophKKdG4tmxvBBFBVIVRemaLFOJYpXn6x
         uW9f66IkdQP5Ep+mm/+/yA+dNV8lYUzZWZGlR5LaWbHrvDOL4ve+1H1LJQnX9vWxP2H0
         jRYxK+p6e0JjG6QubvFwX12IK1JGlodN6Nw6J+V91kmNvTsI4PFhP7ww/Go5zm45/DmW
         kwGB1RXuIj/W6BLz1wODauzGyD8+aeNuG5wzoE2foSnRRlkTWgj20On/TiqQJLATzOS9
         FCx1E4qF6fYFbPiC2qeXAOY4ap2166agZupwIhm956MNkkR/3ItHz1gNfhPkEnIcDxNR
         jgMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxlCz/AzRpf8NAVxa1W6U1UrQtjrs7SqGjWVKxWySARQGJjatE1
	ocx3pzdIoJUNpXsBCqjoBkc=
X-Google-Smtp-Source: AGHT+IG7707T5GTsC3Ijw0jmyP7DkcvnK7RTL0spZjTqScgbd4z8gZ+7k2b9nzyAVKUY11b74e6jdQ==
X-Received: by 2002:a05:6820:1691:b0:591:972f:362 with SMTP id bc17-20020a056820169100b00591972f0362mr215802oob.10.1703190098172;
        Thu, 21 Dec 2023 12:21:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e8ce:0:b0:589:f90a:968d with SMTP id h14-20020a4ae8ce000000b00589f90a968dls1260690ooe.2.-pod-prod-04-us;
 Thu, 21 Dec 2023 12:21:37 -0800 (PST)
X-Received: by 2002:a05:6830:1d9a:b0:6da:aa8:5c0e with SMTP id y26-20020a0568301d9a00b006da0aa85c0emr311320oti.34.1703190097540;
        Thu, 21 Dec 2023 12:21:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703190097; cv=none;
        d=google.com; s=arc-20160816;
        b=GkJORkXc+GlfbQq38sOpFxMAsOA2btWSAZkqShSj40UVpzwpeY/WKe1a4aU89rEAnq
         jBevyEIbbi6RMhZHearXIsML/4I3sulaW6nPp01iaepbc/t0MGi3qqAFpeo4FYEW/ZAY
         8RwpUQMunj5rmeNJcd1hQY7SOYWPPWjfUed7mPxy7FRU3KFI77l2eJwZS0CD7sg89I9Z
         nnsOUHEvWrEDfOaFhvgRTYITh0iAwBboNLhO2H26rK7k1jG50j4wBCow5f/embOe2kGS
         U6rXGG6Y6sqeHneXwi4bQGuR4rZJWnPoqh3r/ZazN1I4mEv4+Z7gKWmVtpIN7Scb0y9S
         iY1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8YbFjGH80BA4VduiXuChGc2yL1fnFJ1q2+v81EA2deQ=;
        fh=qObQPquzet5p+fCG/gXi9YGx8Kjp+xLTApIfLaO5n2U=;
        b=MkjyppSirOeQLQkD4S4KwWhEDIwIFt3Tt65ldLKOrcx5SP8g5pSIdj7Oa13pmZoamL
         o39uGRgJYfFhsEjLXRcuMLB/WG5JmcDzBo8IVJ57iKLVE/um8/E4+/GYPPOwaO3e/9sF
         t6CBv/ahYy1YEDHOBfw4G4EbiuBLKvomRYHuPFhcm3smxWx+Xt+y0RqrIJm74kr7L5jN
         4UQMRLiXBi6xaQ7GllzxgpHI4ILwDpcqNCwfjxFzIXDS3owo1/MezLS2UnzAT/toQgHQ
         y66JFNF3AOD/C0vsV6O/+PSX41m1e2hDg8eU7IXRAE+PG+uGbEh9V5G0F0dXBt3R6Fee
         i9nA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m4+Ahsqu;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id ay40-20020a056130032800b007cb8c7adf99si300968uab.0.2023.12.21.12.21.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Dec 2023 12:21:37 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id 41be03b00d2f7-5c6bd3100fcso616691a12.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Dec 2023 12:21:37 -0800 (PST)
X-Received: by 2002:a05:6a20:2926:b0:195:687:7921 with SMTP id
 t38-20020a056a20292600b0019506877921mr218388pzf.58.1703190096948; Thu, 21 Dec
 2023 12:21:36 -0800 (PST)
MIME-Version: 1.0
References: <20231221183540.168428-1-andrey.konovalov@linux.dev>
 <20231221183540.168428-3-andrey.konovalov@linux.dev> <CANpmjNNkgRbj4jgAGHtKTBB0Qj_u+KmFnBS5699zjL7-p1eV+Q@mail.gmail.com>
In-Reply-To: <CANpmjNNkgRbj4jgAGHtKTBB0Qj_u+KmFnBS5699zjL7-p1eV+Q@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 21 Dec 2023 21:21:25 +0100
Message-ID: <CA+fCnZf1TDEu9JwT2my7-p9XKrHjyWyjpXiGJ2y6SV9mxcCZvA@mail.gmail.com>
Subject: Re: [PATCH mm 3/4] kasan: simplify saving extra info into tracks
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Juntong Deng <juntong.deng@outlook.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=m4+Ahsqu;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52f
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

On Thu, Dec 21, 2023 at 9:12=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Thu, 21 Dec 2023 at 19:35, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Avoid duplicating code for saving extra info into tracks: reuse the
> > common function for this.
> >
> > Fixes: 5d4c6ac94694 ("kasan: record and report more information")
>
> Looking at this patch and the previous ones, is this Fixes really
> needed? I.e. was the previous patch broken?

Yeah, maybe it's not needed in these 3 patches. The original patch
works, these are just clean-ups.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZf1TDEu9JwT2my7-p9XKrHjyWyjpXiGJ2y6SV9mxcCZvA%40mail.gmai=
l.com.
