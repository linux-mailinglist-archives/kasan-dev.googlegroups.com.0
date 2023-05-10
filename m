Return-Path: <kasan-dev+bncBCF5XGNWYQBRBWEC56RAMGQER7MOKOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 917546FE221
	for <lists+kasan-dev@lfdr.de>; Wed, 10 May 2023 18:07:53 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id af79cd13be357-757890c1de9sf424159285a.2
        for <lists+kasan-dev@lfdr.de>; Wed, 10 May 2023 09:07:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683734872; cv=pass;
        d=google.com; s=arc-20160816;
        b=ujb64DaOoJ0YHK/XePJGUZQX5BR6SJnZ7JBSpKpbUwwJ3i4S3UVsm4L5bgokoX3mDP
         0SJDpwXz0Vut9qsHEkB/iYNjkdpE6LbwobrykhgFA7gJ4qLv9aLuOVUgSsAP2bSuo1MM
         FjYIaKg7ghHm9Iv+rYudi0FGD0m6cQ/DJXhvgrmiD62EKAG54xYay+K16rZsQUHd5P/x
         z6Dru2SiBa36zUosJ6JdYePLsnLZuY61Bea66u6f5tK0A9HJ92t78wUCIYIu5nR0iw0q
         xnHtIF90Fvf/XvhWHPJKFKEDzhb/01cRV34Lky0/8WTxg80wN+q/moSXIipqC+hPVVSn
         VMCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:subject:cc:to:from:date:message-id:sender
         :dkim-signature;
        bh=7k6sNm3AVong0xKUdFJfSw4EI1pk6/+rE64Aoz3X2XU=;
        b=mZh1d0lQPUbLsnuxLw+lIxvHS+TA0gzpixjTGfjEY07Rn/nV+jfDV1Fte2/Ys5esOm
         muCkjdfuone4QRSe6Y0BrmXHYv2CwH1D64FM32L6uoUgInRebf05X0YyQ4aDLARE6CMy
         EqiQfK8Xu/7vSS4s23Kxm2SFeTgfnMPd4fOV4f9C4Tu3SnPvmxl5JZqH5H3CDKPsiGfm
         L6GlO9VUlulx3uKcI105+957IAknk4QTibScZIQgOrxEhLs9VJoBNLbxeXmK74tV0QF5
         UujwgbKfLFwnPLDIBo2rdDcZaTYWybfU/0PfuGo6MnnzeMLEp8OnieCt0YuYjEm3wuD5
         FpuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=V4AA29NR;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683734872; x=1686326872;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:subject:cc:to:from:date:message-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7k6sNm3AVong0xKUdFJfSw4EI1pk6/+rE64Aoz3X2XU=;
        b=ndZEFFVs57An6ntD6EGx/E+DpiieiComCylfGXttuItNzZjUXzufcplq1VMEJxMPJN
         Xx5KYboi/rbRx/xwNpfB9fdC4+B1TUBGmgMb1OcB41Hq5rcDjkAGxrwi3K5FCWT7RURm
         jYizr5/hyjfQKPu73Q1eZjPC8NcvxLLbIA3pIO1jdDcCVII93nLc/YyyrSJOOrj8vjW6
         +SC3ju/ugJH8+Pj2jg1hvhBIIZkxIm0khc704o4Rtv2RwOjErJXZaftZVUSEW8h/28RF
         0g/67mGYoBGPiPUMJDnWNAaEMvzG5YVUvc1Ug7F0dck6d/Ck8bKqT0aJ08Juuq1ljwL3
         yU5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683734872; x=1686326872;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:subject:cc:to:from:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=7k6sNm3AVong0xKUdFJfSw4EI1pk6/+rE64Aoz3X2XU=;
        b=RkSryFl9fA0hDeHOyPdYXNzTEod3sVv0P++rEudbB5AtB9R47/jevF9ymqgWTtBIgu
         B0yPLamJ5cVuikgYCLcXlROYzkkcv0tXMV6l7fBYcH4uznJrlRXdPiLtHPCYzajiRo6q
         r/NLDAc/kSJ5+qsI+O00x0cg76iO7X+YMto09zx/ZCNMZgfxueqY1GIqoU2ehUbOU2HU
         KEEz62ZA0a8zJ6Zueokh6DF+yuwO9AYZu3LmxbE44b7x+5vkBF3KiDvnVM1apxkh3X9v
         KqN6uv4a0dMvWQIEhWeXwwDAyyN8VqhPzw783EnXLWiuM3neR+sYE719EuhEjJiRvQ3+
         Trww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyG8lgBuQL/LmXOT2nqzkgwYeSALWis7BZybts8jZxVFPGuxTQF
	Ofewhm7ADQ4JujAj2P9GH18=
X-Google-Smtp-Source: ACHHUZ7fZKmj/9c2quzh03mhm0F0zLFa7SGTup/Y3uey/VHzQWY4JkmWsIX94vhRlFKudsmz9IbNIA==
X-Received: by 2002:a05:620a:4688:b0:74e:36a5:e564 with SMTP id bq8-20020a05620a468800b0074e36a5e564mr5381201qkb.9.1683734872481;
        Wed, 10 May 2023 09:07:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1e87:b0:3f3:93c3:7e8d with SMTP id
 bz7-20020a05622a1e8700b003f393c37e8dls6098989qtb.1.-pod-prod-gmail; Wed, 10
 May 2023 09:07:51 -0700 (PDT)
X-Received: by 2002:a05:622a:1a21:b0:3ed:164c:6834 with SMTP id f33-20020a05622a1a2100b003ed164c6834mr38808378qtb.27.1683734871794;
        Wed, 10 May 2023 09:07:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683734871; cv=none;
        d=google.com; s=arc-20160816;
        b=p0izoTafJtdUMuXE3zxHygPynd375YWZdPXZP7Spha/LheuKFkE2KZ5H3aZI//57UK
         nLgVioB6fnekcYB2mvktnRgflX7H+LrKKxfIZ02hvQPjrX6xnolWo2Sa4KZg7BkQCtqt
         djUqwmNlIzdQFKwXT28XDYq6l2HZR3pHQpPfjb8PQMSFsbULksgDrc/aEo7LU3vxKRRV
         OZiOJRgumw3A2H3BeRP47t2vKhvOEbuJoWvCZDqi22R+enZo2MENVyZvZZfDJ66nkhbe
         iO51HlS5Nj6Nfm9CO5gylmpkxzslKoVmy4vdjGVtzIDQAccwW0XaM3TqDZO+D4Pzo3PM
         ft0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:subject:cc
         :to:from:date:message-id:dkim-signature;
        bh=b4Rid9FL2qAsOfwFHnvreGzE7hpGc3/BOKYFO/I4yNo=;
        b=AvwtQeZ1F2nLeSOeFhaDz7GoIN3+uAvXF13sg0gv36sOgGgDhyjwNU3qMy6SmujVKn
         3fOiZLqkI5/pyNFbFEjnRv3aykTOCgQKOBQlufB1ebg2Qkw773hoxilbyWjg1GQGlgTE
         L2cv3DpyJERwVaQf9kYIwBAyTlD0rTiKl8UG/Fbgsg/MxZkHVIy40F2Bv49FzaUiR0yr
         VeWKBwnEVrdmfkGS/2c9T2HvrlH/09qXpPdZpTIivIzYbbyrEoS8YmkKK7XTUzXUIq7j
         31xaSC3y5shABSyhoRVzr/YPJ2DXopuE8ncUckxss8fVbXcL+CJy0N8TLACxyZoOSZqq
         1TWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=V4AA29NR;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id bz10-20020a05622a1e8a00b003ea887d6fb8si408597qtb.4.2023.05.10.09.07.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 May 2023 09:07:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id d2e1a72fcca58-64115eef620so51242947b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 10 May 2023 09:07:51 -0700 (PDT)
X-Received: by 2002:a17:903:1ca:b0:1ad:bccc:af77 with SMTP id e10-20020a17090301ca00b001adbcccaf77mr295388plh.18.1683734871402;
        Wed, 10 May 2023 09:07:51 -0700 (PDT)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id l9-20020a170903244900b001ac94b33ab1sm3975861pls.304.2023.05.10.09.07.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 May 2023 09:07:50 -0700 (PDT)
Message-ID: <645bc156.170a0220.62d12.7fb3@mx.google.com>
Date: Wed, 10 May 2023 09:07:50 -0700
From: Kees Cook <keescook@chromium.org>
To: Alexander Potapenko <glider@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	akpm@linux-foundation.org, elver@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, andy@kernel.org,
	ndesaulniers@google.com, nathan@kernel.org
Subject: Re: [PATCH] string: use __builtin_memcpy() in strlcpy/strlcat
References: <20230424112313.3408363-1-glider@google.com>
 <6446ad55.170a0220.c82cd.cedc@mx.google.com>
 <CAG_fn=UzQ-jnQrxzvLE6EV37zSVCOGPmsVTxyfp1wXzBir4vAg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=UzQ-jnQrxzvLE6EV37zSVCOGPmsVTxyfp1wXzBir4vAg@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=V4AA29NR;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::434
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Fri, Apr 28, 2023 at 03:48:28PM +0200, Alexander Potapenko wrote:
> >
> > I *think* this isn't a problem for CONFIG_FORTIFY, since these will be
> > replaced and checked separately -- but it still seems strange that you
> > need to explicitly use __builtin_memcpy.
> >
> > Does this end up changing fortify coverage?
> 
> Is fortify relevant here? Note that the whole file is compiled with
> __NO_FORTIFY.

Yeah, agreed. I think I was just curious if that got verified. I'm good
with this.

Acked-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/645bc156.170a0220.62d12.7fb3%40mx.google.com.
