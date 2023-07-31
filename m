Return-Path: <kasan-dev+bncBCCMH5WKTMGRBP6ST6TAMGQEWYI6MPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 14828769D8E
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Jul 2023 19:02:58 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-686c06b8011sf3335427b3a.2
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jul 2023 10:02:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690822976; cv=pass;
        d=google.com; s=arc-20160816;
        b=KdqkrbO8Uj3gepsH8aGhUkoPh0gngKLiOfxuwAdL0AxYdDHIZ6EISr/krGCp4gGviK
         xVBTTwQqzMsZHeV05MCVvIpmpfJcLqUAxI0804gj37wilSWZu3zxgskniX2OPrXIIzKg
         S+bKdG++TeGy7YmydUlqB3Ooweyp5HVxQzanrGt/bWj6S9zFc1GzQFxIcFSmBWqew5Vz
         drY5GFIDjha6bSiin+XwEuNp4MmUkJHGiu2vf8pYKe7zJVguOCCF1Bt0Q8vEMDgU7oK9
         5mtyi3K91RyAg2ZLHjTakE08ZtzHrK/oH7dCRWe72S2EjTKbsAc2kNVZv0+4I3ROkfYa
         hmBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YLmPhdtGOugrUE9ccVJuNAAQCAgBUPeBKmDbgDX/Uyg=;
        fh=FpmOSBwjI87+MAeyVxOnHPZs0VsW7pD6MuuYSDRIGhM=;
        b=GJ1NnT+VHIl48TbpdwbbsLOdaGd+CPgOmixuCMxAR8PIHEx4Y2AgXeoiHlEFS93v5f
         MgYnDzyK2xU/tE+A5A3ySBRaiOU8wU00MKnnaR5CIJ7mM5w/UE4swq4LpLGFPWAdJe9t
         lKLqqM0IAst2UBD0gLoqy1db0b1sS8H9KpMuokckdkt56V6Apt49WkRC6+3zX/p7DGYa
         dXeSqHP/I2OrPttep8ww95NPJv6nAthixrRTn4bkVNWc3vlhokhszVjcfw3OOGii2NNc
         +uKEeHpMDw1W7bwaTkUx95wpmveX7McZvDhlrOMm7jtbHWkFnRJV1tkP93vKadE3MT97
         pmrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=TO2rSHWI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690822976; x=1691427776;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YLmPhdtGOugrUE9ccVJuNAAQCAgBUPeBKmDbgDX/Uyg=;
        b=mttXGK2MWMk64SI7XgLCohWA8iLsSWidXQFkJcBpX3BeynwszZLsjF+fAZRIHiSwyk
         xIA+E6xBkZWrDekLhBLe6JYvKUBOi7v79tgdEjyU7PTwgkZX70HOoKYt3/52qogUV02V
         OWKfi4GquTdrgGrMFqskQcVHXD8Sg1vRW8z5I6Mmp46OdZgijQUWEuXIVVX6/aohAq5Y
         8St5OW63commHp1f16/IRhIbR8nSl5Z23dD57UIi5nsBtI4rkxjymuXaLwR24fgZvodB
         GnZqi72HKankB3LnSBa6FG2ZSkbUZy76pc1Vatm89hEoOl9DRMwjQBGqrOB7GaA6lU/h
         P8zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690822976; x=1691427776;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=YLmPhdtGOugrUE9ccVJuNAAQCAgBUPeBKmDbgDX/Uyg=;
        b=YfBycLjSr7cY/1cCEuJeOn/AYfn/Mq5Ei1lJ1cCJp2BmYw+5++0Z6+OE37jJawC6uz
         nRYOTaMVGprLTBwEYop9lD52yac2Pzt977xax9TTRsduNoA+MO4iPO1Lx/8zQc2CWL0b
         a/KcEsgdU3sQJmFHJcZC92M2VH/rvevSzKiPRd3rpI++GRApqm75ggjom7LwcuY08a3O
         ZmocYMZjX0HH0ktzgClpO+YCrSG25+iFqYRv1guVl73XdMhVya1mjZUpD8dqLDh6EW5G
         qDSXUdxbx05H9df7WMamatYhuPbLp6GRGaZFD7VMhXbJ/u4X2EgzRpPSqX3cZrYw5QxL
         1vAg==
X-Gm-Message-State: ABy/qLaDucePwtnzgXepSMfLCXEcCfo8G7e6XM2E+Xxg0qmoeYOuRGzn
	ZRs5vLZ36Ub9ed0W/r2VKAY=
X-Google-Smtp-Source: APBJJlGXoRJe0V5DE4ZynYs//N6WN5ve1RFTNN162Jtbcp1Cnzryzy3fcQSZvFoeEE1ojwhzUsGmHw==
X-Received: by 2002:a05:6a20:8f21:b0:13d:ac08:6b72 with SMTP id b33-20020a056a208f2100b0013dac086b72mr4286435pzk.18.1690822975837;
        Mon, 31 Jul 2023 10:02:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7b4b:0:b0:686:a110:9519 with SMTP id w72-20020a627b4b000000b00686a1109519ls2216456pfc.0.-pod-prod-09-us;
 Mon, 31 Jul 2023 10:02:55 -0700 (PDT)
X-Received: by 2002:a05:6a00:2e07:b0:682:4b93:a4d3 with SMTP id fc7-20020a056a002e0700b006824b93a4d3mr12335202pfb.1.1690822974961;
        Mon, 31 Jul 2023 10:02:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690822974; cv=none;
        d=google.com; s=arc-20160816;
        b=wJO7tTSEBFwR+BwPDCI+a/fqur40QU/PNcmKo6bXn1a5ZiK6UGhcTYN/gAqykKw49a
         fq78qqWK8thkqZ4gSnihZ1FG0Ik4Pv5x0v+wpS8kavgQHOduHWp0rSK8XcGe1FkC4AEv
         TbjJCC9EQIwHrM8SA99pn0bN98waZQkTZH8CZ+lzu+Q6k0ifMJJLQwxnfoqZV9ETFs11
         oBimtsfBJvz9YoaolFkxAeb2ftGjquLgkWknUEHHKpPZ20tbefph4Pyv5y8az1pndcTP
         Az3COA+WsVJSDzk8K8wUtdPaC/pWiNQsstomV4tXLwocuPl8yppuUC2NU9eV9mYf8bJS
         VaYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RayNNN4Qsk5njctZkhjYqrV8F8rSqnb41Z/GqHhScLY=;
        fh=/L/BfydENXJ5eWZhj6DuxRELOnbBRK5NL0Fx2I2Ns/k=;
        b=vY+A0pgLMK5PnIEzyV/qhHEI/WV6RDZ16pJk9eELS9hiMzEauMjVvalC/Ae0BtyfYb
         sNIMB5s8sQlROM0DZJ5ArDbRdk1VGmx20UTMtSgFeWRkJP6o9hviBEcDDapRYH64nTaA
         VRGnXosahbh1mRaPsLQZ4Vl5infkIGA+Tl6RFGbUKAChhIHQn9qlhfC3gi1WVjCzMzcM
         ZMcZEfGwnrvm/YqDJsRrmamVaCakQE40gucOqb6McHair0NGmFkarGNFzCs+xo5rAg8H
         v9f7AKVaXZfGlkRvPWtemXdyIgtvkkoJJ1FqzUJTz7PZeNv4VsgGNZin6k79yqO72PjX
         fqKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=TO2rSHWI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2c.google.com (mail-io1-xd2c.google.com. [2607:f8b0:4864:20::d2c])
        by gmr-mx.google.com with ESMTPS id p33-20020a056a000a2100b00681f56016b9si703063pfh.4.2023.07.31.10.02.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 Jul 2023 10:02:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) client-ip=2607:f8b0:4864:20::d2c;
Received: by mail-io1-xd2c.google.com with SMTP id ca18e2360f4ac-78bb3ff7cbcso181343839f.3
        for <kasan-dev@googlegroups.com>; Mon, 31 Jul 2023 10:02:54 -0700 (PDT)
X-Received: by 2002:a6b:dc09:0:b0:790:adce:d553 with SMTP id
 s9-20020a6bdc09000000b00790adced553mr2275104ioc.21.1690822974404; Mon, 31 Jul
 2023 10:02:54 -0700 (PDT)
MIME-Version: 1.0
References: <20230727011612.2721843-1-zhangpeng362@huawei.com> <20230727011612.2721843-4-zhangpeng362@huawei.com>
In-Reply-To: <20230727011612.2721843-4-zhangpeng362@huawei.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 31 Jul 2023 19:02:18 +0200
Message-ID: <CAG_fn=WK4Wyh-xeV_-71p3Yms6ZyXbSduAqMZknh1+3XHbgYfg@mail.gmail.com>
Subject: Re: [PATCH 3/3] mm: kmsan: use helper macros PAGE_ALIGN and PAGE_ALIGN_DOWN
To: Peng Zhang <zhangpeng362@huawei.com>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org, elver@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, akpm@linux-foundation.org, 
	wangkefeng.wang@huawei.com, sunnanyong@huawei.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=TO2rSHWI;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as
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

On Thu, Jul 27, 2023 at 3:16=E2=80=AFAM 'Peng Zhang' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> From: ZhangPeng <zhangpeng362@huawei.com>
>
> Use helper macros PAGE_ALIGN and PAGE_ALIGN_DOWN to improve code
> readability. No functional modification involved.
>
> Signed-off-by: ZhangPeng <zhangpeng362@huawei.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWK4Wyh-xeV_-71p3Yms6ZyXbSduAqMZknh1%2B3XHbgYfg%40mail.gm=
ail.com.
