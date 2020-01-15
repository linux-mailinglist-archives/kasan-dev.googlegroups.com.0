Return-Path: <kasan-dev+bncBAABBDH57TYAKGQE7VAOQQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id E8C9E13C95F
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 17:32:13 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id m8sf11575569qta.20
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 08:32:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579105933; cv=pass;
        d=google.com; s=arc-20160816;
        b=F+BpqICYewNpH0xxkOegVFqLARj190BrHRFa98xQ7Q8Vbw+acEDVgVAI9NrL0y4ikR
         9HtbIIbYw8bL5oVam0h7O0dNVaEs4Oy7IUJhyBoltCwyIQml8MX/TRJDKhVKtpadPh8C
         Y0DXfzgscTO2vgtcYaEfQaQUhqvF/bCIe53asRkRVoGN7GD+RRU7exXLxAh+Fo1DbszK
         8NpjX3PwefX3AwWok7swadDysE4ToA+9puPD2o1s7rsn2+2jDhM8X60r66rT0oaavxMj
         XWJcEUZ99U/Fn36QlSUPrXQmnynBLUxVAcUrduWm8nImyr0ZwLpELewkf8n8rieCvrmq
         ADuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:autocrypt:from:references:cc:to:subject:ironport-sdr
         :sender:dkim-signature;
        bh=ajifYsA13dR3ANn4EUDTFPz2+qS1dxfJtXZhxiCbMyo=;
        b=UuEKZNEMi/qqzJSHqzBNMhW8B0OoGo7OgyH/S+R3Vl9ytWQFckTFAluTomF7eQJElV
         S+7FlP/qU3kl3QZm2UwHPIr07fQ9CE9wzcKPqByaPW+4iomWa+7Ev40rP/y5Dgq0SVmo
         Nrkmqwk8OAXm32y5ZHy5zzW5hR18+gPZchWk/uXFwKSQCA3oIFzhPZz63w3jxQc+RYr+
         R0crnem8HxrpGRrmz3+RlOVMOxV2loGz9Smxxzlbbq8oNdCZBMHZReJ/PO0PmRHgOZiW
         cVndpBoT/iucqrO1f2bxW/GEbZI8JbCZA+ngBkC3Ov8j8l0vw9AVz/BdPQfwp6D0+sVd
         3BOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=Icoc4VTJ;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.155 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ajifYsA13dR3ANn4EUDTFPz2+qS1dxfJtXZhxiCbMyo=;
        b=bsO/s02nlDtMHB7gudVAgItUND7dLCEd0V2aBhGMgtuAm1KX1Q9IYraDRvK4pMxaZd
         4yO9F1+48CxZex30bvs53vOMv5Hsa93A1KjSYs96PvVv3jExtoBfdfHWcZIh+4iRjX9T
         ye+/+lqN/P+W29t/T/843X8cJqvgahlQTD5ufL9wSS320ymKz85Ic5TRHrS+fYDBMwK+
         FVmA87wjv9vygpyku2oPoNoWsTP9thkdl6qsuI/BUOw87BLyW9YMKRczQ7oLtSv1SK2i
         Y9nu/BjINGMqvGK/XPpL1B+ToWAEnFgKUDwQ3tNtPkrZly5DcL7BdZl1nmSdtMN+aGF5
         244A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:subject:to:cc:references
         :from:autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ajifYsA13dR3ANn4EUDTFPz2+qS1dxfJtXZhxiCbMyo=;
        b=B5+kSsqNBMbnyiW7go0b7nnN61QgQ+FKqP0ki2ZOK5I9evRNjhezaQ3C/nhjYzCzkC
         RPX8KhBARhJss/OJWXgK3X9J/u11hYPDbJ31DQxSGZ6WZ3OBXkKtGfKYkhH2dmAzYrUd
         lz9pb6/qt27trFGxufI15iNIDQ2eQ9uceMrsEbgHrKuIoBdFP3FPeGXWcIK7AwJ8KeKZ
         /ari4F9BIwVFGl/EKTXSG0eawgvKbbBQ/oOLQTFqTk9cnhZCeWYWeXjMiBUmEMU4QXin
         81quAQUp5Zi28XetR13O2FXu/eXACUhRrPr5/3gtsQt7/tmxkJdUKxJSYFHpFRDoDJxy
         I6Gw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUMXz3+UwvZuAV3dOTd8aNgjjaAdrRh4waItCT7NGsm+B8JOyQV
	KLFQ14SKAb4K4wCVbgSkPaI=
X-Google-Smtp-Source: APXvYqxxNNZ4G16tAREB4PV8Un4gbR9mU0MQOUwWa2+jIutb8NHg0cLTv17xm/K3BYrkfHVFsGMTXg==
X-Received: by 2002:ac8:7088:: with SMTP id y8mr4194808qto.325.1579105932958;
        Wed, 15 Jan 2020 08:32:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:c17:: with SMTP id 23ls4350547qkm.14.gmail; Wed, 15 Jan
 2020 08:32:12 -0800 (PST)
X-Received: by 2002:a05:620a:100d:: with SMTP id z13mr28880294qkj.475.1579105932545;
        Wed, 15 Jan 2020 08:32:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579105932; cv=none;
        d=google.com; s=arc-20160816;
        b=CcQfWcyox/uEh7SDr8OWf/T83Q8zwFnngQEvZ3bPsJJMwsRrNs2pqHyQikUB7hYiDT
         tigmU3CQs2Rd2Lky+dWmzVoqXteiYMBu+2WdFchiyxxUj5FTJ/L+emRCgrIE9gPlElmn
         Z0wDN5bubeRFpCpiG+MUsxd8ee71ret7fEOCoNCCTUJ+jfoTBp3sqWiWteITMg2OKHYP
         abta1+WQciWa33kH81UhLQPvj2bE2KCyKklH7qtYx1/D9sLGuOw6ug4VESFvAS+uIcTk
         HZfBpfN3iHaEbQ7YfiWJztLRmXF8G5HvSnp5gB+K5StlzyG8RrHDebsmAarvLj2SsrSF
         OHbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :ironport-sdr:dkim-signature;
        bh=+Usi5BtCfYy1gr5qC2coiTPoertN10ZV6b0TtBA+fQs=;
        b=Sxbh1PW9bqtho4rnextqsXMZeQFjQbIbbBLwfJX9zJ6vzyWqlkVQ2k/WNU7K9UD7hR
         o2KzXt56HWzzsGZ+LJ5X5giC53zRdjJ14V7DVw97iBCI/7kf/AaMVieROcIFuk5qGbY2
         FYrjsxfdnKuf4RJ58fswGorQz3bIoe4mInGYVQSLO/ZKKKucJUXyNHg4To1Ozexa89na
         ytPJPFtiGIsvOHZ8+eByKrxxpW/1/xANQ4ks8bIrrKLje++yXuPkZ0qQJx7CGyT6c0WX
         PWc7dBfNBCAkfqhGd1kpzKWfUIV1zDA0fAcETD6zMhprjgfT7tADhBG7JlZQk7MmV08j
         S7cA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=Icoc4VTJ;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.155 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa3.hc3370-68.iphmx.com (esa3.hc3370-68.iphmx.com. [216.71.145.155])
        by gmr-mx.google.com with ESMTPS id i53si854839qte.2.2020.01.15.08.32.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Jan 2020 08:32:12 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.155 as permitted sender) client-ip=216.71.145.155;
Received-SPF: None (esa3.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa3.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa3.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa3.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa3.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa3.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: bkdhVv7+jMwYgYDmPTe9LtkpH0O/koXWbzidtzU0jmq2k2W7y0z8sdgd8jQSbc5ha1bt3GZ1ci
 atAFUSXt6n+9zxzrQ84lgG49P9NYylmzqSNxWZ9aWXrXuRImAr5KZhdsdIf7QbnDqPqIx9tIJD
 CTJ/i6OKaxBEkX2arQZvhOK0lcZLiRfq3/YmZTezw8epzATAx2uWIm1r4K0BkOTLQHve+M61Y3
 7h6z7waIS5kexpbL0CS5cKDTtVlsbAnvf762eq6rlbtL5uzpiCDczteptYnhXB3LagqVTHL/cm
 YCo=
X-SBRS: 2.7
X-MesageID: 10950738
X-Ironport-Server: esa3.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.70,323,1574139600"; 
   d="scan'208";a="10950738"
Subject: Re: [PATCH v1 1/4] kasan: introduce set_pmd_early_shadow()
To: =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>
CC: <xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Boris Ostrovsky <boris.ostrovsky@oracle.com>,
	Stefano Stabellini <sstabellini@kernel.org>, George Dunlap
	<george.dunlap@citrix.com>, Ross Lagerwall <ross.lagerwall@citrix.com>,
	Andrew Morton <akpm@linux-foundation.org>, "sergey.dyasli@citrix.com >>
 Sergey Dyasli" <sergey.dyasli@citrix.com>
References: <20200108152100.7630-1-sergey.dyasli@citrix.com>
 <20200108152100.7630-2-sergey.dyasli@citrix.com>
 <96c2414e-91fb-5a28-44bc-e30d2daabec5@citrix.com>
 <6f643816-a7dc-f3bb-d521-b6ac104918d6@suse.com>
From: Sergey Dyasli <sergey.dyasli@citrix.com>
Autocrypt: addr=sergey.dyasli@citrix.com; keydata=
 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
Message-ID: <c116cc6c-c56c-13a5-6dce-ecbb9cf80b3a@citrix.com>
Date: Wed, 15 Jan 2020 16:32:07 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <6f643816-a7dc-f3bb-d521-b6ac104918d6@suse.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=Icoc4VTJ;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.155 as
 permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=citrix.com
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

On 15/01/2020 11:09, J=C3=BCrgen Gro=C3=9F wrote:
> On 15.01.20 11:54, Sergey Dyasli wrote:
>> Hi Juergen,
>>
>> On 08/01/2020 15:20, Sergey Dyasli wrote:
>>> It is incorrect to call pmd_populate_kernel() multiple times for the
>>> same page table. Xen notices it during kasan_populate_early_shadow():
>>>
>>>      (XEN) mm.c:3222:d155v0 mfn 3704b already pinned
>>>
>>> This happens for kasan_early_shadow_pte when USE_SPLIT_PTE_PTLOCKS is
>>> enabled. Fix this by introducing set_pmd_early_shadow() which calls
>>> pmd_populate_kernel() only once and uses set_pmd() afterwards.
>>>
>>> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
>>
>> Looks like the plan to use set_pmd() directly has failed: it's an
>> arch-specific function and can't be used in arch-independent code
>> (as kbuild test robot has proven).
>>
>> Do you see any way out of this other than disabling SPLIT_PTE_PTLOCKS
>> for PV KASAN?
>
> Change set_pmd_early_shadow() like the following:
>
> #ifdef CONFIG_XEN_PV
> static inline void set_pmd_early_shadow(pmd_t *pmd, pte_t *early_shadow)
> {
>     static bool pmd_populated =3D false;
>
>     if (likely(pmd_populated)) {
>         set_pmd(pmd, __pmd(__pa(early_shadow) | _PAGE_TABLE));
>     } else {
>         pmd_populate_kernel(&init_mm, pmd, early_shadow);
>         pmd_populated =3D true;
>     }
> }
> #else
> static inline void set_pmd_early_shadow(pmd_t *pmd, pte_t *early_shadow)
> {
>     pmd_populate_kernel(&init_mm, pmd, early_shadow);
> }
> #endif
>
> ... and move it to include/xen/xen-ops.h and call it with
> lm_alias(kasan_early_shadow_pte) as the second parameter.

Your suggestion to use ifdef is really good, especially now when I
figured out that CONFIG_XEN_PV implies X86. But I don't like the idea
of kasan code calling a non-empty function from xen-ops.h when
CONFIG_XEN_PV is not defined. I'd prefer to keep set_pmd_early_shadow()
in mm/kasan/init.c with the suggested ifdef.

--
Thanks,
Sergey

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/c116cc6c-c56c-13a5-6dce-ecbb9cf80b3a%40citrix.com.
