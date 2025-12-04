Return-Path: <kasan-dev+bncBDW2JDUY5AORBRVSYPEQMGQEXKHPA6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B93FCA20DB
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 01:43:52 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-59578f8468csf150303e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 16:43:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764809032; cv=pass;
        d=google.com; s=arc-20240605;
        b=BKNW0dn4RmjMyHqYxr/qQc905mDxJLPj3DX4amerwq3FvJMxh7YYEhnIrZj3aXj5Cr
         ykhVrKqZ4jvqajoN7+9Zom41/7OX/ivEXlQC1Phm98q8RisicAu4jkeNspXaakSZcCwp
         VCRkSVx8IlRRSXgm/5D444XKF1ZnhSdF30J78yBQdPMjM1ch02VaNLgA4lZbEt1AN/Yx
         MqIKxUvqRR7UxW9g5KO/wlamULuTsPIXYdUgUljXOMR/NNyJQwJn6EyXYu+6n6nfyolU
         mhIgiWlOWONPv57OlSC+cDZkVq2lGP9N3SUzfI6yJVCamy90NfGyTGqgFkO7jYBNTNUi
         fzhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=/sunCFC0H+/nYQ/CL/FjEf23Q81OYqotvYq3O9I7nYE=;
        fh=OMnnFZQxmu7rBG8ZYqGhHAl77YmR9lWp8360oCVxkSQ=;
        b=i5NHd+v30oYsQv/sAdn/OJCOP92g68cV+QouUKSoB6TMbTrSsYNY+cnbPl/1vDLckG
         C3jThDu69MLAT9XWKb9s9xE9NVpUL1L2AVCkJt3f4wPYqU52n22qqA7lkhviDa0YhtP8
         DefBeUUdwwska/SYyZ/dh+qzW+Sku+3FsbxnNss4OUtkrhF1W9+gIiSoo/k8aBjpFga4
         1ex4+/Ix+d0SsItf+o71dlG5Po/kAARJC7rnkt/K+KdnTPaoYdgtM68NagUM8O73ZpLU
         HzguSPuP5/M74f/XvSww+gal9XAAS2pY1O9lY+yM34kbdlq866t1yobwKwQTgLpUggea
         V1/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=khlqd1rg;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764809032; x=1765413832; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/sunCFC0H+/nYQ/CL/FjEf23Q81OYqotvYq3O9I7nYE=;
        b=vI5ar5VVvXk8DBFuRaiHl8lJuzzz1/iO1eFnWdV8JUbhfOcsSNbM9o+nXQg4k35LyP
         4MjyNLSAACmB+GdnDRDCztt0HFmixQly0zs9aPur9nZyfy5LBlZweb2M2uR9gIswBlyI
         yHhJQ+lOvLoS+ohFhtcChQod6etWdZFz1pXuK2D+dp2yfx94U5Nn9UEmQvhiHv0jBsUT
         fXFPIUJqaNhyoiRm3go8+o/qO17ueJDnX2KfbvMGoSc9RwvbScrdCNM1a/tQemGDG+AG
         6fW7hgXwH0DwtvpgA4Qr394EEKsnpFouu8UGmdEN0ppuRga1OPrAegcPnBF05guIMMwv
         dXiw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764809032; x=1765413832; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/sunCFC0H+/nYQ/CL/FjEf23Q81OYqotvYq3O9I7nYE=;
        b=HS+YDXSGUoAdIOS1Smaq1cipuvfTJEqk4btEkg5l3LTgAVoJj99zr4Rbdz4OoLsek5
         HfkPh3EySQP4GxhW70lEKxiVkMdtBi1lxYOuvKMoLkrG0Di3u8fWoGzHGVx0/BslOsq3
         vKUqJV4WFsGqoEzCqvOoZpUjuoIPR+L7se0JWTXEf4HuTREa7ySdGbwoTw9qoZvgxYx5
         iCX1Z8axEc1vuwFE6sLvSPx8F1NkPYkuq80abSWdEomPxIL0BLxyaVq5gJ3f8wvEfLSe
         IHYVqZ28ys5ai4Sup2+GFdxa391FTClK7jBzfN1shgvbrn3h4aiSDvoZGD0Z1wi8/2Bn
         ypxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764809032; x=1765413832;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/sunCFC0H+/nYQ/CL/FjEf23Q81OYqotvYq3O9I7nYE=;
        b=Ww+zQahX+b8h9+vQLz+JpKBcseylr6W/nzhlmkZji3E8PbA8xI/drLFtbnrk45O82I
         5GwmoheE4DklApfANlUemBb6iVa8BYKQFmCKqXqtQCgjCKPvlkSxGsbr4CNe9ItZ3W0J
         c68y9ZAg1EtBL+6ojoCdwr3p4O0T3EI0epckgtzOq7TikyFSdIRRzRKNV85cZLWgHac8
         zyJKtiy2USxdrCUqgCpCWPuCM5GI8dIgwFW9nYATLBdURvPFCRlQiYLR0gTsyzlYO/1W
         /QhT7ZbA5LSSfYMiFGXo/ch2QsMk90zQCD8bjasu9Z1vQ2FCa7aPt9ON0Dl4AzsdZfPy
         3VAA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmF2s7e2CvojgTKQSin5SaZmr51zl3UyaYSyc2dTcVaant3dnoE2OG1WKNNwdladHSNEOoRw==@lfdr.de
X-Gm-Message-State: AOJu0Yx0fGYYfpM1qRTX0EOTUMl7TaJqyyvu8+0KjG6xN0uaTfxHTKpz
	U9zTO73u+2kmfflwJAVGwJw+mr7hysHnh0Nwu33wMEhTmaQrPxpgRdN9
X-Google-Smtp-Source: AGHT+IHP0J1Teghw2MATcnOPZ38OOVjwkvt1JjcjyYJK7A6/yrzg3RkGH3tfg+sDsK477zwVz00XeQ==
X-Received: by 2002:a05:6512:b27:b0:594:2cfe:368f with SMTP id 2adb3069b0e04-597d3f0236cmr1898712e87.11.1764809031523;
        Wed, 03 Dec 2025 16:43:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Y1Hose0lIF1PKLw5sJViWzGdeAUR8KBU6KMVARCJRxkg=="
Received: by 2002:a05:6512:6184:b0:597:d369:7f8a with SMTP id
 2adb3069b0e04-597d6d09415ls39933e87.0.-pod-prod-03-eu; Wed, 03 Dec 2025
 16:43:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUl7JeycUdmvEQtNr+pwdkBCYqH/U5C7qBgYhzWrGdNPy+KUpQXsyp43y9YLQMyJ4EAIbjCtnCVIbE=@googlegroups.com
X-Received: by 2002:a2e:b052:0:b0:37a:455e:f302 with SMTP id 38308e7fff4ca-37e639060bemr11264811fa.27.1764809028603;
        Wed, 03 Dec 2025 16:43:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764809028; cv=none;
        d=google.com; s=arc-20240605;
        b=AQN4Vjfu0W6Cob4UgsMVh5bBOD8950Mz8Zt67P7s/oDiCsaLKAwlVpzpCjTHV6+7s+
         ys20zuULf7/Nc4N1tum7Jhpz220Kz+nkkTgTvqvHYA0kgfqTA0FxJiZ+xlvvhCtj3Iyi
         r00YQGjfdK4+CZyJmhvK/rSISGH9fl+7mLIsGyehmLaOyVth9iacWOu07UVaVujF1N48
         HnEFaUF+n3vIgxQoPj/XTCJI8bvtWNWg22VIodhcg2V8UvKq+9ER5tXs+6RfkP2vnc9F
         orx0NJsqQt66kzRgIUFqtHyLSY7u7OquINH7iafOq53HlIISvlvKJPZb/rYR6KY8QpZM
         M+CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fSZR0s81uMpFgx5g0GkJVL+/X7Q/NOvMK5/MCFI0OA8=;
        fh=Qr9uEvbmKTi/r/f2TmqOfP5MJtuDdfWbQo4gAwVe42g=;
        b=R9l45RlkVcjtKyezpYOan6hVm1DWW43gbKCbP41BjTkJHmrm4w4EIXD8SlnRCGUHRC
         /nit9wh2Rc4iTKRtc3h7IFESxVzBuO4/aFtJ5gLQbYxt5mV/QIRJvJwWjgVaXwD2Mi87
         MRa4/gpVUyBpa27r/eevyxaiphkQHA0nMuIELT0h8blJfnNxOl8uc+R/0EYmZgIgooE5
         nO0cx5cYq25ysRSSv9pak9LVmg1qGPhLHxLgae0Co6ezM5vVJfnn/dvJ1VtgaDhUHb8/
         Shmq2qGhpRt93XknMWmS0jZLtvO+w/ZF4MyZz7i5pC3dQ4zHPRFzk0sYcJOuIuX5EY9N
         KO1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=khlqd1rg;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37e7012520csi19491fa.9.2025.12.03.16.43.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Dec 2025 16:43:48 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-477b198f4bcso2546635e9.3
        for <kasan-dev@googlegroups.com>; Wed, 03 Dec 2025 16:43:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW/uUG2VR5WXTfssvkUik1IHWy5IPKpStRd03A1Fv4y6ieO2jRqP+J+sEUUsWWU6yKWoWAo1L3NYqw=@googlegroups.com
X-Gm-Gg: ASbGncu4ylj+lTmYteMig3+fg4obNPGgBP4cTPQryOlTPr5Xu7lRgY4hVjgApglXMV2
	Z29mP5T5tzdkXNor8cER/U18zXyQ69lLDqnufvpKswGZmG31ETTJ+0LsOx7TR6w25fDUt5qgOzK
	nBTU2mtspJYisT1jLekSAZHRphK6RspVz/dwLUCAObEeZDdh10yLrHTfk5zC45X7bjC0KA/C/rp
	NQ8GOOV3AcZ3xOBXWhIJfoL3na9DZMk3vYzMvBUoRzyErznh9Jvu8dkXZxl7gbc6ZcSo6f9cO1W
	tLpyDIDdust3pdKmfuaS3jv+e1AQ3iPr178q2KzrKSlG
X-Received: by 2002:a05:600c:3152:b0:477:6d96:b3c8 with SMTP id
 5b1f17b1804b1-4792af3d888mr39174785e9.23.1764809027713; Wed, 03 Dec 2025
 16:43:47 -0800 (PST)
MIME-Version: 1.0
References: <cover.1764685296.git.m.wieczorretman@pm.me> <325c5fa1043408f1afe94abab202cde9878240c5.1764685296.git.m.wieczorretman@pm.me>
 <CA+fCnZdzBdC4hdjOLa5U_9g=MhhBfNW24n+gHpYNqW8taY_Vzg@mail.gmail.com> <phrugqbctcakjmy2jhea56k5kwqszuua646cxfj4afrj5wk4wg@gdji4pf7kzhz>
In-Reply-To: <phrugqbctcakjmy2jhea56k5kwqszuua646cxfj4afrj5wk4wg@gdji4pf7kzhz>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 4 Dec 2025 01:43:36 +0100
X-Gm-Features: AWmQ_bl7ZVunvhyvED5tOqclCssm6-frqSDnocWXgYLBUJsGZUA2QPhZVEy1VsU
Message-ID: <CA+fCnZeCayQN3448h6zWy55wc4SpDZ30Xr8WVYW7KQSrxNxhFw@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] kasan: Unpoison vms[area] addresses with a common tag
To: =?UTF-8?Q?Maciej_Wiecz=C3=B3r=2DRetman?= <m.wieczorretman@pm.me>
Cc: jiayuan.chen@linux.dev, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Marco Elver <elver@google.com>, stable@vger.kernel.org, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=khlqd1rg;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Dec 3, 2025 at 5:24=E2=80=AFPM Maciej Wiecz=C3=B3r-Retman
<m.wieczorretman@pm.me> wrote:
>
> >I'm thinking what you can do here is:
> >
> >vms[area]->addr =3D set_tag(addr, tag);
> >__kasan_unpoison_vmalloc(addr, size, flags | KASAN_VMALLOC_KEEP_TAG);
>
>
> I noticed that something like this wouldn't work once I started trying
> to rebase my work onto Jiayuan's. The line:
> +       u8 tag =3D get_tag(vms[0]->addr);
> is wrong and should be
> +       u8 tag =3D kasan_random_tag();

Ah, right.

> I was sure the vms[0]->addr was already tagged (I recall checking this
> so I'm not sure if something changed or my previous check was wrong) but
> the problem here is that vms[0]->addr, vms[1]->addr ... were unpoisoned
> with random addresses, specifically different random addresses. So then
> later in the pcpu chunk code vms[1] related pointers would get the tag
> from vms[0]->addr.
>
> So I think we still need a separate way to do __kasan_unpoison_vmalloc
> with a specific tag.

Why?

Assuming KASAN_VMALLOC_KEEP_TAG takes the tag from the pointer, just do:

tag =3D kasan_random_tag();
for (area =3D 0; ...) {
    vms[area]->addr =3D set_tag(vms[area]->addr, tag);
    __kasan_unpoison_vmalloc(vms[area]->addr, vms[area]->size, flags |
KASAN_VMALLOC_KEEP_TAG);
}

Or maybe even better:

vms[0]->addr =3D __kasan_unpoison_vmalloc(vms[0]->addr, vms[0]->size, flags=
);
tag =3D get_tag(vms[0]->addr);
for (area =3D 1; ...) {
    vms[area]->addr =3D set_tag(vms[area]->addr, tag);
    __kasan_unpoison_vmalloc(vms[area]->addr, vms[area]->size, flags |
KASAN_VMALLOC_KEEP_TAG);
}

This way we won't assign a random tag unless it's actually needed
(i.e. when KASAN_VMALLOC_PROT_NORMAL is not provided; assuming we care
to support that case).

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeCayQN3448h6zWy55wc4SpDZ30Xr8WVYW7KQSrxNxhFw%40mail.gmail.com.
