Return-Path: <kasan-dev+bncBDW2JDUY5AORBG6AWKQQMGQEAK6ZJQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AEF66D6FE9
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Apr 2023 00:09:33 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-17a03f26ff8sf17787232fac.8
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Apr 2023 15:09:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680646171; cv=pass;
        d=google.com; s=arc-20160816;
        b=rGsIM6ASgRgwlEuRQmpikWDLKTa95qpYj+QXov12GXylJbzTHRSfHxAtxEIHuJcF/T
         w9YwIzcAiguLsDUxjhGf7lz45b0nNUuTwiElTF9a8yoofpTMj0pLvOmFrAbKQzybp8QY
         hi2bXjPDSZceQVf52bB+/TL7vqR8O1eUJqniwdAKZ65amYJX3ycbtHITS6gE/n7o9kPG
         VPjAFdFdC/mE+YIvRr+VA43Yrb0mARUSpGAoT0/wPcZTwfsLtNrdwR5/MxqXFP7SnUfR
         8/Uz4dn8kzp0LgTHde4tE/TgeNXcZs6RS68hsgu9pSF4ZZ3fh48EwvYncuXva+h0cBDk
         AgKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=fMq4pj8JKJ6c4A+Fnh3EVrDpdOR5C7S1Lc1xO73/zww=;
        b=axdpPjDvyZ08K2M6VPoRRok602vm5G9Os7871dU2XfBOPAaonw29YZ7DRLEdRLVSai
         PASGJ9vOi6Zhlv1saiWskV2eezEq3yvbMT684bHqk3aQz9PZLcdScBNHcMYzrUYMBOdd
         5hpPq84eb32e957kQN8/B2zl0OW0jrADIH4XHLJShTVrNnjUhH5FnP07nOJ+ZBJyW9Jq
         JlhrQfYeaqDbNIeYXWoXmPgWuEROURDHUj6A863HbTCGKlWlEOZYQWHoaI0JGyFB8LXi
         LCxnh2ZsxkUv0wL7XrmTon1A9fp05QrlPyfbDuHNDcYv7CQFVoE8Zp200Btf/WYfqgW2
         D9dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=JoPIXnG8;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680646171;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fMq4pj8JKJ6c4A+Fnh3EVrDpdOR5C7S1Lc1xO73/zww=;
        b=fSshB4D4GZsnYouTFB9hSQOfB4UVmKNRye+tyui2gJi90VF9IjTCKDURYsBCJ4+XrT
         7kD+vWLr1jWmh0u2fhquS0RZcWIzFjg1tQSzeyRdsSiNs5g7GzFG5UdSxVLn3MB8ZSAc
         jc2GeyI/vJzHEEtXX37alsD3ZugyGLeNyA8qzbWKz/8RGwv5g+EPKCY6mI2ArFHpf8I/
         rHsXY3LNuBE57tmk0ALH3IgbyLU0lJeAq0Br5Bo1fc3Z8Jt+j4bsI3nhi6uMDPyFpCss
         9dZMKMGOGI7FOdjR1zwTYq3XtrHwik9jP8ZjnLNDvSMAtIcfiGlkNPTFnCVTkZFMZJ52
         eS3Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1680646171;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fMq4pj8JKJ6c4A+Fnh3EVrDpdOR5C7S1Lc1xO73/zww=;
        b=gKp5YcMUkzhZDdwMdm7oPIlopHYnLFnSwY4EtiynVkXpResYklshIZBusBtm+7+kOh
         jxljnBZdz5ix+VHCzU5yEyOSm3J1QJRr9ZbZxdnJ2LUCf2+KB71mOUfRNRAygj2hX6GV
         HkTi58NKhcXR/Y1rqHuImIkfqiIibfbYcNWx5rUOhJWzF5A/P9bd1WKsD/BybeU9/m4l
         Fnlf3myRqGWxv7KtTbUgqj135Dyk6kOzCjpZnXMzG++cgT7Rb8kjL8brq3/xrh5fNw4b
         VRm9ZIzmuhV1lxMMK3G7y7GI4Wq+753cU29ilYnNiPJDQ9794uDJ7dxXFiHaOK5v1QGB
         C0kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680646171;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=fMq4pj8JKJ6c4A+Fnh3EVrDpdOR5C7S1Lc1xO73/zww=;
        b=i3DBihI35hhj6f/7VOYupUIA7+zE8KCT2C7n680y/Tl5OKKkxMgdfqB3Q9urGq/05H
         EVcs54FhejPE8GAZ8Gt4UFOjyhLp71QTHTCd22BodwN2obTEzUDzRYvVBONU4C+HjZLL
         1GmclnSpY6WYEitmWa89lDWhitAn6DkpFJXdGlaIUnKRxHPN01CCd674d5RfoYnxmlQq
         9R2DX7+GkKTq7Ovi57Ap+cX+vErNjD5VQfc4bOS8lVDlpmf/eMUXfpDCJspq6d/TLNkC
         DKE4j8ogUNiwTE1ULZkZiS1x0djlaS5VPmHZNdEVDAfmmH2jiNYBi/s2z7gcoF7QlVw7
         5njQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9c/MLpUB6C48Wz7Ge9dxiQE01hS6xyJRTSprdh2XlwBxRvZIoQN
	gHtkLO0EfH/1DRht/jrBGMo=
X-Google-Smtp-Source: AKy350b9I2YNuACxpGfVGeFkXU0LYTuwPz68MzSYBoO5xdRvEq6zhjpRwBnh0jc6kvBju4Xv7yKUcQ==
X-Received: by 2002:a05:6808:1148:b0:386:be95:91e9 with SMTP id u8-20020a056808114800b00386be9591e9mr1540198oiu.1.1680646171535;
        Tue, 04 Apr 2023 15:09:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e904:0:b0:53b:545d:9cb2 with SMTP id bx4-20020a4ae904000000b0053b545d9cb2ls471532oob.6.-pod-prod-gmail;
 Tue, 04 Apr 2023 15:09:31 -0700 (PDT)
X-Received: by 2002:a4a:5248:0:b0:525:59fd:fbe7 with SMTP id d69-20020a4a5248000000b0052559fdfbe7mr2005158oob.2.1680646171001;
        Tue, 04 Apr 2023 15:09:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680646170; cv=none;
        d=google.com; s=arc-20160816;
        b=jvvppT9RUxGy6WziafYtsSQjDh/2E6q4ezLkRyAev2l9eQ07AAVwioDkPvS+fwbUaj
         Nmjs3qIinWkNTYlo1DV1Sx4XOqltmJ61wIoZ6ayf6J1Bh7WUbuOurU1AHxrpKQGeJ0kZ
         NTCj8i3jC/xeK33oGieohrbH+bJCzM4HI+HgXpSipAUMNfwwybBkSGsEAjwJAAEm1WtN
         Ug9Fg3Sm8+GDCsByYsysELz2+HXAUdM4giYCdH/Z6/Hrn7AyTiqHQfAvaXdBTSG8duXl
         +GVu7La1AN0Xx+cXDXXQtxmuLaD9Qc0mz2sz2+aBe6HoKleIY9M+bqBuzM1M9LSSTZiy
         xycA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ypW3uCkatd85laSwJoEHyhvz6A6Q9ytym+XuTNT93dU=;
        b=nLC7rPPbTLBfX5sKej43/fnxws9Qorj1IDD419R1FhtleQQuK1RtGeBe5QZe7DVEgz
         Av06lt7gfjDAQv2/08S+uNDyauhIWzcoukFwV2/9KBTZE2JYZN7vzAxB8nQhVshJMNWf
         eQiirJGP9IZrQjmFrG/e5gtLIgvohVsKwYtD12lcOLPpsbkN5G5ChnNcYCF2xAP+Rd1V
         9gZuYCfGgyyfa1cffGUwUkMQEnFdMguaWyr/hGZ9d7QlVSyiZKHEJreBH7/x2NHfSuvG
         2Q2Bb8sr2GaniZPnokKhi2s3hFZJCVASd63Q7p44kswlzp3wullbbpIhlwpN4Zub5uf4
         LyKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=JoPIXnG8;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id b1-20020a4aba01000000b00525240a102asi736057oop.1.2023.04.04.15.09.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Apr 2023 15:09:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id lr16-20020a17090b4b9000b0023f187954acso35408663pjb.2
        for <kasan-dev@googlegroups.com>; Tue, 04 Apr 2023 15:09:30 -0700 (PDT)
X-Received: by 2002:a17:902:8604:b0:1a0:48ff:539c with SMTP id
 f4-20020a170902860400b001a048ff539cmr1636900plo.11.1680646170341; Tue, 04 Apr
 2023 15:09:30 -0700 (PDT)
MIME-Version: 1.0
References: <20230404084308.813-1-zhangqing@loongson.cn> <20230404084308.813-2-zhangqing@loongson.cn>
In-Reply-To: <20230404084308.813-2-zhangqing@loongson.cn>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 5 Apr 2023 00:09:19 +0200
Message-ID: <CA+fCnZf-segLxa3QxStd6v15ZCge=3=3rOL-9Q_eMc-y2j1nhg@mail.gmail.com>
Subject: Re: [PATCH v2 5/6] kasan: Add (pmd|pud)_init for LoongArch
 zero_(pud|p4d)_populate process
To: Qing Zhang <zhangqing@loongson.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Jonathan Corbet <corbet@lwn.net>, 
	Huacai Chen <chenhuacai@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, WANG Xuerui <kernel@xen0n.name>, 
	Jiaxun Yang <jiaxun.yang@flygoat.com>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=JoPIXnG8;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102c
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

On Tue, Apr 4, 2023 at 10:43=E2=80=AFAM Qing Zhang <zhangqing@loongson.cn> =
wrote:
>
> Loongarch populate pmd/pud with invalid_pmd_table/invalid_pud_table in
> pagetable_init, So pmd_init/pud_init(p) is required, define them as __wea=
k
> in mm/kasan/init.c, like mm/sparse-vmemmap.c.
>
> Signed-off-by: Qing Zhang <zhangqing@loongson.cn>
> ---
>  mm/kasan/init.c | 18 ++++++++++++++----
>  1 file changed, 14 insertions(+), 4 deletions(-)
>
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index cc64ed6858c6..a7fa223b96e4 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -139,6 +139,10 @@ static int __ref zero_pmd_populate(pud_t *pud, unsig=
ned long addr,
>         return 0;
>  }
>
> +void __weak __meminit pmd_init(void *addr)
> +{
> +}
> +
>  static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
>                                 unsigned long end)
>  {
> @@ -166,8 +170,9 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsign=
ed long addr,
>                                 if (!p)
>                                         return -ENOMEM;
>                         } else {
> -                               pud_populate(&init_mm, pud,
> -                                       early_alloc(PAGE_SIZE, NUMA_NO_NO=
DE));
> +                               p =3D early_alloc(PAGE_SIZE, NUMA_NO_NODE=
);
> +                               pmd_init(p);
> +                               pud_populate(&init_mm, pud, p);
>                         }
>                 }
>                 zero_pmd_populate(pud, addr, next);
> @@ -176,6 +181,10 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsig=
ned long addr,
>         return 0;
>  }
>
> +void __weak __meminit pud_init(void *addr)
> +{
> +}
> +
>  static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
>                                 unsigned long end)
>  {
> @@ -207,8 +216,9 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsign=
ed long addr,
>                                 if (!p)
>                                         return -ENOMEM;
>                         } else {
> -                               p4d_populate(&init_mm, p4d,
> -                                       early_alloc(PAGE_SIZE, NUMA_NO_NO=
DE));
> +                               p =3D early_alloc(PAGE_SIZE, NUMA_NO_NODE=
);
> +                               pud_init(p);
> +                               p4d_populate(&init_mm, p4d, p);
>                         }
>                 }
>                 zero_pud_populate(p4d, addr, next);
> --
> 2.20.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZf-segLxa3QxStd6v15ZCge%3D3%3D3rOL-9Q_eMc-y2j1nhg%40mail.=
gmail.com.
