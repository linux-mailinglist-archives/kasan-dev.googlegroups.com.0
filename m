Return-Path: <kasan-dev+bncBDW2JDUY5AORBZ4UWWVAMGQEUJIRLTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EECC7E7365
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Nov 2023 22:08:56 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-421a7c49567sf225461cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Nov 2023 13:08:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699564135; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hqb8wqiBbdzQpQ9Lad1aXlVEkPvUNcC1adsju491dUEvjHhu9994AYJ8kuNBK9Tlue
         vXF0CksX7F5ax/ozmvzm7koJTZnqKr/cZuRq0WEHRj20xjsKINmW26L3LPk1nwM99qfz
         A8sJujCaSDUEA4Xz8HCVvOrauUsgPlIECp5sdo7zLetiXU4j/AV1JcDcMw3liR0j37js
         V+iLaXGR9uYEW9p5u7/SRglEfNNqPQAGMUxMg39zBgObW32SEfp4xwy+T4Rwrc9LcwTz
         nogFuprrueVryT/Le+fbYQEsKjFX8Q+daUlG1zo2jAHnbBElQ6P/8OmdwBsg1MR626U+
         VCJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=A2qHi7JLA5jfZs5r70phIiRw/RJIsB0MRsblLEQXlVQ=;
        fh=Ehiq1FXoKQf+PuGmxvxhEp3/c57MIU4FFoZqZkSnr+E=;
        b=iDvujT+t2thT/SdJKgtdnLY2+3JgD+5MHEoOA55aZBxgp0CAQHPwpH7vj+R0FYw8sr
         CVuvpp2vVGHJmxJDT7Sx2wYo641ziMJ+n4XnAbjLWFdyQVhQOa1Gqk3aLt0O9IwNJVpV
         92FqcGnEOK07u+fcplQGf2HkLwmxvbZPM9VlvZdokqhnCGwEkLAdgzNjMrW8E7KM0aug
         Qvy+f+/x3YLxCe0PcfxnxpHhTEp/qVvWGARBnaoT58pjtUH8PLiueq8wbTTucPYkEwk7
         EfUyO9mtkSXJSADSYxwDnFEB41t3RQSAH4xh8BI9IzgVlEzhQ+lP2hHH18GPt5VXqRvv
         kCKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="NFwuOQa/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699564135; x=1700168935; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=A2qHi7JLA5jfZs5r70phIiRw/RJIsB0MRsblLEQXlVQ=;
        b=Q305t5eW6Pmwb82BKk85viuHPJSRUyktkmZXSF33lCmD+V4MmHV5GtES68J1xPoNZj
         atGv8g9mBNA+Hsey1/kUILUNuHPXiU1XhzPSUZx80DRhdWraBd6tmIFW2SL0vpBI+DpM
         z03nPoDgoic7nM7U/GGDOR1UumeR+WejfPfr5xIytgnizTcO1UaxxnC2vLjxAC/CkHym
         IM79+8UxkRNDHUXUq0elPlaIcGWaW1MBdXvJMDup/X7Flv6LMq9Fjrdfqv5jefahW9rP
         V+upeFlTWPptTDIPg45EiTFdWwhlIjiV6CDWDrwuReQ6YFSENZIgFtiryeQ0HvJ/Xc7Z
         b5ow==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1699564135; x=1700168935; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=A2qHi7JLA5jfZs5r70phIiRw/RJIsB0MRsblLEQXlVQ=;
        b=edM4lYOEEKixcWRUqzj+ZzIqRXTJ5rhm8yZNLKYfLwPp0qdCnXX2vZmbWTi5BFeLQO
         AllZessMjNFZcxBjvUvV1+R59Aa3XVKLZcK4JU6XVUmLnH2WUKxGWe6/40uFFHeJx0wm
         R7UOAc8g3B0vWIEw0rvXy/0igBQ61Gx3eSM3jQ7R7ZhaFwY9XxpDk3YXN8qoixjW0zDL
         35TG0knuAdFtL+pdAszEIiLmdYJ+vJF5PfEL1H4hN9advDdrdcMC1M1Pa6W/cAnlGxUa
         17OEK/7Rq87GIK687BS+pS+JhPX4tSSBQkl3sOXJdUg/RZWSYHnUZzgQSfMiz3WAz7Wk
         AVgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699564135; x=1700168935;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=A2qHi7JLA5jfZs5r70phIiRw/RJIsB0MRsblLEQXlVQ=;
        b=fs0i2GASGRuSiHOfVhWn1puXabCHwnxeRfCpp5niW64oLxLBL62dgZxMQy88oLeAvJ
         olHe75NbVtQcFN6xKQjgQPdA9XkmPrhVxKVkPXmQR2Q5dZYE1hwtD3nJmw3sYZL8vx28
         ul+T69OWwkm/Pe36z2YsgdcD47pJD0z3TRWFvIDeRqUfxRgKRAZ9KPAIIGxsQYyIJyiv
         f5W+aNI+VTiEk84npWG3bvRgIOgvNvbk3XV/+fYU0EmguXHvFLr/iRvdQ4/NRrkj/UPk
         CMef3fd7I8+wpkfvr3QHSjFM1BCVWYoSaWzh6X61Ri2AUU/lWKMLuB+UK2VW21HXGGb0
         Eukw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwahC7DD4BwEeUuLNqCk2jnQ7Wbsd0I1AKGNG7/432zOmvCpSJH
	9FRkl98T0SoU5xtOedSFs3E=
X-Google-Smtp-Source: AGHT+IGNqAugGTFTKIAcLaSi2IR3F48zUzqyK4iO/LaEolu9VpgUIGQrrxDQGoiWorqPi3cpTZSBRg==
X-Received: by 2002:a05:622a:1925:b0:421:1c15:a8fd with SMTP id w37-20020a05622a192500b004211c15a8fdmr473961qtc.14.1699564135150;
        Thu, 09 Nov 2023 13:08:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:fa89:0:b0:62f:e5ab:e5f4 with SMTP id o9-20020a0cfa89000000b0062fe5abe5f4ls1278631qvn.0.-pod-prod-05-us;
 Thu, 09 Nov 2023 13:08:54 -0800 (PST)
X-Received: by 2002:a05:6214:19eb:b0:65b:765:254 with SMTP id q11-20020a05621419eb00b0065b07650254mr6272273qvc.4.1699564134129;
        Thu, 09 Nov 2023 13:08:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699564134; cv=none;
        d=google.com; s=arc-20160816;
        b=ljD9s3x2U70ne1fqdwzywXExPHYcVVtZ6Mn80f7r11b7uDpJzs5LoiUw/pP4q/WRu3
         wjAGe8LrgRG4URnROtT4qtnO9TLUlus2jemC8vC8/nRVz/VxVq9LR1S3GKBatQYYvaTQ
         5Lgucl3nU3ef+YtTesrPVGDB3NCv89tZz77VUrHnOnTl8rYRWRhlLuYV3BWr9HO/LCWC
         IPBZ9p0N2mmim4qhKWXmscrsq78kFwKlK/0YUB11aJMGMvfwff6W4jhqMn5U61TsxlKO
         SHhh+viPkV/vwGY/8710PLi7WufP8w62Z907tRNSEasD1/jJz80q2HpLZRxS/4s/yqFV
         KxPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=OXYSdd3Scp9s+p6eiKxC4NVMsyUlEkxWa4iBppHaBEE=;
        fh=Ehiq1FXoKQf+PuGmxvxhEp3/c57MIU4FFoZqZkSnr+E=;
        b=cUGybsqEZmdn8wvFRUhYT4wOcrAMBf27BGtWervEikgo07dtsLhJWxkDYKB1wLMAP7
         /P0u659fCe/udhj2qetl1pxL0oMxMk+Meu76uiWYqcKnu3Cy7sJEElxq3gQOlv/21do8
         uCj5HI2oZqfqIIY6WQPG8/xOPwtEBMp4kVq4pafiUGUmV7tSDUPhTfpVX/fi3/MbpuSZ
         kPKZy5vQd39Td57Tf7pKk22GLcI50Tv60moX1hutd2d48QrJQXtQq6evb+ZInQ6gTDpA
         telQ+bHU9G5HRqvvCgpS7OpfqhcxShB1B7jnCHVQPp5Sf2hrmvB/hnsHZYnbK2QlKevU
         zTFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="NFwuOQa/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x635.google.com (mail-pl1-x635.google.com. [2607:f8b0:4864:20::635])
        by gmr-mx.google.com with ESMTPS id e8-20020ad44188000000b006709066313bsi443235qvp.1.2023.11.09.13.08.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Nov 2023 13:08:54 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) client-ip=2607:f8b0:4864:20::635;
Received: by mail-pl1-x635.google.com with SMTP id d9443c01a7336-1cc2575dfc7so11386515ad.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Nov 2023 13:08:54 -0800 (PST)
X-Received: by 2002:a17:90b:3902:b0:280:31a8:191d with SMTP id
 ob2-20020a17090b390200b0028031a8191dmr2603322pjb.39.1699564133128; Thu, 09
 Nov 2023 13:08:53 -0800 (PST)
MIME-Version: 1.0
References: <20231109155101.186028-1-paul.heidekrueger@tum.de>
In-Reply-To: <20231109155101.186028-1-paul.heidekrueger@tum.de>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 9 Nov 2023 22:08:42 +0100
Message-ID: <CA+fCnZcMY_z6nOVBR73cgB6P9Kd3VHn8Xwi8m9W4dV-Y4UR-Yw@mail.gmail.com>
Subject: Re: [PATCH] kasan: default to inline instrumentation
To: =?UTF-8?Q?Paul_Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="NFwuOQa/";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::635
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

On Thu, Nov 9, 2023 at 4:51=E2=80=AFPM Paul Heidekr=C3=BCger
<paul.heidekrueger@tum.de> wrote:
>
> KASan inline instrumentation can yield up to a 2x performance gain at
> the cost of a larger binary.
>
> Make inline instrumentation the default, as suggested in the bug report
> below.
>
> When an architecture does not support inline instrumentation, it should
> set ARCH_DISABLE_KASAN_INLINE, as done by PowerPC, for instance.
>
> CC: Dmitry Vyukov <dvyukov@google.com>
> Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D203495
> Signed-off-by: Paul Heidekr=C3=BCger <paul.heidekrueger@tum.de>
> ---
>  lib/Kconfig.kasan | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index fdca89c05745..935eda08b1e1 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -134,7 +134,7 @@ endchoice
>  choice
>         prompt "Instrumentation type"
>         depends on KASAN_GENERIC || KASAN_SW_TAGS
> -       default KASAN_OUTLINE
> +       default KASAN_INLINE if !ARCH_DISABLE_KASAN_INLINE
>
>  config KASAN_OUTLINE
>         bool "Outline instrumentation"
> --
> 2.40.1
>

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you for taking care of this!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcMY_z6nOVBR73cgB6P9Kd3VHn8Xwi8m9W4dV-Y4UR-Yw%40mail.gmai=
l.com.
