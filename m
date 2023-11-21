Return-Path: <kasan-dev+bncBDW2JDUY5AORBTVK6OVAMGQEZPVYG4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 286347F331D
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 17:05:36 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-58a773cb807sf5360166eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Nov 2023 08:05:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700582735; cv=pass;
        d=google.com; s=arc-20160816;
        b=qoNk5ZICM8vBjfEOmrlOrPYCnk5YOk6APP0cojvIG6XluqVMmaEY1i7D+6vNTw9Pzi
         jY2RTT9PSkqAz85VlshCeY9YR4eiS30WqKqE748SmJD4oSvLyimmhlz0d9MIaktOdXMr
         s1PY1Bbyy/Ygt11GCgyP36Qi760JhtZy2Lz38tCPPTL5FbMBq5+mq6/+Rzg+Cb+bg0st
         C0+7pSAO5k19IcQWStvk5sUXjeUmCoHNKeZrUgLE+iFszz63jWM1LLdU5ktP1UHx7bYg
         zhGB5l2RVt80izuVWd9en0VqKOqSqSiZcF+eM9qcw/vb0J8pwkC+oDlPvtUnQHfN/KxU
         +87Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=wFI1TJ2df6aNjztWa1ktNfj17D7T4g+bKARorCJT0lo=;
        fh=7HvVTlPu/758q9pyDnsoZecNvn2PrfH9jHqN5+uHZcU=;
        b=r2Jeqbf+YEsGo/kB4PEiv0HY6dLxiuxxHFxGfKqvaN1HxaSx0w1PKlcQrRPNxlWuto
         uRoODuXGgXW8OWcWJiQyptNJCF9TciY8Vj/5zqzdb1RyCTsGgwDFEPx8GUocdAiFR5vW
         7U+Cq9DfbkSufvogLFmi+aCBzZBrG/+FECpLXWRHnjwgxSCcSzFX1ylIvlB7rVgsvvoZ
         dWt9+vJyN2Rvo8cupczF4bBrl7TXsGx1aGxmiqL8PmbAAT92AsqnwM3C1roUGpBXdFdR
         WkgQyIlOJYv0s9JCEf/czN7RkYRLWqGuJCO6tZtNNZ3IqUZGowzE0kGiFCrvNty6syCE
         03EQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UrNzPuNt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700582735; x=1701187535; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wFI1TJ2df6aNjztWa1ktNfj17D7T4g+bKARorCJT0lo=;
        b=QWgrBT9D807QqsKjQEJ0Do+YxscC9KTLrk+0+1NREMJ34666AkAG8xr6rZpyuOy6RM
         1bisdo5allkiNvqvLqeQzBG3bsCIKNYuBoLMl7czA9sT9Cf/wCSLzHUucxVb1EjLXAA1
         Paqx7+t9n6awww3s3m3dMxP+kIlsf0gTdAQicbMoN/3lCh2UzpRqchL3M92J5a1+t1dp
         yaLCFJboPsfwgfFEJH8kVEdav61KCoXszVeC6WTM5M4z4SK/wJXU7GTVxjHM8BqeuplL
         Wlljna04wI6p1E8/R4GB9dyAGa/tcwrQPMm+e81k7UGXD/6hLaulBfDU0rZSVXLsDJh5
         toSQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1700582735; x=1701187535; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wFI1TJ2df6aNjztWa1ktNfj17D7T4g+bKARorCJT0lo=;
        b=C/xOEEi3xJ5GbeYP6sfFWCp14Dw6ViozmFZhUfP3jH7bssc74BdLzgaZM8XTzx+0kt
         9iaN0EBtUsDgc5IO1H2Hx+pbvOhvGGsyQe3a/pXx/QA0SV/1s3VA471Mm+Wz9eQpKb82
         2NhPMvaezEWcIqUL2FHWc5P+VipcaHW0AKdM/pbcQUM7BD6p8oYQiT4TrgCr/Gv7HaKG
         VNqUlkNbSQzWk4Y0m+4XSwMsedUe92AO7+HzCqLgNIH2zFtk/DPM9Z939V3qax1rG6I4
         i18hScGQ/Ir3/OyRl/p/NMAK6VcDeY8AmJkAjiliaolBzQ1XNFY75MD6NM2CeALP9ryh
         15pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700582735; x=1701187535;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wFI1TJ2df6aNjztWa1ktNfj17D7T4g+bKARorCJT0lo=;
        b=vnuzrgUc408HYjur3h4G7vIvTTXpwsAcyq9cLsMrMF/d+vYeXB+Wt/DXgH97rRmYsP
         dFNv1uWJXHv/VsQeeusp+ARkHOC+1t+LhbSq9QyQDBz/1ohWYJlLYxhmCmHc0peX4Dx6
         eo/YZJCvNpwyQRYaVw3WB3K+O7xp3+BLf0XnzEke5hCcfDLHQw8RVagG/ZppebN1NQDI
         sYjlqghi5u7Pf+f8p1lgCVb87ZbAKC3AUPPvHj/1BaxJk0S3qyTCfyLGSyKweNaQESwB
         jfiNzdOZDysPd+wrc2aKRkmNADUf681ENsnBAtCJ7Lu2nmBJ7JqKRL0AoR7VvttkL3qh
         oBFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyUpLwO575zm9usa9tx5AwmQX1M1V1aBBLGOTjShnyWrwb0zWyz
	bLITezkPasW/omYRFJwXUu8=
X-Google-Smtp-Source: AGHT+IFABqCMnimNd0Fy8MaSocqMC36LwKgLU7MbXJ3XZHjQNWnwB8CTzuu1kgUhEaJitXogRX2FWQ==
X-Received: by 2002:a05:6820:1b93:b0:589:d3a4:6a2f with SMTP id cb19-20020a0568201b9300b00589d3a46a2fmr9195830oob.9.1700582734759;
        Tue, 21 Nov 2023 08:05:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e82a:0:b0:58a:b02:fee with SMTP id d10-20020a4ae82a000000b0058a0b020feels496590ood.1.-pod-prod-06-us;
 Tue, 21 Nov 2023 08:05:34 -0800 (PST)
X-Received: by 2002:a05:6808:1242:b0:3ae:e79d:79a0 with SMTP id o2-20020a056808124200b003aee79d79a0mr11319488oiv.30.1700582734120;
        Tue, 21 Nov 2023 08:05:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700582734; cv=none;
        d=google.com; s=arc-20160816;
        b=Xti4fYmAgLPqNkRt5ngXnAXfvx/hLmYZox8+9EdOyonSszWdATnsznJpfqoCZgzwzT
         kQXisSK7MMAO6olgibgO48s1JyqngpEddLZ0u/OTmu0CaNhPZUr0hT7QoVQqigIDLST5
         mubEdFRxvp7SRED7WyyHunfPgaKbgpTDeLLRLGLYJwunf+kOHw42ou/yc7mY+fvS9kzt
         IAsFZs5Q67XphnanVDk1O2LtBbYXoK/CqKiC2XKhE9i4hGiWWLpbujUC+3lLRM6j9TY+
         IY1v0Hm66P3gZeeWTUXUPwqLkco66v/nifnUJA37ioP3/WSEviP/ah0VhM1FgKZESSFL
         kOrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=PmJ5foKdCDZg8tIi4TPGeihCrXCC5qbN8sSmRpGmvoM=;
        fh=7HvVTlPu/758q9pyDnsoZecNvn2PrfH9jHqN5+uHZcU=;
        b=G/jWKwKd7o196lZU+qh6Jh2y6EGfrS4ifgi6v2cfn8JB+4zN1JOrhnK/VY7yARKs0u
         crsn4hlZ5prI3IXKZlFMY/xkdaVZbGszP/JHfgg7fKkcpS1d8Webo1FfToPCUGe1Z9bl
         pZFhjf8xPvbAG+kcYDglWf8x1ruuT/524Tx/wwIC3LyKKOVBV2lmnqoSdg3EpOJ/L8n5
         aNYzg93f2qmsefPSx8AahJJiikQsEUCXEnMdFqZ6xeLq06KHVrRiHEr/DQZrzlkeiKdv
         j4esaYtiTYeVvDMLUaJx6xjGxhRPHs14KFEg+YidOc0GS55jZPXnnulstV5fLITSc15K
         Gcvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UrNzPuNt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id gl15-20020a0568083c4f00b003aef18f3442si1063261oib.0.2023.11.21.08.05.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Nov 2023 08:05:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-2839c113cbcso3189905a91.3
        for <kasan-dev@googlegroups.com>; Tue, 21 Nov 2023 08:05:34 -0800 (PST)
X-Received: by 2002:a17:90b:38c1:b0:27d:d9c2:6ee5 with SMTP id
 nn1-20020a17090b38c100b0027dd9c26ee5mr12266549pjb.9.1700582733189; Tue, 21
 Nov 2023 08:05:33 -0800 (PST)
MIME-Version: 1.0
References: <202311212204.c9c64d29-oliver.sang@intel.com> <VI1P193MB07520067C14EFDFECCC0B4C399BBA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
In-Reply-To: <VI1P193MB07520067C14EFDFECCC0B4C399BBA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 21 Nov 2023 17:05:22 +0100
Message-ID: <CA+fCnZfTJwfmO-OYcUst0fsWhRa+MzDtkv1N_bMob9_1BivdJA@mail.gmail.com>
Subject: Re: [PATCH] kasan: Improve free meta storage in Generic KASAN
To: Juntong Deng <juntong.deng@outlook.com>
Cc: kernel test robot <oliver.sang@intel.com>, oe-lkp@lists.linux.dev, lkp@intel.com, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, ryabinin.a.a@gmail.com, 
	glider@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-kernel-mentees@lists.linuxfoundation.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UrNzPuNt;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1030
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

On Tue, Nov 21, 2023 at 5:03=E2=80=AFPM Juntong Deng <juntong.deng@outlook.=
com> wrote:
>
> This bug is caused by the fact that after improving the free meta
> storage, kasan_metadata_size() continues to calculate the metadata
> size according to the previous storage method.
>
> I will fix this in a separate patch.

Hi,

Please send a v2 with the fix folded in instead.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfTJwfmO-OYcUst0fsWhRa%2BMzDtkv1N_bMob9_1BivdJA%40mail.gm=
ail.com.
