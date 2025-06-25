Return-Path: <kasan-dev+bncBDAOJ6534YNBBAW757BAMGQEMEIJWAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D08DAE830D
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 14:45:58 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-32b316235a2sf27428411fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 05:45:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750855555; cv=pass;
        d=google.com; s=arc-20240605;
        b=Rb1Km74XwgDw7miYzNR/+wCldjXRVfQX3c5dnbfpdg1215aMqXaqEkoBp8oi0d0Fn5
         4PaJv4mBXd5CAM+UDZLoaiTRnU3jvYn+MBMu81flri6UPOM2jXcttyvWjm3kOLAaAOTr
         9bavFHJIMogyJ7ZEiY48fjG3YuT2xH/P4Csc0Idw2xBBIVkkBlAeiV9Q0KrDRPyyTA69
         a0A8fJ4NX46nSaB41XiPwEL5stSOe1JKhSYTa4H38TMsppmBw4y50DeOvfIMF0u9pL6v
         RKcBmBvvZbP+YqJrm8PDxzp+ZdXBp4OuqoM5lHVtnOAlkMMKuWwQK0SuGiPxUjOjcFX4
         YMRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Mgk4ZmEZDd/yoYuMcoMYi/btIsKS5cA92dJwYnaJtqc=;
        fh=Reyh7V6sMAjpx1Tu6AVDiWoxPblzygS9v/lSUdLlvNk=;
        b=hNNJe5gfCu+0vmjUygXDTcUZZh0d4p+RaWpSCi/7FMv852h8TjaL3nfX5S1zbLjlC7
         /iOxHecJWH+dUNjXtZP9D7xV72tLmhk2yeNhkwKHPeiDx4PbQP5S3AI8bk7tbJLenrgN
         OLZ8lA31p6kd8ISemx9ld//Msxfa4TsAbvPKZyjZ874SQfFIYHZ1nzaXneWEDoIQ/H27
         v9V0kRBApZc7JNBQ97VbN2hKE50Q/RqTVGapUUZ0JJfFwHkFhP9T0RYB/iWNEnwmGhIM
         P+NFadC+tOsAU5RW9Q9vlcDreaJcCRYuY/5UoXyHZXOL4dQZtTTIw8G3IKFgDqzXrHBq
         rKIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=U7EpCFwq;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750855555; x=1751460355; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Mgk4ZmEZDd/yoYuMcoMYi/btIsKS5cA92dJwYnaJtqc=;
        b=TClODzwbFengLCXK0G1b9HrYcoTn0qfgN+iixe1apkqDJWUV6xaTr9Fv7LcOoJqgxZ
         zpZV5gM46dI+ULgZB6EODSh88lP9k/GczfZ6WCFNHwafQJgBT7iZCadVuTyn1jk7ulY1
         FxqwJ4nVQJM+e2Ic69WbBZ7/ylFi/4yufYpVEFT1l7TfedOF9qHHw64zQ2zLluA20Gmm
         KkfxwLbcraCOWRLKUA1QZoj69oysLPyGBXDF15ruvJ8o7VrHmIPRZtOKcrjhmn4XDAhg
         H5vSJ53OwPUHnvNlmP6gqpMfCkzHPTOiA+o3EA0R3+rglQF3Vpg06rtZ/C1hFNIBRbN/
         f11Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750855555; x=1751460355; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Mgk4ZmEZDd/yoYuMcoMYi/btIsKS5cA92dJwYnaJtqc=;
        b=PIN6FKjT1jwMHOUV9xGPraJNS1WDgoGxqKaIDDYI9k7ITZbF7+IFT4i5UCuIGigo9z
         8hvLPOzAaIyulECl7WbQsB9Atjr3kLnygaBIE7P4ID9xz5lvRVGuFJhaSgISte1aJpr7
         avG01eJuhSfJ36pMwhvrvVAC2KIyBboaEc0v+AIOoeZaEth31niFh6aWoNLLVMKxqfu2
         ifVgGHDeqIuyUl/e61ozTW/urRzdzJvFnSO1v+4Xc368IWViUF5A2tM5H/v01txXoc9y
         eBMXnNO5dadWEANxGZoGlao9zSdWxx8qL7Nhg3A0ohyO0o9GMXwGsMPkFnkOnXpXupO4
         ijCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750855555; x=1751460355;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Mgk4ZmEZDd/yoYuMcoMYi/btIsKS5cA92dJwYnaJtqc=;
        b=bgXJ2+5en35plH20R4CXPgFsfYUsNQm5yLHdxgFRQUJVPqrL/L8jPh1yNQk28P94Zh
         /gT56jx3FFe2xXKg0td74+u2a2w3Mhq3I3GQ7/Xt4OzudI7ebDwvFNfLzLRT5xlMhIcf
         /JL4qjZTq18D2mHEtheFbkgqdF0Jf9cY+6O1vF9tVM2++RcfbFKr/2uijr+D0I6skk0E
         GTYXIeSTKVSTe9+GV3MyE39Lq/vIeaRMuOKBoOjGdT/iHVI6cDf9BsN7622unF28R3rS
         /JRXsURErQyjLp0bajDBbeOA+6bD0TIwynF9RR+XImRPPzKbrMLTMMsWAaLFLeez2TU3
         9GMA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXBAObnPb39vrcvPbyM+pTu2u2HFBLpaS1FT7unBE76TBFynm6rwZBVrTpJZrb+p+o0sYeFhQ==@lfdr.de
X-Gm-Message-State: AOJu0YyGPaQxPbDl34mEXkspRr935/gIlCQaCgyH0s3TMIG95i/UTA5x
	oGYGCGX8+ZLsl85sZMy4+uYiiLIFOYRDFG6AAKp/o/Q9LCr0vdyZJylK
X-Google-Smtp-Source: AGHT+IEzExrh5J1FaRuik/RCl4vAN1dJmjA0XSPyBexqGqh8a5Wtj6oayqFj1F1wrFg14aSlYybIDQ==
X-Received: by 2002:a05:651c:515:b0:32a:7baf:9dcf with SMTP id 38308e7fff4ca-32cc659f6a2mr9755901fa.28.1750855555164;
        Wed, 25 Jun 2025 05:45:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd/Yy/o5dh7sqk5MVUCy50iQaEumcL7Sfey9KjmLyJOpA==
Received: by 2002:a2e:aa0d:0:b0:32a:8058:e2e7 with SMTP id 38308e7fff4ca-32b8970e87els13029701fa.1.-pod-prod-05-eu;
 Wed, 25 Jun 2025 05:45:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWqS3OobUtaQJCZTb9RMjPl9T35V9uhzKUaQ/bNnhOKJOJlsl3Qol0Hba4BNUZ0MJSkk6s6ORqc9v4=@googlegroups.com
X-Received: by 2002:a2e:8a84:0:b0:32b:443a:a18e with SMTP id 38308e7fff4ca-32cc6590acamr5887841fa.20.1750855552578;
        Wed, 25 Jun 2025 05:45:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750855552; cv=none;
        d=google.com; s=arc-20240605;
        b=R4sJg29sXuyHdB8K41ihq3foNwSNRTajZkfwd4VGBkbfmr9JJ6WVvhmWjGJ5PZaH2i
         5wZP3wpPs/Nr5Md3/XPYsdypKi5nO0oZF55iZQKcpwy0W0pWtXmjDMtOhAiWCzj0E2qT
         jzvRwbOSmhgX+lf0YotEVs/E1qPRrJi69PIg2xTBiNS2e6qGWkHLgwdzHA+LuZaJxGaI
         GHUzauk8xN2x+9lEAjd3lNKAmDw0VgMToQcU/XDJVIe17DQu8YhKM3jnwxhdynJvim1l
         vAHgwEBUaFbS8EZE9Vqrr6VLG+mVaOcVeolu6KSjQdYZ+FQjVbph1nOfN3cHKyU51LbG
         rrrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=aeUHbst5u6uAyR1ycfeU07wkwThxzbqj2XsMrc/HWnM=;
        fh=IqQxJVUoJztDP51WSPAvgQAPzoUwT5dROcJSjY6I8/I=;
        b=hh3mEJLgt08TodbeklF7oSMB9Xx1xHBxImCw1Q35n+oTY3YYqBWH/yPD8B74G9iDmV
         m2tajVXNKmB8R35D0I27Kqnkfu4CGfsbyBl60lmDNyEgAns5q1hCPsuiPaGbaZxaCanK
         AiB+QFl1w8B0DtHdHL+hnPwZ79eQ+mYEVosbpOi3utXKvQBW6HvY9LUGHEzeqlORJX4j
         QneP4M6h02NYytLps1XKnIvyn6OInwDCeZ7CdcvuYfgHV2HKxetKingDojwV2xzkhQj2
         rQQV3v6QqmbG40SUEy/AcVWm9BwyRektQn/HIdej1VDUqtShWc2T/0oD/5xAV3NLuZAd
         i8lA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=U7EpCFwq;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x136.google.com (mail-lf1-x136.google.com. [2a00:1450:4864:20::136])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32ca8510e29si1149621fa.1.2025.06.25.05.45.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jun 2025 05:45:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::136 as permitted sender) client-ip=2a00:1450:4864:20::136;
Received: by mail-lf1-x136.google.com with SMTP id 2adb3069b0e04-553b60de463so7105735e87.3
        for <kasan-dev@googlegroups.com>; Wed, 25 Jun 2025 05:45:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUGrF6cu3Zv6F/Tj3fe3CjZ+UlTF//sVRQlVgDgg9WfzNChRkX45ntbG4KD7jmCZUI7nUrLGNbuoh4=@googlegroups.com
X-Gm-Gg: ASbGncvWBB6YGILbuRfWxsjR2Hv2pkweQdPaZpTjYm1xkkvR9nA9OTZ0CCCLILJf+TF
	EGM0GQWl4qnUrYG8JBrv9GRv1pSS5XOpTyrm8sxO30LMNMhuFz6ube3qImT1io6oKL5fjfCT0cV
	HfKS+ahqCZx9p+J3sirstWYA7XOFotlzpxQYaVF9MIMw==
X-Received: by 2002:a05:6512:1591:b0:553:abe6:e3e7 with SMTP id
 2adb3069b0e04-554fdf5cefbmr869898e87.47.1750855551832; Wed, 25 Jun 2025
 05:45:51 -0700 (PDT)
MIME-Version: 1.0
References: <20250625095224.118679-1-snovitoll@gmail.com> <20250625095224.118679-10-snovitoll@gmail.com>
 <4d568111-9615-4fba-884a-f2ae629776fe@csgroup.eu>
In-Reply-To: <4d568111-9615-4fba-884a-f2ae629776fe@csgroup.eu>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Wed, 25 Jun 2025 17:45:34 +0500
X-Gm-Features: Ac12FXyn774raFC9M0P_m_Yp5o7tYNYYaJPlJbUzpj4u5O7z5JIOhc_ux4m2QSg
Message-ID: <CACzwLxgVj3YD5faPj=09Z9e4WSEe-sD7Sqn4jhaT7eiePaUUMw@mail.gmail.com>
Subject: Re: [PATCH 9/9] kasan/powerpc: call kasan_init_generic in kasan_init
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, catalin.marinas@arm.com, 
	will@kernel.org, chenhuacai@kernel.org, kernel@xen0n.name, 
	maddy@linux.ibm.com, mpe@ellerman.id.au, npiggin@gmail.com, hca@linux.ibm.com, 
	gor@linux.ibm.com, agordeev@linux.ibm.com, borntraeger@linux.ibm.com, 
	svens@linux.ibm.com, richard@nod.at, anton.ivanov@cambridgegreys.com, 
	johannes@sipsolutions.net, dave.hansen@linux.intel.com, luto@kernel.org, 
	peterz@infradead.org, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	x86@kernel.org, hpa@zytor.com, chris@zankel.net, jcmvbkbc@gmail.com, 
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com, geert@linux-m68k.org, 
	rppt@kernel.org, tiwei.btw@antgroup.com, richard.weiyang@gmail.com, 
	benjamin.berg@intel.com, kevin.brodsky@arm.com, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org, 
	linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=U7EpCFwq;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::136
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
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

On Wed, Jun 25, 2025 at 3:33=E2=80=AFPM Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
>
>
> Le 25/06/2025 =C3=A0 11:52, Sabyrzhan Tasbolatov a =C3=A9crit :
> > Call kasan_init_generic() which enables the static flag
> > to mark generic KASAN initialized, otherwise it's an inline stub.
> > Also prints the banner from the single place.
>
> What about:
>
> arch/powerpc/mm/kasan/init_32.c:void __init kasan_init(void)
> arch/powerpc/mm/kasan/init_book3e_64.c:void __init kasan_init(void)

Thanks, I've missed them. Will add in v2.
I've also found out that I've missed:
arch/arm/mm/kasan_init.c
arch/riscv/mm/kasan_init.c

>
> Christophe
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxgVj3YD5faPj%3D09Z9e4WSEe-sD7Sqn4jhaT7eiePaUUMw%40mail.gmail.com.
