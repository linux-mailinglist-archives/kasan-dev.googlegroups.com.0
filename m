Return-Path: <kasan-dev+bncBDW2JDUY5AORBNEGTSQQMGQE5M7AGCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id A87586D2488
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Mar 2023 17:58:46 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-17afa2c993csf11642421fac.2
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Mar 2023 08:58:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680278325; cv=pass;
        d=google.com; s=arc-20160816;
        b=HUHASjgXt83EPEyFMnbSNVaTyveQA5hUTJ2tOAsZkHvLd0tW+LmIiGX2Ri+wdI3heF
         EBnP/zNgoj7gmULv234auT28VTAj9ToPQwb/0TReBZW4nLWh/RkvnnNqQsWF+zhh/zzU
         /n61bYXHfBl8PvMgn76QXXKgF2zHwXXw7YTOQKFj+H9UqkL7X9DGe2PqyfWp0dNZEukv
         M9FRYpYIGgyHlQHRVF2gS4lLjZKHjq6u0uQInvjHbTT62heYL/XxWAyipPkp58lAe3e/
         GlVHY36dikKqcE111pkThgqR+1JkV6OQOCELK52Xz3/b7BKHr0JCk/EL7c1N/Fi0ByLm
         /Uww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=GGH2FLwoUd2aL1mUjQ3PFMsmk3a5X3U1Y7etN1w91xo=;
        b=I+MWMRdOIyrncoj+ZlCNj3OR/zF964FwA75+xpVIV5vpxq/AmrGCKZQd4C5Yvu8Z7e
         UtqHEqFFy2pyisJU1eaJ1pJPUA7zdpNKm+TX0bzTycpmwcmNG/ZAG5Xgo3TIR3EQ2lrd
         5ZSeTZHRWCi+8yfYgjeeHbfTnVDQGiVWslEkusYTUdhV2yJmo647g3lF7fDjSPAi3mIJ
         7GVLDqBlCqs2LZRIybSlM7bVC41ZLk56gNpVxEZeJVmzblTvna3VxVcHmlZabVkxgR3o
         m8J+AWCcQYvY4CjW7fL8Oi+9pND1EWfdf3TI3a49PSBNuJ2+84bkO1DL2xdZ0OS0cObi
         UWqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=df94nsGP;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680278325;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GGH2FLwoUd2aL1mUjQ3PFMsmk3a5X3U1Y7etN1w91xo=;
        b=iXRJH6ereHuK60NW7PxPBLvuZbSO6ujTbNVdPd0VCj1X3lMwO2H4DTbgLCsmoizl/I
         fPYZ8jcJfkNu5JqWdUcgaPNiYM/fxr4/xG6QsfcoT1wNvOXvbHDQyKvgBoISL2E8pxOu
         m7I53+2jrEihu2mQDz+tbp5Ziv5VPXjKEMssVNAzA9gdiwsTssb6JzBNhKATPp7U4SNL
         5a8TNjOiJOFYhPqSQDwPHptr3skEqFBsdKwJEHxbKuRm8KrDDOg/6l/ZmauhOFtDCQ3+
         27MvViUhFg/1K1Snc0SmJbkgn0dPno+Wit1nWOmJHF2sQBUhu9ck82dqYmAxXgqpv2v1
         D+Xg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1680278325;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GGH2FLwoUd2aL1mUjQ3PFMsmk3a5X3U1Y7etN1w91xo=;
        b=PDMyxMDUe26vu0zf2mLZYCmHnQeQJYgxqGYYVALFWwy3Psg6Af0e02t1cD96zDvUHq
         4yXw3IBdHxXS/b6RBTB5cqdbnJ3vYolusuXXlrjtSo6vwjBwP8A+M33NuuCVn0JaxrLc
         rmeYMo1j3NaCczNutejJnNTb2toe12i82jiShVlVvGRnyP6UK+vTCIYwLMniyzPbKylt
         Uxp0tY2asSsjO16yqEU6KvMuneu/wUb3YqY/TgfM0GpDLOVrgxLnRHblnE2tMcbNgaZG
         nXcYefNeCWazXWz+YgbqVitJ6st/qhU26bNv3knbU62Bv03+J4Ko75ULPGkXehcZjPWa
         +DTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680278325;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=GGH2FLwoUd2aL1mUjQ3PFMsmk3a5X3U1Y7etN1w91xo=;
        b=2LyAH+4DoSJ1T1BDQA1pTcnxIB80/70oo95v8IjB8nsqzHQw0S+EnccLMB17u2Bo0L
         I4BnkymzSiV7tHvk+Jdy8cl1emjH+BaykyqEDLxnmquvQkOq2/SLOOBOsOCykreJqDTX
         xB1UZP6cXSh7mAEW4JqlONW3F3Q9mrGlWmUrN+tqt4K2kicpoWtNyy0kalHpHGn86/y6
         S8avjFusaLxqmaS1MXX2onGt8aIwp8cSQuM5XGm1WiCpCbciWpt9k1gDZKTpgiTBJsqG
         P3+yLljb7TkbvwciP/oTr3ZkJJoPpRJwSgc+4tYSaSc927TY9eMqxJcPDKRTRG9iSjbq
         ox0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXHGXPTKX2SFgEz4rC28bOL9PIkuQyAfotP8vWS5GTyIilCIVnk
	fy+B7lf+h92kylQw6vVGg2E=
X-Google-Smtp-Source: AK7set/udnCME2a0AYCZSMJo1MkDJdp9LgxiPX2U9IDwQpeZf+jtIWupOW26X4334ozj0Z3FosNo2g==
X-Received: by 2002:aca:d05:0:b0:386:a120:4fdc with SMTP id 5-20020aca0d05000000b00386a1204fdcmr7103002oin.8.1680278324998;
        Fri, 31 Mar 2023 08:58:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9a2a:b0:180:2c8e:4c3e with SMTP id
 fo42-20020a0568709a2a00b001802c8e4c3els1349164oab.5.-pod-prod-gmail; Fri, 31
 Mar 2023 08:58:44 -0700 (PDT)
X-Received: by 2002:a05:6870:4686:b0:17a:c2be:33c with SMTP id a6-20020a056870468600b0017ac2be033cmr16520742oap.4.1680278324623;
        Fri, 31 Mar 2023 08:58:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680278324; cv=none;
        d=google.com; s=arc-20160816;
        b=N2AwcBlhIQ5M2Lwrcwbcjz/whx/NpDzvkr6TgNnw7hHOavlc86ilfDjgP7zQuyXowe
         Q/ielx+8mVQ0e8rFpFryfEKeiuxNKspj9taHbGiuyXzzDSwyiwRq+dZh64WvsqR9KppF
         K7aKMInSaGPwUU0edLV+F/4Wlo3uPisoDHPoj9JWM7/Eg8AiKODx2h4F97PDuSYW1ElH
         Cc/1fJFAfGNuWhxoLAQ03KcSFAJRz9Y0CP6QYuNS3d7zP6itmuESq75HM5YBWUEwbc8k
         mF3/jcy40O3bVJTL7mSgTDI43KIh59PSED2mtuDEYfe+uM2NMJykxuayyqsCZnRA8rh8
         KCdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fxJeRCNlob7RdsmYmplWDSRv896kgREUT/PanUMpg+I=;
        b=cKW6isg7r2Xa/qYW59RLBFykokoIuoFCKnymMJPDiWpPHnDCJaN5eWV4pdvtFuf4BZ
         t7ho2he7xj68fZMYIyyf18/kmG4IwOdKxkX96gFGDxYgvcVwwA3br8o13a4pwAiPj01g
         5W8kjALvoXrzs1Lgo2/8HCiE7yhxoxTJNV0gKutBs+ZuST2VyUgSG0auXi3U1vQLCJsA
         hTqfoRXbmBERyGtZ08QgOlS5pM8n23FnTSAugQKboKMoCxJ2NW2RkojqZ3Hfx23q/D+i
         lbPSb+ZPO1TeeCJekTkyqTS9Jy1ndYtbCrkU5z/hJnvJn6qEOza80bv1O7nt9BefnAwF
         b/1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=df94nsGP;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id ma20-20020a056870fd9400b001763813b106si261410oab.5.2023.03.31.08.58.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 Mar 2023 08:58:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id d13so20886942pjh.0
        for <kasan-dev@googlegroups.com>; Fri, 31 Mar 2023 08:58:44 -0700 (PDT)
X-Received: by 2002:a17:902:b48e:b0:1a1:dfd6:b0f0 with SMTP id
 y14-20020a170902b48e00b001a1dfd6b0f0mr9675817plr.11.1680278324230; Fri, 31
 Mar 2023 08:58:44 -0700 (PDT)
MIME-Version: 1.0
References: <20230328111714.2056-1-zhangqing@loongson.cn> <CA+fCnZevgYh7CzJ9gOWJ80SwY4Y9w8UO2ZiFAXEnAhQhFgrffA@mail.gmail.com>
 <dccfbff3-7bad-de33-4d96-248bdff44a8b@loongson.cn> <CA+fCnZddt50+10SZ+hZRKBudsmMF0W9XpsDG6=58p1ot62LjXQ@mail.gmail.com>
 <2360000f-7292-9da8-d6b5-94b125c5f2b0@loongson.cn>
In-Reply-To: <2360000f-7292-9da8-d6b5-94b125c5f2b0@loongson.cn>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 31 Mar 2023 17:58:33 +0200
Message-ID: <CA+fCnZfoTszdoy7o_EfPXOc4QYo_Jgw9Qf0ua2JoNp0PXdrTPA@mail.gmail.com>
Subject: Re: [PATCH] LoongArch: Add kernel address sanitizer support
To: Qing Zhang <zhangqing@loongson.cn>
Cc: Jonathan Corbet <corbet@lwn.net>, Huacai Chen <chenhuacai@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	WANG Xuerui <kernel@xen0n.name>, Jiaxun Yang <jiaxun.yang@flygoat.com>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=df94nsGP;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1032
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

On Thu, Mar 30, 2023 at 6:32=E2=80=AFAM Qing Zhang <zhangqing@loongson.cn> =
wrote:
>
> > I get that, but you already added a special case for
> > __HAVE_ARCH_SHADOW_MAP to addr_has_metadata, so you can just call it?
> >
> ok, all the changes are going to be in v2.

Could you also please put changes to the common KASAN code into a
separate patch/patches? This will simplify any potential backporting
of common KASAN code changes in the future.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfoTszdoy7o_EfPXOc4QYo_Jgw9Qf0ua2JoNp0PXdrTPA%40mail.gmai=
l.com.
