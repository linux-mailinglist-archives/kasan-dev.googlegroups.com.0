Return-Path: <kasan-dev+bncBCRJ7M4BUUBBBBWUXWPQMGQEKTN6FBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 161FE69AAC1
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 12:50:32 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 17-20020a17090a001100b00233cc25fc7bsf481829pja.4
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 03:50:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676634630; cv=pass;
        d=google.com; s=arc-20160816;
        b=YGfN2/rsZyod8MNhdrvs3OkH3xJDjNs47cW7B3/lO4M2O15ifQ/dz6rsXkDNu8E+xG
         JM6Gj81Oi+541Q1pG7v0Zaj6lAjsA0be5EdbqiyLbgsR4d1kIkjWqPDXb6yTrRaHxIRl
         z/WZh1YuI7e/Oat4cNUQkf59hy+Jhq5HCPR4nj99IB5E1RCuj7ArePdotcaiKxXIOuoT
         zEjJNXx9PBcz3Gn5LTk0j4BzZ3xfuNvP1aQLgzQKwF8TRa2M5I8mIklbHrsAdHiyPx1x
         NyFdkuEvMQX6qEJPP+vtAk9msfPXj39jQCpOu1N62VvDg7GjGEuHmacRh+LBZ+s9lj0y
         y8Sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=mvLID2swZnA2QMAp4JAvtSyvHektAektKJFUPJmMjho=;
        b=wIMlWX/gMqwJdLRcOXsXhzCtyQHQ0EidMYevVVySltBqH37GWSmIK63RqnmcRMWzMu
         zc+I43CWDKl7njQ5/osl2G8s62PQcmPf5PVK0Xzx7ICxDgkCUbAVP0G7diHJEwkp8s2Q
         T1bLm53ZN81aCq2yahfESEB5ddoZ5pXGemvw7A5UliPFVJLE+jFnDDuBCQfiePXcsxUL
         us8YckvDIqpoxsRmTCvdsYVe41Wq10hZl0q5BJC+mCfsxLjycIcL4HJVhWaL9SJLEnZN
         Pzwy4zIpCMODMJu39SRMUBj6Jujaqd6oRc2tEwG/4SC9XkZP4cW4XfcHhJ1j7Inwx+ej
         tcug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hvqRlujj;
       spf=pass (google.com: domain of bjorn@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bjorn@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mvLID2swZnA2QMAp4JAvtSyvHektAektKJFUPJmMjho=;
        b=CXgDi43pZ0sxw2yD/0ML5BABNveriJK6KjfHpmjhlf6yj6iHZCpOZ8w1369R1TFivd
         bMEdQHc8VQ01Lc8231Y4hU9RishXexkco08h5kBX9SJ0cVLHce/NIXesTAM+I44qRGA6
         3wcPKQTZqTgMqlT6oqYKRSZzmJF59g82AU8MJeK6+2JxqFwTA7MoYrccmVppXFwpT+vq
         484LGB0dGqoTJbTBXvZDfeIBbweezuItEZ+7RnXfmhufiLxoYTwcHyREU5vd80JDkcib
         sVXe0mjSKXxm03JIhVH5kmbm7ZyJLm08dYR2NLW8KNiFdFtMMQF80WCDwsdtjHbToG8n
         O3CA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mvLID2swZnA2QMAp4JAvtSyvHektAektKJFUPJmMjho=;
        b=O3iaQEu/qw1x14/n7GakSRQSQSe7ADLTD2WCi+H2BKrv7DjA+5d8YSb968ylzBWue0
         g4a3SAZcxlTr4ORRVhZdgWw2H7TSGH83MK8n7Z5ltNjeOKK9d0CunFVB+akoHQyiQcrn
         TCt9ag3Veqi4afA9/OZf44bffSIlQJVW5DPkb4qs2LrVKde3NjAR1g54YDR7bT2Lo2OV
         vRwrtmdBQiAlQLY8pHW9Nxg1Z6H53lSOT8w23VKNdaaGVIkCTd1rTv/Kn/HyeK+tyuW5
         8x/07fsYo46c9lGgVun6VR1vYJ5pGEKeknbsRGdqoy0YO4xsccHJw0xbrBolydKqjwN8
         99ZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXlz/VSHfupCMzXl5XaMSs2pXqf4ySu0eOBFzIycko/SW8PnPJ/
	UGvH+sGaUZgogmvkINNpGyI=
X-Google-Smtp-Source: AK7set/3WncVwvIP3VjSiKEqu4euCaMeB3+Lm2PNic156GETR3N1DKY2FITVE5RqGtW7SBIMy5zayg==
X-Received: by 2002:a05:6a00:d51:b0:5a8:c0ee:876f with SMTP id n17-20020a056a000d5100b005a8c0ee876fmr155636pfv.3.1676634630537;
        Fri, 17 Feb 2023 03:50:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2015:b0:199:182b:34bf with SMTP id
 s21-20020a170903201500b00199182b34bfls1678219pla.3.-pod-prod-gmail; Fri, 17
 Feb 2023 03:50:29 -0800 (PST)
X-Received: by 2002:a17:902:9a4c:b0:19a:996c:5c2b with SMTP id x12-20020a1709029a4c00b0019a996c5c2bmr644415plv.39.1676634629809;
        Fri, 17 Feb 2023 03:50:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676634629; cv=none;
        d=google.com; s=arc-20160816;
        b=fdRqlyTvM9U6K1xXLsvJCeK7FORxqmWiSDwNRwpb6tmhK/pUteZmim17a+tO/Pm9XU
         iXaTtYsI52hUZmpJf70C3dBVZWpfeSadf0V4XlzkM9C/omWr+fxEXUQeMkNcgGzkwDPb
         U7WfniwXSSBkypG0vT1h5MflNTKHYiqO9dzayPrmDhBz8cHnKgdhQ5xEcMrX+l/HtLtm
         rYOiKemw0RYxPNSr80EJPUyblG4UU/iNgtK/5Q0v7up3PvkZ1TKVuXaSzQu4Qb9WKT2k
         j9pmR2FYIk+aFIPHAtqpTT5X0Lw4fR9BLaghEBDsB0SNoe+u0AyT/AxEfTShSjBIsCvw
         p/rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=pi0nC2Kwi7q6nPVIuHo+gOwCrLpWrs058kgD1pCjKgk=;
        b=qR//anJHOhuBfKG+DxrcNcSHgnIB8kwQdoCMj9oDrKzE8Urn7KO68loZXObVE2wJxp
         RNHZHzy1XXaj8pABLHoCSxu8PNAC2Nh3/GD0FdMjJhKW59qnh2EWkLtOFU/2rk42uyp6
         wrDOocWEG42496Y/5/LeOR8fArR1Y4t9o3C3WONfwEZdZku3EoWBjgU/MGCLlcuctGYF
         QDFovrmDeM/pLLTALWigxwPyw3OKfFTeM4Mtj6vFs3ddUf7U3UKjMPthTpEzIEwLQ/vi
         EtnNUfC1OhPE3mo+bx53a5ggxG85nYuisua+Yuy7wFUfFXaO+TgOTihecSUzwSTyTQfG
         GTgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hvqRlujj;
       spf=pass (google.com: domain of bjorn@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bjorn@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id jk6-20020a170903330600b00198e7ebaf1dsi221462plb.9.2023.02.17.03.50.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Feb 2023 03:50:29 -0800 (PST)
Received-SPF: pass (google.com: domain of bjorn@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3EC0661ADD;
	Fri, 17 Feb 2023 11:50:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2CEC6C433D2;
	Fri, 17 Feb 2023 11:50:28 +0000 (UTC)
From: =?utf-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>
To: Alexandre Ghiti <alexghiti@rivosinc.com>, Paul Walmsley
 <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou
 <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo
 Frascino <vincenzo.frascino@arm.com>, Ard Biesheuvel <ardb@kernel.org>,
 Conor Dooley <conor@kernel.org>, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: Re: [PATCH v4 1/6] riscv: Split early and final KASAN population
 functions
In-Reply-To: <20230203075232.274282-2-alexghiti@rivosinc.com>
References: <20230203075232.274282-1-alexghiti@rivosinc.com>
 <20230203075232.274282-2-alexghiti@rivosinc.com>
Date: Fri, 17 Feb 2023 12:50:25 +0100
Message-ID: <87r0uotsse.fsf@all.your.base.are.belong.to.us>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: bjorn@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hvqRlujj;       spf=pass
 (google.com: domain of bjorn@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=bjorn@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Alexandre Ghiti <alexghiti@rivosinc.com> writes:

> This is a preliminary work that allows to make the code more
> understandable.
>
> Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
> ---
>  arch/riscv/mm/kasan_init.c | 185 +++++++++++++++++++++++--------------
>  1 file changed, 116 insertions(+), 69 deletions(-)

Reviewed-by: Bj=C3=B6rn T=C3=B6pel <bjorn@rivosinc.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87r0uotsse.fsf%40all.your.base.are.belong.to.us.
