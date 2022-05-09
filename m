Return-Path: <kasan-dev+bncBAABBFON4SJQMGQE42YPXBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id CFBF951FFB7
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 16:35:01 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id p18-20020adf9592000000b00207bc12decbsf5854841wrp.21
        for <lists+kasan-dev@lfdr.de>; Mon, 09 May 2022 07:35:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652106901; cv=pass;
        d=google.com; s=arc-20160816;
        b=eyRNn058KKnUhKo/vg6nzQUppEu9VCOuj0lMO/m71ChJ2HqKMkk10mzWmq+bbecQkd
         OCCCGcgtkdVVLEe/cymIjCvis/XsJaJHOTnMhZOVW2mFrCTivwTg6pnNU/CcjuY1fsQf
         K4cDsVCtbiDK1ArM4rfnnA1+ynXXvHPxRunabWt3GcB6Ev2xO5wZJXdYAH/W0iLRk3VI
         0dDKDN4ObNxR+47VxcWbtTwRlc+gpIFPG1gsMIZiaTN+8A3xv8fXJ1Q3whzX2p8WI9At
         zkYHlRWXAA8HB7Y2/QDkKr+xJiacpMr+vO19zDYegTMQEGV6rFUtODcz7A4+eNra+qBK
         fWSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HBq+KDxmUk5CKowqBWAivfQ9r/7QuXdEHLsZ7EAfZz8=;
        b=Z3Wab60vvn7EzZ/zOBNfWw4bqEtsFsIFzd4dpNp+F/zm8KTozsJAakFqjiD4ZBnJNc
         EqDCRjd800uBmLuLqJqdey95yj61J5XlM8LMECXV78uJyWD3DJkUCqi+oM8unPErciEt
         xgd02yISBqPPcxjCnC1R3gSZRKg31AoI6fGrBrDIemG73DrY4Zc1a+PNPh5Ne42NetID
         WQZlE7laMAfu62dH7pEXjAJG4PISphEtxteTpc386UZZA96OyvGXGZ8iSqKfMDOPsiEB
         meGkNfJrSfkgtON4TFD3qhYmLVt7YkVpk20Iu8XrK+J3NKnyhOTDTnF+suw87Dz+0ex/
         gxvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uQMwhwbU;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HBq+KDxmUk5CKowqBWAivfQ9r/7QuXdEHLsZ7EAfZz8=;
        b=Ny2HQXGgoACFn3Q9gE46O12+NLJUj3KQGSBv4F41wKRXi8WdMYVLO1ska5Vf6p7YlH
         rYEUIObq5XtmWXH4sZGfx61pULrXMlbJXQ8RmqvkQ7DdDRQpcqkGUJhb1KTg0cOu/DHy
         Tyyi+tj7jT/BIb9qc4x7IhTc8wVeYHaj6VBpcBn7RPc54y3rG/KKCyq3iJUdcc9kcvMG
         mK1xwCJ9fDXIfIddShHUQ9dhZWKTPATXglQu9J9Do9vBCDjIQCunoJJKuAfK74jOykzT
         fMUqjKdP4xf4Z+Dtx2Sz9OA6MiypQI5H+G6ykfl0OaFq5YnoY9+hMZXk7bVR4jOQWjRc
         Lspg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HBq+KDxmUk5CKowqBWAivfQ9r/7QuXdEHLsZ7EAfZz8=;
        b=Y+pg+kj4zYrTv3F8gB5msTc3lg9g1msPUppAJuxSM0F6pZQWP94jCToFJXraBTE2on
         8vua1jCP29WSH6x62bTgzdarWovt8KAE8z6XvHtNSSGNVz1J88kWdigj0MYlgNHXVoQG
         fJSCvSkI1aHz5CYeXIqVKzQRzBmx45f2SFp9cstPRPgY56EkEYYvfzpITva4tpbRETMf
         Kq44kMCfHC6tveA+pnOZ/vLtygiDscROJUFItHTqu5B6JjfRqa1oqg5j2aL8OiV20+gx
         m20koz69c0usNPuJ3AGKF+u1VXL/bA8TwQzX89dJHnVsShHEqGDqXQ8V/oBpuGMF4o9b
         0XLQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ZiBSlEibJh8CHj4DSKoNhcbyGCh8IHuigQ4dgeyzh24hESu82
	kIP37vaIrhmcrQLK3GaIlUE=
X-Google-Smtp-Source: ABdhPJwtHqNL+1JedFgqlqLT+v2t5FICsV5DLBSX/2Q5AajAo1rIjQWhiDg85+Dd6SdIzdatUWwBYQ==
X-Received: by 2002:a7b:c93a:0:b0:394:2583:69fe with SMTP id h26-20020a7bc93a000000b00394258369femr16757082wml.29.1652106901352;
        Mon, 09 May 2022 07:35:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d9f:b0:394:51e4:7b18 with SMTP id
 p31-20020a05600c1d9f00b0039451e47b18ls4021719wms.0.canary-gmail; Mon, 09 May
 2022 07:35:00 -0700 (PDT)
X-Received: by 2002:a7b:ce04:0:b0:394:1f46:213 with SMTP id m4-20020a7bce04000000b003941f460213mr15866434wmc.157.1652106900682;
        Mon, 09 May 2022 07:35:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652106900; cv=none;
        d=google.com; s=arc-20160816;
        b=0jd9J8t1ckc/PX+0cLFt8PdZSAkq3kTHV7insG6r07/jwEJvJPiiUy674ibCmo5m/0
         NxC6GsEMml/hVtIf+L1hFQsDCG9L1J6TKLDzXOj86/ygkXwVTzpGyMsTSxsiTye2UsIX
         OpklTKCO9WInHIwVm1GnwlCX9P7sGckz3g7go9iaXn85Y5/Xiw/pgOxOlMvdi01/IKcW
         Gev8zP5o2LcTh1b9hCULojRIYKxmshdFk0pzoEoM2ljtN1mKHEIeVplvhqziwT4Kq5za
         8WNoF7RdLFg5Zgnlqs9Dot53TQIoeSjLP17FP5Opc6c0nrL4gH+8SZ9VtA7ITYbZdi1H
         cjsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JxWO5ZAfWG1b9Ir0Kan5l8e1N7bA7LtKXbJugSvIxVE=;
        b=JQGtKbcwWih2UsfonTBpXm7icWuRbhhYKIfx6NLWIuR4gPfRqrpgvz3NwWbUD5374W
         Z54bwbEGTdXHYRx/2/zuLLVWR2JTelQAH1rG/N5zSc6TPlHaXuI7ddhwUM8uH12j/xPr
         lorDPn8QpLgqyLIRyAF1gLq5vBn+wV+n16ZyrhrDiGcb6Rv1/KNMXR2j2lOtGVU3nzGh
         /icczUIMeTwOzPI3ucEw9+T2EkjN/s/1ONrZbTBm70VErWsPboJ4M46Km7qpKubJsSeq
         jX8VV9ZYVU5tZ6CD3gD3Kp3Oobh49msIZ3yfAEgQxsVcqTfE2+g15WZwH4q7380gzSrH
         o+mA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uQMwhwbU;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id w1-20020a5d4041000000b0020cca58388esi101199wrp.5.2022.05.09.07.35.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 May 2022 07:35:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 4A825B816D6;
	Mon,  9 May 2022 14:35:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 43AC8C385AF;
	Mon,  9 May 2022 14:34:54 +0000 (UTC)
Date: Mon, 9 May 2022 22:26:20 +0800
From: Jisheng Zhang <jszhang@kernel.org>
To: Anup Patel <anup@brainfault.org>
Cc: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	linux-riscv <linux-riscv@lists.infradead.org>,
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 0/4] unified way to use static key and optimize
 pgtable_l4_enabled
Message-ID: <YnkkjC065kCTtHBC@xhacker>
References: <20220508160749.984-1-jszhang@kernel.org>
 <CAAhSdy1qri5L9pVcZO8areB=TXMSJBg2+cTNMZGQ3g+3Qhxmfg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAhSdy1qri5L9pVcZO8areB=TXMSJBg2+cTNMZGQ3g+3Qhxmfg@mail.gmail.com>
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uQMwhwbU;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass (p=NONE
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

On Mon, May 09, 2022 at 10:07:16AM +0530, Anup Patel wrote:
> On Sun, May 8, 2022 at 9:46 PM Jisheng Zhang <jszhang@kernel.org> wrote:
> >
> > Currently, riscv has several features which may not be supported on all
> > riscv platforms, for example, FPU, SV48, SV57 and so on. To support
> > unified kernel Image style, we need to check whether the feature is
> > suportted or not. If the check sits at hot code path, then performance
> > will be impacted a lot. static key can be used to solve the issue. In
> > the past, FPU support has been converted to use static key mechanism.
> > I believe we will have similar cases in the future. For example, the
> > SV48 support can take advantage of static key[1].
> >
> > patch1 is a simple W=1 warning fix.
> > patch2 introduces an unified mechanism to use static key for riscv cpu
> > features.
> > patch3 converts has_cpu() to use the mechanism.
> > patch4 uses the mechanism to optimize pgtable_l4|[l5]_enabled.
> >
> > [1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html
> 
> Overall, using a script to generate CPU capabilities seems a bit
> over-engineered to me. We already have RISC-V ISA extension

Not all riscv features are *ISA* extensions. For example, SV48 and SV57
are not ISA extensions. IIRC, I asked this question before, here are
Atish's comments:

https://lore.kernel.org/linux-riscv/CAHBxVyF65jC_wvxcD6bueqpCY8-Kbahu1yxsSoBmO1s15dGkSQ@mail.gmail.com/

> parsing infrastructure which can be easily extended to support
> static key arrays.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YnkkjC065kCTtHBC%40xhacker.
