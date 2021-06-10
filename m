Return-Path: <kasan-dev+bncBD6MT7EH5AARBUMARGDAMGQEOBGT6BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4445C3A30D6
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 18:39:46 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id b10-20020a170906194ab02903ea7d084cd3sf61698eje.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 09:39:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623343186; cv=pass;
        d=google.com; s=arc-20160816;
        b=LZ7C870DQHGkg4E9xLoUJ0lkhubn4DGzHhPS+BFV42YYjtgSMD8l3QKBPXeJ6kDjvu
         vTpEConS97eIxyt5AldnyC5VIoIltHitOjL6zcRuEs8cKw439HomvwNa7Tz0IWvd/D4Y
         1oXfu4aeNV70tlOGZWBi/+Jf+XiLk5J3XXR+M2fvCnHEo6+lzvtvjObexfm7FzhQB1OJ
         DACRp4FVkkVbk+yrlhJUZpfRwtDFVMnVtOq0EyJtYKzOMe/3fOZNJrNKN3xw3gsaBo/z
         Ne55FUXmahUHLABygJkqSWm3IOIdsH0jtgYX0qSfj2QmcFfZzSPLCZYi3N1WNxcQ7puM
         tsWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=Fivcc26b0S2hpOJ8I1oqtOs72tlnENdjPAn4bDirDEI=;
        b=aEbxUjAP7hrq2+fCQKaxKyRHv8UhPFRgz1EcfHEhsZgFOEsgKwpJwuf9V+DBdZeAbf
         0OXRMbMPHhwKKPMJmQ+EFws3xEMOW8WN4/pGHp36RACmbzKwu7chUt1htlk/8oiXCNFX
         jvR9nT/YTXVigqwdRvEgCYb/g1K7+H43X5ciGBa2dvwcQ8HtSPlZHcVm3fZfcug/xVQ3
         j6P/XuHwjQpKH1QzZxLjJ5x8fJ7nOi2tDY7aqlkULJojtNAS7SEC4KqfG7RcBA5AeftY
         GDUcc7m6eTMk/laHU6YFZQ5e/+qmQq4tRZozuyaAYCnA0X0Ibi41GLxyx3IY6ofSpsMZ
         q9IQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:references:date:in-reply-to:message-id
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Fivcc26b0S2hpOJ8I1oqtOs72tlnENdjPAn4bDirDEI=;
        b=XsLejd64UshBAu8N2J0CoZTBkQZo8ZuMlVetVIbz2yR948LtrgeUwQleRHXJ3CvF4D
         6XeC58syeLF0D/jrvAv09zT6jxmKP07jyBTH00CopSAnQdWd6NKFUz9Qto5M1S3aIoW4
         RDdbu1lxrHy0+QXm7Tex/ZhJcjii/InyoHVV0Dp+Hi0pOocHf8H4A0xv/Dnq45MuMgsx
         dbkeJT949wqdprlhBACdOlcFK7dPhD+yJ+sYwsJ8PsaHaPWaLo64KJDfAqlx2zlcebaf
         zoLlNHH7SrlVy1cZQK+fKMj5lb2V54tT048Snys39qOh6Zitr8uzBQh7jrmbrONsLFxV
         9Lzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:references:date
         :in-reply-to:message-id:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fivcc26b0S2hpOJ8I1oqtOs72tlnENdjPAn4bDirDEI=;
        b=L7nRgnCvckaEW539t+36tX7QG8zSFO+NRXiwUZ5MLX2nLxN2Y+/+XfEZr1T7fthWwn
         yDGuQS4AJiDFzrEF4uwyHeFihulqXJ6Yo+7o4O4lN29UO5CFCWVwxsfS9qL5svxJNziX
         D1gvC3JFg6LOGmL595gfBuwWrUxu73sbwAOmCGw262bcM0YWjmVTvXDyIWp34NCUy1AA
         9NM81soBeVgZzT6IiAiF1h/MBn1v+nsvTVUUW98CNweE8ucOq12TG/ZXKj6kvT/IuojS
         blB5J6DtRPW90KavDoH/CaMWNKtrtJ3A5T8YdKr7xq0C/1MrRakWQwObJxTpGiHthkmD
         HH0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532KjR6HbCAT/BcjO9IEposhNV80wQV2I9KrjrL9AfTUbLrT4tZb
	QO+k+ilhEEADx1FKtYDd3Fg=
X-Google-Smtp-Source: ABdhPJxfw7KZSTcTm6SDazsk3UtXES8Ey+1tRYC1rYLC9qvS5P9JoooUWRm1tdGlY08F3ODR3OVpjw==
X-Received: by 2002:a17:906:4ad2:: with SMTP id u18mr451098ejt.197.1623343186022;
        Thu, 10 Jun 2021 09:39:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:30b2:: with SMTP id df18ls3284385edb.3.gmail; Thu,
 10 Jun 2021 09:39:45 -0700 (PDT)
X-Received: by 2002:aa7:d304:: with SMTP id p4mr352537edq.29.1623343185126;
        Thu, 10 Jun 2021 09:39:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623343185; cv=none;
        d=google.com; s=arc-20160816;
        b=xU1E22Uzwff22CsVWEdnHXayxc83vxGMl/fG5WjzhJbQdKvsr8TeKPHIPV+3j8WtVA
         WRNUxbnEmNC2k8/Y15NrohHW4Uzoxep5agS1coPyf+fRROqO3HE99moaSLM9fxBVleht
         BhatG5NJtvrM3zyaaz25LN4gU0bVTkqGR7yWp8Q7rJBYEweYeR05Jlr8nKW1HsmhU4Vu
         fLJE0HPo5SND0WRjznTMJu1bSa33MZMqZBz6uAhnTLyfnTzPMWboZpvuqFHtYCLRGVvV
         27ulKkUrqztfb2AbU6cCSaK72v+MwdFA7RE35yTWAxIdeJdrgpUH0RLEduglB6u+Owo/
         V+gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from;
        bh=XZOUkebxC0IK8WTFTptyLueEjI5pCnNNYOgVZqIPwTw=;
        b=agjjgozr6u3rm/rKoci3R+FNitKB+YKmF86X0y+hHR28L/pQYHgybNN4KGjgW5wnaJ
         QYJVKGe/261SLQCUh90bpGLpcQH2RXWGxeWSQcDxGZyOFToiZHuZlhkwe0pCTze3Bn3C
         /JtROQ5OKNda4ACBRhCqiOpIT6wYyKispON3Tr/fOF5bd1CITjCu7XS1YxvSKiSc9pPR
         6Pt5qaSR85joGAeVMy8DJzyY43YTg0YJV/zxRcs5Dc8ZiDhjcC7pDinMFQfRDfGuZ6JJ
         BYfDUGDfAn0AWtGIiTgX2GfFzGj9I7+fD8jh9EIZG7mmDVXqtHVTl8IrwqRLjP9KL80q
         sB8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
Received: from mail-out.m-online.net (mail-out.m-online.net. [212.18.0.9])
        by gmr-mx.google.com with ESMTPS id s9si194991edw.4.2021.06.10.09.39.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Jun 2021 09:39:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) client-ip=212.18.0.9;
Received: from frontend01.mail.m-online.net (unknown [192.168.8.182])
	by mail-out.m-online.net (Postfix) with ESMTP id 4G18p640mYz1qtQ2;
	Thu, 10 Jun 2021 18:39:42 +0200 (CEST)
Received: from localhost (dynscan1.mnet-online.de [192.168.6.70])
	by mail.m-online.net (Postfix) with ESMTP id 4G18p626MNz1qr43;
	Thu, 10 Jun 2021 18:39:42 +0200 (CEST)
X-Virus-Scanned: amavisd-new at mnet-online.de
Received: from mail.mnet-online.de ([192.168.8.182])
	by localhost (dynscan1.mail.m-online.net [192.168.6.70]) (amavisd-new, port 10024)
	with ESMTP id UWj4Zzhp75L1; Thu, 10 Jun 2021 18:39:40 +0200 (CEST)
X-Auth-Info: uOvEB6x6tEBbFu4rjQpXHZh4ihXcEo6qHZ3hLcNwGzcQDLB3o4xhP8eA0qGjKLTp
Received: from igel.home (ppp-46-244-161-203.dynamic.mnet-online.de [46.244.161.203])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.mnet-online.de (Postfix) with ESMTPSA;
	Thu, 10 Jun 2021 18:39:40 +0200 (CEST)
Received: by igel.home (Postfix, from userid 1000)
	id 031D22C36A3; Thu, 10 Jun 2021 18:39:39 +0200 (CEST)
From: Andreas Schwab <schwab@linux-m68k.org>
To: Alex Ghiti <alex@ghiti.fr>
Cc: Palmer Dabbelt <palmer@dabbelt.com>,  corbet@lwn.net,  Paul Walmsley
 <paul.walmsley@sifive.com>,  aou@eecs.berkeley.edu,  Arnd Bergmann
 <arnd@arndb.de>,  aryabinin@virtuozzo.com,  glider@google.com,
  dvyukov@google.com,  linux-doc@vger.kernel.org,
  linux-riscv@lists.infradead.org,  linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com,  linux-arch@vger.kernel.org,
  linux-mm@kvack.org,  Guenter Roeck <linux@roeck-us.net>
Subject: Re: [PATCH v5 1/3] riscv: Move kernel mapping outside of linear
 mapping
References: <mhng-90fff6bd-5a70-4927-98c1-a515a7448e71@palmerdabbelt-glaptop>
	<76353fc0-f734-db47-0d0c-f0f379763aa0@ghiti.fr>
	<a58c4616-572f-4a0b-2ce9-fd00735843be@ghiti.fr>
	<7b647da1-b3aa-287f-7ca8-3b44c5661cb8@ghiti.fr>
X-Yow: Quick, sing me the BUDAPEST NATIONAL ANTHEM!!
Date: Thu, 10 Jun 2021 18:39:39 +0200
In-Reply-To: <7b647da1-b3aa-287f-7ca8-3b44c5661cb8@ghiti.fr> (Alex Ghiti's
	message of "Sun, 18 Apr 2021 07:38:09 -0400")
Message-ID: <87fsxphdx0.fsf@igel.home>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.2 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: schwab@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted
 sender) smtp.mailfrom=whitebox@nefkom.net
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

On Apr 18 2021, Alex Ghiti wrote:

> To sum up, there are 3 patches that fix this series:
>
> https://patchwork.kernel.org/project/linux-riscv/patch/20210415110426.2238-1-alex@ghiti.fr/
>
> https://patchwork.kernel.org/project/linux-riscv/patch/20210417172159.32085-1-alex@ghiti.fr/
>
> https://patchwork.kernel.org/project/linux-riscv/patch/20210418112856.15078-1-alex@ghiti.fr/

Has this been fixed yet?  Booting is still broken here.

Andreas.

-- 
Andreas Schwab, schwab@linux-m68k.org
GPG Key fingerprint = 7578 EB47 D4E5 4D69 2510  2552 DF73 E780 A9DA AEC1
"And now for something completely different."

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87fsxphdx0.fsf%40igel.home.
