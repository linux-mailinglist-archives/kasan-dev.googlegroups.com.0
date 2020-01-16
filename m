Return-Path: <kasan-dev+bncBCMIZB7QWENRB6OHQDYQKGQE53XMCNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D70F813D622
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 09:51:06 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id v188sf8157623vkf.10
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 00:51:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579164666; cv=pass;
        d=google.com; s=arc-20160816;
        b=KNLy0+S1ScvtNOYB2abgASZR1CoMlzhCz7AerVhiibASF7yCOF76rvnKxg/oQLg3YE
         o17GGo/LvJodR7bVUJBMu0vvNkkeQBmqwCFY3n5YTiuT8IgwTXEX2vI99OdobrSfj0Fc
         qdaZR0wJhWHKeT41YZIorHbULR+1HpZLbrLB+nLLTrrB6qNe00/RnNnRCDzUqg/UVkIo
         6DUwZjOgRsTZTPa34nb67Pl/DpG4PVxtcDfWEMqk7IwivL+/tEjPi7QIwvjSiPL2vmac
         9qtB6+CQP5S4aQJt0BtVoWh2n56qrnjmkhysMCZ4zKivExzatxmKLJ3grbo9ADgbHM8n
         p+qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bjv5DyHUKwOc7PNWe0DLjsQslTSn87ALDaDfg/YpCL0=;
        b=qr5pPV4NlIhHAIaaSKvqu+iYa1i+NReGIxCy2iSBIXmMSltUjuq6FqQlMFUhSWIfWZ
         gWxCdxwgesWz18W1JxUbSgCLo/U9INPPfQ4P6K1guzjk1ExHHpHubWRYNK4pCzTVjf6/
         IlENn5WDhgEDhtfOgnESPqZP7ryenkQ06mVHWZJMrFdp47W/gn9ttC58v3X31GqmZMHG
         j3yTwFIUm5VOhOVyFkC52aBWbZE/ntjMbDy9HHE9sJEDEfE9dAqosZFERdVMDLSw+XP3
         bgCQvC35vbUGxmJHKDKTuPRita801tIQnZgUAn9gOVKYuvc/1JyPtb8K6lZcssBIi6pS
         8BaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cEP6hLoU;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bjv5DyHUKwOc7PNWe0DLjsQslTSn87ALDaDfg/YpCL0=;
        b=ZgoA0ABLvFCaaPVKb47BOfh6tn4vX+bwQpkAtKebJVa+9dzll+xoFG6OIHqBcZXvom
         y74/FY7HGKSjikzwehOvrHd/Ra+6KFZoQwVHyv+UzTgfzt/YgZ/kOoDzkrqpVNeVVDAm
         5wAucrojRosqGHinupJm+DOP5Fvj1APaWYn9rPzdEsd72lxuh3+gXj97tOaExfF7dVVJ
         qROTYVgMaiTQ3YUQCrqdi42i6748jX+aBFfLx/AIftjrUjT1HjzySrAU5l77HJQrG1W1
         t2NNvONTD/PmfqF7BWX54O3/QQlz+3efijVvyqdrBm9m9aIWjc98Eze8oRjB71Aw00Vd
         5EPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bjv5DyHUKwOc7PNWe0DLjsQslTSn87ALDaDfg/YpCL0=;
        b=tkFXCq5uItS/X8k/+BoeZNsC6OIfACiOXgu2ZE7LPO0i9WqYcxUCZJ5BeQJaJC8H0y
         6rARhpeyN/ogSDySgDsomMIkn1TCARNRoaKkwsH8zNzyDrGrsckSt4U6yhtEP4fGzFtT
         BkjrwqIJemNEWygsqPHithqNGkMdv8DmjfrtBENv/wrzlzGs/LZjzYwPZtn7vJAqSGI5
         fsNjZmQaZw5By5qSoFpSdCuWyCIHZi4lRQ2guDh5nmJPv8h1I4Fo8UgRK/zfFMnLR3eB
         HhZxHcFKZuvhBTIiARZkedpt6n2RrSHU72zAklNBHQSa4dOK5AA23m/TE7ZT7ktbhEmE
         MXog==
X-Gm-Message-State: APjAAAUxkcHn3ulM1qrBTSY9+0kAPIi+2b3PpNrET0WOHxat8UHzZmMU
	4XRFDVQ1RQkOGDrSecyBQwc=
X-Google-Smtp-Source: APXvYqxd8cDmkpifMXhuDifsqYTo4BSg4PYiVfyow8Q4zGSWaVINeJsuuvG//hntUvGWaVOGzZtNJA==
X-Received: by 2002:a67:f541:: with SMTP id z1mr736210vsn.70.1579164665878;
        Thu, 16 Jan 2020 00:51:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f316:: with SMTP id p22ls1873192vsf.6.gmail; Thu, 16 Jan
 2020 00:51:05 -0800 (PST)
X-Received: by 2002:a67:77d4:: with SMTP id s203mr810012vsc.101.1579164665567;
        Thu, 16 Jan 2020 00:51:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579164665; cv=none;
        d=google.com; s=arc-20160816;
        b=kx+SisDqMkKnxwIKtl8bQJRQMmw0bBXWQ4t0Py99FsLOSUSIjpFiUyuvdbY5FF6ViK
         nHtx7qlbdQTX3Pz1m7u7hJnz8EHNbRI4lgYnlYh7xuVbGd+1tyoOGD9JCrKYXldt+S+8
         R3sfv0DKq6v19ZWTsrWFL77fA2SXt9D8QP43zdVd3BRbiZ4i6/203r3dzUNQuBrppvpZ
         cEUUXU4kLP/eIsAyMWhyqCVkKK6LUABVHi7YMemtQQeINFTEx/i2jQjiEM15u1YojHVa
         PclL5KABt6gbWO7kRGyvZ2bzJTmtmtMqERpL4t2zeMLnmJ+THmu32Sh8EPlpPJJrqBy1
         X84w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+h6b4jmAptddyium2DNixs0SA2T98LtobyUWbV5HXPk=;
        b=f4T28PQe5W5JuJgUZzDIAjPZKVAnKvgNDLi1B7qDMZXxwL/dFC9JSY6VQ162U0/dpZ
         9iYZd7UUcFEWbPID99kjBTctHuiQTKxhWt8GtW+ol520tEjgAzQhfq8B8E1p+ruD4x86
         Prt+S7wuwaeIoao5L5lqRFLNX5bNjgROQytSFETMfr979wcl85Q8wFINSgaODnDMLK8z
         7EP1eMFdGbhO3wkmFmJ7vP63q5spQp93iNBf0XQ732K1DHjdr/7acM6PKdY+xQlHfBv8
         Enqw0eHxseyI7SK/k2KKOtWwOuTM5PUELgL+3GxbdKkQk933kfMKTApquaqKxIIb9gpu
         FREQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cEP6hLoU;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id 75si804916vkx.3.2020.01.16.00.51.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2020 00:51:05 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id a203so18425630qkc.3
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2020 00:51:05 -0800 (PST)
X-Received: by 2002:ae9:eb48:: with SMTP id b69mr31096328qkg.43.1579164664973;
 Thu, 16 Jan 2020 00:51:04 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
In-Reply-To: <20200115182816.33892-1-trishalfonso@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Jan 2020 09:50:53 +0100
Message-ID: <CACT4Y+aLYjJmGHPGN=vRTv9LUxC1uxR1CkP_rrY0958cpQaqhg@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, linux-um@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cEP6hLoU;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Jan 15, 2020 at 7:28 PM Patricia Alfonso
<trishalfonso@google.com> wrote:
>
> Make KASAN run on User Mode Linux on x86_64.
> diff --git a/arch/um/kernel/Makefile b/arch/um/kernel/Makefile
> index 5aa882011e04..f783a7dd863c 100644
> --- a/arch/um/kernel/Makefile
> +++ b/arch/um/kernel/Makefile
> @@ -8,6 +8,9 @@
>  # kernel.
>  KCOV_INSTRUMENT                := n
>
> +# Do not instrument on main.o

It's always good to explain why. Otherwise it will be stuck there
forever because nobody really knows why and if they will break
something by removing it.
This comment is also somewhat confusing. We don't instrument the whole
dir, not just main.c? Should we ignore just this single file as
comment says?

> +KASAN_SANITIZE := n
> +

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaLYjJmGHPGN%3DvRTv9LUxC1uxR1CkP_rrY0958cpQaqhg%40mail.gmail.com.
