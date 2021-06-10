Return-Path: <kasan-dev+bncBD6MT7EH5AARB3UXRGDAMGQEUMKOS4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D5253A3213
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 19:29:19 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id k25-20020a5d52590000b0290114dee5b660sf1282539wrc.16
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 10:29:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623346159; cv=pass;
        d=google.com; s=arc-20160816;
        b=pisGzddc5MZxiA8+EtzV2HZiHbWWKH6+CEZJLkcbHPc2aO6WVqAzmlBCDhwYmki0Ty
         AjjOQ3bfhmBvk8lQ6hD4eJhMHthih+GfL7eEexw7RIlpM/fkJz1ZCdaMVlSosxJAnnO/
         GSyY0OVdeigrMsgczLvnCOkg8WGjUJ5qnQ4w+oQQUlWTOshvcO/HSNvpSfQ6HuF2/QwJ
         rPMOpLwWOkAr9RpWD+tncilil8G9KklojpP0MycEk6yw8wEm3afSft49EIdwPHtss2LX
         C6J31K7sYmoP5YQSH5e9tVDp0SnqG90diWS9TgflxwmlyItDcq755j4buqmvfTT+X5s4
         G+rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=BOq3bERygJRO1ZjMxarERtFd0TLxkww5BTxGssU1BFo=;
        b=gy45pyKfowe9rcHyIveLnadLsrXlusMu2WIO9X9JntiWmFUhtoAXcuuk3ZSCqqrlUJ
         PuojJNYdOdwMWICl6FLFOrjeBz8iOosiCxkUF6PKAlw/CPXPvh8n7hCtZqXW5BL9QRyZ
         v+KpR7Y2PuUYjhublJnLwuIyrq8Qew6kho3h8e7dyKFNIwMJ0T9twxaw5AIShfgygL6K
         X9Qp56DaKM9yVtc0xLT97+VPksjwurr4Xsv3xBxkP14IwobwUNuMWHmSORXN/atvmt/7
         9gfZBUVX5W1peOYsLehRx1kA4pfHwnYAELHIgov0dkk/Pkh5p6spOq/UE3gU/4SGv0V8
         lQ7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:references:date:in-reply-to:message-id
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BOq3bERygJRO1ZjMxarERtFd0TLxkww5BTxGssU1BFo=;
        b=YdIJCncXdwkBkinbvaIpqSPrGpJ++QHbI04l4q4hNTFmELnclkoTVcFA6OgKEo7zXi
         YXpnBsmAp2FJdARFFmJXX2QyiMG/7p6UbO+vIHui4A9RMo4CPd043py+CXBTQagZnABv
         Yfz/JqwOAuGhEs9r3PRQxCW//PBAtcHv81+Ak91LsBNOUGYNNfCxr6yWoJWEy/ZP5I1b
         nuXiQGejZdJiIEVeQx2EMsd687+pXiArLiRFmDElTz2bNgqMXr2fEr6VrstS9UFmxWyU
         LDAJjC50tgTmri3oEZal2eYC2ABSzAMdDWGEswQ9kC4xrhpMzgN+D4VaOacMuIcj3WVo
         bOWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:references:date
         :in-reply-to:message-id:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BOq3bERygJRO1ZjMxarERtFd0TLxkww5BTxGssU1BFo=;
        b=Pcs8tcxTUN8iGy+TIi9AsxFNG2WHm4LSpasb6u6XHwrLmXftjUaGJe9cSYANZfwyid
         rGZ7JswPoO3II5h0PobiuRV+tQFG8jKY0geVVvPkrYvXo7A7zCH454ZtgvWZd/v7yE/D
         4ujgDBYV/GvespqHaAN2Fn7ficsPuxmt6ZrL1gGA24Y61zz023o9/gde9B1gkr96bVA+
         xT9lT8qKkTEMt3L2kB3OzOID4ifqFKKpcvtx5RWM1BJfbcoIgqxYO3kWsDDPwNtkc+ud
         ygh9Gsbrb/zCj5dU7vr35iVgwkjuAgmZVL58pSsBGCa9KghUcIcWC9GYjVMztS7vL5ip
         4ZJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533RXfD7pPJOA+agwT05JqLRT7TJtH6zjGTVbrYIMBRwZ3CuxW5O
	PRemLNLibSXP9OMvcO773oE=
X-Google-Smtp-Source: ABdhPJzAWKYHiOxf+EFhVN3Wg7cXomAkFYJAK3LIcrIwPDJZQ/jrAFqRA7V06BPHB5jjR5LXVwWDIQ==
X-Received: by 2002:a05:600c:1c1b:: with SMTP id j27mr6323054wms.133.1623346158917;
        Thu, 10 Jun 2021 10:29:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ded0:: with SMTP id i16ls2159148wrn.1.gmail; Thu, 10 Jun
 2021 10:29:18 -0700 (PDT)
X-Received: by 2002:adf:df09:: with SMTP id y9mr6829748wrl.108.1623346158154;
        Thu, 10 Jun 2021 10:29:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623346158; cv=none;
        d=google.com; s=arc-20160816;
        b=n/enEa0mNN8HuY6gkZxe7zP4TWEPA4ug42PIF03f6NXb1rAYybNtCcKBwqVG5tmKN2
         UceV1/QTPCQJbmsbF/kMdjM/oe5O3zKYqJLn5EzIc3A9ziJLWtbBd7vBdIexdKZuj2bl
         rqV4ACp+pGE6V/DMmWxMEEAoJJFm4RSvPm4ZucffDDKHOK24hGCEvaf1TR0vIukCsw5H
         Mgc5Xwi9uK3mPIEZJy1uR2jZPfVDMLkngya8J98TzANGznQEnEnjZEJtsbP//7NEIvC6
         NUrlCq5NBLD1wEOsAZD3qqIYv+7MrEZmyTpgBWp8JHUhwyd8ew2P5aoKiBPcE8Ap7+AW
         N+SQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from;
        bh=8uKswxAM5vYaTDkUm0xiJbQd5wv8XjtIOrTaJVyM0rQ=;
        b=c88eRVo47KE1Q8zjJo5kJI+Ep0tSdRs7ZGib4VcB0YgvzNrKhVuh8+EebMCfeYaU9e
         zkEqEHPySTwtp0tUzh3pOUw3AF2PMWAbUwJGPxk1/hxgc0UKJY17VGHwTu9O1IWFJTBu
         uhWbywhvc8LekJqbcyZW6C2b0GOYUXWyzqLJ+DY9yXeX12MxVZzDtyLVjVtrtrB+kXk2
         78FwY/A9NWVU9JWHWQgzK846nqt6l59BXWKwqTUSFnVRWmIB5shTcYm4iLbKt6+Kl7l0
         bclmxMYTvJV0FuVDeaDUvJspbWS7zgzgyVAbBf6tSJVKiHUPooBaZ77XgisCQAQe/WtH
         nneA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) smtp.mailfrom=whitebox@nefkom.net
Received: from mail-out.m-online.net (mail-out.m-online.net. [212.18.0.9])
        by gmr-mx.google.com with ESMTPS id v4si207728wrg.2.2021.06.10.10.29.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 10 Jun 2021 10:29:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of whitebox@nefkom.net designates 212.18.0.9 as permitted sender) client-ip=212.18.0.9;
Received: from frontend01.mail.m-online.net (unknown [192.168.8.182])
	by mail-out.m-online.net (Postfix) with ESMTP id 4G19vK6D7Jz1qt3l;
	Thu, 10 Jun 2021 19:29:17 +0200 (CEST)
Received: from localhost (dynscan1.mnet-online.de [192.168.6.70])
	by mail.m-online.net (Postfix) with ESMTP id 4G19vK4RQLz1qr46;
	Thu, 10 Jun 2021 19:29:17 +0200 (CEST)
X-Virus-Scanned: amavisd-new at mnet-online.de
Received: from mail.mnet-online.de ([192.168.8.182])
	by localhost (dynscan1.mail.m-online.net [192.168.6.70]) (amavisd-new, port 10024)
	with ESMTP id vO5Y0XBKtwZ2; Thu, 10 Jun 2021 19:29:16 +0200 (CEST)
X-Auth-Info: 2HRiD3r3sBASgyEoh1SHqVlhb3EFoSQZduKD2H4uGNLGPC7SubTmYAn+NLEyWCf+
Received: from igel.home (ppp-46-244-161-203.dynamic.mnet-online.de [46.244.161.203])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.mnet-online.de (Postfix) with ESMTPSA;
	Thu, 10 Jun 2021 19:29:16 +0200 (CEST)
Received: by igel.home (Postfix, from userid 1000)
	id 83A702C36A1; Thu, 10 Jun 2021 19:29:15 +0200 (CEST)
From: Andreas Schwab <schwab@linux-m68k.org>
To: Guenter Roeck <linux@roeck-us.net>
Cc: Alex Ghiti <alex@ghiti.fr>,  Palmer Dabbelt <palmer@dabbelt.com>,
  corbet@lwn.net,  Paul Walmsley <paul.walmsley@sifive.com>,
  aou@eecs.berkeley.edu,  Arnd Bergmann <arnd@arndb.de>,
  aryabinin@virtuozzo.com,  glider@google.com,  dvyukov@google.com,
  linux-doc@vger.kernel.org,  linux-riscv@lists.infradead.org,
  linux-kernel@vger.kernel.org,  kasan-dev@googlegroups.com,
  linux-arch@vger.kernel.org,  linux-mm@kvack.org
Subject: Re: [PATCH v5 1/3] riscv: Move kernel mapping outside of linear
 mapping
References: <mhng-90fff6bd-5a70-4927-98c1-a515a7448e71@palmerdabbelt-glaptop>
	<76353fc0-f734-db47-0d0c-f0f379763aa0@ghiti.fr>
	<a58c4616-572f-4a0b-2ce9-fd00735843be@ghiti.fr>
	<7b647da1-b3aa-287f-7ca8-3b44c5661cb8@ghiti.fr>
	<87fsxphdx0.fsf@igel.home> <20210610171025.GA3861769@roeck-us.net>
	<87bl8dhcfp.fsf@igel.home> <20210610172035.GA3862815@roeck-us.net>
X-Yow: A shapely CATHOLIC SCHOOLGIRL is FIDGETING inside my costume..
Date: Thu, 10 Jun 2021 19:29:15 +0200
In-Reply-To: <20210610172035.GA3862815@roeck-us.net> (Guenter Roeck's message
	of "Thu, 10 Jun 2021 10:20:35 -0700")
Message-ID: <877dj1hbmc.fsf@igel.home>
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

On Jun 10 2021, Guenter Roeck wrote:

> On Thu, Jun 10, 2021 at 07:11:38PM +0200, Andreas Schwab wrote:
>> On Jun 10 2021, Guenter Roeck wrote:
>> 
>> > On Thu, Jun 10, 2021 at 06:39:39PM +0200, Andreas Schwab wrote:
>> >> On Apr 18 2021, Alex Ghiti wrote:
>> >> 
>> >> > To sum up, there are 3 patches that fix this series:
>> >> >
>> >> > https://patchwork.kernel.org/project/linux-riscv/patch/20210415110426.2238-1-alex@ghiti.fr/
>> >> >
>> >> > https://patchwork.kernel.org/project/linux-riscv/patch/20210417172159.32085-1-alex@ghiti.fr/
>> >> >
>> >> > https://patchwork.kernel.org/project/linux-riscv/patch/20210418112856.15078-1-alex@ghiti.fr/
>> >> 
>> >> Has this been fixed yet?  Booting is still broken here.
>> >> 
>> >
>> > In -next ?
>> 
>> No, -rc5.
>> 
> Booting v5.13-rc5 in qemu works for me for riscv32 and riscv64,
> but of course that doesn't mean much. Just wondering, not knowing
> the context - did you provide details ?

Does that work for you:

https://github.com/openSUSE/kernel-source/blob/master/config/riscv64/default

Andreas.

-- 
Andreas Schwab, schwab@linux-m68k.org
GPG Key fingerprint = 7578 EB47 D4E5 4D69 2510  2552 DF73 E780 A9DA AEC1
"And now for something completely different."

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/877dj1hbmc.fsf%40igel.home.
