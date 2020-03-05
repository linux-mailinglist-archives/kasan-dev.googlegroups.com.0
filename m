Return-Path: <kasan-dev+bncBDE6RCFOWIARBUHXQLZQKGQEGFWQLQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 93BC517A197
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 09:44:00 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id u9sf1677359lfi.22
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2020 00:44:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583397840; cv=pass;
        d=google.com; s=arc-20160816;
        b=lRT5Mtp3yMMAz2UQkxBHSD4rDiTv5L/jM0Umne+wwcuzHyHi9lYGbGEWPTpvUfRJ76
         Dr4Nf39SLUoaMKjtcdGkUAcZ7mQmFyoLbtMwGxvSx3ULXy02omZWLtmSyHwdamLmxPJk
         YJ8t/12VRhzi69cafQBjIWtm5Ry60RjwFpqT5TSrspuakmXshlj2iAplj1miXddCqV4e
         cSHSV7HahlAj7gOSa+7qyRljH3oMdtPLFHQ9rYWZGEPfQzSZapH6llMJLT8ooCaXCM85
         nZXN0zf0WMJjSXrzTS3vf2qvb/k8kP+MyoMOpHfC+QM5eFgmUvq7bOHkoUvCwyEEbPJ9
         Bfcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=ntW2R+u/Vcxn8PZonyRIUm0Y3dNWh0+R545bNFc6/PU=;
        b=Uz4NqfgdQ01Js6q/KvZWHxDu+mIoJ+eopRTxwal1Ok3zaYcidbGzYA6EhFnFH5GBYe
         rgDo+0JvLv8GPnwot11kjj0/R5Xzj0LRJtcK8cRKJfwtlhbZATO6EX6QjslB0LXO/UyF
         gzhFgEgVAHoONol30KBc/arkf3bVycRJtD++Df2O2w9UbaSeamZvndUBJEYVEXvz8TZY
         toloqvspn0wJsA49i6hO+QCsEdezfNQxL0jDwvuZYxqTEgltrmIJm3Od869Ps+6u7GrN
         6tJQGMmgFABbvGrGndxEscW4Zx9yfreCP616JzfmgG0ti1oajuH8479g6lw843K2GLSo
         9A7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=M2RHZfPP;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ntW2R+u/Vcxn8PZonyRIUm0Y3dNWh0+R545bNFc6/PU=;
        b=GSq5IMclT433NvtE3b4/i/teOgi/jr8grvkFiDuSIQbEYgqhKtlgoOiIoT3NRdqjJb
         gI0Mz+n4zrxcJpU8rgwBClw7Wfw5fWtxsi+6F5sDFDrzofNLMR/s9cslzdyKgDFQj3ki
         mzuSI3MujwNd2EcxI83bFqBydJwLRciXU6DvQ6ldt0FBT8K4SSY42C1Apt5bk7bodbvb
         O28ST1i0fTLfs7LE9ueUgjtlF7rGCjiDa/XhwnysLMF507COpHD5LJb8kOqe92yIPGzO
         P5XlSYCz3vTuY9pngJ0vbkmsVuVipoV5ueAOvgbJ/0XfJOfEOu0oOoNdpEEQE3uYoOGB
         Jl2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ntW2R+u/Vcxn8PZonyRIUm0Y3dNWh0+R545bNFc6/PU=;
        b=D5ZpKoVkm1tdA1HIoUUsRWRxtW/e9+ERn3SxJ9CEKQ5HE7CfRLTXBIrtGgYugyK0Ut
         5zedq17k9/1a/N9PZRhsw2Twp+OEG6cO+0l/ZDcQdLF102PYV/NjXvbRVzbXhAWBVM2s
         6VyEDAk6NbqJUHB11d94Nc4LC3bp7s+PweKp9e7ZQiKtjcc6lEsUcIFfMEtdeZvZre8y
         ZQRygfIvCrefQtAM6ahx+QCDi9538asK5Wj7kMmfbRbTbFoOuSSPvIR9TCQKIowGCwpK
         BKI4Z+xEJqfMD7Xj4GY+2vHunopLjMAMcBHobgV0T/PouWB0Qu4HQs2eHYJChSityKB1
         pGgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3hp7DtKDbHG8iUKeItiXf+0W99X+nCxzK7jaaJrDSD7gBS1fMb
	L7hrqx2PEOTENGulpYWgY8o=
X-Google-Smtp-Source: ADFU+vuB5ujgTt7we77HENvPnD1h7DtxvHUEpaTBDUHSeKdW7nb23Tg9tKW3wjtXZNlrm82k3FkFhg==
X-Received: by 2002:a2e:9606:: with SMTP id v6mr4635471ljh.89.1583397840106;
        Thu, 05 Mar 2020 00:44:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58c6:: with SMTP id u6ls237123lfo.11.gmail; Thu, 05 Mar
 2020 00:43:59 -0800 (PST)
X-Received: by 2002:ac2:48b6:: with SMTP id u22mr4796640lfg.18.1583397839494;
        Thu, 05 Mar 2020 00:43:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583397839; cv=none;
        d=google.com; s=arc-20160816;
        b=vPILJ6iSEoZvZEZVhvYJDaRUVwO+k+tw1GanpjkCWLBEQXKIkFFQ8aDfy+/qIsyXDa
         8juZT02NbsxFDhf5gRGH8tjsj68QqgUOAEQxiUCH+uz81Lg0UTqUnBiEwlH6abDNdJ0G
         x+LT39ICuIhN7H+QJ5dZwVPzEKDLGB6RZ07kAtfWpLlNzAHzMZJn7agwdOQtF998eBx3
         qvvmA2QPmeWKF922sikAfIU4ldTekQaxcqJnJu8rAHEvlzArJ9+z9+I8P0rFi5Zgsyq4
         du87MggP06gwZe74zs1l5PgBThq9IJw7fPptu7rTDrCwG3p8i6hMcOG/Fb5sXvH9+VFf
         R5Rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fbdyI132YwoclqRAqQFcdVx80Hpq+rOO83F3M2/coUY=;
        b=Q5HgvJvUwr2ijEDdarpmJz7F7iZzZkLCsRB7D1Qe8AJeUgMnbe84eabmIo1Agui+JB
         iVNzbks4lSHk2fah1HKwQd8IcmTG3w7hUdL4mpdl8N6afi6xuzWwZUJUjUGcnQP5L89y
         /NpOStgAhyc7QA8SnNAhaC/MTfBMkAgsXDeq7wZtSE8R+FifuCZRxd1nLJcmzuIa3Oua
         MJF7RRi6aocZjBBQmGGor4/vAhYZ6KC2zUR7nQbeGFozcz3oCemDaxKTbRuUEx4Xge1g
         HlpFl9QqPp4b+YYwm4FzMe+/JtyseDlSHAFBd145MIiV2pA5N/a+8mztu/R1N/2+GEh1
         YVGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=M2RHZfPP;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id w6si358688lfq.1.2020.03.05.00.43.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Mar 2020 00:43:59 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id q19so5108238ljp.9
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2020 00:43:59 -0800 (PST)
X-Received: by 2002:a05:651c:2049:: with SMTP id t9mr4675395ljo.39.1583397839207;
 Thu, 05 Mar 2020 00:43:59 -0800 (PST)
MIME-Version: 1.0
References: <20190617221134.9930-1-f.fainelli@gmail.com> <20191114181243.q37rxoo3seds6oxy@pengutronix.de>
 <7322163f-e08e-a6b7-b143-e9d59917ee5b@gmail.com> <20191115070842.2x7psp243nfo76co@pengutronix.de>
 <20191115114416.ba6lmwb7q4gmepzc@pengutronix.de> <60bda4a9-f4f8-3641-2612-17fab3173b29@gmail.com>
 <CACRpkdYJR3gQCb4WXwF4tGzk+tT7jMcV9=nDK0PFkeh+0G11bA@mail.gmail.com> <2639dfb0-9e48-cc0f-27e5-34308f790293@gmail.com>
In-Reply-To: <2639dfb0-9e48-cc0f-27e5-34308f790293@gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Thu, 5 Mar 2020 09:43:48 +0100
Message-ID: <CACRpkdZ8JA=DXOxzYwyvBxCMd2Q5uzLTn87AVK7wdrxHFo5ydQ@mail.gmail.com>
Subject: Re: [PATCH v6 0/6] KASan for arm
To: Florian Fainelli <f.fainelli@gmail.com>
Cc: Marco Felsch <m.felsch@pengutronix.de>, Mark Rutland <mark.rutland@arm.com>, 
	Alexandre Belloni <alexandre.belloni@bootlin.com>, Michal Hocko <mhocko@suse.com>, 
	Julien Thierry <julien.thierry@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Christoffer Dall <christoffer.dall@arm.com>, David Howells <dhowells@redhat.com>, 
	Masahiro Yamada <yamada.masahiro@socionext.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, kvmarm@lists.cs.columbia.edu, 
	Jonathan Corbet <corbet@lwn.net>, Abbott Liu <liuwenliang@huawei.com>, 
	Daniel Lezcano <daniel.lezcano@linaro.org>, Russell King <linux@armlinux.org.uk>, 
	kasan-dev <kasan-dev@googlegroups.com>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Dmitry Vyukov <dvyukov@google.com>, 
	bcm-kernel-feedback-list <bcm-kernel-feedback-list@broadcom.com>, drjones@redhat.com, 
	Vladimir Murzin <vladimir.murzin@arm.com>, Kees Cook <keescook@chromium.org>, 
	Arnd Bergmann <arnd@arndb.de>, Marc Zyngier <marc.zyngier@arm.com>, 
	Andre Przywara <andre.przywara@arm.com>, Philippe Ombredanne <pombredanne@nexb.com>, 
	Jinbum Park <jinb.park7@gmail.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Sascha Hauer <kernel@pengutronix.de>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Nicolas Pitre <nico@fluxnic.net>, Greg KH <gregkh@linuxfoundation.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, 
	Linux Doc Mailing List <linux-doc@vger.kernel.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Rob Landley <rob@landley.net>, philip@cog.systems, 
	Andrew Morton <akpm@linux-foundation.org>, Thomas Garnier <thgarnie@google.com>, 
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=M2RHZfPP;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

Hi Florian,

On Fri, Jan 17, 2020 at 8:55 PM Florian Fainelli <f.fainelli@gmail.com> wrote:

> Let me submit and rebase v7 get the auto builders some days to see if it
> exposes a new build issue and then we toss it to RMK's patch tracker and
> fix bugs from there?

Sorry for hammering, can we get some initial patches going into
Russell's patch tracker here? I can sign them off and put them in
if you don't have time.

Thanks,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdZ8JA%3DDXOxzYwyvBxCMd2Q5uzLTn87AVK7wdrxHFo5ydQ%40mail.gmail.com.
