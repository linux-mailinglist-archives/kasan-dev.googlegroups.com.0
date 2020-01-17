Return-Path: <kasan-dev+bncBDE6RCFOWIARBVURQ3YQKGQEIJN7CTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id D82781407AB
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 11:13:42 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id z17sf6043064ljz.2
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 02:13:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579256022; cv=pass;
        d=google.com; s=arc-20160816;
        b=gUnhCXj3WL1CcCcz6ED3pfV2HkcN4TgCCIqrgRjECuLumEd5YP0MorNHyZ48KPj99m
         MVkDsnIQuIDkQWyoExXZ3CvnMs5dH5aM3JSPLvZvz4P+fB68rYdMvI1Rbjhlk8BX8PbT
         ART6JDCUQBHFfsp7NLhuRBxV5zr6IAlkwEdrAZWnpCDLYM3Ss2XCe4T1qwZ2tMZuZTpV
         8/sn75miXa8yG/GTWq0kW0zu8MoVNTXwVHCe3J/ZWfEyHnUW/bAxg5hfKxD098NBPKaL
         AsR5vV8GhhyLfx6gN0FEbGC+CBYgep6zfBepSvHXdmEtwssh0VefOd5w5MPhXYwV4Km/
         XE9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=BXidUpwS3QbIaUpxfqcxXV+XFhPoTomHb/TkYQko2ZE=;
        b=FzCm3RmuFAda+EdVBV+apH18ZFsgQgTq3451HW62sG2YnI1j3OnjBJoH9n+mNhVyCg
         9JVd4zGGfRqDc/XqpeZUyvfoUr8SMJiSuV8lkoH29sngoWRSrF7kA/ZwJR+eQ2eUSb6D
         CbskCu/vNdknK5ohhZicknBFiGHXB+5GaWy5ZtzlgJ6lQn9bv9gNbszfjoj+ahQM17Nq
         qdXiavtymY9OROgOoga9plCHKphV2SeASNoHAfXlqJJ/9cb58R5ny6UHvWiTNc8wbRwK
         kD43KyVtkpSmNFJVgH5f/W5SYrmHxDGlBnVAEvBh4EdhlA82e+t+i1tADzXELJvkxxKY
         +SHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=JZtAPVZY;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BXidUpwS3QbIaUpxfqcxXV+XFhPoTomHb/TkYQko2ZE=;
        b=Kwwq4r8HKGs8Pz19bjhKSXSwmd6cUhPsXKk1Hl4Mal7I92cBaBYA8y03A/3WRv5B1i
         IasXtJVA7vsZJnSv44JfwBTtasWzoE8TLutxGbWKIpkmG1c1MelOCa9XvZRotXwTbVkO
         1aF7k1p0w8rQjLqc9PWJDQvWeZ682PDuwnLN2h4ypjiBYV2gZN2Zdf8W9jgqR1ONq88v
         xzH6siBX6FARJV8xJEElFuEh98T6ZjcU7Ju0haiooUx6uZZFpPZ9q+ySuK4favgZV6k3
         XbmIASjhZObq5HcokQRPYNa5X3oq08IMkyxPc5uQBRkBX+q/79K6ZXyPL0v6jL5ue7Rk
         emVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BXidUpwS3QbIaUpxfqcxXV+XFhPoTomHb/TkYQko2ZE=;
        b=ZIHc66fPgoMgoQXLEmRc6mgHs6AGK2Zz9KSyMXv0huhtW8tleWruyJ40tm4E0+Az1o
         ug9APqJ3U1aE7RSsESRgfscHqPUTTpsV7LTUWCMfSOz+hgQymDScfpWDbnMkzx2aQ0Af
         JR2N2nqS51x5XQqIWSkgmn6zBRTMsZUUgrZtZIclh1EUZqNPAPunOKivcBVQCLGy6atE
         ZP1ma72FibUDBBDPRWPGo/vbpXNf8xrPYh2qsVkuadPQ11Jg1G3n0YfWndHU5KFnVrL1
         yTV+OO/WBqdYzK0kQrvfVbxeD9Vf0Ks0GDB9fsLXlB7GWsx++6LUK3EjT3SBslebqXLr
         CSgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUWWgFCRFJ1itSka01ujTXQ/qjL5wVePsYsUF5RQq/uicV9i4v3
	ObgG+h8o60YCe0/hElelR58=
X-Google-Smtp-Source: APXvYqxB26MHfixCSppJ5MLnvq3qePaye8EBfv4HJlDOO7x/oG6JruuKVd8BiWXfkOSG4WO9qbhvyQ==
X-Received: by 2002:ac2:4988:: with SMTP id f8mr2537543lfl.210.1579256022466;
        Fri, 17 Jan 2020 02:13:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b5d9:: with SMTP id g25ls3467127ljn.9.gmail; Fri, 17 Jan
 2020 02:13:41 -0800 (PST)
X-Received: by 2002:a2e:9d0f:: with SMTP id t15mr5120106lji.171.1579256021965;
        Fri, 17 Jan 2020 02:13:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579256021; cv=none;
        d=google.com; s=arc-20160816;
        b=pfTSc7ZJ51yVy4Z4lKyYcMz1G465FKwpdGTUge3QJOxnUnPeOhxvzaEKLXwf1/RDCf
         KZwEmEbaT/dGIakL9TAun4kGsWW6v1H61Cdn0a/ecRypZ6HHqRM+oV4VpzSu2qkmOKkg
         86Ueqcqdt29ue+dN5JByDb66ZZjOTe/NHGQe4/FhfchKcs042eKMr0OwX+508v6IsGFu
         59HUzG/S9n0H1Bs7N6EsXb2J97MvosjwuaiZXJqn68WfzOmRzQ2rONXgNZ5Xd7AavX3S
         mkOK5+KjW/et2Jx/4mGDQ6evs95s5CMzUgs4CcD04FoW4NwaFbdiPd1A9TGTWiNbl3a3
         i+ZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5Jhg4+UAB/mfmS/kvRrF2GKzyf6Tn27Jkcr+2SRy5OE=;
        b=MemH76+R+vA6GEJLDNJ17/ytTo7FSNol4Hbi7KS/jidY98O0wtkt745rpKM5RWqNin
         6V3rZq2j268RyrPt+/8Z56IQ06w2Tb0ObAOwpTt6y2b8qEjAKBmKgdqWmU4JLLq9JM4r
         jQ1/zjgfK5oggcIYVxW9Bvf+XWcBFhTmtp7ybuJYvyTV5CiTzqtBCmosHVf3PdRqthnH
         2jM9f7G8boYFX9aRbOJi1Tjz9L6/URzi3fss0GXjfU+i3BszGQg+Sf4ZPA52TYoFZ6g/
         WmDFN7p86kSgHPIur2sPMCQg4RF+HWjZl7ssnw52bLrj3N64ivkb6Fqzq2xEPI/c1jhB
         BxAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=JZtAPVZY;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id h8si1105727ljj.3.2020.01.17.02.13.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 02:13:41 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id a13so25868266ljm.10
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 02:13:41 -0800 (PST)
X-Received: by 2002:a2e:918c:: with SMTP id f12mr5288808ljg.66.1579256021661;
 Fri, 17 Jan 2020 02:13:41 -0800 (PST)
MIME-Version: 1.0
References: <20190617221134.9930-1-f.fainelli@gmail.com> <20191114181243.q37rxoo3seds6oxy@pengutronix.de>
 <7322163f-e08e-a6b7-b143-e9d59917ee5b@gmail.com> <20191115070842.2x7psp243nfo76co@pengutronix.de>
 <20191115114416.ba6lmwb7q4gmepzc@pengutronix.de> <60bda4a9-f4f8-3641-2612-17fab3173b29@gmail.com>
In-Reply-To: <60bda4a9-f4f8-3641-2612-17fab3173b29@gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Fri, 17 Jan 2020 11:13:30 +0100
Message-ID: <CACRpkdYJR3gQCb4WXwF4tGzk+tT7jMcV9=nDK0PFkeh+0G11bA@mail.gmail.com>
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
 header.i=@linaro.org header.s=google header.b=JZtAPVZY;       spf=pass
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

On Tue, Nov 19, 2019 at 1:14 AM Florian Fainelli <f.fainelli@gmail.com> wrote:
> On 11/15/19 3:44 AM, Marco Felsch wrote:
> >
> > With your v7 it is working on my imx6 but unfortunately I can't run my
> > gstreamer testcase. My CPU load goes to 100% after starting gstreamer
> > and nothing happens.. But the test_kasan module works =) So I decided to
> > check a imx6quadplus but this target did not boot.. I used another
> > toolchain for the imx6quadplus gcc-9 instead of gcc-8. So it seems that
> > something went wrong during compilation. Because you didn't changed
> > something within the logic.
> >
> > I wonder why we must not define the CONFIG_KASAN_SHADOW_OFFSET for arm.
>
> That is was oversight. I have pushed updates to the branch here:
>
> https://github.com/ffainelli/linux/pull/new/kasan-v7

I just git Kasan back on my radar because it needs to be fixed some day.

I took this branch for a ride on some QEMU and some real hardware.
Here I use the test module and just hacked it into the kernel instead of
as a module, it then crashes predictably but performs all the KASan
tests first and it works file, as in provokes the right warnings from
KASan.

Tested systems:

QEMU ARM RealView PBA8
QEMU ARM RealView PBX A9
QEMU ARM Versatile AB
Hardware Integrator CP
Hardware Versatile AB with IB2

Can we start to submit these patches to Russell's patch tracker?
Any more testing I should be doing?

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdYJR3gQCb4WXwF4tGzk%2BtT7jMcV9%3DnDK0PFkeh%2B0G11bA%40mail.gmail.com.
