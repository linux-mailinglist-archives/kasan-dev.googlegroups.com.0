Return-Path: <kasan-dev+bncBDE6RCFOWIARBXMY2LZQKGQEUL4WGMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FC5518CA54
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Mar 2020 10:26:54 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id q18sf2348373wrw.5
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Mar 2020 02:26:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584696414; cv=pass;
        d=google.com; s=arc-20160816;
        b=fEODmTZZnq+RDPvmZDQq8BYs8vBkcB+DmaaxSGx/SsU8fE89rkt9qQpArV52T6Fi4F
         djp8g67sk7GNWzd011ShMvMAj+KX6VnELUOvt4nzspm45wzEx8BfkopT1Lfd7jFoHqdv
         pwurlVTBaVLyh6OgDBEgW+3UGmI/Db6nQ72D2cNd9Qv+21PhfHob+7Ry/xY+Fg748C/z
         3ZFv40w2JlxiWkB9V3p9vsya8G8csnIo5AgpAgJGor7XGab/Fa2dbseLtAwGhTEz9zNw
         BRvWXb1IBHCq3OsRJGLOWj/h0R26Ify6DuvmlzUjonAnmDzIvNfHccSrWk9C9FEeQBTx
         aKig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=iQFLbclfBbGJ7jKSW6kwpuLtLcpDIVkz1HVl8PlVzKc=;
        b=dZMgWUMe25ruwxBR43jFQ0g3+IGj9bc/zHp6Y3KGze2rxmJLKWwyVeOHaq8HRgpZjE
         yfxMhufM3FrAqT7AGBYujf/E0BhMMPNITsfu5EAW5bOpCs4wuZylMkqqapRo9BORynFk
         Hbqje82peXjbpnDIXOSwMgz5yvqLF5hPYj/6uHcQ2lzeT1cm0bXAp8w2Va1dTz75JyKY
         r/f0VlGmcweeC+KDWZo18YtMLffSmUnO/inpA+MP9dPn4vH1H5MgvWu0e6S4RZX1ICKM
         vHReMzHlHyBWnWEimg/CXlKaioHaJU9UcWXRtJvOaLg0IsFvjsDYbKL1mI47/csJy0rR
         h3RA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=tbq+fbIO;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iQFLbclfBbGJ7jKSW6kwpuLtLcpDIVkz1HVl8PlVzKc=;
        b=ZDNXy9D4YQUe06B5DMPm0+7BtuYk70JzyH5SJ703KLK0D/5EGi7PXt/fGux9kwpF3t
         6EfiK0uPzKhFLDAOJHDHXekHI/j4copEmhtvRhgT/ojvBNgZROQ0VuRWQCgJWaqLXaXz
         6lQv7fvyYGMGONIGqX6BK5yyQUloZTVfDJibU5dyKJ4UbHXcwBJC4/X07LycMPECy9xz
         tv9K0w6jKFWszoP3D88KB7CCnAqdavsg7YQCP67DCa/MphjfzAbd0A26kHSZL9CDIl6c
         ELfv80+ywQJLe2aqJIEkk7yOoiSKxKMoRozbgUxYtlFYIWhdqlGslagOuAtiCg5e0S03
         RxTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iQFLbclfBbGJ7jKSW6kwpuLtLcpDIVkz1HVl8PlVzKc=;
        b=pZnj5cwNN7Ld9bdSvyMWdU5sFT/ybHZ7o5XJMziTecDQbTWqzLaWlR66lU3JqUjbMa
         ePXkDsuaXsbKGzsfjse6DKMvfXQXE/+f1ZhwPcCXp+5Jq9gWiQe7OwIgBCzaPsqpMlNO
         XRmBoI2h4PICoy54Gc4ZQmrAoEz24wkRzFfyJLmJgJJm2Tct0kEBL+SgOEaGCWAQl7IX
         UdWE1nqbiDIL9k0skAnoeKyvKmd9MvMALuUgcbeCwTxNawQVw18cO0zNBum+bOhxemgG
         NI4nQQ7RTo3DW4Jsv7zIKXDk4TXJqilDjMVao9cSpiZIGLb8MOGwMCC6j29TStuU+TA3
         +QLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1NUzwp6YCWKhdX4F7r6EpUj2LX+ckOd3xh3IWLVTtMM7Kwd0pF
	cT8aFlgv02Bbp0k//ELaI+0=
X-Google-Smtp-Source: ADFU+vsbEIYjbt17weY9L57DtLcLGDRQWpAGYeEkIij2gFog2+MkEow8I7fZSi0fMqX7eJL6DBlW+w==
X-Received: by 2002:adf:e345:: with SMTP id n5mr10240679wrj.220.1584696413872;
        Fri, 20 Mar 2020 02:26:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:bd82:: with SMTP id n124ls2636091wmf.2.gmail; Fri, 20
 Mar 2020 02:26:53 -0700 (PDT)
X-Received: by 2002:a7b:cb42:: with SMTP id v2mr9293094wmj.170.1584696413144;
        Fri, 20 Mar 2020 02:26:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584696413; cv=none;
        d=google.com; s=arc-20160816;
        b=G3fER7GDWQ3HGJRkr0QsMIvSuR13rsIQB7kpnCY9ah035uOQqUguEbQkP2n1KJdKG/
         pwuJxjCDo4cNy78e/MPNOEYgOUxscuVtRccuacyzfysXDe5hKXXs0ah/I6gToRC2YT0M
         MjzuhPMC81IHZWsZ6agviYpw7iryf4cO9lLQxCTgxZW05nMTSFymhkzj9cILOZCXmFYF
         VUvEfYIehjLv6y1Qd/hukJZX50JgEWUDb6/HHv5yMMF3yQKARaPX4whki/37YoYpAefW
         Rg5p52Wbw1X71ZoEBpZXJvKnab2khdciKVucC/DPFqYoS/z8NWG1CZRZ5tk4RxwluwoV
         TbHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Xb2+TkejQMyeRgV2FN7crNaJyjiX8rMU6p7e/O+WXs0=;
        b=WXrJA8Ak2YUpSrL5zuYHFqdPpUEH/J2VcZwZgrS7EXPk8wr1ldsbCEgmdhsNWv2ZSU
         U3ZZrRIZV/gLHumRn/rv07RQYg7Ax6NxjeqgrVXYC8kOhvJNTw63Wpt1xCTS6A9rlGCc
         WinQtnGEAboQN5Xh9NWdnUCifVpNAIFz/YuUjNt397tZ2VFDYCdIpJ+ppTUbKe7eKf6e
         i+Xdwrn7NjxWLHv4FOB83cXyZT82ZK5lIH3S3+myvCFJd8WZc1fc19VT8jHO1UeLFu9Y
         ps4fu1nrAflDDSJ8J2WwLk0XN/N5E1TsdxjSplyI1sQXWplevY/WHolLcWUnOZEr4vCP
         MP+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=tbq+fbIO;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id m2si453390wmi.3.2020.03.20.02.26.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Mar 2020 02:26:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id w1so5634452ljh.5
        for <kasan-dev@googlegroups.com>; Fri, 20 Mar 2020 02:26:53 -0700 (PDT)
X-Received: by 2002:a2e:8ecf:: with SMTP id e15mr4982788ljl.223.1584696412508;
 Fri, 20 Mar 2020 02:26:52 -0700 (PDT)
MIME-Version: 1.0
References: <20190617221134.9930-1-f.fainelli@gmail.com> <20191114181243.q37rxoo3seds6oxy@pengutronix.de>
 <7322163f-e08e-a6b7-b143-e9d59917ee5b@gmail.com> <20191115070842.2x7psp243nfo76co@pengutronix.de>
 <20191115114416.ba6lmwb7q4gmepzc@pengutronix.de> <60bda4a9-f4f8-3641-2612-17fab3173b29@gmail.com>
 <CACRpkdYJR3gQCb4WXwF4tGzk+tT7jMcV9=nDK0PFkeh+0G11bA@mail.gmail.com>
 <2639dfb0-9e48-cc0f-27e5-34308f790293@gmail.com> <CACRpkdZ8JA=DXOxzYwyvBxCMd2Q5uzLTn87AVK7wdrxHFo5ydQ@mail.gmail.com>
 <20200305094328.sizz4vm4wamywdct@pengutronix.de>
In-Reply-To: <20200305094328.sizz4vm4wamywdct@pengutronix.de>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Fri, 20 Mar 2020 10:26:40 +0100
Message-ID: <CACRpkdYzSZY0r=YYiosvi2CA7mia5oiXAWUkbYSqjU1PZ_6w=g@mail.gmail.com>
Subject: Re: [PATCH v6 0/6] KASan for arm
To: Marco Felsch <m.felsch@pengutronix.de>
Cc: Florian Fainelli <f.fainelli@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
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
 header.i=@linaro.org header.s=google header.b=tbq+fbIO;       spf=pass
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

On Thu, Mar 5, 2020 at 10:44 AM Marco Felsch <m.felsch@pengutronix.de> wrote:
> On 20-03-05 09:43, Linus Walleij wrote:
> > Hi Florian,
> >
> > On Fri, Jan 17, 2020 at 8:55 PM Florian Fainelli <f.fainelli@gmail.com> wrote:
> >
> > > Let me submit and rebase v7 get the auto builders some days to see if it
> > > exposes a new build issue and then we toss it to RMK's patch tracker and
> > > fix bugs from there?
> >
> > Sorry for hammering, can we get some initial patches going into
> > Russell's patch tracker here? I can sign them off and put them in
> > if you don't have time.
>
> I've tested the branch on several imx6 based boards with different
> toolchains. Some boards booting normal and some of them are lost in
> space... I didn't debugged it yet just wanted to inform you.

Hm. I will bring up the KASan stack on more boards.

If the system is anywhere close to being low on memory they
will naturally crash, this is an unavoidable side effect of KASan
or anything else that just chew of a big chunk of memory, that I ran into,
as I was booting from initramfs on very memory
constrained systems.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdYzSZY0r%3DYYiosvi2CA7mia5oiXAWUkbYSqjU1PZ_6w%3Dg%40mail.gmail.com.
