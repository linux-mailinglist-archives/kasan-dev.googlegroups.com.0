Return-Path: <kasan-dev+bncBAABBW4TQPZQKGQEJOF5ITY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 22A0517A267
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 10:43:56 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id p4sf2667454wmp.0
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2020 01:43:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583401436; cv=pass;
        d=google.com; s=arc-20160816;
        b=eh5pcQ5Yw1Ival350SrEFCC9TLg3K/AbuY8O40uY71PApPruwADq75Gtkz0YHEfuij
         3tPKWzEVSJp+tswrjVTtzwuQHOyoV8EiVY0DOb8bnhgWiq7D1e/bHqL/ZHjHYvnaT1Ai
         XYcyu+o3wVnIHiYMICs6Y0IprOGtQpGUbOPwC70u/wu1ULUW/9JdVmalgcJMWwOltysi
         tvDke3OzH/OrLuU2IdHMMy/8xMOoioufFYONep0+gRSMYANI1NjFpLx3VghqPlX+pjDv
         QsRdYjhH6WHPtEwRSIwMxUVKRlRGOW9QscR3oDbNe5hbvmkYUMWsDC1pqDfT3ClbpFe4
         WG7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=sG3kvbCsysmqpK5N7eomhso6fr6D6AvpOQ356UjrWUs=;
        b=lW9gfDoZ0bDS03ziV6QLJloNyQkOTEXVx4pTjsY0166gcwnnIOmo/zM1JQXSHh3NnD
         leWjrJK46jsQva8cckAlLogpIMGfGIKcTkYSdEmHAfGGp7Ep4UFWhTiWsea255iUQ6x7
         lS1wCzMg2ImSFs8LTQn39epM07J1k621fHrOXBe8xohy1X0TCcaWc7P6aOPE54DZZiEd
         f7IMx7k1VoJ68Q95GUYoWLS/RR+kO5jWk55QQngvh0fMx5C4yifrnHWHjJOv8iymPY8K
         EdQjTWc+Hww54qZHqLCEeB+HDKBC7xjK/OqZT6pJyWjOdzLL+bgp7gV4nBMvoMbKxLkv
         V2ZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mfe@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=mfe@pengutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sG3kvbCsysmqpK5N7eomhso6fr6D6AvpOQ356UjrWUs=;
        b=MLITaS+awiy/Y//0h2XwaYncIs6qsstpaxbR8+RIw7aKhbLJ88knMF3CgeqekL6T6w
         L+X4TYdEH6k1k3/ikPuWRL5P1wNmFgZB56gIA+IMoJbTYISBWGhkB+/mZz5mbGoiJgYN
         PlDOFRanNsNM92KQOhuw5NMd3yvQ8DfwFBUX54x9nO7Oe+zwo8Y6fBv94LedvuvQHUbW
         Wly4HyhWSGOxqUqhBJ9GJVp8pbEWYRsk+SC7l8fMZlA4L8oCsvzlmfm3jGnYQ8ANS1gH
         MdlSWQErsySiE+QI7PFAhguayGWdvykIXBSOFSUe3N3p+7h8NGkTohUdICff54D+8qWK
         wj8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sG3kvbCsysmqpK5N7eomhso6fr6D6AvpOQ356UjrWUs=;
        b=UrCXasopt6sFXU4ITJP6GdI6fu9DVaVuvxWxiNp9z8Odon/ZPOduiS6eDqaR8Vb2v4
         ZSiqoB07Z7iRZY2h/aqmUCIaBAP3hRx0PepRrANrVwyeH1xmuJfS74JmQ7BaVFHd7tb4
         7dCukLYYqRNUdnw7m7ulM4M4y2anJ658itXHy1mOfrPqaEFbwEffKZG33e1Rv0Nx0uk5
         6N4gd2VwGfgwBu3XsKs7AifyqsVK9OtiRG5V8O9JEFRkTiakgHLnhBWDGF6FcqLDYosz
         F5d9mrD9jCPfnK+dHF47kxZOe7QsMRf4wSnK1pK6L/GWtDsZZjPunjWtYKinBiVclgSj
         WVsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3vie9ne454e3GquDz3OOSeccUAv7FXA/CSubS12mJe8LWi7x2U
	4iUpvRGGUiubeoJHAfP/D1g=
X-Google-Smtp-Source: ADFU+vsRtwNTC7KY8KxzrngjzqQlLmxaQX9VoXFOL5ZsyM+3BOJXhCGiGdV03Lxc91kFpqHq0C/QJg==
X-Received: by 2002:adf:d4d2:: with SMTP id w18mr9790041wrk.180.1583401435845;
        Thu, 05 Mar 2020 01:43:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e589:: with SMTP id l9ls695022wrm.0.gmail; Thu, 05 Mar
 2020 01:43:55 -0800 (PST)
X-Received: by 2002:adf:c404:: with SMTP id v4mr9698973wrf.53.1583401435490;
        Thu, 05 Mar 2020 01:43:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583401435; cv=none;
        d=google.com; s=arc-20160816;
        b=vrLewzycL8n6tP26EKoZ7VdgccvZzAx32oXMHK7yFrXaHimTJFq1zl2h8gmlIFzUuD
         j+c9PJc07/FQWzIBB7FUO9udBviGhdf77TB2fB49FOR2ydB7Lq0hcfenVeqyPDd/eQVD
         KcIY5E+68JZ/YNij/8t/8lvh37aITsMAThsf2bjZ85GAj+9Iz3GJHjmLL6QYhgqmABYo
         3nPIhN/JIlaI9taoQ+6GSfP+d/w4FUgACi3SoeZxlrWoZ3+qKcX2NBkMOu/hFRDQovxW
         zRee8h32e+assl2300ltkn12rti1Al+CG0mv5MK0wEQzw7zA/aOkGQR6UO3AJV9T+cAD
         mRkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=h7kj3gA8ocoT1p8NnPmqfRUczHpCYJtHP9tHr2kEjj4=;
        b=wk/7tToZEClA9/EwcDOKw9GM/DdTpZmfTxsdQNyvupUsbtiq6aY5Q9CqWhhFg0kDdT
         yNPxVyxApUO19jsmc6n4hMG2OTN3aecn2ySZhNGBKW7lJcO1GptkmkbNRFQKk+9FxNtA
         JnRNg40b2qDVHGt+YOSJ3te08WtDqahRiAUv0Sg3Z4qF8HgB53CpZVOyA4slQH+kDjfV
         /tf+lZFSjbMsgWQ5/oLHvFYoDJpYPQ7hIRUq/g5G0yO6zl31jW8/zoAsvWJs6yn8N+BH
         qv6XrlEGLB9+4A6OS6BniKTftPBChBIHTwgzsmNSd4jY6GNKxFnbFDaYefy0IuspWDZz
         Fi7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mfe@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=mfe@pengutronix.de
Received: from metis.ext.pengutronix.de (metis.ext.pengutronix.de. [2001:67c:670:201:290:27ff:fe1d:cc33])
        by gmr-mx.google.com with ESMTPS id m2si337044wmi.3.2020.03.05.01.43.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2020 01:43:55 -0800 (PST)
Received-SPF: pass (google.com: domain of mfe@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) client-ip=2001:67c:670:201:290:27ff:fe1d:cc33;
Received: from pty.hi.pengutronix.de ([2001:67c:670:100:1d::c5])
	by metis.ext.pengutronix.de with esmtps (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <mfe@pengutronix.de>)
	id 1j9n2b-0003Jp-1c; Thu, 05 Mar 2020 10:43:41 +0100
Received: from mfe by pty.hi.pengutronix.de with local (Exim 4.89)
	(envelope-from <mfe@pengutronix.de>)
	id 1j9n2P-0007e4-2o; Thu, 05 Mar 2020 10:43:29 +0100
Date: Thu, 5 Mar 2020 10:43:29 +0100
From: Marco Felsch <m.felsch@pengutronix.de>
To: Linus Walleij <linus.walleij@linaro.org>
Cc: Florian Fainelli <f.fainelli@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexandre Belloni <alexandre.belloni@bootlin.com>,
	Michal Hocko <mhocko@suse.com>,
	Julien Thierry <julien.thierry@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoffer Dall <christoffer.dall@arm.com>,
	David Howells <dhowells@redhat.com>,
	Masahiro Yamada <yamada.masahiro@socionext.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	kvmarm@lists.cs.columbia.edu, Jonathan Corbet <corbet@lwn.net>,
	Abbott Liu <liuwenliang@huawei.com>,
	Daniel Lezcano <daniel.lezcano@linaro.org>,
	Russell King <linux@armlinux.org.uk>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	bcm-kernel-feedback-list <bcm-kernel-feedback-list@broadcom.com>,
	drjones@redhat.com, Vladimir Murzin <vladimir.murzin@arm.com>,
	Kees Cook <keescook@chromium.org>, Arnd Bergmann <arnd@arndb.de>,
	Marc Zyngier <marc.zyngier@arm.com>,
	Andre Przywara <andre.przywara@arm.com>,
	Philippe Ombredanne <pombredanne@nexb.com>,
	Jinbum Park <jinb.park7@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Sascha Hauer <kernel@pengutronix.de>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Nicolas Pitre <nico@fluxnic.net>,
	Greg KH <gregkh@linuxfoundation.org>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Linux Doc Mailing List <linux-doc@vger.kernel.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	Rob Landley <rob@landley.net>, philip@cog.systems,
	Andrew Morton <akpm@linux-foundation.org>,
	Thomas Garnier <thgarnie@google.com>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
Subject: Re: [PATCH v6 0/6] KASan for arm
Message-ID: <20200305094328.sizz4vm4wamywdct@pengutronix.de>
References: <20190617221134.9930-1-f.fainelli@gmail.com>
 <20191114181243.q37rxoo3seds6oxy@pengutronix.de>
 <7322163f-e08e-a6b7-b143-e9d59917ee5b@gmail.com>
 <20191115070842.2x7psp243nfo76co@pengutronix.de>
 <20191115114416.ba6lmwb7q4gmepzc@pengutronix.de>
 <60bda4a9-f4f8-3641-2612-17fab3173b29@gmail.com>
 <CACRpkdYJR3gQCb4WXwF4tGzk+tT7jMcV9=nDK0PFkeh+0G11bA@mail.gmail.com>
 <2639dfb0-9e48-cc0f-27e5-34308f790293@gmail.com>
 <CACRpkdZ8JA=DXOxzYwyvBxCMd2Q5uzLTn87AVK7wdrxHFo5ydQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACRpkdZ8JA=DXOxzYwyvBxCMd2Q5uzLTn87AVK7wdrxHFo5ydQ@mail.gmail.com>
X-Sent-From: Pengutronix Hildesheim
X-URL: http://www.pengutronix.de/
X-IRC: #ptxdist @freenode
X-Accept-Language: de,en
X-Accept-Content-Type: text/plain
X-Uptime: 10:40:52 up 111 days, 59 min, 138 users,  load average: 0.50, 0.16,
 0.05
User-Agent: NeoMutt/20170113 (1.7.2)
X-SA-Exim-Connect-IP: 2001:67c:670:100:1d::c5
X-SA-Exim-Mail-From: mfe@pengutronix.de
X-SA-Exim-Scanned: No (on metis.ext.pengutronix.de); SAEximRunCond expanded to false
X-PTX-Original-Recipient: kasan-dev@googlegroups.com
X-Original-Sender: m.felsch@pengutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mfe@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33
 as permitted sender) smtp.mailfrom=mfe@pengutronix.de
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

On 20-03-05 09:43, Linus Walleij wrote:
> Hi Florian,
> 
> On Fri, Jan 17, 2020 at 8:55 PM Florian Fainelli <f.fainelli@gmail.com> wrote:
> 
> > Let me submit and rebase v7 get the auto builders some days to see if it
> > exposes a new build issue and then we toss it to RMK's patch tracker and
> > fix bugs from there?
> 
> Sorry for hammering, can we get some initial patches going into
> Russell's patch tracker here? I can sign them off and put them in
> if you don't have time.

I've tested the branch on several imx6 based boards with different
toolchains. Some boards booting normal and some of them are lost in
space... I didn't debugged it yet just wanted to inform you.

Regards,
  Marco

> Thanks,
> Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200305094328.sizz4vm4wamywdct%40pengutronix.de.
