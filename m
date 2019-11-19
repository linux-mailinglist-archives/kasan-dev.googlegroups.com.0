Return-Path: <kasan-dev+bncBAABBQE22HXAKGQEHBYICYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 373EB102D55
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 21:14:57 +0100 (CET)
Received: by mail-ua1-x93b.google.com with SMTP id 49sf4920833uad.20
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 12:14:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574194496; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uq/Xii4dYOnESvokjsNS9TZKcIcxRjLr8qQLr/SCkjEBNKOz2sGXyVGH22FwJA8qbx
         uATkvhjITelteScoBligF6c/h6N81wQp+0N4hmvHk8pDfrXVedPvR3gdarYXPb9bPMSm
         4JNBG6R0NUrXzEQM8QuYPrgdsw1YJhGN5M4jC1Hgf2rNPz3VhCxGog12j2g1i4XPYoCV
         Rb3Nep/oAF2MngXv6CJ7+B9H8voEfQMXjdnujbL+Y6fWFqxrop72DnI/0gb+u0A2Bo0v
         6+EEX20Nq3NZ60U47d5e3m8xV+YTBLhTWJxaMwRFkYmxMRDz8Ba1Y2joM/fgW3rvahPM
         4jIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HuDkdfuVnAi2biTcQ5URaWKkD/5PFsdTmGfZRfLpev0=;
        b=UWFfpwrPuQKg2YyuDRH34+3OV6cxePre8l3eAuvgbqOQ97cDCSVdQwIsqR4cIgFNKg
         h2KgJQdogO/eWdJEjOYG06ehFMXt9k4SFA1j14VACETih1PuHmEh98LUELFgPcY6NSge
         Uoh4WDz3bFoepDwYjVMIhWqvcBKO7I0/GsxsoJjxSWeF1y+y74EOSifp/ktOCpIjwwXd
         ujPULvhlFi+t0EZNsXDBGuzw6KffAwDGr0w9BU+C6K0SSa0pacF+CGAFeHIu8087Kbc5
         Cn/JHjT+rWqjNPiZ64Bx8GH6qS35WTPbmCThDCFxeqL4Euj29kR8BPiJ0C+KQdZ1D7eu
         8MIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=SwLovSoQ;
       spf=pass (google.com: domain of srs0=yygb=zl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YYgb=ZL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HuDkdfuVnAi2biTcQ5URaWKkD/5PFsdTmGfZRfLpev0=;
        b=f/3bBPLvkIROBgUqRJRFbdcfJvUQbVHRsXqLqJM3rkGXX14K7k5Z2FaZcB3+/MMx+r
         fSf565pcCxWST95Y1AmbpHrBrq6hEYk54vQa0AagQKUPM19P0Amj4SV8VCWf1tpP2JZo
         OJ5S523P67nM6ih9jw13Bw1MRSt64k8ktXPw47pMSe0ffB8S/AgSyDLmxOdzIRE4z/Pu
         KuNs0d44KOnQdRbqcYZaKV4JDWnI6+d/GdBwzUOjtR0+ccTvIwR8r4nVFiLKsrfNkbvk
         DRdwL4btwKvUuJ3eOiOn8LkBx+mO69oyAQti8tuQrAdh3XNC9xgfAMfoRcPAdEKgAe5D
         3NOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HuDkdfuVnAi2biTcQ5URaWKkD/5PFsdTmGfZRfLpev0=;
        b=KhHJGEmjMBSLsmULoxDZrSean/uDjKUdnwpPTmHaD3MfPln0GrlAIMNwUS7Unk8Ial
         aka2233960Jl+vBqbWyPkdfZYwft5w+9ql/58iCa+EY2dbSg0G7geGZNggAqy/YhZ3hw
         tH2ULw+AkS4oWZlM+5uNwIifSqZ6Z5trL2iANdnzAeNRz5ArW0CqRDDPnLkzbOkGZb8C
         GglnYrVBbYXuf8vY2Cw38gyMQQ6k3rHzy3AhSWxjp3ZiHLDawO47Yo5DuFJD4MsA65I5
         RcPptkCK85QeveBkFk3FCDUnyiExkIlepF0w3GVg9amsgEi71wbENUsIMD+vboCsx7Xn
         Ycmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU62lubHAsDud2qf6/XpQcALxHvU1jjpCjL+h1pXgQtiVmKET+9
	HcU82QXKnbOglK2O5wJ4S7M=
X-Google-Smtp-Source: APXvYqzTHol09zxINQDHXE5sEbxnL0MNqOEgVuQV3+AOapW+qdHxhoQXIt7Kxw1lvSz+amACZlvP/A==
X-Received: by 2002:a67:fad3:: with SMTP id g19mr4505787vsq.216.1574194496231;
        Tue, 19 Nov 2019 12:14:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:710c:: with SMTP id x12ls1554172uan.16.gmail; Tue, 19
 Nov 2019 12:14:55 -0800 (PST)
X-Received: by 2002:ab0:4e87:: with SMTP id l7mr22975283uah.63.1574194495848;
        Tue, 19 Nov 2019 12:14:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574194495; cv=none;
        d=google.com; s=arc-20160816;
        b=J3qzGGDHC/TB74ed5prgyHuETMAoyJYR3mkGoyOhp8pqW0JurTa5/sYDbiW0GRJMJp
         OjTJ2kXrnzns1zKO47MhjC09gB/GE/m8Q/WjhrBIlcNZ9Y/hnq1Fz2CaC1oTjLYE6+iU
         XN7Lw22+G5ZJfIGmNdJ7XyUI2wMZxeTNqHKHOZy7cI6qsNWTFHxBWQYHik+kpHqb45i/
         gzDM4/goV3SDbkbqKRoM1ReWPhaPUJbhox16YtvRpxyyUXbvrr4L2bmARzh8Que9wKEr
         P5IqBkPX46iCRKDWDhPZNPUD0eCtKVaNCOSjzZT2V7njTaTsol8d4dsQ1SsgjDIpvQAT
         I3TA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=PTEYttdJmVnCI1hp3YE0ED2m1O+cmXYC4pHie36qen0=;
        b=hNk540MNCOLKhjGQ0rDtYBTHWUHAaR85DTr00pYOv1yiKf5FTTbTbWuse2P3E1oAqi
         nnfoYbeVvl1CCtzmXGrcyVCBnPB3ztlBM2eOgtDhm7p1y53kkTp9L9Fi3ppBJxpls/b7
         CYPCMT3wNEbVfzaogUXc1I8YI3omNU5NldicLZRg0zOQ2tsVSFO3e2EuJ6UPO3xPkp0r
         1w6FzC0EeY0NOaqp614+EKY0Ra5LwUzv0XWoWXQWWWDBskQl1bwJDw0kfkYJV4GHd3pk
         ZQFK+r/ktxVGhBfKFuzg6Ing2wVUjZsYbrn4Y6oiIetM1Y+5bWr+xaa3p6tBP/44rPK3
         cqVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=SwLovSoQ;
       spf=pass (google.com: domain of srs0=yygb=zl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YYgb=ZL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n138si1269409vkf.2.2019.11.19.12.14.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Nov 2019 12:14:55 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=yygb=zl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [199.201.64.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B175C22317;
	Tue, 19 Nov 2019 20:14:54 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 4BC933520FA7; Tue, 19 Nov 2019 12:14:54 -0800 (PST)
Date: Tue, 19 Nov 2019 12:14:54 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Qian Cai <cai@lca.pw>, Randy Dunlap <rdunlap@infradead.org>,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	Linux Next Mailing List <linux-next@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: Re: linux-next: Tree for Nov 19 (kcsan)
Message-ID: <20191119201454.GE2889@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20191119194658.39af50d0@canb.auug.org.au>
 <e75be639-110a-c615-3ec7-a107318b7746@infradead.org>
 <CANpmjNMpnY54kDdGwOPOD84UDf=Fzqtu62ifTds2vZn4t4YigQ@mail.gmail.com>
 <fb7e25d8-aba4-3dcf-7761-cb7ecb3ebb71@infradead.org>
 <20191119183407.GA68739@google.com>
 <1574190168.9585.4.camel@lca.pw>
 <CANpmjNMfCNqgsXQdDckOg0kuMgvnD8_jka8N0AT2K3hC=CUe0w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNMfCNqgsXQdDckOg0kuMgvnD8_jka8N0AT2K3hC=CUe0w@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=SwLovSoQ;       spf=pass
 (google.com: domain of srs0=yygb=zl=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YYgb=ZL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Nov 19, 2019 at 08:05:45PM +0100, Marco Elver wrote:
> On Tue, 19 Nov 2019 at 20:02, Qian Cai <cai@lca.pw> wrote:
> >
> > On Tue, 2019-11-19 at 19:34 +0100, 'Marco Elver' via kasan-dev wrote:
> > > On Tue, 19 Nov 2019, Randy Dunlap wrote:
> > >
> > > > On 11/19/19 8:12 AM, Marco Elver wrote:
> > > > > On Tue, 19 Nov 2019 at 16:11, Randy Dunlap <rdunlap@infradead.org=
> wrote:
> > > > > >
> > > > > > On 11/19/19 12:46 AM, Stephen Rothwell wrote:
> > > > > > > Hi all,
> > > > > > >
> > > > > > > Changes since 20191118:
> > > > > > >
> > > > > >
> > > > > > on x86_64:
> > > > > >
> > > > > > It seems that this function can already be known by the compile=
r as a
> > > > > > builtin:
> > > > > >
> > > > > > ../kernel/kcsan/core.c:619:6: warning: conflicting types for bu=
ilt-in function =E2=80=98__tsan_func_exit=E2=80=99 [-Wbuiltin-declaration-m=
ismatch]
> > > > > >  void __tsan_func_exit(void)
> > > > > >       ^~~~~~~~~~~~~~~~
> > > > > >
> > > > > >
> > > > > > $ gcc --version
> > > > > > gcc (SUSE Linux) 7.4.1 20190905 [gcc-7-branch revision 275407]
> > > > >
> > > > > Interesting. Could you share the .config? So far I haven't been a=
ble
> > > > > to reproduce.
> > > >
> > > > Sure, it's attached.
> > >
> > > Thanks, the config did the trick, even for gcc 9.0.0.
> > >
> > > The problem is CONFIG_UBSAN=3Dy. We haven't explicitly disallowed it =
like
> > > with KASAN. In principle there should be nothing wrong with KCSAN+UBS=
AN.
> > >
> > > There are 3 options:
> > > 1. Just disable UBSAN for KCSAN, and also disable KCSAN for UBSAN.
> > > 2. Restrict the config to not allow combining KCSAN and UBSAN.
> > > 3. Leave things as-is.
> > >
> > > Option 1 probably makes most sense, and I'll send a patch for that
> > > unless there are major objections.
> >
> > Both option #1 and #2 sounds quite unfortunate, as UBSAN is quite valua=
ble for
> > debugging. Hence, it is desire to make both work at the same time.
>=20
> Apologies, I think I was a bit unclear with #1. For #1, this just
> means that UBSAN is being disabled for the KCSAN runtime and
> vice-versa. All other parts of the kernel are still instrumented with
> both.
>=20
> See here: https://lore.kernel.org/linux-next/20191119185742.GB68739@googl=
e.com/

Huh.   This somehow got stuck into my non-urgent email.  No idea why.

Anyway, I applied and pushed it out on the kcsan branch of -rcu.

						Thanx, Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20191119201454.GE2889%40paulmck-ThinkPad-P72.
