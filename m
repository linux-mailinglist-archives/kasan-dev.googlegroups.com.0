Return-Path: <kasan-dev+bncBAABBMG4SPZAKGQE6HXEQPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D153C15B99C
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 07:35:29 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id z21sf3544025iob.22
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 22:35:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581575728; cv=pass;
        d=google.com; s=arc-20160816;
        b=PvgKhauYOvUKMjQcTCNmLuKQmZosCTa1QoxaKenyymFboQKKOegJ9lrpOKCJFnEsIU
         EP2xMn3vGqiAv/8CenEMBXNLEZbi+FWjv7dSDJl+B8IUii6qcyuGqXtVoe9xcktCu3K0
         JPJSKinc+/YgrxHwtx3lIKYGSIYmXFKSjvEFxv7owEBe/xrCaQCLsX4zly3wBAMUvRU2
         6IlhCkbs/deJnsxBs3uiFSAIUo5u93yhHCSlaW336ZD/iwMeGe5C/OQ2TkV+ew/pNnWQ
         3qc0d3b3CMDCFj6UoTU8TJJovvf1OBhJMJN+wEs5enQE56ThbHTppa1LEBaAJO4h0g7H
         ho8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=s/bu8oCDUTS3fLXhYs621D+1+LkScE7WstcdB0cLXiQ=;
        b=iy9mNzVG9WvR5pC6ZBIUSTVjj698+VRwV9Ic756OxQNLiBoi7dIly9KOpwhM2KK2TT
         Za03KEQSGXWX94uM1D/0nXdkMVxq7jq3CnKS62khi9aNSSJIKA4XSJLle7xqLmgVetrY
         2iK+NH6F2PL/SWYxfiYSpGPtITODlOa2Qk4Yh3SuzBojnO9y9MTHJkbS+2bnsjMcxBH1
         L3/NvQ/JA0Qat1ktdnZcBX1nz4uBA5lIFWQuMK67vAw3jDTiMsiHPDAxzvwXGOHiOHHU
         vaZaNq7Dxk36zN/D0pJ6wY1PeNWCSRh64t7+n8m7l9G4Zx7WR0WvYEueFLw0OEPduBA9
         i8EA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=PSexIC8t;
       spf=pass (google.com: domain of srs0=+dwc=4b=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=+DWC=4B=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=s/bu8oCDUTS3fLXhYs621D+1+LkScE7WstcdB0cLXiQ=;
        b=j7XFfpyHS5JllR1bEP2Y5u+8GX7fti5PA9SEmufOUN1AVrjOxZKWpOgVnsPFwg6BtT
         gfnlZTv+8cbU5nrjbX/z6Ip3WiJgMKhsVDQsf+rhgghZUHZw2HMLTg1vYpYqgPv+WICF
         5SRaI2KsIdx1ei+UR2+tjzQGePFeywCisnToW4Cl/y6Gnw2AnzcAXMSyhhoECLv3QL8Y
         RR6++M8LxGY+ebv9/DIaJRjiO3Il2TztP5Jp8cALUGCMecG7cQ1udi7RLEPNbt4XXABb
         zo7xzJDfStIKMRWjDM+oNPK1iN56BYFb4CmgIaO1pIcB9Uma5Z7nlupNbavF159yEDh0
         DAPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s/bu8oCDUTS3fLXhYs621D+1+LkScE7WstcdB0cLXiQ=;
        b=WUWW7e9BwEmNqR2lE+v+KaDCCBV9Wci/h9WvJw+byWXyChD8ziC0xj2zAJDuPiOp3d
         bWEPHY7cU18Yrpq4OspnNv6aNmujemV98VZxbtQn6wpvDwwCQ6m4EfD8T7rCrV5kemKy
         DmLt77Nz5Xai3cwgOt4cOho1YI0lgDXYWqP0k3R/IesT3WNB2G3Zfk3S46KzcJLmp8hK
         bIF8IEnc3BWbf+CcWs2B7YTXGsEPC0QwsHpfZsPKyMyGBGWhvCZhZKFcf0q0ukjsZRA3
         U29VrNw0F3MEZDr+noHQKdUQRF9cbYWQzKWpTZY+f1pRUczuRmWbTuy48TqwMgpbaHc9
         7fQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX91oU2eudfiXEexLQpG8QAGd+O8TvFGieN/JLfXnMgyHqBpRmo
	56OSyTEM6wgkzgDh0DfUaoQ=
X-Google-Smtp-Source: APXvYqyu797RRX+9SdXVobgdGoDV7nvUbIXZb24dbyE8sMxGaK/2Tdc2Vb4TbojkB/tvFsEQ8FnlkA==
X-Received: by 2002:a6b:d019:: with SMTP id x25mr20805612ioa.275.1581575728811;
        Wed, 12 Feb 2020 22:35:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:6116:: with SMTP id v22ls3806624iob.11.gmail; Wed, 12
 Feb 2020 22:35:28 -0800 (PST)
X-Received: by 2002:a5d:8258:: with SMTP id n24mr20352114ioo.157.1581575728413;
        Wed, 12 Feb 2020 22:35:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581575728; cv=none;
        d=google.com; s=arc-20160816;
        b=DqK6hcjOuWutoMYSG1RWdIZ8Fn7RC0FevZucttiHGxIFdKsICLhClZhMss56YqIn2H
         N4Khpy9sPcX78tk19e8GR7y8UCq21X0v6UNx13QZzBlAOrtp81IXtKkYMQqHOgiUJjOo
         JKZEamg9PI3MZlytc/FDd5sbbW5248R6jACdISDG/jkKOlJhK24r4LAf3qxNPu5vrMBp
         nFK5zi/y4ZRzZ82CfEIPB/TlnVNBUzFpvDoyIhKIMWOI78z58wBIdzDEFut6dCxlZFy7
         n3RRSVFN1WhJszB3nKh/2vtHh1pP6sZuzynFpkh+yZsXxTNwAdx/IGvqUCTUX9nEJN1p
         zfCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=94tRB4x0zmqRgW9oeCG4cW+CfbhMoSyXelNqJ1+P860=;
        b=a3lyhPGgoHL+LwAN7xyJpYLKhqVbJYdQO+kaLIFD6jlaq6FpTAit8s0JlVI9rHFP6e
         RZs8ZP2klV+gNvwEjEqTQk874Uv4Vzw1OJcF5WFVABCixii0HglGE42RyMcOIWowY1c5
         0bNUyouifgYaCvvTGR35p/c7NE56icmoRkQhhWHdoSkhFwATRys++IEmmuE6gNChPAXQ
         OfD3RA+q/w7D1hOhDf516OkSJuyr/yt8ZCJel0PxUPk0r6OTAhLUL6HunmJGTjuebg9U
         tYrOeZWukoTTCMKqAU1d7V+vSEyUXu8UiTCf08VcG8UfdItl7Ho4MdYrDXj3QEz/el/6
         3qjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=PSexIC8t;
       spf=pass (google.com: domain of srs0=+dwc=4b=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=+DWC=4B=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p9si69207iog.5.2020.02.12.22.35.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 12 Feb 2020 22:35:28 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=+dwc=4b=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [62.84.152.189])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 633B62168B;
	Thu, 13 Feb 2020 06:35:27 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 834B43520CBE; Wed, 12 Feb 2020 22:35:25 -0800 (PST)
Date: Wed, 12 Feb 2020 22:35:25 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Qian Cai <cai@lca.pw>
Cc: Marco Elver <elver@google.com>, John Hubbard <jhubbard@nvidia.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>, Jan Kara <jack@suse.cz>
Subject: Re: [PATCH v2 5/5] kcsan: Introduce ASSERT_EXCLUSIVE_BITS(var, mask)
Message-ID: <20200213063525.GU2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <CANpmjNOWzWB2GgJiZx7c96qoy-e+BDFUx9zYr+1hZS1SUS7LBQ@mail.gmail.com>
 <ED2B665D-CF42-45BD-B476-523E3549F127@lca.pw>
 <20200212214029.GS2935@paulmck-ThinkPad-P72>
 <79934F2A-E151-480F-B1B1-1C713F932CEC@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <79934F2A-E151-480F-B1B1-1C713F932CEC@lca.pw>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=PSexIC8t;       spf=pass
 (google.com: domain of srs0=+dwc=4b=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=+DWC=4B=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Content-Transfer-Encoding: quoted-printable
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

On Wed, Feb 12, 2020 at 07:48:15PM -0500, Qian Cai wrote:
>=20
>=20
> > On Feb 12, 2020, at 4:40 PM, Paul E. McKenney <paulmck@kernel.org> wrot=
e:
> >=20
> > On Wed, Feb 12, 2020 at 07:30:16AM -0500, Qian Cai wrote:
> >>=20
> >>=20
> >>> On Feb 12, 2020, at 5:57 AM, Marco Elver <elver@google.com> wrote:
> >>>=20
> >>> KCSAN is currently in -rcu (kcsan branch has the latest version),
> >>> -tip, and -next.
> >>=20
> >> It would like be nice to at least have this patchset can be applied ag=
ainst the linux-next, so I can try it a spin.
> >>=20
> >> Maybe a better question to Paul if he could push all the latest kcsan =
code base to linux-next soon since we are now past the merging window. I al=
so noticed some data races in rcu but only found out some of them had alrea=
dy been fixed in rcu tree but not in linux-next.
> >=20
> > I have pushed all that I have queued other than the last set of five,
> > which I will do tomorrow (Prague time) if testing goes well.
> >=20
> > Could you please check the -rcu "dev" branch to see if I am missing any
> > of the KCSAN patches?
>=20
> Nope. It looks good to me.

Thank you for checking!

							Thanx, Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200213063525.GU2935%40paulmck-ThinkPad-P72.
