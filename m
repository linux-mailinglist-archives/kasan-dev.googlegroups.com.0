Return-Path: <kasan-dev+bncBCJZRXGY5YJBBB456KDAMGQEG2IYYNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F8083B8648
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 17:32:24 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id i24-20020a9d62580000b0290464ba1bb21esf1893672otk.5
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 08:32:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625067143; cv=pass;
        d=google.com; s=arc-20160816;
        b=IpNZd1Em0ksW54nza7dbtRKwmAXiAs+oVyMmqEjvQth1JjS/oy54+AleP9eF+yvngB
         Efx00eDIO768AZtjvqHHNn6qlccBcpVPN27bD5btDD3c78bEBjymfksHLCMbeyfwzkN1
         rWO5B+sZMSx+n5lAG6mDos4Oa28tU9xeKpF9wO6621fgQip7qryZMDnw34wwXBcaPDzJ
         6cFG5bE8ykqHhRbifzvIb5vttaBVYy6RSPW8fOTBcaly9F3mVniXxpfY9Nzw6eGZG438
         0GXbA6j/Qi6eOdSBiwpe3d6P+M9bdOw9lDrklVeRbfNhIOcPhbQXHyAZBf4hSJLhH2JS
         tShw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=al1LnBkLZQ1+zKshcR+dc7xuhWTErKJRBvioh4CgoWM=;
        b=nBi5HGkckuypPbH1o8Nl1oYK9pkCJuKhB0txLHMqiz7wimBz/hC4WebzyUeE64dOBr
         N1GXG/h9UloThA+kz1NtOp3YnNzJp/m7gh68xGYfSscGnh5vv4SlSeUFZfudItJepbAy
         AcB+nLQmI1Pl+XyyF8oWhGFA9he4pFW4tUB/XBrFMupgliEjL4Jh4nQD2vN8L30kdWX+
         OZo+sRmR+NqVEIUj3XA7HKAUbprjSScUjBPCaaQFkw2ARTrxUIWRm2gBGpo9nDZFlkmk
         g4koMTUNTy7ggjoBGjcQiFIofTKKl4JYgkllSwpWLt9yZa58irdSJ2/atbl9fry//Kk5
         ocNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rkCyQ++0;
       spf=pass (google.com: domain of srs0=uabw=ly=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=UabW=LY=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=al1LnBkLZQ1+zKshcR+dc7xuhWTErKJRBvioh4CgoWM=;
        b=OrYys84rw63glhj1myllYWAbmVCZXd+705r0cgThrRghKIWWyE5PM3cfwI90ZptFGx
         amE+y/iI6U3nx6KdJ867bs3P9XvScscZgtw93gmmv2y1P3uijinQdRtvrNO6AeSylUIA
         SH9g53jWVOUKg7QFabCkslP8mNN6elQw/+oROoni3etFaXZdI7sNrJpvlTAZsx8XQONV
         Cbg3i4W085NTBAEqOwHD6E2grR9joba7dA9jFwEnxZgHv0GhJ5mrZO2J4bevSfD0vgTK
         ErG80Von8P9Xtjy0xXjVN/Tl1utUrVNeU14pASyNPaXoE2a5j7u4ImxIWgj1bX4EgnKC
         zQqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=al1LnBkLZQ1+zKshcR+dc7xuhWTErKJRBvioh4CgoWM=;
        b=bgjNB2eD+Kzy/i9P1MH2tW5NmVm2u3fgr4LZ9OtmXu7cyi3tGu5YPKgVFhCf73VioC
         Qz8cPldbBIdqO0IT/Kdb39uxz4WYJ9kdO5/cjtNDSnZM9sLjVJnTKjYnY16EKdGMiuSF
         7qioGNVvrphaXK3vjKlIt1+D5zKLlaXp6nWjEASbgpdex8G8TdDD6leEgwxIX0mZ9Caf
         HMVlMHYI1pqEtt8GThMq5Ei2c91URpaJzDVSYYbnSzbsp/MpltdH1YlHcJhWitcuhujQ
         Ir3nJN0hMrUO30lSKYgMYsW/TS2DvfZ8bzqs9ECHDyRPdOpKS4SGhgdKaMiQkX0gUeIt
         o80w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530CT9jquXhzSKGQg+qN2zRVr6KsgYIIEINv+0nvJof4KlObuN42
	wQAQxNEQWfWV3kh9HzomNEE=
X-Google-Smtp-Source: ABdhPJwO4/Y8oiLc71MzcdHaibOFAbwxN+HqKJjgGwe1XCVOKyEUxbhCwmKTSS17oM9fY+PxtthqPA==
X-Received: by 2002:a9d:2781:: with SMTP id c1mr9315576otb.34.1625067143175;
        Wed, 30 Jun 2021 08:32:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:bd6:: with SMTP id o22ls922485oik.1.gmail; Wed, 30
 Jun 2021 08:32:22 -0700 (PDT)
X-Received: by 2002:aca:af8d:: with SMTP id y135mr488905oie.110.1625067142843;
        Wed, 30 Jun 2021 08:32:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625067142; cv=none;
        d=google.com; s=arc-20160816;
        b=Ea2+KnR84BPf85ibUIUH7BJn8blKS4Z2RX3u441WfguJP92zoG3Gkd8EkPw4OkwYiR
         SRSU6jFESq54MYPYWK4rcUXHOkFkEctu+C+bZpsYrzP+I5PCtohx/6smXZdSBrjSq2An
         t9I5Z6Tu3ZPdJ0mDlLQyqnjD44TpaqjNFfAEqzx7nqFDDZFLnubuWV9g0yZHbyPxFKRj
         1PRqGsQhGnE/JVPREy1YJBMJqwVJDOEgScieWML3kJKr22kDZ/9+qygbFQ9vt7rMeuA7
         Rl/OWfvJVMJHLAGe2+lG/BnLqj/RGWH5zak/1E4CMvkL57F9K5MMDa90dT5zYMW9t6SC
         mVnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=PiqFD4xSS20hITKJzikGmH94Xi72SJmGPI5K5ACZYUQ=;
        b=qebefr8Q5ipiiG3udpJOxyHlYZhxIKCEJ/TRQ1jnhi1WmW0jI9PbX0sHFZZ3prXbXX
         4GeR9Wz4wnC20FrBoqentHx+Rvb5UdFLS9DKXDzY0CeR9MMC6pgNzonDDwuo/MDddO86
         Q5+XS0Bi12YiaB2O1ypd5mZ19oHVNO57SCdGxceQxOSmED/zjhp+tDk81mYH5xW+N4jF
         q+2bxJfNjQdePiEPCEpFTTO0FJPpdm7Zl3YIUAxpL7FRkwRZVcgTUPgxok+u/aSWK6OW
         s8OmuL8Q0+UXUbgilo+heOhS3NDfQaQRN7S4/pwEHoY82fMRKdRbLwc/5ieqyo3mFKBn
         YdLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rkCyQ++0;
       spf=pass (google.com: domain of srs0=uabw=ly=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=UabW=LY=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l8si99540otn.1.2021.06.30.08.32.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 30 Jun 2021 08:32:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=uabw=ly=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id DB2756147D;
	Wed, 30 Jun 2021 15:32:21 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id AF2435C0267; Wed, 30 Jun 2021 08:32:21 -0700 (PDT)
Date: Wed, 30 Jun 2021 08:32:21 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Ingo Molnar <mingo@kernel.org>
Cc: eb@emlix.com, frederic@kernel.org, jbi.octave@gmail.com,
	maninder1.s@samsung.com, qiang.zhang@windriver.com,
	urezki@gmail.com, yury.norov@gmail.com, zhouzhouyi@gmail.com,
	mark.rutland@arm.com, elver@google.com, bjorn.topel@intel.com,
	akiyks@gmail.com, linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
	kasan-dev@googlegroups.com, tglx@linutronix.de
Subject: Re: [GIT PULL tip/core/rcu] RCU, LKMM, and KCSAN commits for v5.14
Message-ID: <20210630153221.GW4397@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210609232926.GA1715440@paulmck-ThinkPad-P17-Gen-1>
 <YNx0CaT2ZTyuNYCK@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <YNx0CaT2ZTyuNYCK@gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rkCyQ++0;       spf=pass
 (google.com: domain of srs0=uabw=ly=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=UabW=LY=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Wed, Jun 30, 2021 at 03:39:21PM +0200, Ingo Molnar wrote:
>=20
> * Paul E. McKenney <paulmck@kernel.org> wrote:
>=20
> > Hello, Ingo!
> >=20
> > This pull request contains changes for RCU, KCSAN, and LKMM.  You can
> > pull the entire group using branch for-mingo.  Or, if you prefer, you
> > can pull them separately, using for-mingo-rcu to pull the RCU changes,
> > for-mingo-kcsan to pull the KCSAN changes, and for-mingo-lkmm to pull
> > the LKMM changes.
> >=20
> > The changes are as follows:
> >=20
> > 1.	RCU changes (for-mingo-rcu):
> >=20
> > 	a.	Bitmap support for "all" as alias for all bits, and with
> > 		modifiers allowed, courtesy of Yury Norov.  This change
> > 		means that "rcu_nocbs=3Dall:1/2" would offload all the
> > 		even-numbered CPUs regardless of the number of CPUs on
> > 		the system.
> > 		https://lore.kernel.org/lkml/20210511224115.GA2892092@paulmck-ThinkPa=
d-P17-Gen-1
> >=20
> > 	b.	Documentation updates.
> > 		https://lore.kernel.org/lkml/20210511224402.GA2892361@paulmck-ThinkPa=
d-P17-Gen-1
> >=20
> > 	c.	Miscellaneous fixes.
> > 		https://lore.kernel.org/lkml/20210511225241.GA2893003@paulmck-ThinkPa=
d-P17-Gen-1
> >=20
> > 	d.	kvfree_rcu updates, courtesy of Uladzislau Rezki and Zhang Qiang.
> > 		https://lore.kernel.org/lkml/20210511225450.GA2893337@paulmck-ThinkPa=
d-P17-Gen-1
> >=20
> > 	e.	mm_dump_obj() updates, courtesy of Maninder Singh, acked
> > 		by Vlastimil Babka.
> > 		https://lore.kernel.org/lkml/20210511225744.GA2893615@paulmck-ThinkPa=
d-P17-Gen-1
> >=20
> > 	f.	RCU callback offloading updates, courtesy of Frederic
> > 		Weisbecker and Ingo Molnar.  ;-)
> > 		https://lore.kernel.org/lkml/20210511230244.GA2894061@paulmck-ThinkPa=
d-P17-Gen-1
> >=20
> > 	g.	SRCU updates, courtesy of Frederic Weisbecker.
> > 		https://lore.kernel.org/lkml/20210511230720.GA2894512@paulmck-ThinkPa=
d-P17-Gen-1
> >=20
> > 	h.	Tasks-RCU updates.
> > 		https://lore.kernel.org/lkml/20210511230924.GA2894768@paulmck-ThinkPa=
d-P17-Gen-1
> >=20
> > 	i.	Torture-test updates.
> > 		https://lore.kernel.org/lkml/20210511231149.GA2895263@paulmck-ThinkPa=
d-P17-Gen-1
>=20
> Pulled into tip:core/rcu.
>=20
> > 2.	Kernel concurrency sanitizer (KCSAN) updates from Marco Elver
> > 	and Mark Rutland (for-mingo-kcsan).
> > 	https://lore.kernel.org/lkml/20210511232324.GA2896130@paulmck-ThinkPad=
-P17-Gen-1
>=20
> Pulled into tip:locking/urgent.
>=20
> > 3.	Linux-kernel memory model (LKMM) updates courtesy of Bj=EF=BF=BDrn T=
=EF=BF=BDpel
> > 	(for-mingo-lkmm).
> > 	https://lore.kernel.org/lkml/20210305102823.415900-1-bjorn.topel@gmail=
.com
>=20
> Pulled into tip:locking/urgent.
>=20
> Thanks Paul, and sorry about the late response! Will get these to Linus=
=20
> ASAP if you don't beat me at it.

I wouldn't be sending it off until Friday morning, Pacific Time, so I am
as usual happy for you to send it.  ;-)

							Thanx, Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210630153221.GW4397%40paulmck-ThinkPad-P17-Gen-1.
