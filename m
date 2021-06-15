Return-Path: <kasan-dev+bncBCJZRXGY5YJBBQ66UODAMGQEBH4IPIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A541B3A8867
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 20:19:48 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id l8-20020a6b70080000b02904d98e22b01esf93704ioc.4
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 11:19:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623781187; cv=pass;
        d=google.com; s=arc-20160816;
        b=oZqpYvvcXgP6jf+tGBzZhxKhiZrl6djLmnNsYBq8RUQIqhQd7fqTw6ZUjUM1162EF2
         NQEb+NYBTVnN+sG4yiadN8y2oO500lb5yYeLSavHwmo0NgUEdFPHeZDE7sPFifqmcvPk
         Y4TA616ChINo3583WdQYNjkUV94+TM8hSCvaq1/5qiGA6Vu0u9HO7qiMkikVuINRMVDP
         WmUIp3LgUUCDUUnJr/LcpEc5eaKadaOeZTaTWQ6jzFtXrm2o8EwC0HvNg1Vw4tnLIZPT
         7t/LLsTksTzLH4/qcPSh9oiufuICQ1fUYtVVfydgIqQ9fDI5X1DOx745vJkhCDKje20s
         wtzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=5unTmRfFEf9OA7OgDpuNSsMGTfKxJa3CRPw8qzoMzWc=;
        b=eqITEsyB38cw6Y1sGLNdbfoLeWtceFPRn/wYGfbeMusmzXRBYX8Ji2CCHes3PHBSHS
         Ezf5WFNQiK4Vnp4vZ9QMghNbt/pt+G6f7+5WSfiJouk9pWKG2aestt/0Z1s4EqH1/cnE
         x6CpqDvEIBpbi8AhwZKod5BF6iW/d7hrTLuOBj3TMuNpKR+GrijBicQ4fz6DojRQPZci
         2mZT+0e0PlbDZv95V6Fz8KvKiRHRMz3UmV5qc8yQ2QVDT/H9doBZBNtk+uDvYyRcvPqD
         72v1me8zsEjGg5aVVH5F14f0kywsyBsCRSVprWP1/2usm6K210wR9/Du/Lx+uBusBUcJ
         SUdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=khqI4M72;
       spf=pass (google.com: domain of srs0=jyjr=lj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=jYJR=LJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:content-transfer-encoding
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5unTmRfFEf9OA7OgDpuNSsMGTfKxJa3CRPw8qzoMzWc=;
        b=UYC7JI511kWy+cTi4jaG9PhIo654CIbqjyRPUaCtb0qUEFUJWaElMUpzQYA3kZ61RY
         exm+AbpCcy0cpXVJp56QFcvMdxg8Or4jvjW1A5dPoXFq0HZCI3cBzONCn5s+20m8ew1v
         Iqs2oOnxUwRQJyJzeCtZGYIcCmLBwuP/iLqmfNroUTGnBkeIeJKEmg3VN5zljD5OxGH0
         rR1XdeisoyACpQYU8fqwhK4TWqUB/MlpRb/j79SotsHA4C65kzuRe/DBuHXwH+A4mKLt
         V/rri/rkF1By60WHNUXDzZCvXcpmWXI2TLYP3hXccqQoh/qDyrxshN2/hq5/OpMTvepg
         9RoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5unTmRfFEf9OA7OgDpuNSsMGTfKxJa3CRPw8qzoMzWc=;
        b=PPFoxQ4teStiIpFifGbkxAv8fDCaTkkFpzaX2wBqQ7j99BsVw+PWTQepCB8TSoO1cL
         H8uPRN5SxXqCsWvOtmyUwM728WFghu7e/KILJAfCW172JIRL9g83kzoVx6HjJT3tgdiq
         1E/0SJuvnuZWPSVwxbRzO3voETtMg939d12OWK6j8xG+AjEkl8QlvSDwKMzP/9OZAzkH
         b3DGJ1ezUIXb7uP6ShPAjD1Kwu+s/hI+80NR6zlMCXL4DUTabU4jwk0aZMewRn2RWVOJ
         HAvCUtQi9nzJp8ijvBmb53UZx0VWXdrxky9Lh9a4mGRzZ2snDn2LMlrIvFziqWJAUokQ
         EmYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Rmv31tcrFaxGiW7pOmlgb87ZGLgjyT7eK8HlFvpysbKZAtsaB
	omhRexMS5cLEyljrjNLa6Gs=
X-Google-Smtp-Source: ABdhPJzYCOAupoUKGQrpawUwY6pqMfkyexmWXrwfU5yL5hHvZL4THx7D9utVfYQLhf1DxlsJsnN8gw==
X-Received: by 2002:a5d:9916:: with SMTP id x22mr492325iol.160.1623781187618;
        Tue, 15 Jun 2021 11:19:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:68a:: with SMTP id o10ls5494624ils.3.gmail; Tue, 15
 Jun 2021 11:19:47 -0700 (PDT)
X-Received: by 2002:a92:d90c:: with SMTP id s12mr563025iln.201.1623781187304;
        Tue, 15 Jun 2021 11:19:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623781187; cv=none;
        d=google.com; s=arc-20160816;
        b=Er6V6c74nTLe2TW9I0mxzzp0Ska9U521Ftp7W/fcbNUOcIKYUbLg7Jj28qYprcyUTL
         n8JNTULchRDGmkSc2DQyB+Qd6s6E5JD207Mk/nspAlTpsvrofI5zBhgXYs+EXRJXN4KD
         IjNRk8JvxxTYJVWFui4pISrs1sPRWdy+RyFcCEbT26huU8WRMFkhM2eVCOiOoTMTr9cp
         kf47bdbEwgXxZtZDzFpuIvFSRXQvBP/jxzYJ/7iknd9d2rU1N8D8NdKj8Vr5qXgA0sWu
         lU5ELNyWS6YOOl97M/8fP2p5sfQvnMF7M/H8A8Ctg3CSGlM2qfiaWNpdfh/1bSEJqIsq
         Ukog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=GwsB3R+0tNGIUuCdgd2ie4uTZz5SOv5j9DnVlvloRAo=;
        b=zcsdoRg8dthvWcE6klA1Iplt7SgCfl426Yd3fikE9l4kXDY68tP3spSYSv3GzEYvVm
         MUhXuVdl0JwVmPxuCp/oZ/nkdlg6//jf4nFrM/PdEuad0bQqSprykdpVybNnKwdjyvqa
         e4SBtFoi3zmT6CI/5abK2+GOqz/GHw26DuQAa9uZ0N3mAczHgnRQTPFuFnBip/pKCdzJ
         Doze6h6P90tHDIfqx2CCIRw456Oa9tc7utSA2zmF5zcpAhq69Ae3H5wc4gAOymh0bB9t
         FQ2yNeSL6lG4aot0Zi3+S2jrLdJfwqFs9lSrAWKAEutYkd23MHMptrNT/ImibNMJxhor
         7mgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=khqI4M72;
       spf=pass (google.com: domain of srs0=jyjr=lj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=jYJR=LJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f9si309257iop.1.2021.06.15.11.19.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 15 Jun 2021 11:19:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=jyjr=lj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 7485F613C2;
	Tue, 15 Jun 2021 18:19:46 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 41BDD5C00F7; Tue, 15 Jun 2021 11:19:46 -0700 (PDT)
Date: Tue, 15 Jun 2021 11:19:46 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, boqun.feng@gmail.com, will@kernel.org,
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 0/7] kcsan: Introduce CONFIG_KCSAN_PERMISSIVE
Message-ID: <20210615181946.GA2727668@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210607125653.1388091-1-elver@google.com>
 <20210609123810.GA37375@C02TD0UTHF1T.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210609123810.GA37375@C02TD0UTHF1T.local>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=khqI4M72;       spf=pass
 (google.com: domain of srs0=jyjr=lj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=jYJR=LJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Wed, Jun 09, 2021 at 01:38:10PM +0100, Mark Rutland wrote:
> Hi Marco,
>=20
> On Mon, Jun 07, 2021 at 02:56:46PM +0200, Marco Elver wrote:
> > While investigating a number of data races, we've encountered data-racy
> > accesses on flags variables to be very common. The typical pattern is a
> > reader masking all but one bit, and the writer setting/clearing only 1
> > bit (current->flags being a frequently encountered case; mm/sl[au]b.c
> > disables KCSAN for this reason currently).
>=20
> As a heads up, I just sent out the series I promised for
> thread_info::flags, at:
>=20
>   https://lore.kernel.org/lkml/20210609122001.18277-1-mark.rutland@arm.co=
m/T/#t
>=20
> ... which I think is complementary to this (IIUC it should help with the
> multi-bit cases you mention below), and may help to make the checks more
> stringent in future.
>=20
> FWIW, for this series:
>=20
> Acked-by: Mark Rutland <mark.rutland@arm.com>

Queued and pushed for v5.15, thank you both!

I also queued the following patch making use of CONFIG_KCSAN_STRICT, and I
figured that I should run it past you guys to make check my understanding.

Thoughts?

							Thanx, Paul

------------------------------------------------------------------------

commit 023f1604e373575be6335f85abf36fd475d78da3
Author: Paul E. McKenney <paulmck@kernel.org>
Date:   Tue Jun 15 11:14:19 2021 -0700

    torture: Apply CONFIG_KCSAN_STRICT to kvm.sh --kcsan argument
   =20
    Currently, the --kcsan argument to kvm.sh applies a laundry list of
    Kconfig options.  Now that KCSAN provides the CONFIG_KCSAN_STRICT Kconf=
ig
    option, this commit reduces the laundry list to this one option.
   =20
    Signed-off-by: Paul E. McKenney <paulmck@kernel.org>

diff --git a/tools/testing/selftests/rcutorture/bin/kvm.sh b/tools/testing/=
selftests/rcutorture/bin/kvm.sh
index b4ac4ee33222..f2bd80391999 100755
--- a/tools/testing/selftests/rcutorture/bin/kvm.sh
+++ b/tools/testing/selftests/rcutorture/bin/kvm.sh
@@ -184,7 +184,7 @@ do
 		TORTURE_KCONFIG_KASAN_ARG=3D"CONFIG_DEBUG_INFO=3Dy CONFIG_KASAN=3Dy"; ex=
port TORTURE_KCONFIG_KASAN_ARG
 		;;
 	--kcsan)
-		TORTURE_KCONFIG_KCSAN_ARG=3D"CONFIG_DEBUG_INFO=3Dy CONFIG_KCSAN=3Dy CONF=
IG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dn CONFIG_KCSAN_REPORT_VALUE_CHANGE_ON=
LY=3Dn CONFIG_KCSAN_REPORT_ONCE_IN_MS=3D100000 CONFIG_KCSAN_INTERRUPT_WATCH=
ER=3Dy CONFIG_KCSAN_VERBOSE=3Dy CONFIG_DEBUG_LOCK_ALLOC=3Dy CONFIG_PROVE_LO=
CKING=3Dy"; export TORTURE_KCONFIG_KCSAN_ARG
+		TORTURE_KCONFIG_KCSAN_ARG=3D"CONFIG_DEBUG_INFO=3Dy CONFIG_KCSAN=3Dy CONF=
IG_KCSAN_STRICT=3Dy CONFIG_KCSAN_REPORT_ONCE_IN_MS=3D100000 CONFIG_KCSAN_VE=
RBOSE=3Dy CONFIG_DEBUG_LOCK_ALLOC=3Dy CONFIG_PROVE_LOCKING=3Dy"; export TOR=
TURE_KCONFIG_KCSAN_ARG
 		;;
 	--kmake-arg|--kmake-args)
 		checkarg --kmake-arg "(kernel make arguments)" $# "$2" '.*' '^error$'

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210615181946.GA2727668%40paulmck-ThinkPad-P17-Gen-1.
