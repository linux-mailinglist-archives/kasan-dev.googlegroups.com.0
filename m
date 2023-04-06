Return-Path: <kasan-dev+bncBC6PNFEKTYIBBOODXOQQMGQEN52PI5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FB9D6D9BE5
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Apr 2023 17:14:02 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id j17-20020adfb311000000b002d660153278sf5071022wrd.20
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Apr 2023 08:14:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680794042; cv=pass;
        d=google.com; s=arc-20160816;
        b=W5owQNYQBGNXd5Ts+CCBzuiaWaAMmoY7BLg2CLJVFNrhJ0srQFq36eY5g/aLwbEGkq
         3Ui+hwjR91TDwF8CnVO23yHj0XSxPkIjrehNd0YgbT6HZyO5bJKxCvZeD4AllDS4H//x
         QGkEk5QjkHc5cUEqs/s9MpNZP2HGkaPVVpGsB1i9vgUeJVmRi+ur5r6dnvhfA81ilpwv
         /ootLHcQ34rb/hBTzudaMYuV8wJrFDQjKXYGJgbgw1r0EOUu8C0fcI0QmrexFvRNpMhS
         JNkHpXh4CyOYL5jfTdSZoU1Ql25EYx/vmHlJi74NpRe7EVv+RaiuJg0L4I/MuI1F8Ush
         dVIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=R+ptFi9aVhBi0lbqR9CDKy+X7vlFORsAqvaYznTqAfw=;
        b=V1rvDMZ2xbtXmW8HiefM0UfvgYcCL8aJ0dI4UPoafWZ3clMltAiAg2e+oaZf8RtFnC
         pZ9ZZI4QBdXlZQRsbGnjs/zRl5KtEpRtSh5WdMcFZVjyiPBsvUI9uT4AYmmX3RXy2Wr4
         f0nNnnNLbauB8NVoHwkVgpprrawgc0a6RrjmKKjAU//sOCMPnxxiNJT95p2Jz+GQBQb6
         sM2FqpTSIZYSzHxJMPzDVx94AdO1IXXS2HE+jjjGq0X9LnVsx8yc9dfrizjHMmFpb5oj
         a9Q8AHP5X2M9F6R0BpNmzruyeAsPeM6HcFUO08Qow/mc52HWLyb9ykLlyG3JiRYmHK3k
         +cuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IshdjaxE;
       spf=pass (google.com: domain of frederic@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680794042;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=R+ptFi9aVhBi0lbqR9CDKy+X7vlFORsAqvaYznTqAfw=;
        b=gRWapeT7xYmwJMjP94fQcMwMA2Nr3OPqbl6LD3fpc8ulKqN7o+93/WPx6oOQX/rIhv
         pAToN8wAa056S82XvElRhN1OIG71/73c3CoyzkJ8XWq9CLaBcOP2/Yn83BUHGFVwXqAb
         Y1uMzAf7YjyyxTOmF8kbGs3pQ2F2IYuuuHmXUcG52ORZHVxaKWVpfEde2p4vXVCrSPEh
         jZ8G7mh9C86lusrQiyCwFMJlgCTRsOs4DD7xRW0AHr+vx8HHZAwU94g2sF78MGVsliuO
         +6nhdkmLAP3ZHEppVh7cOuoflOt1DAbpDFInVhAHubrcKapkuk1SUulm/65cHpnMYqxG
         r2qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680794042;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=R+ptFi9aVhBi0lbqR9CDKy+X7vlFORsAqvaYznTqAfw=;
        b=YlEJNd+ehKfvumT6eLp7uk+DdyjhbmeIJ1RJsG30w1lSDQxIvak1NN+Ee6A1bEDDKd
         9Be9gAf57ykx+M03HVu1J7qhopqK+9+pHOn33gVW5f88geRuDdSRfdsTUOY1gYnSSiFE
         bZtFdScKukckCt2SSqQNMibP/TSkMsjwAU83BjyB+EoMQxn3489p87FhexyiCeDsGjV1
         SKiz93TyJF/yqMzMS1QUFALXMa3wQ3RGUJR9yRY/J78uLAD/JzWu9/X/myhZCJGQvlI4
         jDNZOxpv030bCUIhAHoQ2vF7pqP2uXV6tdIjghbhrkcYejTy2Dxi3+5qphJmkGglfU3K
         d//Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9d9vcAY2x4/rkjJf7LecPOUAVvo+mbE/B3NP/aj7vEbu7t9+Upe
	ySKmReU9nyqk9QiiM0V2ZhJTcw==
X-Google-Smtp-Source: AKy350Z4cSMDdJrH7DZa4zkLoRiNyzs6Pr7HYOWffbU2o/HGZ6U1CatOoRnR79MhPZsx7hFM4Orgsg==
X-Received: by 2002:a5d:4601:0:b0:2cf:e70f:970c with SMTP id t1-20020a5d4601000000b002cfe70f970cmr1918259wrq.12.1680794041558;
        Thu, 06 Apr 2023 08:14:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:64ac:0:b0:2cf:ef77:1717 with SMTP id m12-20020a5d64ac000000b002cfef771717ls2536570wrp.0.-pod-prod-gmail;
 Thu, 06 Apr 2023 08:14:00 -0700 (PDT)
X-Received: by 2002:adf:edd1:0:b0:2cf:e436:f722 with SMTP id v17-20020adfedd1000000b002cfe436f722mr7448269wro.64.1680794040096;
        Thu, 06 Apr 2023 08:14:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680794040; cv=none;
        d=google.com; s=arc-20160816;
        b=RWSPoynkTEUN6jZpv5MAL72C28a5UEnAV7zs+DIa3NAs2S3c5RHk3bm7/cR4HziSw2
         dmgI4nyWJnEB7L7r0+UsgRR/exojV3jVp4vU+QblGCFcDT1CNaivYbtXPE3+UqL3r4Tc
         +jFw/Vm/8NaIx6QWoJuhxtRkD7qEkdI3H4OZ7bML1krVN3pWwV+08eaAMw+GuXYXnk5O
         Rawyh73kMdMyeoWlvBCDLABVUXwmnvr2v8VqcNS7cSjB0S/K1VH0chsxi0ZoSXmOJcmC
         seWQuY16LBBuIN4CzNs5HZXCqy36yDDDE+W7t+/9jljnfqJ5P0FiUL/FQBA4CrND15zi
         fLVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=SrgVmLFNIiXz60UyzKRU9OO4QhY5ffv1afEFRrWoK98=;
        b=FTy5oCYV9KTP+I3MrC4RvgmWUKp+IZcJQGHyi0lAcpjk96PEKikcHpN+y0RVPgK1Hy
         UCipClVn2/LKGLV9LsTHrDRj839fHcnydCu6OGS6PuPlqP2X/RQUmONew8WWSP1mAirl
         VxOAc3ZQcBwTECVAd5i8fkk8mO/foPyvQpCzmSTdLgHu10ehyYn2zO/zJOxAnzPEJlN1
         7oaa+VoLj35qGqBDQ4T5b5V9qlt2EH+bnSpg01UK380rMmUFBzz7VjNiEr+fH6qPxkSF
         ejHgKObFs2um19dJclVwSYNqZ/PMNHDgbnSlVlxu/Xu2yX2eoe8HgrOj68MYPxLjqjMC
         tFuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IshdjaxE;
       spf=pass (google.com: domain of frederic@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id i13-20020a5d584d000000b002c6ec127706si83118wrf.0.2023.04.06.08.13.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Apr 2023 08:14:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D7331643C8;
	Thu,  6 Apr 2023 15:13:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C8F85C433EF;
	Thu,  6 Apr 2023 15:13:57 +0000 (UTC)
Date: Thu, 6 Apr 2023 17:13:54 +0200
From: Frederic Weisbecker <frederic@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>, Oleg Nesterov <oleg@redhat.com>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	linux-kernel@vger.kernel.org, linux-kselftest@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
Message-ID: <ZC7hsjyGc+0DP2D0@localhost.localdomain>
References: <20230316123028.2890338-1-elver@google.com>
 <CANpmjNOwo=4_VpUs1PYajtxb8gvt3hyhgwc-Bk9RN4VgupZCyQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNOwo=4_VpUs1PYajtxb8gvt3hyhgwc-Bk9RN4VgupZCyQ@mail.gmail.com>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IshdjaxE;       spf=pass
 (google.com: domain of frederic@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=frederic@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Le Thu, Apr 06, 2023 at 04:12:04PM +0200, Marco Elver a =C3=A9crit :
> On Thu, 16 Mar 2023 at 13:31, Marco Elver <elver@google.com> wrote:
> One last semi-gentle ping. ;-)
>=20
> 1. We're seeing that in some applications that use POSIX timers
> heavily, but where the main thread is mostly idle, the main thread
> receives a disproportional amount of the signals along with being
> woken up constantly. This is bad, because the main thread usually
> waits with the help of a futex or really long sleeps. Now the main
> thread will steal time (to go back to sleep) from another thread that
> could have instead just proceeded with whatever it was doing.
>=20
> 2. Delivering signals to random threads is currently way too
> expensive. We need to resort to this crazy algorithm: 1) receive timer
> signal, 2) check if main thread, 3) if main thread (which is likely),
> pick a random thread and do tgkill. To find a random thread, iterate
> /proc/self/task, but that's just abysmal for various reasons. Other
> alternatives, like inherited task clock perf events are too expensive
> as soon as we need to enable/disable the timers (does IPIs), and
> maintaining O(#threads) timers is just as horrible.
>=20
> This patch solves both the above issues.
>=20
> We acknowledge the unfortunate situation of attributing this patch to
> one clear subsystem and owner: it straddles into signal delivery and
> POSIX timers territory, and perhaps some scheduling. The patch itself
> only touches kernel/signal.c.
>=20
> If anyone has serious objections, please shout (soon'ish). Given the
> patch has been reviewed by Oleg, and scrutinized by Dmitry and myself,
> presumably we need to find a tree that currently takes kernel/signal.c
> patches?
>=20
> Thanks!

Thanks for the reminder!

In the very unlikely case Thomas ignores this before the next merge window,
I'll tentatively do a pull request to Linus.

Thanks.

>=20
> -- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZC7hsjyGc%2B0DP2D0%40localhost.localdomain.
