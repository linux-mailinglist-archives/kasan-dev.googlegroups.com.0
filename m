Return-Path: <kasan-dev+bncBCC4R3XF44KBBVGYROYAMGQE2MOXHEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id D97B288C75A
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 16:40:06 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1e0c070b660sf17128595ad.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 08:40:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711467605; cv=pass;
        d=google.com; s=arc-20160816;
        b=j1XeUc6edbw97dSj+/KYCPNUmqv2TKfpOUKjcIySZGUWHHx5GJ9FhwXs2nqAfw63PB
         zcrZ+rvx/3UluJvv/K6L/fXh1KhCqm78uhSmFW1yni7X0lJacUdTvV2uCKPapjs7DAFp
         6+Asquz3Q9Ek/ff4KyyU/ftODBNm2TZRx8jNYVUM/kI9scusLj6CcLUrbOwbAyvzlIF+
         pfEtU38T4aqa+C4hixZle5tmOukajmylqN19y9buEWgIvt9ttZLFwOqJmq9wcSXuSI6h
         k28dzdcis4mLym8ixqv11L45elU/LO9pjVOIRodrx+E/CeSOFcdMuEPgZ7Wftq5maB/Q
         uNwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=CPyfenHiFf8rGUpwMKdXYNtX+t3tQomjO5m1RupQbi4=;
        fh=Np/RyrfMXSwt2qi8zqKJnr+cgv25kzwBt4NIQA/Nokw=;
        b=VaStlNKx/gN/3WB6khTNfKcFn48z5W/jbJPRlTiyAyynQpdv2NtW3hIxkur8quC95l
         nkMAsyy+OyDO4N9yBnufwXocCE2/jaeFblzSCUDlWz870wlot8Mo+dyeKiihCHJ5XWQI
         9YeUDmBOcd2Nk2XSH+4ysRxLEUqnv2b6YvX4MrDFmd4FzaH/N4WlL0SNeP6hKRC2e9um
         E4VMxht0UOO3TeHWPx7F7rIIVHyumvdWfxfsFpo/lJ7fJChZg0VAnyGUCfCmUjr1/SEL
         qqphlixeH0eoBcwj5s5Llp38XU6El5/sSkjHi61aMrXqBanEiJNXVBI5AItjakCBz6rB
         irfw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="qyKA41Y/";
       spf=pass (google.com: domain of sj@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711467605; x=1712072405; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CPyfenHiFf8rGUpwMKdXYNtX+t3tQomjO5m1RupQbi4=;
        b=f6fYVJ5Z0uUZY3H/Zv+Ya4JfxxWTIlwuxeTONHBARzQ85xXiG81HfOCUexuPFdO0mO
         95rhr9DT2cOWa6VysiqXZygzNc4FdvTYTQtqhcT02it+FSchO/ENfXwg4umUYu51faXY
         VFFqsIVw6CDpPkhoudPfpHlX6Y3LBhMzVsqY1cHszE+UVipwT8qYCTjkxiFwzz1SJngc
         vfFNAUPdTIzM83GhNN75SA8GXLSyrEiIfh/z+3dEmddavQCkGZuDqGJKkJJvUOwrUKrE
         dEPC6imU8ULvbAmms+qUfAmcMx41oviDGGOK+CqrlmsIE8EtGrT/iVzzsIEE5sdfIAOc
         1ucQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711467605; x=1712072405;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CPyfenHiFf8rGUpwMKdXYNtX+t3tQomjO5m1RupQbi4=;
        b=CuaXS49nZH67MAMbvVLEsJlq9BKOQSg+hHvOqGcBEdmuAUgMYVpuXWeh6e1PRVYH6n
         GCu61rCbPUG6VUlMKjWooRTBe4YsG8spchnU1OLt5OEU2UrJb8zocYcnbNNJrnF/13NK
         5/vMAR16vAv4aFDzT61jIUjxrUhrGuPZ7tQlTmjMnmvOipXS9oG/g02XxPV0kI+p5Gg5
         7Wv+Pm2oAuV0F0YlGmxw9fyEZpfMV8UQlMHa+hz8ai3+pMXrmOrFJkDbVD7ukXDduTmg
         s7YdWVv0kvcJyzRQTlfM46dz/srMS7XfScfx4L5JiTALnZCtXf8jyV60qBxJ3YgegD3E
         lsqw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVgmvICv3J/ikhMwxAxaJlOoU6XWRL/ICT0vSQ7RaJzCX3jFkiXfOX+IR+eKTKKcIB20+almAriapaOZGK5veuogyK59iAo9w==
X-Gm-Message-State: AOJu0YwjUQnjOFh1ojtTte086EAMKtjF3prTfybhYVAiySIhPVNb8mmL
	fHqFJKLQiN4Q3Via6Oi8WBRqF4GGzBE6sE4bz8fyGxyP28mMbzst
X-Google-Smtp-Source: AGHT+IEtJ9R3sDrp46qH9Mv/GNDxF45erzxRa5Pnut3ITSBiNOR57uPA6dPd96b9MQPBTepRTPTNjA==
X-Received: by 2002:a17:903:22c1:b0:1dc:7bc:d025 with SMTP id y1-20020a17090322c100b001dc07bcd025mr14859441plg.4.1711467604632;
        Tue, 26 Mar 2024 08:40:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:11cd:b0:1dd:2b95:71a1 with SMTP id
 q13-20020a17090311cd00b001dd2b9571a1ls4235828plh.1.-pod-prod-08-us; Tue, 26
 Mar 2024 08:40:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUlZVxZLLYgSLhIY4RRapQcQtuXpoBc4dILJL7XqEXHHT58yb4ZFb47L/Xb8MneD6dX3BtZvaC+BUPwU6v9zkUx2LiwOt/dfFiZFw==
X-Received: by 2002:a17:902:ab96:b0:1e0:f8:17ca with SMTP id f22-20020a170902ab9600b001e000f817camr10574479plr.39.1711467603517;
        Tue, 26 Mar 2024 08:40:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711467603; cv=none;
        d=google.com; s=arc-20160816;
        b=pZkNHW+NOmvdDffWQFMO/f+31vAv+vNj3YfxZaVUH4kqe7AV5sBlsl//DKRKa6+otV
         iLjWjJqaASubEhKbfjk5eIp63OVwX2E3qD6KkObA1domFyd1qzKMpLS27Bfy281pgV8H
         IIA4ih+3mMrOBOyY9Efm7iFwAQvCw0INpXYNSOdQ8Wmbs4QkvEdSAGdq7/tS+3X7LKcQ
         Mry8BLx6UCNjNlzbg1HPM77bO08t49wSsdvt03p40l12aF362xBbPknomhyf8rFHP7+i
         1v7LH4Vn4HO7G+/Io1XwbOuyO3vc6ioPnSO5BTuZ5OAtG6csZwQE03GXY/x6nqa2o7V7
         3rBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=dx9N7OwJ25HB8abimiLLiOJ4v7dk6iTkAyGBqy6/tXU=;
        fh=6j9T3RxhFEHnaSF3k/nMpHvQpXbCrITaexPEOSaS+e4=;
        b=fnP8Spu/mid69WJXUV1tij6BS79lT7hsK73oAG0U3U7ImYcpRehj7hZh+iunvrb1mx
         JdPNxUj3xwwJoe5Hq1939MDFvoeC2Gm3kesaWm5iCpvRjtdaM0psz/XOOySqrROSMW1Y
         HJ4rE8MA4BgcbGEt2AoTnWyhKVL/CI2KtYskUPwUArNqxY6AP4CYaRtLOKyWG6OjpLfw
         d0wBf70cmWnIkLtZ2coSgktKA5XLIxskpUikwPYf3SZC9l04QJeNN6R47/HZGQTOb0WT
         1fL8R4jjCQ9fgpRWpbE8EsaLW3oDavopFPtjhfafUNbpzZTCPWBtuAZ2oqh0Yt0HQqUF
         q69Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="qyKA41Y/";
       spf=pass (google.com: domain of sj@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id x22-20020a1709027c1600b001ddddaf7343si443702pll.6.2024.03.26.08.40.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Mar 2024 08:40:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of sj@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 58967CE1F82;
	Tue, 26 Mar 2024 15:40:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C9697C433F1;
	Tue, 26 Mar 2024 15:39:55 +0000 (UTC)
From: SeongJae Park <sj@kernel.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: SeongJae Park <sj@kernel.org>,
	hannes@cmpxchg.org,
	roman.gushchin@linux.dev,
	mgorman@suse.de,
	dave@stgolabs.net,
	willy@infradead.org,
	liam.howlett@oracle.com,
	penguin-kernel@i-love.sakura.ne.jp,
	corbet@lwn.net,
	void@manifault.com,
	peterz@infradead.org,
	juri.lelli@redhat.com,
	catalin.marinas@arm.com,
	will@kernel.org,
	arnd@arndb.de,
	tglx@linutronix.de,
	mingo@redhat.com,
	dave.hansen@linux.intel.com,
	x86@kernel.org,
	peterx@redhat.com,
	david@redhat.com,
	axboe@kernel.dk,
	mcgrof@kernel.org,
	masahiroy@kernel.org,
	nathan@kernel.org,
	dennis@kernel.org,
	jhubbard@nvidia.com,
	tj@kernel.org,
	muchun.song@linux.dev,
	rppt@kernel.org,
	paulmck@kernel.org,
	pasha.tatashin@soleen.com,
	yosryahmed@google.com,
	yuzhao@google.com,
	dhowells@redhat.com,
	hughd@google.com,
	andreyknvl@gmail.com,
	keescook@chromium.org,
	ndesaulniers@google.com,
	vvvvvv@google.com,
	gregkh@linuxfoundation.org,
	ebiggers@google.com,
	ytcoode@gmail.com,
	vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com,
	rostedt@goodmis.org,
	bsegall@google.com,
	bristot@redhat.com,
	vschneid@redhat.com,
	cl@linux.com,
	penberg@kernel.org,
	iamjoonsoo.kim@lge.com,
	42.hyeyoo@gmail.com,
	glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	songmuchun@bytedance.com,
	jbaron@akamai.com,
	aliceryhl@google.com,
	rientjes@google.com,
	minchan@google.com,
	kaleshsingh@google.com,
	kernel-team@android.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev,
	linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v6 30/37] mm: vmalloc: Enable memory allocation profiling
Date: Tue, 26 Mar 2024 08:39:54 -0700
Message-Id: <20240326153954.89199-1-sj@kernel.org>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <CAJuCfpGwLRBWKegYq5XY++fCPWO4mpzrhifw9QGvzJ5Uf9S4jw@mail.gmail.com>
References: 
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: sj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="qyKA41Y/";       spf=pass
 (google.com: domain of sj@kernel.org designates 145.40.73.55 as permitted
 sender) smtp.mailfrom=sj@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Tue, 26 Mar 2024 00:51:21 -0700 Suren Baghdasaryan <surenb@google.com> w=
rote:

> On Mon, Mar 25, 2024 at 11:20=E2=80=AFAM SeongJae Park <sj@kernel.org> wr=
ote:
> >
> > On Mon, 25 Mar 2024 10:59:01 -0700 Suren Baghdasaryan <surenb@google.co=
m> wrote:
> >
> > > On Mon, Mar 25, 2024 at 10:49=E2=80=AFAM SeongJae Park <sj@kernel.org=
> wrote:
> > > >
> > > > On Mon, 25 Mar 2024 14:56:01 +0000 Suren Baghdasaryan <surenb@googl=
e.com> wrote:
> > > >
> > > > > On Sat, Mar 23, 2024 at 6:05=E2=80=AFPM SeongJae Park <sj@kernel.=
org> wrote:
> > > > > >
> > > > > > Hi Suren and Kent,
> > > > > >
> > > > > > On Thu, 21 Mar 2024 09:36:52 -0700 Suren Baghdasaryan <surenb@g=
oogle.com> wrote:
> > > > > >
> > > > > > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > > > > > >
> > > > > > > This wrapps all external vmalloc allocation functions with th=
e
> > > > > > > alloc_hooks() wrapper, and switches internal allocations to _=
noprof
> > > > > > > variants where appropriate, for the new memory allocation pro=
filing
> > > > > > > feature.
> > > > > >
> > > > > > I just noticed latest mm-unstable fails running kunit on my mac=
hine as below.
> > > > > > 'git-bisect' says this is the first commit of the failure.
> > > > > >
> > > > > >     $ ./tools/testing/kunit/kunit.py run --build_dir ../kunit.o=
ut/
> > > > > >     [10:59:53] Configuring KUnit Kernel ...
> > > > > >     [10:59:53] Building KUnit Kernel ...
> > > > > >     Populating config with:
> > > > > >     $ make ARCH=3Dum O=3D../kunit.out/ olddefconfig
> > > > > >     Building with:
> > > > > >     $ make ARCH=3Dum O=3D../kunit.out/ --jobs=3D36
> > > > > >     ERROR:root:/usr/bin/ld: arch/um/os-Linux/main.o: in functio=
n `__wrap_malloc':
> > > > > >     main.c:(.text+0x10b): undefined reference to `vmalloc'
> > > > > >     collect2: error: ld returned 1 exit status
> > > > > >
> > > > > > Haven't looked into the code yet, but reporting first.  May I a=
sk your idea?
> > > > >
> > > > > Hi SeongJae,
> > > > > Looks like we missed adding "#include <linux/vmalloc.h>" inside
> > > > > arch/um/os-Linux/main.c in this patch:
> > > > > https://lore.kernel.org/all/20240321163705.3067592-2-surenb@googl=
e.com/.
> > > > > I'll be posing fixes for all 0-day issues found over the weekend =
and
> > > > > will include a fix for this. In the meantime, to work around it y=
ou
> > > > > can add that include yourself. Please let me know if the issue st=
ill
> > > > > persists after doing that.
> > > >
> > > > Thank you, Suren.  The change made the error message disappears.  H=
owever, it
> > > > introduced another one.
> > >
> > > Ok, let me investigate and I'll try to get a fix for it today evening=
.
> >
> > Thank you for this kind reply.  Nonetheless, this is not blocking some =
real
> > thing from me.  So, no rush.  Plese take your time :)
>=20
> I posted a fix here:
> https://lore.kernel.org/all/20240326073750.726636-1-surenb@google.com/
> Please let me know if this resolves the issue.

I confirmed it is fixing the issue, and replied to the patch with my Tested=
-by:
tag.  Thank you for this kind fix, Suren.


Thanks,
SJ

[...]

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240326153954.89199-1-sj%40kernel.org.
