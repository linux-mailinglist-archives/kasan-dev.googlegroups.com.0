Return-Path: <kasan-dev+bncBCC4R3XF44KBBYUAQ6YAMGQETTUJEJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1383D88ADA4
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Mar 2024 19:20:20 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-430ac6a7aa0sf85318761cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Mar 2024 11:20:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711390819; cv=pass;
        d=google.com; s=arc-20160816;
        b=e7piksfCFelRmD2zMBTU/9w1K/2iufz/XM0fgK/2zEaE6WWkDeHw8BL3Nl/JgUjiuB
         Q4+lyyMPhHPiHzKjfpTTl/TbeB99rqqHi51/dczgojjr5u7SFPSgL1x0dsTswt3ZPVCk
         Ft490/0tcQqggwt/DEPP3VufmWyTcv5GcFGwSvKgvGXJvCMCdqpTwf1RPS7HYrw5pijA
         fP/KA4/D5dKcHprw8M4mAPxSpE+7JTr6FwEACDZJ6eNNzlbPDh69Chg8o0gdc5R0gMdf
         2q/C7JoxK1K8r2Bjh9F6WiLRXfRk9TmWOQRltvhDEzoiPtCi8+wcZNxOxrrHJ4LLY1y+
         Nf/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=mLx+BYe2qly2gLXgxhsSM8kGxP6frzH3/ZnBol4pQQM=;
        fh=gh9TfmtgVv2rO+T8XAG7KYQD4+xX2U6RfHYEpOfeP3Q=;
        b=BGtetfrvV7AN0pmzmWp/98MXPBxZadb1+SDpMV/66ph0NQalWFK4KtmZsPTPICYSPW
         ZFWXWgF2DL4WPRUoVJJvRgQ9K+cKkeymFzLgSQE+8kIovU4aLO/dMVDN6nAjsB0JU6Ej
         Fz45h/dii22rhA7Z4dgawk2nmDTv/hFmsINDu27Lp+Dg85+ZZRCjuliB8vQqfEfG1h9y
         +3DQ0DmdAweGAy//93a03IkMRjGcfjo0ifbuUF3NfzAvBQPTEl5GVwiLfI7Ys7RkVflI
         Va4Kvrh86JeDs6ljlVMRBMHVr6Nh6XBkkYL1H/M9Z77xWfenfF+UiVe913Qn+YPVh0EG
         Ymxg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XEkb4FbW;
       spf=pass (google.com: domain of sj@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711390819; x=1711995619; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mLx+BYe2qly2gLXgxhsSM8kGxP6frzH3/ZnBol4pQQM=;
        b=HOFp8dr5tya88BI0FE1M2adaOY2yXRsSfEygiXAvY3ycNsDRnaF65y8DXC6p/0YHKm
         AyRzmog2D8FOHm7CrfAQHgphCHvt2MXwY8Khziuvvj+EdUgEGY3O4mJFFEOazBLgmaqp
         +PvadCPI7I8c5uclt/iWr/cU9lP7qAULjUm1rn+z8CStWmPIO6rmYqAJDHolcghjn3YI
         zcsr1dalVZFBE/9tW6gA27wKuAHUv64XTeCUWWiO76vSLM8Fho+OJC43TuexGKjjpt4V
         MVSxHl4jbbpBQ1+LzJI//j1x/PdZjhuop7STE/hQbzYgu7libLYGQ11u0D2FpjX7YpRm
         G8uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711390819; x=1711995619;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=mLx+BYe2qly2gLXgxhsSM8kGxP6frzH3/ZnBol4pQQM=;
        b=cnhQOFCHy/S7wpDItZflerTT/2EaBU5GYZncjaQyleHd01zZcAs/wmdAUHeH3pJ9ok
         ybeYEBtTchjTsKTXgLONLcR46ebJQaGSVzg7uDLp3aMfCoG6o1cH5poIOlVjh8a/48Zj
         XZfwJt1EmTot0EYiRVPjm6qrI19Z3YeWi7b8HrYxkqxXTVyoUfrgnB39QIxIDVhspPHa
         6pSMfCZ5o2re02mcC/qUJL/j7OZvGU9rtvweqMJ0IeZ/L0wxuVmSS9PxEb2eRz1q1xGQ
         W1psimOYu6LYhEeqgPWewFsyKOLEmjd4YgAdFWr3fXCJSsHXAbORsnxZ6O0iURvVRAcl
         VrnA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVTW72/mbdaTzEZcwRLQxhBrZWRrUojvJw7P4mGBkrvUkEyFuEgT7L9gM9U7JJhIFwozjJ3CguG8sI6IgstEUmM0gP5wYwS7Q==
X-Gm-Message-State: AOJu0Yw5a9a5rMZNCAFb+GUoaPtfd22Xz7fOnsUg2IEUdo2p6ascPJxR
	xnSnYrS1zCZ7QD4IkE617yNyRQNfLNMStZrL+rvPwBTn5JbVVJ/o
X-Google-Smtp-Source: AGHT+IEAqqAn7yf3Csf1mwlSLK9i2m7012YRpkcBI8t3dzJHca8v16FUebzEW0Y+TkDiqMnFCFY+GA==
X-Received: by 2002:a05:622a:1193:b0:431:5ac3:6c11 with SMTP id m19-20020a05622a119300b004315ac36c11mr5905511qtk.16.1711390818789;
        Mon, 25 Mar 2024 11:20:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:191e:b0:42f:512e:fc4e with SMTP id
 w30-20020a05622a191e00b0042f512efc4els10854681qtc.0.-pod-prod-00-us; Mon, 25
 Mar 2024 11:20:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXTRg3lJbp+jU/QOy+Man8+UZPOEGTbmI6ZcKfRgu+e3oxx3fBF9G1XjAFWfIymn1XoWhVNjZvZsGb+ukPsQsfjN+sDSD2OIpRpFA==
X-Received: by 2002:a05:620a:470e:b0:78a:5d4d:78c9 with SMTP id bs14-20020a05620a470e00b0078a5d4d78c9mr2688772qkb.25.1711390818078;
        Mon, 25 Mar 2024 11:20:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711390818; cv=none;
        d=google.com; s=arc-20160816;
        b=BIVFAfqLrmJBM5If6IqLPz/cpDbiWYURBZDbiZ3hnFTzVPC6ASQMsdgHPyvvB1sZyt
         rrToJtooVASgcj5MDNIG1zXZa9XyD5kHg0CwPjghwoz4Zwpci0Q009Advz5+rtBO9l8M
         lewwdcel8AZfIg2cCvFfaGW3GaArmjdcLuPFIUMvzzHApGC510yX4szL4h4v6vmY5ylk
         1uah9kDbGmfn5uHg/oz67zyxtL/qY3+uUxOT/9pLp+QQvgulWZh1B3S6Epd4S7dI8dE2
         oFtAmFbQl4H5ceHGgC7QksfJq01aUeAs3s0LAnB3TvdLlY0eDXT6E8Q+EeJYHDxZxWnd
         Tclg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jw/Fh/RYsoUgVlZSPyEBwAC6yZDivQ6KkMRDm0qnHDE=;
        fh=R50vF5dU5LtylvFtNrdwZ2jtcoMHeTwJwJQSvEw3d+s=;
        b=ngnMbqCaf92yPKYogpl8wqXZur7+B/lq8eLJxBjqwIAosm0Imdrb6KEWdwHo6gLwF4
         6rcoa/k1pLWDxiL5MX6O70X5GRBbwvwpFKvI9GYfrQ+jMeFfyJT9nRqRgJql2jXNP4jX
         57tlA7uNWhlPtxXh5QkNBxdzfV57HdStagpHNUytPPMPC3SNqJDjW77dNs/YLg+fP42D
         vxm3g4KZxK6qKLj7UKe63E/CpVg8nJhxC1aOhFRJQaiNRlcmubjmIGiBtXDQK+HgaVwA
         3CjWTaBg2lc1Ztue+l/JEHXXT0zKIG0l67SWEvynHGJgVF+GMnATIUu+8AoPzQAPQh1W
         lkZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XEkb4FbW;
       spf=pass (google.com: domain of sj@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id h3-20020a37c443000000b0078a45a5c896si398398qkm.3.2024.03.25.11.20.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Mar 2024 11:20:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of sj@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 40FAACE0B4C;
	Mon, 25 Mar 2024 18:20:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 55A0CC433F1;
	Mon, 25 Mar 2024 18:20:09 +0000 (UTC)
From: SeongJae Park <sj@kernel.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: SeongJae Park <sj@kernel.org>,
	vbabka@suse.cz,
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
Date: Mon, 25 Mar 2024 11:20:07 -0700
Message-Id: <20240325182007.233780-1-sj@kernel.org>
X-Mailer: git-send-email 2.39.2
In-Reply-To: <CAJuCfpGiuCnMFtViD0xsoaLVO_gJddBQ1NpL6TpnsfN8z5P6fA@mail.gmail.com>
References: 
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: sj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XEkb4FbW;       spf=pass
 (google.com: domain of sj@kernel.org designates 2604:1380:40e1:4800::1 as
 permitted sender) smtp.mailfrom=sj@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, 25 Mar 2024 10:59:01 -0700 Suren Baghdasaryan <surenb@google.com> w=
rote:

> On Mon, Mar 25, 2024 at 10:49=E2=80=AFAM SeongJae Park <sj@kernel.org> wr=
ote:
> >
> > On Mon, 25 Mar 2024 14:56:01 +0000 Suren Baghdasaryan <surenb@google.co=
m> wrote:
> >
> > > On Sat, Mar 23, 2024 at 6:05=E2=80=AFPM SeongJae Park <sj@kernel.org>=
 wrote:
> > > >
> > > > Hi Suren and Kent,
> > > >
> > > > On Thu, 21 Mar 2024 09:36:52 -0700 Suren Baghdasaryan <surenb@googl=
e.com> wrote:
> > > >
> > > > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > > > >
> > > > > This wrapps all external vmalloc allocation functions with the
> > > > > alloc_hooks() wrapper, and switches internal allocations to _nopr=
of
> > > > > variants where appropriate, for the new memory allocation profili=
ng
> > > > > feature.
> > > >
> > > > I just noticed latest mm-unstable fails running kunit on my machine=
 as below.
> > > > 'git-bisect' says this is the first commit of the failure.
> > > >
> > > >     $ ./tools/testing/kunit/kunit.py run --build_dir ../kunit.out/
> > > >     [10:59:53] Configuring KUnit Kernel ...
> > > >     [10:59:53] Building KUnit Kernel ...
> > > >     Populating config with:
> > > >     $ make ARCH=3Dum O=3D../kunit.out/ olddefconfig
> > > >     Building with:
> > > >     $ make ARCH=3Dum O=3D../kunit.out/ --jobs=3D36
> > > >     ERROR:root:/usr/bin/ld: arch/um/os-Linux/main.o: in function `_=
_wrap_malloc':
> > > >     main.c:(.text+0x10b): undefined reference to `vmalloc'
> > > >     collect2: error: ld returned 1 exit status
> > > >
> > > > Haven't looked into the code yet, but reporting first.  May I ask y=
our idea?
> > >
> > > Hi SeongJae,
> > > Looks like we missed adding "#include <linux/vmalloc.h>" inside
> > > arch/um/os-Linux/main.c in this patch:
> > > https://lore.kernel.org/all/20240321163705.3067592-2-surenb@google.co=
m/.
> > > I'll be posing fixes for all 0-day issues found over the weekend and
> > > will include a fix for this. In the meantime, to work around it you
> > > can add that include yourself. Please let me know if the issue still
> > > persists after doing that.
> >
> > Thank you, Suren.  The change made the error message disappears.  Howev=
er, it
> > introduced another one.
>=20
> Ok, let me investigate and I'll try to get a fix for it today evening.

Thank you for this kind reply.  Nonetheless, this is not blocking some real
thing from me.  So, no rush.  Plese take your time :)


Thanks,
SJ

> Thanks,
> Suren.
>=20
> >
> >     $ git diff
> >     diff --git a/arch/um/os-Linux/main.c b/arch/um/os-Linux/main.c
> >     index c8a42ecbd7a2..8fe274e9f3a4 100644
> >     --- a/arch/um/os-Linux/main.c
> >     +++ b/arch/um/os-Linux/main.c
> >     @@ -16,6 +16,7 @@
> >      #include <kern_util.h>
> >      #include <os.h>
> >      #include <um_malloc.h>
> >     +#include <linux/vmalloc.h>
> >
> >      #define PGD_BOUND (4 * 1024 * 1024)
> >      #define STACKSIZE (8 * 1024 * 1024)
> >     $
> >     $ ./tools/testing/kunit/kunit.py run --build_dir ../kunit.out/
> >     [10:43:13] Configuring KUnit Kernel ...
> >     [10:43:13] Building KUnit Kernel ...
> >     Populating config with:
> >     $ make ARCH=3Dum O=3D../kunit.out/ olddefconfig
> >     Building with:
> >     $ make ARCH=3Dum O=3D../kunit.out/ --jobs=3D36
> >     ERROR:root:In file included from .../arch/um/kernel/asm-offsets.c:1=
:
> >     .../arch/x86/um/shared/sysdep/kernel-offsets.h:9:6: warning: no pre=
vious prototype for =E2=80=98foo=E2=80=99 [-Wmissing-prototypes]
> >         9 | void foo(void)
> >           |      ^~~
> >     In file included from .../include/linux/alloc_tag.h:8,
> >                      from .../include/linux/vmalloc.h:5,
> >                      from .../arch/um/os-Linux/main.c:19:
> >     .../include/linux/bug.h:5:10: fatal error: asm/bug.h: No such file =
or directory
> >         5 | #include <asm/bug.h>
> >           |          ^~~~~~~~~~~
> >     compilation terminated.
> >
> >
> > Thanks,
> > SJ
> >
> > [...]
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240325182007.233780-1-sj%40kernel.org.
