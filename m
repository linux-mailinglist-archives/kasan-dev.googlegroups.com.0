Return-Path: <kasan-dev+bncBCS2NBWRUIFBBRXY5OUQMGQEL23FVKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id AA1927D8C5F
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Oct 2023 01:54:48 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-507c7db3bf0sf2003e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Oct 2023 16:54:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698364488; cv=pass;
        d=google.com; s=arc-20160816;
        b=LWCL//YYzTFFdu6vtTqZ+WO09Jtg3LW+aKu29phroMzKPbRz5jr+ft/HpXHtJ13aZM
         X5oyRzIDoaiaVTDdxTNKBXwDrbKJ3eDmMqOuczESp1TWkpaVKFtuaniMNmD8grSLFWRl
         oUMROpPWb1nIGb3wCXrC4K21bGRSJIvVBp0gecX80e9dz0CNnsmYEm5ZkOqbr9u5ZgUl
         bVxJhw3MJuG1TiVGjBNkXaYU3QK0yhWepkNGdLYvX9eGPFlLEYqqu8nmMJcfpMWGWtV1
         I+DwM9ksmO1cctspHuamUa/p7tHuqSjrBlm787gtTlJWJHELeeoPnCdrsuKJWiF4X19V
         eALA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=VHl4B58R5s3rjc27v8ayG3xD1X2TdR1pq+OlMFoArGM=;
        fh=IbUJGniV65HjVcebiXPvGqvpT0jXTmZ2goXrGG7aXJs=;
        b=d7c5WYJsS01NCQfe7Ro7QW6O4RfdJPXDLWz6/h+FSyeyNLgU0hqGkTQ52qfcfef5pj
         lWTNOfTCDhdCiGMHIvwkX1XhckQjGpFR6kIvGTejlhGrezYXzJVwAzEj99aWSmQ+wCsy
         +lgFZ/Eb1ZaK7BDXUYb3TugkSLW3iniY4S8H+G20qtZsDSajQwsRmwGJ4zxw0OZ7IDkE
         kssWTrmyIqkEdmC4i+X+HoLwVKaRc5aOeYKAPv4Br8jAahVD4dozpITKu1SRq7uzMD1r
         bOmo/7fRTxsmoOEw3P2ZekezUyFo2tX9nkz/7G+Y2lqxGN1WMsD8UvXNu+bCk+sEbxoV
         bm4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="wlXDU2r/";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.176 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698364488; x=1698969288; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=VHl4B58R5s3rjc27v8ayG3xD1X2TdR1pq+OlMFoArGM=;
        b=E+yWXoGoj1rRKlHF1oNglUlOOcKlWuu0hzzbTSdWNuy+qzmg9gfUJ2wze/3ffkD9jc
         AATsoygPGjBrgACFVsDo7zfXl86Cd6w5Yisz02BzbxJw2uML0IB4IDNeCrBnzxkVdwWo
         0I3+ka/njyLUPd/2893H7Nk8H6Je/xjjA9V4DibDh1bI3vpE9GPwrAv5+rdbwrfIiexH
         N6PbOexd3rsONWAvi9F+mV1+ozRT6b1v2PC9rAOHQgjAenzH0vd3lXGw/HOS74OiTkHn
         XSVRcsNRO7G822NpB4A9kpb2XD4otQisNmxo+lmuNWX6GSJRwmbOJlI3W7uzoWsK0p9b
         PZnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698364488; x=1698969288;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VHl4B58R5s3rjc27v8ayG3xD1X2TdR1pq+OlMFoArGM=;
        b=cx1KIIUW18Enr7DYHiO4LP577djrhitTo9t2O5OEIniNExMDakz9e3AUJfDtlSkeJa
         +8C8L87SrZ6Zyg7wRMuTnSO/4WVTw+SnzRCtVJB8+f7quo2tbGbvH8uwjow7Gfaitqal
         ayUp4gZdOtVbDzdosGqFmd8bEXtjpTiwEVF3cS9LkBuD54/5g6LGJNsFL8kT/Z5Cv/UX
         MGnG3+X1u7m4kV1LPBSxPqtbE9TyHdk9UA7cE+VcSw26+a8ZX8oCdfEOntueYxc57vcT
         N3vIJXHZnLvbuwfTfe7o2EVkdXcrltXxgjy+pT4Mr76gjYZouimdFM+MZ3x01oSejPQR
         njXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywnv6EBn2XANIiEcFIuJdOUT3efnHz/MwoCR9cVZZ21EFaPjsmA
	wH42ejVdXmMjbxOwUVgokx4=
X-Google-Smtp-Source: AGHT+IHXOXPyG0FhrfpW+mlFQgkOIIAmz/HmvzRM1oJ92NbbIUAI4JARxdC47GS6FVtndEVcTHinHw==
X-Received: by 2002:a05:6512:2141:b0:502:a55e:fec0 with SMTP id s1-20020a056512214100b00502a55efec0mr42794lfr.6.1698364487226;
        Thu, 26 Oct 2023 16:54:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4892:b0:507:9702:8b88 with SMTP id
 eq18-20020a056512489200b0050797028b88ls397299lfb.1.-pod-prod-03-eu; Thu, 26
 Oct 2023 16:54:45 -0700 (PDT)
X-Received: by 2002:a05:6512:4024:b0:4fe:49d:6ae2 with SMTP id br36-20020a056512402400b004fe049d6ae2mr876505lfb.0.1698364485471;
        Thu, 26 Oct 2023 16:54:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698364485; cv=none;
        d=google.com; s=arc-20160816;
        b=gdwG71/NVu7LEQnBn36S8N66wXTJLCloXUdTA53m7slVUmGwe/UEMCv4HUneMvVTrZ
         PWcHYrCJnIBbYP1f2QkSFms9ZFOYGTEvXSiA/IW2KYn8zvZddphr0YC+rXlIBraD7ctI
         AIlLF5J/jzFO41BT7ik1SqKn8vT5d6ef+6U7eVUlbSkmXy/dAWGtUXDJQWK4jxUM/SVA
         hX/2Edpjjij6sKbMFc/p2/F2cuONwXgqd8+4bsi0Q+Tmu79S1ZrdrKCfMagVH7LDaaUZ
         az4PySSBnEhTdAOMVdJwcuiBms+N53qT4ca/hs0m4l1otSQpo6Zp/1YHDI8YNtvaUbWH
         zNjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=fxBcC6WpG3KRFkLY2+tQDJJ4+RZgo+8n9ZWicropf8c=;
        fh=IbUJGniV65HjVcebiXPvGqvpT0jXTmZ2goXrGG7aXJs=;
        b=PYQ5h8c5jJ6pMynEd2RCRYUrY3TP+TrXQ3qEGPXw5yDHF62/3yex69i/6YYJz62a0Q
         uXK4QiihGSbwwLYRp5uCTNkU3znEZd6JzjxJkegyPqlbT9uFSUoN1+Kmi/04gS8OMbUv
         Mc4I0OGo8to0gxCj43Ss4Sy5XyeGjNovLyCOGjfHsIbDkRf8C/kvheRMe5Jtt897rGn5
         CR7EfonAWDPYO/wQKz5iBda/HV4RoeOE4VkQT0IlSDEosw8dlx7BSVfIofeQl0t4Ek7M
         qBlH8toxNo6iq+g4efDTWk7eCerPRmRJ4SlCANoEIug77/a3CNlylaXZVeVRH+O8+p3F
         WiGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="wlXDU2r/";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.176 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-176.mta1.migadu.com (out-176.mta1.migadu.com. [95.215.58.176])
        by gmr-mx.google.com with ESMTPS id d32-20020a0565123d2000b005008765a16fsi19693lfv.13.2023.10.26.16.54.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Oct 2023 16:54:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.176 as permitted sender) client-ip=95.215.58.176;
Date: Thu, 26 Oct 2023 19:54:33 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v2 28/39] timekeeping: Fix a circular include dependency
Message-ID: <20231026235433.yuvxf7opxg74ncmd@moria.home.lan>
References: <20231024134637.3120277-1-surenb@google.com>
 <20231024134637.3120277-29-surenb@google.com>
 <87h6me620j.ffs@tglx>
 <CAJuCfpH1pG513-FUE_28MfJ7xbX=9O-auYUjkxKLmtve_6rRAw@mail.gmail.com>
 <87jzr93rxv.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <87jzr93rxv.ffs@tglx>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="wlXDU2r/";       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.176 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Fri, Oct 27, 2023 at 01:05:48AM +0200, Thomas Gleixner wrote:
> On Thu, Oct 26 2023 at 18:33, Suren Baghdasaryan wrote:
> > On Wed, Oct 25, 2023 at 5:33=E2=80=AFPM Thomas Gleixner <tglx@linutroni=
x.de> wrote:
> >> > This avoids a circular header dependency in an upcoming patch by onl=
y
> >> > making hrtimer.h depend on percpu-defs.h
> >>
> >> What's the actual dependency problem?
> >
> > Sorry for the delay.
> > When we instrument per-cpu allocations in [1] we need to include
> > sched.h in percpu.h to be able to use alloc_tag_save(). sched.h
>=20
> Including sched.h in percpu.h is fundamentally wrong as sched.h is the
> initial place of all header recursions.
>=20
> There is a reason why a lot of funtionalitiy has been split out of
> sched.h into seperate headers over time in order to avoid that.

Yeah, it's definitely unfortunate. The issue here is that
alloc_tag_save() needs task_struct - we have to pull that in for
alloc_tag_save() to be inline, which we really want.

What if we moved task_struct to its own dedicated header? That might be
good to do anyways...

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20231026235433.yuvxf7opxg74ncmd%40moria.home.lan.
