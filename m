Return-Path: <kasan-dev+bncBDYJPJO25UGBBFNO56UQMGQEWYURTWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id F14ED7D9CEA
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Oct 2023 17:28:22 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id a640c23a62f3a-9ae7663e604sf158713566b.3
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Oct 2023 08:28:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698420502; cv=pass;
        d=google.com; s=arc-20160816;
        b=WfknFrruOIa4sSUDcznoqcIUoNE5bkmKBCLmbZZ6EYTjZ9fVUgrpaU8SNJ4qZHNqtM
         EObtXRDIgDSGzoQ3WHzpI3ZMXNKSpuSm35nCZZ2sDdj1j9c8DX4DH3EJYF3R2fmZU401
         +rWnZ/n8zcSokFgAIzO7qBhVM9XI5m+bNOkocdM52/et/v8AZCzo2LtZHPofMK2HnbzC
         7vTjAQ0lIX2TGPTjUfOwOKtTNsGAyoEr+T5gammIX9KA1bZp9iZ6TYdXwlkmct2goZaT
         X8TGIjGdCvFCyB3o+FZrfj3OLUOvZVmgXBT+DBpwYyrey4MVQjv6FfnJmN/Jp0bLucgW
         Y3Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C1WeYbcxJvJLvtP1BHWGO2Im9mKtDObDTqNDOablxrA=;
        fh=00Oux9zaM1b5Pf1vZ/6h7eQKGSEhzDT2M+8bcqgo53Y=;
        b=FBWvOSGZ8iGcG1hk0OiDjYpEQihDznu4OdORffxW/7gjJ5UwH6Tj7XvfJcah3bxJDm
         C8TceKuNhHS54G7p49zBpqK3rARQzOsYI9p3gldoLpEBXSrzebE0KU3bMOUiCffOBJ4W
         E55+UKUU3ZueAyZQoDwxAgVvM6eSBz0WrvEz+PPx9VCUhXaDlocXeLvymzPYoRXNIZyw
         6bXjXYwdn1T+28vamUGRbeSMkGpzijlT2L5R8VbmMIKJEkjsqiKcGZhiyrTz6yUyeRGy
         EQcxHkhGGdGyZEoDFCQErPLDcsEDdId+kR/abtkHMdcuasnG68FqHBkl1oYLmm6/kGWt
         OjBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GDTbAS+U;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698420502; x=1699025302; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=C1WeYbcxJvJLvtP1BHWGO2Im9mKtDObDTqNDOablxrA=;
        b=so6w1A4pv4r06OVSJ0NjrHkZjnw50CouHq127j7U3GMoNksrRLAUXSZNo1lV2tRtfe
         ucMWQqlXP/HUjMJJZdUjEYD4iMoyH/RYdcBS7t4gc8Y2mwq4UZtyAUpFisFFZoN+72H9
         gxNOh180J47TTaVkZ45+wCqTaTdFnz+7BcGA2/vu7BlFfgHCkT7d0JLe0e4yYnwm3rL1
         kok3yZ8JW2EVSZPW+aAtS2Wt1lt5gnDvY6kjlgxfG1mm5QHP6T9nICGAePtyOp1hWj0o
         0Z4zr/cyWT1FQcQtDjZgGaF61iZKrzy6HdU9gCvPrIoSBXg5y94IYhQw8MmCIrehj2H0
         qSog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698420502; x=1699025302;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=C1WeYbcxJvJLvtP1BHWGO2Im9mKtDObDTqNDOablxrA=;
        b=R383FxKh+gXJaA9tRf4RE8rofGoyM1xp7o1hURyisl1oPhjHlosbx4t9HzAMA1esf8
         DX9hoEhISKDGGtaoXXG038ahljEFFWjr/IF7g52JL3EtK3Zsck1LXUrcNjgfH0nuoYiL
         KPal956TjWzVJ5tKHw6Ak7kyV4fcZO1Evw5rSCMJMvbCZLZGMWO5m6RrZ9/byxiy6kgr
         OSGCaeiFfCWBkWKZ3aK4coiIp7h2rQU+Ezpyo/yvdkWdjXISgAZeCdX+vxnzDcXip15M
         S9yNAC2HsTBMOv21TwgXhTAE7tZUMpwFNdddmY+uCqEWQHB/iYbiH9aAmxYop9w4Svvl
         nn8g==
X-Gm-Message-State: AOJu0YxozdKv0iXae2UMHKWjUrfDoBy+AHD4aale7qCrdbwR4pe7qGxu
	gfRBWNnghQbCshlVT9H93ZQ=
X-Google-Smtp-Source: AGHT+IHPmJU8KF0E3kvqIA2cTXLhGJo/eoqRv+qM1iqMNIXGyt2xBiXU+h0sM6XNb3OnE7NuSshSaw==
X-Received: by 2002:a17:906:4784:b0:9b2:b691:9b5f with SMTP id cw4-20020a170906478400b009b2b6919b5fmr2663249ejc.41.1698420502033;
        Fri, 27 Oct 2023 08:28:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:de10:0:b0:530:7adf:2268 with SMTP id h16-20020aa7de10000000b005307adf2268ls299730edv.2.-pod-prod-02-eu;
 Fri, 27 Oct 2023 08:28:20 -0700 (PDT)
X-Received: by 2002:a05:6402:1049:b0:540:c989:fcdd with SMTP id e9-20020a056402104900b00540c989fcddmr2510009edu.11.1698420500412;
        Fri, 27 Oct 2023 08:28:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698420500; cv=none;
        d=google.com; s=arc-20160816;
        b=vMWXZSne3YZbjs76a55bIWupbD45qgkHQ1Ie1B7F/gnZHhlKhJbDcBX5JEJBAHDSVU
         v7c3sHKY2webrxoGbLGvOiP6gGE4DS5nHuKl9CqI0nM/Hot4xIciBmq8R50oD6J10QjD
         51t6fWNNlKYEsiJrqA1rSCVPkph/wGR8/+cb1hRyHsbt6yNcMlQi6MNnufWexieAxpfI
         Xs0AM/hou2Ptf1R3eTxJ8eLMlxmumySS6ayev7XEkZAHXpG6YIig23YMWoo4vOiaK0Iq
         JkA2SiCUZqDF23Ewg0DMU2OMU71iUyB/YmHwhcCNz86XfQrWT4RyYUGAuR7EvHzlQi/2
         JISw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pNsl5MInPLJ8RSTN609h9x1G8bOqBML3/WHWrkX2PGU=;
        fh=00Oux9zaM1b5Pf1vZ/6h7eQKGSEhzDT2M+8bcqgo53Y=;
        b=bF0OmStHwvHsYqDw/t8YGTUVjaFtpEiNAi78lvivBVXK3A/GZLJ3IS2pjs4pSOr/3m
         kRhJMxcCVuGzkXQeIh7/7Lap1QsFXQ6k8w44OFA2TNmY/3at/r21nPznk28WhJxQno8/
         dpWA+q6IQ56yY/rZKgoGQ/UohktUSZbBs8VIc0GOynnZd0al0Gpz4r3i0CvTlC/5bix7
         lj38KsawUEdVkzlI+QSey7xQa+sIGB6UCps3x/+11Uo21it4E5kh+E/varY1M4313cDO
         xdkQ7T5PBfLoEEtaDuxZJIQ/cDKjvu25VoTunrpmDjcg8dn+cPo2Cp8VwrWPZy5Vtiz7
         pSzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GDTbAS+U;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x234.google.com (mail-lj1-x234.google.com. [2a00:1450:4864:20::234])
        by gmr-mx.google.com with ESMTPS id m25-20020aa7d359000000b0053e90546ff6si146585edr.1.2023.10.27.08.28.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Oct 2023 08:28:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::234 as permitted sender) client-ip=2a00:1450:4864:20::234;
Received: by mail-lj1-x234.google.com with SMTP id 38308e7fff4ca-2c50906f941so32940201fa.2
        for <kasan-dev@googlegroups.com>; Fri, 27 Oct 2023 08:28:20 -0700 (PDT)
X-Received: by 2002:a05:651c:1070:b0:2c5:47f:8ff7 with SMTP id
 y16-20020a05651c107000b002c5047f8ff7mr2161033ljm.18.1698420499387; Fri, 27
 Oct 2023 08:28:19 -0700 (PDT)
MIME-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com> <20231024134637.3120277-29-surenb@google.com>
 <87h6me620j.ffs@tglx> <CAJuCfpH1pG513-FUE_28MfJ7xbX=9O-auYUjkxKLmtve_6rRAw@mail.gmail.com>
 <87jzr93rxv.ffs@tglx> <20231026235433.yuvxf7opxg74ncmd@moria.home.lan> <b20fe713-28c6-4ca8-b64a-df017f161524@app.fastmail.com>
In-Reply-To: <b20fe713-28c6-4ca8-b64a-df017f161524@app.fastmail.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 Oct 2023 08:28:08 -0700
Message-ID: <CAKwvOdnKwGnxZnnDW-miaUO+M5AN_Np1A0fmj18Mz1AV2aQPzg@mail.gmail.com>
Subject: Re: [PATCH v2 28/39] timekeeping: Fix a circular include dependency
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Thomas Gleixner <tglx@linutronix.de>, 
	Suren Baghdasaryan <surenb@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Michal Hocko <mhocko@suse.com>, Vlastimil Babka <vbabka@suse.cz>, Johannes Weiner <hannes@cmpxchg.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Mel Gorman <mgorman@suse.de>, 
	Davidlohr Bueso <dave@stgolabs.net>, Matthew Wilcox <willy@infradead.org>, 
	"Liam R. Howlett" <liam.howlett@oracle.com>, Jonathan Corbet <corbet@lwn.net>, void@manifault.com, 
	Peter Zijlstra <peterz@infradead.org>, juri.lelli@redhat.com, ldufour@linux.ibm.com, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Ingo Molnar <mingo@redhat.com>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	peterx@redhat.com, David Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Luis Chamberlain <mcgrof@kernel.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, dennis@kernel.org, Tejun Heo <tj@kernel.org>, 
	Muchun Song <muchun.song@linux.dev>, Mike Rapoport <rppt@kernel.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	Yu Zhao <yuzhao@google.com>, David Howells <dhowells@redhat.com>, Hugh Dickins <hughd@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Kees Cook <keescook@chromium.org>, vvvvvv@google.com, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Eric Biggers <ebiggers@google.com>, ytcoode@gmail.com, 
	Vincent Guittot <vincent.guittot@linaro.org>, dietmar.eggemann@arm.com, 
	Steven Rostedt <rostedt@goodmis.org>, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Shakeel Butt <shakeelb@google.com>, Muchun Song <songmuchun@bytedance.com>, 
	Jason Baron <jbaron@akamai.com>, David Rientjes <rientjes@google.com>, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	Linux-Arch <linux-arch@vger.kernel.org>, linux-fsdevel@vger.kernel.org, 
	linux-mm@kvack.org, linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=GDTbAS+U;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2a00:1450:4864:20::234
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Thu, Oct 26, 2023 at 11:35=E2=80=AFPM Arnd Bergmann <arnd@arndb.de> wrot=
e:
>
> On Fri, Oct 27, 2023, at 01:54, Kent Overstreet wrote:
> > On Fri, Oct 27, 2023 at 01:05:48AM +0200, Thomas Gleixner wrote:
> >> On Thu, Oct 26 2023 at 18:33, Suren Baghdasaryan wrote:
> >> > On Wed, Oct 25, 2023 at 5:33=E2=80=AFPM Thomas Gleixner <tglx@linutr=
onix.de> wrote:
> >> >> > This avoids a circular header dependency in an upcoming patch by =
only
> >> >> > making hrtimer.h depend on percpu-defs.h
> >> >>
> >> >> What's the actual dependency problem?
> >> >
> >> > Sorry for the delay.
> >> > When we instrument per-cpu allocations in [1] we need to include
> >> > sched.h in percpu.h to be able to use alloc_tag_save(). sched.h
> >>
> >> Including sched.h in percpu.h is fundamentally wrong as sched.h is the
> >> initial place of all header recursions.
> >>
> >> There is a reason why a lot of funtionalitiy has been split out of
> >> sched.h into seperate headers over time in order to avoid that.
> >
> > Yeah, it's definitely unfortunate. The issue here is that
> > alloc_tag_save() needs task_struct - we have to pull that in for
> > alloc_tag_save() to be inline, which we really want.
> >
> > What if we moved task_struct to its own dedicated header? That might be
> > good to do anyways...
>
> Yes, I agree that is the best way to handle it. I've prototyped
> a more thorough header cleanup with good results (much improved
> build speed) in the past, and most of the work to get there is
> to seperate out structures like task_struct, mm_struct, net_device,
> etc into headers that only depend on the embedded structure
> definitions without needing all the inline functions associated
> with them.

This is something I'll add to our automation todos which I plan to
talk about at plumbers; I feel like it should be possible to write a
script that given a header and identifier can split whatever
declaration out into a new header, update the old header, then add the
necessary includes for the newly created header to each dependent
(optional).
--=20
Thanks,
~Nick Desaulniers

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKwvOdnKwGnxZnnDW-miaUO%2BM5AN_Np1A0fmj18Mz1AV2aQPzg%40mail.gmai=
l.com.
