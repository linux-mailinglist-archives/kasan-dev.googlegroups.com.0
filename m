Return-Path: <kasan-dev+bncBDEKVJM7XAHRBNVU5WUQMGQESI323GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 39A717D8ECA
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Oct 2023 08:35:37 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-692c0c3bcc5sf1522047b3a.3
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Oct 2023 23:35:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698388535; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gg245Bb7WNn7DUeFyEvc/E6D1FzkOvyiYZwYg9OZn0Fx3x+889oXq+zB6WubSmU0B+
         IC0a0UJ8k2NWotdfSF/bm7Kb84p7Oqhh7bgVcQSfPOYzc/CXIw1BRXojBepToKyeFodR
         3t+gyOcwa/HnPsXoRLq8gI4puRKnCEngw+WKTE/zWJppmt10dSsvJqdwFF034UC5K1V/
         +tjsr0pruqCqWKN0+IApknDPcsWljDI41s1xCY0uzk6SWJ4mz6kFFboLq5BWhkUO10jk
         I6H5dsk+/13OjyUQcpTvGF/AOUxIitq6yYl9LLa/mB8IS/ALM+LXg+VciKdtEOiCtycv
         Q6UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:subject
         :cc:to:from:date:references:in-reply-to:message-id:mime-version
         :user-agent:feedback-id:sender:dkim-signature;
        bh=jlxHJ8WcDIGnc8uqjbBrnFIakzsm8Yogb85sbCcTZCU=;
        fh=uWZzO5qpQEQcsf25sMR9iCX0G8RZ+AMlAp30gdARf6w=;
        b=Tv1P1i//uE+OYzIztHXPhjUXRidMRaYOizkissHBGjjzDEAhGgFEv48cjiOKN+jC4C
         DKH9eu9PHJb42FOJrhDyC0N5THOZdDWFNVT6Px8BBN78T6mc2Rmv7k3+6KtbaZXzGexr
         9EaEtEAid5p8OfyhhIyYqeosxqd+HY+vO0yFepfDVS8/Yqh8zk4DM53bwr6PaT0TO1b3
         +RC8gX1+6RSmuE1GvbxJTQA8lN6CDRZT4xqVBa9SoJTbGf6yt65uNQk17P02u5uFCmqZ
         Ttqsy0GHQkdbQfn914z78/i3FeZjvXMly5ZA24HKoDdQyzQvruMRMYyGq6xY5mYoasTN
         A3xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm2 header.b=Co3DoD8b;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=G8VR12s6;
       spf=pass (google.com: domain of arnd@arndb.de designates 64.147.123.18 as permitted sender) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698388535; x=1698993335; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:subject:cc:to:from:date
         :references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=jlxHJ8WcDIGnc8uqjbBrnFIakzsm8Yogb85sbCcTZCU=;
        b=LWTc42xRU248p3IyoyUh1va0Jo/oN4cJR3AjctJ8jX3iZrUYnmXpW1tkmNpmHsxv+y
         4hap3wYK+OA4px7gbMtOkLy7feXSaTR0d9kJ2/VVbQdcZWQb2Lw1a9TkOoPC5mb4Qqyl
         Hw78cp8RWSDQ6/7HtPSBMpwjiXrTWCRcz5HP9dJSu115f/fOXRyPX6G1GtXXx3U0i160
         3W9Q15KAqCSSalWCjFSs5FcdkH0/B6peAev8eL+fFL7bt+2YZKmvFmr7ipiH7g1UdWvv
         1HzIL9V2oGoK8CmZr28FILy3CBxzYpfa3ie9fisisQ6wo9DZ2+eAiPn9U8gn/YJ15SG2
         wMaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698388535; x=1698993335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jlxHJ8WcDIGnc8uqjbBrnFIakzsm8Yogb85sbCcTZCU=;
        b=TSb1xUERkSt0/fVJZa7iAu3/3HkztNUbLSI5l56RUKZ+h7YHfibyfQi0slflf7kIez
         uaBciL/fN6Zbh67O6SIxNrj02d+J+d0PUl0/hiVaJkmoKwQ65E3JabKFw6BCM/SCRC9w
         kVjC11ZTERt4iqyO6WBMn8kLLTnWIvYYhzkMIvOmVemvJSyjYZiulN6pk01pFxpHGYhR
         EiCVtjRgJCqKSk3aA/nNRI81jz5+B5Z1jkcoQ66NiDZq2mewOGRIEyOXkiiVz98EbIGc
         +vkXtWXP5ag2HLrD9OhzSIWnU7DNkzfeKzTSasAUotcqLB4SY8BsJ4nzyBpCobHDNW2b
         mtUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyv/em7S8VTJ32DvOZGqoZS22ylQpoHo6RVR/w6/4zgz40SeNbW
	Y/H/6/oA6VbQatzCJWKrHXQ=
X-Google-Smtp-Source: AGHT+IE6BauW80QEKMJO/b8TTWCKw3U3eRXl6ntC5xgdOctD/scvrXt9BHJLufwf5UlB1Ayy7UGckQ==
X-Received: by 2002:a05:6a20:3d0e:b0:125:517c:4f18 with SMTP id y14-20020a056a203d0e00b00125517c4f18mr2504993pzi.8.1698388535071;
        Thu, 26 Oct 2023 23:35:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8b8e:0:b0:690:ea06:ac7b with SMTP id r14-20020aa78b8e000000b00690ea06ac7bls371251pfd.1.-pod-prod-01-us;
 Thu, 26 Oct 2023 23:35:33 -0700 (PDT)
X-Received: by 2002:a05:6a00:2d82:b0:6be:5a6c:d3f7 with SMTP id fb2-20020a056a002d8200b006be5a6cd3f7mr2075458pfb.2.1698388533220;
        Thu, 26 Oct 2023 23:35:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698388533; cv=none;
        d=google.com; s=arc-20160816;
        b=N1ztHXEBur6agrf5PCVJVGPYocPTSCLq/Zvfk4cEEm+C8EyvCgF2Fbayl94xMMn2+B
         KNbbkWf6LNlAZkEuOYcqaRwuUjs9ppXhoHL1O3GoDAf3GHCz6DnOyrCf5CBk83aSB7dw
         Dg8wUMfOCcWTOXN0dTTzRk5t6TFSk7L6H89aYIGaruCwj8XPBkw9FwSyQH1IJxSTlDS2
         i3AnkO+qD6qcShaIzAyuFsBTf7wLssRNPsUjvTSXychkHZI7SmymCICfaoEIePiGVYFy
         bCHBbnE7IHuZ3N0yWVjyCdrmWABbTjcB8x0HuWP1GVnJrclYZSWDiRYinW6SHIA+lrY4
         pfFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id
         :dkim-signature:dkim-signature;
        bh=ijn9LKOmAMUGBGwJHsN1qvv5KR6XAd5/U4/K/UeLB/A=;
        fh=uWZzO5qpQEQcsf25sMR9iCX0G8RZ+AMlAp30gdARf6w=;
        b=gaN3ZtlVFeF1cq87thPfX9Ako9hfiZCSa2ba5IamlohnMaEwNK+actNsUfxKB8De4o
         z+xd9oyfXkm1zr5/EhThtMI2REgJOhvr7iPgYC9jeG7l8V7Z8iBEuZs9McIe329ID6XM
         YHONeK/9z5CXGoI27hpytF+EJ5R0YRuqf7ddtdr/UayCmzD3VxcUR4p36+qe8XnQt2XF
         zy7JCzQhbZbw9qzhWgSlVQv2mHqYeAx0lyULswLPH7IOrjGB1YakgDecPqQ1ZbjZFzgD
         awX6KLShKr5uQS6J7wlhNyU5LDJ9Kjzkk9pFc8mEDcls5v4GpICXhdFO3Kaf5PiksZVS
         XjCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm2 header.b=Co3DoD8b;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=G8VR12s6;
       spf=pass (google.com: domain of arnd@arndb.de designates 64.147.123.18 as permitted sender) smtp.mailfrom=arnd@arndb.de
Received: from wnew4-smtp.messagingengine.com (wnew4-smtp.messagingengine.com. [64.147.123.18])
        by gmr-mx.google.com with ESMTPS id s15-20020a056a00178f00b0068fc872aba7si56589pfg.0.2023.10.26.23.35.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Oct 2023 23:35:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 64.147.123.18 as permitted sender) client-ip=64.147.123.18;
Received: from compute5.internal (compute5.nyi.internal [10.202.2.45])
	by mailnew.west.internal (Postfix) with ESMTP id 453572B001CD;
	Fri, 27 Oct 2023 02:35:27 -0400 (EDT)
Received: from imap51 ([10.202.2.101])
  by compute5.internal (MEProxy); Fri, 27 Oct 2023 02:35:31 -0400
X-ME-Sender: <xms:LVo7ZRWsO_unWYu4ju6ykbSu9MYRJfztp2h3Hg91pQmQ1bQ7KXmCuA>
    <xme:LVo7ZRk_VbZ3s_4MFpp4aUnzy34FteDE0FNGnvLqNeFIFqxw4AQ_fAL4VF172GTww
    8K9fHpJD02cY0xiRfg>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvkedrleefgdduudduucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepofgfggfkjghffffhvfevufgtgfesthhqredtreerjeenucfhrhhomhepfdet
    rhhnugcuuegvrhhgmhgrnhhnfdcuoegrrhhnugesrghrnhgusgdruggvqeenucggtffrrg
    htthgvrhhnpeegfeejhedvledvffeijeeijeeivddvhfeliedvleevheejleetgedukedt
    gfejveenucevlhhushhtvghrufhiiigvpedtnecurfgrrhgrmhepmhgrihhlfhhrohhmpe
    grrhhnugesrghrnhgusgdruggv
X-ME-Proxy: <xmx:LVo7ZdaraAnXl7vbxcbu3owb9AQodY0_BeE21QSXqHQfgyHky4Urfw>
    <xmx:LVo7ZUXaHk4M_ArR8v54dGQDfuVQbnZYZ7P1x01AJs86H5ezMF3Exw>
    <xmx:LVo7ZbmxHEW-g-Q9jYAzYXCrpN5ZcT1sWKrQtBuAHgjrTCDtaVCDLQ>
    <xmx:Llo7ZT-fuieYFxFRVAc9BzDL-760Z8iDF-9Ct6bKgRo4g3IfQQwSAu5oprg>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id F0DD6B60089; Fri, 27 Oct 2023 02:35:24 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.9.0-alpha0-1048-g9229b632c5-fm-20231019.001-g9229b632
MIME-Version: 1.0
Message-Id: <b20fe713-28c6-4ca8-b64a-df017f161524@app.fastmail.com>
In-Reply-To: <20231026235433.yuvxf7opxg74ncmd@moria.home.lan>
References: <20231024134637.3120277-1-surenb@google.com>
 <20231024134637.3120277-29-surenb@google.com> <87h6me620j.ffs@tglx>
 <CAJuCfpH1pG513-FUE_28MfJ7xbX=9O-auYUjkxKLmtve_6rRAw@mail.gmail.com>
 <87jzr93rxv.ffs@tglx> <20231026235433.yuvxf7opxg74ncmd@moria.home.lan>
Date: Fri, 27 Oct 2023 08:35:03 +0200
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Kent Overstreet" <kent.overstreet@linux.dev>,
 "Thomas Gleixner" <tglx@linutronix.de>
Cc: "Suren Baghdasaryan" <surenb@google.com>,
 "Andrew Morton" <akpm@linux-foundation.org>,
 "Michal Hocko" <mhocko@suse.com>, "Vlastimil Babka" <vbabka@suse.cz>,
 "Johannes Weiner" <hannes@cmpxchg.org>,
 "Roman Gushchin" <roman.gushchin@linux.dev>,
 "Mel Gorman" <mgorman@suse.de>, "Davidlohr Bueso" <dave@stgolabs.net>,
 "Matthew Wilcox" <willy@infradead.org>,
 "Liam R. Howlett" <liam.howlett@oracle.com>,
 "Jonathan Corbet" <corbet@lwn.net>, void@manifault.com,
 "Peter Zijlstra" <peterz@infradead.org>, juri.lelli@redhat.com,
 ldufour@linux.ibm.com, "Catalin Marinas" <catalin.marinas@arm.com>,
 "Will Deacon" <will@kernel.org>, "Ingo Molnar" <mingo@redhat.com>,
 "Dave Hansen" <dave.hansen@linux.intel.com>, x86@kernel.org,
 peterx@redhat.com, "David Hildenbrand" <david@redhat.com>,
 "Jens Axboe" <axboe@kernel.dk>, "Luis Chamberlain" <mcgrof@kernel.org>,
 "Masahiro Yamada" <masahiroy@kernel.org>,
 "Nathan Chancellor" <nathan@kernel.org>, dennis@kernel.org,
 "Tejun Heo" <tj@kernel.org>, "Muchun Song" <muchun.song@linux.dev>,
 "Mike Rapoport" <rppt@kernel.org>,
 "Paul E. McKenney" <paulmck@kernel.org>, pasha.tatashin@soleen.com,
 yosryahmed@google.com, "Yu Zhao" <yuzhao@google.com>,
 "David Howells" <dhowells@redhat.com>, "Hugh Dickins" <hughd@google.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>,
 "Kees Cook" <keescook@chromium.org>,
 "Nick Desaulniers" <ndesaulniers@google.com>, vvvvvv@google.com,
 "Greg Kroah-Hartman" <gregkh@linuxfoundation.org>,
 "Eric Biggers" <ebiggers@google.com>, ytcoode@gmail.com,
 "Vincent Guittot" <vincent.guittot@linaro.org>, dietmar.eggemann@arm.com,
 "Steven Rostedt" <rostedt@goodmis.org>, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com,
 "Christoph Lameter" <cl@linux.com>, "Pekka Enberg" <penberg@kernel.org>,
 "Joonsoo Kim" <iamjoonsoo.kim@lge.com>,
 "Hyeonggon Yoo" <42.hyeyoo@gmail.com>,
 "Alexander Potapenko" <glider@google.com>,
 "Marco Elver" <elver@google.com>, "Dmitry Vyukov" <dvyukov@google.com>,
 "Shakeel Butt" <shakeelb@google.com>,
 "Muchun Song" <songmuchun@bytedance.com>,
 "Jason Baron" <jbaron@akamai.com>,
 "David Rientjes" <rientjes@google.com>, minchan@google.com,
 kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, Linux-Arch <linux-arch@vger.kernel.org>,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
Subject: Re: [PATCH v2 28/39] timekeeping: Fix a circular include dependency
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm2 header.b=Co3DoD8b;       dkim=pass
 header.i=@messagingengine.com header.s=fm3 header.b=G8VR12s6;       spf=pass
 (google.com: domain of arnd@arndb.de designates 64.147.123.18 as permitted
 sender) smtp.mailfrom=arnd@arndb.de
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

On Fri, Oct 27, 2023, at 01:54, Kent Overstreet wrote:
> On Fri, Oct 27, 2023 at 01:05:48AM +0200, Thomas Gleixner wrote:
>> On Thu, Oct 26 2023 at 18:33, Suren Baghdasaryan wrote:
>> > On Wed, Oct 25, 2023 at 5:33=E2=80=AFPM Thomas Gleixner <tglx@linutron=
ix.de> wrote:
>> >> > This avoids a circular header dependency in an upcoming patch by on=
ly
>> >> > making hrtimer.h depend on percpu-defs.h
>> >>
>> >> What's the actual dependency problem?
>> >
>> > Sorry for the delay.
>> > When we instrument per-cpu allocations in [1] we need to include
>> > sched.h in percpu.h to be able to use alloc_tag_save(). sched.h
>>=20
>> Including sched.h in percpu.h is fundamentally wrong as sched.h is the
>> initial place of all header recursions.
>>=20
>> There is a reason why a lot of funtionalitiy has been split out of
>> sched.h into seperate headers over time in order to avoid that.
>
> Yeah, it's definitely unfortunate. The issue here is that
> alloc_tag_save() needs task_struct - we have to pull that in for
> alloc_tag_save() to be inline, which we really want.
>
> What if we moved task_struct to its own dedicated header? That might be
> good to do anyways...

Yes, I agree that is the best way to handle it. I've prototyped
a more thorough header cleanup with good results (much improved
build speed) in the past, and most of the work to get there is
to seperate out structures like task_struct, mm_struct, net_device,
etc into headers that only depend on the embedded structure
definitions without needing all the inline functions associated
with them.

      Arnd

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/b20fe713-28c6-4ca8-b64a-df017f161524%40app.fastmail.com.
