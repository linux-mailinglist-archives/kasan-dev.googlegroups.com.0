Return-Path: <kasan-dev+bncBCLL3W4IUEDRBB6MZWRAMGQE72IYTHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id D2ACF6F666B
	for <lists+kasan-dev@lfdr.de>; Thu,  4 May 2023 10:00:07 +0200 (CEST)
Received: by mail-ej1-x63f.google.com with SMTP id a640c23a62f3a-94a355cf318sf18931266b.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 May 2023 01:00:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683187207; cv=pass;
        d=google.com; s=arc-20160816;
        b=km8K65M2tXEsIBX2mG1l5gpF+NI4ijqcMGxN9G2oezP32AZk2QCfUcygYc7ItlRUMT
         yj6hh1p6cncOy36mRa7OUZiWxKPOmPGL8fLwwnR/xY2pdx56kN1mJGCLtSjCosvvB4qf
         sYJawW897j1VnceGpbPBsmBfBqd/fhgXp3i0Fwv49wowEzJ5l8rYAWlvRxE4pEV+0mc1
         3Cw+KW7GIyAufkwkefA3+x3kIL2H6CHb1LlLy0FlLCOHUHKDXOZANHD81BFXukGE1qNy
         C1JLhK3kwh44TqNH0KqY/J9C7yCFXkqV4KbiKDk7Y2eZl7vhVXtwn567J7kD5zWiFDg2
         /Swg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=ZrIGGzsOHVGwIj1WPxS8VfULlDuntiFzGy/5Ihoh1AA=;
        b=DMyKW/D9WZ253RHOn9MyfvvNMW5254lo0kpA76OCtcA9WX8+6GWSJ2h1QTTbSFtiPQ
         M5a6Fsk/d0QeehsUgkov4xywwrvaA0At0NwT2uf3ftxgYmMqNF2V1KJdHu3egu8jQdbf
         Tt1ZrDh8KLCBNaAl+Hvohxrbuq4BLIU3RjCRvbDDL99Q3aCA85DJJ4StFs59k8yFqIZR
         adHmqSB6WCwySY3ui3K+uDXjsQgioFVGViuHkWGKkS1U04CzS1CByq8NXiMk4JXV0Iqz
         oVjmbKjCvpR3Sf8EKiyfIDWGIcVc+tXFcNJICrjftmGSjzNGYLJUpwrMDOw2970A8prw
         lQ2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=i7U3c2nW;
       spf=pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683187207; x=1685779207;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZrIGGzsOHVGwIj1WPxS8VfULlDuntiFzGy/5Ihoh1AA=;
        b=SSLdMnO5BLTFdeA4mRhmcDG2v/8pF9cZLxtLbL1syPuzp0g/5XrDO8f0pacsRH2uK7
         ZLEUA1Tkc6/DHvZth71okrA3uKUR3+X4+YH6fJrYrQ+DLaZgrqUwwHk/4V37ycMsMhj5
         VSZpnu4Mtum+0RuCYmJNPt3rwFKgdqGt52wOTFjszm6tf0MeV/lJKBIfn2XcdFHI7T2B
         Wt5bszdURUm1wtwXD1VAYt5dB0nxkw9TEUyCwTrAKQjiUCITrdKZED2ngguaPDAHwQVt
         XCO+kM8DpiKZh+w2FjphLRcm+pcrlOPhUaHVmM8g/bMVSInIbvEYFzoH8NYrIjd0YLq7
         /cAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683187207; x=1685779207;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZrIGGzsOHVGwIj1WPxS8VfULlDuntiFzGy/5Ihoh1AA=;
        b=NWBml4VdNaXc0dsmTDWZ3VP4R9JUpoiPZzMR0YBWww4728kPeEZpkGMBP7mJx3BYtt
         UdvtPo1+3hdwR1LUFDjdd9dDXopU5iszqzQHUxBj/AXSJLi/a63BYciqP8oyyVzNVmFi
         wb56wSt7BnSwv2Q1056KgFP0wxBDVBlBBZn2JrANing0lKJov3s7fPQz2JPLZhO5yr8e
         Menw1O73i0uW07e6xqLa1nS0Cy6/JNfTuXHnoiQp7w7Jwe/t+d43xyYqmsXoww30Ri62
         Kb91xxGLNAnRizb7b2so7D1zYmZnkdiTYxuRDLNOavO/b061PQPXcaV/0GH12CNCqo2L
         GSPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwqpk7zagjIEx6ddiK1YlJbP5FO8z0IlxORPNLxWvVZBBvcgY5k
	vdiJ2wV2h3LgVQyNFEfkuV0=
X-Google-Smtp-Source: ACHHUZ4gWvUAz0S+jIxo/gbX1TA6WQjT1MZf0I0B7OZs2MOAmhGAnLGLCUoT/Ok3+J438wyKb+EkMQ==
X-Received: by 2002:a17:906:5da5:b0:962:3303:6747 with SMTP id n5-20020a1709065da500b0096233036747mr2005473ejv.11.1683187207283;
        Thu, 04 May 2023 01:00:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:44a:b0:502:3ff4:37d8 with SMTP id
 p10-20020a056402044a00b005023ff437d8ls149376edw.1.-pod-prod-02-eu; Thu, 04
 May 2023 01:00:06 -0700 (PDT)
X-Received: by 2002:aa7:c559:0:b0:50b:caae:ae6e with SMTP id s25-20020aa7c559000000b0050bcaaeae6emr647292edr.17.1683187205987;
        Thu, 04 May 2023 01:00:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683187205; cv=none;
        d=google.com; s=arc-20160816;
        b=yE93bNbgWFzRJgTrjSFYVkE/G7KttzaomOyuc/W5rG/ec0KuoYslkGuU+BdXm5RG8i
         EiRpUjpSeYYujt7CALVmCyc7rqfbSwVbv4bG1W5X+ZMmv0tl7V7YTuyd77zs9UW4eE0m
         FBLjYGOWZnBie+48HlqixxmlBdH107w4vkcKAwGP0HkmLehZdhs/jow0w3z6578G3y2X
         lOQI/l22Mokd1gOTz5XY8SefuLX2WwCibptX7ACu/XemEzf68z3UEubw6af1z3jnJzFT
         YNPhdlD9SOgSWsmCaNxHlv6YqGyKCvQNBozvlvktnuYYkrvrZX3gTkUNKm78Tlq2Xdku
         AmKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=14yIEEd7A8I6Tu7lFvLcP+c0d1kvUNzGycGQrBMqaec=;
        b=Rx0s8VdTKHbDX+5jLWIR+irQ5SH36aonfzNuIWUjmk8XqNFXGB6Qz6YW49k8uy0GOr
         4kAbq2vwgAfOjGM9LZahtR7nrUUaurCbkm5Te/cNNS73a9zUW6ATXOaB1m1BQhdSpB2m
         FDnkYZWfnV52OO6zrz900zT2yQDvmx+aVJtjDCqA0IoSvYbGk4J4ol66k8ItslGLp5EY
         sMpYmEWbificgh6sTrYUzjcUHMiOw3GLhV6p1LjHmtnXhleBvCxJb3rX8qKs5/7nFA29
         vTFxYtNMWPqf4ElRjWOr87lIrsgEGoaDxSNNxB6kTddIvaHdsg0NoKkuRfheWdSVdU2K
         Nppg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=i7U3c2nW;
       spf=pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
Received: from bee.tesarici.cz (bee.tesarici.cz. [2a03:3b40:fe:2d4::1])
        by gmr-mx.google.com with ESMTPS id fd19-20020a056402389300b0050a31d1615bsi218270edb.1.2023.05.04.01.00.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 May 2023 01:00:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) client-ip=2a03:3b40:fe:2d4::1;
Received: from meshulam.tesarici.cz (dynamic-2a00-1028-83b8-1e7a-4427-cc85-6706-c595.ipv6.o2.cz [IPv6:2a00:1028:83b8:1e7a:4427:cc85:6706:c595])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by bee.tesarici.cz (Postfix) with ESMTPSA id C0CB514F3D5;
	Thu,  4 May 2023 10:00:03 +0200 (CEST)
Date: Thu, 4 May 2023 10:00:02 +0200
From: Petr =?UTF-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Tejun Heo <tj@kernel.org>, Kent Overstreet <kent.overstreet@linux.dev>,
 Johannes Weiner <hannes@cmpxchg.org>, Michal Hocko <mhocko@suse.com>,
 akpm@linux-foundation.org, vbabka@suse.cz, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
 tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
 x86@kernel.org, peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
 mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 dennis@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
 paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com,
 yuzhao@google.com, dhowells@redhat.com, hughd@google.com,
 andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org, Alexei Starovoitov
 <ast@kernel.org>, Andrii Nakryiko <andrii@kernel.org>
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <20230504100002.3d410939@meshulam.tesarici.cz>
In-Reply-To: <CAJuCfpE4YD_BumqFf2-NC8KS9D+kq0s_o4gRyWAH-WK4SgqUbA@mail.gmail.com>
References: <ZFIVtB8JyKk0ddA5@moria.home.lan>
	<ZFKNZZwC8EUbOLMv@slm.duckdns.org>
	<20230503180726.GA196054@cmpxchg.org>
	<ZFKlrP7nLn93iIRf@slm.duckdns.org>
	<ZFKqh5Dh93UULdse@slm.duckdns.org>
	<ZFKubD/lq7oB4svV@moria.home.lan>
	<ZFKu6zWA00AzArMF@slm.duckdns.org>
	<ZFKxcfqkUQ60zBB_@slm.duckdns.org>
	<CAJuCfpEPkCJZO2svT-GfmpJ+V-jSLyFDKM_atnqPVRBKtzgtnQ@mail.gmail.com>
	<ZFK6pwOelIlhV8Bm@slm.duckdns.org>
	<ZFK9XMSzOBxIFOHm@slm.duckdns.org>
	<CAJuCfpE4YD_BumqFf2-NC8KS9D+kq0s_o4gRyWAH-WK4SgqUbA@mail.gmail.com>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.37; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: petr@tesarici.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tesarici.cz header.s=mail header.b=i7U3c2nW;       spf=pass
 (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as
 permitted sender) smtp.mailfrom=petr@tesarici.cz;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=tesarici.cz
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

On Wed, 3 May 2023 13:14:57 -0700
Suren Baghdasaryan <surenb@google.com> wrote:

> On Wed, May 3, 2023 at 1:00=E2=80=AFPM Tejun Heo <tj@kernel.org> wrote:
> >
> > Hello,
> >
> > On Wed, May 03, 2023 at 09:48:55AM -1000, Tejun Heo wrote: =20
> > > > If so, that's the idea behind the context capture feature so that w=
e
> > > > can enable it on specific allocations only after we determine there=
 is
> > > > something interesting there. So, with low-cost persistent tracking =
we
> > > > can determine the suspects and then pay some more to investigate th=
ose
> > > > suspects in more detail. =20
> > >
> > > Yeah, I was wondering whether it'd be useful to have that configurabl=
e so
> > > that it'd be possible for a user to say "I'm okay with the cost, plea=
se
> > > track more context per allocation". Given that tracking the immediate=
 caller
> > > is already a huge improvement and narrowing it down from there using
> > > existing tools shouldn't be that difficult, I don't think this is a b=
locker
> > > in any way. It just bothers me a bit that the code is structured so t=
hat
> > > source line is the main abstraction. =20
> >
> > Another related question. So, the reason for macro'ing stuff is needed =
is
> > because you want to print the line directly from kernel, right? =20
>=20
> The main reason is because we want to inject a code tag at the
> location of the call. If we have a code tag injected at every
> allocation call, then finding the allocation counter (code tag) to
> operate takes no time.

Another consequence is that each source code location gets its own tag.
The compiler can no longer apply common subexpression elimination
(because the tag is different). I have some doubts that there are any
places where CSE could be applied to allocation calls, but in general,
this is one more difference to using _RET_IP_.

Petr T

> > Is that
> > really necessary? Values from __builtin_return_address() can easily be
> > printed out as function+offset from kernel which already gives most of =
the
> > necessary information for triaging and mapping that back to source line=
 from
> > userspace isn't difficult. Wouldn't using __builtin_return_address() ma=
ke
> > the whole thing a lot simpler? =20
>=20
> If we do that we have to associate that address with the allocation
> counter at runtime on the first allocation and look it up on all
> following allocations. That introduces the overhead which we are
> trying to avoid by using macros.
>=20
> >
> > Thanks.
> >
> > --
> > tejun =20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230504100002.3d410939%40meshulam.tesarici.cz.
