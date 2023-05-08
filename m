Return-Path: <kasan-dev+bncBCLL3W4IUEDRBL554SRAMGQECTS4M4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 364736FB4C7
	for <lists+kasan-dev@lfdr.de>; Mon,  8 May 2023 18:09:20 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-4f139de8c55sf4966713e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 May 2023 09:09:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683562159; cv=pass;
        d=google.com; s=arc-20160816;
        b=j/bZneLRcdg9vGaCeQCXZ9mVYPPkT+lz5JzLbWeZoIBKujNxLhAhxE6PYxV+vnk7EL
         cm5oJH7+IAONixiLMzOsgQFbosj1HR95PkIdngTXTB93NbbmG/6CGY3sLpvFQ36LB3cA
         T71MPXt5JvzZVLBgHr1RXTq6Y+HAO7B7TufVF0N/l0HwWbtsQNAARwJRd/vrZekXWcwT
         Fb5dFyONPgYVPII+3HUHqf2cbJIbRN7ffltLle7AxOtSflZaQJJ4Uaj1WtSOmWBHOAuI
         FM1dXTvDtlMuwaDR6sAQrJ7EMYIuJIxusmGVCDLrNIkDL/34y7EPyV6qUWddTOGGcvPW
         JhvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=/kvLDwjNOSlLqLDmzPyMVbn6yH9Cx9A0fgn8vtdNdtc=;
        b=SG7VKdQPF2IlGzYg6kCKpxp1LNBaaR5cBa1y5zbq928NV6wVNIozaNyPFwXM6c9ig3
         dFaI0+kotCZvXsZaj8+mtRCDRTdYnbhSPCngrLvYaFWdfNjDTmtmBdwsHH9fs0RJY27x
         0zmyCvzefyx5LhKVNKBMsL40xsrDjR8mZ4CJRgwr6G1juzt4IZq/6uBBeEYb7Ry6RACl
         OGgeYD9mlqIY2qxxyGC+7tIMqIYMHYI+t9ReMLAe1TmY5KU4n0SPhYbYhfOCnG5sRpXO
         4N3OVHU1hONNH7QzSJe8fC4kTYGGefpH6w5Ais+3abhWXCxbWUh1SzFUvJfrzadC9l8H
         1rmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=CADkuX60;
       spf=pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683562159; x=1686154159;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/kvLDwjNOSlLqLDmzPyMVbn6yH9Cx9A0fgn8vtdNdtc=;
        b=DXtysj+Lgy4IVXmNuV1v4P0jcDl8RhV09lQahdRmf0ITPVjzpwqqZygd+O21WKSwfL
         PKol9pgwuDvF40cauGmVlZ2LNn+MIJ9S+R8iS7IEtoeYuS4wQlKu+PKXPo3Au/TaG7af
         mqtMYkteZDNyaE82fVWbgN/UGr3s8Hsn5QB1dH+/cOWvkp11doaqcT5ul37AsBRqoXA5
         tGtktvaHq6NuWrxl9kMyyCwuDQXh5ww3cFA+i7WYC9X26ZVUd8OR5QFp0MjYxBHwlpJp
         PmoNabUUsQ4zxkbguoetsjrENHpCva04fRyYwpcCFTxgu0uG3dQl+trkkTGKC6omYdmn
         t/GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683562159; x=1686154159;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/kvLDwjNOSlLqLDmzPyMVbn6yH9Cx9A0fgn8vtdNdtc=;
        b=UvjmxD021SwUnTuU5uViUin195oPv/n2svmK1D0xI2Vzx0207qqJpRRcgz8BgpQBve
         1ghXAKd+c3z/ghmCdBupV0cv+5Rh5qbnB1CgjgOv05wpVZxv1wYb0e8X0jpNI9duuc3D
         uB1zGmuuEYQUuZxEh7zoU4+noLnlxm+jIJiZNxpkJ9VxUhuYNyJp+HcldBn5IlSUOypG
         zdmA8f6IwdyJJVMAp3yUWFEJ4gddpk+RS6dbah1CWp9Dyx46wfCZthNOvQD78Tve8UXY
         EecKqHE4nSHWy0pXPiK6A1s8h13o0h8z24b7juyJRiRaJjW+gkk4A3fKx+5BrHxSVsUV
         UYWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDy0mICpU1q0/8MoNkDyoUEmC8KTAZog0EQyUJ5ROlkEW/8yZR2N
	4JqasnfCDf0hq64zGCJHqd4=
X-Google-Smtp-Source: ACHHUZ4GNCKyXYSxGP4k5GHnb2rb9uqPm9Q6BYfoCbTH/UusSjqcURYrV0P3yugEzy4TQi6XyHDmQw==
X-Received: by 2002:a2e:a992:0:b0:2ac:7ab9:f1d7 with SMTP id x18-20020a2ea992000000b002ac7ab9f1d7mr4104279ljq.4.1683562159359;
        Mon, 08 May 2023 09:09:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b15:b0:4e8:c8b4:347a with SMTP id
 w21-20020a0565120b1500b004e8c8b4347als701104lfu.1.-pod-prod-gmail; Mon, 08
 May 2023 09:09:18 -0700 (PDT)
X-Received: by 2002:a05:6512:1021:b0:4e8:61ea:509a with SMTP id r1-20020a056512102100b004e861ea509amr2481705lfr.7.1683562157975;
        Mon, 08 May 2023 09:09:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683562157; cv=none;
        d=google.com; s=arc-20160816;
        b=NpK4bzhjhO66pMrMtb0+WLJiTq8SHEk1CeWyZLHHrtvBZoRHYXYETLi94t2L5Z+Qwl
         gcXyhOpyY1kqr9S/JrMkMXG8988gZGQvBNrav+qUt993INuScnVSMKgURTa1y1Nv9m2P
         WBPGzoPggP8hXOn4undwKQ6vKnLxKFZxB/8V5+vwcTgrEo7fdlTc0OqDcPXp3dOrUhS+
         UkglB/sn3LrlAeVL5O6C/M2f1SbPDfPUl72izwxOTMJ4mF1vkCT/Ekp7/48m3lKBr0eF
         249q5hl6YtZcgKYhyS/mQi8nwzbYhREq/e5TR5va9bKbjLdCu9PAgzIIKZx2uUheS5fB
         Jq8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=3vhaqezEwBKNVkdCmLqVMfvToTleKNzHmBxoVSbRVoQ=;
        b=caC3QMOJ6bzhfZv5dw2l5urikGFiUA8hx5mtkYgJuMTS2szTm0VOjk+iD6YYv52qot
         uJfW5XT+wy4/Jt9CqKbW6U0CWt/v6aTcw6FIQnLVyeioo7WG5jeenRyyZ8dwX++ZF3Ft
         +M7SZZeNB7UHIowpyGzivELfrpkV0zzSMXwlaIQRBW0aQo3xANc+ggBtrN8gZNKbmk3J
         0/86AgPsQPxDkRE8DS4Da9VRmFpyLnY+B6v9VNymgkc+nRxFX+0FKYFqhRGIynjp/Q1e
         zXe7aON3G7jqeYdE+LRnjhHpaq6B/nkqvMLXfYC0hmkwE1KbFXjgS5JfCgst9YnAKMCu
         kcsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=CADkuX60;
       spf=pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
Received: from bee.tesarici.cz (bee.tesarici.cz. [2a03:3b40:fe:2d4::1])
        by gmr-mx.google.com with ESMTPS id r9-20020ac25f89000000b004dc4bb412f7si19789lfe.12.2023.05.08.09.09.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 May 2023 09:09:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) client-ip=2a03:3b40:fe:2d4::1;
Received: from meshulam.tesarici.cz (dynamic-2a00-1028-83b8-1e7a-4427-cc85-6706-c595.ipv6.o2.cz [IPv6:2a00:1028:83b8:1e7a:4427:cc85:6706:c595])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by bee.tesarici.cz (Postfix) with ESMTPSA id 481AC155357;
	Mon,  8 May 2023 18:09:14 +0200 (CEST)
Date: Mon, 8 May 2023 18:09:13 +0200
From: Petr =?UTF-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Michal Hocko <mhocko@suse.com>, Suren Baghdasaryan <surenb@google.com>,
 akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
 void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
 ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org,
 arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
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
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <20230508180913.6a018b21@meshulam.tesarici.cz>
In-Reply-To: <ZFkb1p80vq19rieI@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
	<ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
	<CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com>
	<ZFN1yswCd9wRgYPR@dhcp22.suse.cz>
	<ZFfd99w9vFTftB8D@moria.home.lan>
	<20230508175206.7dc3f87c@meshulam.tesarici.cz>
	<ZFkb1p80vq19rieI@moria.home.lan>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.37; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: petr@tesarici.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tesarici.cz header.s=mail header.b=CADkuX60;       spf=pass
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

On Mon, 8 May 2023 11:57:10 -0400
Kent Overstreet <kent.overstreet@linux.dev> wrote:

> On Mon, May 08, 2023 at 05:52:06PM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> > On Sun, 7 May 2023 13:20:55 -0400
> > Kent Overstreet <kent.overstreet@linux.dev> wrote:
> >  =20
> > > On Thu, May 04, 2023 at 11:07:22AM +0200, Michal Hocko wrote: =20
> > > > No. I am mostly concerned about the _maintenance_ overhead. For the
> > > > bare tracking (without profiling and thus stack traces) only those
> > > > allocations that are directly inlined into the consumer are really
> > > > of any use. That increases the code impact of the tracing because a=
ny
> > > > relevant allocation location has to go through the micro surgery.=
=20
> > > >=20
> > > > e.g. is it really interesting to know that there is a likely memory
> > > > leak in seq_file proper doing and allocation? No as it is the speci=
fic
> > > > implementation using seq_file that is leaking most likely. There ar=
e
> > > > other examples like that See?   =20
> > >=20
> > > So this is a rather strange usage of "maintenance overhead" :)
> > >=20
> > > But it's something we thought of. If we had to plumb around a _RET_IP=
_
> > > parameter, or a codetag pointer, it would be a hassle annotating the
> > > correct callsite.
> > >=20
> > > Instead, alloc_hooks() wraps a memory allocation function and stashes=
 a
> > > pointer to a codetag in task_struct for use by the core slub/buddy
> > > allocator code.
> > >=20
> > > That means that in your example, to move tracking to a given seq_file
> > > function, we just:
> > >  - hook the seq_file function with alloc_hooks =20
> >=20
> > Thank you. That's exactly what I was trying to point out. So you hook
> > seq_buf_alloc(), just to find out it's called from traverse(), which
> > is not very helpful either. So, you hook traverse(), which sounds quite
> > generic. Yes, you're lucky, because it is a static function, and the
> > identifier is not actually used anywhere else (right now), but each
> > time you want to hook something, you must make sure it does not
> > conflict with any other identifier in the kernel... =20
>=20
> Cscope makes quick and easy work of this kind of stuff.

Sure, although AFAIK the index does not cover all possible config
options (so non-x86 arch code is often forgotten). However, that's the
less important part.

What do you do if you need to hook something that does conflict with an
existing identifier?

Petr T

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230508180913.6a018b21%40meshulam.tesarici.cz.
