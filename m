Return-Path: <kasan-dev+bncBCKPFB7SXUERBQ4T4XCQMGQEFEI6Z7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FA38B4350B
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Sep 2025 10:11:50 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-324e41e946esf1233383a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Sep 2025 01:11:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756973507; cv=pass;
        d=google.com; s=arc-20240605;
        b=bxTq92Yl2mmR5axVTDH0WgcbRYRPN+vJSHj+MGJ6eyjO0zfcfDEnDzqDoEinA87+MB
         Mhpzd8A/xIC/4SXhyLoWqXHl3zb/+RgfarwrIoBzEsS+uGO8GLs/na4ORfJP2CgYpbCE
         R4JkZwgzr+/du6QHQSNlS2UXc0D0xnLdUhl/0D3iIgrbpKHsQqTWyNSs2NBz0LYlX1gZ
         8SM11n+LjPf0OVH/kuvhwStuCvgSmV/EyJPEw0oRyivTXVH/F0NxDQRCrIJxxwEhtKv+
         MIEpKCFH6Ca7OKeTFeqywI9jGOLs0e6J8nXZUb0gKhyfVQsSaCoWVLtNQ3FFmJktdKUT
         xquw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=4blQu5Kzhs6HYlwXgcU4OJsTOERNCaU7fmQWTVOMLhg=;
        fh=q16Z1UlZ1KKw9aH6Im6w7y5GTN3EnHesEoUROu2QBQM=;
        b=TWnJzzvKvwJMCDcxnAJbIWrNS75VDf1aUy7yWN+e8vRe2MaaSVB2IwONJ91U77hbKy
         /1R+27DrD9149nUmdElBEgHt06JmrV9cdp58FvQ9juOsdKQisQEQnC1ooq+vUvmSqTiO
         YwYbeIDMmUu7jVeDnjm2kqd2zeNrRnzbTE18qU+F7I01pOedjKtnHMMv99pJfvK40e+j
         p54WIIPcdESdd+4Jp61qQVgXF0KN2EDFfDZZyQpyFfVs6CBWfYJp/g/pRXCjiHp9h/GP
         NSIYTWjcKdw/lTjL0VzMKYgRWEgRPZOCw45dNyg2xmtKAMeW42HRVXswH0i9Vjl2aIKb
         sM1A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="JW4/Qwge";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756973507; x=1757578307; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=4blQu5Kzhs6HYlwXgcU4OJsTOERNCaU7fmQWTVOMLhg=;
        b=tEQIJBlidqUdjgXx5noqdH9yRq/Bu8pmyVtSYtRVQQxVvrjyvJuwfpg/hXliBoazAA
         HAY1PoycDaydr1DjceDX70Ed2Mjbj/mFzpz0MZ7yOESofrjhw/uycxcLvKYF96RJ4fI1
         us5evRALXGnm8gITscR5F4FAX2aIJv6V9IlgwuoraG4Sc3A6uFneyUaA9hQLMFoJ0CEG
         wMGA/PkQeJqZTmVxdVN0hGELc9fMMtdgUkOgEEsFrejVLanZeC9+LC+UUPHP5t91tRsT
         k6BBj34gPg+4FUKdpzDh+RhGlAOZ+hUXRHe1xORMaf6KrHWdMwfm9F3mAE7kYu4r01FD
         0QMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756973507; x=1757578307;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=4blQu5Kzhs6HYlwXgcU4OJsTOERNCaU7fmQWTVOMLhg=;
        b=v8c+EPi9bjAWqoDs9BriGBjaknnn7tejuMZAf0+Ji92LvSHhC2WOoD6kwd7AyqKWyc
         npfbNLm2jcEL0keGAb3glNAeCtpxb/8qEQfMqoGl/qhPMOJDCvvTcuomG2Wjji9F7Vpz
         I0f26gGYi5wIzzAO0T+2F4CgkPui0OQIpYpU747G4gWrfbTcgXAjaOMJyO+4+5NSQh10
         iovnNCUkncUY528COZwTKufXaI/dcYnONsQXy6a45Cqw4XC52HvOuyJkZcJs3q52PkOe
         B9RxQTIR19oW6So3/R3GTK34Xoo/Z9JoeNG19gv1PZRUl8gOdkHtY2gwIxwFa6hwweKW
         h6Tg==
X-Forwarded-Encrypted: i=2; AJvYcCVBgXr8l0c4w82R7mS5X4BeabOmkQJI2o8gQRhrwWfkf2u53rczI1yIL6L/0vYLKS/hQNNPUA==@lfdr.de
X-Gm-Message-State: AOJu0YwJfkSn/4YAA5wpaA+1z2uKLoT92x0tiLcMtIWrFRRv7mQCc7VA
	tMNUDh7JCrSAYPopbg92srREdE5kDls54uIG6fKwtRMyftwiOy/4mpAX
X-Google-Smtp-Source: AGHT+IEgaqiOFkvcwyD7I9LjXyglHzqeU1zA4/Fa6RdM2HHTqIVexlrP1e7JWAXIZQYPNgqji6Cihw==
X-Received: by 2002:a17:90b:2245:b0:32b:90a5:ed2c with SMTP id 98e67ed59e1d1-32b90a5f1f2mr2826336a91.20.1756973507423;
        Thu, 04 Sep 2025 01:11:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdvVkfUW+T7gCJuyUhFJ2yIolTYlJ47vsbMRPVm+5AQSw==
Received: by 2002:a17:90b:5584:b0:321:c794:1cbb with SMTP id
 98e67ed59e1d1-327aacd18fdls8375913a91.1.-pod-prod-06-us; Thu, 04 Sep 2025
 01:11:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV1D583HiV0EHdIzK+IBrn4HFiwqYq0y1cvL4jttfxjEQaB28P+JmyMMh1wjomJ6K9bpyFIU1Ps72o=@googlegroups.com
X-Received: by 2002:a05:6a21:999f:b0:24c:48f3:3fd2 with SMTP id adf61e73a8af0-24c48f34120mr1414666637.24.1756973506089;
        Thu, 04 Sep 2025 01:11:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756973506; cv=none;
        d=google.com; s=arc-20240605;
        b=ArPplHH8pQDj6lul9nk401Th9ZXbZM1R8n/rEPQPURzaUmYuY5Jfr6dQdD5ex6cqMn
         FTuO9edz9ClS6j9I8FX5NvACl7ndOW1zqFObdaYg8I9CsJsGqnmwx1+aZvLrkWpl1mgS
         R7GMxYnmFvrO5uD2ExMXPx5i0DNe2HwiwJAOsTtJMUGlpi+RhhHlLCBJqZMt0ueHqfWs
         CJ4TJPTB8dFAx0Lda5QOmdFIApZBNuaRJce8GCxNkvV7ixBTP0yfwqnFn4OPuJqtNYku
         vDLQ3mIKiW4jp+g3y+Fh9T/dKhVR3nk+RnocsPUjlGRifid5JYtXEr/0Bx75plJ6I71R
         Io8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Pr0Y4bkCbfd3itfrxpuVGdfdmmRa0XxzBqHDc5t+1Us=;
        fh=UGuqUXvML/cHLhf4E1PmZ8AzOnpOlFnqJwHOSj3W6X8=;
        b=gyq8E9vjP7Tu+CW+Gkj2cYkzQn7rvbbbFIqRBeKryY3Tv3Hn82XqKFklXtMAgEVEKl
         /sTzJs9Ye/f3aNKzVzEyYesxjT/TLUsPcYghdV0WO95fkwVEJeA1atCkVpVjd4+mszMQ
         LnTimtcK9X2kw3P+aStPp4E9uNNkYZDwGzYkBY70JAGkuP2w0q27NIYh3CSNXIq9iyMK
         WKLQ0tLWNya4qqQia2pJwtY56MylYYvXZ7CQLfHErtc/uw9vmzEYFxs2vj5KWIN8wqKR
         DeihvqDkkSrH36aT2OgObFAiHWpmE3rYmmmBhXarFsjkP0ROGJmnOgij0sMiQVjzOUx1
         qVdQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="JW4/Qwge";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32b91305464si74953a91.0.2025.09.04.01.11.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Sep 2025 01:11:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-502-44yZFtgQN2Gh_XbvPEWQXg-1; Thu,
 04 Sep 2025 04:11:41 -0400
X-MC-Unique: 44yZFtgQN2Gh_XbvPEWQXg-1
X-Mimecast-MFC-AGG-ID: 44yZFtgQN2Gh_XbvPEWQXg_1756973499
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id DF26F180034D;
	Thu,  4 Sep 2025 08:11:38 +0000 (UTC)
Received: from localhost (unknown [10.72.112.19])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 5AD32180035E;
	Thu,  4 Sep 2025 08:11:36 +0000 (UTC)
Date: Thu, 4 Sep 2025 16:11:33 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: glider@google.com, dvyukov@google.com, elver@google.com,
	linux-mm@kvack.org, ryabinin.a.a@gmail.com,
	vincenzo.frascino@arm.com, akpm@linux-foundation.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org, sj@kernel.org,
	lorenzo.stoakes@oracle.com, snovitoll@gmail.com,
	christophe.leroy@csgroup.eu
Subject: Re: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three
 modes
Message-ID: <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv>
References: <20250820053459.164825-1-bhe@redhat.com>
 <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="JW4/Qwge";
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

On 09/03/25 at 03:22pm, Andrey Konovalov wrote:
> On Wed, Aug 20, 2025 at 7:35=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote=
:
> >
> > Currently only hw_tags mode of kasan can be enabled or disabled with
> > kernel parameter kasan=3Don|off for built kernel. For kasan generic and
> > sw_tags mode, there's no way to disable them once kernel is built.
> > This is not convenient sometime, e.g in system kdump is configured.
> > When the 1st kernel has KASAN enabled and crash triggered to switch to
> > kdump kernel, the generic or sw_tags mode will cost much extra memory
> > for kasan shadow while in fact it's meaningless to have kasan in kdump
> > kernel.
> >
> > So this patchset moves the kasan=3Don|off out of hw_tags scope and into
> > common code to make it visible in generic and sw_tags mode too. Then we
> > can add kasan=3Doff in kdump kernel to reduce the unneeded meomry cost =
for
> > kasan.
>=20
> Continuing the discussion on the previous version: so the unwanted
> extra memory usage is caused by the shadow memory for vmalloc
> allocations (as they get freed lazily)? This needs to be explained in
> the commit message.

Hmm, up to now, there are two parts of big amount of memory requiring
for kernel as I observed. One is the direct memory mapping shadow of
kasan, which is 1/8 of system RAM in generic mode and 1/16 of system
RAM in sw_tags mode; the other is the shadow meomry for vmalloc which
causes meomry big meomry usage in kdump kernel because of lazy vmap
freeing. By introducing "kasan=3Doff|on", if we specify 'kasan=3Doff', the
former is avoided by skipping the kasan_init(), and the latter is avoided
by not build the vmalloc shadow for vmalloc.

Yes, I totally agree with you, I should have put this in cover letter
and the main patch log to explain it better.

>=20
> If so, would it help if we make the kasan.vmalloc command-line
> parameter work with the non-HW_TAGS modes (and make it do the same
> thing as disabling CONFIG_KASAN_VMALLOC)?
>=20
> What I don't like about introducing kasan=3Doff for non-HW_TAGS modes is
> that this parameter does not actually disable KASAN. It just
> suppresses KASAN code for mapping proper shadow memory. But the
> compiler-added instrumentation is still executing (and I suspect this
> might break the inline instrumentation mode).

I may not follow your saying it doesn't disable KASAN. In this patchset,
not only do I disable the code for mapping shadow memory, but also I
skip any KASAN checking. Please see change of check_region_inline() in
mm/kasan/generic.c and kasan_check_range() in mm/kasan/sw_tags.c. It
will skip any KASAN checking when accessing memory.

Yeah, the compiler added instrumentation will be called, but the if
(!kasan_enabled()) checking will decide if going further into KASAN code
or just return directly. I tried inline mode on x86_64 and arm64, it
works well when one reviewer said inline mode could cost much more
memory, I don't see any breakage w or w/o kasan=3Doff when this patchset
applied..

>=20
> Perhaps, we could instead add a new kasan.shadow=3Don/off parameter to
> make it more explicit that KASAN is not off, it's just that it stops
> mapping shadow memory.

Hmm, as I explained at above, kasan=3Doff will stop mapping shadow memory,
and also stop executing KASAN code to poison/unpoison memory and check the
shadow. It may be inappropriate to say it only stops mapping shadow.

>=20
> Dmitry, Alexander, Marco, do you have any opinion on kasan=3Doff for
> non-HW_TAGS modes?
>=20
> On a side note, this series will need to be rebased onto Sabyrzhan's
> patches [1] - those are close to being ready. But perhaps let's wait
> for v7 first.

I replied to Sabyrzhan's patchset, on top of this patchset, it's much
easier and cleaner to remove kasan_arch_is_ready(). We don't need
introduce CONFIG_ARCH_DEFER_KASAN. Please see below patchset which is
based on this patchset introducing 'kasan=3Doff|on' to genric|sw_tags
mode.

[PATCH 0/4] mm/kasan: remove kasan_arch_is_ready()
https://lore.kernel.org/all/20250812130933.71593-1-bhe@redhat.com/T/#u

>=20
> [1] https://lore.kernel.org/all/20250810125746.1105476-1-snovitoll@gmail.=
com/
>=20

Thanks a lot for reviewing and feedback.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
LlJtTeNMdtZAA9B%40MiWiFi-R3L-srv.
