Return-Path: <kasan-dev+bncBCCMH5WKTMGRBVNW26VAMGQEIEZACCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B1357EDD52
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 10:05:27 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4219f585f25sf134581cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 01:05:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700125526; cv=pass;
        d=google.com; s=arc-20160816;
        b=j28+pse/5D70ucWQ+3Rri813Q1Grs1rMNJyti4Bql8dPSWk6o1bCztiHEGa3UfAsGj
         kUxOPzo0GuGYIrJ3+pAiiX4UkFqFYpVp14bMLMc45VUk34nMGqYi8VvMR3LjGR0M39B5
         FAz32V/VXCFY90X49XRyorgsVXp3gzrbi+2LrSaw93/BQ6BJ7VnIDs4UcRlUxrisHYMi
         0Y81u+EPdWVnxDvSfvMMqByc1vKVjkFjVjRkzkG82B1kKJIXqeAvBajoFpkcnhK+Xxzd
         TXxNYbp75JqLs5BUIYsOSHCz5L6YBdxvUTmi7WCNMJt7OvruD6vb9Ec3xjHzeltxGV0p
         btqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WxR+zqcZjqiH4cqExmvFtP4gz2A5rg5XpF9M/tE/dAA=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=mQaJRxE0oVfdeHGTZnvu5olzC8Pfqya27IQyGoRx33RraeiikdHuZkp84YBZjRjN+X
         PtanC+VZLHoGubDvW4KoVxvAoPmsKOA7QAs6tztcKLqRovXSlspketbPhblvkKH7izUd
         6p3eucNDbsqFxLKCtohJsWN45VF3JER2HchJAtfKKACac803t3F87uMKvFqfixoquwvG
         3a0j7TT15/FVVr59BFRtA/N/vGUpAqwi58OmaYc9J033G8oazN8RvvOF+OCONj7NMJXR
         h8GgtnRzdw+YHS8mapeQ7Do4k3PuDHdMeXGT3FZ3oGkY2Izo33QlxyFRZO0HNLIn30NJ
         B5ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WAFDAw+n;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700125526; x=1700730326; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WxR+zqcZjqiH4cqExmvFtP4gz2A5rg5XpF9M/tE/dAA=;
        b=xboEwoUCdWGbIMMnsoluU6legdy1XHM9ZCzX3PpSCVRnOr12QG4mBWI7Dvd5UwQ81B
         qeUWDipACX3/2FeOn6GI1tfAZIkzRdIQi5GE4LkWfvtZ31cEyaKLvl/bF394rUVZMDgt
         MTlF7e0W9QWTZnlWXUlGHENiU2YfZt4eKebS41+8M8RboIdoRdAd3b80XyCX13KZdg+2
         GfGBkEpAOdW83cJ1uUbPNsdIb9sM0tcSbRNh4a8LwsvNCWLcDv0rIyo/CuROKF9txI8/
         uebbEidzgHA93sJx/y6TcX+umEF5ZulxaaeEFhIDqTTIoiBeylRRlK7cdtm9A+aN9tIJ
         1LeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700125526; x=1700730326;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WxR+zqcZjqiH4cqExmvFtP4gz2A5rg5XpF9M/tE/dAA=;
        b=ejn9qsciVaMmNMLCh8mUF4QaKN2Lf99tKh+xQjZQQx7CCh8Mhj+QPm1MZUJkLhehx9
         0gseoQ2j4ohsHXRmTr0oyVQ4dmHLzYZXByKoy8h9GEVMCzd787wOWgANhuJEPftEhacv
         tP00NNhtGz6PX/9O0O4C3Iz6w3dl1m252aifTyKfqtQ+ePylUImlBJUQ7xsYo2hJ38MT
         ZrjckW+GmB0dASJlEvcnbwSvFTbtM+sU40KaH/1zjtz68YoCoZbg1eVVs7ZiYXDlF3jb
         1iSWS9PqKAJpd/LayVSQ3Ch71h4T7b3oGrF8QzPTbO7dTIQw9eFo2L5xhEtvg2n4rAIq
         g/zA==
X-Gm-Message-State: AOJu0YxLzQl+eH1XcmWuQd34Kz2qCqnkJq+xeKdOn7iFNNThw2303Vds
	R+rbw7YetNCmAUQfkf+XWj4=
X-Google-Smtp-Source: AGHT+IGQnezYJra1uRN9VeCiFjwJgnIErp0twt31e9hHdGzv+ZZInLR47TocmK7MTwYAOSNlczlYGA==
X-Received: by 2002:ac8:4d04:0:b0:421:a2b0:5b44 with SMTP id w4-20020ac84d04000000b00421a2b05b44mr127770qtv.25.1700125525998;
        Thu, 16 Nov 2023 01:05:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a1b:b0:41c:b790:86d1 with SMTP id
 f27-20020a05622a1a1b00b0041cb79086d1ls851272qtb.2.-pod-prod-06-us; Thu, 16
 Nov 2023 01:05:25 -0800 (PST)
X-Received: by 2002:a05:620a:4d92:b0:77b:d28d:9324 with SMTP id uw18-20020a05620a4d9200b0077bd28d9324mr6144813qkn.76.1700125524944;
        Thu, 16 Nov 2023 01:05:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700125524; cv=none;
        d=google.com; s=arc-20160816;
        b=lKiknBBShzOrXe0srla2HC8YQ5ah721Yj0Z4H4wSsGVajZzLi1nyMGBgzwcD37PlY6
         IOLTQwmmMnhySz3buwu+zgYYM2+T/DQVOQ1ffKNMYCiOuGNhFrz350KTyAd6OS/R+9og
         1gTwMtD+4oxY/SKqaP9af9gSAER7oDNiKbu8Ps4sr3NYQti61DRg+82ph/dEfNO8cB87
         pecoPkjUKdyAF38BLKCkkqD1zZgbCkj9d7azWFJjrSl/5YiT52F1fjscSWw6Y9mBFCcD
         G1bEm5BgxRPD7ZwKHENxHbdnkRtP0e98XoAdMJ5nT6TTg767MbmSNGXDVWTBsRnSPu4O
         9FuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=cXPXLemzi7uHNP/MTyau/JmrJz+5u7EITKeIMDjwkIM=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=DWK8hwO5Ev2rN+8sOd+L6pWoQJzUnEZiFzeazlFdZE1R3eEoCZEVACRWu4ZUfN+xJJ
         JCNVqFDWOeI/e6fXh22gYWR7YjDv6DSdE4xC18eDs/0fhkkN1BDy1B/YmthZenVMfJuv
         m0CzBFFveEOV5s4SECREasRbj6O8dWFjNCm6c0US8fW+y2L7iq3QKqGUw2kFxd25Xskv
         so3G2gRyQ19mqyVACQloeZeuHZfEb/A8HxMP33zzwyiIuTs02AXuTEBQXzOq/5c/imu4
         Lqfnkyh0jLU77XRtca20/a9L8lVD4fPuaGPxgJeZvy+lzX6vy8/oDrFepXYchk+HQ863
         JEdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WAFDAw+n;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2e.google.com (mail-qv1-xf2e.google.com. [2607:f8b0:4864:20::f2e])
        by gmr-mx.google.com with ESMTPS id ea9-20020a05620a488900b0076709fdb678si610800qkb.4.2023.11.16.01.05.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 01:05:24 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) client-ip=2607:f8b0:4864:20::f2e;
Received: by mail-qv1-xf2e.google.com with SMTP id 6a1803df08f44-66d0169cf43so3112776d6.3
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 01:05:24 -0800 (PST)
X-Received: by 2002:a05:6214:d1:b0:675:b8ff:b5e2 with SMTP id
 f17-20020a05621400d100b00675b8ffb5e2mr7955988qvs.50.1700125524454; Thu, 16
 Nov 2023 01:05:24 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com> <20231115203401.2495875-31-iii@linux.ibm.com>
In-Reply-To: <20231115203401.2495875-31-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 10:04:48 +0100
Message-ID: <CAG_fn=WW1BUehMSsbjtPb4gKpakLGi3bF2KFEPxE4dV7n1ToSQ@mail.gmail.com>
Subject: Re: [PATCH 30/32] s390/unwind: Disable KMSAN checks
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Marco Elver <elver@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Pekka Enberg <penberg@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=WAFDAw+n;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2e as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Nov 15, 2023 at 9:35=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> The unwind code can read uninitialized frames. Furthermore, even in
> the good case, KMSAN does not emit shadow for backchains. Therefore
> disable it for the unwinding functions.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  arch/s390/kernel/unwind_bc.c | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/arch/s390/kernel/unwind_bc.c b/arch/s390/kernel/unwind_bc.c
> index 0ece156fdd7c..7ecaab24783f 100644
> --- a/arch/s390/kernel/unwind_bc.c
> +++ b/arch/s390/kernel/unwind_bc.c
> @@ -49,6 +49,7 @@ static inline bool is_final_pt_regs(struct unwind_state=
 *state,
>                READ_ONCE_NOCHECK(regs->psw.mask) & PSW_MASK_PSTATE;
>  }
>
> +__no_kmsan_checks

Please add some comments to the source file to back this annotation,
so that the intent is not lost in git history.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWW1BUehMSsbjtPb4gKpakLGi3bF2KFEPxE4dV7n1ToSQ%40mail.gmai=
l.com.
