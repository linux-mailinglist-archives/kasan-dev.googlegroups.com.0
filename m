Return-Path: <kasan-dev+bncBC7OD3FKWUERB25DVOXAMGQEE4CG2QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 32E3C852777
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 03:20:29 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-295aaffe58bsf4507304a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 18:20:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707790828; cv=pass;
        d=google.com; s=arc-20160816;
        b=r/lf/yn8AeQaFLKZb41yDI3dzTMVOeXtnlmKw0aPU0Il59ePcCMUHXdp1yNEaNLO+P
         UM7BJhO8sA/zUSE7Xj6EH4Njl5st2l2RYxIOOcFdrmyC6tZlFiNyuKzrYntVA9JFOOH5
         GvHLSutfQ5L3JTjbc7zKb8Ws0mdXRGNCSjO7JpSUrOilnZDsPr2ZCxlcMEVbWGJ1Hbyd
         qGMIS3Ky3D83rOLAeCoV56CVWCvxvMW0hnqLbXWNwQ/10wXg4GrIUSZlvVcHjpUSFKGB
         MGXyHRzyQgv5vLvf9bJ4YiENCPD4qH+olZPaIQiIpuoH9x0dwxyg4rs4S7n5svi5bHqL
         DEFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BIJaRtpuWCiFx5PVLT/7E+Uf8z+ZeE8nTxMcvHO/3CY=;
        fh=WvlqUMsuc3uOfolxlfHgZ0Yv8FkzNowo5Q24lYYjBDc=;
        b=IUZP4epWwk50kiHfe/5dRQvHDRmSTK/aXtgkdNC1PbqYszQ7XxoRL+s0lul5RNwyVN
         u17LLNBEgzxZHNmSfHTF/2/1C0oI+j0mKZ1SC0z4KAbLt4ULB6Ehm3wPCDtxX2gUTKdw
         aGdy+vL1CHnl6u4vrEIwjmrqQLB4C2FmLS8/Ij4URkgQXwPMCa+CcvkhxlV/+20wot2L
         KOoqDqxF0/MiCS/BOj91BWOnLloA8RnKFpoSwNB19DlApsJDy4Z+yYPWMkN5KO1Be77m
         /KfM+Na6UXYPT9fT0643C47xzfI/AlXK0+f7D4caWDifOep5gSpCj69o5y/tLVp8AqR1
         gRDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nBarJyLZ;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707790828; x=1708395628; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BIJaRtpuWCiFx5PVLT/7E+Uf8z+ZeE8nTxMcvHO/3CY=;
        b=P4QlCwfF/wOqT9tJU5Iv1ozA4uryO+A+q5noTY47vmqSX4knJIdXMwwTxv+63Xe9jC
         2SSewB6ZjsO20vGJoR/DWYAL0R0GDnlEe9tyFhMdRJmoc4zXrEzs51emcTT8hwtzZW37
         7Ymrh+nYNWC/Wwr//+7yC19LyhpwRusdqpvRw7QABcDTU7hItjilvpUpAgtxxUW4nEds
         vEPDTt2l/pB5u/R1dOIoJ6m+3t10yCcddusXeOCmB24HBUJGjX6qnMk8J1DcoA9f9xXv
         bUC6fBMM0Xr1rE1dR7JPYvOOwHT3KHX9Hte+FK1EZfg9iQq3bTYPqTEYQ0i8uSCrXemr
         jWOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707790828; x=1708395628;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BIJaRtpuWCiFx5PVLT/7E+Uf8z+ZeE8nTxMcvHO/3CY=;
        b=C8wV6q+5x+VHDbJ3MEhq/lBPatfpVWYAFR2UmrFjFcmYuBGV4dxv1FOJGOaOJt2gts
         O7VW66jNpxMeJsUAn1/5v8Kp8oNREaaVQ349lWjHjorKPzNHX0gh5KBTwZk7qnau+WD8
         27JYs74m+fjrmOjbEaPbhtUFApE3Ntu5Q23eujiKFF9vKRRV0AQLfx4aeK0BHPWqHGiP
         lxZWdAllFkN4Qco3CVEuAW7MTnniTLex1Nx2/rYpmsJDiY6NZb4wUrHJjxGFQIXrm/nN
         EGyttumPo0/974k2AwQK0DhyR3sznQceEuqLr1ayEQ5fPfYQpVoO3dKjmksUr92x6Dcy
         RWNw==
X-Gm-Message-State: AOJu0YxlvA8PqpLJZOwXa13/O5PgngPjmQeXkpI5tfxjMm4S8mjigg1F
	8OKs9+b3gfzjTA+HuXDj3zljUCfvnAo4xpsICGKuxsM42nRPihW6
X-Google-Smtp-Source: AGHT+IGkBs/wxYFrzRdwNf7MwyPRh5oeGj2gPSPVX215badVN67Pj5TTT5y5XL/bHtEM+VDrk3DD6Q==
X-Received: by 2002:a17:90a:d18d:b0:296:13d5:110 with SMTP id fu13-20020a17090ad18d00b0029613d50110mr1761970pjb.17.1707790827729;
        Mon, 12 Feb 2024 18:20:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:46:b0:297:703:db14 with SMTP id d6-20020a17090b004600b002970703db14ls2341530pjt.2.-pod-prod-00-us;
 Mon, 12 Feb 2024 18:20:26 -0800 (PST)
X-Received: by 2002:a17:90b:3616:b0:296:e3e:fc0 with SMTP id ml22-20020a17090b361600b002960e3e0fc0mr1728538pjb.1.1707790826513;
        Mon, 12 Feb 2024 18:20:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707790826; cv=none;
        d=google.com; s=arc-20160816;
        b=V4n2Nh6D4Nmutrk/+SbIdWEG/zbBBA8w2fOa9CtmEk4Nnv9PtF7MKCv9xOEHqD/oiw
         vBjLqhINLAPN2OWhblZTAFcwjS3FrNJmw8PDEo+62Kz+bEhm+XLqLbR04N2JGcJN/fYX
         jzmFM+IogC/O8nuve8gkrb1+hSR50XNQGEcdoN7HEUQ7PtBavqI3wepIGxyBL9rKVIs6
         s2nnYPrO0FqnucRekWj5eXIV5Efnzlw373Gqrn+5zMKrs77p7t8K9xFnpa5ucsKNHWTI
         HCw4Au91R7wU8qWcQUcepQsp5bNA9fX/KpFUmPTbS6j5SBLwJoPy2SxhJGEOht25Z4D9
         iPwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=S9sbRuvYiarABejv+1FZRtHjtyC1exllh7yCDkk639Q=;
        fh=WvlqUMsuc3uOfolxlfHgZ0Yv8FkzNowo5Q24lYYjBDc=;
        b=BtgE0bxE7zfAain5wMQbX+lqSkUs5NzlLZbh1zA8ksLdHae5+KR+21zf5FlWTwbnmM
         f9lyhv0IjM1Vb4Q98TqcvZXlr0LdI+p6RqyoM/6jf/0m0OBs8lQhRzF+Vdp4CQzwDe2b
         6Tjs5aCpZ7YRZEPMx6oQV5VJoMYJWoe0buiOkbfQzHBN4axUrzDuPSXihC8exzD1rKeA
         5H0C5LBCjRQcJQUpTfvcct+wt+wML902D8pTllB3JkcYzTPTvVRdIhDTGkVCVak2l3oR
         JzkiKFTbjoV0KRBpErQN3N1ckmPAUbAwuxFAtmVbEk1yWsIBlHLjA/GCB2bMUQHW9ewt
         i24A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nBarJyLZ;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCVnhLTwM0uJyqsJRq3dL/O80iYb2nISiQgJgx94HV+z2dJV7urb3p9XgLS5WfM/kp9rJXTcJ7dMZmW88aBGvxlgyejHQ4W4tZ32Hw==
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id w4-20020a17090a8a0400b00297002c50c5si165218pjn.1.2024.02.12.18.20.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 18:20:26 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-dc25e12cc63so4021707276.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 18:20:26 -0800 (PST)
X-Received: by 2002:a25:df91:0:b0:dc6:de93:7929 with SMTP id
 w139-20020a25df91000000b00dc6de937929mr863370ybg.26.1707790825358; Mon, 12
 Feb 2024 18:20:25 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-6-surenb@google.com>
 <202402121413.94791C74D5@keescook>
In-Reply-To: <202402121413.94791C74D5@keescook>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 12 Feb 2024 18:20:13 -0800
Message-ID: <CAJuCfpGkdAy58nR02_PSVXc4=R3faRUL-7Hack3R_aWmAgk5HA@mail.gmail.com>
Subject: Re: [PATCH v3 05/35] mm: introduce slabobj_ext to support slab object extensions
To: Kees Cook <keescook@chromium.org>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nBarJyLZ;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Mon, Feb 12, 2024 at 2:14=E2=80=AFPM Kees Cook <keescook@chromium.org> w=
rote:
>
> On Mon, Feb 12, 2024 at 01:38:51PM -0800, Suren Baghdasaryan wrote:
> > Currently slab pages can store only vectors of obj_cgroup pointers in
> > page->memcg_data. Introduce slabobj_ext structure to allow more data
> > to be stored for each slab object. Wrap obj_cgroup into slabobj_ext
> > to support current functionality while allowing to extend slabobj_ext
> > in the future.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>
> It looks like this doesn't change which buckets GFP_KERNEL_ACCOUNT comes
> out of, is that correct? I'd love it if we didn't have separate buckets
> so GFP_KERNEL and GFP_KERNEL_ACCOUNT came from the same pools (so that
> the randomized pools would cover GFP_KERNEL_ACCOUNT ...)

This should not affect KMEM accounting in any way. We are simply
changing the vector of obj_cgroup objects to hold complex objects
which can contain more fields in addition to the original obj_cgroup
(in our case it's the codetag reference).
Unless I misunderstood your question?

>
> Regardless:
>
> Reviewed-by: Kees Cook <keescook@chromium.org>
>
> --
> Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGkdAy58nR02_PSVXc4%3DR3faRUL-7Hack3R_aWmAgk5HA%40mail.gmai=
l.com.
