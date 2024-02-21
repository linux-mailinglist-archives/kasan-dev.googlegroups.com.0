Return-Path: <kasan-dev+bncBCC2HSMW4ECBBAOU3GXAMGQEUAN7ISI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1064385EA10
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 22:24:19 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1dc1db2fb48sf26070055ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 13:24:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708550657; cv=pass;
        d=google.com; s=arc-20160816;
        b=CsS9El8gDcHgPZJBGiR8S9/amME9n0Hp8mhmFejPhRARubjFM+ghHBKSslJlxwWoEx
         ThND2TCSwRaZo9IUfvfenxwhBXCMYaeHx2ttx1w5czwe2jSxTpmJLpZeeRgVau3hy2PP
         QTfJQocSoUlQj5L04OR3oGn4oOuVNYkAMzqjPgfhgcoGg/Cq0ZYRSZtOGqioq8xTMXYE
         DZwb8ld8Bs0iEqXY4hzPYfmXRRh7P4ZQRzhe2JiwD79yvEjK+j3dLdBjTmci6GCDN57q
         CS0z4PiLwuzviYns5lBZ1XQijHSTXf6dchwr7/arWg60QyJqgfG8QCPE1TOXRYETos+B
         MfUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=3O3CuH45HhbrzNI0ENdtqw2+aiYKLlkLaHn+eoc5YwA=;
        fh=trFEpThaLQdWfzLMWN0sGkC9UuGJqjsxoyF73VKWygg=;
        b=aozrjSh0f538gRtNCP5L7XCLhsEqBsegz8ipzzzi0WdvuLXx08yFadTGBwoBd3M7tZ
         9YwxjLzNwfMwT81SinmrUCQxCsged05IyuX36M0l0uk/SDw8d2ux9mkmD3avCsWmQi4C
         VgSr4bcQpd4NlWjpdFBOjXoW5Uf8tjE/qu03wDfWW3vq4ayx4xblu4XKKtuNYQEicYhG
         WIE9aadSls3qQUBk2y0czwVBT1CzO791NU9kciGtq5tT9E3bFszjF6yo6clPo9SSWzy6
         dKE4h+rg2Z6D3b7AxksH+l5VMSmh7MRF2UcUI/SflhsTXPZgCWiHS38i0TUbJSk6V/Yk
         jnbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=VHjrcGCl;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708550657; x=1709155457; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3O3CuH45HhbrzNI0ENdtqw2+aiYKLlkLaHn+eoc5YwA=;
        b=gueueeJk1hdmxZWXpYikKE9bVBlBQ6bY5dUOu4Kcjl99QkfmdRZQmyEOTI4pyApaaO
         eHX0YZhCnDeYLF7wSVDHJmPhnIS9QEB+2woBWG+Bx0wRORZfvbcw+A6ig1mmkqPucxnh
         nGeUyk9OVrCsXsPTONekjgp/U3XblLJ9cM5jegmhlGJhzw8nUWo0hbVCxXkQSe6xE1AW
         STBbYOe0p2yMNYy7r1eckoWWMc6Dc5/MlDGXVnNB/Lz4EfLSVGU5daBS93UDYUGN+t1H
         747V12kgdKOHM35lkOIVlZHlmbnMOhqfvNqm3iIidra2h+B0r0EEElocXeVFnD+8HlRS
         gHwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708550657; x=1709155457;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3O3CuH45HhbrzNI0ENdtqw2+aiYKLlkLaHn+eoc5YwA=;
        b=j+1QQqHuORRAt8kAdIuHaqVLuEh1McoFUgvOC8umwQ6x1/hCHtZWLq707mtVJdR3z0
         dpKGLi/u2uCvuk3gW8fHtZF+p+ZXpeghCuatO3J5znArtk8tzCSbuBBAxVqXrz/RnKBy
         NSugUr7GhvjzN5dmoMqhoSPq1WexN3RWsUjaVLnF3iIgOZbhm0XU7e+8Pnf6U+aK0/bK
         Yw4WK/cuNxvvPiv54phFi8Jy+3kP5Gm/NLCJav7m/+d8XhrfaCTl1k09KVtYmmLX9T/j
         UcK2smeo/mDPfVM/I8thMdfJAK9RvG3fXtvdvPZspT6DW2MIQjBqqiQ9440U/35zwDep
         i0JQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXTWWXxY+fvp9QUOc+ts/8so7gqfJ7wfoumvHh6CzwXRjwVH/rqQvpVkUJZcdnaGoT+JwMzQMRbMOWb80nvKtsNTFfaTPSypQ==
X-Gm-Message-State: AOJu0YwXI+YGqz3JvmbCaEKzQHvsv1cyaVtrOLEVWsdPvxsWvNGvwFFO
	8bbAuF4XW7NQavsWhd2FVY2LzAV2l6JneEuBcjLHIkZ7qJTFPGZz
X-Google-Smtp-Source: AGHT+IFaKXvD2wBMZCxfzjNblKaYQ7Qa+T6Muqf2Hbv12rtDiE96xvSVUbbPElIjbTyiQntWbSpuXg==
X-Received: by 2002:a17:902:8c85:b0:1d9:b8cf:779 with SMTP id t5-20020a1709028c8500b001d9b8cf0779mr18460701plo.33.1708550657561;
        Wed, 21 Feb 2024 13:24:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ed8c:b0:1d9:f798:d1f6 with SMTP id
 e12-20020a170902ed8c00b001d9f798d1f6ls3481857plj.1.-pod-prod-08-us; Wed, 21
 Feb 2024 13:24:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX/3scfMRAe6P9ybpcTaG5gGZDJqOvxIxF/b2lzNarAbZOp0AH+2HrJqZpDkLpmz0MYwXf2iFCR8HuJNIj3k/0cH+SvWH/9uW2++A==
X-Received: by 2002:a17:902:a507:b0:1db:2ad9:9393 with SMTP id s7-20020a170902a50700b001db2ad99393mr15836305plq.48.1708550656471;
        Wed, 21 Feb 2024 13:24:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708550656; cv=none;
        d=google.com; s=arc-20160816;
        b=Q/XfqpPzTb/ytZqktWZgzyCPamAGjCt/orE0S8NjpFTZdNQgG1WI2uhsQSJDeOXy4J
         Yq3H7RMwtBMP9OlRWdVhkJhboKc7dyWOlYEWMR/OglJlVNG/63Q2K+Ve9yUzL7djKD1b
         AsGnXXWfHqzdPm+2EW0Cn+WmES7vuZOpvmLcmrTh6LZ52t3hFs0zVyUka3PO9eaPXSyc
         mwoTmQAS3PXICDWAwbJssJB0HsfnpwUwktZBBMjqIrwuRhgIEzFOePylyR9PMWVbc4Dp
         YQ7fymRKFaTgjxNHN0E6JELxVloLXHI07V/Rgmj4FIMwDjgHFHmAkO4uqOlZa+xhHm28
         u9TQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=cZXkUcelidv55pcogEZ5q8CQsV5tGZzpTAAvQxpkWOQ=;
        fh=psDvmBmRyaYhtvImTLl5f0EP5CkpIax2o+NLt/LJgWY=;
        b=IIGRRtBqEA7nc/s9u6K65lWvuqRINz74eKstzWSFtbCsFKM7F3fuhTj/EiRP9ZPiM/
         VbuyvgeqTZP+ApXqErrC1Y1+Fc0a4GiawuvVtLyGYD6t2dWvPGn1o5fvWTZXRK7u+cx0
         XHBqOORwtoxwzkDWWuB/LUlLmr2EyKyHFD/V9Oktf6twm8+isTx+0wIz9qmdfcFqNUNX
         ADRPnxKmaf6jrcrCFcfpksLEfdVOWsv843imZmbe5UR3f4L62xlfCeSzrop2Rbjuf9uJ
         lik8xCoXz9oa39dCh2zoG5zrBGruPcpf7GXCa5NGJGjQJADs6h8KzDCUDHFXRLKrjsRH
         EI9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=VHjrcGCl;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
Received: from mail-ot1-x32e.google.com (mail-ot1-x32e.google.com. [2607:f8b0:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id kv5-20020a17090328c500b001db63388676si667771plb.8.2024.02.21.13.24.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 13:24:16 -0800 (PST)
Received-SPF: pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::32e as permitted sender) client-ip=2607:f8b0:4864:20::32e;
Received: by mail-ot1-x32e.google.com with SMTP id 46e09a7af769-6e2ddc5f31eso3120966a34.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 13:24:16 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWqeY1zwjxmc9D4B6k/KE6+TpR+8PYkVMwZqHuUpwWFT9IVw+lch6Gnayv0JwUa51kXpD3FXZRjoX26yAOBVkcH6IRYl8QI5DUUsg==
X-Received: by 2002:a05:6830:1005:b0:6e2:eba0:ec4d with SMTP id
 a5-20020a056830100500b006e2eba0ec4dmr18796951otp.33.1708550655819; Wed, 21
 Feb 2024 13:24:15 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-6-surenb@google.com>
In-Reply-To: <20240221194052.927623-6-surenb@google.com>
From: Pasha Tatashin <pasha.tatashin@soleen.com>
Date: Wed, 21 Feb 2024 16:23:39 -0500
Message-ID: <CA+CK2bAAzRfsDYG+LVvp9LAJLpJoakhTAB3i6JiGDogvz8kfHg@mail.gmail.com>
Subject: Re: [PATCH v4 05/36] fs: Convert alloc_inode_sb() to a macro
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Alexander Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pasha.tatashin@soleen.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601
 header.b=VHjrcGCl;       spf=pass (google.com: domain of pasha.tatashin@soleen.com
 designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
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

On Wed, Feb 21, 2024 at 2:41=E2=80=AFPM Suren Baghdasaryan <surenb@google.c=
om> wrote:
>
> From: Kent Overstreet <kent.overstreet@linux.dev>
>
> We're introducing alloc tagging, which tracks memory allocations by
> callsite. Converting alloc_inode_sb() to a macro means allocations will
> be tracked by its caller, which is a bit more useful.
>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Cc: Alexander Viro <viro@zeniv.linux.org.uk>
> Reviewed-by: Kees Cook <keescook@chromium.org>

Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BCK2bAAzRfsDYG%2BLVvp9LAJLpJoakhTAB3i6JiGDogvz8kfHg%40mail.gm=
ail.com.
