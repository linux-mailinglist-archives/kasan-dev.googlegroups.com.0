Return-Path: <kasan-dev+bncBCC2HSMW4ECBBCND3KXAMGQETXEOAFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6039185EDBE
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 01:12:58 +0100 (CET)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-608084ce3c3sf20879897b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 16:12:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708560777; cv=pass;
        d=google.com; s=arc-20160816;
        b=Oq8riytbpRHhYWFI2yUA/viwxElhhP9WRImcsMe9kVnaa3XxBx81f6n/vyM9KlnxkV
         t/Z2v/WzbJ0IOGqmUgOYqswGLUfgTkP5RR2H1u5P9O1yVUIoQuy4KxON+daxEuLFgHjm
         +ZxO/0HNPj/mDmi6i24iA5clS6bmWVWh24bsAT4r0ANAJQG705OdAx2XIwn7J3x2VHe2
         fWSHp901ZEM9yY6AoVI2boQHmd6UkWwqELsvLg8nVMPgbGZ6TVM7/TeGD1lYCWgj5fsB
         5yKMTpC87Na0eJ8KmptYys2NBtsXUEqnebsl+lVm/+lRPD2368zpL3Kdn5diS0km/mXn
         0uGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=nvMMR4vyc4WsfRkTicye9cvIsPZZrjuEbOEuLBkyYcQ=;
        fh=3TVVSMSpgCA0ofR3YO8kUW6RGJEVzLIgwtKrNlM+ozg=;
        b=AMgHxBAZWVulFlVghNL4nv3xxl5gtSRhp5c2WCKg3fxiljT29LliyWDKAOMgXCOlwj
         lJ5czCZwF+ZDDKwvDabekL5EH/57iF7tv5dqmaqVfJv9suHrt5OIWGhZoT+WSgi94tzL
         3/aKsJ4S5V02/cjGEr2Ql2XDqxWiD2v8p0wYZ/QbxFUsmf+zyXTlQyIP/YLNiPYbK7BP
         AchwiX1KRtM6UZNuC2Qc5swzFZGJnNhgAiuZHx1oVA3rNDgX5Hikom+Em5v/VvrxKc6S
         wmx4nQlO3Vl39jJdOQmfvFIlndmNDRVBbTE5PsLcUcOcK56aGf5MQf/8MpSIoi3lvGoR
         M3nA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b="z0Z1l/Rd";
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708560777; x=1709165577; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nvMMR4vyc4WsfRkTicye9cvIsPZZrjuEbOEuLBkyYcQ=;
        b=fYbPCsgDvouSW5IgwjnZwZGKrzG7ikq1bJSiUa+TyAGfzwCc3kePpVGWryu1CSFKio
         0cjGcpyYR/cZHyjGpD1pcpUR+sY3cHXo8mttW5Xsc4fq+ySg0a1Eu3G5DcRUXMKKWKMa
         irHevssJpt9fywcON2PNYbxAAjo2wulSRtg0soHxGFmmxh4ymxIjjjUn5e7yv0tk9drG
         Mu3KI1caim9yjq+WzVqZUO/yM/TYJUUE6B8bu5ATyITvgJ6HZqBkr7GzwoYfqxdM+srD
         Nkp92wgT4lsHqKBgOizle33lJ0hMoN1JC7HwiKORYtY2HBklkjd2Z/P6CRd9s6kUMtTN
         2p+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708560777; x=1709165577;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=nvMMR4vyc4WsfRkTicye9cvIsPZZrjuEbOEuLBkyYcQ=;
        b=EfI6SLxiJFZh+iVvFwpk8E89xjFJxsRemPNjg/ugbY2uaXaZfvF31oKjx4yfJbEWUP
         dDWQABTgL3HQkGKg9OznzcXlc4KykU4w9SSTfL1SgCiTIkTKcQh4sQjS//dxQeKSMfJ4
         HGUY2FLYwJ0GFRf6YfgX5k307laNWxm6xZuJwtyhJj7Jkq2pbSSi0Rc9d7VNfIJXNzWB
         v57JoI9nc1viDCXP8BsCyUpxlIB9ZZC1zZhAqS7mKxPzmqvUTZa5xOUYe5tAa3M7GBvn
         hImg88WXRSpoWIN6KV3X6ayRlRN6Wzl7yrdhDOGwEDUtV8MnBogWlqaKRHZO7whDqESr
         S2Bg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVCC6W/FePuLZOEXnz/ZbDBdSnBs2KaYKVjwjvDRTyTb6h5LNJ4LNHbcSEMVpxeCGu44NZog3oshUQcYdC7WTNex/8HJVXWTw==
X-Gm-Message-State: AOJu0YywjQQIrV0Drla/vnEWXyNtxOTt9QV+LxA43S28LsEkgRjZBjy8
	ACAYOFLKbkPPAHtI41p703Zq9OpCONU3m2vYOfD5cmLaYHwCcqKL
X-Google-Smtp-Source: AGHT+IHDjt340I1mwo3WOh9X2QM+ofM8CkxFEaIR44CoszNtZa7rm/78k4+2/hqf84lef3oUoqDijg==
X-Received: by 2002:a25:ba4e:0:b0:dc7:4a94:d867 with SMTP id z14-20020a25ba4e000000b00dc74a94d867mr900622ybj.36.1708560777162;
        Wed, 21 Feb 2024 16:12:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d64e:0:b0:dcc:4b24:c0e0 with SMTP id n75-20020a25d64e000000b00dcc4b24c0e0ls2779768ybg.0.-pod-prod-06-us;
 Wed, 21 Feb 2024 16:12:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWHvjuVbMYIoZb4coVYWVQpyvYEcKMISVabgYB3R6H3velGhqE4aHi00yYwvhK8cLCD7v4aZ1AyOsX76y99sRWFBf2kzc99IHPKMw==
X-Received: by 2002:a05:690c:d17:b0:608:4bab:8b06 with SMTP id cn23-20020a05690c0d1700b006084bab8b06mr10072700ywb.45.1708560776121;
        Wed, 21 Feb 2024 16:12:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708560776; cv=none;
        d=google.com; s=arc-20160816;
        b=Cl/22L8qD3bTg+3tcY2Gc+GkwdJsgSGA3R2IGmLtx+ZyP9x9ZowX1hboammtaBKixq
         Fz2vx4JowbmS2lIe7Sg0rNqgXW9oGEOCDguMthzpz+9OoZOlBupT3sqLpdW0JDU7Jtah
         ZuPA1xztwtHq78+swzmgBtL37W/N5COIVzkpGgolnvVYaoAnhsclM8AX1jS1VnIE1A+L
         MtMguFKvdj07JxV1vyCbXLDCPK+50XhehFHgRR8Tr499e59IakfiSjW9QjadhUOCJNtd
         AnNgzdbKOvkrQQUsbO2LOZcoTqLGwd+vPnWYUovRT0FcusWjahRHuo6M/TZRq0lW6I0k
         c61Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=yPsvw9vJzS5OOehh2obqY5C9ccmf1AALBE4na8IWGEE=;
        fh=FHJZmS0vmDJi4vBOrziOl1HogF6URtcFcOHPdtUZ0qg=;
        b=hfBoQybkRwczLrvS+8+MkpmN64lggzqwGDTqYs+PWksDI/JzvV8NoTkCUKwKC5aOCQ
         1Mc8r7KQiuuqDUPhglGMfEym1WfuV2+hKmGomD/F3TdF7Ye1L/InRzPgmQaZxX85zqfJ
         12nE32KBNKY2cnJqGuYwKQlXeJMqOgMoAUd7CZDbvPxKzap+gJyJDWX1VMtafzHH4rXL
         MnhvXATkk3QOXeJ/MdK3vHmbdBDUqQbRXoiuAnYY1s4x41Kycb8wNNdwhdkQrDdzzjn+
         AuaYfKS+vbgx0AounfBD/xspNJ7j9fQGztouifnCi1ueKt8CmnWHPP08CJ9mLGK6nkOk
         BfkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b="z0Z1l/Rd";
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
Received: from mail-qt1-x82d.google.com (mail-qt1-x82d.google.com. [2607:f8b0:4864:20::82d])
        by gmr-mx.google.com with ESMTPS id z64-20020a814c43000000b0060861e9cba2si527492ywa.2.2024.02.21.16.12.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 16:12:56 -0800 (PST)
Received-SPF: pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::82d as permitted sender) client-ip=2607:f8b0:4864:20::82d;
Received: by mail-qt1-x82d.google.com with SMTP id d75a77b69052e-42dc883547fso7014271cf.3
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 16:12:56 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVa+hnEiV88+ZIMttbgCkgmXczE/twxYtPJrcnZtE1Fzm1H1JHobDsfmdYZQtrZo5mBD0qHzLL5k7Nwsa3zDh3zPOCkU5Ui+a1U8Q==
X-Received: by 2002:a05:622a:1996:b0:42e:1911:93fc with SMTP id
 u22-20020a05622a199600b0042e191193fcmr11082250qtc.55.1708560775667; Wed, 21
 Feb 2024 16:12:55 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-11-surenb@google.com>
In-Reply-To: <20240221194052.927623-11-surenb@google.com>
From: Pasha Tatashin <pasha.tatashin@soleen.com>
Date: Wed, 21 Feb 2024 19:12:19 -0500
Message-ID: <CA+CK2bBBcJfgBU-O600Wx-2yHs6RUdhT+n0wsHtieU-rSHn-Ng@mail.gmail.com>
Subject: Re: [PATCH v4 10/36] slab: objext: introduce objext_flags as
 extension to page_memcg_data_flags
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
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pasha.tatashin@soleen.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601
 header.b="z0Z1l/Rd";       spf=pass (google.com: domain of
 pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::82d as permitted
 sender) smtp.mailfrom=pasha.tatashin@soleen.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=soleen.com
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
> Introduce objext_flags to store additional objext flags unrelated to memc=
g.
>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Kees Cook <keescook@chromium.org>

Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BCK2bBBcJfgBU-O600Wx-2yHs6RUdhT%2Bn0wsHtieU-rSHn-Ng%40mail.gm=
ail.com.
