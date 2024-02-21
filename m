Return-Path: <kasan-dev+bncBCC2HSMW4ECBB46U3GXAMGQEFJVQGYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 10DF285EA57
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 22:26:13 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-290a26e6482sf5228985a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 13:26:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708550771; cv=pass;
        d=google.com; s=arc-20160816;
        b=Aj3GJJexPWo8IisqZy+j6piflcera9ZkoFqVePs4VGfTwVl7GIEPGZsGLH+vo3f3Yw
         UxGokh2o0UfZCI+QhhR5USOuDTVZHBFVjLcKnhm4wGYCTisjoar7Hb8ZavrVPZnayS+2
         SBfeYm76dFH5mdRPtf6T+ktZqibdCQ2DddtW/SClka+PFFaRYEMnUAm0nvNc/T92X26G
         khw9nYMIQq0wb/RxGjjPST5GVsscBwXyRYkgatjJmbyf/oR0FB18xdXjWD6K3mmSQ7iz
         AKaseqeo5EmSptdwmdZDo61Vlnv2H7D5xmGfTjYRMNqLZgmV3nD4+3nS+LxrIje0ZpsI
         dYLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=pr+LvBV8Xzev9FzJFsATdftp/hFKRkTD0w9wVMFmtMI=;
        fh=YGnx/aP4cJIdPNfVDxR6KNbbZaqgYLdtYUnhul6MbWk=;
        b=0iKQqz9xYQLhNMV97Ud51mCLjMOizfSqg5BM37S6lcAUK1WkU73zDwXiqAlTmfD8u9
         mShsHcnxO22YeVjJwOOv6QOG3s9m5D4pat6d7YtxJ6shVhUz410jmfki2QW5lakGEnvc
         pqemBnbeS1t5tSojsFmVWPzLMR3Za9HhF0E0RLBSctlJqK0gpdCEIQBNYz5FKxqSBFc6
         THA/3akjsYDKMQcOhVpwRO62+RkqsuOK08OtWESIEIHcWie23NgkyIi2z/v296rEnhb5
         M0B7HHzzX9jHWYo22wq4TCrhuXX1O1/UDQQ2C3J6Seufu9F71ShYe4ND12LA2xILyzwH
         X5dA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=pUvYWAEP;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708550771; x=1709155571; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pr+LvBV8Xzev9FzJFsATdftp/hFKRkTD0w9wVMFmtMI=;
        b=ezFIZmVIIeoCthb8bKiDHuch8WQuzhq6IgIm+Ju64SJiRwxwRsLTIlnq8K9Fi7Zu+M
         VQq6qjVJ0ryfNWXAseqrewHE1s7H8lflb5qQmYeqc6WfuKk12Bd7B4Fz4mBag/2JD0BW
         xMOID//Ltpxk0UKvykIgQV8alPtdYjcVek5DTWGA/P1ZjP7sQlqMsv8oFahoirmwjrOe
         26sZi4WW7A2Pa9S78GvrwuQnRwh8eFtKCTiT293YykA1wMo497jlPWZZb7NWUGHqkFlN
         A31eTY33Bc7BHJ+gx3Zte1nl+MWKU8eGfUJwINtmHXUkXEgBoTgCfTnHXD8z1VqBYViF
         LcWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708550771; x=1709155571;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pr+LvBV8Xzev9FzJFsATdftp/hFKRkTD0w9wVMFmtMI=;
        b=IoW4hicdg3zSP0pPUeWz7UAcb8mLDVvPJJlL2zyze5wUTNfILjRT/mVdzCpQpGmvbU
         t4t+ZzSMjBSXIF/B2mHJC9/8vSyX6Endf0VOx7ch2oi47+OhwzbuixBcdJcKJ/WP26DL
         ktmrYV98mahPMyxEZeUKhoWi1T+um+5q9IUpHHSiYGSksqcj0y2TG1jTVg26B9zTJRpr
         ibuV2T+QsHHIFPxVjL0MLhe2O0OJHXcB6XdkgFuOX303FQffrCw2raa6MM71iR/H1JLp
         G/6/3nnJclHSdtKXtHcFGzqRd+78g+0f97CQ8LHQS7yuzRN2bo8SkTp17U08BC6ZluCx
         6rqg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW+ximQ+zrY7O79ctaZheYQjwjIm6LQKVDlOUFex41fJKln3qekTFZzHlLSgLm2p3JT/dfE9gPX+7YT1eLGZ0Qb4owBQ6FGdw==
X-Gm-Message-State: AOJu0YzbTAiKEvsbSZXl+lznrbhUlNaaCkg/pDCUEGqO+9Gzh1QEHpR+
	fSJ+p7HF6N+wRukO9MqUmpkItQNJQZ3BpkdNvREapi56I+2eBxLk
X-Google-Smtp-Source: AGHT+IEo2GpPm8Az1mZPX6vgJ1KFarAD2sDah+K460dm9Dhcnit7HnU7z5b9Kiy6M43dvSGx14014A==
X-Received: by 2002:a17:90b:98:b0:29a:2a63:604b with SMTP id bb24-20020a17090b009800b0029a2a63604bmr1899459pjb.3.1708550771591;
        Wed, 21 Feb 2024 13:26:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3d12:b0:298:d44d:198f with SMTP id
 pt18-20020a17090b3d1200b00298d44d198fls432357pjb.0.-pod-prod-03-us; Wed, 21
 Feb 2024 13:26:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVXwgtMl8nJUth4OSGTac63F1sQ3HPhUayOJcpOh3ykDHFYvWYa2pNLDeJ7+irJ4+qPG7GPPKaLDsUV1tRQpIbHw8X/Xrv2P7XR5Q==
X-Received: by 2002:a17:90b:3104:b0:299:4a62:548a with SMTP id gc4-20020a17090b310400b002994a62548amr14286828pjb.34.1708550770569;
        Wed, 21 Feb 2024 13:26:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708550770; cv=none;
        d=google.com; s=arc-20160816;
        b=nwQ1j0Z8Y5oseijoczKyr8tf4UO9YZPf7ejeyc8yVrYInNEe3xG55UGII0e/unyUJ3
         9DwovWjvWLyD1MOB6MhxGXl37q0Bvvt7SVqgMmHmj3zCpHTksm/9Y4+63CzBywHRkXL1
         xE7EPjFnKPdeOd+8IqGLv1e+Qe44hS+/AKSpgLqchxB9zCVH+WuQ/t49QqgFeJOr8x9/
         qg+EtB6w6vKo+htymn/BXn7r5Fx8oPdUcUBhW0627CPdNY4c5OsORmuxgZl58MxztYmU
         +kQKc1Sskh6Aj01HOaLco50LBbdj4BnMs/z5xqQEyJwim+zG/JWIBr+hhxodCG/Hj5iy
         5xzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1oEaHzezRAll9SQ0JkGYVz7chMh/UI28PlbGaomS6oA=;
        fh=hYUQ0Q06gLROXUInDBSnu4LIIIlHiPSYpc5YbOgceaE=;
        b=R1GWsgGKs3h0A5iwqvE0HbfNUwziTt0GMF3QcHJW2WF6QSgqOBkFA9El6/OpQ8+c4f
         rcyXY+TmJdVOvIReKq8M6icDKpiamZQFeVxKp30CbHVQ/6Vs5bZN8BxoH2Ahpf6H0Ruk
         JGlgoqnjG7rHVHwos6M02XF9ikQy6vaT+SlUJyti9qCY6DI+iKJt7zr/wMBJEujhJXSk
         VtVPk5YXUYbRYvNppJFQToCV6uLgNcf5RsQT2wVfQF0Ocx1je60fLYaXgqRrzBOxsZTh
         +crBRciDEnBw3keSv8s6Zb3P0fMuw79toDU7fC+JElsE2Fwe11wBJYq6p/p3kBPQXlSb
         z1Vw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=pUvYWAEP;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
Received: from mail-oi1-x235.google.com (mail-oi1-x235.google.com. [2607:f8b0:4864:20::235])
        by gmr-mx.google.com with ESMTPS id y1-20020a17090ad70100b0029a3c01e471si53604pju.3.2024.02.21.13.26.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 13:26:10 -0800 (PST)
Received-SPF: pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::235 as permitted sender) client-ip=2607:f8b0:4864:20::235;
Received: by mail-oi1-x235.google.com with SMTP id 5614622812f47-3c049ccb623so4727147b6e.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 13:26:10 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW85TSujTG/GPQgDqnQCAssWPwudn0MINPYX6uz98RjOAOQ9hVMPmBNO7ngklmlGq+r3BskHdyHh257wLkQ3q0hAGe1I6JVv+zanA==
X-Received: by 2002:a05:6808:1208:b0:3c0:3d12:2002 with SMTP id
 a8-20020a056808120800b003c03d122002mr24802049oil.13.1708550769929; Wed, 21
 Feb 2024 13:26:09 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-7-surenb@google.com>
In-Reply-To: <20240221194052.927623-7-surenb@google.com>
From: Pasha Tatashin <pasha.tatashin@soleen.com>
Date: Wed, 21 Feb 2024 16:25:33 -0500
Message-ID: <CA+CK2bDX7v8+NHi2ioxQ4KF+vBYA0JhR3=Sj6ZxBS0jD7i2Gmw@mail.gmail.com>
Subject: Re: [PATCH v4 06/36] mm: enumerate all gfp flags
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
	cgroups@vger.kernel.org, =?UTF-8?B?UGV0ciBUZXNhxZnDrWs=?= <petr@tesarici.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pasha.tatashin@soleen.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601
 header.b=pUvYWAEP;       spf=pass (google.com: domain of pasha.tatashin@soleen.com
 designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
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
> Introduce GFP bits enumeration to let compiler track the number of used
> bits (which depends on the config options) instead of hardcoding them.
> That simplifies __GFP_BITS_SHIFT calculation.
>
> Suggested-by: Petr Tesa=C5=99=C3=ADk <petr@tesarici.cz>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Kees Cook <keescook@chromium.org>

Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BCK2bDX7v8%2BNHi2ioxQ4KF%2BvBYA0JhR3%3DSj6ZxBS0jD7i2Gmw%40mai=
l.gmail.com.
