Return-Path: <kasan-dev+bncBCC2HSMW4ECBBQGS3GXAMGQEB6EO3UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F43385E9EF
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 22:21:06 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1dc1db2fb48sf26034605ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 13:21:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708550465; cv=pass;
        d=google.com; s=arc-20160816;
        b=uI4CoZsfZDOru944r5Ji5NB3fUj88DqWFqeU6xVbITnoeTxmK02kG+biwvtaBSnvoA
         6rr4M0RY/NmcvcnHqxfoJkr9znYd/WcWRxcurjtlufb4IzFljlqzFNJBqqEnqJSJpEoQ
         4kglJvVSLau577/D7wkskbW6AjZnhjRmfSuzMafiuR550j5ARg5j2VONBgKpZnqlFo/O
         muzRuCBIEk1856xK7v6V1Awgz2hO+5gH4dYF/+XNUt41xzgyfjUnFvn8I8JG2cgT06O7
         X8vPeZeQlxxzDyObCC79ENYC/QpFpCusgbf/9tTu2qV7LjWvMQQvOyEos3ceAMueraP7
         LbUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=emouO4N8Hjckc7i/FEhNw4pZP8WAglwNKXLMLPXfDYA=;
        fh=ImVtx5689LsyORa4/wcYNCOCeNCCrQQPFEWDmI7o39M=;
        b=pdnNPgrjaTMIkY693LOeCzMQaQZ90rOaw5D0SMQwV9eUVM9KNwXtK47nhSiuFHkShJ
         bhzvYdEi/dRLCy0UAdlW58H4nW+3Tk1Me2Ut0iASeAoUf4zinn/yoHYFZ7z7zTN5fwMM
         JEThPCMkRc0QWwQwtC98D/imie1H7a5x0/mrDedgpHRifvBJUQBDBXJvsk9PI3ynJuIo
         xQCoOh8PG77+9IibrUJg7gjL91EzI7AMHH7ewJqwZrvbXz2f+rul7kRub8E5tZo2GYOJ
         fc7V3T2w1ITeMMqiee4mLN0rwfmS82TWEJZjjjw/qfSbDuhIgawXitGnsCBbMSXh1TSd
         lgFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=uvj6T9J7;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708550465; x=1709155265; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=emouO4N8Hjckc7i/FEhNw4pZP8WAglwNKXLMLPXfDYA=;
        b=fn09TGImyOYr4+nFNcdSZZ0xHfutKy7Q3fvsvldisCCL4u3oy03L9auoBX9w/gahAr
         2WFpd1laUlKcnZy2F7k1KMy2aEyFn+3bFvLl8ZcS+JOtWnU/Ev9pkXvyE8vqvq4WG/6h
         ioGa2qsULHoF4hw/go63iMeVlLzoug//AyJW4uYvMhK/zcmoLqPHhwEKgXdwkt4+x5tz
         5jSdfSbkQdSCHeCgDMzcnSlRc3pP62c/tNhZdKPgBku22Hp8gAG7DyQMt+cRCzNXhbUt
         IBQtsB97/K1MfoMHWguyotm7rjvL1UADfQ+6z0esldQ5Gh5OV+SCQPkut9DeaVZRPxLW
         bmmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708550465; x=1709155265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=emouO4N8Hjckc7i/FEhNw4pZP8WAglwNKXLMLPXfDYA=;
        b=WFcPmMxIhwV/yStZZ3mWLF8wk2nwBY5u00Je7fZX9XDZghX2PKkUcZkUHfwnVgkQGX
         x0sFDMlepwP82uCg8RlfGVf7bl+fsy9TWTLz4u1/W3TBNNhNxCv7a2GjGyki6AjJ6vls
         xUD31whwKfF+jUH321XQ7L9caIPXtrJK28eYdpCN8vH8nSgNPFA6WUK7H4H4So0k0VSm
         G1yvnqFAJc/75BDQHDq/Y/SVVaQeUOGU0gP6VMLF/yEvWzHtnoI6Ku6s4lQ98LFozkEU
         iimB0wds6CcxP7uzOKO+3BNEmvr37hBXcqcdMQCG72Hy2Pe+QgVnodUHEwnXz6eRYRvu
         pXjg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWKBOVKb77ejsif/UoBaBeA8BRc8nCCUnL+AeyADOh0I5AcHgwzUB/XePx/7EtZlNSrDYoA+c1wiaCraepsgkJlUObsNSx63Q==
X-Gm-Message-State: AOJu0YwZ7Zdq4HbQ3PE7thmj34FX1Wg2twOLnugfMPMiHZ8RZKIPfwJU
	Nuq3dz+Ygn/lf96zoa3+60T5zkfYkE69c+9RtvsP3eZtx8X3QkMW
X-Google-Smtp-Source: AGHT+IGUTDXW5JT9ZmFKVRgXE2ENNdTh+kcA9zulkWuMLnhQsJRkwW3gWvND+WVm14BhJLtmMwgOdg==
X-Received: by 2002:a17:902:ce92:b0:1db:f41a:3d9b with SMTP id f18-20020a170902ce9200b001dbf41a3d9bmr13067557plg.22.1708550465142;
        Wed, 21 Feb 2024 13:21:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c18a:b0:1db:600b:52c with SMTP id
 d10-20020a170902c18a00b001db600b052cls1470685pld.0.-pod-prod-08-us; Wed, 21
 Feb 2024 13:21:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXuInfGJO/qMtStN8dmF6IeOlfWS2ucgCq1hMwtbj4D/kdbmpiGwz8medX9Djt0zN4vPZhDSk6ned76g1VpRueF0LLu8Yz8sOWDeA==
X-Received: by 2002:a17:902:7843:b0:1da:2a91:8c08 with SMTP id e3-20020a170902784300b001da2a918c08mr18769414pln.3.1708550463311;
        Wed, 21 Feb 2024 13:21:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708550463; cv=none;
        d=google.com; s=arc-20160816;
        b=Ep8+/qO0V6rQVfbC7HNr+O8sxSFfjLsTnGsZEP9Aytje2HGv03iI+BRouZdvi8VK/b
         OgD7iiM21JCNIflzwoNSRz2d0Wn2NjOQ80LG5AmsfpKyZOUyqy4aLUEpAXN1DOqnJ+Fr
         0xJVO1f00nNeYPMQMAFSD0pFRPl/IHke+dkYzHQBKNSzYDGWN5WuVmzibNLJSeHJx2Ne
         6XYONJE5JWpiCxCMhtjGnfN3neda0sixC2VTlbdj2gUkdcQQoIyMP3s0NSJUoOWymfqd
         B0HUJgmrNY2ztaUb2JG83VpIx3mCIJ/t/QqWXIC3sE4TIeSo2YlC58LgPLN0Fw243lGq
         tI9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=JFD4yQzqaLEAi4PA03QBYwNo3rIHnJT2RUQoKF+C/Mg=;
        fh=ht3H1eZH43d6+Zw6GjWTRenpNp+ud2DGfL0Vt+ARml4=;
        b=xnlFmUz+XEMWYQC3SD1CiXa81LBpE5r+bQ0oNg6gqsrod3nKcYaW24SXIeOEV+AVyd
         0VYRlX2tvPWoHXJqLkrzt4PLVF98H83fAeG6tuCu1qmd91Ct0VBigDSvxTJlaaiE7Rji
         LXUeTw6yqYI3uer4Z0HzmwAa/BkmR5Tw0fmYo8fpyNO3bif2ycrnsdZmCblxM+rAK/fq
         E5gX8yA3kWi+fXernADFnXVd0DShl18vgnfrxZhsl0VaUP1SySETx23G10lRuZrUdvRG
         kfLLMB03s+e7PyMCIo4Z6bKmw8fygSq7Zi3mt5SFhEkZ2EvIbbyo33bAgQMDjdSF99+n
         91vw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=uvj6T9J7;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id s18-20020a170903215200b001d4b701bb69si646136ple.1.2024.02.21.13.21.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 13:21:03 -0800 (PST)
Received-SPF: pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id d75a77b69052e-42a0ba5098bso40436181cf.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 13:21:03 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX5Gwe4Ub5DxY9qSUWE2llq8BPI4q+DmiQYD0Yq7b2BKkkctJ/7FGVCdpZBfYJ/VHqM/sB776Re5w+r8lZeUxJJCXX2ISMuT1x8uw==
X-Received: by 2002:ac8:5981:0:b0:42e:17d9:f8bd with SMTP id
 e1-20020ac85981000000b0042e17d9f8bdmr9654015qte.24.1708550462298; Wed, 21 Feb
 2024 13:21:02 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-5-surenb@google.com>
In-Reply-To: <20240221194052.927623-5-surenb@google.com>
From: Pasha Tatashin <pasha.tatashin@soleen.com>
Date: Wed, 21 Feb 2024 16:20:26 -0500
Message-ID: <CA+CK2bBqUV-mTOYSuDCBaMjy+HyEs+=YnY9Ay9iQ45mStSn47w@mail.gmail.com>
Subject: Re: [PATCH v4 04/36] scripts/kallysms: Always include __start and
 __stop symbols
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
 header.b=uvj6T9J7;       spf=pass (google.com: domain of pasha.tatashin@soleen.com
 designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
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
> These symbols are used to denote section boundaries: by always including
> them we can unify loading sections from modules with loading built-in
> sections, which leads to some significant cleanup.
>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Kees Cook <keescook@chromium.org>

Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BCK2bBqUV-mTOYSuDCBaMjy%2BHyEs%2B%3DYnY9Ay9iQ45mStSn47w%40mai=
l.gmail.com.
