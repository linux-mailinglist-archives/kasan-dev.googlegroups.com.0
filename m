Return-Path: <kasan-dev+bncBCS2NBWRUIFBBX6662XAMGQEWGUZXOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id F3751868C9B
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 10:46:08 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-512cbfc32desf2400920e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 01:46:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709027168; cv=pass;
        d=google.com; s=arc-20160816;
        b=ifAWiP9SA1KpRwLOOfX4aOtllm+3Q6OHOJsT/N8x09foH4EyJ8T2/5VM9xbhqcm72l
         SxkuCHqJWN20B8Wt9fDaW2Qgkuy8KJz5dMvEge9AucgAh+rzVPfXUv4OQCrWH6xQKLbe
         JAIXOCiehnsvKxSnMl5c5ZLp7IWEEfvn3WSjqRTKKu2vja9/rIngTwr87Xf6ExY0ImdR
         ZtE1aMeXBew/SuumKdr+KRTGyP5ISX28bNRd397/YGl5eQILzSnDuecp5jSpToCB3HZF
         WSfDMYQpRrHyoYr30ZCzwUL+0FpWEbfRe5jhBtzRsXpC9TPaBf0fCm5/TFNvWqz4CVmP
         tR7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=hZ5PMKR2HqFCQ0mPUExbtMglaI2gnR6bywRZfzhEQIQ=;
        fh=Rw6bqodjD2q9UymeA38kgHQjR/oZSBdKtVDXzuVNek8=;
        b=m7UjObzp/wpRXwB0lgoteG5YRDgbbc9lX53uwjzVKr72YXBVu7yb/cFKREEI8+kcOs
         FYJqJyL67nRPLPFL/psgepMBLDB0kSt5OO2qBqUFo9c1AZrU52LLz1vXqFiNz9JQxOnq
         EMAz7K7w5urF9pGMb1/AKPu/h7EBhO+vsydPsGGZ5o8+pJQ4ftEAO1KWgsBv2IVpRVgu
         hd9ArHoZ4foSsCI4xZDqJjd4JpARNWU/zQT5KtsepXJ0v5hy1CFooR0g8uIYlXXhgMHP
         +rKq49LR2bBhJ5Xb5hWwGNiagFnpmQxHQNSSdoP57lWSVDjzxqn3a2av1Te+rreXAeQA
         /ZCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bnFZzcs8;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.176 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709027168; x=1709631968; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=hZ5PMKR2HqFCQ0mPUExbtMglaI2gnR6bywRZfzhEQIQ=;
        b=Fd9Wr4N0eXo/svp/LSVaVzKdK2oRa/bj8pmUFe2nXO87/S6B7uwhiqfsTK9FhZv0bL
         o+SBA75ItjSODOKF1C5V5B2eEvi1b4O2NSDPAv1jIfGuwXSYisDkaMlvo5ljx/t72oJ2
         /j2AGxk166Nx8nouBnjIfG6oBAcMxo/T+iA4WTelzOQxrHlj1aSk80BYzKvTZKqR1GbH
         iywZD8552jW8o885YbQ0bcxk+KaD5kLCbwzA0u9EefPXhX4m81bA/IjvtumjGWglJp2I
         RJMRzf3KSJtCclwv3IsQHC5WTHHbTP+6a7J8IY/0PMxW/QZQB+4Y+J9PbzGwptHsDuyJ
         uu5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709027168; x=1709631968;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hZ5PMKR2HqFCQ0mPUExbtMglaI2gnR6bywRZfzhEQIQ=;
        b=RyGlMpGhymJTnexxBaku6GQ0ecrJ3KYQ0EKSfA7LhJNUQVkDu9AhqDnaC11yR5KbtC
         3vrBl2WE5bMCXowhHxp8CU02TH8PFAx4hS5BeUYYTpmYbJJlmneAG7ZvduODLaF47wSs
         qyW48+eZk1zAkLZbD6saavhmeivOdS8ASzyZGDXEvtZGXrVQJtoenjYfjINjnhoszx92
         3jNp7E76lOkdW8/XSXEi8u94K2nydIHTF7Ao1DJb02L/rUFCY75MOIiP2khcflYGlF4G
         RBzfxyJB4CFnTUx8GEAs8mxf7IXMTV061wbL2bcSetAZAWvfwUOrEV36rsj5HJGUnRGQ
         on9g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWJEz4XMlFqZBSrPYi0WslceyI07nCERF++5s3v2GbKQsghIF+fW7C6sVyZjfeqaTjxnSiHI5LDi+opg6oFw0jVUgG4NYKIJQ==
X-Gm-Message-State: AOJu0YzPt4i7cguKrc/Rx7DA/t1m8Z2r9PqwJx/Lb//FZ1hSBKm/piCi
	PQD1mVsD7MBfejr/sVhJCUkQhtHFgea92Ju8xdIqpRPLe1ohEWuy
X-Google-Smtp-Source: AGHT+IHQDIgG/rLn+qk/L6StksmOVbZAOLhOAcHb77ay099kQk1XU76vr4Hzezv9DD6zmLWJP1AJ1g==
X-Received: by 2002:ac2:4e04:0:b0:511:7b80:2265 with SMTP id e4-20020ac24e04000000b005117b802265mr3598016lfr.5.1709027168027;
        Tue, 27 Feb 2024 01:46:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f20:b0:512:e01b:d981 with SMTP id
 y32-20020a0565123f2000b00512e01bd981ls1175556lfa.2.-pod-prod-00-eu; Tue, 27
 Feb 2024 01:46:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX6EDGQ3HCjBEON8dLJVR24/aGedr3ufMbUBepE5w8dIgocbQMeTJbQ0Y0S6eKr6uzwbiVsVIxUUC5omfeVveu4LQKHD9TYHlomdw==
X-Received: by 2002:a19:2d55:0:b0:512:ea7e:3430 with SMTP id t21-20020a192d55000000b00512ea7e3430mr3313841lft.25.1709027165927;
        Tue, 27 Feb 2024 01:46:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709027165; cv=none;
        d=google.com; s=arc-20160816;
        b=gvupS7Il0Jb5EFoDlVMxsGsa8J/M4Uz1a3VmDlOZ9Hey64R6GSqvvgFR8Rl3Y25+im
         VGhX/Y/debJURqGhb433bWZW6Jy3eOzDfMYIAVY9KLiGqZpGBvu7FaAHQmUSfx0LeKJO
         B0mMJeufDvv7X4r3yaBN8KViGhFrrO//+m+fOvQLHEWMRRS2UAU6pjQvbGDn3anlOBYY
         yUb9uwvNvr8BfHtBwaSksQ4b5CoOX6Gmiev0u9/Bo+lYuwqmfd6Q4CYjX2R48iIUB2yO
         9AzqGIHt3P2hThWsb3h2djvvZxwK6vJ2osRzvtWiP6Lpk6O1+LBU+dGd01mBmVJB36Ox
         tW2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=9nlWS0taAPbDFSntCaJ2TVsOBW7I3UD2z/xphXUPlTY=;
        fh=UwD/H3ywsdD8tnw4ySuZhMQUkhKuIDpEkmEQBTTD7Ro=;
        b=JRukENn+oSXyR+qkrGqcGDDO7w81LtLiSiuA0jfKfgA5aD+1p84A88lgTU/YymtKkg
         WRsJPgyyXSdHnkHqpvmJPKC3JuK1h3KVs7P1Uk5akI2tAYYzITlLzXUXo8ic0ZTwnq4R
         l2f9ixwbHhKPrlAWQWniUqsxX0gADwWZmtRpTgwN99tI/yJfxTroHPbpZlMi6Hw2ZYBR
         mjhL/gptM7ZfEwPTFvVeh/CSWeq8EOi3phzVkuJdUZTJlYYOce8KJsUzpTltmEu8NSYo
         CiBIkrkk0pAYiLbd/xt/TjrMW2n9yTAMdTKMk4hyhERdVvkZSY8xZkJw7K+uXN5+aQDi
         H9Ig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bnFZzcs8;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.176 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-176.mta0.migadu.com (out-176.mta0.migadu.com. [91.218.175.176])
        by gmr-mx.google.com with ESMTPS id c33-20020a05651223a100b00512f3dd861fsi691lfv.9.2024.02.27.01.46.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Feb 2024 01:46:05 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.176 as permitted sender) client-ip=91.218.175.176;
Date: Tue, 27 Feb 2024 04:45:54 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, 
	mhocko@suse.com, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, 
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, 
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v4 15/36] lib: introduce support for page allocation
 tagging
Message-ID: <z3uitmi57ccg2iifn5nb3pav6skh4zjfvemhuxqdlmwdij3242@wx2lbakzwrxc>
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-16-surenb@google.com>
 <d6141a99-3409-447b-88ac-16c24b0a892e@suse.cz>
 <CAJuCfpGZ6W-vjby=hWd5F3BOCLjdeda2iQx_Tz-HcyjCAsmKVg@mail.gmail.com>
 <72cc5f0b-90cc-48a8-a026-412fa1186acd@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <72cc5f0b-90cc-48a8-a026-412fa1186acd@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=bnFZzcs8;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.176 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Tue, Feb 27, 2024 at 10:30:53AM +0100, Vlastimil Babka wrote:
>=20
>=20
> On 2/26/24 18:11, Suren Baghdasaryan wrote:
> > On Mon, Feb 26, 2024 at 9:07=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz=
> wrote:
> >>
> >> On 2/21/24 20:40, Suren Baghdasaryan wrote:
> >>> Introduce helper functions to easily instrument page allocators by
> >>> storing a pointer to the allocation tag associated with the code that
> >>> allocated the page in a page_ext field.
> >>>
> >>> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> >>> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> >>> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> >>
> >> The static key usage seems fine now. Even if the page_ext overhead is =
still
> >> always paid when compiled in, you mention in the cover letter there's =
a plan
> >> for boot-time toggle later, so
> >=20
> > Yes, I already have a simple patch for that to be included in the next
> > revision: https://github.com/torvalds/linux/commit/7ca367e80232345f471b=
77b3ea71cf82faf50954
>=20
> This opt-out logic would require a distro kernel with allocation
> profiling compiled-in to ship together with something that modifies
> kernel command line to disable it by default, so it's not very
> practical. Could the CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT be
> turned into having 3 possible choices, where one of them would
> initialize mem_profiling_enabled to false?
>=20
> Or, taking a step back, is it going to be a common usecase to pay the
> memory overhead unconditionally, but only enable the profiling later
> during runtime? Also what happens if someone would enable and disable it
> multiple times during one boot? Would the statistics get all skewed
> because some frees would be not accounted while it's disabled?

I already wrote the code for fast lookup from codetag index -> codetag -
i.e. pointer compression - so this is all going away shortly.

It just won't be in the initial pull request because of other
dependencies (it requires my eytzinger code, which I was already lifting
from fs/bcachefs/ for 6.9), but it can still probably make 6.9 in a
second smaller pull.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/z3uitmi57ccg2iifn5nb3pav6skh4zjfvemhuxqdlmwdij3242%40wx2lbakzwrxc=
.
