Return-Path: <kasan-dev+bncBCLL3W4IUEDRBK5V4SRAMGQEOBZBBTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 713EC6FB464
	for <lists+kasan-dev@lfdr.de>; Mon,  8 May 2023 17:52:12 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2ac8393dd5esf19944271fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 May 2023 08:52:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683561131; cv=pass;
        d=google.com; s=arc-20160816;
        b=rjhyIaQVQraR20A7DZ1FlMsRd440vS+5BN8cLPVqjlneIKXdH/bo+at30jYOmdxBRZ
         iBah9DtLnhedu9Y0NGikdOhGxkLZm908WjFGrjmQ29gMz4KW0RvRAlL+782zdgnuD+lx
         mxiMBDkZttS3t2HjyIxT0autqZu4HYWJokVdD5U2PUnedj7kjxdGo+yX3pvm1PP7Ts/0
         SeruaHA1tFVFM31pUSJ2GP5M31yiwerkJ/lQhMkYsSS+0mGW2lDbHDDFwTKOoWga+2Uf
         pz0PKILMO0yCvJbS3KPn1A3Y0BYvStpig66bBunUF1I20aVIt9p1UN+YJozak5UgPMDp
         s9qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=DRE37SCzrMoXFYP77aMu40Eoc4rh/Zx1ndNUgsVSbjQ=;
        b=DYhK/VgNvvSaEwW7l1s+gEjk1u6V6IAa5XyPjoACQfNK8Bv5GhSmCFy7AgJlO69ZV5
         3QUDsQBGfeZpqBT0wxkDeVq5zJ6MhxMFWVTe5F6QYd5Dst8e5oMmkvjK3icjjWzZJmub
         wArTilVvyFgpxJTxnbwLMQN0vIik95PltP/TtaGGmEqt018uOI4HsabKRMXVO8zihIRs
         nt96gg02w1MqiBXM77dXC4sr5ZnmmzBS5He4bxkvZE2LZEjdabciL2/riWfMnOd1i7Gb
         v9UeKxcP30s9fNg99kzk8SdA/Kwk1HjIJrLCA8S3bd4G6+YtrIVNxaINaViB6cI3X4d1
         W+7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=Jzw6i+az;
       spf=pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683561131; x=1686153131;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DRE37SCzrMoXFYP77aMu40Eoc4rh/Zx1ndNUgsVSbjQ=;
        b=Od6bVobmfdzzaHcd/ahbNcbxKw3RMtNslgCJIx7Ao6M84V8udTqAhSfNuXLkrM9Sv6
         y3IsOQ0T1TC3RA0ZUDtx9JlxsbtPzXf38ITJvlFBxqH/AkHhZpkMeuecn9aCw9XiO+N8
         zEEphb8jWaZ/Ga3mdHHJ3aMBQDffNtaiw71RX5Lmn+aTsCoEJVGxdTIZi/80HrmmkRCb
         t73rKBucDpIVkgeA1TfQRw5DxSZUixtIzMFmKD5enLvUydSczcrOPkq0wdq5wELxHwQ5
         jw197b9bmFaxd+lBQ2BEdohTFiXeuuuyQMuEzxwDyLRuSsQqvbpvHjWuZnpTjPNsCFmw
         s1xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683561131; x=1686153131;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DRE37SCzrMoXFYP77aMu40Eoc4rh/Zx1ndNUgsVSbjQ=;
        b=OXdYIJ8ZsyWAmBIqfZNd1HhkQQydoQLXqMW/Uus8r+RaVKOesxgbsKSNz2J5m6pUq0
         D+jeulZyKjrsQplbXPl9vHLxkGXDQ/pC0wQkBhgY0XQ7cF+OzrCPza23TLntpkUuzUU2
         6zhorwKgXpqch1grUtow5O4F1PY/X/TudqGWeDNkSjTLn0O4P6ywqUMJUPuKThgp1ajs
         Jf7XcwUC5ZNwxcy2G84TrnWLJdmraUnChkpLVY9BlWM8j4BsnP22d7B+rQaSdrDMFcVG
         vgbWBNyi045asjzruWs1G/yRsUfKwimjj2tL3oeyoV+svPif2oHcL8nU5an0dTXFrXVL
         w38Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDx9+LKS2MFWwe/nBL4v8TwAJp12Riy6u9c+v/+MMYSLUKezJ02+
	zEEu5HQ85LJMhhjaVxEp/nk=
X-Google-Smtp-Source: ACHHUZ4tR4sqTUaTIc2GqGyf5H11XzdyUlAyQ1iNdkeP6rcVXgArc/FVSaO/8QAAxMBhtJRoXIeSFg==
X-Received: by 2002:ac2:43b8:0:b0:4f0:b01:94d2 with SMTP id t24-20020ac243b8000000b004f00b0194d2mr2539372lfl.4.1683561131541;
        Mon, 08 May 2023 08:52:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8913:0:b0:2ac:6805:ece7 with SMTP id d19-20020a2e8913000000b002ac6805ece7ls3186081lji.6.-pod-prod-gmail;
 Mon, 08 May 2023 08:52:10 -0700 (PDT)
X-Received: by 2002:a2e:9d45:0:b0:2ad:8620:80f3 with SMTP id y5-20020a2e9d45000000b002ad862080f3mr1511033ljj.30.1683561130113;
        Mon, 08 May 2023 08:52:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683561130; cv=none;
        d=google.com; s=arc-20160816;
        b=qlVT5NCVp9796YKcg88qI41JAKqfLTQUfEZvGklCy6pQrPUC4fx6/juEihDIrAwWGO
         kESZfgRx4gUys/8qw1qARg4KbjyAliz+LefMopnu1dpULINHZsq505vRYx1KCOkxOq83
         qfcRWOtPtt4BDER3qp54awMFzkvVJgd/QI5UQ2dbgMxgXnfz3JVePtuSzRGh9bM01qjA
         wBvNE3fiqk1t8U1H564tMaQ5DwhrtN0iM1g/8WaPNvAInHzhThAd5lChclE7tHJBxeAi
         L0/65YJhXFwHjykmqGiK1dLGMduxk0vCX0TzdiodFX55u2wn89MWlsmZ2eVQkWAzddyt
         q4nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=xEgxDWaaWzHtxyJwYN5qDNGo1ASJXO5J79Zx8OXDQ6s=;
        b=YkdIEukMTC9UiPTwcR9lzrmqY/uhRL8vOjpmfLA2kcI9fPSRxERpVQuoy1C93Ckk1S
         EY1xACdI3UptRSPrxN3TxKzBxrzKcJH8VdZGReD9Fwgq3wXvoCFyBmMsH7Xq462GqwJf
         M1CHhLkVaOrYW7otMadZjMGsJVeFFrCY+QJ7maDG5cTc4m5YucmfWOpm6d1CpDdtWhAW
         /2li+CvHyc6oKWbfK2U1JljhnObtK9D1YrPkRddKIvjYj5jGK613QMCHhs+KZS0Qkood
         al4AgwiHFbl7vODYrPIHPEwxBARfKDRpW/+1cgB3SiZU8GrqA5R1DijML4q1F6RrH3B8
         DODQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=Jzw6i+az;
       spf=pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
Received: from bee.tesarici.cz (bee.tesarici.cz. [77.93.223.253])
        by gmr-mx.google.com with ESMTPS id h5-20020a2ebc85000000b002ac885a8f29si454276ljf.3.2023.05.08.08.52.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 May 2023 08:52:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) client-ip=77.93.223.253;
Received: from meshulam.tesarici.cz (dynamic-2a00-1028-83b8-1e7a-4427-cc85-6706-c595.ipv6.o2.cz [IPv6:2a00:1028:83b8:1e7a:4427:cc85:6706:c595])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by bee.tesarici.cz (Postfix) with ESMTPSA id 9C16C1551B1;
	Mon,  8 May 2023 17:52:07 +0200 (CEST)
Date: Mon, 8 May 2023 17:52:06 +0200
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
Message-ID: <20230508175206.7dc3f87c@meshulam.tesarici.cz>
In-Reply-To: <ZFfd99w9vFTftB8D@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
	<ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
	<CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com>
	<ZFN1yswCd9wRgYPR@dhcp22.suse.cz>
	<ZFfd99w9vFTftB8D@moria.home.lan>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.37; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: petr@tesarici.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tesarici.cz header.s=mail header.b=Jzw6i+az;       spf=pass
 (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted
 sender) smtp.mailfrom=petr@tesarici.cz;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=tesarici.cz
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

On Sun, 7 May 2023 13:20:55 -0400
Kent Overstreet <kent.overstreet@linux.dev> wrote:

> On Thu, May 04, 2023 at 11:07:22AM +0200, Michal Hocko wrote:
> > No. I am mostly concerned about the _maintenance_ overhead. For the
> > bare tracking (without profiling and thus stack traces) only those
> > allocations that are directly inlined into the consumer are really
> > of any use. That increases the code impact of the tracing because any
> > relevant allocation location has to go through the micro surgery. 
> > 
> > e.g. is it really interesting to know that there is a likely memory
> > leak in seq_file proper doing and allocation? No as it is the specific
> > implementation using seq_file that is leaking most likely. There are
> > other examples like that See?  
> 
> So this is a rather strange usage of "maintenance overhead" :)
> 
> But it's something we thought of. If we had to plumb around a _RET_IP_
> parameter, or a codetag pointer, it would be a hassle annotating the
> correct callsite.
> 
> Instead, alloc_hooks() wraps a memory allocation function and stashes a
> pointer to a codetag in task_struct for use by the core slub/buddy
> allocator code.
> 
> That means that in your example, to move tracking to a given seq_file
> function, we just:
>  - hook the seq_file function with alloc_hooks

Thank you. That's exactly what I was trying to point out. So you hook
seq_buf_alloc(), just to find out it's called from traverse(), which
is not very helpful either. So, you hook traverse(), which sounds quite
generic. Yes, you're lucky, because it is a static function, and the
identifier is not actually used anywhere else (right now), but each
time you want to hook something, you must make sure it does not
conflict with any other identifier in the kernel...

Petr T

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230508175206.7dc3f87c%40meshulam.tesarici.cz.
