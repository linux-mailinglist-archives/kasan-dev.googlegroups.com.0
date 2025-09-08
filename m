Return-Path: <kasan-dev+bncBDW2JDUY5AORBTPU7TCQMGQE4KHMXTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CE98B49ADF
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 22:19:27 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-336d2a128ecsf23499741fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 13:19:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757362766; cv=pass;
        d=google.com; s=arc-20240605;
        b=OQfcI/nTbgcEJ0CXhFmWFU2Dx1qsS9s/5yCbfitTu7cRlBFd/FVEnrNnL96H4+KA0+
         Juz8UD1VaZo0dRxoTW18Yd8Az/ESXRRCI5j2TWfZqG18o2eLXIUjrdVDv13IRlN7zMrP
         aBMnD393xXIf2wxr7ef2wxU7L+uknIDkMsWgu05AqQrm0BwmjfmgOYmASedPGa4qonOD
         BBIKHDobLkgaPIqAGHEcko8f3fkHADu0WTfHytHvDdEQDGGWl9rEqeXF25vNZtQTjkkx
         g9rIWfsWXDpg2bnGIeCeMXlUpCAMLoEbXsjssOHvuiKz1Jh5YEFhjV7YTmDpmfHP50D/
         yYsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=UtaP37analedctfjBzU468KoH9GF5vIu5jJLmvpvhdo=;
        fh=aaUtTP5n1pvVt+BIHKr1Lp2AVYb1znt7ADksKFLN0LU=;
        b=FVMBE8BoJ5LrGl27/5YGRYThM8N0pMEREu2UjPr19khQU0xLLZ+Da3Q2EXhAOcr0p5
         MRkTLO0wjLLD/VQbq4hSA9v4ZeMxbBSd17PQO1eR/1G1LS3E4IKlahzyTPMeKW46vP6O
         /GUuA8/W9ke9cm6KApWfslASAOVRuHzZepM/ZkV87HV33SoN02AORyp/yLNccN6wUy1R
         7UfIPjPsI4Wvf2/8XVB3XMdCfPprKFBX0tL+iQTu8yBa6VQt+qt4OJGIscRD25LhdPII
         akPYSxcr0xqNC6gvPWPkEwaxZqPwJfJUvipYUC6rQ5YpCjofyrSkfVYGQ5iFMib9rQ6f
         D3FA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P3rb07NV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757362766; x=1757967566; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UtaP37analedctfjBzU468KoH9GF5vIu5jJLmvpvhdo=;
        b=t7E030j3WmqBOJGjX8YrZm3vH6ctwu59d8h8ZjDxxdVlLY8GIWCY1hJBQC/5+jQ0A5
         2or0PAkfGjFszs4GsENwYbiOkbWw9s8Fj1CTXTbBzcU/PbRv+1QJRyED/Gl1ZV47SFkl
         9BuWKEEprfde1VzmKxUAGmURq6F7h0hCTjPaH6v/P/Am54aYS46TtdYylAiRDLnsAimf
         mEzWzoecaSMNGFhiXbl5CtFt2vD1qWsPQHynu2sxKvSGxNkN5VC/3b819s52II5KE+PA
         23gp2TZJjDwgHphzQtfhZjN5fnsxWc5qRqizhQ4j040Q5t2xobJ4iDtQ6s/hjaGPJ7pg
         GI3w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757362766; x=1757967566; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UtaP37analedctfjBzU468KoH9GF5vIu5jJLmvpvhdo=;
        b=Kqrui1/2Ks5liHvlJKC/vOM46NiLrcRkH8kYB9J7K4nMhCxLbOIWiQq4a10uxC1zmK
         aKa+Crn6JunLoV5WFoO0P3V2m8LeIiwf6Q1F4ddCXc9zszn6iEf8xcpJ7TkAvb1jr/U3
         QH7nvY+1tpVL1NB+wqi/zpHmV4CdWZYO0j1WpIaxmlURWyIm6vbIzJ2mHMAWMVnws8RV
         4E2b9zBtWj8fvrDGmxvPA0JUsa+HKZmUAhVjCCkEpDPazppqJzOqj9iy2ivF8Qw2c3sr
         iXSuPExhMIQ54BZIb/De5kj9gnjo0iLbjFjcoe75YFvYqbOMH/xdGSuqNdDti4cb6xnm
         68KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757362766; x=1757967566;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UtaP37analedctfjBzU468KoH9GF5vIu5jJLmvpvhdo=;
        b=SnexUBnwAfEWMURBsORu7TFTrCoZeZo55ElaqPsT2CUPBHmLVmaVyXrmA6h0ETDA3n
         WGjUGzpy9LYc3NR7d9Tfe3YmHJbpSn2qKwIgpVUm5tzD7gW1LwxAVlgiIMeLnMKcLG9l
         WRroe0LdKpDCGmf1a7D4ggPV6r0nVfTwWER6thB/fTEzSFgHm7ihF4Xjfnw6zhekOzEL
         nkrgQMZNVLaz8h0yV3UIADgJFQIhs7PjXtF//Kfx05XPR4j6TcnmV8yh8RY7Do9323Kj
         yEoTW6785kBZwXFMyEi78KaDXAHgq/Xy+hMeaujR9xm9kBayMLHynCsSYguIyXqlb6yv
         /Lpw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXdzay/pwyU5/v1rXI0SciBOLoMP7evu6HNnfDRLZkJVAhqd4dID5+W0UQkkjl2nT07dDVaYA==@lfdr.de
X-Gm-Message-State: AOJu0YyN+5hB6fRQ4ANNUn7fsRoC1AcburhG0As6z1+O3AJDPLUHizVI
	ZK29P0Qppi8u/aYGUf5ExT8pAUXjxBojYOWgkSrX3ZxdsX6hTUWrxDeR
X-Google-Smtp-Source: AGHT+IHVY+/Af8GaVMcasxEHb2E3EoeHJIZTIkYcGQdU3VESCR4ZYCwpNbLxt7U4SXExsDcY7PLRGQ==
X-Received: by 2002:a2e:a590:0:b0:336:718f:75ac with SMTP id 38308e7fff4ca-33b58fa3316mr19506461fa.4.1757362766145;
        Mon, 08 Sep 2025 13:19:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeA25RUErihTYzzujBGyd7C0ZQ4G+dpF2J7IjeYCFLPyw==
Received: by 2002:a2e:a375:0:b0:336:ce07:d3a4 with SMTP id 38308e7fff4ca-338cd204e47ls7043311fa.0.-pod-prod-08-eu;
 Mon, 08 Sep 2025 13:19:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWdeLVkAp2tdrYUz2ClrX5eRfA4sM3IU9+wwGMrzwSWWeExDPKEzXRRVu1A51df48g1zm4/kQJBz9Y=@googlegroups.com
X-Received: by 2002:a2e:a9a5:0:b0:336:be6a:5a72 with SMTP id 38308e7fff4ca-33b6191de10mr21085231fa.45.1757362763151;
        Mon, 08 Sep 2025 13:19:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757362763; cv=none;
        d=google.com; s=arc-20240605;
        b=AgDrJtHsCILzcvp6JrvcbEfM6Gu82+cfFs/v2hioLsIRbFbILldXlp3JeULu74esZz
         vlNydv0Vg/58iQBms9LDATP52HKu+iPlQXRf5QCohdIpKbeOyEcCjHUbe/n3RfvZDIYb
         ZxdE8zwJQ3LwdBPuas9JaKi+Qmnfpzw0L2URSvRSPEyYY3ATS/ULKyJX6p7gMdEJxENJ
         iIhQC+XYJWqhjbvTGnrxlKS38wpJWvMq7j5IUJnjJAmW0R3vyAG69s0BiLE8ea8hYAFV
         r2QyJlj5xFyGjGg43kluh5r8L0/TrvejqB6fyEgKt8YvCLJKCG1UlxQx9MfinZihQi4D
         UPow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wK9/DwHmthANAPoxGvgtMIu4IcfAIwwBdfEzyf7aCYc=;
        fh=XQGHdl0aR52ZDjUwUieYDqE0S087jDg+NeuW5Sdpr+k=;
        b=hEm7DNuY/eUXPzJzPN224LgJsnRXVPL7TvbpsejZK3x7j+NHcci2DXRiMHubv+xP9q
         ZrxK7VyysuC3AQSVjpafujTS7Ch1cxPLqejg/h0N2iM7iH2so7qGg7RH+wwnbJ+Dr9Gm
         YrrV9SpYDmPudzJyXgdx6lRvpgI5QJKTORjCqUGey1uYrXSN1eM+uOTYQyugu1d3xEn9
         +pdI90sxFgrvbO3x4btsQdvYJy2WJgK+MaG8j93gctngEjKe8BZ55k32srH8htqDCxfI
         eywgV3TxrIESPsbK2cFwJMhRcW5I6jDDuLT8OxUjihpxFqr6erFRJNPISjsJsolltT/Y
         5CZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P3rb07NV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-337f4c2e981si3572911fa.2.2025.09.08.13.19.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Sep 2025 13:19:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-45b4d89217aso31453805e9.2
        for <kasan-dev@googlegroups.com>; Mon, 08 Sep 2025 13:19:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUNQL6aR32rb9/l+z0o42bJQ8UJR0mWE4zrzQIISO0CwaUUrB2OUZRV3jS1ELwJsckAZPLy4MGqRIU=@googlegroups.com
X-Gm-Gg: ASbGnctQWZp3EUs7RhKEZPkc5uFDH1VQuNj35Ruj7jex8jqlJMcT1Q8djS8i4q0Z+xQ
	6QaddqMKrBuE209lu8Ou1KrXlyg6Zt6sOTA6c+gVz7sChFvR4YRIloFnpHNauwRAA5DQlEP3wTx
	/WX+ndvyWyLc5Nr305FtdhqQWtOO1BJTgcc3+0MbHTvNhYcs726MyW7nRsAWloa5Ly7kuwSOcYa
	OJHCTBozfH1kCTv9kduaMyNQ9YdUw==
X-Received: by 2002:a05:600c:1c97:b0:45d:e54b:fa0c with SMTP id
 5b1f17b1804b1-45de54bfc44mr65122055e9.17.1757362762024; Mon, 08 Sep 2025
 13:19:22 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <2f8115faaca5f79062542f930320cbfc6981863d.1756151769.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZf1YeWzf38XjkXPjTH3dqSCeZ2_XaK0AGUeG05UuXPAbw@mail.gmail.com> <cfz7zprwfird7gf5fl36zdpmv3lmht2ibcfwkeulqocw3kokpl@u6snlpuqcc5k>
In-Reply-To: <cfz7zprwfird7gf5fl36zdpmv3lmht2ibcfwkeulqocw3kokpl@u6snlpuqcc5k>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 8 Sep 2025 22:19:11 +0200
X-Gm-Features: AS18NWCIvLKT4zY1Ax7hHZz8nFS_pHxT1rFM_aQWd_F5XVIT_8vgGZz-WQhHzM8
Message-ID: <CA+fCnZe52tKCuGUP0LzbAsxqiukOXyLFT4Zc6_c0K1mFCXJ=dQ@mail.gmail.com>
Subject: Re: [PATCH v5 15/19] kasan: x86: Apply multishot to the inline report handler
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com, 
	kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com, 
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com, 
	trintaeoitogc@gmail.com, axelrasmussen@google.com, yuanchu@google.com, 
	joey.gouly@arm.com, samitolvanen@google.com, joel.granados@kernel.org, 
	graf@amazon.com, vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org, 
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com, 
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com, 
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz, kaleshsingh@google.com, 
	justinstitt@google.com, catalin.marinas@arm.com, 
	alexander.shishkin@linux.intel.com, samuel.holland@sifive.com, 
	dave.hansen@linux.intel.com, corbet@lwn.net, xin@zytor.com, 
	dvyukov@google.com, tglx@linutronix.de, scott@os.amperecomputing.com, 
	jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org, 
	lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com, 
	kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org, 
	jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com, mhocko@suse.com, 
	ada.coupriediaz@arm.com, hpa@zytor.com, leitao@debian.org, 
	peterz@infradead.org, wangkefeng.wang@huawei.com, surenb@google.com, 
	ziy@nvidia.com, smostafa@google.com, ryabinin.a.a@gmail.com, 
	ubizjak@gmail.com, jbohac@suse.cz, broonie@kernel.org, 
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com, rppt@kernel.org, 
	pcc@google.com, jan.kiszka@siemens.com, nicolas.schier@linux.dev, 
	will@kernel.org, jhubbard@nvidia.com, bp@alien8.de, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=P3rb07NV;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Sep 8, 2025 at 3:04=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> >> +       if (kasan_multi_shot_enabled())
> >> +               return true;
> >
> >It's odd this this is required on x86 but not on arm64, see my comment
> >on the patch that adds kasan_inline_handler().
> >
>
> I think this is needed if we want to keep the kasan_inline_recover below.
> Because without this patch, kasan_report() will report a mismatch, an the=
n die()
> will be called. So the multishot gets ignored.

But die() should be called only when recovery is disabled. And
recovery should always be enabled.

But maybe this is the problem with when kasan_inline_handler(), see my
comment on the the patch #13.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZe52tKCuGUP0LzbAsxqiukOXyLFT4Zc6_c0K1mFCXJ%3DdQ%40mail.gmail.com.
