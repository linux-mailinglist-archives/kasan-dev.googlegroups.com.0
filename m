Return-Path: <kasan-dev+bncBCC2HSMW4ECBBJOX3GXAMGQESL5D24I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 82D1F85EAD9
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 22:31:18 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-365208cebf2sf2345925ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 13:31:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708551077; cv=pass;
        d=google.com; s=arc-20160816;
        b=WQ5Xe7uCAm1rqkudu6jaK1uatjLIDesY33bGnhVZXSYM3wSXnFf+Ef7lfP+7m2ywjl
         wqpMI/AuZ5WE3XchMBI8fSjaM/ReOc4IZhUyLrDld5avIk8puJCwWquVPnVzVnv+0v9f
         Z/TncjfSUI/tIMTr5BK5+IGfgmA8wg6k1Slt4Akv9P3FinUX3Bec8ebNUqheaK87vGMV
         Bs8r0YhsjmRO4tgn15jnjyByOksxToMVGiTvZX2l9yBlYHsjlC4lunJe2pFdy3kTJXsy
         cJ82c2jz2XihvuQD91j4W/Zd4avO33i2LPOF4djcKG3KiyVe70Zhy2Jv3U8mBcsqUs/k
         qyRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=3N28SCAp/COW1fk42EIa6NeUdjJcVg36hNt55DvU8/4=;
        fh=/dvJJIt7aWcOgn6NByWBwP2uDYA4FK6pwQQ9fHTtwjc=;
        b=qX7/I1tIlMhBfp3ZamIYqgvFQTxCzwgP//CjAEksAHaOvYTd5wFIu839WpMvEY2lig
         oX3/TLr40Q/Z2bMR50akbDdqSohr2AwK71Dh/62L3sg0HNy5eCtwriPCp58+pmqKEZGm
         j9dJRZFm2X+of0cFMR1+7gtwBx75EyCJ4UDedyVmF95QE13eKceltCwQdbWGarTKGMlI
         NQUd2Vbs3YJF+PX/Nrj+tb3rloComRhsumBZAXqCfgIy6c27bXOi/EmNVJQEXZ6SOsFt
         xObHW1r0/tgKJu1yVG3ot40QluQZ4mGyB+jd+rkJARKkd40vDRR6Cd/34sqawHZ1smnS
         3Cig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=0Y8axHHq;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708551077; x=1709155877; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3N28SCAp/COW1fk42EIa6NeUdjJcVg36hNt55DvU8/4=;
        b=M+IUj3K+nNPZ+hH05EZ+xJuHXyspAPLX36N3ZpitkcMc+tLbKrSiv/PAUxtkvkdMdT
         /p6/JUEReLE8h7euRJEu9b8j0e4znVPip/2hS/PCa8Y7KofMigKPr4OjojERIFnq+oy7
         JFTngQVKD4oRHHX7RkqPDnW2GjK0O5gEmRncajfxOC7kih3kRytBCTPA2+HjG4udxYxL
         J3+QMt37Gh6+E2GKdj+0wM8NrKg7mSUhitMFXsMcCzbNaQMtSh3d0sU2eub8ogzi6uJy
         nk7UYzNdYW746TaF27NNDuh1/acefcmxCRBj1M8SrVE1quoyUjVLx8MBVlf1dmGDgrXQ
         6KYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708551077; x=1709155877;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3N28SCAp/COW1fk42EIa6NeUdjJcVg36hNt55DvU8/4=;
        b=eDmQbD8IX+nO47KgsDCKeBJfIgkdxKuS3uy5otixRxfxqCcluSvkUruA7P+2uLSspo
         rq9y/W6AZJqTKVmL1GxI8WSX+p4fEG26DgQWuvOJ1NXCztstbJh4+MUhoc9Mlu8iifN0
         AxxhpaKnC001cTrobfzskLq//vbfKickTyA6ihygWzwbNFd4OeInyqTezEXJwjeh5bNz
         g8QII4V/kn7eiMghHU7kZWdYnSHE1ZqSgB0oxA8crAEHsMldQGAdRSe2dv5fQl5ZY8Uz
         n9C58rhS/UHm22+Orj+oxB1JnUsaWTv6C6KbILd3CQKm/G+zXqHy+8he+g9kfT3Kr9/j
         DwMQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUwoHHax5RIWmGEtPVn3xkQkHByQo2CnXiJigY231QYlmTkK5BoTVzROW/M3ekNpCrxUB8hhEEzKScRzDvSmyTZgbnSod42vw==
X-Gm-Message-State: AOJu0YyCTWS6huHTewq6TyoW7OPgmA6W9kb+DkWnvRCI9xdZ53MOWdsm
	V663ecJJtE+u27yT7STKXWwKSLqTrpsAlSKKmPbm37uhvk1yOX9i
X-Google-Smtp-Source: AGHT+IH3322NcCS7yIScGBZBaHRszpTnaAwoL4oRtvylM78QsSYkxThEjBFzwDlmSCFrsDgZI6DRSA==
X-Received: by 2002:a92:b703:0:b0:365:1edf:8e2a with SMTP id k3-20020a92b703000000b003651edf8e2amr613492ili.14.1708551077373;
        Wed, 21 Feb 2024 13:31:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:2806:0:b0:364:ff62:9c77 with SMTP id l6-20020a922806000000b00364ff629c77ls2145451ilf.2.-pod-prod-00-us;
 Wed, 21 Feb 2024 13:31:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU1QZPiKm4jGCVEATCS/D++r/zWV4gEIG17qh2dYGpA/v5yfeUOAXnxuYO+J/XJc8EZZWyHQEG/v/AMjCaFHdYDC/PFab0qV6G48g==
X-Received: by 2002:a05:6e02:1b0a:b0:365:102a:ee10 with SMTP id i10-20020a056e021b0a00b00365102aee10mr610550ilv.6.1708551076612;
        Wed, 21 Feb 2024 13:31:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708551076; cv=none;
        d=google.com; s=arc-20160816;
        b=uF6nORhBbA5n0c2DfmDkQATHbN1rNvgX2xcgqJXY2Jwiuoq9cLHOscAYE2Z3lhWtRT
         Kjg/EM7ScN61v/89cDObewApQl0i0wUCyS7/UNWjssOPt3NNwC/Kr1JlahXqfXz2TkG9
         blioy8Sw+QdXKQV8ewgb5UwFoENP7b2ffsXlCltNRPgjtwdV4reB6LfVVE1sEl5ir/SY
         jYDZ8wa1y9AEF5hZyL2dsQUkz6ReKKR8uO9t909cCrQvNu4akJRlAVz52RjTo7F/oNUn
         qmwdbJt+N/mWH7iN6ctCzd1uRaPVbDvaV0oR5pPZIBj0lF3MTAsC2lYbp8n6ZXCzCNqi
         T6sA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gFsioKErNguGb0UXfpCehO3mOIaCj+gYffuxZggc6lc=;
        fh=CP8iFXMJ/zdfZg99FksKx/zIy0gc6cdUblFrzi+IfrA=;
        b=Q/LWiUlHQqG4sCfpK14IacwnPuEAKKvdUZe5scufniz4/yG/Lv6i59MLHcDShfni2e
         vfn8M84EDOxKcwHmcM4tmBfpNRcTYHjTvXM/s9XxmYFp4EMgFudupm6FIpgESEppDxjl
         mK/32WUAGO1M3+7QG/om05HBWvjFdOTduplyVcvX6uHV9/6GiXjEbdNedb7iDQqs8APP
         qC9UFg00ICqk/o4ayYeTUcK7Cj344DpGiBtChvbFNZcWcAY0kpjgRTROoXV4kU+LhZcc
         mo3LIXILZYtd5oY2/dPjepMmhM+QIuPkgxnN0fdZvJKNLGnchedgwCiDso1zd9JEdvN2
         lsig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=0Y8axHHq;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
Received: from mail-qt1-x82d.google.com (mail-qt1-x82d.google.com. [2607:f8b0:4864:20::82d])
        by gmr-mx.google.com with ESMTPS id ep14-20020a0566384e0e00b004742bc24109si353993jab.3.2024.02.21.13.31.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 13:31:16 -0800 (PST)
Received-SPF: pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::82d as permitted sender) client-ip=2607:f8b0:4864:20::82d;
Received: by mail-qt1-x82d.google.com with SMTP id d75a77b69052e-42a4516ec46so2209741cf.0
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 13:31:16 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWSHfQbt9JEzyI0/ZYhEuWE3mGk98bSL1WjmAxptSxXFuWY2bVCLxR7v+7b8FtKgPUXmP8LmB1FSowBsLwEzY4jQMhaXaLoPCij7Q==
X-Received: by 2002:ac8:570f:0:b0:42c:78fd:e4fa with SMTP id
 15-20020ac8570f000000b0042c78fde4famr1316065qtw.32.1708551075946; Wed, 21 Feb
 2024 13:31:15 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-8-surenb@google.com>
In-Reply-To: <20240221194052.927623-8-surenb@google.com>
From: Pasha Tatashin <pasha.tatashin@soleen.com>
Date: Wed, 21 Feb 2024 16:30:39 -0500
Message-ID: <CA+CK2bDOiV8xwig1pDdTVjkO4KhK+jJ0wXAtNon1ZXQGviih4A@mail.gmail.com>
Subject: Re: [PATCH v4 07/36] mm: introduce slabobj_ext to support slab object extensions
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
 header.b=0Y8axHHq;       spf=pass (google.com: domain of pasha.tatashin@soleen.com
 designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
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
> Currently slab pages can store only vectors of obj_cgroup pointers in
> page->memcg_data. Introduce slabobj_ext structure to allow more data
> to be stored for each slab object. Wrap obj_cgroup into slabobj_ext
> to support current functionality while allowing to extend slabobj_ext
> in the future.
>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BCK2bDOiV8xwig1pDdTVjkO4KhK%2BjJ0wXAtNon1ZXQGviih4A%40mail.gm=
ail.com.
