Return-Path: <kasan-dev+bncBDXK3J6D5EHRBBNTUHCAMGQEWLNKFOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id E697DB14785
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 07:17:59 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-764072aca31sf4865315b3a.2
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 22:17:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753766278; cv=pass;
        d=google.com; s=arc-20240605;
        b=PBo/FvD66hDnFfp4oeQ8JofZoEIeMu5aymnfHnZEgAUQcJRexrSU8COM3se2ASgAgY
         nEic/om8jduiwroxAM0F/65fuVdsnPqy6y0PTkTwFh9+8+rwXJ/FUxRQmguZBxYJ4kqI
         bADV18sKbxOzQoHcIOkkUjCZjwfh+BlZpY9MsXbGwAHMauiRk2AAh8QI1iBZxrenNsrz
         7E7WxXRCBKwj1VVyNUYaHaD8zkPExzBsmTcRlQWic7a0WRXeJ1P3V9J7gGFBz+Ar1MUQ
         6wAoGQGlhTkE1bskAXed6+3FDgckXrjQNKYPLsHqQkIs0Lu6ydve+CeLqv/V4JKa7P8p
         1Gzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=MD48rpikxwcdTGQJ8iEQBt4OzD5EXmp98BxpGAYqrag=;
        fh=HyaL1FGCmQSNsKEMqGUVfguoosTANL89l5s76E1vgYI=;
        b=eEGvXVXKjI0gC39V0S7Inp8bHJUxCn0e6yaLHeQ+TxtBWcvYYjgI6xbz5TsokM969N
         I8ZxxyUZdoTVLDygz4xOwlPirdgjnGTB+E7NVA1wYDG0KKc6Q/0bjuDk1NCEAZ21tOzN
         OyQIs3o2m6jGVE+EqJVK9jmyo+/wbKKXNgnfFzwtLUNd3e8w0Jq7i2XbtFJDqOHoP/af
         Iiz6c0b3b0LpMhtSvbe8RNT1c/GOK049Tw+EY00xr+pMIlVSO8Fd/gxOYszJnad4cl/f
         ikG+WUuOpNPG5MknDRHXOQZfzfYN8gDb/Oumkan3XMqaySpHsvZGvVm0XuvB1GbWYimP
         nF9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gBIHnq81;
       spf=pass (google.com: domain of jogidishank503@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=jogidishank503@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753766278; x=1754371078; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MD48rpikxwcdTGQJ8iEQBt4OzD5EXmp98BxpGAYqrag=;
        b=sdAQckF/B+44kfaFelmibcCztLGjwfAvXzOBpDYmJEIkohmXfboNmrS/lJ+beCrgV2
         jqSR3IVAcBLydZ7wqhccGyiM3ajmo6upc7wBUBJyZ+YjhudidT9fJlv7yejabDHTEdTM
         EYRoVl381zLDZK46IKXOe0yTFQzVTRDVxo2FVQ0Sb9B0z5M97vBH6hwZ389/DL2wmeB2
         gcYYExVVAwaQoEIqh4Va6Re65fnnciSACxymZcNN5NxNJVo38OgRfaItZ2qOXam31DhG
         3ZnpBJwZv8Vc3TQ9HtlsBLhE6t4e2T4ii5kuVw+qCJBkfy1dh/ejA25FXhPpB4oKLZXm
         4vig==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1753766278; x=1754371078; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=MD48rpikxwcdTGQJ8iEQBt4OzD5EXmp98BxpGAYqrag=;
        b=Bluks08LlwjXj/dJ+d/SyFwbvf9AnZ88rDJeYDfTT8X8EfeE23gd2tLsvFanbQ/dsU
         zRT2wZT7hNiaalvYMct++a3XNgbkMdv8oaZimHjVAcSD34fSJi4mom6iPmkRCDKarAez
         YnPrKVF5zQ1+pUi2eJZnIZM1JBFIXyn64FRwnPlur+LCNBdNbSisp9UKuGO6WfloWsIN
         lA1KcsCvWykLkY9rnyx53nKmLQZN4Jtbc290uCsrf1CLMtzy3IRtl5XFrqT+YF+th+RR
         lriVhujIHSt60Hs8Gl9jfODv/288HqMIwzRIYmpVwILyBaXM0UN9ovhWMS/ulr3zjUxc
         VZ+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753766278; x=1754371078;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MD48rpikxwcdTGQJ8iEQBt4OzD5EXmp98BxpGAYqrag=;
        b=etKWA3f2ync/QbLVcXkasXqPht/cWlmJ2TbtGxNoBIPyViIvgAcmGPySrKZamNGpRg
         WLlImM+Fx8vXITRfeHo6maSkAF/pLM7h4Ps+UYRn7oxzHCY0HQTZ6+xaKxj2q76tCCao
         izyKQCPWWI8CNNhkAahuagaXXk1gwrbs6nVbhIzgR3YfhkoNrceIe6JUtzzHc/QEPYpw
         GYVmv9h+U6GAqy30HrAgET43Fxl9vw4vc2CIU3PSxyeeOyo4Ag53a4k1y+2l7a7cmd8E
         risVyxL1ma7K4Lr9ypRPo6Z1c1okJsqrkcoBqccV4+p36HTkcqarV+M68VoFePh05nrk
         dA/A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXUVG7WH0WOcOmlpLnCbpBWoA0gNb+diFMu9Vc0G2hwngcl0I0nsLmmxGK9yvfwjJaoJ3BMQA==@lfdr.de
X-Gm-Message-State: AOJu0YymSLYi8hCIcIIhYKZ2EMMDHj8NPN18njFL//g2DRlnFindDSPV
	qlohF0E5N97kEVrgYDb863w1rjov28C5Wyqr4T0OHOSsu/o6tfJPtRwn
X-Google-Smtp-Source: AGHT+IERm4IpOzULsxayPv59BAXEjVRTS5SLBil+vbFtcrputEjvWOwR2IFtVG8AgSS0Fk6y+fcBaw==
X-Received: by 2002:a05:6a00:428b:b0:769:93fb:210a with SMTP id d2e1a72fcca58-76993fb26e9mr2320155b3a.21.1753766277849;
        Mon, 28 Jul 2025 22:17:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeM2g63o52/6Rd53DyR7OO3E3yaH3FCVyyjvyKJjoD7lg==
Received: by 2002:a05:6a00:3e02:b0:736:b8d0:3d3d with SMTP id
 d2e1a72fcca58-76163064b77ls6313032b3a.2.-pod-prod-08-us; Mon, 28 Jul 2025
 22:17:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWbvxofUrh4vkYKMEe3SYQEL8Z4LwbgVz09OlGgeNlGM36Eu9/1CyflD2/HoLqlwBqPInB5OU9tDnQ=@googlegroups.com
X-Received: by 2002:a05:6a00:cc2:b0:736:a8db:93b4 with SMTP id d2e1a72fcca58-763356297b8mr19181731b3a.2.1753766276173;
        Mon, 28 Jul 2025 22:17:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753766276; cv=none;
        d=google.com; s=arc-20240605;
        b=Ffw/1+fSb8cJNBCjigX/4tIQa/g9SNXBUlh3c0auRtTrvvIggSe59KzE7z4zyxMz7E
         xFgigDS/EinHDtLuXRD0iKJNJBQqHgNujHY9BeisfZlByHokyl2iiBmgHRiqSkKk0QoZ
         2ZuaL8wgFSrnjIUNmUSOWVgskBflbsSqRFefDEVGpqraHQiavEafLgOoAfQYWDPYz01o
         MSVhfPxK2ZUdIugBKYZw67zcW3U7S9/xgSZ6NVnxw3Z9N/ab3mPLDcG3E6QdiAbV3Ar/
         9Bwf11vc4Ixx3yNrpZB15bbFzftUpcC4SAicdXU2vWyqtQN+YQ89RT9Zoosea9qOHGVv
         BEEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UWn8kN4Zswuo3r3NmW934i71f3n23BKXr6ubPDUeJDo=;
        fh=9GFlTNLxbkqpnGbkBsScNT44NG66aG3eZlPJn+Nw0oc=;
        b=ZTDSMIMX7kpnR1zkzxUotjrYFokCraDWY5xRKekG5ERpEVYUxk52HhJoL45AMduhOO
         3NfNep25mftbRXk/efqK+tK3Me1k149tlSVUlmTMFR2g8/S9GWbylmHt7Wr8XcnfoVxa
         QjFfdMWNVFMPib08bNyPv1hap8T1D+UIAEO/911BfJuVfODMYdk+uGh046h+Cw3lW7WV
         vkuFFTLlsBjVvlnoo5uk+t/dIh8SJgVLAYd8gbd4NNLB0Xtupm1PlT7Y3aKT35AQu4kR
         CY5xUiSMJaqNCd+wAfeWxk11knxzVzyRmSoub8dQjLdFneU6pyp7u9gDU2aqFyiZOi2B
         wxmA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gBIHnq81;
       spf=pass (google.com: domain of jogidishank503@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=jogidishank503@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102d.google.com (mail-pj1-x102d.google.com. [2607:f8b0:4864:20::102d])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-764060149dasi331785b3a.0.2025.07.28.22.17.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 22:17:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of jogidishank503@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) client-ip=2607:f8b0:4864:20::102d;
Received: by mail-pj1-x102d.google.com with SMTP id 98e67ed59e1d1-315f6b20cf9so5576962a91.2
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 22:17:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU2ao4b3ZflY5GeL6fIstIGQ7cBULzoIAefkblo/JdK7WZei6qOgKH/0Dss8HzYfOFyfd7JY8xG49k=@googlegroups.com
X-Gm-Gg: ASbGncsAox0CoBb0uAkWaWODDMg52FEkfP+6rzcMvwjtE1KDSBuYMM7iNZ1zkDZmssS
	B5/GVjT36ubJg1+zT+R62VtedcLoBlVurHZR3UtCCK15oLrdIe/TjtZO8g1WQaM3m6M7O6RgBRN
	u4+n/s/FD1Fu3TubXqbpjzi9ROQ1V61IE1dQPek311tBwZX5K99AmgO4rTpwecM0TeS3k3nqKMa
	IKwDy6xQ6Cm0QcZDDSUvYd+CBRGuzG63d99ZNvT
X-Received: by 2002:a17:90b:5623:b0:311:c1ec:7d12 with SMTP id
 98e67ed59e1d1-31e77afe58fmr19429769a91.23.1753766275330; Mon, 28 Jul 2025
 22:17:55 -0700 (PDT)
MIME-Version: 1.0
References: <20250728104327.48469-1-jogidishank503@gmail.com> <202507290502.vaOga5pZ-lkp@intel.com>
In-Reply-To: <202507290502.vaOga5pZ-lkp@intel.com>
From: Jogi Dishank <jogidishank503@gmail.com>
Date: Tue, 29 Jul 2025 10:47:45 +0530
X-Gm-Features: Ac12FXzuOlVn_e5uHuOChCKXIpMYTtiVdEcNzTbMzngjtcgM8K1QtQdZI6n47W0
Message-ID: <CADorM-_PZd-_2g9EWy4V4RCLS7xp9MOZs0k5GNrbB7FOwSB+tA@mail.gmail.com>
Subject: Re: [PATCH] kcsan: clean up redundant empty macro arguments in atomic ops.
To: kernel test robot <lkp@intel.com>
Cc: elver@google.com, oe-kbuild-all@lists.linux.dev, dvyukov@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	rathod.darshan.0896@gmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jogidishank503@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gBIHnq81;       spf=pass
 (google.com: domain of jogidishank503@gmail.com designates
 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=jogidishank503@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Hello,

Please disregard this patch. I would like to formally withdraw this patch

Sorry for the noise.

Thanks.
Dishank Jogi

On Tue, 29 Jul 2025 at 03:14, kernel test robot <lkp@intel.com> wrote:
>
> Hi Dishank,
>
> kernel test robot noticed the following build errors:
>
> [auto build test ERROR on linus/master]
> [also build test ERROR on v6.16 next-20250728]
> [If your patch is applied to the wrong git tree, kindly drop us a note.
> And when submitting patch, we suggest to use '--base' as documented in
> https://git-scm.com/docs/git-format-patch#_base_tree_information]
>
> url:    https://github.com/intel-lab-lkp/linux/commits/Dishank-Jogi/kcsan-clean-up-redundant-empty-macro-arguments-in-atomic-ops/20250728-184659
> base:   linus/master
> patch link:    https://lore.kernel.org/r/20250728104327.48469-1-jogidishank503%40gmail.com
> patch subject: [PATCH] kcsan: clean up redundant empty macro arguments in atomic ops.
> config: x86_64-buildonly-randconfig-002-20250729 (https://download.01.org/0day-ci/archive/20250729/202507290502.vaOga5pZ-lkp@intel.com/config)
> compiler: gcc-12 (Debian 12.2.0-14+deb12u1) 12.2.0
> reproduce (this is a W=1 build): (https://download.01.org/0day-ci/archive/20250729/202507290502.vaOga5pZ-lkp@intel.com/reproduce)
>
> If you fix the issue in a separate patch/commit (i.e. not just a new version of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <lkp@intel.com>
> | Closes: https://lore.kernel.org/oe-kbuild-all/202507290502.vaOga5pZ-lkp@intel.com/
>
> All errors (new ones prefixed by >>):
>
> >> kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1260:9: warning: data definition has no type or storage class
>     1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~
> >> kernel/kcsan/core.c:1260:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~
> >> kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1261:9: warning: data definition has no type or storage class
>     1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1261:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~
> >> kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1262:9: warning: data definition has no type or storage class
>     1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1262:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~
> >> kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1263:9: warning: data definition has no type or storage class
>     1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1263:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~
> >> kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1264:9: warning: data definition has no type or storage class
>     1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1264:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~
> >> kernel/kcsan/core.c:1270:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1265:9: warning: data definition has no type or storage class
>     1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1265:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1270:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1270 | DEFINE_TSAN_ATOMIC_OPS(8);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1260:9: warning: data definition has no type or storage class
>     1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~
> >> kernel/kcsan/core.c:1260:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1261:9: warning: data definition has no type or storage class
>     1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1261:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1262:9: warning: data definition has no type or storage class
>     1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1262:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1263:9: warning: data definition has no type or storage class
>     1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1263:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1264:9: warning: data definition has no type or storage class
>     1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1264:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1265:9: warning: data definition has no type or storage class
>     1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1265:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1271:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1271 | DEFINE_TSAN_ATOMIC_OPS(16);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1260:9: warning: data definition has no type or storage class
>     1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~
> >> kernel/kcsan/core.c:1260:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1261:9: warning: data definition has no type or storage class
>     1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1261:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1262:9: warning: data definition has no type or storage class
>     1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1262:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1263:9: warning: data definition has no type or storage class
>     1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1263:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1264:9: warning: data definition has no type or storage class
>     1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1264:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1265:9: warning: data definition has no type or storage class
>     1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1265:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1272:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1272 | DEFINE_TSAN_ATOMIC_OPS(32);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1260:9: warning: data definition has no type or storage class
>     1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~
> >> kernel/kcsan/core.c:1260:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1260 |         DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1261:9: warning: data definition has no type or storage class
>     1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1261:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1262:9: warning: data definition has no type or storage class
>     1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1262:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1263:9: warning: data definition has no type or storage class
>     1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1263:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1264:9: warning: data definition has no type or storage class
>     1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1264:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1264 |         DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: error: macro "DEFINE_TSAN_ATOMIC_RMW" requires 3 arguments, but only 2 given
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1193: note: macro "DEFINE_TSAN_ATOMIC_RMW" defined here
>     1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
>          |
>    kernel/kcsan/core.c:1265:9: warning: data definition has no type or storage class
>     1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1265:9: error: type defaults to 'int' in declaration of 'DEFINE_TSAN_ATOMIC_RMW' [-Werror=implicit-int]
>     1265 |         DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
>          |         ^~~~~~~~~~~~~~~~~~~~~~
>    kernel/kcsan/core.c:1274:1: note: in expansion of macro 'DEFINE_TSAN_ATOMIC_OPS'
>     1274 | DEFINE_TSAN_ATOMIC_OPS(64);
>          | ^~~~~~~~~~~~~~~~~~~~~~
>    cc1: some warnings being treated as errors
>
>
> vim +/DEFINE_TSAN_ATOMIC_RMW +1270 kernel/kcsan/core.c
>
> 0b8b0830ac1419 Marco Elver      2021-11-30  1169
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1170  #define DEFINE_TSAN_ATOMIC_LOAD_STORE(bits)                                                        \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1171        u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder);                      \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1172        u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder)                       \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1173        {                                                                                          \
> 0b8b0830ac1419 Marco Elver      2021-11-30  1174                kcsan_atomic_builtin_memorder(memorder);                                           \
> 9d1335cc1e97cc Marco Elver      2020-07-24  1175                if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
> 55a55fec5015b3 Marco Elver      2021-08-09  1176                        check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC, _RET_IP_);    \
> 9d1335cc1e97cc Marco Elver      2020-07-24  1177                }                                                                                  \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1178                return __atomic_load_n(ptr, memorder);                                             \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1179        }                                                                                          \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1180        EXPORT_SYMBOL(__tsan_atomic##bits##_load);                                                 \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1181        void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1182        void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1183        {                                                                                          \
> 0b8b0830ac1419 Marco Elver      2021-11-30  1184                kcsan_atomic_builtin_memorder(memorder);                                           \
> 9d1335cc1e97cc Marco Elver      2020-07-24  1185                if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
> 9d1335cc1e97cc Marco Elver      2020-07-24  1186                        check_access(ptr, bits / BITS_PER_BYTE,                                    \
> 55a55fec5015b3 Marco Elver      2021-08-09  1187                                     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC, _RET_IP_);          \
> 9d1335cc1e97cc Marco Elver      2020-07-24  1188                }                                                                                  \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1189                __atomic_store_n(ptr, v, memorder);                                                \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1190        }                                                                                          \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1191        EXPORT_SYMBOL(__tsan_atomic##bits##_store)
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1192
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1193  #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1194        u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1195        u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1196        {                                                                                          \
> 0b8b0830ac1419 Marco Elver      2021-11-30  1197                kcsan_atomic_builtin_memorder(memorder);                                           \
> 9d1335cc1e97cc Marco Elver      2020-07-24  1198                if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
> 14e2ac8de0f91f Marco Elver      2020-07-24  1199                        check_access(ptr, bits / BITS_PER_BYTE,                                    \
> 9d1335cc1e97cc Marco Elver      2020-07-24  1200                                     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
> 55a55fec5015b3 Marco Elver      2021-08-09  1201                                             KCSAN_ACCESS_ATOMIC, _RET_IP_);                       \
> 9d1335cc1e97cc Marco Elver      2020-07-24  1202                }                                                                                  \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1203                return __atomic_##op##suffix(ptr, v, memorder);                                    \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1204        }                                                                                          \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1205        EXPORT_SYMBOL(__tsan_atomic##bits##_##op)
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1206
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1207  /*
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1208   * Note: CAS operations are always classified as write, even in case they
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1209   * fail. We cannot perform check_access() after a write, as it might lead to
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1210   * false positives, in cases such as:
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1211   *
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1212   *    T0: __atomic_compare_exchange_n(&p->flag, &old, 1, ...)
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1213   *
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1214   *    T1: if (__atomic_load_n(&p->flag, ...)) {
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1215   *            modify *p;
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1216   *            p->flag = 0;
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1217   *        }
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1218   *
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1219   * The only downside is that, if there are 3 threads, with one CAS that
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1220   * succeeds, another CAS that fails, and an unmarked racing operation, we may
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1221   * point at the wrong CAS as the source of the race. However, if we assume that
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1222   * all CAS can succeed in some other execution, the data race is still valid.
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1223   */
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1224  #define DEFINE_TSAN_ATOMIC_CMPXCHG(bits, strength, weak)                                           \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1225        int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1226                                                              u##bits val, int mo, int fail_mo);   \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1227        int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1228                                                              u##bits val, int mo, int fail_mo)    \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1229        {                                                                                          \
> 0b8b0830ac1419 Marco Elver      2021-11-30  1230                kcsan_atomic_builtin_memorder(mo);                                                 \
> 9d1335cc1e97cc Marco Elver      2020-07-24  1231                if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
> 14e2ac8de0f91f Marco Elver      2020-07-24  1232                        check_access(ptr, bits / BITS_PER_BYTE,                                    \
> 9d1335cc1e97cc Marco Elver      2020-07-24  1233                                     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
> 55a55fec5015b3 Marco Elver      2021-08-09  1234                                             KCSAN_ACCESS_ATOMIC, _RET_IP_);                       \
> 9d1335cc1e97cc Marco Elver      2020-07-24  1235                }                                                                                  \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1236                return __atomic_compare_exchange_n(ptr, exp, val, weak, mo, fail_mo);              \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1237        }                                                                                          \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1238        EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_##strength)
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1239
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1240  #define DEFINE_TSAN_ATOMIC_CMPXCHG_VAL(bits)                                                       \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1241        u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1242                                                           int mo, int fail_mo);                   \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1243        u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1244                                                           int mo, int fail_mo)                    \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1245        {                                                                                          \
> 0b8b0830ac1419 Marco Elver      2021-11-30  1246                kcsan_atomic_builtin_memorder(mo);                                                 \
> 9d1335cc1e97cc Marco Elver      2020-07-24  1247                if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
> 14e2ac8de0f91f Marco Elver      2020-07-24  1248                        check_access(ptr, bits / BITS_PER_BYTE,                                    \
> 9d1335cc1e97cc Marco Elver      2020-07-24  1249                                     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
> 55a55fec5015b3 Marco Elver      2021-08-09  1250                                             KCSAN_ACCESS_ATOMIC, _RET_IP_);                       \
> 9d1335cc1e97cc Marco Elver      2020-07-24  1251                }                                                                                  \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1252                __atomic_compare_exchange_n(ptr, &exp, val, 0, mo, fail_mo);                       \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1253                return exp;                                                                        \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1254        }                                                                                          \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1255        EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_val)
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1256
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1257  #define DEFINE_TSAN_ATOMIC_OPS(bits)                                                               \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1258        DEFINE_TSAN_ATOMIC_LOAD_STORE(bits);                                                       \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1259        DEFINE_TSAN_ATOMIC_RMW(exchange, bits, _n);                                                \
> c843b93f690ae6 Dishank Jogi     2025-07-28 @1260        DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);                                                 \
> c843b93f690ae6 Dishank Jogi     2025-07-28  1261        DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
> c843b93f690ae6 Dishank Jogi     2025-07-28  1262        DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
> c843b93f690ae6 Dishank Jogi     2025-07-28  1263        DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
> c843b93f690ae6 Dishank Jogi     2025-07-28  1264        DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);                                                 \
> c843b93f690ae6 Dishank Jogi     2025-07-28  1265        DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);                                                \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1266        DEFINE_TSAN_ATOMIC_CMPXCHG(bits, strong, 0);                                               \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1267        DEFINE_TSAN_ATOMIC_CMPXCHG(bits, weak, 1);                                                 \
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1268        DEFINE_TSAN_ATOMIC_CMPXCHG_VAL(bits)
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1269
> 0f8ad5f2e93425 Marco Elver      2020-07-03 @1270  DEFINE_TSAN_ATOMIC_OPS(8);
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1271  DEFINE_TSAN_ATOMIC_OPS(16);
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1272  DEFINE_TSAN_ATOMIC_OPS(32);
> 353e7300a1db92 Christophe Leroy 2023-05-12  1273  #ifdef CONFIG_64BIT
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1274  DEFINE_TSAN_ATOMIC_OPS(64);
> 353e7300a1db92 Christophe Leroy 2023-05-12  1275  #endif
> 0f8ad5f2e93425 Marco Elver      2020-07-03  1276
>
> --
> 0-DAY CI Kernel Test Service
> https://github.com/intel/lkp-tests/wiki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CADorM-_PZd-_2g9EWy4V4RCLS7xp9MOZs0k5GNrbB7FOwSB%2BtA%40mail.gmail.com.
