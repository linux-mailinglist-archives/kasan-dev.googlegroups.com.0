Return-Path: <kasan-dev+bncBCUY5FXDWACRB3NE6DDQMGQEEX6BDJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id DFD15C085B9
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Oct 2025 01:57:35 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-592f576d68esf1507752e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 16:57:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761350254; cv=pass;
        d=google.com; s=arc-20240605;
        b=NSkbSMrIvE4uOEdR25TSz8uoAnpW1pEsBAkEjdHdhQH88PsmFtWEMpCzwDmO1P1SQM
         rmceS16fvaU8RUuRP0q/kE1m1D5qf4X5926wNSN5lcKzCr7Fs8GnPc+AwDfPzqZTo14C
         fbOa1oOGK/siux30n/UjYDNfRR6XyAMoFSkMo2oyaIbNJckq4DI+/i+/Q8QQMfk+mwnC
         zl15GKT87giaVawrMK52iWPCrBoU19NQ+ZfURq39VZhiTTWNIYTuOT7ewrjEPfiUMtvJ
         bLZA/rxGi9cV8fvsURbdkCLcVWi3rpJaBdTGGCFN5S72czlWWeXP30plif3InE7IoDEE
         96rA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Y4UFXxn4NwQs9iD30ccrhK7pjoz0AKluwps7WqaaRi4=;
        fh=BOQhfJK95JdxL9bzwsgx8GgFDVLPHCbdyMAv/gZJI2k=;
        b=Kx1ggJjVBqp4kQw1yzLbyqLno+LbEmnGwxQ4F0X0JmqEXhhJhU5ERj91d7u0EYoUbB
         s4F48Hmgq2bBhlfuyZxpTMLs14YZxf1qSQDUpC295z6vrGiEnJAKp82nAZqemDzH1q3y
         i9o66tKpJVGCe18YJADAP7fvZcWmGvBO5O7iY/D7ihR4f+LAHJaR1JqeSAbSnURkJDtp
         2pTVk1FHGTs6rFVaWJZtGHqTW+nK/2A3abTZOaPG+DhLSaNKbaN7/ziNf1RsK1CClbIO
         oseu588dRvvmAHavCrgGj7oG7tUrAwD8WAxvVHPHnNBwIFqzSYZvMLljqCvbrVvX4kVm
         Q+Ug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MEvbGTva;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761350254; x=1761955054; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Y4UFXxn4NwQs9iD30ccrhK7pjoz0AKluwps7WqaaRi4=;
        b=r7eML12oyBA3RZ5RvW8klgss8HcseELzTGJezF3jr+fxzUObdT7PhggrJjmSKC5fPx
         HX37fl4p5X5zWIEl1HI+SautjBBjIJ012tAfpVOaTYbQWsMHXkBH8m5XggQccoOd8AdS
         3xSIEoGybyP3lTZZYGK+fWYFjTRq4bOT1cl04+qlnHexctpUDVvaF8XG+2ix6E4eBGZ/
         e/HviSxUUnyDSG6keaQDz4d4TJnvEo+FyeeOedHszAP4/Rc6UAKd+uVK/Yrcb+xvJVMY
         bCa5MnaZLsQQ25nr1evN4K9odpsJRU7xtSLRB+NgI5SsIeXjDzYr1E/tS+L9z+ECyjSg
         PNug==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761350254; x=1761955054; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Y4UFXxn4NwQs9iD30ccrhK7pjoz0AKluwps7WqaaRi4=;
        b=bZeazeedUIkB9pymEEWrV+vpqbUjvL14oAaFpGnrSDMlqAS/NFMc2Rzaj/jcJ86q4J
         ipsxWTzdVtUPftskH7tLcvugvrACJoG0bc8QNs5OabRIpyycsDtzx1sgIL9E9zwwaWxC
         06r453mo2MqndMqWHRm0kyAHggi9Wi/vXQdwrwPHHQUVRD9GyWzKEa1mbENlVrZgFu0Z
         jQlMNk6aNm8sAOdwmZa7hMNblVj/RpDKndUIVSYoREOo/e+WGixwTkjhNDq3sGr0ZWpV
         VA/9fLtu35AMptW+U6+0ZscvDr7tJKkhjtLXJUeaQ3mjgiVuonf/JHXQIxYozk9RK+/U
         UnSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761350254; x=1761955054;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y4UFXxn4NwQs9iD30ccrhK7pjoz0AKluwps7WqaaRi4=;
        b=pSY6MPTXQwoRQ39Nbses9NLQy1z9PTdcgTrXfka74kDYumgHabhabVJAQLKdzPMAF7
         Nz4d93tH80Fj8HMqQU4sFQQiMPm6cx+8uxH8xngWoxwuKgEGi2wXoT5EOowa5XqLeYQX
         RgZU+2FvbMBEb+bwI997ik8GklfhWk1EvJ1v5OCQvbEXsakAtuOELrfyJaXp3TPwlJkw
         bJdH85NpiZ+JHDQHwVolppH0jXiGPUJwEWxCHfnI/spSTB5ANdIj4lpvGukVNfFAc9rx
         s0Ecl5Uq5bHq+rLUemS0bMSJ2Q82/IUObe1FhSBXK54S9688jlPCvqD5wR35/Y2BVXYT
         K+6g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWN3n46zXk7Flt7FCSpIozyZUatRW/Oyxj3a0aNEjTdT/pPLP/2MyTJo1uMPORM4WPEhJWKEg==@lfdr.de
X-Gm-Message-State: AOJu0YxQ6xr/GK27SHaYfLY2CVAlZ31c8PH2Fg3qJBd4yfcVeg5pO/3h
	+0yP47jEyOdKscnvyC41PiIy5nCiZ+YbGTQDVs+U2GUqOFqpIkg3Uaw4
X-Google-Smtp-Source: AGHT+IEO/0hX/wIDc6IisdEVIzR8DlkFHhVPRs0TpsNWfGr1v0DTNo0Iq/vyhL5SgZpkjRGnIqxOKQ==
X-Received: by 2002:a05:6512:3c96:b0:57e:b9a:9c82 with SMTP id 2adb3069b0e04-592fca71031mr1685039e87.39.1761350253972;
        Fri, 24 Oct 2025 16:57:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Zxpml0k9/KDtZ75TopEp+juDWQY8LsOuccaPft+NVHmg=="
Received: by 2002:ac2:499c:0:b0:591:c783:8980 with SMTP id 2adb3069b0e04-592f53c50b4ls282316e87.1.-pod-prod-03-eu;
 Fri, 24 Oct 2025 16:57:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVCUdP4vsyu9FbP1SF2eAbcIUisyMb2oJ84v5Gkb6N93HCwVpC+hxZCNMZKc9rx1/2kpgqRnzT1540=@googlegroups.com
X-Received: by 2002:ac2:4e08:0:b0:579:f0fc:46f7 with SMTP id 2adb3069b0e04-592fca8d30fmr1406334e87.56.1761350250520;
        Fri, 24 Oct 2025 16:57:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761350250; cv=none;
        d=google.com; s=arc-20240605;
        b=k16w2PtFsP/ruakxFVLUGjCb401Jc6GZkZw9vJLdZVulKl2YRsxQKr23XbY7hp0WMw
         wHJoVWPi1gP5zH+lVXaiY+9Yx0SVYNma62SEdrRlSjjdPkn3A8/MRWeL11kaAx36IgvV
         4X/5aqt+JEzg3dATbwvhk+2eiWI0HXFgNZBWhfXvs++vMADvhTVwu+FcC8KYl2V2C3/j
         1mWKTYvAhpOsbIZBic+kRTn/AJgKocWZihfbt0pi0441eLicNaWM0hFiWTYntEQBvxyB
         6M+oaVPJa5zQbG54GIvBVtY2wZhPBIYRQ/1+HHZ7K3N7X/GO4zdgS0lS1XYtknUzma77
         3qCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dNKLlMrwd1/HZexcmyJUATq+vFaKLMO+fNIoDoZR3Os=;
        fh=SWih6+pQ6hwxtZCsKAE33+YWZbcEczQt1fPlvvls6Qo=;
        b=Ocwgm5r1LLSFhnTJCZ6y9efCjJ+fHOU9IQB4ngna2bdkAB5N8gyxEEsHSPauDrPZRz
         u78tEKQyJH0+Kq49YsoV5By3r5VhqUuyNwshyjMh76GRiaGGhkiKq9TCfBBSb0NGClbs
         MGE3WoyFp6Dvl9JenHl2BjMVCbYc+eA7KbJJPTwvbMKb853c1DkHEp5lY3/kfmh4cGKF
         E3PBMaZfV5IBln7GwmeoOAwvwF/x5xEzjgiZ95TaBwPCP04cJzIBhNAXuCod8STQEJ6a
         ZkDMnHgGaKoKv8nfGszM51saLFeyVxIsR17bDGv8UCpSvMOcW2wqZ3hqNab2oBniYdSS
         Yssw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MEvbGTva;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5930289359csi3883e87.4.2025.10.24.16.57.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Oct 2025 16:57:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-3ee130237a8so1807450f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 24 Oct 2025 16:57:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVzHMYWambOmHcC/12X1wrQ0A3XYs8zABbbxvVALTgH/e2wqWGa/BnzMW8FIvOFlYaD2FEUw7eWSRA=@googlegroups.com
X-Gm-Gg: ASbGncuLzDF9tNzRWrAhCIK0r1e5FniFyRV9NSs2pEcQ41U6tJsAmmEdW9jJBSRVtbV
	TkVU3BntxAlreDtKzr2Sk1stMALQc13JmaezpGDKisgPO0AqGngunUZgmEXY/ZuD3iMqadPIeUN
	T29it/d4QWl/Qg9kAPjvz8NPtNdubWQJSlmBOl/mKY/fVs5jIIkTigyGUzQEVTQh7O2Fbdifki3
	wD2cPG31Bp7VMYMsPZ8gSE7Yk6+eD9xAQ4od8L97Lr8WFNgez1FX7aCpZXn1BNMk4Zlu8m6msS+
	qKkH63LvfpFOG8cGFvQxmyIcoUun
X-Received: by 2002:a5d:5f55:0:b0:427:5ed:296d with SMTP id
 ffacd0b85a97d-42990712615mr3163617f8f.28.1761350249591; Fri, 24 Oct 2025
 16:57:29 -0700 (PDT)
MIME-Version: 1.0
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
In-Reply-To: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Fri, 24 Oct 2025 16:57:18 -0700
X-Gm-Features: AWmQ_bltQWl9Zt65mlT3O0wfqqWroGd-22lI3adDJdCXk0hQ4ymeHmC7hV8Eb1Q
Message-ID: <CAADnVQKYDgwgAQ+geFrY=xDxNoe2YuEYVQU+d3V3nMhkMBg1zw@mail.gmail.com>
Subject: Re: [PATCH RFC 00/19] slab: replace cpu (partial) slabs with sheaves
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Harry Yoo <harry.yoo@oracle.com>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-rt-devel@lists.linux.dev, 
	bpf <bpf@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MEvbGTva;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
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

On Thu, Oct 23, 2025 at 6:53=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> Percpu sheaves caching was introduced as opt-in but the goal was to
> eventually move all caches to them. This is the next step, enabling
> sheaves for all caches (except the two bootstrap ones) and then removing
> the per cpu (partial) slabs and lots of associated code.
>
> Besides (hopefully) improved performance, this removes the rather
> complicated code related to the lockless fastpaths (using
> this_cpu_try_cmpxchg128/64) and its complications with PREEMPT_RT or
> kmalloc_nolock().
>
> The lockless slab freelist+counters update operation using
> try_cmpxchg128/64 remains and is crucial for freeing remote NUMA objects
> without repeating the "alien" array flushing of SLUB, and to allow
> flushing objects from sheaves to slabs mostly without the node
> list_lock.
>
> This is the first RFC to get feedback. Biggest TODOs are:
>
> - cleanup of stat counters to fit the new scheme
> - integration of rcu sheaves handling with kfree_rcu batching

The whole thing looks good, and imo these two are lower priority.

> - performance evaluation

The performance results will be the key.
What kind of benchmarks do you have in mind?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQKYDgwgAQ%2BgeFrY%3DxDxNoe2YuEYVQU%2Bd3V3nMhkMBg1zw%40mail.gmail.com.
