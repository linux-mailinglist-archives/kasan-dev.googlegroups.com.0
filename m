Return-Path: <kasan-dev+bncBDAMN6NI5EERBT5C4WUQMGQEFC6ZS7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 95B3C7D724C
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Oct 2023 19:33:04 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-5079641031asf5860755e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Oct 2023 10:33:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698255184; cv=pass;
        d=google.com; s=arc-20160816;
        b=0XiLSvomG9JV8wTQr1evS1gbbKbm0zS+oYBgnkQP3NvnFmdMB3V3d7IiNVT6LdphMh
         hU3+23V7/kcxDVODE6fqgfR3AK8ZXmq0zYsr2hR4dD6b9uUrmE7EzeK4U3N5I8xY74cx
         y3JeWxG5SXj97sZ5onWH6mA4qmpjM7xhJdJBI5x/X0TBp7Cgo0jYW80YzfAEl598GRmS
         GN2xQVsImxcsNWKuYkJTxXW/PgraGoYdVfmDQ0+G0AVGF+u6+QfVVsKP8I5Pn9m/flLZ
         VCYfraQAk7sANMtbdWQsBtvPtKmLf5eUI1qbeHq5sQv/VCm5zjHg0PHZCaNgErp1pGx/
         Hu7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=Kr87gW6h6DQNrIkVr0UdBi1RnqgRh3HzKEdRB2T2O2c=;
        fh=AFOxcCB9MfPdzo/iQ5IkYJt05Y8hJ+Uaf8xHeAP0L18=;
        b=Jp+RD3F9TOEiB5vmQzOxvYhwbH7RWl6FDaUKVPa9npCiyeU2y6pV7qgNp2nq3SWcL5
         fWxSpkawSB78ZFHszd5frohspSjGl729kHVjannAsmlBVhd/wuM/use05xwVxC/NMmTX
         KL2DCYzFlqMB25yL1KROy1xXHUwvo+syxEYJQdPPg58zhVOVBou7Em8B9byaYNvJz2dP
         Ia38IQeAttqpKDB48WG3T6Fbzdb7m4Id+N8mapDqf5XAxIyNyIEA4cuSIlugtSbYJ6AH
         xZclogieBKWXnlYnYLvX0tjyjKGG6apvwEHW6VohhQM4UUSUFiMqDEn1APO5ZeU3rszm
         zo+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=14FcZImO;
       dkim=neutral (no key) header.i=@linutronix.de header.b=CkKs0Vb+;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698255184; x=1698859984; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Kr87gW6h6DQNrIkVr0UdBi1RnqgRh3HzKEdRB2T2O2c=;
        b=kkInIaVR5kfO0fOYI+Muy6vM2+GWCYILq5ht/E7XxExCSHg3d5I4prqOSVH5s0tOsS
         c8uOfxSAyvQ44E/3ejEAkg6BQmvGKyAjdhMueo5FHxhBhoKXLaliuniiUCjFAfrObTMj
         K0tSLm+ajcHcuBXtwj2eLmdxGpm8mWyroPTmv9ntAOE+NvMgdMU6gqeD9N693jMC/C35
         i5VsUGtxyXxIUgM+aNLGpjSoe6B1Im36w2rBgu7PfBPs32eZh/N6b10UEF+jI96o3Bnx
         gpupYVVqDsHRgIz7/Cuski5ZZQ+HlnRJqJi8dqll0dfA4H8nteSnjKuitP7laH2/ESsw
         gRdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698255184; x=1698859984;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Kr87gW6h6DQNrIkVr0UdBi1RnqgRh3HzKEdRB2T2O2c=;
        b=EnrBtnfnoG9cAG8+GJtXwhFkbp7ga624TM0UMpPhACmcOjE3plAeymonhRLB4BaPXr
         LIgfVEnqtUppzIXUr/6y4IXL7BIfl6kF/dWBmPIF6CM86/G10LTlyD9STJB95k+Qf2/j
         mnwezUASBY/n7/9go2kC0aWEF+gQWn9kanxZbOGFcqUEcdqitvt+oe27hxroEF5H58ID
         SrDrsjyqs5TD1f664hsF+wUJtFFMDHG+8oqc0tKUVkaZUbcPubuK1lYMhNec+wI0HZv2
         XwWwY+guspUjrthzjQ+C0DZoAwEspuwTtgODtoBoE1nAZA9QdZphsoo+iv4LMIHAP8Dv
         MvTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzmSe3X+iAe7cklQUca5viOkX0CrHCx57dx4UhffKpm+K8HpQQh
	wQtPUzd9pWhpsi/uYFa5ioA=
X-Google-Smtp-Source: AGHT+IFTFbWJn1OMcIk80VYnsIeRIpFNkyXnE+yICmxVJOHsO47rCBeq3O1LUIGOZ4Pmb2RZbKHxvg==
X-Received: by 2002:ac2:5df6:0:b0:507:b15d:2ff1 with SMTP id z22-20020ac25df6000000b00507b15d2ff1mr11437439lfq.38.1698255183319;
        Wed, 25 Oct 2023 10:33:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d16:b0:507:b8d5:d6cf with SMTP id
 d22-20020a0565123d1600b00507b8d5d6cfls172749lfv.1.-pod-prod-05-eu; Wed, 25
 Oct 2023 10:33:01 -0700 (PDT)
X-Received: by 2002:a2e:a9a7:0:b0:2c0:34ed:b5ea with SMTP id x39-20020a2ea9a7000000b002c034edb5eamr12112229ljq.45.1698255181385;
        Wed, 25 Oct 2023 10:33:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698255181; cv=none;
        d=google.com; s=arc-20160816;
        b=NAisWVUmRNPhrC3u/Lj8I5YJcXIS+w9bfqpDJ7luBkwfkNK8L0II24eC4zklRKE6Te
         g7tFtQfp/J6dJkOXE7I0o6Hv6WCWnlDXsuwZlIkJjXYCf0Z7Oag72Bm+IDpfapwC+vAB
         vO8EMBYzpWCdrFxyLY3x8Jl0EYkm1IVMxCMu91MnQdJIrWMc8FYk/9iVm1bnF3lwWYyJ
         jEroNMXxqPcYaaLKr/Fh/lxWEbIDW/0+ztBHOJAJvAlGK6reV83pKaBgPFEL4MXwLWzi
         9PqWJE5Yrzj5txDO+HC/6dON5GSQZayqLEXKWWVb9LosLccYhcpcyYFvx8NHOtKTYdIc
         9l+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=IMbPag9QwdHG5LCrp7GKbj7qfyS+r03W9FBPD7TqsHo=;
        fh=AFOxcCB9MfPdzo/iQ5IkYJt05Y8hJ+Uaf8xHeAP0L18=;
        b=dbRa4ysc/9mTOlQ+PNnjnqdz9V+GronHiZrSMOF2L469uZFra+oUZupZkOkdl3Z2Oh
         igRR63cS2ijNh6+vLx7IvgpY43FWM/l5bRkc8q49bnrEkU2Clsbcm1pjF0J0W7zchhF0
         bduyL7jQCAWlClT4MRmH52L0SAj7OaaaeHe7F8OWNHvzGa1TfbndPKJcC3ihJyqY/38d
         ETlXjbW0f06+9QWkgL07szUhCKCkzmXu9l/wUCXti2X0Q6q3vtH2Dext/Wvia58nSOAI
         1yuCuZ95I27gZDCh3jIw6skMesg4SsiAc46/pwz/d2ndtStTmoDBJtHFt3zoHIkVRtl1
         Z+yA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=14FcZImO;
       dkim=neutral (no key) header.i=@linutronix.de header.b=CkKs0Vb+;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id f1-20020a2eb5a1000000b002c12145a0cbsi470817ljn.7.2023.10.25.10.33.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Oct 2023 10:33:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
 masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
 keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v2 28/39] timekeeping: Fix a circular include dependency
In-Reply-To: <20231024134637.3120277-29-surenb@google.com>
References: <20231024134637.3120277-1-surenb@google.com>
 <20231024134637.3120277-29-surenb@google.com>
Date: Wed, 25 Oct 2023 19:33:00 +0200
Message-ID: <87h6me620j.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=14FcZImO;       dkim=neutral
 (no key) header.i=@linutronix.de header.b=CkKs0Vb+;       spf=pass
 (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1
 as permitted sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Tue, Oct 24 2023 at 06:46, Suren Baghdasaryan wrote:
> From: Kent Overstreet <kent.overstreet@linux.dev>
>
> This avoids a circular header dependency in an upcoming patch by only
> making hrtimer.h depend on percpu-defs.h

What's the actual dependency problem?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87h6me620j.ffs%40tglx.
