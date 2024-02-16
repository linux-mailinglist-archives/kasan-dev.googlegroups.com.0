Return-Path: <kasan-dev+bncBCS5BWNH3ENRBC6MXSXAMGQEO3KBM7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id CA4EA857889
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 10:08:28 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-362cfc117ecsf96335ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 01:08:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708074507; cv=pass;
        d=google.com; s=arc-20160816;
        b=N3ZFdLmjgEo4T+3pbnqpg7J8pVspsXL5msaoqL+pJ0PFY+Uo0ZJ17fkSoKQxCAbCDf
         1DV/PEmwB9TyjGsPlU+ki+u/CfNlxhpiq+0BpDmCJ3y08Wi5x6OYXWJ62WCI5Dk9vQka
         c5TWw9DqSDzrq7Ap6i768KjcPcWjm0mkFcJBf9T4oSE2Wp+8wx3WP8PuL6TOciMar+0a
         EqOYnorbh6bAOPJZ1gpbGbbMd7iJkjIxiNRbnWZXsxJPJIbbE5c/YgNIMsO9xq83uo3B
         inLBJZxCVdpUmM/55x1BHXzZFy3GUrzLyonww7R5yr8oc2asnSQrW4kCfcMIfTpOO2i8
         e2xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:organization:in-reply-to:subject:cc:to:from:sender
         :dkim-signature;
        bh=ciVnFjztnNfTasUsUAPKMTuDhaYLI0Q+QuXtiOpTROc=;
        fh=UoZYWn0dAbpCUQXdFnd5RO10b4io9WgZ9qSZsNXvco0=;
        b=h+JVA+twT3UJiu6O0E8rwkSnhUq7SXHbtSDtWcQ65bajr1pP8ifN3MJluaj1KhwW+w
         LZlVeMOWVo8L5KqqxDb6cEvJ6TMT+vhge9L3g4lKfUH1Ofx99giU5JwX7OyljV9UYJUH
         zdfyOQ/LyzNuLqUs04YF0ty8tOBTwhMzMS7GNbJxHs+ree78RgeA0srTNXhukQHCNV6z
         5ePsArGNwpJPG8EQ2VKLq1V6VwKzQZX7gtNbvgBKQlOcDpz+xYdu38jNqcRTiMqlJ9NP
         prfs2oQJV7gWozMJy+Mm0ydYKVLymsRFxVVIJtc31Nv5nzemKZhd4UqHrppDgMxPYvp3
         0wHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="XMx6/EQZ";
       spf=pass (google.com: domain of jani.nikula@intel.com designates 192.198.163.7 as permitted sender) smtp.mailfrom=jani.nikula@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708074507; x=1708679307; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :organization:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ciVnFjztnNfTasUsUAPKMTuDhaYLI0Q+QuXtiOpTROc=;
        b=my/Jzsn/hpgwtBG/E27WDDElGtnztLmO/9IgS92jAyGny+JzRIvdPgGv+40SCBkJmM
         AoYorvVCzOfsQv1Xvpf3qDMQ7vA7pCZWw6jXRXqf+LEOxGTJnsEYAJ2UgD0l461TLFj5
         vmYEvS+y1kaGfsHosIBYazdGtMzUIv9Ju1T+fjh1hxE9oQpgRKjzuD7x7OA+IKR3J0fH
         w78GibPn9PyL6qf4bsN4rCKhoLwTMF2wn5LtYvYvDfiE0WFT8M+YDrKHv9jsvtnxEy6X
         hiCnSYnTX/lKN0qrZzHdI4IBeoFK+0xzXMik+o//JPPo1pEcY3BEhhZtyZORFnozSLjG
         pwnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708074507; x=1708679307;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:organization:in-reply-to:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ciVnFjztnNfTasUsUAPKMTuDhaYLI0Q+QuXtiOpTROc=;
        b=OZkoX+e1HtxIAhBEx/P/EvNPQZAUzyCoYqS7F9NRX80KUWlUVd1cjdcPi74VY/lqtg
         P6ynCAUJXmDVaD1b5m1WE/Q/ha34MdWyP6nj75IO/9hkZR8Gdv84aMJAXOQ7yrKQyP5T
         J5eMg3Z+c6uUmllQgAucE+jjnqzFcE2I9nSWrj0I+vOTV1fHtw3Ti+1tbL13zOtZrFHg
         CD6ibqDhdG7g4jUoYx51x4MWs/oXHydPQbC5v3OpH209tkthrncF1O+Dqv8CMubtWLGM
         B3awpPzBuTfvpB5I/BL3vQEuKihFcM3FDCduFdR7wrStrDPz7Qx22oTv81vXvQqnsjDy
         1d9A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXXC/0yUcnMyDir6Dy4OOHWwDygXQL0Fx6Fcyw6+9foHOEj19Ydhjcqh5l7w67zmKvVyJFfYzDSSGKL1BXv8YtzuFd/YFL3Gg==
X-Gm-Message-State: AOJu0YzhywGIx10ZKhHNXfz9iEVsQh58fFdLoEr2IUPdEI40mj/3/dbW
	PYjpn60yb2IWFH8z0NfPNukQ7wMUSGwum3aoKJLORCdohXMpVIFJ
X-Google-Smtp-Source: AGHT+IEiWa8fdSP0QSwv41LPMTyl8PMWC1fo/z2vUpWQAKX0m6bckrjrmu9wrDMsa2e5NWlEiRMlcw==
X-Received: by 2002:a05:6e02:3a83:b0:363:ca7e:908 with SMTP id cr3-20020a056e023a8300b00363ca7e0908mr191156ilb.16.1708074507217;
        Fri, 16 Feb 2024 01:08:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:68c:b0:364:f2cd:ef95 with SMTP id
 o12-20020a056e02068c00b00364f2cdef95ls381184ils.1.-pod-prod-05-us; Fri, 16
 Feb 2024 01:08:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW4gWSIyghNGjoS0OGOnSp+UlHamvD3t819wznPyisQYLctn4uXgUoPRnvRFKyu9XfYsSGC8CiwGfysGsNYj4axqir23AVjvTwG+A==
X-Received: by 2002:a5e:da08:0:b0:7c7:2400:8e67 with SMTP id x8-20020a5eda08000000b007c724008e67mr360771ioj.10.1708074506170;
        Fri, 16 Feb 2024 01:08:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708074506; cv=none;
        d=google.com; s=arc-20160816;
        b=qEtJ/n/Eybw5HAEfojnEHTZjFzGGmt6xClmpb22SFKk1PnNYtCNL+Rl8YBB/knlOQJ
         wG8yRrMVi6VJVGKae+EhOdCLtJJJ/RcDXqE9dhc2byVh70NJD4LwYimNNYua12yk37yq
         TVs0in2yrmcc7Q4NYd+uTT8qCoVEXawLI+iFE0m2muTMYaeSrQtpjkaEFqFkCDxedepA
         0DdX2p3rGQmnymIhpUa4hZrk5ub8X5KMFAWCtUh96y5Zi8QO+WatM7nypBZgdPWuSKR7
         x5E0/E7QmGWBMTJA1U1NqSd7GqRWaK552LPpUWkXvRwQ2lcJgVnyZlp/aCs+cgxK1+6K
         sDkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:organization:in-reply-to
         :subject:cc:to:from:dkim-signature;
        bh=T/cmnehpCc4aAlkuHwsyq2PgupB8HJnesuUvtm3GClY=;
        fh=1qtMbsoHBXeurxioIkUPEnwxSt3xgrZ00XqZJDQFXxc=;
        b=j3KXpN7dM2Bdb4Blf1cIpGwFIJuCc6kmkacLcVvpKfYP8gvgwFVsyrtEsZ2ObGpPVJ
         8oN1TKb49dvNU0V86dCmfTsPcDAGFpBOz5H+dxvcUJcPX8yLtSJWPPl08+oBwfFWNvz+
         NhzB2FyXyeyFdY7ZcCr+YYQ30RGdcQfH2xDmyhZGFGwtVdwznuG8Uz0aRlzYA+pHX4z0
         E2bpxdUHT2W6K/qx/dZ+tv7/fQgV2n7zywOUs9HIrWbrQ0A2jA/hQgX92wb5qtwoddcj
         w5PMQyLbIsiiNFcpEKkhd2U3/uRDAthgcrtaD6MAoS86NqLtTKAyCg1i6bEWXg0yUvEv
         c0FA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b="XMx6/EQZ";
       spf=pass (google.com: domain of jani.nikula@intel.com designates 192.198.163.7 as permitted sender) smtp.mailfrom=jani.nikula@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.7])
        by gmr-mx.google.com with ESMTPS id w1-20020a056638030100b00473d7d16a89si255126jap.0.2024.02.16.01.08.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 16 Feb 2024 01:08:25 -0800 (PST)
Received-SPF: pass (google.com: domain of jani.nikula@intel.com designates 192.198.163.7 as permitted sender) client-ip=192.198.163.7;
X-IronPort-AV: E=McAfee;i="6600,9927,10985"; a="27650616"
X-IronPort-AV: E=Sophos;i="6.06,164,1705392000"; 
   d="scan'208";a="27650616"
Received: from fmviesa004.fm.intel.com ([10.60.135.144])
  by fmvoesa101.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 Feb 2024 01:08:23 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.06,164,1705392000"; 
   d="scan'208";a="8431336"
Received: from pshishpo-mobl1.ger.corp.intel.com (HELO localhost) ([10.252.48.79])
  by fmviesa004-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 Feb 2024 01:08:02 -0800
From: Jani Nikula <jani.nikula@linux.intel.com>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
 mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
 void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
 tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
 x86@kernel.org, peterx@redhat.com, david@redhat.com, axboe@kernel.dk,
 mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
 paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com,
 yuzhao@google.com, dhowells@redhat.com, hughd@google.com,
 andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com,
 vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
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
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
In-Reply-To: <plijmr6acz2cvrfokgc46bt5budre5d5ed3alpapu4gvhkqkmn@55yhfdhigjp3>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
References: <20240212213922.783301-1-surenb@google.com>
 <87sf1s4xef.fsf@intel.com>
 <plijmr6acz2cvrfokgc46bt5budre5d5ed3alpapu4gvhkqkmn@55yhfdhigjp3>
Date: Fri, 16 Feb 2024 11:07:59 +0200
Message-ID: <87jzn44w0g.fsf@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jani.nikula@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b="XMx6/EQZ";       spf=pass
 (google.com: domain of jani.nikula@intel.com designates 192.198.163.7 as
 permitted sender) smtp.mailfrom=jani.nikula@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Fri, 16 Feb 2024, Kent Overstreet <kent.overstreet@linux.dev> wrote:
> On Fri, Feb 16, 2024 at 10:38:00AM +0200, Jani Nikula wrote:
>> I wonder if it wouldn't be too much trouble to write at least a brief
>> overview document under Documentation/ describing what this is all
>> about? Even as follow-up. People seeing the patch series have the
>> benefit of the cover letter and the commit messages, but that's hardly
>> documentation.
>> 
>> We have all these great frameworks and tools but their discoverability
>> to kernel developers isn't always all that great.
>
> commit f589b48789de4b8f77bfc70b9f3ab2013c01eaf2
> Author: Kent Overstreet <kent.overstreet@linux.dev>
> Date:   Wed Feb 14 01:13:04 2024 -0500
>
>     memprofiling: Documentation
>     
>     Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>

Thanks! Wasn't part of this series and I wasn't aware it existed.

BR,
Jani.


-- 
Jani Nikula, Intel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87jzn44w0g.fsf%40intel.com.
