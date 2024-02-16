Return-Path: <kasan-dev+bncBCS5BWNH3ENRBBN6XSXAMGQETZ7DLTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 33F258577C8
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 09:38:31 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-298ed31e228sf1107832a91.2
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 00:38:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708072709; cv=pass;
        d=google.com; s=arc-20160816;
        b=iyQebh6qEem8Y8MZwu1sYhTXTQ2rdCDtJgveOUoc4YidMtvACgeSwBC0DhueNYey2W
         SYpymrTbkJFy1939BG3FTBMR9OR4bO7A9h4gFqmOBYfUDCTqT8HwLJVhAsIeT21dtQmo
         yEfAujaplYRgbmBac6QA2snCnUKcmQ8s4AJXEaZrj+WPS2/TrE9KqDN7HsXQwAEvNH5p
         GtPzsHfF+jPLvqbKeYrjfwDaUAXY22bAsj8mjFUTmxB6prn8BXQsK98mFfUMgqSH3ANM
         NPJU7etNqO4N2+KF3lQ3YthBVWuesEhbCzqy8nep3ybJa8cZe33n1cg0mchMKT9fddVu
         WjYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:organization:in-reply-to:subject:cc:to:from:sender
         :dkim-signature;
        bh=5CVAAYqGk+rqvXXYWuuyLQk7ba4CbK9REj0E2x89lFU=;
        fh=qRs+vrZ8zUCg89Gkzc2FzXHYes7jOwS1AkSZiA3Q/+c=;
        b=EewqKxCqVJebwx9jtI8vwNqPyHNRVCImBGOpe8yZCvbeCiHdRz/YDBZp5vvTySUq8u
         yW0sRNsjbCGDbIreN36lb+guDVBo0YKx0YY4KL0Fe9NbRtZNU9MW54K/ngivCfMSPEzY
         QUU8ewJja/dExbgzgl8QrAJ13g6+6HA75cbtrY+y1C5uCjU2CYgXaut9c4RqBpBl49oJ
         fSJtfX69NGFl4fZ5nqTNWpN735GUCmpPeU5HSbVvdLz+rZ3rpoU3IhOQ7b105w503WJD
         7CJAhZGMTmNY/cEEzSkz9CWwWLKnx56nOJB1kPHPM+cLCLRauFsPlzc4CMs1EkTcbzT7
         ICpA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Cog6cQBn;
       spf=pass (google.com: domain of jani.nikula@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=jani.nikula@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708072709; x=1708677509; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :organization:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5CVAAYqGk+rqvXXYWuuyLQk7ba4CbK9REj0E2x89lFU=;
        b=d48r2mA1IuENaGhpIxREE3KKmGUaAn72D6fOgX3NOV+83nz//EQiePG2aO54rUKxXD
         po+rhlmoXHYP5TAyhM8zDTziBvdqrWKmV4i4wbykhCvGjsFoUdIOJa3HTsscz7U5i43t
         9W7f/iTdqP1P4yGraNn881PqWKGuyXT9hSkhK/LMzRMWgD2FnJVCJUAxHjnx/FE7JhL0
         RIWfAQGN5ctk95MIC4+FvSZFY2zmmUi23OKweeWDUIW0uspep/4WW4hWt6Ie4h61e94D
         ULmMOSTRp+5XBO6pbZ3RL+E7rvPTo6lqRnRiiOrr6gIA2X89z2Yd0+acvETDyA38LOeP
         q83w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708072709; x=1708677509;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:organization:in-reply-to:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5CVAAYqGk+rqvXXYWuuyLQk7ba4CbK9REj0E2x89lFU=;
        b=GVIfAryX9RBhUKmtRcNS83sjGhiTIMBg7vwCwYwWwXlFQ2thql/tg008AdhuXIEDhC
         csEIIG1f4J9ykE52Y8nJp1NlK9XjdP3PFikTxqFwLtJVnVieDeFVL83vLUe6LZ1uPaRG
         JcTm+cZjvFFzpEDDksczMB60a1plV87RIvBQp/1nVsIgKQ6HV/tH/kMXMtVCuIHAk8Hl
         ijwoqHtEQFi4z8iKieTjQWleVm1W/byWegZkOdcoqFdYY0Wh/jUF89UebHRWhHGYIkSH
         DRKiBmjpp1faGyqIxCJFqieFKwvyqLiLzDpaZOPNaNXSbVxzFmhKXNkKkowsuctZpqg4
         Zwyg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWft9Qa5qYCBuIKMsrycSxqrXzqMC6KD53as2gJ1C65ihV3JkpU5krhhWhOLOyfl214YS/Q2SlZzT1ZKyVs70/wV/pkQjUtAw==
X-Gm-Message-State: AOJu0YyKSrsHs+WrR9BZIJBbglchNSEZq9MEtfU/x3euJ73itC9+4XNi
	HrrdSeT0XAkJdodV7TA9IoPmQmfi3TxChJHgGmusT6SBFxrqbpWM
X-Google-Smtp-Source: AGHT+IFWTV9q2LGRrTZNJPIy3mEZpw2dirJ+QRNe9CZ3nYCqzSKxt49aH/E2qtZNyHdaldoCgO2V5w==
X-Received: by 2002:a17:90b:118e:b0:299:29e1:d0e7 with SMTP id gk14-20020a17090b118e00b0029929e1d0e7mr2793971pjb.8.1708072709485;
        Fri, 16 Feb 2024 00:38:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3d12:b0:297:2864:3177 with SMTP id
 pt18-20020a17090b3d1200b0029728643177ls347124pjb.0.-pod-prod-09-us; Fri, 16
 Feb 2024 00:38:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUfb39kGCRGYmh/PA9X7i4bue80OlUYELkSe6YA09SxThhXE9iC6gtCm4w5VYzrPNM0fYoGRxkEK9lb75qTvflwdm6eH/AeNqU/Gg==
X-Received: by 2002:a17:90a:69a7:b0:298:d65f:f208 with SMTP id s36-20020a17090a69a700b00298d65ff208mr4350655pjj.2.1708072708216;
        Fri, 16 Feb 2024 00:38:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708072708; cv=none;
        d=google.com; s=arc-20160816;
        b=bnVOzpperMvxfG8LZr49qzW2fZI0ujIzJ6tMwQ67mB2MBeuWMlZXbqCUqn4UjNS+b0
         jLFxJxyQtV1cIxGEH18irD3i3242BSnKEzggEQbVr+6Zv0u3+6VKCEHow9DJ8nu8SzZW
         PfvUDiwn/odvtKTlPX2St1tidjYgKGp0rAM/L0g0VBnsLERNmy7kvC3p/iAUMd9UrXiI
         IutNpdUsfHArzSzLMsNbIornqnXXLLR4JaVxzSczKpBTHfx1/8VQluSXXLl4TraJbEMW
         LDxKzGUkvc+OT+FfEEBOkk0uX+moTmuHIdl3WsmQN5ccNv6LNq5EMjppDoKTnUgS6eB1
         80vQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:organization:in-reply-to
         :subject:cc:to:from:dkim-signature;
        bh=TX4bvbcO7qOs5Hovh4GeuvoihJmdj20LCeKuDIZoRKA=;
        fh=WZNRCURZhgNosWw2Wvm5MmSH5/7GXoi1FHSqo4VjCNo=;
        b=LzjvLWBOBKY0Cnb7Xfg3s6kllCrgekGm9jjBoKqU4br4157RwFAvKQxzFsEzxJU41q
         kWGeICMXJIIBvU3Y+LRuiokTvlJ94iuDZjCUNI4QKDPLpVyWqWsfRP7a+uGu2LnO2YKq
         f+Lk4biUVz3dv5fcoNynwDCc2t2qLSl5jfZm2Td8dJE2kbiXMJuzXJI43OjJKNFj3hZ+
         950eH0JBV1vdURNDdvRR0lbLFlmNsCsPpkf5oFEei+omxwkV6sHK3CKDQMPXH5p1vEuY
         IPOhYIFIIb4ExEFSrcRsMTWpJIkhrREgW72EoBIWu/usv58OfzBrZEWF5rGLTwdYgvO2
         61Cg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Cog6cQBn;
       spf=pass (google.com: domain of jani.nikula@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=jani.nikula@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id o21-20020a17090ad25500b0029933281f04si75070pjw.3.2024.02.16.00.38.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 16 Feb 2024 00:38:28 -0800 (PST)
Received-SPF: pass (google.com: domain of jani.nikula@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-IronPort-AV: E=McAfee;i="6600,9927,10985"; a="2063353"
X-IronPort-AV: E=Sophos;i="6.06,164,1705392000"; 
   d="scan'208";a="2063353"
Received: from orviesa006.jf.intel.com ([10.64.159.146])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 Feb 2024 00:38:27 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.06,164,1705392000"; 
   d="scan'208";a="4144870"
Received: from pshishpo-mobl1.ger.corp.intel.com (HELO localhost) ([10.252.48.79])
  by orviesa006-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 Feb 2024 00:38:04 -0800
From: Jani Nikula <jani.nikula@linux.intel.com>
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
 arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
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
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
References: <20240212213922.783301-1-surenb@google.com>
Date: Fri, 16 Feb 2024 10:38:00 +0200
Message-ID: <87sf1s4xef.fsf@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jani.nikula@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Cog6cQBn;       spf=pass
 (google.com: domain of jani.nikula@intel.com designates 198.175.65.20 as
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

On Mon, 12 Feb 2024, Suren Baghdasaryan <surenb@google.com> wrote:
> Memory allocation, v3 and final:
>
> Overview:
> Low overhead [1] per-callsite memory allocation profiling. Not just for debug
> kernels, overhead low enough to be deployed in production.
>
> We're aiming to get this in the next merge window, for 6.9. The feedback
> we've gotten has been that even out of tree this patchset has already
> been useful, and there's a significant amount of other work gated on the
> code tagging functionality included in this patchset [2].

I wonder if it wouldn't be too much trouble to write at least a brief
overview document under Documentation/ describing what this is all
about? Even as follow-up. People seeing the patch series have the
benefit of the cover letter and the commit messages, but that's hardly
documentation.

We have all these great frameworks and tools but their discoverability
to kernel developers isn't always all that great.

BR,
Jani.


-- 
Jani Nikula, Intel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87sf1s4xef.fsf%40intel.com.
