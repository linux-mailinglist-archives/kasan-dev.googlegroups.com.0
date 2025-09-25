Return-Path: <kasan-dev+bncBD53XBUFWQDBB36G2LDAMGQEMZEJRHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id AAA60B9D15E
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Sep 2025 04:05:37 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-424c8578d40sf5520145ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 19:05:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758765936; cv=pass;
        d=google.com; s=arc-20240605;
        b=csYQU6B63Shd6kRqc+DPlUWHUvmJZ6tRPPS4Ls8PnEJuR8YLA5wa36qqK7j2CZ3tay
         IABvDkB/YbAPs6TwHABpTQMT1pWhvBz5sPlS8rNcZvpAu/+MqQPviJ9R5ooCSASuBO/A
         XwvbrBz7nMKwL3dk2eyfAke9v9YrYNv3zZSqLvujwKQYeuI+9dNo7PXS4/cVJV9tV7QQ
         j97lC+FSkVUDULSKPhDEqO+I5Zb3yWJc0EisXkj78MXF+uNDaveywLrevCRQvpQhIe2r
         s6mdj6D54DQxtbMndZ7j4lSiqgstHUywK7etn/UmsmzZuPpfjoaA7gWbzxcEtISZ/1cc
         4vaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=tM6BqKkw858dGGyFDOgwSTfvb+M72IDHYe8pX8ub59Y=;
        fh=T5lKtchLo/l1OAxKsL3updSWHp6vuUTOqkQ2oKSluRE=;
        b=TJcDhHPBV1qpQmqp+BFpHD38lVa1qq640T05+wnkXsiiUKNg349WHrh1AmfBH92ZtS
         zZKmJlgE/vibldy+wiIgDRUDnRPbulbRjUkdoieVl3/jgKstkvEsGQL1TIrje3HWK7eS
         Jh/OObS/VDUP9Lfb4fGWU0Ve7gQ8IvM6h5UljevvOHX2C8Itzq/5diNE8lFSpJRZDE5W
         2XsLVOuL8JlIY4lSMHHnYNnNz7bloSh9XXU/vutUjzHyPR0eLzHkkcF4rTm8StNWEPp+
         aIScZEcKML4LN/0YeDg2XUArIpIRoEquSjhhRzWBOpsLyKefiLTUcox25fg7V7KjTqwC
         xvHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mSsHa6Js;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758765936; x=1759370736; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tM6BqKkw858dGGyFDOgwSTfvb+M72IDHYe8pX8ub59Y=;
        b=IYt8vjNhAsZS6uMPpzR1V93Ju03vs6fML2X+RJFmXa6yYXDfyNsUpgcHQJh0sEpHrv
         gQJiYxOArcKU+011cMNSgbn47t0YWU1O2ep1b1mJdsg3sxNDG+jI0SISD8b9VoRoy9YV
         LcMmhEcc8LPblIXcTZy3zIRo6bKwIhWa0E54PWTEBouXaJtykc0wo/2MuE29DxJD/m/b
         fsjQMy3XfuY1k6JBHb7XwoyBTbO3ZuegF9U973nc7DSwtrIzR8Atmbps46MIjhjdMROd
         b/sjKy2wEF6dDEsdOlYevBz9LC0M3mmTDoxBvR1ORzifZaG9tKJr+VlEc96sqRp0+0WE
         Qm9g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758765936; x=1759370736; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=tM6BqKkw858dGGyFDOgwSTfvb+M72IDHYe8pX8ub59Y=;
        b=TE2rxMlALf9e8QBkoh0DuGJ14mJ205yDkND6z+mN/hpthaVX4xZJMXDe2L4N3nbUGA
         ZpC95j6H8d4BDU/T3E3HEAdsWO7yMLAAoc3IK13CSgop6EieiM60b4m5v+Nu0HLk/eqI
         V6ikMYN0USraUjtP/o325QZxsRn7gUGy8VeH4dQVZ9nKGTlshrSV7kM2jgorvxwZeqpA
         Z7mWxxrlmIGXrqDKOiw108aUaqWHsJuHH87DuFbTOkOpQApcfKK7AT8ECVl2xviI/4m5
         JGBBpc7N6cq+UZ4/hIN8zBC7Dowv/gvXPdpyJaxl/+5jtnvdBylEZRnu5iMZTcSXjtHu
         cVIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758765936; x=1759370736;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tM6BqKkw858dGGyFDOgwSTfvb+M72IDHYe8pX8ub59Y=;
        b=REuLRbXfVQM1z8XToNPQokDFEmGH+xqIWFFSR2ptl1AvVH6mTWAOZrf+FIKZHrVkZS
         XS1QSgtzIf0O1wQrIxZx8q4k0eU5Lhfxu+M6923Vz2rLvmngfVZqEkrabxY8ek/QpHoM
         RU5DegiojA5obhfKzL8lH4sm7+VamawPnAstN5YQsfa+bmkP2riSoGqVlubI2eHmHvR4
         wDco+97MIbLihMgRK+ieJNCq85r7N+trSIkwQPJmsntk6cp+n4dbn5csEP7IHtK6OvFV
         /afgBjZIBHAZCWHy9nBl6rn/fH2ZrlNx27FHt/8QsBRYT2edWxVWTp7Kx0fQr4vU3Wl0
         a/cw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWnhOeLsglehr44yUgCDDIZNl6J8U4VsBUqjT66mzpcscDvbpPyw0wUOz9MwUzkfWsjppC/cQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw8Wd7FJLDrmy1EzInprV8C6oFwozQrDoQBqVoyaP5RTl6KwzJJ
	GjVGUH2oVKTPwXfrZUkfkNk1uwrbbYep00VNL/JF7nSTpOPq0p3Ak2WO
X-Google-Smtp-Source: AGHT+IH2jb/kcvpOSyB6fw5mnP6F5xuiSMUDJU8QOKb5MZJ6+tIKXo4BG51a6ZgMWPPoUliM032AWw==
X-Received: by 2002:a92:d342:0:b0:424:8c2d:ca43 with SMTP id e9e14a558f8ab-42595654ed3mr23830585ab.29.1758765935923;
        Wed, 24 Sep 2025 19:05:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd716nBKh1K1+YNBCfjTEHkeQBfEQUN1nScO0QfDH7tPCw=="
Received: by 2002:a05:6e02:480a:b0:41c:6466:4299 with SMTP id
 e9e14a558f8ab-42595644bcals3855945ab.1.-pod-prod-07-us; Wed, 24 Sep 2025
 19:05:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXjljhr+7C03ewo151X0xxQqLFaUj+1+FhWgPwTPrGqElQyTpRURiHU+wPaHb8xD2Vz+ZZASHdNqUA=@googlegroups.com
X-Received: by 2002:a05:6e02:b49:b0:424:8120:546 with SMTP id e9e14a558f8ab-4259565853amr29268105ab.32.1758765935023;
        Wed, 24 Sep 2025 19:05:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758765935; cv=none;
        d=google.com; s=arc-20240605;
        b=CPGrThV6M9f6MAEDboRK75f6BpES51du/gteqAY/EeABmYrTaKuiIgtTWQhOQlyjbp
         Yg3Fo756vURtUdx5xJN/D+u2outkcL/9b3E4Gf29tY8rreuzDv6RBfyZQLRwMxlrF1Of
         29Ke4DZm9k/MPt8qRbidnFzZAJvPDszNCfMJ41HsUCUUWnvLtHL+KMb70Gzr1gm1dnrz
         WlqnmUPw9O1flHfwtLH6EcZhXL6tqZO1MRTVxxhNR1mf6HcvltHyl0J5fdmB4VXWqzcp
         KFM8alnicFwjjNKt2IdRT3gHDZh0sCrylW6sg16p/75I163wNiqoPf6E5v2g9vYgB5/H
         imwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=JHHL33LsFFZTfiqVPHubJTFh9Ll2HmMvlyBTNdInq0Y=;
        fh=a+nwj7EePsV9rUCx+BPYddSRrCno2ZatX8LHRiP6pGM=;
        b=HfdHsU+1Dr3jweqLvKMHFeV/XkJvKdVIg4/Js1c2Bh4RR/+HHFc2ucaf1J1Sm55p5N
         W97avq1r0DTIRgV5nwibwi5fy111QZKZ7kAl5ueiEcMoXwOfjjVpYghhPSYSY+d2zL0O
         C578hCUaAsQaGst5KGsX8jVhD2Pq70vMkT9OMPEtMUqc1iXPRjJgNhClBTu0TlG2ttmJ
         H0HsUlmdeIAvAT1C/bW6sXeaZO6qEMGe8CH023eLVi1bC9JzkQE+pYmSMhSfR1L6jCU6
         3QcTYbOJoYOuZc1sXegqEL8rWSUQ4ktw7RrPjB37SnMwe+iGf2dp+l9HDKQsNsn4/OUU
         +IaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mSsHa6Js;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-425b9038e16si415255ab.0.2025.09.24.19.05.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 19:05:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-27d69771e3eso4134635ad.3
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 19:05:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUSrADyc7Bh2KaA91Eg+70o9GMUdpm/37iHsei0GmYplUgQjzQMuUvIPvOngd2VRjzQRZbZc2twn5g=@googlegroups.com
X-Gm-Gg: ASbGncsx2JsZOtYDlv5ISlc58o7f10a3JSgaUwZR45YTjEfa9OJXZCNjRHILHO8IwRs
	x4AEqCcTQqIDF5wrJk0v8W46Iz4bTcMiMewjP39rOac/fp+zCPctF6DsOylcqEhaT8Dxg6zj4Yn
	NzpRpgdEnxvKdJPafPNpPAiH2PZW0WnhlJruMkwAYNCXy0YDvT00Ct7BzVlLFjygQOIRBa13m4Q
	E/x8jUIe/yNIOJjVD1YtpbiNXz00ZCIVHAjG6IzyzTk+n7W3Eq1yLejfuuP8pAr7SijBJ+GrJQY
	7AZrhZo/0BPo4rjxqULq9AfufAEn0DtJth+9jeLIZlhn3PRphJGS/HZO5vSHx4EtSzrCawbZ1bz
	XBE5232rOz1oRbuK4wZqOjlD7WAOZerzY1A==
X-Received: by 2002:a17:902:d50a:b0:267:da75:e0f with SMTP id d9443c01a7336-27ed4a06dd7mr20974665ad.11.1758765934070;
        Wed, 24 Sep 2025 19:05:34 -0700 (PDT)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-78102c26faasm387777b3a.93.2025.09.24.19.05.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 19:05:33 -0700 (PDT)
Date: Thu, 25 Sep 2025 10:05:22 +0800
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Randy Dunlap <rdunlap@infradead.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>, Rong Xu <xur@google.com>,
	Naveen N Rao <naveen@kernel.org>,
	David Kaplan <david.kaplan@amd.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Jinjie Ruan <ruanjinjie@huawei.com>, Nam Cao <namcao@linutronix.de>,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
	linux-mm@kvack.org, llvm@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, "David S. Miller" <davem@davemloft.net>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	linux-trace-kernel@vger.kernel.org
Subject: Re: [PATCH v5 04/23] mm/ksw: add build system support
Message-ID: <aNSjYrXXO2BjYA87@mdev>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
 <20250924115124.194940-5-wangjinchao600@gmail.com>
 <3504b378-4360-4e55-b28d-74aabd4308d7@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3504b378-4360-4e55-b28d-74aabd4308d7@infradead.org>
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=mSsHa6Js;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

On Wed, Sep 24, 2025 at 10:06:10AM -0700, Randy Dunlap wrote:
> 
> 
> On 9/24/25 4:50 AM, Jinchao Wang wrote:
> > Add Kconfig and Makefile infrastructure.
> > 
> > The implementation is located under `mm/kstackwatch/`.
> > 
> > Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
> > ---
> >  mm/Kconfig.debug             |  8 ++++++++
> >  mm/Makefile                  |  1 +
> >  mm/kstackwatch/Makefile      |  2 ++
> >  mm/kstackwatch/kernel.c      | 23 +++++++++++++++++++++++
> >  mm/kstackwatch/kstackwatch.h |  5 +++++
> >  mm/kstackwatch/stack.c       |  1 +
> >  mm/kstackwatch/watch.c       |  1 +
> >  7 files changed, 41 insertions(+)
> >  create mode 100644 mm/kstackwatch/Makefile
> >  create mode 100644 mm/kstackwatch/kernel.c
> >  create mode 100644 mm/kstackwatch/kstackwatch.h
> >  create mode 100644 mm/kstackwatch/stack.c
> >  create mode 100644 mm/kstackwatch/watch.c
> > 
> > diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
> > index 32b65073d0cc..89be351c0be5 100644
> > --- a/mm/Kconfig.debug
> > +++ b/mm/Kconfig.debug
> > @@ -309,3 +309,11 @@ config PER_VMA_LOCK_STATS
> >  	  overhead in the page fault path.
> >  
> >  	  If in doubt, say N.
> > +
> > +config KSTACK_WATCH
> > +	bool "Kernel Stack Watch"
> > +	depends on HAVE_HW_BREAKPOINT && KPROBES && FPROBE && STACKTRACE
> > +	help
> > +	  A lightweight real-time debugging tool to detect stack corrupting.
> 
> 	                                                         corruption.
Thanks, will fix in next version.
> 
> > +
> > +	  If unsure, say N.
> 
> 
> -- 
> ~Randy
> 

-- 
Jinchao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aNSjYrXXO2BjYA87%40mdev.
