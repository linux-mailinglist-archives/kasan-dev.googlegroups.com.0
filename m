Return-Path: <kasan-dev+bncBD53XBUFWQDBBPGH2LDAMGQEHXSDHZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id DA3CBB9D176
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Sep 2025 04:06:54 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-33428befd39sf891119a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 19:06:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758766013; cv=pass;
        d=google.com; s=arc-20240605;
        b=KxlKWkDjg2wfRF23Bc99UhiuoPRsn7WrhAQWOGKEMb8YY8PLhrTtQnLNqaDbOZnFcq
         73fWZQE6WHU2TETITiF4SnGcFNU0xXq/cusE2VJEQqqBTbS3WV+4zFxlqct7Ean3+e17
         kkFgHSBSIzKksKQVPVktPoCHQQabggQf+80jqnGA7P/50wacCo4MSxhwZGt2QsMMS0Ws
         6/g1c/fAlACq37LvSAqXqXFdrN6Y5B7Sw0CQXuKscR271rZHM9rz01rqO0emDWtntaVl
         TzvdPlo3oWYm+Emzf0h9jzQw/qoLfBE20SD1esS7XzoJrGFMw2K1a//14MjdZwg5KuP3
         prHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=lQTVWck9xXHgsfqnYgYTYnUbCR/0dXVKpaQHn30a6AY=;
        fh=Ad2/Tviij2oC9mGOXCfnWUynf6K7hXl1ijO/2ti/gnk=;
        b=NnYSwGq8tl5bQpM138hrmFtIdku1J1CXHpjCqeYKDHPvWRt8xzZmJ6GOoru9j7F0GY
         S5rl9s+ulZ7WU7xCb3aGySLa3lRgvqaEl/hFA5zNbU7l1NmJdekif0Ohxf1ApADM/V61
         p5xce0Ogyf/ChE52uD6Ar/yOtESgfenN3Pkh/pJAFzEFHXgr4Xunsz6NSMzCV7o/RgIf
         jXSgjaWgaIAkPKjV9RCIkPgr9TCVprn5anofxvxneBRCItcyN28ISuJaLv9QO01QSyi6
         wuYH+VMnnD8vxXOlOy9TS9LE0ERk/hATAWGCXoRvPI0Ut8ChASRrfBxwfm0GZexhr+uH
         tWlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GQeFvECO;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758766013; x=1759370813; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lQTVWck9xXHgsfqnYgYTYnUbCR/0dXVKpaQHn30a6AY=;
        b=CEq7mY+UYnl1UQoeWECE3QoN99wcf2FWA5QLn8q5WUfXP3ppjauWIB/2rR/EZcYJM4
         fSPtJ73Hs0MfZQGR8c6Y3xNj3xLOa2qCVh5z5ka8cQ1mIwYDM3Hr7OiE4O3bnh26tAba
         6qR33Y4caJW9+dkxOTj2oUvPuruk8r3kcRncn25FCtYb8H0q3BbGU1jk8n+SkLWluk1l
         pNmouXdZ7FASlFniih3puj/LjfzOYU9G7i3xPvTqf3k/rGRuthKMQxMPWeJj0U1PMuy2
         Q3pAEAJ49pJxJqs4QYMLZw5mgSQF9OX/LxgHK8kHErr4UGmL2do4BM/jZFPT32x0EYVU
         7pyQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758766013; x=1759370813; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=lQTVWck9xXHgsfqnYgYTYnUbCR/0dXVKpaQHn30a6AY=;
        b=EwjN5nKb42/twBQUewzu1SfS1qpPXbkauadzH6qsuqKpxWBf61ndrN45+EEDRbndWu
         GHuq5PbW5TEcRJKaEhQ4WFuD5Iy190iK1D4BdLC6IfSYjX5vtjwGPgOCUxmsp58Ka3St
         jSWxfYnMJO1qvh+qbzsM2HE7VICBbT6jw9jxlc5HIxq+rOWVmJtjJaf8Ex1tSO2jZJ5W
         CDBP/M+AhOzCkKOhQ/nqBSwKdj/yyTXDzeVUfLDu5eJidKFwIVptQMp7vRiNXd/PPDg8
         qyFlo1Rrkt7BmW4GU+MbcKM5NGRq5H8Yw38Z0HZ3rLbr8X0BznpwsJQ89QX4PJDfm1+6
         Lq4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758766013; x=1759370813;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lQTVWck9xXHgsfqnYgYTYnUbCR/0dXVKpaQHn30a6AY=;
        b=SXv7aG0g/OEf03+D5VXnujwG7tFQwFanb7wYsCGtvEjd2EUKd0vrgopC/ITqREKHgN
         +aYXOPfs6viOGvLjwMMfMgXNvaiGpfxhkuYiUuiZPuOSapUtLFbBMc48d+ec1S0/UoU4
         me7MRgVAvhDQ9E8drBQ2k4fN2uKE15Hmi9+HHNXFRQ6aazOB7uROTky4uupg6IaX4H68
         AAlEvuafrcmml6bLPh4JwgwTIyfeIcm0qvsJEgO3F/I7xWTrLSi+wrd4+IX23gHHF9MZ
         vcOscBHg5crRFpOCOUhFGIoV4fDKkeSEeSJlkHYk1YTywKUmP7LRA6hFZoQ8/0Fa4H7l
         3L/A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCViWkAREgi9tQCD/hxYEly0D/1u0Tvud2pX76jcCZyD3wbomtHpRaiOjyFD+otg/UmqISYuKQ==@lfdr.de
X-Gm-Message-State: AOJu0YzHBHzg2KssCkw+7kV3u0ZIfCa3kohxU6SNNmXJRBRfkHEjwBpF
	vnqo/s6xamqhzb6+6wXxR5JhlXOo1mv2eY2dzk9s6q7jteEX1MwkzXuL
X-Google-Smtp-Source: AGHT+IGmREiyElYi4TxS/Vwi8AeD9ykRVbqhRysxgngDEYs+SiSnuw1eLX5Gdsyhht3N/u6J178veg==
X-Received: by 2002:a17:90b:1d86:b0:32e:dd8c:dd2a with SMTP id 98e67ed59e1d1-3342a17c192mr1852918a91.0.1758766012877;
        Wed, 24 Sep 2025 19:06:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6st9I1KX3glT8dSZLezu2R2q3jUJZ1qvyop0gt/dQgrw=="
Received: by 2002:a17:90b:3d48:b0:32e:ddb7:ede6 with SMTP id
 98e67ed59e1d1-3342a5fd60els727528a91.1.-pod-prod-08-us; Wed, 24 Sep 2025
 19:06:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVj89V0HsydWWDaNPrTLsxSaAMfsXPTKJ3AM7ZFmvAKZu9aQ82zdqeuGq6omNruZ2hFkNIJvsJtvas=@googlegroups.com
X-Received: by 2002:a17:90a:e388:b0:32e:4849:78b with SMTP id 98e67ed59e1d1-3342a28229fmr1520258a91.16.1758766009623;
        Wed, 24 Sep 2025 19:06:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758766009; cv=none;
        d=google.com; s=arc-20240605;
        b=QeMKTsIX6K8GOrU3eGrSOitca2FNbAuoCmdA2jUzUpuGW30/g0PdIFCU00HGssyg2S
         n5T72FU/OS0z4sJZxOxAOTcHw+Ov/OqO0lxIv2Ihs5p9zgyovOuLeo4OyRnpOkyShVOI
         +x/9skhxnlmU3FibaJr48bSynYQm6E0y/5WOvA5NJB04ZGUBwGO5eI6oFSFOKqv9HaQA
         sMsOLNygxR7n+HKNbgxZghlxJAMYP2O3xBvk/Ib5IPFp/Wt4eLjqLLiJPb2hW+sic1/m
         naJ+ysg8eFRoH+7IAd2jCM2DmlJkD/Nn6CykqIWDJvH7KF/+TLyjL70b4Baqy0tdNp3Q
         eUew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=TDDNQxOCofAWfoIkXGgKX3OgUnzUt3+cN5qe0WBH0Fk=;
        fh=wM57bMzMt3cR2EulihRhQFn8Gn7FwsvPyakBG+85VT4=;
        b=DPBzXbCmd+zvI5s4UUlDY5RD33xe9OBLZJ8M21Y+W0fr8IrfdgXon+VP9OcaMXMTrv
         4U8R2+eOT4/2jlxzOZT+mXK/dPfu4J3QLDIdaVUJnT4juXKU+lji5xhbuJFLSIDT4Fbx
         JUkL4xXtt1gp6Cw8Vjj6Z6PzRgZp1qN0rJr+UDjVUojDsF1E6mZxRdA0J4eL1wJo8OvE
         wDOi2eK8JIb67fF5gyRqU7drqGSJiG6BWcI5bQOZ6w5S3D29BzTlesJNhtmW6mefdjfN
         1h0L1HzVoORrNYzRit4Npw3FFDsIdwixEax15reI+8C4g+jVp1YLq39pXG/1tLe3h3Gl
         ekRA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GQeFvECO;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-334314f0348si51148a91.1.2025.09.24.19.06.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 19:06:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-b54dd647edcso437519a12.1
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 19:06:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVfPncKhklEgrKxEtF0n8syak3ikdOPqMnWDWULwSLcJV6H8lnaH56vT7lGPhjKVe+jBJbNL4arJxI=@googlegroups.com
X-Gm-Gg: ASbGncuF6MwaQ4HjLOxlQOCbQP4bif/oY/FQq50G1/c+hhf2nN5fy5EvdbFDPrThk1A
	oKcEL/y6/H3IgT8itd7MxAMq1UD3O/2QkSyT1XI6p+Snv24nfpeQyw0xgaXQoNsrxlM3ZMlEKUC
	ge9bnHf4k5JmZz8sKz1CDa8z40fmiCAG1l7DWECQyiCi5xF61ZbGJGl/hv8j9RTZtVwXKub4TVT
	pF1ye8g9RcMBdm7z4gsaaYRxpJFraQ7bL6eheCllgGTsTlNca+t1aCLFwTxwq5d/NM+W9FuDFyw
	tHnlSepXRvPVI9LZxkVOmIWc2KzrXPWwKjKFHxSz4bOumiOPV/oX0Mm6XIb2g/lt/mCOMdp5jUh
	6ZzjPL/0BnRultzrmw+rDe9g=
X-Received: by 2002:a17:902:f54c:b0:271:479d:3de3 with SMTP id d9443c01a7336-27ed49c7763mr18733235ad.12.1758766009065;
        Wed, 24 Sep 2025 19:06:49 -0700 (PDT)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27ed66cf181sm6940845ad.28.2025.09.24.19.06.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 19:06:48 -0700 (PDT)
Date: Thu, 25 Sep 2025 10:06:44 +0800
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
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
Subject: Re: [PATCH v5 17/23] mm/ksw: add test module
Message-ID: <aNSjtMdxZXdhgPRA@mdev>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
 <20250924115931.197077-1-wangjinchao600@gmail.com>
 <20250924115931.197077-2-wangjinchao600@gmail.com>
 <CANpmjNNnVx3=dQsoHL+T-95Z_iprCd3FXeYpnHdmi4d06X-x_g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNnVx3=dQsoHL+T-95Z_iprCd3FXeYpnHdmi4d06X-x_g@mail.gmail.com>
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GQeFvECO;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

On Wed, Sep 24, 2025 at 10:44:50PM +0200, Marco Elver wrote:
> On Wed, 24 Sept 2025 at 14:00, Jinchao Wang <wangjinchao600@gmail.com> wrote:
> >
> > Introduce a separate test module to validate functionality in controlled
> > scenarios.
> >
> > The module provides a proc interface (/proc/kstackwatch_test) that allows
> > triggering specific test cases via simple commands:
> >
> >   echo test0 > /proc/kstackwatch_test
> 
> This should not be in /proc/ - if anything, it should go into debugfs.
Thanks, will fix in next version.
> 
> > Test module is built with optimizations disabled to ensure predictable
> > behavior.
> >
> > Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
> > ---
> >  mm/Kconfig.debug        |  10 ++++
> >  mm/kstackwatch/Makefile |   6 ++
> >  mm/kstackwatch/test.c   | 122 ++++++++++++++++++++++++++++++++++++++++
> >  3 files changed, 138 insertions(+)
> >  create mode 100644 mm/kstackwatch/test.c
> >
> > diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
> > index 89be351c0be5..291dd8a78b98 100644
> > --- a/mm/Kconfig.debug
> > +++ b/mm/Kconfig.debug
> > @@ -317,3 +317,13 @@ config KSTACK_WATCH
> >           A lightweight real-time debugging tool to detect stack corrupting.
> >
> >           If unsure, say N.
> > +
> > +config KSTACK_WATCH_TEST
> > +       tristate "KStackWatch Test Module"
> > +       depends on KSTACK_WATCH
> > +       help
> > +         This module provides controlled stack corruption scenarios to verify
> > +         the functionality of KStackWatch. It is useful for development and
> > +         validation of KStackWatch mechanism.
> > +
> > +         If unsure, say N.
> > diff --git a/mm/kstackwatch/Makefile b/mm/kstackwatch/Makefile
> > index 84a46cb9a766..d007b8dcd1c6 100644
> > --- a/mm/kstackwatch/Makefile
> > +++ b/mm/kstackwatch/Makefile
> > @@ -1,2 +1,8 @@
> >  obj-$(CONFIG_KSTACK_WATCH)     += kstackwatch.o
> >  kstackwatch-y := kernel.o stack.o watch.o
> > +
> > +obj-$(CONFIG_KSTACK_WATCH_TEST)        += kstackwatch_test.o
> > +kstackwatch_test-y := test.o
> > +CFLAGS_test.o := -fno-inline \
> > +               -fno-optimize-sibling-calls \
> > +               -fno-pic -fno-pie -O0 -Og
> > diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
> > new file mode 100644
> > index 000000000000..1ed98931cc51
> > --- /dev/null
> > +++ b/mm/kstackwatch/test.c
> > @@ -0,0 +1,122 @@
> > +// SPDX-License-Identifier: GPL-2.0
> > +#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
> > +
> > +#include <linux/delay.h>
> > +#include <linux/kthread.h>
> > +#include <linux/list.h>
> > +#include <linux/module.h>
> > +#include <linux/prandom.h>
> > +#include <linux/printk.h>
> > +#include <linux/proc_fs.h>
> > +#include <linux/random.h>
> > +#include <linux/spinlock.h>
> > +#include <linux/string.h>
> > +#include <linux/uaccess.h>
> > +
> > +#include "kstackwatch.h"
> > +
> > +static struct proc_dir_entry *test_proc;
> > +
> > +#define BUFFER_SIZE 16
> > +#define MAX_DEPTH 6
> > +
> > +struct work_node {
> > +       ulong *ptr;
> > +       struct completion done;
> > +       struct list_head list;
> > +};
> > +
> > +static DECLARE_COMPLETION(work_res);
> > +static DEFINE_MUTEX(work_mutex);
> > +static LIST_HEAD(work_list);
> > +
> > +static void test_watch_fire(void)
> > +{
> > +       u64 buffer[BUFFER_SIZE] = { 0 };
> > +
> > +       pr_info("entry of %s\n", __func__);
> > +       ksw_watch_show();
> > +       ksw_watch_fire();
> > +       pr_info("buf[0]:%lld\n", buffer[0]);
> > +
> > +       barrier_data(buffer);
> > +       pr_info("exit of %s\n", __func__);
> > +}
> > +
> > +
> > +static ssize_t test_proc_write(struct file *file, const char __user *buffer,
> > +                              size_t count, loff_t *pos)
> > +{
> > +       char cmd[256];
> > +       int test_num;
> > +
> > +       if (count >= sizeof(cmd))
> > +               return -EINVAL;
> > +
> > +       if (copy_from_user(cmd, buffer, count))
> > +               return -EFAULT;
> > +
> > +       cmd[count] = '\0';
> > +       strim(cmd);
> > +
> > +       pr_info("received command: %s\n", cmd);
> > +
> > +       if (sscanf(cmd, "test%d", &test_num) == 1) {
> > +               switch (test_num) {
> > +               case 0:
> > +                       test_watch_fire();
> > +                       break;
> > +               default:
> > +                       pr_err("Unknown test number %d\n", test_num);
> > +                       return -EINVAL;
> > +               }
> > +       } else {
> > +               pr_err("invalid command format. Use 'testN'.\n");
> > +               return -EINVAL;
> > +       }
> > +
> > +       return count;
> > +}
> > +
> > +static ssize_t test_proc_read(struct file *file, char __user *buffer,
> > +                             size_t count, loff_t *pos)
> > +{
> > +       static const char usage[] = "KStackWatch Simplified Test Module\n"
> > +                                   "============ usage ==============\n"
> > +                                   "Usage:\n"
> > +                                   "echo test{i} > /proc/kstackwatch_test\n"
> > +                                   " test0 - test watch fire\n";
> > +
> > +       return simple_read_from_buffer(buffer, count, pos, usage,
> > +                                      strlen(usage));
> > +}
> > +
> > +static const struct proc_ops test_proc_ops = {
> > +       .proc_read = test_proc_read,
> > +       .proc_write = test_proc_write,
> > +};
> > +
> > +static int __init kstackwatch_test_init(void)
> > +{
> > +       test_proc = proc_create("kstackwatch_test", 0600, NULL, &test_proc_ops);
> > +       if (!test_proc) {
> > +               pr_err("Failed to create proc entry\n");
> > +               return -ENOMEM;
> > +       }
> > +       pr_info("module loaded\n");
> > +       return 0;
> > +}
> > +
> > +static void __exit kstackwatch_test_exit(void)
> > +{
> > +       if (test_proc)
> > +               remove_proc_entry("kstackwatch_test", NULL);
> > +       pr_info("module unloaded\n");
> > +}
> > +
> > +module_init(kstackwatch_test_init);
> > +module_exit(kstackwatch_test_exit);
> > +
> > +MODULE_AUTHOR("Jinchao Wang");
> > +MODULE_DESCRIPTION("Simple KStackWatch Test Module");
> > +MODULE_LICENSE("GPL");
> > --
> > 2.43.0
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115931.197077-2-wangjinchao600%40gmail.com.

-- 
Jinchao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aNSjtMdxZXdhgPRA%40mdev.
