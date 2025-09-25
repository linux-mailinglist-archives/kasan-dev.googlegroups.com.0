Return-Path: <kasan-dev+bncBD53XBUFWQDBBY6H2LDAMGQEBT3K26Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CEB54B9D17F
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Sep 2025 04:07:32 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-78f3a8ee4d8sf9620576d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 19:07:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758766052; cv=pass;
        d=google.com; s=arc-20240605;
        b=JeqTY8PO+WASR7DiN9SM6uK00Pi8nDmgwKHNDHaLXz8J1eNPIH9Vt2DDl3Z1rvM1KV
         S3JlRITMwbncdOOwVcYoI6Q9pITeKGLZZJfLb9kn53ckTTRQ2NmDsa9LwI20KPpvAhMH
         9sDYD8JnjcPcxV4HMs1aAfwQWe9FHDXPCRe64NtUKCWWC15S8easmB/uxRn/SZTBweey
         FGO+vGwb+Q7qC3C03OgJ7okhuNkRM3P7VIQFRmHFHdWd4AMoae2CXGcu1Xj3M9r5Zcsg
         6UYTdov7gmxh5mw/8E6usxWKlgMHSE7Gvq/Yw2HeCFiao2a9BkZ5HNno8WEdA+BsQV8j
         Jdkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=IIPXnPL3lmz1og2TLPZwLY/ZgjtTN/4Zy3yEMRexg3I=;
        fh=St1tU5gPqo6iv0eZFTSqzKKPbvRmAs3HFiVHfUN9Vl4=;
        b=c+5h46tcrmTS2VYTwL91d06GhWOpqpdulnarwjb/RgXWqnLbH4u2k8aD92px4gUk8D
         mbCuIiRcqzwypvBuILbHrBRRUqMz3ne0BbQjZVUnSh+0FyqNpFdqs3js99Tm9UTQIXfP
         kaoNhhkXwdIWdMzamAaL6qoT171ShWJlXjq7zia/H5FlxA5sHGY+SDPM7M1cTRbkSGoF
         HVO1tpyvVNRYlcBGo2OGKnyS646havt3TZpgRSHX/TB36+vshbAoxhyxuf0THIjv+jpG
         KF5vS+guOFJ9wBasG33xYob6B0Mh2gkBKDzHwo1lTJfI97kUfhQGFqC4oEsh4oviNc7U
         VyrA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="dPW/ilIx";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758766052; x=1759370852; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IIPXnPL3lmz1og2TLPZwLY/ZgjtTN/4Zy3yEMRexg3I=;
        b=rA0JyuFejtEo+dzHLXSWOTs51B8jj0LuHyeN7YZ6VQ7keuG050VCTIIucafOfDpf6j
         bNNU/udNshGgnqUESa3YSs9L2dLnmdW6ZOPPgLmbo92YAyEj9IjD2jw1UptX6sJ1Faf7
         csBN2XNipKbMc6dXR1KcHEZfQ4aegyH9cmo9/GK2Le47MeJr2DTrvvTdPZSAp3C7LolE
         ldwdiDS9VcjM5jk5F5axY7BIk8cTxmIdg733eUA0otbyVTPVhfTjLtmKHzNuJEavyBml
         qW6liKcUuyxrIQd8t+kCqr/VdeDL1xH121bMpkFAZIJZTt+h3HK8lVgk+8BfcebtL7/T
         hVnQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758766052; x=1759370852; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=IIPXnPL3lmz1og2TLPZwLY/ZgjtTN/4Zy3yEMRexg3I=;
        b=nA8wBnb3iIBZa7AFh6kfZwF+NKWW9tGm7q6Jhoi1YqWaN6GsRjAR11lEpbWeEiWtAE
         BvNTHOm/dD7pRJl40fE/QRcFCikJWTYuvAinuDUUnydBbeFo/MaO/RlxmdLyDJLhTcBf
         9qYU9DyopYE8auH73WAbJkvQMchdiEadyyqUv6cuWa4ujXdzw9PLAES+HBs2xrwRIZSQ
         X3IUTSb5RuXoGOuY+bFZx0guLN6E9P9SCoaLfiLigPR8b54Xee/pkYRyEVRRsH2W5V3Q
         jaE79PdA3x4+HXyJdbjzzkTlDdRf10kDZ2a4F7Hw0CTjhoi8NKB/w0xNrGvWxx99ZvVX
         CXmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758766052; x=1759370852;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IIPXnPL3lmz1og2TLPZwLY/ZgjtTN/4Zy3yEMRexg3I=;
        b=nMVX+Wnwzv1QUOxn3tbYzjf/icMiLa4iVJdnQQBLimldy3bWE5/DJQwNd9KaPEBQO+
         PN+NhtmrBHUDiL9z2jcoYnD+nuX1Wav+TXJ+tgIIuiC2YoJB7uM5WQfL+kz2EaRaiIsu
         yl122oJTn41kvrNUTuJBhGs6e5avRM+4KMopHQyCjcmDcBFyBKoRQlAwK8Vl4bSBV9RI
         /POJV282+0Iq+5XAXYQBGcXHTvvcJXo8jUWAZ/17vMCQoX6aTb/abkkc2I9PLrI3FccH
         oqdcn8mRIY4rrjfyuzKrNKei2jmAq3CBQL6EsutRFRi7izTZ+cDF87DhHk6baYJhGcBv
         6pAA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUH+OgEdcl4ZR1iOrJ6uDiCar50MUb0+aQzM+UUq307UuagXcqlOsmkCCo0qpJoNZ9twOFIWg==@lfdr.de
X-Gm-Message-State: AOJu0YxqoLRbk/fmT9iB7Hlsl+vBWq6CSQMxzZlIvwnT8boP6R4EfrH8
	suD9trPfcYI5Q+YCaoSyPeFFcguf8BQ0KyIhAR5H1XheBjQDHFvAd3vL
X-Google-Smtp-Source: AGHT+IH6WuW4VtaOK+v7+WRKWqyGsaCHbvMiQ65AwobzwjPkO+h5it2qZ84cabgdU9ds6SE7+xzcXg==
X-Received: by 2002:a05:6214:2521:b0:710:e1bc:ae42 with SMTP id 6a1803df08f44-7fc2c8a4793mr32458576d6.10.1758766051681;
        Wed, 24 Sep 2025 19:07:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6SocGyBuuv1cW094KuKUmmxF5gIQurXZZL3Ko+g+opPw=="
Received: by 2002:ad4:46c7:0:b0:70d:b7b1:9efb with SMTP id 6a1803df08f44-7fd7d047137ls9920846d6.1.-pod-prod-07-us;
 Wed, 24 Sep 2025 19:07:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8H5Ex72Xh4Lt4s5o0P7rh9qd406Nz3LhpxGkyQ8ypiiglmaSC4zANoL29AvZmUpks+4L3CLYMlSI=@googlegroups.com
X-Received: by 2002:a05:6102:38d0:b0:521:f2f5:e444 with SMTP id ada2fe7eead31-5acd4636144mr1097024137.17.1758766050799;
        Wed, 24 Sep 2025 19:07:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758766050; cv=none;
        d=google.com; s=arc-20240605;
        b=JyNdZxc9nj/gsNmYwgdJwDHDS/NdfgOF1UTgJsmpMWRkspnSJLhxLqn9QWzd3kfVEl
         XIbIkqWv+G0mX4mUoh9Gzh4idlBNseaIGCL98B9praPnnRdbaxQppFjVXZTSs4LtEoQt
         sm/sYR5YBq0vYQpBHyuDpnZwtMaYN5xhj+ShXq1qyrfPHEf49opsoe3Yo+7L+65QN8h+
         Z6tBqTooDEMroEoBltrnqXAmjU3D+YDvCz/BSziN7xkwOu5UaMMldzosqcQ3toip8q8B
         oF1p43Wbx/NZyX0872XZRIULFgkLNvO0KKlAEAXQvThAUj+3EyfbCr7XV+00CaL20KQX
         7mRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=z3v0KAw/a5VLZK8q/426U2Svx1Ly/zqTFJD1qMEvdMs=;
        fh=ArECCwxK1S0JuuJ/GNw9CGBX/BkvPr9ZOvgKvuXTh18=;
        b=EREnx3uYJ3Wp4BpbLYiUjKSBwLUmcvGzh5oI07cKiTWXuTn/GUIc9fN422uKgN32MM
         YBVqY2ZD1VN22Tc8lP+2MhDWyZI/8iMk3yiLaOMWcCJK/xWPfe6qsq/Si7aK6LXdTvLb
         Oe8asrtrPPkj/p9maDa4zjB9TdSzQn9i7y/dwrMz/G9feL2KdDCjXwF9GNtUV31Fnptl
         b5D+GuTjWk0nzMpf5ShFrvOXDbtmyRrYCM8pnviYztJjNoq/dAQ6VO/FQYl+y9iX7yBE
         OzNjmd9bXLzMnoHujmp+UVt2Nb+3cDM0BjCEXxwv9jcH2z53rZ0hRJjTfmgftJIeWDV+
         Rg9w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="dPW/ilIx";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-916d36c168asi29441241.2.2025.09.24.19.07.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 19:07:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id 41be03b00d2f7-b5565f0488bso328442a12.2
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 19:07:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUmmqb8bRjwV63bZ1CTHujqrHrFD1uUe46MDX/+a1YrGq5ODwriBqrrsU30KExRjUNznGVmxPcXoRE=@googlegroups.com
X-Gm-Gg: ASbGnctHfls2D23NiQzCFK1P+Vs0q5S6rq/IqgQGZcSVsBLnjPqOTDoC6R1fPaAqP0j
	UWp6IGF1fzs4ftGJmOfienULrdEFAABEcFzcIFyG4gum11vDN91p+7l9GoHdZcTpL1lnWkq4sRc
	/hGJChDjrpjRUYfPC9aOXHT6xskxAPk2RffYJ/CshcL05l9vOVk1jiOLc6KCkHCQxSJGcx6AJlj
	KW2PLGT/+HrLqhlXxx3iG3hTAd4wtiM+KYYVIAFWdwH9B1W1JUge5tfYold3QomiZDOV7m+6xpS
	mNizwzbIlOTflHaO0+Zv83ie2s+JdXz9PLp+Xkklm0qBoAoF6bo/CSXcpoBztmjtsnLOVUoUx37
	mabeKM5+bEBDJjGmPYoV/i5ZxfyDIF/blSw==
X-Received: by 2002:a17:902:fccf:b0:273:31fb:a872 with SMTP id d9443c01a7336-27ed4a06cefmr13125795ad.6.1758766049602;
        Wed, 24 Sep 2025 19:07:29 -0700 (PDT)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27ed6abff9fsm6469775ad.133.2025.09.24.19.07.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 19:07:28 -0700 (PDT)
Date: Thu, 25 Sep 2025 10:07:26 +0800
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
Subject: Re: [PATCH v5 06/23] mm/ksw: add singleton /proc/kstackwatch
 interface
Message-ID: <aNSj3j1P9O-XWbRE@mdev>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
 <20250924115124.194940-7-wangjinchao600@gmail.com>
 <CANpmjNOuA3q3BweB9kTUpAX4CX1U25Pqa0Hiyt__=7zio81=Uw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOuA3q3BweB9kTUpAX4CX1U25Pqa0Hiyt__=7zio81=Uw@mail.gmail.com>
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="dPW/ilIx";       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

On Wed, Sep 24, 2025 at 10:49:35PM +0200, Marco Elver wrote:
> On Wed, 24 Sept 2025 at 13:51, Jinchao Wang <wangjinchao600@gmail.com> wrote:
> >
> > Provide the /proc/kstackwatch file to read or update the configuration.
> > Only a single process can open this file at a time, enforced using atomic
> > config_file_busy, to prevent concurrent access.
> 
> Why is this in /proc and not debugfs?
Thanks, will fix in next version.
> 
> > ksw_get_config() exposes the configuration pointer as const.
> >
> > Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
> > ---
> >  mm/kstackwatch/kernel.c      | 77 +++++++++++++++++++++++++++++++++++-
> >  mm/kstackwatch/kstackwatch.h |  3 ++
> >  2 files changed, 79 insertions(+), 1 deletion(-)
> >
> > diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
> > index 3b7009033dd4..4a06ddadd9c7 100644
> > --- a/mm/kstackwatch/kernel.c
> > +++ b/mm/kstackwatch/kernel.c
> > @@ -3,11 +3,15 @@
> >
> >  #include <linux/kstrtox.h>
> >  #include <linux/module.h>
> > +#include <linux/proc_fs.h>
> > +#include <linux/seq_file.h>
> >  #include <linux/string.h>
> > +#include <linux/uaccess.h>
> >
> >  #include "kstackwatch.h"
> >
> >  static struct ksw_config *ksw_config;
> > +static atomic_t config_file_busy = ATOMIC_INIT(0);
> >
> >  struct param_map {
> >         const char *name;       /* long name */
> > @@ -74,7 +78,7 @@ static int ksw_parse_param(struct ksw_config *config, const char *key,
> >   * - sp_offset  |so (u16) : offset from stack pointer at func_offset
> >   * - watch_len  |wl (u16) : watch length (1,2,4,8)
> >   */
> > -static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
> > +static int ksw_parse_config(char *buf, struct ksw_config *config)
> >  {
> >         char *part, *key, *val;
> >         int ret;
> > @@ -109,18 +113,89 @@ static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
> >         return 0;
> >  }
> >
> > +static ssize_t kstackwatch_proc_write(struct file *file,
> > +                                     const char __user *buffer, size_t count,
> > +                                     loff_t *pos)
> > +{
> > +       char input[MAX_CONFIG_STR_LEN];
> > +       int ret;
> > +
> > +       if (count == 0 || count >= sizeof(input))
> > +               return -EINVAL;
> > +
> > +       if (copy_from_user(input, buffer, count))
> > +               return -EFAULT;
> > +
> > +       input[count] = '\0';
> > +       strim(input);
> > +
> > +       if (!strlen(input)) {
> > +               pr_info("config cleared\n");
> > +               return count;
> > +       }
> > +
> > +       ret = ksw_parse_config(input, ksw_config);
> > +       if (ret) {
> > +               pr_err("Failed to parse config %d\n", ret);
> > +               return ret;
> > +       }
> > +
> > +       return count;
> > +}
> > +
> > +static int kstackwatch_proc_show(struct seq_file *m, void *v)
> > +{
> > +       seq_printf(m, "%s\n", ksw_config->user_input);
> > +       return 0;
> > +}
> > +
> > +static int kstackwatch_proc_open(struct inode *inode, struct file *file)
> > +{
> > +       if (atomic_cmpxchg(&config_file_busy, 0, 1))
> > +               return -EBUSY;
> > +
> > +       return single_open(file, kstackwatch_proc_show, NULL);
> > +}
> > +
> > +static int kstackwatch_proc_release(struct inode *inode, struct file *file)
> > +{
> > +       atomic_set(&config_file_busy, 0);
> > +       return single_release(inode, file);
> > +}
> > +
> > +static const struct proc_ops kstackwatch_proc_ops = {
> > +       .proc_open = kstackwatch_proc_open,
> > +       .proc_read = seq_read,
> > +       .proc_write = kstackwatch_proc_write,
> > +       .proc_lseek = seq_lseek,
> > +       .proc_release = kstackwatch_proc_release,
> > +};
> > +
> > +const struct ksw_config *ksw_get_config(void)
> > +{
> > +       return ksw_config;
> > +}
> >  static int __init kstackwatch_init(void)
> >  {
> >         ksw_config = kzalloc(sizeof(*ksw_config), GFP_KERNEL);
> >         if (!ksw_config)
> >                 return -ENOMEM;
> >
> > +       if (!proc_create("kstackwatch", 0600, NULL, &kstackwatch_proc_ops)) {
> > +               pr_err("create proc kstackwatch fail");
> > +               kfree(ksw_config);
> > +               return -ENOMEM;
> > +       }
> > +
> >         pr_info("module loaded\n");
> >         return 0;
> >  }
> >
> >  static void __exit kstackwatch_exit(void)
> >  {
> > +       remove_proc_entry("kstackwatch", NULL);
> > +       kfree(ksw_config->func_name);
> > +       kfree(ksw_config->user_input);
> >         kfree(ksw_config);
> >
> >         pr_info("module unloaded\n");
> > diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
> > index a7bad207f863..983125d5cf18 100644
> > --- a/mm/kstackwatch/kstackwatch.h
> > +++ b/mm/kstackwatch/kstackwatch.h
> > @@ -29,4 +29,7 @@ struct ksw_config {
> >         char *user_input;
> >  };
> >
> > +// singleton, only modified in kernel.c
> > +const struct ksw_config *ksw_get_config(void);
> > +
> >  #endif /* _KSTACKWATCH_H */
> > --
> > 2.43.0
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115124.194940-7-wangjinchao600%40gmail.com.

-- 
Jinchao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aNSj3j1P9O-XWbRE%40mdev.
