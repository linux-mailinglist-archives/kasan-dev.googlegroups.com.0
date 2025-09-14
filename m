Return-Path: <kasan-dev+bncBDC4FFVJQ4BRBBH2TLDAMGQENLAUJFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id B30D9B5690D
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Sep 2025 15:03:03 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-6218ba3ed9fsf3438640eaf.0
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Sep 2025 06:03:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757854982; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZU+LYIJ/ro/1fnR7WQOZO6Iz0ys4E44USzE+og5kfP/L3qk/H9RtWpiJpS+XVIm2o1
         HBuZ+NCib/nocvRHFAAiS80lMRhFqpAQGeUa/G2EqLbKLLxEy25pd+BXRgsNh841RFuH
         HsB0sWo4zxEOOKVhljLZSYJqaN6Dgt0H4KfQY9/EIAJm7gj6rE3XQfWSHR/UE5nPVs6J
         OhvQxTKiKFG1GHVINEbzkBXJ9qQDQG43slUbZ3rLI7oMZJy39/4iL33/l+J+y3lUAKfe
         ck9m4EGGM8N1kjcUJ4vCMuRcBZdtQp4cBQWJKiBCjSkcU45/EC7ARDNM6S5WuVrOwV6E
         NaPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=4Flj/t0Bi6t/3ZpKWvC3wRytREPIAJeyoEI81twKUvc=;
        fh=6mt27Pncc7EEBMOaaimvM9VK7eNKtEuMZNESQVzdQDc=;
        b=c5VdIEPyKUXEKUlh1I6aQSqe1HuacXC0U940a4/7Aw4JT1RBZfdV2Ic15rkmcXtAVV
         48j1qxrLe6O/KxHlQ10mwfpPmgfD54rssFqLrxkI7x/XO5fMQsGEGmdTuezOs6ZAOPsu
         4hNDN2UthUHixcibrJSPJTjqj/NcDOi/XOomykO8KzQRpLIsMO0zg7eXQcM7uI5z6EYa
         FgplnukOtHyAjrMKzidOwBFxZd0Pgyb1KOeDuhNyr3pSQAVyozxar/yah29g+GmMDg6j
         AIcQvIrB8rB1lRim8OjolhZRYHymyLWFYnUpi0Czn0j9nxsU6qiUx+wS0a9vMFpv8Ev5
         CJOg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tfN1I3Sx;
       spf=pass (google.com: domain of mhiramat@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=mhiramat@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757854982; x=1758459782; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4Flj/t0Bi6t/3ZpKWvC3wRytREPIAJeyoEI81twKUvc=;
        b=noBeRxp6lCdhZ+mQ8SWVz2gk4LSF6IHuUYUPjpUjhJNGjKDf+UHkma8YTzT18RXRDj
         8+9IAcNc8znJHJS37HEMxtDA0QtJLVoI9LfKMgoXEnjfa/80GV9JRW5TPOdTsp5vTZx1
         penW8JvjgFwYO3PpeyG8P3HS1Npk4JqUm8PZUbBFSpKVkOhkL95gn/Z+nGDPMNRBzUbF
         167V+mK/VQBkKS5wGXu0Gbupop5hIi8+XFM9GyWhHGb7nD9G6uUDdUDRUrV+lUBxh2ZC
         HabQ/aW+0+uAX8oAaGy38Jde8OlUo6THbic8iXHxhIf1isE0KnBapNrIYPEI7hha0u5K
         aK9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757854982; x=1758459782;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4Flj/t0Bi6t/3ZpKWvC3wRytREPIAJeyoEI81twKUvc=;
        b=dgvT3dAGGN0XKaBWaTG65nEcg2qYyCv93r3DtHUvRMdZDH/tp4zeLvBZSieHcmoQOp
         TNKd4sfmAJDab4HYg6XnqoLmuB3Jp22J6EL5e/VRuR46pVgq5FeF/Wrrsf/yKGR0/NDE
         +UQ8vd6u7iBRFLUIWwg4TBMpe7l3ODhcms+qxZCU5YaWsrTCcrE+z1AIZ3fVVzj6al1e
         tnnZERqutCT+E+srISiqJ5nFRNC/VdVYFUAgGxcetmv7ZG4DVyQEJW8dQconXMqN6Dxu
         XDdazRyTIcYziSxJoQiSh3HsGOV7426vbqCULkdsBwfM9L5Rt6AIX2WRjyvAABtkpkl/
         np3A==
X-Forwarded-Encrypted: i=2; AJvYcCXl+MWKrV3hnoixqVmEeE0IbfLecqgL/eSQYGUbKvOhcHB8AC/dLX1++GC3H4sXPrQa5xsoAA==@lfdr.de
X-Gm-Message-State: AOJu0YxibNZU7piHb6jRV3G8Pn+Cxd1hK7TkKaeEgtxhDeAta7/LQOTs
	rZVbwS5PHBzd/Xz+m1L9cHf075UFE0vJJVPXgWYH83FIXZE600o/LNMl
X-Google-Smtp-Source: AGHT+IH1izGSdiWPuAsPMOgZ4Qhmh1eKxYvb0ggjzh6FFPoKvE5Wiek6bXg3nIgbt1mpYr2Kvf5swA==
X-Received: by 2002:a05:6820:820:b0:621:a8ea:c471 with SMTP id 006d021491bc7-621bed8fbd5mr4274512eaf.3.1757854981597;
        Sun, 14 Sep 2025 06:03:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdGwrX14zYy0T6mVHk/hMZ7Z9/2SvkOsGEfIXejrEgvIQ==
Received: by 2002:a05:6820:1f90:b0:621:a2f1:abe6 with SMTP id
 006d021491bc7-621b45347c9ls853707eaf.2.-pod-prod-08-us; Sun, 14 Sep 2025
 06:02:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUpLC9gAba5ynTmXIAqZxURb0yUeVDpDlf9xx0JlzQSx30/vpoVgU5n5rmXEeKLvmPrwGBNAHC1uiw=@googlegroups.com
X-Received: by 2002:a05:6830:6a91:b0:746:d65b:a3b0 with SMTP id 46e09a7af769-75352d8adf9mr5232305a34.2.1757854978744;
        Sun, 14 Sep 2025 06:02:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757854978; cv=none;
        d=google.com; s=arc-20240605;
        b=MQ3NjniyCr4fdZwmZwOaWkrj60u4tAeOGRvhuRf1ordcvw7JnWG4QFs0vin/LsLLKw
         uXRBDbvuPIpJraVc35nJ1kMSk2yCvRuQVCJVleO4+Y1OjJBeGh8NAgwiOa8k2rqmTXeh
         v939+pQRZDImFjNnBWKya41GkteS992T1W69pptBrYGcXKfp4dZfhNOjD7QraaiPdVFX
         LT1Usjr1VJiCVaJ611hicYSZ7fOon/pJlHXX7Z5NrQlJ+gTCTwuGVmMHyi4TegvvZ3V7
         us0xC2BsTDPb8SKJvg9GnbH5BWfE+A8/XN9aDWhtbdxK+imRoSfxn3JfwELlEA/jdDPR
         xltQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=OQvwWwEuhKFk13QOyAig49OX2R4iNlJHBcgD+YReILk=;
        fh=DrqTWZ1Ijbt59Thq+DC/pYHP6TvU/6BnlqK8uqeVPgA=;
        b=RVrxg73QheLyfvZNB/1XBNuNCiZvXKz4oOaTlCkCQiqzZ+wzdBhQWPcY44fcioyswH
         PNrv58XDWc771uEg2WWaLwM14pvrlq4Rs4GiWWcn8uf0DwCv5797T3o0lROyox0+NW0L
         4MJyf1VkUvmoKxLf6fhxZnVdl9J2kEWZi5HT/2mcXhZoZktn9tmvz1vgxbFiFpqKcg9t
         IFqowNWJ2Qw4KvkvWASDCBMH+z/oga7f7qJLIODCyqT/9ehy2bir0r+LcjjyhFPPh0R8
         sFWgOzAw+9GBddUmETrT22ItbqdQWOdxmVatsnel0cwuV9OMpJxYRy/DgNuk4cfidQ+h
         FnXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tfN1I3Sx;
       spf=pass (google.com: domain of mhiramat@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=mhiramat@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-75245d09334si396783a34.0.2025.09.14.06.02.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 14 Sep 2025 06:02:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhiramat@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id C899543B05;
	Sun, 14 Sep 2025 13:02:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6FC9EC4CEF0;
	Sun, 14 Sep 2025 13:02:45 +0000 (UTC)
Date: Sun, 14 Sep 2025 22:02:42 +0900
From: "'Masami Hiramatsu' via kasan-dev" <kasan-dev@googlegroups.com>
To: Randy Dunlap <rdunlap@infradead.org>
Cc: Jinchao Wang <wangjinchao600@gmail.com>, Andrew Morton
 <akpm@linux-foundation.org>, Peter Zijlstra <peterz@infradead.org>, Mike
 Rapoport <rppt@kernel.org>, Alexander Potapenko <glider@google.com>,
 Jonathan Corbet <corbet@lwn.net>, Thomas Gleixner <tglx@linutronix.de>,
 Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
 <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin"
 <hpa@zytor.com>, Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot
 <vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>,
 Steven Rostedt <rostedt@goodmis.org>, Ben Segall <bsegall@google.com>, Mel
 Gorman <mgorman@suse.de>, Valentin Schneider <vschneid@redhat.com>, Arnaldo
 Carvalho de Melo <acme@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
 Mark Rutland <mark.rutland@arm.com>, Alexander Shishkin
 <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, Ian
 Rogers <irogers@google.com>, Adrian Hunter <adrian.hunter@intel.com>,
 "Liang, Kan" <kan.liang@linux.intel.com>, David Hildenbrand
 <david@redhat.com>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka
 <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko
 <mhocko@suse.com>, Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers
 <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, Justin
 Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, Alice Ryhl
 <aliceryhl@google.com>, Sami Tolvanen <samitolvanen@google.com>, Miguel
 Ojeda <ojeda@kernel.org>, Masahiro Yamada <masahiroy@kernel.org>, Rong Xu
 <xur@google.com>, Naveen N Rao <naveen@kernel.org>, David Kaplan
 <david.kaplan@amd.com>, Andrii Nakryiko <andrii@kernel.org>, Jinjie Ruan
 <ruanjinjie@huawei.com>, Nam Cao <namcao@linutronix.de>,
 workflows@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org,
 linux-mm@kvack.org, llvm@lists.linux.dev, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 kasan-dev@googlegroups.com, "David S. Miller" <davem@davemloft.net>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 linux-trace-kernel@vger.kernel.org
Subject: Re: [PATCH v4 03/21] HWBP: Add modify_wide_hw_breakpoint_local()
 API
Message-Id: <20250914220242.1e8dc83e011b9568dd7a5ace@kernel.org>
In-Reply-To: <6b5e5d3e-5db8-44f2-8dca-42f317be8e0d@infradead.org>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
	<20250912101145.465708-4-wangjinchao600@gmail.com>
	<6b5e5d3e-5db8-44f2-8dca-42f317be8e0d@infradead.org>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mhiramat@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tfN1I3Sx;       spf=pass
 (google.com: domain of mhiramat@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=mhiramat@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Masami Hiramatsu (Google) <mhiramat@kernel.org>
Reply-To: Masami Hiramatsu (Google) <mhiramat@kernel.org>
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

On Fri, 12 Sep 2025 21:13:07 -0700
Randy Dunlap <rdunlap@infradead.org> wrote:

> 
> 
> On 9/12/25 3:11 AM, Jinchao Wang wrote:
> > +/**
> > + * modify_wide_hw_breakpoint_local - update breakpoint config for local cpu
> > + * @bp: the hwbp perf event for this cpu
> > + * @attr: the new attribute for @bp
> > + *
> > + * This does not release and reserve the slot of HWBP, just reuse the current
> 
>                                                  of a HWBP; it just reuses

OK,

> 
> and preferable s/cpu/CPU/ in comments.

OK.

Thanks for review!

> 
> > + * slot on local CPU. So the users must update the other CPUs by themselves.
> > + * Also, since this does not release/reserve the slot, this can not change the
> > + * type to incompatible type of the HWBP.
> > + * Return err if attr is invalid or the cpu fails to update debug register
> > + * for new @attr.
> > + */
> > +#ifdef CONFIG_HAVE_REINSTALL_HW_BREAKPOINT
> > +int modify_wide_hw_breakpoint_local(struct perf_event *bp,
> > +				    struct perf_event_attr *attr)
> > +{
> 
> -- 
> ~Randy
> 


-- 
Masami Hiramatsu (Google) <mhiramat@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250914220242.1e8dc83e011b9568dd7a5ace%40kernel.org.
