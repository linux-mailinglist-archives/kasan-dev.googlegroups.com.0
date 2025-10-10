Return-Path: <kasan-dev+bncBCT4XGV33UIBBAFRUHDQMGQE2OPWAJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id F3042BCB4DE
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Oct 2025 02:51:13 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-78e30eaca8esf78938556d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 17:51:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760057473; cv=pass;
        d=google.com; s=arc-20240605;
        b=VE8IABy1OupGpgtMnn0+XrZ99ztwC1fCDUMKs/b/KfLtT1d3XyVVGxLCUNcdf4pj1u
         FNk5TbioZaX/fdjaG+GeDdqvSJFq5wvyr3veHeokKJ4Qp5x6p6d46Dr0u2QJx5At/rCH
         TzizQOCXhl8lLcrUrDcC8oIT58eO5KnXbpZPvd1P2tC0Ekry9ODcOY8W5UIoLjpL6aAH
         GyPwn/O8hmK3q8MVw5SM2gRIJ+z3ka88s4V8fjLbN4twmCxdoIrJmvdjJQ/mzWLHW6we
         38krWbyNzwEmFm9MYKAmj+IMQzCsxDLAj6KKmm0j3n8N5BjrlPwMqtKKRTRzm4qDv+kb
         HTNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=qtAHVnua5f2kvI6vLO1OyKqI+1UQHNxdQP4NZ7p0Zn4=;
        fh=bdYjXmXCitxSv1ZfYqnVGpvRQhe6W1Vvm37TPcqr5Ig=;
        b=K6vOo0Fbe9rUTuPES11LprXaqP/iq/sSG+C463jPN7bMnsBv5kad3pdUAzolLDQvL+
         lIgQVmVjQnPJsz0xaYWM9VMjssLlq0A9bJdUWLHcx3unUmbM44izUB/eogTlMz75alzK
         li6Ax5rU77NF5/bHyNYNCMaouCplkMkPLdcwT+Gg/lzbAcIEOupvLTusoWM/8ROWzI2T
         JxI2+RWpZcU7W7P8EtfLoZsFKGCagTCxW4ktp8wi3Nkung3Zfu0NUQ3gj08V6QjRT7NL
         0k0dx7qSFzSbeB0T8CAsW31Sk+hVHN6qMBdqOb9tr1Z+G7MKm2ILgUg22m6GU2wiKZvg
         UXiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=2JktYbzm;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760057473; x=1760662273; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qtAHVnua5f2kvI6vLO1OyKqI+1UQHNxdQP4NZ7p0Zn4=;
        b=GgZznKakWcLnsLaNNNNUYIf3lR71LgoD4wohm6/NXqb6eFPelmgIxenM3liRqOfeY9
         QL/+d4hrnLVlb9sK30Trbc6MMGxDIWYHku0OtIzj1l4a8ni15Nkjc3f2eRD5rmu/aSn8
         +FuKQKF0Bra3bA0OgOqDT23l9lzenauo9ams5xmftx515n8pORoxVxeiWqsypNBnOuTg
         aih4kOsZ3PgTmwJHqtZjr33upoOM6YUD4RqKYpCsFgWhlitqqB/LXVG0mRQK2Wh18LsX
         u85hotijN6nhG/w/gyNRRf37WpRoKFhPc1cx0onfaidfDXoYKyZr/KQATUfQLKOh+kZT
         O7KA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760057473; x=1760662273;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qtAHVnua5f2kvI6vLO1OyKqI+1UQHNxdQP4NZ7p0Zn4=;
        b=I9qnQcewce8pI+fE8BPNJx21ACD5y9tXrO+zRD87jQQ+3lGrN/rsYivlICOWIMD2PU
         Xipf7b0fg6zp2s7iYRDGyEb5Fa9ZHsK0Tj5ieceR4VdHbe9wGGmW/WquRXe/GX7YwyXW
         XsbynAh7K5qYI51msRT4UQjP0QGX4CrJY3tTO8Cyno4gsiFDVxaLS+hqbYXD1pXJSoTl
         bkP8wLh61VG4/NT1brgjqEgpamf/LPC/gJkHMscAhUy4HCsdcRtdWSIF3KG91Wp9XZLc
         xpmtdz9z/dTLLRNHi51FCtNgerFIKSB1TkhB4i3RQqb3ivUOChg9YYCy7wTSP4x9lq+y
         a1+A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXNERThMmpfWceOfClgC5CAL0uZASpJjgk5RLRtqbF3kpqxP7ZrpVUWHe/wA7I20mRSmSEenQ==@lfdr.de
X-Gm-Message-State: AOJu0YyyQroqQamd0CdER+IbX9MZjSPMWJrbXD6CjKCLd0uFMsACGTcC
	jxw7drYZ8C7Y9RAn0RYUn6vl0HgKB0meBt/9BEL18vGwf2zfpjhSoKMj
X-Google-Smtp-Source: AGHT+IEzkfsmFz8vogmps4L5k+XI20NL0Q4/3ybFfKe6HFoJSvXxds+sSMf8Hkk8PTLyKK+6DMxErA==
X-Received: by 2002:a05:6214:d0a:b0:7f1:3094:306d with SMTP id 6a1803df08f44-87b2ef93676mr122069516d6.47.1760057472596;
        Thu, 09 Oct 2025 17:51:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4wKNkuCxdMtIjGnASnKTRm/Ka35AK+XBvs8PdmJbH4uA=="
Received: by 2002:a05:622a:8586:b0:4b0:8b27:4e49 with SMTP id
 d75a77b69052e-4e6f87034c7ls28093781cf.0.-pod-prod-02-us; Thu, 09 Oct 2025
 17:51:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWioK1WJE+XGm+Ee9mgv5gwOasbzTZkL4HR7cBWwia20e/3hyagit8NfiXxdZuZenD1SRjogy566rU=@googlegroups.com
X-Received: by 2002:a05:620a:450d:b0:849:f88d:b744 with SMTP id af79cd13be357-883504a910dmr1423583885a.20.1760057471378;
        Thu, 09 Oct 2025 17:51:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760057471; cv=none;
        d=google.com; s=arc-20240605;
        b=Uzq7IUZUYfNtuBbNEeLuy+mUYdx55+nHE4OvGJD3VgjogB1ixf4R8Q+3G8ovIqbtX7
         mAT7wxLrtQ4KUwNly6SZOgvJoEHb69ZC/3eV/N+NL7wWzctZOsHwLlG/88J0lCCjI+pC
         G+QgRbvtbVlDMiIdcPoqG1DjAGWSAwKYbCZ4lK93juRGsMRr+JVKbAwTMPkMX3rpDrva
         aMoiIzbVrv64lp5LgrJTWJplVYYb0bB0HK4v0mlAF3ZOY4chwlyhs4ywM79hx/ey6h1T
         GWselIXlekhllLRmohYkWINlLaAW6WQfnehe3icF9upxVM2Bfvr5u8qi6PM043ptf63N
         Ws4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ixaQLTg3CkcDLvWdQYxVSRQH9QTFlcattUSgzftfR1c=;
        fh=ZSVsQQzvvPClk95ChF4pYwiG6FAyfQLCtvQrcRf/9r0=;
        b=DlP67Uf2fynmQGsDwqXZ2x8czXgjIihOXiVnPAlWE3mYsL1PkSZCAVInKWtF0QRC7o
         48J37+P/gr/t5yf24pjDfujIH31vcLzi9DM8iYaCaRJK3tI4H1mOAgRD68YEUDiyEwj3
         jczskQID1m9bjszxrjCpKhdxrwDyI38pJGY/GSeYuqA43Ffieid0GU9Vcputc6LoCjEQ
         sNQRZMPHebBhGsaQLD+TY0xyvLeJvAo4SBIhXKms7GSODlyJvuZ3Ezsld/RLmAgnuIOd
         MwvzOu9rQSW/7helZkVpkUrroIFyp5x00mR4VbW7zdF6nqqknikOuc4I2MD9EeNzNXlm
         tt0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=2JktYbzm;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-885eba8f59fsi6344185a.0.2025.10.09.17.51.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 17:51:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 3176543F7C;
	Fri, 10 Oct 2025 00:51:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 24497C4CEE7;
	Fri, 10 Oct 2025 00:51:08 +0000 (UTC)
Date: Thu, 9 Oct 2025 17:51:07 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Jinchao Wang <wangjinchao600@gmail.com>
Cc: Masami Hiramatsu <mhiramat@kernel.org>, Peter Zijlstra
 <peterz@infradead.org>, Mike Rapoport <rppt@kernel.org>, Alexander
 Potapenko <glider@google.com>, Randy Dunlap <rdunlap@infradead.org>, Marco
 Elver <elver@google.com>, Jonathan Corbet <corbet@lwn.net>, Thomas Gleixner
 <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov
 <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
 "H. Peter Anvin" <hpa@zytor.com>, Juri Lelli <juri.lelli@redhat.com>,
 Vincent Guittot <vincent.guittot@linaro.org>, Dietmar Eggemann
 <dietmar.eggemann@arm.com>, Steven Rostedt <rostedt@goodmis.org>, Ben
 Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>, Valentin
 Schneider <vschneid@redhat.com>, Arnaldo Carvalho de Melo
 <acme@kernel.org>, Namhyung Kim <namhyung@kernel.org>, Mark Rutland
 <mark.rutland@arm.com>, Alexander Shishkin
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
Subject: Re: [PATCH v7 00/23] mm/ksw: Introduce real-time KStackWatch
 debugging tool
Message-Id: <20251009175107.ee07228e3253afca5b487316@linux-foundation.org>
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=2JktYbzm;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu,  9 Oct 2025 18:55:36 +0800 Jinchao Wang <wangjinchao600@gmail.com> =
wrote:

> This patch series introduces KStackWatch, a lightweight debugging tool to=
 detect
> kernel stack corruption in real time. It installs a hardware breakpoint
> (watchpoint) at a function's specified offset using `kprobe.post_handler`=
 and
> removes it in `fprobe.exit_handler`. This covers the full execution windo=
w and
> reports corruption immediately with time, location, and a call stack.
>=20
> The motivation comes from scenarios where corruption occurs silently in o=
ne
> function but manifests later in another, without a direct call trace link=
ing
> the two. Such bugs are often extremely hard to debug with existing tools.
> These scenarios are demonstrated in test 3=E2=80=935 (silent corruption t=
est, patch 20).
>=20
> ...
>
>  20 files changed, 1809 insertions(+), 62 deletions(-)

It's obviously a substantial project.  We need to decide whether to add
this to Linux.

There are some really important [0/N] changelog details which I'm not
immediately seeing:

Am I correct in thinking that it's x86-only?  If so, what's involved in
enabling other architectures?  Is there any such work in progress?

What motivated the work?  Was there some particular class of failures
which you were persistently seeing and wished to fix more efficiently?

Has this code (or something like it) been used in production systems?=20
If so, by whom and with what results?

Has it actually found some kernel bugs yet?  If so, details please.

Can this be enabled on production systems?  If so, what is the
measured runtime overhead?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0251009175107.ee07228e3253afca5b487316%40linux-foundation.org.
