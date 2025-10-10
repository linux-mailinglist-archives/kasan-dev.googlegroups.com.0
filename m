Return-Path: <kasan-dev+bncBD53XBUFWQDBBFHZULDQMGQE7HMIQSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 33EDBBCBFEC
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Oct 2025 09:58:15 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4de5fe839aesf75978041cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Oct 2025 00:58:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760083092; cv=pass;
        d=google.com; s=arc-20240605;
        b=hpZ0NU8vxo9A2hJKAu5ej7SC0YsY71aUn+keKQmw/zgpgo4dvfKLPQD5JBKFgBkOL8
         ges0N29GaF8QUXuWjJXRf6fmi7dlttPe9rzckm51DauX2AOMD1g9AZehKPn6zjLscTa2
         8Fnfe7CleGuYCVpe/0xtXUWyJSRGPSm2uISVYY8nXS4Nu7mQLYk+POPfSiuEJVRAC/i0
         qALWuBtNIT/fA3YHc3+fSOodQIOhXdoIYI7VHys/htsohJmf14YJSvhMiK4NH5x/zRqf
         ZcPmXFvysQzc0FwKeMfkP94ba0h2h4yz6GkLVOQCWuX7eqef73K0AF2hKTlFtlytpRNf
         IbZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=YURSfslj2R9nY6R2dhI0Ui4CP24OUhUtjT094Mq+UYs=;
        fh=q4/KflRH5uGPBlU21FAbw0mx+w5RFecw7hJaq1wsVqg=;
        b=fQaeTdrhGQT3olIsK1uELvszdsT6Tnk9Ld/uIa+H1ZosSDUrH+xkjTcQvPGfj13Y7W
         6FXAQNyx6odKZKOhssCq/BVGOeZpKXoaqIuAd8jR0xvDpapAIRgU+Ord/bWf2pCHKsRZ
         zZCe7HXXspn9sC1hTr712EC+QhyHW26+A4S/n+bK2KfbHAoF0j2jpDLdvsXJaIZFgjWm
         OhvW5V1H7c+bSFkOzKHFR0Qp0CcWwzSws2FRl3HrwWC4kpZscijWNxKCsdlF0EAMZneo
         +vNPoQoCYUwkmjCkctKQ6PBKIFrHxxua9j6g5JMuD0DDx3va1RWl5PkaiIiOc5ucD61S
         0Jug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GNkuBAKR;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760083092; x=1760687892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YURSfslj2R9nY6R2dhI0Ui4CP24OUhUtjT094Mq+UYs=;
        b=YM7lrot7LU5E+FnN4/pboy2fQK258p/BSqgMCbqS8U5eybk4PXCYxrWcPzWD2yYDjx
         RP7UWa0ZGonMsdCJDmE4FpAI3r3JdCaFLuMpYYPvBCMRfTpcsdrjRi7W27ziz9KwCPhk
         Jwwvgb6KHV/6ooumlIM8F5yHS4QTyQj0dvmGzktu/80bVfbOCxUZOarD4fHcsRREzKq2
         dpZcg2D5TDkNY7Q5O/2/IwUFpRL+lJY5VhJl0PXr94v0W7E1Oj0Oh748GX6S/Ylk8xeo
         bkzNwII5qES3/djhtfF32Iyp9W3emwYzXqM/baWzRgRnd7wN0i9Aj5oI36DLYL3AcvuF
         f8mw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760083092; x=1760687892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=YURSfslj2R9nY6R2dhI0Ui4CP24OUhUtjT094Mq+UYs=;
        b=Kc4+HXZeLZHihe9qmwfIdnnbR4ZzcqIR1mJKHZrTKPdKZ/BYHw7enNTZGOItJTMp6T
         DKtbGn6kYsxX+ylxHNAU+0Wd71oZsPljSNQbkZw339NQSaSoUW5CbfA9UIbjrTnsAiaJ
         yvt/9Dbu9NXbax+mRiWIoZusxRnEd1TmJq/DR421VdkWpu0itKDI2QhK5FRjR2wS7/L8
         T0SXFrV06u+pWKR/Iv1GK3RLtL0l3TNM1Czm2PysBq9S9UvbAELZVzPOTmcq4ooufnVM
         QsM+lW8qxQni/22MptjDMP65Ockm+CBWGx16IHIXQAMJP/LT5GK92iPk2kbK9tURm7Ai
         h0vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760083092; x=1760687892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YURSfslj2R9nY6R2dhI0Ui4CP24OUhUtjT094Mq+UYs=;
        b=I80ljM0NcF1EhANRVs6Uy5aNSq6qrNWhhZt2c8o23LRDKskjIjbRnKgcqAYlIBrd8G
         8LC0SZoRV2aZ5Xm879qUH6lkaqozYQYDue3yV9w5sahEIsWprtz7rUHOCTbh1xM5t+Gb
         AZDpH2Ap7eJE7x1LsxFTS2FnVA27b3jQFenoyHMyQnJDAWKZ/IRH3h1yu9ilV4EC8JJE
         Wd71uZ7ePEBI2yNtyN1tzLpYHGQm47ZP7OZ4nhv+LUyOjMrxJGZLSmnNMFQbfIOByl6y
         5KRDDsG40YG533SASKNcOyGKHS2TC9dwhZwz6CqEPbDQ4l+K+L/nyR5V5OYtSX2Qmds4
         IMxg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX9Wm2Yxwo4XLCl0TxDmSeZE2DREQRiO2U+CE6GvRPYDFsweNE0dfTOBzYIvPiLJ9mDocFNXw==@lfdr.de
X-Gm-Message-State: AOJu0YxvMV6CoGFmABrdGncZxhjjHqHvGrRb8h0IOhxhyYKMEoTtskqE
	8d2KVfbykqi/TLK1nvkyxx5AqJ/m+s+sdU6g3fyRXuSPbFazMmy/XfaM
X-Google-Smtp-Source: AGHT+IGcFqd9tgRpBbMQ4UXAu1l0oEW5VEQ6yQzWjfJRuSjsI9m4FeCFZflkUURE+WQMqoDbk0BdFg==
X-Received: by 2002:ac8:7d0d:0:b0:4de:45ff:1de with SMTP id d75a77b69052e-4e6eacd1fb3mr141937401cf.21.1760083092513;
        Fri, 10 Oct 2025 00:58:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5lV51riBMuOjQwdP0xEOpEtfxVY9yNRXGe08+oMS67wg=="
Received: by 2002:a05:622a:8d10:b0:4cf:440f:86c0 with SMTP id
 d75a77b69052e-4e6f891559als37741611cf.2.-pod-prod-05-us; Fri, 10 Oct 2025
 00:58:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUx5UnJyuF0jvapSy9Hq5h5TGIbz1mAIMEkQNBoo7KzNHHRoOb+YrneWNLEEeN15BmMX/aBOr1ccwY=@googlegroups.com
X-Received: by 2002:a05:620a:40c2:b0:812:96a1:7297 with SMTP id af79cd13be357-8834d1ab0abmr1527014585a.0.1760083091584;
        Fri, 10 Oct 2025 00:58:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760083091; cv=none;
        d=google.com; s=arc-20240605;
        b=aPWd2mWMieEon9miSVfIU9mKuZKRKcwP2/NZZmECEcckn7ocRgJNc0Zi+eoqCNGzGW
         7dWquH789rjMGjh4e9QQgsgFVh0m22G8ZLEH5zXMGCBB5UQyE95MvB0dO6Qfy+G8wcrA
         xrGhzFSoCnSw65XlEDcCaDpKUxg9mvLiDrpluRsBHCUHh/V8iJWT4nXu4bXuVkJbOZCt
         THoKneFjUwSjmQ98hVm1ySeEf1pTxlua8rhREZecTHuceNOSvAL9koU3oXi+g+KgvymP
         +8BaLdC5dggaejNA1wOfh3qHxQuv4CAFRidPredQPtjMdQ4Jt7cn6Bfsh5lgDTFGX6ow
         FYqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=2Nucw4E7LkwzxjCbFb3F737DKijbeBN9zMwZ0PDOoZQ=;
        fh=ir5KB7Tr+nHR5zUPzjczi3pk336AsKodwJnOglciATc=;
        b=G6/yh7ekY8adb6CFMz7bu3sgoqFfZ+AjBYolklbmjTC91R9m5tPFCoVkMvZwGHklaE
         dJkjYX0OmEQx+VTyeW+WgzdfHVNHL+6XaKqKQ0YEyWINTy1Vr0/GMnMW9uwYh93oTxfX
         zNZF4io3d7f+7klMUrY9GizOzHnOPd1syuaJTjyYq4/81AqYRoBkAjbXIt2QH/vwRB3a
         QM7z8sCGE371IVItEMWQ/43MOrfp60pcypQpdvMt2V0NYlmfWL/8N2TwcrV7tyNRP5Yx
         jPd+zQ56beBjOtJP5sK8qvg/IFWiR8EV3Qth3Zd6+BSB/10K3UkUq8tStmMYSiZurizl
         EDPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GNkuBAKR;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-885ee304a23si8638985a.1.2025.10.10.00.58.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Oct 2025 00:58:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-28e8c5d64d8so16987565ad.1
        for <kasan-dev@googlegroups.com>; Fri, 10 Oct 2025 00:58:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUirgFSA8UvIfgR7BhVkrkSlZPrVxawqrkM2gkzv0mbpQnHGmy0E8+O1Wc93cKbSI35N3UTCDFIUAs=@googlegroups.com
X-Gm-Gg: ASbGnct6EvVVmypkzxt6v28Ved6MmJw15ailFQLXPIRFIH7OsAQx/30oDNfSXEx3xRn
	D+kcZ4hZhVkehPL2z1tsNrExn00khKhwc8zQgwMQR7CWmmwYvwXl/gQ9+bbCb6ZxA7jF7fwphtx
	Jh3hW9I4nymVLFq84ld+8V97KK0ifY1G388K0SO5zoYFgq+4NaPNhn6mAaJWB7OSueBrO71tMnp
	E9MuXUySz89YhOmYqFTFMe277HpXHZ9QyH6sZbQEi66DIQs14kYeqsXOkF4tlJMU3MfXZgN64C0
	SA/RVY/IDtQ7dEC7HzrUwzPed96NirxOKCw+LgbsNfDfT3c3GsQrBeuQ05z3v94fNBOlVP9ekRd
	IlXhVqzYzFM9WQN1GFBPyT+bu1TO1+sjp2B8GZtHZvVhhCuV4nFv1mpV0ukOz3UzVxeY=
X-Received: by 2002:a17:903:298e:b0:28e:756c:7082 with SMTP id d9443c01a7336-29027374b38mr134966335ad.15.1760083090502;
        Fri, 10 Oct 2025 00:58:10 -0700 (PDT)
Received: from localhost ([103.121.208.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29034f070ecsm49587725ad.60.2025.10.10.00.58.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Oct 2025 00:58:09 -0700 (PDT)
Date: Fri, 10 Oct 2025 15:58:03 +0800
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>, Jonathan Corbet <corbet@lwn.net>,
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
Subject: Re: [PATCH v7 00/23] mm/ksw: Introduce real-time KStackWatch
 debugging tool
Message-ID: <aOi8i1Y0decaamaX@mdev>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
 <20251009175107.ee07228e3253afca5b487316@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20251009175107.ee07228e3253afca5b487316@linux-foundation.org>
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GNkuBAKR;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

On Thu, Oct 09, 2025 at 05:51:07PM -0700, Andrew Morton wrote:
> On Thu,  9 Oct 2025 18:55:36 +0800 Jinchao Wang <wangjinchao600@gmail.com=
> wrote:
>=20
> > This patch series introduces KStackWatch, a lightweight debugging tool =
to detect
> > kernel stack corruption in real time. It installs a hardware breakpoint
> > (watchpoint) at a function's specified offset using `kprobe.post_handle=
r` and
> > removes it in `fprobe.exit_handler`. This covers the full execution win=
dow and
> > reports corruption immediately with time, location, and a call stack.
> >=20
> > The motivation comes from scenarios where corruption occurs silently in=
 one
> > function but manifests later in another, without a direct call trace li=
nking
> > the two. Such bugs are often extremely hard to debug with existing tool=
s.
> > These scenarios are demonstrated in test 3=E2=80=935 (silent corruption=
 test, patch 20).
> >=20
> > ...
> >
> >  20 files changed, 1809 insertions(+), 62 deletions(-)
>=20
> It's obviously a substantial project.  We need to decide whether to add
> this to Linux.
>=20
> There are some really important [0/N] changelog details which I'm not
> immediately seeing:

Thanks for the review and questions.

>=20
> Am I correct in thinking that it's x86-only?  If so, what's involved in
> enabling other architectures?  Is there any such work in progress?

Currently yes.
There are two architecture-specific dependencies:

- Hardware breakpoint (HWPB) modification in atomic context.
  This has been implemented for x86 in patches 1=E2=80=933.
  I think it is not a big problem for other architectures.

- Stack canary locating mechanism, which does not work on parisc:
  - Automatic canary discovery scans from the stack base to high memory.
  - This feature is optional; a stack offset address can be provided instea=
d.

Future work could include enabling support for other architectures such
as arm64 and riscv once their hardware breakpoint implementations allow
safe modification in atomic context. I do not currently have the
environment to test those architectures, but the framework was designed
to be generic and can be extended by contributors familiar with them.

> What motivated the work?  Was there some particular class of failures
> which you were persistently seeing and wished to fix more efficiently?
>=20
> Has this code (or something like it) been used in production systems?=20
> If so, by whom and with what results?

The motivation came from silent stack corruption issues. They occur
rarely but are extremely difficult to debug. I personally encountered
two such bugs which each took weeks to isolate, and I know similar
issues exist in other environments. KStackWatch was developed as a
result of those debugging efforts. It has been used mainly in my own
debugging environment and verified with controlled test cases
(patches 17=E2=80=9321). If it had existed earlier, similar bugs could have
been resolved much faster.

>=20
> Has it actually found some kernel bugs yet?  If so, details please.

It was designed to help diagnose bugs whose existence was already known
but whose root cause was difficult to locate. So far it has been used
in my personal environment and can be validated with controlled test
cases in patches 17=E2=80=9321.

>=20
> Can this be enabled on production systems?  If so, what is the
> measured runtime overhead?

I believe it can.  The overhead is summarized below.

Without watching:
  - Per-task context: 2 * sizeof(ulong) + 4 bytes (=E2=89=8820 bytes on x86=
_64)

With watching:
  - Same per-task context as above
  - One or more preallocated HWBPs (configurable, at least one)
  - Small additional memory for managing HWBP and context state
  - Runtime overhead (measured on x86_64):

       Type                 |   Time (ns)  |  Cycles
       -----------------------------------------------
       entry with watch     |     10892    |   32620
       entry without watch  |       159    |     466
       exit  with watch     |     12541    |   37556
       exit  without watch  |       124    |     369

Would you prefer that I include the measurement code (used to collect the
timing and cycle statistics shown above) in the next version of the patch
set, or submit it separately as an additional patch?

--=20
Jinchao

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
Oi8i1Y0decaamaX%40mdev.
