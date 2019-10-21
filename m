Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKFEW7WQKGQE3XELMFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3d.google.com (mail-yw1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EF7CDF1D1
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2019 17:43:37 +0200 (CEST)
Received: by mail-yw1-xc3d.google.com with SMTP id r64sf10833648ywb.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2019 08:43:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571672616; cv=pass;
        d=google.com; s=arc-20160816;
        b=VuWW4n8OmZEPrKWD2T8pzU1GJQ0VMYut3x2aBCx/pgFJpYMZX0lEYjmOOcHSuYjF/X
         8xC+vCsz3y30FQzfUF/NH0jcIa8KF5MEm+rSJf37v2ebj6fHmmKQ6BeEUGPKx6SDBAXH
         hwnSMmqNu7/QCz0sn5a9w5rFUzssxWFMpWmiMeWucyAxyJUgxv3GMQXnIcqnAOu9Teds
         +rLUeTlGZlJsmil1RtSh0daA52d8RHVc2tWWCauc5DCiDPYluDNuyqrb0RyBo4XbRa4G
         Ucb5KoEnIoMh8yKcGptJ5XPPw6PdOsYBBewKWT4As9tFxmsgGi96tM4YoNdCdFyE07fS
         pGig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vpRY0KWkV4IVYyakJBt6btcoTCpNzvjXxNH3Y9zlIkY=;
        b=qwEy8n+0HP95AW+H9aAYPWs5L1qH3LBpffibMty3BWKzIyyluvNQTlAOEvaSvbwulJ
         5EgkKMqoipeRs9359JarkEBvf1Oz0LBLotshj/WU8uoHxasXOzNiyqjxHuVCVxqgJsq7
         fhSqt5f7HcqAZ+UkoGD5oVFStWMhm1c3KPxELhtHbTR8ef9hazM6YdB0lw73HnNIhLdu
         OtPbZgWdCVeTA1gn/Lj+oBCMexsuv9R2XxsIaFsiOQweKwUROFrnyHZWIFBkZmvJoXLY
         ODTg1GhF+9jEC0c78PxWRWH58QQckGlx9WWsd1/pDx+PWqUzF1KT2VF0wisFEUAHYqeb
         zoYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kSbOVSxR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vpRY0KWkV4IVYyakJBt6btcoTCpNzvjXxNH3Y9zlIkY=;
        b=kxPHvYKOkHpP4jEjsJSpJReT4kWgpr0Qi5Edq5q8wuAAlErSN36ahBVEvsmI0gVDx1
         13m4fkS/AwXAGlxCjKyjp/sbs3Qd4NGWxoS1dbIvbtNjj2BQ0TWXLoqk76mKr/eY5+Mu
         BvV3sJBBelFgqI1wIEZAC5+0C9HjpiEkf4ODvqNqVa2rKa57vN20bDfyAc1kriDeFpkg
         BHkFBAOdQUmSCMZACJPGzn9ZnCJ1eE19okAd+RHrQl0XnBbPjTZJutfBRPm/ITlwco98
         i1LOdBa4PbZhrQGSkxe2GkYSexmvbyGHLcjHBqifv3LwX40o7za94VbuWoEtDlaW+fJX
         F85g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vpRY0KWkV4IVYyakJBt6btcoTCpNzvjXxNH3Y9zlIkY=;
        b=TIOhPYXiYHejOzZu2t+e/Zq72agduPshgXWUthU6bXIiHLG32QdqETKIjBPSH6qJoG
         iPGQykQI3Ksk0dTFHvmyPEnkjeA0ZA5XuCr9ZFo8AWsHO35rt8Sryr2pI3VUgwZ4f9Vn
         njHYdDybTxxEH227Ecunoqpifl7lJPteYji58KlWjTPkUcCwG/SNU7i6rIcSGbdPFJUE
         zL/psxEMn5fmZ3R8oUa+Evz/ZKtj1rboNLg37ZJ+kaf7wrE4GO9iIBwsJcVXugSo3u5k
         qeEFAKxvjT2BQUD8JwRhe8DwO6uHUXjIZpbDmfPYi7nRKXTiAgT673dTyXH85itezX9P
         VvUQ==
X-Gm-Message-State: APjAAAXFvIbZTcETI/t0/Gb5VwdInsTkknTDLPFw09hex4U2GiiFWxi1
	1zwrQksm/GuAtiPIhCp9xi8=
X-Google-Smtp-Source: APXvYqyZehVaKC4mFYMFVMiv9YIVlHnoC62t3mzrYRBFh5kDDemUvNVtt2Hj2ZX+CrMaYPJV1ejrMg==
X-Received: by 2002:a25:84ce:: with SMTP id x14mr14772765ybm.433.1571672616307;
        Mon, 21 Oct 2019 08:43:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:338a:: with SMTP id z132ls513052ybz.14.gmail; Mon, 21
 Oct 2019 08:43:35 -0700 (PDT)
X-Received: by 2002:a25:6841:: with SMTP id d62mr16704990ybc.348.1571672615586;
        Mon, 21 Oct 2019 08:43:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571672615; cv=none;
        d=google.com; s=arc-20160816;
        b=kTjuVLabaWt4eADxJ/38wnVu333o1d2XatHQnKWWFsKZYcU0TP6/DSdv8DdulJHDpC
         EZHfayjo6JZFkmre/AI8kfA56hhbVXtVqkPDa6xFP8OuxJFs9BIhB0v921Nczu61uWp4
         t0EOUmUsQxujfyg44cspCPyjR6wIoBHKKJsXnlI21EioP5Lr1YKg3wIgYoogAexNpsQr
         iwvUamnOktBmXeNXORVUodXejD/HBbHuV/Yswpi2uteiK+O7MT5R8wBM5qlVDqMX+yKj
         uNAr7G2JQ9jwJZSDB0fMLvtRdBtImXVtKBzPDeaDF5IPNYwENsvAr6BA6RTNttCDZUEa
         SfXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cnXjVYkeWXq+gubvSOjcYVnZzqsBIZ+DNJdYhPS5/D8=;
        b=CSSNHYaNfY1Y2z5SVq5ps+yYbbbLcJnEwNiR7v3Vb7MCXSDi0o7n5Mxkiy+ajn8B9z
         bIXzU3T57xKwxvJAAQxb3NDn1h57wPZUUbnSlZKyg8XXy3478LWU9q+0Lprjaoehk5H3
         H3sY7sGssDEAFFQ5zYjuDb0n0xpAT0tauYqRedazLZjbL3Ypk4GmaVbhEsYzqXQhl6pU
         hyFJVEQCp3yZbMsI9pV1ycWnCSLaTv6AMMD5+AJ367vAWmCNAT9PAS4xbwnwwM225+u1
         OJxzA1UskTUjhpW6TTXzZ5ugcx4SJIK5acqQbwyG9QhDp6tV04tVNuk3v4vRlR08/+Mb
         Io7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kSbOVSxR;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id r16si919791ybk.1.2019.10.21.08.43.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2019 08:43:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id k25so11392957oiw.13
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2019 08:43:35 -0700 (PDT)
X-Received: by 2002:aca:f492:: with SMTP id s140mr20094795oih.83.1571672614698;
 Mon, 21 Oct 2019 08:43:34 -0700 (PDT)
MIME-Version: 1.0
References: <20191017141305.146193-1-elver@google.com> <20191017141305.146193-3-elver@google.com>
 <CACT4Y+b9VYz0wji085hvg3ZMMv6FR_WGc_NcEZETSOvME6hYOQ@mail.gmail.com>
In-Reply-To: <CACT4Y+b9VYz0wji085hvg3ZMMv6FR_WGc_NcEZETSOvME6hYOQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 21 Oct 2019 17:43:22 +0200
Message-ID: <CANpmjNPyxjjkRigstizGLh4rQKhY8JVUzD-6sJLYf62KB77F5w@mail.gmail.com>
Subject: Re: [PATCH v2 2/8] objtool, kcsan: Add KCSAN runtime functions to whitelist
To: Dmitry Vyukov <dvyukov@google.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, 
	Jade Alglave <j.alglave@ucl.ac.uk>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Luc Maranget <luc.maranget@inria.fr>, Mark Rutland <mark.rutland@arm.com>, 
	Nicholas Piggin <npiggin@gmail.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	"open list:KERNEL BUILD + fi..." <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux-MM <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kSbOVSxR;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 21 Oct 2019 at 17:15, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Oct 17, 2019 at 4:13 PM Marco Elver <elver@google.com> wrote:
> >
> > This patch adds KCSAN runtime functions to the objtool whitelist.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  tools/objtool/check.c | 17 +++++++++++++++++
> >  1 file changed, 17 insertions(+)
> >
> > diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> > index 044c9a3cb247..d1acc867b43c 100644
> > --- a/tools/objtool/check.c
> > +++ b/tools/objtool/check.c
> > @@ -466,6 +466,23 @@ static const char *uaccess_safe_builtin[] = {
> >         "__asan_report_store4_noabort",
> >         "__asan_report_store8_noabort",
> >         "__asan_report_store16_noabort",
> > +       /* KCSAN */
> > +       "__kcsan_check_watchpoint",
> > +       "__kcsan_setup_watchpoint",
> > +       /* KCSAN/TSAN out-of-line */
>
> There is no TSAN in-line instrumentation.

Done @ v3.

> > +       "__tsan_func_entry",
> > +       "__tsan_func_exit",
> > +       "__tsan_read_range",
>
> There is also __tsan_write_range(), right? Isn't it safer to add it right away?

Added all missing functions for v3.

Many thanks for the comments!


> > +       "__tsan_read1",
> > +       "__tsan_read2",
> > +       "__tsan_read4",
> > +       "__tsan_read8",
> > +       "__tsan_read16",
> > +       "__tsan_write1",
> > +       "__tsan_write2",
> > +       "__tsan_write4",
> > +       "__tsan_write8",
> > +       "__tsan_write16",
> >         /* KCOV */
> >         "write_comp_data",
> >         "__sanitizer_cov_trace_pc",
> > --
> > 2.23.0.866.gb869b98d4c-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPyxjjkRigstizGLh4rQKhY8JVUzD-6sJLYf62KB77F5w%40mail.gmail.com.
