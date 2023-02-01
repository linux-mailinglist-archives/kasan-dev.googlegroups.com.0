Return-Path: <kasan-dev+bncBCMIZB7QWENRBNXN5CPAMGQE5LGVTKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 10A7A68632F
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Feb 2023 10:53:59 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id j37-20020a05600c1c2500b003deaf780ab6sf596343wms.4
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Feb 2023 01:53:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675245238; cv=pass;
        d=google.com; s=arc-20160816;
        b=SyMZwn93QEnN6a/03K1mYn6D6p7rzxbODymv6JzTARpjqQQC0iLp9YvGWj0LUPFPaw
         GSsnkcSnikBmiUg9zElqYLUoX1CZrmc38HmprQVzBq08E1h8ouz0+bdiDHCMOisuR/n7
         dviYD3hWjM+U7qYRIBn11nn/XPuoHatPY+6uZKjZq0JlcsfnFJcTkWlvNGbQ/AMuVZff
         Yw4cq6uNXRdWbUMfEdfVLLLhr0Ril7Md6LmMWyfStV7is5jEQ3iD+47fZFktDqK2Xssx
         DWP6eXq2DX8j7wWnR4PhQ5Mm4VnuKO3zkNwGCrWnNfpIxkObwSJZq5VnF0NbGsp/0+RX
         d/TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uKWJYD7mn+1M+p2mUUO8qc5nVJNIovOIUtoIdUusv9Q=;
        b=pCSqEHpBa99XH/3ABKHGyUNUTTBsdEGIO1e5LpkC0DPXFt7SCOaO8dVTsEMB9MbGPP
         qeQzoaBkNHNQf/wEltRCphrY4Hgz39yRWQAGmnlo9kQ0BC43Q2SPjXcryvcMiF7k8i2l
         jGRYKXwyMf5VuIy0tS9HxoiqIKn5q0HMPz2ZDrIXGZZ/XRc9GczjKsxId/xG104934M0
         O13lTrW7IT4VCZAuHtsy5TXtZdms1JbCD7Lxrz8kFunlsh7G98f4wveJ/u6AwuxjmW/v
         H523JDj0Pp1kPKiQTKvI8sXRNiqL5cFaTSR+ArXUEBUh64638t4obj0WPHJ3p/zd9HHV
         +eVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kGuhkOUG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uKWJYD7mn+1M+p2mUUO8qc5nVJNIovOIUtoIdUusv9Q=;
        b=ifJSGsJ+I5t0xZrmagIJAZI448mJSE1/PNJlMcOaVg2nrUsHYOUeCitmXcDpW9trwU
         uTdo+heBncJTMf7UCClKlaU9/EJYAu8U5c5V4rOYbgY6HC+P7qhgrWwLmemXZxonVxwp
         RoSsTUQYH+XLwbBCakKGR8TUsRztbKKXYxc9OlPn6Eb+VxMOqJ2c2ZoRrlfkYd7Oo4NA
         0FzQbwL87OjCrPOggoWjvfp7VCpWcMO2oB30+vrED+RHMA3eBmu2AIpxJM65shr6QC9G
         LCJ3scvcoq8sSZ2XZfQvevQghB5Zx0ENmODSN4mJIhmDK8ouboCB01LNXW+htWJ6eFoA
         WfLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=uKWJYD7mn+1M+p2mUUO8qc5nVJNIovOIUtoIdUusv9Q=;
        b=lzRwP58GaM3D5HPppzBuNQvaeEPu8vN+EHxfPXycz1dmXrxdqHhwmgLn3vzfgTMEi2
         NeUZ28N0peRvM2I3Q6BcpIgVnFsCMPMrUj56IhSCBpqdm2FK04JvsV+lHmtUj4TmDQgU
         kSD+/lRG90glcebd9SRq82V1Ho0YA0lEcrARSe2gbPlooTZqBPQuD5Nk20EezIGR0sg7
         YTqov9HUcH1+fPQD0r4e/mJmQFeTP4uyxgk5xqWuqVBKenc1cj9FM0ucUa6cwowBM3/T
         z5vs3YDF4C2g92SszI2bTuby+ZNiEm/cCxGA7PwcbLwGYFr2o6P3soHWEd737EzT4wB2
         PLcg==
X-Gm-Message-State: AO0yUKXpQv8/+58nkSBlvpr108/9opdfQsUB0iMlMmlipZxVBpiZ/NF6
	Sz1WuB/QXGW5Fgf04vzkzCs=
X-Google-Smtp-Source: AK7set/ZEieugxtkrqzlWBC1KSQg9Z6QoLx9BMQ+BycrvFprhRKwWdDTxdXeBW0bvfhOX/+X91RcHw==
X-Received: by 2002:a05:600c:4ecb:b0:3dc:45a7:ffe4 with SMTP id g11-20020a05600c4ecb00b003dc45a7ffe4mr73826wmq.178.1675245238418;
        Wed, 01 Feb 2023 01:53:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d04:b0:3dc:4f57:78be with SMTP id
 l4-20020a05600c1d0400b003dc4f5778bels700467wms.2.-pod-control-gmail; Wed, 01
 Feb 2023 01:53:57 -0800 (PST)
X-Received: by 2002:a05:600c:245:b0:3db:887:8c8c with SMTP id 5-20020a05600c024500b003db08878c8cmr1327721wmj.27.1675245237224;
        Wed, 01 Feb 2023 01:53:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675245237; cv=none;
        d=google.com; s=arc-20160816;
        b=thjaesUXrDZHlB65+R5y9G3gVJ8p8/v4+m//sIB3tRF5Sfn3RtXQ+4tCYdVO2Z/V2o
         N88GIF/ua7Ny+TN9RlRMqIFIM3oRfghxCvjXq1HMAr3vbXLhG8Tck7ylxG5ujM7GsNGh
         N4LKpWoD2chxT9krlw09G7zMuVze1vbvhpYlhNLrBw8NXlAPV3KFgoa8BTQ5F4e/teuK
         9QUZc70mdkRzHz/6XBe15+Pbu/KY1Ar1/n02Ehy/+yyvGZnuVzCXZkauvNgfuuVh7kDx
         8PlFHihC8gGukA5dBkAPrvvGOUXWwSH3Po7aBirCa7QmeUDbbl7SOIvxNqf6w84TJSQ3
         DpAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hXBLBJgX4EaRecabGDlsbhKYn/5vHTxOlvqGwGoHBPg=;
        b=PExvxzmyB7QQhrxKEtMeT/WKtBzTgzcQvirP8C7xCA9ZD8OSY+LhuYkRPzXfCX0W1X
         3vpGV3I4RfJSe2UPAriB/zo3kC0mtuFY8L1QrV1RAqXtaMQ3azh6im/Z+1R163Zh4+jD
         +mABLDwn/nGH/Wb/YqsdB8gqdHdsyPO6qNxS4LMLLPkyHV9D8H++nQPchF2wH9EHkQr0
         7WA4sRH1B/QgL3iGgC41gu6G5l1tZ8A9UJBqIjY5WIg804OrlSCBeWIZQp4TbbmL/FRF
         MIXYckO4gs4cPowFqbxD35feYYCNK+ut3pQgTYQCgVK04nghs2BRfLUNqlDk+pU5d1r5
         6v2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kGuhkOUG;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id l4-20020a7bc444000000b003da0515e72csi62304wmi.2.2023.02.01.01.53.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Feb 2023 01:53:57 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id d8so6445026ljq.9
        for <kasan-dev@googlegroups.com>; Wed, 01 Feb 2023 01:53:57 -0800 (PST)
X-Received: by 2002:a05:651c:231b:b0:290:7402:78a1 with SMTP id
 bi27-20020a05651c231b00b00290740278a1mr233501ljb.183.1675245236576; Wed, 01
 Feb 2023 01:53:56 -0800 (PST)
MIME-Version: 1.0
References: <20230127162409.2505312-1-elver@google.com> <Y9QUi7oU3nbdIV1J@FVFF77S0Q05N>
 <CANpmjNNGCf_NqS96iB+YLU1M+JSFy2tRRbuLfarkUchfesk2=A@mail.gmail.com>
 <Y9ef8cKrE4RJsrO+@FVFF77S0Q05N> <CANpmjNOEG2KPN+NaF37E-d8tbAExKvjVMAXUORC10iG=Bmk=vA@mail.gmail.com>
In-Reply-To: <CANpmjNOEG2KPN+NaF37E-d8tbAExKvjVMAXUORC10iG=Bmk=vA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 1 Feb 2023 10:53:44 +0100
Message-ID: <CACT4Y+Yriv_JYXm9N1YAMh+YuiT57irnF-vyCqxnTTux-2Ffwg@mail.gmail.com>
Subject: Re: [PATCH v2] perf: Allow restricted kernel breakpoints on user addresses
To: Marco Elver <elver@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@redhat.com>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kGuhkOUG;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22f
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, 1 Feb 2023 at 10:34, Marco Elver <elver@google.com> wrote:
>
> On Mon, 30 Jan 2023 at 11:46, Mark Rutland <mark.rutland@arm.com> wrote:
> [...]
> > > This again feels like a deficiency with access_ok(). Is there a better
> > > primitive than access_ok(), or can we have something that gives us the
> > > guarantee that whatever it says is "ok" is a userspace address?
> >
> > I don't think so, since this is contextual and temporal -- a helper can't give
> > a single correct answert in all cases because it could change.
>
> That's fair, but unfortunate. Just curious: would
> copy_from_user_nofault() reliably fail if it tries to access one of
> those mappings but where access_ok() said "ok"?

I also wonder if these special mappings are ever accessible in a user
task context?
If yes, can a racing process_vm_readv/writev mess with these special mappings?

We could use copy_from_user() to probe that the watchpoint address is
legit. But I think the memory can be potentially PROT_NONE but still
legit, so copy_from_user() won't work for these corner cases.

> Though that would probably restrict us to only creating watchpoints
> for addresses that are actually mapped in the task.
>
> > In the cases we switch to another mapping, we could try to ensure that we
> > enable/disable potentially unsafe watchpoints/breakpoints.
>
> That seems it'd be too hard to reason that it's 100% safe, everywhere,
> on every arch. I'm still convinced we can prohibit creation of such
> watchpoints in the first place, but need something other than
> access_ok().
>
> > Taking a look at arm64, our idmap code might actually be ok, since we usually
> > mask all the DAIF bits (and the 'D' or 'Debug' bit masks HW
> > breakpoints/watchpoints). For EFI we largely switch to another thread (but not
> > always), so that would need some auditing.
> >
> > So if this only needs to work in per-task mode rather than system-wide mode, I
> > reckon we can have some save/restore logic around those special cases where we
> > transiently install a mapping, which would protect us.
>
> It should only work in per-task mode.
>
> > For the threads that run with special mappings in the low half, I'm not sure
> > what to do. If we've ruled out system-wide monitoring I believe those would be
> > protected from unprivileged users.
>
> Can the task actually access those special mappings, or is it only
> accessible by the kernel?
>
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYriv_JYXm9N1YAMh%2BYuiT57irnF-vyCqxnTTux-2Ffwg%40mail.gmail.com.
