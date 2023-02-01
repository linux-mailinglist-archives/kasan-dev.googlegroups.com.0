Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGPE5CPAMGQEXUDVWIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 84DAD6862E9
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Feb 2023 10:34:19 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id cn7-20020a05622a248700b003b7f2a89829sf7911710qtb.6
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Feb 2023 01:34:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675244058; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z0PIaKOaM3o+1ukcOTtSABtedi1yZ1r95M83S1owYiG25tINwywnrMK+FuqqtOdLKn
         HqatWiZd+jGvDvBViNg3Vw8xYCUDPKwlC5S5lQWH5JBLXoqJXZOMUY559WqdPG4R/luI
         kb2eMTdbMcAb9z9KdFlqxlcN4PuBkiQJZnP/6DkPgzP8I4wa+uj5PLnbeIhldXqP8kDm
         DbpKGqRov+Peep99q2f27wUU24QIu4uhRB/bJ2X4L8OLalUwNj6tyK+X74Sf5LRDmgpb
         4tEqLXjE8CvKEMoH84VjkMNlY0LlapN3/G4tIlB+DYk9i75KkNNtOtqEZiH/Sa6U1ObF
         0tbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=avhd6vaazpuhftOB8PPL9eZwKi3Ym1ur9GQzeV1N3oE=;
        b=aI2ZSw78i5MAOmWb9hxtZrMROvdtbvINnL0P0RK6s05WKGmfbuhX108BufsGiUPO+K
         rm2Y09Bztm0R1srzBmBcH8VAS2RVATLNQrducIFhrvhQdwHosNSAL7o8Kk95Cyr/y1WN
         1cjXHTHY0kUl/SCkrCJaHDkaYnyT560tAlVA/RzMSRNK1c5tApAMWyl1FVKnMYR1dK9X
         10ravuJn0Pgfl9Idmh4xWz6G/DVVzS768PNkMOYBY4bxYigrzOBkXkuuIIgl+p+SJMNB
         e2AtDKR7NigKMAQ65x7cUE+IPp0xlAwuje4PDhmlRkvgMvSpWkKc1hgqrsl7oykWYu22
         6vqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bVa6yGtr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=avhd6vaazpuhftOB8PPL9eZwKi3Ym1ur9GQzeV1N3oE=;
        b=aFg9kkS2k/8uwGGSJ4tbEuq/YZxELOWy4mLSy4kgL73Zz61jPMl25ESTWOt1fCS/KX
         19yX0/u4PlqjfXV/0dN5TU9fNENkY5j8IIX2Yh3rwz+b5RgmPU8Fxg0qClK2zyLeHhNX
         nUqw6tEpzPFq+hb7LSXWjEcijwWnpLqg1//OkyPryRnEVFv0tJbj4//qg0GpK8SQwpz4
         126z2s6BOenAoa9sw6QeJREYLQhyp/RlvZ/Q0AclnBVtozuGd9C0uZw7sQAhnw7kgNwK
         9GtWe5zUI5ciNRTqf6turFKM9Gj1oljCyGOEcEmvC6fBymHl2aulwKNXGslzYlJ4Pf5+
         vzAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=avhd6vaazpuhftOB8PPL9eZwKi3Ym1ur9GQzeV1N3oE=;
        b=spD4qhFLGlZvEayj89BdjmtXOKH/2htBx3Sp9fsiCRDD6UECBoyZVBPozNr2aPfNTt
         NMk+aHjpHeS7xYAX2WVFcnQv824X555NgdTVu+wcXz7vyfg0US+nvGswBeAVHEmynQrz
         SvsSeJhZgHKNrO/AgKAON4JQakYfZW6CUF9PemwSDVdIf5qr8zdDZI/VGdtV/AIzt/Bz
         GTn1uTdPIoS6cln7kDkOXV0BVVMogg1Ggif6mv4jTthDTYOnxRQUf7q61gG33JvsGBMM
         6gmEK8IcD6q+GqAIFpykOYN7JD4cGcIpjvL7PLw49IvbKp/SEiOCGOVr1UdrfIwTYN2z
         lImw==
X-Gm-Message-State: AO0yUKWquqsDc/UMtCwN2S06n+TUh3rRBkrf6itkuBZrSVc+JENTI0i+
	/NfmqW4MHMvmZ//DT7O+Fi0=
X-Google-Smtp-Source: AK7set/1IAIU3hDwS4jeCIagalpA5hZjA+hHMMne3A4KBtMH5Z5ryRYdxzKTo0yZbQPryJGfgPfu0g==
X-Received: by 2002:a37:789:0:b0:729:30e8:83e0 with SMTP id 131-20020a370789000000b0072930e883e0mr123648qkh.304.1675244058094;
        Wed, 01 Feb 2023 01:34:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:98b:b0:3b8:2529:98c4 with SMTP id
 bw11-20020a05622a098b00b003b8252998c4ls7134975qtb.9.-pod-prod-gmail; Wed, 01
 Feb 2023 01:34:17 -0800 (PST)
X-Received: by 2002:ac8:4e81:0:b0:3b8:6ca4:bb23 with SMTP id 1-20020ac84e81000000b003b86ca4bb23mr2927500qtp.15.1675244057422;
        Wed, 01 Feb 2023 01:34:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675244057; cv=none;
        d=google.com; s=arc-20160816;
        b=RtL9vSZZfVlJv16uw/DYZG8lnyNlUJXgEZ/uGFJQxToi7Y8XTBzELXfpIoi1qLhCw/
         qP3/cS681lLeKSKuz5h94qr/vZH0baOTNA3+9X7Lx0CnWD+ftG2cG2x8SzDy7wD6oNlM
         cwts6QNOiC/hvszCq+m77u6tk9crSxeUdOpW3hA/vikmkXscqkYJ8kGyvb4N7M0qJU8T
         mIUk9QIr1fTHu1zCfna9w6LjpbBPRKNPo3lsnVTnOmcDrE1hHAzo9L7BsMDV+KsFgF4J
         qIKL+Yu+amj9UnUv+AoTGdcLzA4xwHu85yPQjdPap6crI5sbf1470X/No80mmsonuEGF
         S/eQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zhWSgBLB/d7CBkiS7vUeRrl+u5WlVlYA2/RDeWKtD4s=;
        b=atw84LGAcozP720oAub1ma7FImopOp7gzCkZcgVDBbSa9SjYi/QdyW4grVa66kxeBk
         VEK0nzfB5j8nA6NYbNDiQp8hzRcxD/jW5xXBcAMxEJd5lT7uXcBCzAQSk9Nb/qM92kfb
         eE3kjjd7jBY0sSw4VW5RiiejZ3G/+PiocF1krnX/MBNZ1m5hIwvjQC75lEP1+2H+I8kS
         inVxT2hMtCcxOZZNRmDmlyyjGj0xp6y6OWf6mo1EugnFpdN6jMPP+RIXlNnr5g7yLB46
         tFBVA8VBjri0593V8Tezm8JA4WeWkipcmCvK9EPosjvOJpFhkbqRyh5bfYT2VY3PYflO
         x0RA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bVa6yGtr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id fy14-20020a05622a5a0e00b003b86bcd62dcsi681051qtb.1.2023.02.01.01.34.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Feb 2023 01:34:17 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-4a263c4ddbaso238782157b3.0
        for <kasan-dev@googlegroups.com>; Wed, 01 Feb 2023 01:34:17 -0800 (PST)
X-Received: by 2002:a81:fe02:0:b0:506:369c:69c1 with SMTP id
 j2-20020a81fe02000000b00506369c69c1mr221926ywn.192.1675244056986; Wed, 01 Feb
 2023 01:34:16 -0800 (PST)
MIME-Version: 1.0
References: <20230127162409.2505312-1-elver@google.com> <Y9QUi7oU3nbdIV1J@FVFF77S0Q05N>
 <CANpmjNNGCf_NqS96iB+YLU1M+JSFy2tRRbuLfarkUchfesk2=A@mail.gmail.com> <Y9ef8cKrE4RJsrO+@FVFF77S0Q05N>
In-Reply-To: <Y9ef8cKrE4RJsrO+@FVFF77S0Q05N>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 1 Feb 2023 10:33:40 +0100
Message-ID: <CANpmjNOEG2KPN+NaF37E-d8tbAExKvjVMAXUORC10iG=Bmk=vA@mail.gmail.com>
Subject: Re: [PATCH v2] perf: Allow restricted kernel breakpoints on user addresses
To: Mark Rutland <mark.rutland@arm.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=bVa6yGtr;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as
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

On Mon, 30 Jan 2023 at 11:46, Mark Rutland <mark.rutland@arm.com> wrote:
[...]
> > This again feels like a deficiency with access_ok(). Is there a better
> > primitive than access_ok(), or can we have something that gives us the
> > guarantee that whatever it says is "ok" is a userspace address?
>
> I don't think so, since this is contextual and temporal -- a helper can't give
> a single correct answert in all cases because it could change.

That's fair, but unfortunate. Just curious: would
copy_from_user_nofault() reliably fail if it tries to access one of
those mappings but where access_ok() said "ok"?

Though that would probably restrict us to only creating watchpoints
for addresses that are actually mapped in the task.

> In the cases we switch to another mapping, we could try to ensure that we
> enable/disable potentially unsafe watchpoints/breakpoints.

That seems it'd be too hard to reason that it's 100% safe, everywhere,
on every arch. I'm still convinced we can prohibit creation of such
watchpoints in the first place, but need something other than
access_ok().

> Taking a look at arm64, our idmap code might actually be ok, since we usually
> mask all the DAIF bits (and the 'D' or 'Debug' bit masks HW
> breakpoints/watchpoints). For EFI we largely switch to another thread (but not
> always), so that would need some auditing.
>
> So if this only needs to work in per-task mode rather than system-wide mode, I
> reckon we can have some save/restore logic around those special cases where we
> transiently install a mapping, which would protect us.

It should only work in per-task mode.

> For the threads that run with special mappings in the low half, I'm not sure
> what to do. If we've ruled out system-wide monitoring I believe those would be
> protected from unprivileged users.

Can the task actually access those special mappings, or is it only
accessible by the kernel?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOEG2KPN%2BNaF37E-d8tbAExKvjVMAXUORC10iG%3DBmk%3DvA%40mail.gmail.com.
