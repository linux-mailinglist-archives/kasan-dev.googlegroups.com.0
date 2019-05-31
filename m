Return-Path: <kasan-dev+bncBCVLJ7OQWEPBBUVCY7TQKGQEKDZRBBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 67809318D9
	for <lists+kasan-dev@lfdr.de>; Sat,  1 Jun 2019 03:13:56 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id z11sf5391472otk.7
        for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 18:13:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559351635; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y65DzGqpzcsdSC7jIhBsUg8UHOH2qEs17kvc15XtdG7fssxaVGZERIreSadF1sxrl8
         HOtpMzHlRmt11jeCPmXQD3lm12Ld+Np3btFBh5HeFS/pErptr08VJB42heEk2uDziUyu
         heQqUD7W0Zw8W7lwnByuQTeY58K8Gt8Ck3TipZjakISu3oCjGPfmHKLVpaQFvlS2ULSa
         4qVEZeJ+vpY2QyVgZMW8kBO4UVxPjt157cSpmXE07rs2KZFnsqdrGe0UADg8+nX8iuj/
         wcMCb1L4x4zAuPk+EOI8qEYCuVEtaGqTA6+NjCI62NRJIFrQe1wFsKjnSVM1qLfKZSLq
         weyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:from:cc:to:subject
         :mime-version:references:in-reply-to:user-agent:date:dkim-filter
         :sender:dkim-signature;
        bh=b08VZu2bG8dQrSSekr/GXTd9HEc84NId21DhVTzZywg=;
        b=UDBwNKbt1qm2+W8ig80naJZSKLDnkSiO42WupMZSLU4uqJmeR4nSNX6QKrxED3OzCx
         1+dIyPIMa8UCgE8kbWLk0Amuv+BFVgrkJZpSFgyVaHkKixYBb8qEdtbXd1rZhR/8b2oc
         CUOUaWEY4jb8FmAFyAw+DzrZ7vx7CHXZNjJTahNemWowWjKmfwQmBZUYDBTlrakPNCO/
         CcyVOVXddgjfMlZBS69PmPES2QS8IxpvRahvXjGtcori0jAtEMwT5iikxMgVC3JjrcnR
         jJACXT5z7rgLvPus4Sycnt7k2Fh5YFp3Vfd/pZwo3K7cPie7n6A7Qb37BkmHOGHtprlb
         ar1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=fail header.i=@zytor.com header.s=2019051801 header.b=Afsfgv0m;
       spf=pass (google.com: domain of hpa@zytor.com designates 198.137.202.136 as permitted sender) smtp.mailfrom=hpa@zytor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zytor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:dkim-filter:date:user-agent:in-reply-to:references
         :mime-version:subject:to:cc:from:message-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=b08VZu2bG8dQrSSekr/GXTd9HEc84NId21DhVTzZywg=;
        b=MuL8QP9rxgu8VkrsDFC0oQMIFKoHXs8ocFh3HCrDivnBdYdeJHiOX82HiCfoQmDnZU
         +0xGA3GWfSezTPZ+Db/cZH+lEDwEqtXsw32ILjM5r+cREuiFMkbDwSEroyASSUjTS5Ju
         3tSNQwvT8KscohF+yjh6O4+b2lW3bfP9qGqPka2oI7R3EJL35DA4wGgzwSoDXTOv4VJ3
         fkPlbw+Sve2h6xeXiAT5asLrcWNXfNQPwozWFYgHbdCoFWQbiJuEAtt1FSgJ91mcqTqF
         UqQlJI350N5yQDoXB2/guwJt0ZLzkOVhSF9zTb1hX5DsH5OsLtLWpHB/zMJaQJx2SX2A
         LMmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:dkim-filter:date:user-agent:in-reply-to
         :references:mime-version:subject:to:cc:from:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=b08VZu2bG8dQrSSekr/GXTd9HEc84NId21DhVTzZywg=;
        b=rUWPEtog47NGUqgKI7GPikMzl/2eLlXGe2eEN4aBxPswuZ5jJKyCl0jHpXHhyQhWWC
         sO7VvOPQre0b+R+//XJSIwfxU7lWitGG7tx5vaDl3KX8PWEzIZW8IbgvOzOnS/OqdDS0
         jBwjznOf5gwRyITuxXxplUBcJ3da0eBf6AZTU0yKNzVg18frV9PVTM6cIetSuoLylD+7
         NkjUoAicARd6L2mrmjhZBenAOgFFFzYnFgI5WCKjViDj7npLo4UuLw16f762XADOsRKu
         05ahslpQ3em60qJ6JSNPhnYXKifse1Rv9UZkBwZoapNF42qbouT69uBK7paWocmvdm61
         zh5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVqdn26VanzMabFu2fNaF46evOZBc7N34P8AhFjOnYC8kBBzc/K
	uBD3t1uol1Q+2dj52dLxy9c=
X-Google-Smtp-Source: APXvYqyEGViG2H9Hf/HFDyZuiKDKXby93DV+jdlmgQXQsqdS0RDu9ydtnXVaeSImKzZ9xFY42L8x6g==
X-Received: by 2002:aca:d9c5:: with SMTP id q188mr972576oig.77.1559351634935;
        Fri, 31 May 2019 18:13:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:e651:: with SMTP id d78ls60023oih.6.gmail; Fri, 31 May
 2019 18:13:54 -0700 (PDT)
X-Received: by 2002:aca:4c3:: with SMTP id 186mr948666oie.12.1559351634545;
        Fri, 31 May 2019 18:13:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559351634; cv=none;
        d=google.com; s=arc-20160816;
        b=GfW2tDG04I98OD1SR3VSpKcIZBY82doTLhdo0fFbAtA2ea5jCkNuJ+LVqCxRF9UFlp
         lxZ0xRN1laO1mDpvef4qMawDO7yfPp93ZW+RYQ89VD1PMuTgZJr6l5VbWkaBIALeQywn
         Q9S1mutJd7ECEqTyzDPlVFfsNQcjb6Ne3IM2bavb50hAsq75oU+5Du4FMy94WWDQ/0Xm
         5edQtcTIiqpzT+3kwnhDcXs/1LxxQ/hrLk0byZbejut8jgbnh3qz9OXyFzYKGhT6HJyq
         2K7tBGs1MQfUfCg1EVP3v4Ng/69G+dzOLSoWK3zDjCCHO723U/SB8EMwBNCZTbIXnwno
         xX/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:from:cc:to:subject:content-transfer-encoding
         :mime-version:references:in-reply-to:user-agent:date:dkim-signature
         :dkim-filter;
        bh=CuGVe8YH5AlNt8m91Od8n8Cr+8ORd3+2zjg1HKvHIqA=;
        b=ugDrVp+e2KNQlH4U0P8dFoz+dUpWdtWG+wso4/w1fMUdifNlhneJ1dwdIp+lqsOQmA
         eSDx1u+AkSXJGmO0P31Dw4x5n/VSEK6wyTgQe1gyQkScyX/0YWerYwvmvwO3OmYiT07a
         RkLLEDWh/q9yJJSmMSZzDlbTw4zx1k4gE0fWQP3tWtJBvdrMwgjH8KPUDEYAVfqgQMJ3
         4ppCL8gJ7fx9qayMFJO/lHNWWWlqd28IczQi0hBMZKYeBVWF2Hhhs6iweg3+Co1O2sk1
         is6T0j94UZzTimNWwgPjffx6JQzaKoBrAamIGEiJAGDO5/0negtWfcAxLq6TfPVLDZBm
         DeOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=fail header.i=@zytor.com header.s=2019051801 header.b=Afsfgv0m;
       spf=pass (google.com: domain of hpa@zytor.com designates 198.137.202.136 as permitted sender) smtp.mailfrom=hpa@zytor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zytor.com
Received: from mail.zytor.com (terminus.zytor.com. [198.137.202.136])
        by gmr-mx.google.com with ESMTPS id k22si317985otp.1.2019.05.31.18.13.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 31 May 2019 18:13:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of hpa@zytor.com designates 198.137.202.136 as permitted sender) client-ip=198.137.202.136;
Received: from [IPv6:2607:fb90:3627:8679:c06a:8bb1:5a73:12ff] ([IPv6:2607:fb90:3627:8679:c06a:8bb1:5a73:12ff])
	(authenticated bits=0)
	by mail.zytor.com (8.15.2/8.15.2) with ESMTPSA id x511DX2t3668045
	(version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128 verify=NO);
	Fri, 31 May 2019 18:13:34 -0700
DKIM-Filter: OpenDKIM Filter v2.11.0 mail.zytor.com x511DX2t3668045
Date: Fri, 31 May 2019 16:41:46 -0700
User-Agent: K-9 Mail for Android
In-Reply-To: <CANpmjNOsPnVd50cTzUW8UYXPGqpSnRLcjj=JbZraTYVq1n18Fw@mail.gmail.com>
References: <20190529141500.193390-1-elver@google.com> <20190529141500.193390-3-elver@google.com> <EE911EC6-344B-4EB2-90A4-B11E8D96BEDC@zytor.com> <CANpmjNOsPnVd50cTzUW8UYXPGqpSnRLcjj=JbZraTYVq1n18Fw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Subject: Re: [PATCH 2/3] x86: Move CPU feature test out of uaccess region
To: Marco Elver <elver@google.com>
CC: Peter Zijlstra <peterz@infradead.org>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@google.com>,
        Mark Rutland <mark.rutland@arm.com>, Jonathan Corbet <corbet@lwn.net>,
        Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
        Borislav Petkov <bp@alien8.de>,
        the arch/x86 maintainers <x86@kernel.org>,
        Arnd Bergmann <arnd@arndb.de>, Josh Poimboeuf <jpoimboe@redhat.com>,
        "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
        LKML <linux-kernel@vger.kernel.org>,
        linux-arch <linux-arch@vger.kernel.org>,
        kasan-dev <kasan-dev@googlegroups.com>
From: hpa@zytor.com
Message-ID: <3B49EF08-147F-451C-AA5B-FC4E1B8568EE@zytor.com>
X-Original-Sender: hpa@zytor.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=fail
 header.i=@zytor.com header.s=2019051801 header.b=Afsfgv0m;       spf=pass
 (google.com: domain of hpa@zytor.com designates 198.137.202.136 as permitted
 sender) smtp.mailfrom=hpa@zytor.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=zytor.com
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

On May 31, 2019 2:57:36 AM PDT, Marco Elver <elver@google.com> wrote:
>On Wed, 29 May 2019 at 16:29, <hpa@zytor.com> wrote:
>>
>> On May 29, 2019 7:15:00 AM PDT, Marco Elver <elver@google.com> wrote:
>> >This patch is a pre-requisite for enabling KASAN bitops
>> >instrumentation:
>> >moves boot_cpu_has feature test out of the uaccess region, as
>> >boot_cpu_has uses test_bit. With instrumentation, the KASAN check
>would
>> >otherwise be flagged by objtool.
>> >
>> >This approach is preferred over adding the explicit kasan_check_*
>> >functions to the uaccess whitelist of objtool, as the case here
>appears
>> >to be the only one.
>> >
>> >Signed-off-by: Marco Elver <elver@google.com>
>> >---
>> >v1:
>> >* This patch replaces patch: 'tools/objtool: add kasan_check_* to
>> >  uaccess whitelist'
>> >---
>> > arch/x86/ia32/ia32_signal.c | 9 ++++++++-
>> > 1 file changed, 8 insertions(+), 1 deletion(-)
>> >
>> >diff --git a/arch/x86/ia32/ia32_signal.c
>b/arch/x86/ia32/ia32_signal.c
>> >index 629d1ee05599..12264e3c9c43 100644
>> >--- a/arch/x86/ia32/ia32_signal.c
>> >+++ b/arch/x86/ia32/ia32_signal.c
>> >@@ -333,6 +333,7 @@ int ia32_setup_rt_frame(int sig, struct ksignal
>> >*ksig,
>> >       void __user *restorer;
>> >       int err = 0;
>> >       void __user *fpstate = NULL;
>> >+      bool has_xsave;
>> >
>> >       /* __copy_to_user optimizes that into a single 8 byte store
>*/
>> >       static const struct {
>> >@@ -352,13 +353,19 @@ int ia32_setup_rt_frame(int sig, struct
>ksignal
>> >*ksig,
>> >       if (!access_ok(frame, sizeof(*frame)))
>> >               return -EFAULT;
>> >
>> >+      /*
>> >+       * Move non-uaccess accesses out of uaccess region if not
>strictly
>> >+       * required; this also helps avoid objtool flagging these
>accesses
>> >with
>> >+       * instrumentation enabled.
>> >+       */
>> >+      has_xsave = boot_cpu_has(X86_FEATURE_XSAVE);
>> >       put_user_try {
>> >               put_user_ex(sig, &frame->sig);
>> >               put_user_ex(ptr_to_compat(&frame->info),
>&frame->pinfo);
>> >               put_user_ex(ptr_to_compat(&frame->uc), &frame->puc);
>> >
>> >               /* Create the ucontext.  */
>> >-              if (boot_cpu_has(X86_FEATURE_XSAVE))
>> >+              if (has_xsave)
>> >                       put_user_ex(UC_FP_XSTATE,
>&frame->uc.uc_flags);
>> >               else
>> >                       put_user_ex(0, &frame->uc.uc_flags);
>>
>> This was meant to use static_cpu_has(). Why did that get dropped?
>
>I couldn't find any mailing list thread referring to why this doesn't
>use static_cpu_has, do you have any background?
>
>static_cpu_has also solves the UACCESS warning.
>
>If you confirm it is safe to change to static_cpu_has(), I will change
>this patch. Note that I should then also change
>arch/x86/kernel/signal.c to mirror the change for 32bit  (although
>KASAN is not supported for 32bit x86).
>
>Thanks,
>-- Marco

I believe at some point the intent was that boot_cpu_has() was safer and could be used everywhere.
-- 
Sent from my Android device with K-9 Mail. Please excuse my brevity.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3B49EF08-147F-451C-AA5B-FC4E1B8568EE%40zytor.com.
For more options, visit https://groups.google.com/d/optout.
