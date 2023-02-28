Return-Path: <kasan-dev+bncBDW2JDUY5AORBQXO7GPQMGQEUIHISBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 63EF66A61BE
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 22:51:00 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id k10-20020a92b70a000000b00316fed8644fsf6650309ili.21
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Feb 2023 13:51:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677621059; cv=pass;
        d=google.com; s=arc-20160816;
        b=r8jeduE7AQ39d+aamymeRbEBoF4m2KwqOVIm0I2yy2EA9Cj402Xr+uQ/F4R4RKORSk
         CfY3dwh6sg8ncP0vMdxV5o2bsBrQdg3wBYxBDmjfjf6eHmMv4CKOqwus2tw0R5ajAmwh
         sbW6dmt4oNigYLhqIrzoJkwOXBETEytH9RTqa4Ry5UfmsjsX8A8BE6DHab7ZAHIObI/u
         A2h/xbzkDojlV5JRmW6J5VO+QUFRlcVjL58B3CkYreu+enbqCBBHQ6tvXXPYgTELIgXr
         8EyKU13DdNV2p1XlbXFSb7fMgpLJKE06mlNWzDAFbXiTlRAaZzlfsTR+i9fDe1dU23He
         nGfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=aQ2fxV6ZVaU8CJ38Cs/z4EUuopl360dWwpheYPt1ygc=;
        b=UzIOeoyLvaDubH08rVIsPeK2YYIwI0RpMJeZn4Y5/yhuwAIqhpprz/UL1xMJMg1DJk
         0FStrRgcFvN8QTM8anedYIuScYjwKOIUsFy7yYmrU3tJ6tRZggwTq98/yBEuMlWJzMd3
         15/FFC3MSq14ccHsm+ZDkva7sseWFd381y17uOxGmxNLt2O1CDPFvDLv/kKmEX+Ol3ML
         EqQASe9eJgDYNhInBKKzGdvSch3/bwtHdtZJJaImG3tZVGFV7gbwZZmCiWxmAtHdisHl
         cUuAQzmxQOBu+BQ4LWL8ox+WNZ5J1PZfVUhuI5CBETGiCxo2Niaqp4h2GjOuZyNd7YRc
         sIuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="B9/smwhj";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=aQ2fxV6ZVaU8CJ38Cs/z4EUuopl360dWwpheYPt1ygc=;
        b=iEfPPwfboYoSJmUAuxlN38urJLWSYuPMTnXT0yNGhnZmGl9+Pwvj7Z2saNwZgCTpbS
         NXb3WI4pnNpXVg3g3Js/l9/kuxm12M3yEwQzSPTgj2mPVzMTkDgK263rgTiSz9b4Bym2
         JQ5qTufCClL4l7XRlOwMYnB91ahAylj4+UwpCsZ8Q8i7X75C0GBlH+Bt4dmLGV+IIHKR
         GqS44PnnJHq13HdWUlCRq8J/JHWQb3YIU3Hek+mmhSehdN+fSegAkXa8AJx3Q6B7aee0
         kv4z5R5NzZN9L8ZoDwy2ehlKOFfqwBMm+OjbeVFBFrKzN/WxYaSpqZVluC8UeGFG8Rnt
         v+mA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=aQ2fxV6ZVaU8CJ38Cs/z4EUuopl360dWwpheYPt1ygc=;
        b=lvMptFtO/Utc0UWi9yD2naB/fKicrHi7iJ96wz1hS1l2/kdg7pRTVO3GORSbFl/49M
         /9AIc7L3YjJaX4Cy1541NQe7kUuyr4z4866oMc3jz6ZAhR6WA787gOsk7rPY86TUMFjV
         soKYLOd06yHuOWN5XG96m7S0QstDD+XRlUbncqYGd8Q+nGZ6blA8d3gzVIAAlkCy6Y9N
         /eZwPFG9B4LMp6chWf6XKi5uN1Uq/BBjmm3L+E8b5Jq49wpltSrbwVsp0k+cV1es6NE5
         vkc6Xy+nWoaaFvyjepFYpyBiqG6CojfYaFXD1iQ8wJ2wpv28nm3YubRkYXrr8wDzQOgc
         WM3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=aQ2fxV6ZVaU8CJ38Cs/z4EUuopl360dWwpheYPt1ygc=;
        b=jEes4hFyz7roaOMBKjIxIzAXKFePLQvrsf+3DYHv7X7Nabt10W1dRDTFpBCvwDF7Vb
         4pkH5wTizpj4hSft4uyIjEX8P3PF9M9/pq4GaHAwg7cwEgxpxJ+6Lg4WSWsYwOg225B3
         +SjO6brraVp93N0RRVCY4LiLB6o4XKenkPmrAGvKMl0ssxhu6llVCB5VkKp1Wfjc+WH6
         epS5L3paCudEgtWiY8BGQ6ct83nUm8OiaFpL4t9YQzGcxMgUjwuvasw64FMqba5mYLlQ
         WZUeLJBKTFV+IlvqnOXZ74OCalz2dwoSKnxoOjS3I7NV8h8iPuFOS/DY/ydWTzzhmRNf
         pGeQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWLf2VF8UUyIX14K7+Puy5q0OCvNk9X9b8JCLF4s1fbQSgmOZyQ
	s7cvhc5d+Cu18M0K0CyS80s=
X-Google-Smtp-Source: AK7set/GdSZGfUSH9B7vt6tOLSV78t2fXHV/iFJH6AKotUY0kr2WjhBf9/RS/b4uY1Te4H6Xtl8FpQ==
X-Received: by 2002:a92:6d05:0:b0:315:8de2:2163 with SMTP id i5-20020a926d05000000b003158de22163mr2051782ilc.5.1677621058915;
        Tue, 28 Feb 2023 13:50:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c38d:0:b0:315:326d:f382 with SMTP id d13-20020a92c38d000000b00315326df382ls5982005ilp.11.-pod-prod-gmail;
 Tue, 28 Feb 2023 13:50:58 -0800 (PST)
X-Received: by 2002:a92:c243:0:b0:317:f50:383b with SMTP id k3-20020a92c243000000b003170f50383bmr3283806ilo.27.1677621058457;
        Tue, 28 Feb 2023 13:50:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677621058; cv=none;
        d=google.com; s=arc-20160816;
        b=ljz610RgHlH0gVUqyOBNgAQkNjwI+usqeflXG8cosk+IvWPCpEFxSOBRJy0qSgGGUn
         hG1H5spJzegwijmNfpEs4YyiFI+RCZpXKMVXGGRFPH/7+Bcl/f6XJoNWk0iitA8cplOe
         Mu5xPG9OTKvU/eMZwCxMIvO/E+5+6EKDAOS9+Qr9GLxe56lH/s1n7jbqjD52kz7e53Md
         43NnBFV6ttXK1KM5gVUFQezEtdV+AtQabZDMRXkpnpJxkmuMNjho0vG4hHKYjAJKswgq
         /uWi2uoTVoD+mrcWSGs1Q4A97c3Cl2pi6c+8ctoyHxRxx3uIVY8fuhgXbb0RcPXQV8lP
         r+oQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0LVmFrLrm92phvm/Baac+5/XWBy/z8f4Ods8WhgeHYw=;
        b=t0Y3kRBJgXCTv8Zp1aeoIrzBtBFSwpAKGbRCYcXWGGAIduUK2ynZ+QGfeW0NwfdtJV
         INQjlM1ci0DMnQCPrWBC+ePHNH0t/+RMSxQPlsc6/Wrh1oKCAfiwaUxfeAnYDBKW19um
         ay2SMmS0xp+EGFO8GPEvA/pUHm56GrVTbCZAUGt+uTyeKuPO9PCmeyBN1wOYm6j3nNzX
         p6j9Uwd/bwL71FyK1fEZvDPx6mO+RY6SvrDbf7OPe5nuCfBaqcQ6sUnMnkCM628vAH4F
         ntVqirO2IlvZfXOizfxD5iZQyNhRu2mp5obWtcVeKJEu4CLWxcd1uVAmCwc75M/5aQI1
         ZOrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="B9/smwhj";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id q1-20020a056638344100b003636f49184dsi1067638jav.7.2023.02.28.13.50.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Feb 2023 13:50:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id qa18-20020a17090b4fd200b0023750b675f5so15114497pjb.3
        for <kasan-dev@googlegroups.com>; Tue, 28 Feb 2023 13:50:58 -0800 (PST)
X-Received: by 2002:a17:903:2591:b0:19a:8bc7:d814 with SMTP id
 jb17-20020a170903259100b0019a8bc7d814mr1498018plb.13.1677621057764; Tue, 28
 Feb 2023 13:50:57 -0800 (PST)
MIME-Version: 1.0
References: <20230209031159.2337445-1-ouyangweizhao@zeku.com>
 <CACT4Y+Zrz4KOU82jjEperYOM0sEp6TCmgse4XVMPkwAkS+dXrA@mail.gmail.com>
 <93b94f59016145adbb1e01311a1103f8@zeku.com> <CACT4Y+a=BaMNUf=_suQ5or9=ZksX2ht9gX8=XBSDEgHogyy3mg@mail.gmail.com>
 <CA+fCnZf3k-rsaOeti0Q7rqkmvsqDb2XxgxOq6V5Gqp6FGLH7Yg@mail.gmail.com>
 <b058a424e46d4f94a1f2fdc61292606b@zeku.com> <2b57491a9fab4ce9a643bd0922e03e73@zeku.com>
 <CA+fCnZcirNwdA=oaLLiDN+NxBPNcA75agPV1sRsKuZ0Wz6w_hQ@mail.gmail.com> <Y/4nJEHeUAEBsj6y@arm.com>
In-Reply-To: <Y/4nJEHeUAEBsj6y@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 28 Feb 2023 22:50:46 +0100
Message-ID: <CA+fCnZcFaOAGYic-x7848TMom2Rt5-Bm5SpYd-uxdT3im8PHvg@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: fix deadlock in start_report()
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: =?UTF-8?B?6KKB5biFKFNodWFpIFl1YW4p?= <yuanshuai@zeku.com>, 
	Dmitry Vyukov <dvyukov@google.com>, 
	=?UTF-8?B?5qyn6Ziz54Kc6ZKKKFdlaXpoYW8gT3V5YW5nKQ==?= <ouyangweizhao@zeku.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Weizhao Ouyang <o451686892@gmail.com>, 
	=?UTF-8?B?5Lu756uL6bmPKFBlbmcgUmVuKQ==?= <renlipeng@zeku.com>, 
	Peter Collingbourne <pcc@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="B9/smwhj";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Feb 28, 2023 at 5:09=E2=80=AFPM Catalin Marinas <catalin.marinas@ar=
m.com> wrote:
>
> On Mon, Feb 27, 2023 at 03:13:45AM +0100, Andrey Konovalov wrote:
> > +Catalin, would it be acceptable to implement a routine that disables
> > in-kernel MTE tag checking (until the next
> > mte_enable_kernel_sync/async/asymm call)? In a similar way an MTE
> > fault does this, but without the fault itself. I.e., expose the part
> > of do_tag_recovery functionality without report_tag_fault?
>
> I don't think we ever re-enable MTE after do_tag_recovery(). The
> mte_enable_kernel_*() are called at boot. We do call
> kasan_enable_tagging() explicitly in the kunit tests but that's a
> controlled fault environment.

Right, but here we don't want to re-enable MTE after a fault, we want
to suppress faults when printing an error report.

> IIUC, the problem is that the kernel already got an MTE fault, so at
> that point the error is not really recoverable.

No, the problem is with the following sequence of events:

1. KASAN detects a memory corruption and starts printing a report
_without getting an MTE fault_. This happens when e.g. KASAN sees a
free of an invalid address.

2. During error reporting, an MTE fault is triggered by the error
reporting code. E.g. while collecting information about the accessed
slab object.

3. KASAN tries to print another report while printing a report and
goes into a deadlock.

If we could avoid MTE faults being triggered during error reporting,
this would solve the problem.

> If we want to avoid a
> fault in the first place, we could do something like
> __uaccess_enable_tco() (Vincenzo has some patches to generalise these
> routines)

Ah, this looks exactly like what we need. Adding
__uaccess_en/disable_tco to kasan_report_invalid_free solves the
problem.

Do you think it would be possible to expose these routines to KASAN?

> but if an MTE fault already triggered and MTE is to stay
> disabled after the reporting anyway, I don't think it's worth it.

No MTE fault is triggered yet in the described sequence of events.

> So I wonder whether it's easier to just disable MTE before calling
> report_tag_fault() so that it won't trigger additional faults:

This will only help in case the first error report is caused by an MTE
fault. However, this won't help with the discussed problem: KASAN can
detect a memory corruption and print a report without getting an MTE
fault.

Nevertheless, this change makes sense to avoid a similar scenario
involving 2 MTE faults.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcFaOAGYic-x7848TMom2Rt5-Bm5SpYd-uxdT3im8PHvg%40mail.gmai=
l.com.
