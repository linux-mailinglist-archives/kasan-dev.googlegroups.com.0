Return-Path: <kasan-dev+bncBDX4HWEMTEBRBW675H4QKGQE5PAG6HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 894D82465BA
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 13:54:04 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id u66sf710436uau.17
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 04:54:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597665243; cv=pass;
        d=google.com; s=arc-20160816;
        b=ru3NtCNedmfReSATLGVrnPMbGlESSq0bL95d8K3nBIy+8EzEsLyzMzsrErgxtVTT8c
         InvuoqF/UrUrV8hUc1JdBIQoMwj+rf56XYsfqYA5eHV/HoWYCKAWKA1G23Cv1xDYFnLC
         /jQv46NZu24gT/DaisjnwxvOyp5POLh53TBRWFbKUMyUbH1nqtSAsh+iMTcscYStFhhb
         iVYL7rvF11GJFHiaxXVlGOx5ZE/FLOxh98wwPcalvoldILXd4ZnsBQJyg0Lnoa99oRD9
         qH770N8KOLkEqasSU7f1vGzF/F4mo21Prqy/nlsvHo6jMvtUA1aoAq9X6b6UVr1AYJ4g
         ZKkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2XBmMPw22ZHljSV0+r3tz+021flgjlJhc7/hmUhtK3o=;
        b=F4++7mYGutDr4HiIXyFBlTsu5Z/q5MzE/eMZSGK+dOSdFW6BhK2i+rYmpM6+MeE2z+
         6KMgUz7p6tVCbV7dtrD+W3dylyy4ESWGo5ZsnyQS/yruAykJZoOwifL+efz3lSg0Ceg7
         E8DpP1wRYRz2BkZwqKOdXgDKOMUn8hYjRRqpmlLI0bKQJn5ITRq8uTXjf7my8y4eiKO6
         sxm2UO6TpdE4PgJ0KSbFA1leTW+mtK2PEk/LfAzAVX4PTqoW9LZQSo93Oxlt8BMu0kPi
         a4bzh64vkwQUQfmGdImIJ+qZOQTNjCu8HbJMAMAEivTTBSQFhxl8GemXEkvqiwlQrFVA
         3Stg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cUo2YqnI;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2XBmMPw22ZHljSV0+r3tz+021flgjlJhc7/hmUhtK3o=;
        b=nvBJQuU4Blz/GxzvArvDv57NqgqLalIRrNfLdxg5XwcAhUrsG4+4fD6khXlyw1eorZ
         8nQ3FSKHpPgVwYIst7GHvNY5wJlrVc5D7hTUJDOy+Y2UCcjMZIO3NT9STrykTGsarHzc
         nMOwbWCq57vpDqed05CpLAFYwfjCnAWYXHiPpu7+VkViQQMocsR5hT/sKg/EdQgfW+Yk
         sNH4BuCJqBRQGUjAeKurMlOX9gg3uxQaLDfz3q9SQ42PuFZa63AGheo9vw9bN1F6r5An
         QrzOGfsSSyEJDHJ6jwdaThaBY6UEZkf/0aA6F9XAIIYYdvkceihfZQa9yUonYOxHvLcR
         sXXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2XBmMPw22ZHljSV0+r3tz+021flgjlJhc7/hmUhtK3o=;
        b=LVFO1lQRlCViYcsk3uWg62MRYYkyZ+woPBfTPSgpGr9ek2EH30qsB3TYKh07TE+LzX
         9mzO3GbPDHve5eA2XzZ+mThn15mkkvRWDkJ2i84tCHYbjTaGb83tX5rbxVpyMYX+U3If
         Z7GHoYQSTZbeTEMu7BCAPLDZl1lRYr7I10DMsAqnnsLUCCdv2kQhuga4lvkn0F72CpM4
         ankd/rovxjtElTaiP6n1zS0z1HtOKNH8tytWzn2f/CAm5d7fD1fHi9rDC0wHl2DRlDP9
         z+8UeX7nrSRNDNdbgUJe1ovI692oOeNogLprWXT1UqsS+8+MyNrDpod8RvODgIw8hmvp
         gkxw==
X-Gm-Message-State: AOAM5332kYGTOU/m6581vmSt4/Va3XZicO+W5IbzXK1CuhTgq9cnN5OF
	pv4aCTVY6nIzCUlOOGG56ww=
X-Google-Smtp-Source: ABdhPJyXI4yC8u1paBJ9k8piqrFhA5RGptF7tVKrPD/h3cm1ErTMrLnZDADMtjEgREm8BqanKjoHEQ==
X-Received: by 2002:ab0:804:: with SMTP id a4mr7309422uaf.3.1597665243547;
        Mon, 17 Aug 2020 04:54:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7f0b:: with SMTP id a11ls1822362vsd.1.gmail; Mon, 17 Aug
 2020 04:54:03 -0700 (PDT)
X-Received: by 2002:a67:c294:: with SMTP id k20mr8325920vsj.166.1597665243117;
        Mon, 17 Aug 2020 04:54:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597665243; cv=none;
        d=google.com; s=arc-20160816;
        b=i99sC8bVlu9lP2+mg0zD7E+gMmUa0W27vAWA7iHAxC2cILb3joScPHiciJ694Wvj2N
         Z0UrAoiEoxTmwMku5rvIUKxNT49FNAb6fQcy8MVLowmzENhQu/LZFKqC6wV7d/nMX6dN
         4cfkK9+bxWB/hhSIGEUtmYhONqLZupsMKIGSrq/P9vGG30LzxjBWehTePg/8nPUMsIej
         HHm6M9AwN2mkmddkD7dW9DpA23cL3xn3iVH1Vs0jkvKFDqHY17FkH+oB3PPlCzq+f4DT
         138FjV8IIhvG8pc74vxKuj2rxpkqxqB2SM6JTh1w4n1s/8sxHITaYRffidDHgSF+9478
         JvZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CPagJq8bfLV5JHleSz/YdyHxTxcPKxeM2AT318YsVDU=;
        b=niMCeuPCNmscvNQCJFhHNvyYfpUVtcEg5hbJXCzaQG2dV/HQZKYSoVIKjISxIWK8oS
         nCbN+MniZTSZ7nRr0Vx/qF9u/y3Zo2N/CeGPIZySOKSaA6MHHgwLP7lqEx9nrFX7JcvC
         EUiFY39rI99Nnv0mEGOlEKnUI+XhnKiZgJIrXgsH7LeYUNMhyozA4I3B5Ds/aucoZDWI
         gv19SXJr6mwM4LM/dCxUtUnLYYn+xzR/SFP6G1q9joewsQythu95IaTHCEHCk+D4BXF9
         v7OQEqY3ks7EB3KKCg0w/ytFWwlOq9U6jZu5vf+F/5kYil8rTT6hrB/RaFrdXQubgKAC
         +Xjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cUo2YqnI;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id k201si898691vka.4.2020.08.17.04.54.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Aug 2020 04:54:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id 17so8117628pfw.9
        for <kasan-dev@googlegroups.com>; Mon, 17 Aug 2020 04:54:03 -0700 (PDT)
X-Received: by 2002:a65:680b:: with SMTP id l11mr3369972pgt.440.1597665241999;
 Mon, 17 Aug 2020 04:54:01 -0700 (PDT)
MIME-Version: 1.0
References: <20200813151922.1093791-1-alex.popov@linux.com>
 <20200813151922.1093791-2-alex.popov@linux.com> <202008150939.A994680@keescook>
In-Reply-To: <202008150939.A994680@keescook>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 Aug 2020 13:53:51 +0200
Message-ID: <CAAeHK+yPFoQZanzjXBty8rM9eY4thv+ThdHX7mz-sgeg147F7w@mail.gmail.com>
Subject: Re: [PATCH RFC 1/2] mm: Extract SLAB_QUARANTINE from KASAN
To: Kees Cook <keescook@chromium.org>, Alexander Popov <alex.popov@linux.com>
Cc: Jann Horn <jannh@google.com>, Will Deacon <will@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Peter Zijlstra <peterz@infradead.org>, Krzysztof Kozlowski <krzk@kernel.org>, 
	Patrick Bellasi <patrick.bellasi@arm.com>, David Howells <dhowells@redhat.com>, 
	Eric Biederman <ebiederm@xmission.com>, Johannes Weiner <hannes@cmpxchg.org>, 
	Laura Abbott <labbott@redhat.com>, Arnd Bergmann <arnd@arndb.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, kernel-hardening@lists.openwall.com, 
	LKML <linux-kernel@vger.kernel.org>, notify@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cUo2YqnI;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Sat, Aug 15, 2020 at 6:52 PM Kees Cook <keescook@chromium.org> wrote:
>
> On Thu, Aug 13, 2020 at 06:19:21PM +0300, Alexander Popov wrote:
> > Heap spraying is an exploitation technique that aims to put controlled
> > bytes at a predetermined memory location on the heap. Heap spraying for
> > exploiting use-after-free in the Linux kernel relies on the fact that on
> > kmalloc(), the slab allocator returns the address of the memory that was
> > recently freed. Allocating a kernel object with the same size and
> > controlled contents allows overwriting the vulnerable freed object.
> >
> > Let's extract slab freelist quarantine from KASAN functionality and
> > call it CONFIG_SLAB_QUARANTINE. This feature breaks widespread heap
> > spraying technique used for exploiting use-after-free vulnerabilities
> > in the kernel code.
> >
> > If this feature is enabled, freed allocations are stored in the quarantine
> > and can't be instantly reallocated and overwritten by the exploit
> > performing heap spraying.

[...]

> In doing this extraction, I wonder if function naming should be changed?
> If it's going to live a new life outside of KASAN proper, maybe call
> these functions quarantine_cache_*()? But perhaps that's too much
> churn...

If quarantine is to be used without the rest of KASAN, I'd prefer for
it to be separated from KASAN completely: move to e.g. mm/quarantine.c
and don't mention KASAN in function/config names.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByPFoQZanzjXBty8rM9eY4thv%2BThdHX7mz-sgeg147F7w%40mail.gmail.com.
