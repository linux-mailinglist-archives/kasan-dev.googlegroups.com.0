Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6PR3H5AKGQEEJIJAWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id EE29226045D
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Sep 2020 20:16:26 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id o14sf7265724qtq.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Sep 2020 11:16:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599502586; cv=pass;
        d=google.com; s=arc-20160816;
        b=xIAA+MIKksyCtWTUMjg1z7jrM3VKqspZi+fedeOiPjbYta1416iY6cj/CryE/zidRB
         QWp/ddsfkArYERPkEZ43I3erxEDzi4IYuv/gq7HHKjU0EJ7iVnlLoM371SLDTWrybaxq
         95UTkqbGSIspXuGpxCO42+CAVD2EFxAVJL9YRT481w/HpF6brFIWwZVz88lF+4pPtCSI
         0N6s06DRh7i3qud0sGwoTrqgc8PF9BT0ZHaMPn7+DSuDEgO2gEYKsjiCDBRlNTRau+ZG
         pK4XNGkV6cwkrwh2ZlFydcB+pXyb7EvsyFM0pFr0Jt7EBzai+7n3lH6rGwDle4HrxJtg
         75ZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VX2RcTKJ13AN9P7Vs9sT7q4Nz1W+z31hBxsSn388EzI=;
        b=dPvx8596pTeO6pbtOlMcJnszz8Q7a+IYyg35k2zayI/Q/8FbNfM3wOQzUlJj+krjFj
         nqV58S6ORTl4i2a7TukP7Z7yEATgbLgy9M/bc5Zzqm8AIqtzKCP1pauGyludxYhaMvb8
         BqoCIYUbtWg1tFIBUyleUsEFOYRBYpB0KIb7J8Bi0JmIsQno0fiYLQZrlPn7cJ1JsObJ
         R3DuqyiXifvpfxTMNnNp6e5zQzgQiPGCABTKYTDGkY3j0cRssx3+TxkXV2/aIMKGlTPU
         niuy/J13DKBHXUjV9bNmYiwAFJ0Ms/Gpw/TnBzCJzNlLXT0TCWvS8wF8Wm3Qb5Xd3kTz
         Xdcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K4nkmgZM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VX2RcTKJ13AN9P7Vs9sT7q4Nz1W+z31hBxsSn388EzI=;
        b=iLpTG6KiUeXK2HgFr2mg9b5OnM9uREcoutzEGBJnvZz7b+YS+Wc+NTn5MaduBWQCKE
         FgnoRNqTg6b+st8hhiAUYNOo2XAJldmuY3GYpv8kix1LLjTebAwtoC1xSGWXGGcNtCH4
         kUTL273vqhPSnYIyhFMWnZXGFuvyR/ubZNjWFhnBiWBY0X5wWreAr053o0F5NWru3GuR
         ivlIiAqCu0NzQ0Ho74GoinQw0m+C2RRR8PVL7Pydfvw5q3M1cwf6CzVXOrgdk6UKXgnh
         BHrsfXXfDSFhsYrMT/XTMI6iKKH4CAJKSgMECiX+9Yv9zuy0RFgxHIxbfJKKt2wzIR7b
         lA/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VX2RcTKJ13AN9P7Vs9sT7q4Nz1W+z31hBxsSn388EzI=;
        b=kgEMUQDOHoGFeX/cGC49bcK+8dWIndtJLEDclYwaUt6ZeH1klXpnbngqeFSw7yrPTz
         +bwmEoMeeDG5yPBfkujdF5vsFqj1FkRNX68nth+Det2J5kIfJeGvekE4pYCjipxOwASX
         ZD+cD7/hem7dolsXnMH37PHljRT65VOE4XyeU3IKhicHmgBephXZnDY1d3S3U/qc/Jko
         +EjoSv1i88rc7woA9WfpKj+HUJMoywG+oaL/g+pwB5EOlO3KNTrskZi4Dfg2enAYrEUL
         +2Chpp7BWD2VwmRbCom6woVxGgS6owa5pTsHsptskjmQ2zch/B7qgU2Tj0ne7Eudg/G+
         m5Sw==
X-Gm-Message-State: AOAM533f089JGteTkm5cYexjCHNw/T2phk4rJrcIlkAEFwnKViFroPNZ
	lOjO+xxlcTnWkJkRuntciYE=
X-Google-Smtp-Source: ABdhPJw4dkcPKfjDeWyxm3ZUTHicP/yl9fZojK8K9Dx+ZV8AV7QzKeNuo4KbThobj+nBd3uHFjFtsw==
X-Received: by 2002:ac8:4a93:: with SMTP id l19mr13792930qtq.163.1599502586037;
        Mon, 07 Sep 2020 11:16:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:bd24:: with SMTP id m36ls314896qvg.6.gmail; Mon, 07 Sep
 2020 11:16:25 -0700 (PDT)
X-Received: by 2002:a0c:8b5d:: with SMTP id d29mr21455646qvc.172.1599502585595;
        Mon, 07 Sep 2020 11:16:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599502585; cv=none;
        d=google.com; s=arc-20160816;
        b=OjARngMP7B61epGGN4wKEL7sAJJb/kV+uyXihAOJTwUIl29bcqC5M7nruMDe3IG+O4
         R/BAY81xyR/rHZRbSQWv0D2aGgEqZjUwFWJOJYrpLnAjoPn5Es3q1rFsTczbjwDmg+i4
         hA3Yu4a6558Yu9Ulmy8PgUNsEjNkmbxsYGg2wUwzWN59kpyueMRbggREXweonB4wtp8F
         UYbmfhecwQ9DbbgfiAUA67xFrAfYec2wN1k04wtUac4p924COKO5uENV6XyvkmfYNpLk
         N+TZIHvpXu/tXITbvTWPD1X1OsrZNEnT+4+QNRiwNwUt1rB7Fww0OQ5/XMBOTMA942n0
         OfGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=R5wKHqfwSX4tMBwD67UcVJ4BSt4O+DvIHtBQvGXOV+4=;
        b=ccS6Ptz9DIVQQV/mt/7YF3vML24L4q5BDRtLdiqzPtvqNsZxeOZ8CzrJSvLzRhcV9z
         xgx5sVewTanhI0P4mBJCLZFG7a2T6lWa0ck4sInsvc/Vw8SVY1KKitdvlipmiGNApILX
         N9e7YGPeQ5IDbeZbqfZrne6Tls8jrCyBCbx7GBjavBSL2FgGhFfQnDfdDGM/JnG2MqtK
         Wp2vLfWnA0lWKrfC7oXdEDNR8rqed36bRr/tFstX1UdrJNplmQYSnYGjR5BmU1VrFEWr
         yrJUw99rccpIzR4z+96bFOx6V190Uh0okNHPUbioZtKd/9n2oZ2q6qw/Cs4rYNbxraiJ
         7KHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=K4nkmgZM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc41.google.com (mail-oo1-xc41.google.com. [2607:f8b0:4864:20::c41])
        by gmr-mx.google.com with ESMTPS id e1si86650qka.0.2020.09.07.11.16.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Sep 2020 11:16:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) client-ip=2607:f8b0:4864:20::c41;
Received: by mail-oo1-xc41.google.com with SMTP id o20so1144829ook.1
        for <kasan-dev@googlegroups.com>; Mon, 07 Sep 2020 11:16:25 -0700 (PDT)
X-Received: by 2002:a4a:4fd0:: with SMTP id c199mr15788309oob.54.1599502584851;
 Mon, 07 Sep 2020 11:16:24 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-10-elver@google.com>
 <CAAeHK+zGpJd6szPounYz6wogO9TMT18TmQu_mfXUWQd65QTf0w@mail.gmail.com>
 <CANpmjNM14iW8vDuLANrCGBds930r2bZ=gwkoqORpuLa5-8gW6g@mail.gmail.com> <CAAeHK+w35Aqt8csAvBHg5rcKHm4cL0rPCM4VupfyG-58eMK-UQ@mail.gmail.com>
In-Reply-To: <CAAeHK+w35Aqt8csAvBHg5rcKHm4cL0rPCM4VupfyG-58eMK-UQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Sep 2020 20:16:13 +0200
Message-ID: <CANpmjNP9DPMdKqYGT-1gpc8Vhca3LoB2s+fbiL_2LvcSdozRTw@mail.gmail.com>
Subject: Re: [PATCH RFC 09/10] kfence, Documentation: add KFENCE documentation
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>, 
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=K4nkmgZM;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as
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

On Mon, 7 Sep 2020 at 19:55, Andrey Konovalov <andreyknvl@google.com> wrote:
> On Mon, Sep 7, 2020 at 6:33 PM Marco Elver <elver@google.com> wrote:
[...]
> > > > +Guarded allocations are set up based on the sample interval. After expiration
> > > > +of the sample interval, a guarded allocation from the KFENCE object pool is
> > > > +returned to the main allocator (SLAB or SLUB).
> > >
> > > Only for freed allocations, right?
> >
> > Which "freed allocation"? What this paragraph says is that after the
> > sample interval elapsed, we'll return a KFENCE allocation on kmalloc.
> > It doesn't yet talk about freeing.
>
> It says that an allocation is returned to the main allocator, and this
> is what is usually described with the word "freed". Do you mean
> something else here?

Ah, I see what's goin on. So the "returned to the main allocator" is
ambiguous here. I meant to say "returned" as in kfence gives sl[au]b a
kfence object to return for the next kmalloc. I'll reword this as it
seems the phrase is overloaded in this context already.

[...]
> > > > +Upon deallocation of a KFENCE object, the object's page is again protected and
> > > > +the object is marked as freed. Any further access to the object causes a fault
> > > > +and KFENCE reports a use-after-free access. Freed objects are inserted at the
> > > > +tail of KFENCE's freelist, so that the least recently freed objects are reused
> > > > +first, and the chances of detecting use-after-frees of recently freed objects
> > > > +is increased.
> > >
> > > Seems really similar to KASAN's quarantine? Is the implementation much
> > > different?
> >
> > It's a list, and we just insert at the tail. Why does it matter?
>
> If the implementation is similar, we can then reuse quarantine. But I
> guess it's not.

The concept is similar, but the implementations are very different.
Both use a list (although KASAN quarantine seems to reimplement its
own singly-linked list). We just rely on a standard doubly-linked
list, without any of the delayed freeing logic of the KASAN quarantine
as KFENCE objects just change state to "freed" until they're reused
(freed kfence objects are just inserted at the tail, and the next
object to be used for an allocation is at the head).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP9DPMdKqYGT-1gpc8Vhca3LoB2s%2BfbiL_2LvcSdozRTw%40mail.gmail.com.
