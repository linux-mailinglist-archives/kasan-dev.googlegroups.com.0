Return-Path: <kasan-dev+bncBDX4HWEMTEBRB47QUP5AKGQEQKWVXBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id CFC78255A10
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Aug 2020 14:28:36 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id w24sf629843ply.5
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Aug 2020 05:28:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598617715; cv=pass;
        d=google.com; s=arc-20160816;
        b=sTjtvbnnufagTeN8voWHlYsk9eKloDPYOjFJku+l8zsABrKvYJ3Gol0sXz5iA47/pP
         RQuJHafIXUeMPIFXOM1RAfkd50EIqswCfgKsOZEZ+W82a3UGO5mUCk7FlbQwGtmMXc2b
         CRYAlLHhaOHr91UN41HBNCYy7k5nwktDdGMsv0OydzsHZyvQ2v8aXILk80XxN/BeD1xC
         hAXiWLzlknSHk4Sa8dNMUJa7UBztx98c/Xp8xEloExGbfpjjchCzuUVtrlURjeKqYV7s
         UdLW45sI7gA8wx8875RcilvNpMiLtubNbnS3P3yy4jGTTWtXyS/XQIUOgs1OdfcWwBCs
         CuPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FgDdlFdBQQZfuE5hQGzeDJ6IzN5htQTdCHKxvt1X+I0=;
        b=l7RTasPQpyJOUf3qROBRh9GO0F9xrCn8uDIK3U+LkXgCTY6flHmd61EsUBSZH9sjxL
         l/taiDqh0E2IodsbQ5z6qqKLRfMfLyK7R0RYKOXqQaX2D8tIPC4h+ONkR5GHK+DVkm96
         AepqYTZ6eUj1YhnFXcVfrC044zWZOZHfRT4zNx3CcQwEVYP6C8E/A4FTnjJh4y00fZmU
         XfbTF9B4988NURGUFxkbyiob/vlggI9xkp9sZBAyABAEoLw6OD3mo3f4ezerwJgntYyb
         avdUMyz1Q74khNdiQ83ftTzHC4CHkkYxiKaKu1h7+pxoYHOSvkQ9b8yE+mwANKNnQHYx
         iOCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X+FVf6O2;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FgDdlFdBQQZfuE5hQGzeDJ6IzN5htQTdCHKxvt1X+I0=;
        b=qZS0theR6a5vmLSx2vLhaZ+8Fmyn/XZLmC3qKoTRXMyKo6EBg4kmOmaeUl1Uv2pB3T
         YV6/ZLM672ZxJ3SRU08N1tJr2Richv9mtyfl+bbZKScKWIG5OmIlRSn4QNMeRm/HxmeU
         +IlCQz+PRb8BvW1sQNMk7Fil6+BT+CkGzipty09QrS9SuwYRMF66UDefhYot/0VXSwEC
         q1jUzEWaQo8t2LjhzIJF+q/k5+mdadSMOYiPSKcpQiUmOjEEbsBBZKk1Lvszc9xvyQpT
         rS5puwWh/vhgOLa8rBwbrc8N4WWrpt9X8naPU8WvW94wb4IG0Q8iQYFGSo33qwF8CgdU
         g9HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FgDdlFdBQQZfuE5hQGzeDJ6IzN5htQTdCHKxvt1X+I0=;
        b=HgtkPW+GoCgGWXito9zTYkG8F+mWDVDIFxTPJjyilR8l372Rz+dnO/qw9VVxE125vT
         kEbKCxA+Be67vPsrlcrUcoui/7bgYHsEjp5lZz+Scc3En6v/XV9Cn8xOxcWOmavR+uCm
         9yjv3N385fsvdToy4+FdAvj/ImTlFqOZo13Ycy6efkaQK0DvzbCc/cqEACj8yBjZn2si
         3zYrDFZn2Qo2IZF+Fh1OGCkk1VtHpcJ11Xab/02GwU+LdH4EKEbPNKk5y2QQjNpDzOTs
         mT7nz4OFydYIcit5rjf95rwjp88lfmDAJ51+ZVQbMhvaj2qTOZTssxk8SglCg/Nnlyzp
         pY3g==
X-Gm-Message-State: AOAM533lzi8M72C8OUMsWmQsr2RTwd4vnVlYtd76eoIQD2CeZsTywL2t
	Z/4kRSESYQV/iX7BdtuycgM=
X-Google-Smtp-Source: ABdhPJxfVVzWqSVTAjA9oyQ3mmCU0rQed6w2LUROZv0/b1VB0LFmkgo8KdgZuVQewpTbgivagLcLIQ==
X-Received: by 2002:a17:902:c209:: with SMTP id 9mr1154289pll.296.1598617715504;
        Fri, 28 Aug 2020 05:28:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:96d9:: with SMTP id h25ls356781pfq.0.gmail; Fri, 28 Aug
 2020 05:28:35 -0700 (PDT)
X-Received: by 2002:a05:6a00:1344:: with SMTP id k4mr1068745pfu.131.1598617715087;
        Fri, 28 Aug 2020 05:28:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598617715; cv=none;
        d=google.com; s=arc-20160816;
        b=XVOlWipULJyxNxJ5nV4hXjTfXFvtWPExix1XuDOjkcN5Kkg+8ZolCtDEW9+D+Zly5S
         MNPyzLBQPtylGpnGR7+D4F0YQZhfB8iB8JAMNYn7MyIHEAMNj1bSIGzSOnc7I88GFCI/
         qMlVv0Q3jWWbcFmcKCoSe3igTeCf9HxKfkvtNqvNrswb4sXETYom5aXqEsjmOeeVP5qV
         492jcwTRvnOZFy6VbaJlBhRRiCaeWrDbB+o6Z/STcAXPd/EyNBhrORzZ9SkgFKC5jruh
         poeqNojOTzsPy9Dl0ebfQPvFf7YYjXRrbY2oigkcgm/jEJtLlr0vh9NZfDdj5AW9Sbhs
         SZsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yn8qp0pF0/ymUX0XYVgXndiqVwNlWscX3zxb5Gz4UJU=;
        b=e3H+VeGjVN2jBil4BGERtzoVnH/GpoImctfa6DAeuid9pRffWST8AMF9g7uWpCmgPW
         lXW/sIP30dfS2pCRNVCUvQoa7M4x0BgpJODftVp59HIMCm5KBk6Qf4XlJKUE1izezmBh
         OPrir2rccSiy0EgQBLL+63OY4WEPmDBbwQN9z3g5by8L7Xljr6iS9Z3WViVOTuQauAjp
         Q+XHQicL4D7pTULECEH9ze9ozkh+m3EFEfHIFYXW9+5F1oFpOnWizU+yNcwBYDUeI8g2
         rEksR1ajC7syOgm4R0bVoFaAIdYtM/ngNJKG/uO4n9kKe8fUEaXcNGfSe4xBNtoTqGzm
         YULA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=X+FVf6O2;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id m15si42041pgc.5.2020.08.28.05.28.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Aug 2020 05:28:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id z18so436599pjr.2
        for <kasan-dev@googlegroups.com>; Fri, 28 Aug 2020 05:28:35 -0700 (PDT)
X-Received: by 2002:a17:90a:a791:: with SMTP id f17mr1015324pjq.136.1598617714338;
 Fri, 28 Aug 2020 05:28:34 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <5d0f3c0ee55c58ffa9f58bdea6fa6bf4f6f973a4.1597425745.git.andreyknvl@google.com>
 <20200828111221.GA185387@elver.google.com>
In-Reply-To: <20200828111221.GA185387@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Aug 2020 14:28:23 +0200
Message-ID: <CAAeHK+zpKXQT4-6CfVt1BfXr=SdYjWjhMR_0yV4Wncbz7Aq73w@mail.gmail.com>
Subject: Re: [PATCH 35/35] kasan: add documentation for hardware tag-based mode
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=X+FVf6O2;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042
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

On Fri, Aug 28, 2020 at 1:12 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, Aug 14, 2020 at 07:27PM +0200, Andrey Konovalov wrote:
> > Add documentation for hardware tag-based KASAN mode and also add some
> > clarifications for software tag-based mode.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  Documentation/dev-tools/kasan.rst | 73 +++++++++++++++++++++----------
> >  1 file changed, 51 insertions(+), 22 deletions(-)
> >
> > diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> > index a3030fc6afe5..aeed89d6eaf5 100644
> [...]
> > -Tag-based KASAN uses the Top Byte Ignore (TBI) feature of modern arm64 CPUs to
> > -store a pointer tag in the top byte of kernel pointers. Like generic KASAN it
> > -uses shadow memory to store memory tags associated with each 16-byte memory
> > -cell (therefore it dedicates 1/16th of the kernel memory for shadow memory).
> > +Software tag-based KASAN uses the Top Byte Ignore (TBI) feature of modern arm64
> > +CPUs to store a pointer tag in the top byte of kernel pointers. Like generic
> > +KASAN it uses shadow memory to store memory tags associated with each 16-byte
> > +memory cell (therefore it dedicates 1/16th of the kernel memory for shadow
> > +memory).
>
> It might be helpful to be more specific vs. saying "modern arm64 CPUs".
> Does the "modern" qualifier suggest not all arm64 CPUs support the
> feature?  (HW tag-based KASAN below is specific, and mentions ARMv8.5.)

Will clarify this in v2.

> > +On each memory allocation software tag-based KASAN generates a random tag, tags
> > +the allocated memory with this tag, and embeds this tag into the returned
> > +pointer.
> >
> > -On each memory allocation tag-based KASAN generates a random tag, tags the
> > -allocated memory with this tag, and embeds this tag into the returned pointer.
> >  Software tag-based KASAN uses compile-time instrumentation to insert checks
> >  before each memory access. These checks make sure that tag of the memory that
> >  is being accessed is equal to tag of the pointer that is used to access this
> > -memory. In case of a tag mismatch tag-based KASAN prints a bug report.
> > +memory. In case of a tag mismatch software tag-based KASAN prints a bug report.
> >
> >  Software tag-based KASAN also has two instrumentation modes (outline, that
> >  emits callbacks to check memory accesses; and inline, that performs the shadow
> > @@ -215,9 +222,31 @@ simply printed from the function that performs the access check. With inline
> >  instrumentation a brk instruction is emitted by the compiler, and a dedicated
> >  brk handler is used to print bug reports.
> >
> > -A potential expansion of this mode is a hardware tag-based mode, which would
> > -use hardware memory tagging support instead of compiler instrumentation and
> > -manual shadow memory manipulation.
> > +Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses aren't
> > +checked).
> > +
> > +Software tag-based KASAN currently only supports tagging of slab memory.
> > +
> > +Hardware tag-based KASAN
> > +~~~~~~~~~~~~~~~~~~~~~~~~
> > +
> > +Hardware tag-based KASAN is similar to the software mode in concept, but uses
> > +hardware memory tagging support instead of compiler instrumentation and
> > +shadow memory.
> > +
> > +Hardware tag-based KASAN is based on both arm64 Memory Tagging Extension (MTE)
> > +introduced in ARMv8.5 Instruction Set Architecture, and Top Byte Ignore (TBI).
>
> Is there anything inherently tying tag-based KASAN to arm64?

Not really, the approach is generic and can be used by any arch that
supports memory tagging.

> I guess if
> some other architecture supports MTE, they just have to touch arch/,
> right?

For the most part - yes, but maybe adjustments to the generic code
will be required. No way to know before one tries to integrate another
arch.

> You could reword to say that "Hardware tag-based KASAN is currently only
> supported on the ARM64 architecture.
>
> On the ARM64 architecture, tag-based KASAN is based on both ..."

Will do in v2, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzpKXQT4-6CfVt1BfXr%3DSdYjWjhMR_0yV4Wncbz7Aq73w%40mail.gmail.com.
