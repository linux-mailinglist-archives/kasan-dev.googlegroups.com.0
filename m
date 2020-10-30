Return-Path: <kasan-dev+bncBCMIZB7QWENRBB5D6H6AKGQEKRZY5KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 980562A0CBC
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 18:46:48 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id e16sf5161152pgm.1
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 10:46:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604080007; cv=pass;
        d=google.com; s=arc-20160816;
        b=yC8oTTrXJIh1xHL/Zx2UbRa/lbGCPqbO7dcnkhLJgZtdUjgSsMhOX33HAJso3R3rWO
         RAkcsQjYDrYI0DVOFqPPHCwfiL3e4KDMKcZHWwXFxkE+qOklwFVfjfyLJhx/lZtl5PBX
         zbgvY7IVmZAIMUpxefIcw+jrOqgvArU0Rn5hm0C8eVPCJ2XdBTJ+wOSUqulv8egNMqFM
         ODRKaqjvmlJ01/ALVOdcZjvp/8vdD7tvHB8EvHycVocaABDdn31DDB6GMbn6KXN8LqwZ
         X3ykvOOCTDHIu3rtryb9qCYt7SOkRko1ZLUUpTsoaN/pxhhZPal0SO6yZXS6pYGVOxwm
         imDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tzobsHRo0tXuE0/5IIg6l5dyAJ9xYjpo9nLIMskpjfI=;
        b=B0c4WtHumip69HsdIf04MFOWIdOnehVnjadrSpWTfBpu+aS336A/yHE6NnggqSNpEj
         F4wtvpMETCKUO2GNGIWpAmpiIFlmYFbBAogy2BWBglKGYOsKgqkgXM8SbXYxONWgldDU
         rWCTftOLFxscFR6XnKZGW3YwyxZUKj5+leQ2xmTSwFuTPF+SMwSzO/0INN8MFk2ntscF
         5qdWINRFTiWft50QL1AxkCQOz4fzGl5Yurav090Spl1LvF9cDwJc9DHaiXokGo8iGgML
         dPB09IslSa0+i+h0DB0xwHdZvs43i73RQfwU3XROUK0Wyf3DT7PO5Nn0E3XlGsjHwO3R
         bzNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZXXWtx1P;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tzobsHRo0tXuE0/5IIg6l5dyAJ9xYjpo9nLIMskpjfI=;
        b=JsEPNP7U4xl0MgDkRzB4yRYa+vclzBUITBfgrRCkmkzBJ2aMU4aQsBX68P7HvhvGcZ
         AUS49DyCv3gvmZkdRlob0EFr16lUN023pP0kluYrZ6bZoNuAbESPErWO3+WOcigk3jtJ
         /sCnxAFmkibz2C8Vh0jrIcmAQu3o0U/DvRGRZHuwZzPcycAlXhN4TmyTWpiyqklkJdjn
         AFwGNZdmVp39C8vUZCDtcRpm6u01Hv7MLw/+18jnOJxTwnxkojmQHLY22X8TejxUnJlg
         zQEkQhajL67pZx+LLm6ejdyDyxWVajlvuTxIQTAfGI3LquBz9bw7zVqxGnz2TEvzEfqU
         /fbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tzobsHRo0tXuE0/5IIg6l5dyAJ9xYjpo9nLIMskpjfI=;
        b=FAPVM20/73ZyR5RHQYKTRav2svhfJRGhcyQSWhnjiF4ZUFk2ZwbZ+KEHsWzIqAePi5
         vv/3A5UozMd/bCtJhinEE1mvYxtlga/GGJsNiKWfv+DGa+7QVnsDwvKz6MBw4Tkqiph3
         5mlMVGYCO/t1NIEh4t65i11hYfynYGpp585X84T8e8uOIMEv1lQPYGXC4QOJ4UIVMuIV
         8JQWCJvyn3hDYTEZS63y5k8M2yPvbmrwzZRgkd0oy1tkamcl7ojwBczzgFCfvJo8ZQhf
         JIrLSG8ZXT/Fey9/nmAnzP51/NP00+tbm+Pb3B8UBNf7mYk7uYFcYIZXM7OSv2ldjEI7
         iP1A==
X-Gm-Message-State: AOAM5327TMn1VhQlzyaa2D4tHwk4R5SdVWuKZKfUyqYw/Omca77Zpazx
	TJH0fuy3mwWODWDfVNiiUyk=
X-Google-Smtp-Source: ABdhPJwi+K9ULOLqQLSWQHW/xy+GI8wDH0PINz0sRD9qGChWbggS/CBOs9Z2jlZzHUozVU+BQrdv8w==
X-Received: by 2002:a17:90b:a05:: with SMTP id gg5mr4087122pjb.214.1604080007314;
        Fri, 30 Oct 2020 10:46:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6a85:: with SMTP id n5ls3171719plk.9.gmail; Fri, 30
 Oct 2020 10:46:46 -0700 (PDT)
X-Received: by 2002:a17:90a:488c:: with SMTP id b12mr4192093pjh.204.1604080006759;
        Fri, 30 Oct 2020 10:46:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604080006; cv=none;
        d=google.com; s=arc-20160816;
        b=Y7zpJ+2LpD+5u0VCFSL821/PWbdoFS3RbArxBrx0yCNKWI4tawRHlNeTzNQWH/ApXh
         5hR8p8ougudWtfqpD5HqvEhAumN+D0OIiKc4MtVMITjvwlLmi8qAybDmUAdMUdDESisA
         DBJEGOrVKsozaXl5QAPbgWSZzAKjX9s4rX/gEnyOkgmKZQvUN5TGQw3NypiGGCiMD0ZF
         ZVE+kUvkOLN5lOO6LjgGui1U5MBAABBbGQIVFGpNyJzXxCl0AJJrWHTlriw1j/3qsxQD
         Om4KAn3MXG4yecGvb0tETJANseBj2nSFADxQe0JKlmukNYjs9+yv8HXnYLBz+sB92P5Z
         1cBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+DWGshIzBKZkowUsfKXy+FsPzRhu2gsbri/5lPafTJ0=;
        b=kcYMB9K/f+SAeIBhz3HLO2RPcsenU47p4RVhbbaMbJKrhmTQGYs22FkCPewObqSDCu
         1pkf6+8LgEV73YiAo1H4GNk0XBDKxjwo4lYAjVCWrY/EuvR5BrrXNyFXo1YV1HWKR5Hq
         1dIApG0FdU4B1o0DvRaGCwFTB/BMbblzO5fK89lqOuhmmxNXFJZ4alMi71aO2+cuNng7
         kg3HVcLDL8W2zfmFEmsO4U4Q8LdXz7b4LqkmWQY5krN62+3/skBXGD2mDdnmFrQxSRTM
         A58TMYbpZYGM6oc44lSKRQ9+sxhTISCnYzfc8xdHx9e3e7shkc+H9AZTZxs2BnnFHH3+
         bUTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZXXWtx1P;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id ce12si502454pjb.1.2020.10.30.10.46.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 10:46:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id w5so3113378qvn.12
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 10:46:46 -0700 (PDT)
X-Received: by 2002:a05:6214:a0f:: with SMTP id dw15mr10113630qvb.44.1604080005622;
 Fri, 30 Oct 2020 10:46:45 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <6f87cb86aeeca9f4148d435ff01ad7d21af4bdfc.1603372719.git.andreyknvl@google.com>
 <CACT4Y+bJxJ+EeStyytnnRyjRwoZNPGJ9ws20GfoCBFGWvUSBPg@mail.gmail.com> <CAAeHK+wkjVVHy+fB2SHpqNOC3s2afKEGG-=gs=Z8nwwF7hJdmA@mail.gmail.com>
In-Reply-To: <CAAeHK+wkjVVHy+fB2SHpqNOC3s2afKEGG-=gs=Z8nwwF7hJdmA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 18:46:33 +0100
Message-ID: <CACT4Y+ZUTkMgtQUiaS-7r-G=urYJo7LFZihZ4ZeimAmkg=0MyA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 12/21] kasan: inline and rename kasan_unpoison_memory
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZXXWtx1P;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
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

On Fri, Oct 30, 2020 at 5:35 PM 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
> > On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> > >
> > > Currently kasan_unpoison_memory() is used as both an external annotation
> > > and as internal memory poisoning helper. Rename external annotation to
> > > kasan_unpoison_data() and inline the internal helper for for hardware
> > > tag-based mode to avoid undeeded function calls.
> > >
> > > There's the external annotation kasan_unpoison_slab() that is currently
> > > defined as static inline and uses kasan_unpoison_memory(). With this
> > > change it's turned into a function call. Overall, this results in the
> > > same number of calls for hardware tag-based mode as
> > > kasan_unpoison_memory() is now inlined.
> >
> > Can't we leave kasan_unpoison_slab as is? Or there are other reasons
> > to uninline it?
>
> Just to have cleaner kasan.h callbacks definitions.
>
> > It seems that uninling it is orthogonal to the rest of this patch.
>
> I can split it out into a separate patch if you think this makes sense?

I don't have a strong opinion either way.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZUTkMgtQUiaS-7r-G%3DurYJo7LFZihZ4ZeimAmkg%3D0MyA%40mail.gmail.com.
