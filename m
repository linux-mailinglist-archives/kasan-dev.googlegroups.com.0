Return-Path: <kasan-dev+bncBDW2JDUY5AORBQHXXGGQMGQEKHJ72IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5141346A91C
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:08:17 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id 85-20020a6b0258000000b005ed47a95f03sf10502247ioc.0
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:08:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638824896; cv=pass;
        d=google.com; s=arc-20160816;
        b=IF/KYtS6DhbpGNl24Kbxw9nueuooWt8C10wm6aYlw17Wi5jgdnqYhdm26RfO4ckoIY
         Gpfl9grEnSDOFBex4/PDSPuYZnGRMKxvChPBI51H3oFsLkITW9+wjSde0TKCGnJ7HAPB
         Ehp0R6JYTPWVE2cZea2j+zqxf1bL627ecwq8LPm4yQXmf5CqouG4jAxmAhv/X6T76CwW
         MbGgxSuRORNM4W82s20bYyHQ0UNvOeqDe9f3R+Y8Xoydk2eUHphHk3Qdq/RVowoxI/6+
         II89GR6BZsr0EdR/n5PzLiTnQ8vw9vgpuvUMC/40SkydM/dJPZ6b8h3xCxX1e6+8xQRC
         xCMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=DZbKBgXN9i6WNv+oSPFZlu4dABCoq8jhr5UKL3RBjD0=;
        b=mV70zRcUYir57gCYdoggyTvvuQwhxwsPST4lDT3zap48KJMvRt+NaZlPmbvnfnxQ+n
         usPLahSgfIEmVOxS8EOa1JRs3eDzM582hhHZlXX6Ssd75W/N7niPu+WuClFo9qBSCexg
         KNaw3Z6WEB9xKLz7MPFWU9Ro5pTCwVw1m/nGTDpRU32n4sr2Q/VjYM+f+jMllWMylkDz
         g7mW/u+9VZ8iFtXbOhQiKniA4qZfSe/rzCcq3B+/N5EmvQbEXxHOJNwAKIUjKyfbY60E
         doKk74ANtrzF7Xj4nW4+pnta0xUzaWEzs+O0R3Ky6GF77j1Q7sc3DMUOYGH+5Xe9lUFm
         wV2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=INmG1BwT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::135 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DZbKBgXN9i6WNv+oSPFZlu4dABCoq8jhr5UKL3RBjD0=;
        b=HvRqe+facfColfjt+5WtvLg2rNWWNNa/HXlG3I9pPPLg5OwxM59pHnH4HPS4A9eZzH
         6kJdRHEm+J5BFHcmXTcjwKhlasy5Lv2bfT4bdL6AspbZnJ3IkRg7DdNhrWd8GmQqhW4A
         PEeGoSO+reX/XYC2pUZ1Sp13/cB6kFWxNiTFxzgoLRsRMlf1HjSxj+/gAQRkLV1BnjEs
         kJwv4n+1r2GiAHXnc74W/1drgpQiz2pfQZNjHqDRmRLTFU+bWtr3TfCRLQVXHMh5RzoS
         wke3Ate5HQSRYa3t2EXNjwgXRqqrmEeXIBf2anB21yAXSdkLYfQBjqDcjDrNJHwdZOoe
         /v2w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DZbKBgXN9i6WNv+oSPFZlu4dABCoq8jhr5UKL3RBjD0=;
        b=bnTZwxkrKBa3tYRsrUnaTOvBQ+hyl7HTsaxHDQ8uH4MfKz2CcziiVdxo1qpXRansvR
         bCttpFVoWxQPqMLRbDFhA/8RQUJub406HLNiZAdzNSNWVMVvPtRpQPjFnUKjw94QEJxF
         9ng0sPb00QDTHknLpVBBzwPYO2ZAXTSA71NoJO0BTCRYUPzJzU1ZzMbVZGjQcW055JD+
         IH/YNZuK1hgm97bOJRHHAf5WA5n6kypOV7d7BzAdArsryhkYBkBImwjO4U2qyguYbeDY
         Umof78+LoBa2XtV693B/vW4X2/kgjKtk8/K1jUj40zEB1bVmB9ttkePYFwRJq9Y09iyK
         0/qQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DZbKBgXN9i6WNv+oSPFZlu4dABCoq8jhr5UKL3RBjD0=;
        b=Rm4y9TQ90i0CgUbBxVHNYN8qYNbBS0mvaVuhO9qvcX5Bq/SWqY/JUc6RVkHBrON1jN
         wNYx9NtTwy6OedR4NmI9NbF1ksu6R3b+EAZFheANh/kL28229mkt+hSFZs9+dF7QWZaa
         7zf/uWhlzFGf3hsg3xXE00emat+wVXWMJfsBuOYa3MVfcAi4cjedGoXeFU+H/m9IurB8
         zUylKEA/PYVhfxhH1tcgI0OhhB3SN9B2JkU5OzzBlLV+npH2uqzOlOOeNZ3JydcVafSz
         Sl3eC813Mzce1RhC0wKoGlSnYcLGjdR+8yD4AXAfiObCha3YodCiRaXUWVuMqsXCSJnB
         DYUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530zezhHb0aZTjib6mxMEYwK6eViri2qVnwL2CMpRMtA600vmsQY
	Ujo8CGNgebP3E9pIyQ/xsC0=
X-Google-Smtp-Source: ABdhPJwmHGIlv6LQm+CzCdJuFjLKn3KQvGRIguCOlarkuaMGQSLpzHGTpFzZvjiaMxP6NdBwLMdYYw==
X-Received: by 2002:a5d:888c:: with SMTP id d12mr32643986ioo.175.1638824896068;
        Mon, 06 Dec 2021 13:08:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1341:: with SMTP id i1ls2141675iov.9.gmail; Mon, 06
 Dec 2021 13:08:15 -0800 (PST)
X-Received: by 2002:a6b:7c46:: with SMTP id b6mr38420233ioq.129.1638824895724;
        Mon, 06 Dec 2021 13:08:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638824895; cv=none;
        d=google.com; s=arc-20160816;
        b=FGYX1I8pwqvr499X2WaWD5bOW0AJs8/9jXE19c8X9YxRm8X4XiL3dFe05vojjqY3Z4
         CSVnXTQTizdgY71RE8G7vWAAlwOGTBQM6QcJSS4KDu5gUv+pSFg11qUeCA5+hREYOnqU
         icfY9hwdmDA9nwMycEfCjc02D6RzVsn1o8t1GyfcRlwG1fblQhMdrkxRxrcoGZpfFU8Q
         s6SgMY6rYaA9uUmMDUvCPc2UndOzoNF6kTlOHf0yMcS3M602DQC9KCWnCMKRf7sbml01
         /wx/Sirie7FgAZlh+GeR5vYyTw2nLNXnBTFZ8924w7SYBRn+yTwPTwrSZj6ShDorY7xB
         sewQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MIBC6uZiK3qw8zipA5+LmK5bPUNLM9r4EQ+nUCy7/lw=;
        b=vYnLjyDcwKtad/U9eq+dsX6Qga+5PvJ8ouDD5aedfmKVjpfKLPB9SRmHMlNGLaCB8I
         FgLriivjdqA6Nv1xRa+Xu6gXCxnRAutUQfgvtitP+wrzIE18pgk643cHvuCR4Ig7vaCW
         7awxWVI6lo/iUdT7dOdEbCTKT2ez9nlPuWcq7sFiktGCocRib1qX7tfMKpgUm5hP0njJ
         CnJszTsTwiHIoYw2DeTDTyVAZVppmkoNPaqzwBzKQKhjFmuZWt3VOTHJ3uBmk4ezBvA7
         WuhMLiO1K5W7QrEv51xqrjcI5e1nWJKufGqY33FbckXvAC2CxkTTz4sK8qChyn9Dd0kK
         K49Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=INmG1BwT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::135 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x135.google.com (mail-il1-x135.google.com. [2607:f8b0:4864:20::135])
        by gmr-mx.google.com with ESMTPS id d4si669722iob.2.2021.12.06.13.08.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 13:08:15 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::135 as permitted sender) client-ip=2607:f8b0:4864:20::135;
Received: by mail-il1-x135.google.com with SMTP id 15so11636133ilq.2
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 13:08:15 -0800 (PST)
X-Received: by 2002:a05:6e02:1605:: with SMTP id t5mr38923380ilu.233.1638824895522;
 Mon, 06 Dec 2021 13:08:15 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638308023.git.andreyknvl@google.com> <f405e36b20bd5d79dffef3f70b523885dcc6b163.1638308023.git.andreyknvl@google.com>
 <YajVYNBDOyI3hTx1@elver.google.com>
In-Reply-To: <YajVYNBDOyI3hTx1@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 6 Dec 2021 22:08:04 +0100
Message-ID: <CA+fCnZfuH6GNRQ7m-HU=MSrroe9BMounEuoFTSGJUGGk8=vKzQ@mail.gmail.com>
Subject: Re: [PATCH 20/31] kasan, vmalloc: reset tags in vmalloc functions
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=INmG1BwT;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::135
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

On Thu, Dec 2, 2021 at 3:17 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Nov 30, 2021 at 11:07PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > In preparation for adding vmalloc support to SW/HW_TAGS KASAN,
> > reset pointer tags in functions that use pointer values in
> > range checks.
> >
> > vread() is a special case here. Resetting the pointer tag in its
> > prologue could technically lead to missing bad accesses to virtual
> > mappings in its implementation. However, vread() doesn't access the
> > virtual mappings cirectly. Instead, it recovers the physical address
>
> s/cirectly/directly/
>
> But this paragraph is a little confusing, because first you point out
> that vread() might miss bad accesses, but then say that it does checked
> accesses. I think to avoid confusing the reader, maybe just say that
> vread() is checked, but hypothetically, should its implementation change
> to directly access addr, invalid accesses might be missed.
>
> Did I get this right? Or am I still confused?

No, you got it right. Will reword in v2.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfuH6GNRQ7m-HU%3DMSrroe9BMounEuoFTSGJUGGk8%3DvKzQ%40mail.gmail.com.
