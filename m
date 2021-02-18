Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCM3XOAQMGQEDDV3Z2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 08BF331F0F3
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 21:26:50 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id q5sf2179359iot.9
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 12:26:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613680009; cv=pass;
        d=google.com; s=arc-20160816;
        b=jN/HL8Qw/2I/toizlxscIcPwtQHgTxKHkfcM9t7SAphxQUPtvbRLpnhJC81R7x4yuH
         Qn5NhgxdlRTL0QOaPLVLB3bf8kkjTi6BThS1TmExfMMuVfQx8OJCC8CAtv0BtrGg+G6Z
         2NjwdVuEoS+32aQdigKXPhw+DD4DvNtq+p91We748D0+HLvj+VMd7qJNaMXxK3NsU/95
         y/eNgrQqQXvQ1yBirpr/rZTRnHFbPScxe3I1XfXf+LjHebXg9DOUsJ0+AZDdlyMTJxN9
         VytYVgadnmuRr8yKAfh9Vfr78LoFY/9f1Xnq5W4kBix96pq2M4VE8PNn82/jq+MfMplg
         fbVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3BQ4dxcDWjjj444gZRewsDXdE9E3yZpTxRhjhlOkd14=;
        b=jwSS0RDdrp4ZRhmgV38J0IPnXGyOH8CEhNeIG/vbLU0J+0lla2iwZEztg6vFmO+u9X
         9RgCGTfoKr+sEw/HDUSpXXDf7HvMBRhOq+p+lneKGP7Q3d8ZCUnGrB6rto2eiJU4XeNk
         RtXf3BRVLzr6Mul8h48cWCNd90i9J3WlqZLCdOCqBBMJloR6mjkxZquhYsFZhjKb6zW3
         aNq+ORBcTDA/LVNdYdWljoeKTklop+/+AJkD6YzmgbEq0RyI5Cc/mtbEnvr5TKGTnAoq
         YFA6/Mi9ssiO66ryf4JWhOTWKqX6Q7DKTnQ+7hpB8SC3bDNsoq4ebA+9leS04qnQa5Ya
         2F5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="uInv/Zqo";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3BQ4dxcDWjjj444gZRewsDXdE9E3yZpTxRhjhlOkd14=;
        b=VQaHWxSLAQ3AxcWMbFmkyWfb6cFBBM6iSI7U5oynxXA2+tiEA0XOUwUK8RZ3jtnTdx
         1hvwy0oFyqsusk0MU1VCRdMvhTijy0oKhv/KDAtMs62F3wEV/e0cio5Q/ZZptRGz+hE9
         KWO0vXc86T7RK8GvYGe0X3wZO9zDkK5dWJhfBjYDPeODoUVbe89Zb7gsL85Nc5EVzcH1
         Fektm4YBUPyQje5003rXEQ8u1lrU5oPsW8KXLY8kZ25t1UWKb/MrKnFUMFPkV4HdXFj2
         y9ZUjQ/aolWfAcoIfgBiEDQtvCqnUUWjIu3WpwGZTsIZC7cjA1+Q9hFFO7Arc3Sw3ZwS
         s+IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3BQ4dxcDWjjj444gZRewsDXdE9E3yZpTxRhjhlOkd14=;
        b=prJIxbKzrOo2cGqYPa5t/GiJkLfchKXkvaRC/K3VYC+NePagte64y0A6mfTwRyLh66
         Fea7cVy5qH0NcofGuNvePcpZJjH89XwWOF3Wabi3kqE/KPmIJN/2eQip4IxGSn/7YOtn
         U/625DnZ2fwE3fiFIU29rSIurUFR2sbWtbypnE7KigKfr/ho2qfUhLvx1gBySLgsTvWw
         gcKgDIHExCjk92a8xmR0DSysJBIvjyxOuw/EIi0AzbpG1qTD1dhvaiO2a9NX0ehLa8Ha
         LPRdmV4j6GArRfw1kBcyMsXJ9y5taBdp8LFzHBtdrMOz46qIkopSwb/FdooAIuph7S6Y
         nf3w==
X-Gm-Message-State: AOAM533zSdaGXgSn+v4ExlkFKlJF9QnvGYRYkV5X/78It/Gtp5/5anDj
	dfJ1JFyW9M/ipMbPfSGzIFU=
X-Google-Smtp-Source: ABdhPJz96XOtToXR4R44ieI0jgvkjgKoB3AL152mI8oem0E/HccQezEXqtuP66gnqoWOojcssbUEsA==
X-Received: by 2002:a05:6e02:1c05:: with SMTP id l5mr903099ilh.6.1613680009091;
        Thu, 18 Feb 2021 12:26:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:3606:: with SMTP id d6ls1799762ila.3.gmail; Thu, 18 Feb
 2021 12:26:48 -0800 (PST)
X-Received: by 2002:a92:d6ca:: with SMTP id z10mr836874ilp.19.1613680008648;
        Thu, 18 Feb 2021 12:26:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613680008; cv=none;
        d=google.com; s=arc-20160816;
        b=JKD06mPUF+NyY+Pm45VGFBWP85t8gb728GV0al8/wnU4E9k9OBQAroI9fiQK03WW0H
         3cKlV42+ktbHxRzMXB4XYRe9IgJ/8FJu6osVuSTjktnoRgOnwvf4/qxFSqJp0Xqcz8U/
         pNRsdT+rcSp81cQ2emwtwD5QpTFEOQtmLj8cQydw1yNHl3wkSEGRYANoEHNo28yhZH4H
         bEd7Gn1i/BLL7KsKsH+yzSeZayOsleOrUzJHWU4WVogZmXytIG+pnKDF6HGOUZnV3Hkt
         iYpsoUMFF0+6g16e35Aos8CsBkItiyQJCcZD/Z2/IpawamtxNzD0WPoBF3M69XmTe3Sr
         9aLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GC4n6p0kCS6da68jsD6jAKKzKuFPDfyocm7j6MYSTS8=;
        b=yV26rlRMeewU0ZU/dWpThjT/fECzuvlpSvcG1l5LXYiFLellElJGncJQxLXPSDTVBJ
         zwlszYBU5HKHPDQhu9wvI69bhZIfmpOFbmELwSVYSfgdViEHTAFPfvd/5+k9WUFIg4qT
         BJp1yDUOGqyS6Oy3mDK1tsr5q/zU9jog1bpaR2kH0VqOT4llqURqAZpvceDnaHr0lsnb
         2/u3KYIlXStYidUTfBoaNsQXd/5JxCfJuoaJa+rivokkmfCzGhiQI1RfBdgmif1nsNQY
         8mZhJPY/ezbf90xSsciOMhiSl2SHeFt1DROOfUt8h43B/fqF+70n0tbhCXRNFDuXoGrt
         48nQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="uInv/Zqo";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id y6si338935ill.1.2021.02.18.12.26.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Feb 2021 12:26:48 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id l18so2242447pji.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Feb 2021 12:26:48 -0800 (PST)
X-Received: by 2002:a17:90b:350b:: with SMTP id ls11mr5575629pjb.166.1613680008214;
 Thu, 18 Feb 2021 12:26:48 -0800 (PST)
MIME-Version: 1.0
References: <487751e1ccec8fcd32e25a06ce000617e96d7ae1.1613595269.git.andreyknvl@google.com>
 <e58cbb53-5f5b-42ae-54a0-e3e1b76ad271@redhat.com> <CAAeHK+x2OwXXR-ci9Z+g=O6ZivM+LegxwkrpTqJLy2AZ9iW7-g@mail.gmail.com>
 <509c1c80-bb2c-0c5c-ffa3-939ca40d2646@redhat.com>
In-Reply-To: <509c1c80-bb2c-0c5c-ffa3-939ca40d2646@redhat.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Feb 2021 21:26:36 +0100
Message-ID: <CAAeHK+yuvaYxjbfPwEeeh3mMa6_1hg=5LnjogxT2Vb1a-yiOmw@mail.gmail.com>
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
To: David Hildenbrand <david@redhat.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	George Kennedy <george.kennedy@oracle.com>, Konrad Rzeszutek Wilk <konrad@darnok.org>, 
	Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="uInv/Zqo";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1032
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

On Thu, Feb 18, 2021 at 8:46 PM David Hildenbrand <david@redhat.com> wrote:
>
> > 1. For KASAN_GENERIC: leave everything as is to be able to detect
> > these boot-time bugs.
> >
> > 2. For KASAN_SW_TAGS: remove boot-time poisoning via
> > kasan_free_pages(), but use the "invalid" tag as the default shadow
> > value. The end result should be the same: bad accesses will be
> > detected. For unallocated memory as it has the default "invalid" tag,
> > and for allocated memory as it's poisoned properly when
> > allocated/freed.
> >
> > 3. For KASAN_HW_TAGS: just remove boot-time poisoning via
> > kasan_free_pages(). As the memory tags have a random unspecified
> > value, we'll still have a 15/16 chance to detect a memory corruption.
> >
> > This also makes sense from the performance perspective: KASAN_GENERIC
> > isn't meant to be running in production, so having a larger perf
> > impact is acceptable. The other two modes will be faster.
>
> Sounds in principle sane to me.

I'll post a v2 soon, thanks!

> Side note: I am not sure if anybody runs KASAN in production. Memory is
> expensive. Feel free to prove me wrong, I'd be very interest in actual
> users.

We run KASAN_SW_TAGS on some dogfood testing devices, and
KASAN_HW_TAGS is being developed with the goal to be running in
production.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByuvaYxjbfPwEeeh3mMa6_1hg%3D5LnjogxT2Vb1a-yiOmw%40mail.gmail.com.
