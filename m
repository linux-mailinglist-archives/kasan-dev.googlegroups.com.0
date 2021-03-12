Return-Path: <kasan-dev+bncBDX4HWEMTEBRBP7EVWBAMGQEZBXNPRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 51777338F29
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 14:53:05 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id g11sf15773870ilc.8
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 05:53:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615557184; cv=pass;
        d=google.com; s=arc-20160816;
        b=rMRrbVYQYeplw6AgbCa3eWgh5MABeUKkNy/AqH/SNv5M6mGH30+iC4fRCkcDTHGURb
         W8XS8OF10qTosJ+jYL+5LIB0pQDz4S4h3EwgVaEjlmy2IoOLcWlrKHsVxHV+OnP98Ncy
         oPbuh0v6ospm047emlodsEumOek7WrfY3vblMaQ4P6h3eiwDRVtX6N7mjFPxgVh4SPcN
         mg1PHNoorBU9OpFFmHiSg08W/GhQ8C471CF7oUjdGVouzfnE7Xw3RtSi6+94X40OC6UD
         E19AZayeWI09j0UMHVD6uGc78HXNlWei0VIhEJOfNLpvIVlM2DnrHLkPXaawibFjjiWl
         8pMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=c8Dt0mDXuiaWf8NupUzgmAz3d+X6PIeg/eMHoDhLONc=;
        b=waHqzYFlIAoZLYiHepMXZWoUjggqvCvjX9r7lP89Tc8ccJMB1IGrJ8HQY+i89Or+BK
         vqSsrp/ptr9+K+NLyI/49gEQ/kd+J4irva//eo5aPOxtwg5U6lx2JNLFMrjDt//yDFfF
         VKyQZwI9P9vLxOzjgZ6T9gvCOG5V4hGni0jrY/9sorfBhE2AB8Ek5wXIEWxxKt5h+bPY
         wH8KqipWFSzV/RJIt4/5TJAWox9Pbiz7Hv4G/YSeToOCJef4SMXijlC5vRLwANBwYnhS
         wyIVoP0/V/EG0+hIyuW380hwNyQ/FZW1g736UNbf4bm9U8EMnvDR47hkLsxUq0Se+OOn
         rB3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CZjD9K3A;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c8Dt0mDXuiaWf8NupUzgmAz3d+X6PIeg/eMHoDhLONc=;
        b=oc/i+YR69V8VMGM/adAIbfwiCpcwRkIIeoSe4SVZL8ulWfEs4UaZ6tOZmWmxqH7m5i
         6XZ4b/qtrZCI/1L3UuC2RyMRxvE1ft3mNjEfzz28hZsBEJlH26PbWTxUmPPzqPdcGnpu
         jmAth+Wsu3pL6RuaZiU4xUF+ThnVsoIirQ8dnr5ioD7FvIvw6JGEAUzir3OMSLHNPKsK
         7dagdjVRXadhp/QvIoVEEHxmr974eW61vP0UeX3pIV8gDzJKPf1AIB4SGvd/9KJm4Ach
         QNfWI6wNahbxx7uUyOxOLGnGZ0eiOJSbgUAmtCbAI2d+/4YoGTF3SChPRMPDGtCL1K4O
         5q3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c8Dt0mDXuiaWf8NupUzgmAz3d+X6PIeg/eMHoDhLONc=;
        b=Uzl/nHz1UELckw3qkkHSri6Ll/jwX5YQvwZPLA50IbHySSFvAkBLPEPphk7Obg9c6v
         M1bH0avq3rJXUNFxxVtC3hz2NS6FGoQIU2RAYnjhoVQ+QxcOkrx2PVg1RM7418Bb/Wkb
         wlkvXiDU5aB+mJO5N9nUz2Y35xjxBdxnf0twTjwj3UVIATTvBXLyVY9t3XtAQ2/0UH3+
         YUiazvrg0Ze0vF1uE1KVjUbgt1PjJANEkxuHB1hPEwrly8WilmosUHZcl9jjJBX++mVh
         sItPEzR/Inttt8KI9TEGeYSLFKjOP2q5u5aBpbd6O0pMzOTVKqK/GCPBjxVWhTxjDChK
         Zahg==
X-Gm-Message-State: AOAM532h787YsIgkHIJd+X8E+lusmNByyc4IzLDQ6pY/Zxc/FAwkbHA6
	qSMK2GN4Qg5ycuDZYArdFYA=
X-Google-Smtp-Source: ABdhPJyJBehcBf1WnYUk6Fx29pmIldPb729353aqy7zhDXqMehFFOxa03ZHJ85voZEcUfCAw82jURQ==
X-Received: by 2002:a5d:8d92:: with SMTP id b18mr10384115ioj.167.1615557183968;
        Fri, 12 Mar 2021 05:53:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:22d6:: with SMTP id e22ls1386294ioe.0.gmail; Fri,
 12 Mar 2021 05:53:03 -0800 (PST)
X-Received: by 2002:a6b:fc16:: with SMTP id r22mr9585402ioh.102.1615557183628;
        Fri, 12 Mar 2021 05:53:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615557183; cv=none;
        d=google.com; s=arc-20160816;
        b=PWVk9cvsRaE28D3tPIznLhQPNR+xEjgt/h+6EKr7YcXNJFx05GsoteuZTJX/g0kAsF
         hqYaj767bFaQnTXJsuZakP5qNRjvqQ5cWfdRuhBqxJvtzyTYV7JJc+QgDirqlYMyc3wJ
         o7KXySVFt8HSuUpdHsud4XIbsJYEgM/hIo6TtHPeAg7HUBfQviqMtNXzi38iggPowvJ3
         eh0EqNcbl8n7748PWqRGYcT5NCi4Uqc5aMmNEnCBEC2mQ3yQOGOcGDX/kQhbzo9SGSmh
         Gy+TnPi6bZg0sACCaW1JbKR8uuQ4/CtZ46pxsTZ3S4hyXdmj/FEjWa6mwXMdYIAaznAX
         llTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aih4YwIUaxwo1xIQPYb13vTPOicVAxjDZ9nf+fTCPBc=;
        b=rCHhFkBeM2x3lEHrDHCpD968PDhOjkz17p5pfCJ4QrlSSVIcW1o5Tq6pEg1nTXOnoo
         klXwVrs9l1rgU7GjC4B4vyn01uBnfJWLpuLCWNtMbIjT1lCcSM+pxqlkzTnE3Fmt+hz5
         KG4T49JuDrCxN8e9ZqswYchXIIfMA6GVxZcGRWs2GgHmyEiu71c77zd7q4S7Du6QtjKk
         v88LGNsIMy9he5TZU7H6QodYmUxnDDWDRUWig+bcfL6CzH2u/mUR1fEricvXVyP/tM1r
         RIKT+um/uitAw8hC8kzWP3corOqM3KPHAbmu36tyWDA96Jh0n+aIO+E+Kru0Y3J01iuE
         DOZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CZjD9K3A;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id w1si231116ilh.2.2021.03.12.05.53.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 05:53:03 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id kk2-20020a17090b4a02b02900c777aa746fso11095196pjb.3
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 05:53:03 -0800 (PST)
X-Received: by 2002:a17:90a:8c08:: with SMTP id a8mr14442823pjo.136.1615557183176;
 Fri, 12 Mar 2021 05:53:03 -0800 (PST)
MIME-Version: 1.0
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
 <6cb4988a241f086be7e7df3eea79416a53377ade.1615498565.git.andreyknvl@google.com>
 <YEtH3oADQeTx1+bK@elver.google.com>
In-Reply-To: <YEtH3oADQeTx1+bK@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Mar 2021 14:52:52 +0100
Message-ID: <CAAeHK+w=3E+oowUUWfnF=SX9KYYqbV+hp1OsUFPpJf8HGnJx9g@mail.gmail.com>
Subject: Re: [PATCH 09/11] kasan: docs: update shadow memory section
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CZjD9K3A;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034
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

On Fri, Mar 12, 2021 at 11:52 AM Marco Elver <elver@google.com> wrote:
>
> On Thu, Mar 11, 2021 at 10:37PM +0100, Andrey Konovalov wrote:
> [...]
> > -The kernel maps memory in a number of different parts of the address
> > -space. This poses something of a problem for KASAN, which requires
> > -that all addresses accessed by instrumented code have a valid shadow
> > -region.
> > -
> > -The range of kernel virtual addresses is large: there is not enough
> > -real memory to support a real shadow region for every address that
> > -could be accessed by the kernel.
> > +The kernel maps memory in several different parts of the address space.
> > +The range of kernel virtual addresses is large: there is not enough real
> > +memory to support a real shadow region for every address that could be
> > +accessed by the kernel. Therefore, KASAN only maps real shadow for certain
> > +parts of the address space.
> >
> >  By default
> >  ~~~~~~~~~~
>
> While we're here, can we change this "By default" heading which seems
> wrong -- the paragraph starts with "By default, ..." as well.
>
> Perhaps "Default Behaviour"?

Sounds good, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw%3D3E%2BoowUUWfnF%3DSX9KYYqbV%2Bhp1OsUFPpJf8HGnJx9g%40mail.gmail.com.
