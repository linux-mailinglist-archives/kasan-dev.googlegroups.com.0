Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVHEVWBAMGQEHJFHOBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id BAAA0338F2B
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 14:53:25 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id 194sf29288536ybl.5
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 05:53:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615557204; cv=pass;
        d=google.com; s=arc-20160816;
        b=OIMhpbPeT+t9P13oWpYxmDLXNLXLWN8LKC3YrF++PbHGlGikIRrlVY4itt4rNcid4y
         qC8QbeD0I27gjoEMZWHR6HIJkbhxm51Jvoo9LeY7J4wL4RO2aT4Hn/TJzTCefCvSxWXb
         198LT5RmFlPav5e8fM4v6Cj6fAWYM/gjRjB+HbodcsAxuhtsft2eQAEEakMzG/Y5m7wO
         4b3wKcukje7Y1WgAcYJAaNX/aitO7nZE62PY0cGm/+sdZ+dv/6nr/F1xcBKg4XHTM+L4
         Sz1HsiPUQ9HGHsWXG7KJQw/wWeYMRvn6adByjmOIpPOMF9qniCXAbwx7gRTrUqUJJwWn
         I56Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OcnXT6xJBII33Q21Y+TP1GKlbUfiUJg9Sz+QdIh1Pdw=;
        b=iFSTtrzTu+p0KEkq82DFV5Q9F+9JdoHnwjIvxuOBC/RhlQ1hKexDo3Aj/XFkLOLc+c
         rp43WAo8jevtPxjiHx1YJP28ZDTu+T8Ne3pNzHdee7H8GlehWTKNhhUQg58nm6CkGjNL
         HUnpcFwK3EV62e+l6UdWMEj6LEj6GtR7xGD3MNlYgbM9g++xEorZnj2b3Nu4XI7+ccyq
         7k/JE/VM5uayNQBkjBBdnWrtyzhUNXegXLYG/T2wqMRZwGNomUv2jE+/TP+0+0XwPnOx
         GwagE6VeEU88Hxm0wtXSNkiNkDQmQXmk47anoiziVWOww9aE2dgCHcnaDbM9ydP0CVX6
         H12g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JmtfWbWc;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OcnXT6xJBII33Q21Y+TP1GKlbUfiUJg9Sz+QdIh1Pdw=;
        b=PgKk2+WzAvbMoemC/pFKdgHKsuCEluZm1OtPgWAUZV5JUoEnOztH0QTbz9gayNbjJ7
         D/KpaOl8XspDWkpMEFXylpSod8CjfQ1TbKohXQhO2rq30G+ASU8OaP1pil0ybS+URxXX
         GxadCGJ/TJ4evu4L0enHWRI2VEPI+hcWqYJdmCf1rSZAFHtBDtYeMxDpkKBj6Qd7xUf+
         P1hktEjcrLfKmVuX190lBukyiQHtCGviD5x9+DlLu+DaZk9Xs3+kYEhpVzjvUEGruEqb
         EDPG0H1LcAo67ZQzsHINFUfFCF7MYT+hy2MTnlHqry4JCnpyBI3VNUlyfhNrLVWowP5h
         GMzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OcnXT6xJBII33Q21Y+TP1GKlbUfiUJg9Sz+QdIh1Pdw=;
        b=STDVgnGxG8t65wIm2weOUARqjxkfYFwd/6ReLknGbYmdtClqUcF1dMKSuyYNmekQ5A
         R9NQDEWbAfw2aY6WfCG1tgjcUyqlaX1JMRZaS+No6pdgSSwwT6ZBEdH0rHB0NM/igDoe
         BnIzM9Qs8rVd42e92YhVnOt7JUTDbc0hRUMC7YqPkABxYqu/WOamehbZPlyjYifqMTzm
         k8WVOaaZRco2VCx2LccOQJLRO1lvsmq/KL1nRJSQBJ9109HD3e0c8SiFEHj4EBe09H4G
         8az13y8fBVJrcy8jh7nA3hGDNUpNKey4HtnjWpe3/Dlm6ZVFYo0PZKlEpyMIJIlmtAeV
         b+9w==
X-Gm-Message-State: AOAM531L6OXKZ9NZf2IrCxLxVp56r957Lv2BfUKpyeXtQAMuPxZz7nG5
	9EOFzuCD61xrFi1EHXkFQqA=
X-Google-Smtp-Source: ABdhPJxXJwL7V0zhKnWFdgwU4fcoNazxGGrwLvEYjJvZC5BjPi2hEIQsCdpxRgksaCfvyeUViRue6A==
X-Received: by 2002:a25:250e:: with SMTP id l14mr18798490ybl.43.1615557204789;
        Fri, 12 Mar 2021 05:53:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7343:: with SMTP id o64ls4334600ybc.8.gmail; Fri, 12 Mar
 2021 05:53:24 -0800 (PST)
X-Received: by 2002:a25:2d6a:: with SMTP id s42mr19809116ybe.376.1615557204281;
        Fri, 12 Mar 2021 05:53:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615557204; cv=none;
        d=google.com; s=arc-20160816;
        b=GpMsuDgIRAv8gT9PE6toRuYDfSSY50F606rmu/iNpl7UNGYVL9i3fcRcVtKLcuN7bT
         h8Y1J/82KPNIsxhpriuJCy0HTq92tUiXQMCZwRXgdy64WRgotw48JT6qDWUWZ2aC0/7g
         r5VHXwDfhCczXSUAzPfDOr9l4i8nR1SywIby9ehj+F5PNy4agYfUZ2Y1LddWyhZncJUp
         dz0YY+tRP8LAqR2pVluWh7zT2WW045OU+TVSMQsJ/rriGl4S1VeVP+/A2f/9muNAVi3l
         6myVUd3OAkrnWU2ABO1gh8QcoTVqi0m/kg1PjbZaBEIE/o87LQm35VbJpPIX7aJJWNam
         qUpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=V6BEPK+M0OwagrMXpdDRFVmxDxwlzupSAEzWiSG+mbk=;
        b=zgAIN73DZ8PTFeNUXpZ2e8zn2msIrCRjGVt1xATOsXI4XbKmj98XWEPL4xEkYv6aNo
         gZ7W3hmsklSpoUb56zz8sBI4gaXjLEnRH9xcz8DfzY2kWqCzZylU/WMzWDN+7+sMweXv
         lhnc1ErqS4aCRjRNvi6UIszjP6d8f0Nizy/aVv1gXU0tfU2C/1kLqLHJ2PHI/Pv5Zo8t
         h7pKI/iC1wjtl9PUv8QNFBWI+L2F1OL1ZwzmRcO79tidQz8+N+rEBSl5nNTZW9yb21CI
         E4U36L3KnWA8ZE0NNH11zANKObUQF40x3NGomZexlxPBzIuLAgYIvFrvQfe3FjKRYyfs
         nQ7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JmtfWbWc;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id x23si354287ybd.1.2021.03.12.05.53.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 05:53:24 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id z5so11970380plg.3
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 05:53:24 -0800 (PST)
X-Received: by 2002:a17:90a:a10c:: with SMTP id s12mr14172815pjp.166.1615557203811;
 Fri, 12 Mar 2021 05:53:23 -0800 (PST)
MIME-Version: 1.0
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
 <f9e2d81b65dac1c51a8109f039a5adbc5798d169.1615498565.git.andreyknvl@google.com>
 <YEtGpCV6jwWk1ZNO@elver.google.com>
In-Reply-To: <YEtGpCV6jwWk1ZNO@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Mar 2021 14:53:12 +0100
Message-ID: <CAAeHK+zbvDvSw=3kE+R+L2SFkwCaEN58nt8xFWwNsvuVvHh_oQ@mail.gmail.com>
Subject: Re: [PATCH 11/11] kasan: docs: update tests section
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JmtfWbWc;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62f
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

On Fri, Mar 12, 2021 at 11:47 AM Marco Elver <elver@google.com> wrote:
>
> On Thu, Mar 11, 2021 at 10:37PM +0100, Andrey Konovalov wrote:
> [...]
> > -With ``CONFIG_KUNIT`` enabled, ``CONFIG_KASAN_KUNIT_TEST`` can be built as
> > -a loadable module and run on any architecture that supports KASAN by loading
> > -the module with insmod or modprobe. The module is called ``test_kasan``.
> > +   With ``CONFIG_KUNIT`` enabled, KASAN-KUnit tests can be built as a loadable
> > +   module and run by loading the `test_kasan.ko`` with ``insmod`` or
>
> s/`test_kasan.ko``/``test_kasan.ko``/
> (Missing `)
>
> Also, "the" before test_kasan.ko is incorrect if nothing follows ("the
> test_kasan.ko module" on the other hand would be fine).

Will fix both, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzbvDvSw%3D3kE%2BR%2BL2SFkwCaEN58nt8xFWwNsvuVvHh_oQ%40mail.gmail.com.
