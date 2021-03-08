Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSHCTCBAMGQE75LY2FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C10C33108D
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 15:14:34 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id z5sf6469452pfz.19
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 06:14:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615212873; cv=pass;
        d=google.com; s=arc-20160816;
        b=PtqV523RReOHo7LekmoUr/V2mPN+s2UoINCgU6jgeeGBY8PjOrqwyskcRGZoMzYtTU
         cbhNSSxmcizhxyASWAIgy7SNRy7uYkllWB4F00rUEVU4izTw5nFPhOQuGE2BZT1wcUs7
         9AbFtRXGB6FxugXXz3T4uefXzapMRIuUG+R1NUP0eiQvX3nPZwDUPke18aUlRHofZYFF
         +bLDMuxZv5d2tZBuQGFo/guqSv7pbfDTP+nG+itB4lalnlsiGiCjGW1RiGF5XcSRcG+q
         cF1FLAV0Wi6q0SamzdYYDzRFF8RwVMI5PSnBpzypulVGWtMigoqKj20DWPt6bEQ7E0Gl
         0KDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nZRaqupEBOCMlmeWfKVms8kkIwu5jBfQ2A14QLd7mRY=;
        b=wDSJ1uDAm3EKKoVnCRUh0L+umhUKHt0s7h0Nc1VPnISfjM/5BTOleMXFP4tUkopao9
         mr5VTONxRh4AT4MtNhT34/25drQVQs3jhAOxZw2E2X192BIQg3wa0RxQe++5NU+ixLcl
         WCTX7CbFNrpkbCouo2AWe0BxXRfTgov0SHERi8i3f0H2JFtOHyS0rEY6mbNL6TCS07si
         LSDoUNjiuYcdrVWr5/8cuZYlbmboqdJ6LtrbRcmuoA8b4KJTFmLOrkyGJPCFSo1T13fO
         HRyLnRTM/eQ2hKY+7N6mufFGQ4CdRpmotnExGfEE4lFN8UsiooskHsVL4ADiCjEDj7QT
         1sAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PVVo8+Kw;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nZRaqupEBOCMlmeWfKVms8kkIwu5jBfQ2A14QLd7mRY=;
        b=l4hKjKZbzygSaOI2EqmYnFzCdHTAQBQpbQ60VJ7r4YUvlPRUD5UQhxDhJMSjMgeqis
         7IY6rqYu80DOErz4hqtMbr7r+S5DzY708UoGnzcdulF/13/6e1qMIQ4E8407Yq0OpwOu
         Ew8V86liyK3InTVecftFnJc8cYc4qeQEZzDWQhgqo6MBwgjGbLPBaPnDuzdJMbPVVCJ9
         wb6gd/fbykMVDylXIPdSMfUIGvFC/7vqf+Sq9otqaB55aIsi1MKWJHq5DgzA7Y4YQT49
         J3ie4l+CxT80UpdyNK4g33kJleyzyS+jvq+6roLdtffy9QewkR0A7ve+7QH8i3KVmnSY
         ooTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nZRaqupEBOCMlmeWfKVms8kkIwu5jBfQ2A14QLd7mRY=;
        b=C36gQHkxaNLwWDlL+YKHJkXntUujkDlLcyGYDtVyi92Ism/aoDIECpCwvTwbPlW1bN
         IxKptpXkyMDW6j+D+baS0CDsevAWn8rMDjl3Derj6thxwWJS32YKI3E5Hn94pXO0PuTa
         0yPozWjoX3qKRJB1E/ykEQuGFCqfK9D//jsspGXC6Hlf48H9ogo/aQtnI7DN4zYnxCpY
         SmADIkdDUnUypX3hQ1zosbA7zAhNiihkMjJOXHw05iPPPoticBNow9kVBHJfRzmvR91S
         HOU0S8DWrnYvDNXV8oGBi8z6sRopyh/hTuHCnt2zHOGzVKCMyUusJJdUgE6xJK+8GkzA
         s1og==
X-Gm-Message-State: AOAM530WtlboDaTVh8DYHNx3IdRWt3ewV0CBim5EuIGxXxRbpvxFPSVr
	ay++DbLswHUNpQquvQxoz7c=
X-Google-Smtp-Source: ABdhPJxx1VYR+5sXb75ZsKKFVcLUWOsKqsiRVAiLkt0jXi99gX6WS5lW1BZG9/89BWaK+icb5GgOOQ==
X-Received: by 2002:a17:90b:1213:: with SMTP id gl19mr24918844pjb.55.1615212872948;
        Mon, 08 Mar 2021 06:14:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:63d8:: with SMTP id n24ls6802778pgv.8.gmail; Mon, 08 Mar
 2021 06:14:32 -0800 (PST)
X-Received: by 2002:aa7:9521:0:b029:1f1:b27f:1a43 with SMTP id c1-20020aa795210000b02901f1b27f1a43mr11098417pfp.4.1615212872449;
        Mon, 08 Mar 2021 06:14:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615212872; cv=none;
        d=google.com; s=arc-20160816;
        b=jpl6nvlBikwZLhK4V/sVbzexv43s4IFQwybZor4TkUKEhw72LKNXEKCqFhw1O5a9Hp
         toEfU5WmIhq0ih7oTYuNzOItfejO7cDBlJlwaXGH3FIu1b+d3r+eIIf50h0PLHPLIExR
         VU4q2AxxKhevEMrinHq5L7XjUU0zLWtpTk+TIdd6XKlfWXD9H96zjTT+iTNGIHkhiiMn
         sYC4mbqtMXV3OjxWHpViqG9XEp7yLS/j7ruXnp1FyRFtnVOqz5jlmCiHI28xVwF6/QSZ
         SPt7tiQBrjrORUpKBqO1jjtl7lnOAE8rUFSNlH2xXEAGLPOWSTXpM8+RS9nq9hFSytk7
         NqRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gw2zAlnEvV8GmMv5rpZu0isYBOrALdBIALM778oYDbQ=;
        b=UAcKM2xo6h1ZChDrCHgpmZSG/5A440sZL+13SE6nX1nwNpYFi+x28eXi2foMYzuuHQ
         qtVgGSaaQldpdDIpvNr9OTkxcqrGZFFtWARyAqRUTZqgug9+lJigJrUXBddlSyZGc/96
         eqFIRdpVMwRKBsvEaqRXVfh4HU0DzgAn/HK5Rukp9MZE6rH9AMUR8Fna6BVFfPzAJnzd
         s09UrI02FhGLJrJc9yHx4K6XAPPK0KAnafQW+ZEny0dG/jFbQnl2xMFqgaiLD2Brah/E
         NHNQq1pnpdqifkrphyCMvhxwKJZXtS9GJIP014udWAtGzU60AbST0wVuTFeVWkRS5LwM
         CdeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PVVo8+Kw;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::632 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x632.google.com (mail-pl1-x632.google.com. [2607:f8b0:4864:20::632])
        by gmr-mx.google.com with ESMTPS id f7si218506pjs.1.2021.03.08.06.14.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 06:14:32 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::632 as permitted sender) client-ip=2607:f8b0:4864:20::632;
Received: by mail-pl1-x632.google.com with SMTP id w7so1442790pll.8
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 06:14:32 -0800 (PST)
X-Received: by 2002:a17:903:31ca:b029:e6:65f:ca87 with SMTP id
 v10-20020a17090331cab02900e6065fca87mr11507964ple.85.1615212872017; Mon, 08
 Mar 2021 06:14:32 -0800 (PST)
MIME-Version: 1.0
References: <cover.1614989433.git.andreyknvl@google.com> <a7f1d687b0550182c7f5b4a47c277a61425af65f.1614989433.git.andreyknvl@google.com>
 <YEYMDn/9zQI8g+3o@elver.google.com>
In-Reply-To: <YEYMDn/9zQI8g+3o@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Mar 2021 15:14:21 +0100
Message-ID: <CAAeHK+zGDDhpzHqBrKcYhY3UvDG8iXfkCBVQ-5Se0QyESpQ91Q@mail.gmail.com>
Subject: Re: [PATCH 3/5] kasan, mm: integrate page_alloc init with HW_TAGS
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PVVo8+Kw;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::632
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

On Mon, Mar 8, 2021 at 12:35 PM Marco Elver <elver@google.com> wrote:
>
> > -     kasan_free_nondeferred_pages(page, order, fpi_flags);
> > +     init = want_init_on_free();
> > +     if (init && !IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>
> Doing the !IS_ENABLED(CONFIG_KASAN_HW_TAGS) check is awkward, and
> assumes internal knowledge of the KASAN implementation and how all
> current and future architectures that support HW_TAGS work.
>
> Could we instead add a static inline helper to <linux/kasan.h>, e.g.
> kasan_supports_init() or so?
>
> That way, these checks won't grow uncontrollable if a future
> architecture implements HW_TAGS but not init.

Good idea, I'll add a helper in v2.

> Hmm, KASAN certainly "supports" memory initialization always. So maybe
> "kasan_has_accelerated_init()" is more accurate?  I leave it to you to
> decide what the best option is.

Let's call it kasan_has_integrated_init().

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzGDDhpzHqBrKcYhY3UvDG8iXfkCBVQ-5Se0QyESpQ91Q%40mail.gmail.com.
