Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR4DZ26AMGQECD2QKAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AABFA1B523
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 13:04:25 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-46dd301a429sf39250411cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 04:04:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737720263; cv=pass;
        d=google.com; s=arc-20240605;
        b=jDSrV+3w7rZ2xexiC8EXwApEiID91eX/zX6zQpZrwcNzNJEcgYoDzc7RKCU0jZi/jy
         cqZyYHMG9ek+LOagpwfe7VEAIqKUk1yRZWOWrw2wwWYnwPVGYh5JY8GOXc0xzLBxyLb3
         wZ7T7UxprnDeC1AsOzSantIYykm+hvVo/qNslFu8O2GBS0zZIaM6faOKpPCzHlIFtfX/
         BrEQvVeiAQo2/HDcBErc5RLFV1TaApOjBrCdk9MxuG9PD3l7JWXJF63j/20ZAOfHvvP4
         AC1HBnzsFXBKhDPUSKBQB9UIxPWMBSuyuv+pjD9KQeavBsbqdRAtR+ALJkk+AyswmmAI
         AqBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YU7G9PpPzGbtZHC05cTkt11sGbWd/KJ5yYp4/YtL4gw=;
        fh=pMtR2bFAeIDZrMQYCqHL3Xht4iMIcSICoMqxTxKp+aw=;
        b=hFlyMW8Xxi3F8PojTVk0bURy64nv//ftXTbFtmi2eF3ZJuh2/LUDph60ZFSZEZjmxC
         nGyCZTjA4rR1uowRqwnBAw7snYljC4Jo3ef4JMpzOdCgIxR+gqhnPcpbtW7KGGH4+SH0
         oI0ElFHLDhNtHLHLD89SSf8GhpDscwA6ARlp2IHzWkOcvQAEbAGfku7JYq3i42LaBOMp
         rgyMD1TGIIqCMfsHcTD5dh2cLtc5GtIefuOA/gifjMi2cxWHKCqG/oQvORVPA5MW0pQR
         UK0T5mwDs5MYMuGmZf20VuQN8cQxCQN6m1zHdw75c8e6WjPqvORLhy/SFC89xuPHAM/g
         mXHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HdZQ24rD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737720263; x=1738325063; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YU7G9PpPzGbtZHC05cTkt11sGbWd/KJ5yYp4/YtL4gw=;
        b=l3Shoz9sdUWzLC1iYO4uxaPEYgjxFjegydq1CyoZP3r6we2xjZob3Nhhi5gi01uubg
         8xBku3Y3F/0AgLu5+EuG/kE93EKoDUoNHnDsvKdrKITipa0ImWFHrNLB1ODGHSuC2mi2
         7Ciq7NvWB8xKLLdyJJsLlUpfqFRbGX1eYdeKp1nD2ieIFeeVtTn/UKUZI3Rzy9Uhhheu
         tnZY62bqttqrNbH15swmyCav0IR/I8oNHsSLlpTpzhNyPQEh+MqMWxFYX2tz0iawYtic
         WpPcmFWA0XbHtu4cRYDSCcpTzO9SAEIKNKkw7XjfLVpiKdFXB/Y/4o9HLwM5XEsfYPAh
         Yzhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737720263; x=1738325063;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YU7G9PpPzGbtZHC05cTkt11sGbWd/KJ5yYp4/YtL4gw=;
        b=UFDrRaw02SB9mwsmKWrYWwN15Ed8Ibi6THSULM+2XaOPwATTlAyJ6WaBDV0d/RIEeW
         Kpcm54zKApzXIBqJhW0vD8c3qUULuosIph/pSIEVXkHsQMWHh4H/r1YRjQyRGqZ7MlTj
         MkY5zCymw3hlrXVOJo3DS5HTM49pNpW9yjlZtPFZGpL9gTnFhC8LkKtTcMtsL87VLyWK
         b4LqbzUpvauS25px+lIKwq/6N9d+ZHPrNelq1KTKOxnpkudyCklt368VXZvXfVGZnNl9
         nOuQEoOvs7pZRm8GJva4NbY9ujrPpMV0nDTqxi+Hl806Bi1+Wt5uG/QWFVIASmZApFgc
         2eGA==
X-Forwarded-Encrypted: i=2; AJvYcCUjZsFHr+8RUxrS97u0cpcm9bMxybyo+9z/MzaE5wm1Ocxb8HfgYqGmPil7S3Z69kaZFYn8ww==@lfdr.de
X-Gm-Message-State: AOJu0YyUzAPLkVVMF5Lh27v69wmHA0h1YDBUCyrvSnRAb5Ovuy9rPtw4
	th+Z/9+zE17W7e7kvHvb1kKv5gOeCjq/LAerFt354oSMmd6GZPQK
X-Google-Smtp-Source: AGHT+IGi+tPhn8Rp23u2HbyJV7EVwcD8kV4fGERzE+oGD31tS7RQwW3aRinlJZjkVi2nT94+SVWB0Q==
X-Received: by 2002:ad4:5bc1:0:b0:6d8:99cf:d2db with SMTP id 6a1803df08f44-6e1b21da05fmr503050786d6.38.1737720263481;
        Fri, 24 Jan 2025 04:04:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:9e91:0:b0:6d8:b1cf:a07d with SMTP id 6a1803df08f44-6e203141709ls15327626d6.2.-pod-prod-02-us;
 Fri, 24 Jan 2025 04:04:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUZd9o5e+LzgMV/HTLvNg6PblhyFCjLqQZoaokpOSoHN+TFXGFdyFDcPM2DipgSs9PUzYWAN3Z8oZo=@googlegroups.com
X-Received: by 2002:a05:620a:29c2:b0:7b6:da21:751c with SMTP id af79cd13be357-7be632199d3mr4375176885a.11.1737720262535;
        Fri, 24 Jan 2025 04:04:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737720262; cv=none;
        d=google.com; s=arc-20240605;
        b=bC4Hpwj6bq7/aaNw1nU6IvVVIiBrf/wV9lED4lSHnCTpwHgVp+DQswm28NWRv1aEAp
         E45mApWJZjFso0ngUecgDdxJtMEoIQ8iR9vNJLdl4Fct96QxamyHzSVu0BkAklPo2r5Y
         CpgqeBA4AzhMfgaOODTHujLnsHzUcjhzbZYDLW9BZLncRYb9M4GX6V/0iSC+29aolSGB
         LQoBgwnAxb7NvGqIztUWE4vLAL6P6cpMZE681pnmZtykTxlzMPUvC9kxzJ6aBi7ly2pw
         +Y0EsPmrBAbB9KQAzVWZLrSW+JYdXXvQ891LVzhaLBPLCgCWJ9vo+Orcurv1TG3DbN+T
         o33A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CSX+I23Oo26cufSOeOQC+f6IhD956qz71ZwQ4NUSVJ4=;
        fh=KnSZQU6Kx4p5WXQ48VEO+a6HtlEnngza+2r6Vt6OL/c=;
        b=FWXe79pjIye/ZU1nnRJfL3z9TFo07mxGwov9y1iXI0BRp6F/Nw/WObq2g6+q0qaH66
         UcQg2fife/1sTLl6E2+oMGm9j4EeBqZ8lkVScuREXtb21o/CKUz605wpiXWy2/ADyDr+
         XgzQ6NBbJHoZaOiFZn6SRbjcmrD+MZK1P7kN425ezyxmqjnWnVFxsUdVImgY/utKRBdV
         B1qwy+tIvKLuwhQr3MFhM4EEpsjgeDe6bSUq4/d/psKCiNTZKCxWKYAEbMbmYHZgmNZV
         4hXplt1tpcv3RObm+mNUY8stqgiHTV+GvwoQyY1E9vSfv1oquRkTGxiK9EmQ+MisAZtV
         vPvA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HdZQ24rD;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7be9adb92edsi7192785a.0.2025.01.24.04.04.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Jan 2025 04:04:22 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-21680814d42so32485615ad.2
        for <kasan-dev@googlegroups.com>; Fri, 24 Jan 2025 04:04:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUJsUH7sgvxTLo4r1jo8ndBHjWXr3jghk0Y5YpggYMb/yXIbksyZEDwqVYW9EToo/wsv2iGG9vk4jY=@googlegroups.com
X-Gm-Gg: ASbGnctZrj59nTjs//WP+hne/R9c+VLZqcMXZ2bBG3UylvYER1zh24I6ni2fvgYy8EX
	P7sQCHBd+GWSXuzaIUfOma2AcHYgEl20x89x/IbJ3vtmQBRqfStsDV4DnM7BRjyl7QSFPfljcpm
	xnJACGSsqy6zjdCtQMgw==
X-Received: by 2002:a17:902:e80f:b0:215:8dd3:536a with SMTP id
 d9443c01a7336-21c352ddfc1mr467804675ad.4.1737720261424; Fri, 24 Jan 2025
 04:04:21 -0800 (PST)
MIME-Version: 1.0
References: <20250123-kfence_doc_update-v1-1-9aa8e94b3d0b@gentwo.org>
 <b788d591-4c5f-4c1d-be07-651db699fb7a@suse.cz> <CANpmjNM_2EB-sTBjPDADNh_cAEJS8euY_71pw0WNu2h_eisAYA@mail.gmail.com>
 <c63dd8c4-a66a-4a97-ac94-70b3159ba3a8@suse.cz>
In-Reply-To: <c63dd8c4-a66a-4a97-ac94-70b3159ba3a8@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 24 Jan 2025 13:03:44 +0100
X-Gm-Features: AWEUYZm28xnd5LD3ceGeFbFo-hDUX9NWI27ecbNAaKsVlaUXmPGeTLJFJu_kABI
Message-ID: <CANpmjNNpFTweLW_QawTa6eqF6vOrKZPL17r16CaVipPWqZsSKQ@mail.gmail.com>
Subject: Re: [PATCH] KFENCE: Clarify that sample allocations are not following
 NUMA or memory policies
To: Vlastimil Babka <vbabka@suse.cz>
Cc: cl@gentwo.org, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Andrew Morton <akpm@linux-foundation.org>, 
	Yang Shi <shy828301@gmail.com>, Huang Shijie <shijie@os.amperecomputing.com>, 
	kasan-dev@googlegroups.com, workflows@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Christoph Lameter <cl@linux.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=HdZQ24rD;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, 24 Jan 2025 at 09:42, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> On 1/24/25 09:37, Marco Elver wrote:
> > On Fri, 24 Jan 2025 at 09:13, Vlastimil Babka <vbabka@suse.cz> wrote:
> >>
> >> On 1/23/25 23:44, Christoph Lameter via B4 Relay wrote:
> >> > From: Christoph Lameter <cl@linux.com>
> >> >
> >> > KFENCE manages its own pools and redirects regular memory allocations
> >> > to those pools in a sporadic way. The usual memory allocator features
> >> > like NUMA, memory policies and pfmemalloc are not supported.
> >>
> >> Can it also violate __GFP_THISNODE constraint? That could be a problem, I
> >> recall a problem in the past where it could have been not honoured by the
> >> page allocator, leading to corruption of slab lists.
> >
> > KFENCE does not sample page allocator allocations. Is kmalloc()
> > allowed to take __GFP_THISNODE?
>
> Yeah and SLUB is honouring it.

Fix: https://lore.kernel.org/all/20250124120145.410066-1-elver@google.com/

Thanks for pointing it out.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNpFTweLW_QawTa6eqF6vOrKZPL17r16CaVipPWqZsSKQ%40mail.gmail.com.
