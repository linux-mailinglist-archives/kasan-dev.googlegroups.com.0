Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7PIUC5AMGQEMWE5Q4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AA169DB4A5
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Nov 2024 10:14:39 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3a7a5031e75sf7073525ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Nov 2024 01:14:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732785278; cv=pass;
        d=google.com; s=arc-20240605;
        b=i+S+P1X/Dd9wsNCecy7SNFSEAMHzIlrp6t97azVbvPXM0Uqf12/GzuhbSYpK2DAQPu
         QNuiSDcrOcmCV8Fs41yH6SczqR5RaITgt35HoA4/WS75OYFGtInGprQxhr9XEBVZ6NQa
         g7blCnLRhCl07ScvKE7ym4lMJZ3YBWUYHyWajBIHVcINiHCSfkUFdAIapfsm+Ahualah
         fKpZg/aC0Oy0zx1eD+PyFnPq4WoBxtQh+Iwsr069onDWP8pPOUttMQ7rlKSp3u52TMTi
         /YhzVj6tN40tEge6uELhmEgKqG7UG0Tgb88Gw+rUdo71vDO2CGOqGiO9j8D2dfVMaX2u
         gVpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VxrCRgbjRvZ1stY31xczRqhXQqyjz7K0mkik5P14wAg=;
        fh=LgLKykPr8wkVH9jWwmFrH3v0r65rkvbnrUTzLxEEwkY=;
        b=aSgh2bLIzgAwJcRExLwxwS6aV43Y+QYQUrtXVq603GedAlqlJzmoJx7d4byhZXdwc6
         HZ2+q6EnxkNLr4npMsauUnB56mVPWT78dncGiIKli2jpwFLuWsVSiyvNO9+a3K4Y4ScK
         quxpztqwuEArIq7wTkbCQqulT0vp6cee7UfelROdclyuIqx3DPa/lrOUZLyhHpo9FG1R
         wzD7u6ukTmv+50NdAYmiWJOX5nVfjqXbUhekf6JFeik2jDjdXF3IXhlSLb7SjdTrvlkR
         vlW7v0/ukACDizC/hjU/dNu3yfFc5pzL87Omchg036i5CeH0JhrjnZZFzuDmY6avcEla
         neZg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Y5sBwn76;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732785278; x=1733390078; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VxrCRgbjRvZ1stY31xczRqhXQqyjz7K0mkik5P14wAg=;
        b=cTwi4ffOuinL/Ac5tDOF/9ijf44m446uTpqsZZwtn8p1uNJMZvegNZx945G6FCxQ9c
         5ehDaQtf9foVeB1yXt6OI55ySDu/8idHJI8hTjtqUJoIgNoTI9u7vDLMDdcJJl9nRuzC
         Bhjaxv2YwdlE0M7VIJwG3aCoJ6s+sKL6RvJN7bsxRQED55hujfrHfR/Qo0NCfBQSxJks
         B3yVIot1XGJn8XsFquW1ZAuUnkF9foj8XwwRN8VZFCkOH0gbhsIqLAPmWp3xNhKe7OA9
         scnTUOfxDuyc0qOpuMvt1UTIplttJbK9XoRKOgbGkztYPyLxMH2pWB2tyHG18ELPufd9
         DsSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732785278; x=1733390078;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VxrCRgbjRvZ1stY31xczRqhXQqyjz7K0mkik5P14wAg=;
        b=XRLNGZK2+ZZgR+23TNTpeED8oQwef5A6KN6m1o3N1MoYhGb19CnDtCA5zsGHeOeOEO
         BKj2qy0hvafWFcctFajGny4sWYbOoQzmFvPOzeo21YiDzXG4H11bV3V2K/O1WCgUnLfz
         m8LIvv/a0TiBoKr883fJddiRyiXdmuzxNP/B9l3S0D6LHgOM0M59VRJdDg1C4vHUIFkH
         LzOvMoeYGCW2VUBFy0v05X5QPp0baxzyZCzHyN8tVNxp44KJDR1ZHNoZNIrvvvarGTfj
         fKHu3kVgDsRQHG6FuWNB8BhOZDUSfleZKd8vpkdUvfKEtYyQ+pvYMu5+UeMOCNtSs2Q9
         059Q==
X-Forwarded-Encrypted: i=2; AJvYcCU+YDTMYd1Lw07KSodMu0bbEMCfpkY3dCg1oexA/H7O83ilxJgwbOqc9Ld2zmRE8AXDGxcumw==@lfdr.de
X-Gm-Message-State: AOJu0YwRmfK4AnFUN5ddK4vY6ndO8rkgoGlMrC6l0nN1AGSXG8mXzD73
	TGRpu26WE0iQB8VqQ31KdgxLnx+dmN5acqf+hJjoZ0iZRlDlZIjW
X-Google-Smtp-Source: AGHT+IF3Bc0frcevwfLalEJPQwEZjmc8KW8DBaf+NCF6ZoxJJbKVBrX9l7kXDgX1Wa0Z1SAwCV9tBw==
X-Received: by 2002:a05:6e02:20e3:b0:3a7:c3aa:a82b with SMTP id e9e14a558f8ab-3a7c5525305mr70647205ab.1.1732785278131;
        Thu, 28 Nov 2024 01:14:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d0d0:0:b0:3a7:d12f:a147 with SMTP id e9e14a558f8ab-3a7d12fafb0ls279435ab.0.-pod-prod-03-us;
 Thu, 28 Nov 2024 01:14:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVEuzIsK9GLe+H6tZpYqVkHXT95VDuG3rEJHnN8n4rla1qYqiX4131ad7EI+uhiKcpAVTMNBSOHMdU=@googlegroups.com
X-Received: by 2002:a05:6602:2d8f:b0:83a:ab63:20b with SMTP id ca18e2360f4ac-843ecec8bd5mr889164939f.4.1732785276795;
        Thu, 28 Nov 2024 01:14:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732785276; cv=none;
        d=google.com; s=arc-20240605;
        b=iFjvH/VfZjP0UmE2pMA9x5oDZZ0zEpYGHJVU6Gk5VPEGNxVYDHassezYPefx61fahh
         gtWNZ7CzDqMi3vXKFcbjEz6chR5bXhQ6TtKF3GOX1mmtD3Xm1tOcSunSOkGTRrYEJ56w
         zFh5QtEn30zpvrxFpqAKGZ7PFKJR6kmUQap3DiImtw4rMqjX0dyBk+bQGA6BG0DUEzj3
         cKFFCz+Abqpfb/WAdHcQmYY5ID6Vb18w1Nib1icu7vV84MM88b/SlTrHZFTwxAMo3qlB
         GBfTrBoaZk0JPxteAylib4Mr+h4P901PJ6sGjOjhuFtGVtu6mxidcdNBQ1fusXwHhllB
         nt/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+RwrGvFnR/1yuMp6y+4dSC7bCdIbBw1r8nPWRcX5aNU=;
        fh=8Rown2BzdboR9C9djsxjWCa/U3pKyWgacRUOKVifTFI=;
        b=ghYAMqZzaZBvgQiNegam1VKdsb2SjeY9nr74r3hPUP5x0pcl2urHf2c/oSLm3gH4SP
         XoLpUoeZQO4nAirS66eWAON/EPCAHqVULxOkTeJYxU1uQWHR+Ubda/9EfcbEXr30mqee
         njFRpnWQb1M1dwue3qbnqn3aGd1rH5znQur11oJJViTZ0gJUbGWbds5YzUSTJ35nOxqC
         tNSKarfzmShaBxsY5iKWpiYQn/tGBb+THLb+1lHNauf1VipuIYklxRu9kFpzNKtOyNbP
         b5YMyvuxHJ3PiQve8tXZNRBl67+mSQUrDE0pW9Jl285g4OA7h3i911wbtFT7Vb/Ops3b
         xF7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Y5sBwn76;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-84405d18feasi3815539f.0.2024.11.28.01.14.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Nov 2024 01:14:36 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-7250c199602so531625b3a.1
        for <kasan-dev@googlegroups.com>; Thu, 28 Nov 2024 01:14:36 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV34mED5nlkZXqwpx8YDhKEbLgHNrprkw/3/Bu3HVg1RJ1owOQujc6XwReSPgqUW3KJJ7l5jGZ+fhg=@googlegroups.com
X-Gm-Gg: ASbGnctIHAZe61MBtGTWMacb4EVIO+dqe+pPF8rHtz0L6jHSh/XXbz77za0FecOauPf
	1f+568n9OVGVjOO1lJOxNxmg9waWINZ5GyuA5ONwlLqEc69f8wOMKRsf0HyAy5uQ=
X-Received: by 2002:a05:6a00:92a2:b0:71e:6c65:e7c4 with SMTP id
 d2e1a72fcca58-72530185399mr8749308b3a.26.1732785275833; Thu, 28 Nov 2024
 01:14:35 -0800 (PST)
MIME-Version: 1.0
References: <20241122154051.3914732-1-elver@google.com> <20241127172523.b12b82d150aad5069e024645@linux-foundation.org>
In-Reply-To: <20241127172523.b12b82d150aad5069e024645@linux-foundation.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 28 Nov 2024 10:13:59 +0100
Message-ID: <CANpmjNPDVORFLCqnm3n1RHnJBKdim_x=kurbOJ0QYxaztT4q=g@mail.gmail.com>
Subject: Re: [PATCH] stackdepot: fix stack_depot_save_flags() in NMI context
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, Oscar Salvador <osalvador@suse.de>, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Y5sBwn76;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::431 as
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

On Thu, 28 Nov 2024 at 02:25, Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Fri, 22 Nov 2024 16:39:47 +0100 Marco Elver <elver@google.com> wrote:
>
> > Per documentation, stack_depot_save_flags() was meant to be usable from
> > NMI context if STACK_DEPOT_FLAG_CAN_ALLOC is unset. However, it still
> > would try to take the pool_lock in an attempt to save a stack trace in
> > the current pool (if space is available).
> >
> > This could result in deadlock if an NMI is handled while pool_lock is
> > already held. To avoid deadlock, only try to take the lock in NMI
> > context and give up if unsuccessful.
>
> Is it possible to trigger this deadlock in current kernels, or is this
> a might-happen-in-the-future thing?

I can't find evidence this happens right now (at least with the quick
test I just ran), so it's more of a might happen if use of this API
broadens.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPDVORFLCqnm3n1RHnJBKdim_x%3DkurbOJ0QYxaztT4q%3Dg%40mail.gmail.com.
