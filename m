Return-Path: <kasan-dev+bncBCMIZB7QWENRBZULQTZAKGQEL55MQFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B0AB156FD0
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 08:27:36 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id t4sf5899375ili.21
        for <lists+kasan-dev@lfdr.de>; Sun, 09 Feb 2020 23:27:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581319655; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qya74fni+E6E5DTrllMGf7gMrkc3evP46hZ1QJ4OwFj4koUPxv9jMFdQYtYkXY9X5h
         jg6slXQLAvvagRXkNfUKcU6X00A8WF/ae0mesMDe2SawzZ+TTfp6q+bgzGlniuXu/mjB
         PlXckqe4x+7x9it7mjYF6eOwpDirZ89NrSxOzFDiCYsdIMAnXFpHTQ8/Y5R67Qa5XE8f
         iInXuEkS89B/i5GEyKTgqgdsiGCeNTEmol+qlenRcegcIPPp3VBPjXzz9FwJykL+I9W4
         yTdhR850rf9rMmTjyYTvUBvQpgVsc0NNDjr9YBtD1vSoE/DPcgUwHzxQBc8waiWU1jWd
         jNVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8fvYido1OXLXMVRFD6BTpmvn3J96j3IQoeC+vl2jHAs=;
        b=D7soVOiZLqabilOqwsSVxQ1MXHs0nFe9fkMzlPHYvj5TNLiaOF4/XphyFVa/1cVtrz
         uqqsblwkS48gdIp00Y735rUlVCmiSoGitP3vsL0gAasSnfRcSrvEdvOPympos2TJ2J1E
         HPLYcvW7Z8s5VggpN823TFQKXxQyePOPwOt5MT/N/CdQbDv1YqTGdu0zgafXU4LSbqce
         bfIjJBIvss78WsCRqAKyVWUgtk6YZrtiEvGby4e8T4Tnhd/wuqCY9EU1zsdCON7OpaZV
         x+vfn6yeA9Nyx6E7RyaoCbbfdO/Y/GaLSTYI1REDEnMCfTu5uohmcwKmmNk3jc4Ylpks
         B9IQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Qdfc8f2F;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8fvYido1OXLXMVRFD6BTpmvn3J96j3IQoeC+vl2jHAs=;
        b=HYkp2NMiot1RXn67eLmKKgvaNX3+4P3DnevTpPNLKSlBFKmbsZkLU7vSdOmKPH+R65
         Wi+XfqD1WHS2zD6ytIo6rOdZA+FDh4wezl+QVlwNmAoXMPbaA7VPbIeqojmYe0nNJNSy
         z2llerXi6hZJ/NjxAPXwJ1i0MgWY3qkUeykv9QvuQYNr9BQf6x6eSqGHHZP1BENQCncH
         2PTaodgXWLPqXPfqY6f7J0brZ0KMBdVK9BUN6pzH3ttR6fyb8pH5cU98nDOdQ0JdHBgW
         tEy8wFId4WpWKfk1t6izSTpyeEFKq/Y9Ipgy4WnrdiwkrmNwEK4VykE/XZ9qHpBPFcWo
         QQSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8fvYido1OXLXMVRFD6BTpmvn3J96j3IQoeC+vl2jHAs=;
        b=uL+wCWfj5XKscVxLbdhuBVKo9Lq9jildB/Giy9Dxh2dXPHAGL7q7jgemLYxoXZpzDy
         j/XTKm0tMsIEEwwKzxIHvQVAyE/GSxNhLRl4dC0MJCvh8dsxyI50zeoru6YijTlAI36f
         /XSzT5kTctJHCCNjN3DNaQEnAt4VmGYU8bywNmHvgXgzwkxOCRyZvNkRcv4QQfNbKxdU
         KWH3T+wgMQ+VMAudDKlE7JiM+cG8ShN35XfZG7Wn3AyY0EQ71G0WgeFtkxopG19dQ35t
         mgqh7C+yttuZLkYyUNFMJa1ZcHqTf3E8vTmwtaBvCXFXQ7nV92hU+0bepW/ltx0tfgsR
         2ZMw==
X-Gm-Message-State: APjAAAV/PqP9BFTSeYW6xcrzH8i6QfkLykEQIs0j9R/RYe6QskQEkf3C
	0sJcZfKWrW8xAmSiTvk/tqI=
X-Google-Smtp-Source: APXvYqxgcOhKZAG0cUXpD3W9UWoqPDzPSFP/VTWOd20mj5tWgLnESeQ2kJPXa7R7Bw1oi3DGu058/Q==
X-Received: by 2002:a92:981b:: with SMTP id l27mr163188ili.118.1581319654830;
        Sun, 09 Feb 2020 23:27:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:db04:: with SMTP id b4ls1391807iln.5.gmail; Sun, 09 Feb
 2020 23:27:34 -0800 (PST)
X-Received: by 2002:a92:d587:: with SMTP id a7mr147900iln.188.1581319654512;
        Sun, 09 Feb 2020 23:27:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581319654; cv=none;
        d=google.com; s=arc-20160816;
        b=d42kLzVbFyCkM3KaWXh1RqAesBbUuixwImORhXUMfo1lkc8ucQWyS0BJ9H5HU+jRWA
         2Paph5ZQf/E1Qb8KcmYjMFVr6VLRAj1GbIpdWOmo0eyhqlO8weaQre55WXuMJVScblaK
         s0Nhupo5rmRVMizouoopqWrNPg+fGj3SCSp6JWyo2V+JWs7cBN5ADuaK5QnQ9A60zRWR
         a1CbMBpJUI0g/24hy/EcnDs60x/Frb5fjiyz8+ri54XHVnxtz8QOqS6hMOeoDEJfz3do
         GC5OfWtt+LzAHI1yaP4fUaZv7O5DQWhe8LbRzrppMbPGXzxLyqGYQIVSJOJePiEmV7wq
         8k2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hzcZT/UWGik4t5gs1NKn0cClPiT0b3AGqVBvPjLWL6E=;
        b=Rnf6+VjIFoCcL8UVUz+034CtK2D/2lAMvvOFhvfLq5kxQgqrfn1YNKMnF4BZG6CCI2
         46Xet2WsFdXIBOr7uQ1RANtWvgjYVT8ccmF7B9KnI/jXZ61vOuI2AWpnm3ghf33GWlVp
         TH6WKUMHDgKbzwMcfTQ/j7+ty0Xxb3EgExRQOUGYPc1nA48PIVahBGe8GK7q1XNi4Xul
         e5ei6wFzDee5Xc4RpSJ0iaVmEi9WZWcbJdYwokCicjPuXx64f+Gy7Br3DWZGLRDkJNnF
         feqU+5YBql57xx1exe19QWrsaM7PGAFUidaPLKKvttHggPvymiIiPCP/zGFedYDZWyQ3
         JiZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Qdfc8f2F;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id k9si334333ili.4.2020.02.09.23.27.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 09 Feb 2020 23:27:34 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id z19so2530244qkj.5
        for <kasan-dev@googlegroups.com>; Sun, 09 Feb 2020 23:27:34 -0800 (PST)
X-Received: by 2002:a37:e30f:: with SMTP id y15mr180681qki.8.1581319653847;
 Sun, 09 Feb 2020 23:27:33 -0800 (PST)
MIME-Version: 1.0
References: <cover.1581282103.git.jbi.octave@gmail.com> <38efa7c3a66dd686be64d149e198f2fddc3e7383.1581282103.git.jbi.octave@gmail.com>
In-Reply-To: <38efa7c3a66dd686be64d149e198f2fddc3e7383.1581282103.git.jbi.octave@gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Feb 2020 08:27:22 +0100
Message-ID: <CACT4Y+aPgahWAyvM8KZm1bY3PfpKGjP_EHgCO8wsvo53EtGBYA@mail.gmail.com>
Subject: Re: [PATCH 10/11] kasan: add missing annotation for end_report()
To: Jules Irenge <jbi.octave@gmail.com>
Cc: Boqun Feng <boqun.feng@gmail.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux-MM <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Qdfc8f2F;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Sun, Feb 9, 2020 at 11:49 PM Jules Irenge <jbi.octave@gmail.com> wrote:
>
> Sparse reports a warning at end_report()
>
> warning: context imbalance in end_report() - unexpected lock
>
> The root cause is a missing annotation at end_report()
>
> Add the missing annotation __releases(&report_lock)
>
> Signed-off-by: Jules Irenge <jbi.octave@gmail.com>

Acked-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  mm/kasan/report.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 5451624c4e09..8adaa4eaee31 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -87,7 +87,7 @@ static void start_report(unsigned long *flags) __acquires(&report_lock)
>         pr_err("==================================================================\n");
>  }
>
> -static void end_report(unsigned long *flags)
> +static void end_report(unsigned long *flags)  __releases(&report_lock)
>  {
>         pr_err("==================================================================\n");
>         add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
> --
> 2.24.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaPgahWAyvM8KZm1bY3PfpKGjP_EHgCO8wsvo53EtGBYA%40mail.gmail.com.
