Return-Path: <kasan-dev+bncBDRZHGH43YJRBJMVYL6AKGQEJHQ6GSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6586D2952DC
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 21:23:18 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id c8sf2455760ilh.9
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 12:23:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603308197; cv=pass;
        d=google.com; s=arc-20160816;
        b=m0G3X875zHaKmor4+J99WEfKvu6jIpL05UxQhpbw38a5E04dg9rCcAL+ihvZL+nIqV
         HG/hnKPiyurq622kGyxyBBBhKqSr0y6uIrnXBgkL+PI7Fs4ptsJ7TessjYt/iCY3au2t
         Jp7UFT7N5X0a1OdkhK+S+ptxBMI1jq0sXeOrgC+Xn+mf5Czx1sxrJ9s9kmPme0CWCpog
         vo7bkURUijCqXv1C6t4oWGzZbnmhCPyn9IG2+o3MfUkqM8l2zLYUqtZGm0cmIgup5/Qi
         F9MhRVYbrIf1MReonjMsCs6ulDQ3IZcfc971quLO6Ck9kzayp4l3OBgXb56fzEIvlVKL
         Fqeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=3kXxsrpmJL6AAGbH4I8lkfav15qqHMR2A/8sgsESm9g=;
        b=Zc26CWJdIxj5+d9xYU5qBqWAKM40dMjjk8T6Kc6dVntStOVvEcJ+v1vdiVN7WHmD6b
         EAy2HtyzljMXcSpQa0oR0p2PhAx2avexvHmrUCcd6QGbcyQLr46G+k15wkDNzHs7IMvY
         vbInqoEn+JgwYo97N4tcaqAxFfwksdegAuVqtPieCESea6PLUwhSHclQV+hHjR0xEmhh
         yrvGlP/ZjohebiscF/musYQsf6ow2js4FjD4qPqr08ma+yv2oB+sFwiC9CGQNLD1P05A
         27hfLjOINAwlSgzWH+q+OJ/DmYAUELB1oBEudUQSuTKDxvwUPe+rtPH2F3HwjkjcxT7+
         2VOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=t8zYGjnd;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b42 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3kXxsrpmJL6AAGbH4I8lkfav15qqHMR2A/8sgsESm9g=;
        b=eH//rvOs9ivS6qvjb6BxOqwebrX7Yb6E/RL8WqjjNL28G2pUUJHGkrVHzj6gc8UAj5
         hQfAkcyPCmnWYMvnxzZJq2YwmWhGCB4iqNA2Xvo9YSIK/wh1UR6n5g5ox0eLoa/tbMvL
         qT+6ebreV7HquGFSNZU4XotV2l8iB7S7ZY2i1MhwIKnBQ4+DSFrRjEHD/98GzD6CYBNr
         cVJA+MDspmTW+4tYFJu6lIexwJEfpImHB921jB1oCE8o5a56uUjEO8hYTVbc4EqjRS6X
         HTcnbO0U3zwCgWYO7lXc1HNdmZ3v2KpNPMj1tbW8n+sr9FIjO2WA2AwkMZgVov7GCtYS
         BUyg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3kXxsrpmJL6AAGbH4I8lkfav15qqHMR2A/8sgsESm9g=;
        b=m4AxXm8kbT15x3+gy0S51B8fPhtbdLaf/xnUvy/wjfswenOswy8be9ZozpzYDq7mVd
         hT4pwRJOUMbY0O50G3MUITL7ZO8ksqtV6WTmmmY2fSc8i0c8ePY2JU80PNW5c6EK5RJg
         odt+XAEluJ9d8BxrFKKODTNArp8SlbyStyj+TxlxlDfNm19O3+qdxauQaGcRKMafaEiV
         SOXFdQQKmxO1aGViOLD44sqJ4eSKcWYg+saG+xNRwW2j4kF1rsDUuACEyX4Lp3yk2mJA
         j5zqkJkoWw4xBOvM/dd3mJ+QrrbIl7cwyMeHo1Ir9+AmGMFR7Gl+OJMhIZNn/76iQQst
         Bu1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3kXxsrpmJL6AAGbH4I8lkfav15qqHMR2A/8sgsESm9g=;
        b=KGM3M9yrCk6h8GSby+vYZ7DPBYVgvC47uxiJpHSeYf1su89L93peWPmLpSyWp0C+nn
         fPvotDS6FroHlj0M/T1z8GCIuE0f1+g/UvYi2E9/Jm5Lc5iWen+1t+8Gnv1H1HFhMghP
         DkntLGslaQ6XFIS0Fnh/8oqMkoHBBUKKXeBmUPZU0QbkQ845KpuXOMvodQI1Snt0jZUT
         UsQbuGnkyYwvRsihJThgWar+XGH1bp8MsTj9IsczxdeYvgUyNN0BhrT0ueUstCk/ZDN6
         LPFgek/7GWwVqTJOM85ZC3vchzoFkhKTGgu+QxuDYaGtDMIBqMlIA21BRaxLiDm/4/Je
         WaLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5321docnXRC+sKhI9OsMHnmpseO9MUS6c1k1FJniglCKs9fgf67C
	sxo740KdJRvirtLKnap4Gxo=
X-Google-Smtp-Source: ABdhPJxBcxIZ9f4Pp7/vMqN7tfGbjxlnVVoRjJyLelQgyKBSdqYHennEdE2FiGIuM97E6x5qwyCE/A==
X-Received: by 2002:a92:d441:: with SMTP id r1mr3746773ilm.164.1603308197192;
        Wed, 21 Oct 2020 12:23:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d58c:: with SMTP id a12ls127015iln.2.gmail; Wed, 21 Oct
 2020 12:23:16 -0700 (PDT)
X-Received: by 2002:a05:6e02:c1:: with SMTP id r1mr3758250ilq.250.1603308196757;
        Wed, 21 Oct 2020 12:23:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603308196; cv=none;
        d=google.com; s=arc-20160816;
        b=KpmK1ACeymOiPawyhCtAHUDOVZMqcyokdedPRcCQir4rCT/rZJam0uo8yVanr0S4Ok
         djcleGsIcKhYlIf4l1le/AXEpPe3/y/XPBm0qPG3u0nSlCWu4GwiO53nB43wRpMKMwPa
         j0viUgMZb4JY4FHFFHks04xg26LpQXIOBB1+4mIwcL25jr73mEaSfT7r2/nkwhE9vpkm
         2lvqMyIR3vXcQPK+UUj+5GnwmapSN/5Y11UAfao4W/VKZ5/QSZcIsndRRVjxGH5Y6YG4
         wssYVdvB4bOzLkh+P/bfl4wtn225YoS8eXtONzfFU/qvbFi7IlLH8dj4ulMk1zK4ocNi
         7log==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ngb6VdnFO3Cj0Aq7+OesUyk7zjfF0LMjcERe0s6GBrk=;
        b=K0d7zKl8bznUyejQuaIN34VO827n7fCS+UheAAx2uqSh+ZMmS8o/H4YmnzqWHLnVzZ
         RIWJnPqMbu6DIz062CA3eXekOvok5l7RUuy5/CQMFN7l/rLU+1vMzaXOOpSGpltj3ud+
         b2GxcTguXKmz9W6H2KVZ0fjN0tWXadBNxq4lwgdV+DVbL1dhjP/Alz72MbBvsOh4lD2i
         5cEUTbnSF/qn3Gvoi/1xK625nnQg+Vr+v91z9u4oTX6PTWjbs/4Ybb+BLGyUCOmnuVND
         JdLSOKGsdFoTZkAn+gXalSPq3oJHUNieA1lcCLz65oSIpOaWQss6bi/LHjGCpqK+GYPW
         u2RA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=t8zYGjnd;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b42 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb42.google.com (mail-yb1-xb42.google.com. [2607:f8b0:4864:20::b42])
        by gmr-mx.google.com with ESMTPS id e1si150940ilm.0.2020.10.21.12.23.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Oct 2020 12:23:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b42 as permitted sender) client-ip=2607:f8b0:4864:20::b42;
Received: by mail-yb1-xb42.google.com with SMTP id l15so2758830ybp.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Oct 2020 12:23:16 -0700 (PDT)
X-Received: by 2002:a25:384c:: with SMTP id f73mr6935747yba.135.1603308196270;
 Wed, 21 Oct 2020 12:23:16 -0700 (PDT)
MIME-Version: 1.0
References: <e9b1ba517f06b81bd24e54c84f5e44d81c27c566.camel@perches.com>
 <CAMj1kXHe0hEDiGNMM_fg3_RYjM6B6mbKJ+1R7tsnA66ZzsiBgw@mail.gmail.com> <1cecfbfc853b2e71a96ab58661037c28a2f9280e.camel@perches.com>
In-Reply-To: <1cecfbfc853b2e71a96ab58661037c28a2f9280e.camel@perches.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Wed, 21 Oct 2020 21:23:05 +0200
Message-ID: <CANiq72=FFasodzT76EqaSj_NEY2chV6hzoDtkhMMQfa422oJrQ@mail.gmail.com>
Subject: Re: [PATCH -next] treewide: Remove stringification from __alias macro definition
To: Joe Perches <joe@perches.com>
Cc: Ard Biesheuvel <ardb@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>, 
	X86 ML <x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Herbert Xu <herbert@gondor.apana.org.au>, 
	"David S. Miller" <davem@davemloft.net>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-efi <linux-efi@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Crypto Mailing List <linux-crypto@vger.kernel.org>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=t8zYGjnd;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::b42 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Oct 21, 2020 at 9:07 PM Joe Perches <joe@perches.com> wrote:
>
> Using quotes in __section caused/causes differences
> between clang and gcc.

Yeah, it is a good cleanup get.

Thanks!

> https://lkml.org/lkml/2020/9/29/2187

Can you please put this in a Link: like Ard suggested? (and ideally
find the message in lore.kernel.org instead).

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72%3DFFasodzT76EqaSj_NEY2chV6hzoDtkhMMQfa422oJrQ%40mail.gmail.com.
