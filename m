Return-Path: <kasan-dev+bncBC7OBJGL2MHBB27WVXBQMGQE2BY7P7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CA98AFAD88
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 09:46:53 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-e819f79d125sf3301187276.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 00:46:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751874412; cv=pass;
        d=google.com; s=arc-20240605;
        b=WhjLRVE4EzjaaVdwjtLPVXDD0OykI9CPPJtHbeizf9u0BFK/uFV72SZc5jVRcCfKxU
         x+IKKRevAz0xLsqoW9WNguQpHkOv3zIp8bHZhrxco3O8hrTPwVM/ADVIvByKtHlzgZPf
         8RKmhqm/PIeGjWLJDOSiVrHOYWzibTwS8/EzbhAGzBz0MzhYWgW94rb+h4KoWOPht0l4
         qQriwXs+a8uerUppn/iFw5l9J8+q/m8p18H+hqi0wfwlM5JcB6vLNzWKUa2rktwwqd6L
         0EUcFBegIpzebyuRq4WSa0Hdd8k3eE6xjTSGqFDQNj5hd2Ygc0qfl1I/WSRV++AmvGrI
         wInA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dP7ZiOPCFKuEH507InWzy/EHQNXewj8+7t7xiN7ta18=;
        fh=8H1gtoshMcUfU+GFZt+mkrlW3KTEgNYAuQdgh3vKkU0=;
        b=hT+LY1H4B54IA4g2Pnmqqycymx153TuDxced6SnUtHebPa8WMVnMpKDNKo5zwiOK4h
         OQ6GF8vN+ULJnc+Qs0QqghwrSujF0tsBgE2lznxE/+B1iamZ6+LXvV7GPX5qxSzjyDB6
         kcocfBteiK3YMrHFUHEtP+ZcUpGCwb1JAzW7g/7c6lc6AUDUFeUwwNz4ZDg6PcxzOqsR
         INtlsW6GLb54PW8H0j+u9VE1J8nJal8MsfZmxtc/B2DgfJA7zVl2Oc/ixoxpudPxZkiA
         lc2i3KSTPqt7L1Qr+Y2lXcEe1lf20qaHhnMv31jtBnEFYOEe0Vw31Lt9lhDwc3X+/ttd
         6voA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XPa6P4TF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751874412; x=1752479212; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dP7ZiOPCFKuEH507InWzy/EHQNXewj8+7t7xiN7ta18=;
        b=Ex5XpQ7Bd8yjj03A8CUrGNmguW1nyHt1b5tgPhkEOTx2ixICBoAQyLbxkBL7oXNTDt
         SAYVK90L6D0V9BQG0dc1g6pKFKpFkwNEjeNqroo3DJBOh7k46/3bQTKn3rd9jfIcNoLQ
         TT+EKzziUCSEVd0pqPf+LQbuqETpH5ZCIZGcIQvtnD9Hdpel+dzq70SF9vwxs+S0Om9u
         FmsHPtDUGjZpSE2D9WSVKE6V0PGr/ovryhgAisi0lpNgpJl2HW/N3gf0hW19npFhMSp8
         zcliH5mLxF63ct/Or+3b+ufNSMBzOOqqUA5Phpwh7s3+qHs4OAxOJK0a7YgrnwAH6R4K
         Wgvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751874412; x=1752479212;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dP7ZiOPCFKuEH507InWzy/EHQNXewj8+7t7xiN7ta18=;
        b=NGtTcs2OJ07z4JXqH5Q19qyDV4Xe+lzUPXm5ccBGh9JmTBK+bK9oYj65X0svKN0yJk
         goNoecS9k8h8ocS5IRT7dJ9Bp7CIpZ4G36xjC42jiBoMD/SoFUJ/7EGOLYCM9z/bQZe1
         hmyA7naYkY1cKshaw82uadJ6hGtJ/N9kbL9VJGNg+KI8YXc3xHDY4pDlOdHFEuiTZclq
         l7kHi6O9R/8NfuFLihStGJBqAkYaPtoGxYNWP67iT7xQN62yP2IlzIZY/G3ehb9J/ipO
         2i//feQsdBjfo4UPmqlak4Bol/eihJAo+A0vKB6kQFwgJyX6mkhjHfkO6crxDXV0K+0J
         nD5A==
X-Forwarded-Encrypted: i=2; AJvYcCXrZr+PL/HK+iw+/9CADJ/GjE1dxtSk6QNFVceWhEGnmbJlcgu5H/pkBll91p0O6wUPU4fT6w==@lfdr.de
X-Gm-Message-State: AOJu0Yy3Fep0tZuXRwxKRTO2EziID3U17lAS3sYrN3hXCfaBAkHWX7YI
	qaLX2Q3+ls3YJGzVdm/frpBX/50b35pOKMI6jh4/yo5L/KWi2gLblHZl
X-Google-Smtp-Source: AGHT+IEM27b2CeMIPfPykdeGpeDSAbum6756C0Sdg3j53tlyS6ggy/RdD1jPREfPdKl2eZXZmMGDyA==
X-Received: by 2002:a05:6902:1684:b0:e8b:5465:fd73 with SMTP id 3f1490d57ef6-e8b5465fdb6mr2808658276.4.1751874411890;
        Mon, 07 Jul 2025 00:46:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZex9xxABIcmhfokHqPwO/pn8xem3Ya6nVGpm9AfHg5Ylg==
Received: by 2002:a25:5104:0:b0:e7d:5a87:b47b with SMTP id 3f1490d57ef6-e89a368d39dls1889298276.0.-pod-prod-01-us;
 Mon, 07 Jul 2025 00:46:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWHehjGpCfNXSNpSI3w0TGBXeXC9DnoUXHlmm4NUy+aU+Dn1cLZ9F0E/UF994HFM07ncLrgYkPHZ6I=@googlegroups.com
X-Received: by 2002:a05:690c:d94:b0:714:31:c9c6 with SMTP id 00721157ae682-7176ccea434mr97101757b3.30.1751874410719;
        Mon, 07 Jul 2025 00:46:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751874410; cv=none;
        d=google.com; s=arc-20240605;
        b=ebLFvOiQ7YZu2FrCoR3C/FnGBkqKwHwQzETaNtICJ1cOcqyAEf43IoOSH/LyqdDB89
         Vwe+3FmnAIHonOtDHQuWBlpTgx0ttqyfq1IyQcEbhLaFEV7VTq4PJqJHZKha66O3pDnN
         vVHnmdn7nEhohIVECwGrosObBWLIrR8qtGaWYJF0ufVk3rvz6dYoDIJX9pcJb3PWMx6x
         48K32EChoLJffez6el6wN1awnFEpf0wHryhDwLoef/uDB0y5PV4SvLHV+7j/BNaUIXIl
         FGcifL6rEiq9loGOqcfyMQ/MeEOfOQ7u0nWAVnIRXFNeOTBJ3dOpHEsElmzTv/nQn24e
         agCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9fNW/ipNPp9E7WVydECVXrddec24Up9r1hPRynNq8M0=;
        fh=pJ9tlhkOVFkeLFodmWskE31NCBUsrOPvXgGgnT0I+go=;
        b=BZqHNRiXvZemueEh0n/+f1uIXIz0iSO1Sd+mObim9g/ivqwYkrM5YoSXb6mvb09Mec
         K9cUHAeKd0/gzSgh6w+CIlVAq4nUTPDzX9KnIVNCKDUArvk1FlyR3uowJvUN2BaOs/88
         i+hBgjljh5x6fIlnAtPBhjMbq8HtJFINCu8qbGlkSd8jKqrUDHZs9H9U1/KX6vSCb7uk
         OZbQUR0GVywdfTwj3XGxGXQBSFc59oeRiYYTk4GJ9lox2RN7XOh/xtX7QID+yFR3ScLy
         yz0Lm/PXK+LvDNlhs4G7qUORgjq1tDlRt5OKBYjj06gRdw4VDJNqKOtz8kuy9OaZzw29
         x4Ig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XPa6P4TF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-716659facd5si4053997b3.3.2025.07.07.00.46.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 00:46:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id 41be03b00d2f7-b0b2d0b2843so1786305a12.2
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 00:46:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW4CVv7H8VdTBpO983ZCr9sL5rU6xFbxvzDTkLatDwPrkdRsyjiI+ICKOpOfJPKBfGqs6U3TGx7+3I=@googlegroups.com
X-Gm-Gg: ASbGncv0a1WLxYPBfiUyPvIJNBCwrs8COUyAAb+GCf9OpoEXy1itWxo77N1rqqkYfzW
	R4KuZP8zPEP84Qa7AAGyzDgTnrIm9FsKvY0JqjyllQqsqoGwZ6XqrAws62PJw8WRQahOlROGXa2
	Hy7PaphYX2rwC7oINCALwaB2JmZjw2FYkEEIC5pzSW2QVoE6mQzxY+2g98oWhCn7/zF/KOzT0dz
	w==
X-Received: by 2002:a17:90b:57d0:b0:30e:5c7f:5d26 with SMTP id
 98e67ed59e1d1-31aba8d28a3mr10983089a91.24.1751874409534; Mon, 07 Jul 2025
 00:46:49 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1751862634.git.alx@kernel.org> <740755c1a888ae27de3f127c27bf925a91e9b264.1751862634.git.alx@kernel.org>
In-Reply-To: <740755c1a888ae27de3f127c27bf925a91e9b264.1751862634.git.alx@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Jul 2025 09:46:12 +0200
X-Gm-Features: Ac12FXwJB9HCD4i8JLB6RoA7PkR95ZBhaAJktuICujVit91FZfsr8G443fGUagE
Message-ID: <CANpmjNNQaAExO-E3-Z83MKfgavX4kb2C5GmefRZ0pXc5FPBazw@mail.gmail.com>
Subject: Re: [RFC v3 5/7] mm: Fix benign off-by-one bugs
To: Alejandro Colomar <alx@kernel.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, 
	shadow <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Jann Horn <jannh@google.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=XPa6P4TF;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52a as
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

On Mon, 7 Jul 2025 at 07:06, Alejandro Colomar <alx@kernel.org> wrote:
>
> We were wasting a byte due to an off-by-one bug.  s[c]nprintf()
> doesn't write more than $2 bytes including the null byte, so trying to
> pass 'size-1' there is wasting one byte.  Now that we use seprintf(),
> the situation isn't different: seprintf() will stop writing *before*
> 'end' --that is, at most the terminating null byte will be written at
> 'end-1'--.
>
> Fixes: bc8fbc5f305a (2021-02-26; "kfence: add test suite")
> Fixes: 8ed691b02ade (2022-10-03; "kmsan: add tests for KMSAN")

Not sure about the Fixes - this means it's likely going to be
backported to stable kernels, which is not appropriate. There's no
functional problem, and these are tests only, so not worth the churn.

Did you run the tests?

Otherwise:

Acked-by: Marco Elver <elver@google.com>

> Cc: Kees Cook <kees@kernel.org>
> Cc: Christopher Bazley <chris.bazley.wg14@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Jann Horn <jannh@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Linus Torvalds <torvalds@linux-foundation.org>
> Signed-off-by: Alejandro Colomar <alx@kernel.org>
> ---
>  mm/kfence/kfence_test.c | 4 ++--
>  mm/kmsan/kmsan_test.c   | 2 +-
>  2 files changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index ff734c514c03..f02c3e23638a 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -110,7 +110,7 @@ static bool report_matches(const struct expect_report *r)
>
>         /* Title */
>         cur = expect[0];
> -       end = &expect[0][sizeof(expect[0]) - 1];
> +       end = ENDOF(expect[0]);
>         switch (r->type) {
>         case KFENCE_ERROR_OOB:
>                 cur = seprintf(cur, end, "BUG: KFENCE: out-of-bounds %s",
> @@ -140,7 +140,7 @@ static bool report_matches(const struct expect_report *r)
>
>         /* Access information */
>         cur = expect[1];
> -       end = &expect[1][sizeof(expect[1]) - 1];
> +       end = ENDOF(expect[1]);
>
>         switch (r->type) {
>         case KFENCE_ERROR_OOB:
> diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> index a062a46b2d24..882500807db8 100644
> --- a/mm/kmsan/kmsan_test.c
> +++ b/mm/kmsan/kmsan_test.c
> @@ -105,7 +105,7 @@ static bool report_matches(const struct expect_report *r)
>
>         /* Title */
>         cur = expected_header;
> -       end = &expected_header[sizeof(expected_header) - 1];
> +       end = ENDOF(expected_header);
>
>         cur = seprintf(cur, end, "BUG: KMSAN: %s", r->error_type);
>
> --
> 2.50.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNQaAExO-E3-Z83MKfgavX4kb2C5GmefRZ0pXc5FPBazw%40mail.gmail.com.
