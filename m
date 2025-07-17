Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXWG4LBQMGQENH3R7RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id D06ACB08652
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 09:16:48 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-7048ed0751fsf11870876d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 00:16:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752736607; cv=pass;
        d=google.com; s=arc-20240605;
        b=OclSyEPQKlldGqzTZgsfN0cK9th4pSXFVTs3OBffMXtW+yUtbn7lWUtqbZUW7tMn8P
         Y0Ks6WlKKC1ZT66s0m0CHM6inw8slLwFDcRc9kktycZTy2C+ZDbIi4WWSypWACdIKuFP
         25Nny8p7Zh8SApOX+d2g7yuxI4o0wSJ13WHwSI+lBFxoi6DyMmck07Vh0hlVLIKYucwA
         6DKuK3+9Rwj9zh7Cu8cUNIPAN5twDK4uxMg2hkbEG0BWY5nH4jAgPLpXSmOOPmyQQ/de
         m8hihp3Liqhy42u5qaXQecDTHqHk8U3VsBVCU99XDlCMdgVrj0v1Wo9j9fENtU/1R1T3
         5oRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Exc6vPP2vr+mcpxrGdGE5OvR0dqqNS49AdMa9J7wlQo=;
        fh=ibJm+mpM3uXZOAI6K5QQadGIW69tAYonMl2ipG2r1AM=;
        b=fC6XiiBtyMRgscJVornL9vTgCAuLiguXy9HGfPg8IttIKC6mXfJPF81tFEDxvWUTrn
         d4+z/VZD65LNr14QCbY7XalHQm9Shg7VJbyllkbBhzqlnQWhea9wKZ+ZLoHJwIj+O0/U
         quxeQKSK/4pqH4krVhqgbVx7nCq+mqoR0E1EIwZ8f1Uadx1Yzn53LiLoDKtNMZ1LlrX5
         n0+acRMl/61Y2UOe8dWJqfnFF63Un8sL8eAkpYxvMdbwjat1Y0xKeyB4qFZ3j4r2iEv2
         NKFpCs7QVIRsZL0h+gCOVT0TuUB7jN2268t6FXfZZrTIYmwwdKsneF9+wDPnz9/8Xnsl
         BGBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EVvPR5xa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752736607; x=1753341407; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Exc6vPP2vr+mcpxrGdGE5OvR0dqqNS49AdMa9J7wlQo=;
        b=Lp1h4OVgVb6PuRaCUvuX2n1NaUVYcc5gVYp2AL4bV9nqSeVw6rWgI3NPgMTTo46+C2
         c2cXuuPwm+ArMOVdZusFCIKpB00nGeqjo2HuSjqP6CT5Q+wxmBIlAjUxSWP8o6sXGjn2
         QP0UDMpcGIL7odwhJ86OcSJOhGuLrRqVB5XHPxN/EQ43g81gffmY0Hq0Ojf6I5G6Dh5i
         b/gF0k59wDTsCZrFZJhVaAQcL1+ONl3F9qs5vlKtCo3oNSLGX3noJv4ZZd252HQCf5NY
         imBauEZIbic71mj5cYAnLMvd8awWMUVHrgnCJCfvGU5pWZks2/rjgZYcXlx8Uo2ylqhs
         H4iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752736607; x=1753341407;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Exc6vPP2vr+mcpxrGdGE5OvR0dqqNS49AdMa9J7wlQo=;
        b=esbuuNFPT/NtIHqzo9iLHW9onGyvaICvVW3kWeaz4YmR7FkQMFJkwlPukdDuxna4Av
         00ec+b5ccRkm70tnIim6otKv8cK1F7QXdnBvTIY0MTh5F+0F0IYH7L3Dyy85BB5Vqfpg
         KxLkaANEBxC+KF+ItjVpN1n4IQV3Wxzq6RPA4M6ScGEzbL4t6vbEXFFjmk4Lv+5q8Q1x
         WMfnmfkKc/bpJ1kW4aiQjmcot/NufuNwbSBTY30TddcpadA5IwN5aEkbsG9xuFbrAX/B
         /bGsz1NeF2nJ1HpEBvtdxq6PN86Rpd+XruB5i9vpKhF0l+ca1gvBtGnT+ZpoyQgRGjb+
         7c6Q==
X-Forwarded-Encrypted: i=2; AJvYcCU8QlrF73NwQR34Z5AQ0k7UccYBQBtMfM2M5UyY7FS1A8fU2Rr940WQiO1Jzf4NTh+6J5i1sg==@lfdr.de
X-Gm-Message-State: AOJu0YzZmnw7pqDT26QpgY17g4bjvrUxjQ/hiLXIwvs4F2qUWdSjaV/T
	glm9S8I6IJsMRaN09kVBXDks9XnbxHA2pHd5lgI0fIhBjZF2yvxf73ym
X-Google-Smtp-Source: AGHT+IGeLCqd4Gb2IxqLZqPGSahaIAV/4QXPX+hJwFvXEnUB8L5OhaMec7bDAI20itJtnf59M/ydJg==
X-Received: by 2002:a05:6214:318e:b0:702:d8de:ec3c with SMTP id 6a1803df08f44-704f6bb4fb5mr89631356d6.37.1752736607370;
        Thu, 17 Jul 2025 00:16:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdB+UU1mLCNoyjoyR8MH3XStE+QUO615uaW5GQ3xZ4kjg==
Received: by 2002:ad4:5be1:0:b0:6fb:4b71:4195 with SMTP id 6a1803df08f44-70504c47e9cls9205116d6.2.-pod-prod-06-us;
 Thu, 17 Jul 2025 00:16:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWM9yMugjJ52EFC3dSwdvRkzO26OXEiDo6KunUNW23Ha92x5PlTffQXpvpS2LUcNVUiABjvcIQ61z8=@googlegroups.com
X-Received: by 2002:a05:6214:dc1:b0:704:9a37:7e07 with SMTP id 6a1803df08f44-704f6bb5beemr100792536d6.36.1752736605829;
        Thu, 17 Jul 2025 00:16:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752736605; cv=none;
        d=google.com; s=arc-20240605;
        b=Md3vrAO4YRYqbp/JyLJEhikzTvksq0lu9pY26+oKxqKawx4YIegitlMaRx/HnHy8+L
         AdgxUTNnbhVGrehswD4sOEXCVBnGahyfO/dmVu0aUWv5pUUqRJwrm3AXf419cogM5izj
         gDAdrFuRYOlSzwvbXoQ/NP0xgV7JEHdmjW/dKkFCR0e+Ie9Q9n3WglKYQ869BHl2nFY1
         ZZAE9KBSUo+G1GDvIlve+vzFZtftV+x7uzdkgAYOx84wmEeB2eA4rZpI1+Yk+SWTSnor
         RltOeZfJTdR3r8NZeeTwCOZZEoWv9oIl5jOjc2tgO8QHN2AjF+QayQPR/mSx8IGZ3wZm
         SF8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WIe9kkvkYYKGSFuvVvovx0O+wBZjypzfMuU0ydKokdQ=;
        fh=9yc9K62cPV7g0jTcLVK2bthPyh6KIAB5tJgQERkZCH0=;
        b=FTfXhyQRSSmRnexpApDtcvzDXi7+zB7JPRlrIgDpwW5jktyDK+laO3ZWpmiphNg3U3
         yuWE+qwmrFNGTDDAe+EJyxEs0Vt7c1sfL6NJeyLbQPjBszMLp+LHQ1vK3XL4RJwdF0o7
         UeryQN5uP38xWyZuKY83+cbOUdrPYm8Ihi8/pPfuFSlYjqzwCmWGJdwDeQyksb2aZyeX
         CRxyCzg3MNAUwbIOVPNK4mxu8GH7aMT0sUYDglCRArWt3c1+Puig0vmJQLGfYAKsu6Qn
         tLLcTnsTrkHLY/Qhg6e1J6I5KZYurpbKK0uvXEgeHdIjySB2y3jS0QupXFdfRsjppkq9
         KyRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EVvPR5xa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4aba2aeb447si818001cf.0.2025.07.17.00.16.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jul 2025 00:16:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id 98e67ed59e1d1-3137c20213cso690039a91.3
        for <kasan-dev@googlegroups.com>; Thu, 17 Jul 2025 00:16:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV8JmdPtd43ybAd1PvsdKZjSqx52OG6BYjpbsqlrhra6FkvsLDdPN9Wl+tTGiuw3bh8GsH84OLSrG4=@googlegroups.com
X-Gm-Gg: ASbGncv8TYF56MUZg08rlwwhhJ+1sXtCsnX82uJYy3HSZXHJbhQHyAU/RY4OOyqKdg3
	44B9LChJZg1hQSp86lBF0xShqCvEpUZruqPCUMhgTXgVM4DvOBq3gcO2ONAPbVBdByWTof3HuBy
	kRW2sMJtURVRm/fcwy+SGFUdgvm96MNz3woro+tWOusg7yjKm5rJcZ8tM/OS67sH6ixuX2GUQ4N
	7SU/Dn4JqQSWitCsvJ65DrVYC44k7BMDLl8GNQ=
X-Received: by 2002:a17:90b:2684:b0:311:ff18:b84b with SMTP id
 98e67ed59e1d1-31c9f47c7d7mr7122717a91.25.1752736604492; Thu, 17 Jul 2025
 00:16:44 -0700 (PDT)
MIME-Version: 1.0
References: <20250717024834.689096-1-sohambagchi@outlook.com>
In-Reply-To: <20250717024834.689096-1-sohambagchi@outlook.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Jul 2025 09:16:07 +0200
X-Gm-Features: Ac12FXwIGhVeEpUQ0grjozMyt1Ndc63XTLmOY3WAMnQKcc2xypvxOlA-e1Ryozk
Message-ID: <CANpmjNOu2bqqevOcPGmZR1Dp69KFY9-TW3i2i_37BCTcE5rYSg@mail.gmail.com>
Subject: Re: [PATCH] smp_wmb() in kcov_move_area() after memcpy()
To: Soham Bagchi <sohambagchi@outlook.com>
Cc: dvyukov@google.com, andreyknvl@gmail.com, akpm@linux-foundation.org, 
	tglx@linutronix.de, arnd@arndb.de, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=EVvPR5xa;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as
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

[+Cc glider@google.com]

On Thu, 17 Jul 2025 at 04:48, Soham Bagchi <sohambagchi@outlook.com> wrote:

Patch title should be something like "kcov: use write barrier after
memcpy() in kcov_move_area()".

> KCOV Remote uses two separate memory buffers, one private to the kernel
> space (kcov_remote_areas) and the second one shared between user and
> kernel space (kcov->area). After every pair of kcov_remote_start() and
> kcov_remote_stop(), the coverage data collected in the
> kcov_remote_areas is copied to kcov->area so the user can read the
> collected coverage data. This memcpy() is located in kcov_move_area().
>
> The load/store pattern on the kernel-side [1] is:
>
> ```
> /* dst_area === kcov->area, dst_area[0] is where the count is stored */
> dst_len = READ_ONCE(*(unsigned long *)dst_area);
> ...
> memcpy(dst_entries, src_entries, ...);
> ...
> WRITE_ONCE(*(unsigned long *)dst_area, dst_len + entries_moved);
> ```
>
> And for the user [2]:
>
> ```
> /* cover is equivalent to kcov->area */
> n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
> ```
>
> Without a write-memory barrier, the atomic load for the user can
> potentially read fresh values of the count stored at cover[0],
> but continue to read stale coverage data from the buffer itself.
> Hence, we recommend adding a write-memory barrier between the
> memcpy() and the WRITE_ONCE() in kcov_move_area().
>
> [1] https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/kcov.c?h=master#n978
> [2] https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/Documentation/dev-tools/kcov.rst#n364
>
> Signed-off-by: Soham Bagchi <sohambagchi@outlook.com>

Thanks for the patch.

Besides the minor nits, this looks good.

> ---
>  kernel/kcov.c | 9 +++++++++
>  1 file changed, 9 insertions(+)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 187ba1b80bd..d6f015eff56 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -978,6 +978,15 @@ static void kcov_move_area(enum kcov_mode mode, void *dst_area,
>         memcpy(dst_entries, src_entries, bytes_to_move);
>         entries_moved = bytes_to_move >> entry_size_log;
>
> +       /**

This is incorrect comment style - this is a kernel-doc comment, but
not appropriate here.

> +        * A write memory barrier is required here, to ensure
> +        * that the writes from the memcpy() are visible before
> +        * the count is updated. Without this, it is possible for
> +        * a user to observe a new count value but stale
> +        * coverage data.
> +        */
> +       smp_wmb();
> +
>         switch (mode) {
>         case KCOV_MODE_TRACE_PC:
>                 WRITE_ONCE(*(unsigned long *)dst_area, dst_len + entries_moved);
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOu2bqqevOcPGmZR1Dp69KFY9-TW3i2i_37BCTcE5rYSg%40mail.gmail.com.
