Return-Path: <kasan-dev+bncBC7OBJGL2MHBBM52T7CAMGQECBTY4BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id DCDEBB142F1
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 22:27:33 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-2403e4c82dbsf10079455ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 13:27:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753734452; cv=pass;
        d=google.com; s=arc-20240605;
        b=dkYn+fu6KnAkvWenYkCn8ZaZiRnV9vHLNytqE3wip8WhUqtywCms9E5g5suww1uJ4Y
         eDDUos5MSqCyR6Hcnj3SJbGsPAbnN9Sd4ak1ytn6StOgGL5o01Em+hQCESZtjL1xTRyh
         j8E7mXwQMO6JiUhwyNVNr+Ql216dVhZq8bmf1eGK4aC7ALWD3f3BTgHnBKEWN9kKUtSs
         2K17k+n349kIZFRsn+Wl2ILNe9HTv4IwB75ZzjMqBG/+U4LqTGMvp0O+zsMr1zbcSX5/
         1SdRSOagrz+jdgCjdK3ze+GEq+/1Pmg5HKnKsZ3Eck+fawJP2P4CUKMY3zqjmdk5el+N
         ym2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=M0B4RcgWl9FrDsLVoj+hNL0E0K+VHKeV01DjOSjELhg=;
        fh=yy8CUmBOZnKVcl8nxDJF78FPYNTBZSr4Gu5K+IXEZt0=;
        b=PadHNO/6oiuZE07fqBuhdS0FfOl+oQnhAQhrmpL41kTTE/fHWX4iBBvhGwwJoPvxft
         I5knkVd6TvZFUXAreNRHBEMX5CFoj2ROGRTs98cf+Fgcz6xh24/3d8LKs1rh4y1VJKlb
         4TO57ErqD0ZSDtGxxnryeVvJNgSClXEBXzL50HV+dU9ELUl6x6IHGxpQH4xqDKmA8XM1
         vLvwuld8sJfCN3lHsvbJ1lUCwNBXPcilNyvMHpRbWJls9T/3cw5WsprRzmH5/+kivrQC
         4j6N889H+bS9lUsPE/ZXfshEdsd2OpF71+EmAHFgvKD6abUCzk6hT/0rz20pMpu/2pSU
         moHg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wFwyXNho;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753734452; x=1754339252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=M0B4RcgWl9FrDsLVoj+hNL0E0K+VHKeV01DjOSjELhg=;
        b=C68v5Pzi/YVyU05C/WyncBXxKhIQU27dp9BBvw7jCIQCqRqzy66AF67o4RbaihDnTO
         GvwDH2MB/Y4qOlQXWgt4opym8XDQ5yOaT8x+ErM/rZqGFHcdD02APJ4GGrmJfhdFNM3S
         ausuOXSUoBy5DeMrKn42GXS8vZRfzH9AXWPSZj7Rql3eEdTNIWK5a8Kq/5fBMfStgLQ1
         M5zbVPK9SiaXM6FKbu5HcnbBNA8wVWgEuh5KIxqpwXEHtTmC2btDPqiZZ2uq5rDenqAg
         mnSrBh8k1ZEnbjSdqyQLWs6jhU6Aw7K0HgPWoEJSNwr3uW+VQuX+xgFXzMvZn3moWT4H
         osGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753734452; x=1754339252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=M0B4RcgWl9FrDsLVoj+hNL0E0K+VHKeV01DjOSjELhg=;
        b=knJhlB7swrd7taxbnGqVALxWNapHPeiTxaJVN6/oR7fh6wsojz1ANLQ54skMmrLCLg
         3M0fdfcycOgXUgAO68cV93gkuV69YMT7WwxL9s1u3+iJ0dy4rahEG++iE3se/Gpyo4Ic
         Ta7620WAkj2JxNrAhCuEPyGYtOFjXkK/Rwl6yeIeaZUGLz0pK0TqRQkctNplyY2h0kGv
         WRmZGC4/rAXgj4H06F2mBzcm6QcRcYiCjBY1VwPXu3JX/X/n38R+zPcNI9Ay2g/nYpvM
         V41yx6oTNS3bGcZPoCmrthsmsRS65v6CJA88LV2Ln9k9z+/ZNj289FkQCJP00k3Q0xyZ
         Rb+w==
X-Forwarded-Encrypted: i=2; AJvYcCXvlXbJbAH8xpqJ8JIfFlMO5mTS9qoCmTxkGMBk5QsayBoN/FpBnaKn04uJ1bfzpzXierhpJQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw2KOLN8QoEebeRHsKIKHPOanCXsqtNxQXS3E04zd4tI3rdxbSg
	S1stVx413FVYxS/TNdvls8mdxxVO/xZSmTBi4wVlzHun8pDle2WTaQcs
X-Google-Smtp-Source: AGHT+IEuP9a7SAECVvlkISt0CMFEFfqukwb163ojTn868gHpF7pgZ5b85lfckZR+M18nJqTSTdoexw==
X-Received: by 2002:a17:903:2349:b0:240:41a4:96c0 with SMTP id d9443c01a7336-24041a4ac7amr52950515ad.29.1753734451935;
        Mon, 28 Jul 2025 13:27:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc+YstxopQCVAfpuDZ8xWTwQi5HmdpG7d7pw8/sNPvtzg==
Received: by 2002:a17:90b:574f:b0:31e:f73d:d1a4 with SMTP id
 98e67ed59e1d1-31ef73dd306ls1189571a91.1.-pod-prod-09-us; Mon, 28 Jul 2025
 13:27:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXibIOiRcU0BdKZMKQgkRpVgw2PA3oI5PuSV4MiWYa8kK2lFNvEGBXSVPNDDjbVmNlsch9l4t+rofQ=@googlegroups.com
X-Received: by 2002:a17:903:1446:b0:234:d7b2:2ab9 with SMTP id d9443c01a7336-23fb306bcbfmr220865905ad.12.1753734450520;
        Mon, 28 Jul 2025 13:27:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753734450; cv=none;
        d=google.com; s=arc-20240605;
        b=AKTrOx5w+A6o7CJwyj24FXzWCgzAArReMAQTfsN0BtgAlHlxY/evcFADynjR4VgTxX
         6v/IgBpOOi1LwaITn93Z1NVf2mI0t3M2HwOh6JxSVsCcvNQBWdqA6U7pHOotCW1gmw+s
         Qn1YBZ2MdR/vjvPuZQlbWlLSi91LAktk4bpWeBrGS2L6XQWdOi07LZlipO0uQIwy5wrt
         0McrJX+fpDdHvPa+VbwyFhBLqPloqEKfeuYPGfG8xjrYb8uRsPaNDMkTDAP42YRLXLmx
         HspGYYp9z6zFo0jt5JsWWnLAoFNeJ0fQJ+IlcPN1xxBFSQqedjcelh3Bf5dFCQ8GydRM
         quaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=k6z/pDkQGQHJDGGW0WyP2y56SRGD0QXG8oTjmKwbrE4=;
        fh=f/zzupLctgejLCPCW/SVZQImCff2UJ4GKI5XExwG8Bw=;
        b=gxCGkqpQpmg0h0CACEoy4ku6xkBtN2PZmWTc+W2D/B97TZW83lMoOO+MU+vzuEkE3F
         BUqA4Af92b6gcvAoZm45dLJ7PEXgZyJWj15YYEx+p+Seoncl4U54MJccO5YBmOlWX83o
         zzmHnmC9Bilh9CEh0uw3v/Zh3d/Z3oOzg0F/Ry+DtLNTh9vYlvb0v3/O0JDAoRc/14NS
         2Qm+CcbxcYL6Imuva/YZFcuGE8u/9VCcoHerPTIBMjF9k8Xu3gQ30m8KoyZ/OIwR38tE
         5Kb6W0rZNStaaUrIqvqJF0JgdRmAObHjGnnXJOTuIAnXMIT9aCaA9d0esAPp0O9tG+FI
         LwaQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wFwyXNho;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2405504e0f9si512515ad.0.2025.07.28.13.27.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 13:27:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id 98e67ed59e1d1-31223a4cddeso3519453a91.1
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 13:27:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXAcB47/p9v1eAY7TwXtEGLPgZ36KlbMuVsV9peEBYg0Ieg6XxwjgmzejiKAw+0xcwiXyyBsQZrpac=@googlegroups.com
X-Gm-Gg: ASbGncu9bTbIr2Nkjq0hNANMc3c+RDhP1BXMAXACXbtgAZ/i5Ceqq9WyMcXziQzolhb
	hmLQA0+1aIkqPsBAHWQ+JAMjjvi4yNN30c5ThWwqvhIHXVvqCF4zGd0OvCN1yaQTCA8X0jCrpXL
	oH/q+l3FY170okerT5JCYqEm+WVfoYXPlrDJ7P22R/UCnCuCh7XmhMA3MFRmqLve3Aou/fvf4Zv
	MRYAcTp2oCBTFugVVP60RTSQB/5pxpxRgT6LltEWhucTy0OoA==
X-Received: by 2002:a17:90b:17ca:b0:31e:4112:4031 with SMTP id
 98e67ed59e1d1-31e77a4a2a3mr16714413a91.30.1753734449857; Mon, 28 Jul 2025
 13:27:29 -0700 (PDT)
MIME-Version: 1.0
References: <20250728184318.1839137-1-soham.bagchi@utah.edu>
In-Reply-To: <20250728184318.1839137-1-soham.bagchi@utah.edu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Jul 2025 22:26:53 +0200
X-Gm-Features: Ac12FXyPiMnImA19a92DEHCy10HpY4KQmzQuVM_kBdjTuWMJ5YVQbefnl37AKdc
Message-ID: <CANpmjNOP5OFX4LDNkfYdJMTDUEmEDpw9ha41Og5zbKt+VKZuzA@mail.gmail.com>
Subject: Re: [PATCH 1/2] kcov: use write memory barrier after memcpy() in kcov_move_area()
To: Soham Bagchi <soham.bagchi@utah.edu>
Cc: dvyukov@google.com, andreyknvl@gmail.com, akpm@linux-foundation.org, 
	tglx@linutronix.de, glider@google.com, sohambagchi@outlook.com, arnd@arndb.de, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, corbet@lwn.net, 
	workflows@vger.kernel.org, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=wFwyXNho;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1034 as
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

On Mon, 28 Jul 2025 at 20:43, Soham Bagchi <soham.bagchi@utah.edu> wrote:
>
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
> Signed-off-by: Soham Bagchi <soham.bagchi@utah.edu>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  kernel/kcov.c | 9 +++++++++
>  1 file changed, 9 insertions(+)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 187ba1b80bd..f6ee6d7dc2c 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -978,6 +978,15 @@ static void kcov_move_area(enum kcov_mode mode, void *dst_area,
>         memcpy(dst_entries, src_entries, bytes_to_move);
>         entries_moved = bytes_to_move >> entry_size_log;
>
> +       /*
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
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250728184318.1839137-1-soham.bagchi%40utah.edu.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOP5OFX4LDNkfYdJMTDUEmEDpw9ha41Og5zbKt%2BVKZuzA%40mail.gmail.com.
