Return-Path: <kasan-dev+bncBCCMH5WKTMGRBD5DT66AMGQEUKI73SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 98245A12710
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2025 16:17:36 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-7bcf01691b7sf981418885a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2025 07:17:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736954255; cv=pass;
        d=google.com; s=arc-20240605;
        b=GlXqM9+9nz4BwvMYefZ5rGVSnNw2qHw02kh8JR9s9l+P6iwpwImIpKh9s9qTAHV1nK
         wFNONt5PeMVOewmlo0L8zp5D/bz8QJrFiDfBbkjgGLQOrC9H7R2A2N3xuITqYYj0709A
         DblpkadhjdtycXiHDxm5i6QHpgt3Y9hCjzjcq2xzUk2V1NlTulJG5BQ3E+Qb0Boee1WR
         TCwtkVOdFYiwuWZAOer21B0cDgAhy9MmqnxlnC+0BZ66HN59Rf0LBVbq8TTGHOBEl683
         w+MIFiEU2FuN+v6Vd1c0OMPO2d0Y1OSuPGKOgMSWTsTsOPPgG7HrfQntDcDCuqPhCkz5
         m1fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=llVsVVnDrHNVTV3UOsySmCmVnYvGddtQDvQZawCq/Lg=;
        fh=gOQ/m3Nv6Lro6Pdh/Nr/XG7Z4diBaQpa8EKmzrYHjOE=;
        b=AGUgsRmevEK/2vxyqUmiTFZ5bkiH7ADvaCDzNwCHUJemn929M9y3Co7uIOKpt6ICp9
         puseGCyrk7fMe8AG/nrgc++CJjzxAwpUoPDtc8vgp2sGjd4zG1MFQoPrAszgmuDeALyn
         1WQZZ0tDw9/HpA5lmGkCNG8Z6+TdfV1yAFeZgcVx3qR1yeAobQVNVloKApkqPVvKUD7/
         5Vqn1K/FU9DKPgH+FjeDkgvS1db0pBeNfgLHvFkNHn5i2ACb/7MDUrXaGpEvi8c72Nia
         eZXnACzTqrmlKBPYVrjvaaS0JVnZp82IDekkV9z+LH95F9Q92B5yyHPWKniApXzNkqu5
         H9uw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0KqNCA8X;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736954255; x=1737559055; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=llVsVVnDrHNVTV3UOsySmCmVnYvGddtQDvQZawCq/Lg=;
        b=PXdIdeYt+pRf59CZRBg2IQcZL4kJLo0k5MWwiqxViI3RAXGm1tkPx/VCQX/IY4kqOH
         +V4u1op6B5h+O873jSbv7J87qGeQMzBGzmZzmoGRTqEXJIqxDj46efkwSeq1KF00BXu9
         AX4GZpyuk8PJiSHjDGd6HE/dcbbLxNwdtVpi220Jb2xYyL0UENP06yBKg1abP7rXlyW5
         LexQW1U0wgyyBVWfXi/OXDnBjllEnWYIX6fZizGJIHv5vE1XnubsJxONQ8nVhlr7kWhq
         L0YynwHoKACa6PKu1VKC+WzlGnb8dHxwmEPpSPoQGrFBa7L0U7TpBUR4Itjm2Cu31oUl
         mAaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736954255; x=1737559055;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=llVsVVnDrHNVTV3UOsySmCmVnYvGddtQDvQZawCq/Lg=;
        b=tQQ87oJkpUdBdviFB+D4tVEfgHyJt5pOkK/HA891FvM67eX2pFUxXoQjFIUkAzslz4
         XNHWNpbMYpUVSx9MA1uURwJv7cJWEeDD4cmOVxWsfdmixtvwS3bn5DJ3LYFuPZFHLdWH
         g3IuU6c5MW3NyEEGegZyUZ0XexQbBxMNgeEa6Xru5vV0FFZ5WmvBmUt+JpHWh2gH1o3C
         T5A8vTL4MZy0/7PCIwBo9GUyrK13BdHu4aLX3HCtjvurNUehMehyjmjh/fi3eS7bOp8w
         n8uS8F92vOSn1WIBqRf5mrk8g3EhNV6tCgq4/ohsKVWt9uqKEyaOQwZuZuCpYS+BCdaD
         Iuuw==
X-Forwarded-Encrypted: i=2; AJvYcCUvDbG97zuEhvjMqD1IuHnjhs73y2S1RNwyXUSuYXlclmz7MjzbjLcuSq0EVfz4EDqSYpblLA==@lfdr.de
X-Gm-Message-State: AOJu0Yy1+0XhtylwC11DY1/wFWMD4oKlTDB79rIgMRG8Dew8poVzD1vC
	qC+bEbx3/zQnqunelzGyKGywfM/lRIgRcwKuwyemn7pjTSnVCsjh
X-Google-Smtp-Source: AGHT+IGfPq/pJZV8gh684qhfxO39NIrhKpdKVDpqqP7jEOu7YvyWPTD3r46EwDLbjoBZfscT3lIJdQ==
X-Received: by 2002:a05:6214:4111:b0:6d8:8416:9c54 with SMTP id 6a1803df08f44-6df9b1ed60bmr530493616d6.16.1736954255213;
        Wed, 15 Jan 2025 07:17:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:9e91:0:b0:6cb:d4f7:64e0 with SMTP id 6a1803df08f44-6dfa37d106fls47652016d6.2.-pod-prod-09-us;
 Wed, 15 Jan 2025 07:17:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWFS72MVD5u5KT4f3q6FCysrmBI6HWegFsbE0ZBlANt09PARRnTYwFotDWs4Rl/xf6Su6zC1bICMCo=@googlegroups.com
X-Received: by 2002:a05:6102:5128:b0:4b1:1565:f4f1 with SMTP id ada2fe7eead31-4b3d0f619abmr28700191137.3.1736954254363;
        Wed, 15 Jan 2025 07:17:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736954254; cv=none;
        d=google.com; s=arc-20240605;
        b=hcXkaEFhwmeVtFEcX8AQVsYOw1PFrzCyYa9YClqGc3EmUkeXSVQyL+yYq5jRLy8B7G
         fQEFdrtJrf4beYlf8m8bBp31AwpOdiyGz77Snwp6M8moaa1hrwX27/Fsi6wKkpzdHdMa
         6YGUb7xhyxfd6hZXAP50gb8Ax5uX4lsxEAswJ3K3R2yUp6w0+8eAO3yYh+XfJrv7mT1S
         ycI8roPE/UU9ebMzgq7lCK4tKDQ/2rhLT6q4eFNv+CL6OyKIUrgL+s2tt5lsAwFHSxW4
         TuA4JkWvRZsut9FW3FE7fj+8J2765PMwajimxQSk4vnntl+0qur1iSDuepdDnLJl9ZHx
         w7iA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=A7WzHPt/cWpfOHApvRgjD4QZNtPcP64L7GIPpO/klVU=;
        fh=fj0+kU0e/DKf/ERVPrk6vPY0cwToPRAuQW3jpI1i/sY=;
        b=D4g4GfOPV5OfZyYnG1szkFWcOvKLGypatgonDFTJteg5MhxvsVBt7I3Gc2e0yBEZlj
         dA4NnILB2ihJ67akLrQVu/Pewr6j5CYVdLw8C7BJP7w9Qx3kPZBn9oL+LUSClZJkChRZ
         wgf7AQO7hvxUXzd1U2lww9fLvBn9RQMdetGJNV909QxmWKoVhpRddRxlf0xWDLMafHel
         qba4OY5j2kRkWKD2WKsIJW8v9N+83D3hYUdnXw+vJdU47J6/miC1+FLng+MeXNUmoenj
         rC91x9pnMJbBW8IPmxu93bprs7Sc4bBxo68tgsXYBP5t5Ot7tHNk9ePXGzSjCUdPSm2y
         3dKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0KqNCA8X;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4b6090077b3si625015137.2.2025.01.15.07.17.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2025 07:17:34 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-6d900c27af7so64345686d6.2
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2025 07:17:34 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWymoazuaiyoG11QUeBi3daRSBBnVLseTvZxIRp0RoavApyeIRWHiK2Mw3L88V+Nroir8q6Lr600pw=@googlegroups.com
X-Gm-Gg: ASbGnctYVikrqK9RsvLK//bqKoS8AtvwjR05U9AgJL8DA7ZA+iqdBn8rVagN7RsxjlV
	9U3VecTeeyZOR9/SJvazfZvV3PmW7z9Jr8YbvEoHOHPeiL8spryNvA+sr1R6eSUYSex6W
X-Received: by 2002:a05:6214:2f8e:b0:6df:ba24:2af2 with SMTP id
 6a1803df08f44-6dfba242b5bmr334969386d6.25.1736954253788; Wed, 15 Jan 2025
 07:17:33 -0800 (PST)
MIME-Version: 1.0
References: <20250114-kcov-v1-0-004294b931a2@quicinc.com> <CANpmjNPUFnxvY-dnEAv09-qB5d0LY_vmyxhb3ZPJV-T9V9Q6fg@mail.gmail.com>
 <Z4ZfzoqhrJA0jeQI@hu-jiangenj-sha.qualcomm.com>
In-Reply-To: <Z4ZfzoqhrJA0jeQI@hu-jiangenj-sha.qualcomm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 15 Jan 2025 16:16:57 +0100
X-Gm-Features: AbW1kvYef5mtP3iXS_rQEHTfWGlWNRIExvdT9bNMIFnqNFmmY6UipxblFzMqMNY
Message-ID: <CAG_fn=XFkNVkT3EmB99SdEBAwkGq3EUdM9xR4rzH_HatrJw8rQ@mail.gmail.com>
Subject: Re: [PATCH 0/7] kcov: Introduce New Unique PC|EDGE|CMP Modes
To: Joey Jiao <quic_jiangenj@quicinc.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Jonathan Corbet <corbet@lwn.net>, 
	Andrew Morton <akpm@linux-foundation.org>, Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>, 
	Christoph Lameter <cl@linux.com>, Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	workflows@vger.kernel.org, linux-doc@vger.kernel.org, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, kernel@quicinc.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=0KqNCA8X;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Jan 14, 2025 at 2:00=E2=80=AFPM Joey Jiao <quic_jiangenj@quicinc.co=
m> wrote:
>
> On Tue, Jan 14, 2025 at 11:43:08AM +0100, Marco Elver wrote:
> > On Tue, 14 Jan 2025 at 06:35, Jiao, Joey <quic_jiangenj@quicinc.com> wr=
ote:
> > >
> > > Hi,
> > >
> > > This patch series introduces new kcov unique modes:
> > > `KCOV_TRACE_UNIQ_[PC|EDGE|CMP]`, which are used to collect unique PC,=
 EDGE,
> > > CMP information.
> > >
> > > Background
> > > ----------
> > >
> > > In the current kcov implementation, when `__sanitizer_cov_trace_pc` i=
s hit,
> > > the instruction pointer (IP) is stored sequentially in an area. Users=
pace
> > > programs then read this area to record covered PCs and calculate cove=
red
> > > edges.  However, recent syzkaller runs show that many syscalls likely=
 have
> > > `pos > t->kcov_size`, leading to kcov overflow. To address this issue=
, we
> > > introduce new kcov unique modes.

Hi Joey,

Sorry for not responding earlier, I thought I'd come with a working
proposal, but it is taking a while.
You are right that kcov is prone to overflows, and we might be missing
interesting coverage because of that.

Recently we've been discussing the applicability of
-fsanitize-coverage=3Dtrace-pc-guard to this problem, and it is almost
working already.
The idea is as follows:
- -fsanitize-coverage=3Dtrace-pc-guard instruments basic blocks with
calls to `__sanitizer_cov_trace_pc_guard(u32 *guard)`, each taking a
unique 32-bit global in the __sancov_guards section;
- these globals are zero-initialized, but upon the first call to
__sanitizer_cov_trace_pc_guard() from each callsite, the corresponding
global will receive a unique consequent number;
- now we have a mapping of PCs into indices, which can we use to
deduplicate the coverage:
-- storing PCs by their index taken from *guard directly in the
user-supplied buffer (which size will not exceed several megabytes in
practice);
-- using a per-task bitmap (at most hundreds of kilobytes) to mark
visited basic blocks, and appending newly encountered PCs to the
user-supplied buffer like it's done now.

I think this approach is more promising than using hashmaps in kcov:
- direct mapping should be way faster than a hashmap (and the overhead
of index allocation is amortized, because they are persistent between
program runs);
- there cannot be collisions;
- no additional complexity from pool allocations, RCU synchronization.

The above approach will naturally break edge coverage, as there will
be no notion of a program trace anymore.
But it is still a question whether edges are helping the fuzzer, and
correctly deduplicating them may not be worth the effort.

If you don't object, I would like to finish prototyping coverage
guards for kcov before proceeding with this review.

Alex

> > > 2. [P 2-3] Introduce `KCOV_TRACE_UNIQ_EDGE` Mode:
> > >    - Save `prev_pc` to calculate edges with the current IP.
> > >    - Add unique edges to the hashmap.
> > >    - Use a lower 12-bit mask to make hash independent of module offse=
ts.

Note that on ARM64 this will be effectively using bits 11:2, so if I
am understanding correctly more than a million coverage callbacks will
be mapped into one of 1024 buckets.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXFkNVkT3EmB99SdEBAwkGq3EUdM9xR4rzH_HatrJw8rQ%40mail.gmail.com.
