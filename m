Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEOX7LBAMGQE26WTIUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C392AEB9EB
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 16:32:54 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-2d9e7fbfedasf2395064fac.3
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 07:32:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751034770; cv=pass;
        d=google.com; s=arc-20240605;
        b=QAj4ujvItOi254d7L9i1Ky5/4cbbZcc1Wmncabi0IYyksr4Ye2NGEsQ13WhbZg8AIL
         Y5QJe1UYaL/dfFQNU8OAa9yxehS2WGbEDR8ktSdLcCwxHcCIMlCrJPTpCqLVEkeucwzJ
         2AguRytSo8o0Iiq77w0mlubw2aRrkK5G2HyUkTDbayzx/OLJNEjAVlQcb/yQyuhTFJNN
         WPnb7oS+4Y9FJIYGeNAcPhsxfqLgFPamx4Nm7qyM0Td2cqgAzVAQce9G1mJfmQ9S95Si
         BePKFnHFzg3jnWiGq+Pd+4OZYoZc3NdWawH2H8LWGiCKmZTWfOCRA1wgmLQIoKAZ6jwq
         Z80A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BuWSAqzOjfET9iMwNebOjNUg10AqU1s8yIWD8ix60hk=;
        fh=BAQL46IKGd/JfQikPVhmjKdfCfP033wBvxLlfGy6rBA=;
        b=gNJkU+Lysm8Jby+mQQjiONxhYfR215xSb6yETyVTt3D/nQcHw6aIQURUZISHTQ6lQ6
         8tO2feQL610XwBOAZST+8+kc5PO5YDEdIbR18MnaqgNGGbKpdCfsF3QrbjqSL3jZkFGU
         ueCzaENOJibbN6IOix+1WVZaTbLAD7s1gQEGU4NrokLpu1pdugCExtwJp50lSHB5YvXa
         bNJ0Rx1uz3fc8/qwyRydEQuiNN2N1vkVKSsJOWVO7DqfhDGUDNgWjzHZyE8zhNgyupoY
         D5H3yQLRAOl09NvwlnhRfVBE2qWN8WnZIE3tsKVZExnzrDYrpU2zz5pOaFAmuz+Pq09O
         yPGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xhk9Jyen;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751034770; x=1751639570; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BuWSAqzOjfET9iMwNebOjNUg10AqU1s8yIWD8ix60hk=;
        b=n043kx4hTVd5EPPYdd4uXyQmAKnejt6KwAlCAfu3pckMKgWKTYcxtekMRvnuxx42td
         Dgu8SX6sASWo9z2dst63g6QDHdXHQ0gBE933MAHw11z9u65TiYCgQGImxZPopKQCoRdp
         RxIoQRTRVncCN2A7jI/7wpw1VgsxZCBET/j7pCLvEbdf9xxRZxxLSsV28F33IbtRrEIG
         8PgGXaPUG/7fC7sn4jOOScBVlxBMz1MLj32CfVT5ujG58BKoUI9mTXXCWi1Oo7RuSsKR
         dRgVtsUEmz+jFG9ZyTV35UlOl9lvnN1VvbsdtKhaJLQrZa91gF7um/Hl/13Ve5Ck2isw
         +SNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751034770; x=1751639570;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BuWSAqzOjfET9iMwNebOjNUg10AqU1s8yIWD8ix60hk=;
        b=CfCWyRK1O2lFPIHWcLZYSgyn8QG631mDSQAn8aUiEpljkF1EAVTfdpsHqxvqGWIZhk
         bGGbVy2ec3hXyFJ/YI3bPE7imTAM9Qi4jIDnZ/iU7vwoYO99SI7wuH2hVa1FONb9Vego
         HB6JVMhfuh5HcbfvnUNBnGGq6XFZ3Kf7lcee3g/YYc089AehRmYHlRLzqMAu6IY7JLgy
         3PfjLLYq8URAZPvW14AcETXsibvQcLBGnjcpgwnkRer96217rCNn+oDs5lDwUHxwr9R9
         vjAZ0eYnXAt6ymnvkcqmfuA2qch7/G4ji0vlRlM0oIZMB/5X6FwZUFYwYE2RVMnvNXLd
         2BMg==
X-Forwarded-Encrypted: i=2; AJvYcCW5gzDkEWaGvXZTzOMDNxwFqBRZvsgZbMR0Y4y/BK9XGn/nD8FyKDH8SsV+tqKLNa8Z/rHxgA==@lfdr.de
X-Gm-Message-State: AOJu0YzNZGNpVcE7rKDUVp4MSU2UVhiFc7thcw5zG+hFM4Myb44eD3Za
	KtYlJmfPiJxkN+Zk5WhQCPU4xr1rtKVzDp9kx/TQXRn6+yWjCd/6dDHv
X-Google-Smtp-Source: AGHT+IHuL+HGZ6wsWE//oYkSxCcImlWNz/WVQnisNVM3Tb6CZj5e4m/S4yz0s1G4HbszEdazdRTMpA==
X-Received: by 2002:a05:6871:813:b0:2da:843d:e530 with SMTP id 586e51a60fabf-2efed43d937mr2287119fac.2.1751034770141;
        Fri, 27 Jun 2025 07:32:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe2x4D5cl5rIRhXqxsMhwJ6WUDlVdlo6hhRi2anuH77aQ==
Received: by 2002:a05:6871:151:b0:2da:b91c:91bd with SMTP id
 586e51a60fabf-2efcf29c689ls1198605fac.1.-pod-prod-09-us; Fri, 27 Jun 2025
 07:32:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWEwtg4uqa8JyZnZyfhOSvDzIuQ3c2QdjXfD/tQzID9bR1gpuas/hWFFhHDxn6dO98hmkRSALPFEC8=@googlegroups.com
X-Received: by 2002:a05:6870:93c5:b0:2ea:765f:da78 with SMTP id 586e51a60fabf-2efed6847f0mr2132039fac.21.1751034768307;
        Fri, 27 Jun 2025 07:32:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751034768; cv=none;
        d=google.com; s=arc-20240605;
        b=EZiDVl124Qge0/orrF4AjJW0XeDtAf1+z9kDnzphZu90SOyOxVMmsEJ61vDpJFrnUm
         R/27GZjvX6jXMEp47oMzUG8m2fJLU0LiXpU9jLro2/ai1kVWzLCFrzQX+yzJ+xtZgFeO
         rekNx6jjlPIkQWJz4Q2sJEyXFf4Aq1FFa3irv+RjfBqBr5ya0ZPtDa8smPyFZwv2xp21
         x40Tp/iOfu5wtbSudbT/MIFsx3nZZIDA55Y68GkOJn8ZQvrOhePFd1f+qr6YOIJ61W4a
         VqIg6NmzHr6JbUMDEOfCJew+h1irFEvp9+/3nrbh2z9sz2Q9Yg4L5qWC5guOoPKOJLRW
         eojA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=JRHcsCTsHBJJ/xPjm9td2b9ZVcHsn4qi0sxiMajgt+I=;
        fh=C+nVG4mJzMsTHmfvxoN0V/Hlaym3GLkBzfIw9woRYJM=;
        b=ctuCfp+egbkYN1tu9JlIKSKgQ3TVD5askqlKOm9VNydOKhX2cKZSTZnXdkv5Np+j/o
         MqZdXbmKhNOa5FjDa9DOuvHPLd7gBxDoq8oXO4y6NH8ZzdXPAskJUl7mwGiVY91ojWaX
         ueIY8cyXCh5siNw0dVJJyQCXUGBqCkgvChhHlm/SNtmtP+LY/XcsxQ6F05JLmiNw1aat
         cTHBunpx/EhdopHGolsEr0nJNhK+mLKQvoNs3lysWTdWocJnPbQsdA5RuJMJYrb0DjgQ
         oHCMHYsHLLOHVacZdTTkRe52BFKS0qlnsb35QaiYxzIomxU8266XWH7SWvnwFwgu1Zrs
         1c6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xhk9Jyen;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2efd4c2626fsi191869fac.0.2025.06.27.07.32.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Jun 2025 07:32:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id 6a1803df08f44-6faf66905baso32597486d6.2
        for <kasan-dev@googlegroups.com>; Fri, 27 Jun 2025 07:32:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXMHeevNu+I7ZkB8ajJ3Z4UsqVgE2VJcU+P8cJXeeknXDZvbOMfWDMQa+Yt9XqKmYLFPme24askPDs=@googlegroups.com
X-Gm-Gg: ASbGncvVK503+U2YnrBILpCL1XX+5OT6rgcoUKdBvK9FCNKwFfVUOklf9WV3gegsoKY
	sgA7xJ8VqewPkgge+BK7PHwVtURcVpYGtY38kM3IYefNnzf3EINNrMdXVFzMQ5BbHPJOktha6Bn
	SKugpCWCubcIh5e4naUXraAiFA4QoQ84kRXCkwpMaYakztCWs1MyuVvJIntTfFrE7xvq2kmQqeb
	w==
X-Received: by 2002:a05:6214:3c9e:b0:6fb:59de:f8ab with SMTP id
 6a1803df08f44-70002b09787mr64657346d6.10.1751034767488; Fri, 27 Jun 2025
 07:32:47 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-7-glider@google.com>
 <20250627081146.GR1613200@noisy.programming.kicks-ass.net> <CAG_fn=UrOBF=hQ5y6VN9VuA67GeVOyaaWtrnaSLz4TnC7u1fiw@mail.gmail.com>
In-Reply-To: <CAG_fn=UrOBF=hQ5y6VN9VuA67GeVOyaaWtrnaSLz4TnC7u1fiw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 Jun 2025 16:32:11 +0200
X-Gm-Features: Ac12FXyNdmWFSSJKEPyXOJOFO_SgvNyJtoRQ-REuaA1XlHVfOaH0P5mnZZsSDRc
Message-ID: <CAG_fn=W6hXNnYLZpHN5Ein_iZ-tqJDFZWXaQm29eUf7xQoU=Lg@mail.gmail.com>
Subject: Re: [PATCH v2 06/11] kcov: x86: introduce CONFIG_KCOV_UNIQUE
To: Peter Zijlstra <peterz@infradead.org>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xhk9Jyen;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f31 as
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

On Fri, Jun 27, 2025 at 4:24=E2=80=AFPM Alexander Potapenko <glider@google.=
com> wrote:
>
> On Fri, Jun 27, 2025 at 10:11=E2=80=AFAM Peter Zijlstra <peterz@infradead=
.org> wrote:
> >
> > On Thu, Jun 26, 2025 at 03:41:53PM +0200, Alexander Potapenko wrote:
> > > The new config switches coverage instrumentation to using
> > >   __sanitizer_cov_trace_pc_guard(u32 *guard)
> > > instead of
> > >   __sanitizer_cov_trace_pc(void)
> > >
> > > This relies on Clang's -fsanitize-coverage=3Dtrace-pc-guard flag [1].
> > >
> > > Each callback receives a unique 32-bit guard variable residing in the
> > > __sancov_guards section. Those guards can be used by kcov to deduplic=
ate
> > > the coverage on the fly.
> >
> > This sounds like a *LOT* of data; how big is this for a typical kernel
> > build?
>
> I have a 1.6Gb sized vmlinux, which has a .text section of 176Mb.
> There are 1809419 calls to __sanitizer_cov_trace_pc_guard, and the
> __sancov_guards section has a size of 6Mb, which are only allocated at
> runtime.

Also note that most of this array will be containing zeroes.
The high coverage watermark across all syzbot instances is below 900K
coverage points: https://syzkaller.appspot.com/upstream
But that is coverage aggregated from multiple runs of the same kernel binar=
y.
CONFIG_KCOV_UNIQUE will be only initializing the guards for the code
that was executed during a single run (<=3D 1 hour), and only when
coverage collection was enabled for the current process, so background
tasks won't be polluting them.

>
> If we take a vmlinux image from syzbot (e.g.
> https://storage.googleapis.com/syzbot-assets/dadedf20b2e3/vmlinux-67a9938=
6.xz),
> its .text section is 166Mb, and there are 1893023 calls to
> __sanitizer_cov_trace_pc, which will translate to exactly the same
> number of __sanitizer_cov_trace_pc_guard, if we apply the unique
> coverage instrumentation.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DW6hXNnYLZpHN5Ein_iZ-tqJDFZWXaQm29eUf7xQoU%3DLg%40mail.gmail.com.
