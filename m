Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTGITXCAMGQE6O6OD2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D81DB13A0A
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 13:51:42 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-3b78a034d25sf748207f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 04:51:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753703501; cv=pass;
        d=google.com; s=arc-20240605;
        b=KBpifZmfIFNSrlrxXla32GPBnRQZjQqYuPIX/6hVyD/Ttul4rDipZEtW3mj3/SUdl8
         E9W3aXl9g114JzkTqfNwa89Wo3fmhK6Dl6ZUsnVApZmoYlsRYvyk3a9tsMuYFq0wJZNh
         Y88ti/LYJA7pI4FL76ruS43vIkScS0gHvC0DAEOBk90OPNwJskt0H7TmYXp+tu5U7jpZ
         1msl8dPXd7wlx3MGwHbvlQybG6twc/qMadyzw5FlHP6g5VjowcxDN6gJEYsIx+zhydKH
         RBKSg63KZODgojXF6H0K3G5RmZhUWQyWqaOU35p2nzo10iFaVfP4Nokg6g2B4k7r1alE
         WboQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=1oOns9po82Im/UsexYqh8ii5Tcb+J9n1E4+C7F2BUsc=;
        fh=zKASMGaJNqSKD7Aut2leF2jQ4y7qNcdjzUZhCwFlc74=;
        b=IpfRwQ2lSNoaPZOYi6EV7iAkxYtn72vOCudoDylVduOmE3bKarLzNj7VwoZIq+zb3S
         xqUXJCHkvNrw0cWT8XgYsZMRwlE43YnjGFOT62G7mSYMiE0N3pTrGm1o6tFFoAuXPaF8
         HiwvIuStnnlSQtYuZC4DuXvBCJDBoAIYP9QYvKFWGLoDZnUUu6Dh5VTAqjGAq1ZSfF/A
         SFKTpiuZx2AF4sbrC0lCLFSITXeWcXWmB56pK4nE4LLoWBmAxykH6DSYImlCBy0b88j8
         VoB9WKuPA+wJUPDmo5JQwzJTsrYA8mlvDdHbRzUUQkY3i0Ty0deN17tPApKPtN3KKwGG
         dBZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=glFAPL+V;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753703501; x=1754308301; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=1oOns9po82Im/UsexYqh8ii5Tcb+J9n1E4+C7F2BUsc=;
        b=uBqXw9ocnD+cdyD2LqSM8cdSjvUfXke33xW42V1I3Mw2RZTvg9LAYaUttdN/LSNWXE
         fNteT3xjQdAmhlP+nkigcRaUgeBBFlgDBbLIR61d9KdV8qIasDolieyvBZgkoFnVwwXY
         7KA9qJW+604njangyq4t5SgtYRGweu3uyP3mvvjI3+oF9kTjNgTgN540Fis4PeWJOh9J
         DkdQiq9DpBLqxKEslheSim5nl2ZxYFDtFn90khG02zG/NqSWCsMJh7QdcYAmsdZ5IWnk
         Fy+pXTfvwvRQMGpc19SgTWpnaYQQP4Nxb4hxDamnvaEPsAl4G34QCRZjVXehjho5lWEs
         wXFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753703501; x=1754308301;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1oOns9po82Im/UsexYqh8ii5Tcb+J9n1E4+C7F2BUsc=;
        b=IloXyrqk/KIHVv0WapqbQvFHWSHTR6FyxvhOFNoFvP7Srw1vNX3Ki5R6WY+8eS14DB
         G9aMWZ81eHbYBY+I+qzWEJgVwutwJ1X7thuAbhp78ppM+8RCQzYsKeRZcvCiXIj6SwbO
         lJevvijR693xSGZ/APe6v7wflJvRfcKLXM6BFGTAKXnihXWMsDJ1oKfXnz5kuZ8B6YRe
         Rp9qTJavUxCVrcmkPhA404Y3Xg+v6wYOb/rI+Tb/YhzuR3cYVsmfDaMt7GCouCPkU3SR
         GJhm/PQYCF17ZSAv26/adB3SzjNiqaXyhZVz/3GdTa5hWxCoNwYk9diybfJdNUKEnQzL
         JQNQ==
X-Forwarded-Encrypted: i=2; AJvYcCWOS0IVm0Z/SQQovMZYC7I1CUFktBOt6QmLeH6THNuL1v9CX5E4+B6Kugexnw1NXKMI1Jf8og==@lfdr.de
X-Gm-Message-State: AOJu0YyaRTJ3jFErz4PU6DeIqdQnAE68K/QYDpiNckYwI2dnaAKzMa+T
	FfmVMLyvdY7v73bSidQCoOvpo04lxFt3nH/oPMvUQv4pW1uCxUlQLurr
X-Google-Smtp-Source: AGHT+IGky1/4WWwNHdmUf1W+exJozVMVlbtM8tFhKuXGi1izuzbWoe7lR4ReNtqcmMvoNBvI/HQ2bg==
X-Received: by 2002:a05:6000:250f:b0:3b7:737b:4067 with SMTP id ffacd0b85a97d-3b7765e58b0mr7506256f8f.4.1753703501177;
        Mon, 28 Jul 2025 04:51:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfyHiJRyTHnfVNruC0GSW7HYqAC4qfXGjfnoBuxugekmQ==
Received: by 2002:a05:600c:6387:b0:455:1744:2c98 with SMTP id
 5b1f17b1804b1-4586e627c50ls22321935e9.1.-pod-prod-02-eu; Mon, 28 Jul 2025
 04:51:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUstXq0aASxUQW1s7QHyGqGOgY1/OJ27qjosiRp+nxFmWHPoEB5g6e/rubTyYAJPjOjchL+Pe11cIc=@googlegroups.com
X-Received: by 2002:a05:6000:4c8:b0:3b7:83c0:a9ab with SMTP id ffacd0b85a97d-3b783c0b042mr3192394f8f.55.1753703498115;
        Mon, 28 Jul 2025 04:51:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753703498; cv=none;
        d=google.com; s=arc-20240605;
        b=G30/IYbqbMGvmzMi53wWaRKAGwCP0bngddD2b8f1cOteZ0vDT2A4+zx322ozujYpwj
         akop79fUZ9r/KzRls0SnzfOut4vc0HQqCmbt8T0aTB5H+tO/h74aLvJ09BcHD9zctnLP
         lYcE5ia3nLshIsM2dZkvp+AxuidbmORQlgiVPscrE43wHVgRjd23MZPujxwZ7kp3tfDh
         E6ThC3mt2tRLeFFu24zPUTTqiTK4w/4iSKYubl48O3xNfClH73sQ9/6rKFd3zFgpVYnt
         1i5aDZZXfZXYz4RHgk8WjBPQ1IIKI0JQeoSp+E8jvwh8liLvbDT5sjdpjav1DCJHMK94
         eB4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=l56t6uPmq3cSkV0C7DGr6+BsykVsDYraodDtRGzpDuE=;
        fh=CNo2pY4U3KuUS5zcLuiM747I/41AxCoDo6HMOchYa8M=;
        b=ksY/PXIg3wfp5zX2bGE8U47aLTbZ+iW2bISjy6c729WWQFPa2E9/dctF0MMawqgCg4
         F6542knqe6tUgeA33j+IuIb0ZxIkc5nvp1skN7Ur5ZNpOjuv6zVFhDbI+jwPX8/srKEF
         xus6N+9O9hNKRWTt/vr0EKIM9eqtsdLMbYglYdjxkTNFKTAAYLBeRz1bXvzL9wpOkFXE
         1HDNA+EvOTMzdTk7O+ZJ/C+mKCFf5geV+3N4Woa6Qx9ujXX5r038jCJKpj35sHb83ZIV
         Kwwt7rFRz2EWWTf0OZRgu+JHRJVWzh6Q0wZPp5w5gKxFVAMWBZuQrWw6fuHReISfZqsk
         WTqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=glFAPL+V;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b7845511besi105892f8f.8.2025.07.28.04.51.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 04:51:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-3b7886bee77so947100f8f.0
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 04:51:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVoPm1bZJ7UzbE2a2jvvcNpm6E2FT9lF2mvTJR0fR5pc0UvOwUZxjY6I7ITPeRP9zGPXDI8XTPxU6o=@googlegroups.com
X-Gm-Gg: ASbGncvj+rU6SKe30KUDWSB+zqbiESNJO5fhwPBbj1HyipmCkYpzukUrEk5cNU6/mTG
	5cKunrA1zPf8dL0rKAAhR8AuQ0Bj/qqwssJyP67KzGGctnNtag5cvukXcFNoW9pMUQeX/s7rYGl
	k3Wm+ssi018myZTufcrn9fyyaTTfvNjrMB6roH4dCxoPstnJGpK7e+qGlth7dAUxaMTBC3WNKS9
	/xnw7CjKgCvs7cdHWlpZTX/9fyoXnqZ1lR9MzqhGLnahBc7ANOL+9nXPWjXO5aC9oJPhu9cvpY0
	wtFWrTkoiXzGc4LkFokbQUG5/VVIJi4XTcOFdfKF23Ngo0WCKM3HYFPzfCerFF/1II0RnxDhqk5
	+Gz6j6j7zNc36pYQixg1DEshY4KC/TikiAKaX3r6k7E/OIFVovbBHqWBoq4wT8lQiDhP38g==
X-Received: by 2002:a05:6000:2dca:b0:3a4:f7e6:2b29 with SMTP id ffacd0b85a97d-3b7765e5877mr9262604f8f.5.1753703497322;
        Mon, 28 Jul 2025 04:51:37 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:2834:9:4524:5552:e4f3:8548])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-4587ac78af2sm96075685e9.33.2025.07.28.04.51.36
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Jul 2025 04:51:36 -0700 (PDT)
Date: Mon, 28 Jul 2025 13:51:30 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jogi Dishank <jogidishank503@gmail.com>
Cc: dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, rathod.darshan.0896@gmail.com
Subject: Re: [PATCH] kcsan: clean up redundant empty macro arguments in
 atomic ops.
Message-ID: <aIdkQixt-tfT7IPw@elver.google.com>
References: <20250728104327.48469-1-jogidishank503@gmail.com>
 <CANpmjNN-xAqYrPUoC5Vka=uohtJzhOfJsD9hhqhPJzQGt=CHGQ@mail.gmail.com>
 <CADorM--0n1zeT8jxT3LtjmqrP5Cp1g-hFS=oz_12SptjZwRWtw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CADorM--0n1zeT8jxT3LtjmqrP5Cp1g-hFS=oz_12SptjZwRWtw@mail.gmail.com>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=glFAPL+V;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::435 as
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

On Mon, Jul 28, 2025 at 05:11PM +0530, Jogi Dishank wrote:
> Yes, I build the kernel with the change.
> And it's build without any error.

You have to set CONFIG_KCSAN=y

kernel/kcsan/core.c:1270:1: error: too few arguments provided to function-like macro invocation
 1270 | DEFINE_TSAN_ATOMIC_OPS(8);
      | ^
kernel/kcsan/core.c:1261:40: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
      |                                               ^
kernel/kcsan/core.c:1193:9: note: macro 'DEFINE_TSAN_ATOMIC_RMW' defined here
 1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
      |         ^
kernel/kcsan/core.c:1270:1: error: type specifier missing, defaults to 'int'; ISO C99 and later do not support implicit int [-Wimplicit-int]
 1270 | DEFINE_TSAN_ATOMIC_OPS(8);
      | ^
kernel/kcsan/core.c:1261:2: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
      |         ^
kernel/kcsan/core.c:1270:1: error: too few arguments provided to function-like macro invocation
kernel/kcsan/core.c:1262:40: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
      |                                               ^
kernel/kcsan/core.c:1193:9: note: macro 'DEFINE_TSAN_ATOMIC_RMW' defined here
 1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
      |         ^
kernel/kcsan/core.c:1270:1: error: type specifier missing, defaults to 'int'; ISO C99 and later do not support implicit int [-Wimplicit-int]
 1270 | DEFINE_TSAN_ATOMIC_OPS(8);
      | ^
kernel/kcsan/core.c:1262:2: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
      |         ^
kernel/kcsan/core.c:1270:1: error: too few arguments provided to function-like macro invocation
kernel/kcsan/core.c:1263:39: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
      |                                              ^
kernel/kcsan/core.c:1193:9: note: macro 'DEFINE_TSAN_ATOMIC_RMW' defined here
 1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
      |         ^
kernel/kcsan/core.c:1270:1: error: type specifier missing, defaults to 'int'; ISO C99 and later do not support implicit int [-Wimplicit-int]
 1270 | DEFINE_TSAN_ATOMIC_OPS(8);
      | ^
kernel/kcsan/core.c:1263:2: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
      |         ^
kernel/kcsan/core.c:1271:1: error: too few arguments provided to function-like macro invocation
 1271 | DEFINE_TSAN_ATOMIC_OPS(16);
      | ^
kernel/kcsan/core.c:1261:40: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
      |                                               ^
kernel/kcsan/core.c:1193:9: note: macro 'DEFINE_TSAN_ATOMIC_RMW' defined here
 1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
      |         ^
kernel/kcsan/core.c:1271:1: error: type specifier missing, defaults to 'int'; ISO C99 and later do not support implicit int [-Wimplicit-int]
 1271 | DEFINE_TSAN_ATOMIC_OPS(16);
      | ^
kernel/kcsan/core.c:1261:2: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
      |         ^
kernel/kcsan/core.c:1271:1: error: too few arguments provided to function-like macro invocation
kernel/kcsan/core.c:1262:40: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
      |                                               ^
kernel/kcsan/core.c:1193:9: note: macro 'DEFINE_TSAN_ATOMIC_RMW' defined here
 1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
      |         ^
kernel/kcsan/core.c:1271:1: error: type specifier missing, defaults to 'int'; ISO C99 and later do not support implicit int [-Wimplicit-int]
 1271 | DEFINE_TSAN_ATOMIC_OPS(16);
      | ^
kernel/kcsan/core.c:1262:2: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
      |         ^
kernel/kcsan/core.c:1271:1: error: too few arguments provided to function-like macro invocation
kernel/kcsan/core.c:1263:39: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
      |                                              ^
kernel/kcsan/core.c:1193:9: note: macro 'DEFINE_TSAN_ATOMIC_RMW' defined here
 1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
      |         ^
kernel/kcsan/core.c:1271:1: error: type specifier missing, defaults to 'int'; ISO C99 and later do not support implicit int [-Wimplicit-int]
 1271 | DEFINE_TSAN_ATOMIC_OPS(16);
      | ^
kernel/kcsan/core.c:1263:2: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
      |         ^
  CC      lib/crypto/mpi/mpi-cmp.o
kernel/kcsan/core.c:1272:1: error: too few arguments provided to function-like macro invocation
 1272 | DEFINE_TSAN_ATOMIC_OPS(32);
      | ^
kernel/kcsan/core.c:1261:40: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
      |                                               ^
kernel/kcsan/core.c:1193:9: note: macro 'DEFINE_TSAN_ATOMIC_RMW' defined here
 1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
      |         ^
kernel/kcsan/core.c:1272:1: error: type specifier missing, defaults to 'int'; ISO C99 and later do not support implicit int [-Wimplicit-int]
 1272 | DEFINE_TSAN_ATOMIC_OPS(32);
      | ^
kernel/kcsan/core.c:1261:2: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
      |         ^
kernel/kcsan/core.c:1272:1: error: too few arguments provided to function-like macro invocation
kernel/kcsan/core.c:1262:40: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
      |                                               ^
kernel/kcsan/core.c:1193:9: note: macro 'DEFINE_TSAN_ATOMIC_RMW' defined here
 1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
      |         ^
kernel/kcsan/core.c:1272:1: error: type specifier missing, defaults to 'int'; ISO C99 and later do not support implicit int [-Wimplicit-int]
 1272 | DEFINE_TSAN_ATOMIC_OPS(32);
      | ^
kernel/kcsan/core.c:1262:2: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1262 |         DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);                                                 \
      |         ^
kernel/kcsan/core.c:1272:1: error: too few arguments provided to function-like macro invocation
kernel/kcsan/core.c:1263:39: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
      |                                              ^
kernel/kcsan/core.c:1193:9: note: macro 'DEFINE_TSAN_ATOMIC_RMW' defined here
 1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
      |         ^
kernel/kcsan/core.c:1272:1: error: type specifier missing, defaults to 'int'; ISO C99 and later do not support implicit int [-Wimplicit-int]
 1272 | DEFINE_TSAN_ATOMIC_OPS(32);
      | ^
kernel/kcsan/core.c:1263:2: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1263 |         DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);                                                  \
      |         ^
kernel/kcsan/core.c:1274:1: error: too few arguments provided to function-like macro invocation
 1274 | DEFINE_TSAN_ATOMIC_OPS(64);
      | ^
kernel/kcsan/core.c:1261:40: note: expanded from macro 'DEFINE_TSAN_ATOMIC_OPS'
 1261 |         DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);                                                 \
      |                                               ^
kernel/kcsan/core.c:1193:9: note: macro 'DEFINE_TSAN_ATOMIC_RMW' defined here
 1193 | #define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
      |         ^
fatal error: too many errors emitted, stopping now [-ferror-limit=]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aIdkQixt-tfT7IPw%40elver.google.com.
