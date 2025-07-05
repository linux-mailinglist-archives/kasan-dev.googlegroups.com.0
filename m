Return-Path: <kasan-dev+bncBAABBL4YU3BQMGQE4BAACAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D1CCAFA1C9
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Jul 2025 22:33:53 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-2e94cfbbbc1sf816946fac.3
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Jul 2025 13:33:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751747631; cv=pass;
        d=google.com; s=arc-20240605;
        b=VxefaIGZa0dR1SKe5XbTE8qsi2hGsoKtvbiRrQY95wruR7+KXZW+2wTUlybZlbO/36
         /bSHC+clwAQpaMjGgekOburnqhPIfhfmoiO3RRlwhs+ywP61HFwCa2UnAW05CVPGCZtd
         iHdhOgHPpFiKKcuTa+YbmBpZHIl6KpiY4Ebb626rluX9hHWYpueFRFClzxCZvawwmqS9
         uVrTi5q0KBLIjrr2KD94QBcVFI7MewOpPSgwPl3F7mWnXnanq20lGRyAO5sIlsnBmFHL
         0zgT/gp3La+YbunOhpFTcfGlbFjXcRTNMnTr9oBzjtZ91+NwraZIqHtQJTrqwO8iYITV
         XaUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-disposition
         :mime-version:message-id:subject:cc:to:from:date:dkim-signature;
        bh=4Jwgd6++rL16RKFsrdSiYKD82OTXrOHeTCcHw9RawRw=;
        fh=kRsxZdYZIuCbtcvR5rbnFE2J8/pPDsy0euyTOJuaeFM=;
        b=MbAAiQtnVQ/adIJMI5jhUaCJWTWBUWCxIwisrXKtrnPt/JjEUkhdPBQVWojpISEEyu
         8dNxCAlNZrAp7hkvHSu/2VuXleQdagTIjsmSyXW/pbzCA+KMA8/AL31HQ+C10toUZm10
         8IYxXhgxY5MCid6FUrN7UlgVRKYQRqDLnHc9wOE2rAgcL1QO0H28Vu0XRWztOJkz57Jg
         Xc0a5wqCGCXIssVnwz0c4dBfYsjZlpBqVFfuRMxiB+KsFJpow34pFeTGZPSI/ronFzWm
         GZG/+kOLqyzV6b6BC7pmnpeTOLRzujAfGf8K8HTVa6ImQvp3kjTa29ldsjHxoqig/LCl
         mboQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IpEYLkd8;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751747631; x=1752352431; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4Jwgd6++rL16RKFsrdSiYKD82OTXrOHeTCcHw9RawRw=;
        b=O6qoIIWk8rdBxL7XX6paRRZOLvOD6v2vXZ6poGMcOF0HvHOWMvl+LC/lUj3Nx1Fnbh
         ciCIKaK3fRYHofG+Xfkooq3PaPmr/WkZgjzrgAIpOhJ9zAg7NMdjMHIBQ1csZlH7vmvC
         XAtYJQtDS0JZ4e+YgH0Tk2HFXwKVUCGYszjSBt4+7oia8mhncOofD2IwuClb07fXefAC
         VR4FCy2aEgc8pLLm86pj7vuWWYsd7SioOJNTN5/HAq2EzFZiX0E1BfO5CDlov8swcHKM
         0GwMfdjLQJfWeh8wsw7oBkUJhnhdUhPSmnEOVFsGb7CD0sjEnLJ4yWgFUKeFXRDsXXjm
         15xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751747631; x=1752352431;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4Jwgd6++rL16RKFsrdSiYKD82OTXrOHeTCcHw9RawRw=;
        b=ZV4NsmSH9kv87dEYVHLHdBn5e1tUhB48KdUl6yzR/sAWUGN2np2bpCRNMDxGADK1iF
         49qeln2QmRyJIrv9O6qq2vOZoa8aNPzi7MB7hlcyT0BeEpih0RP2LextLh276FGs2l+D
         oJ3L3xpubc4QKOKcYtWpKiPsK1+C0Ew3WTBBxMQ7Z61iZn6nupLKzrLSdOGMXm0SkLGB
         mEjHB3foolPe6Avv5LiaD06yV3x+ClB4K5wo25IwsVn3ttMOv8un+lYbLEqCZSmcziaV
         phm3klZ0irhc5zkqDQ2Kd3CGBLexzn4HxDGbo0fL2G70xJP0WVpLrrvXQCN5jIQLUDBq
         x4HQ==
X-Forwarded-Encrypted: i=2; AJvYcCUDcTQN1xxf47fNfB193TOVnfIDbrWZdqp3GLvK+Mq1Pff9RM0e52AVoDj5ZjqFs8FAkZUbvQ==@lfdr.de
X-Gm-Message-State: AOJu0YxGWxfMjI4/3I2FguW2Sz/uFuoBB2Ht9Q5mlo5RPbOl2zJ3U5u1
	XgcWh4L4Sj1ZjInl9DnsTQ/sYVL7YOst7AaLaNA//73mVT6tJ03Kp4fY
X-Google-Smtp-Source: AGHT+IFRHGmvmITnEBZJdDICGkkrwJZj5cjaoBFIHGm++DJzzT0h9+JzJznwWeu6XgtUFDQqP42Xgw==
X-Received: by 2002:a05:6808:6ec6:b0:40b:999f:b2f0 with SMTP id 5614622812f47-40d27dd87b1mr2131267b6e.0.1751747631536;
        Sat, 05 Jul 2025 13:33:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeD5+lypTqbwu3oC8vGhCfXuhkZsx9zOm8+IrIUBLS55Q==
Received: by 2002:a05:6820:2303:b0:611:cba5:4626 with SMTP id
 006d021491bc7-61395926657ls375680eaf.2.-pod-prod-02-us; Sat, 05 Jul 2025
 13:33:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXZFBRC/3ga6cenXf3HlajtKKg9nT4ki4i1qOY5Vgh8CJb0b9Ld1PcBCu0NWm11dOrtF40RuoeOo+k=@googlegroups.com
X-Received: by 2002:a05:6830:2709:b0:735:22:7cad with SMTP id 46e09a7af769-73cb44e8756mr2175545a34.11.1751747630694;
        Sat, 05 Jul 2025 13:33:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751747630; cv=none;
        d=google.com; s=arc-20240605;
        b=k/RusSgr7yxxspsW7pUDMPdfBP4d1H90mkTh0PacrhxAHzOxb5J93kXo5SvOBARlts
         sf8D47WuCP9WD5lgRNxTTwA8SgP9e27dEQ+0BY3dWb+v2+IHQvSlJRTsIAkS+VDFAnYl
         tjdJVt08qO+2cb+hoZrPX2zhQAAlHTxFUlhkGj2/qo9yB4WWTGOnQQ9eSgd4azQRfDIN
         7Wln5Ajysg0wyvN9jcYiQFPPk7VEDBYagCAvsGHVy8Pwigl3igaMGl03jrURi0YZWMwK
         Gx85my7YWtITkxW1j6VGXeIMxbSvEkyLnOgkbsqCAhGUTuiswpT9PC4F/rFpsqqClOQc
         FoCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=DY1vOEDZYMCxgghd0vxj7SmrVDWY3d/f5umSVK2e/u4=;
        fh=na11TYA/k1yqmLD4g4uBrYQKv0nCmZTlq1JwXwd3Y1I=;
        b=BkHw9Lpe3CcD2gZNuw2tVzZNq8WQqQuh2deKRcVjjXDpMJw5NqKovn/ttluwIpUMO5
         9ADUppbXu/+WgC/PVq4ZH3miGGK7Kl67Ll5EZfjGkvXNfqI2CpdZgVuliG3McfBojl6G
         JZ69myx1/n2gX5vo8hqQlwVTa4TeEMtGwFwH06PqWEk7Rwu2F3XsGRDPrdZOFaYDsZ9H
         OiLoQFgthq4MlPQDYwIFKhZsotjx/HTt4qtaAG3Va2o6yHDRyWeSbgUhu1aeNT4nBzys
         2yElM0tl758FYVRpLpveeAsQFlGj8l0AZg0Dy8wwaHtyPO2td43CegN0i0JfxZwzE8G8
         BmLw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IpEYLkd8;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-73cae544e6fsi142846a34.3.2025.07.05.13.33.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Jul 2025 13:33:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id B47DF44F3F;
	Sat,  5 Jul 2025 20:33:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A74D0C4CEE7;
	Sat,  5 Jul 2025 20:33:48 +0000 (UTC)
Date: Sat, 5 Jul 2025 22:33:47 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org, 
	Kees Cook <kees@kernel.org>
Cc: Alejandro Colomar <alx@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Subject: [RFC v1 0/3] Add and use seprintf() instead of less ergonomic APIs
Message-ID: <cover.1751747518.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IpEYLkd8;       spf=pass
 (google.com: domain of alx@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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

Hi Kees,

As I anticipated in private, here's an API that we're using in the
shadow project.  I've added it in the kernel, and started replacing some
existing calls to s*printf() calls, and it was a bug mine.

I haven't even built the code yet.  I present it for discussion only at
the moment.  (Thus, RFC, not PATCH.)  Also, I've used ==NULL style for
null checks, to be more explicit, even if that's against the coding
style.  I'll change that for the actual patches, but for now during
discussion, I prefer having the explicit tests for my own readability.

The improvement seems quite obvious.  Please let me know your opinion.
I also have a few questions for the maintainers of the specific code, or
at least for someone who deeply understands it, as I found some
questionable code.  (See the individual commit messages, and code
comments for those.)

On top of that, I have a question about the functions I'm adding,
and the existing kernel snprintf(3): The standard snprintf(3)
can fail (return -1), but the kernel one doesn't seem to return <0 ever.
Should I assume that snprintf(3) doesn't fail here?  (I have a comment
in the source code of the implementation asking for that.)

What do you think?

Alejandro Colomar (3):
  vsprintf: Add [v]seprintf(), [v]stprintf()
  stacktrace, stackdepot: Add seprintf()-like variants of functions
  mm: Use seprintf() instead of less ergonomic APIs

 include/linux/stackdepot.h |  13 +++++
 include/linux/stacktrace.h |   3 +
 kernel/stacktrace.c        |  28 ++++++++++
 lib/stackdepot.c           |  12 ++++
 lib/vsprintf.c             | 109 +++++++++++++++++++++++++++++++++++++
 mm/kfence/kfence_test.c    |  24 ++++----
 mm/kmsan/kmsan_test.c      |   4 +-
 mm/mempolicy.c             |  18 +++---
 mm/page_owner.c            |  32 ++++++-----
 mm/slub.c                  |   5 +-
 10 files changed, 208 insertions(+), 40 deletions(-)

Range-diff against v0:
-:  ------------ > 1:  2d20eaf1752e vsprintf: Add [v]seprintf(), [v]stprintf()
-:  ------------ > 2:  ec2e375c2d1e stacktrace, stackdepot: Add seprintf()-like variants of functions
-:  ------------ > 3:  be193e1856aa mm: Use seprintf() instead of less ergonomic APIs
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1751747518.git.alx%40kernel.org.
