Return-Path: <kasan-dev+bncBD55D5XYUAJBB5FYUSWQMGQE5NUQA7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id DCEA783194B
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 13:41:25 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-429be9198bbsf142061cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 04:41:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705581685; cv=pass;
        d=google.com; s=arc-20160816;
        b=tUarTyuYAtewJzmvEk+6yN+v1WKCyeQUXylmRPb7Jlg0yw8PP2FR+YdybtuSEm0Fj+
         dqzJhb+tv0JLkA6E6fWYnZUfQLUjT7ZdWnDqbCpl/xjW+jFIdruU8dBqXqSRdUaUFUtM
         zqRG9SRHhAiAhO2X175DcnoNdN1DkjcURcXyAWytRJ8nKQlDQQlhnUC1ahfoX0ypgsg9
         OjKwwGIc56kLkbPrV93gkbgzoek655bXuaf2iQBLdVnUUiR8zYUdA/bjc1gYM98LdUuJ
         V2IusVp9xjuxthYu87A0n0Oq0/FIk4HUVNlZ6/Kxlo9xhoiw374dlFP0YVH7iAZ38RPh
         7zRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=tPFYuYIpodgJjdHXL0tw4iEiFociiRIxSdtXyRWgu98=;
        fh=4PS0TUR1kckMCap9/Z2+yRxeTQGnq78XsODFWEbTt8k=;
        b=wtS3qTq9P5YZi1E0uoEFR04bDiMbk66jOnVTV6t5MZSwwawPf+yOtsw6nXMvRZ+In3
         EW51RUNK9yFWlmF6Dyg70EPDhexGgbRVXDzQ5fVYcs5VkN88I9gfu8hGqlh52sKPHDcW
         N7bKOxxNd75U1gYw/e11YHG3J/nLLC+tO1hbbmP4D0/DqwQ6TdfqbzZyY2qlPXLKtuYh
         17I9m+txCXBkz8rHCNZs+WPitgTprXuQpEzRkoULPCJ76H1bY4brW24PssvJ53KAaGGT
         Rqx8nv8R0xkUTcF8jnH6sR4tmP3fWGLtMjNx3Bc0GoiU6hhHfMzKp0q4UmkrexOwkeOR
         9S6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=ZpC231ch;
       spf=pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705581685; x=1706186485; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tPFYuYIpodgJjdHXL0tw4iEiFociiRIxSdtXyRWgu98=;
        b=Ixoj1liLXj1eCqqEATbm67KpbfnvqsJN2UcujByax1tbNoipmD9/oOol5+QNPZ65BX
         16TAt4/hO8q/foRK3jOq6ruCrBu71nGZMu91G5DkJQn+G37h1g43/nzMKqH6lnSot9Ws
         9Ai/8owrqHldq88UahibbvJHJ0NMT8T2kVnViIRO2wivXs7tCdNIlYKk2kD399w73a++
         5ShwUiSCcRgr25mdZRyhR3q1iXrQQ5+Bz5J7/505klcC1bejuR0qqPMRZXbA8DAhQzIO
         FMYkuf3/dlV4IfYJQDjq3f02XNqE0T72Lvc8NKOg2LeAsuTV6UkuOs0AXzVMsM5UV+dI
         H5Jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705581685; x=1706186485;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tPFYuYIpodgJjdHXL0tw4iEiFociiRIxSdtXyRWgu98=;
        b=w7oSS7H567/qImySRoLhcbMfOccOIhSFb3HNXYLVEhEutgTnL9CrdRJBCCvihJaUbe
         pyF3bqOClHZfuH/HeFURnrRyp2xAJREidgJuqqpp4fbVvmlBLIh8MmRTAGHnWvW0TeBR
         ICW5hBtRPvuIUzdGRWyx+UW4eJANcBm4EStHNiFQQ1QzDzrfbzz7jrZSLRbLNwjUO73m
         yog/ZBTZYFj1yQtv72UQ3LvEZhXtwV0TMxZgK8xzNGuIx1KIM8cppdu9WugsgsR+jm8b
         OZEyLakA9NOFOInQVi+88OxygYVaRi0bER9kHVRltZx39HMpOLvk4qmoz6hWLA+kfZJQ
         BvfA==
X-Gm-Message-State: AOJu0Yx3rY/TZL//QlYxcubLohGLCSUC87cIcXWKw9cy2VMhq/F/aRZl
	vergfWHHHFbz0o3HXxoG0OmIHmmB7HfRHg/jJCryGQ05qvKH4eio
X-Google-Smtp-Source: AGHT+IFN+xF/3xpoJOqpQSvpKhsMQPOKzszRUrJlh3v8/6SfRzrVBxboSXE/nmqq5yxyw94IzALovw==
X-Received: by 2002:a05:622a:4a11:b0:429:ca07:1c8 with SMTP id fv17-20020a05622a4a1100b00429ca0701c8mr92753qtb.23.1705581684866;
        Thu, 18 Jan 2024 04:41:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d8d5:0:b0:dc2:2438:21ff with SMTP id p204-20020a25d8d5000000b00dc2243821ffls1595023ybg.2.-pod-prod-07-us;
 Thu, 18 Jan 2024 04:41:23 -0800 (PST)
X-Received: by 2002:a25:b11a:0:b0:dc2:5679:ebab with SMTP id g26-20020a25b11a000000b00dc25679ebabmr482909ybj.110.1705581683591;
        Thu, 18 Jan 2024 04:41:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705581683; cv=none;
        d=google.com; s=arc-20160816;
        b=EK9RzzxkioydM3FBVzVIa8NBSWRQcrPniaKc75JfbHDE4yNdLNSfycMe0BpKEhdAXw
         e4SjSD3Kspm3HBZM7LTbtEUp+nbK4ctIZ6vGkOZz1jQAh+Xb0OYUYyaiCJVWekgsob+G
         orqu2InoMeFO6zZ2K4ET/lkicb4R+0M+x4AgB1PumGn+xQwajgL3nK1GeikbcqSTar9q
         r5N2KdJ4rgBSXsiEclThNo+0IEWXxC4C6TPh1yoQkJ/EjBTSc2ggr9ahZVWb/Ia5M5p7
         ukF1+Vbsq2yMqfqCQS0zEIS4EIXrbnreuKu3Lc7WWjmxrVcg4f/Uj0LMnhts74EwTCo6
         PD6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=5Sj5Fokpddg/A5UFLhYpTg8LTiDQa2v0otIwtPzw540=;
        fh=4PS0TUR1kckMCap9/Z2+yRxeTQGnq78XsODFWEbTt8k=;
        b=o54/nfoRV6cZDMrIOr16j9mXpxu8YjuoUYHL1c/YguUZtXePKciQOo0HEORZ2sSjWw
         Bi+QISQ8GIN6PCPGdFvNT0KK0mmlXvgN0z2D6biN1NxkzgjchtXXr3jXGZg06S6DfXvW
         wMxZ2qGia0yEOfx/vbAJs4Vr2eZB3dRzqiZZdgOgjSp7+2WSpYIC+KFKEklcNZaN9Mc2
         heL0DLBLzTk8c8RujNg/SAkNPklj2EwacXOTduV4AQhYnBG72sIRdmighRE4D42cA5GD
         qDJ03kmnwd5mvL5pFcQ5EA+lS1BHNNEnrkyII9Lq6Mwkz/xLscg4a3r685UmjKXCiaHb
         AarQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=ZpC231ch;
       spf=pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id j126-20020a25d284000000b00dc25753beacsi89251ybg.0.2024.01.18.04.41.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jan 2024 04:41:23 -0800 (PST)
Received-SPF: pass (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-6db82a57c50so3093510b3a.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Jan 2024 04:41:23 -0800 (PST)
X-Received: by 2002:a05:6a00:2d81:b0:6db:8b3a:ec0d with SMTP id fb1-20020a056a002d8100b006db8b3aec0dmr737515pfb.9.1705581683085;
        Thu, 18 Jan 2024 04:41:23 -0800 (PST)
Received: from GQ6QX3JCW2.bytedance.net ([203.208.189.13])
        by smtp.gmail.com with ESMTPSA id y17-20020a056a00191100b006d977f70cd5sm3199744pfi.23.2024.01.18.04.41.19
        (version=TLS1_3 cipher=TLS_CHACHA20_POLY1305_SHA256 bits=256/256);
        Thu, 18 Jan 2024 04:41:22 -0800 (PST)
From: "lizhe.67 via kasan-dev" <kasan-dev@googlegroups.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	lizefan.x@bytedance.com,
	lizhe.67@bytedance.com
Subject: [RFC 0/2] kasan: introduce mem track feature
Date: Thu, 18 Jan 2024 20:41:07 +0800
Message-ID: <20240118124109.37324-1-lizhe.67@bytedance.com>
X-Mailer: git-send-email 2.43.0
MIME-Version: 1.0
X-Original-Sender: lizhe.67@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=ZpC231ch;       spf=pass
 (google.com: domain of lizhe.67@bytedance.com designates 2607:f8b0:4864:20::42f
 as permitted sender) smtp.mailfrom=lizhe.67@bytedance.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: lizhe.67@bytedance.com
Reply-To: lizhe.67@bytedance.com
Content-Type: text/plain; charset="UTF-8"
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

From: Li Zhe <lizhe.67@bytedance.com>

1. Problem
==========
KASAN is a tools for detecting memory bugs like out-of-bounds and
use-after-free. In Generic KASAN mode, it use shadow memory to record
the accessible information of the memory. After we allocate a memory
from kernel, the shadow memory corresponding to this memory will be
marked as accessible.
In our daily development, memory problems often occur. If a task
accidentally modifies memory that does not belong to itself but has
been allocated, some strange phenomena may occur. This kind of problem
brings a lot of trouble to our development, and unluckily, this kind of
problem cannot be captured by KASAN. This is because as long as the
accessible information in shadow memory shows that the corresponding
memory can be accessed, KASAN considers the memory access to be legal.

2. Solution
===========
We solve this problem by introducing mem track feature base on KASAN
with Generic KASAN mode. In the current kernel implementation, we use
bits 0-2 of each shadow memory byte to store how many bytes in the 8
byte memory corresponding to the shadow memory byte can be accessed.
When a 8-byte-memory is inaccessible, the highest bit of its
corresponding shadow memory value is 1. Therefore, the key idea is that
we can use the currently unused four bits 3-6 in the shadow memory to
record relevant track information. Which means, we can use one bit to
track 2 bytes of memory. If the track bit of the shadow mem corresponding
to a certain memory is 1, it means that the corresponding 2-byte memory
is tracked. By adding this check logic to KASAN's callback function, we
can use KASAN's ability to capture allocated memory corruption.

3. Simple usage
===========
The first step is to mark the memory as tracked after the allocation is
completed.
The second step is to remove the tracked mark of the memory before the
legal access process and re-mark the memory as tracked after finishing
the legal access process.

The first patch completes the implementation of the mem track, and the
second patch provides an interface for using this facility, as well as
a testcase for the interface.

Li Zhe (2):
  kasan: introduce mem track feature base on kasan
  kasan: add mem track interface and its test cases

 include/linux/kasan.h        |   5 +
 lib/Kconfig.kasan            |   9 +
 mm/kasan/generic.c           | 437 +++++++++++++++++++++++++++++++++--
 mm/kasan/kasan_test_module.c |  26 +++
 mm/kasan/report_generic.c    |   6 +
 5 files changed, 467 insertions(+), 16 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240118124109.37324-1-lizhe.67%40bytedance.com.
