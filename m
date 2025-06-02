Return-Path: <kasan-dev+bncBDCPL7WX3MKBBTGQ67AQMGQEJAH2SJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 03117ACBAC5
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Jun 2025 20:07:10 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3dc83674dbbsf99095545ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Jun 2025 11:07:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1748887628; cv=pass;
        d=google.com; s=arc-20240605;
        b=Oy0aRBCfdx3DDW+k4pdKEu8gejYkh6p5OzcSKliFRPCtoMwJD2jI+t2eFtHjcEv0Ov
         jEMX5L9JFdBruuKXZij/w/Q61QQuXFIMy+vlEM6yKuYtpDnibGkXCAGt8GOFa/rP45n7
         p8/ZnWvXv4mfrfmPGTLcWUnRNYvhmAaqYigb0UhVd9tSF1mYoixy2ZHrDLbqiK3NRfDp
         S1U+bP3E0r89+CpswFJbBO6sDZOoV6oHJtM1ZGDH0Z4MMFNTbkicdBUnReyRD5yfuOPl
         71/JMvwTnvhSrrpVxUknC3BA/yc3B1YPRMT6XZr/SNfp+78W9EHARhtxvlAd6UBRrKlr
         nrUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=FTjIRzhIznRVy+xkqko77CH9HbC52l0HpvxrH8uAMcg=;
        fh=w+II3jdpnpMMZMX1tAaiigI7tkjuFq1U/Rtmd2dQUNg=;
        b=HpDfSDrR7nIhNadSxr+g6Zn+4HPX2lyQi8B03t3Foq0f45c5fYb6GetmwGvuKpGjvE
         /RvfydFDcUbSHd+a/sQ8rPvPNWmijq2k2ibks3ob/vWmtFHMjGGxZoLkI8KuUgYSDBq2
         QOYNsGVjgorqpIcqM9uKctA6E781ljlnRBPeMEULkrh5DoqdCMaOq5ojGyqfsDI26COk
         gWWaKAzUKTN1Xko84vsLHwq0yJ+5zrpoJOH45JdOXjBuXkjr3ziAcYJ2QqfSvtLeSYGQ
         UsYTGyyAUMUAVlvSZZXfMaN7UFGPqeD799gNgreqKbah0p8dE2Wt/Timz3nYRoX2bvnf
         98EA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mbHsuyGY;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1748887628; x=1749492428; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=FTjIRzhIznRVy+xkqko77CH9HbC52l0HpvxrH8uAMcg=;
        b=j/JSORiguPZraVl0EVM3JR9bMSzhY/lmd/vJWKEEtT1QXZjKKQSzD3nkH5NS3ygpxY
         QjnMUslZdlTWQSMhg5AG5k1X3blfs396fBvK/SlvsjzbVgA0YPXgkHsnfN6sdiJgLVQR
         DXXPZJBZfO+ZXPSMM8ba/N4v+y4fGCH3hkaDfx25S8mPuErpWZyaIWMJtODDHsJH9eJn
         +WbexcjK41f8ccgpMKEVLqCQ+Bd4DzG0q4fTY0y5kO8Cns7FMutKyTfASOYqAyT+wid3
         QU1PpEh60bXdJqVvZ7lUnhA2wWpFjIFqgi6R2f0l2v7tqeY7Mpi9E+uhLCxR3wF3HdxU
         oPcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1748887628; x=1749492428;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FTjIRzhIznRVy+xkqko77CH9HbC52l0HpvxrH8uAMcg=;
        b=YpmKVoEVOltrMFIHNlx9QTGbB/8s+E+/y5EZsXNU5mmh2YKsZEcRAuLifEJLQzC1HD
         hgR0yTuEFSQr//l0vXt+PXNBEmF79HCJD+Hk8WC8wfttxxJQUK2/RjUzCcMA9DQS7NAA
         P8WUxaQSOyx+AbOty7vL3n+vfzpvbfvBc3Tma2vFOqPUwwuPOHmNPXUjcozzb84Al0uV
         6LCFILlNuShvB6DDZY8Fs6YqYenDTI/+Pk0PTtrj/rM5eLuaKTne7xcJbwse7UwnJt7s
         aMcGNYroD9Xyv71yG1Vnd/MZ6Kz0obOEnMkmYaGNu5WAZfCESPlVuHMNbhEk03cr1IEs
         nCHg==
X-Forwarded-Encrypted: i=2; AJvYcCVXm5iQPkbIyZqZnyRHdBIgpmxyBBpZL6o6ya6ymEPN+/hr5BkPkko0+CpCS0ukZlcGGTR5BQ==@lfdr.de
X-Gm-Message-State: AOJu0YwvEwQbWi8qQXNNdLwnS0/2hQTe8aCSo9LFUBrlJ4QeupDNDKx2
	co92r3O/wvV2O8TbvJdS9YOWLPAywq8vwXMDRuGD7stMkDOOOIpKUxib
X-Google-Smtp-Source: AGHT+IHJOSm9XiHrhKjUTf4H0v96jklsxPv+sD5x8dsCmBuczaTTqgmTga0Uj194vat6RPnkPTaBLQ==
X-Received: by 2002:a05:6e02:12e9:b0:3dc:8667:3426 with SMTP id e9e14a558f8ab-3dd9cbd5e6cmr142397675ab.17.1748887628425;
        Mon, 02 Jun 2025 11:07:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcKS2eh+JEPQtRF8CK0cXpaHrjMlDRD8Hn5ZgIAeklFBQ==
Received: by 2002:a92:d14f:0:b0:3dd:b6c9:5f59 with SMTP id e9e14a558f8ab-3ddb6c9624cls221785ab.1.-pod-prod-05-us;
 Mon, 02 Jun 2025 11:07:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWpOQW3iX4dn5aDMVuOdg6Ug3rUJYB/rQftx2x7A+CNYRvOLZ1nVvPkXH1bihdxxQqnTLjEKVOQpDs=@googlegroups.com
X-Received: by 2002:a05:6602:4183:b0:864:4a1b:dfc5 with SMTP id ca18e2360f4ac-86d052154eamr1572652839f.9.1748887627492;
        Mon, 02 Jun 2025 11:07:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1748887627; cv=none;
        d=google.com; s=arc-20240605;
        b=iSc28M+GSAdLacz44XAyUCyFRj6KKjZr7t325BauEvTVt+ycXisrG91oAHmLgglnev
         04RiPRZRAUkkoGGKAmr1+EA0BtDT+ayXXALFt/URYZCn2jRJjrHfOsyzenuU9r87WQ0D
         U8iMeuVJeTAn1HXDYxcVHCaCMvjc+qGbbO3KDl8W8/6JFsDt26XHPTb5+LGF1NF9kxt0
         EstU8+sj+hNscSdlDiEr/AgkFQdQvSZP7QFlAfNCzchCFnsPORrdwfGOhzEQdcAfCAjW
         cXARb0c0U2tBj3NB8HpdRCD364jHJZ7eCykfZNHe5BNd0sX2KtBEZAvARZb1ByU3N4T4
         ZjEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=zWBxM/gDXSjQfeGWvydBPVkDTaFm1X7fkpfxe8EA9PI=;
        fh=tpiJT+LDNjHus61rmSleXr6ToyZwMvVA5nH7yi0FuSI=;
        b=UjBYO1Zp1dR/0ucWkjYQlO4iGEWYVfKY9Gla1tciWw9g1Ycug5D3/UGUgo/5CDxf0a
         rtGiC0kFdFWSPzGi/rmyqi4HnTThtKSl2ScwREKa0IgXwQYwxHHWK0D40sKJC5EIyBrI
         axOTu+5gGhx6Fy2iRubJ9QX1+BTz2wMr0DwjkCeOsfKW6jUL540oq6T40e0i0Yo6aMhS
         iaWwLQ+NDiSySmx27CmSQYRj2lujvies3DaqnKUcQ4SSWRWVts1g1clrMfGo9mfktykL
         YLrlnyTtATmldpItZbZM0yMH5Dhy/gPb1BKh/keCajFUYfGml1clOmuEKqkgAKhkqF3+
         /LSQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mbHsuyGY;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-86cf5fcec21si43224439f.4.2025.06.02.11.07.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Jun 2025 11:07:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id E8259A50393;
	Mon,  2 Jun 2025 18:07:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8E5B1C4CEEB;
	Mon,  2 Jun 2025 18:07:06 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Junhui Pei <paradoxskin233@gmail.com>
Cc: Kees Cook <kees@kernel.org>,
	elver@google.com,
	andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] ubsan: Fix incorrect hand-side used in handle
Date: Mon,  2 Jun 2025 11:06:27 -0700
Message-Id: <174888758557.4018560.13578751882908437370.b4-ty@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250602153841.62935-1-paradoxskin233@gmail.com>
References: <20250602153841.62935-1-paradoxskin233@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mbHsuyGY;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Mon, 02 Jun 2025 23:38:41 +0800, Junhui Pei wrote:
> __ubsan_handle_divrem_overflow() incorrectly uses the RHS to report.
> It always reports the same log: division of -1 by -1. But it should
> report division of LHS by -1.

Oops, this has been wrong for a long time! :) I've added the appropriate
Fixes tag.

Applied to for-linus/hardening, thanks!

[1/1] ubsan: Fix incorrect hand-side used in handle
      https://git.kernel.org/kees/c/c50b612bef51

Take care,

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/174888758557.4018560.13578751882908437370.b4-ty%40kernel.org.
