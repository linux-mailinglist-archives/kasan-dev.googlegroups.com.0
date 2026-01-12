Return-Path: <kasan-dev+bncBCT4XGV33UIBBLH3STFQMGQEIVGOVJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 44AE4D14C6E
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 19:30:06 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-7cdcd09efc6sf20946479a34.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 10:30:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768242604; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZfN37t+JuxVu497fdDK/Xu9mfoij5286SoPIIiABRQAgyjume1l+iiVZc4VIe0Lbog
         YwOyT41VydXBgjLkfQuvyat0MOS0q24hcblspJRWoIuJXFKIbdyIqFsKuTYhkM3zK2Ax
         n7TC3nka9n+lk0Q+KMsCgOgzkGPakR4uMooKKHCkhbuzfAr01aGkpS3sE4in3wiwzE3F
         QtW2kgb+bkpy4ooDnSo9692Om724TXqKLVHerQC8/yD+Pi+Dlr5JlKH5Wr+hRO3/8HSh
         Mesoxd+yJCs2h5N4kQLKYE6qIH+lzkmwZsIiStydU2t8ry+5fD4CFDns0fey+vdaVAcr
         jM3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=2g8Zp/jrwcgMw4QstS8qgPpcJaXZaFVC6rBCgczxATQ=;
        fh=R2U04OkLteSYEYAS3n/zjH2kzDeSpCSXiTjUYLxDYpg=;
        b=TE5osxXE/yOxddJ25Tkyir3ZIgC38FN+GB1RRLuYCv5rDxWtkNujHnLkFP+RO+S8xg
         x7BXfeZhCKtKPymrHTx5P/yJXxat6zv2maewfRt9YWeQVy/sZ8SD7gKsLQc/R9Zk2ssq
         AjaQ9yi+Xt6dZu/R8g7tXPU/zby+HF9JTpEwzQS+7bMmalydNo9QMha5glcWcG5NBOFj
         OaV8ueEguVG7/oa5bLRXe+fZ2+UXSwDYnr2AEwBTsG7uYKzABdh5b0SejJyvHPpY3UZD
         WudPK0/+5XwhPIG/GISxNHo2DZIOUN+2geHrNhegZrPIHqGILNSmwOnCGwObxx94QWm9
         paJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=zzVnZrOK;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768242604; x=1768847404; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2g8Zp/jrwcgMw4QstS8qgPpcJaXZaFVC6rBCgczxATQ=;
        b=r7u7/JMWSEeMaJIAGS7vmJZWDnoGWwomGuQTWCYUNhAGYrNr6PYNwGQ9NjvHj1xjpy
         mzFxbvq+l/540vvmQPJNBeJ3uyZYFbuBeT9HK1CfUnlkRXjAnrtcpar/pRBUm1aX3yee
         HUzF7+i0M+UExxXvphf3PXa2U3ie9sRlq9t4yrwDNcCrjGQcwuKePulBvMTo/8xQfrpa
         /57xMNY9JwzB2Ix+0TRRDhIS9w8QwBqYKe2vJw9j54hhbIHl7e7sAp22aDuLcACS9GX2
         A1JIg0hKymVAF87WO9Owo5hEO273LBY2FMFySPFlxA/qEZp0lweNHhzqaZtzjpVEzEaG
         +QYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768242604; x=1768847404;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2g8Zp/jrwcgMw4QstS8qgPpcJaXZaFVC6rBCgczxATQ=;
        b=op4JHqDB4hwfpe0tdQ6xRGY8mErfXk0+MsN9FFHGyqFeHwsREAbbEztbBz9gnJiNZV
         ECMhf1wWN/pvhsMV5PEz9rRD1v8MH0K97XW9gJOWoHDRjIxMljKTqzdwyAMpmw/vCEMo
         LzRMj/VLuG4SrVR8RupdLlJ539KL3HJ+XRtEmZo5uDMgy31FvDd5zI8czsEw9ITB/CtQ
         SfJTn2W4X3o471ors/+ow0daF+8Vw20ZAhmuUgngoMUznq9Fq/TnXpC0q6p/5JVe6uS6
         /2WN+NOW/Uog+pwGsUsnDTFLNIjHne2deaiMFKVzNoiig2QxeuUx0hzdVMka6P9paue8
         pOJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVGjZkX9/hjUYJPi8YOlc1Wm8e0kkJg2tv4ShlBJgXZ1Vl+8JcUX8ZMRu5SjxYQfTchdkiPnA==@lfdr.de
X-Gm-Message-State: AOJu0Yx7NwOl24Lwog/8c7C/sV1YB48BnekbE2GBTf2o0AOI8mx8aN6V
	/7/9wqgFnb6G3P35onqpZFIWseUxKpjSHckfpEYVGhP1kysrOH7sSP2z
X-Google-Smtp-Source: AGHT+IFtAkxgrJcy56t3l5DtaLhX31URqBaHOzgu/ujEgV/0Elih7+x5Ycbuihhx/GaOUSclP45JVg==
X-Received: by 2002:a05:6820:448f:b0:659:9a49:8f33 with SMTP id 006d021491bc7-65f550a3dd6mr7955580eaf.68.1768242604454;
        Mon, 12 Jan 2026 10:30:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G5PGdfEZ+y/xD78hJ6pxR/m4A2GVf4AtqI1HTtWsHurg=="
Received: by 2002:a05:6820:6e96:b0:65b:2551:35e7 with SMTP id
 006d021491bc7-65f47420560ls3534015eaf.1.-pod-prod-07-us; Mon, 12 Jan 2026
 10:30:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWw9LsnhjfdpssypToXGwvMEd8c5M4jMlMGC128nA738KSciPmOJUKzT7IIUxrrGNakxbYUTSZzfjE=@googlegroups.com
X-Received: by 2002:a05:6830:dc2:b0:7c6:d0b2:8eb6 with SMTP id 46e09a7af769-7ce50926cedmr10187779a34.15.1768242601974;
        Mon, 12 Jan 2026 10:30:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768242601; cv=none;
        d=google.com; s=arc-20240605;
        b=XHDI1xGHYVVTsb6dSxxkcUTlbJA8TWThEyFguydQxaB+Jm+Aa+gm/jsBsYhOOxiSBE
         MbEF5Tqo9JEqewkTR7PYDTIqP4KuvKJ77Lo68zDmJz9bLzL/NSCqirGdet0nCj6NGWmE
         pLybJKzooUGSxMfnN+CkNuvg0p0U0GriO3RM0G6NXmJvx/bmJlNp6XgFIxvB5JFHAiH4
         AjB9rD/6jrcEWFCrBJmJzgdsuSYFioD7sA2Q9PzZlytlPiTTUAL2jeUpyOoT/iIcuvMn
         hA8rZZ8Y48MKpagW8tUkDAlOSj9kzxwA1Ez54bWc18t8fnDnxIHGqA8qFnDSIDTO9Ps0
         y/Zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=L4cDU1NowQNzgKUbPEkmBg8eSmoVUqiQeSeSb+NHqgs=;
        fh=Ae4YTxKIwfurMElOGefQ3RAS3Q0+J7tjLZ+fMm20xAU=;
        b=PS5BgzlY1w0qHlKEaXbmfrOoXx2sgLudkOC9urVnAzfHAKF1k6dB4jSmcAKFgO52Qp
         kA3AoEBrnFSjXYSI8uce7QP6F1JHHoH+qxrt/m7cMNPw2RafX74hf8rkf9DDC0BKvacq
         QYBiV2nrnLG60hYdmiqVM1eX1dnkfWYcpovF6SSE75Np2tsji6EBc6JelLECDIQ8JNji
         Rj3et1dzqxf5Z6Qy5gYRuTu8l/K/kmVIPGMf7PgB0QBC8LVy9DjB70S0GP6vbXWcnWge
         PV/+1bRgYOXF6ghj6ln7b8DHrXeW9E6+hn3UVDyf+BFhyDvSTuLT2H22K6Gv4AA2BVcH
         0bwQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=zzVnZrOK;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7ce4816475bsi789999a34.1.2026.01.12.10.30.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 10:30:01 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id B931743463;
	Mon, 12 Jan 2026 18:30:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5F1E7C116D0;
	Mon, 12 Jan 2026 18:29:58 +0000 (UTC)
Date: Mon, 12 Jan 2026 10:29:57 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: corbet@lwn.net, morbo@google.com, rppt@kernel.org,
 lorenzo.stoakes@oracle.com, ubizjak@gmail.com, mingo@redhat.com,
 vincenzo.frascino@arm.com, maciej.wieczor-retman@intel.com, maz@kernel.org,
 catalin.marinas@arm.com, yeoreum.yun@arm.com, will@kernel.org,
 jackmanb@google.com, samuel.holland@sifive.com, glider@google.com,
 osandov@fb.com, nsc@kernel.org, luto@kernel.org, jpoimboe@kernel.org,
 Liam.Howlett@oracle.com, kees@kernel.org, jan.kiszka@siemens.com,
 thomas.lendacky@amd.com, jeremy.linton@arm.com, dvyukov@google.com,
 axelrasmussen@google.com, leitao@debian.org, ryabinin.a.a@gmail.com,
 bigeasy@linutronix.de, peterz@infradead.org, mark.rutland@arm.com,
 urezki@gmail.com, brgerst@gmail.com, hpa@zytor.com, mhocko@suse.com,
 andreyknvl@gmail.com, weixugc@google.com, kbingham@kernel.org,
 vbabka@suse.cz, nathan@kernel.org, trintaeoitogc@gmail.com,
 samitolvanen@google.com, tglx@kernel.org, thuth@redhat.com,
 surenb@google.com, anshuman.khandual@arm.com, smostafa@google.com,
 yuanchu@google.com, ada.coupriediaz@arm.com, dave.hansen@linux.intel.com,
 kas@kernel.org, nick.desaulniers+lkml@gmail.com, david@kernel.org,
 bp@alien8.de, ardb@kernel.org, justinstitt@google.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, llvm@lists.linux.dev,
 linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org,
 linux-kbuild@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v8 00/14] kasan: x86: arm64: KASAN tag-based mode for
 x86
Message-Id: <20260112102957.359c8de904b11dc23cffd575@linux-foundation.org>
In-Reply-To: <cover.1768233085.git.m.wieczorretman@pm.me>
References: <cover.1768233085.git.m.wieczorretman@pm.me>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=zzVnZrOK;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 12 Jan 2026 17:26:29 +0000 Maciej Wieczor-Retman <m.wieczorretman@pm.me> wrote:

> The patchset aims to add a KASAN tag-based mode for the x86 architecture
> with the help of the new CPU feature called Linear Address Masking
> (LAM). Main improvement introduced by the series is 2x lower memory
> usage compared to KASAN's generic mode, the only currently available
> mode on x86. The tag based mode may also find errors that the generic
> mode couldn't because of differences in how these modes operate.

Well this is a hearty mixture of arm, x86 and MM.  I guess that means
mm.git.

The review process seems to be proceeding OK so I'll add this to
mm.git's mm-new branch, which is not included in linux-next.  I'll aim
to hold it there for a week while people check the patches over and
send out their acks (please).  Then I hope I can move it into mm.git's
mm-unstable branch where it will receive linux-next exposure.

> [1] Currently inline mode doesn't work on x86 due to things missing in
> the compiler. I have written a patch for clang that seems to fix the
> inline mode and I was able to boot and check that all patches regarding
> the inline mode work as expected. My hope is to post the patch to LLVM
> once this series is completed, and then make inline mode available in
> the kernel config.
> 
> [2] While I was able to boot the inline tag-based kernel with my
> compiler changes in a simulated environment, due to toolchain
> difficulties I couldn't get it to boot on the machine I had access to.
> Also boot time results from the simulation seem too good to be true, and
> they're much too worse for the generic case to be believable. Therefore
> I'm posting only results from the physical server platform.
> 
> ======= Compilation
> Clang was used to compile the series (make LLVM=1) since gcc doesn't
> seem to have support for KASAN tag-based compiler instrumentation on
> x86.

OK, known issues and they are understandable.  With this patchset is
there any way in which our testers can encounter these things?  If so
can we make changes to protect them from hitting known issues?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112102957.359c8de904b11dc23cffd575%40linux-foundation.org.
