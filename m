Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWEGZTEAMGQELAVTDJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 397A6C4CB17
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 10:35:22 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-9489bfaef15sf241348539f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 01:35:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762853721; cv=pass;
        d=google.com; s=arc-20240605;
        b=XuSHgk1UtJvWAoiFygbPK/Rzf/ac+qptLejrYKQBQQL4w6Cd6hkfNKwdXg/nxI33OV
         A5ZwkQJNZ6KmdwJUHVp7mxHcK3V2MBlr4Cy5svA/fEBVFyakwp0nHpOYRKxebqQXeKhi
         KhCO034qP6RMVR1zJCKB2JMjQ8PaqqFwpvJqCjb+2lEcT8rhoWkGO+atEy5IK7cdcgAw
         1z3SFflup6UUgfjZ3BKdDVcD5BMO/RRxDHjmQhobQpfwLwHvdOqSvxKH7GnpyDPYKVmS
         gu5LnHCuKuIVLgDFOYnTiFsbIqRw93yT+CDVzSoVtieJbEF0jLlbpYf0GvB+t5eTwDWY
         0WJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=L5yOUxCgnRDpdVjhfRiZ9FIRPzPRijpOFsXmWA/BbMc=;
        fh=Z//MHc15sFYCJ6TZz/XCIG5xRiq0zVUaCG8OHZkI92M=;
        b=Lvn5OpnQWXrBbWqfFtHAX1jZ6WdOCyp0Ellq2crdCzur494cGXt9vk/AIR15W1UHvm
         LtUS8g0wlBGtB4JJwy8FL3hH3W5doTHMyc1hZLyW+4JhDISyIFtTOyF3Hxneg4/UrfZ/
         dEIR+tUBSFHMFwOAvZsivHRH7D+wIlj3xszqWW0WBN8FcoVMeeR81qeE4Qk338KEakJR
         ck6O4mnV+RsDCFiWtiodkbSzMlcPnRr0dbJ8h427LKzVVHUkp4gp7YzCYRedf+5kMOio
         bFzMmN7k9eQcGK3HQ42T0UiBFIHBfeRiwF4igTdwjDFr4bgbB7eNHQwmTxtrSML/kIoi
         Gb4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Jh4VWfiZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762853721; x=1763458521; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=L5yOUxCgnRDpdVjhfRiZ9FIRPzPRijpOFsXmWA/BbMc=;
        b=e6r7fiEZtZQ/N1o1p94HwSzY3UfULcVvUtxl4RHM4xMkSZuCtY47WWX2DeavNjwSec
         jlHX2UjKzybdiPWOEvUUK6wpCWPtXi/5cLlFkDJ++RqwVQK60z9Op6G6wMEPzS6VnOgl
         tZsQ42t0yQbdYS9qrwxh4PYVSdzw2N0lGbvkOHxbI/tCYmoJIubzsITzyuUxf06Gejxo
         pcHQdzQ+qxoqLMlc27ChwQJlUa987ojPr/QfpdFlTpvMi+In+mOWDJcJUFujM3yO+vl0
         /wvkFdT4E19O+fnrVjtz7ZIq0GoZ53E0Y2JQ8OdDVctA2YJ/wrmjMV+s7RmBlMxUuGMl
         FZPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762853721; x=1763458521;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=L5yOUxCgnRDpdVjhfRiZ9FIRPzPRijpOFsXmWA/BbMc=;
        b=ZIEbS3Iznrg/kf0rDXwBVyMEhuikcvn0mckKGu5zrfZYpdf3xKwZDA2BG08xgo+eZg
         DQIPMuvUPVnYN2LmXrgCDZ0oT6+oAJAg9aUpKjNGHawBUMIH+8fWPD3HTI4xN+nn5w6z
         38kglsjY4a3AuPn2sDxOxGa3+UvzmlHYAL/zfjQd0ZV6w/nifBeNCfu0Q4Om4zqkfb6Z
         RMiCJnH3TgyAyARo3w83hsLSnp+8uKqMOJd7o9sIZi5QdiGK2PxVVdNncaqQ1oySfcwe
         1tnM2S9iIAJa9A+SDQ705X4UuKqFDm+eQ2sR0MCA61DI6R/7GWJ6hBBpV+a2JBvqP/jD
         +jSQ==
X-Forwarded-Encrypted: i=2; AJvYcCVWAPAtRJ0tO3wMtFpccPM3UeW6GlfScGj3au70KW7ydNyoDldTZiKmHjzzBQC4ZMHHkMIwzw==@lfdr.de
X-Gm-Message-State: AOJu0YzaMytbykz17HNuR6PWZQvuIyJIPm1VxPoJf/QqPTV4ybq6P1Vm
	+iebSvXaMJeK8pMthDmUUOrfypCnOMcajPabfIHgk54d8Dko2S1E5RZJ
X-Google-Smtp-Source: AGHT+IGHKIGZj5Y4YGskX/nOHuw7J50/y8d4uFC+lwmKhl3xdL7vgEh9tXL3z9Pp8jtcm/M2hbM/9Q==
X-Received: by 2002:a05:6e02:318b:b0:431:d726:9efd with SMTP id e9e14a558f8ab-43367df03a9mr174974525ab.12.1762853720713;
        Tue, 11 Nov 2025 01:35:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YIwkYkTl19lJipjIBkQ4W8KNQf542GfuDuCe2gHWrhpg=="
Received: by 2002:a05:6e02:4813:b0:433:1622:eb86 with SMTP id
 e9e14a558f8ab-4334eee4984ls18228935ab.0.-pod-prod-07-us; Tue, 11 Nov 2025
 01:35:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUWKV6LTla6BQroy5fm0GOl+ENtBbvc5LAmwvzvuSNRwSWCLb1FWnUrl/W1pLpr4Noy+ddkPHWbC9A=@googlegroups.com
X-Received: by 2002:a05:6e02:741:b0:433:283c:b9f with SMTP id e9e14a558f8ab-43367ddc3e2mr154026575ab.3.1762853719912;
        Tue, 11 Nov 2025 01:35:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762853719; cv=none;
        d=google.com; s=arc-20240605;
        b=NVt3wwmo9D9JXMUOpcSrBg+9QXEzyzzwuhVqB0EFOrdycFWKJltQ7D/OcrvD4lG3od
         FzOjISr7tGEmkkqUf9dqIgjOyX1MOtogof+K8emG0v22PDjw6Jxm4lyY2KZggRsqxi+U
         T6LdDCLYoGHkkFM2Q66Tl/y8mBnnXhq60gDRc/rW+BAkzlAzuhjI1RwPPbrEy+XCiidp
         4Tm+egZLFO6pJ34PFdbEmZ+9dzHecm5pLU6T1sRzdpIkQyAqJO0sfPJ8vSzSb3CHCBg5
         XjMLHwMCiK047mx3B1tYAzaQeE1jB0yC1VMUQt95o0GDBssPOKMUlHMDNcGfmx2jBR/c
         TtAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EetqUyAEJqiuKxD3fEI2nbY8lCOitzdVH7lF4O8jjNY=;
        fh=Og3OTgvUmjALiZCZ906KVetWQ3Z5dBs+B+XYMGNZoMA=;
        b=dMaQTfhYac2VQDCPCpjuuqrdEdgxBVET/LwQ2p+zMfV8OmO0gKwu2D20WVwuVyoBYw
         CPP6U6GlytgzVVyZSYBOpReoHVfBSJYxpazMX1BGFy7J6dJmPcM4XiGKIyEgomVruy6e
         9PphbCw/s5t9eyinTX3kZReq4iJcNWRIlJQ2afr5IOiMV8prNnSJ/AtirAd2siOTKCN6
         kHFH4k3soP1sniYFS3OtKoBrO9WO6U7xidB5x6aAFaeentLGdiDxYq01DHTTPTGU0EBo
         ZGY8Tq1iN3JXd/qKPha/owMYKY6XSel2OL5yGiPATI47U886zzptfPygr8gl2sgu2/4V
         P/xQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Jh4VWfiZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-5b7468c7791si620305173.3.2025.11.11.01.35.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Nov 2025 01:35:19 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-3437af844afso2486932a91.0
        for <kasan-dev@googlegroups.com>; Tue, 11 Nov 2025 01:35:19 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXhsBgcOvLRwxsyiazdIW51yB60wJ38wf07yD7XE/hWsCF+n+zU4F//dVuPb1G6vAhmzSTYAK+KFSE=@googlegroups.com
X-Gm-Gg: ASbGncu/Xm5upwURz6TxaZLCCn5Gp6p+pDEPVyNkA0W5FewlyWXSkGlcdvtVCIYoOTj
	YIx/OPLYnVNnFNWNVYXje5v3Ogkxe6HMUTQ+lDOUt4O8GI6w5imz+UaE3ZtFIPyL0hu3alLBXI8
	7jw68JuN9QJXIKgXpi4bX8EHF1dUlc+XvvvgXG60FehrnaGCoo28VpHaewrXfj4/LQXdpl3AuJk
	HY6m7SMQK8fFbQ18USv/i9hepzyosjdA8KDbLJlF/xvcYrqlHHTGFAFDaZRiSMx0BSg+pEcUJj1
	sAUxwoc+4fizBU42LdcbPv2RAw==
X-Received: by 2002:a17:90b:390f:b0:340:c151:2d66 with SMTP id
 98e67ed59e1d1-3436cd0bb4cmr14245240a91.30.1762853718758; Tue, 11 Nov 2025
 01:35:18 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <fd549c974b53b5410dbf85c0cf6a1f9a74c1f63a.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <fd549c974b53b5410dbf85c0cf6a1f9a74c1f63a.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Nov 2025 10:34:41 +0100
X-Gm-Features: AWmQ_bkZUqiS435kDnMhK6mmvyG8PwqBjo8fr1ltJrKRlyqzMnD3vTHwKYRZs0Y
Message-ID: <CAG_fn=UoQeoHh6Bpy0YOCywpfaimuYZM_d043JfxLVReW8PdJQ@mail.gmail.com>
Subject: Re: [PATCH v6 07/18] kasan: arm64: x86: Make special tags arch specific
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, 
	kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, 
	ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, 
	morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, 
	baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, 
	wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, 
	fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, 
	ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, 
	brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, 
	mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, 
	thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, 
	jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, 
	mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, 
	vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, 
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, 
	ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, 
	broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, 
	maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, 
	rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, 
	llvm@lists.linux.dev, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Jh4VWfiZ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1030
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

> -#include <asm/kasan.h>
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> +#include <asm/kasan-tags.h>

Perhaps moving this part to patch 04, along with the newly added
kasan-tags.h, would be cleaner.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUoQeoHh6Bpy0YOCywpfaimuYZM_d043JfxLVReW8PdJQ%40mail.gmail.com.
