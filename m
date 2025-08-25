Return-Path: <kasan-dev+bncBDCPL7WX3MKBBC4KWPCQMGQEUF2CGQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id A9BD1B34B95
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:18:21 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-2460e91cf43sf35086135ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:18:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153100; cv=pass;
        d=google.com; s=arc-20240605;
        b=g3+zefrlxWI3AdzHC9DvLCL19+lOtTba8OtxLPX/+mMpc3N6f1NT+QF1HXiCqTbqTO
         2dPAa1wvbsiynbb/NEkEirxPYEwznF60jQgjIgADW5bzV9O0M+YOD0oVzCvDljul+NvA
         tOlivdhIXYQY0hW48ApMmSm5f9tGbe7rYF8lwiV+lg94gGFRFogn8A/Rs3iblUpAlvSY
         WH5PwZ0mQJIl3oWdCKV9O9PQ59WnNZTRUPCisE3685OxqqmnJPnYJN9sI6kpN6jORg5p
         O0cyizdUd/Ur2RrbzqwgbN4omR4as9TLyn8N2ZZ/RxLH7AAxf2yQArN+TrR4AHESFiJ4
         yK6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :references:in-reply-to:user-agent:subject:cc:to:from:date
         :dkim-signature;
        bh=CPfGq+wBpnkJ0bLm+Fi3XByC7Q/dP5vwdpF/Cx03DSY=;
        fh=E1EuPAcPKN1rBIvnPHeBwNuvXVcZ7LVRM/x+mvu8RlQ=;
        b=C5/kkX3c1AkHsw6dmtGcf/xEsZS6Q8eCWmXHhKeOBQEtIqaeiBClEa2CPrSVcFGbZO
         kc04URHqdQS7D3KJDllCeDM1Y2Du1hPELxkiCZz4CYfdXBcUTpKPe92ugKF2r1mNPPG2
         wNqtAXO6DE2GeqLb9i6/pfslwzQ1zH+EA0Ztj8n5OT/A+r7HtBm/WUIcVZi8KUBVa8sP
         di/VL7pL10skzXCmvD5zqDc12U0zTs9gBpwNNKgsPUjES9Mvmh4isvdCCcsLVVa3+wOx
         H3G377i0kr75OhwUDwiSbVfnbxntT9Btgs5K03y4PGpfwSvKCkCXOIXa8sVfH+jILiw9
         9r/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hFlxFsri;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153100; x=1756757900; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:references:in-reply-to:user-agent:subject:cc:to:from
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=CPfGq+wBpnkJ0bLm+Fi3XByC7Q/dP5vwdpF/Cx03DSY=;
        b=bxHXfdXiDSrK7OY8lGXNc1YS+e1/BMi3kFT4aTQJICnkEtpHABOvdTa6hWFjYSOd6i
         vjK3kP43RhmnpVZdonNClsc3Wc9MBkVMesyb+1Hfw4v4GMTW0NjGrmPtWmKd9KMqNxte
         /sBvHoX7rDS3zK+E8bug3odI17jKrdr0Ng3tRVV+uHFNhti6cx7ij9xM8SL1GAeU6Rf3
         bcliDgrPVUy03S+fr9DKUCAFTKNfGtGl9RllOnU8GfLjHbN8JjXTvkw6b/XDpgqVSZTA
         P1QNTLZjrapSrocG4pcoATr4wPjcXUSCsoTx7laReoeODiYS1LaPr+O8X13CEWHlZtS/
         4S1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153100; x=1756757900;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:references:in-reply-to:user-agent:subject:cc:to:from
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CPfGq+wBpnkJ0bLm+Fi3XByC7Q/dP5vwdpF/Cx03DSY=;
        b=PMIZ2meWCbKtXiaiHNWYlkP/Xxs3GVcv2btvP1i8NoPqyUVBTr9O8Gs0Nnms/qNqpv
         O7X6u167s2y4zOkMQwZdRwCcbPh3u/j16RFk9TBOuZ2WhuQl2YFEuP2k1RT2ca0BKnI6
         5aWvBV7N7Mnu3Au7x0eiL8YJuvPoF3hH3DzCBAscsMv8BklCpML/hmXxtRHxmRvFttei
         E9dqCRKQB/X25hMNRERbSCCumS/6olfE27BrIyH3o1CSl3+6DphpkEFqkyhO1GHbKQbI
         5BrH9qeckr9Wtg6UiAPKMbDFhmCZBVrQgt3EaccWQ0SJ5atAxU7NcITf+BYiYjNSjWoM
         8XkA==
X-Forwarded-Encrypted: i=2; AJvYcCWGC26NIjD5REtpQe6C5mq9DP0zFh9GXqChTsAyQbjD/FgNowpTTrxfZN2giVqcib7q1M0x/w==@lfdr.de
X-Gm-Message-State: AOJu0YzmEQn6vC2+bn/EK7XFGvbdWbr60pqShldFhMW2YsGABhVooYIH
	iWus/FvyxF8JOeB0j1dcpEal+kbeKqCitqyBloS9ED9hS/r47VN+a3kc
X-Google-Smtp-Source: AGHT+IGcxLy84BMePHhDBJPZ9O66E7K2rVLSR1/RqQmhgZhuieW2sOKKFE/0TXWPRb+O+wzuOweorA==
X-Received: by 2002:a17:902:ce01:b0:245:fd33:5b16 with SMTP id d9443c01a7336-2462ef1f2f6mr184313665ad.36.1756153099652;
        Mon, 25 Aug 2025 13:18:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdsj4hlFeLITDKBgIbI5UL68hUDxHzx0lfrnjHJN/EXGw==
Received: by 2002:a17:902:e38d:b0:246:7333:30d1 with SMTP id
 d9443c01a7336-246733334a6ls16111085ad.2.-pod-prod-07-us; Mon, 25 Aug 2025
 13:18:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXUOE7wRDvBBJ+Bu339Lwbsz796bkeAGAX0q4UtxQsxhCLmTmL/8Jg16pKQrmw8v4Ti3/bPspIaCic=@googlegroups.com
X-Received: by 2002:a17:903:230f:b0:246:c816:a77c with SMTP id d9443c01a7336-246c816a86fmr57424565ad.8.1756153098211;
        Mon, 25 Aug 2025 13:18:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153098; cv=none;
        d=google.com; s=arc-20240605;
        b=V9xUqUTxU174K3GlGaSMubmJbMlMYjt70TrwA1wNS+I6aRv8mUXqaYGF+FXivTYUfm
         8OTk6kvFgnvKx20G6WPIJGP1r5vhedZmdvbN3rBlNdU1eB6YOu82qT2Aw5vKyWmiIPrN
         2G7G5Nbz/OGeuEqw/YKT2hX8xL5GZ27VBJs2DTl1GUiOIR7wj8HAY6OjN71/tP+mcsaX
         XbQ1lc9J9+OJ7r3ybbEgbl9tPrJ67iUlduQTg69u/5x3B3K4yL9IGOCt4NkdHpMTzKyx
         YrufnLu37jb8sj/9uX76QLRUJhkfw8F3rRdJP7B0ZXtA+I4WdnwGE+u/E3R21Am1uEWj
         ttKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:dkim-signature;
        bh=yNerjuxI+KYbw3mNCEHMV8i09CJJK9GCt86H4fr7e/g=;
        fh=sIE10nwOKsxxGMknMgKQoAoANTiGPzhD2/JCUA+MEgs=;
        b=NiHclmFdh5aZFDggWR/ClqnwjYQPxOrHxZ8fw56FeAiuN04FE6MjtH8sSEkhnT1Yzn
         Ws/g7Lq87Izg3YYQ7VmWrLqGL11ax1F2P2sJaHBVAgdM+QXyWvaPnuMXvbM7Syz2falO
         kSMhapi0X1YQhnPsMSVmoNvakyhel/xaJGYu77bWz36pvP/tJDpi4MaHF5ylCJhmeA2+
         J1M63CxWw++KC8ikAHTjtCKOo29F7CkZfQ88ByTZFIQOW1o0YwMFaeNinhd/4hdA8knt
         /He7Mx5kUxkYe5G4UhlKkC1eOZrbiJ+jgpkAsg75k6a19h1Wo5h0WXj/gczLSJwNR5AS
         ZGEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hFlxFsri;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2467a703105si3381845ad.8.2025.08.25.13.18.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Aug 2025 13:18:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 47722601E5;
	Mon, 25 Aug 2025 20:18:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 51237C4CEED;
	Mon, 25 Aug 2025 20:18:16 +0000 (UTC)
Date: Mon, 25 Aug 2025 16:17:53 -0400
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>, elver@google.com
CC: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 "Gustavo A. R. Silva" <gustavoars@kernel.org>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 David Hildenbrand <david@redhat.com>, David Rientjes <rientjes@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Florent Revest <revest@google.com>,
 GONG Ruiqi <gongruiqi@huaweicloud.com>, Harry Yoo <harry.yoo@oracle.com>,
 Jann Horn <jannh@google.com>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Matteo Rizzo <matteorizzo@google.com>, Michal Hocko <mhocko@suse.com>,
 Mike Rapoport <rppt@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Suren Baghdasaryan <surenb@google.com>, Vlastimil Babka <vbabka@suse.cz>,
 linux-hardening@vger.kernel.org, linux-mm@kvack.org
Subject: =?US-ASCII?Q?Re=3A_=5BPATCH_RFC=5D_slab=3A_support_for_compiler-?=
 =?US-ASCII?Q?assisted_type-based_slab_cache_partitioning?=
User-Agent: K-9 Mail for Android
In-Reply-To: <20250825154505.1558444-1-elver@google.com>
References: <20250825154505.1558444-1-elver@google.com>
Message-ID: <0DC67CE5-6006-4949-A81D-882DBDF4DAC4@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hFlxFsri;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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



On August 25, 2025 11:44:40 AM EDT, Marco Elver <elver@google.com> wrote:
>Additionally, when I compile my kernel with -Rpass=alloc-token, which
>provides diagnostics where (after dead-code elimination) type inference
>failed, I see 966 allocation sites where the compiler failed to identify
>a type. Some initial review confirms these are mostly variable sized
>buffers, but also include structs with trailing flexible length arrays
>(the latter could be recognized by the compiler by teaching it to look
>more deeply into complex expressions such as those generated by
>struct_size).

Can the type be extracted from an AST analysis of the lhs?

struct foo *p = kmalloc(bytes, gfp);

Doesn't tell us much from "bytes", but typeof(*p) does...

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0DC67CE5-6006-4949-A81D-882DBDF4DAC4%40kernel.org.
