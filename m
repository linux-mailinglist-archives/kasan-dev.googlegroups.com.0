Return-Path: <kasan-dev+bncBD53XBUFWQDBBG5JZDEAMGQEBOECPVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5516BC47F9E
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:36:45 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-9489a3f6e3dsf218792139f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:36:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792603; cv=pass;
        d=google.com; s=arc-20240605;
        b=DAoWeQjKQ23d0Uu0WceUf1fxamjEyWLGXzSD9AGPI0m1pyRenRq/46xeHxLhyR9Zys
         8UU/QaAZpBDoA3Gg2hToeY6zW3HOFEiBMh5mrA5JJaihEleaKtmcjn1yLB1kXL+xJfOW
         ElURZ/1JE1eN3Nx3K50ceHMS8EvaUJf6bQcoaaCABjrk9APnQF/cWTftQySAYxy6lahc
         KMf84DkGYcitegEncxkNFoorY7beEZQ2AzLzqUux8nP/O3Hm0w6H+meSBlTrSq3+YSyl
         5X8p7s5W9xaA7Ymui8oIc7pNwdILKKYv2UR0swAzMZA1f4gwXRqsg1J/+mU5mxsGrE5E
         tZng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=mR2l+oDtGKWlXW+pc4fasEFMcWsZ06l7vzxJn8UoiWk=;
        fh=JFT9683AF1Gt5vYS6drTxGraqkjjRZyesr1+NPq2WV0=;
        b=DHTmOfxJZQEig2s/btS1uNXMoU5On1eYeKij/lFpw28yruvG7ve9uLcmFBEKYfEt4R
         dJwJN0NkOrJbRF2n1CXZBMp9l488Eyx2iHJ5RRyw7sbaAa1dfVHv7OeGK4q43zLtiHSi
         /sRBygYHgvQRrg4eHtHRAcDkLLsVxfDK3XQE78pHTVH/L9/OQK3ikAw+JCHAElo6O+yv
         CFApgr+M7muIvz/tHVIYEWZvkWgM1F5XRjhsWbbhwGPgfa+n6biJ0Csjm8VbNYSvWMk1
         iHwMyCt4hnJvzcg6VM2ymAETn+oCR7uHmPWAE9MLpts+Tr+oxf/G5Ke5IM+lcEBdkt2B
         quiA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="ZeaMrS/9";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792603; x=1763397403; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mR2l+oDtGKWlXW+pc4fasEFMcWsZ06l7vzxJn8UoiWk=;
        b=WaEMzW3L7ptl9avJyaLeC+tN5lbfddL7dYQ5H9+9XyoWEQg3woGItid2CbBsKmO/Ic
         LzCQLjTxJAFE+R6mbD8yg5q58xVNzZk4D3LMZSP/WOO9dQCPmgAzNtC9ZS6kMVbIf8fp
         4A5ezxQUrz56I2HuykmYXPzcstt3M0+G2dokm0A9BY1hsDzzjqAgmtTaTxYfsMr2Qwf2
         UtC7x5jGHxXuggWXCO5kwTNNRpJJKlzVlPzSPf7OPIlw2jldzmMO5DBNuLBtUOBrFXE6
         NlTmWOqzrKUrjdD0hR3O00gORo8zSdjV2kmL1eTb3LVh6XQLMl3IJZGAKMO7JFHeMS3Z
         EAvg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792603; x=1763397403; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=mR2l+oDtGKWlXW+pc4fasEFMcWsZ06l7vzxJn8UoiWk=;
        b=BzTzpmTuVUEJV+QY72bygyGKSzbJKEx2VHjNJJ10wd5oW+xHVr4jQgtZSeX//YAIkE
         vGrEkTt4itvUyfWzIdpL1uVuylEHU+ndyfgGPr1IbLVwghJ+ZT4y+P/j1wScFCJ9BPwJ
         u7w5plqLIbVMX1eyz//GaXhe88wMvFXhX0iYe3nAj49R8+HzIMh/mWtpmEOt+/+Diqqi
         J4FyzevGEBeA5LqvAMCvEYrAzWXUTjTcDXsI+pwNy3/xDazOGhCgPkB29g/SEuUUrJ4Z
         37XDqxNx753B2qNCU1/1RMtmplVGLVMYWORCh9txWtsi8gXgoz6DKejTgNkepSop1+A1
         y0WA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792603; x=1763397403;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:to
         :from:x-gm-gg:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mR2l+oDtGKWlXW+pc4fasEFMcWsZ06l7vzxJn8UoiWk=;
        b=Y9rRu5z+E1MXZ7EM15wlWEdz9w2N0UI111HvwSvXSkh+VYhHADSNwlZ7gwmr3afiRK
         Y7lLWmwNKR+hoUv1aeVfbIq5nVbWOAWcPxBpnwE8GNQdNF8JboLXfzWS9cMTkh1qZwNV
         GMIW5jT2mMuHEEuhbQ6SQycZVAWkoC5N2eruD4M11vf6UYz1J6hq261S+DJzlXIiXMMy
         OW30GiBWj8MuU7kJnYm5xMNjxkoDaNeFCt/CUjWAUV7DOSuxBq27DaJf4s9800sYFaUv
         XKp3CfIazzqH/euuRHZp+ddJCLdGFVpyzgiUPphjQsRMqzl0ZUPjbkRw7oLEP678l02q
         LhtA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUdmYrIF//wPZdxMqKVZoFYZvL8GA9W2h+ad9VmyKm/TQJ0MQljpZsiDFCyHhsR1vV/W2B8oA==@lfdr.de
X-Gm-Message-State: AOJu0YyCtT8vW4FeMcPnlG6kj7c/p9/BT/8yutt7757y2438y6Z0U79O
	k9VjdtykJWhhkzVYmL4p1FQTYRuRGunb0RZlIRqcLNUxNoy9i0+NMUPD
X-Google-Smtp-Source: AGHT+IEbF3oV2EHDNBAUTRsdW+3TzbT96wT7YLcYn0WN/XRIS2DeiT0kmiUIIYAYWBLfEv7g9p8xNg==
X-Received: by 2002:a05:6e02:3498:b0:433:7ad4:7394 with SMTP id e9e14a558f8ab-4337ad477d4mr69136715ab.20.1762792603426;
        Mon, 10 Nov 2025 08:36:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZYTR9wC7N39oex4N1gKFYwJplkhV9STUvzqkCTHaEOVg=="
Received: by 2002:a05:6e02:1a4c:b0:433:8a74:2890 with SMTP id
 e9e14a558f8ab-4338a742ab7ls3501445ab.1.-pod-prod-05-us; Mon, 10 Nov 2025
 08:36:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV2MOJSNtCUCHaWet9je/Hfygosp6ztVVzVtrncHqO9aVl6h+5CoDY1PpUjVvq3KwrGrFyEYvgqz/s=@googlegroups.com
X-Received: by 2002:a05:6e02:b4b:b0:433:24d7:309b with SMTP id e9e14a558f8ab-43367dec4a4mr132443255ab.14.1762792602237;
        Mon, 10 Nov 2025 08:36:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792602; cv=none;
        d=google.com; s=arc-20240605;
        b=gf34pSXZG+A64ZDySi9eRY83OiyJxHiD1pG0fXALeY+WJSGALhy3BOCM75vwl0LZoG
         p1VkyQlQgvI2Gt+wjMr/0jwQrF3cA8m7mCy1+eXfDoDM0vVTQ9b4WKnWOjmoZfI1Ok9/
         XTEX9rDhKGpeSYIuqGLSfLs07r9Wb4Vqg3FxltrLsYOx7tjjY9tyoeeZ9JgPWs46kJZY
         y/17BNwA/tLKZn3nwxJCOZTOpUJaeq2zxEpn4ArxGYDT0BvAq4s+8wDCjPOPu7GbA3h9
         JDlmBrmD9LiHK4oitriQaB42/trZcUsUeetic/1EP24yaIG+S0Rdqi3/F8LzAfqb8GMX
         tuug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:to
         :from:dkim-signature;
        bh=OmF3ZiRo+z3/MUzNtC1wwNg9IEmuUusZSisJNz5BISs=;
        fh=4Im/zVsClL5vNsOVNxL13JxKQeQXiGkzUi6i74ouZfA=;
        b=cZF0i7oqv5tZL/95MvMT9WNF3mxYrMsLmwuQeKGFvSxwieaascj2ntKvs4VERuVimt
         zwwm6TMkU4F4PCwVrJYSEge8ESkAF1NCkCA0S+m26Zqi88OgJHA8BB28TT6+nTTjH2ox
         DnmYvjgR/Bh3mZ7yOsUb1lOuSYxc8kPRE8uw7hHWdIvAAk+S3VDB8WulWeDEfIGthkIa
         XnEMksYp+ye+8DyzpAbeZYPNgzK2uSIg8cTic7DnNvgslBOjlJtjqP1plSLgLnMCA51q
         jI5Ij8041ls0znziT9On3L9wdTa6ZPiT0P76VeftjDX51V/RQVtWd6yfHUdNUjYBwVe0
         TVlQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="ZeaMrS/9";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-433797053e9si5119965ab.0.2025.11.10.08.36.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:36:42 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id 98e67ed59e1d1-3439e1b6f72so1141698a91.2
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:36:42 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWexXDOVVU4Rl/vkbxkRG/9NEeY24nVMus8kKMuoPp0blLJloVmDRNYlxPf6HCYuMAdiCKBEWPd12k=@googlegroups.com
X-Gm-Gg: ASbGncsAGgs4jA3rJ87jk9MIewtakE8Wr64bm5ML5EgvJyT4ynB44QGNluRMn/y1SzG
	PnivEh9T5GKnN4WfwPARPK2hd3gPQMXjHu/wj2qaj8LWesSYvBC8yZifLCNQX7vz4jYiQWmNPxA
	LaPQKFRUgOVYetkxvKnPFJA09j+SyBG34SZ3QbN1oUtayeiCNbhsLTTnJNI6mw0uWJPHgcutlFg
	lS8hzK2vr/yg+dkUzneh9/0R2zY8HBekH3T3bAo7oquyeSZP16//K53CK4C76prhdMxNKMWMubz
	FbcomelqnML28l73ok/hOYPSQqW1Sx1a5BPEYygMaqdYK/D0gQx490H6t4h3VjwQwd0j+XktIlk
	5oTPaVpEsYuK0Mr+pboOnW+xtVySmH0ioH9ceFGA5kttTzx19RsnfzC6Sf6mLfJcasbv2j3KtNd
	MHUS8xb77oBTQ=
X-Received: by 2002:a17:90b:2d0d:b0:340:bfcd:6af8 with SMTP id 98e67ed59e1d1-3436cb73a21mr10515621a91.4.1762792601393;
        Mon, 10 Nov 2025 08:36:41 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-ba8faf1dc06sm13055990a12.16.2025.11.10.08.36.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:36:40 -0800 (PST)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	"Masami Hiramatsu (Google)" <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Alice Ryhl <aliceryhl@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Ben Segall <bsegall@google.com>,
	Bill Wendling <morbo@google.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	David Kaplan <david.kaplan@amd.com>,
	"David S. Miller" <davem@davemloft.net>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Ian Rogers <irogers@google.com>,
	Ingo Molnar <mingo@redhat.com>,
	James Clark <james.clark@linaro.org>,
	Jinchao Wang <wangjinchao600@gmail.com>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Juri Lelli <juri.lelli@redhat.com>,
	Justin Stitt <justinstitt@google.com>,
	kasan-dev@googlegroups.com,
	Kees Cook <kees@kernel.org>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	"Liang Kan" <kan.liang@linux.intel.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	linux-arm-kernel@lists.infradead.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-perf-users@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Mel Gorman <mgorman@suse.de>,
	Michal Hocko <mhocko@suse.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nam Cao <namcao@linutronix.de>,
	Namhyung Kim <namhyung@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Naveen N Rao <naveen@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Rong Xu <xur@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	=?UTF-8?q?Thomas=20Wei=C3=9Fschuh?= <thomas.weissschuh@linutronix.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Will Deacon <will@kernel.org>,
	workflows@vger.kernel.org,
	x86@kernel.org
Subject: [PATCH v8 00/27] mm/ksw: Introduce KStackWatch debugging tool
Date: Tue, 11 Nov 2025 00:35:55 +0800
Message-ID: <20251110163634.3686676-1-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="ZeaMrS/9";       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Earlier this year, I debugged a stack corruption panic that revealed the
limitations of existing debugging tools. The bug persisted for 739 days
before being fixed (CVE-2025-22036), and my reproduction scenario
differed from the CVE report=E2=80=94highlighting how unpredictably these b=
ugs
manifest.

The panic call trace:

<4>[89318.486564]  <TASK>
<4>[89318.486570]  dump_stack_lvl+0x48/0x70
<4>[89318.486580]  dump_stack+0x10/0x20
<4>[89318.486586]  panic+0x345/0x3a0
<4>[89318.486596]  ? __blk_flush_plug+0x121/0x130
<4>[89318.486603]  __stack_chk_fail+0x14/0x20
<4>[89318.486612]  __blk_flush_plug+0x121/0x130
...27 other frames omitted
<4>[89318.486824]  ksys_read+0x6b/0xf0
<4>[89318.486829]  __x64_sys_read+0x19/0x30
<4>[89318.486834]  x64_sys_call+0x1ada/0x25c0
<4>[89318.486840]  do_syscall_64+0x7f/0x180
<4>[89318.486847]  ? exc_page_fault+0x94/0x1b0
<4>[89318.486855]  entry_SYSCALL_64_after_hwframe+0x73/0x7b
<4>[89318.486866]  </TASK>

Initially, I enabled KASAN, but the bug did not reproduce. Reviewing the
code in __blk_flush_plug(), I found it difficult to trace all logic
paths due to indirect function calls through function pointers.

I added canary-locating code to obtain the canary address and value,
then inserted extensive debugging code to track canary modifications. I
observed the canary being corrupted between two unrelated assignments,
indicating corruption by another thread=E2=80=94a silent stack corruption b=
ug.

I then added hardware breakpoint (hwbp) code, but still failed to catch
the corruption. After adding PID filters, function parameter filters,
and depth filters, I discovered the corruption occurred in
end_buffer_read_sync() via atomic_dec(&bh->b_count), where bh->b_count
overlapped with __blk_flush_plug()'s canary address. Tracing the bh
lifecycle revealed the root cause in exfat_get_block()=E2=80=94a function n=
ot
even present in the panic call trace.

This bug was later assigned CVE-2025-22036
(https://lore.kernel.org/all/2025041658-CVE-2025-22036-6469@gregkh/).
The vulnerability was introduced in commit 11a347fb6cef (March 13, 2023)
and fixed in commit 1bb7ff4204b6 (March 21, 2025)=E2=80=94persisting for 73=
9
days. Notably, my reproduction scenario differed significantly from that
described in the CVE report, highlighting how these bugs manifest
unpredictably across different workloads.

This experience revealed how notoriously difficult stack corruption bugs
are to debug: KASAN cannot reproduce them, call traces are misleading,
and the actual culprit often lies outside the visible call chain. Manual
instrumentation with hardware breakpoints and filters was effective but
extremely time-consuming.

This motivated KStackWatch: automating the debugging workflow I manually
performed, making hardware breakpoint-based stack monitoring readily
available to all kernel developers facing similar issues.

KStackWatch is a lightweight debugging tool to detect kernel stack
corruption in real time. It installs a hardware breakpoint (watchpoint)
at a function's specified offset using kprobe.post_handler and removes
it in fprobe.exit_handler. This covers the full execution window and
reports corruption immediately with time, location, and a call stack.

Beyond automating proven debugging workflows, KStackWatch incorporates
robust engineering to handle complex scenarios like context switches,
recursion, and concurrent execution, making it suitable for broad
debugging use cases.

## Key Features

* Immediate and precise stack corruption detection
* Support for multiple concurrent watchpoints with configurable limits
* Lockless design, usable in any context
* Depth filter for recursive calls
* Low overhead of memory and CPU
* Flexible debugfs configuration with key=3Dval syntax
* Architecture support: x86_64 and arm64
* Auto-canary detection to simplify configuration

## Architecture Support

KStackWatch currently supports x86_64 and arm64. The design is
architecture-agnostic, requiring only:
* Hardware breakpoint modification in atomic context

Arm64 support required only ~20 lines of code(patch 18,19). Future ports
to other architectures (e.g., riscv) should be straightforward for
developers familiar with their hardware breakpoint implementations.

## Performance Impact

Runtime overhead was measured on Intel Core Ultra 5 125H @ 3 GHz running
kernel 6.17, using test4 from patch 24:

     Type                 |   Time (ns)  |  Cycles
     -----------------------------------------------
     entry with watch     |     10892    |   32620
     entry without watch  |       159    |     466
     exit  with watch     |     12541    |   37556
     exit  without watch  |       124    |     369

Comparation with other scenarios:

Mode                        |  CPU Overhead (add)  |  Memory Overhead (add)
----------------------------+----------------------+-----------------------=
--
Compiled but not enabled    |  None                |  ~20 B per task
Enabled, no function hit    |  None                |  ~few hundred B
Func hit, HWBP not toggled  |  ~140 ns per call    |  None
Func hit, HWBP toggled      |  ~11=E2=80=9312 =C2=B5s per call  |  None

The overhead is minimal, making KStackWatch suitable for production
environments where stack corruption is suspected but kernel rebuilds are no=
t feasible.

## Validation

To validate the approach, this series includes a self-contained test module=
 and
a companion shell script. The module provides several test cases covering
scenarios such as canary overflow, recursive depth tracking, multi-threaded
silent corruption, retaddr overwriten. A detailed workflow example and usag=
e
guide are provided in the documentation (patch 26).

While KStackWatch itself is a new tool and has not yet discovered productio=
n
bugs, it automates the exact methodology that I used to manually uncover
CVE-2025-22036. The tool is designed to make this powerful debugging techni=
que
readily available to kernel developers, enabling them to efficiently detect=
 and
diagnose similar stack corruption issues in the future.

---
Patches 1=E2=80=933 of this series are also used in the wprobe work propose=
d by
Masami Hiramatsu, so there may be some overlap between our patches.
Patch 3 comes directly from Masami Hiramatsu (thanks).
---

Changelog:
v8:
* Add arm64 support
  * Implement hwbp_reinstall() for arm64.
  * Use single-step mode as default in ksw_watch_handler().
* Add latency measurements for probe handlers.
* Update configuration options
  * Introduce explicit auto_canary parameter.
  * Default watch_len to sizeof(unsigned long) when zero.
  * Replace panic_on_catch with panic_hit ksw_config option.
* Enable KStackWatch in non-debug builds.
* Limit canary search range to the current stack frame when possible.
* Add automatic architecture detection for test parameters.
* Move kstackwatch.h to include/linux/.
* Relocate Kconfig fragments to the kstackwatch/ directory.

v7:
  https://lore.kernel.org/all/20251009105650.168917-1-wangjinchao600@gmail.=
com/
  * Fix maintainer entry to alphabetical position

v6:
  https://lore.kernel.org/all/20250930024402.1043776-1-wangjinchao600@gmail=
.com/
  * Replace procfs with debugfs interface
  * Fix typos

v5:
  https://lore.kernel.org/all/20250924115124.194940-1-wangjinchao600@gmail.=
com/
  * Support key=3Dvalue input format
  * Support multiple watchpoints
  * Support watching instruction inside loop
  * Support recursion depth tracking with generation
  * Ignore triggers from fprobe trampoline
  * Split watch_on into watch_get and watch_on to fail fast
  * Handle ksw_stack_prepare_watch error
  * Rewrite silent corruption test
  * Add multiple watchpoints test
  * Add an example in documentation

v4:
  https://lore.kernel.org/all/20250912101145.465708-1-wangjinchao600@gmail.=
com/
  * Solve the lockdep issues with:
    * per-task KStackWatch context to track depth
    * atomic flag to protect watched_addr
  * Use refactored version of arch_reinstall_hw_breakpoint

v3:
  https://lore.kernel.org/all/20250910052335.1151048-1-wangjinchao600@gmail=
.com/
  * Use modify_wide_hw_breakpoint_local() (from Masami)
  * Add atomic flag to restrict /proc/kstackwatch to a single opener
  * Protect stack probe with an atomic PID flag
  * Handle CPU hotplug for watchpoints
  * Add preempt_disable/enable in ksw_watch_on_local_cpu()
  * Introduce const struct ksw_config *ksw_get_config(void) and use it
  * Switch to global watch_attr, remove struct watch_info
  * Validate local_var_len in parser()
  * Handle case when canary is not found
  * Use dump_stack() instead of show_regs() to allow module build
  * Reduce logging and comments
  * Format logs with KBUILD_MODNAME
  * Remove unused headers
  * Add new document

v2:
  https://lore.kernel.org/all/20250904002126.1514566-1-wangjinchao600@gmail=
.com/
  * Make hardware breakpoint and stack operations
    architecture-independent.

v1:
  https://lore.kernel.org/all/20250828073311.1116593-1-wangjinchao600@gmail=
.com/
  * Replaced kretprobe with fprobe for function exit hooking, as
    suggested by Masami Hiramatsu
  * Introduced per-task depth logic to track recursion across scheduling
  * Removed the use of workqueue for a more efficient corruption check
  * Reordered patches for better logical flow
  * Simplified and improved commit messages throughout the series
  * Removed initial archcheck which should be improved later
  * Replaced the multiple-thread test with silent corruption test
  * Split self-tests into a separate patch to improve clarity.
  * Added a new entry for KStackWatch to the MAINTAINERS file.
---

Jinchao Wang (26):
  x86/hw_breakpoint: Unify breakpoint install/uninstall
  x86/hw_breakpoint: Add arch_reinstall_hw_breakpoint
  mm/ksw: add build system support
  mm/ksw: add ksw_config struct and parser
  mm/ksw: add singleton debugfs interface
  mm/ksw: add HWBP pre-allocation
  mm/ksw: Add atomic watchpoint management api
  mm/ksw: ignore false positives from exit trampolines
  mm/ksw: support CPU hotplug
  sched/ksw: add per-task context
  mm/ksw: add entry kprobe and exit fprobe management
  mm/ksw: add per-task ctx tracking
  mm/ksw: resolve stack watch addr and len
  mm/ksw: limit canary search to current stack frame
  mm/ksw: manage probe and HWBP lifecycle via procfs
  mm/ksw: add KSTACKWATCH_PROFILING to measure probe cost
  arm64/hw_breakpoint: Add arch_reinstall_hw_breakpoint
  arm64/hwbp/ksw: integrate KStackWatch handler support
  mm/ksw: add self-debug helpers
  mm/ksw: add test module
  mm/ksw: add stack overflow test
  mm/ksw: add recursive depth test
  mm/ksw: add multi-thread corruption test cases
  tools/ksw: add arch-specific test script
  docs: add KStackWatch document
  MAINTAINERS: add entry for KStackWatch

Masami Hiramatsu (Google) (1):
  HWBP: Add modify_wide_hw_breakpoint_local() API

 Documentation/dev-tools/index.rst       |   1 +
 Documentation/dev-tools/kstackwatch.rst | 377 +++++++++++++++++++++
 MAINTAINERS                             |   9 +
 arch/Kconfig                            |  10 +
 arch/arm64/Kconfig                      |   1 +
 arch/arm64/include/asm/hw_breakpoint.h  |   1 +
 arch/arm64/kernel/hw_breakpoint.c       |  12 +
 arch/x86/Kconfig                        |   1 +
 arch/x86/include/asm/hw_breakpoint.h    |   8 +
 arch/x86/kernel/hw_breakpoint.c         | 148 +++++----
 include/linux/hw_breakpoint.h           |   6 +
 include/linux/kstackwatch.h             |  68 ++++
 include/linux/kstackwatch_types.h       |  14 +
 include/linux/sched.h                   |   5 +
 kernel/events/hw_breakpoint.c           |  37 +++
 mm/Kconfig                              |   1 +
 mm/Makefile                             |   1 +
 mm/kstackwatch/Kconfig                  |  34 ++
 mm/kstackwatch/Makefile                 |   8 +
 mm/kstackwatch/kernel.c                 | 295 +++++++++++++++++
 mm/kstackwatch/stack.c                  | 416 ++++++++++++++++++++++++
 mm/kstackwatch/test.c                   | 345 ++++++++++++++++++++
 mm/kstackwatch/watch.c                  | 309 ++++++++++++++++++
 tools/kstackwatch/kstackwatch_test.sh   |  85 +++++
 24 files changed, 2130 insertions(+), 62 deletions(-)
 create mode 100644 Documentation/dev-tools/kstackwatch.rst
 create mode 100644 include/linux/kstackwatch.h
 create mode 100644 include/linux/kstackwatch_types.h
 create mode 100644 mm/kstackwatch/Kconfig
 create mode 100644 mm/kstackwatch/Makefile
 create mode 100644 mm/kstackwatch/kernel.c
 create mode 100644 mm/kstackwatch/stack.c
 create mode 100644 mm/kstackwatch/test.c
 create mode 100644 mm/kstackwatch/watch.c
 create mode 100755 tools/kstackwatch/kstackwatch_test.sh

-*=20
2.43.0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0251110163634.3686676-1-wangjinchao600%40gmail.com.
