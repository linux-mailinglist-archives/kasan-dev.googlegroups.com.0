Return-Path: <kasan-dev+bncBD53XBUFWQDBBFFKZDEAMGQEKM6MZOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id C6D48C48030
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:38:45 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-4330bc0373bsf26378625ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:38:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792724; cv=pass;
        d=google.com; s=arc-20240605;
        b=QpiviyH/gDpHx0QBOaSbkrmpgEL10xLv7B69J4eUX/GCITYQh+5JglxT2ul/DfjPXS
         Gu9LAYvxkJUXDpWcfyGQ1lwH+Onc7Y6Qs48sTSv/yiWeoKReXJuWcH5Law9wKwe2dQQ7
         rgh4BRCbGmp0rj8uu8n3W0Zk7oVxGQVC7K2dlvauy7osvGF6JpK10qR34abis4OgHlS0
         qm6Oy61ZXu+BKyoC9DTLWYdygFzQ0mylHXquUOhLScBOICQKoo2gSLbWwDLYq/qS9Mqz
         CIWtRQWb/2CT/tKEj+RTr9oexBVfMSr0MI5S5Gj1lpPpdNjELO1BpwczKbp+KSY/Y5k5
         L7FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=HurBJknjr3jksBuqkuN6ndUwEe1ML4tmeXfHeNKLUh8=;
        fh=Wrp4uiEO0dULHPDl4mekfu9QklVp1qq6TpSP4O0hARE=;
        b=KSZ/COpAzC6jVAdbRNHEeG/p+nzEXtb7hmVQ6hTdWRLDLWgfvIP5tCuze8/UCjBzbo
         NDqnBAK4Wp88HWcz9ekjBHd+l/NVcgflyohhmVsXwq1cISCr/4qLDu3YNEvuFsammp8c
         qm/I4/PcXkH7YRjvJb7F5PrUEAAUbLA0zWxOl8oUlIwmA5WjuUl8us6K5hGUx1v5iPB1
         w5Uu0PDQzGM/ChJSaYp/sM3Xumojb/mT+bm1Izg8JShHEouXX7EX93q3OJVLYhN1jQxQ
         llCZoTbmWQk+4rVtM9i6rerA3taJg9HHbhOwQ+HuDJnKUS524Hd6xeRNMbuLB+weGPqE
         iaLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mySbK+hk;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792724; x=1763397524; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HurBJknjr3jksBuqkuN6ndUwEe1ML4tmeXfHeNKLUh8=;
        b=kSxar+ghn425vgCuWgq7ILQReH6uamj8Lkwq4afQWwyX/ViA0FSzSR/dmEp2jfVXEO
         aO9Wgrpie6PNuyT2v9/XhV4M4/0b4w0IiJoRjkWkjj4fuWwb3TYFhwvMCh9IPuTo/HnC
         X076+Rrv1Q6U6UBf/cBgjky7epNmTpwLFq2nrEJBcQ2thUqLev/klrBvxREdypT2bfh2
         bHZ2jPojEdyqqYLSxVYHvEEpokFjts6NkS/65wZaL4zdyXPj5Bd35MfkJ7rIQHqnkzqJ
         G8CNUhVeh96h5SWB0uG3Y6jiHJAyip5a8232369m7wj5v3sxc+gplDi7SnVBQSfcUlwY
         RWhA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792724; x=1763397524; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=HurBJknjr3jksBuqkuN6ndUwEe1ML4tmeXfHeNKLUh8=;
        b=Zaa7bTYi6gc6j0ObMRVhVjGM3c2pGMW/B23iYVxvlQrbJDSAGYeiY3lszpfUjJlh2S
         NNex4lVlBYUXJvDxzWcqV95Loo2hNvYs1a0CwQF0gaMAv4z1psgdlvsvNf2j6co0NQSe
         y3K93kKEtZmqTLHLGCX45p3xBZHiqPO08NvAWTc892/Ej9J4FmFoqvsNUn9jx+lebWD4
         39lrITVVZPDwDOv/gA0UeqtCDGFSbLnGQl/70KZhbgGicpdWAeyoWoi20owtmFMk8lrl
         /l3cYQMrG+zEQmRoGE45BEsYzXCQ3njuIdn/QSsFyNPqPtJlF7AjarZ8715mUT26aMEB
         zeWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792724; x=1763397524;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HurBJknjr3jksBuqkuN6ndUwEe1ML4tmeXfHeNKLUh8=;
        b=psQMh904AiZ4ha6TmN5w1bcZwLpl0Uw1zzOugoZvHzJk/J0ec7MyvLCn9qjU5WmzAj
         1NW0s7/jmCGmymCmD3hbrLqtfeOtbtlaNQxYQSXeWS5ZCvR3ALgIX/rGiDCbl8BrhMRE
         EhN9GmtmrODUWZns9zPHRJGDUUV1SJRTYxDIGMmOROM8As6weWk0VZHpp2e9jL/t+Nzy
         7uxDAIT7waN0g5Ri4Ns/Nm4/qBZdYEBsFSMYz/kedh6kJJ1Jv46fPL8urb+UJioNqZu6
         bH/9QUde+k1fVCN4vRx6fG+PsK88MGeoW39asSkmBr9MQXhzsf16xNXDBbbAO/yUV/4l
         Fvcg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXYRfJAbiXSFcIDIeSJz/1NJ3GGR4K3x9mF1dKvyiSwHJB/kre4tVoEzrXT3dG6PxttqE7vwQ==@lfdr.de
X-Gm-Message-State: AOJu0YwCMraFElmkOnHNtU8WEZJ6I9h/XFn9H90TZMyCLvICDkPv5OnZ
	YJPftvjxBFIDATAJJjBPUSIUPRvY98Ns3gT0ImM6aR//KVzu9oVIrZlH
X-Google-Smtp-Source: AGHT+IFWJpriYaQ/Xjkc8rvwLCTPLqDtuSO7yrSRMt9CotFaS4TWgSvz1ceJhMtKi0q8noEcZDsC0A==
X-Received: by 2002:a05:6e02:348b:b0:433:7896:3e51 with SMTP id e9e14a558f8ab-433789648b9mr100582555ab.2.1762792724305;
        Mon, 10 Nov 2025 08:38:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bdTtkDASJvG/+aXi5vrwJ1s0xDhgcnFQ0jCW9oth5rug=="
Received: by 2002:a05:6e02:4412:b0:433:2dd3:38e0 with SMTP id
 e9e14a558f8ab-4337ab3d10bls8236675ab.2.-pod-prod-09-us; Mon, 10 Nov 2025
 08:38:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWjiAUbz1ryl6kHTrpaZkl22ZkC2Y82e3A3Amf5OhoJreRX+V90WyrkXhfaw7QT9bdr0siiHUe5G8k=@googlegroups.com
X-Received: by 2002:a05:6e02:2167:b0:433:4f43:231e with SMTP id e9e14a558f8ab-43367dca1d3mr124734515ab.4.1762792723480;
        Mon, 10 Nov 2025 08:38:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792723; cv=none;
        d=google.com; s=arc-20240605;
        b=SIiQadV1bcB/d6HS+RXrf83sGWlCuuoGZ8js11nnIdPaQVkBy/ncYCkg/1T+GVhusi
         8/l0qeXObFcXpprgu0glUWWx7xetNkp7RJ14/YVueWLqMNJxgaXXWmKnR5r7HiFOcHP5
         gWdMf5iv3+YaibGcE3XHB0dUbRpgxLCIJ0B40m5jtlB2OffIYJ/is6aNd82S0f910PBM
         Og5oq0j3pQs8RYfsQZcVjq+jHY3L304bp2FkkQxVfSxAlrxKlZkgRtl1yyJ8uOmAbyDe
         gbpXlEQ1z0hBseulveWmajEjldmC2bifKGWta+qOmmY3eonZ28U3FrScVOilgeWoMbOm
         uFvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=3UfdW5vQJBbw1wKbWsFdhhHcBKlPZrTKHywEKgKhNPc=;
        fh=Fez+hiwgF/55r6eg9zWMugdg1CITk7I4ml4MZoSOVIU=;
        b=Mf5HIvykpiQfBMOvoWiugEkxIbV6BLYSXN1f5ygKheSmDuaEZdQVQ+T0lZ8fig106Q
         iAxQZPWaC/Px4OFYUrW+cEGUboJGf9GIeqHXlpTkZkaNKRZxzVsjauZ6ysEb/n+O0Xlb
         U2vn5asevkRRmg+wF+h/V92ZiE0pkfD4pAiOITrtMOqwJAhlU88uxmVOuD0lgXD9qkiy
         amZkHFqt8iUUjPbZJ6DZreDIxWL3lhlVsuTj9mMc7iRcwPDu+0pK2IUYuPgZQnrIZVSN
         YjdlGmw8F0IkrMkAhut6pfqiBsMVqSukqk9Va/2T+nyE8KT5ZTl4vuznofjANp6+Wsxx
         n1Fg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mySbK+hk;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-4334f460776si5303985ab.1.2025.11.10.08.38.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:38:43 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id 98e67ed59e1d1-3418ac74bffso2286869a91.1
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:38:43 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX/PVR6CDJ3PdS8kVMgG+0pXHtUTmsNIlPJTqXfs3WLHHASWaNdCz+KgbZAbEvIRJwER8g/TCAqaJA=@googlegroups.com
X-Gm-Gg: ASbGncvwLaBHxzFCmg9jhA492t3pfK4Xo1khV2DrrIOMoQjXPmc8oaVOb2tl6MGD7D+
	pWR96sdRmR+3Z88HUyieYKL45EgBbYnwV3qSDP4JNmNBpqkeTC78vthYe8Wiyn2VBig/1wyBCiK
	2UbXTvxjgVh72WXu9eAd67L4EjjRMTnBrAXoKpczcUosGKM0vXjkABPpOucXID1HHQD/QeI8QNX
	1bxvVZkcmrsMeUWKd4Mb9AcsQYa77XncFMbx1icxhb87P+D3ZaOsE1k7jsHn8NMA17eg5ZsqP+N
	ywKYS1lui1AZIYY32t/rGKrAg4QvGsLBaHcWr+rTldJ7xpgwZ5IUDnAyQMhxRCtblylGGMtgeL9
	oLv6ZGE27B5YnANq4LXURGfFQpUjMAmypT2msjYuyTRnzQ89ysEYErpg0KsFTqpbryfnZZGGRBm
	HohiWbVvNkvenCFmAhbMYdqg==
X-Received: by 2002:a17:90b:42:b0:340:7b2e:64cc with SMTP id 98e67ed59e1d1-3436cb91daamr9486479a91.15.1762792722638;
        Mon, 10 Nov 2025 08:38:42 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7b0c963613esm12684061b3a.1.2025.11.10.08.38.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:38:42 -0800 (PST)
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
Subject: [PATCH v8 27/27] MAINTAINERS: add entry for KStackWatch
Date: Tue, 11 Nov 2025 00:36:22 +0800
Message-ID: <20251110163634.3686676-28-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=mySbK+hk;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Add a maintainer entry for Kernel Stack Watch.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 MAINTAINERS | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index ddecf1ef3bed..9757775de515 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13615,6 +13615,15 @@ F:	Documentation/filesystems/smb/ksmbd.rst
 F:	fs/smb/common/
 F:	fs/smb/server/
 
+KERNEL STACK WATCH
+M:	Jinchao Wang <wangjinchao600@gmail.com>
+S:	Maintained
+F:	Documentation/dev-tools/kstackwatch.rst
+F:	include/linux/kstackwatch.h
+F:	include/linux/kstackwatch_types.h
+F:	mm/kstackwatch/
+F:	tools/kstackwatch/
+
 KERNEL UNIT TESTING FRAMEWORK (KUnit)
 M:	Brendan Higgins <brendan.higgins@linux.dev>
 M:	David Gow <davidgow@google.com>
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-28-wangjinchao600%40gmail.com.
