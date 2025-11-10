Return-Path: <kasan-dev+bncBD53XBUFWQDBB5FJZDEAMGQEK4PHLFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EA9EC47FFE
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:38:14 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-882485f2984sf34893576d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:38:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792693; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qk+LQbNUToBbDc6iD+LoKL79/PbleHX8OA0DUQhwY+YNjXHqv7Kf2dwHcnP6TE5FC2
         T5qWZ2+tGHKsSDvEXzZ9dbtLVunbC+CLtGd0lKSmhY1SlcsWovoszt60EhqTC8cStCzm
         ZI/mPA2sZvYaddflPmO3ZkzwB4zuXQIR97uwlU0KChExswprcwUi4B/W33Wge0MOzhKr
         doWhAErET3loZhGv8Nq7lZ0LslvQg/IkZDj9F5XUo++AFdodTriTxbTw1ng7PDT4+0K2
         SfF1LwnN/nXE0hmXTLJCwi0YJO+Cm9MOfjhaX6B84LJG9zKzlmd7+QGI5gm/wFn2bA0/
         k/sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=183uVBiNI9KciNZYM7KfEAtn0nVkLm0nBBSRSLPb3bI=;
        fh=96UFHknuxwwo7MCMU3+168mrjpYH/kOAS/6uGJ3ewPM=;
        b=AbpPEbD83taJKbyeOjIfna+vjB3C6f1ZOQihNRnK2qqIlQhsNDicXzcp/FsEtrSy8E
         jthzrtKIx1Wq4/aHLDgsL+18dts3LRiHL9GC1Uahw6caeEZftqHDj8CbWomcDqnodtgv
         7G4nnuL2g2vE1BFTyeAqacLu6Z4i8U7twfcQoITSuHC+/5IEs1yoorcNqhJnu0rKnR7s
         sGNG0ZIVWpmkRH2DEw9q0+FTMTp03Z+spf2zYiqa9yzXAsPwIBjOmhFtDI3DdvJviZNP
         eKBN7sbIpXodkf1lD5eXU56tG7UkjpbPBJRrX5aEpCb+00UMCvqp0QIqy7rudED604ZQ
         z8Hw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=h2uQOu8c;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792693; x=1763397493; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=183uVBiNI9KciNZYM7KfEAtn0nVkLm0nBBSRSLPb3bI=;
        b=QwFkgDwtLcJRLyIMpdm707dheQbzupj/QNQIWOJTkCvDeYcfBPFLXIWfKZHCAq5qzz
         7M7bprsAc+C2xU+0gTzQOkJfXOG7GP+hQRHftRnqKbxR6wZC4xb8Rz5E6l20Fj0/p7W7
         E+Yp/ZsxmUVu2EVBn5CrVWOuhuUimrFWFpoaj2HIj4l369L83LUjbqlXnqyKZq1x1At5
         8TIf0NPU804RIawv5CasJvhaJmCmG1CHyR1RwosAwbVDvyMonvj1qGZGCDJyU3ExMFy0
         nOL/c9qWBMKUhBtnTKNu9yovQU4bY/jsrW6zEjPJfk3jrbzpI+i6eo9apb7XR4zgkmUT
         IYrg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792693; x=1763397493; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=183uVBiNI9KciNZYM7KfEAtn0nVkLm0nBBSRSLPb3bI=;
        b=d26h77U0jb87PJ/NmrFEQVR4mpBC6RoMFQcoDcnGh6ehhZS8+7zhrN55tR9F4KxjgM
         c/gNERf5V1ZlHy0+p67ZQhLTG8rO4MuZ3+KadKMz/EP3ppk3pFZ3SCfMpKtQ+ZDMIqKP
         VsoR3tuTA/V7TybDlwtMxmNNe/8+k0m753QpcERCam9PFN8Pa4rN/BF6TuR8dClzVrA6
         EAwXT0Fe0ribSQ/Ishl63krlqbchU096s8gyvo1pDpBg1pgnM+w//cW7iIk3wfk5nv0n
         M2MnOJ/tRcSZr84hPFrpCiNidyafLqB8z5d234cHprRj5BVl9fz5Hejru0U3K6GP9DP8
         j06Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792693; x=1763397493;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=183uVBiNI9KciNZYM7KfEAtn0nVkLm0nBBSRSLPb3bI=;
        b=iBSHtBt5stlTQ/JSReYslgMfoo0szKY5FLF2nzsuZTDRTVKmj1swUr9h/nAV5W3CoI
         ujHf3wlXBh2MmiGkLV7jthvdlb1XqN63eejBxo0RGzkpysztCbCfl9LMqM4e27Q49x9E
         2pivGNFIcUJAjAMf7oG50OJNK4HVydNnocZyY1ApauXG0P+nTL7aQHs6t5HYXS5GFh/m
         IoJ2GJOXizwbKEKYKLovamxVhEYKrZfqLyj2ILFmUWo/Xz71YERbnt0qKVbBYdNmb7Qa
         YpGx5INAlt0MM+BvURgyhI5bj2e/IeYQCySN5WipjtWlZlZefacPMUSmFPL/Sm49KydC
         9+aA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUo9+QIabrOIHuIVMQdrg/leP7a9cMeHJS80K+n6V4BAWDPv1wv6/hRg3CYzVTAsUl5JedgqQ==@lfdr.de
X-Gm-Message-State: AOJu0YwbN4X718OsSd1cZZUaBI/+W9vMW4934P4jyvWJGwPiBq+ZdymS
	HxgLxgd8VV2RgGtaUYEiVSTP72zYWjcjlKVDeXLGLYZqK/hRBdodAUlT
X-Google-Smtp-Source: AGHT+IHHPd3vnjXVfVImb104BM+KvLbrHRcC+ZyRhSTadLpOa9RIy9S+jJZMoXJQS9kRIbBmb5Wgsg==
X-Received: by 2002:a05:6214:242a:b0:87c:651:da29 with SMTP id 6a1803df08f44-8823866bd9emr117790296d6.35.1762792692867;
        Mon, 10 Nov 2025 08:38:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aW+BzWHfjBvC92LCj9C9JgWnGt7q9kUAaZ8uvXGOAumw=="
Received: by 2002:ad4:5969:0:b0:880:5771:2e16 with SMTP id 6a1803df08f44-8825293b330ls21804116d6.0.-pod-prod-09-us;
 Mon, 10 Nov 2025 08:38:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWCvbXjuBTeB2Av/vyf9CZTPLs7MNI0jlVZmpzyPYz/0ApJQ/UijtsarYqs9Xj006vpznW9dVzlDh8=@googlegroups.com
X-Received: by 2002:a05:6214:f2a:b0:880:4f97:d17b with SMTP id 6a1803df08f44-882385c4948mr101206196d6.19.1762792691620;
        Mon, 10 Nov 2025 08:38:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792691; cv=none;
        d=google.com; s=arc-20240605;
        b=cpcjHpcFz+c6bbRKG0ec7Mf7Y7A2YzcoVPj6cR+BGHpjivGdu8rtCv00Wr70JX4VGL
         E+hoWIBSKHw8UTqRNq/a8sf4xXtubtKTjXEs8U7P2s7zuT+iMLrXeTxhgGwwhnQBYwui
         bdQZjkiQuFpgPx/vdqYtA7apOVJPICNyrJOcBQL3+SHkfe5djPS50z2cIgUanmuU21lq
         m0kI0gH6cWC+tngLwIemlTnbEMjD25A3VZ176CpFirNr/rrbbTgTZnMYaD1CIG3ch5JH
         iphbbCw03rrL63qSwc3gQIBhWV+LUIrOAgH2h6xbHjZG2b2qNgGT8/26PwF0F4WSEIwB
         5KiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=tjEoXPNXhfVJUSFrtIZUZPOp73U+hEWiDpkQ2qC/SvQ=;
        fh=gOaRfAnYDkXsBFv2LCDYuvsnx7j2FFMrmJdoQdOgk4E=;
        b=TT7CT37ugoZ7rBGOiNgDREr3DBt7w6+2w5bBeyZdySVkwCAW6/Z/nxXssDxEQSadgQ
         QB2Os8PbAGiEPATmxNP4R7W8OjXfn71MFTy57MMUX0mYhR0WOkKUgTxZOomB6GdNgs8R
         tcrWo5gX/NqPP5FGOH3z9O13m0MxNZM8+id9HGmS1zw2RHTMcfGivzfR8AA24x4kfHk7
         FpdU7x94iLFfrkOAS2nMsWePrtLj+AkIAx88slKUdnDDT0rP7kSW2aXbi3Eidaj3NDq8
         8HhBKnpJWEEKYcNcUks/SBksKKMsEG4hBwedUDA9d6sO+iD9MttOejxTP8T6+JRF5OBo
         OrDg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=h2uQOu8c;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x533.google.com (mail-pg1-x533.google.com. [2607:f8b0:4864:20::533])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-8823881122asi5342536d6.0.2025.11.10.08.38.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:38:11 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::533 as permitted sender) client-ip=2607:f8b0:4864:20::533;
Received: by mail-pg1-x533.google.com with SMTP id 41be03b00d2f7-b67ae7e76abso1903087a12.3
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:38:11 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVMkzn6c+znqyUVZVIICKvSdPy74XZUHN2ToUsVqlJohuFtBKTNEC4byHXowY9qXxTIxoTsPnCTHUU=@googlegroups.com
X-Gm-Gg: ASbGncscCCVws1zJKa6V57I4PI7DsLVd7eVHu/b7vchwsvBmnmVo2Q+Clp9uchdH93A
	fUbTTFSDHBVrv7HhRUdqi2HOi1HdzSg0tbI2AZv+BvryJK9NrFrOxJMyBE42YPkZu3a5lj32Ti1
	fNQA5qo89nb6Syu304fy0qph/F90vFPPV8LyqJINzCi1tB6Kwc+ApGDjNcZ2gbNfeU0FigCPKF2
	Rf29+CRImKoksSk6u7Z+Nbaao1N0+pYsYhuD9AbqPpFOvmfXyvIB4QHNWxW2QtjSJiRLVJZ5kIB
	iyNhgcPSTcpyo+ytGdRhei4w5e/Fp9/oSsR9oZUH3Dijdpn9HYPbk/df5Rs39BSD5pDJaaqAr2G
	IoAhIWj6mLXCha0XZXSIolhfceSODdJnKA2LtYUzmkdWYVquQy2fdbAfj74QVAeBCnZgE8x2BW6
	mNcuZ52yGOQHA=
X-Received: by 2002:a17:903:244a:b0:25c:8745:4a58 with SMTP id d9443c01a7336-297e53f933cmr112300665ad.3.1762792690825;
        Mon, 10 Nov 2025 08:38:10 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-341d0aee149sm8572006a91.1.2025.11.10.08.38.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:38:10 -0800 (PST)
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
Subject: [PATCH v8 20/27] mm/ksw: add self-debug helpers
Date: Tue, 11 Nov 2025 00:36:15 +0800
Message-ID: <20251110163634.3686676-21-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=h2uQOu8c;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::533 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide two debug helpers:

- ksw_watch_show(): print the current watch target address and length.
- ksw_watch_fire(): intentionally trigger the watchpoint immediately
  by writing to the watched address, useful for testing HWBP behavior.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 include/linux/kstackwatch.h |  2 ++
 mm/kstackwatch/watch.c      | 34 ++++++++++++++++++++++++++++++++++
 2 files changed, 36 insertions(+)

diff --git a/include/linux/kstackwatch.h b/include/linux/kstackwatch.h
index ce3882acc5dc..6daded932ba6 100644
--- a/include/linux/kstackwatch.h
+++ b/include/linux/kstackwatch.h
@@ -60,5 +60,7 @@ void ksw_watch_exit(void);
 int ksw_watch_get(struct ksw_watchpoint **out_wp);
 int ksw_watch_on(struct ksw_watchpoint *wp, ulong watch_addr, u16 watch_len);
 int ksw_watch_off(struct ksw_watchpoint *wp);
+void ksw_watch_show(void);
+void ksw_watch_fire(void);
 
 #endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index c2aa912bf4c4..a298c31848a2 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -273,3 +273,37 @@ void ksw_watch_exit(void)
 {
 	ksw_watch_free();
 }
+
+/* self debug function */
+void ksw_watch_show(void)
+{
+	struct ksw_watchpoint *wp = current->ksw_ctx.wp;
+
+	if (!wp) {
+		pr_info("nothing to show\n");
+		return;
+	}
+
+	pr_info("watch target bp_addr: 0x%llx len:%llu\n", wp->attr.bp_addr,
+		wp->attr.bp_len);
+}
+EXPORT_SYMBOL_GPL(ksw_watch_show);
+
+/* self debug function */
+void ksw_watch_fire(void)
+{
+	struct ksw_watchpoint *wp;
+	char *ptr;
+
+	wp = current->ksw_ctx.wp;
+
+	if (!wp) {
+		pr_info("nothing to fire\n");
+		return;
+	}
+
+	ptr = (char *)wp->attr.bp_addr;
+	pr_warn("watch triggered immediately\n");
+	*ptr = 0x42; // This should trigger immediately for any bp_len
+}
+EXPORT_SYMBOL_GPL(ksw_watch_fire);
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-21-wangjinchao600%40gmail.com.
