Return-Path: <kasan-dev+bncBD53XBUFWQDBBR5JZDEAMGQE3D2DYYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CD7AC47FCE
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:37:29 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-297b35951b7sf55580945ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:37:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792647; cv=pass;
        d=google.com; s=arc-20240605;
        b=JVZql8jgB8uaZdaJy1nKkQG4G27Juk092esdTmd2Z0An1phpU0OJ9AOdyVxIt9SuHO
         zfekgDhqBfKnljNsdlMYI1VB+YmmgNJFQ7rvXqXVtrbX/UwPNawSAe1ikyAXQE35q2U4
         JOlqPCV5dc+qkYjPdCfyxVsrPuERSgRccKuUwHxKPrwmztnPFEP+Cg4PfFw+na6Z3BpX
         AFBQ3V+ScyugCm4Ikj7OxmeMyeiUGDCKYiTGPnJyu0UYfQmaDqAOs+ojmNPiKU8bXe4K
         1Ol2z8VMgg99Nxe6kATqPUEguD/saZef4msRHR6q7pPslMv2B4lVgC1RgvHxKlnt21zm
         hUNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=AMrJlxkpKpJwflHlHmm1nXgEa7hHz/RMFdLsEBnwcYc=;
        fh=5a+eWZuDt68ZsOz+hOzYTi6lWe+iMJG/D0J6QyXE9G4=;
        b=RK8eVDc3GW7Mttvn2N3Rn44G2EMRFpJWOhpTBnc7pYzTCE2+9jyGTKnp2GLJqTNEg8
         JMkyomtn3jZULjOH8npIuz5641Bc3ewuyCkuEICHXuDxEu2pXBhIFNEm1EC8F5Q2xypN
         pu/kXWuABTRcVNc7HzojTa4RTUkSAJVGFo6dHF5t9zUbiQVVRmIfAgGkMa9iZNWRxtB9
         y/gkEbL59/XqEoynijxyRxigfyncrDMV025QbXPZ5ia0YODEdl+fhVRrjp+ze6zYWUqc
         oDQNLezHg2nEHMdysjfqAgJgBKuzvm5VD29c7sS/LCJclKzu9WTvF5TQ+SSxJOCs6sah
         zMHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aTJsvOO+;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792647; x=1763397447; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AMrJlxkpKpJwflHlHmm1nXgEa7hHz/RMFdLsEBnwcYc=;
        b=qv960LfvBi1aARfyadCYP4wmM6T4smletmNnFR5sB4s/Xd00E1IwLshad7oiALSNWv
         SuBP5FN9bD5TqGwZ9J/PH9jOd6/6YR+/RwgDr/qvXoB5KzXAnrJrHeEe+YgNnAR6sruN
         GiOh1v8472FQcGbi0BX7A4Zps1NeOfCiZGaY/QFc9ypS6dAICq1WoXlp+Es/gFUWbqKt
         vrN6mV9xHJ7yJH3ke5kiIDkWfHeoqAhLR0nu2FNO+9jF604bzctek4+dmF+G2n/2J/PU
         UblrLd2bjrrtfxyoDfILk8XlFNOe8S6AYYywVbzxjAfSlhth3lq4B+amGi0TaxNc/w3v
         MqCw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792647; x=1763397447; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=AMrJlxkpKpJwflHlHmm1nXgEa7hHz/RMFdLsEBnwcYc=;
        b=T/5MxxHC1946lGpdGhmy1UOy7O80G9PAZW3yU9NK1XK2NeYWJ1JnM6wLrO6Z+rLAJo
         HSdR8Irv1BvNptX/UHquFZGGdUo6YBnrQhTXUQtut4WeZYpWdA4hwYKjhUHTwpLbkxpN
         AaK7CA/CRPcr0K5l044kpEoLLsN/JESsS/dK093hfBZ+cAUHnvyCasJpgZJNPmarr/FG
         z7WNqgPtDnBaY2khG121SSJ6q6PNWh1HQOIsClvaH0GzFjcNBDgnHjuSKkS4ceKRbWam
         c2UMoZdBzb5r7kSrEGFn3rkU0+/S2GE1vknCvwh0G9r5up6E6wMXp6oNsDF0aADcmEsa
         35Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792647; x=1763397447;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AMrJlxkpKpJwflHlHmm1nXgEa7hHz/RMFdLsEBnwcYc=;
        b=dS+fSf1dn01ev867tA3pj08WmHv2cEGNuDdHrRIIqRY7EynnFJQ2qOkUA3j8C6haWw
         7XO5hPFridxP2cj9aa3752QyoVT5UYKZcP9UP1SB3uFwUrIBxYlLNxHKqN6uJmMASmYX
         l2x2WCX/427cwJrGvU8ejUsnf5ZF47r7v6e65Wlhhrekqwt4B+fB2t/4bU9tX6kfyXgw
         3iz9QWwhDFCO1QEjQYatGZj32ufFoOGnwmK4WCHga+iG4YLbCs86b7THsDRoDg3kUbPN
         liN0vlnKGmlL6dtUPEiyEunmic9QNGy9eC2Lvm/vT51sWLpIuONHAIy9acYV5xxP6Pa/
         H1gA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUFOQwiC1J5BtU0y4cX3QDaFnhkAO2kKz5hSLl7ikwOrnR5zrM31XhDhT+3HfQXwEGN1Swxmw==@lfdr.de
X-Gm-Message-State: AOJu0YydVfMr8f95RXjSyR6GSv9P80Ce46Utz7tk6NSpX9HbgMRyYa8+
	DEX/nDFY4SZpScK9gru+oYW2VfBI2bzook82h0k+pqIjGz2WQ3aqMORq
X-Google-Smtp-Source: AGHT+IHFKl2jGIQtVLkd+y5gw4OgDyaHBj2UskAvbv3DOMvgdPHCp987te0dT3Zq7pFFFERDRu6hyQ==
X-Received: by 2002:a17:902:f70a:b0:295:5dbe:f629 with SMTP id d9443c01a7336-297e540dd62mr88521245ad.8.1762792647488;
        Mon, 10 Nov 2025 08:37:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aHHltz/sou0cp10hTMmvGUE62hbc+xpcB1VhQgYdleTQ=="
Received: by 2002:a17:90b:35c7:b0:343:3877:bfd6 with SMTP id
 98e67ed59e1d1-3433877d330ls4249871a91.2.-pod-prod-05-us; Mon, 10 Nov 2025
 08:37:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXVEIr/pBBs765Zl3EY9zNZgJU/AfRaAuNlLDP8z7MXYBZr8Q4JvWzzLKqp9K3RpvU1c29dVM7/17g=@googlegroups.com
X-Received: by 2002:a17:90b:57e6:b0:32e:528c:60ee with SMTP id 98e67ed59e1d1-3436cbf33e7mr10597752a91.24.1762792646216;
        Mon, 10 Nov 2025 08:37:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792646; cv=none;
        d=google.com; s=arc-20240605;
        b=MQxK7AsM9dOQ+6iujQz3DHqVenojJOUe+Xj6n+8XmioEcoKidC+YUJhQFUzuYRGE8H
         xV/5L3fkfJQVPXY0YTHcFne+viHI3CRB2V5ooRTYRie7ut/D8WSP/XQ7GTkdaU0I7MFi
         xCR/TfqvE894clydrDQ/U+CPAy9qXIwcJRhV4SxO2KcZJD8Cfa1kQeRHbFa1RbOZMT+j
         rYZb4Ni4x46OXiJnCxzs+Ernw66eH/Z1JLtU7huQXD6gZkyD4eNcc4uiorAe5nDvZjxn
         RmVuewP3IJ7jn1QzsRupE4FeWE9/T2taH5npqOyXwTigsTmzdNDXXAXFb9JqRVTOeI5C
         lw9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=NvOciuVeFDrZI28wwbDFkVg+RFkidCZi4q1TH1/mApw=;
        fh=XyuuH1/7qhz/lMyBK7ui5YTypsX8l3jA/3eXjybo9oQ=;
        b=WUt9ZayWhpvvltlwXwDCuPqfq9+Uc8KvN/NTwf7IA7mqBqTci2/ZPZe24vfJ9FcOMH
         Sl/gfWjunMOEQ7ZDI5MGN/tnQjaiLe3xtdPm8NWocd58z+aNk59msnCArujJOncco6gO
         WREjyCQ9NCXjw6LHwbluEufeZEAjBhP2Ux9/G4qKGwk0+bzMg4Yz0METten+ushKeyZU
         hIoen0OB4Rp4/I2Eyi2bXYlx83yMIdhoftVIgeSgUrbe3/fP/0yvCbYl20zqkQf4YUaM
         mX2jfQJyGy1abZXwb6yqV0vGRS75yawwRp4tmTqdis+IzZ4socV8Br0o4FA1QHLyEApX
         UZtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aTJsvOO+;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7b0cb3a3883si294610b3a.3.2025.11.10.08.37.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:37:26 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-297f8c26dc7so15259045ad.2
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:37:26 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXABI/xvsnSxiJD3Vg4+ATb4PZdtyquAF22fLB11DATebPFAB328un/3em+mG7i8bPBTwMXbimpu90=@googlegroups.com
X-Gm-Gg: ASbGncu7BKG13sZF7b1tyWXAFhneqnsDYbj0lM0uDYaabw+xrstuNEScGsb8Nxx0/KV
	Z3zIbcGMmzANQOwhK2JTbBAT2lUCHN+o0pgRPlzVCDT05qmslKM7uFy+So3EutkbYPa4jZvk5Za
	Og8TXWtZcDh0P06YsTi0hlD8s4zJ9yLFIZszMq6pb2mvgxyrYxy7beP/7VX1w0ZKhfRE3Wa6X3K
	3nfzw9D3ZFROpXyJEgVrVn+2gxIQAYV/hvW8bgMt/SPZ6OyOkTPi5AAwlEciPUMuv29r9zdmc39
	LslFscoKHAKkry0jCipQ8yZKvtYXl40AWbvs4pnsAPrz+kEYuNsO0nQcb1ZL1smNDXqPOBksviD
	SdG6oVB8jlqTh4E+/IvsPGRAoBo43bCfbAM5DI4PaYX80cSyHqt2z3Mv/iHVNxBjEVlhXQkKxZy
	Bt0skRVatjhnM=
X-Received: by 2002:a17:902:da4b:b0:27e:f018:d2fb with SMTP id d9443c01a7336-297e540dbf8mr108586355ad.6.1762792645676;
        Mon, 10 Nov 2025 08:37:25 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29650c5ce87sm150078775ad.29.2025.11.10.08.37.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:37:25 -0800 (PST)
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
Subject: [PATCH v8 10/27] mm/ksw: support CPU hotplug
Date: Tue, 11 Nov 2025 00:36:05 +0800
Message-ID: <20251110163634.3686676-11-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=aTJsvOO+;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Register CPU online/offline callbacks via cpuhp_setup_state_nocalls()
so stack watches are installed/removed dynamically as CPUs come online
or go offline.

When a new CPU comes online, register a hardware breakpoint for the holder,
avoiding races with watch_on()/watch_off() that may run on another CPU. The
watch address will be updated the next time watch_on() is called.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/watch.c | 52 ++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 52 insertions(+)

diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index f922b4164be5..99184f63d7e3 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -85,6 +85,48 @@ static void ksw_watch_on_local_cpu(void *info)
 	WARN(ret, "fail to reinstall HWBP on CPU%d ret %d", cpu, ret);
 }
 
+static int ksw_watch_cpu_online(unsigned int cpu)
+{
+	struct perf_event_attr attr;
+	struct ksw_watchpoint *wp;
+	call_single_data_t *csd;
+	struct perf_event *bp;
+
+	mutex_lock(&all_wp_mutex);
+	list_for_each_entry(wp, &all_wp_list, list) {
+		attr = wp->attr;
+		attr.bp_addr = (u64)&holder;
+		bp = perf_event_create_kernel_counter(&attr, cpu, NULL,
+						      ksw_watch_handler, wp);
+		if (IS_ERR(bp)) {
+			pr_warn("%s failed to create watch on CPU %d: %ld\n",
+				__func__, cpu, PTR_ERR(bp));
+			continue;
+		}
+
+		per_cpu(*wp->event, cpu) = bp;
+		csd = per_cpu_ptr(wp->csd, cpu);
+		INIT_CSD(csd, ksw_watch_on_local_cpu, wp);
+	}
+	mutex_unlock(&all_wp_mutex);
+	return 0;
+}
+
+static int ksw_watch_cpu_offline(unsigned int cpu)
+{
+	struct ksw_watchpoint *wp;
+	struct perf_event *bp;
+
+	mutex_lock(&all_wp_mutex);
+	list_for_each_entry(wp, &all_wp_list, list) {
+		bp = per_cpu(*wp->event, cpu);
+		if (bp)
+			unregister_hw_breakpoint(bp);
+	}
+	mutex_unlock(&all_wp_mutex);
+	return 0;
+}
+
 static void ksw_watch_update(struct ksw_watchpoint *wp, ulong addr, u16 len)
 {
 	call_single_data_t *csd;
@@ -206,6 +248,16 @@ int ksw_watch_init(void)
 	if (ret <= 0)
 		return -EBUSY;
 
+	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
+					"kstackwatch:online",
+					ksw_watch_cpu_online,
+					ksw_watch_cpu_offline);
+	if (ret < 0) {
+		ksw_watch_free();
+		pr_err("Failed to register CPU hotplug notifier\n");
+		return ret;
+	}
+
 	return 0;
 }
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-11-wangjinchao600%40gmail.com.
