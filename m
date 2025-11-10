Return-Path: <kasan-dev+bncBD53XBUFWQDBBQ5JZDEAMGQELPA3FAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id A1C23C47FC8
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:37:25 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-340bc4ef67fsf3746868a91.3
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:37:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792644; cv=pass;
        d=google.com; s=arc-20240605;
        b=MooTaobl0FXvA+mSNKR/GIpzaplw/GMFhAbYyAsaCLhU6HRESmRS8Oz+c46OXPISiS
         djrXN34EM4lM893Ri32+yb4yeHxKGkqpowmmF5BAW+GzQWTquhh4PG4FPCOaf2SYKrTz
         6HbRiQZ8EQL5DkovLnIgpEXvY9AAQN3Ljr4Y0Z4qkLBrS1FrDcVIfweOEoUW/GLTo62A
         SNAJKjC/12VvIyAUzdIXxzMkzByDRTp9ZWCV6J7zJv5P3FQNqkMgcCXa/Vkj6Eew1Eiy
         Bnuxc8keURhcguKRZ1Q4Rx/TC7QhEfG4k/2RV+G8C9LYMZIA2uEf9vMMV3YTFMCRASbo
         6bLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=31yOFXeumihApTFZKhU8bFKSe/9dhY/Rt+fMolaaM+w=;
        fh=YA65IJI25htdY7DsfHLy8uX4Vvv14G4td8eVCKZj3hY=;
        b=jFZCClWW+AhAGroQjtiWBMsqUZfPU8NqUjrh1yBopDW3CiqYU/Kz06Ob5RlmafeHmN
         UDJmw5lm+BtMF12WY9LAZoW/7xhsNbvGqOcT9MB3ziqOQIzM/o8NT9jT9mAkyL5QKbab
         QhO+kNsdlUpGaQwN5I2HBvmoGkYvijblXHrHCRGmQEIb5cSXXZYZEM8HdV2QLLkpR5Dv
         xD3JhIIEtbm+mwXKbOhxpoLbrAr7PL/XUcc/U8zQeC50FRNIu1uW9hUIfRNXIklUF85H
         Ylbb+pH8tOKiE+JM6+bOohJNNlVfyUnvVZU8Bwv1wFHwM6pOkOv3p1EIQ9Ii24yqX0Wz
         v0Gg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NyPftUC6;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792644; x=1763397444; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=31yOFXeumihApTFZKhU8bFKSe/9dhY/Rt+fMolaaM+w=;
        b=jpAFGzmTJkQRIY53+sItMnyqMJypQjLQ1fBCiWixGOntNiEpCWGkw5/tEpnEm+H5xu
         lhW7NqKDtr9NddQvJ2K7AB4HogYTJf3nUERdvzvln3/6pQntUkSYRI3FTjnHmjkWhX50
         JdefWcu8Xt0f+udvPH12Etuh1xUcAhavkiKVsr34+Z93AxfjZdj4X9UuNSNkvBuzEps/
         lxNhAkDTyiNtREq222s0WooSAR1HC4jaLRq4QpXW1WXT2eY4Br4qqx/B2LQkUcwEdye7
         5HQZ7luWVeqv4V7CX5J7fDia1Vxwh7glFK8Mc/5zrGeGkrrHTP2hIQw1jqDkbgE+UUTn
         3iBw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792644; x=1763397444; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=31yOFXeumihApTFZKhU8bFKSe/9dhY/Rt+fMolaaM+w=;
        b=JXfY4slw9eXUN0QdN2hR3FOkMt3FfQqYXzIewfWAzM5ULdZGAdRTyWbeIwt7hLRF2n
         hiuaBvE5FzpOO71aH6jbBLx48TkXb/9mREZxf6mZtqimXzpiEwSPUQ94WVZZpP91Sfj6
         o0ND1Y/FNArbDcMRwBPSVsuSpWWpsdfPRZjso7eM2RpH0vDQwGfY1fr5ywSeqmjuU0vZ
         qQM6UzkZYdj7HdmONbg4ZQvZcaoI8Dfxps1Cj68Vb5wWVXZqgoVhg+p2xgZmH7yOC2zz
         fMbI5esdS2wyM5rFuM3yocrOZULYEVsFyvXmD+w8fFwPs1/Vzzn6WcsBkA9eywl0Mrlp
         5Fqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792644; x=1763397444;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=31yOFXeumihApTFZKhU8bFKSe/9dhY/Rt+fMolaaM+w=;
        b=Zl8zIyanUvLYRuA+H9ONlnTbeyuXRZCONW83X6ue5APgTe28R5fn3QZi7mnHvjF20D
         vVJZ4eHTqztOYMg+eA0ZkahRezGVCwqdAGvjzWEQ4uBAy36vRegzJJQqhx/3BoNRCnE5
         grMZo9aYP1364F6o/5XJKKtFF+ARnvbkbGVtykFhgUUn02dHFup9mDwAziat+Njm1u2v
         a4jyRz6/cwXcLCdsUB4cAjZkvbNLAICbawol9GtBYeOoCTnpMvZ2aFoTgXUjXx13N+mL
         vAwMU7UDa/huk0pr1XJesnYBf83v3uKopZbwJGybTr+C3N6ny59GkFhTbAc7ZWuldDHt
         B7HA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXtroIY5uYFAm9kuzVlUBjwz7NHv6kVuAsLVB2NnM/Zn0OVgd7UmbZNhNQW3oHUiafuR3udQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz4mDqdGWAxrjJGEW9eFm/x06kMZWLeymPQ51dVfyQyIm85m7Ky
	Cq9g2Kxzk1eY7YuyV48t9HLhGeDdIDX9gL07t6b5NrEYp2Gw1pUvJ1Um
X-Google-Smtp-Source: AGHT+IGg3Ojw1tC2DSyKuk3DbiMc6quGUd89z2EwDkpV+/GPJJbwoFup1wmdV68jUmV8IlCEs9+eHA==
X-Received: by 2002:a17:90b:5245:b0:340:2f48:b51a with SMTP id 98e67ed59e1d1-3436cb9ec36mr9727905a91.15.1762792644060;
        Mon, 10 Nov 2025 08:37:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bxBY+Tb0DB5TVn/bsDNOn0hZhVmg1WMz86T/mfWRMihw=="
Received: by 2002:a17:90b:3e84:b0:330:4949:15b5 with SMTP id
 98e67ed59e1d1-341cd2d6162ls5530787a91.1.-pod-prod-07-us; Mon, 10 Nov 2025
 08:37:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX9L2NRxmjDyQT/TF9iHVqlbiPoWFKj80+OeRN+x6Ql+VH81tGKzU3KBnZoojbrrTxBGhG5Z9n+Kx0=@googlegroups.com
X-Received: by 2002:a17:902:d551:b0:267:9931:dbfb with SMTP id d9443c01a7336-297e571801bmr113661205ad.54.1762792642361;
        Mon, 10 Nov 2025 08:37:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792642; cv=none;
        d=google.com; s=arc-20240605;
        b=fF55OdV/13eUFyTTiW9bmz4W/cBKoH+cb0YcDETzEu6rAckGf/SomXKQiXkydd5teU
         iZe7gGiKvE5NlGBFbKzEAb6lqqqIg+5eBZtS6sIDdzg1kTt9URF+uKXj2d2R5jcW5yZY
         a9xn7UB1vnDsxVzgAkcpex1QaPb1hEB21sJkbGyKDPXUQd6mseOHZpd6jrV8Gc8qqqNO
         9D+w4NPxdHuTjMTbFP3fpgqR4F6X4f1Rifl7FkYUxVngPmdsQ52Fpm9M9NIbCGRoADW+
         P3q4/vayi00GYnoIWUu3hiK29/ZIe9xIFfEfcfbtYCq4yMFzH6VFCku1NR2A4H1t6c2m
         J4GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=pLWfzYX4fFMPPLWMDyPb3KZEfyFxyFdWrCERfTSFQ90=;
        fh=5HV+LFL4Gs70m643UxqKbe3skRRxYyElu76FhDcioA4=;
        b=gL2yMPpXx4QH1NKZliUNyo34oGKgGPQ1itn9J9mkKxabCoIAowB7FYvUkbgd1mkExA
         2GqTET60KrVip8XQybWVF62H0dQagLjbfgTgoTzjcTbkxl5ydTN+MJAbSGkpzpwV1+dV
         cP/FNr+rAKAf6oa/FWaoIA3S44mzYsPGxFUFEzGCA1cb8uaXn8oSVoFDztzWPCWeg3X6
         6mafrBlCV0UQb8AWKpshxszm2Xg33m72C1ZOvE1GrVbDwdF6HUc+Qf3VU5QPKqDUH0tM
         2DAbed+SnMbWbXOQokIzrRoQHOnsG2OEO3tlnckI41IM9yKdBygwAOwEz78PzXrLhljI
         PNgA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NyPftUC6;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-298147dc082si2738005ad.7.2025.11.10.08.37.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:37:22 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 41be03b00d2f7-bb2447d11ceso1011898a12.0
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:37:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVfSNy6mh5ZzNnMC0s4BJcNhkQYwSzG3P/iD1GeTEPJKGqaJeXgaAISKEhWsvilEonyWMcUd7iX2lg=@googlegroups.com
X-Gm-Gg: ASbGncsJ1UgLm5LevMn9EKocRwzukSS5wI+c78Jn0vs/D/ejPLtk0ZseIVdl4ZP3qYo
	tH/dJ6+QmuaLwzsLT2F0Em7joyHgX5WQnkf+3pItwCoaBaTQPggsjUjpwuCpmcnIMWW+PzEBxNN
	GysGqrC4PEBLdNBlWmBG2Vk06ZgqH4mv91yYDej2vA1XASQheh+bwilnt1gBp8af9yViGWbfsBe
	hGUQdCoPBU8cqjT4krg/HctiD8ZQDjhLvyPLvEgfX3edJKW9PvMXmPtr7TUHdmyEpx6X2djPBEg
	PFPlsEiMgK99IZOEdYtOIuyB8VewEuPY5pMzl3p3Xr9+Afgc9ktMUFnsmA3pczBA3d3Ih/2peS0
	i7MUngMHCgdKlEqLYKrq6CJjSF1BQRPSpTxszGFbXeZAttAt52gsV0jsGjeO9uiPE20Ekw1QmyO
	YLmtQY0ndumE4=
X-Received: by 2002:a17:902:f791:b0:297:e267:c4c1 with SMTP id d9443c01a7336-297e5718125mr109122315ad.55.1762792641884;
        Mon, 10 Nov 2025 08:37:21 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29651c740b5sm154589925ad.70.2025.11.10.08.37.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:37:21 -0800 (PST)
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
Subject: [PATCH v8 09/27] mm/ksw: ignore false positives from exit trampolines
Date: Tue, 11 Nov 2025 00:36:04 +0800
Message-ID: <20251110163634.3686676-10-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NyPftUC6;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Because trampolines run after the watched function returns but before the
exit_handler is called, and in the original stack frame, so the trampoline
code may overwrite the watched stack address.

These false positives should be ignored. is_ftrace_trampoline() does
not cover all trampolines, so add a local check to handle the remaining
cases.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/watch.c | 38 ++++++++++++++++++++++++++++++++++++++
 1 file changed, 38 insertions(+)

diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index 3817a172dc25..f922b4164be5 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -2,6 +2,7 @@
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
 #include <linux/cpuhotplug.h>
+#include <linux/ftrace.h>
 #include <linux/hw_breakpoint.h>
 #include <linux/irqflags.h>
 #include <linux/kstackwatch.h>
@@ -14,10 +15,46 @@ static DEFINE_MUTEX(all_wp_mutex);
 
 static ulong holder;
 
+#define TRAMPOLINE_NAME "return_to_handler"
+#define TRAMPOLINE_DEPTH 16
+
+/* Resolved once, then reused */
+static unsigned long tramp_start, tramp_end;
+
+static void ksw_watch_resolve_trampoline(void)
+{
+	unsigned long sz, off;
+
+	if (likely(tramp_start && tramp_end))
+		return;
+
+	tramp_start = kallsyms_lookup_name(TRAMPOLINE_NAME);
+	if (tramp_start && kallsyms_lookup_size_offset(tramp_start, &sz, &off))
+		tramp_end = tramp_start + sz;
+}
+
+static bool ksw_watch_in_trampoline(unsigned long ip)
+{
+	if (tramp_start && tramp_end && ip >= tramp_start && ip < tramp_end)
+		return true;
+	return false;
+}
 static void ksw_watch_handler(struct perf_event *bp,
 			      struct perf_sample_data *data,
 			      struct pt_regs *regs)
 {
+	unsigned long entries[TRAMPOLINE_DEPTH];
+	int i, nr = 0;
+
+	nr = stack_trace_save_regs(regs, entries, TRAMPOLINE_DEPTH, 0);
+	for (i = 0; i < nr; i++) {
+		//ignore trampoline
+		if (is_ftrace_trampoline(entries[i]))
+			return;
+		if (ksw_watch_in_trampoline(entries[i]))
+			return;
+	}
+
 	pr_err("========== KStackWatch: Caught stack corruption =======\n");
 	pr_err("config %s\n", ksw_get_config()->user_input);
 	dump_stack();
@@ -164,6 +201,7 @@ int ksw_watch_init(void)
 {
 	int ret;
 
+	ksw_watch_resolve_trampoline();
 	ret = ksw_watch_alloc();
 	if (ret <= 0)
 		return -EBUSY;
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-10-wangjinchao600%40gmail.com.
