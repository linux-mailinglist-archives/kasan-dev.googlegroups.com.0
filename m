Return-Path: <kasan-dev+bncBD53XBUFWQDBBX4I5XDAMGQE4CTGNNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D375BAB0F3
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:45:53 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-2711a55da20sf43494975ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:45:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200351; cv=pass;
        d=google.com; s=arc-20240605;
        b=H8Zz828qwizkJ5VvHZLXg7ptMQOAB90mSzDMPTxlc+yE0VpaU7TGPHjmNNd8v4fVuj
         k2vjVgQG1cC83a2cg9AKCbdNxiHqu1gkEJUJnicdky8bVemaY4WlCspJt+5HWZAQ2xBM
         mlYnCu6sCKWHOZnrrx5eNo+afngRgZYgZyzvOZ6FkPVySRbO9iRnkiXPDtDYEM9JTwlu
         l2T16TViiRmIABgzWTh15hWy7Wj3Ohy0hepKWWoVm3Uh7PMkDfa+z5Bibm3KssMe9Kqg
         qT8v1QZVVqlpzf9GoMuVXa/8AgrvuU2+4ovvLhRia44QxuOzokSRwcFhvp9Pu5TkEz3Y
         9G1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=w82aIRRon3IKfoPmFNDNkegpeY5dgoz4xVcwcWqT1IA=;
        fh=3L0BdrewLUrkuiUibzwUm0gL9Jqr8umsjEtrC8pi3Rk=;
        b=a1Bwv6DK/2bMNDjODu/4ROkeGyu+AerLDy/iuaL8cCtjJYqviFz0YYMZE/Z6WEA49Z
         8/txr9NEwc0DZbAcvGZPS+UU7D6hZEsb9/qsS09ZShAwx8wA8LU3VctFrE0RaLG27hKH
         zjcizWCuVK2GBkGLUtlKlg6KQmxXcm5xMbYrZ599eS8g7998HzAOFYJ/mraHkY3wawrS
         DZmOTGiGXI+p5N5jVqKWnAey5j4MKhIQZFbKZ0rSSwNMzjTSjbWLdZdbLchXIFum0oZT
         8LrW4256ifmGnKol99usn2dCtB5B+7JtHNBaeSVRBP13FNOv5iAA9BAZaFU1ZggNSb5+
         oUWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hfIDvJPg;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200351; x=1759805151; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w82aIRRon3IKfoPmFNDNkegpeY5dgoz4xVcwcWqT1IA=;
        b=NHEOCoI7OyI3u3qlYhSFpI6NZdWWcxQrGvP7ngU5nyXQ0uVWbhfZW4/tqen0k9zvbN
         TGiQpcCe2vWZuLdfcmp3zKjIH2VBXQ/uu4G/nXwvO02Xo43FxfvuPY0Zdk6WsMF0ldrG
         0vL5Fy2hOYgDGJAcC6uhmSX7LebkpZpDP9QfeFHUKelp9UaWtJK5bCt09T7cmxwCTwxE
         nxyDH8NivYeTGJjHYUx2MCZKcxi5mP8LwAPqKgrvjpiyz/wrtXjdgc8fJElIh7wcm7nt
         E7MR+0tLpO1oTIs93aiIvuqLPHlUktKz3lRLDlOvXOFhLx2aatKbBOfNwfspDw9DEfZG
         iKIw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200351; x=1759805151; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=w82aIRRon3IKfoPmFNDNkegpeY5dgoz4xVcwcWqT1IA=;
        b=Ue9HGOV1pS/Qk/QaN4+u9Xw4zhH9Kj08dNyBOht8cLjBu2V92WEEjH60F3ANCHwFN2
         542zkC0PNqHeg8th8rFPauqzeFMG2FEYQaVbw3JbXxf8EBwVwZ2a5Ja5+bfQDMNRwQdh
         G3CUAdYuwvrYXjBWeZeCssoNtumFi2c6rksmhtA9cP5F337WrVLbvhEhOZfeNEOnOC1A
         idiwDaM95kbcF9dMgxTtMPPghzvXDt+ix88AK6wBxhDi/WDRVbFPbZ2EzEZEWNabaE2T
         c6rSWFIuhKe0EPqGAd6oTyG7NhkzPJzQYX5pVHOIagiBJdCGnZT/6C+MsYV+WMCRW9hW
         IxAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200351; x=1759805151;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=w82aIRRon3IKfoPmFNDNkegpeY5dgoz4xVcwcWqT1IA=;
        b=fDb9+hV9KZ/S0AFKW/0j/S6cqIW3mgodlVjrcDFtZUIdy2O2KK1J58IFUHEbk6f48y
         YElC2NFqyF5vhXhzO5QpJEU3oJxcIxaP5lm3F+wH9xRylMAyz883OzgJy9fIlg66KEeq
         45sAva+0kb8Z3Q1SM1Y6OiqD334C/5KGEdXhjc4Zn6L1KM6arf2pjcAw5jEOpP35iffY
         4sNOUjIGxffjSi2tRw3eQqLa8RDAPbHL373d6AiEgMzhYut5ZY7K5wsSNN96ytkZRf1T
         AsjkUq3UcGpb++WSgSQxvJjy86VcGrNTng+e0AMkqUKjriFy0zo7IJi7A4Y1U7EhYEfY
         DeEA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXJ9MqzRCadx5GW3TXj74rRfQpbbs5uEpxR5u0kKm3VSD8jBptedNp3xR8+UNJlN02sQG/3AA==@lfdr.de
X-Gm-Message-State: AOJu0YxRz6fXgC76qINyQS/7VfIvPwmAOMX6g6djXpZAO7WYlYSK6dGx
	ttGbLMN+NaHw174vBcfbhRfOUWMVCgTof+kQymDrJRWGZA8S1pLWdqti
X-Google-Smtp-Source: AGHT+IH3lJyUnPcJLfAehalytmfs3cvEsw4HBnesGGc46M8+fbtt1AQxgTb3jMAP3OttO6ZWCSvUDw==
X-Received: by 2002:a17:902:d4c2:b0:267:a1f1:9b23 with SMTP id d9443c01a7336-27ed49fbd2fmr211548235ad.18.1759200351497;
        Mon, 29 Sep 2025 19:45:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6fQpr3vpkIP2L67dx8V4FvCFNFfMjo/w/3G6l3BUfHyQ=="
Received: by 2002:a17:90b:28c3:b0:336:c0f7:fba4 with SMTP id
 98e67ed59e1d1-336c0f814f1ls2419815a91.1.-pod-prod-04-us; Mon, 29 Sep 2025
 19:45:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWla0UK3zJhDT/k4zkcqg8UqzTYlQnQXoupIJIE0VOkjbgHZiR2Qwkl5sNrVavZfmhl6EMPB3WyjPA=@googlegroups.com
X-Received: by 2002:a05:6a21:e098:b0:24d:38c:26bd with SMTP id adf61e73a8af0-2e7d1ff0a57mr25262789637.43.1759200349936;
        Mon, 29 Sep 2025 19:45:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200349; cv=none;
        d=google.com; s=arc-20240605;
        b=PHgwkxCDTJHOUBoGm2bobXUIs6EDIb43XUxkT9u0hgqFY5irVDsxBwSKzAr7XslqVd
         vl67ZuQtWO5MH+CJZTKcvbPPeOstFCMSmG61MeUMCfTfXflqprE+iyvt3oORXYuKnpiu
         6H0zakTY7wQ/waiSMEhO1Fo2ofBO8di/7Wve89d9OX5iTVLCHQfQunMMDjy6fIuE9b84
         ydCbojHb7c7dttuKUjrwlFgU7Hdm+5Ipzdn4LqpbWtLRjuTp1YIQ6d75+jucq8WHdtsT
         hS+LhcszKPa3QwhPSStEEUo6FksYOmzjYFTg0qg5niOSfArTxs13hYneZmFzQRH+fJB/
         fMOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OyJZmUduTn6h/ct8/Xe3ui1NubLI+U0SzVd7OlZC6q4=;
        fh=TcCxdzfFwt65w8ds3esOtMeqX2skRm8CM7OmnO7FP4c=;
        b=MyvTSl4qj1IlZR+aGKe7H2uF/uIXW6BJXqqvkBnv1PO751eN7vm0l4hxt5MBWGWN1B
         OClUGnRN6FH5uOB+P/sZdglFgqGUUQW74ok4+hlEjRQ9G0hF7izZGPS2HGJdzr5aQya4
         t/SMR+D+tKSrhG1cvd1jSgbeWQQ+MQBY640Dnw8S5NHZ/fsSsrDH28uhdHtMS3IR4u5Z
         mceE2VcR3sIKUrvXbdOwSC/4F7Tf+miSLzbu3c3XMbcX8KLwxhRfWz0Y2SXdwLdYFz11
         33bNU6jBbP1rGxeAPpl3NO/ciJsf26WNCoxOVjVWSZZggAUW7cpMYj8cYxSGWSX5A9t6
         44rg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hfIDvJPg;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-78102bfcd4csi508215b3a.5.2025.09.29.19.45.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:45:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-b57f361a8fdso2437738a12.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:45:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVk7BZraaqFpyh1+Jt/pCLQQvp8qP/eKm8eDuua0nbIfx14xlSp0v6Vk29fVfhh5MEDCjPlTuT98s4=@googlegroups.com
X-Gm-Gg: ASbGnctas1IqZmOAeVDYQNVjKWNDx82+AUN39I9Ut1OUu+XC8WtFareFrC88euUCpRe
	1+TEW/HyST7mu6fzNM4yziH2iU1HgkBFvZjVIBZIw/FcR572oS+BYyb45pzFFGJiE2TtNlq0m84
	ba88FsAyw3UWIyZrZ9naQh8Vdvj0p8ptPwFQoqEXdyqa4QGwNAfAs8E3alhapF4ENwGcTuIwQYF
	PrYdS1tT96Xftv5VxoDEoOWbuaxfrKWh90cwySjcmzdGha58Y7IEym/GAJkIRVjWXcf2r3R/a+W
	TuFDUeD5/hMxHxL22rVxy3kdCbKqT6Nqgd0UIR3vhqGfPn7L/60eKSKZEvyZc9TJpmEdK1DWO3E
	/fxypzonfsfpx7jbxUK4ASTAc+1oTb7jqG+92HjNYleYWKrrVpA2FOgEKI33VHAEA83qFT1i8qE
	+M
X-Received: by 2002:a17:903:2352:b0:249:44b5:d5b6 with SMTP id d9443c01a7336-27ed4a920b9mr200539425ad.40.1759200349322;
        Mon, 29 Sep 2025 19:45:49 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27ed6886c9csm145811695ad.88.2025.09.29.19.45.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:45:48 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Mel Gorman <mgorman@suse.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Kees Cook <kees@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Rong Xu <xur@google.com>,
	Naveen N Rao <naveen@kernel.org>,
	David Kaplan <david.kaplan@amd.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Nam Cao <namcao@linutronix.de>,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	linux-trace-kernel@vger.kernel.org
Cc: Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v6 18/23] mm/ksw: add stack overflow test
Date: Tue, 30 Sep 2025 10:43:39 +0800
Message-ID: <20250930024402.1043776-19-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hfIDvJPg;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Extend the test module with a new test case (test1) that intentionally
overflows a local u64 buffer to corrupt the stack canary.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/test.c | 20 +++++++++++++++++++-
 1 file changed, 19 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
index 80fec9cf3243..012692c97a50 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -32,6 +32,20 @@ static void test_watch_fire(void)
 	pr_info("exit of %s\n", __func__);
 }
 
+static void test_canary_overflow(void)
+{
+	u64 buffer[BUFFER_SIZE];
+
+	pr_info("entry of %s\n", __func__);
+
+	/* intentionally overflow */
+	for (int i = BUFFER_SIZE; i < BUFFER_SIZE + 10; i++)
+		buffer[i] = 0xdeadbeefdeadbeef;
+	barrier_data(buffer);
+
+	pr_info("exit of %s\n", __func__);
+}
+
 static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 				size_t count, loff_t *pos)
 {
@@ -54,6 +68,9 @@ static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 		case 0:
 			test_watch_fire();
 			break;
+		case 1:
+			test_canary_overflow();
+			break;
 		default:
 			pr_err("Unknown test number %d\n", test_num);
 			return -EINVAL;
@@ -74,7 +91,8 @@ static ssize_t test_dbgfs_read(struct file *file, char __user *buffer,
 		"============ usage ===============\n"
 		"Usage:\n"
 		"echo test{i} > /sys/kernel/debug/kstackwatch/test\n"
-		" test0 - test watch fire\n";
+		" test0 - test watch fire\n"
+		" test1 - test canary overflow\n";
 
 	return simple_read_from_buffer(buffer, count, ppos, usage,
 				       strlen(usage));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-19-wangjinchao600%40gmail.com.
