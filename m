Return-Path: <kasan-dev+bncBD53XBUFWQDBBP7ER7DAMGQEA74TQAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 89535B548FC
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:13:21 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-25177b75e38sf20000965ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:13:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757672000; cv=pass;
        d=google.com; s=arc-20240605;
        b=fRh/ciJhFC7jp52EStZGE42T2OD9DnVyhfTrhRDELKdZTRtxXtH5dsaCotB/Mc3+1Q
         mPu2WBAEBGDklUq/TKKY4hE9dXQh2JiBYdTrRDNj6x7LRhZn/iJ7COY4ybJ6x0YK1Dsm
         KX5aFtmZNqrwR1Jf/Mj7xcYOfBsBRaR1HpnrIepapX1v2ca7e0BmnAZSCVRsO4ZhL09W
         zHJRcdzJwsxzQMztGZml1dOCdPm4/lMuYXXycLQGB4Z7N/6G5ScSRTOWyOktbQwzXL/4
         LVny2QrNQFMpaCuJJBnTkWp4RwmTHm2RY7rzDCbak+WV4G20Mnv8qYHWcwhE2hbF1CX4
         k0kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=iCnz0QCZLYSBfRZy7IxqNngxDroj4wFx4GOQnK835pA=;
        fh=fPiA1DBoUHYdSOQoOScLcLOunodQNwlOBBhDmSdWsrM=;
        b=ZqvHOpf8eMpmTuJ7Fnx9NVCDvrwVTyCLE6juSE4UpdP9af7YeC5/Z+rSrGr77qltQF
         Rxa+dYdCZ5NAAjV3bUr17if1dZqRfK+PKqI/AzT+3E3R0KbQ6oTRSnhHDAtDi6B9dih0
         vUlHENoh4yieLZi452Ajyc4LrbiTeAoYtXbwhcVmDm67dZM5+6oWPvyxAq96/WUSTU/B
         jQTRQk16lhck43+wLwqrFk96Uv5Rn6k4Fdkww6phYAZIG7tXpiajPGXodSSkqB8lp87M
         b6zX+lIjIGMa5zYtyqvDbGxFRHOJV+ySFbh7bQX5KbqLFDHPa3nf5DcWqscPEdCxIQr7
         RHIA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=C6hEgGFe;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757672000; x=1758276800; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iCnz0QCZLYSBfRZy7IxqNngxDroj4wFx4GOQnK835pA=;
        b=Llex5asrJvn4jwDbKxSlEjboJHgldO1uQrgYdqy6/pb6oY73Hv7wXiqdc5wk9Espuj
         +8kCoOpddHbn+mUtNQadcSeGtBUDJlOHFyIMnfNs2IVxW9ypezVNV4rPiFFle5u9Hky/
         67vGJDkbsxvsp0inANCivuwRGjO/Mu/YcuR4PCHz8DPFXJZFYxvGA8p4Bt7ufM/EFBil
         z+SSGdBEi3oFgZO/i+if2JtVH0IZOy5Oq2oThht52O8tHhDZB696J6uSPs54g3AE9cR9
         S2lfilrzITkRkn2D1rZXClKkI7qFuxjgsPns6LIUnXMRIN5+arsCpCgOJrsXQ2MF5wC+
         +qUA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757672000; x=1758276800; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=iCnz0QCZLYSBfRZy7IxqNngxDroj4wFx4GOQnK835pA=;
        b=Fx2yZ7mmdoRNTuNuIF6c2r33ugJnCMZDUYz6CMEVci8WwBJkf17aD1sz5g17dsKwkS
         pX4az6pUbVTiQDN79m/XhULlQDUmYGiiNC97jMw57cdy7xQicDgmK0IhZBWUxLsfXkgR
         NkoN2FigIzZDLquzWTanOtXlxE9RyR/YVTxCDxEbiIEeENfRpv/VigUl5NyH0CnlYbQp
         mkVKfbVsdjKSLoHe9nW/fY0uWu5vQTFIYsrdolSU79aj0SrQXNgSnp00QYqYjL+o36O8
         pSUSn95Fi/I5z4XmZ5KlYY2d+ufS6s55r6kHcCXV6lBSDMih2Q17j3pfzA4yvfbB/XRI
         ckXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757672000; x=1758276800;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iCnz0QCZLYSBfRZy7IxqNngxDroj4wFx4GOQnK835pA=;
        b=PRB+yr/5PEBC4Ns2ZEPwtWShc6m7MqHY/uKZBmVJjMM0hItA9FhPDgzQymIIlXUKhN
         HhMOE4Y9j70J1jUzk3XxXPr/WmgZH9C+njAMWt7SUPzqriAstx2Yk8B33U1gh0OJeDxN
         wf2hZLwVBAtKnKddCERYkK5BjpoKZSpAk8eC7bfvIcEDVhrK9tWy5vvom98GZdBQ/m/W
         aRkNBR5rN1hXGbzeP2I/r9Jn28KfXfq06LDGMyfdp18RW+Gos/emPoygKGntXxaunMiP
         lMqPvrNzIXAmJAdZTp/2GPtDbL769Rd5kmJ6tvqbTT5PBKNaXAGCIE30a2tkJfbc8Q+Q
         QuYw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVbcIzXZejQ5shDvUkdvxqf14/tHaiqO4CEkiLpydaTbUx+/tU4F8iRZKd4Y0xU556udKvPaw==@lfdr.de
X-Gm-Message-State: AOJu0YwJ2NW7ztNiXvCRHBBTuMYcTSf86hB6hEGR+BmPaJ3CllqiFBL0
	+fwMh2ZQ8m0dmqpXcA8SYfoKmbtwvjMJrlfPkNcBr+3u17xhbrXH6+/b
X-Google-Smtp-Source: AGHT+IEKOo7HDAZrBIgczsJGJ1NkTOl4Ej+cY7c2/BTxG2otzqHQt3SeCDE6J0NdUkj40qVtkmG55Q==
X-Received: by 2002:a17:902:f311:b0:249:1440:59a6 with SMTP id d9443c01a7336-25d26e431c7mr17081445ad.33.1757672000074;
        Fri, 12 Sep 2025 03:13:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd70/gYd9RTiiL9xCIVkkcepujCRWakE77lJW+fAlr+JIA==
Received: by 2002:a17:902:f790:b0:24b:63d:52b0 with SMTP id
 d9443c01a7336-25beca65274ls18954405ad.2.-pod-prod-01-us; Fri, 12 Sep 2025
 03:13:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWM+zos6j2DMBALLwe1lmroVcZ3uarWo5a/X+FobuB3AAZhxLKE5O88u+nnMlIqeeXf40Y1IepuAPU=@googlegroups.com
X-Received: by 2002:a17:902:8606:b0:24e:e5c9:ecf7 with SMTP id d9443c01a7336-25d26e43dbbmr17981375ad.34.1757671998580;
        Fri, 12 Sep 2025 03:13:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671998; cv=none;
        d=google.com; s=arc-20240605;
        b=Aox6Ib3L2fceuPvkX+zM+ha2XfJ75rH6GtMDGpuEv2OlPzL7eINeBflUron6qfmtPb
         2nff8tfBmXsE0083pWTOlMVWIelf6dL+UugYknhDU8NeA8EOIvu289KqxCJ2MjiZBQ5d
         0eAxG4xQmlI9LkckstzwLk7vEotvfUFutD2q/Y/l9Zi0eyhqGH5DmjVIpXuR2C9m/tcm
         CXavWwnBRjjbYamWQJFZnQqkfkDTf9DYY3Um2BclqNQXyDykvUrKO0fi4TJhcC/5UFoE
         pIR9oKEIfsMzyLFXFukyEjVHdo+zW8mRevVfJzsg4eJDXOuS94cfzSYJRRDV8oWp7Wqq
         uRJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C6BBsZfnmfgl1Jgn+pU00vd6g5c1DTmTteWqGp/Sk64=;
        fh=8ZsgwQjM9KlLHBfpPWApoIBj+S7DvdTPA6xvD4KXQpY=;
        b=hDFkJJJBHf5czFm8ZwsKITSh7FFERzYbGgVeZaIozV80XCBTEKHK5cMu/vIDYgNL0c
         cY7aN0N1VWaf//dFKZb0ulWaZMozTauMv85CMfmjiLMxdyce2EkxkfVxT+8FsYoiBygY
         XbBSvq0QbBft6RDj/A/8RRUcyYOvTM6gop2jRmiby1t2Y+X8revpzSv2RDvFm45K1aVy
         OQYc3HCZAOGgfCxin/WhdiZwCrjj4Cs8dWXvuAomNjiXjVMNN9+WpvLWbzKpv6HB9ctF
         1mmY51FZuu5ku+ldvtgUTxXhTjRnl88UU6daUuaxnM2QiN0EdFju7BfOsuTT6aQZupRE
         Y7cA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=C6hEgGFe;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-25c370a502fsi1661725ad.2.2025.09.12.03.13.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:13:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id 41be03b00d2f7-b52047b3f19so1238337a12.2
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:13:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV9LJKU44AuZ624WYRLr2wNy9bBRK/1FG7UDYAnylV3tjA9T5/A4ECjH1iZCR9nHXN6pqqHVY9P26U=@googlegroups.com
X-Gm-Gg: ASbGncvWUM53efniSAGC3BQh39Fs92wuBPvJA7TPSb1ypBmawPrfvx1xUH3wXHxIU4b
	TYcmxIrNrHarN8xs94zECT3s+xfXsqO1gGm7uxUENsBpTUifvIMsmsJ43vBAEWx//e+8YX0Sokc
	ri8kmq944otrYBD6NPVCpfUzwrN2aw4aAESHAyBQ7SlSAYNvZ4FulGOiS/hMzGms3vHBWrOd15m
	+MdK3P0OwMfqLHA2s1Y4Q7K2P/vsayUK0ZsYWMnekUZ+k2LklnyFmeo38YcX0zyZYowh4FFgcwY
	gscjqXKzlfeqSyTlIqqe0+LI+WUqNqZW9jgWSs74a2XnfrBDQZriBB62R/F0zxpGIbFAa3/S/Gd
	ORbxIai1mQHQ9Ert5Ua+cCBqMfbX/y/CLGnWPycsRqTbxnA==
X-Received: by 2002:a05:6a21:33a6:b0:246:3a6:3e41 with SMTP id adf61e73a8af0-2602a5937a8mr3020791637.6.1757671998049;
        Fri, 12 Sep 2025 03:13:18 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-32dd98b43a7sm5206301a91.13.2025.09.12.03.13.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:13:17 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH v4 16/21] mm/ksw: add stack overflow test
Date: Fri, 12 Sep 2025 18:11:26 +0800
Message-ID: <20250912101145.465708-17-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=C6hEgGFe;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
overflows a local u64 buffer to corrupt the stack canary. This helps
validate detection of stack corruption under overflow conditions.

The proc interface is updated to document the new test:

 - test1: stack canary overflow test

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/test.c | 28 +++++++++++++++++++++++++++-
 1 file changed, 27 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
index 76dbfb042067..ab1a3f92b5e8 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -40,6 +40,27 @@ static void canary_test_write(void)
 	pr_info("canary write test completed\n");
 }
 
+/*
+ * Test Case 1: Stack Overflow (Canary Test)
+ * This function uses a u64 buffer 64-bit write
+ * to corrupt the stack canary with a single operation
+ */
+static void canary_test_overflow(void)
+{
+	u64 buffer[BUFFER_SIZE];
+
+	pr_info("starting %s\n", __func__);
+	pr_info("buffer 0x%lx\n", (unsigned long)buffer);
+
+	/* intentionally overflow the u64 buffer. */
+	((u64 *)buffer + BUFFER_SIZE)[0] = 0xdeadbeefdeadbeef;
+
+	/* make sure the compiler do not drop assign action */
+	barrier_data(buffer);
+
+	pr_info("canary overflow test completed\n");
+}
+
 static ssize_t test_proc_write(struct file *file, const char __user *buffer,
 			       size_t count, loff_t *pos)
 {
@@ -63,6 +84,10 @@ static ssize_t test_proc_write(struct file *file, const char __user *buffer,
 			pr_info("triggering canary write test\n");
 			canary_test_write();
 			break;
+		case 1:
+			pr_info("triggering canary overflow test\n");
+			canary_test_overflow();
+			break;
 		default:
 			pr_err("Unknown test number %d\n", test_num);
 			return -EINVAL;
@@ -82,7 +107,8 @@ static ssize_t test_proc_read(struct file *file, char __user *buffer,
 		"KStackWatch Simplified Test Module\n"
 		"==================================\n"
 		"Usage:\n"
-		"  echo 'test0' > /proc/kstackwatch_test  - Canary write test\n";
+		"  echo 'test0' > /proc/kstackwatch_test  - Canary write test\n"
+		"  echo 'test1' > /proc/kstackwatch_test  - Canary overflow test\n";
 
 	return simple_read_from_buffer(buffer, count, pos, usage,
 				       strlen(usage));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-17-wangjinchao600%40gmail.com.
