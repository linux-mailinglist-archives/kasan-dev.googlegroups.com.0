Return-Path: <kasan-dev+bncBD53XBUFWQDBBQ4XQTDAMGQETQKIB2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 24BDFB50D24
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:25:25 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4b5f75c17a3sf111754541cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:25:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757481924; cv=pass;
        d=google.com; s=arc-20240605;
        b=SP6bWncRg7DZUgsFmXFZ4OZIAFf0LJqK1Qybi82tHwDwidscRjjW+F/o+2lPVxc3z4
         uKsn1SlGeH/rNPAPhL9GQsfXNDwWgh2weatyKJ3HhjROWq8EU3z0rvpfaeXuJGuCVkw4
         jrcp70/8eDnm9hrfqByHNnEyO5QDxO4QsldmLlQGRjN4ASuco9DNdMRurYGJob8StFly
         JyXdguwRlOI5W0uSabqeGHDEGtsZ8r3fMJuvKe1rKd1gacHxE7dxql2He9f+ou2h7gtG
         hIMdORYDlgrnWBfkxHvOAW5xWqhkJ+6vFp1CWkyzDZV7UjDoRadY03KUX93ukN4Rld0y
         Pbqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=GK+2hC6keoAqveOh5lTL+mecvNcOaXEHGqz0npaCGsY=;
        fh=6ZdD8+N01CAev+t50IoX7iSS2/kTBCUkLZDHGJEh+J4=;
        b=aGR8H/TXNWJTQ7J/eQ7UVl0AnW0XYduc9mqRL178qHWCAgqECkz8+K9MjZKOVv61s5
         nxnNk8j6sLEIe/VWAkfs9NA5NEVHH14pm/Tgg9mKAbGpgc7krS59H6vx73kWHdRzfA+q
         SHtEg371TPIGBFy4/a9tySF+KCDRDfyx21dZqc35lR1gXoFUfOVAWRSJioprpz5Tz5Vf
         0mftz5mLA331vWX8EevxqOV+XTK1yMVdnKw4BT3RWgOnGQy3muMPEfjly7I3jFqnWaOm
         B12n41GxF50grTeqJKIRgC/YY3yslXtbPjBKiQ8Vzu9vBZhCFLIlla5QC0DEEyr7XUWk
         LiRQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OKmJv49S;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757481924; x=1758086724; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GK+2hC6keoAqveOh5lTL+mecvNcOaXEHGqz0npaCGsY=;
        b=eUGI0TJ3kZ+SX+2FtqEjv67twQ37fr1Ik3INn+B8IRhl2ottj0ZSUScQMSxdLJjcKU
         zJSEO7TkUHA/EVs+FMjHAxwMhxSlysuK+AF2d5wwuJoPGLAypw/bpk+dKKzRsQZL+mkN
         Dfj60CfleiDpr907mF2/hjMAQQRDKHKi4s1gRDmL5gGVWtLgak5Nf8P5QpMtUxZa1JQY
         DSRwCY4fD9T1hO8BJwFjB8ru7R3XKZ0F1uCAPtez3DMrST8Q3oHyRNkQOvthgd20cLVS
         ror5AaGJfQGmPHh2FFSbwrMCvkUk+mB45e5fX9sE3DpPoqRAVw/kU71Dt6SVIFq5ZLYT
         ejvg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757481924; x=1758086724; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=GK+2hC6keoAqveOh5lTL+mecvNcOaXEHGqz0npaCGsY=;
        b=nkW1t4ld26uBCUJwhu8+VtmV+LoybNzhkKZT2BdAMgT/132581GG8qWsmK4zyYj9VU
         uEkfADmb27C++yjhbdaKZKYHMFWj2nlfUKhSF7QJyy7Ac0YNLaaF5QUDcFTXubxUIJbD
         uyvNZUPhDic3Dh5vVOw8DPdMtGYeDHtv1an3LcwdgpQFKXa08K77T+PA0QwM44lNjXwd
         U+K6WZwrIzBpG7uLUl617TwLcP2kEn9GYEDRhqXuDPwl4fNIq/EyN93THePqfNjW2Xs0
         aJbw4JDf61/QZPDcjGvID28O3L7+wXeMDJlveDJQryz1kH5rGh8N0FHqq1dSzpNo6IG0
         NwUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757481924; x=1758086724;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GK+2hC6keoAqveOh5lTL+mecvNcOaXEHGqz0npaCGsY=;
        b=FPef9Vl1GMSkcngJpHrqfsoScJ3umOFeAqIZlu4wr37q6nyPU1KGaonNlXxQF1fTSq
         as8/Q/nHJpN/f2tqARAzmSZu+FRysutfZ5wJ0CAJ8xwI2wBG8lhsAdoHiqh7+GlI+FUF
         jAPrgNoV3Q4rjxdSWDECZidTDD9DQOMu7h/vi8ZPC23QMZUBQyL3pGwfDwhRa2jHEjym
         OPRg1T3q6qZRrZUyfVWNJLH+eUDrxjGlulAFu1QzqyFsrD8mU0bXyShqTzo7X5gpqaee
         C6qVEXrDpVbu0FKWfXbvpNovWlZztzTuj6Ml2AQfIJvHcPj/8cxlZvWaYJqesxKCg9EX
         JaNw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWbn5TSKOvWIBsgFJXH5ui5C3PRs+9lsxrbi/M0YXB47EnKCnc/vgrO9iLniGNbFyaeRFKW7Q==@lfdr.de
X-Gm-Message-State: AOJu0YwRvXaOwGIO+sgncylv7XvP0dDlX+e2YVc5M9XWakOGuFuUgKcr
	bFye3OCFRopYDVotiQUWvcx+cwzKgGS11EiVduxTRBCopdtBMx63unx3
X-Google-Smtp-Source: AGHT+IGSzh6eX3Z+YgN4ue/KjKyiw7Acc/eGpRRqy+D2XCYuIi09/oJpTMAZC6yqzU94lnNxkM0CNQ==
X-Received: by 2002:a05:622a:18a1:b0:4b2:fb0b:1122 with SMTP id d75a77b69052e-4b5f84bb472mr150567501cf.79.1757481923951;
        Tue, 09 Sep 2025 22:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcVmHb38xNBzOn5I7n7KmHFS6AzQ/nb/e7X+Djv4igvuQ==
Received: by 2002:a05:622a:1804:b0:4a5:a87e:51cf with SMTP id
 d75a77b69052e-4b5ea9ff8f0ls84358821cf.1.-pod-prod-07-us; Tue, 09 Sep 2025
 22:25:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVk7YU28OTBGYt3dPTGfir5s931Lbq/QTE0FrxT6V9pQpRRyVq6rrHom7lH8jWVc9NwsxMVV/2063w=@googlegroups.com
X-Received: by 2002:ac8:58c6:0:b0:4ae:6ac1:f497 with SMTP id d75a77b69052e-4b5f83b150amr170226831cf.32.1757481922097;
        Tue, 09 Sep 2025 22:25:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757481922; cv=none;
        d=google.com; s=arc-20240605;
        b=I26YCLZ7rymWrbMa8KQWy4fQcGSw4m1ps9WrAdqSASv1ScpNgET6QxOxH8JyuTQPP5
         nFsw1LpbWaHguzPlmixZBUmwkQMvB61tcVe9hUwaPzdqfLO3jHTpaqzyiebNAN2Z44FR
         JrXq0TvjgzsTyBmRHU0g5DVpbdF2gO06DTuxkT+bd7j2l96yBNJzXc/PFjPBx0PUlVzp
         2BVPGsSMoUTZM9R105RHjOpclsxs1ihkCuT25xyYYFIsou1UzvVxu3VBnhi4/bjY6oac
         N7O7c7cPt3nrHzTpZ756u3RVNUQII4I2PCf3A1irqy7zloHjJHZ25xKp1gPe4GQ/JyPJ
         Ru6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=8iH0uUA/mqRHCjkyWem4sk7YGmV7N6yemXibteoDcT8=;
        fh=Ls61Mki3m6/2mOwNyVISVdH8wFz4uxwpU3sz6s0GYG4=;
        b=KIqiZ4RMEP6Pxi23ThCWF76O6jP73bYLIHJOFUrDO/5LCJjVMeTJOOD0BMcNH1HJQX
         rm8dz9giVsBwEUtcnlhzw7eSye3b4rU8CM1Hhc5J4NmaSMRdLiLwJv354nBxHQpmCHVp
         EGEMnYT9RrrIaoC4KCB12lr0qy6CK/2dU8K9LoQFuj3lDQ+oOc22qaUnKsbLLnAVmf84
         hPp2R5K9QAyZyQwwUYsHaK2Q94gJ3FSEDOtmv6IUbrA2DhakEhl9wnBhJ3Vtt2UnATYj
         JTRKpjMPYZR7YY1v/CzhGlhTl5ub1y+aHv0HecrnWmclDkATj9dzm6boxqf9fxRrw7xG
         cTpA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OKmJv49S;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-81b52874013si17253085a.0.2025.09.09.22.25.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:25:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-2445805aa2eso62819375ad.1
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:25:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW/Foml+hxsopWl9dvvj14WqJeQJ34S68ZU7UU2jrQCEEmo3dXwzqj9cybuJyUkAAa8ms1Tiv6ao/w=@googlegroups.com
X-Gm-Gg: ASbGnctnTBrgWhd7PSwTbWCQGiUS6hTlc1M4Pba7NO70M0OxyrM8lvZs4Zd6vw2zDrE
	lJ8vTRPy7oY4Qq/fHvuREJ0xBcaK1RPP3YQFkABScD9GehNpstCf9c9QkITnb5Q5AOE3lG4azn9
	NQHwlv4FjYob3SRgow619au90NJI8KrJk8enx6RkBX/7rj674ixRaru+Ssb45PTUbtQFTJZ/jfC
	aFLmjl0DgcSWp/DQLwVTKOgCsCBkVqDfoxUKpScs0yu2gd3zJ2YTb7xUVJGrNPCe1c9aSnOktCh
	TWkkqFBoESmoS9s5pUOzm8eipAuFQCyAKVmkQWSVN2YzAxNlYL87erYfGmflHKfU3w9sY0/XLgr
	B3PwXguwL4Z6AwUV/y+gjqFw2XSgSkkRrug==
X-Received: by 2002:a17:902:ce12:b0:248:79d4:93c0 with SMTP id d9443c01a7336-25175f75c60mr198301765ad.56.1757481921566;
        Tue, 09 Sep 2025 22:25:21 -0700 (PDT)
Received: from localhost.localdomain ([2403:2c80:17::10:4007])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25a27422ebcsm14815125ad.29.2025.09.09.22.25.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:25:21 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	"Naveen N . Rao" <naveen@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-mm@kvack.org,
	linux-trace-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v3 05/19] mm/ksw: add /proc/kstackwatch interface
Date: Wed, 10 Sep 2025 13:23:14 +0800
Message-ID: <20250910052335.1151048-6-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910052335.1151048-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OKmJv49S;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide the /proc/kstackwatch file to read or update the configuration.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kernel.c      | 75 +++++++++++++++++++++++++++++++++++-
 mm/kstackwatch/kstackwatch.h |  3 ++
 2 files changed, 77 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index 1502795e02af..8e1dca45003e 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -3,7 +3,10 @@
 
 #include <linux/kstrtox.h>
 #include <linux/module.h>
+#include <linux/proc_fs.h>
+#include <linux/seq_file.h>
 #include <linux/string.h>
+#include <linux/uaccess.h>
 
 #include "kstackwatch.h"
 
@@ -12,6 +15,7 @@ MODULE_DESCRIPTION("Kernel Stack Watch");
 MODULE_LICENSE("GPL");
 
 static struct ksw_config *ksw_config;
+static atomic_t config_file_busy = ATOMIC_INIT(0);
 
 /*
  * Format of the configuration string:
@@ -23,7 +27,7 @@ static struct ksw_config *ksw_config;
  * - local_var_offset : offset from the stack pointer at function+ip_offset
  * - local_var_len    : length of the local variable(1,2,4,8)
  */
-static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
+static int ksw_parse_config(char *buf, struct ksw_config *config)
 {
 	char *func_part, *local_var_part = NULL;
 	char *token;
@@ -92,18 +96,87 @@ static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
 	return -EINVAL;
 }
 
+static ssize_t kstackwatch_proc_write(struct file *file,
+				      const char __user *buffer, size_t count,
+				      loff_t *pos)
+{
+	char input[MAX_CONFIG_STR_LEN];
+	int ret;
+
+	if (count == 0 || count >= sizeof(input))
+		return -EINVAL;
+
+	if (copy_from_user(input, buffer, count))
+		return -EFAULT;
+
+	input[count] = '\0';
+	strim(input);
+
+	if (!strlen(input)) {
+		pr_info("config cleared\n");
+		return count;
+	}
+
+	ret = ksw_parse_config(input, ksw_config);
+	if (ret) {
+		pr_err("Failed to parse config %d\n", ret);
+		return ret;
+	}
+
+	return count;
+}
+
+static int kstackwatch_proc_show(struct seq_file *m, void *v)
+{
+	seq_printf(m, "%s\n", ksw_config->config_str);
+	return 0;
+}
+
+static int kstackwatch_proc_open(struct inode *inode, struct file *file)
+{
+	if (atomic_cmpxchg(&config_file_busy, 0, 1))
+		return -EBUSY;
+
+	return single_open(file, kstackwatch_proc_show, NULL);
+}
+
+static int kstackwatch_proc_release(struct inode *inode, struct file *file)
+{
+	atomic_set(&config_file_busy, 0);
+	return single_release(inode, file);
+}
+
+static const struct proc_ops kstackwatch_proc_ops = {
+	.proc_open = kstackwatch_proc_open,
+	.proc_read = seq_read,
+	.proc_write = kstackwatch_proc_write,
+	.proc_lseek = seq_lseek,
+	.proc_release = kstackwatch_proc_release,
+};
+
+const struct ksw_config *ksw_get_config(void)
+{
+	return ksw_config;
+}
 static int __init kstackwatch_init(void)
 {
 	ksw_config = kzalloc(sizeof(*ksw_config), GFP_KERNEL);
 	if (!ksw_config)
 		return -ENOMEM;
 
+	if (!proc_create("kstackwatch", 0600, NULL, &kstackwatch_proc_ops)) {
+		pr_err("create proc kstackwatch fail");
+		kfree(ksw_config);
+		return -ENOMEM;
+	}
+
 	pr_info("module loaded\n");
 	return 0;
 }
 
 static void __exit kstackwatch_exit(void)
 {
+	remove_proc_entry("kstackwatch", NULL);
 	kfree(ksw_config);
 
 	pr_info("module unloaded\n");
diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 7c595c5c24d1..277b192f80fa 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -35,4 +35,7 @@ struct ksw_config {
 	char config_str[MAX_CONFIG_STR_LEN];
 };
 
+// singleton, only modified in kernel.c
+const struct ksw_config *ksw_get_config(void);
+
 #endif /* _KSTACKWATCH_H */
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910052335.1151048-6-wangjinchao600%40gmail.com.
