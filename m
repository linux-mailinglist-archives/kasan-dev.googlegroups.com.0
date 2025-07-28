Return-Path: <kasan-dev+bncBCCMH5WKTMGRBINNT3CAMGQELVLTFQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id F391CB13E42
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 17:26:26 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-612e67cee87sf3665605a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 08:26:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753716386; cv=pass;
        d=google.com; s=arc-20240605;
        b=GghkiQSdDz/Czr23ubseXXQB+maVNSTBXxps12KpY4QsRa0qXhPihRtfhwJXrptV+z
         yt9VwKGTcMfWRdJ5wIi60XWVFqV/+xM8m3Txay0FIm5fKrjZtz1/yg9PiHNUYzejs/ER
         CMxriDwOVptnOodbDF1Cd4vKhp2lxV/cugg06E2J4coSdSwUeEBbZcdveqLrd6+BWmwL
         vwbV2eFbdQrudw59mEaC9pk/Cz7aHVbstewpT4M3jyiuju1bijGjf1hWzYhpt3ddzOV4
         OrebK0V3aoejV8QQ+Mq3cvOnaNvddHOIY9g0VLrIAZ1dz/u2OVVjiF6Mn5UUMKXn1/gB
         luUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=pM8tcHT9/D63mYLqszRHvC86vJVXTRpur1im9bxSi50=;
        fh=3AIIfMg9oA4fgAQwoqVPDfhWozMOA9N9A2gfuvbIyEI=;
        b=Pw254j57dDFn6gXQ+kHt6Bn11oXAHG2sayefP/jyWltWPEHhCj3ImDXsYV7ZzvMB6n
         T5g16Io+TrU5Va839cJ32HosQ5mBVmLdMRkFtOiRJvb2Du7iaWqqm++CmAS5uSLIyiI7
         opUFV3rrYw9gOxi31M73B7HfI/YdH3+iYNywjk8i+MgW7ucPwplkaYjxvtvJqyy8+L2F
         TF4hz+jV6W8+AFqMn8LJG4fsT8qQBBvB0Qjk/FXcCz5e3h3oRNgQ5XT4mutDt2z913um
         nj0tNfMGNgm7AIdycCKbXhAJmnJyqnNIprJTJR+ppiarpGkfWfmqRXLYyb5rK6QAzdRg
         Nqhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=x517lByx;
       spf=pass (google.com: domain of 3npahaaykctuxczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3npaHaAYKCTUXcZUViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753716386; x=1754321186; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=pM8tcHT9/D63mYLqszRHvC86vJVXTRpur1im9bxSi50=;
        b=tJEf0pLOcmof8t612MOngCKKfyBE5jVMA5wTuRL0Jk+E3xxPyf3wBzNcfwKofL9WuL
         0p30H5BxtsUPrgGiuXxBtHGNGplY8nLflRTzL1tnZ0xS/CvOvvm5SYx2tdddxKKqtqf/
         ORf12Vo/AmykT4CNg3KmrvlH2v6NFxsnT9TDIN6TxFm7qp8PdITruZnbYxJgGoBVpYzQ
         bxSHzsBbpaD5yeXW/vBrpmDs3TSmsFD0zqLPgE4dWzdtePwP4YGueIgJbDC4qYTb6iqU
         k2dkbKwETASs6+/BBG86L22SB0yCefSjSw4QijlCeVD4+gum5Z5wep4Rh+iw1uWh9B1E
         4zVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753716386; x=1754321186;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pM8tcHT9/D63mYLqszRHvC86vJVXTRpur1im9bxSi50=;
        b=KgY4YU8G0O+QgtaDSpULOcgbUJvelugsYerH/wLIe7RW1ZUC83Nx8ahog90UCL3RsQ
         nMx8zu4iYMmOgbqEEp+Vrxg/eyzyjLEvqX2Yh0Ap5PE8piuilbWfc2M+YY7y1PYnYc3X
         5cCPzqO0DCyjSToqMldzIz/jNizipVy+pZYo0WepkX7CAgUxiaXZwNspz8bZGqgDmcd8
         /B3NyRd2HRuqUU9VGikBTfpc+wg1VhSGQfA325bo3fwVxbKeKZv2wo+k3KcTIS7ZSLYL
         g/vCK+zTJhCWkLCMh5I54TqNPm05R8C18frQDP51eVj15G2zw2VkTxlugChzBa4zECdo
         wqvg==
X-Forwarded-Encrypted: i=2; AJvYcCUJt2OXhw1dK97BeelLWcovrV1bLQB34xZpnVBOliC1ZBSwiwJCPWTcxD4RxH0UWtwRyNiNGw==@lfdr.de
X-Gm-Message-State: AOJu0Yz6Izin1Fl91s6dnn4nzr7Ad1/ku5mH+it3PqIkwf1vfyvAYV6O
	0DhccvfzOLUKouY8SsVGqu74KXWhFk3+I4K/uAv85AX8Vc/+NoLDcik7
X-Google-Smtp-Source: AGHT+IEt0lehyU8irt48ITJWd0WgQoMVinpZd0mMmPllyb2dijFB1bsW+A9heDOVGFTDppQrTS6rdQ==
X-Received: by 2002:a05:6402:1d53:b0:612:c966:4464 with SMTP id 4fb4d7f45d1cf-614f1d8555fmr10606849a12.25.1753716386371;
        Mon, 28 Jul 2025 08:26:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcmof1vQ0jTj/vYVqeRDUlinplUBN6OI4i4/SQetxMrhg==
Received: by 2002:a05:6402:3583:b0:60c:50c3:81bd with SMTP id
 4fb4d7f45d1cf-614c0aaeb97ls3739302a12.1.-pod-prod-09-eu; Mon, 28 Jul 2025
 08:26:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWqXjYG37xJPex5vlPcIRiD9fqihR0fcP4QJpizDamy2FklqNyEPvXalBfU6/VouLxBD0WRHuTqLmQ=@googlegroups.com
X-Received: by 2002:a05:6402:2803:b0:612:dea2:9c4e with SMTP id 4fb4d7f45d1cf-614f1b97a8emr10031310a12.1.1753716383458;
        Mon, 28 Jul 2025 08:26:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753716383; cv=none;
        d=google.com; s=arc-20240605;
        b=CYiGRNlrJBalyhoqfdd1mRrsyLzOxZjkiLc/FIptdhQkJX8Z0XOrJe1v4r79koClKL
         IrcueBVLFfWqyPHd0RxArS/W0RrvjQF/c909/9sOpP2SpH6Q2GLK3x+dT3rVnV8TrfNV
         9VaTB0mry1NJA2Pxz5mrDGqe8ak1vTlNbtlBDLnuuAnbuQHj9l3AwprLqIHLH8Uk74UJ
         Ny1zm5UZQcLX6ahWceSs0MvpEYr/hPzdIXCmtZK4nOV6PEWTrnuHYQO3IHto+4S9onNJ
         1weLb+KIQPiAvZCX2Tgo2qGalhknwXwqioqk0feuh8xOMHljmS+2AHZNK5yQkbHNmvgl
         4Nzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=hykQKzruNCv5r2lQ9UgjaMRVHwcJ9+lJEhAaVBLVSIs=;
        fh=S+cN0MUxAZVL0B18WroRdrbzpWDpSuLPzket4jBZ2xA=;
        b=MW1vW4mWQDfdGnYgdSJnl0w8zlkTsfDEx+KaOPeYA0ffMigQq9q7oqDjNK1MkjvkED
         q/Ka9DmmdrvfDwzhL1L/7SQo7UfWoZDe6fUAbBbS3cwR3ZjFVEqEiXuSiyWyvdkUHw8G
         sSd+J9FfO/VAgpxbW4kGQkuw5ImxGnHEbDS2KDWOrv4W4ybmmpLOsDnzH7jHkJwSVrEi
         G/RA6E53D+DwOtSjtxc+Mi/P0azOyT1fHY3AOsRtjP4RrZY3f5gFyDeN5wWvJgEwmvVk
         MdxB/OdVBTt/d9fNUGqj0hUacyGAoOjsdSoPZg1TNkWWBy/DtXS0OOypZuOO4eSDvRp+
         d0Zg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=x517lByx;
       spf=pass (google.com: domain of 3npahaaykctuxczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3npaHaAYKCTUXcZUViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-61530cd9882si110089a12.5.2025.07.28.08.26.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 08:26:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3npahaaykctuxczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-3b782c29be3so1395509f8f.0
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 08:26:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUGN2IKY1Xc7TmYD/tAAr4NPFBM259/yct4ZkoX7iisicuZLKwAbTe4D4dQLS1R6oNvqsoCs5haaXI=@googlegroups.com
X-Received: from wrmc6.prod.google.com ([2002:adf:e706:0:b0:3b7:828a:15fa])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:3110:b0:3a4:d4cd:b06
 with SMTP id ffacd0b85a97d-3b776776423mr8151840f8f.34.1753716382935; Mon, 28
 Jul 2025 08:26:22 -0700 (PDT)
Date: Mon, 28 Jul 2025 17:25:48 +0200
In-Reply-To: <20250728152548.3969143-1-glider@google.com>
Mime-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.470.g6ba607880d-goog
Message-ID: <20250728152548.3969143-11-glider@google.com>
Subject: [PATCH v3 10/10] kcov: use enum kcov_mode in kcov_mode_enabled()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=x517lByx;       spf=pass
 (google.com: domain of 3npahaaykctuxczuvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3npaHaAYKCTUXcZUViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Replace the remaining declarations of `unsigned int mode` with
`enum kcov_mode mode`. No functional change.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I739b293c1f689cc99ef4adbe38bdac5813802efe
---
 kernel/kcov.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 82ed4c6150c54..6b7c21280fcd5 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -949,7 +949,7 @@ static const struct file_operations kcov_fops = {
  * collecting coverage and copies all collected coverage into the kcov area.
  */
 
-static inline bool kcov_mode_enabled(unsigned int mode)
+static inline bool kcov_mode_enabled(enum kcov_mode mode)
 {
 	return (mode & ~KCOV_IN_CTXSW) != KCOV_MODE_DISABLED;
 }
@@ -957,7 +957,7 @@ static inline bool kcov_mode_enabled(unsigned int mode)
 static void kcov_remote_softirq_start(struct task_struct *t)
 {
 	struct kcov_percpu_data *data = this_cpu_ptr(&kcov_percpu_data);
-	unsigned int mode;
+	enum kcov_mode mode;
 
 	mode = READ_ONCE(t->kcov_mode);
 	barrier();
@@ -1134,7 +1134,7 @@ void kcov_remote_stop(void)
 {
 	struct task_struct *t = current;
 	struct kcov *kcov;
-	unsigned int mode;
+	enum kcov_mode mode;
 	void *area;
 	unsigned int size;
 	int sequence;
-- 
2.50.1.470.g6ba607880d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250728152548.3969143-11-glider%40google.com.
