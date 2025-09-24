Return-Path: <kasan-dev+bncBD53XBUFWQDBBXV2Z7DAMGQEBQ2RYYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id EE9EFB99B77
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 14:00:50 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-4257e203f14sf73792775ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 05:00:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758715248; cv=pass;
        d=google.com; s=arc-20240605;
        b=UahbXf6J3YdLEeHniilplKh2pE0AvseRFCzIzkNPlg7CJL8sHHic+h/CY86xlE/dpx
         YEt9TDUB/wxKnqPNIObgCLd8c7m8vH8lnrpmAwN7ZgdjhIgCraoL7P602gCxYa0yCQZ6
         Nbmg1GuamfTSEzUYBJQExRrjwHp3gPd69OkKFvq9acc0GLosucC3cGN9eEsFjKwkiyrO
         yOprePiOTBPyk1gH8SCrZs5McWLj57hAyNRVaQAKeAwE27nooomgppr74o3avxOpy5b1
         NpEdKd8AbCtGCIDCUpccCzfLYQWIZEQJ7kOfnEGDpPLlrfuiWytT9rceQN8TArKRAqt0
         +EoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=e8YM7JEF2qmUYEsEfSkQyiBbYVhOaebQGQBUSx/vaDw=;
        fh=x80SvtxqPsfquJDQgHMlPUNiDAIY05EOX4WdocCWWmU=;
        b=NN306hMaXCpPHt4u5abOHfV/86v3od6TR8OwVWOhVmnAssro1SjNU6giURxFnLdxn5
         7vAvS/eG1+eGXx7cynIjriU2qWGgZppVeUXWDo8yLE8+KgRp9nuUqxBKfrZ2Wv90/9Xi
         ILx7NOjJIPXwHXoEbZoc9zzCKV9stJi7YIdXuS7bSiInPisBkS3P/mQXYQTZ18/9+lla
         hOLrxs7vTiZ3AY03BMAra+hIQUXM5SCKQcfq84cWDgYOmoh7M5XnFRzjQcz2ZM7Za3S3
         Xe7MJyjcGcb59HdYIQTRSsKPmKvUqP1bcpurpYOLCtdjtHMff3J5uQkEKCN/EcYU7cgL
         z13g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="FsO/eOXf";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758715248; x=1759320048; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=e8YM7JEF2qmUYEsEfSkQyiBbYVhOaebQGQBUSx/vaDw=;
        b=SRe/X6cSFtSpypqHYgyRTuUXAdr4HR3bXBklpXAzERaFsikAAMe5LScGzmtv+Y3SwE
         xU4GutiVshRR3KI4Of6EHSoLXQevZegZIYZj7y2amGCCS3WBhipNcI0wXyyx3t6VyPVI
         UluibGrT83GneWo9UmpPzzyKRYwpwW4aaDzWxxS83r/lvlT+q6ToPMmLH/a3dSnKa5Uy
         i9u/F711MyqcekXFr1l6ifpIBum1XMd4KGmv9l2Ng3MOX9cGozezc92KLFHZHkSRmR1G
         ngR39lPRH8fd5z0BBllUcTAv7LhMVzr2GgRUKWAUxdtdQAmk4ge3J4rmJXUlROPftMJ8
         H5hg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758715248; x=1759320048; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=e8YM7JEF2qmUYEsEfSkQyiBbYVhOaebQGQBUSx/vaDw=;
        b=JvaQKSVoyViS2jDyzMsEdgv4MqETXmdARJ534FWIZu+opbCGHWjtgILUUTqBxgujlX
         F7yZEIqMDg5gQ9O0PEe8q2ez8a7XzP/fVUS74yIu1geBYF4KXG6Znol2GwiQ0yhes4y0
         Wum2QLd+xGYZpb4xqxRt8kDsUdfDfip1GF9TMYVbkrHyb5vu4tHotpsedXBL9tbRNZ17
         9ap/b6/FLJ8C1gzat6KW1mJxSLyZKfo5Gp1RX29vE7npMoEtIyFqm3khwGy2VVwVfdfi
         p3bUAyg1yJeEeVZlQb+GUr3rWRLmxz4f4Ums91kCC+6e0S/d9DQgyCUKlrHEbh9yp+Eg
         bi3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758715248; x=1759320048;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=e8YM7JEF2qmUYEsEfSkQyiBbYVhOaebQGQBUSx/vaDw=;
        b=qtFM3O0JiaihNI+rF/nhh43Z45dgg0Tc2zlgl89g/ZNK3vdudF3YImeU6Ck6w1TxiH
         Sc/09LqX8+PLViPEFPAlR3vFC8VDBFvF7gOXIzgnT55bs1Pmnz1rZ1Lz92IN1vMVjmCA
         zXZdHzwIdHvxuNT0G+E1CkmKaZ4BIDnSEP+ayVRiNZkmtxgOlddjPy8e36d51eUffQq7
         cYVXcTIZchPxT6eqwDBynDvA2gczeTvQYLcfJyRwX6zZP73str5n8j3R8IOdFrk5lMDO
         aJtjIcG1ZmuJvqyA/2ud7HUapoCiwM01aLrQRgHdrrgiFZohFnunGB8UU/E+gFhJt007
         LvMA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVZ2d11hb6FHRlSjJU65O1ETvWRotPFDeujVFW5uG0Idx0qCedBpbR1DEaxUHRgpZ4CMpsGBg==@lfdr.de
X-Gm-Message-State: AOJu0YxTvQFDEa8ULcjImxPibXMeCA+gw++Scb00TLIFPwfeKt12zV9Z
	GCoX1VXQUbEBUfETRdZyZ7lIBSNx2OFoNPHN0BytHuM7lyIZMfOSZ9tg
X-Google-Smtp-Source: AGHT+IHPaCkw1EQxFfbGY7wQYd1unidL7bo5ace/sAwPzHvRnENQDgBpDPA3jguJz/AiIXzKadFpNw==
X-Received: by 2002:a05:6e02:1c23:b0:424:7d35:bce8 with SMTP id e9e14a558f8ab-42581eae244mr104435645ab.25.1758715230786;
        Wed, 24 Sep 2025 05:00:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4Rzm9jIQKblm7WmzSdgGoatuCq15dzvX/a/VR2c+cC+w==
Received: by 2002:a05:6e02:4401:10b0:425:8b08:8d7a with SMTP id
 e9e14a558f8ab-4258b08904dls10471775ab.0.-pod-prod-05-us; Wed, 24 Sep 2025
 05:00:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVFflWH7rL92BPoEIAbgWtA6X6BaooDJwbYsZNDLBp4/a3vyTudJK0q+WYQfdV/Y4smbIYvbTU7xyM=@googlegroups.com
X-Received: by 2002:a92:cd85:0:b0:425:7411:3743 with SMTP id e9e14a558f8ab-42581eae4d5mr99770445ab.28.1758715229232;
        Wed, 24 Sep 2025 05:00:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758715229; cv=none;
        d=google.com; s=arc-20240605;
        b=CmSpfAyRScIA144qEli4p1zly4rYC6rwAc2aKeLO4p9GYMlRU2dffKXguHGzaE7NXP
         349gZSh+DNV/Lus8AA4vtTwFIb+wp/yUmaqnM8pz3lurQ/fQFW1ncPm3ItpnTHOVxzMg
         XVmokglE8DpOJrrFMdNLsjAP43F9SyRDrG8b/CDaGkozoFTRHb5AsQaOeXpfV7/GDtXQ
         UUMpZbLzDONvD9NSMuUJM4ImIMSj0pdmITLank0nQ1DTEXAaNuW6pDZWrCuRskTnRFu+
         /eKui7Kgazev0zdDA5cxatjKqUdBn34eEq8hZVJpveEjKn9uemaBhDjMWPADRhKeigwB
         4zaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tQq22tqtHC6AWIlA5VH2udrw6r/hyqmcjV7oYivMnv0=;
        fh=aA8j5HM0Jo5C9ATYU0cu7S04uPLS/B2cC7n1+rdB+og=;
        b=TBlu4mVprFT6ZiSOvZWNokPT6NkDNpWlJsdYiHHKLakWq7VBzJKGplCFC9RfwHWSvn
         0AcO+NrueLt+sx2v5siUY9EJ4WeaJ5RQufw/61GMTc1oZkvMs3T0HIGFRrwlvdYs+IYv
         vQMDT0fvjFU+BDO2cq5oFeHHIkxz48BDKw/kKovdKpWANAG7BY/7GpCy8WVAM1vNHtOE
         UWbjpSXX8AsRS5iz7RhqHJGLl89q/fZMk5ACKoqdYU29bRdo8k8h8ybZ1szKE5xjMk3o
         MxgVyo741eDzq4bksWSpVJqAwZ1XTCxAsJ6zoy54gA4LTlvAjQOX/Yxd+sjYluZkXjy8
         qhkg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="FsO/eOXf";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-42584b6ac65si1613435ab.1.2025.09.24.05.00.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 05:00:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id d2e1a72fcca58-77f605f22easo1358123b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 05:00:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXMuXD93vpYLyZ2NP9VY+sZk74SWXEN2UxGlIMqDb0OgHPYPUzmsvzuPFlsncrN4I56hxbgtRZ13qY=@googlegroups.com
X-Gm-Gg: ASbGnctN1fZbAYz9W4tTs0fv5SP6XjWWl5TQFkz2PHmB0zZTKDezoXCYIMJcEfLLuPq
	K0P31iv0cZR3ThpUBLYhz+jKL/24tKGSNWJQIfhKGPB9/U9lKZteTzYQjbatlNBn1ICljlarOH5
	mnlVcqUGLPeqgapWMZaIUbEsDFfOq8M/NZ/vfQiLy5hJ/nRHcXY+d15z+aH3JE2xuOgEabf02Lv
	i8yzEbT1Bjyzs+8sKU9dDBXj09M7a1Uj7//U+G39R2p56xMzmzCowxdp8/DdOud5iBWQ7spM/Av
	NyqkU/0YWVsQZ+aWPtWeCzlxECGX4mlPrRGbps8mZQ9V61R2Es9b3g7xQy6fvBUwZU9uKJ6/pq6
	TiK17XySxMAidCzqeHrkaw/olnb+zjlsszg==
X-Received: by 2002:a05:6a21:338a:b0:2b1:c9dc:6dab with SMTP id adf61e73a8af0-2cfef7df0b2mr8342943637.48.1758715228483;
        Wed, 24 Sep 2025 05:00:28 -0700 (PDT)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-77f2fdfbffesm9620110b3a.73.2025.09.24.05.00.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 05:00:27 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
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
Subject: [PATCH v5 18/23] mm/ksw: add stack overflow test
Date: Wed, 24 Sep 2025 19:59:24 +0800
Message-ID: <20250924115931.197077-3-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115931.197077-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
 <20250924115931.197077-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="FsO/eOXf";       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
index 1ed98931cc51..740e3c11b3ef 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -43,6 +43,20 @@ static void test_watch_fire(void)
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
 
 static ssize_t test_proc_write(struct file *file, const char __user *buffer,
 			       size_t count, loff_t *pos)
@@ -66,6 +80,9 @@ static ssize_t test_proc_write(struct file *file, const char __user *buffer,
 		case 0:
 			test_watch_fire();
 			break;
+		case 1:
+			test_canary_overflow();
+			break;
 		default:
 			pr_err("Unknown test number %d\n", test_num);
 			return -EINVAL;
@@ -85,7 +102,8 @@ static ssize_t test_proc_read(struct file *file, char __user *buffer,
 				    "============ usage ==============\n"
 				    "Usage:\n"
 				    "echo test{i} > /proc/kstackwatch_test\n"
-				    " test0 - test watch fire\n";
+				    " test0 - test watch fire\n"
+				    " test1 - test canary overflow\n";
 
 	return simple_read_from_buffer(buffer, count, pos, usage,
 				       strlen(usage));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115931.197077-3-wangjinchao600%40gmail.com.
