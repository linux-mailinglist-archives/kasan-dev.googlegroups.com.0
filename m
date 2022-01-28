Return-Path: <kasan-dev+bncBAABBJVNZ6HQMGQEJLBMZQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7228B49F877
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 12:42:32 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id b185-20020a37b2c2000000b004783172e402sf4609716qkf.5
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 03:42:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643370151; cv=pass;
        d=google.com; s=arc-20160816;
        b=NgxJHODWwI4iEJ/LdBV6Bk07+8BtDfE3s1UwMCgLebeurM+6FzPs1ZkoO/S39inamz
         dz+7kZsDQhdV+XOz4rBRIrc2N0iVrUyHxEwKB7zS1KXKCZ/B0t0vObRiShKR0S0Wdr/X
         hfKmMQl2cUz2Wtv4pWwnKyiHWCaj/etudygfbof1zfQii0gasRNftvvz56+tJZOfXaRW
         RyyrnzoTZ9KREYp8MA2yiFNV4PlmN7sy3/J14zcDeshi7hVs4XDb47ObyZYzNj/B/QDT
         9l+e7p/1oq1u+Vzh+bIcE5hXoVRJ0RsNldMAo6/Pec2O9IuLc2y0+H158X5E1kYmrx4B
         O10g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=c1ppFPfXdvkXoTFBLkDBYPfj3bWBdrUTalOTVNrnIVc=;
        b=g50QaNIRBYq96eS/xOIYBH6CQnz8udK6D+xqSZ24G0vrbeN7DTbZgluQBxEdGjRl1y
         4zxhOeoyITbrWr5R1zmxalFdpRccxSgGy1IJP6P4jc0jgRoPPJ3iASNN2Wl3NgWiqsiB
         I/+wMKeMrsMO+o/fnfexIjgrtyqmhdKGcEn/qOPuPIHLuTuzt1sPbifejDghLSFFfcc7
         a1YURTDoF0Llg6Movv3Li35GpCWfuQpTq/UwJL8DEfI1vqapoQ6xGVR1CP6die+YPL2Z
         Qm/rkksuE7S/fLdfgq+vr0/r2oIf1psEo+T55f7wm7gTxM+nj0KklPEHRkoM+FTLXGaQ
         rKNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c1ppFPfXdvkXoTFBLkDBYPfj3bWBdrUTalOTVNrnIVc=;
        b=X/uPbslxpGCvIJEEaDoo/Aj690mfwWzuOsi7wwp41hUdiOcKBEx4Sao5+1t6mgZY2x
         IcVwwuyA5Zxg54S+zx12LKtxDGaj1LvjEGjxiiiJwZRO+JUkdGCsX2MA7xd6Xe+Knnk0
         02NP/g0asoM/h4JKQv5lzKbFQ2gS17w7M6dMjzmDTn7Mp8jh47TIHihhgwIQACSsNTdI
         4kbv2SYUAk2pV3NHawKgs73S681jiQAxKy6uIUQ5MgVryxcKSNvPwuhYJzJJaLi2fehl
         i9Q+VG7kBKfwviN5NY+ibIDwJh15pDBwMXggn1IJdAZbvItqrdvmW4OkwOrobBySlMjm
         eMrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c1ppFPfXdvkXoTFBLkDBYPfj3bWBdrUTalOTVNrnIVc=;
        b=aaD4SBbnosqnyn+tf4O1p0g9F91MkAt5MJeu2SlgL39HCJT+K+q/bIBGxTayQjVepk
         pGprBzTZnt6oRpjI52FbvuGTZ2QwhpA5V/TCrsujVyDJO+aUy++hRoQSXW7pCX/GS4G9
         b5vBbGfSf5A4MPhHgBPKlF1fX7kMvJxOfHHmgHPoWksZI+0znxVNpCd9C4v34yUt8n6Z
         9X6qan+8qyv6P7n6jfYe0rQkk1GIN3W7dIpk7d1O7qwR5a77zvSxK4b6x1OTqobcSmP9
         9QjW1K7nxHSI6CFgwJFFK/09ZIh9EICoKWD024cIBRuSIjc5w9zrETYqe/iEDf1Xv0Q0
         9OGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531n3WEDm4Mr9kuiTVVJyX1ADjsTCLK8vjVU1bDHMCCF8UlPRxn+
	WFY9Y/5t1MO9emGY3u8DVPE=
X-Google-Smtp-Source: ABdhPJwkqGpNwav8WqUJsDj8abppBxsw6sxHUAGTedtPYELPH/oi7MZLfmLqy/b9BHnBtNhUey9PuA==
X-Received: by 2002:a37:2f44:: with SMTP id v65mr5204135qkh.225.1643370151514;
        Fri, 28 Jan 2022 03:42:31 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5097:: with SMTP id kk23ls4175075qvb.6.gmail; Fri,
 28 Jan 2022 03:42:30 -0800 (PST)
X-Received: by 2002:a05:6214:258f:: with SMTP id fq15mr6890499qvb.5.1643370150598;
        Fri, 28 Jan 2022 03:42:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643370150; cv=none;
        d=google.com; s=arc-20160816;
        b=SABmsdl+9qWayiipXLkj1xHIOq4czxAOPwL8l7+Ue29nOqFtNn4Cmy5Y6jCPp0zfH9
         e7CmGfLH9eLQmXf+/4pn17HFYZkOZfgDAc40/MXf2JDAhdMME/QIQxoYv0ATagMtIITo
         Tsq81owhYMG7dXMkuOJ7OkDQXKa909+dHV6WB3m8IUcQbogVWmgSKguLLLEZcbW9Qa6U
         WC+wEEsIK6U4RVgII87yxOr9sbT56dynR4a79t2hC2p27Lt0cYS7ZN3zoF8Ka2aIDcu6
         AvnlYS+/hYYKYtSRfLnhmyx09k/myvdh2h41tomiYSxLVf50v7LBdQq1mV7Brttx/tJb
         wWZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from;
        bh=kb5jp+HwFdWZaxh/wzSn4PSPYXmGdpTEy3PT45zKCaI=;
        b=EyKGLfUQaqHLeE96PD9FBuQvEHuMqAseMxFZFrnWhz/t+GuJmUiVooie7Jecv0ThXI
         Byt0U+I8HB4WnPMMcLHQGV7YkSsWMZv0s3ICRUirhFDYMwqyLhWarhUg3O3hvSb7ZuZN
         OvdXcm0TRXBWK8ZtvV5PqAHIvJSmLAKTqw1beO4JIIO9gqnjX8syISaaP+JSLi6N+O0b
         DhAmYN87JQay1EwTxvwhOfFjitgW+rLGzedoKLf5vbaHUdnt6ZmfAKslC9bQpBgwA5rX
         l1CWz7PkNjuhoRtXboinY8607BWEK6PkN1BEV/KCD8QcX1zBmWZ206/zUd3BMagQdX6R
         5uaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id i12si2639039qkn.5.2022.01.28.03.42.29
        for <kasan-dev@googlegroups.com>;
        Fri, 28 Jan 2022 03:42:30 -0800 (PST)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from linux.localdomain (unknown [113.200.148.30])
	by mail.loongson.cn (Coremail) with SMTP id AQAAf9Dxb+Kh1vNhREgFAA--.17556S5;
	Fri, 28 Jan 2022 19:42:27 +0800 (CST)
From: Tiezhu Yang <yangtiezhu@loongson.cn>
To: Baoquan He <bhe@redhat.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Marco Elver <elver@google.com>
Cc: kexec@lists.infradead.org,
	linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 3/5] kcsan: unset panic_on_warn before calling panic()
Date: Fri, 28 Jan 2022 19:42:23 +0800
Message-Id: <1643370145-26831-4-git-send-email-yangtiezhu@loongson.cn>
X-Mailer: git-send-email 2.1.0
In-Reply-To: <1643370145-26831-1-git-send-email-yangtiezhu@loongson.cn>
References: <1643370145-26831-1-git-send-email-yangtiezhu@loongson.cn>
X-CM-TRANSID: AQAAf9Dxb+Kh1vNhREgFAA--.17556S5
X-Coremail-Antispam: 1UD129KBjvdXoW7Xw4kJF18Xr43KF1kGr15Jwb_yoWDKFc_C3
	4kXa1UKr4kX3s0va1UKw15XrZrKw4jvF109a1UKws5G348Jr1UXFs5JFn8Grn5XFsxCr9x
	trn8Wrnakw40kjkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUIcSsGvfJTRUUUbqxYjsxI4VWkKwAYFVCjjxCrM7AC8VAFwI0_Wr0E3s1l1xkIjI8I
	6I8E6xAIw20EY4v20xvaj40_Wr0E3s1l1IIY67AEw4v_Jr0_Jr4l82xGYIkIc2x26280x7
	IE14v26r1rM28IrcIa0xkI8VCY1x0267AKxVW5JVCq3wA2ocxC64kIII0Yj41l84x0c7CE
	w4AK67xGY2AK021l84ACjcxK6xIIjxv20xvE14v26r1I6r4UM28EF7xvwVC0I7IYx2IY6x
	kF7I0E14v26r4j6F4UM28EF7xvwVC2z280aVAFwI0_GcCE3s1l84ACjcxK6I8E87Iv6xkF
	7I0E14v26rxl6s0DM2AIxVAIcxkEcVAq07x20xvEncxIr21l5I8CrVACY4xI64kE6c02F4
	0Ex7xfMcIj6xIIjxv20xvE14v26r1j6r18McIj6I8E87Iv67AKxVW8JVWxJwAm72CE4IkC
	6x0Yz7v_Jr0_Gr1lF7xvr2IYc2Ij64vIr41lFIxGxcIEc7CjxVA2Y2ka0xkIwI1lc2xSY4
	AK67AK6r4kMxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8C
	rVAFwI0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVWUtVW8Zw
	CIc40Y0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x02
	67AKxVW8JVWxJwCI42IY6xAIw20EY4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Jr
	0_Gr1lIxAIcVC2z280aVCY1x0267AKxVW8JVW8JrUvcSsGvfC2KfnxnUUI43ZEXa7IU5Zj
	jPUUUUU==
X-CM-SenderInfo: p1dqw3xlh2x3gn0dqz5rrqw2lrqou0/
X-Original-Sender: yangtiezhu@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
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

As done in the full WARN() handler, panic_on_warn needs to be cleared
before calling panic() to avoid recursive panics.

Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
---
 kernel/kcsan/report.c | 10 +++++++++-
 1 file changed, 9 insertions(+), 1 deletion(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 6779440..752ab33 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -492,8 +492,16 @@ static void print_report(enum kcsan_value_change value_change,
 	dump_stack_print_info(KERN_DEFAULT);
 	pr_err("==================================================================\n");
 
-	if (panic_on_warn)
+	if (panic_on_warn) {
+		/*
+		 * This thread may hit another WARN() in the panic path.
+		 * Resetting this prevents additional WARN() from panicking the
+		 * system on this thread.  Other threads are blocked by the
+		 * panic_mutex in panic().
+		 */
+		panic_on_warn = 0;
 		panic("panic_on_warn set ...\n");
+	}
 }
 
 static void release_report(unsigned long *flags, struct other_info *other_info)
-- 
2.1.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1643370145-26831-4-git-send-email-yangtiezhu%40loongson.cn.
